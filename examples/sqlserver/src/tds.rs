mod panic_boundary;

use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use futures::TryStreamExt;
use tiberius::{AuthMethod, Client, Column, ColumnType, Config, EncryptionLevel, QueryItem};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};
use zeroize::Zeroizing;

use crate::executor::{QueryRow, SqlExecutor, SqlSession};
use crate::query::ReadQuery;
use crate::runtime_config::{ConnectionSettings, read_bounded};
use crate::runtime_error::RuntimeError;
use crate::{AvailabilityGroupName, ObservationFailureKind};

const MAX_SECRET_BYTES: u64 = 4096;
const MAX_QUERY_ROWS: usize = 4096;
const MAX_CELL_BYTES: usize = 4096;

pub struct TdsExecutor {
    settings: ConnectionSettings,
}

impl TdsExecutor {
    pub fn new(settings: ConnectionSettings) -> Self {
        Self { settings }
    }
}

pub(crate) struct TdsSession {
    client: Option<Client<Compat<TcpStream>>>,
    query_timeout: Duration,
}

#[derive(Clone, Copy)]
pub(crate) enum TdsPurpose {
    Observer,
    Mutation,
}

#[async_trait]
impl SqlExecutor for TdsExecutor {
    async fn connect(&self) -> Result<Box<dyn SqlSession>, RuntimeError> {
        Ok(Box::new(
            connect_session(&self.settings, TdsPurpose::Observer).await?,
        ))
    }
}

pub(crate) async fn connect_session(
    settings: &ConnectionSettings,
    purpose: TdsPurpose,
) -> Result<TdsSession, RuntimeError> {
    timeout(settings.connect_timeout, async {
        let (username_stage, password_stage, application_name) = match purpose {
            TdsPurpose::Observer => (
                "observer username",
                "observer password",
                "kuberic-sqlserver-observer",
            ),
            TdsPurpose::Mutation => (
                "mutation username",
                "mutation password",
                "kuberic-sqlserver-ag-adapter",
            ),
        };
        let username = read_secret(&settings.username_file, username_stage).await?;
        let password = read_secret(&settings.password_file, password_stage).await?;
        let config = connection_config(settings, &username, &password, application_name);
        let tcp = TcpStream::connect((settings.endpoint.host(), settings.endpoint.port()))
            .await
            .map_err(|_| {
                RuntimeError::new(
                    ObservationFailureKind::Unreachable,
                    "TCP connect",
                    "cannot reach the configured SQL Server endpoint",
                )
            })?;
        tcp.set_nodelay(true).map_err(|_| {
            RuntimeError::new(
                ObservationFailureKind::Unreachable,
                "TCP connect",
                "cannot configure the SQL Server connection",
            )
        })?;
        let client = panic_boundary::contain("TLS/TDS login", async {
            Client::connect(config, tcp.compat_write())
                .await
                .map_err(|error| driver_error("TLS/TDS login", error))
        })
        .await?;
        Ok(TdsSession {
            client: Some(client),
            query_timeout: settings.query_timeout,
        })
    })
    .await
    .map_err(|_| timed_out("TLS/TDS connect"))?
}

fn connection_config(
    settings: &ConnectionSettings,
    username: &str,
    password: &str,
    application_name: &'static str,
) -> Config {
    let mut config = Config::new();
    config.host(settings.endpoint.host());
    config.port(settings.endpoint.port());
    config.database("master");
    config.application_name(application_name);
    // Required avoids both plaintext fallback and the driver's On/Off panic.
    config.encryption(EncryptionLevel::Required);
    if let Some(path) = &settings.ca_certificate_file {
        // Config validation rejects non-UTF-8 paths before this point.
        config.trust_cert_ca(path.to_string_lossy());
    }
    config.authentication(AuthMethod::sql_server(username, password));
    // ApplicationIntent is not a write fence and can trigger replica routing.
    // Connect to the registered instance directly.
    config
}

#[async_trait]
impl SqlSession for TdsSession {
    async fn query(
        &mut self,
        query: ReadQuery,
        availability_group: &AvailabilityGroupName,
    ) -> Result<Vec<QueryRow>, RuntimeError> {
        self.query_text(
            query.sql(),
            availability_group.as_str(),
            query.columns(),
            query.label(),
        )
        .await
    }
}

impl TdsSession {
    pub(crate) async fn query_text(
        &mut self,
        sql: &str,
        parameter: &str,
        columns: &[&str],
        stage: &'static str,
    ) -> Result<Vec<QueryRow>, RuntimeError> {
        // The future owns the client, so an error, panic, or cancellation cannot
        // leave a partially decoded session available for another query.
        let mut client = self
            .client
            .take()
            .ok_or_else(|| malformed(stage, "TDS session is closed; reconnect before observing"))?;
        let (client, rows) = timeout(
            self.query_timeout,
            panic_boundary::contain(stage, async move {
                let name = parameter;
                let mut stream = client
                    .query(sql, &[&name])
                    .await
                    .map_err(|error| driver_error(stage, error))?;
                let mut rows = Vec::new();
                let mut result_sets = 0;
                while let Some(item) = stream
                    .try_next()
                    .await
                    .map_err(|error| driver_error(stage, error))?
                {
                    match item {
                        QueryItem::Metadata(metadata) => {
                            result_sets += 1;
                            if result_sets != 1 {
                                return Err(malformed(stage, "unexpected multiple result sets"));
                            }
                            validate_result_columns(columns, metadata.columns(), stage)?;
                        }
                        QueryItem::Row(row) => {
                            if rows.len() == MAX_QUERY_ROWS {
                                return Err(malformed(
                                    stage,
                                    "query exceeds the 4096-row observation limit",
                                ));
                            }
                            let mut values = QueryRow::new();
                            for (index, column) in row.columns().iter().enumerate() {
                                let value = row.try_get::<&str, _>(index).map_err(|_| {
                                    malformed(stage, "expected a text or NULL DMV column")
                                })?;
                                if value.is_some_and(|text| text.len() > MAX_CELL_BYTES) {
                                    return Err(malformed(
                                        stage,
                                        "DMV column exceeds the size limit",
                                    ));
                                }
                                if values
                                    .insert(column.name().to_owned(), value.map(str::to_owned))
                                    .is_some()
                                {
                                    return Err(malformed(stage, "duplicate DMV column name"));
                                }
                            }
                            rows.push(values);
                        }
                    }
                }
                if result_sets != 1 {
                    return Err(malformed(stage, "missing DMV result set"));
                }
                drop(stream);
                Ok((client, rows))
            }),
        )
        .await
        .map_err(|_| timed_out(stage))??;
        self.client = Some(client);
        Ok(rows)
    }

    pub(crate) async fn execute_mutation(mut self, sql: &str) -> Result<(), RuntimeError> {
        let mut client = self.client.take().ok_or_else(|| {
            malformed(
                "native mutation",
                "TDS session is closed; reconnect before executing",
            )
        })?;
        panic_boundary::contain("native mutation", async move {
            client
                .execute(sql, &[])
                .await
                .map_err(|error| driver_error("native mutation", error))?;
            Ok(())
        })
        .await
    }
}

fn validate_result_columns(
    expected_columns: &[&str],
    columns: &[Column],
    stage: &'static str,
) -> Result<(), RuntimeError> {
    if columns.len() != expected_columns.len()
        || columns
            .iter()
            .zip(expected_columns)
            .any(|(actual, expected)| {
                actual.name() != *expected || actual.column_type() != ColumnType::NVarchar
            })
    {
        return Err(malformed(
            stage,
            "DMV result schema does not match the predefined query",
        ));
    }
    Ok(())
}

pub(crate) async fn read_secret(
    path: &Path,
    stage: &'static str,
) -> Result<Zeroizing<String>, RuntimeError> {
    let bytes = Zeroizing::new(read_bounded(path, MAX_SECRET_BYTES, stage).await?);
    let text =
        std::str::from_utf8(&bytes).map_err(|_| malformed(stage, "Secret must be UTF-8 text"))?;
    if text.is_empty() || text.contains(['\0', '\r', '\n']) {
        return Err(malformed(
            stage,
            "Secret must be nonempty text without NUL or line endings",
        ));
    }
    Ok(Zeroizing::new(text.to_owned()))
}

pub(crate) fn driver_error(stage: &'static str, error: tiberius::error::Error) -> RuntimeError {
    use tiberius::error::Error;

    let code = error.code();
    let (kind, message) = match &error {
        Error::Server(_) => server_error(code),
        Error::Tls(_) => (
            ObservationFailureKind::Tls,
            "TLS certificate or handshake validation failed",
        ),
        Error::Io { kind, .. } if *kind == std::io::ErrorKind::TimedOut => (
            ObservationFailureKind::TimedOut,
            "SQL Server transport timed out",
        ),
        Error::Io { kind, .. }
            if stage == "TLS/TDS login"
                && matches!(
                    kind,
                    std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput
                ) =>
        {
            (
                ObservationFailureKind::Tls,
                "TLS certificate or handshake validation failed",
            )
        }
        Error::Io { .. } => (
            ObservationFailureKind::Unreachable,
            "SQL Server transport failed",
        ),
        Error::Routing { .. } => (
            ObservationFailureKind::Unsupported,
            "SQL Server routing is not allowed for an instance-bound observer",
        ),
        _ => (
            ObservationFailureKind::Malformed,
            "invalid TDS response or unsupported column encoding",
        ),
    };
    let mut failure = RuntimeError::new(kind, stage, message);
    failure.server_code = code;
    failure
}

fn server_error(code: Option<u32>) -> (ObservationFailureKind, &'static str) {
    match code {
        Some(18452 | 18456 | 18470 | 18486 | 18487 | 18488) => (
            ObservationFailureKind::Authentication,
            "SQL Server authentication failed",
        ),
        Some(229 | 230 | 262 | 297 | 300 | 916) => (
            ObservationFailureKind::PermissionDenied,
            "SQL Server denied the observation permission",
        ),
        _ => (
            ObservationFailureKind::Unsupported,
            "SQL Server rejected the observation query",
        ),
    }
}

fn timed_out(stage: &'static str) -> RuntimeError {
    RuntimeError::new(
        ObservationFailureKind::TimedOut,
        stage,
        "observation deadline exceeded",
    )
}

fn malformed(stage: &'static str, message: &'static str) -> RuntimeError {
    RuntimeError::new(ObservationFailureKind::Malformed, stage, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_errors_never_echo_server_text() {
        let marker = "secret-password-and-connection-string";
        let errors = [
            tiberius::error::Error::Protocol(marker.into()),
            tiberius::error::Error::Tls(marker.to_owned()),
            tiberius::error::Error::Io {
                kind: std::io::ErrorKind::ConnectionReset,
                message: marker.to_owned(),
            },
            tiberius::error::Error::Routing {
                host: marker.to_owned(),
                port: 1433,
            },
        ];
        for error in errors {
            let sanitized = driver_error("test", error);
            assert!(!sanitized.to_string().contains(marker));
            assert!(!format!("{sanitized:?}").contains(marker));
        }
    }

    #[test]
    fn permission_and_login_failures_are_distinct() {
        assert_eq!(
            server_error(Some(297)).0,
            ObservationFailureKind::PermissionDenied
        );
        assert_eq!(
            server_error(Some(18456)).0,
            ObservationFailureKind::Authentication
        );
        assert_eq!(
            server_error(Some(208)).0,
            ObservationFailureKind::Unsupported
        );
    }

    #[tokio::test]
    async fn discarded_tds_sessions_require_a_new_connection() {
        let mut session = TdsSession {
            client: None,
            query_timeout: Duration::from_secs(1),
        };
        let error = session
            .query(
                ReadQuery::Permissions,
                &AvailabilityGroupName::new("test-ag").unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind, ObservationFailureKind::Malformed);
        assert_eq!(
            error.message,
            "TDS session is closed; reconnect before observing"
        );
    }

    #[tokio::test]
    async fn discarded_tds_sessions_reject_probes_and_native_statements() {
        let mut session = TdsSession {
            client: None,
            query_timeout: Duration::from_secs(1),
        };
        let probe = session
            .query_text("SELECT @P1 AS value", "identity", &["value"], "probe")
            .await
            .unwrap_err();
        assert_eq!(probe.kind, ObservationFailureKind::Malformed);
        assert_eq!(probe.stage, "probe");
        let mutation = session.execute_mutation("SELECT 1").await.unwrap_err();
        assert_eq!(mutation.kind, ObservationFailureKind::Malformed);
        assert_eq!(mutation.stage, "native mutation");
    }

    #[test]
    fn result_metadata_is_validated_even_when_no_rows_are_returned() {
        for query in ReadQuery::ALL {
            let validate_columns = |query: ReadQuery, columns: &[Column]| {
                validate_result_columns(query.columns(), columns, query.label())
            };
            let expected: Vec<Column> = query
                .columns()
                .iter()
                .map(|name| Column::new((*name).to_owned(), ColumnType::NVarchar))
                .collect();
            validate_columns(query, &expected).unwrap();
            assert!(validate_columns(query, &[]).is_err());
            assert!(validate_columns(query, &expected[1..]).is_err());
            let mut reordered = expected.clone();
            reordered.swap(0, 1);
            assert!(validate_columns(query, &reordered).is_err());
            let mut wrong_type = expected.clone();
            wrong_type[0] = Column::new(query.columns()[0].to_owned(), ColumnType::Int8);
            assert!(validate_columns(query, &wrong_type).is_err());
            let mut duplicate = expected.clone();
            duplicate.push(expected[0].clone());
            assert!(validate_columns(query, &duplicate).is_err());
        }
    }
}
