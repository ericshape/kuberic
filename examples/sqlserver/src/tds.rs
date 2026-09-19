use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use tiberius::{AuthMethod, Client, Config, EncryptionLevel, Row, ToSql};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::compat::TokioAsyncWriteCompatExt;

use crate::types::Endpoint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TdsErrorKind {
    Unreachable,
    Authentication,
    PermissionDenied,
    TimedOut,
    Protocol,
    Query,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct TdsError {
    kind: TdsErrorKind,
    message: String,
}

impl TdsError {
    pub fn new(kind: TdsErrorKind, message: impl Into<String>) -> Self {
        let message = message
            .into()
            .chars()
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .take(1_024)
            .collect();
        Self { kind, message }
    }

    pub fn kind(&self) -> TdsErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TdsQueryKind {
    Capabilities,
    AnchorBefore,
    AvailabilityGroup,
    AvailabilityReplicas,
    ReplicaStates,
    AvailabilityDatabase,
    DatabaseReplicaStates,
    AutomaticSeeding,
    PhysicalSeeding,
    AnchorAfter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdsQuery {
    kind: TdsQueryKind,
    statement: &'static str,
    parameters: Vec<String>,
}

impl TdsQuery {
    pub(crate) fn new(
        kind: TdsQueryKind,
        statement: &'static str,
        parameters: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            kind,
            statement,
            parameters: parameters.into_iter().collect(),
        }
    }

    pub fn kind(&self) -> TdsQueryKind {
        self.kind
    }

    pub fn statement(&self) -> &'static str {
        self.statement
    }

    pub fn parameters(&self) -> &[String] {
        &self.parameters
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdsRow {
    columns: BTreeMap<String, Option<String>>,
}

impl TdsRow {
    pub fn new(columns: BTreeMap<String, Option<String>>) -> Self {
        Self { columns }
    }

    pub fn from_pairs<const N: usize>(columns: [(&str, Option<&str>); N]) -> Self {
        Self {
            columns: columns
                .into_iter()
                .map(|(name, value)| {
                    (
                        name.to_string(),
                        value.map(std::string::ToString::to_string),
                    )
                })
                .collect(),
        }
    }

    pub fn get(&self, column: &str) -> Option<Option<&str>> {
        self.columns
            .get(column)
            .map(|value| value.as_deref())
    }
}

pub type TdsResultSet = Vec<TdsRow>;

#[async_trait]
pub trait TdsExecutor: Send + Sync {
    /// Executes every query, in order, over one TDS session.
    async fn execute(&self, queries: &[TdsQuery]) -> Result<Vec<TdsResultSet>, TdsError>;
}

pub struct TdsConnectionConfig {
    endpoint: Endpoint,
    database: String,
    username: String,
    password: String,
    ca_certificate: Option<PathBuf>,
    connect_timeout: Duration,
    query_timeout: Duration,
}

impl TdsConnectionConfig {
    pub fn new(
        endpoint: Endpoint,
        username: impl Into<String>,
        password: impl Into<String>,
        ca_certificate: Option<PathBuf>,
        connect_timeout: Duration,
        query_timeout: Duration,
    ) -> Result<Self, TdsError> {
        let username = username.into();
        let password = password.into();
        if username.is_empty() {
            return Err(TdsError::new(
                TdsErrorKind::Authentication,
                "observer username must not be empty",
            ));
        }
        if password.is_empty() {
            return Err(TdsError::new(
                TdsErrorKind::Authentication,
                "observer password must not be empty",
            ));
        }
        if connect_timeout.is_zero() || query_timeout.is_zero() {
            return Err(TdsError::new(
                TdsErrorKind::Protocol,
                "TDS timeouts must be positive",
            ));
        }

        Ok(Self {
            endpoint,
            database: "master".to_string(),
            username,
            password,
            ca_certificate,
            connect_timeout,
            query_timeout,
        })
    }
}

pub struct TiberiusExecutor {
    config: TdsConnectionConfig,
}

impl TiberiusExecutor {
    pub fn new(config: TdsConnectionConfig) -> Self {
        Self { config }
    }

    async fn connect(
        &self,
    ) -> Result<Client<tokio_util::compat::Compat<TcpStream>>, TdsError> {
        let mut config = Config::new();
        config.host(self.config.endpoint.host());
        config.port(self.config.endpoint.port());
        config.database(&self.config.database);
        config.application_name("kuberic-sqlserver-observer");
        config.encryption(EncryptionLevel::Required);
        config.authentication(AuthMethod::sql_server(
            &self.config.username,
            &self.config.password,
        ));

        if let Some(path) = &self.config.ca_certificate {
            let path = path.to_str().ok_or_else(|| {
                TdsError::new(
                    TdsErrorKind::Protocol,
                    "TLS CA certificate path must be valid UTF-8",
                )
            })?;
            config.trust_cert_ca(path);
        }

        let address = config.get_addr();
        let tcp = timeout(self.config.connect_timeout, TcpStream::connect(&address))
            .await
            .map_err(|_| {
                TdsError::new(
                    TdsErrorKind::TimedOut,
                    format!("timed out connecting to {}", self.config.endpoint),
                )
            })?
            .map_err(|error| {
                TdsError::new(
                    TdsErrorKind::Unreachable,
                    format!("could not connect to {}: {error}", self.config.endpoint),
                )
            })?;
        tcp.set_nodelay(true).map_err(|error| {
            TdsError::new(
                TdsErrorKind::Unreachable,
                format!(
                    "could not configure connection to {}: {error}",
                    self.config.endpoint
                ),
            )
        })?;

        timeout(
            self.config.connect_timeout,
            Client::connect(config, tcp.compat_write()),
        )
        .await
        .map_err(|_| {
            TdsError::new(
                TdsErrorKind::TimedOut,
                format!(
                    "timed out negotiating TDS with {}",
                    self.config.endpoint
                ),
            )
        })?
        .map_err(classify_driver_error)
    }
}

#[async_trait]
impl TdsExecutor for TiberiusExecutor {
    async fn execute(&self, queries: &[TdsQuery]) -> Result<Vec<TdsResultSet>, TdsError> {
        let mut client = self.connect().await?;
        let mut result_sets = Vec::with_capacity(queries.len());

        for query in queries {
            let parameters: Vec<&dyn ToSql> = query
                .parameters
                .iter()
                .map(|value| value as &dyn ToSql)
                .collect();
            let rows = timeout(self.config.query_timeout, async {
                client
                    .query(query.statement, &parameters)
                    .await?
                    .into_first_result()
                    .await
            })
            .await
            .map_err(|_| {
                TdsError::new(
                    TdsErrorKind::TimedOut,
                    format!("TDS query {:?} timed out", query.kind),
                )
            })?
            .map_err(classify_driver_error)?;

            result_sets.push(
                rows.into_iter()
                    .map(row_to_strings)
                    .collect::<Result<_, _>>()?,
            );
        }

        Ok(result_sets)
    }
}

fn row_to_strings(row: Row) -> Result<TdsRow, TdsError> {
    let names: Vec<String> = row
        .columns()
        .iter()
        .map(|column| column.name().to_string())
        .collect();
    let mut columns = BTreeMap::new();

    for (index, name) in names.into_iter().enumerate() {
        if columns.contains_key(&name) {
            return Err(TdsError::new(
                TdsErrorKind::Protocol,
                format!("TDS result contains duplicate column {name}"),
            ));
        }
        let value = row
            .try_get::<&str, _>(index)
            .map_err(classify_driver_error)?
            .map(std::string::ToString::to_string);
        columns.insert(name, value);
    }

    Ok(TdsRow::new(columns))
}

fn classify_driver_error(error: tiberius::error::Error) -> TdsError {
    let kind = match &error {
        tiberius::error::Error::Io {
            kind: std::io::ErrorKind::TimedOut,
            ..
        } => TdsErrorKind::TimedOut,
        tiberius::error::Error::Io { .. } | tiberius::error::Error::Tls(_) => {
            TdsErrorKind::Unreachable
        }
        tiberius::error::Error::Server(server) if server.code() == 18_456 => {
            TdsErrorKind::Authentication
        }
        tiberius::error::Error::Server(server) if matches!(server.code(), 229 | 230 | 297) => {
            TdsErrorKind::PermissionDenied
        }
        tiberius::error::Error::Protocol(_)
        | tiberius::error::Error::Encoding(_)
        | tiberius::error::Error::Conversion(_)
        | tiberius::error::Error::Utf8
        | tiberius::error::Error::Utf16 => TdsErrorKind::Protocol,
        _ => TdsErrorKind::Query,
    };
    TdsError::new(kind, error.to_string())
}
