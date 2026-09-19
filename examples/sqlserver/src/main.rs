use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use serde::Serialize;
use sqlserver_replicated::{
    AvailabilityGroupName, Endpoint, MonitorState, ObservationTarget, ServerCapabilities,
    SqlIdentifier, SqlServerHealthMonitor, SqlServerInstanceManager, TdsConnectionConfig,
    TiberiusExecutor,
};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(
    name = "sqlserver-observe",
    about = "Observe one SQL Server EXTERNAL availability-group replica"
)]
struct Args {
    /// DNS name used both for TDS and TLS certificate verification.
    #[arg(long, env = "KUBERIC_SQLSERVER_HOST")]
    host: String,

    #[arg(long, env = "KUBERIC_SQLSERVER_PORT", default_value_t = 1433)]
    port: u16,

    /// File containing the observation principal's username.
    #[arg(long, env = "KUBERIC_SQLSERVER_USERNAME_FILE")]
    username_file: PathBuf,

    /// File containing the observation principal's password.
    #[arg(long, env = "KUBERIC_SQLSERVER_PASSWORD_FILE")]
    password_file: PathBuf,

    /// Optional single PEM, CRT, or DER CA certificate in addition to system roots.
    #[arg(long, env = "KUBERIC_SQLSERVER_TLS_CA_CERTIFICATE")]
    tls_ca_certificate: Option<PathBuf>,

    #[arg(long, env = "KUBERIC_SQLSERVER_AVAILABILITY_GROUP")]
    availability_group: String,

    #[arg(long, env = "KUBERIC_SQLSERVER_DATABASE")]
    database: String,

    #[arg(
        long,
        env = "KUBERIC_SQLSERVER_CONNECT_TIMEOUT_SECONDS",
        default_value_t = 10
    )]
    connect_timeout_seconds: u64,

    #[arg(
        long,
        env = "KUBERIC_SQLSERVER_QUERY_TIMEOUT_SECONDS",
        default_value_t = 10
    )]
    query_timeout_seconds: u64,

    /// Continue observing until interrupted instead of emitting one sample.
    #[arg(long)]
    watch: bool,

    #[arg(
        long,
        env = "KUBERIC_SQLSERVER_POLL_INTERVAL_SECONDS",
        default_value_t = 5
    )]
    poll_interval_seconds: u64,
}

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum OutputEvent {
    Startup {
        capabilities: ServerCapabilities,
        least_privilege_warnings: Vec<&'static str>,
    },
    Observation {
        state: Box<MonitorState>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();

    let endpoint = Endpoint::new(args.host, args.port)?;
    let username = read_secret(&args.username_file).await?;
    let password = read_secret(&args.password_file).await?;
    let connection = TdsConnectionConfig::new(
        endpoint,
        username,
        password,
        args.tls_ca_certificate,
        Duration::from_secs(args.connect_timeout_seconds),
        Duration::from_secs(args.query_timeout_seconds),
    )?;
    let target = ObservationTarget::new(
        AvailabilityGroupName::new(args.availability_group)?,
        SqlIdentifier::new(args.database)?,
    );
    let instance = Arc::new(SqlServerInstanceManager::new(
        Arc::new(TiberiusExecutor::new(connection)),
        target,
    ));

    let capabilities = instance.check_startup_capabilities().await?;
    let warnings = capabilities.least_privilege_warnings();
    for warning in &warnings {
        tracing::warn!("{warning}");
    }
    print_event(&OutputEvent::Startup {
        capabilities,
        least_privilege_warnings: warnings,
    })?;

    let monitor = Arc::new(SqlServerHealthMonitor::new(
        instance,
        Duration::from_secs(args.poll_interval_seconds),
    )?);
    if !args.watch {
        print_event(&OutputEvent::Observation {
            state: Box::new(monitor.poll_once().await?),
        })?;
        return Ok(());
    }

    let shutdown = CancellationToken::new();
    let mut observations = monitor.subscribe();
    let monitor_task = {
        let monitor = monitor.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move { monitor.run(shutdown).await })
    };

    loop {
        tokio::select! {
            result = observations.changed() => {
                result?;
                if let Some(state) = observations.borrow_and_update().clone() {
                    print_event(&OutputEvent::Observation {
                        state: Box::new(state),
                    })?;
                }
            }
            result = tokio::signal::ctrl_c() => {
                result?;
                shutdown.cancel();
                break;
            }
        }
    }
    monitor_task.await??;
    Ok(())
}

async fn read_secret(path: &Path) -> Result<String, std::io::Error> {
    tokio::fs::read_to_string(path).await
}

fn print_event(event: &OutputEvent) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", serde_json::to_string(event)?);
    Ok(())
}
