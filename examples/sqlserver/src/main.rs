mod output;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use output::OutputWriter;
use sqlserver_replicated::ObservationFailureKind;
use sqlserver_replicated::instance::{SqlServerInstanceManager, unix_millis};
use sqlserver_replicated::monitor::{ObservationReport, SqlServerMonitor};
use sqlserver_replicated::runtime_config::ObserverConfig;
use sqlserver_replicated::runtime_error::RuntimeError;
use sqlserver_replicated::tds::TdsExecutor;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(about = "Observe an existing SQL Server 2022 instance; never modifies AG state")]
struct Args {
    /// JSON configuration containing target identity and mounted Secret file paths.
    #[arg(long)]
    config: PathBuf,
    /// Continuously emit the latest complete observations as newline-delimited JSON.
    #[arg(long)]
    watch: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("sqlserver-observer: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<ExitCode, RuntimeError> {
    let config = ObserverConfig::read(&args.config).await?;
    let executor = TdsExecutor::new(config.connection().clone());
    let manager = SqlServerInstanceManager::new(executor, config);
    let output = OutputWriter::new()?;
    if !args.watch {
        return tokio::select! {
            biased;
            result = shutdown_signal() => {
                result?;
                Ok(ExitCode::from(130))
            }
            result = async {
                let observation = manager.observe().await?;
                let report = ObservationReport::new(manager.config(), observation, unix_millis()?);
                output.write(&report).await?;
                Ok(if report.fresh { ExitCode::SUCCESS } else { ExitCode::FAILURE })
            } => result,
        };
    }

    let (publisher, mut receiver) = watch::channel(None);
    let cancellation = CancellationToken::new();
    let monitor_cancellation = cancellation.clone();
    let monitor = SqlServerMonitor::new(manager);
    let task = tokio::spawn(async move { monitor.run(publisher, monitor_cancellation).await });
    let mut failed = false;
    let output_result = tokio::select! {
        biased;
        result = shutdown_signal() => result,
        result = watch_output(&mut receiver, &output, &mut failed) => result,
    };
    cancellation.cancel();
    task.await.map_err(|_| {
        RuntimeError::new(
            ObservationFailureKind::Unsupported,
            "monitor",
            "observation task terminated unexpectedly",
        )
    })??;
    output_result?;
    Ok(if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

async fn watch_output(
    receiver: &mut watch::Receiver<Option<ObservationReport>>,
    output: &OutputWriter,
    failed: &mut bool,
) -> Result<(), RuntimeError> {
    loop {
        receiver.changed().await.map_err(|_| {
            RuntimeError::new(
                ObservationFailureKind::Unreachable,
                "monitor",
                "observation publisher closed",
            )
        })?;
        let report = receiver.borrow_and_update().clone();
        if let Some(report) = report {
            *failed |= !report.fresh;
            output.write(&report).await?;
        }
    }
}

async fn shutdown_signal() -> Result<(), RuntimeError> {
    let signal_error = |_| {
        RuntimeError::new(
            ObservationFailureKind::Unsupported,
            "shutdown",
            "cannot listen for process shutdown",
        )
    };
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(signal_error)?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.map_err(signal_error),
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await.map_err(signal_error)
}
