use serde::Serialize;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::executor::SqlExecutor;
use crate::instance::{SqlServerInstanceManager, unix_millis};
use crate::observation::InstanceSnapshot;
use crate::runtime_config::ObserverConfig;
use crate::runtime_error::RuntimeError;
use crate::{
    AvailabilityGroupName, Observation, ObservationFailureKind, ReplicaIdentity, ServerName,
};

pub const OBSERVATION_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservationSource {
    pub host: String,
    pub port: u16,
    pub availability_group: AvailabilityGroupName,
    pub expected_server_name: ServerName,
    pub replica: ReplicaIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservationReport {
    pub schema_version: u16,
    pub source: ObservationSource,
    pub evaluated_at_unix_millis: u64,
    pub max_age_millis: u64,
    pub fresh: bool,
    pub observation: Observation<InstanceSnapshot>,
}

impl ObservationReport {
    pub fn new(
        config: &ObserverConfig,
        observation: Observation<InstanceSnapshot>,
        evaluated_at_unix_millis: u64,
    ) -> Self {
        let max_age_millis = config.max_age_millis();
        Self {
            schema_version: OBSERVATION_SCHEMA_VERSION,
            source: ObservationSource {
                host: config.connection().endpoint().host().to_owned(),
                port: config.connection().endpoint().port(),
                availability_group: config.target().availability_group.clone(),
                expected_server_name: config.target().expected_server_name.clone(),
                replica: config.target().replica.clone(),
            },
            evaluated_at_unix_millis,
            max_age_millis,
            fresh: observation.is_fresh_at(evaluated_at_unix_millis, max_age_millis),
            observation,
        }
    }

    pub fn is_fresh_at(&self, now_unix_millis: u64) -> bool {
        self.observation
            .is_fresh_at(now_unix_millis, self.max_age_millis)
    }
}

pub struct SqlServerMonitor<E> {
    manager: SqlServerInstanceManager<E>,
}

impl<E: SqlExecutor> SqlServerMonitor<E> {
    pub fn new(manager: SqlServerInstanceManager<E>) -> Self {
        Self { manager }
    }

    pub async fn run(
        &self,
        publisher: watch::Sender<Option<ObservationReport>>,
        cancellation: CancellationToken,
    ) -> Result<(), RuntimeError> {
        loop {
            let observation = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(()),
                result = self.manager.observe() => result?,
            };
            let report = ObservationReport::new(self.manager.config(), observation, unix_millis()?);
            publisher.send(Some(report)).map_err(|_| {
                RuntimeError::new(
                    ObservationFailureKind::Unreachable,
                    "monitor",
                    "observation subscriber closed",
                )
            })?;
            // Delay after each attempt rather than accumulating missed timer ticks.
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(()),
                _ = tokio::time::sleep(self.manager.config().poll_interval()) => {}
            }
        }
    }
}
