use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::observation::{
    ObservationTarget, RuntimeError, ServerCapabilities, SqlServerSnapshot, check_capabilities,
    observe,
};
use crate::tds::TdsExecutor;
use crate::types::Observation;

/// Owns the connection boundary for one directly addressed SQL Server replica.
///
/// It intentionally exposes observation only. Availability-group mutations are
/// introduced by a later delivery stage.
pub struct SqlServerInstanceManager {
    executor: Arc<dyn TdsExecutor>,
    target: ObservationTarget,
}

impl SqlServerInstanceManager {
    pub fn new(executor: Arc<dyn TdsExecutor>, target: ObservationTarget) -> Self {
        Self { executor, target }
    }

    pub fn target(&self) -> &ObservationTarget {
        &self.target
    }

    pub async fn check_startup_capabilities(&self) -> Result<ServerCapabilities, RuntimeError> {
        check_capabilities(self.executor.as_ref()).await
    }

    pub async fn observe_at(&self, observed_at_unix_millis: u64) -> Observation<SqlServerSnapshot> {
        observe(
            self.executor.as_ref(),
            &self.target,
            observed_at_unix_millis,
        )
        .await
    }

    pub async fn observe_now(&self) -> Result<Observation<SqlServerSnapshot>, RuntimeError> {
        Ok(self.observe_at(unix_millis()?).await)
    }
}

pub(crate) fn unix_millis() -> Result<u64, RuntimeError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| RuntimeError::Malformed {
            field: "system clock",
            detail: error.to_string(),
        })?
        .as_millis();
    u64::try_from(millis).map_err(|error| RuntimeError::Malformed {
        field: "system clock",
        detail: error.to_string(),
    })
}
