use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::watch;
use tokio::time::{MissedTickBehavior, interval};
use tokio_util::sync::CancellationToken;

use crate::instance::{SqlServerInstanceManager, unix_millis};
use crate::observation::{RuntimeError, SqlServerSnapshot};
use crate::types::Observation;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SuccessfulSnapshot {
    pub value: SqlServerSnapshot,
    pub observed_at_unix_millis: u64,
}

impl SuccessfulSnapshot {
    pub fn is_fresh_at(&self, now_unix_millis: u64, max_age_millis: u64) -> bool {
        now_unix_millis
            .checked_sub(self.observed_at_unix_millis)
            .is_some_and(|age| age <= max_age_millis)
    }
}

/// Retains the latest attempt separately from the last successful snapshot.
///
/// This lets consumers distinguish current failure from stale last-known
/// evidence without ever treating that evidence as fresh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MonitorState {
    pub latest_attempt: Observation<SqlServerSnapshot>,
    pub last_successful: Option<SuccessfulSnapshot>,
}

pub struct SqlServerHealthMonitor {
    instance: Arc<SqlServerInstanceManager>,
    poll_interval: Duration,
    state: watch::Sender<Option<MonitorState>>,
}

impl SqlServerHealthMonitor {
    pub fn new(
        instance: Arc<SqlServerInstanceManager>,
        poll_interval: Duration,
    ) -> Result<Self, RuntimeError> {
        if poll_interval.is_zero() {
            return Err(RuntimeError::Malformed {
                field: "poll interval",
                detail: "poll interval must be positive".to_string(),
            });
        }
        let (state, _) = watch::channel(None);
        Ok(Self {
            instance,
            poll_interval,
            state,
        })
    }

    pub fn subscribe(&self) -> watch::Receiver<Option<MonitorState>> {
        self.state.subscribe()
    }

    pub fn latest(&self) -> Option<MonitorState> {
        self.state.borrow().clone()
    }

    pub async fn poll_once_at(&self, observed_at_unix_millis: u64) -> MonitorState {
        let latest_attempt = self.instance.observe_at(observed_at_unix_millis).await;
        let last_successful = match &latest_attempt {
            Observation::Present {
                value,
                observed_at_unix_millis,
            } => Some(SuccessfulSnapshot {
                value: value.clone(),
                observed_at_unix_millis: *observed_at_unix_millis,
            }),
            Observation::Absent { .. } | Observation::Failed(_) => self
                .state
                .borrow()
                .as_ref()
                .and_then(|state| state.last_successful.clone()),
        };
        let state = MonitorState {
            latest_attempt,
            last_successful,
        };
        self.state.send_replace(Some(state.clone()));
        state
    }

    pub async fn poll_once(&self) -> Result<MonitorState, RuntimeError> {
        Ok(self.poll_once_at(unix_millis()?).await)
    }

    pub async fn run(&self, shutdown: CancellationToken) -> Result<(), RuntimeError> {
        let mut ticker = interval(self.poll_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return Ok(()),
                _ = ticker.tick() => {
                    self.poll_once().await?;
                }
            }
        }
    }
}
