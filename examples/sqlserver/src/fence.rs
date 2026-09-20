use std::collections::BTreeSet;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::instance::unix_millis;
use crate::runtime_error::RuntimeError;
use crate::{ObservationFailureKind, OpaqueId, ReplicaIdentity};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RemovedIncarnation {
    pub source: ReplicaIdentity,
    pub engine_id: String,
    pub container_id: String,
    pub removed_at_unix_millis: u64,
}

/// A privileged infrastructure primitive. The HA controller authenticates the
/// operation before calling it; a stopped process alone is never sufficient.
#[async_trait]
pub trait FenceProvider: Send + Sync {
    async fn remove(&self, source: &ReplicaIdentity) -> Result<RemovedIncarnation, RuntimeError>;
    async fn verify(&self, receipt: &RemovedIncarnation) -> Result<(), RuntimeError>;
}

#[async_trait]
pub trait DockerCommands: Send + Sync {
    async fn run(&self, context: &str, arguments: &[String]) -> Result<Vec<u8>, RuntimeError>;
}

pub struct DockerCli;

#[async_trait]
impl DockerCommands for DockerCli {
    async fn run(&self, context: &str, arguments: &[String]) -> Result<Vec<u8>, RuntimeError> {
        let mut child = Command::new("docker")
            .arg("--context")
            .arg(context)
            .args(arguments)
            .env_remove("DOCKER_HOST")
            .env_remove("DOCKER_CONTEXT")
            .env_remove("DOCKER_TLS_VERIFY")
            .env_remove("DOCKER_CERT_PATH")
            .env_remove("DOCKER_API_VERSION")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| {
                error(
                    ObservationFailureKind::Unreachable,
                    "cannot start Docker command",
                )
            })?;
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut bytes = Vec::new();
            let stdout = child.stdout.take().ok_or_else(|| {
                error(
                    ObservationFailureKind::Malformed,
                    "missing Docker output stream",
                )
            })?;
            stdout
                .take(65_537)
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| {
                    error(
                        ObservationFailureKind::Unreachable,
                        "cannot read Docker response",
                    )
                })?;
            if bytes.len() > 65_536 {
                return Err(error(
                    ObservationFailureKind::Malformed,
                    "Docker response exceeds the size limit",
                ));
            }
            let status = child.wait().await.map_err(|_| {
                error(
                    ObservationFailureKind::Unreachable,
                    "cannot wait for Docker command",
                )
            })?;
            if !status.success() {
                return Err(error(
                    ObservationFailureKind::Unreachable,
                    "Docker command failed; absence is unproven",
                ));
            }
            Ok(bytes)
        })
        .await
        .map_err(|_| {
            error(
                ObservationFailureKind::TimedOut,
                "Docker command deadline exceeded",
            )
        })?
    }
}

pub struct DockerFenceProvider<C = DockerCli> {
    commands: C,
    context: String,
    engine_id: String,
    owner_id: String,
    registered: Vec<ReplicaIdentity>,
}

impl DockerFenceProvider<DockerCli> {
    pub fn new(
        context: String,
        engine_id: String,
        owner_id: String,
        registered: Vec<ReplicaIdentity>,
    ) -> Result<Self, RuntimeError> {
        Self::with_commands(DockerCli, context, engine_id, owner_id, registered)
    }
}

impl<C: DockerCommands> DockerFenceProvider<C> {
    pub fn with_commands(
        commands: C,
        context: String,
        engine_id: String,
        owner_id: String,
        registered: Vec<ReplicaIdentity>,
    ) -> Result<Self, RuntimeError> {
        for value in [&context, &engine_id, &owner_id] {
            OpaqueId::new("Docker fence identity", value.as_str()).map_err(|_| {
                error(
                    ObservationFailureKind::Malformed,
                    "invalid Docker fencing configuration",
                )
            })?;
        }
        let mut ids = BTreeSet::new();
        let mut logical = BTreeSet::new();
        if registered.len() != 3
            || registered.iter().any(|replica| {
                !container_id(replica.incarnation())
                    || !ids.insert(replica.incarnation())
                    || !logical.insert(replica.logical_id())
            })
        {
            return Err(error(
                ObservationFailureKind::Malformed,
                "three unique immutable Docker incarnations are required",
            ));
        }
        Ok(Self {
            commands,
            context,
            engine_id,
            owner_id,
            registered,
        })
    }

    fn check_source(&self, source: &ReplicaIdentity) -> Result<(), RuntimeError> {
        if source.native_replica_id().is_none()
            || !self.registered.iter().any(|replica| {
                replica.logical_id() == source.logical_id()
                    && replica.incarnation() == source.incarnation()
                    && replica
                        .native_replica_id()
                        .is_none_or(|id| source.native_replica_id() == Some(id))
            })
        {
            return Err(error(
                ObservationFailureKind::Inconsistent,
                "fence target is not the registered exact incarnation",
            ));
        }
        Ok(())
    }

    async fn engine(&self) -> Result<(), RuntimeError> {
        let bytes = self
            .commands
            .run(&self.context, &args(&["info", "--format", "{{json .ID}}"]))
            .await?;
        let engine: String = serde_json::from_slice(&bytes).map_err(|_| {
            error(
                ObservationFailureKind::Malformed,
                "invalid Docker daemon identity",
            )
        })?;
        if engine != self.engine_id {
            return Err(error(
                ObservationFailureKind::Inconsistent,
                "Docker daemon identity changed",
            ));
        }
        Ok(())
    }

    async fn absent(&self, id: &str) -> Result<bool, RuntimeError> {
        let output = self
            .commands
            .run(
                &self.context,
                &args(&[
                    "container",
                    "ls",
                    "--all",
                    "--no-trunc",
                    "--format",
                    "{{json .ID}}",
                ]),
            )
            .await?;
        let text = std::str::from_utf8(&output).map_err(|_| {
            error(
                ObservationFailureKind::Malformed,
                "invalid Docker inventory encoding",
            )
        })?;
        let mut seen = BTreeSet::new();
        for line in text.lines() {
            let value: String = serde_json::from_str(line).map_err(|_| {
                error(
                    ObservationFailureKind::Malformed,
                    "invalid Docker inventory record",
                )
            })?;
            if !container_id(&value) || !seen.insert(value) {
                return Err(error(
                    ObservationFailureKind::Malformed,
                    "invalid or duplicate container identity",
                ));
            }
        }
        Ok(!seen.contains(id))
    }

    async fn inspect_owner(&self, source: &ReplicaIdentity) -> Result<(), RuntimeError> {
        // Project only ownership fields, never Config.Env or credential values.
        let format = r#"{"id":{{json .Id}},"owner":{{json (index .Config.Labels "io.kuberic.sqlserver.lab")}},"replica":{{json (index .Config.Labels "io.kuberic.sqlserver.replica")}}}"#;
        let output = self
            .commands
            .run(
                &self.context,
                &args(&[
                    "container",
                    "inspect",
                    "--format",
                    format,
                    source.incarnation(),
                ]),
            )
            .await?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Owner {
            id: String,
            owner: String,
            replica: String,
        }
        let owner: Owner = serde_json::from_slice(&output).map_err(|_| {
            error(
                ObservationFailureKind::Malformed,
                "invalid Docker ownership response",
            )
        })?;
        if owner.id != source.incarnation()
            || owner.owner != self.owner_id
            || owner.replica != source.logical_id()
        {
            return Err(error(
                ObservationFailureKind::Inconsistent,
                "container ownership or incarnation does not match",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl<C: DockerCommands> FenceProvider for DockerFenceProvider<C> {
    async fn remove(&self, source: &ReplicaIdentity) -> Result<RemovedIncarnation, RuntimeError> {
        self.check_source(source)?;
        self.engine().await?;
        if !self.absent(source.incarnation()).await? {
            self.inspect_owner(source).await?;
            self.commands
                .run(
                    &self.context,
                    &args(&["container", "update", "--restart=no", source.incarnation()]),
                )
                .await?;
            self.commands
                .run(
                    &self.context,
                    &args(&["container", "stop", "--time", "10", source.incarnation()]),
                )
                .await?;
            self.inspect_owner(source).await?;
            // No --volumes: retain all database storage. Removing the exact
            // immutable ID, unlike stop/readiness, prevents restarting it.
            self.commands
                .run(
                    &self.context,
                    &args(&["container", "rm", source.incarnation()]),
                )
                .await?;
        }
        let receipt = RemovedIncarnation {
            source: source.clone(),
            engine_id: self.engine_id.clone(),
            container_id: source.incarnation().to_owned(),
            removed_at_unix_millis: unix_millis()?,
        };
        self.verify(&receipt).await?;
        Ok(receipt)
    }

    async fn verify(&self, receipt: &RemovedIncarnation) -> Result<(), RuntimeError> {
        self.check_source(&receipt.source)?;
        if receipt.engine_id != self.engine_id
            || receipt.container_id != receipt.source.incarnation()
            || receipt.removed_at_unix_millis > unix_millis()?
        {
            return Err(error(
                ObservationFailureKind::Inconsistent,
                "fence receipt identifies another incarnation or daemon",
            ));
        }
        self.engine().await?;
        if !self.absent(&receipt.container_id).await? {
            return Err(error(
                ObservationFailureKind::Inconsistent,
                "fenced container still exists and could restart",
            ));
        }
        Ok(())
    }
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn container_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn error(kind: ObservationFailureKind, message: &'static str) -> RuntimeError {
    RuntimeError::new(kind, "infrastructure fence", message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Guid;
    use std::sync::Mutex;

    struct Model {
        present: bool,
        wrong_owner: bool,
        fail_inventory: bool,
        calls: Vec<Vec<String>>,
    }
    struct Fake(Mutex<Model>);

    #[async_trait]
    impl DockerCommands for Fake {
        async fn run(&self, _: &str, arguments: &[String]) -> Result<Vec<u8>, RuntimeError> {
            let mut model = self.0.lock().unwrap();
            model.calls.push(arguments.to_vec());
            let id = "a".repeat(64);
            match arguments.get(1).map(String::as_str) {
                Some("--format") => Ok(br#""engine-1""#.to_vec()),
                Some("ls") if model.fail_inventory => Err(error(ObservationFailureKind::Unreachable, "inventory unavailable")),
                Some("ls") => Ok(if model.present { serde_json::to_vec(&id).unwrap() } else { Vec::new() }),
                Some("inspect") => Ok(serde_json::to_vec(&serde_json::json!({
                    "id": id, "owner": if model.wrong_owner { "foreign" } else { "owner-1" }, "replica": "replica-0"
                })).unwrap()),
                Some("rm") => { model.present = false; Ok(Vec::new()) }
                Some("update" | "stop") => Ok(Vec::new()),
                _ => panic!("unexpected Docker command"),
            }
        }
    }

    fn provider(
        wrong_owner: bool,
        fail_inventory: bool,
    ) -> (DockerFenceProvider<Fake>, ReplicaIdentity) {
        let nodes = ['a', 'b', 'c']
            .iter()
            .enumerate()
            .map(|(index, id)| {
                ReplicaIdentity::desired(format!("replica-{index}"), id.to_string().repeat(64))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let source = ReplicaIdentity::observed(
            "replica-0",
            Guid::parse("replica", "00000001-1111-2222-3333-444444444444").unwrap(),
            "a".repeat(64),
        )
        .unwrap();
        (
            DockerFenceProvider::with_commands(
                Fake(Mutex::new(Model {
                    present: true,
                    wrong_owner,
                    fail_inventory,
                    calls: Vec::new(),
                })),
                "lab".into(),
                "engine-1".into(),
                "owner-1".into(),
                nodes,
            )
            .unwrap(),
            source,
        )
    }

    #[tokio::test]
    async fn removal_is_exact_positive_and_keeps_volumes() {
        let (provider, source) = provider(false, false);
        let receipt = provider.remove(&source).await.unwrap();
        provider.verify(&receipt).await.unwrap();
        let state = provider.commands.0.lock().unwrap();
        assert!(!state.present);
        assert!(
            state
                .calls
                .iter()
                .any(|args| args == &vec!["container".to_owned(), "rm".to_owned(), "a".repeat(64)])
        );
        assert!(
            !state
                .calls
                .iter()
                .flatten()
                .any(|value| value == "--volumes" || value == "--force")
        );
    }

    #[tokio::test]
    async fn foreign_ownership_and_failed_inventory_never_prove_fencing() {
        for (wrong, failed) in [(true, false), (false, true)] {
            let (provider, source) = provider(wrong, failed);
            assert!(provider.remove(&source).await.is_err());
            let state = provider.commands.0.lock().unwrap();
            assert!(!state.calls.iter().any(|args| matches!(
                args.get(1).map(String::as_str),
                Some("stop" | "rm" | "update")
            )));
        }
    }

    #[tokio::test]
    async fn already_stopped_is_not_a_fence_while_the_container_exists() {
        let (provider, source) = provider(false, false);
        let receipt = RemovedIncarnation {
            source: source.clone(),
            engine_id: "engine-1".into(),
            container_id: source.incarnation().into(),
            removed_at_unix_millis: unix_millis().unwrap(),
        };
        assert!(provider.verify(&receipt).await.is_err());
    }
}
