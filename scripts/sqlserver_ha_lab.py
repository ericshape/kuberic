#!/usr/bin/env python3
"""Explicitly owned, disposable SQL Server laboratory; never an HA controller."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from urllib.parse import urlsplit
import uuid


REPOSITORY = Path(__file__).resolve().parent.parent
OWNER_LABEL = "io.kuberic.sqlserver.lab"
REPLICA_LABEL = "io.kuberic.sqlserver.replica"
TOKEN_LABEL = "io.kuberic.sqlserver.lab.resource"
ROLE_LABEL = "io.kuberic.sqlserver.role"
SQLCMD = "/opt/mssql-tools18/bin/sqlcmd"
PURPOSES = ("authority", "approval", "fence", "lease")
IMAGE_PATTERN = re.compile(
    r"mcr\.microsoft\.com/mssql/server"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[0-9a-f]{64}"
)
ID_PATTERN = re.compile(r"[0-9a-f]{64}")
CONTEXT_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
SQL_NAME_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,47}")
DOCKER_OVERRIDES = (
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
    "DOCKER_API_VERSION",
    "SQLCMDPASSWORD",
)
STAGES = (
    "initialized", "credentials", "image", "network", "volumes",
    "containers", "principals", "endpoints", "database", "configurations",
    "bootstrap", "ready", "destroy",
)
STATES = (
    "provisioning", "ready", "failed", "destroying", "destroy_failed",
    "destroyed", "destroyed_data_retained",
)
CONTAINER_FORMAT = (
    '{"id":{{json .Id}},"name":{{json .Name}},'
    '"labels":{{json .Config.Labels}},"image":{{json .Config.Image}},'
    '"image_id":{{json .Image}},"hostname":{{json .Config.Hostname}},'
    '"user":{{json .Config.User}},"mounts":{{json .Mounts}},'
    '"network_mode":{{json .HostConfig.NetworkMode}},'
    '"networks":{{json .NetworkSettings.Networks}},'
    '"ports":{{json .HostConfig.PortBindings}},'
    '"restart":{{json .HostConfig.RestartPolicy.Name}},'
    '"privileged":{{json .HostConfig.Privileged}},'
    '"state":{{json .State.Status}}}'
)
NETWORK_FORMAT = (
    '{"id":{{json .Id}},"name":{{json .Name}},"labels":{{json .Labels}},'
    '"driver":{{json .Driver}},"internal":{{json .Internal}},'
    '"containers":{{json .Containers}}}'
)
VOLUME_FORMAT = (
    '{"name":{{json .Name}},"labels":{{json .Labels}},'
    '"created_at":{{json .CreatedAt}},"driver":{{json .Driver}},'
    '"scope":{{json .Scope}},"options":{{json .Options}}}'
)


class LabError(Exception):
    """A diagnostic that is safe to display without command output."""


class CommandError(LabError):
    def __init__(self, operation: str, reason: str):
        self.operation = operation
        super().__init__(f"{operation}: {reason}; raw command output is suppressed")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LabError(message)


def environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ)
    for key in DOCKER_OVERRIDES:
        env.pop(key, None)
    env.update(extra or {})
    return env


class Executor:
    def __init__(self) -> None:
        self.programs: dict[str, str] = {}

    def program(self, name: str) -> str:
        if name not in self.programs:
            path = shutil.which(name)
            require(path is not None, f"Required executable is unavailable: {name}")
            self.programs[name] = path
        return self.programs[name]

    def run(
        self, argv: list[str], *, operation: str, data: bytes | None = None,
        env: dict[str, str] | None = None, timeout: float = 30,
    ) -> bytes:
        try:
            result = subprocess.run(
                argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL if data is None else None,
                env=env if env is not None else environment(), timeout=timeout,
                check=False, umask=0o077,
            )
        except subprocess.TimeoutExpired:
            raise CommandError(operation, "deadline exceeded") from None
        except OSError:
            raise CommandError(operation, "could not execute the required program") from None
        if result.returncode:
            raise CommandError(operation, f"command exited with status {result.returncode}")
        require(len(result.stdout) <= 4 * 1024 * 1024, f"{operation}: output exceeds the safety limit")
        return result.stdout


def json_object(data: bytes) -> dict:
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError):
        raise LabError("Invalid JSON response; raw content is suppressed") from None
    require(isinstance(value, dict), "Expected a JSON object")
    return value


def private_stat(path: Path, *, directory: bool = False) -> os.stat_result:
    info = path.lstat()
    predicate = stat.S_ISDIR if directory else stat.S_ISREG
    require(predicate(info.st_mode), "Expected a real directory or regular file, not a symlink")
    require(info.st_uid == os.geteuid(), "Laboratory files must belong to the current user")
    require(
        stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600),
        "Laboratory directories must be 0700 and private files must be 0600",
    )
    if not directory:
        require(info.st_nlink == 1, "Hard-linked laboratory files are not allowed")
    return info


def read_private(path: Path, limit: int = 131072) -> bytes:
    original = private_stat(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600
                and (info.st_dev, info.st_ino) == (original.st_dev, original.st_ino),
                "Private file identity or permissions changed")
        data = stream.read(limit + 1)
    require(len(data) <= limit, "Private file exceeds the safety limit")
    return data


def private_text(path: Path) -> str:
    try:
        value = read_private(path, 4096).decode("ascii")
    except UnicodeError:
        raise LabError("Private credential file is not ASCII; contents are suppressed") from None
    require(bool(value) and not any(character in value for character in "\x00\r\n"),
            "Private credential file must be nonempty without NUL or line endings")
    return value


def write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def validate_directory(value: str, *, new: bool) -> Path:
    path = Path(value)
    require(path.is_absolute() and str(path) == value, "Use a normalized absolute directory path")
    require(".." not in path.parts, "Parent-directory traversal is not allowed")
    home = Path.home().resolve()
    require(path != home and path != Path("/"), "Root and home directories are not laboratories")
    require(
        path != REPOSITORY and path not in REPOSITORY.parents
        and REPOSITORY not in path.parents,
        "Use a directory outside the repository and outside its ancestors",
    )
    for parent in reversed(path.parents):
        require(stat.S_ISDIR(parent.lstat().st_mode), "Directory ancestors must not be symlinks")
    if new:
        require(not os.path.lexists(path), "The laboratory directory must not already exist")
    else:
        private_stat(path, directory=True)
    return path


@contextlib.contextmanager
def directory_lock(directory: Path):
    path = directory / "lab.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        private_stat(path)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise LabError("Another process is using this laboratory") from None
        yield
    finally:
        os.close(fd)


def save_manifest(directory: Path, manifest: dict) -> None:
    pending = directory / "ha-lab.json.next"
    if os.path.lexists(pending):
        private_stat(pending)
        pending.unlink()
    destination = directory / "ha-lab.json"
    if os.path.lexists(destination):
        private_stat(destination)
    write_private(pending, (json.dumps(manifest, indent=2) + "\n").encode())
    os.replace(pending, destination)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def canonical_uuid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(uuid.UUID(value)) == value and uuid.UUID(value).version == 4
    except ValueError:
        return False


def native_guid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
        return str(parsed) == value and parsed.int != 0
    except ValueError:
        return False


def validate_image(value: object) -> None:
    require(
        isinstance(value, str) and IMAGE_PATTERN.fullmatch(value) is not None,
        "Supply mcr.microsoft.com/mssql/server[:tag]@sha256:<64 lowercase hex digits>",
    )


def validate_context(value: object) -> None:
    require(
        isinstance(value, str) and value != "default"
        and CONTEXT_PATTERN.fullmatch(value) is not None,
        "An explicit named Docker context other than 'default' is required",
    )


def validate_sql_names(database: object, group: object) -> None:
    for value in (database, group):
        require(
            isinstance(value, str) and SQL_NAME_PATTERN.fullmatch(value) is not None,
            "SQL names must start with a letter and contain at most 48 letters, digits or underscores",
        )
    require(
        database.lower() not in {"master", "model", "msdb", "tempdb", "distribution"},
        "A system database cannot be used as the laboratory database",
    )


class Docker:
    def __init__(self, executor: Executor, context: str, binding: dict | None = None):
        validate_context(context)
        self.executor = executor
        self.context = context
        self.binding = binding
        self.executable = executor.program("docker")
        self.deadline_at: float | None = None

    def raw(self, args: list[str], **kwargs) -> bytes:
        kwargs.setdefault("operation", "docker")
        kwargs.setdefault("env", environment())
        if self.deadline_at is not None:
            remaining = self.deadline_at - time.monotonic()
            require(remaining > 0, "SQL service/seeding readiness deadline exceeded")
            kwargs["timeout"] = min(kwargs.get("timeout", 30), remaining)
        return self.executor.run([self.executable, "--context", self.context, *args], **kwargs)

    @contextlib.contextmanager
    def bounded(self, deadline: float):
        previous = self.deadline_at
        self.deadline_at = min(deadline, previous) if previous is not None else deadline
        try:
            yield
        finally:
            self.deadline_at = previous

    def identity(self) -> dict:
        context = json_object(self.raw([
            "context", "inspect", self.context, "--format",
            '{"name":{{json .Name}},"endpoint":{{json .Endpoints.docker.Host}}}',
        ]))
        require(context.get("name") == self.context, "Docker context identity changed")
        endpoint = context.get("endpoint")
        require(isinstance(endpoint, str), "Docker context has no endpoint")
        parsed = urlsplit(endpoint)
        require(
            parsed.scheme == "unix" and not parsed.netloc and parsed.path.startswith("/")
            and not parsed.query and not parsed.fragment,
            "Only a local Unix-socket Docker context is supported; remote/shared hosts are refused",
        )
        info = json_object(self.raw([
            "info", "--format",
            '{"id":{{json .ID}},"os":{{json .OSType}},"architecture":{{json .Architecture}}}',
        ]))
        require(
            info.get("os") == "linux" and info.get("architecture") in ("x86_64", "amd64"),
            "A native Linux x86_64/amd64 Docker daemon is required; emulation is not supported",
        )
        engine = info.get("id")
        require(
            isinstance(engine, str) and re.fullmatch(r"[A-Za-z0-9:_.-]{1,256}", engine) is not None,
            "Docker returned an invalid daemon ID",
        )
        result = {"engine_id": engine, "docker_endpoint": endpoint}
        if self.binding is not None:
            require(
                all(result[key] == self.binding[key] for key in result),
                "Docker daemon ID or context endpoint changed; no resource operation is authorized",
            )
        return result

    def run(self, args: list[str], **kwargs) -> bytes:
        self.identity()
        return self.raw(args, **kwargs)

    def inventory(self, kind: str) -> list[dict]:
        if kind == "container":
            args = ["container", "ls", "--all", "--no-trunc", "--format",
                    '{"id":{{json .ID}},"name":{{json .Names}}}']
        elif kind == "network":
            args = ["network", "ls", "--no-trunc", "--format",
                    '{"id":{{json .ID}},"name":{{json .Name}}}']
        else:
            args = ["volume", "ls", "--format", '{"name":{{json .Name}}}']
        rows = [json_object(line) for line in self.run(args).splitlines() if line.strip()]
        for row in rows:
            require(isinstance(row.get("name"), str) and bool(row["name"]), "Invalid Docker inventory name")
            if kind != "volume":
                require(
                    isinstance(row.get("id"), str) and ID_PATTERN.fullmatch(row["id"]) is not None,
                    "Docker inventory did not return full immutable IDs",
                )
        return rows

    def lookup(self, kind: str, name: str, identity: str = "") -> dict | None:
        # Absence comes only from a successful complete inventory, never an inspect error.
        rows = self.inventory(kind)
        matches = [row for row in rows if row["name"] == name or (identity and row.get("id") == identity)]
        if not matches:
            return None
        require(len(matches) == 1, "Ambiguous resource identity in Docker inventory")
        row = matches[0]
        require(
            row["name"] == name and (not identity or row.get("id") == identity),
            "A managed resource name or immutable ID was replaced/reused",
        )
        template = {"container": CONTAINER_FORMAT, "network": NETWORK_FORMAT, "volume": VOLUME_FORMAT}[kind]
        result = json_object(self.run([kind, "inspect", row.get("id", name), "--format", template]))
        expected_name = f"/{name}" if kind == "container" else name
        require(result.get("name") == expected_name, "Inspected resource name changed")
        if kind != "volume":
            require(result.get("id") == row["id"], "Inspected immutable resource ID changed")
        return result


def initial_manifest(
    directory: Path, args: argparse.Namespace, binding: dict, *, owner: str | None = None,
) -> dict:
    owner = owner or str(uuid.uuid4())
    prefix = "kuberic-sql-" + uuid.UUID(owner).hex
    nodes, volumes, helpers = [], [], []
    for index in range(3):
        replica = f"replica-{index}"
        hostname = f"{prefix}-{index}"
        nodes.append({
            "logical_id": replica, "container_id": "", "container_name": hostname,
            "native_replica_id": "",
            "hostname": hostname, "resource_token": str(uuid.uuid4()),
            "port": args.first_port + index,
            "observer_config": str(directory / f"{replica}.observer.json"),
            "replication_host": hostname, "replication_port": 5022,
            "mutation_username_file": str(directory / f"{replica}.mutation.username"),
            "mutation_password_file": str(directory / f"{replica}.mutation.password"),
        })
        volumes.append({
            "name": f"{prefix}-data-{index}", "replica_id": replica,
            "resource_token": str(uuid.uuid4()), "created_at": "",
        })
        helpers.append({
            "logical_id": replica, "container_name": f"{prefix}-init-{index}",
            "container_id": "", "resource_token": str(uuid.uuid4()),
        })
    return {
        "version": 1, "owner_id": owner, "directory": str(directory),
        "docker_context": args.docker_context, **binding,
        "image": args.image, "image_id": "",
        "resource_id": f"sqlserver-lab:{owner}", "configuration_id": f"initial:{owner}",
        "epoch": 1, "primary_replica_id": "replica-0",
        "database_name": args.database_name, "availability_group": args.availability_group,
        "native_group_id": "",
        "journal_path": str(directory / "journal.sqlite"),
        "issuer_keys": {purpose: str(directory / f"issuer-{purpose}.seed") for purpose in PURPOSES},
        "nodes": nodes,
        "network": {"id": "", "name": f"{prefix}-net", "resource_token": str(uuid.uuid4())},
        "volumes": volumes, "helpers": helpers,
        "state": "provisioning", "stage": "initialized",
        "bootstrap_ag": args.bootstrap_ag, "write_lease_seconds": args.write_lease_seconds,
        "ready_timeout": args.ready_timeout,
    }


def load_manifest(directory: Path) -> dict:
    manifest = json_object(read_private(directory / "ha-lab.json"))
    owner = manifest.get("owner_id")
    require(canonical_uuid(owner), "Invalid manifest owner UUID")
    require(read_private(directory / "owner-id") == owner.encode(), "Manifest ownership marker mismatch")
    require(manifest.get("directory") == str(directory), "Manifest belongs to another directory")
    validate_context(manifest.get("docker_context"))
    validate_image(manifest.get("image"))
    validate_sql_names(manifest.get("database_name"), manifest.get("availability_group"))
    require(
        type(manifest.get("version")) is int and manifest["version"] == 1
        and type(manifest.get("epoch")) is int and manifest["epoch"] == 1,
        "Unsupported laboratory manifest version or epoch",
    )
    nodes = manifest.get("nodes")
    require(isinstance(nodes, list) and len(nodes) == 3, "Manifest must contain exactly three nodes")
    require(all(isinstance(node, dict) for node in nodes), "Invalid node records")
    legacy = "native_group_id" not in manifest and all("native_replica_id" not in node for node in nodes)
    if legacy:
        # Older receipts still authorize exact Docker cleanup, never native SQL adoption.
        manifest["native_group_id"] = ""
        for node in nodes:
            node["native_replica_id"] = ""
    port = nodes[0].get("port")
    require(type(port) is int and 1024 <= port <= 65533, "Invalid published port range")
    require(type(manifest.get("bootstrap_ag")) is bool, "Invalid bootstrap setting")
    require(type(manifest.get("write_lease_seconds")) is int and manifest["write_lease_seconds"] in (30, 60),
            "Invalid native write lease duration")
    require(type(manifest.get("ready_timeout")) is int and 30 <= manifest["ready_timeout"] <= 600,
            "Invalid readiness deadline")
    args = argparse.Namespace(
        docker_context=manifest["docker_context"], image=manifest["image"],
        first_port=port, database_name=manifest["database_name"],
        availability_group=manifest["availability_group"], bootstrap_ag=manifest["bootstrap_ag"],
        write_lease_seconds=manifest["write_lease_seconds"], ready_timeout=manifest["ready_timeout"],
    )
    expected = initial_manifest(directory, args, {
        "engine_id": manifest.get("engine_id"), "docker_endpoint": manifest.get("docker_endpoint"),
    }, owner=owner)
    require(set(manifest) == set(expected), "Unexpected or missing manifest fields")
    for key in ("resource_id", "configuration_id", "primary_replica_id", "journal_path", "issuer_keys"):
        require(manifest[key] == expected[key], "Manifest identity or private file references changed")
    require(isinstance(manifest["engine_id"], str) and bool(manifest["engine_id"]), "Missing daemon identity")
    require(isinstance(manifest["docker_endpoint"], str), "Missing Docker endpoint")
    require(manifest["state"] in STATES and manifest["stage"] in STAGES, "Invalid provisioning state")
    require(
        manifest["image_id"] == "" or (
            isinstance(manifest["image_id"], str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", manifest["image_id"]) is not None
        ), "Invalid pinned image identity",
    )
    require(manifest["native_group_id"] == "" or native_guid(manifest["native_group_id"]),
            "Invalid native availability group identity")
    ids, tokens, replica_ids = set(), set(), set()
    for collection in ("nodes", "helpers", "volumes"):
        actual = manifest[collection]
        require(isinstance(actual, list) and len(actual) == 3, "Invalid resource collection")
        for item, pattern in zip(actual, expected[collection]):
            require(isinstance(item, dict) and set(item) == set(pattern), "Invalid resource record")
            mutable = {"container_id", "resource_token", "created_at", "native_replica_id"}
            require(all(item[key] == value for key, value in pattern.items() if key not in mutable),
                    "Generated resource name or file reference changed")
            validate_token(item["resource_token"], tokens)
            if "container_id" in item:
                validate_id(item["container_id"], ids)
            else:
                require(isinstance(item["created_at"], str) and len(item["created_at"]) <= 128,
                        "Invalid volume creation identity")
            if collection == "nodes":
                native_id = item["native_replica_id"]
                require(native_id == "" or native_guid(native_id), "Invalid native replica identity")
                if native_id:
                    require(native_id not in replica_ids, "Duplicate native replica identity")
                    replica_ids.add(native_id)
    network = manifest["network"]
    require(isinstance(network, dict) and set(network) == set(expected["network"])
            and network["name"] == expected["network"]["name"], "Invalid network identity")
    validate_token(network["resource_token"], tokens)
    validate_id(network["id"], ids)
    if manifest["state"] == "ready":
        require(all(node["container_id"] for node in nodes) and network["id"] and manifest["image_id"],
                "Ready manifest is missing immutable identities")
        if not legacy:
            require(manifest["bootstrap_ag"] and native_guid(manifest["native_group_id"])
                    and len(replica_ids) == 3, "Ready manifest is missing its bootstrapped native topology")
    return manifest


def validate_id(value: object, seen: set) -> None:
    require(isinstance(value, str) and (value == "" or ID_PATTERN.fullmatch(value) is not None),
            "Expected a full immutable resource ID")
    if value:
        require(value not in seen, "Duplicate immutable resource ID")
        seen.add(value)


def validate_token(value: object, seen: set) -> None:
    require(canonical_uuid(value) and value not in seen, "Invalid or reused resource ownership token")
    seen.add(value)


def sql_literal(value: str) -> str:
    return "N'" + value.replace("'", "''") + "'"


def sql_identifier(value: str) -> str:
    return "[" + value.replace("]", "]]") + "]"


def password() -> str:
    return "Aa1!" + secrets.token_urlsafe(36)


def tar_bytes(files: dict[str, bytes], *, uid: int = 10001, mode: int = 0o600,
              directories: tuple[str, ...] = ()) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name in directories:
            entry = tarfile.TarInfo(name)
            entry.type, entry.mode, entry.uid, entry.gid = tarfile.DIRTYPE, 0o700, uid, 0
            archive.addfile(entry)
        for name, contents in files.items():
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.uid, entry.gid = len(contents), mode, uid, 0
            archive.addfile(entry, io.BytesIO(contents))
    return output.getvalue()


class Laboratory:
    def __init__(self, directory: Path, manifest: dict, executor: Executor):
        self.directory, self.manifest, self.executor = directory, manifest, executor
        self.docker = Docker(executor, manifest["docker_context"], manifest)
        self.setup_deadline: float | None = None
        self.setup_lease_started: float | None = None

    def save(self) -> None:
        save_manifest(self.directory, self.manifest)

    def stage(self, stage: str) -> None:
        self.manifest["stage"] = stage
        self.save()

    def labels(self, item: dict, role: str, replica: str | None = None) -> dict[str, str]:
        result = {
            OWNER_LABEL: self.manifest["owner_id"], TOKEN_LABEL: item["resource_token"],
            ROLE_LABEL: role,
        }
        if replica:
            result[REPLICA_LABEL] = replica
        return result

    def label_args(self, item: dict, role: str, replica: str | None = None) -> list[str]:
        return [part for key, value in self.labels(item, role, replica).items()
                for part in ("--label", f"{key}={value}")]

    def check_labels(self, info: dict, item: dict, role: str, replica: str | None = None) -> None:
        labels = info.get("labels")
        require(isinstance(labels, dict) and all(
            labels.get(key) == value for key, value in self.labels(item, role, replica).items()
        ), "Resource ownership labels do not match this laboratory")

    def network(self) -> dict | None:
        item = self.manifest["network"]
        info = self.docker.lookup("network", item["name"], item["id"])
        if info is not None:
            self.check_labels(info, item, "network")
            require(info.get("driver") == "bridge" and info.get("internal") is True,
                    "Managed network is not the private internal bridge")
            require(isinstance(info.get("containers"), (dict, type(None))), "Invalid network attachments")
            item["id"] = info["id"]
        return info

    def volume(self, item: dict) -> dict | None:
        info = self.docker.lookup("volume", item["name"])
        if info is not None:
            self.check_labels(info, item, "data", item["replica_id"])
            require(info.get("driver") == "local" and info.get("scope") == "local"
                    and info.get("options") in (None, {}), "Shared or externally configured volumes are refused")
            created = info.get("created_at")
            require(isinstance(created, str) and 0 < len(created) <= 128, "Volume has no creation identity")
            require(not item["created_at"] or item["created_at"] == created,
                    "A named volume was replaced/reused")
            item["created_at"] = created
        return info

    def container(self, item: dict, *, helper: bool = False) -> dict | None:
        info = self.docker.lookup("container", item["container_name"], item["container_id"])
        if info is None:
            return None
        self.check_labels(info, item, "volume-init" if helper else "sqlserver", item["logical_id"])
        require(info.get("image") == self.manifest["image"]
                and bool(self.manifest["image_id"]) and info.get("image_id") == self.manifest["image_id"],
                "Managed container no longer matches the pinned image")
        require(info.get("hostname") == item["container_name"]
                and info.get("user") == ("0:0" if helper else "10001:0")
                and info.get("privileged") is False, "Container isolation identity changed")
        require(info.get("restart") == "no", "Unexpected automatic container restart policy")
        index = int(item["logical_id"][-1])
        mounts = info.get("mounts")
        require(isinstance(mounts, list) and len(mounts) == 1, "Unexpected container mounts")
        mount = mounts[0]
        require(isinstance(mount, dict) and mount.get("Type") == "volume"
                and mount.get("Name") == self.manifest["volumes"][index]["name"]
                and mount.get("Destination") == "/var/opt/mssql" and mount.get("RW") is True,
                "A container uses unowned or shared storage")
        network_id = self.manifest["network"]["id"]
        expected_networks = {"none"} if helper else {network_id, self.manifest["network"]["name"]}
        require((helper or bool(network_id)) and info.get("network_mode") in expected_networks,
                "Container network identity changed")
        networks = info.get("networks") or {}
        allowed = {"none"} if helper else {self.manifest["network"]["name"]}
        require(isinstance(networks, dict) and set(networks).issubset(allowed),
                "Container has an unexpected network attachment")
        if not helper:
            for attachment in networks.values():
                require(isinstance(attachment, dict)
                        and attachment.get("NetworkID", "") in ("", network_id),
                        "Container is attached to a different network incarnation")
            if info.get("state") in {"running", "paused", "restarting"}:
                require(set(networks) == allowed
                        and all(value.get("NetworkID") == network_id for value in networks.values()),
                        "Running SQL container is missing its exact owned network")
        expected_ports = {} if helper else {
            "1433/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(item["port"])}],
        }
        require((info.get("ports") or {}) == expected_ports, "Container published ports changed")
        require(info.get("state") in {"created", "running", "paused", "restarting", "removing", "exited", "dead"},
                "Unknown container process state")
        item["container_id"] = info["id"]
        return info

    def verify_all(self) -> dict:
        network = self.network()
        volumes = [self.volume(item) for item in self.manifest["volumes"]]
        helpers = [self.container(item, helper=True) for item in self.manifest["helpers"]]
        nodes = [self.container(item) for item in self.manifest["nodes"]]
        if network is not None:
            ids = {item["container_id"] for item in self.manifest["nodes"] + self.manifest["helpers"]
                   if item["container_id"]}
            require(set(network["containers"] or {}).issubset(ids),
                    "An unregistered container is attached to the laboratory network")
        return {"network": network, "volumes": volumes, "helpers": helpers, "nodes": nodes}

    def need_container(self, item: dict, *, helper: bool = False) -> None:
        require(self.container(item, helper=helper) is not None, "Required owned container is absent")

    def exec_file(self, item: dict, args: list[str], *, helper: bool = False, **kwargs) -> bytes:
        self.need_container(item, helper=helper)
        return self.docker.run(["exec", "--user", "0:0", item["container_id"], *args], **kwargs)

    def copy_files(self, item: dict, target: str, files: dict[str, bytes], *,
                   helper: bool = False, uid: int = 10001, mode: int = 0o600,
                   directories: tuple[str, ...] = ()) -> None:
        self.need_container(item, helper=helper)
        self.docker.run(
            ["cp", "--archive", "-", f"{item['container_id']}:{target}"],
            data=tar_bytes(files, uid=uid, mode=mode, directories=directories),
        )

    def openssl(self, args: list[str]) -> None:
        self.executor.run([self.executor.program("openssl"), *args], operation="openssl", timeout=120)

    def credentials(self) -> None:
        seen = set()
        for purpose in PURPOSES:
            seed = secrets.token_bytes(32)
            require(seed not in seen, "Entropy source repeated an issuer seed")
            seen.add(seed)
            write_private(Path(self.manifest["issuer_keys"][purpose]), seed)
        write_private(self.directory / "endpoint-backup.password", password().encode())
        for node in self.manifest["nodes"]:
            replica = node["logical_id"]
            for role in ("sa", "observer", "mutation", "master", "endpoint"):
                write_private(self.directory / f"{replica}.{role}.password", password().encode())
            for role, username in (("observer", "kuberic_observer"), ("mutation", "kuberic_mutator")):
                write_private(self.directory / f"{replica}.{role}.username", username.encode())
            sa = self.secret(node, "sa")
            write_private(self.directory / f"{replica}.sa.env", (
                "ACCEPT_EULA=Y\nMSSQL_PID=Developer\nMSSQL_ENABLE_HADR=1\n"
                f"MSSQL_SA_PASSWORD={sa}\nMSSQL_MEMORY_LIMIT_MB=2048\n"
            ).encode())
        ca_key, ca_cert = self.directory / "ca.key", self.directory / "ca.crt"
        self.openssl([
            "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256", "-days", "31",
            "-subj", f"/CN=Kuberic SQL laboratory {self.manifest['owner_id']}",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", str(ca_key), "-out", str(ca_cert),
        ])
        for node in self.manifest["nodes"]:
            replica = node["logical_id"]
            key, csr, cert, ext = (self.directory / f"{replica}.tls.{suffix}"
                                   for suffix in ("key", "csr", "crt", "ext"))
            write_private(ext, (
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\n"
                f"subjectAltName=DNS:{node['hostname']},IP:127.0.0.1\n"
            ).encode())
            self.openssl([
                "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
                "-subj", f"/CN={node['hostname']}", "-keyout", str(key), "-out", str(csr),
            ])
            self.openssl([
                "x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
                "-set_serial", str(secrets.randbits(159) | 1), "-days", "30", "-sha256",
                "-extfile", str(ext), "-out", str(cert),
            ])
            for option, value in (("-verify_hostname", node["hostname"]), ("-verify_ip", "127.0.0.1")):
                self.openssl(["verify", "-CAfile", str(ca_cert), "-purpose", "sslserver",
                              option, value, str(cert)])
            for path in (key, csr, cert):
                private_stat(path)
        private_stat(ca_key)
        private_stat(ca_cert)
        write_private(self.directory / "mssql.conf", (
            "[hadr]\nhadrenabled = 1\n[network]\nforceencryption = 1\n"
            "tlscert = /var/opt/mssql/secrets/tls.crt\n"
            "tlskey = /var/opt/mssql/secrets/tls.key\ntlsprotocols = 1.2\n"
        ).encode())

    def secret(self, node: dict, role: str) -> str:
        return private_text(self.directory / f"{node['logical_id']}.{role}.password")

    def image(self) -> None:
        image = self.manifest["image"]
        self.docker.run(["image", "pull", "--platform", "linux/amd64", image], timeout=600)
        info = json_object(self.docker.run([
            "image", "inspect", image, "--format",
            '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}},'
            '"digests":{{json .RepoDigests}},"volumes":{{json .Config.Volumes}}}',
        ]))
        require(info.get("os") == "linux" and info.get("architecture") == "amd64",
                "The pinned image must be Linux AMD64")
        digest = "mcr.microsoft.com/mssql/server@" + image.split("@")[1]
        require(isinstance(info.get("digests"), list) and digest in info["digests"],
                "Image inspection did not confirm the requested repository digest")
        require(isinstance(info.get("id"), str) and re.fullmatch(r"sha256:[0-9a-f]{64}", info["id"]),
                "Image has no immutable identity")
        declared = info.get("volumes") or {}
        require(isinstance(declared, dict) and set(declared).issubset({"/var/opt/mssql"}),
                "Image would create unmanaged anonymous volumes")
        self.manifest["image_id"] = info["id"]
        self.save()

    def create_network(self) -> None:
        item = self.manifest["network"]
        require(self.docker.lookup("network", item["name"]) is None, "Generated network name already exists")
        output = self.docker.run([
            "network", "create", "--driver", "bridge", "--internal",
            *self.label_args(item, "network"), item["name"],
        ]).strip()
        require(ID_PATTERN.fullmatch(output.decode("ascii", errors="replace")) is not None,
                "Network creation did not acknowledge a full ID; use explicit cleanup")
        item["id"] = output.decode("ascii")
        self.save()
        require(self.network() is not None, "Created network is absent")

    def create_volumes(self) -> None:
        for item in self.manifest["volumes"]:
            require(self.docker.lookup("volume", item["name"]) is None, "Generated volume name already exists")
            output = self.docker.run([
                "volume", "create", "--driver", "local",
                *self.label_args(item, "data", item["replica_id"]), item["name"],
            ]).strip()
            require(output == item["name"].encode(), "Volume creation acknowledgement is inconsistent")
            require(self.volume(item) is not None, "Created volume is absent")
            self.save()

    def create_container(self, item: dict, *, helper: bool) -> None:
        require(self.docker.lookup("container", item["container_name"]) is None,
                "Generated container name already exists")
        index = int(item["logical_id"][-1])
        require(self.volume(self.manifest["volumes"][index]) is not None, "Owned volume is absent")
        args = [
            "container", "create", "--pull", "never", "--platform", "linux/amd64",
            "--name", item["container_name"], "--hostname", item["container_name"],
            "--restart", "no", "--user", "0:0" if helper else "10001:0",
            "--network", "none" if helper else self.manifest["network"]["id"],
            "--mount", f"type=volume,source={self.manifest['volumes'][index]['name']},target=/var/opt/mssql",
            *self.label_args(item, "volume-init" if helper else "sqlserver", item["logical_id"]),
        ]
        if helper:
            args += ["--entrypoint", "/bin/sleep", "--memory", "128m", self.manifest["image"], "600"]
        else:
            args += [
                "--memory", "3g", "--publish", f"127.0.0.1:{item['port']}:1433",
                "--env-file", str(self.directory / f"{item['logical_id']}.sa.env"), self.manifest["image"],
            ]
        output = self.docker.run(args, timeout=120).strip()
        require(ID_PATTERN.fullmatch(output.decode("ascii", errors="replace")) is not None,
                "Container creation did not acknowledge a full ID; use explicit cleanup")
        item["container_id"] = output.decode("ascii")
        self.save()
        self.need_container(item, helper=helper)

    def remove_container(self, item: dict, *, helper: bool = False) -> None:
        info = self.container(item, helper=helper)
        if info is None:
            return
        identity = item["container_id"]
        self.docker.run(["container", "update", "--restart=no", identity])
        if info["state"] == "paused":
            self.docker.run(["container", "unpause", identity])
        if info["state"] not in {"created", "exited", "dead"}:
            self.docker.run(["container", "stop", "--time", "20", identity], timeout=45)
        self.need_container(item, helper=helper)
        self.docker.run(["container", "rm", identity])
        require(self.docker.lookup("container", item["container_name"], identity) is None,
                "Container removal was not positively confirmed")

    def containers(self) -> None:
        for node, helper in zip(self.manifest["nodes"], self.manifest["helpers"]):
            self.create_container(helper, helper=True)
            self.docker.run(["container", "start", helper["container_id"]])
            replica = node["logical_id"]
            self.copy_files(helper, "/var/opt/mssql", {
                "mssql.conf": read_private(self.directory / "mssql.conf"),
                "secrets/tls.key": read_private(self.directory / f"{replica}.tls.key"),
                "secrets/tls.crt": read_private(self.directory / f"{replica}.tls.crt"),
            }, helper=True, directories=("secrets", "backup"))
            self.exec_file(helper, ["/bin/chown", "10001:0", "/var/opt/mssql"], helper=True)
            self.exec_file(helper, ["/bin/chmod", "0700", "/var/opt/mssql"], helper=True)
            permissions = self.exec_file(helper, [
                "/usr/bin/stat", "-c", "%u:%g:%a", "/var/opt/mssql/secrets/tls.key",
                "/var/opt/mssql/secrets",
            ], helper=True)
            require(permissions.splitlines() == [b"10001:0:600", b"10001:0:700"],
                    "TLS private-key ownership or permissions were not established")
            self.remove_container(helper, helper=True)
            self.create_container(node, helper=False)
            self.copy_files(node, "/usr/local/share/ca-certificates", {
                "kuberic-lab.crt": read_private(self.directory / "ca.crt"),
            }, uid=0, mode=0o644)
            self.docker.run(["container", "start", node["container_id"]])
            try:
                self.exec_file(node, ["/usr/bin/test", "-x", SQLCMD], operation="image-tools")
                self.exec_file(node, ["/usr/bin/test", "-x", "/usr/sbin/update-ca-certificates"],
                               operation="image-tools")
            except CommandError as error:
                if error.operation != "image-tools":
                    raise
                raise LabError(f"The pinned image must bundle {SQLCMD} and update-ca-certificates; no download is attempted") from None
            self.exec_file(node, ["/usr/sbin/update-ca-certificates"], timeout=60)
            self.wait(node, "SELECT N'KUBERIC_LAB_READY';", login_retry=True)
            self.sql(node, self.capability_sql(node))

    def sql(self, node: dict, sql: str, *, role: str = "sa", timeout: float = 60) -> bytes:
        self.need_container(node)
        username = "sa" if role == "sa" else private_text(
            self.directory / f"{node['logical_id']}.{role}.username"
        )
        require(username == {"sa": "sa", "observer": "kuberic_observer", "mutation": "kuberic_mutator"}.get(role),
                "Generated SQL username file changed")
        return self.docker.run([
            "exec", "--interactive", "--user", "10001:0", "--env", "SQLCMDPASSWORD",
            node["container_id"], SQLCMD, "-S", f"tcp:{node['hostname']},1433",
            "-U", username, "-d", "master", "-N", "-b", "-V", "11",
            "-l", "5", "-t", str(max(1, min(120, int(timeout) - 1))), "-h", "-1", "-W",
        ], operation="sql", env=environment({"SQLCMDPASSWORD": self.secret(node, role)}),
            data=("SET NOCOUNT ON;\nSET XACT_ABORT ON;\n" + sql + "\nGO\n").encode(), timeout=timeout)

    def wait(self, node: dict, query: str, *, login_retry: bool = False) -> None:
        deadline = time.monotonic() + self.manifest["ready_timeout"]
        with self.docker.bounded(deadline):
            while True:
                remaining = deadline - time.monotonic()
                require(remaining > 0, "SQL service/seeding readiness deadline exceeded")
                try:
                    output = self.sql(node, query, timeout=min(30, remaining))
                except CommandError as error:
                    if not login_retry or error.operation != "sql":
                        raise
                else:
                    if time.monotonic() < deadline and b"KUBERIC_LAB_READY" in [
                        line.strip() for line in output.splitlines()
                    ]:
                        return
                remaining = deadline - time.monotonic()
                require(remaining > 0, "SQL service/seeding readiness deadline exceeded")
                time.sleep(min(1, remaining))

    def capability_sql(self, node: dict) -> str:
        return f"""
IF ISNULL(CONVERT(int, SERVERPROPERTY('ProductMajorVersion')), 0) <> 16
 OR ISNULL(CONVERT(int, SERVERPROPERTY('EngineEdition')), 0) <> 3
 OR ISNULL(CONVERT(nvarchar(128), SERVERPROPERTY('Edition')), N'') NOT LIKE N'Developer%'
 OR ISNULL(CONVERT(int, SERVERPROPERTY('IsHadrEnabled')), 0) <> 1
 OR NOT EXISTS (SELECT 1 FROM sys.dm_os_host_info WHERE host_platform = N'Linux')
 OR CHARINDEX(N'(X64)', CONVERT(nvarchar(4000), @@VERSION)) = 0
 THROW 51000, 'Unsupported laboratory engine', 1;
IF @@SERVERNAME IS NULL OR @@SERVERNAME <> {sql_literal(node['hostname'])}
 THROW 51000, 'Unexpected SQL Server identity', 1;
IF EXISTS (SELECT 1 FROM sys.availability_groups) OR EXISTS (SELECT 1 FROM sys.databases WHERE database_id > 4)
 THROW 51000, 'Laboratory storage is not a fresh isolated instance', 1;
"""

    def principals(self) -> None:
        for node in self.manifest["nodes"]:
            self.sql(node, f"""
CREATE LOGIN [kuberic_observer] WITH PASSWORD = {sql_literal(self.secret(node, 'observer'))}, CHECK_POLICY = OFF;
GRANT VIEW SERVER STATE TO [kuberic_observer];
GRANT VIEW SERVER PERFORMANCE STATE TO [kuberic_observer];
GRANT VIEW ANY DEFINITION TO [kuberic_observer];
GRANT VIEW ANY DATABASE TO [kuberic_observer];
CREATE LOGIN [kuberic_mutator] WITH PASSWORD = {sql_literal(self.secret(node, 'mutation'))}, CHECK_POLICY = OFF;
ALTER SERVER ROLE [sysadmin] ADD MEMBER [kuberic_mutator];
CREATE MASTER KEY ENCRYPTION BY PASSWORD = {sql_literal(self.secret(node, 'master'))};
CREATE LOGIN [kuberic_endpoint_login] WITH PASSWORD = {sql_literal(self.secret(node, 'endpoint'))}, CHECK_POLICY = OFF;
CREATE USER [kuberic_endpoint_user] FOR LOGIN [kuberic_endpoint_login];
""")
            self.sql(node, """
IF ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), -1) <> 0
 OR ISNULL(HAS_PERMS_BY_NAME(NULL, NULL, N'ALTER ANY AVAILABILITY GROUP'), -1) <> 0
 OR ISNULL(HAS_PERMS_BY_NAME(NULL, NULL, N'VIEW SERVER PERFORMANCE STATE'), 0) <> 1
 OR ISNULL(HAS_PERMS_BY_NAME(NULL, NULL, N'VIEW SERVER STATE'), 0) <> 1
 OR ISNULL(HAS_PERMS_BY_NAME(NULL, NULL, N'VIEW ANY DEFINITION'), 0) <> 1
 OR ISNULL(HAS_PERMS_BY_NAME(NULL, NULL, N'VIEW ANY DATABASE'), 0) <> 1
 THROW 51000, 'Observer permissions are incorrect', 1;
""", role="observer")
            self.sql(node, """
IF ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) <> 1
 THROW 51000, 'Laboratory mutation permissions are incorrect', 1;
""", role="mutation")

    def export_file(self, node: dict, name: str) -> bytes:
        self.need_container(node)
        data = self.docker.run(["cp", f"{node['container_id']}:/var/opt/mssql/secrets/{name}", "-"])
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                entries = archive.getmembers()
                require(len(entries) == 1 and entries[0].isfile()
                        and entries[0].name == name and 0 < entries[0].size <= 65536,
                        "Invalid certificate export archive")
                stream = archive.extractfile(entries[0])
                require(stream is not None, "Missing certificate export")
                return stream.read(65537)
        except tarfile.TarError:
            raise LabError("Invalid certificate export; raw content is suppressed") from None

    def endpoints(self) -> None:
        primary, *secondaries = self.manifest["nodes"]
        encryption = sql_literal(private_text(self.directory / "endpoint-backup.password"))
        self.sql(primary, f"""
CREATE CERTIFICATE [kuberic_endpoint] AUTHORIZATION [kuberic_endpoint_user]
 WITH SUBJECT = N'Owned Kuberic laboratory mirroring endpoint';
BACKUP CERTIFICATE [kuberic_endpoint] TO FILE = '/var/opt/mssql/secrets/endpoint.cer'
 WITH PRIVATE KEY (FILE = '/var/opt/mssql/secrets/endpoint.pvk', ENCRYPTION BY PASSWORD = {encryption});
""")
        self.exec_file(primary, ["/bin/chmod", "0600", "/var/opt/mssql/secrets/endpoint.cer",
                                "/var/opt/mssql/secrets/endpoint.pvk"])
        exports = {name: self.export_file(primary, name) for name in ("endpoint.cer", "endpoint.pvk")}
        for name, content in exports.items():
            write_private(self.directory / name, content)
        for node in secondaries:
            self.copy_files(node, "/var/opt/mssql/secrets", exports)
            self.sql(node, f"""
CREATE CERTIFICATE [kuberic_endpoint] AUTHORIZATION [kuberic_endpoint_user]
 FROM FILE = '/var/opt/mssql/secrets/endpoint.cer'
 WITH PRIVATE KEY (FILE = '/var/opt/mssql/secrets/endpoint.pvk', DECRYPTION BY PASSWORD = {encryption});
""")
        for node in self.manifest["nodes"]:
            self.sql(node, """
CREATE ENDPOINT [kuberic_hadr] STATE = STARTED AS TCP (LISTENER_PORT = 5022)
 FOR DATABASE_MIRRORING (
   ROLE = ALL, AUTHENTICATION = CERTIFICATE [kuberic_endpoint],
   ENCRYPTION = REQUIRED ALGORITHM AES
 );
GRANT CONNECT ON ENDPOINT::[kuberic_hadr] TO [kuberic_endpoint_login];
IF NOT EXISTS (
 SELECT 1 FROM sys.database_mirroring_endpoints m
 INNER JOIN sys.tcp_endpoints t ON t.endpoint_id = m.endpoint_id
 WHERE m.state_desc = N'STARTED' AND t.port = 5022
 AND m.connection_auth = 4 AND m.certificate_id > 0
 AND m.is_encryption_enabled = 1 AND m.encryption_algorithm = 2
) THROW 51000, 'Certificate/AES endpoint was not established', 1;
""")

    def database(self) -> None:
        name = self.manifest["database_name"]
        database = sql_identifier(name)
        self.sql(self.manifest["nodes"][0], f"""
CREATE DATABASE {database}
 ON PRIMARY (NAME = {sql_literal(name)}, FILENAME = {sql_literal('/var/opt/mssql/data/' + name + '.mdf')},
 SIZE = 16MB, FILEGROWTH = 16MB)
 LOG ON (NAME = {sql_literal(name + '_log')}, FILENAME = {sql_literal('/var/opt/mssql/data/' + name + '.ldf')},
 SIZE = 16MB, FILEGROWTH = 16MB);
GO
ALTER DATABASE {database} SET RECOVERY FULL;
GO
USE {database};
CREATE TABLE dbo.lab_marker (id int NOT NULL PRIMARY KEY, note varchar(40) NOT NULL);
INSERT INTO dbo.lab_marker VALUES (1, 'Owned disposable SQL Server laboratory');
GO
USE master;
BACKUP DATABASE {database} TO DISK = {sql_literal('/var/opt/mssql/backup/' + name + '.bak')} WITH INIT, CHECKSUM;
BACKUP LOG {database} TO DISK = {sql_literal('/var/opt/mssql/backup/' + name + '.trn')} WITH INIT, CHECKSUM;
IF NOT EXISTS (
 SELECT 1 FROM sys.databases d INNER JOIN sys.database_recovery_status r ON r.database_id = d.database_id
 WHERE d.name = {sql_literal(name)} AND d.recovery_model_desc = N'FULL'
 AND d.state_desc = N'ONLINE' AND r.last_log_backup_lsn > 0
) THROW 51000, 'Database backup preparation did not complete', 1;
""", timeout=120)

    def configurations(self) -> None:
        for node in self.manifest["nodes"]:
            replica = node["logical_id"]
            config = {
                "mode": "observe_only", "host": "127.0.0.1", "port": node["port"],
                "availability_group": self.manifest["availability_group"],
                "expected_server_name": node["hostname"], "replica_id": replica,
                "incarnation": node["container_id"],
                "observer_username_file": str(self.directory / f"{replica}.observer.username"),
                "observer_password_file": str(self.directory / f"{replica}.observer.password"),
                "ca_certificate_file": str(self.directory / "ca.crt"),
                "connect_timeout_ms": 5000, "query_timeout_ms": 5000,
                "sample_timeout_ms": 30000, "poll_interval_ms": 1000, "max_age_ms": 60000,
            }
            write_private(Path(node["observer_config"]), (json.dumps(config, indent=2) + "\n").encode())

    def setup_sql(self, node: dict, query: str) -> bytes:
        require(self.setup_deadline is not None and self.manifest["state"] == "provisioning"
                and self.manifest["stage"] == "bootstrap" and self.manifest["bootstrap_ag"],
                "Setup SQL is authorized only during fresh owned AG bootstrap")
        # Renew between bounded steps: even a renewal plus one slow probe plus the
        # following renewal must fit within the native lease, without background work.
        budget = self.manifest["write_lease_seconds"] / 4
        deadline = min(self.setup_deadline, time.monotonic() + budget)
        with self.docker.bounded(deadline):
            result = self.sql(node, query, timeout=budget)
        require(time.monotonic() < deadline, "AG setup step or synchronization deadline exceeded")
        return result

    def capture_native_ids(self) -> None:
        primary = self.manifest["nodes"][0]
        names = ", ".join(sql_literal(node["hostname"]) for node in self.manifest["nodes"])
        ordering = " ".join(
            f"WHEN {sql_literal(node['hostname'])} THEN {index}"
            for index, node in enumerate(self.manifest["nodes"])
        )
        output = self.setup_sql(primary, f"""
IF @@SERVERNAME IS NULL OR @@SERVERNAME <> {sql_literal(primary['hostname'])}
 THROW 51000, 'Unexpected setup primary', 1;
SELECT LOWER(CONVERT(char(36), ag.group_id)) + N'|' + LOWER(CONVERT(char(36), r.replica_id))
 FROM sys.availability_groups ag
 INNER JOIN sys.availability_replicas r ON r.group_id = ag.group_id
 WHERE ag.name = {sql_literal(self.manifest['availability_group'])}
 AND r.replica_server_name IN ({names})
 AND EXISTS (
   SELECT 1 FROM sys.dm_hadr_availability_replica_states local_state
   WHERE local_state.group_id = ag.group_id AND local_state.is_local = 1
   AND local_state.role_desc = N'PRIMARY'
 )
 ORDER BY CASE r.replica_server_name {ordering} ELSE 3 END;
""")
        try:
            rows = [line.strip().split("|") for line in output.decode("ascii").strip().splitlines()]
        except UnicodeError:
            raise LabError("Native GUID query returned invalid encoding; content is suppressed") from None
        require(len(rows) == 3 and all(len(row) == 2 and all(native_guid(value) for value in row) for row in rows),
                "Native identity query must return exactly three GUID-only pairs")
        groups = {row[0] for row in rows}
        replicas = {row[1] for row in rows}
        require(len(groups) == 1 and len(replicas) == 3, "Native topology has inconsistent or duplicate GUIDs")
        self.manifest["native_group_id"] = rows[0][0]
        for node, row in zip(self.manifest["nodes"], rows):
            node["native_replica_id"] = row[1]
        self.save()

    def renew_setup_lease(self) -> None:
        primary = self.manifest["nodes"][0]
        require(native_guid(self.manifest["native_group_id"]) and native_guid(primary["native_replica_id"]),
                "Setup lease requires the captured exact native primary identity")
        started = time.monotonic()
        output = self.setup_sql(primary, f"""
EXEC sys.sp_set_session_context @key=N'external_cluster', @value=N'yes';
IF @@SERVERNAME IS NULL OR @@SERVERNAME <> {sql_literal(primary['hostname'])}
 OR NOT EXISTS (
   SELECT 1 FROM sys.availability_groups ag
   INNER JOIN sys.dm_hadr_availability_replica_states ar ON ar.group_id = ag.group_id
   WHERE ag.name = {sql_literal(self.manifest['availability_group'])}
   AND ag.group_id = {sql_literal(self.manifest['native_group_id'])}
   AND ag.cluster_type_desc = N'EXTERNAL' AND ag.db_failover = 1
   AND ag.required_synchronized_secondaries_to_commit = 1
   AND ar.is_local = 1 AND ar.role_desc = N'PRIMARY'
   AND ar.replica_id = {sql_literal(primary['native_replica_id'])}
 )
 OR NOT EXISTS (
   SELECT 1 FROM sys.databases WHERE name = {sql_literal(self.manifest['database_name'])}
   AND state_desc = N'ONLINE' AND replica_id = {sql_literal(primary['native_replica_id'])}
 )
 THROW 51000, 'Owned setup primary or database identity changed', 1;
ALTER AVAILABILITY GROUP {sql_identifier(self.manifest['availability_group'])}
 SET (WRITE_LEASE_VALIDITY = {self.manifest['write_lease_seconds']});
SELECT N'KUBERIC_LAB_LEASE_RENEWED';
""")
        require(output.strip() == b"KUBERIC_LAB_LEASE_RENEWED",
                "Native setup lease renewal was not acknowledged")
        self.setup_lease_started = started

    def synchronized_sql(self, node: dict, *, cluster: bool = False) -> str:
        role = "PRIMARY" if node["logical_id"] == self.manifest["primary_replica_id"] else "SECONDARY"
        remote_guard = ""
        if cluster:
            replicas = ", ".join(sql_literal(item["native_replica_id"]) for item in self.manifest["nodes"])
            remote_guard = f"""
 AND (SELECT COUNT(DISTINCT remote_state.replica_id)
      FROM sys.dm_hadr_database_replica_states remote_state
      INNER JOIN sys.availability_databases_cluster adc
        ON adc.group_id = remote_state.group_id AND adc.group_database_id = remote_state.group_database_id
      INNER JOIN sys.dm_hadr_availability_replica_states peer
        ON peer.group_id = remote_state.group_id AND peer.replica_id = remote_state.replica_id
      WHERE remote_state.group_id = ag.group_id
      AND adc.database_name = {sql_literal(self.manifest['database_name'])}
      AND remote_state.replica_id IN ({replicas})
      AND remote_state.synchronization_state_desc = N'SYNCHRONIZED'
      AND remote_state.synchronization_health_desc = N'HEALTHY'
      AND peer.connected_state_desc = N'CONNECTED') = 3
"""
        marker = "KUBERIC_LAB_CLUSTER" if cluster else "KUBERIC_LAB"
        return f"""
IF @@SERVERNAME IS NULL OR @@SERVERNAME <> {sql_literal(node['hostname'])}
 THROW 51000, 'Unexpected setup observation identity', 1;
SELECT CASE WHEN EXISTS (
 SELECT 1 FROM sys.availability_groups ag
 INNER JOIN sys.dm_hadr_availability_replica_states ar ON ar.group_id = ag.group_id AND ar.is_local = 1
 INNER JOIN sys.dm_hadr_database_replica_states dr ON dr.group_id = ag.group_id AND dr.is_local = 1
 INNER JOIN sys.databases d ON d.database_id = dr.database_id
 WHERE ag.name = {sql_literal(self.manifest['availability_group'])}
 AND ag.group_id = {sql_literal(self.manifest['native_group_id'])}
 AND ar.replica_id = {sql_literal(node['native_replica_id'])}
 AND dr.replica_id = ar.replica_id
 AND ag.cluster_type_desc = N'EXTERNAL' AND ag.db_failover = 1
 AND ag.required_synchronized_secondaries_to_commit = 1
 AND ar.role_desc = {sql_literal(role)}
 AND d.name = {sql_literal(self.manifest['database_name'])} AND d.state_desc = N'ONLINE'
 AND dr.synchronization_state_desc = N'SYNCHRONIZED'
 AND dr.synchronization_health_desc = N'HEALTHY' AND dr.is_suspended = 0
 AND (SELECT COUNT(*) FROM sys.availability_databases_cluster db WHERE db.group_id = ag.group_id) = 1
 AND (SELECT COUNT(*) FROM sys.availability_replicas r WHERE r.group_id = ag.group_id) = 3
 AND (SELECT COUNT(*) FROM sys.availability_replicas r WHERE r.group_id = ag.group_id
      AND r.availability_mode_desc = N'SYNCHRONOUS_COMMIT'
      AND r.failover_mode_desc = N'EXTERNAL' AND r.seeding_mode_desc = N'AUTOMATIC') = 3
 {remote_guard}
) THEN N'{marker}_READY' ELSE N'{marker}_WAIT' END;
"""

    def synchronization_probe(self, node: dict, *, cluster: bool = False) -> bool:
        self.renew_setup_lease()
        output = self.setup_sql(node, self.synchronized_sql(node, cluster=cluster)).strip()
        marker = b"KUBERIC_LAB_CLUSTER" if cluster else b"KUBERIC_LAB"
        require(output in (marker + b"_READY", marker + b"_WAIT"),
                "Native synchronization query returned an unexpected response; content is suppressed")
        return output == marker + b"_READY"

    def bootstrap(self) -> None:
        self.setup_deadline = time.monotonic() + self.manifest["ready_timeout"]
        try:
            with self.docker.bounded(self.setup_deadline):
                self.bootstrap_owned_group()
        finally:
            self.setup_deadline = None

    def bootstrap_owned_group(self) -> None:
        group = sql_identifier(self.manifest["availability_group"])
        database = sql_identifier(self.manifest["database_name"])
        replicas = ",\n".join(
            f"{sql_literal(node['hostname'])} WITH ("
            f"ENDPOINT_URL = {sql_literal('tcp://' + node['hostname'] + ':5022')}, "
            "AVAILABILITY_MODE = SYNCHRONOUS_COMMIT, FAILOVER_MODE = EXTERNAL, "
            "SEEDING_MODE = AUTOMATIC, SECONDARY_ROLE (ALLOW_CONNECTIONS = ALL))"
            for node in self.manifest["nodes"]
        )
        session = "EXEC sys.sp_set_session_context @key=N'external_cluster', @value=N'yes';\n"
        primary, *secondaries = self.manifest["nodes"]
        self.setup_sql(primary, session + f"""
CREATE AVAILABILITY GROUP {group}
 WITH (CLUSTER_TYPE = EXTERNAL, DB_FAILOVER = ON,
 WRITE_LEASE_VALIDITY = {self.manifest['write_lease_seconds']},
 REQUIRED_SYNCHRONIZED_SECONDARIES_TO_COMMIT = 1)
 FOR DATABASE {database} REPLICA ON {replicas};
""")
        self.capture_native_ids()
        for node in secondaries:
            self.renew_setup_lease()
            self.setup_sql(node, session + f"""
ALTER AVAILABILITY GROUP {group} JOIN WITH (CLUSTER_TYPE = EXTERNAL);
ALTER AVAILABILITY GROUP {group} GRANT CREATE ANY DATABASE;
""")
        for node in secondaries:
            self.renew_setup_lease()
            self.setup_sql(primary, f"ALTER AVAILABILITY GROUP {group} MODIFY REPLICA ON "
                           f"{sql_literal(node['hostname'])} WITH (SEEDING_MODE = AUTOMATIC);")
        while True:
            # Do not accumulate stale successes from different rounds.
            ready = [self.synchronization_probe(node) for node in self.manifest["nodes"]]
            if all(ready) and self.synchronization_probe(primary, cluster=True):
                return
            require(self.setup_deadline is not None, "Missing setup deadline")
            remaining = self.setup_deadline - time.monotonic()
            require(remaining > 0, "AG synchronization deadline exceeded")
            time.sleep(min(1, remaining))

    def provision(self) -> None:
        for stage, action in (
            ("credentials", self.credentials), ("image", self.image),
            ("network", self.create_network), ("volumes", self.create_volumes),
            ("containers", self.containers), ("principals", self.principals),
            ("endpoints", self.endpoints), ("database", self.database),
            ("configurations", self.configurations),
        ):
            self.stage(stage)
            action()
        evidence = self.verify_all()
        require(evidence["network"] is not None and all(item is not None for item in evidence["volumes"])
                and all(item is not None and item["state"] == "running" for item in evidence["nodes"])
                and all(item is None for item in evidence["helpers"]),
                "Provisioned resources changed before the ready checkpoint")
        self.stage("bootstrap")
        self.bootstrap()
        keys = ("resource_id", "configuration_id", "epoch", "primary_replica_id", "database_name", "journal_path")
        config = {key: self.manifest[key] for key in keys}
        node_keys = ("observer_config", "replication_host", "replication_port",
                     "mutation_username_file", "mutation_password_file")
        config["nodes"] = [{key: node[key] for key in node_keys} for node in self.manifest["nodes"]]
        write_private(self.directory / "convergence.json", (json.dumps(config, indent=2) + "\n").encode())
        require(self.setup_lease_started is not None
                and time.monotonic() < self.setup_lease_started + self.manifest["write_lease_seconds"],
                "Initial setup lease expired before the ready checkpoint")
        self.manifest["state"] = "ready"
        self.stage("ready")

    def destroy(self, *, data: bool) -> None:
        self.verify_all()
        self.manifest["state"] = "destroying"
        self.stage("destroy")
        for helper in self.manifest["helpers"]:
            self.remove_container(helper, helper=True)
        for node in self.manifest["nodes"]:
            self.remove_container(node)
        network = self.network()
        if network is not None:
            require(not network["containers"], "Network still has attached containers")
            item = self.manifest["network"]
            self.docker.run(["network", "rm", item["id"]])
            require(self.docker.lookup("network", item["name"], item["id"]) is None,
                    "Network removal was not positively confirmed")
        if data:
            for item in self.manifest["volumes"]:
                if self.volume(item) is not None:
                    self.docker.run(["volume", "rm", item["name"]])
                    require(self.docker.lookup("volume", item["name"]) is None,
                            "Volume removal was not positively confirmed")
        self.manifest["state"] = "destroyed" if data else "destroyed_data_retained"
        self.save()

    def summary(self, evidence: dict | None = None) -> dict:
        result = {
            "manifest": str(self.directory / "ha-lab.json"),
            "owner_id": self.manifest["owner_id"], "state": self.manifest["state"],
            "stage": self.manifest["stage"], "docker_context": self.manifest["docker_context"],
            "engine_id": self.manifest["engine_id"],
            "bootstrap_ag": self.manifest["bootstrap_ag"],
        }
        if evidence is not None:
            result["network"] = {
                "name": self.manifest["network"]["name"], "id": self.manifest["network"]["id"],
                "present": evidence["network"] is not None,
            }
            for kind in ("nodes", "helpers", "volumes"):
                result[kind] = []
                for item, info in zip(self.manifest[kind], evidence[kind]):
                    row = {"name": item.get("container_name", item.get("name")), "present": info is not None}
                    if kind != "volumes":
                        row.update(logical_id=item["logical_id"], container_id=item["container_id"],
                                   process_state=info["state"] if info is not None else "absent")
                    result[kind].append(row)
        return result


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Owned, explicitly opt-in local three-node SQL Server 2022 Developer laboratory.",
        epilog="No failover, forced recovery, post-setup lease renewal, production support, or operator integration.",
    )
    commands = result.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="Provision and synchronize a NEW private three-node EXTERNAL AG")
    create.add_argument("--directory", required=True, help="New absolute directory OUTSIDE this repository")
    create.add_argument("--docker-context", required=True, help="Explicit named local Unix-socket context, not default")
    create.add_argument("--image", required=True, help="mcr.microsoft.com/mssql/server[:tag]@sha256:<digest>")
    create.add_argument("--accept-eula", action="store_true", help="Explicitly accept the SQL Server EULA")
    create.add_argument("--allow-mutations", action="store_true", help="Authorize disposable Docker and SQL setup")
    create.add_argument("--bootstrap-ag", action="store_true", default=True,
                        help="Compatibility flag: create always creates/joins/seeds the initial EXTERNAL AG")
    create.add_argument("--write-lease-seconds", type=int, choices=(30, 60), default=60)
    create.add_argument("--first-port", type=int, default=15433, help="First of three distinct loopback TDS ports")
    create.add_argument("--database-name", default="kuberic_lab")
    create.add_argument("--availability-group", default="kuberic_lab_ag")
    create.add_argument("--ready-timeout", type=int, default=240,
                        help="Each service startup and the entire AG bootstrap deadline, 30..600 seconds")
    inspect = commands.add_parser("inspect", help="Validate ownership and show Docker presence, not SQL health")
    inspect.add_argument("--directory", required=True)
    destroy = commands.add_parser("destroy", help="Remove exact owned containers/network; retain volumes by default")
    destroy.add_argument("--directory", required=True)
    destroy.add_argument("--destroy-data", action="store_true", help="Also irreversibly remove exact owned named volumes")
    return result


def record_failure(lab: Laboratory, state: str) -> None:
    lab.manifest["state"] = state
    try:
        lab.save()
    except (OSError, LabError):
        raise LabError(
            "Operation failed and failure-state persistence also failed; preserve the last durable "
            "ha-lab.json and owner-id for explicit ownership-checked cleanup"
        ) from None


def execute(args: argparse.Namespace, executor: Executor) -> dict:
    if args.command == "create":
        require(args.accept_eula and args.allow_mutations,
                "create requires BOTH --accept-eula and --allow-mutations; neither is implicit")
        validate_image(args.image)
        validate_context(args.docker_context)
        validate_sql_names(args.database_name, args.availability_group)
        require(1024 <= args.first_port <= 65533, "The three loopback ports must be in 1024..65535")
        require(30 <= args.ready_timeout <= 600, "Readiness timeout must be in 30..600 seconds")
        directory = validate_directory(args.directory, new=True)
        executor.program("docker")
        openssl = executor.program("openssl")
        version = executor.run([openssl, "version"], operation="openssl")
        require(re.match(rb"OpenSSL (?:1\.1\.1|[3-9]\.)", version) is not None,
                "OpenSSL 1.1.1 or 3+ is required, including req -addext; LibreSSL is not supported")
        docker = Docker(executor, args.docker_context)
        binding = docker.identity()
        directory.mkdir(mode=0o700)
        private_stat(directory, directory=True)
        with directory_lock(directory):
            manifest = initial_manifest(directory, args, binding)
            write_private(directory / "owner-id", manifest["owner_id"].encode())
            lab = Laboratory(directory, manifest, executor)
            lab.save()
            try:
                lab.provision()
            except (LabError, OSError, KeyboardInterrupt):
                record_failure(lab, "failed")
                raise
            return lab.summary()
    directory = validate_directory(args.directory, new=False)
    with directory_lock(directory):
        manifest = load_manifest(directory)
        lab = Laboratory(directory, manifest, executor)
        if args.command == "inspect":
            return lab.summary(lab.verify_all())
        try:
            lab.destroy(data=args.destroy_data)
        except (LabError, OSError, KeyboardInterrupt):
            record_failure(lab, "destroy_failed")
            raise
        return lab.summary()


def main(argv: list[str] | None = None, executor: Executor | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result = execute(args, executor or Executor())
    except LabError as error:
        print(f"Laboratory refused/failed: {error}. Preserve ha-lab.json and owner-id if created.", file=sys.stderr)
        return 1
    except OSError:
        print("Laboratory filesystem operation failed; preserve all ownership evidence. Details suppressed.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Laboratory operation interrupted; preserve ownership evidence for explicit cleanup.", file=sys.stderr)
        return 130
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
