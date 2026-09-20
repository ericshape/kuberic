"""Server-free safety/contract tests. No Docker daemon, SQL Server, or real keys."""

from __future__ import annotations

import contextlib
import copy
import io
import itertools
import json
import os
from pathlib import Path
import stat
import subprocess
import unittest
from unittest import mock
import uuid

import sqlserver_ha_lab as lab


IMAGE = "mcr.microsoft.com/mssql/server@sha256:" + "b" * 64


class FakeExecutor(lab.Executor):
    """Stateful Docker command double; all external execution stays in memory."""

    def __init__(self):
        super().__init__()
        self.calls = []
        self.created = []
        self.deleted = []
        self.objects = {"container": {}, "network": {}, "volume": {}}
        self.counter = itertools.count(1)
        self.engine = "test-engine-id"
        self.endpoint = "unix:///test-only/docker.sock"
        self.os_type = "linux"
        self.architecture = "x86_64"
        self.image_architecture = "amd64"
        self.image_id = "sha256:" + "a" * 64
        self.image_volumes = {}
        self.failure = None
        self.missing = set()
        self.lost_container_response = False
        self.fail_sql = False
        self.permissions = b"10001:0:600\n10001:0:700\n"
        self.native_group = "11111111-1111-4111-8111-111111111111"
        self.native_replicas = [
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "44444444-4444-4444-8444-444444444444",
        ]
        self.native_id_response = None
        self.sql_failure = None
        self.sync_sequences = {}
        self.cluster_sequence = []
        self.sync_checks = []
        self.sync_delay = 0
        self.advance_clock = None
        self.lease_ack = b"KUBERIC_LAB_LEASE_RENEWED\n"

    def program(self, name):
        lab.require(name not in self.missing, f"Required executable is unavailable: {name}")
        return f"/test-only/{name}"

    def encode(self, value):
        return json.dumps(value).encode()

    def labels(self, args):
        return dict(args[index + 1].split("=", 1)
                    for index, arg in enumerate(args) if arg == "--label")

    def resource(self, kind, identity):
        matches = [item for item in self.objects[kind].values()
                   if item.get("id") == identity or item["name"].lstrip("/") == identity]
        if len(matches) != 1:
            raise lab.CommandError("docker", "test object lookup failed")
        return matches[0]

    def run(self, argv, *, operation, data=None, env=None, timeout=30):
        env = lab.environment() if env is None else dict(env)
        self.calls.append({"argv": list(argv), "operation": operation, "data": data, "env": env,
                           "timeout": timeout})
        if self.failure is not None and self.failure(argv):
            raise lab.CommandError(operation, "injected command failure")
        if argv[0].endswith("/openssl"):
            args = argv[1:]
            if args == ["version"]:
                return b"OpenSSL 3.0.0 test-only\n"
            for flag in ("-out", "-keyout"):
                if flag in args:
                    lab.write_private(Path(args[args.index(flag) + 1]), b"NOT-A-REAL-KEY-OR-CERTIFICATE\n")
            return b""
        if argv[1:3] != ["--context", "owned-lab"]:
            raise AssertionError("Every Docker command must specify the owned named context")
        args = argv[3:]
        command = args[:2]
        if command == ["context", "inspect"]:
            return self.encode({"name": "owned-lab", "endpoint": self.endpoint})
        if args[0] == "info":
            return self.encode({"id": self.engine, "os": self.os_type, "architecture": self.architecture})
        if command == ["image", "pull"]:
            return b""
        if command == ["image", "inspect"]:
            return self.encode({"id": self.image_id, "os": "linux", "architecture": self.image_architecture,
                                "digests": [IMAGE], "volumes": self.image_volumes})
        if len(command) == 2 and command[1] == "ls":
            kind = command[0]
            rows = [{"name": item["name"].lstrip("/"),
                     **({"id": item["id"]} if kind != "volume" else {})}
                    for item in self.objects[kind].values()]
            return b"\n".join(self.encode(row) for row in rows)
        if len(command) == 2 and command[1] == "inspect":
            return self.encode(self.resource(command[0], args[2]))
        if command == ["network", "create"]:
            identity = f"{next(self.counter):064x}"
            info = {"name": args[-1], "id": identity, "labels": self.labels(args),
                    "driver": "bridge", "internal": True, "containers": {}}
            self.objects["network"][identity] = info
            self.created.append(("network", copy.deepcopy(info), list(args)))
            return identity.encode() + b"\n"
        if command == ["volume", "create"]:
            name = args[-1]
            info = {"name": name, "labels": self.labels(args), "driver": "local", "scope": "local",
                    "options": {}, "created_at": f"test-creation-{next(self.counter)}"}
            self.objects["volume"][name] = info
            self.created.append(("volume", copy.deepcopy(info), list(args)))
            return name.encode() + b"\n"
        if command == ["container", "create"]:
            identity = f"{next(self.counter):064x}"
            name = args[args.index("--name") + 1]
            network = args[args.index("--network") + 1]
            volume = args[args.index("--mount") + 1].split(",")[1].split("=")[1]
            ports = {}
            networks = {"none": {}}
            if network != "none":
                real_network = self.resource("network", network)
                networks = {real_network["name"]: {"NetworkID": network}}
                binding = args[args.index("--publish") + 1].split(":")
                ports = {"1433/tcp": [{"HostIp": binding[0], "HostPort": binding[1]}]}
            info = {
                "name": "/" + name, "id": identity, "labels": self.labels(args),
                "image": IMAGE, "image_id": self.image_id, "hostname": name,
                "user": args[args.index("--user") + 1],
                "mounts": [{"Type": "volume", "Name": volume, "Destination": "/var/opt/mssql", "RW": True}],
                "network_mode": network, "networks": networks, "ports": ports,
                "restart": "no", "privileged": False, "state": "created",
            }
            self.objects["container"][identity] = info
            self.created.append(("container", copy.deepcopy(info), list(args)))
            if self.lost_container_response:
                self.lost_container_response = False
                raise lab.CommandError("docker", "lost creation response")
            return identity.encode() + b"\n"
        if command in (["container", "start"], ["container", "stop"],
                       ["container", "unpause"], ["container", "update"]):
            info = self.resource("container", args[-1])
            if command[1] in ("start", "unpause"):
                info["state"] = "running"
                if info["network_mode"] != "none":
                    network = self.resource("network", info["network_mode"])
                    network["containers"][info["id"]] = {"Name": info["name"].lstrip("/")}
            elif command[1] == "stop":
                info["state"] = "exited"
            return b""
        if len(command) == 2 and command[1] == "rm":
            kind, identity = command[0], args[2]
            info = self.resource(kind, identity)
            key = info.get("id", info["name"])
            del self.objects[kind][key]
            if kind == "container":
                for network in self.objects["network"].values():
                    network["containers"].pop(key, None)
            self.deleted.append((kind, identity))
            return identity.encode()
        if args[0] == "cp":
            if args[-1] == "-":
                name = args[1].rsplit("/", 1)[1]
                return lab.tar_bytes({name: b"FAKE-ENCRYPTED-ENDPOINT-EXPORT"})
            return b""
        if args[0] == "exec":
            identity_index = next(index for index, value in enumerate(args)
                                  if value in self.objects["container"])
            executable = args[identity_index + 1]
            if executable == "/usr/bin/stat":
                return self.permissions
            if executable == lab.SQLCMD:
                payload = data or b""
                if self.fail_sql or (self.sql_failure is not None and self.sql_failure in payload):
                    raise lab.CommandError("sql", "injected SQL failure")
                if b"ORDER BY CASE r.replica_server_name" in payload:
                    if self.native_id_response is not None:
                        return self.native_id_response
                    return "\n".join(f"{self.native_group}|{replica}" for replica in self.native_replicas).encode()
                if b"KUBERIC_LAB_LEASE_RENEWED" in payload:
                    return self.lease_ack
                if b"SELECT CASE WHEN" in payload and b"KUBERIC_LAB" in payload:
                    container = self.resource("container", args[identity_index])
                    replica = container["labels"][lab.REPLICA_LABEL]
                    cluster = b"KUBERIC_LAB_CLUSTER_READY" in payload
                    sequence = self.cluster_sequence if cluster else self.sync_sequences.get(replica, [])
                    ready = sequence.pop(0) if sequence else True
                    self.sync_checks.append(("cluster" if cluster else "local", replica, ready))
                    if self.advance_clock is not None:
                        self.advance_clock(self.sync_delay)
                    prefix = b"KUBERIC_LAB_CLUSTER" if cluster else b"KUBERIC_LAB"
                    return prefix + (b"_READY\n" if ready else b"_WAIT\n")
                if b"KUBERIC_LAB_READY" in payload:
                    return b"KUBERIC_LAB_READY\n"
                # Deliberately hostile raw output: callers must never display a secret batch.
                return b"server echoed secret input: " + (data or b"")
            return b""
        raise AssertionError(f"Unexpected fake command shape: {command}")


class LabTest(unittest.TestCase):
    def setUp(self):
        self.root = Path.cwd() / (".sqlserver-ha-lab-test-" + uuid.uuid4().hex)
        self.root.mkdir(mode=0o700)
        self.directory = self.root / "lab"
        self.fake = FakeExecutor()
        self.files = {self.directory / "lab.lock", self.directory / "ha-lab.json"}
        self.directories = [self.directory, self.root]
        original_write = lab.write_private

        def tracked_write(path, content):
            self.files.add(path)
            return original_write(path, content)

        self.patches = [
            mock.patch.object(lab, "REPOSITORY", self.root / "repository"),
            mock.patch.object(lab, "write_private", side_effect=tracked_write),
            mock.patch.object(lab.secrets, "token_bytes", side_effect=(
                index.to_bytes(32, "big") for index in range(1, 1000)
            )),
            mock.patch.object(lab.secrets, "token_urlsafe", side_effect=(
                f"public_test_password_not_a_real_secret_{index}" for index in range(1000)
            )),
        ]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        # Remove only exact test-created paths, never recurse or use cleanup globs.
        for path in self.files:
            if os.path.lexists(path):
                path.unlink()
        for path in self.directories:
            if os.path.lexists(path):
                path.rmdir()

    def args(self, *extra):
        return [
            "create", "--directory", str(self.directory), "--docker-context", "owned-lab",
            "--image", IMAGE, "--accept-eula", "--allow-mutations", *extra,
        ]

    def invoke(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = lab.main(args, self.fake)
        return code, stdout.getvalue(), stderr.getvalue()

    def create(self, *extra):
        code, output, error = self.invoke(self.args(*extra))
        self.assertEqual(code, 0, error)
        return lab.load_manifest(self.directory), json.loads(output)

    def mutate_manifest(self, callback):
        manifest = json.loads((self.directory / "ha-lab.json").read_bytes())
        callback(manifest)
        lab.save_manifest(self.directory, manifest)

    def test_acknowledgements_are_independently_required_before_any_execution(self):
        for missing in ("--accept-eula", "--allow-mutations"):
            with self.subTest(missing=missing):
                args = self.args()
                args.remove(missing)
                code, output, error = self.invoke(args)
                self.assertEqual(code, 1)
                self.assertIn("requires BOTH", error)
                self.assertEqual(output, "")
                self.assertEqual(self.fake.calls, [])
                self.assertFalse(self.directory.exists())

    def test_image_and_named_context_are_strict_gates(self):
        cases = [
            ("--image", "mcr.microsoft.com/mssql/server:2022-latest"),
            ("--image", "mcr.microsoft.com/mssql/server@sha256:abc"),
            ("--image", "other/image@sha256:" + "a" * 64),
            ("--docker-context", "default"), ("--docker-context", "-injected"),
        ]
        for flag, value in cases:
            with self.subTest(flag=flag, value=value):
                args = self.args()
                args[args.index(flag) + 1] = value
                if value.startswith("-"):
                    args[args.index(flag):args.index(flag) + 2] = [f"{flag}={value}"]
                code, _, _ = self.invoke(args)
                self.assertEqual(code, 1)
                self.assertEqual(self.fake.calls, [])
        lab.validate_image("mcr.microsoft.com/mssql/server:2022-CU22-ubuntu-22.04@sha256:" + "a" * 64)

    def test_required_arguments_and_help_do_not_execute_programs(self):
        for args, status in ((["--help"], 0), (["create", "--help"], 0),
                             (["inspect", "--help"], 0), (["destroy", "--help"], 0),
                             (["create"], 2)):
            with self.subTest(args=args), contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                lab.main(args, self.fake)
            self.assertEqual(result.exception.code, status)
        self.assertEqual(self.fake.calls, [])

    def test_local_native_daemon_is_required(self):
        for field, value in (("endpoint", "tcp://remote:2376"), ("endpoint", "ssh://remote"),
                             ("architecture", "aarch64"), ("os_type", "windows")):
            with self.subTest(field=field):
                previous = getattr(self.fake, field)
                setattr(self.fake, field, value)
                code, _, _ = self.invoke(self.args())
                self.assertEqual(code, 1)
                self.assertFalse(self.fake.created)
                self.assertFalse(self.directory.exists())
                setattr(self.fake, field, previous)

    def test_missing_dependencies_fail_before_directory_or_resources(self):
        for name in ("docker", "openssl"):
            with self.subTest(name=name):
                self.fake.missing = {name}
                code, _, error = self.invoke(self.args())
                self.assertEqual(code, 1)
                self.assertIn(name, error)
                self.assertFalse(self.directory.exists())
                self.assertFalse(self.fake.created)

    def test_openssl_version_and_runtime_failure_propagate(self):
        self.fake.failure = lambda argv: argv[0].endswith("/openssl")
        code, _, error = self.invoke(self.args())
        self.assertEqual(code, 1)
        self.assertIn("openssl", error)
        self.assertFalse(self.directory.exists())
        self.fake.failure = lambda argv: argv[0].endswith("/openssl") and "req" in argv
        code, _, error = self.invoke(self.args())
        self.assertEqual(code, 1)
        self.assertIn("openssl", error)
        manifest = lab.load_manifest(self.directory)
        self.assertEqual((manifest["state"], manifest["stage"]), ("failed", "credentials"))
        self.assertFalse(self.fake.created)

    def test_existing_symlink_root_home_and_repository_directories_are_refused(self):
        self.directory.mkdir(mode=0o700)
        with self.assertRaises(lab.LabError):
            lab.validate_directory(str(self.directory), new=True)
        self.directory.rmdir()
        self.directory.symlink_to(self.root, target_is_directory=True)
        self.files.add(self.directory)
        with self.assertRaises(lab.LabError):
            lab.validate_directory(str(self.directory), new=True)
        with self.assertRaises(lab.LabError):
            lab.validate_directory(str(self.directory / "child"), new=True)
        self.directory.unlink()
        for path in ("/", str(Path.home()), str(self.root), str(lab.REPOSITORY),
                     str(lab.REPOSITORY / "secret-lab"), "relative", str(self.root / ".." / "unsafe")):
            with self.subTest(path=path), self.assertRaises(lab.LabError):
                lab.validate_directory(path, new=True)
        self.files.remove(self.directory)

    def test_complete_manifest_observer_and_convergence_contracts(self):
        manifest, summary = self.create()
        self.assertEqual(summary["state"], "ready")
        self.assertEqual(manifest["version"], 1)
        self.assertEqual(manifest["epoch"], 1)
        self.assertEqual(manifest["primary_replica_id"], "replica-0")
        self.assertEqual(manifest["docker_context"], "owned-lab")
        self.assertEqual(manifest["engine_id"], self.fake.engine)
        self.assertEqual(manifest["image"], IMAGE)
        self.assertTrue(manifest["bootstrap_ag"])
        self.assertEqual(manifest["native_group_id"], self.fake.native_group)
        self.assertEqual([node["native_replica_id"] for node in manifest["nodes"]], self.fake.native_replicas)
        self.assertTrue(Path(manifest["journal_path"]).is_absolute())
        self.assertFalse(Path(manifest["journal_path"]).exists())
        self.assertEqual(set(manifest["issuer_keys"]), set(lab.PURPOSES))
        seeds = [lab.read_private(Path(path)) for path in manifest["issuer_keys"].values()]
        self.assertEqual(len(set(seeds)), 4)
        self.assertTrue(all(len(seed) == 32 for seed in seeds))
        example = json.loads((Path(__file__).resolve().parent.parent
                              / "examples/sqlserver/observer.example.json").read_bytes())
        for index, node in enumerate(manifest["nodes"]):
            config = json.loads(lab.read_private(Path(node["observer_config"])))
            self.assertEqual(set(config), set(example))
            self.assertEqual(config["host"], "127.0.0.1")
            self.assertEqual(config["port"], 15433 + index)
            self.assertEqual(config["replica_id"], f"replica-{index}")
            self.assertRegex(config["incarnation"], r"^[0-9a-f]{64}$")
            self.assertEqual(config["incarnation"], node["container_id"])
            self.assertEqual(config["expected_server_name"], node["hostname"])
            self.assertEqual(config["ca_certificate_file"], str(self.directory / "ca.crt"))
            self.assertEqual(node["replication_host"], node["hostname"])
            self.assertEqual(node["replication_port"], 5022)
            for key in ("observer_username_file", "observer_password_file"):
                self.assertTrue(Path(config[key]).is_absolute())
                self.assertNotIn(b"\n", lab.read_private(Path(config[key])))
            extensions = lab.read_private(self.directory / f"replica-{index}.tls.ext")
            self.assertIn(f"DNS:{node['hostname']},IP:127.0.0.1".encode(), extensions)
        convergence = json.loads(lab.read_private(self.directory / "convergence.json"))
        self.assertEqual(set(convergence), {"resource_id", "configuration_id", "epoch", "primary_replica_id",
                                           "database_name", "journal_path", "nodes"})
        for node in convergence["nodes"]:
            self.assertEqual(set(node), {"observer_config", "replication_host", "replication_port",
                                        "mutation_username_file", "mutation_password_file"})
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        for path in self.files:
            if path.exists():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_secrets_are_only_in_private_files_stdin_or_sqlcmd_environment(self):
        manifest, _ = self.create("--bootstrap-ag")
        secrets_in_files = [lab.read_private(self.directory / f"replica-{index}.{role}.password")
                            for index in range(3) for role in ("sa", "observer", "mutation", "master", "endpoint")]
        secrets_in_files += [lab.read_private(self.directory / "endpoint-backup.password")]
        argv_bytes = json.dumps([call["argv"] for call in self.fake.calls]).encode()
        code, output, error = self.invoke(["inspect", "--directory", str(self.directory)])
        self.assertEqual(code, 0, error)
        for secret in secrets_in_files:
            self.assertNotIn(secret, argv_bytes)
            self.assertNotIn(secret.decode(), output + error)
            self.assertNotIn(secret, lab.read_private(self.directory / "ha-lab.json"))
        sql_calls = [call for call in self.fake.calls if call["operation"] == "sql"]
        self.assertTrue(sql_calls)
        for call in sql_calls:
            args = call["argv"]
            self.assertIn(lab.SQLCMD, args)
            self.assertIn("-N", args)
            self.assertNotIn("-C", args)
            self.assertNotIn("-P", args)
            self.assertNotIn("-Q", args)
            self.assertNotIn("TrustServerCertificate", " ".join(args))
            self.assertIn(["--env", "SQLCMDPASSWORD"], [args[index:index + 2] for index in range(len(args))])
            self.assertTrue(call["env"]["SQLCMDPASSWORD"])
            self.assertIsInstance(call["data"], bytes)
        self.assertNotIn(".Config.Env", argv_bytes.decode())
        self.assertTrue(all(node["container_id"] for node in manifest["nodes"]))

    def test_all_resources_are_owned_and_helpers_use_only_pinned_image(self):
        manifest, _ = self.create()
        self.assertEqual(len(self.fake.created), 10)
        for kind, resource, args in self.fake.created:
            self.assertEqual(resource["labels"][lab.OWNER_LABEL], manifest["owner_id"])
            self.assertTrue(lab.canonical_uuid(resource["labels"][lab.TOKEN_LABEL]))
            self.assertIn(uuid.UUID(manifest["owner_id"]).hex, resource["name"])
            if kind == "container":
                self.assertIn(resource["labels"][lab.REPLICA_LABEL], {"replica-0", "replica-1", "replica-2"})
                self.assertIn(IMAGE, args)
                self.assertIn("--pull", args)
                if resource["labels"][lab.ROLE_LABEL] == "volume-init":
                    self.assertEqual(resource["network_mode"], "none")
                    self.assertIn("/bin/sleep", args)
                    self.assertNotIn("--env-file", args)
                else:
                    self.assertEqual(resource["user"], "10001:0")
                    env_file = args[args.index("--env-file") + 1]
                    self.assertTrue(Path(env_file).is_absolute())
        self.assertEqual(len(self.fake.deleted), 3)
        self.assertTrue(all(kind == "container" and lab.ID_PATTERN.fullmatch(identity)
                            for kind, identity in self.fake.deleted))
        config = lab.read_private(self.directory / "mssql.conf")
        self.assertIn(b"forceencryption = 1", config)
        self.assertIn(b"hadrenabled = 1", config)

    def test_inherited_docker_and_sqlcmd_overrides_are_sanitized(self):
        overrides = {name: "untrusted-inherited-value" for name in lab.DOCKER_OVERRIDES}
        with mock.patch.dict(os.environ, overrides):
            self.create()
        for call in self.fake.calls:
            for key in lab.DOCKER_OVERRIDES:
                if key == "SQLCMDPASSWORD" and call["operation"] == "sql":
                    self.assertNotEqual(call["env"][key], overrides[key])
                else:
                    self.assertNotIn(key, call["env"])
            if call["argv"][0].endswith("/docker"):
                self.assertEqual(call["argv"][1:3], ["--context", "owned-lab"])

    def test_bootstrap_is_mandatory_and_uses_only_supported_initial_setup(self):
        manifest, _ = self.create("--write-lease-seconds", "30")
        sql = b"\n".join(call["data"] for call in self.fake.calls if call["operation"] == "sql").decode()
        for phrase in ("CREATE AVAILABILITY GROUP", "CLUSTER_TYPE = EXTERNAL", "DB_FAILOVER = ON",
                       "WRITE_LEASE_VALIDITY = 30", "REQUIRED_SYNCHRONIZED_SECONDARIES_TO_COMMIT = 1",
                       "AVAILABILITY_MODE = SYNCHRONOUS_COMMIT", "FAILOVER_MODE = EXTERNAL",
                       "SEEDING_MODE = AUTOMATIC", "GRANT CREATE ANY DATABASE",
                       "RECOVERY FULL", "BACKUP DATABASE", "BACKUP LOG",
                       "AUTHENTICATION = CERTIFICATE", "ENCRYPTION = REQUIRED ALGORITHM AES",
                       "ENCRYPTION BY PASSWORD", "DECRYPTION BY PASSWORD"):
            self.assertIn(phrase, sql)
        self.assertNotRegex(sql, r"ALTER AVAILABILITY GROUP[^\n;]*\bFAILOVER\b")
        self.assertNotIn("FORCE_FAILOVER", sql)
        self.assertIn("SET (WRITE_LEASE_VALIDITY = 30)", sql)
        self.assertIn("external_cluster", sql)
        self.assertIn(manifest["native_group_id"], sql)
        self.assertIn(manifest["nodes"][0]["native_replica_id"], sql)

    def test_default_prepares_database_and_all_three_synchronized_replicas(self):
        self.create()
        sql = b"\n".join(call["data"] for call in self.fake.calls if call["operation"] == "sql").decode()
        self.assertIn("CREATE AVAILABILITY GROUP", sql)
        self.assertIn("WRITE_LEASE_VALIDITY = 60", sql)
        self.assertEqual(sql.count("JOIN WITH (CLUSTER_TYPE = EXTERNAL)"), 2)
        self.assertIn("BACKUP LOG", sql)
        self.assertIn("ALTER SERVER ROLE [sysadmin] ADD MEMBER [kuberic_mutator]", sql)
        self.assertNotIn("ADD MEMBER [kuberic_observer]", sql)
        self.assertEqual(self.fake.sync_checks, [
            ("local", "replica-0", True), ("local", "replica-1", True),
            ("local", "replica-2", True), ("cluster", "replica-0", True),
        ])

    def test_setup_lease_is_renewed_between_join_seed_and_sync_steps(self):
        self.fake.sync_sequences["replica-2"] = [False, False, True]
        with mock.patch.object(lab.time, "sleep"):
            self.create()
        statements = [call["data"] for call in self.fake.calls if call["operation"] == "sql"]
        for index, statement in enumerate(statements):
            if any(marker in statement for marker in (
                b"JOIN WITH (CLUSTER_TYPE", b"MODIFY REPLICA ON", b"SELECT CASE WHEN",
            )):
                self.assertIn(b"KUBERIC_LAB_LEASE_RENEWED", statements[index - 1])
        renewals = [call for call in self.fake.calls if b"KUBERIC_LAB_LEASE_RENEWED" in (call["data"] or b"")]
        self.assertEqual(len(renewals), 14)
        self.assertTrue(all(call["timeout"] <= 15 for call in renewals))
        self.assertEqual(self.fake.sync_checks[-1], ("cluster", "replica-0", True))
        sql_count = len(statements)
        code, _, error = self.invoke(["inspect", "--directory", str(self.directory)])
        self.assertEqual(code, 0, error)
        self.assertEqual(sum(call["operation"] == "sql" for call in self.fake.calls), sql_count)
        manager = lab.Laboratory(self.directory, lab.load_manifest(self.directory), self.fake)
        with self.assertRaises(lab.LabError) as result:
            manager.renew_setup_lease()
        self.assertIn("only during", str(result.exception))
        self.assertIsNone(manager.setup_deadline)

    def test_sync_successes_must_share_a_round_and_primary_final_check(self):
        self.fake.sync_sequences = {
            "replica-0": [True, False, True, True],
            "replica-1": [False, True, True, True],
            "replica-2": [True, True, True, True],
        }
        self.fake.cluster_sequence = [False, True]
        with mock.patch.object(lab.time, "sleep"):
            self.create()
        for replica in ("replica-0", "replica-1", "replica-2"):
            self.assertEqual(sum(kind == "local" and member == replica
                                 for kind, member, _ in self.fake.sync_checks), 4)
        self.assertEqual([ready for kind, _, ready in self.fake.sync_checks if kind == "cluster"], [False, True])

    def test_setup_lease_failure_is_fatal_and_retains_native_ownership_receipt(self):
        self.fake.sql_failure = b"KUBERIC_LAB_LEASE_RENEWED"
        code, output, error = self.invoke(self.args())
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertIn("sql: injected SQL failure", error)
        manifest = lab.load_manifest(self.directory)
        self.assertEqual((manifest["state"], manifest["stage"]), ("failed", "bootstrap"))
        self.assertEqual(manifest["native_group_id"], self.fake.native_group)
        self.assertTrue(all(node["container_id"] for node in manifest["nodes"]))
        self.assertEqual(len(self.fake.objects["container"]), 3)
        self.assertFalse((self.directory / "convergence.json").exists())
        statements = [call["data"] for call in self.fake.calls if call["operation"] == "sql"]
        self.assertFalse(any(b"JOIN WITH" in statement for statement in statements))

    def test_seeding_command_failure_cannot_publish_ready(self):
        self.fake.sql_failure = b"MODIFY REPLICA ON"
        code, _, error = self.invoke(self.args())
        self.assertEqual(code, 1)
        self.assertIn("sql: injected SQL failure", error)
        manifest = lab.load_manifest(self.directory)
        self.assertEqual((manifest["state"], manifest["stage"]), ("failed", "bootstrap"))
        self.assertEqual([node["native_replica_id"] for node in manifest["nodes"]], self.fake.native_replicas)
        self.assertFalse(self.fake.sync_checks)
        self.assertFalse((self.directory / "convergence.json").exists())
        self.assertEqual(len(self.fake.objects["volume"]), 3)

    def test_invalid_lease_acknowledgement_is_not_reported_or_accepted(self):
        self.fake.lease_ack = b"raw-secret-batch"
        code, output, error = self.invoke(self.args())
        self.assertEqual(code, 1)
        self.assertIn("not acknowledged", error)
        self.assertNotIn("raw-secret-batch", output + error)
        self.assertEqual(lab.load_manifest(self.directory)["state"], "failed")

    def test_native_ids_reject_extra_non_guid_output_without_leaking_it(self):
        self.fake.native_id_response = b"raw-secret-batch"
        code, output, error = self.invoke(self.args())
        self.assertEqual(code, 1)
        self.assertIn("GUID-only", error)
        self.assertNotIn("raw-secret-batch", output + error)
        manifest = lab.load_manifest(self.directory)
        self.assertEqual((manifest["state"], manifest["stage"]), ("failed", "bootstrap"))
        self.assertEqual(manifest["native_group_id"], "")
        self.assertFalse(any(b"KUBERIC_LAB_LEASE_RENEWED" in (call["data"] or b"") for call in self.fake.calls))

    def test_native_ids_reject_duplicate_replicas(self):
        self.fake.native_replicas[2] = self.fake.native_replicas[0]
        code, _, error = self.invoke(self.args())
        self.assertEqual(code, 1)
        self.assertIn("duplicate GUIDs", error)
        self.assertEqual(lab.load_manifest(self.directory)["state"], "failed")

    def test_synchronization_has_one_bounded_setup_deadline(self):
        clock = [0.0]

        def advance(seconds):
            clock[0] += seconds

        self.fake.sync_sequences = {f"replica-{index}": [False] * 10 for index in range(3)}
        self.fake.advance_clock = advance
        self.fake.sync_delay = 10
        with mock.patch.object(lab.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(lab.time, "sleep", side_effect=advance):
            code, _, error = self.invoke(self.args("--ready-timeout", "30"))
        self.assertEqual(code, 1)
        self.assertIn("deadline", error)
        self.assertEqual(clock[0], 30)
        manifest = lab.load_manifest(self.directory)
        self.assertEqual((manifest["state"], manifest["stage"]), ("failed", "bootstrap"))
        self.assertFalse((self.directory / "convergence.json").exists())

    def test_old_receipts_remain_usable_for_exact_cleanup(self):
        self.create()

        def old_receipt(manifest):
            manifest.pop("native_group_id")
            manifest["bootstrap_ag"] = False
            for node in manifest["nodes"]:
                node.pop("native_replica_id")

        self.mutate_manifest(old_receipt)
        code, _, error = self.invoke(["destroy", "--directory", str(self.directory), "--destroy-data"])
        self.assertEqual(code, 0, error)
        self.assertFalse(self.fake.objects["container"])
        self.assertEqual(lab.load_manifest(self.directory)["state"], "destroyed")

    def test_planned_and_forced_fixtures_have_independent_ownership_and_incarnations(self):
        planned, _ = self.create()
        forced_directory = self.root / "forced"
        self.directories.insert(1, forced_directory)
        self.files.update({forced_directory / "lab.lock", forced_directory / "ha-lab.json"})
        args = self.args("--first-port", "16433")
        args[args.index("--directory") + 1] = str(forced_directory)
        self.fake.native_group = str(uuid.uuid4())
        self.fake.native_replicas = [str(uuid.uuid4()) for _ in range(3)]
        code, _, error = self.invoke(args)
        self.assertEqual(code, 0, error)
        forced = lab.load_manifest(forced_directory)
        self.assertNotEqual(planned["owner_id"], forced["owner_id"])
        self.assertNotEqual(planned["native_group_id"], forced["native_group_id"])
        planned_ids = {node["container_id"] for node in planned["nodes"]}
        forced_ids = {node["container_id"] for node in forced["nodes"]}
        self.assertFalse(planned_ids & forced_ids)
        self.assertEqual([node["port"] for node in forced["nodes"]], [16433, 16434, 16435])
        code, _, error = self.invoke(["destroy", "--directory", str(self.directory), "--destroy-data"])
        self.assertEqual(code, 0, error)
        self.assertEqual(set(self.fake.objects["container"]), forced_ids)
        code, _, error = self.invoke(["inspect", "--directory", str(forced_directory)])
        self.assertEqual(code, 0, error)

    def test_daemon_and_context_endpoint_changes_prevent_cleanup(self):
        self.create()
        previous_deletions = list(self.fake.deleted)
        for field, value in (("engine", "other-engine"), ("endpoint", "unix:///other/docker.sock")):
            with self.subTest(field=field):
                previous = getattr(self.fake, field)
                setattr(self.fake, field, value)
                code, _, error = self.invoke(["destroy", "--directory", str(self.directory), "--destroy-data"])
                self.assertEqual(code, 1)
                self.assertIn("changed", error)
                self.assertEqual(self.fake.deleted, previous_deletions)
                setattr(self.fake, field, previous)

    def test_every_resource_is_validated_before_first_cleanup_mutation(self):
        manifest, _ = self.create()
        previous_deletions = list(self.fake.deleted)
        changed = self.fake.resource("container", manifest["nodes"][-1]["container_id"])
        changed["labels"][lab.OWNER_LABEL] = str(uuid.uuid4())
        code, _, error = self.invoke(["destroy", "--directory", str(self.directory), "--destroy-data"])
        self.assertEqual(code, 1)
        self.assertIn("ownership", error)
        self.assertEqual(self.fake.deleted, previous_deletions)
        self.assertEqual(lab.load_manifest(self.directory)["state"], "destroy_failed")

    def test_reused_container_name_and_volume_creation_identity_are_refused(self):
        manifest, _ = self.create()
        previous_deletions = list(self.fake.deleted)
        identity = manifest["nodes"][0]["container_id"]
        original = self.fake.objects["container"].pop(identity)
        changed = copy.deepcopy(original)
        changed["id"] = "f" * 64
        self.fake.objects["container"][changed["id"]] = changed
        code, _, error = self.invoke(["destroy", "--directory", str(self.directory)])
        self.assertEqual(code, 1)
        self.assertIn("replaced/reused", error)
        del self.fake.objects["container"][changed["id"]]
        self.fake.objects["container"][identity] = original
        volume = self.fake.resource("volume", manifest["volumes"][0]["name"])
        volume["created_at"] = "replacement-volume"
        code, _, error = self.invoke(["destroy", "--directory", str(self.directory), "--destroy-data"])
        self.assertEqual(code, 1)
        self.assertIn("replaced/reused", error)
        self.assertEqual(self.fake.deleted, previous_deletions)

    def test_unregistered_network_attachment_blocks_cleanup(self):
        manifest, _ = self.create()
        self.fake.resource("network", manifest["network"]["id"])["containers"]["f" * 64] = {"Name": "unrelated"}
        previous = list(self.fake.deleted)
        code, _, error = self.invoke(["destroy", "--directory", str(self.directory)])
        self.assertEqual(code, 1)
        self.assertIn("unregistered", error)
        self.assertEqual(self.fake.deleted, previous)

    def test_normalized_network_name_still_requires_exact_network_id(self):
        manifest, _ = self.create()
        network = manifest["network"]
        container = self.fake.resource("container", manifest["nodes"][0]["container_id"])
        container["network_mode"] = network["name"]
        code, _, error = self.invoke(["inspect", "--directory", str(self.directory)])
        self.assertEqual(code, 0, error)
        container["networks"][network["name"]]["NetworkID"] = "f" * 64
        code, _, error = self.invoke(["inspect", "--directory", str(self.directory)])
        self.assertEqual(code, 1)
        self.assertIn("network incarnation", error)

    def test_failed_inspect_or_inventory_is_not_absence(self):
        self.create()
        previous = list(self.fake.deleted)
        for command in (["container", "inspect"], ["container", "ls"], ["volume", "ls"], ["network", "ls"]):
            with self.subTest(command=command):
                self.fake.failure = lambda argv: argv[3:5] == command
                code, output, error = self.invoke(["destroy", "--directory", str(self.directory), "--destroy-data"])
                self.assertEqual(code, 1)
                self.assertEqual(output, "")
                self.assertIn("injected command failure", error)
                self.assertEqual(self.fake.deleted, previous)

    def test_genuine_absence_is_positively_enumerated(self):
        manifest, _ = self.create()
        node = manifest["nodes"][0]
        del self.fake.objects["container"][node["container_id"]]
        network = self.fake.resource("network", manifest["network"]["id"])
        del network["containers"][node["container_id"]]
        code, output, error = self.invoke(["inspect", "--directory", str(self.directory)])
        self.assertEqual(code, 0, error)
        self.assertFalse(json.loads(output)["nodes"][0]["present"])
        self.assertTrue(any(call["argv"][3:6] == ["container", "ls", "--all"] for call in self.fake.calls))

    def test_destroy_retains_data_then_removes_only_exact_owned_volumes(self):
        manifest, _ = self.create()
        unrelated = {"name": "unrelated-data", "labels": {lab.OWNER_LABEL: "another-owner"},
                     "driver": "local", "created_at": "not-owned", "scope": "local", "options": {}}
        self.fake.objects["volume"]["unrelated-data"] = unrelated
        code, output, error = self.invoke(["destroy", "--directory", str(self.directory)])
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(output)["state"], "destroyed_data_retained")
        self.assertEqual(len(self.fake.objects["volume"]), 4)
        self.assertFalse(self.fake.objects["container"])
        self.assertFalse(self.fake.objects["network"])
        code, output, error = self.invoke(["destroy", "--directory", str(self.directory), "--destroy-data"])
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(output)["state"], "destroyed")
        self.assertEqual(set(self.fake.objects["volume"]), {"unrelated-data"})
        self.assertEqual({identity for kind, identity in self.fake.deleted if kind == "volume"},
                         {item["name"] for item in manifest["volumes"]})
        self.assertTrue((self.directory / "owner-id").exists())
        self.assertTrue((self.directory / "ha-lab.json").exists())
        self.assertTrue((self.directory / "ca.key").exists())
        for call in self.fake.calls:
            self.assertNotIn("prune", call["argv"])
            self.assertNotIn("-v", call["argv"])
            self.assertNotIn("--volumes", call["argv"])
        code, _, error = self.invoke(["destroy", "--directory", str(self.directory), "--destroy-data"])
        self.assertEqual(code, 0, error)

    def test_lost_create_response_retains_intent_and_recovers_exact_owned_id(self):
        self.fake.lost_container_response = True
        code, _, error = self.invoke(self.args())
        self.assertEqual(code, 1)
        self.assertIn("lost creation response", error)
        manifest = lab.load_manifest(self.directory)
        self.assertEqual((manifest["state"], manifest["stage"]), ("failed", "containers"))
        self.assertEqual(manifest["helpers"][0]["container_id"], "")
        self.assertTrue(manifest["network"]["id"])
        self.assertEqual(len(self.fake.objects["container"]), 1)
        orphan_id = next(iter(self.fake.objects["container"]))
        code, _, error = self.invoke(["destroy", "--directory", str(self.directory), "--destroy-data"])
        self.assertEqual(code, 0, error)
        self.assertIn(("container", orphan_id), self.fake.deleted)
        self.assertEqual(lab.load_manifest(self.directory)["helpers"][0]["container_id"], orphan_id)

    def test_partial_destroy_failure_preserves_identity_for_explicit_retry(self):
        manifest, _ = self.create()
        self.fake.failure = lambda argv: argv[3:5] == ["volume", "rm"]
        code, _, error = self.invoke(["destroy", "--directory", str(self.directory), "--destroy-data"])
        self.assertEqual(code, 1)
        self.assertIn("injected command failure", error)
        failed = lab.load_manifest(self.directory)
        self.assertEqual(failed["state"], "destroy_failed")
        self.assertEqual(failed["network"], manifest["network"])
        self.assertEqual(failed["volumes"], manifest["volumes"])
        self.assertFalse(self.fake.objects["container"])
        self.assertFalse(self.fake.objects["network"])
        self.fake.failure = None
        code, _, error = self.invoke(["destroy", "--directory", str(self.directory), "--destroy-data"])
        self.assertEqual(code, 0, error)
        self.assertFalse(self.fake.objects["volume"])

    def test_pending_name_cannot_adopt_resource_with_wrong_creation_token(self):
        self.fake.lost_container_response = True
        self.invoke(self.args())
        orphan = next(iter(self.fake.objects["container"].values()))
        orphan["labels"][lab.TOKEN_LABEL] = str(uuid.uuid4())
        code, _, error = self.invoke(["destroy", "--directory", str(self.directory), "--destroy-data"])
        self.assertEqual(code, 1)
        self.assertIn("ownership", error)
        self.assertEqual(self.fake.deleted, [])

    def test_manifest_tampering_and_symlinked_manifest_are_refused_without_docker(self):
        self.create()
        original = lab.read_private(self.directory / "ha-lab.json")
        callbacks = [
            lambda m: m["nodes"][0].update(container_name="somebody-elses-container"),
            lambda m: m["nodes"][0].update(observer_config="/etc/passwd"),
            lambda m: m.update(owner_id=str(uuid.uuid4())),
            lambda m: m.update(directory="/some/other/directory"),
            lambda m: m.update(version=2),
        ]
        for callback in callbacks:
            with self.subTest(callback=callback):
                lab.save_manifest(self.directory, json.loads(original))
                self.mutate_manifest(callback)
                count = len(self.fake.calls)
                code, _, _ = self.invoke(["destroy", "--directory", str(self.directory), "--destroy-data"])
                self.assertEqual(code, 1)
                self.assertEqual(len(self.fake.calls), count)
        manifest_path = self.directory / "ha-lab.json"
        manifest_path.unlink()
        manifest_path.symlink_to(self.directory / "owner-id")
        count = len(self.fake.calls)
        code, _, error = self.invoke(["inspect", "--directory", str(self.directory)])
        self.assertEqual(code, 1)
        self.assertIn("symlink", error)
        self.assertEqual(len(self.fake.calls), count)

    def test_wrong_file_permissions_are_refused(self):
        self.create()
        path = self.directory / "owner-id"
        path.chmod(0o644)
        code, _, error = self.invoke(["inspect", "--directory", str(self.directory)])
        self.assertEqual(code, 1)
        self.assertIn("0600", error)
        path.chmod(0o600)

    def test_missing_bundled_sqlcmd_is_clear_and_leaves_owned_failed_state(self):
        self.fake.failure = lambda argv: "/usr/bin/test" in argv and lab.SQLCMD in argv
        code, output, error = self.invoke(self.args())
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertIn(lab.SQLCMD, error)
        self.assertIn("no download", error)
        manifest = lab.load_manifest(self.directory)
        self.assertEqual(manifest["state"], "failed")
        self.assertTrue(manifest["nodes"][0]["container_id"])

    def test_daemon_failure_during_tools_probe_is_not_mislabeled(self):
        def fail_after_sql_start(argv):
            return argv[3:4] == ["info"] and any(
                item["labels"][lab.ROLE_LABEL] == "sqlserver" and item["state"] == "running"
                for item in self.fake.objects["container"].values()
            )

        self.fake.failure = fail_after_sql_start
        code, _, error = self.invoke(self.args())
        self.assertEqual(code, 1)
        self.assertIn("docker: injected command failure", error)
        self.assertNotIn("must bundle", error)
        self.assertEqual(lab.load_manifest(self.directory)["state"], "failed")

    def test_wrong_image_architecture_fails_closed(self):
        self.fake.image_architecture = "arm64"
        code, _, error = self.invoke(self.args())
        self.assertEqual(code, 1)
        self.assertIn("AMD64", error)
        self.assertFalse(self.fake.created)
        self.assertEqual(lab.load_manifest(self.directory)["state"], "failed")

    def test_image_declared_unmanaged_volumes_are_refused(self):
        self.fake.image_volumes = {"/unowned": {}}
        code, _, error = self.invoke(self.args())
        self.assertEqual(code, 1)
        self.assertIn("anonymous volumes", error)
        self.assertFalse(self.fake.created)

    def test_tls_key_permission_check_failure_stops_provisioning(self):
        self.fake.permissions = b"0:0:644\n0:0:755\n"
        code, _, error = self.invoke(self.args())
        self.assertEqual(code, 1)
        self.assertIn("private-key ownership", error)
        self.assertEqual(lab.load_manifest(self.directory)["state"], "failed")
        self.assertFalse(any(lab.SQLCMD in call["argv"] for call in self.fake.calls))

    def test_readiness_is_bounded_and_never_treats_sql_failure_as_success(self):
        self.fake.fail_sql = True
        ticks = itertools.count(0, 20)
        with mock.patch.object(lab.time, "monotonic", side_effect=lambda: next(ticks)), \
                mock.patch.object(lab.time, "sleep") as sleep:
            code, _, error = self.invoke(self.args("--ready-timeout", "30"))
        self.assertEqual(code, 1)
        self.assertIn("deadline", error)
        self.assertEqual(lab.load_manifest(self.directory)["state"], "failed")
        self.assertLessEqual(sleep.call_count, 1)

    def test_readiness_deadline_also_bounds_docker_identity_checks(self):
        manifest, _ = self.create("--ready-timeout", "30")
        manager = lab.Laboratory(self.directory, manifest, self.fake)
        sql_calls = sum(call["operation"] == "sql" for call in self.fake.calls)
        with mock.patch.object(lab.time, "monotonic", side_effect=[0, 0, 20, 40]), \
                self.assertRaises(lab.LabError) as result:
            manager.wait(manifest["nodes"][0], "SELECT N'KUBERIC_LAB_READY';", login_retry=True)
        self.assertIn("deadline", str(result.exception))
        self.assertEqual(self.fake.calls[-1]["argv"][3:5], ["context", "inspect"])
        self.assertEqual(self.fake.calls[-1]["timeout"], 10)
        self.assertEqual(sum(call["operation"] == "sql" for call in self.fake.calls), sql_calls)
        self.assertIsNone(manager.docker.deadline_at)

    def test_disappearing_resources_cannot_be_published_as_ready(self):
        original = lab.Laboratory.verify_all

        def disappear(manager):
            evidence = original(manager)
            evidence["nodes"][0] = None
            return evidence

        with mock.patch.object(lab.Laboratory, "verify_all", disappear):
            code, _, error = self.invoke(self.args())
        self.assertEqual(code, 1)
        self.assertIn("ready checkpoint", error)
        self.assertEqual(lab.load_manifest(self.directory)["state"], "failed")
        self.assertFalse((self.directory / "convergence.json").exists())

    def test_malformed_private_text_does_not_echo_credential_bytes(self):
        path = self.root / "bad-credential"
        lab.write_private(path, b"\xffdo-not-echo-private-content")
        with self.assertRaises(lab.LabError) as result:
            lab.private_text(path)
        self.assertNotIn("do-not-echo", str(result.exception))

    def test_daemon_failure_during_readiness_is_not_retried_as_sql_failure(self):
        self.create()
        manifest = lab.load_manifest(self.directory)
        manager = lab.Laboratory(self.directory, manifest, self.fake)
        self.fake.failure = lambda argv: argv[3:4] == ["info"]
        with mock.patch.object(lab.time, "sleep") as sleep, self.assertRaises(lab.CommandError) as result:
            manager.wait(manifest["nodes"][0], "SELECT N'KUBERIC_LAB_READY';", login_retry=True)
        self.assertEqual(result.exception.operation, "docker")
        sleep.assert_not_called()

    def test_real_executor_suppresses_sql_output_and_timeout_details(self):
        secret = b"CREATE LOGIN x WITH PASSWORD='do-not-display-this'"
        executor = lab.Executor()
        with mock.patch.object(lab.subprocess, "run", return_value=subprocess.CompletedProcess(
            ["docker"], 1, secret, secret
        )) as run, self.assertRaises(lab.CommandError) as result:
            executor.run(["docker", "--context", "owned-lab"], operation="sql", data=secret)
        self.assertNotIn(secret.decode(), str(result.exception))
        kwargs = run.call_args.kwargs
        self.assertFalse(kwargs.get("shell", False))
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(kwargs["umask"], 0o077)
        with mock.patch.object(lab.subprocess, "run", side_effect=subprocess.TimeoutExpired(
            ["secret-command"], 1, output=secret, stderr=secret
        )), self.assertRaises(lab.CommandError) as result:
            executor.run(["docker"], operation="sql")
        self.assertNotIn(secret.decode(), str(result.exception))

    def test_real_dependency_detection_and_filesystem_failure_are_not_masked(self):
        with mock.patch.object(lab.shutil, "which", return_value=None), self.assertRaises(lab.LabError):
            lab.Executor().program("openssl")
        with mock.patch.object(lab.subprocess, "run", side_effect=FileNotFoundError("secret-text")), \
                self.assertRaises(lab.CommandError) as result:
            lab.Executor().run(["missing"], operation="docker")
        self.assertNotIn("secret-text", str(result.exception))


if __name__ == "__main__":
    unittest.main()
