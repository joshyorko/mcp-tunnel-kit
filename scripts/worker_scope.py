"""Owner-capability admission and durable, bounded workspace lifecycle jobs."""

import fcntl
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
import threading
import time
import uuid

MUTATIONS = {"workspace_create_scoped", "workspace_start_scoped"}
READS = {"workspace_status_scoped"}


class ScopeError(Exception):
    pass


def private_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as handle:
        info = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ScopeError(
                "Scope and job records must be private operator-owned files."
            )
        return json.load(handle)


def tools():
    result = []
    for tool in sorted(MUTATIONS | READS):
        mutation = tool in MUTATIONS
        properties = {"name": {"type": "string", "enum": ["cas-worker-01"]}}
        if mutation:
            properties["request_id"] = {
                "type": "string",
                "minLength": 1,
                "maxLength": 128,
            }
        result.append(
            {
                "name": tool,
                "description": (
                    "Submit one approved owner-scoped lifecycle job; poll workspace_status_scoped. Never replay an uncertain job."
                    if mutation
                    else "Read the approved owner scope job and verified workspace identity."
                ),
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": properties,
                    "required": list(properties),
                },
                "annotations": {
                    "readOnlyHint": not mutation,
                    "destructiveHint": mutation,
                    "openWorldHint": True,
                },
            }
        )
    return result


class WorkerScope:
    def __init__(self, config, state, inventory, metadata, invoke):
        self.config = Path(config)
        self.state = Path(state)
        self.inventory, self.metadata, self.invoke = inventory, metadata, invoke
        self.threads = {}
        self.mutex = threading.Lock()

    def load(self):
        value = private_json(self.config)
        expected = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "docs/devsy-worker-scope.proposed.json"
            ).read_text()
        )
        for key, want in expected.items():
            if key != "enabled" and value.get(key) != want:
                raise ScopeError("Approved lifecycle scope changed; call refused.")
        expiration = value.get("expires_at", 0)
        invalid_expiration = expiration is not None and (
            isinstance(expiration, bool)
            or not isinstance(expiration, (int, float))
            or not math.isfinite(expiration)
            or expiration <= time.time()
        )
        if value.get("enabled") is not True or invalid_expiration:
            raise ScopeError("Owner lifecycle capability is disabled or expired.")
        if not re.fullmatch("[a-f0-9]{64}", value.get("capability_sha256", "")):
            raise ScopeError("Owner capability is not configured.")
        for path, digest in value.get("bindings", {}).items():
            if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
                raise ScopeError("Approved provider or cluster configuration changed.")
        return value

    def authenticate(self, credential):
        scope = self.load()
        if not isinstance(credential, str) or not credential.startswith("Bearer "):
            raise ScopeError("Owner capability required.")
        actual = hashlib.sha256(credential[7:].encode()).hexdigest()
        if not hmac.compare_digest(actual, scope["capability_sha256"]):
            raise ScopeError("Owner capability refused.")
        return scope

    def root(self):
        self.state.mkdir(parents=True, mode=0o700, exist_ok=True)
        info = self.state.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ScopeError("Lifecycle state is not private and operator-owned.")

    def read(self, name):
        path = self.state / (name + ".json")
        return private_json(path) if path.exists() or path.is_symlink() else None

    def write(self, name, value):
        with tempfile.NamedTemporaryFile(
            mode="w", dir=self.state, delete=False
        ) as handle:
            path = Path(handle.name)
            try:
                json.dump(value, handle)
                handle.flush()
                os.fsync(handle.fileno())
                os.replace(path, self.state / (name + ".json"))
                fd = os.open(self.state, os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            finally:
                path.unlink(missing_ok=True)

    def verified(self, name, scope, expected_uid=None):
        row = self.metadata(name)
        provider = row.get("provider", {})
        options = provider.get("options", {})
        if (
            row.get("id") != name
            or row.get("context") != scope["context"]
            or provider.get("name") != scope["provider"]
            or options.get("KUBERNETES_CONTEXT", {}).get("value")
            != scope["kubernetes_context"]
            or options.get("KUBERNETES_NAMESPACE", {}).get("value")
            != scope["namespace"]
            or row.get("source", {}).get("gitRepository") != scope["repository"]
            or not isinstance(row.get("uid"), str)
            or (expected_uid is not None and row["uid"] != expected_uid)
        ):
            raise ScopeError("Workspace identity or provider scope changed.")
        return row["uid"]

    def call(self, tool, arguments, credential):
        scope = self.authenticate(credential)
        mutation = tool in MUTATIONS
        fields = {"name", "request_id"} if mutation else {"name"}
        if (
            tool not in MUTATIONS | READS
            or not isinstance(arguments, dict)
            or set(arguments) != fields
        ):
            raise ScopeError(
                "Scoped lifecycle accepts only its exact typed parameters."
            )
        name = arguments.get("name")
        if name not in scope["allowed_new_names"] or name in scope["protected_names"]:
            raise ScopeError("Workspace name is outside the approved scope.")
        if mutation and (
            not isinstance(arguments["request_id"], str)
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", arguments["request_id"])
        ):
            raise ScopeError("Invalid bounded lifecycle request ID.")
        self.root()
        with self.mutex:
            fd = os.open(
                self.state / "admission.lock",
                os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                0o600,
            )
            try:
                info = os.fstat(fd)
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                    raise ScopeError("Unsafe lifecycle admission lock.")
                fcntl.flock(fd, fcntl.LOCK_EX)
                record = self.read(name)
                active = self.threads.get(name)
                if (
                    record
                    and record["status"] in {"accepted", "running"}
                    and not (active and active.is_alive())
                ):
                    record["status"] = "outcome_unknown"
                    self.write(name, record)
                if not mutation:
                    result = record or {"name": name, "status": "not_submitted"}
                    if record and record.get("workspace_uid"):
                        result = {**record, "identity_verified": False}
                        try:
                            self.verified(name, scope, record["workspace_uid"])
                            result["identity_verified"] = True
                        except Exception:
                            pass
                    return result
                operation = "create" if tool == "workspace_create_scoped" else "start"
                if operation == "create" and record:
                    return record
                if active and active.is_alive():
                    return record
                if operation == "create":
                    if name in self.inventory():
                        raise ScopeError(
                            "Existing workspace is not owned by this creation receipt; no adoption or recreation."
                        )
                    expected_uid = None
                else:
                    if not record or not record.get("workspace_uid"):
                        raise ScopeError(
                            "Start requires a previously verified scoped workspace UID."
                        )
                    expected_uid = self.verified(name, scope, record["workspace_uid"])
                    if record.get("request_id") == arguments["request_id"]:
                        return record
                record = {
                    "name": name,
                    "operation_id": str(uuid.uuid4()),
                    "operation": operation,
                    "request_id": arguments["request_id"],
                    "status": "accepted",
                    "retry_safe": False,
                }
                if expected_uid:
                    record["workspace_uid"] = expected_uid
                self.write(name, record)
                accepted = dict(record)
                thread = threading.Thread(
                    target=self.run, args=(record, scope, expected_uid), daemon=True
                )
                self.threads[name] = thread
                thread.start()
                return accepted
            finally:
                os.close(fd)

    def run(self, record, scope, expected_uid):
        name = record["name"]
        try:
            self.load()
            record["status"] = "running"
            self.write(name, record)
            self.invoke(record["operation"], name, scope)
            record["workspace_uid"] = self.verified(name, scope, expected_uid)
            record["status"] = "completed"
        except Exception:
            record["status"] = "outcome_unknown"
            record["error_code"] = "lifecycle_outcome_unknown"
        self.write(name, record)

    def wait(self):
        for thread in list(self.threads.values()):
            thread.join(5)
