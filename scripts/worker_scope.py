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
        properties = {"name": {"type": "string", "enum": ["cas-worker-01", "rcc-worker-01"]}}
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
                    "Submit one approved owner-scoped lifecycle job using the verified Codex worker image built from main, with a blank /workspaces directory and no CAS checkout. Clone engineering repositories into separate workspaces after readiness. Poll workspace_status_scoped; never replay an uncertain job."
                    if mutation
                    else "Read and reconcile the owner scope job without provisioning. Only new_request_allowed=true permits one fresh create request ID; never replay an old ID."
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
    def __init__(self, config, state, inventory, metadata, invoke, absence=None,
                 source_resolver=None):
        self.config = Path(config)
        self.state = Path(state)
        self.inventory, self.metadata, self.invoke = inventory, metadata, invoke
        self.absence = absence
        self.source_resolver = source_resolver
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

    @staticmethod
    def source_matches(row, execution):
        source = row.get("source", {})
        if execution.get("source_kind") == "image":
            return (source.get("image") == execution["image_ref"] + "@" + execution["image_digest"]
                    and not source.get("gitRepository")
                    and not row.get("devContainerPath"))
        return (source.get("gitRepository") == execution["repository"]
                and source.get("gitCommit") == execution["revision"]
                and row.get("devContainerPath") == execution["recipe"])

    def verified_row(self, name, scope, expected_uid=None):
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
            or not self.source_matches(row, self.execution_context(self.read(name), scope))
            or not isinstance(row.get("uid"), str)
            or (expected_uid is not None and row["uid"] != expected_uid)
        ):
            raise ScopeError("Workspace identity or provider scope changed.")
        return row

    def verified(self, name, scope, expected_uid=None):
        return self.verified_row(name, scope, expected_uid)["uid"]

    def execution_context(self, record, scope):
        """Validate a job's pinned source against policy, retaining legacy pins."""
        context = record.get("execution_context") if isinstance(record, dict) else None
        if (not isinstance(context, dict)
                or context.get("repository") != scope["repository"]
                or context.get("recipe") != ("Containerfile.worker" if context.get("source_kind") == "image"
                                             else ".devcontainer/remote-worker/devcontainer.json")
                or not re.fullmatch(r"[a-f0-9]{40}", context.get("revision", ""))
                or ("source_ref" in context and context["source_ref"] != scope["source_ref"])
                or ("recipe_sha256" in context
                    and not re.fullmatch(r"[a-f0-9]{64}", context.get("recipe_sha256", "")))):
            raise ScopeError("Recorded worker source snapshot is invalid.")
        if context.get("source_kind") == "image":
            digest = context.get("image_digest", "")
            if (not re.fullmatch(r"sha256:[a-f0-9]{64}", digest)
                    or context.get("image_ref") != "ghcr.io/joshyorko/codex-action-server"):
                raise ScopeError("Recorded worker image snapshot is invalid.")
        elif context.get("source_kind") not in {None, "git"}:
            raise ScopeError("Recorded worker source kind is invalid.")
        return dict(context)

    def pin_identity(self, record, uid):
        """An operation may observe one UID, including while provisioning runs."""
        key = "identity-" + hashlib.sha256(record["operation_id"].encode()).hexdigest()
        wanted = {"name": record["name"], "operation_id": record["operation_id"], "workspace_uid": uid}
        fd = os.open(self.state / "identity.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise ScopeError("Unsafe workspace identity lock.")
            fcntl.flock(fd, fcntl.LOCK_EX)
            prior = self.read(key)
            if prior is not None and prior != wanted:
                raise ScopeError("Scoped workspace identity changed; no adoption or rebind.")
            if prior is None:
                self.write(key, wanted)
        finally:
            os.close(fd)

    def owned_workspace(self, name, uid, credential):
        scope = self.authenticate(credential)
        if name not in scope["allowed_new_names"] or name in scope["protected_names"]:
            raise ScopeError("Workspace is outside the approved diagnostic scope.")
        self.root()
        record = self.read(name)
        if (not record or record.get("operation") not in {"create", "start"}
                or record.get("status") not in {"running", "completed", "outcome_unknown"}
                or not isinstance(record.get("operation_id"), str)):
            raise ScopeError("Diagnostics require an admitted scoped workspace operation.")
        if record.get("workspace_uid") and record["workspace_uid"] != uid:
            raise ScopeError("Scoped workspace identity changed; no remote command ran.")
        pin = self.read("identity-" + hashlib.sha256(record["operation_id"].encode()).hexdigest())
        if record["status"] == "outcome_unknown" and not pin and not record.get("workspace_uid"):
            raise ScopeError("Unknown operation has no recorded workspace identity; operator reconciliation required.")
        row = self.verified_row(name, scope, uid)
        kubeconfig = row["provider"]["options"].get("KUBERNETES_CONFIG", {}).get("value")
        execution = self.execution_context(record, scope)
        if (not self.source_matches(row, execution)
                or kubeconfig not in scope.get("bindings", {})):
            raise ScopeError("Workspace source, recipe, or cluster identity changed.")
        self.pin_identity(record, row["uid"])
        current = self.read(name)
        if not current or current.get("operation_id") != record["operation_id"]:
            raise ScopeError("Workspace operation changed during identity verification.")
        return {"context": scope["context"], "provider": scope["provider"], "workspace": name,
                "workspace_uid": row["uid"], "kubernetes_context": scope["kubernetes_context"],
                "namespace": scope["namespace"], "kubeconfig": kubeconfig,
                "repository": execution["repository"], "revision": execution["revision"],
                "recipe": execution["recipe"],
                "operation_id": record["operation_id"],
                **{key: execution[key] for key in ("source_kind", "image_ref", "image_digest") if key in execution}}

    def worker_authorized(self, name, uid, operation_id):
        """Private-network policy probe; no credentials, provider calls, or writes."""
        try:
            scope = self.load()
            if name not in scope["allowed_new_names"] or name in scope["protected_names"]:
                return False
            record = self.read(name)
            if (not record or record.get("operation_id") != operation_id
                    or record.get("status") not in {"running", "completed", "outcome_unknown"}):
                return False
            pin = self.read("identity-" + hashlib.sha256(operation_id.encode()).hexdigest())
            return pin == {"name": name, "operation_id": operation_id, "workspace_uid": uid}
        except Exception:
            return False

    def reconcile(self, record, scope):
        """An absence proof permits a new intent, never replay of this operation."""
        if record.get("operation") != "create":
            return record
        if self.absence is None and record.get("new_request_allowed") is not True:
            return record
        retiring = record["status"] in {"completed", "retired"}
        previous_status = record["status"]
        if retiring:
            record.setdefault("retired_receipt", dict(record))
        record.setdefault("unreconciled_receipt", dict(record))
        record["new_request_allowed"] = False
        record["retry_safe"] = False
        try:
            cutoffs = [record.get(key) for key in (
                "accepted_at", "started_at", "grant_issued_at", "recovery_cutoff")]
            cutoffs = [value for value in cutoffs if not isinstance(value, bool)
                       and isinstance(value, (int, float)) and math.isfinite(value)
                       and 0 < value <= time.time()]
            # A later capability renewal must not hide this operation's remnants.
            proof_scope = {**scope, "recovery_cutoff": min(cutoffs) if cutoffs else None}
            siblings = {}
            for sibling in scope["allowed_new_names"]:
                if sibling == record["name"]:
                    continue
                sibling_record = self.read(sibling)
                if not sibling_record or sibling_record.get("status") != "completed":
                    continue
                sibling_uid = sibling_record.get("workspace_uid")
                row = self.verified_row(sibling, scope, sibling_uid)
                execution = self.execution_context(sibling_record, scope)
                if (not self.source_matches(row, execution)
                        or row["provider"]["options"].get("KUBERNETES_CONFIG", {}).get("value") not in scope.get("bindings", {})):
                    raise ScopeError("Sibling source or provider binding changed.")
                siblings[sibling] = sibling_uid
            proof_scope["verified_siblings"] = siblings
            evidence = self.absence(record["name"], proof_scope)
            if (not isinstance(evidence, dict) or evidence.get("kind") != "absent"
                    or any(evidence.get(key) is not True for key in (
                        "workspace_absent", "provider_resources_absent", "lifecycle_processes_absent"))
                    or evidence.get("namespace") != scope["namespace"]
                    or evidence.get("kubernetes_context") != scope["kubernetes_context"]
                    or not isinstance(evidence.get("namespace_uid"), str)
                    or not evidence["namespace_uid"]):
                raise ScopeError("Complete provider absence proof required.")
            self.load()  # Revocation or configuration drift during checks denies recovery.
            record["reconciliation"] = {key: evidence[key] for key in (
                "kind", "observed_at", "namespace_uid", "namespace", "kubernetes_context",
                "workspace_absent", "provider_resources_absent", "lifecycle_processes_absent")}
            for key in ("preexisting_auxiliary_count", "recovery_cutoff"):
                if key in evidence:
                    record["reconciliation"][key] = evidence[key]
            record["status"] = "retired" if retiring else "failed"
            record["error_code"] = "workspace_retired" if retiring else "lifecycle_reconciled_absent"
            record["new_request_allowed"] = True
            record["next_action"] = "Submit workspace_create_scoped once with a fresh request_id. Old request IDs never replay."
        except Exception as error:
            record["status"] = previous_status if retiring else "outcome_unknown"
            record["error_code"] = "retirement_not_verified" if retiring else "lifecycle_outcome_unknown"
            phase = getattr(error, "phase", None)
            if phase not in {"configuration", "processes", "tasks", "inventory", "namespace",
                             "resources", "auxiliary_resources", "volumes", "recheck"}:
                phase = "validation"
            record["reconciliation"] = {"kind": "blocked", "error_code": "absence_not_proven", "phase": phase}
            record.pop("next_action", None)
        self.write(record["name"], record)
        return record

    def archived_request(self, name, request_id):
        for path in self.state.glob("history-*.json"):
            record = private_json(path)
            if record.get("name") == name and record.get("request_id") == request_id:
                return {**record, "new_request_allowed": False, "retry_safe": False, "replayed_receipt": True}
        return None

    def migrate_legacy_creation(self, *, receipts, name, operation_id, fingerprint,
                                source, workspace_uid, created_at, credential):
        """Operator-only migration; never provisions or relaxes duplicate admission.

        Source and UID are historical operator evidence, not adopted workspace
        identity. The original receipt and fresh absence proof remain durable.
        Run with the bridge stopped while extending its approved name scope.
        """
        scope = self.authenticate(credential)
        if (name != "rcc-worker-01" or name not in scope["allowed_new_names"]
                or name in scope["protected_names"]
                or source != "git:https://github.com/joshyorko/rcc.git"
                or not isinstance(workspace_uid, str)
                or not re.fullmatch(r"default-rc-[a-z0-9]+", workspace_uid)
                or not isinstance(fingerprint, str) or not re.fullmatch(r"[a-f0-9]{64}", fingerprint)
                or not isinstance(operation_id, str)
                or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", operation_id)
                or isinstance(created_at, bool) or not isinstance(created_at, (int, float))
                or not math.isfinite(created_at) or not 0 < created_at < time.time()):
            raise ScopeError("Legacy migration identity or cutoff refused.")
        self.root()
        receipts.private_root()
        key, _ = receipts.key({"name": name})
        with self.mutex:
            descriptors = []
            try:
                for path in (self.state / "admission.lock", receipts.state / (key + ".lock")):
                    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
                    descriptors.append(fd)
                    info = os.fstat(fd)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                            or stat.S_IMODE(info.st_mode) != 0o600):
                        raise ScopeError("Unsafe migration lock.")
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                legacy_path = receipts.state / (key + ".json")
                stored = receipts.read(legacy_path)
                original = stored.get("original_receipt", stored) if stored else None
                if (not original or original.get("name") != name
                        or original.get("operation_id") != operation_id
                        or original.get("fingerprint") != fingerprint
                        or original.get("status") != "outcome_unknown"):
                    raise ScopeError("Legacy receipt does not match migration evidence.")
                record = self.read(name)
                evidence = {"source": source, "workspace_uid": workspace_uid, "created_at": created_at}
                if record and (record.get("operation_id") != operation_id
                               or record.get("legacy_receipt") != original
                               or record.get("legacy_identity") != evidence):
                    raise ScopeError("Existing scoped record prevents legacy migration.")
                if not record:
                    record = {"name": name, "operation_id": operation_id, "operation": "create",
                              "request_id": "legacy-" + operation_id, "status": "outcome_unknown",
                              "retry_safe": False, "new_request_allowed": False,
                              "accepted_at": created_at, "legacy_receipt": original,
                              "legacy_identity": evidence}
                    self.write(name, record)
                record = self.reconcile(record, scope)
                if record.get("new_request_allowed") is True:
                    self.archive(record)
                    receipts.write(legacy_path, {**original, "status": "reconciled_scoped",
                        "original_receipt": original, "scoped_operation_id": operation_id,
                        "reconciliation": record["reconciliation"]})
                return record
            finally:
                for fd in reversed(descriptors):
                    os.close(fd)

    def archive(self, record):
        key = "history-" + hashlib.sha256(record["operation_id"].encode()).hexdigest()
        prior = self.read(key)
        if prior is None:
            self.write(key, record)
        elif (prior.get("operation_id"), prior.get("request_id")) != (record["operation_id"], record["request_id"]):
            raise ScopeError("Conflicting lifecycle history; recovery refused.")

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
                if mutation:
                    archived = self.archived_request(name, arguments["request_id"])
                    if archived:
                        return archived
                if (
                    record
                    and record["status"] in {"accepted", "running"}
                    and not (active and active.is_alive())
                ):
                    record["status"] = "outcome_unknown"
                    record["retry_safe"] = False
                    record["error_code"] = "lifecycle_outcome_unknown"
                    record["finished_at"] = time.time()
                    record["diagnostics"] = {
                        **record.get("diagnostics", {}),
                        "phase": "worker_lost",
                    }
                    self.write(name, record)
                if not mutation:
                    if (record and record["status"] in {"outcome_unknown", "failed", "retired"}
                            and not (active and active.is_alive())):
                        record = self.reconcile(record, scope)
                    result = record or {"name": name, "status": "not_submitted"}
                    if record and record.get("workspace_uid"):
                        result = {**record, "identity_verified": False}
                        try:
                            self.verified(name, scope, record["workspace_uid"])
                            result["identity_verified"] = True
                        except Exception:
                            if record["status"] == "completed" and not (active and active.is_alive()):
                                record = self.reconcile(record, scope)
                                result = {**record, "identity_verified": False}
                    return result
                operation = "create" if tool == "workspace_create_scoped" else "start"
                recovered = None
                if operation == "create" and record:
                    if (active and active.is_alive() or record.get("request_id") == arguments["request_id"]
                            or record.get("new_request_allowed") is not True):
                        return record
                    record = self.reconcile(record, scope)
                    if record.get("new_request_allowed") is not True:
                        return record
                    recovered = record
                    record = None
                if record and record["status"] == "outcome_unknown":
                    return record
                if active and active.is_alive():
                    return record
                if operation == "create":
                    existing_names = self.inventory()
                    pending = sum(1 for sibling in scope["allowed_new_names"]
                                  if sibling != name and (self.read(sibling) or {}).get("status") in {"accepted", "running", "outcome_unknown"})
                    if pending >= scope["max_pending_creates"]:
                        raise ScopeError("Scoped pending creation limit reached.")
                    if len(existing_names) >= scope["max_active_workspaces"]:
                        raise ScopeError("Scoped workspace capacity reached.")
                    if name in existing_names:
                        raise ScopeError(
                            "Existing workspace is not owned by this creation receipt; no adoption or recreation."
                        )
                    expected_uid = None
                    if self.source_resolver is None:
                        raise ScopeError("Approved main source resolver is unavailable; no job submitted.")
                    try:
                        snapshot = self.source_resolver(scope)
                    except Exception:
                        raise ScopeError("Approved main source could not be resolved; no job submitted.") from None
                    if (not isinstance(snapshot, dict)
                            or snapshot.get("repository") != scope["repository"]
                            or snapshot.get("source_ref") != scope["source_ref"]
                            or snapshot.get("recipe") != scope["recipe"]
                            or not re.fullmatch(r"[a-f0-9]{40}", snapshot.get("revision", ""))
                            or not re.fullmatch(r"[a-f0-9]{64}", snapshot.get("recipe_sha256", ""))
                            or not isinstance(snapshot.get("recipe_snapshot"), bytes)
                            or len(snapshot["recipe_snapshot"]) > 1024 * 1024
                            or hashlib.sha256(snapshot["recipe_snapshot"]).hexdigest() != snapshot["recipe_sha256"]):
                        raise ScopeError("Approved main source snapshot is invalid; no job submitted.")
                    job_source = {key: snapshot[key] for key in (
                        "repository", "source_ref", "revision", "recipe", "recipe_sha256",
                        "source_kind", "image_ref", "image_digest") if key in snapshot}
                    if snapshot.get("source_kind") != scope.get("source_kind"):
                        raise ScopeError("New creation source kind differs from approved policy.")
                    self.execution_context({"execution_context": job_source}, scope)
                else:
                    if not record or not record.get("workspace_uid"):
                        raise ScopeError(
                            "Start requires a previously verified scoped workspace UID."
                        )
                    expected_uid = self.verified(name, scope, record["workspace_uid"])
                    if record.get("request_id") == arguments["request_id"]:
                        return record
                    job_source = self.execution_context(record, scope)
                if recovered:
                    self.archive(recovered)
                record = {
                    "name": name,
                    "operation_id": str(uuid.uuid4()),
                    "operation": operation,
                    "request_id": arguments["request_id"],
                    "accepted_at": time.time(),
                    "grant_issued_at": scope.get("issued_at"),
                    "status": "accepted",
                    "retry_safe": False,
                    "new_request_allowed": False,
                    "execution_context": {
                        key: scope[key]
                        for key in (
                            "context", "provider", "kubernetes_context", "namespace", "binary",
                        )
                        if key in scope
                    } | job_source,
                }
                if expected_uid:
                    record["workspace_uid"] = expected_uid
                self.write(name, record)
                accepted = dict(record)
                thread = threading.Thread(
                    target=self.run,
                    args=(record, scope, expected_uid,
                          snapshot.get("recipe_snapshot") if operation == "create" else None),
                    daemon=True,
                )
                self.threads[name] = thread
                thread.start()
                return accepted
            finally:
                os.close(fd)

    def run(self, record, scope, expected_uid, recipe_snapshot=None):
        name = record["name"]
        record["started_at"] = time.time()
        record["diagnostics"] = {"phase": "preflight", "devsy_invoked": False}
        try:
            record["status"] = "running"
            self.write(name, record)
            self.load()
            record["diagnostics"] = {"phase": "invoke", "devsy_invoked": None}
            self.write(name, record)
            job_scope = {**scope, "execution_context": record["execution_context"],
                         "operation_id": record["operation_id"]}
            if recipe_snapshot is not None:
                job_scope["recipe_snapshot"] = recipe_snapshot
            result = self.invoke(record["operation"], name, job_scope)
            if result is not None:
                record["diagnostics"].update(
                    {
                        key: result[key]
                        for key in ("phase", "exit_code", "devsy_invoked", "stderr_code")
                        if key in result
                    }
                )
            self.write(name, record)
            if result is not None and result.get("exit_code", 0) != 0:
                record["status"] = (
                    "failed"
                    if result.get("devsy_invoked") is False
                    else "outcome_unknown"
                )
            else:
                record["diagnostics"]["phase"] = "verify_workspace"
                self.write(name, record)
                uid = self.verified(name, scope, expected_uid)
                self.pin_identity(record, uid)
                record["workspace_uid"] = uid
                record["status"] = "completed"
        except Exception as exc:
            record["status"] = (
                "failed"
                if record["diagnostics"].get("devsy_invoked") is False
                else "outcome_unknown"
            )
            record["exception_type"] = type(exc).__name__
        if record["status"] != "completed":
            record["error_code"] = (
                "lifecycle_failed"
                if record["status"] == "failed"
                else "lifecycle_outcome_unknown"
            )
        record["finished_at"] = time.time()
        self.write(name, record)

    def wait(self):
        for thread in list(self.threads.values()):
            thread.join(5)
