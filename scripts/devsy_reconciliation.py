"""Conservative read-only absence proof for the single approved worker scope.

The caller holds lifecycle admission and refuses active in-process jobs. Unknown
or partial provider state never becomes permission to submit another creation.
"""
from datetime import datetime
from decimal import Decimal
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid

PROC_ROOT = Path("/proc")
SAFE_ERROR = "Absence could not be established; operation remains non-retryable."
RESOURCES = ("pods,persistentvolumeclaims,jobs,deployments,statefulsets,daemonsets,"
             "replicasets,cronjobs,services,replicationcontrollers")
PHASES = frozenset({"configuration", "processes", "tasks", "inventory", "namespace", "resources",
                    "auxiliary_resources", "volumes", "recheck"})


class ReconciliationError(Exception):
    """Only a fixed public error; command output is never retained."""

    def __init__(self, phase="configuration"):
        super().__init__(SAFE_ERROR)
        self.phase = phase if phase in PHASES else "configuration"


def _refuse():
    raise ReconciliationError()


def _configuration(env, scope, name):
    if (name != "cas-worker-01" or name not in scope["allowed_new_names"]
            or name in scope.get("protected_names", []) or scope["provider"] != "kubernetes"):
        _refuse()
    kube = env.get("KUBECONFIG") or str(Path(env["HOME"]) / ".kube/config")
    if os.pathsep in kube or not Path(kube).is_absolute():
        _refuse()
    bindings = scope["bindings"]
    # Bind the exact selected path; a different ambient config cannot borrow trust.
    if kube not in bindings:
        _refuse()
    for path, digest in bindings.items():
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
            _refuse()
    return kube


def _processes_absent(binary):
    for process in PROC_ROOT.iterdir():
        if not process.name.isdigit():
            continue
        try:
            if process.stat().st_uid != os.getuid():
                continue
            argv = process.joinpath("cmdline").read_bytes().split(b"\0")
        except FileNotFoundError:
            continue  # A process that exited cannot submit new provider work.
        argv = [part.decode("utf-8", errors="replace") for part in argv if part]
        if not argv:
            continue
        child = "--scoped-child" in argv and any(Path(arg).name == "devsy_bridge.py" for arg in argv)
        native = Path(argv[0]).name in {Path(binary).name, "devsy"} and any(
            argv[index:index + 2] in (["workspace", "up"], ["workspace", "create"], ["workspace", "start"])
            for index in range(len(argv) - 1))
        if child or native:
            _refuse()


def _references(value, name):
    if isinstance(value, dict):
        return any(_references(item, name) for item in value.values())
    if isinstance(value, list):
        return any(_references(item, name) for item in value)
    return value == name


def _tasks_absent(env, name):
    home = Path(env.get("DEVSY_HOME") or str(Path(env["HOME"]) / ".devsy"))
    tasks = home / "state/tasks"
    if not tasks.exists():
        return
    for path in tasks.glob("*.json"):
        task = json.loads(path.read_text())
        if not isinstance(task, dict):
            _refuse()
        if _references(task, name) and task.get("status", "").lower() not in {
                "completed", "succeeded", "failed", "cancelled", "canceled"}:
            _refuse()


def _query(args, cwd, env, *, text_only=False):
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True,
                            timeout=10, check=False)
    if result.returncode:
        _refuse()
    return result.stdout if text_only else json.loads(result.stdout)


def _items(value):
    if (not isinstance(value, dict) or not isinstance(value.get("items"), list)
            or value.get("kind") == "Status" or "error" in value or value.get("isError")):
        _refuse()
    if any(not isinstance(item, dict) for item in value["items"]):
        _refuse()
    return value["items"]


def _preexisting_auxiliary(output, recovery_cutoff):
    """Only metadata predating the original operation can explain leftovers."""
    count = 0
    seen = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) != 4:
            _refuse()
        kind, name, uid, created = fields
        if (kind not in {"Secret", "ConfigMap", "Role", "RoleBinding", "ServiceAccount"}
                or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", name)
                or (kind, name) in seen):
            _refuse()
        seen.add((kind, name))
        if str(uuid.UUID(uid)) != uid:
            _refuse()
        match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)", created)
        if not match:
            _refuse()
        # Preserve sub-microsecond precision at the immutable operation boundary.
        whole = datetime.fromisoformat(match[1] + match[3].replace("Z", "+00:00")).timestamp()
        timestamp = Decimal(int(whole)) + Decimal(match[2] or "0")
        if (kind, name) in {("ConfigMap", "kube-root-ca.crt"), ("ServiceAccount", "default")}:
            continue
        if not recovery_cutoff or timestamp >= Decimal(str(recovery_cutoff)):
            _refuse()
        count += 1
    return count


def absence_proof(binary, cwd, env, scope, name):
    """Return sanitized absence evidence, or refuse without disclosing diagnostics."""
    phase = "configuration"
    try:
        kube = _configuration(env, scope, name)
        phase = "processes"
        _processes_absent(binary)
        phase = "tasks"
        _tasks_absent(env, name)
        phase = "inventory"
        rows = _query([binary, "--context", scope["context"], "--result-format", "json",
                       "workspace", "list", "--skip-pro"], cwd, env)
        if not isinstance(rows, list) or any(not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"]
                                             or row["id"] == name for row in rows):
            _refuse()
        kubectl = shutil.which("kubectl", path=env.get("PATH", ""))
        if not kubectl:
            _refuse()
        command = [kubectl, "--kubeconfig", kube, "--context", scope["kubernetes_context"], "--request-timeout=5s"]
        phase = "namespace"
        namespace = _query(command + ["get", "namespace", scope["namespace"], "-o", "json"], cwd, env)
        metadata = namespace.get("metadata", {})
        uid = metadata.get("uid")
        if not isinstance(uid, str) or not uid or metadata.get("name") != scope["namespace"] or metadata.get("deletionTimestamp"):
            _refuse()
        phase = "resources"
        resources = _query(command + ["--namespace", scope["namespace"], "get", RESOURCES, "-o", "json"], cwd, env)
        if _items(resources):
            _refuse()
        phase = "auxiliary_resources"
        # kubectl may fetch full objects internally; emit and retain metadata only.
        auxiliary = _query(command + ["--namespace", scope["namespace"], "get",
                           "secrets,configmaps,roles,rolebindings,serviceaccounts", "-o",
                           "custom-columns=KIND:.kind,NAME:.metadata.name,UID:.metadata.uid,CREATED:.metadata.creationTimestamp",
                           "--no-headers"],
                           cwd, env, text_only=True)
        recovery_cutoff = scope.get("recovery_cutoff")
        if (isinstance(recovery_cutoff, bool) or not isinstance(recovery_cutoff, (int, float))
                or not math.isfinite(recovery_cutoff) or recovery_cutoff <= 0 or recovery_cutoff > time.time()):
            recovery_cutoff = 0
        preexisting_auxiliary_count = _preexisting_auxiliary(auxiliary, recovery_cutoff)
        phase = "volumes"
        volumes = _query(command + ["get", "persistentvolumes", "-o", "json"], cwd, env)
        for volume in _items(volumes):
            if not isinstance(volume.get("spec"), dict) or not isinstance(volume.get("metadata"), dict):
                _refuse()
            claim = volume["spec"].get("claimRef", {}) or {}
            if claim and (not isinstance(claim, dict) or not isinstance(claim.get("namespace"), str)
                          or not claim["namespace"]):
                _refuse()
            metadata = volume["metadata"]
            if not isinstance(metadata.get("name"), str) or not metadata["name"]:
                _refuse()
            markers = json.dumps(metadata, sort_keys=True).lower()
            if claim.get("namespace") == scope["namespace"] or (not claim and "devsy" in markers):
                _refuse()
        phase = "recheck"
        _configuration(env, scope, name)
        _tasks_absent(env, name)
        _processes_absent(binary)
        return {"kind": "absent", "observed_at": time.time(), "namespace_uid": uid,
                "kubernetes_context": scope["kubernetes_context"], "namespace": scope["namespace"],
                "workspace_absent": True, "provider_resources_absent": True,
                "lifecycle_processes_absent": True,
                "preexisting_auxiliary_count": preexisting_auxiliary_count,
                "recovery_cutoff": recovery_cutoff}
    except Exception:
        # JSON, filesystem, permission, process and provider errors all fail closed.
        # Never chain exceptions: they may contain credential-bearing argv/output.
        raise ReconciliationError(phase) from None
