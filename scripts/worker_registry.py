"""Publish verified worker identities without changing static CAS targets.

The lifecycle caller supplies verified scope ownership. This module only owns
private registry persistence; it never contacts or mutates a provider.
"""
import fcntl
import json
import math
import os
from pathlib import Path
import re
import stat
import time
import uuid

SAFE_ERROR = "Worker target publication failed; recheck the private registry before retrying."


class RegistryError(Exception):
    pass


def _refuse():
    raise RegistryError(SAFE_ERROR)


def _identity(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}", value):
        _refuse()
    return value


def _target_name(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
        _refuse()
    return value


def _target(selection):
    if not isinstance(selection, dict) or selection.get("provider") != "kubernetes":
        _refuse()
    if not isinstance(selection.get("namespace"), str) or not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", selection["namespace"]):
        _refuse()
    kubeconfig = selection.get("kubeconfig")
    if (not isinstance(kubeconfig, str) or len(kubeconfig) > 4096 or not Path(kubeconfig).is_absolute()
            or ".." in Path(kubeconfig).parts or any(ord(character) < 32 or ord(character) == 127 for character in kubeconfig)):
        _refuse()
    if (selection.get("repository") != "https://github.com/joshyorko/codex-action-server.git"
            or selection.get("recipe") != ".devcontainer/remote-worker/devcontainer.json"
            or not isinstance(selection.get("revision"), str) or not re.fullmatch(r"[a-f0-9]{40}", selection["revision"])):
        _refuse()
    return {"transport": "devsy-kubernetes",
            **{key: _identity(selection[key]) for key in ("context", "provider", "workspace", "workspace_uid", "kubernetes_context")},
            **{key: selection[key] for key in ("namespace", "kubeconfig", "repository", "revision", "recipe")},
            "user": "vscode", "codex_bin": "/home/vscode/.local/bin/codex"}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _refuse()
        result[key] = value
    return result


def _private_file(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        _refuse()


def _read(path, *, directory=None):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        return None
    with os.fdopen(fd) as handle:
        _private_file(os.fstat(handle.fileno()))
        if os.fstat(handle.fileno()).st_size > 1024 * 1024:
            _refuse()
        return json.load(handle, object_pairs_hook=_unique_object)


def _owner(owner, target):
    if not isinstance(owner, dict) or set(owner) != {"operation_id", "workspace_uid"}:
        _refuse()
    _identity(owner["operation_id"])
    if owner["workspace_uid"] != target["workspace_uid"]:
        _refuse()


def _validate_registry(value):
    if (not isinstance(value, dict) or set(value) - {"version", "targets", "owners", "history"}
            or type(value.get("version")) is not int or value["version"] != 1
            or not isinstance(value.get("targets"), dict) or not isinstance(value.get("owners", {}), dict)
            or not isinstance(value.get("history", []), list) or len(value.get("history", [])) > 32):
        _refuse()
    for name, target in value["targets"].items():
        _target_name(name)
        if target != _target(target):
            _refuse()
    for name, owner in value.get("owners", {}).items():
        if name not in value["targets"]:
            _refuse()
        _owner(owner, value["targets"][name])
    for receipt in value.get("history", []):
        if not isinstance(receipt, dict) or set(receipt) != {
                "target_name", "target", "owner", "replaced_at", "replaced_by_operation_id"}:
            _refuse()
        _target_name(receipt["target_name"])
        if receipt["target"] != _target(receipt["target"]):
            _refuse()
        _owner(receipt["owner"], receipt["target"])
        _identity(receipt["replaced_by_operation_id"])
        timestamp = receipt["replaced_at"]
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)) or not math.isfinite(timestamp) or timestamp <= 0:
            _refuse()


def _write(directory, name, value):
    temporary = "." + name + "." + uuid.uuid4().hex + ".tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(value, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def publish(path, static_targets_source, target_name, selection, operation_id):
    """Atomically publish one verified target, preserving all unrelated entries."""
    directory = lock = None
    try:
        target_name = _target_name(target_name)
        operation_id = _identity(operation_id)
        target = _target(selection)
        path = Path(path)
        if not path.is_absolute() or path.name in {"", ".", ".."}:
            _refuse()
        if path.resolve() == Path(static_targets_source).resolve():
            _refuse()
        path.parent.mkdir(mode=0o700, exist_ok=True)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(directory)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            _refuse()
        lock = os.open("." + path.name + ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                       0o600, dir_fd=directory)
        _private_file(os.fstat(lock))
        fcntl.flock(lock, fcntl.LOCK_EX)
        static = _read(static_targets_source)
        if not isinstance(static, dict) or not isinstance(static.get("targets"), dict) or target_name in static["targets"]:
            _refuse()
        value = _read(path.name, directory=directory)
        if value is None:
            value = {"version": 1, "targets": {}, "owners": {}}
        _validate_registry(value)
        if any(owner["operation_id"] == operation_id and name != target_name
               for name, owner in value.get("owners", {}).items()):
            _refuse()
        if any(receipt["owner"]["operation_id"] == operation_id for receipt in value.get("history", [])):
            _refuse()
        previous = value["targets"].get(target_name)
        if previous is not None:
            owner = value.get("owners", {}).get(target_name)
            if owner is None:
                _refuse()
            if owner["operation_id"] == operation_id:
                if previous != target:
                    _refuse()
                return {"target": target_name, "operation_id": operation_id,
                        "workspace_uid": target["workspace_uid"], "published": True}
            receipt = {"target_name": target_name, "target": previous, "owner": owner,
                       "replaced_at": time.time(), "replaced_by_operation_id": operation_id}
            value["history"] = (value.get("history", []) + [receipt])[-32:]
        value["targets"][target_name] = target
        value.setdefault("owners", {})[target_name] = {"operation_id": operation_id, "workspace_uid": target["workspace_uid"]}
        _write(directory, path.name, value)
        return {"target": target_name, "operation_id": operation_id,
                "workspace_uid": target["workspace_uid"], "published": True}
    except Exception:
        # Do not retain paths, selected metadata, or raw filesystem errors.
        raise RegistryError(SAFE_ERROR) from None
    finally:
        if lock is not None:
            os.close(lock)
        if directory is not None:
            os.close(directory)
