"""Bounded read-only version checks for the two registered Dakota Codex daemons.

This module never starts or restarts a daemon.  It connects through the existing
strictly pinned forced-command SSH endpoint and sends only two exact read-only
commands: ``codex --version`` and ``codex app-server daemon version``.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
from urllib.parse import urlsplit


TARGETS = ("dakota-cpu", "dakota-nvidia")
VERSION_RE = re.compile(r"(?:codex|codex-cli) [0-9][A-Za-z0-9_.+-]{0,80}\Z")
IPV4_RE = re.compile(r"100\.(?:6[4-9]|[7-9][0-9]|10[0-9]|11[0-9]|12[0-7])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\Z")
USERNAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}\Z")
PATH_RE = re.compile(r"/[A-Za-z0-9_./+-]{1,511}\Z")


class DriftError(ValueError):
    """A sanitized read-only fleet probe refusal."""


def _owned_private(path: Path) -> bytes:
    try:
        info = path.lstat()
        if (path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 128 * 1024):
            raise DriftError("Native diagnostic input is not a bounded private file")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o600):
            os.close(fd)
            raise DriftError("Native diagnostic input is not a bounded private file")
        with os.fdopen(fd, "rb") as stream:
            raw = stream.read(128 * 1024 + 1)
        if len(raw) > 128 * 1024:
            raise DriftError("Native diagnostic input is too large")
        return raw
    except OSError:
        raise DriftError("Native diagnostic input is unavailable") from None


def _target_identity(name: str, value: dict) -> dict:
    expected = {"transport", "destination", "codex_bin", "socket_path", "ssh_config", "known_hosts"}
    if not isinstance(value, dict) or set(value) != expected:
        raise DriftError("Native target entry is incomplete")
    if (value["transport"] != "ssh" or value["destination"] != name + "-native"
            or value["ssh_config"] != "/run/codex-ssh/ssh_config"
            or value["known_hosts"] != "/run/codex-ssh/known_hosts"):
        raise DriftError("Native target does not use the approved forced-command endpoint")
    for field in ("codex_bin", "socket_path"):
        path = value[field]
        if (not isinstance(path, str) or not PATH_RE.fullmatch(path)
                or ".." in Path(path).parts or str(Path(path)) != path):
            raise DriftError("Native target executable or socket path is invalid")
    return value


def _ssh_endpoint(raw_config: bytes, alias: str) -> tuple[str, int, str]:
    try:
        lines = raw_config.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise DriftError("Native SSH configuration is invalid") from None
    blocks = []
    current = None
    for line in lines:
        try:
            fields = shlex.split(line, comments=True)
        except ValueError:
            raise DriftError("Native SSH configuration is invalid") from None
        if not fields:
            continue
        key = fields[0].lower()
        if key in {"match", "include"}:
            raise DriftError("Native SSH configuration contains an unsupported directive")
        if key == "host":
            if len(fields) != 2 or fields[1] in {"*", "!"} or any(char in fields[1] for char in "*!?"):
                raise DriftError("Native SSH endpoint alias is ambiguous")
            current = {"alias": fields[1], "options": {}}
            blocks.append(current)
            continue
        if current is None or len(fields) != 2 or key in current["options"]:
            raise DriftError("Native SSH configuration is ambiguous")
        if key in {"proxycommand", "proxyjump", "localcommand", "remotecommand", "permitlocalcommand"}:
            raise DriftError("Native SSH configuration contains an unsupported directive")
        current["options"][key] = fields[1]
    matches = [row for row in blocks if row["alias"] == alias]
    if len(matches) != 1:
        raise DriftError("Pinned native SSH endpoint is missing or duplicated")
    options = matches[0]["options"]
    required = {
        "identityfile": "/run/codex-ssh/identity",
        "identitiesonly": "yes",
        "stricthostkeychecking": "yes",
        "userknownhostsfile": "/run/codex-ssh/known_hosts",
        "globalknownhostsfile": "/dev/null",
        "batchmode": "yes",
        "forwardagent": "no",
        "preferredauthentications": "publickey",
    }
    if any(options.get(key) != value for key, value in required.items()):
        raise DriftError("Native SSH endpoint policy differs from the approved pinned settings")
    host, port, user = options.get("hostname"), options.get("port"), options.get("user")
    if (not isinstance(host, str) or not IPV4_RE.fullmatch(host)
            or not isinstance(port, str) or not port.isdecimal() or not 1024 <= int(port) <= 65535
            or not isinstance(user, str) or not USERNAME_RE.fullmatch(user)):
        raise DriftError("Native SSH endpoint identity is invalid")
    return host, int(port), user


def _check_known_host(raw_known: bytes, host: str, port: int) -> None:
    endpoint = f"[{host}]:{port}"
    try:
        lines = raw_known.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise DriftError("Native host-key file is invalid") from None
    keys = set()
    for line in lines:
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            continue
        if len(fields) < 3:
            raise DriftError("Native host-key file is invalid")
        if endpoint in fields[0].split(","):
            if fields[1] != "ssh-ed25519" or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", fields[2]):
                raise DriftError("Native host-key entry is invalid")
            keys.add((fields[1], fields[2]))
    if len(keys) != 1:
        raise DriftError("Native target does not have one pinned SSH host key")


def _parse_cli(stdout: str) -> str:
    lines = stdout.splitlines()
    if len(lines) != 1:
        raise DriftError("Codex CLI version response is invalid")
    value = lines[0].strip()
    if not VERSION_RE.fullmatch(value):
        raise DriftError("Codex CLI version response is invalid")
    return value.split(" ", 1)[1]


def _parse_daemon(stdout: str, expected_socket: str) -> dict:
    try:
        value = json.loads(stdout)
    except (ValueError, TypeError):
        raise DriftError("Native daemon version response is invalid") from None
    if not isinstance(value, dict):
        raise DriftError("Native daemon version response is invalid")
    status = value.get("status")
    if status != "running":
        return {"status": "stopped" if status == "stopped" else "unknown", "version": None}
    if value.get("socketPath") is not None and value["socketPath"] != expected_socket:
        return {"status": "socket_mismatch", "version": None}
    raw_version = value.get("version") or value.get("appServerVersion") or value.get("serverVersion")
    version = None
    if isinstance(raw_version, str):
        version = raw_version[7:] if raw_version.startswith("codex ") else raw_version
        if not re.fullmatch(r"[0-9][A-Za-z0-9_.+-]{0,80}", version):
            version = None
    return {"status": "running" if version else "running_version_unknown", "version": version}


def _ssh_command(native_dir: Path, alias: str, host: str, port: int, user: str,
                 codex_bin: str, remote_argv: list[str]) -> list[str]:
    known = str(native_dir / "known_hosts.native")
    identity = str(native_dir / "identity")
    command = shlex.join([codex_bin, *remote_argv])
    return ["ssh", "-F", "/dev/null", "-T", "-i", identity,
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + known,
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ForwardAgent=no",
            "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
            "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no",
            "-o", "ConnectTimeout=10", "-p", str(port), user + "@" + host, command]


def _run_version_command(runner, command):
    environment = os.environ.copy()
    environment.pop("SSH_AUTH_SOCK", None)
    environment.pop("GIT_SSH_COMMAND", None)
    try:
        result = runner(command, capture_output=True, text=True, timeout=25,
                        stdin=subprocess.DEVNULL, check=False, env=environment)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not isinstance(result.stdout, str) or len(result.stdout) > 8192:
        return None
    return result.stdout


def native_upgrade_gate(*, approval: bool, active_sessions: str | None,
                        artifact_verified: bool, rollback_ready: bool,
                        installer_available: bool) -> dict:
    """Keep daemon installation blocked until a separate verified lifecycle exists."""
    blockers = []
    if approval is not True:
        blockers.append("separate_operator_approval_required")
    if active_sessions != "idle":
        blockers.append("native_session_state_not_proven_idle")
    if artifact_verified is not True:
        blockers.append("qualified_binary_digest_not_verified")
    if rollback_ready is not True:
        blockers.append("native_rollback_not_proven")
    if installer_available is not True:
        blockers.append("separately_approved_native_lifecycle_not_implemented")
    return {"status": "ready" if not blockers else "blocked",
            "blockers": blockers, "mutated": False}


def probe_target(name: str, target: dict, native_dir: Path, *, runner=subprocess.run) -> dict:
    """Read one device's binary and daemon versions over the existing pinned SSH path."""
    value = _target_identity(name, target)
    _owned_private(native_dir / "identity")
    ssh_config = _owned_private(native_dir / "ssh_config.native")
    known_hosts = _owned_private(native_dir / "known_hosts.native")
    host, port, user = _ssh_endpoint(ssh_config, value["destination"])
    _check_known_host(known_hosts, host, port)
    cli_output = _run_version_command(runner, _ssh_command(
        native_dir, value["destination"], host, port, user, value["codex_bin"], ["--version"]))
    if cli_output is None:
        cli = {"status": "unavailable", "version": None}
    else:
        try:
            cli = {"status": "available", "version": _parse_cli(cli_output)}
        except DriftError:
            cli = {"status": "unknown", "version": None}
    daemon_output = _run_version_command(runner, _ssh_command(
        native_dir, value["destination"], host, port, user, value["codex_bin"],
        ["app-server", "daemon", "version"]))
    if daemon_output is None:
        daemon = {"status": "unavailable", "version": None}
    else:
        try:
            daemon = _parse_daemon(daemon_output, value["socket_path"])
        except DriftError:
            daemon = {"status": "unknown", "version": None}
    cli_version, daemon_version = cli["version"], daemon["version"]
    drift = ("unknown" if cli_version is None or daemon_version is None
             else "in_sync" if cli_version == daemon_version else "cli_daemon_drift")
    return {"target": name, "connection": "available" if cli["status"] == "available" else "partial_or_unavailable",
            "installed_cli": cli, "running_daemon": daemon, "version_drift": drift,
            "active_sessions": "not_checked", "native_upgrade": native_upgrade_gate(
                approval=False, active_sessions=None, artifact_verified=False,
                rollback_ready=False, installer_available=False)}


def reconcile(target_map: dict, native_dir: Path, *, runner=subprocess.run) -> dict:
    """Probe CPU and NVIDIA independently so one offline host cannot hide the other."""
    if not isinstance(target_map, dict) or not isinstance(target_map.get("targets"), dict):
        raise DriftError("Native target inventory is invalid")
    results = {}
    for name in TARGETS:
        target = target_map["targets"].get(name)
        if target is None:
            results[name] = {"target": name, "connection": "not_registered",
                             "installed_cli": {"status": "unknown", "version": None},
                             "running_daemon": {"status": "unknown", "version": None},
                             "version_drift": "unknown", "active_sessions": "not_checked",
                             "native_upgrade": native_upgrade_gate(approval=False, active_sessions=None,
                                 artifact_verified=False, rollback_ready=False, installer_available=False)}
            continue
        try:
            results[name] = probe_target(name, target, native_dir, runner=runner)
        except DriftError:
            results[name] = {"target": name, "connection": "blocked_or_unavailable",
                             "installed_cli": {"status": "unknown", "version": None},
                             "running_daemon": {"status": "unknown", "version": None},
                             "version_drift": "unknown", "active_sessions": "not_checked",
                             "native_upgrade": native_upgrade_gate(approval=False, active_sessions=None,
                                 artifact_verified=False, rollback_ready=False, installer_available=False)}
    return {"schema_version": 1, "mutated": False, "targets": results}
