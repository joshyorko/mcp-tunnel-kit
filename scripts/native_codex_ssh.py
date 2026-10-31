#!/usr/bin/env python3
"""Prepare or dispatch a narrowly scoped native Codex SSH endpoint."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import pwd
import re
import shlex
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any


PROFILE_KEYS = {"address", "port", "codex_bin", "socket", "state_dir", "helper"}
SAFE_PATH = re.compile(r"^/[A-Za-z0-9_./+-]+$")


class ConfigurationError(ValueError):
    """The private profile or its staged paths do not satisfy the contract."""


def _private_file(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ConfigurationError(f"{label} is unavailable: {path}") from exc
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600):
        raise ConfigurationError(f"{label} must be a regular non-symlink file owned by this user with mode 0600")
    return metadata


def _state_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ConfigurationError(f"state directory is unavailable: {path}") from exc
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise ConfigurationError("state directory must be a real directory owned by this user with mode 0700")


def _profile_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not SAFE_PATH.fullmatch(value):
        raise ConfigurationError(f"{label} must be an absolute path without whitespace or shell/config syntax")
    path = Path(value)
    if ".." in path.parts or "." in path.parts:
        raise ConfigurationError(f"{label} must not contain dot path components")
    return path


def _validate_address(value: Any) -> str:
    if not isinstance(value, str):
        raise ConfigurationError("listen address must be a Tailscale CGNAT IPv4 address")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ConfigurationError("listen address must be a valid tailnet IPv4 address") from exc
    if parsed.version != 4 or parsed not in ipaddress.ip_network("100.64.0.0/10"):
        raise ConfigurationError("listen address must be a Tailscale CGNAT IPv4 address")
    return str(parsed)


def load_profile(profile_path: Path) -> dict[str, Any]:
    """Load and validate an operator-owned private native SSH profile."""
    _private_file(profile_path, "profile")
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ConfigurationError("profile must contain valid UTF-8 JSON") from exc
    if not isinstance(profile, dict) or set(profile) != PROFILE_KEYS:
        raise ConfigurationError("profile must contain exactly: " + ", ".join(sorted(PROFILE_KEYS)))

    profile["address"] = _validate_address(profile["address"])
    port = profile["port"]
    if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ConfigurationError("port must be in the unprivileged range 1024-65535")

    for field in ("codex_bin", "socket", "state_dir", "helper"):
        profile[field] = str(_profile_path(profile[field], field.replace("_", " ")))
    state_dir = Path(profile["state_dir"])
    _state_directory(state_dir)
    if Path(profile["helper"]) != state_dir / "native_codex_ssh.py":
        raise ConfigurationError("helper must be state_dir/native_codex_ssh.py")
    codex_bin = Path(profile["codex_bin"])
    try:
        executable = codex_bin.stat()
    except OSError as exc:
        raise ConfigurationError("codex_bin must resolve to an executable file") from exc
    if not stat.S_ISREG(executable.st_mode) or not os.access(codex_bin, os.X_OK):
        raise ConfigurationError("codex_bin must resolve to an executable file")

    _safe_state_paths(
        state_dir,
        state_dir / "ssh_host_ed25519_key",
        state_dir / "authorized_keys",
        state_dir / "sshd.pid",
    )
    return profile


def _safe_state_paths(state_dir: Path, host_key: Path, authorized_keys: Path, pid_file: Path) -> None:
    """Require private owned state and existing key inputs directly within it."""
    _state_directory(state_dir)
    uid = os.geteuid()
    for label, path in (("host key", host_key), ("authorized keys", authorized_keys), ("pid file", pid_file)):
        if (not path.is_absolute() or any(char.isspace() or char in "#\"'`$;\\" for char in str(path))
                or path.parent != state_dir):
            raise ConfigurationError(f"{label} must be directly inside the private state directory")
    for label, path in (("host key", host_key), ("authorized keys", authorized_keys)):
        metadata = _private_file(path, label)
        if metadata.st_uid != uid:
            raise ConfigurationError(f"{label} must be owned by this user")
    try:
        pid_metadata = pid_file.lstat()
    except FileNotFoundError:
        pass
    else:
        if (not stat.S_ISREG(pid_metadata.st_mode) or pid_metadata.st_uid != uid
                or stat.S_IMODE(pid_metadata.st_mode) != 0o600):
            raise ConfigurationError("pid file must be an owned regular file with mode 0600 when present")


def render_config(
    *, address: str, port: int, state_dir: Path, host_key: Path,
    authorized_keys: Path, pid_file: Path, helper: Path,
) -> str:
    """Render the forced-command-only sshd configuration for validated paths."""
    address = _validate_address(address)
    if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ConfigurationError("port must be in the unprivileged range 1024-65535")
    _safe_state_paths(state_dir, host_key, authorized_keys, pid_file)
    helper = _profile_path(str(helper), "helper")
    if helper != state_dir / "native_codex_ssh.py":
        raise ConfigurationError("helper must be state_dir/native_codex_ssh.py")

    username = pwd.getpwuid(os.geteuid()).pw_name
    if username == "root":
        raise ConfigurationError("the native Codex SSH service cannot run as root")
    profile = state_dir / "profile.json"
    values = {
        "address": address,
        "port": str(port),
        "host_key": str(host_key),
        "authorized_keys": str(authorized_keys),
        "pid_file": str(pid_file),
        "username": username,
        "helper": str(helper),
        "profile": str(profile),
    }
    return "\n".join((
        "AddressFamily inet",
        f"ListenAddress {values['address']}",
        f"Port {values['port']}",
        f"HostKey {values['host_key']}",
        f"PidFile {values['pid_file']}",
        f"AuthorizedKeysFile {values['authorized_keys']}",
        f"AllowUsers {values['username']}",
        "StrictModes yes",
        "PubkeyAuthentication yes",
        "AuthenticationMethods publickey",
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        "UsePAM no",
        "PermitRootLogin no",
        "PermitEmptyPasswords no",
        "PermitTTY no",
        "DisableForwarding yes",
        "AllowAgentForwarding no",
        "AllowTcpForwarding no",
        "AllowStreamLocalForwarding no",
        "X11Forwarding no",
        "PermitTunnel no",
        "GatewayPorts no",
        "PermitUserEnvironment no",
        "PermitUserRC no",
        f"ForceCommand {values['helper']} dispatch --profile {values['profile']}",
        "LogLevel VERBOSE",
        "",
    ))


def render_profile(profile_path: Path) -> str:
    profile = load_profile(profile_path)
    state_dir = Path(profile["state_dir"])
    return render_config(
        address=profile["address"], port=profile["port"], state_dir=state_dir,
        host_key=state_dir / "ssh_host_ed25519_key",
        authorized_keys=state_dir / "authorized_keys", pid_file=state_dir / "sshd.pid",
        helper=Path(profile["helper"]),
    )


def _service_unit(state_dir: Path) -> str:
    return "\n".join((
        "[Unit]",
        "Description=Bounded native Codex SSH endpoint on the configured tailnet address",
        "",
        "[Service]",
        "Type=simple",
        f"ExecStart=/usr/bin/sshd -D -e -f {state_dir / 'sshd_config'}",
        "Restart=on-failure",
        "RestartSec=5s",
        "UMask=0077",
        "NoNewPrivileges=yes",
        "# The configured Codex socket may resolve under /tmp.",
        "PrivateTmp=no",
        "ProtectSystem=strict",
        f"ReadWritePaths={state_dir}",
        "RestrictAddressFamilies=AF_INET AF_UNIX",
        "",
        "[Install]",
        "WantedBy=default.target",
        "",
    ))


def _stage_private_file(path: Path, content: bytes, mode: int, label: str) -> None:
    """Create a generated file once, or accept an identical safe prior stage."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        metadata = None
    if metadata is not None:
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != mode):
            raise ConfigurationError(f"existing {label} must be a regular owned non-symlink file with mode {mode:04o}")
        if path.read_bytes() != content:
            raise ConfigurationError(f"{label} already exists with different content; refusing to replace it")
        return

    fd, temporary_name = tempfile.mkstemp(prefix=".native-codex-ssh-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
    except FileExistsError:
        # A concurrent preparation is safe only when it wrote identical bytes.
        metadata = path.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != mode or path.read_bytes() != content):
            raise ConfigurationError(f"{label} already exists with different or unsafe content")
    finally:
        temporary.unlink(missing_ok=True)


def prepare(profile_path: Path, *, source_tool: Path | None = None) -> Path:
    """Stage config, helper, profile snapshot, and service unit without activation."""
    profile = load_profile(profile_path)
    state_dir = Path(profile["state_dir"])
    source_tool = source_tool or Path(__file__)
    try:
        source_metadata = source_tool.lstat()
    except OSError as exc:
        raise ConfigurationError("helper source is unavailable") from exc
    if not stat.S_ISREG(source_metadata.st_mode):
        raise ConfigurationError("helper source must be a regular non-symlink file")

    # The staged snapshot pins the exact dispatch allowlist used by ForceCommand.
    profile_bytes = (json.dumps(profile, sort_keys=True, indent=2) + "\n").encode()
    staged_profile = state_dir / "profile.json"
    if profile_path.absolute() != staged_profile.absolute():
        _stage_private_file(staged_profile, profile_bytes, 0o600, "profile snapshot")
    config = render_config(
        address=profile["address"], port=profile["port"], state_dir=state_dir,
        host_key=state_dir / "ssh_host_ed25519_key",
        authorized_keys=state_dir / "authorized_keys", pid_file=state_dir / "sshd.pid",
        helper=Path(profile["helper"]),
    )
    _stage_private_file((state_dir / "sshd_config"), config.encode(), 0o600, "sshd config")
    _stage_private_file(Path(profile["helper"]), source_tool.read_bytes(), 0o700, "helper")
    service = _service_unit(state_dir).encode()
    _stage_private_file(state_dir / "native-codex-ssh.service", service, 0o600, "service unit")
    return state_dir


def dispatch(original_command: str | None, *, profile: Path | None = None) -> int:
    """Execute only one argv derived from the explicitly pinned private profile."""
    if not original_command or profile is None:
        print("native Codex SSH accepts only commands from its configured private profile", file=sys.stderr)
        return 126
    try:
        config = load_profile(profile)
        argv = tuple(shlex.split(original_command, posix=True))
    except (ConfigurationError, ValueError) as exc:
        print(f"native Codex SSH command rejected: {exc}", file=sys.stderr)
        return 126
    codex = config["codex_bin"]
    allowed_commands = (
        (codex, "--version"),
        (codex, "app-server", "daemon", "version"),
        (codex, "app-server", "proxy", "--sock", config["socket"]),
    )
    if argv not in allowed_commands:
        print("command is not allowed", file=sys.stderr)
        return 126
    os.execv(codex, list(argv))
    return 126


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    for action in ("render-config", "prepare"):
        subparser = subparsers.add_parser(action)
        subparser.add_argument("--profile", type=Path, required=True)
    dispatch_parser = subparsers.add_parser("dispatch", help=argparse.SUPPRESS)
    dispatch_parser.add_argument("--profile", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.action == "dispatch":
        return dispatch(os.environ.get("SSH_ORIGINAL_COMMAND"), profile=args.profile)
    try:
        if args.action == "prepare":
            state_dir = prepare(args.profile)
            print(f"Prepared native Codex SSH files in {state_dir}; no service was installed or activated.")
        else:
            sys.stdout.write(render_profile(args.profile))
    except ConfigurationError as exc:
        print(f"native Codex SSH config: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
