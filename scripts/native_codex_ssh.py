#!/usr/bin/env python3
"""Render a narrowly scoped sshd config or dispatch one approved Codex command."""

from __future__ import annotations

import argparse
import os
import pwd
import shlex
import stat
import sys
from pathlib import Path


CODEX = "/home/kdlocpanda/.codex/packages/app-server-daemon/current/bin/codex"
SOCKET = "/home/kdlocpanda/.codex/app-server-control/app-server-control.sock"
ALLOWED_COMMANDS = (
    (CODEX, "app-server", "daemon", "version"),
    (CODEX, "app-server", "proxy", "--sock", SOCKET),
)
DEFAULT_ADDRESS = "100.81.124.110"
DEFAULT_PORT = 22222


class ConfigurationError(ValueError):
    pass


def _safe_state_paths(state_dir: Path, host_key: Path, authorized_keys: Path, pid_file: Path) -> None:
    """Require a private, owned state directory and private regular key files."""
    try:
        state = state_dir.lstat()
    except OSError as exc:
        raise ConfigurationError(f"state directory is unavailable: {state_dir}") from exc
    uid = os.geteuid()
    if not stat.S_ISDIR(state.st_mode) or state.st_uid != uid or stat.S_IMODE(state.st_mode) != 0o700:
        raise ConfigurationError("state directory must be a real directory owned by this user with mode 0700")

    resolved_state = state_dir.resolve(strict=True)
    for label, path in (("host key", host_key), ("authorized keys", authorized_keys), ("pid file", pid_file)):
        if (not path.is_absolute() or any(char.isspace() or char in "#" for char in str(path))
                or path.parent.resolve(strict=True) != resolved_state):
            raise ConfigurationError(f"{label} must be directly inside the private state directory")
    for label, path in (("host key", host_key), ("authorized keys", authorized_keys)):
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ConfigurationError(f"{label} is unavailable: {path}") from exc
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ConfigurationError(f"{label} must be a regular file owned by this user with mode 0600")


def render_config(
    *, address: str, port: int, state_dir: Path, host_key: Path,
    authorized_keys: Path, pid_file: Path, helper: Path,
) -> str:
    import ipaddress

    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ConfigurationError("listen address must be a valid tailnet IPv4 address") from exc
    allowed_ranges = (ipaddress.ip_network("100.64.0.0/10"),)
    if parsed_address.version != 4 or not any(parsed_address in network for network in allowed_ranges):
        raise ConfigurationError("listen address must be a Tailscale CGNAT IPv4 address")
    if not 1024 <= port <= 65535:
        raise ConfigurationError("port must be in the unprivileged range 1024-65535")
    _safe_state_paths(state_dir, host_key, authorized_keys, pid_file)
    if not helper.is_absolute() or any(char.isspace() or char in "#" for char in str(helper)):
        raise ConfigurationError("helper path must be absolute and contain no whitespace or '#'")

    username = pwd.getpwuid(os.geteuid()).pw_name
    if username == "root":
        raise ConfigurationError("the native Codex SSH service cannot run as root")
    values = {
        "address": address,
        "port": str(port),
        "host_key": str(host_key),
        "authorized_keys": str(authorized_keys),
        "pid_file": str(pid_file),
        "username": username,
        "helper": str(helper),
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
        f"ForceCommand {values['helper']} dispatch",
        "LogLevel VERBOSE",
        "",
    ))


def dispatch(original_command: str | None) -> int:
    if not original_command:
        print("native Codex SSH accepts only the two configured commands", file=sys.stderr)
        return 126
    try:
        argv = tuple(shlex.split(original_command, posix=True))
    except ValueError:
        print("invalid SSH command syntax", file=sys.stderr)
        return 126
    if argv not in ALLOWED_COMMANDS:
        print("command is not allowed", file=sys.stderr)
        return 126
    os.execv(CODEX, list(argv))
    return 126  # execv either replaces the process or raises.


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    render = subparsers.add_parser("render-config", help="print a constrained sshd configuration")
    render.add_argument("--address", default=DEFAULT_ADDRESS)
    render.add_argument("--port", type=int, default=DEFAULT_PORT)
    render.add_argument("--state-dir", type=Path, required=True)
    render.add_argument("--host-key", type=Path, required=True)
    render.add_argument("--authorized-keys", type=Path, required=True)
    render.add_argument("--pid-file", type=Path, required=True)
    render.add_argument("--helper", type=Path, required=True)
    subparsers.add_parser("dispatch", help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.action == "dispatch":
        return dispatch(os.environ.get("SSH_ORIGINAL_COMMAND"))
    try:
        sys.stdout.write(render_config(
            address=args.address, port=args.port, state_dir=args.state_dir,
            host_key=args.host_key, authorized_keys=args.authorized_keys,
            pid_file=args.pid_file, helper=args.helper,
        ))
    except ConfigurationError as exc:
        print(f"native Codex SSH config: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
