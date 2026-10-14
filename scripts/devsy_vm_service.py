"""Systemd entrypoint for the private host Devsy MCP bridge."""

import json
import os
from pathlib import Path
import stat
import sys


class ServiceError(RuntimeError):
    """Credential-free host bridge startup error."""


def start_configured_bridge(configuration, *, bridge, state_dir,
                            read_private, write_private, start=None):
    """Start only the bridge described by the private managed configuration."""
    value = bridge.settings(configuration)
    if value is None:
        raise ServiceError("Host Devsy MCP bridge is not enabled in the managed configuration")
    expected_state = (Path(state_dir).resolve() / "devsy-bridge").resolve()
    try:
        configured_state = Path(value["state"])
    except (KeyError, OSError, TypeError):
        raise ServiceError("private bridge state binding drift") from None
    if not configured_state.is_absolute() or configured_state != expected_state:
        raise ServiceError("private bridge state binding drift")
    try:
        metadata = configured_state.lstat()
    except OSError:
        raise ServiceError("Host Devsy bridge state is unavailable") from None
    if (not stat.S_ISDIR(metadata.st_mode) or configured_state.is_symlink()
            or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise ServiceError("private bridge state ownership or mode mismatch")
    try:
        (start or bridge.start)(value)
        receipt = json.loads(read_private(configured_state / "process.json"))
    except Exception:
        raise ServiceError("Host Devsy bridge refused to start; private details omitted") from None
    if not isinstance(receipt, dict) or not bridge.owned_process(receipt):
        raise ServiceError("Host Devsy bridge process identity mismatch")
    write_private(configured_state / "systemd.pid", str(receipt["pid"]) + "\n")
    return {"binary": value["binary"], "state": str(configured_state), "pid": receipt["pid"]}


def main() -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import compose_control
    import devsy_bridge

    state_dir = Path(os.environ.get(
        "CONTROL_PLANE_STATE_DIR",
        str(Path.home() / ".local/share/codex-control-plane"),
    ))
    try:
        start_configured_bridge(
            compose_control.config(), bridge=devsy_bridge, state_dir=state_dir,
            read_private=compose_control.read_private,
            write_private=compose_control.write_private,
        )
    except Exception:
        print("Host Devsy bridge startup failed; private details omitted.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
