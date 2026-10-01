#!/usr/bin/env python3
"""Local stdio MCP adapter for the already-running Friday Hermes API."""

from __future__ import annotations

import ipaddress
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from mcp.server.mcpserver import MCPServer
from friday_contract import RUN_ID_RE, SESSION_ID


DEFAULT_API_BASE_URL = "http://127.0.0.1:8642/p/friday"
DEFAULT_TIMEOUT_SECONDS = 30.0


def validate_api_base_url(value: str) -> str:
    """Accept only an HTTP origin on a numeric loopback address."""
    try:
        parsed = urlsplit(value)
        address = ipaddress.ip_address(parsed.hostname or "")
        parsed.port  # Validate the port syntax/range.
    except (ValueError, TypeError):
        raise ValueError("FRIDAY_API_BASE_URL must be loopback HTTP scoped to /p/friday") from None
    if (
        parsed.scheme != "http"
        or not address.is_loopback
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path.rstrip("/") != "/p/friday"
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("FRIDAY_API_BASE_URL must be loopback HTTP scoped to /p/friday")
    return f"http://{parsed.netloc}/p/friday"


class RunRegistry:
    """Small atomic registry that limits status reads to runs this adapter submitted."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self._runs: dict[str, dict[str, str | int]] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if data.get("version") != 1 or not isinstance(data.get("runs"), dict):
                raise ValueError
            runs = data["runs"]
            for run_id, record in runs.items():
                if (
                    not isinstance(run_id, str)
                    or not RUN_ID_RE.fullmatch(run_id)
                    or not isinstance(record, dict)
                    or not isinstance(record.get("created_at"), int)
                ):
                    raise ValueError
            self._runs = runs
        except (OSError, ValueError, TypeError, AttributeError):
            raise RuntimeError("the local run registry is invalid or unreadable; refusing status lookups") from None

    def contains(self, run_id: str) -> bool:
        with self._lock:
            return run_id in self._runs

    def register(self, run_id: str) -> None:
        with self._lock:
            self._runs[run_id] = {"created_at": int(time.time())}
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            payload = json.dumps({"version": 1, "runs": self._runs}, sort_keys=True, separators=(",", ":"))
            fd, temp_path = tempfile.mkstemp(prefix=".runs.", suffix=".tmp", dir=self.path.parent)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as output:
                    output.write(payload)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temp_path, self.path)
                dir_fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except Exception:
                try:
                    os.close(fd)
                except OSError:
                    pass
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
                raise


def _read_friday_profile_api_key() -> str:
    env_path = Path(os.environ.get(
        "FRIDAY_API_ENV_FILE",
        str(Path.home() / ".hermes/profiles/friday/.env"),
    )).expanduser()
    try:
        from dotenv import dotenv_values
        value = dotenv_values(env_path, interpolate=False).get("API_SERVER_KEY")
    except (OSError, ValueError):
        return ""
    return value.strip() if isinstance(value, str) else ""


def load_settings() -> tuple[str, str, float, RunRegistry]:
    api_key = os.environ.get("FRIDAY_API_KEY", "") or _read_friday_profile_api_key()
    if not api_key:
        raise ValueError("Friday API key is missing; configure API_SERVER_KEY in the Friday profile .env")
    base_url = validate_api_base_url(os.environ.get("FRIDAY_API_BASE_URL", DEFAULT_API_BASE_URL))
    try:
        timeout = float(os.environ.get("FRIDAY_HTTP_TIMEOUT_SECONDS", str(DEFAULT_TIMEOUT_SECONDS)))
    except ValueError:
        raise ValueError("FRIDAY_HTTP_TIMEOUT_SECONDS must be a positive number no greater than 120") from None
    if not 0 < timeout <= 120:
        raise ValueError("FRIDAY_HTTP_TIMEOUT_SECONDS must be a positive number no greater than 120")
    registry_path = Path(os.environ.get(
        "FRIDAY_RUN_REGISTRY",
        str(Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
            / "friday-chatgpt-tunnel" / "runs.json"),
    )).expanduser()
    return api_key, base_url, timeout, RunRegistry(registry_path)


def build_server() -> MCPServer:
    from friday_tools import FridayApi, register_friday_tools

    api_key, base_url, timeout, registry = load_settings()
    api = FridayApi(
        api_key=api_key,
        base_url=base_url,
        timeout=timeout,
        session_id=SESSION_ID,
        registry=registry,
    )
    server = MCPServer(
        name="Friday local run bridge",
        version="0.1.0",
        instructions="Submit a new request to the dedicated Friday ChatGPT session and check only runs submitted by this bridge.",
    )
    # Keep integrations modular: Friday is registered here; a future MemoryD
    # tool module can be added here without changing the tunnel launcher.
    register_friday_tools(server, api)
    return server


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--check-config":
        try:
            load_settings()
        except (ValueError, RuntimeError) as exc:
            print(f"Friday adapter configuration error: {exc}", file=sys.stderr)
            return 2
        print("Friday adapter configuration OK (loopback-only; no API call made).", file=sys.stderr)
        return 0
    if len(sys.argv) != 1:
        print("usage: friday_mcp_adapter.py [--check-config]", file=sys.stderr)
        return 2
    try:
        server = build_server()
    except (ValueError, RuntimeError) as exc:
        print(f"Friday adapter configuration error: {exc}", file=sys.stderr)
        return 2
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
