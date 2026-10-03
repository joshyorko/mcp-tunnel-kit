#!/usr/bin/env python3
"""Private local setup and read-only acceptance for pinned upstream Executor v2."""

from __future__ import annotations

import argparse
import asyncio
import importlib.metadata
import json
import logging
import os
from pathlib import Path
import stat
import sys
import tempfile

from codex_mcp_check import validate_mcp_url

CODEX_URL = "http://127.0.0.1:8088/mcp"
COMPACT_TOOLS = {"skills", "execute", "resume"}


class SetupError(Exception):
    """Only fixed, credential-free diagnostics cross the CLI boundary."""


def private_path(path: Path, directory: bool = False) -> None:
    info = path.lstat()
    expected = 0o700 if directory else 0o600
    if (stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != expected
            or (directory and not stat.S_ISDIR(info.st_mode))
            or (not directory and not stat.S_ISREG(info.st_mode))):
        raise SetupError("Executor data must be owned by you, directory 0700 and secret files 0600; symlinks are refused.")


def write_private(path: Path, text: str) -> None:
    if path.exists() or path.is_symlink():
        private_path(path)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(text)
            handle.flush()
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def refuse_live_tunnel() -> None:
    # Refuse any local client conservatively, without reading or printing its secrets.
    configured = Path(os.environ.get("TUNNEL_CLIENT_BIN", str(Path.home() / ".local/bin/tunnel-client"))).resolve()
    message = "A tunnel-client is already running. Stop its foreground pane before launching another client."
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            if (process / "exe").samefile(configured):
                raise SetupError(message)
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            pass  # Keep the argv-name fallback when executable metadata is unavailable.
        try:
            arguments = (process / "cmdline").read_bytes().split(b"\0")
            if any(Path(os.fsdecode(arg)).name == "tunnel-client"
                   or (arg and not arg.startswith(b"-") and Path(os.fsdecode(arg)).resolve() == configured)
                   for arg in arguments[:2]):
                raise SetupError(message)
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue


def result_data(result) -> dict:
    if result.is_error:
        raise SetupError("Executor MCP call failed; response omitted.")
    data = result.structured_content
    if data is None:
        blocks = [block.text for block in result.content if block.type == "text"]
        if len(blocks) != 1:
            raise SetupError("Unexpected Executor MCP result shape.")
        data = json.loads(blocks[0])
    if not isinstance(data, dict):
        raise SetupError("Unexpected Executor MCP result shape.")
    return data


def completed(data: dict):
    execution = data.get("execution", {})
    if data.get("status") != "completed" or not execution.get("ok"):
        raise SetupError("Executor execution did not complete successfully; details omitted.")
    if data.get("unavailableApps"):
        raise SetupError("An Executor app is unavailable; check the Action Server.")
    return execution.get("value")


async def acceptance(url: str, key: str, data_dir: Path, health_only: bool) -> None:
    import httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async with httpx.AsyncClient(headers={"Authorization": "Bearer " + key},
                                 trust_env=False, follow_redirects=False, timeout=30) as http:
        async with streamable_http_client(url, http_client=http) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                catalog = await session.list_tools()
                if {tool.name for tool in catalog.tools} != COMPACT_TOOLS or catalog.next_cursor:
                    raise SetupError("Executor must advertise only skills, execute and resume.")
                print("Executor authenticated MCP healthy; external catalog: execute, resume, skills.")
                if health_only:
                    return
                paths = set()
                for query in ("", "thread", "target"):
                    code = "return await tools.search(" + json.dumps({
                        "namespace": "codex", "query": query, "limit": 100,
                    }) + ");"
                    value = completed(result_data(await session.call_tool("execute", {"code": code})))
                    items = value.get("items", [])
                    if not items:
                        raise SetupError("Codex search returned no tools; register the app after the Action Server is available.")
                    paths.update(item["path"] for item in items)
                    print(f"tools.search codex/{query or 'all'} OK; {len(items)} matches.")
                if "tools.codex.list_targets" not in paths:
                    raise SetupError("Codex catalog lacks the harmless list_targets operation.")
                registration = json.loads((data_dir / "codex-integration.json").read_text())
                response = result_data(await session.call_tool("execute", {
                    "code": "return await tools.codex.list_targets({});",
                }))
                if response.get("status") == "approval-required":
                    invocation = response.get("invocation", {})
                    schema = response.get("elicitation", {}).get("requestedSchema", {})
                    if (invocation.get("app") != registration["id"]
                            or invocation.get("tool") != "list_targets"
                            or invocation.get("input") != {}
                            or invocation.get("accounts") != {}
                            or schema.get("properties") != {}):
                        raise SetupError("Unexpected approval request; no approval was sent.")
                    response = result_data(await session.call_tool("resume", {
                        "requestId": response["requestId"],
                        "response": {"action": "accept", "content": {}},
                    }))
                native = completed(response)
                if native.get("isError"):
                    raise SetupError("Action Server read-only operation failed; response omitted.")
                payload = native.get("structuredContent")
                if payload is None:
                    payload = json.loads(next(block["text"] for block in native["content"]
                                              if block.get("type") == "text"))
                if payload.get("error") or not isinstance(payload.get("result", {}).get("targets"), list):
                    raise SetupError("Unexpected list_targets response; contents omitted.")
                print(f"Action Server list_targets through Executor OK; {len(payload['result']['targets'])} targets; contents omitted.")


async def register(url: str, key: str, data_dir: Path) -> None:
    import httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async with httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=120) as http:
        origin = url.removesuffix("/mcp")
        headers = {"Authorization": "Bearer " + key}
        response = await http.get(origin + "/v1/apps", params={"owner": "local", "slug": "codex"}, headers=headers)
        response.raise_for_status()
        existing = [app for app in response.json() if app["slug"] == "codex"]
        marker = data_dir / "codex-integration.json"
        if existing:
            if not marker.exists() or json.loads(marker.read_text()) != {"id": existing[0]["id"], "url": CODEX_URL}:
                raise SetupError("The codex namespace already exists without this registration record; inspect it before changing anything.")
            print("Existing codex integration retained.")
            return
        # Only initialize and discover. Do not start an offline Action Server.
        try:
            async with streamable_http_client(CODEX_URL, http_client=http) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    catalog = await session.list_tools()
                    names = {tool.name for tool in catalog.tools}
                    if not {"list_targets", "discover_threads"}.issubset(names):
                        raise SetupError("Action Server lacks the required Codex read-only tools.")
        except SetupError:
            raise
        except Exception:
            raise SetupError("Action Server is unavailable at 127.0.0.1:8088/mcp; no app was imported. Run --register-codex when its owner starts it.") from None
        response = await http.post(origin + "/dashboard/api/apps/import", headers=headers, json={
            "source": {"kind": "mcp", "name": "Codex", "url": CODEX_URL},
        })
        response.raise_for_status()
        app = response.json()
        if app.get("slug") != "codex":
            raise SetupError("Import returned an unexpected namespace; inspect Executor apps before retrying.")
        write_private(marker, json.dumps({"id": app["id"], "url": CODEX_URL}) + "\n")
        print("Registered Codex Action Server as upstream Executor MCP app codex.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    for mode in ("check-config", "write-auth-header", "health", "register-codex", "probe", "check-tunnel-ownership"):
        modes.add_argument("--" + mode, action="store_true")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    try:
        if args.check_tunnel_ownership:
            refuse_live_tunnel()
            return 0
        data_dir = Path(os.environ.get("EXECUTOR_DATA_DIR", str(Path.home() / ".local/share/executor")))
        private_path(data_dir, directory=True)
        key_file = data_dir / "keys.json"
        private_path(key_file)
        key = json.loads(key_file.read_text())["apiKey"]
        if not isinstance(key, str) or len(key) < 32 or any(char.isspace() for char in key):
            raise SetupError("Executor API key file is invalid; contents omitted.")
        try:
            url = validate_mcp_url(os.environ.get("EXECUTOR_MCP_URL", "http://127.0.0.1:4312/mcp"))
        except ValueError:
            raise SetupError("EXECUTOR_MCP_URL must be numeric loopback HTTP at /mcp, without URL credentials or suffixes.") from None
        for package, version in {"mcp": "2.0.0", "httpx": "0.28.1"}.items():
            if importlib.metadata.version(package) != version:
                raise SetupError("Install the pinned requirements.txt in the check Python environment.")
        if args.check_config:
            print("Executor private configuration valid; no MCP request made.")
        elif args.write_auth_header:
            write_private(data_dir / "tunnel-auth-header", "Bearer " + key + "\n")
        elif args.register_codex:
            asyncio.run(register(url, key, data_dir))
        else:
            asyncio.run(asyncio.wait_for(acceptance(url, key, data_dir, args.health), timeout=90))
    except SetupError as error:
        print(str(error), file=sys.stderr)
        return 2
    except Exception:
        print("Executor setup/check failed; check private storage and local service readiness. Raw errors omitted.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
