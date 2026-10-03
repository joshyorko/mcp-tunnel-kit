#!/usr/bin/env python3
"""Local read-only readiness checks for the existing Codex Action Server.

The tunnel now forwards HTTP natively. This file registers no tools and starts
no server. --probe calls only discover_threads and read_thread on target local.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import importlib
import importlib.metadata
import json
import logging
import os
import re
import sys
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

DEFAULT_MCP_URL = "http://127.0.0.1:8088/mcp"


class ProbeError(Exception):
    """Fixed diagnostic text only; never include an upstream response."""


def validate_mcp_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except (ValueError, TypeError):
        raise ValueError("CODEX_MCP_URL must be numeric loopback HTTP at /mcp") from None
    if (
        parsed.scheme != "http"
        or not address.is_loopback
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/mcp"
        or parsed.query
        or parsed.fragment
        or port == 0
        or any(ch.isspace() or ord(ch) < 32 for ch in value)
        or "," in value
    ):
        raise ValueError("CODEX_MCP_URL must be numeric loopback HTTP at /mcp")
    return value


def native_result(response, operation: str, target: str = "local") -> dict:
    if response.is_error:
        raise ProbeError("Read-only Codex query failed; upstream response omitted.")
    data = response.structured_content
    if data is None:
        blocks = [block.text for block in response.content if block.type == "text"]
        if len(blocks) != 1:
            raise ProbeError("Codex query returned an unexpected result shape.")
        data = json.loads(blocks[0])
    if not isinstance(data, dict) or data.get("error"):
        raise ProbeError("Read-only Codex query failed; upstream response omitted.")
    envelope = data.get("result")
    if (
        not isinstance(envelope, dict)
        or envelope.get("operation") != operation
        or envelope.get("connection", {}).get("target") != target
        or not isinstance(envelope.get("result"), dict)
    ):
        raise ProbeError("Codex query returned an unexpected result shape or target.")
    return envelope["result"]


async def probe(url: str, cwd: str, target: str = "local", require_thread: bool = False) -> None:
    import httpx
    from mcp import ClientSession, types
    from mcp.client.streamable_http import streamable_http_client

    async with httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=20) as http:
        async with streamable_http_client(url, http_client=http) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                names = []
                cursor = None
                seen = set()
                while True:
                    params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
                    catalog = await session.list_tools(params=params)
                    names.extend(tool.name for tool in catalog.tools)
                    cursor = getattr(catalog, "next_cursor", None)
                    if not cursor:
                        break
                    if cursor in seen:
                        raise ProbeError("Codex tool discovery returned a repeated cursor.")
                    seen.add(cursor)
                if not {"discover_threads", "read_thread"}.issubset(names):
                    raise ProbeError("Upstream catalog lacks the Codex read-only query tools.")
                print("MCP initialization OK; tool catalog: " + ", ".join(names))
                response = await session.call_tool("discover_threads", {"payload": {
                    "target": target, "cwd": cwd, "limit": 1,
                }})
                result = native_result(response, "thread/list", target)
                threads = result.get("data")
                if not isinstance(threads, list):
                    raise ProbeError("Codex thread list returned an unexpected result shape.")
                print(f"discover_threads OK; target {target}; matching threads in page: {len(threads)}")
                if not threads and require_thread:
                    raise ProbeError("No matching thread; read proof is incomplete.")
                if threads:
                    thread = threads[0]
                    if thread.get("cwd") != cwd or not isinstance(thread.get("id"), str):
                        raise ProbeError("Codex discovery returned a different workstream.")
                    response = await session.call_tool("read_thread", {"payload": {
                        "target": target, "cwd": cwd, "thread_id": thread["id"],
                        "include_turns": False,
                    }})
                    metadata = native_result(response, "thread/read", target).get("thread", {})
                    if metadata.get("cwd") != cwd or metadata.get("id") != thread["id"]:
                        raise ProbeError("Codex read returned a different workstream.")
                    print("read_thread OK; turns excluded; thread contents omitted.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check-config", action="store_true", help="No network or server startup")
    mode.add_argument("--probe", action="store_true", help="Local MCP initialization, catalog and read-only query")
    parser.add_argument("--cwd", default=str(Path.cwd()), help="Exact absolute worktree path for the probe")
    parser.add_argument("--target", default="local", help="Operator-configured logical target, never an SSH destination")
    parser.add_argument("--require-thread", action="store_true", help="Fail unless discovery produces an exact thread read")
    args = parser.parse_args()
    try:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", args.target):
            raise ValueError("Invalid logical target")
        url = validate_mcp_url(os.environ.get("CODEX_MCP_URL", DEFAULT_MCP_URL))
        if not PurePosixPath(args.cwd).is_absolute() or ".." in PurePosixPath(args.cwd).parts:
            raise ValueError("Probe cwd must be an absolute path without parent traversal")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    try:
        for package, expected in {"mcp": "2.0.0", "httpx": "0.28.1"}.items():
            if importlib.metadata.version(package) != expected:
                raise ValueError("version mismatch")
            importlib.import_module(package)
    except (ImportError, ValueError, importlib.metadata.PackageNotFoundError):
        print("Codex MCP dependencies unavailable or incompatible; install requirements.txt in the check Python environment.", file=sys.stderr)
        return 2
    if args.check_config:
        print("Codex MCP configuration OK; no MCP request made.", file=sys.stderr)
        return 0
    # Transport exceptions can contain headers/URLs or response text. Do not log them.
    logging.disable(logging.CRITICAL)
    try:
        asyncio.run(asyncio.wait_for(probe(url, args.cwd, args.target, args.require_thread), timeout=30))
    except Exception:
        print("Codex MCP probe failed; check local service readiness and permissions. Response omitted.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
