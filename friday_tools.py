"""Friday-only MCP tool module for the local ChatGPT tunnel adapter."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from friday_contract import MAX_MESSAGE_LENGTH, REQUEST_ID_MAX_LENGTH, RUN_ID_RE


def _valid_request_id(value: str) -> bool:
    return bool(value) and len(value) <= REQUEST_ID_MAX_LENGTH and all(33 <= ord(ch) <= 126 for ch in value)


def _redact(value: Any, secret: str) -> Any:
    if isinstance(value, str):
        return value.replace(secret, "[REDACTED]") if secret else value
    if isinstance(value, list):
        return [_redact(item, secret) for item in value]
    if isinstance(value, dict):
        return {_redact(key, secret): _redact(item, secret) for key, item in value.items()}
    return value


class FridayApi:
    def __init__(self, *, api_key: str, base_url: str, timeout: float, session_id: str, registry):
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout
        self.session_id = session_id
        self.registry = registry

    async def request(self, method: str, path: str, *, json_body=None, request_id=None) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self.api_key}"}
        if request_id is not None:
            headers["Idempotency-Key"] = request_id
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.request(method, path, json=json_body)
        except httpx.TimeoutException:
            result: dict[str, Any] = {"ok": False, "error": "timeout"}
            if method == "POST":
                result["acceptance_unknown"] = True
            return result
        except httpx.RequestError:
            result = {"ok": False, "error": "upstream_unavailable"}
            if method == "POST":
                result["acceptance_unknown"] = True
            return result

        try:
            body: Any = response.json()
        except ValueError:
            body = response.text
        return {
            "ok": response.is_success,
            "http_status": response.status_code,
            "response": _redact(body, self.api_key),
        }


def register_friday_tools(server: MCPServer, api: FridayApi) -> None:
    """Register the bounded Friday tools. Add future integrations in the adapter entrypoint."""

    @server.tool(
        description="Submit a request to Friday in the dedicated ChatGPT tunnel session. The returned status may be queued or running; use friday_status to check it. Reuse request_id to make a manual retry idempotent.",
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False),
        structured_output=True,
    )
    async def friday_submit(message: str, request_id: str) -> dict[str, Any]:
        if not isinstance(message, str) or not message.strip():
            return {"ok": False, "error": "message_required"}
        if len(message) > MAX_MESSAGE_LENGTH:
            return {"ok": False, "error": "message_too_long", "max_characters": MAX_MESSAGE_LENGTH}
        if not isinstance(request_id, str) or not _valid_request_id(request_id):
            return {"ok": False, "error": "invalid_request_id", "max_characters": REQUEST_ID_MAX_LENGTH}

        result = await api.request(
            "POST",
            "/v1/runs",
            json_body={"input": message, "session_id": api.session_id},
            request_id=request_id,
        )
        response = result.get("response")
        if result.get("ok") and isinstance(response, dict):
            run_id = response.get("run_id")
            if isinstance(run_id, str) and RUN_ID_RE.fullmatch(run_id):
                try:
                    api.registry.register(run_id)
                except OSError:
                    result["tracking_error"] = "Friday accepted the run, but local status tracking could not be persisted."
        return result

    @server.tool(
        description="Return the current upstream status for a run previously submitted by this bridge.",
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True),
        structured_output=True,
    )
    async def friday_status(run_id: str) -> dict[str, Any]:
        if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
            return {"ok": False, "error": "invalid_run_id"}
        if not api.registry.contains(run_id):
            return {"ok": False, "error": "run_id_not_created_by_this_adapter"}
        return await api.request("GET", f"/v1/runs/{quote(run_id, safe='')}")

    @server.tool(
        description="Request cancellation of a run previously submitted by this bridge. The API may return status=stopping while the executor exits; use friday_status to confirm a terminal status. This tool does not claim the run has stopped.",
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False),
        structured_output=True,
    )
    async def friday_stop(run_id: str) -> dict[str, Any]:
        if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
            return {"ok": False, "error": "invalid_run_id"}
        if not api.registry.contains(run_id):
            return {"ok": False, "error": "run_id_not_created_by_this_adapter"}
        return await api.request("POST", f"/v1/runs/{quote(run_id, safe='')}/stop")
