#!/usr/bin/env python3
"""Pinned disposable Executor proves first-use scoped create without browser consent."""

import hashlib
import ipaddress
import json
from pathlib import Path
import secrets
import tempfile
import threading
import time
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import executor_devsy_live as live

ROOT = Path(__file__).resolve().parents[1]


def main():
    control = live.load_script("compose_control")
    bridge = live.load_script("devsy_bridge")
    scope_module = live.load_script("worker_scope")
    setup = live.load_script("devsy_owner_setup")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        token = secrets.token_hex(32)
        config = root / "scope.json"
        value = json.loads((ROOT / "docs/devsy-worker-scope.proposed.json").read_text())
        value.update(
            enabled=True,
            expires_at=time.time() + 3600,
            capability_sha256=hashlib.sha256(token.encode()).hexdigest(),
            bindings={},
        )
        config.write_text(json.dumps(value))
        config.chmod(0o600)
        rows = {}
        calls = []

        def invoke(operation, name, approved):
            calls.append(operation)
            execution = approved["execution_context"]
            rows[name] = {
                "id": name,
                "uid": "fixture-uid",
                "context": "default",
                "source": {"gitRepository": execution["repository"],
                           "gitCommit": execution["revision"]},
                "devContainerPath": execution["recipe"],
                "provider": {
                    "name": "kubernetes",
                    "options": {
                        "KUBERNETES_CONTEXT": {"value": "ror"},
                        "KUBERNETES_NAMESPACE": {"value": "devsy"},
                    },
                },
            }

        recipe = b"{}"
        scope = scope_module.WorkerScope(
            config, root / "jobs", lambda: set(rows), lambda n: rows[n], invoke,
            source_resolver=lambda approved: {
                "repository": approved["repository"], "source_ref": approved["source_ref"],
                "revision": "d" * 40, "recipe": approved["recipe"],
                "recipe_sha256": hashlib.sha256(recipe).hexdigest(),
                "recipe_snapshot": recipe,
            },
        )

        class Synthetic:
            def __init__(self):
                self.scope = scope
                self.stopping = threading.Event()

            def catalog(self):
                return scope_module.tools() + [
                    live.tool("workspace_delete", destructive=True)
                ]

            def call(self, name, args, credential=None):
                result = scope.call(name, args, credential)
                return {
                    "content": [{"type": "text", "text": json.dumps(result)}],
                    "structuredContent": result,
                    "isError": False,
                }

        server = bridge.BridgeServer(
            ("127.0.0.1", 0),
            Synthetic(),
            ipaddress.ip_network("127.0.0.0/8"),
            "fixture",
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}/mcp"
        try:
            with live.disposable_executor(control, [url]) as (origin, restart):
                cookie = control.Http(origin, None)
                cookie.deadline = time.monotonic() + 600
                _, headers = cookie.request(
                    "POST",
                    "/api/auth/self-host/setup",
                    {
                        "email": "owner@example.test",
                        "password": secrets.token_urlsafe(24),
                        "name": "Fixture Owner",
                        "organizationName": "Scope Fixture",
                    },
                    {"Origin": origin},
                )
                cookie_headers = {
                    "Origin": origin,
                    "Cookie": "; ".join(
                        v.split(";", 1)[0] for v in headers.get_all("Set-Cookie", [])
                    ),
                }
                organizations, _ = cookie.request(
                    "GET", "/api/auth/organization/list", headers=cookie_headers
                )
                organization_id = organizations[0]["id"]
                pat, _ = cookie.request(
                    "POST",
                    "/api/auth/api-key/create",
                    {
                        "name": "fixture owner",
                        "metadata": {"organization": organization_id},
                    },
                    cookie_headers,
                )
                http = control.Http(origin, "Bearer " + pat["key"])
                http.deadline = time.monotonic() + 600
                prefix = "/api/organizations/" + organization_id
                app, _ = http.request(
                    "POST",
                    prefix + "/apps/import",
                    {"source": {"kind": "mcp", "name": "Devsy", "url": url}},
                )
                setup.deploy_owner_source(
                    control, http, prefix + "/apps/" + app["id"], url
                )
                profile = setup.connect_owner(http, prefix, app["id"], token)
                session = control.Mcp(http, "/mcp?elicitation_mode=browser")
                path = "tools.devsy.profiles[" + json.dumps(profile["id"]) + "]"
                result = live.successful(
                    control,
                    session,
                    "return await "
                    + path
                    + '.workspace_create_scoped({name:"cas-worker-01",request_id:"first-use"});',
                )
                live.require(
                    result["structuredContent"]["status"] == "accepted",
                    "First create did not immediately return an accepted receipt",
                )
                scope.wait()
                replay = live.successful(
                    control,
                    session,
                    "return await "
                    + path
                    + '.workspace_create_scoped({name:"cas-worker-01",request_id:"repeated"});',
                )
                live.require(
                    replay["structuredContent"]["operation_id"]
                    == result["structuredContent"]["operation_id"]
                    and calls == ["create"],
                    "Scoped create was replayed",
                )
                denied = control.execution(
                    session.call(
                        "tools/call",
                        {
                            "name": "execute",
                            "arguments": {
                                "code": "return await "
                                + path
                                + '.workspace_create_scoped({name:"codex-action-server",request_id:"forbidden"});'
                            },
                        },
                    )
                )
                live.require(
                    denied.get("status") == "completed"
                    and not denied["execution"]["ok"]
                    and calls == ["create"],
                    "Protected name was admitted",
                )
                gated = control.execution(
                    session.call(
                        "tools/call",
                        {
                            "name": "execute",
                            "arguments": {
                                "code": "return await "
                                + path
                                + ".workspace_delete({});"
                            },
                        },
                    )
                )
                live.require(
                    gated["status"] == "approval-required" and calls == ["create"],
                    "Raw deletion no longer requires approval",
                )
                print(
                    "PASS: API-only private profile setup; first scoped create completed without browser approval; replay suppressed; protected name refused; raw deletion gated."
                )
        finally:
            scope.wait()
            server.shutdown()
            server.server_close()
            thread.join(5)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(
            "Scoped Executor fixture failed: "
            + type(error).__name__
            + "; private response omitted.",
            file=sys.stderr,
        )
        raise
