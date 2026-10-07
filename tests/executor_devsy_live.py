#!/usr/bin/env python3
"""Disposable pinned-Executor integration check, with synthetic Codex and Devsy.

Run explicitly on a Linux Docker runner:
    python tests/executor_devsy_live.py

This owns its Docker container and anonymous volume, uses generated fixture-only
credentials, and never connects to a running Executor or a real Devsy binary.
No mutation is approved. The test is intentionally outside pytest discovery.

The public setup/import/PAT/browser contracts come from UsefulSoftwareCo/executor
at e1c4f014c89c3f27648fd77c728311b6a2767819, especially e2e/support/actors.ts,
e2e/tests/pat-mcp.spec.ts, and e2e/tests/import-approvals.spec.ts.
"""

from __future__ import annotations

import contextlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGE = ("ghcr.io/usefulsoftwareco/executor-selfhost:2.0.0-beta.8"
         "@sha256:a7d4e9d7c40aa02e08224757a59679ae61b6bfb59a61b3d06308e29f4652305a")
READS = {"provider_list", "workspace_list", "workspace_status"}
MUTATION = "workspace_delete"
CODEX_CONTROLS = {"start_thread", "create_thread_and_start_turn", "start_turn", "resume_thread",
                  "steer_turn", "interrupt_turn", "update_thread_settings", "update_turn_settings",
                  "set_thread_goal", "clear_thread_goal"}
FIXTURE_TOOLS = READS | {"workspace_create", "workspace_start", "workspace_stop", MUTATION,
                        "workspace_exec", "provider_add", "provider_delete", "provider_use",
                        "future_tool"}
STAGE = "fixture setup"
READ_RESULT = {
    "content": [{"type": "text", "text": "Synthetic Devsy read receipt"}],
    "structuredContent": {"fixture": "devsy-read", "items": [{"name": "fixture-only"}]},
    "isError": False,
    "_meta": {"fixture": "pass-through"},
}
CODEX_RESULT = {
    "content": [{"type": "text", "text": "Synthetic Codex read receipt"}],
    "structuredContent": {"result": {"targets": []}, "error": None},
    "isError": False,
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def tool(name, *, destructive=False):
    return {"name": name, "description": "Synthetic fixture " + name,
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            # Intentionally misleading: production normalization must override this.
            "annotations": {"readOnlyHint": not destructive, "destructiveHint": destructive}}


def stdio_fixture(log_path):
    """The only Devsy child launched by this test; records every actual invocation."""
    for line in sys.stdin:
        message = json.loads(line)
        if "id" not in message:
            continue
        method = message.get("method")
        if method == "initialize":
            result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "synthetic-devsy", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": [tool(name) for name in sorted(FIXTURE_TOOLS)]}
        elif method == "tools/call":
            params = message["params"]
            with open(log_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(params) + "\n")
                handle.flush()
            result = READ_RESULT if params["name"] in READS else {
                "content": [{"type": "text", "text": "Mutation reached synthetic fixture"}],
                "isError": True,
            }
        elif method == "ping":
            result = {}
        else:
            print(json.dumps({"jsonrpc": "2.0", "id": message["id"],
                              "error": {"code": -32601, "message": "Unknown fixture method"}}), flush=True)
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)


@contextlib.contextmanager
def fixture_servers(directory, host="127.0.0.1", subnet="127.0.0.0/8"):
    from mcp_fixtures import LoopbackServer

    bridge = load_script("devsy_bridge")
    log_path = directory / "devsy-calls.jsonl"
    binary = directory / "synthetic-devsy"
    binary.write_text(
        "#!" + sys.executable + "\nimport runpy, sys\n"
        + "sys.argv = [" + repr(str(Path(__file__).resolve())) + ", '--stdio-fixture', "
        + repr(str(log_path)) + "]\n"
        + "runpy.run_path(sys.argv[0], run_name='__main__')\n",
        encoding="utf-8",
    )
    binary.chmod(0o700)
    env = {"PATH": os.defpath, "HOME": str(directory), "DEVSY_HOME": str(directory / "devsy")}
    devsy = bridge.Devsy(str(binary), str(directory), env=env, timeout=15)
    server = bridge.BridgeServer((host, 0), devsy,
                                 ipaddress.ip_network(subnet), "executor-ci-fixture")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    codex_calls = []

    def dispatch(method, path, _headers, message):
        if method != "POST" or path != "/mcp" or not isinstance(message, dict):
            return 405, None, False
        if "id" not in message:
            return 202, None, False
        reply = {"jsonrpc": "2.0", "id": message["id"]}
        if message["method"] == "initialize":
            reply["result"] = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                               "serverInfo": {"name": "synthetic-codex", "version": "1"}}
        elif message["method"] == "tools/list":
            reply["result"] = {"tools": [tool(name, destructive=True) for name in sorted(
                {"list_targets", "discover_threads"} | CODEX_CONTROLS)]}
        elif message["method"] == "tools/call":
            codex_calls.append(message["params"])
            reply["result"] = CODEX_RESULT
        else:
            reply["error"] = {"code": -32601, "message": "Unknown fixture method"}
        return 200, reply, False

    codex = LoopbackServer(dispatch, host)
    try:
        yield {"devsy": f"http://{host}:{server.server_port}/mcp", "codex": codex.url + "/mcp",
               "calls": lambda: [json.loads(line) for line in log_path.read_text().splitlines()]
               if log_path.exists() else [], "codex_calls": codex_calls}
    finally:
        codex.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def docker(*arguments, timeout=60):
    result = subprocess.run(["docker", *arguments], check=False, capture_output=True,
                            text=True, timeout=timeout)
    require(result.returncode == 0, "Docker fixture command failed: " + arguments[0])
    return result.stdout.strip()


@contextlib.contextmanager
def disposable_executor(control, fixture_urls, network="host"):
    require(sys.platform == "linux" and shutil.which("docker"), "This live check requires Linux Docker")
    # The native runtime also allocates ephemeral ports. Match upstream release tests
    # by keeping the public listener below Linux's usual ephemeral range.
    for _ in range(100):
        port = 12000 + secrets.randbelow(10000)
        try:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", port))
            break
        except OSError:
            continue
    else:
        raise AssertionError("No unoccupied fixture port below the ephemeral range")
    origin = f"http://127.0.0.1:{port}"
    name = "executor-devsy-fixture-" + uuid.uuid4().hex
    # No host directories, named existing volumes, Docker socket, or credentials are mounted.
    networking = ["--network", network]
    if network != "host":
        networking += ["--publish", f"127.0.0.1:{port}:{port}"]
    args = ["run", "--detach", "--name", name, "--init", *networking,
            "--volume", "/app/data", "--env", "DO_NOT_TRACK=1", "--env",
            "HOST=" + ("127.0.0.1" if network == "host" else "0.0.0.0"),
            "--env", f"PORT={port}", "--env", f"BETTER_AUTH_URL={origin}",
            "--env", "EXECUTOR_APPS_ALLOW_PRIVATE_FETCH=true",
            "--env", "EXECUTOR_URL_ALLOW_LOOPBACK_HTTP=false", "--env",
            "EXECUTOR_URL_ALLOW_HTTP_ORIGINS=" + json.dumps([
                urllib.parse.urlsplit(url)._replace(path="", query="", fragment="").geturl()
                for url in fixture_urls]), IMAGE]
    def ready():
        deadline = time.monotonic() + 120
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), control.NoRedirect())
        while True:
            try:
                with opener.open(origin + "/health", timeout=2) as response:
                    require(response.status == 200, "Unexpected Executor health response")
                break
            except (OSError, urllib.error.HTTPError):
                require(time.monotonic() < deadline, "Disposable Executor did not become healthy")
                time.sleep(0.5)

    def restart():
        docker("restart", "--time", "10", name, timeout=60)
        ready()

    try:
        docker(*args, timeout=300)
        ready()
        yield origin, restart
    finally:
        # Name is generated here, never accepted from an environment variable or user input.
        subprocess.run(["docker", "rm", "--force", "--volumes", name], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)


def successful(control, session, code):
    result = control.execution(session.call("tools/call", {"name": "execute", "arguments": {"code": code}}))
    diagnostic = {"status": result.get("status"), "execution_ok": result.get("execution", {}).get("ok"),
                  "unavailable_count": len(result.get("unavailableApps") or [])}
    error = result.get("execution", {}).get("error")
    if isinstance(error, dict):
        diagnostic["error_keys"] = sorted(error.keys())
        for key in ("_tag", "phase", "reason"):
            if error.get(key) in {"McpError", "ProviderError", "connect", "discover", "call", "schema", "transport",
                                  "timeout", "request", "invalid_response", "invalid_input"}:
                diagnostic[key] = error[key]
    require(result.get("status") == "completed" and result.get("execution", {}).get("ok"),
            "Executor fixture execution did not complete: " + json.dumps(diagnostic))
    require(not result.get("unavailableApps"), "Executor reported an unavailable fixture app")
    return result["execution"].get("value")


def verify_fixtures(control, fixtures):
    """Also runnable without Docker to validate the actual stdio/HTTP bridge chain."""
    url = fixtures["devsy"]
    session = control.Mcp(control.Http(url.removesuffix("/mcp")), "/mcp")
    tools = {entry["name"]: entry for entry in session.tools()}
    require(READS | {MUTATION} <= tools.keys(), "Devsy fixture discovery missed expected tools")
    for name, entry in tools.items():
        require(entry["annotations"]["readOnlyHint"] is (name in READS), "Bridge read hint was not normalized")
        require(entry["annotations"]["destructiveHint"] is (name not in READS), "Bridge destructive hint was not normalized")
    result = session.call("tools/call", {"name": "provider_list", "arguments": {}})
    require(result == READ_RESULT, "Bridge did not preserve the complete MCP read result")
    require(fixtures["calls"]() == [{"name": "provider_list", "arguments": {}}],
            "Bridge fixture made an unexpected call")
    before = fixtures["calls"]()
    try:
        session.call("tools/call", {"name": "future_tool", "arguments": {}})
    except control.ControlError:
        pass
    else:
        raise AssertionError("Bridge accepted an unknown tool")
    require(fixtures["calls"]() == before, "Unknown tool reached the synthetic Devsy process")


def exercise_executor(control, origin, fixtures, restart):
    global STAGE
    STAGE = "first-owner setup"
    browser = control.Http(origin)
    browser.deadline = time.monotonic() + 600
    configuration, _ = browser.request("GET", "/api/auth/self-host/config")
    require(configuration.get("setup") is True, "Refusing to initialize an existing Executor")
    _, headers = browser.request("POST", "/api/auth/self-host/setup", {
        "name": "Isolated CI Owner", "email": "executor-ci@example.test",
        "password": "Synthetic-fixture-" + secrets.token_hex(24), "organizationName": "Isolated CI lab",
    }, {"Origin": origin})
    cookie = "; ".join(value.split(";", 1)[0] for value in headers.get_all("Set-Cookie", []))
    require(cookie, "Self-host setup did not issue a browser session")
    browser_headers = {"Origin": origin, "Cookie": cookie}
    organizations, _ = browser.request("GET", "/api/auth/organization/list", headers=browser_headers)
    require(len(organizations) == 1, "Fixture expected exactly one organization")
    organization = organizations[0]["id"]
    token, _ = browser.request("POST", "/api/auth/api-key/create", {
        "name": "Disposable Devsy CI", "expiresIn": 600, "metadata": {"organization": organization},
    }, browser_headers)
    try:
        STAGE = "Codex and Devsy imports"
        http = control.Http(origin, "Bearer " + token["key"])
        http.deadline = time.monotonic() + 600
        # Imports can compile packages; each operation remains bounded by Http's request limit.
        prefix = "/api/organizations/" + urllib.parse.quote(organization, safe="")
        codex_receipt = control.ensure_mcp_app(http, fixtures["codex"], "Codex")
        codex, _ = http.request("GET", prefix + "/apps/" + codex_receipt["id"])
        require(codex.get("slug") == "codex", "Unexpected Codex namespace")
        codex_source_path = prefix + "/apps/" + codex["id"] + "/source"
        codex_source, _ = http.request("GET", codex_source_path)
        control.verify_codex_app_source(codex_source, fixtures["codex"])
        devsy_receipt = control.ensure_mcp_app(http, fixtures["devsy"], "Devsy")
        devsy, _ = http.request("GET", prefix + "/apps/" + devsy_receipt["id"])
        require(devsy.get("slug") == "devsy", "Unexpected Devsy namespace")
        devsy_source_path = prefix + "/apps/" + devsy["id"] + "/source"
        devsy_source, _ = http.request("GET", devsy_source_path)
        control.verify_devsy_app_source(devsy_source, fixtures["devsy"])
        require(http.request("GET", codex_source_path)[0] == codex_source,
                "Importing Devsy changed Codex source or deployment")
        for receipt, name in ((codex_receipt, "Codex"), (devsy_receipt, "Devsy")):
            require(control.ensure_mcp_app(http, fixtures[name.lower()], name, receipt) == receipt,
                    "Repeated setup changed an app receipt")
        require(http.request("GET", codex_source_path)[0] == codex_source
                and http.request("GET", devsy_source_path)[0] == devsy_source,
                "Repeated setup changed source or deployment")
        STAGE = "container restart and app retention"
        restart()
        for receipt, name in ((codex_receipt, "Codex"), (devsy_receipt, "Devsy")):
            require(control.ensure_mcp_app(http, fixtures[name.lower()], name, receipt) == receipt,
                    "Restart changed an app receipt")
        require(http.request("GET", codex_source_path)[0] == codex_source
                and http.request("GET", devsy_source_path)[0] == devsy_source,
                "Restart changed source or deployment")
        # A pinned PAT needs no organization header on the bare /mcp endpoint.
        session = control.Mcp(http, "/mcp?elicitation_mode=browser")
        control.verify_compact(session)
        STAGE = "read-only catalog readiness after restart"
        deadline = time.monotonic() + 30
        for namespace, required in (("codex", {"list_targets"}),
                                    ("devsy", {"provider_list", "workspace_list"})):
            while True:
                code = "return await tools.search(" + json.dumps({
                    "namespace": namespace, "query": "", "limit": 100}) + ");"
                readiness = control.execution(session.call("tools/call", {"name": "execute", "arguments": {"code": code}}))
                require(readiness.get("status") == "completed" and readiness.get("execution", {}).get("ok"),
                        "Read-only catalog readiness did not complete")
                value = readiness["execution"].get("value")
                paths = {item["path"] for item in value.get("items", [])} if isinstance(value, dict) else set()
                if (not readiness.get("unavailableApps") and
                        {"tools." + namespace + "." + name for name in required} <= paths):
                    break
                require(time.monotonic() < deadline, "Restarted Executor apps did not become discoverable")
                # Only discovery is repeated. Tool calls and approval requests are never retried.
                time.sleep(0.5)
        STAGE = "scoped discovery"
        for namespace, expected in (("codex", {"list_targets", "discover_threads"}),
                                    ("devsy", READS | {MUTATION})):
            search = successful(control, session, "return await tools.search(" + json.dumps({
                "namespace": namespace, "query": "", "limit": 100,
            }) + ");")
            paths = {item["path"] for item in search["items"]}
            require({f"tools.{namespace}.{name}" for name in expected} <= paths,
                    namespace + " scoped search missed expected fixture tools")
            require(all(path.startswith("tools." + namespace + ".") for path in paths),
                    "Scoped search crossed namespaces")
        STAGE = "provider read pass-through"
        before = fixtures["calls"]()
        result = successful(control, session, "return await tools.devsy.provider_list({});")
        require(result == READ_RESULT, "Executor did not preserve the complete Devsy MCP result")
        require(fixtures["calls"]() == before + [{"name": "provider_list", "arguments": {}}],
                "Executor did not perform exactly one Devsy read")
        STAGE = "workspace read pass-through"
        require(successful(control, session, "return await tools.devsy.workspace_list({});") == READ_RESULT,
                "Workspace read did not traverse without approval")
        STAGE = "Codex read pass-through"
        require(successful(control, session, "return await tools.codex.list_targets({});") == CODEX_RESULT,
                "Codex read changed after Devsy import")
        STAGE = "Codex control calls bypass Executor approval"
        for name in sorted(CODEX_CONTROLS):
            result = successful(control, session, "return await tools.codex." + name + "({});")
            require(result == CODEX_RESULT, "Codex control call did not reach the synthetic CAS fixture")
            require(fixtures["codex_calls"][-1] == {"name": name, "arguments": {}},
                    "Codex control call reached a different native operation")
        STAGE = "browser mutation approval"
        before = fixtures["calls"]()
        pending = control.execution(session.call("tools/call", {"name": "execute", "arguments": {
            "code": "return await tools.devsy.workspace_delete({});",
        }}))
        require(pending.get("status") == "approval-required", "Mutation did not require browser approval")
        require(fixtures["calls"]() == before, "Mutation reached the upstream before approval")
        invocation = pending.get("invocation", {})
        require(invocation.get("app") == devsy["id"] and invocation.get("tool") == MUTATION
                and invocation.get("input") == {}, "Approval refers to the wrong invocation")
        approval = urllib.parse.urlsplit(pending["approvalUrl"])
        require(approval.scheme + "://" + approval.netloc == origin,
                "Browser approval link points outside disposable Executor")
        require(token["key"] not in pending["approvalUrl"], "Browser approval URL disclosed the PAT")
        review_path = "/api/mcp/approvals/" + urllib.parse.quote(pending["requestId"], safe="") + "?" + approval.query
        try:
            browser.request("GET", review_path)
        except urllib.error.HTTPError as error:
            require(error.code in {401, 403}, "Anonymous review failed unexpectedly")
        else:
            raise AssertionError("Anonymous caller could read the browser approval")
        review, _ = browser.request("GET", review_path, headers=browser_headers)
        require(review.get("status") == "pending", "Owner cannot inspect pending browser review")
        require(review.get("request", {}).get("requestId") == pending["requestId"],
                "Owner review returned a different pending interaction")
        require(fixtures["calls"]() == before, "Reading browser review executed the mutation")
        unknown = control.execution(session.call("tools/call", {"name": "execute", "arguments": {
            "code": "return await tools.devsy.future_tool({});",
        }}))
        require(unknown.get("status") == "approval-required", "Unknown tool bypassed browser approval")
        require(fixtures["calls"]() == before, "Unknown tool reached the native fixture")
        require(http.request("GET", codex_source_path)[0] == codex_source,
                "Devsy execution changed Codex source or deployment")
        # No browser answer or MCP resume is sent. Revocation and container teardown retire the pause.
    finally:
        browser.request("POST", "/api/auth/api-key/delete", {"keyId": token["id"]}, browser_headers)


def main():
    global STAGE
    if len(sys.argv) == 3 and sys.argv[1] == "--stdio-fixture":
        stdio_fixture(sys.argv[2])
        return 0
    require(sys.argv[1:] in ([], ["--check-fixtures"]), "Use no arguments or --check-fixtures")
    control = load_script("compose_control")
    with tempfile.TemporaryDirectory(prefix="executor-devsy-fixture-") as temporary:
        with fixture_servers(Path(temporary)) as fixtures:
            verify_fixtures(control, fixtures)
            if sys.argv[1:] == ["--check-fixtures"]:
                print("Synthetic Devsy stdio -> host HTTP bridge: discovery and read pass-through passed.")
                return 0
            STAGE = "disposable Executor startup"
            with disposable_executor(control, [fixtures["codex"], fixtures["devsy"]]) as (origin, restart):
                exercise_executor(control, origin, fixtures, restart)
    print("Pinned Executor: Codex import/update, ten control calls without approval, Devsy reads, and browser mutation pause passed.")
    print("No Devsy mutation was approved or forwarded; Codex controls used only disposable synthetic fixture state.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        # Assertion messages are fixed; HTTP bodies, auth cookies, and PATs are never printed.
        print((STAGE + ": " + str(error)) if isinstance(error, AssertionError) else
              "Disposable Executor integration failed during " + STAGE + " ("
              + type(error).__name__ + "); response omitted.",
              file=sys.stderr)
        raise SystemExit(1)
