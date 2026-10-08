"""Deployment boundary regressions; no production credentials or Docker starts."""

import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import socket
import shlex
import subprocess
import tempfile
import unittest
import copy
import threading
import time
import urllib.error
from contextlib import redirect_stderr
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from mcp_fixtures import LoopbackServer

ROOT = Path(__file__).resolve().parents[1]
INDEX = '''import { defineApp, toolAnnotations, withApprovals } from "apps"
import { mcpRouter } from "apps/mcp"
import { always } from "apps/operations/approval"

export default defineApp({ accounts: {} }, async ({ signal, cache }) => ({
  tools: withApprovals(await mcpRouter({
    url: "http://172.30.86.1:8088/mcp",
    cache,
    signal,
  }),
    // Ask before running tools the server marks destructive. Edit this rule to change which tools need approval.
    (tool) => (toolAnnotations(tool)?.destructiveHint === true ? always() : undefined),
  ),
}))
'''
CODEX_INDEX = '''import { defineApp } from "apps"
import { mcpRouter } from "apps/mcp"

export default defineApp({ accounts: {} }, async ({ signal, cache }) => ({
  tools: await mcpRouter({
    url: "http://172.30.86.1:8088/mcp",
    cache,
    signal,
  }),
}))
'''


class ComposeBoundaryTests(unittest.TestCase):
    def helper(self):
        path = ROOT / "scripts/compose_control.py"
        self.assertTrue(path.is_file(), "Compose boundary helper is missing")
        spec = importlib.util.spec_from_file_location("compose_control", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_bridge_only_restart_never_mutates_compose_or_bootstraps_apps(self):
        helper = self.helper()
        bridge = helper.host_bridge()
        state = '/fixture/private/devsy-bridge'
        configuration = {'x-operator': {'devsy_state': state}}
        value = {'state': state}
        events = []
        with patch.object(helper, 'config', return_value=configuration), \
             patch.object(helper, 'host_bridge', return_value=bridge), \
             patch.object(helper, 'network_preflight', side_effect=lambda config: events.append('preflight')), \
             patch.object(bridge, 'settings', return_value=value), \
             patch.object(bridge, 'stop', side_effect=lambda path: events.append(('stop', path))), \
             patch.object(bridge, 'start', side_effect=lambda config: events.append(('start', config))), \
             patch.object(helper, 'compose', side_effect=AssertionError('Container mutation forbidden')), \
             patch.object(helper, 'bootstrap', side_effect=AssertionError('App bootstrap forbidden')), \
             patch('sys.argv', ['compose_control.py', 'restart-devsy']):
            self.assertEqual(helper.main(), 0)
        self.assertEqual(events, ['preflight', ('stop', state), ('start', value)])

    def test_host_devsy_errors_are_actionable_at_the_command_boundary(self):
        helper = self.helper()
        bridge = helper.host_bridge()
        message = "Set an absolute existing Devsy executable and working directory."
        for operation in ("settings", "start", "stop", "health"):
            with self.subTest(operation=operation):
                stderr = io.StringIO()
                with patch.object(bridge, operation, side_effect=bridge.BridgeError(message)), \
                     patch.object(helper, "status", side_effect=lambda: helper.devsy_call(bridge, operation, {})), \
                     patch("sys.argv", ["compose_control.py", "status"]), redirect_stderr(stderr):
                    self.assertEqual(helper.main(), 2)
                self.assertEqual(stderr.getvalue(), message + "\n")

    def test_unexpected_host_devsy_errors_keep_private_details_omitted(self):
        helper = self.helper()
        bridge = helper.host_bridge()
        stderr = io.StringIO()
        with patch.object(bridge, "settings", side_effect=RuntimeError("PRIVATE_FIXTURE_VALUE")), \
             patch.object(helper, "status", side_effect=lambda: helper.devsy_call(bridge, "settings", {})), \
             patch("sys.argv", ["compose_control.py", "status"]), redirect_stderr(stderr):
            self.assertEqual(helper.main(), 1)
        self.assertIn("Control-plane setup/probe failed (RuntimeError at ", stderr.getvalue())
        self.assertIn("devsy_call:", stderr.getvalue())
        self.assertIn("raw errors and private values omitted.", stderr.getvalue())
        self.assertNotIn("PRIVATE_FIXTURE_VALUE", stderr.getvalue())

    def test_existing_unrelated_network_overlap_is_rejected(self):
        helper = self.helper()
        networks = [{"Name": "unrelated", "IPAM": {"Config": [
            {"Subnet": "172.30.0.0/16", "Gateway": "172.30.0.1"}]}}]
        with self.assertRaises(helper.ControlError):
            helper.validate_network("172.30.86.0/24", "172.30.86.1", [], networks)

    def test_managed_bridge_is_retained_but_mismatched_gateway_is_rejected(self):
        helper = self.helper()
        network = {"Name": "codex-control-plane_control-plane", "Driver": "bridge", "Id": "123456789012abcdef",
                   "Labels": {"com.docker.compose.project": "codex-control-plane",
                              "com.docker.compose.network": "control-plane"},
                   "IPAM": {"Config": [{"Subnet": "172.30.86.0/24", "Gateway": "172.30.86.1"}]}}
        routes = [{"dst": "172.30.86.0/24", "dev": "br-123456789012"}]
        helper.validate_network("172.30.86.0/24", "172.30.86.1", routes, [network])
        network["IPAM"]["Config"][0]["Gateway"] = "172.30.86.2"
        with self.assertRaises(helper.ControlError):
            helper.validate_network("172.30.86.0/24", "172.30.86.1", routes, [network])

    def test_labeled_nonbridge_network_is_not_adopted(self):
        helper = self.helper()
        network = {"Name": "codex-control-plane_control-plane", "Driver": "macvlan",
                   "Labels": {"com.docker.compose.project": "codex-control-plane",
                              "com.docker.compose.network": "control-plane"},
                   "IPAM": {"Config": [{"Subnet": "172.30.86.0/24", "Gateway": "172.30.86.1"}]}}
        with self.assertRaises(helper.ControlError):
            helper.validate_network("172.30.86.0/24", "172.30.86.1", [], [network])

    def test_host_route_overlap_and_public_gateway_are_rejected(self):
        helper = self.helper()
        for subnet, gateway, routes in (
            ("172.30.86.0/24", "172.30.86.1", [{"dst": "172.30.0.0/16", "dev": "vpn0"}]),
            ("8.8.8.0/24", "8.8.8.1", []),
            ("172.30.86.0/24", "172.30.87.1", []),
        ):
            with self.subTest(subnet=subnet, gateway=gateway):
                with self.assertRaises(helper.ControlError):
                    helper.validate_network(subnet, gateway, routes, [])

    def test_target_prepare_rewrites_only_local_socket_and_preserves_original(self):
        helper = self.helper()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            server = socket.socket(socket.AF_UNIX)
            try:
                server.bind(str(base / "daemon.sock"))
                data = {"targets": {"local": {"transport": "local", "socket_path": str(base / "daemon.sock"),
                                               "codex_bin": "codex"},
                                    "devsy": {"transport": "devsy", "context": "default", "workspace": "existing"}}}
                original = json.dumps(data)
                source = base / "operator.json"
                source.write_text(original)
                generated = helper.prepare_targets(source, base, os.getuid())
                self.assertEqual(source.read_text(), original)
                data["targets"]["local"]["socket_path"] = "/run/native-codex/daemon.sock"
                self.assertEqual(generated, data)
            finally:
                server.close()

    def test_secret_file_permissions_and_symlinks_fail_closed(self):
        helper = self.helper()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            file = base / "secret"
            file.write_text("NONPRODUCTION_FIXTURE_TOKEN")
            file.chmod(0o600)
            self.assertEqual(helper.read_private(file), "NONPRODUCTION_FIXTURE_TOKEN")
            file.chmod(0o644)
            with self.assertRaises(helper.ControlError):
                helper.read_private(file)
            file.chmod(0o600)
            link = base / "link"
            link.symlink_to(file)
            with self.assertRaises(helper.ControlError):
                helper.read_private(link)

    def test_codex_source_imports_every_tool_without_executor_approval_wrapper(self):
        helper = self.helper()
        url = "http://172.30.86.1:8088/mcp"
        source = {"files": [{"path": "index.ts", "content": CODEX_INDEX}]}
        helper.verify_codex_app_source(source, url)
        self.assertNotIn("withApprovals", CODEX_INDEX)
        for text in (CODEX_INDEX.replace(url, "http://172.30.86.1:8089/mcp"), INDEX):
            with self.assertRaises(helper.ControlError):
                helper.verify_codex_app_source({"files": [{"path": "index.ts", "content": text}]}, url)

    def test_devsy_retains_stock_destructive_approval_source(self):
        helper = self.helper()
        helper.verify_devsy_app_source({"files": [{"path": "index.ts", "content": INDEX.replace(
            "http://172.30.86.1:8088/mcp", "http://172.30.86.1:8089/mcp")}]},
                                       "http://172.30.86.1:8089/mcp")
        self.assertIn("withApprovals", INDEX)
        self.assertIn("toolAnnotations(tool)?.destructiveHint === true ? always()", INDEX)

    def test_comments_cannot_impersonate_stock_import_source(self):
        helper = self.helper()
        fake = '// url: "http://172.30.86.1:8088/mcp" mcpRouter( withApprovals( toolAnnotations(tool)?.destructiveHint === true ? always() : undefined\nexport default unrelated()'
        with self.assertRaises(helper.ControlError):
            helper.verify_codex_app_source({"files": [{"path": "index.ts", "content": fake}]}, "http://172.30.86.1:8088/mcp")

    def test_fresh_private_parent_creation_survives_normal_umask(self):
        helper = self.helper()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            old = os.umask(0o022)
            try:
                helper.write_private(root / "secrets" / "executor-pat", "NONPRODUCTION_PAT\n")
                helper.private_directory(root)
            finally:
                os.umask(old)
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)

    def test_mcp_negotiated_version_is_used_for_subsequent_requests(self):
        helper = self.helper()
        requests = []
        def dispatch(method, path, headers, body):
            requests.append((body, dict(headers)))
            if "id" not in body:
                return 202, None, False
            result = {"protocolVersion": "2025-03-26", "capabilities": {}, "serverInfo": {"name": "fixture", "version": "1"}} if body["method"] == "initialize" else {"tools": []}
            return 200, {"jsonrpc": "2.0", "id": body["id"], "result": result}, True
        server = LoopbackServer(dispatch)
        try:
            helper.Mcp(helper.Http(server.url), "/mcp").tools()
        finally:
            server.close()
        for _, headers in requests[1:]:
            self.assertEqual(next(value for name, value in headers.items() if name.lower() == "mcp-protocol-version"), "2025-03-26")

    def test_saved_app_rename_refuses_duplicate_import(self):
        helper = self.helper()
        self.assertTrue(callable(getattr(helper, "ensure_codex_app", None)), "Bounded import function is missing")
        requests = []
        app = {"id": "fixture_app", "slug": "renamed", "name": "Renamed", "activeDeployment": "fixture_deployment"}
        def dispatch(method, path, headers, body):
            requests.append((method, path))
            if path == "/api/context":
                return 200, {"organization": "fixture_org"}, False
            if path.endswith("/inventory"):
                return 200, {"apps": [app]}, False
            return 400, {}, False
        server = LoopbackServer(dispatch)
        try:
            with self.assertRaises(helper.ControlError):
                helper.ensure_codex_app(helper.Http(server.url), "http://172.30.86.1:8088/mcp", {"organization": "fixture_org", "id": "fixture_app", "url": "http://172.30.86.1:8088/mcp"})
        finally:
            server.close()
        self.assertFalse(any(method == "POST" for method, _ in requests))

    def test_import_without_receipt_is_adopted_on_retry_without_duplicate(self):
        helper = self.helper()
        apps, requests = [], []
        def dispatch(method, path, headers, body):
            requests.append((method, path))
            if path == "/api/context":
                return 200, {"organization": "fixture_org"}, False
            if path.endswith("/inventory"):
                return 200, {"apps": apps}, False
            if method == "POST" and path.endswith("/apps/import"):
                app = {"id": "fixture_app", "slug": "codex", "name": "Codex", "activeDeployment": "fixture_deployment"}
                apps.append(app)
                return 200, app, False
            if path.endswith("/source"):
                return 200, {"files": [{"path": "index.ts", "content": CODEX_INDEX}]}, False
            return 400, {}, False
        server = LoopbackServer(dispatch)
        try:
            first = helper.ensure_codex_app(helper.Http(server.url), "http://172.30.86.1:8088/mcp")
            second = helper.ensure_codex_app(helper.Http(server.url), "http://172.30.86.1:8088/mcp")
        finally:
            server.close()
        self.assertEqual(first, second)
        self.assertEqual(sum(method == "POST" for method, _ in requests), 1)

    def test_existing_codex_app_is_updated_in_place_from_exact_legacy_source(self):
        helper = self.helper()
        app = {"id": "fixture_app", "slug": "codex", "name": "Codex", "activeDeployment": "dpl_old"}
        apps, requests = [app.copy()], []
        retained_files = [{"path": "index.ts", "content": INDEX},
                          {"path": "metadata.json", "content": "{\"fixture\":true}"}]
        def dispatch(method, path, headers, body):
            requests.append((method, path, body))
            if path == "/api/context":
                return 200, {"organization": "fixture_org"}, False
            if path.endswith("/inventory"):
                return 200, {"apps": apps}, False
            if path.endswith("/apps/fixture_app"):
                return 200, apps[0], False
            if path.endswith("/apps/fixture_app/source"):
                if apps[0]["activeDeployment"] == "dpl_new":
                    return 200, {"files": [{"path": "index.ts", "content": CODEX_INDEX}, retained_files[1]]}, False
                return 200, {"files": retained_files}, False
            if method == "POST" and path.endswith("/apps/fixture_app/deploy"):
                apps[0]["activeDeployment"] = "dpl_new"
                return 200, {"app": apps[0]}, False
            return 400, {}, False
        server = LoopbackServer(dispatch)
        try:
            receipt = helper.ensure_codex_app(helper.Http(server.url),
                                              "http://172.30.86.1:8088/mcp",
                                              {"organization": "fixture_org", "id": "fixture_app",
                                               "url": "http://172.30.86.1:8088/mcp"})
        finally:
            server.close()
        self.assertEqual(receipt["id"], "fixture_app")
        self.assertEqual(sum(method == "POST" and path.endswith("/apps/import")
                             for method, path, _ in requests), 0)
        deployments = [body for method, path, body in requests if method == "POST" and path.endswith("/deploy")]
        self.assertEqual(len(deployments), 1)
        self.assertEqual(deployments[0]["files"], [{"path": "index.ts", "content": CODEX_INDEX}, retained_files[1]])

    def test_unknown_existing_codex_source_is_not_overwritten_or_duplicated(self):
        helper = self.helper()
        requests = []
        def dispatch(method, path, headers, body):
            requests.append((method, path))
            if path == "/api/context":
                return 200, {"organization": "fixture_org"}, False
            if path.endswith("/inventory"):
                return 200, {"apps": [{"id": "fixture_app", "slug": "codex", "name": "Codex",
                                         "activeDeployment": "dpl_current"}]}, False
            if path.endswith("/source"):
                return 200, {"files": [{"path": "index.ts", "content": "export default unrelated()"}]}, False
            return 400, {}, False
        server = LoopbackServer(dispatch)
        try:
            with self.assertRaises(helper.ControlError):
                helper.ensure_codex_app(helper.Http(server.url), "http://172.30.86.1:8088/mcp")
        finally:
            server.close()
        self.assertFalse(any(method == "POST" for method, _ in requests))

    def test_undeployed_or_replaced_saved_app_is_not_imported_over(self):
        helper = self.helper()
        for identifier, deployment in (("replacement", "fixture_deployment"), ("fixture_app", None)):
            requests = []
            def dispatch(method, path, headers, body):
                requests.append((method, path))
                if path == "/api/context":
                    return 200, {"organization": "fixture_org"}, False
                if path.endswith("/inventory"):
                    return 200, {"apps": [{"id": identifier, "slug": "codex", "name": "Codex", "activeDeployment": deployment}]}, False
                return 400, {}, False
            server = LoopbackServer(dispatch)
            try:
                with self.assertRaises(helper.ControlError):
                    helper.ensure_codex_app(helper.Http(server.url), "http://172.30.86.1:8088/mcp", {"organization": "fixture_org", "id": "fixture_app", "url": "http://172.30.86.1:8088/mcp"})
            finally:
                server.close()
            self.assertFalse(any(method == "POST" for method, _ in requests))

    def test_rootless_and_user_namespace_engines_are_rejected(self):
        helper = self.helper()
        self.assertTrue(callable(getattr(helper, "validate_engine", None)), "Rootful engine guard is missing")
        helper.validate_engine(["name=seccomp,profile=builtin", "name=cgroupns"])
        for options in (["name=rootless"], ["name=userns"]):
            with self.assertRaises(helper.ControlError):
                helper.validate_engine(options)

    def test_real_browser_branded_id_schema_is_accepted_but_model_response_is_rejected(self):
        helper = self.helper()
        schema = {"type": "object", "properties": {"requestId": {"anyOf": [
            {"type": "string", "pattern": "^apr_", "minLength": 5},
            {"type": "string", "pattern": "^elc_", "minLength": 5}]}},
            "required": ["requestId"], "additionalProperties": True}
        class Session:
            def tools(self):
                return [{"name": "execute"}, {"name": "skills"}, {"name": "resume", "inputSchema": schema}]
        helper.verify_compact(Session())
        original = copy.deepcopy(schema)
        schema["properties"]["response"] = {"type": "object"}
        with self.assertRaises(helper.ControlError):
            helper.verify_compact(Session())
        schema.clear()
        schema.update(original)
        schema["properties"]["requestId"]["anyOf"][1]["type"] = "number"
        with self.assertRaises(helper.ControlError):
            helper.verify_compact(Session())

    def test_import_reply_failure_is_reconciled_without_posting_twice(self):
        helper = self.helper()
        apps, posts = [], []
        def dispatch(method, path, headers, body):
            if path == "/api/context":
                return 200, {"organization": "fixture_org"}, False
            if path.endswith("/inventory"):
                return 200, {"apps": apps}, False
            if method == "POST":
                posts.append(body)
                apps.append({"id": "fixture_app", "slug": "codex", "name": "Codex", "activeDeployment": "fixture_deployment"})
                return 500, {}, False
            if path.endswith("/source"):
                return 200, {"files": [{"path": "index.ts", "content": CODEX_INDEX}]}, False
            return 400, {}, False
        server = LoopbackServer(dispatch)
        try:
            with self.assertRaises(urllib.error.HTTPError):
                helper.ensure_codex_app(helper.Http(server.url), "http://172.30.86.1:8088/mcp")
            receipt = helper.ensure_codex_app(helper.Http(server.url), "http://172.30.86.1:8088/mcp")
        finally:
            server.close()
        self.assertEqual(receipt["id"], "fixture_app")
        self.assertEqual(len(posts), 1)

    def test_trickled_sse_does_not_extend_the_read_deadline(self):
        helper = self.helper()
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                try:
                    for _ in range(20):
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                        time.sleep(0.015)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *_args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
        thread.start()
        client = helper.Http(f"http://127.0.0.1:{server.server_port}")
        started = time.monotonic()
        client.deadline = started + 0.06
        try:
            with self.assertRaises(helper.ControlError):
                client.request("GET", "/mcp")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        self.assertLess(time.monotonic() - started, 0.2)

    def test_oversized_sse_line_is_rejected_before_decoding(self):
        helper = self.helper()
        server = LoopbackServer(lambda *_: (200, {"result": "x" * (2 * 1024 * 1024)}, True))
        try:
            with self.assertRaises(helper.ControlError):
                helper.Http(server.url).request("GET", "/mcp")
        finally:
            server.close()

    def test_stock_tunnel_secret_loader_accepts_id_without_trailing_newline(self):
        for suffix in ("", "\n"):
            with self.subTest(newline=bool(suffix)), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                identifier = "tunnel_00000000000000000000000000000000"
                source = base / "tunnel-id"
                source.write_text(identifier + suffix)
                binary = base / "fixture-client"
                marker = base / "id-read"
                arguments = base / "arguments"
                binary.write_text("#!/bin/sh\n" + 'printf "%s" "$CONTROL_PLANE_TUNNEL_ID" > ' + shlex.quote(str(marker)) + "\n" + 'printf "%s\\n" "$@" > ' + shlex.quote(str(arguments)) + "\n")
                binary.chmod(0o700)
                script = base / "loader.sh"
                script.write_text((ROOT / "scripts/tunnel-secrets.sh").read_text().replace("/run/secrets/control-plane-tunnel-id", shlex.quote(str(source))).replace("/usr/bin/tunnel-client", shlex.quote(str(binary))))
                result = subprocess.run(["sh", str(script)], env={"PATH": os.defpath}, capture_output=True, text=True, timeout=3)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(marker.read_text(), identifier)
                self.assertNotIn(identifier, result.stdout + result.stderr + arguments.read_text())

    def test_changed_file_bind_is_not_replaced_under_running_cas(self):
        helper = self.helper()
        self.assertTrue(callable(getattr(helper, "write_bind_file", None)), "Live bind update boundary is missing")
        with tempfile.TemporaryDirectory() as temporary:
            file = Path(temporary) / "targets.json"
            helper.write_private(file, "original\n")
            with patch.object(helper, "compose", return_value=json.dumps([{"Service": "codex-action-server", "State": "running"}])):
                with self.assertRaises(helper.ControlError):
                    helper.write_bind_file(file, "changed\n")
            self.assertEqual(file.read_text(), "original\n")
            with patch.object(helper, "compose") as compose:
                helper.write_bind_file(file, "original\n")
                compose.assert_not_called()

    def test_terminal_resume_retires_receipt_but_transport_uncertainty_preserves_it(self):
        helper = self.helper()
        for outcome in ("denied", "unavailable", "native-error", "transport"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary)
                pending = state / "browser-approval.json"
                helper.write_private(pending, json.dumps({"requestId": "apr_fixture", "approvalUrl": "http://127.0.0.1:4312/approvals/fixture",
                    "mcpSession": {"sessionId": "FIXTURE_ORIGINAL_SESSION", "protocolVersion": "2025-11-25"}}))
                class Session:
                    def tools(self):
                        return [{"name": "execute"}, {"name": "skills"}, {"name": "resume", "inputSchema": {"type": "object", "properties": {"requestId": {"type": "string"}}, "required": ["requestId"]}}]
                    def call(self, method, params):
                        if outcome == "transport":
                            raise OSError("fixture transport failure")
                        data = {"status": "unavailable"} if outcome == "unavailable" else {"status": "completed", "execution": {"ok": outcome != "denied", "value": {"isError": True}}}
                        return {"structuredContent": data}
                with patch.object(helper, "executor_session", return_value=(None, Session())), patch.dict(os.environ, {"CONTROL_PLANE_BOOTSTRAP_DIR": str(state)}):
                    with self.assertRaises((helper.ControlError, OSError)):
                        helper.probe(resume=True)
                ambiguous = outcome in {"transport", "unavailable"}
                self.assertEqual(pending.exists(), ambiguous)
                self.assertEqual(bool(list(state.glob("browser-approval-terminal-*.json"))), not ambiguous)

    def test_resume_attaches_original_transport_without_initialize(self):
        helper = self.helper()
        self.assertIn("state", inspect.signature(helper.Mcp.__init__).parameters)
        requests = []
        def dispatch(method, path, headers, body):
            requests.append((body, dict(headers)))
            return 200, {"jsonrpc": "2.0", "id": body["id"], "result": {"tools": []}}, False
        server = LoopbackServer(dispatch)
        try:
            session = helper.Mcp(helper.Http(server.url), "/mcp?elicitation_mode=browser",
                                 state={"sessionId": "FIXTURE_ORIGINAL_SESSION", "protocolVersion": "2025-03-26"})
            session.tools()
        finally:
            server.close()
        self.assertEqual([body["method"] for body, _ in requests], ["tools/list"])
        lowered = {name.lower(): value for name, value in requests[0][1].items()}
        self.assertEqual(lowered["mcp-session-id"], "FIXTURE_ORIGINAL_SESSION")
        self.assertEqual(lowered["mcp-protocol-version"], "2025-03-26")

    def test_probe_persists_transport_and_ambiguous_resume_does_not_reexecute(self):
        helper = self.helper()
        calls, restored = [], []
        transport = {"sessionId": "FIXTURE_ORIGINAL_SESSION", "protocolVersion": "2025-11-25"}
        class Session:
            def session_state(self):
                return transport
            def tools(self):
                return [{"name": "execute"}, {"name": "skills"}, {"name": "resume", "inputSchema": {"type": "object", "properties": {"requestId": {"type": "string"}}, "required": ["requestId"]}}]
            def call(self, method, params):
                calls.append(params)
                if params["name"] == "resume":
                    return {"structuredContent": {"status": "unavailable", "requestId": "apr_fixture"}}
                if "tools.search(" in params["arguments"]["code"]:
                    return {"structuredContent": {"status": "completed", "execution": {"ok": True, "value": {"items": [{"path": "tools.codex.list_targets"}, {"path": "tools.codex.discover_threads"}]}}}}
                return {"structuredContent": {"status": "approval-required", "requestId": "apr_fixture", "approvalUrl": "http://127.0.0.1:4312/approvals/fixture"}}
        def connect(state=None):
            restored.append(state)
            return None, Session()
        with tempfile.TemporaryDirectory() as temporary, patch.object(helper, "executor_session", side_effect=connect), patch.dict(os.environ, {"CONTROL_PLANE_BOOTSTRAP_DIR": temporary}):
            self.assertEqual(helper.probe(), 3)
            pending = Path(temporary) / "browser-approval.json"
            saved = pending.read_text()
            self.assertIn("mcpSession", json.loads(saved), "Pending receipt lost its original MCP transport")
            self.assertEqual(json.loads(saved)["mcpSession"], transport)
            with self.assertRaises(helper.ControlError):
                helper.probe(resume=True)
            self.assertEqual(pending.read_text(), saved)
            with self.assertRaises(helper.ControlError):
                helper.probe()
        self.assertEqual(restored[:2], [None, transport])
        self.assertEqual(sum(params.get("arguments", {}).get("code") == "return await tools.codex.list_targets({});" for params in calls), 1)
        self.assertEqual(next(params["arguments"] for params in calls if params["name"] == "resume"), {"requestId": "apr_fixture"})

    def test_legacy_pending_receipt_is_not_reinitialized_or_discarded(self):
        helper = self.helper()
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"CONTROL_PLANE_BOOTSTRAP_DIR": temporary}):
            pending = Path(temporary) / "browser-approval.json"
            helper.write_private(pending, json.dumps({"requestId": "apr_fixture", "approvalUrl": "http://127.0.0.1:4312/approvals/fixture"}))
            original = pending.read_text()
            with patch.object(helper, "executor_session", side_effect=helper.ControlError("Fixture transport blocked")) as connect:
                with self.assertRaises(helper.ControlError):
                    helper.probe(resume=True)
                connect.assert_not_called()
            self.assertEqual(pending.read_text(), original)

    def test_prepare_preserves_selected_existing_runtime_and_receipts(self):
        helper = self.helper()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "operator.json"
            state, runtime, receipts = base / "cache", base / "old-runtime", base / "old-receipts"
            runtime.mkdir(mode=0o700)
            receipts.mkdir(mode=0o700)
            (runtime / "existing-history.db").write_bytes(b"fixture retained database")
            (receipts / "existing-receipt.json").write_text('{"receipt":"fixture-retained"}')
            sock = socket.socket(socket.AF_UNIX)
            try:
                sock.bind(str(base / "daemon.sock"))
                source.write_text(json.dumps({"targets": {"local": {"transport": "local", "socket_path": str(base / "daemon.sock")}}}))
                configuration = {"x-operator": {"targets_source": str(source)}, "services": {
                    "codex-action-server": {"user": f"{os.getuid()}:{os.getgid()}", "volumes": [
                        {"source": str(base / "targets.json"), "target": "/run/codex-action-server/targets.json"},
                        {"source": str(base), "target": "/run/native-codex"},
                        {"source": str(state), "target": "/var/lib/codex-action-server"},
                        {"source": str(runtime), "target": "/var/lib/codex-action-server/runtime"},
                        {"source": str(receipts), "target": "/var/lib/codex-action-server/receipts"}]},
                    "app-ready": {"volumes": [{"source": str(base / "bootstrap"), "target": "/var/lib/tunnel-kit"}]}}}
                with patch.object(helper, "compose", return_value="[]"):
                    helper.prepare(configuration)
            finally:
                sock.close()
            self.assertEqual((runtime / "existing-history.db").read_bytes(), b"fixture retained database")
            self.assertEqual((receipts / "existing-receipt.json").read_text(), '{"receipt":"fixture-retained"}')
            self.assertFalse((state / "runtime").exists(), "Preparation silently created a hidden replacement runtime")
            self.assertFalse((state / "receipts").exists(), "Preparation silently created a hidden replacement receipt store")


if __name__ == "__main__":
    unittest.main()
