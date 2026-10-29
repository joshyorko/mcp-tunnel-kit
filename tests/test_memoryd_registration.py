"""Managed Executor registration tests for the read-only MemoryD app."""
import importlib.util
import json
from pathlib import Path
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "compose_control", ROOT / "scripts/compose_control.py"
)
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)
bridge_spec = importlib.util.spec_from_file_location(
    "codex_memoryd_mcp", ROOT / "scripts/codex_memoryd_mcp.py"
)
bridge = importlib.util.module_from_spec(bridge_spec)
bridge_spec.loader.exec_module(bridge)

URL = "http://172.30.86.1:8090/mcp"
EXPECTED = {"memory_status", "memory_recall", "memory_search"}


class FakeMemorydBackend:
    def request(self, method, path, payload=None):
        if path == "/healthz":
            return {"ok": True}
        return {"ok": True, "data": {"authority": "recall_not_authority"}}


class FakeExecutorHttp:
    def __init__(self):
        self.calls = []
        self.apps = []
        self.url = None

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        if path == "/api/context":
            return {"organization": "org_test"}, {}
        if path == "/api/organizations/org_test/inventory":
            return {"apps": list(self.apps)}, {}
        if path == "/api/organizations/org_test/apps/import":
            self.url = body["source"]["url"]
            app = {
                "id": "app_memoryd",
                "slug": "memoryd",
                "name": "MemoryD",
                "activeDeployment": "deployment_1",
            }
            self.apps.append(app)
            return app, {}
        if path == "/api/organizations/org_test/apps/app_memoryd/source":
            return {"files": [{"path": "index.ts", "content": control.devsy_app_source(self.url)}]}, {}
        raise AssertionError(f"unexpected Executor API path: {path}")


class MemorydRegistrationTests(unittest.TestCase):
    def test_catalog_verifier_rejects_missing_extra_or_write_tools(self):
        tools = bridge.tool_catalog()
        control.verify_memoryd_catalog(tools)
        with self.assertRaises(control.ControlError):
            control.verify_memoryd_catalog(tools + [{
                "name": "memory_conclude",
                "annotations": {"readOnlyHint": False, "destructiveHint": True},
            }])

    def test_executor_import_is_idempotent_for_the_read_only_memoryd_endpoint(self):
        server = bridge.McpServer(("127.0.0.1", 0), FakeMemorydBackend())
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/mcp"
            http = FakeExecutorHttp()
            receipt = control.ensure_memoryd_app(http, url)
            self.assertEqual(receipt, {"organization": "org_test", "id": "app_memoryd", "url": url})
            replay = control.ensure_memoryd_app(http, url, receipt)
            self.assertEqual(replay, receipt)
            self.assertEqual(
                http.calls[2][2],
                {"source": {"kind": "mcp", "name": "MemoryD", "url": url}},
            )
            self.assertEqual(sum(call[1].endswith("/apps/import") for call in http.calls), 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_executor_search_checks_all_three_memoryd_tools(self):
        class Session:
            def call(self, method, params):
                self.request = (method, params)
                return {"content": [{"type": "text", "text": json.dumps({
                    "status": "completed",
                    "execution": {"ok": True, "value": {"items": [
                        {"path": f"tools.memoryd.{name}"} for name in sorted(EXPECTED)
                    ]}},
                })}]}

        session = Session()
        control.search_memoryd(session)
        self.assertEqual(session.request[0], "tools/call")

    def test_read_smoke_calls_status_recall_and_search_without_returning_memory_content(self):
        class Session:
            def call(self, method, params):
                self.request = (method, params)
                value = {"read_only_tools": [
                    {"isError": False, "contentBlocks": 1},
                    {"isError": False, "contentBlocks": 1},
                    {"isError": False, "contentBlocks": 1},
                ]}
                envelope = {"status": "completed", "execution": {"ok": True, "value": value}}
                return {"content": [{"type": "text", "text": json.dumps(envelope)}]}

        session = Session()
        result = control.probe_memoryd_reads(session)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["tools_called"], 3)
        self.assertNotIn("content", result)
