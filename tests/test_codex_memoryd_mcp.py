"""Read-only MCP contract for the codex-memoryd bridge."""
import importlib.util
import json
from pathlib import Path
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "codex_memoryd_mcp", ROOT / "scripts/codex_memoryd_mcp.py"
)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)
compose_spec = importlib.util.spec_from_file_location(
    "compose_control", ROOT / "scripts/compose_control.py"
)
compose_control = importlib.util.module_from_spec(compose_spec)
compose_spec.loader.exec_module(compose_control)


class Backend:
    def __init__(self):
        self.calls = []

    def request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        if path == "/healthz":
            return {"ok": True}
        return {"ok": True, "data": {"authority": "recall_not_authority", "items": []}}


class McpContractTests(unittest.TestCase):
    def test_tool_catalog_contains_only_scoped_read_only_tools(self):
        response = bridge.handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, Backend()
        )
        tools = response["result"]["tools"]
        self.assertEqual(
            [tool["name"] for tool in tools],
            ["memory_status", "memory_recall", "memory_search"],
        )
        for tool in tools:
            self.assertTrue(tool["annotations"]["readOnlyHint"])
            self.assertFalse(tool["annotations"]["destructiveHint"])
            self.assertNotIn("profile", tool["inputSchema"]["properties"])
            self.assertNotIn("workspace", tool["inputSchema"]["properties"])

    def test_search_always_uses_the_configured_profile_and_workspace(self):
        backend = Backend()
        response = bridge.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "memory_search",
                    "arguments": {"query": "Dakota deployment", "limit": 5},
                },
            },
            backend,
        )
        self.assertEqual(
            backend.calls,
            [("POST", "/v1/search", {
                "profile": "personal",
                "workspace": "dakota-codex-only",
                "query": "Dakota deployment",
                "limit": 5,
                "includeArchived": False,
            })],
        )
        self.assertFalse(response["result"]["isError"])
        self.assertIn("recall_not_authority", response["result"]["content"][0]["text"])

    def test_write_tool_and_scope_override_are_rejected_without_backend_access(self):
        for name, arguments in (
            ("memory_conclude", {"content": "must not be written"}),
            ("memory_search", {"query": "x", "profile": "work"}),
            ("memory_recall", {"query": "x", "workspace": "other"}),
        ):
            backend = Backend()
            response = bridge.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                },
                backend,
            )
            self.assertTrue(response["result"]["isError"])
            self.assertEqual(backend.calls, [])

    def test_initialize_negotiates_a_supported_streamable_http_version(self):
        response = bridge.handle_message(
            {
                "jsonrpc": "2.0",
                "id": "init",
                "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
            },
            Backend(),
        )
        self.assertEqual(response["result"]["protocolVersion"], "2025-11-25")
        self.assertIn("tools", response["result"]["capabilities"])

    def test_existing_tunnel_kit_mcp_client_discovers_and_calls_the_http_bridge(self):
        backend = Backend()
        server = bridge.McpServer(("127.0.0.1", 0), backend)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}"
            client = compose_control.Mcp(compose_control.Http(origin), "/mcp")
            tools = client.tools()
            self.assertEqual(
                [tool["name"] for tool in tools],
                ["memory_status", "memory_recall", "memory_search"],
            )
            result = client.call(
                "tools/call",
                {"name": "memory_search", "arguments": {"query": "runtime"}},
            )
            self.assertFalse(result["isError"])
            self.assertEqual(
                backend.calls[-1],
                ("POST", "/v1/search", {
                    "profile": "personal",
                    "workspace": "dakota-codex-only",
                    "query": "runtime",
                    "includeArchived": False,
                }),
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_backend_and_listener_origins_cannot_be_public(self):
        with self.assertRaises(ValueError):
            bridge.MemorydBackend("http://memory.example:8787")
        with self.assertRaises(ValueError):
            bridge._private_bind_address("8.8.8.8:8090")
        self.assertEqual(bridge._private_bind_address("172.30.86.1:8090"), ("172.30.86.1", 8090))


if __name__ == "__main__":
    unittest.main()
