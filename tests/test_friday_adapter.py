import asyncio
import json
import logging
import os
import shutil
import subprocess
import threading
import time
import unittest
from contextlib import asynccontextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


TEST_DIR = Path(__file__).resolve().parents[1]
ADAPTER = TEST_DIR / "friday_mcp_adapter.py"
LAUNCHER = TEST_DIR / "launch-friday.zsh"
PYTHON = Path(__import__("sys").executable)
ZSH = os.environ.get("ZSH_BIN") or shutil.which("zsh") or "zsh"
TEST_API_KEY = "test-only-friday-key-never-use-in-production"
logging.getLogger("httpx").setLevel(logging.WARNING)


class FakeFridayHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        pass

    def _reply(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except BrokenPipeError:
            pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        server = self.server
        is_stop = self.path.endswith("/stop")
        with server.lock:
            server.posts.append({
                "path": self.path,
                "body": payload,
                "idempotency_key": self.headers.get("Idempotency-Key"),
                "authorization": self.headers.get("Authorization"),
            })
        delay = server.stop_delay if is_stop else server.post_delay
        if delay:
            time.sleep(delay)
        status = server.stop_status if is_stop else server.post_status
        body = server.stop_body if is_stop else server.post_body
        self._reply(status, body)

    def do_GET(self):
        server = self.server
        with server.lock:
            server.gets.append(self.path)
        if server.get_delay:
            time.sleep(server.get_delay)
        self._reply(server.get_status, server.get_body)


class FakeFridayServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), FakeFridayHandler)
        self.lock = threading.Lock()
        self.posts = []
        self.gets = []
        self.post_status = 202
        self.post_body = {"run_id": "run_0123456789abcdef0123456789abcdef", "status": "queued"}
        self.post_delay = 0
        self.stop_status = 202
        self.stop_body = {"run_id": "run_0123456789abcdef0123456789abcdef", "status": "stopping"}
        self.stop_delay = 0
        self.get_status = 200
        self.get_body = {"run_id": "run_0123456789abcdef0123456789abcdef", "status": "running"}
        self.get_delay = 0


def result_data(result):
    value = getattr(result, "structuredContent", None)
    if value is None:
        value = getattr(result, "structured_content", None)
    if value is not None:
        return value
    for block in result.content:
        if getattr(block, "text", None):
            return json.loads(block.text)
    raise AssertionError("MCP tool returned no structured result")


class FridayAdapterTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.missing_entrypoints = not ADAPTER.is_file() or not LAUNCHER.is_file()

    def test_adapter_and_launcher_entrypoints_exist(self):
        self.assertTrue(ADAPTER.is_file(), "Friday stdio MCP adapter has not been implemented")
        self.assertTrue(LAUNCHER.is_file(), "Friday launcher has not been implemented")

    def setUp(self):
        if self.missing_entrypoints and self._testMethodName != "test_adapter_and_launcher_entrypoints_exist":
            self.skipTest("behavioral tests run once adapter and launcher exist")
        if self.missing_entrypoints:
            return
        self.upstream = FakeFridayServer()
        self.thread = threading.Thread(target=self.upstream.serve_forever, daemon=True)
        self.thread.start()
        self.state_dir = Path(self.temp_dir())

    def temp_dir(self):
        import tempfile
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        return self._temp.name

    def tearDown(self):
        if not hasattr(self, "upstream"):
            return
        self.upstream.shutdown()
        self.upstream.server_close()
        self.thread.join(timeout=2)

    def adapter_env(self, **overrides):
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
            "FRIDAY_API_KEY": TEST_API_KEY,
            "FRIDAY_API_BASE_URL": f"http://127.0.0.1:{self.upstream.server_port}/p/friday",
            "FRIDAY_RUN_REGISTRY": str(self.state_dir / "runs.json"),
            "FRIDAY_HTTP_TIMEOUT_SECONDS": "1",
        }
        env.update(overrides)
        return env

    @asynccontextmanager
    async def mcp(self, **env_overrides):
        params = StdioServerParameters(
            command=str(PYTHON),
            args=[str(ADAPTER)],
            cwd=str(TEST_DIR),
            env=self.adapter_env(**env_overrides),
        )
        async with stdio_client(params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                yield session

    async def test_discovery_exposes_submit_status_and_stop(self):
        async with self.mcp() as session:
            tools = await session.list_tools()
        self.assertEqual({tool.name for tool in tools.tools}, {"friday_submit", "friday_status", "friday_stop"})

    async def test_submit_uses_fixed_session_and_exact_idempotency_key(self):
        async with self.mcp() as session:
            result = await session.call_tool("friday_submit", {
                "message": "Give me a short status update.",
                "request_id": "chatgpt-test-request-001",
            })
        data = result_data(result)
        self.assertEqual(data["http_status"], 202)
        self.assertEqual(data["response"]["status"], "queued")
        self.assertEqual(len(self.upstream.posts), 1)
        post = self.upstream.posts[0]
        self.assertEqual(post["path"], "/p/friday/v1/runs")
        self.assertEqual(post["idempotency_key"], "chatgpt-test-request-001")
        self.assertEqual(post["body"]["input"], "Give me a short status update.")
        self.assertEqual(post["body"]["session_id"], "friday-chatgpt-tunnel")
        self.assertEqual(set(post["body"]), {"input", "session_id"})
        self.assertEqual(post["authorization"], f"Bearer {TEST_API_KEY}")

    async def test_status_requires_registered_run_and_preserves_running_state(self):
        async with self.mcp() as session:
            await session.call_tool("friday_submit", {"message": "hello", "request_id": "req-2"})
            result = await session.call_tool("friday_status", {
                "run_id": "run_0123456789abcdef0123456789abcdef",
            })
        data = result_data(result)
        self.assertEqual(data["http_status"], 200)
        self.assertEqual(data["response"]["status"], "running")
        self.assertEqual(self.upstream.gets, ["/p/friday/v1/runs/run_0123456789abcdef0123456789abcdef"])

    async def test_stop_posts_exact_route_for_registered_run_and_preserves_stopping(self):
        async with self.mcp() as session:
            await session.call_tool("friday_submit", {"message": "hello", "request_id": "req-stop"})
            result = await session.call_tool("friday_stop", {
                "run_id": "run_0123456789abcdef0123456789abcdef",
            })
        data = result_data(result)
        self.assertEqual(data["http_status"], 202)
        self.assertEqual(data["response"]["status"], "stopping")
        self.assertNotIn(data["response"]["status"], {"stopped", "cancelled", "canceled"})
        stops = [post for post in self.upstream.posts if post["path"].endswith("/stop")]
        self.assertEqual(len(stops), 1)
        self.assertEqual(stops[0]["path"], "/p/friday/v1/runs/run_0123456789abcdef0123456789abcdef/stop")
        self.assertEqual(stops[0]["authorization"], f"Bearer {TEST_API_KEY}")

    async def test_stop_rejects_unknown_and_invalid_run_ids_before_network(self):
        async with self.mcp() as session:
            unknown = await session.call_tool("friday_stop", {
                "run_id": "run_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            })
            invalid = await session.call_tool("friday_stop", {"run_id": "../../etc/passwd"})
        self.assertEqual(result_data(unknown)["error"], "run_id_not_created_by_this_adapter")
        self.assertEqual(result_data(invalid)["error"], "invalid_run_id")
        self.assertEqual(self.upstream.posts, [])
        self.assertEqual(self.upstream.gets, [])

    async def test_stop_preserves_already_terminal_response(self):
        self.upstream.stop_status = 409
        self.upstream.stop_body = {
            "error": {"code": "run_already_terminal", "message": "run has already completed"},
            "run_id": "run_0123456789abcdef0123456789abcdef",
            "status": "completed",
        }
        async with self.mcp() as session:
            await session.call_tool("friday_submit", {"message": "hello", "request_id": "req-stop-terminal"})
            result = await session.call_tool("friday_stop", {
                "run_id": "run_0123456789abcdef0123456789abcdef",
            })
        data = result_data(result)
        self.assertFalse(data["ok"])
        self.assertEqual(data["http_status"], 409)
        self.assertEqual(data["response"]["status"], "completed")
        self.assertEqual(data["response"]["error"]["code"], "run_already_terminal")

    async def test_stop_preserves_upstream_not_found_and_auth_errors(self):
        async with self.mcp() as session:
            await session.call_tool("friday_submit", {"message": "hello", "request_id": "req-stop-errors"})
            self.upstream.stop_status = 404
            self.upstream.stop_body = {"error": {"code": "run_not_found"}}
            not_found = await session.call_tool("friday_stop", {
                "run_id": "run_0123456789abcdef0123456789abcdef",
            })
            self.upstream.stop_status = 401
            self.upstream.stop_body = {"error": {"code": "unauthorized"}}
            unauthorized = await session.call_tool("friday_stop", {
                "run_id": "run_0123456789abcdef0123456789abcdef",
            })
        self.assertEqual(result_data(not_found)["http_status"], 404)
        self.assertEqual(result_data(not_found)["response"]["error"]["code"], "run_not_found")
        self.assertEqual(result_data(unauthorized)["http_status"], 401)
        self.assertEqual(result_data(unauthorized)["response"]["error"]["code"], "unauthorized")

    async def test_stop_timeout_reports_unknown_acceptance_without_retry(self):
        self.upstream.stop_delay = 0.25
        async with self.mcp(FRIDAY_HTTP_TIMEOUT_SECONDS="0.05") as session:
            await session.call_tool("friday_submit", {"message": "hello", "request_id": "req-stop-timeout"})
            result = await session.call_tool("friday_stop", {
                "run_id": "run_0123456789abcdef0123456789abcdef",
            })
        data = result_data(result)
        self.assertFalse(data["ok"])
        self.assertEqual(data["error"], "timeout")
        self.assertTrue(data["acceptance_unknown"])
        stops = [post for post in self.upstream.posts if post["path"].endswith("/stop")]
        self.assertEqual(len(stops), 1)

    async def test_stop_response_redacts_api_key(self):
        self.upstream.stop_body = {"status": "stopping", "detail": f"accepted by {TEST_API_KEY}"}
        async with self.mcp() as session:
            await session.call_tool("friday_submit", {"message": "hello", "request_id": "req-stop-redact"})
            result = await session.call_tool("friday_stop", {
                "run_id": "run_0123456789abcdef0123456789abcdef",
            })
        data = result_data(result)
        self.assertEqual(data["response"]["detail"], "accepted by [REDACTED]")
        self.assertNotIn(TEST_API_KEY, json.dumps(data))

    async def test_unknown_or_invalid_run_ids_never_reach_upstream(self):
        async with self.mcp() as session:
            unknown = await session.call_tool("friday_status", {"run_id": "run_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
            invalid = await session.call_tool("friday_status", {"run_id": "../../etc/passwd"})
        self.assertFalse(result_data(unknown)["ok"])
        self.assertFalse(result_data(invalid)["ok"])
        self.assertEqual(self.upstream.gets, [])

    async def test_status_preserves_upstream_not_found_status(self):
        self.upstream.get_status = 404
        self.upstream.get_body = {"error": {"message": "run not found"}}
        async with self.mcp() as session:
            await session.call_tool("friday_submit", {"message": "hello", "request_id": "req-404"})
            result = await session.call_tool("friday_status", {
                "run_id": "run_0123456789abcdef0123456789abcdef",
            })
        data = result_data(result)
        self.assertEqual(data["http_status"], 404)
        self.assertEqual(data["response"]["error"]["message"], "run not found")

    async def test_invalid_input_lengths_and_request_ids_are_rejected_locally(self):
        async with self.mcp() as session:
            too_long = await session.call_tool("friday_submit", {
                "message": "x" * 8001, "request_id": "req-long",
            })
            bad_request_id = await session.call_tool("friday_submit", {
                "message": "hello", "request_id": "contains spaces",
            })
        self.assertFalse(result_data(too_long)["ok"])
        self.assertFalse(result_data(bad_request_id)["ok"])
        self.assertEqual(self.upstream.posts, [])

    async def test_non_loopback_api_configuration_is_refused(self):
        env = self.adapter_env(FRIDAY_API_BASE_URL="https://example.invalid")
        proc = await asyncio.create_subprocess_exec(
            str(PYTHON), str(ADAPTER), cwd=TEST_DIR, env=env,
            stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=3)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(b"loopback", stderr.lower())
        self.assertNotIn(TEST_API_KEY.encode(), stderr)

    async def test_base_url_must_use_friday_profile_prefix(self):
        env = self.adapter_env(FRIDAY_API_BASE_URL=f"http://127.0.0.1:{self.upstream.server_port}")
        proc = await asyncio.create_subprocess_exec(
            str(PYTHON), str(ADAPTER), cwd=TEST_DIR, env=env,
            stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=3)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(b"/p/friday", stderr)

    async def test_upstream_error_status_and_body_are_preserved_and_redacted(self):
        self.upstream.post_status = 409
        self.upstream.post_body = {"error": {"message": f"conflict {TEST_API_KEY}"}}
        async with self.mcp() as session:
            result = await session.call_tool("friday_submit", {"message": "hello", "request_id": "req-3"})
        data = result_data(result)
        self.assertEqual(data["http_status"], 409)
        self.assertEqual(data["response"]["error"]["message"], "conflict [REDACTED]")
        self.assertNotIn(TEST_API_KEY, json.dumps(data))

    async def test_timeout_is_not_retried_and_is_reported_as_unknown_acceptance(self):
        self.upstream.post_delay = 0.25
        async with self.mcp(FRIDAY_HTTP_TIMEOUT_SECONDS="0.05") as session:
            result = await session.call_tool("friday_submit", {"message": "hello", "request_id": "req-timeout"})
        data = result_data(result)
        self.assertFalse(data["ok"])
        self.assertEqual(data["error"], "timeout")
        self.assertTrue(data["acceptance_unknown"])
        self.assertEqual(len(self.upstream.posts), 1)

    async def test_registry_survives_adapter_restart(self):
        async with self.mcp() as session:
            await session.call_tool("friday_submit", {"message": "hello", "request_id": "req-persist"})
        async with self.mcp() as session:
            result = await session.call_tool("friday_status", {
                "run_id": "run_0123456789abcdef0123456789abcdef",
            })
        self.assertEqual(result_data(result)["http_status"], 200)
        registry = json.loads((self.state_dir / "runs.json").read_text())
        self.assertEqual(list(registry["runs"]), ["run_0123456789abcdef0123456789abcdef"])
        self.assertNotIn(TEST_API_KEY, json.dumps(registry))

    async def test_profile_dotenv_key_is_used_without_loading_other_values(self):
        profile_env = self.state_dir / "friday.env"
        profile_env.write_text(
            f"API_SERVER_KEY={TEST_API_KEY}\nOTHER_SECRET=must-not-be-exported\n",
            encoding="utf-8",
        )
        async with self.mcp(FRIDAY_API_KEY="", FRIDAY_API_ENV_FILE=str(profile_env)) as session:
            await session.call_tool("friday_submit", {"message": "hello", "request_id": "req-profile-key"})
        self.assertEqual(self.upstream.posts[0]["authorization"], f"Bearer {TEST_API_KEY}")

    async def test_missing_key_fails_before_server_start_without_echoing_secrets(self):
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
            "FRIDAY_API_ENV_FILE": str(self.state_dir / "missing.env"),
        }
        proc = await asyncio.create_subprocess_exec(
            str(PYTHON), str(ADAPTER), cwd=TEST_DIR, env=env,
            stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=3)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(b"API_SERVER_KEY", stderr)
        self.assertNotIn(TEST_API_KEY.encode(), stderr)

    async def test_launcher_missing_credentials_stops_before_running_tunnel(self):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp")}
        proc = await asyncio.create_subprocess_exec(
            ZSH, str(LAUNCHER), "--check", cwd=TEST_DIR, env=env,
            stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=3)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(b"CONTROL_PLANE_API_KEY", stderr)

    async def test_response_redacts_api_key_in_nested_json_keys(self):
        self.upstream.post_body = {
            f"top-{TEST_API_KEY}": "unchanged",
            "nested": {TEST_API_KEY: [1, 2.5, True, False, None, "unchanged"]},
            "items": [{"inner": [{f"list-{TEST_API_KEY}": {
                "count": 7, "enabled": False, "detail": f"value-{TEST_API_KEY}",
            }}]}],
        }
        async with self.mcp() as session:
            result = await session.call_tool("friday_submit", {
                "message": "hello", "request_id": "req-redact-json-keys",
            })
        data = result_data(result)
        self.assertFalse(TEST_API_KEY in json.dumps(data), "API key leaked through JSON object keys")
        for block in result.content:
            text = getattr(block, "text", None)
            if text:
                self.assertFalse(TEST_API_KEY in text, "API key leaked through MCP text output")
        expected = {
            "top-[REDACTED]": "unchanged",
            "nested": {"[REDACTED]": [1, 2.5, True, False, None, "unchanged"]},
            "items": [{"inner": [{"list-[REDACTED]": {
                "count": 7, "enabled": False, "detail": "value-[REDACTED]",
            }}]}],
        }
        self.assertTrue(data["ok"])
        self.assertEqual(data["http_status"], 202)
        self.assertEqual(len(self.upstream.posts), 1)
        self.assertTrue(
            json.dumps(data["response"], sort_keys=True) == json.dumps(expected, sort_keys=True),
            "Redaction changed JSON values, types, or structure",
        )


if __name__ == "__main__":
    unittest.main()
