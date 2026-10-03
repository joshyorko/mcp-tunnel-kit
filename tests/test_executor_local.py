"""Foreground launch must never disclose Executor's browser pairing credential."""

import os
import importlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from mcp_fixtures import LoopbackServer

ROOT = Path(__file__).resolve().parents[1]


class ExecutorLaunchTests(unittest.TestCase):
    def ownership_helper(self):
        with patch.object(sys, "path", [str(ROOT), *sys.path]):
            return importlib.import_module("executor_mcp")

    def test_serve_filters_pairing_link_without_hiding_ready_endpoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            binary = base / "executor-fixture"
            binary.write_text(
                "#!/bin/sh\n"
                'if [ "$1" = "--version" ]; then echo "executor v2.0.0-beta.8"; exit; fi\n'
                '[ "$1" = "serve" ] || exit 12\n'
                'echo "MCP: http://127.0.0.1:4312/mcp"\n'
                'echo "  http://127.0.0.1:4312/#pair=PRIVATE_PAIRING_FIXTURE"\n'
            )
            binary.chmod(0o700)
            result = subprocess.run(
                [shutil.which("zsh"), str(ROOT / "launch-executor.zsh")],
                env={"PATH": os.environ["PATH"], "HOME": str(base),
                     "EXECUTOR_BIN": str(binary), "EXECUTOR_DATA_DIR": str(base / "data")},
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("http://127.0.0.1:4312/mcp", result.stdout)
            self.assertNotIn("PRIVATE_PAIRING_FIXTURE", result.stdout + result.stderr)

    def test_repeat_registration_retains_dashboard_owned_app_without_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            key = "NONPRODUCTION_EXECUTOR_REGISTRATION_KEY"
            (base / "keys.json").write_text(json.dumps({"apiKey": key}))
            (base / "keys.json").chmod(0o600)
            marker = {"id": "app_fixture", "url": "http://127.0.0.1:8088/mcp"}
            (base / "codex-integration.json").write_text(json.dumps(marker))
            requests = []

            def dispatch(method, path, headers, body):
                requests.append((method, path))
                parsed = urlsplit(path)
                if (method == "GET" and parsed.path == "/v1/apps"
                        and parse_qs(parsed.query) == {"owner": ["local"], "slug": ["codex"]}
                        and headers.get("Authorization") == "Bearer " + key):
                    return 200, [{"id": "app_fixture", "slug": "codex"}], False
                return 400, {}, False

            server = LoopbackServer(dispatch)
            try:
                result = subprocess.run(
                    [sys.executable, str(ROOT / "executor_mcp.py"), "--register-codex"],
                    env={"PATH": os.defpath, "EXECUTOR_DATA_DIR": str(base),
                         "EXECUTOR_MCP_URL": server.url + "/mcp"},
                    capture_output=True, text=True, timeout=10,
                )
            finally:
                server.close()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(requests), 1)
            self.assertIn("Existing codex integration retained", result.stdout)
            self.assertNotIn(key, result.stdout + result.stderr)

    def test_configured_renamed_client_is_detected_without_secret_reads(self):
        with tempfile.TemporaryDirectory() as temporary:
            alias = Path(temporary) / "renamed-client-fixture"
            alias.symlink_to(shutil.which("sleep"))
            process = subprocess.Popen([str(alias), "30"])
            try:
                process_path = Path(f"/proc/{process.pid}")
                deadline = time.monotonic() + 2
                while not (process_path / "exe").samefile(alias):
                    self.assertIsNone(process.poll(), "Fixture exited before its executable was ready")
                    self.assertLess(time.monotonic(), deadline, "Fixture executable did not become ready")
                    time.sleep(0.01)
                helper = self.ownership_helper()
                # Only this fixture can satisfy the guard; a production tunnel cannot mask a miss.
                with patch.object(Path, "iterdir", return_value=iter([process_path])), patch.dict(os.environ, {"TUNNEL_CLIENT_BIN": str(alias)}):
                    with self.assertRaisesRegex(helper.SetupError, "already running"):
                        helper.refuse_live_tunnel()
            finally:
                process.terminate()
                process.wait(timeout=5)

    def test_configured_executable_is_detected_before_cmdline_is_ready(self):
        helper = self.ownership_helper()
        with tempfile.TemporaryDirectory() as temporary:
            process_path = Path(temporary) / "7"
            process_path.mkdir()
            (process_path / "exe").symlink_to(shutil.which("sleep"))
            (process_path / "cmdline").write_bytes(b"")
            with patch.object(Path, "iterdir", return_value=iter([process_path])), patch.dict(os.environ, {"TUNNEL_CLIENT_BIN": shutil.which("sleep")}):
                with self.assertRaisesRegex(helper.SetupError, "already running"):
                    helper.refuse_live_tunnel()


if __name__ == "__main__":
    unittest.main()
