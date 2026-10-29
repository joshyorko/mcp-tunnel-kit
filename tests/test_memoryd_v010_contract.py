"""Exercise the MCP bridge against the pinned MemoryD v0.1.0 HTTP server."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import subprocess
import tempfile
import time
import unittest
from urllib.request import ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "codex_memoryd_mcp", ROOT / "scripts/codex_memoryd_mcp.py"
)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)

RELEASE_BINARY_SHA256 = "6bd47e96dc225b88e5bf4eb0d45ef68eaec4df0e1582a0ad62b1930c459110e6"


@unittest.skipUnless(os.environ.get("MEMORYD_V010_BINARY"), "pinned MemoryD v0.1.0 binary not supplied")
class ReleasedMemorydContractTests(unittest.TestCase):
    def test_recall_options_and_search_archive_policy_on_released_server(self):
        binary = Path(os.environ["MEMORYD_V010_BINARY"]).resolve()
        self.assertEqual(hashlib.sha256(binary.read_bytes()).hexdigest(), RELEASE_BINARY_SHA256)

        with tempfile.TemporaryDirectory(prefix="memoryd-contract-") as temp_dir:
            root = Path(temp_dir)
            config = root / "config.toml"
            config.write_text("", encoding="utf-8")
            env = {
                "HOME": temp_dir,
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "XDG_CONFIG_HOME": temp_dir,
                "XDG_DATA_HOME": temp_dir,
                "XDG_CACHE_HOME": temp_dir,
            }
            process = subprocess.Popen(
                [str(binary), "--config", str(config), "--db", str(root / "memory.db"),
                 "serve", "--bind", "127.0.0.1:0"],
                cwd=temp_dir,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            try:
                opener = build_opener(ProxyHandler({}))
                deadline = time.monotonic() + 10
                startup_log = b""
                while True:
                    if process.poll() is not None:
                        self.fail("MemoryD exited before readiness")
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not select.select([process.stderr], [], [], remaining)[0]:
                        self.fail("MemoryD did not become ready")
                    startup_log += os.read(process.stderr.fileno(), 4096)
                    address = re.search(
                        rb"codex-memoryd HTTP server listening[^\n]*127\.0\.0\.1:([0-9]+)",
                        startup_log,
                    )
                    if address:
                        origin = f"http://127.0.0.1:{int(address.group(1))}"
                        break

                with opener.open(origin + "/healthz", timeout=1) as response:
                    self.assertEqual(response.status, 200)

                backend = bridge.MemorydBackend(origin)
                request = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "memory_recall",
                        "arguments": {"query": "synthetic contract", "maxTokens": 64, "packMode": "debugging"},
                    },
                }
                result = bridge.handle_message(request, backend)["result"]
                self.assertFalse(result["isError"])
                pack = json.loads(result["content"][0]["text"])["data"]["pack"]
                self.assertEqual(pack["max_tokens"], 64)
                self.assertEqual(pack["mode"], "debugging")

                request["params"]["arguments"] = {"query": "synthetic contract"}
                result = bridge.handle_message(request, backend)["result"]
                self.assertFalse(result["isError"])
                pack = json.loads(result["content"][0]["text"])["data"]["pack"]
                self.assertEqual(pack["max_tokens"], 1200)
                self.assertEqual(pack["mode"], "default")

                def post(path, payload):
                    if process.poll() is not None:
                        self.fail("MemoryD exited before the synthetic request")
                    req = Request(
                        origin + path,
                        data=json.dumps(payload).encode(),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with opener.open(req, timeout=5) as response:
                        value = json.load(response)
                    self.assertTrue(value["ok"])
                    return value["data"]

                scope = {"profile": "personal", "workspace": "dakota-codex-only"}
                created = post("/v1/conclusions", {
                    **scope,
                    "target": "user",
                    "conclusions": ["syntheticarchiveprobe active", "syntheticarchiveprobe archived"],
                })
                _, archived_id = created["record_ids"]
                forgotten = post("/v1/forget", {**scope, "ids": [archived_id], "mode": "archive"})
                self.assertEqual(forgotten["archived"], [archived_id])
                control = post("/v1/search", {
                    **scope, "query": "syntheticarchiveprobe", "include_archived": True,
                })
                self.assertEqual(
                    {(item["content"], item["archived"]) for item in control["matches"]},
                    {("syntheticarchiveprobe active", False), ("syntheticarchiveprobe archived", True)},
                )

                request["params"] = {
                    "name": "memory_search",
                    "arguments": {"query": "syntheticarchiveprobe"},
                }
                result = bridge.handle_message(request, backend)["result"]
                self.assertFalse(result["isError"])
                matches = json.loads(result["content"][0]["text"])["data"]["matches"]
                self.assertEqual(
                    [(item["content"], item["archived"]) for item in matches],
                    [("syntheticarchiveprobe active", False)],
                )
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                process.stderr.close()
