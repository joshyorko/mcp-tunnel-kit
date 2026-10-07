"""Execute readiness JavaScript across the Executor result-size boundary."""

import importlib.util
import json
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
RESULT_LIMIT = 65536
REQUIRED_PATHS = {
    "codex": ["list_targets", "discover_threads"],
    "devsy": [
        "provider_list", "workspace_list", "workspace_status", "workspace_create",
        "workspace_start", "workspace_stop", "workspace_delete", "workspace_exec",
        "provider_add", "provider_delete", "provider_use",
    ],
}
EXECUTE_SEARCH = """
const fs = require('node:fs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const tools = {search: async options => {
  if (options.namespace !== input.namespace || options.limit !== 100 || !options.query)
    throw new Error('unexpected discovery scope');
  return {items: input.catalog, remaining: 0};
}};
(async () => {
  const AsyncFunction = Object.getPrototypeOf(async function() {}).constructor;
  const result = await new AsyncFunction('tools', input.code)(tools);
  const serialized = JSON.stringify(result);
  const truncated = Buffer.byteLength(serialized, 'utf8') > input.limit;
  const value = truncated ? serialized.slice(0, input.limit) + '[result truncated]' : result;
  process.stdout.write(JSON.stringify({status: 'completed', execution: {
    ok: true, value, truncated
  }, unavailableApps: []}));
})().catch(error => { console.error(error); process.exit(1); });
"""


class CatalogSession:
    def __init__(self, namespace, missing_required=False):
        self.namespace = namespace
        names = list(REQUIRED_PATHS[namespace])
        if missing_required:
            names.pop(0)
        names.extend(f"fixture_{index}" for index in range(64 - len(names)))
        self.catalog = [
            {"path": f"tools.{namespace}.{name}", "description": "Fixture tool",
             "signature": "x" * 2048}
            for name in names
        ]
        assert len(json.dumps({"items": self.catalog}).encode()) > RESULT_LIMIT
        self.results = []

    def call(self, method, params):
        assert method == "tools/call" and params["name"] == "execute"
        result = subprocess.run(
            ["node", "-e", EXECUTE_SEARCH],
            input=json.dumps({"code": params["arguments"]["code"],
                              "namespace": self.namespace, "catalog": self.catalog,
                              "limit": RESULT_LIMIT}),
            capture_output=True, text=True, check=True, timeout=10,
        )
        data = json.loads(result.stdout)
        self.results.append(data["execution"])
        return {"structuredContent": data}


@pytest.mark.parametrize("namespace", ["codex", "devsy"])
@pytest.mark.parametrize("missing_required", [False, True])
def test_large_catalog_discovery_preserves_required_path_validation(namespace, missing_required):
    spec = importlib.util.spec_from_file_location("compose_control", ROOT / "scripts/compose_control.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    session = CatalogSession(namespace, missing_required)
    search = getattr(module, "search_" + namespace)
    if missing_required:
        with pytest.raises(module.ControlError, match="lacks"):
            search(session)
    else:
        search(session)
    assert len(session.results) == 2
    for result in session.results:
        assert not result["truncated"]
        assert len(result["value"]["items"]) == 64
        assert all(set(item) == {"path"} for item in result["value"]["items"])
