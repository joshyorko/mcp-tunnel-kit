"""Host Devsy systemd bridge startup uses declared private settings."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


def service_module():
    spec = importlib.util.find_spec("devsy_vm_service", [str(ROOT / "scripts")])
    assert spec is not None, "the Host Devsy systemd service adapter is missing"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_service_wrapper_imports_through_legacy_runpy_launcher(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "host_devsy_service.py").write_text(
        (ROOT / "scripts/host_devsy_service.py").read_text()
    )
    (scripts / "devsy_vm_service.py").write_text("def main():\n    return 0\n")
    launcher = tmp_path / "start-host-devsy.py"
    launcher.write_text(
        "import runpy\n"
        f"runpy.run_path({str(scripts / 'host_devsy_service.py')!r}, run_name='__main__')\n"
    )
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)

    result = subprocess.run(
        [sys.executable, str(launcher)], cwd=tmp_path, env=env,
        capture_output=True, text=True, check=False,
    )

    assert result.returncode == 0, result.stderr


def test_bridge_starts_from_explicit_settings_and_writes_identity_receipt(tmp_path):
    module = service_module()
    state = tmp_path / "control-plane/devsy-bridge"
    state.mkdir(parents=True, mode=0o700)
    configuration = {"x-operator": {"devsy_enabled": "true"}}
    value = {"binary": "/home/linuxbrew/.linuxbrew/bin/devsy",
             "cwd": "/srv/control-plane", "state": str(state), "home": "/private/devsy"}
    events = []

    class Bridge:
        def settings(self, supplied):
            assert supplied is configuration
            return value

        def start(self, supplied):
            assert supplied is value
            events.append("start")
            (state / "process.json").write_text(json.dumps({"pid": 1234}))

        def owned_process(self, record):
            return record == {"pid": 1234}

    def read_private(path):
        return Path(path).read_text()

    def write_private(path, data):
        Path(path).write_text(data)

    result = module.start_configured_bridge(
        configuration, bridge=Bridge(), state_dir=tmp_path / "control-plane",
        read_private=read_private, write_private=write_private,
    )

    assert result["binary"] == "/home/linuxbrew/.linuxbrew/bin/devsy"
    assert events == ["start"]
    assert (state / "systemd.pid").read_text() == "1234\n"


def test_bridge_refuses_settings_outside_the_declared_private_state(tmp_path):
    module = service_module()
    events = []

    class Bridge:
        def settings(self, _configuration):
            return {"binary": "/brew/bin/devsy", "state": "/tmp/foreign/devsy-bridge"}

        def start(self, _value):
            events.append("start")

    with pytest.raises(module.ServiceError, match="private bridge state binding drift"):
        module.start_configured_bridge(
            {}, bridge=Bridge(), state_dir=tmp_path / "control-plane",
            read_private=lambda _path: "{}", write_private=lambda *_args: None,
        )
    assert events == []
