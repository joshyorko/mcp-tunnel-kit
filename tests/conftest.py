import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import deploy_control_plane
import vm_deploy_host


@pytest.fixture(autouse=True)
def synthetic_instance_profile(request):
    if request.path.name not in {
        "test_deploy_control_plane.py",
        "test_deploy_failures.py",
        "test_deploy_workflow.py",
        "test_activate_recovery.py",
        "test_kamal_model.py",
        "test_local_kamal.py",
        "test_local_kamal_config.py",
        "test_public_docker_config.py",
    }:
        return
    value = json.loads((ROOT / "config/instance.example.json").read_text())
    deploy_control_plane.LOCAL_CONFIGURED = False
    deploy_control_plane.SSH = deploy_control_plane.DEFAULT_SSH
    deploy_control_plane.KEY = deploy_control_plane.DEFAULT_KEY
    deploy_control_plane.KNOWN = deploy_control_plane.DEFAULT_KNOWN
    deploy_control_plane.configure_instance(value)
    vm_deploy_host.configure_profile(value)
