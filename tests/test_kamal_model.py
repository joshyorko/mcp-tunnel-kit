import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import kamal_model


def manifest():
    return {
        "version": 1,
        "images": {
            "cas": {
                "repository": "ghcr.io/joshyorko/codex-action-server",
                "digest": "sha256:" + "a" * 64,
                "revision": "a" * 40,
            },
            "executor": {
                "repository": "ghcr.io/usefulsoftwareco/executor-selfhost:2.0.0-beta.12",
                "digest": "sha256:" + "b" * 64,
            },
            "schema_proxy": {
                "repository": "ghcr.io/joshyorko/codex-action-server",
                "digest": "sha256:" + "c" * 64,
                "revision": "c" * 40,
            },
            "tunnel": {
                "repository": "ghcr.io/openai/tunnel-client:v0.0.15",
                "digest": "sha256:" + "d" * 64,
            },
        },
    }


def profile(*, identity=None, devsy=None):
    return {
        "host": "kamal-test-deploy",
        "network": {
            "name": "mcp-control-plane",
            "subnet": "172.30.86.0/24",
            "gateway": "172.30.86.1",
        },
        "ssh_user": "kdlocpanda",
        "ssh_key": "/runner/tmp/kamal_deploy_key",
        "ssh_known_hosts": "/runner/tmp/kamal_known_hosts",
        "ssh_config": "/runner/tmp/kamal_ssh_config",
        "state_dir": "/home/kdlocpanda/.local/share/codex-control-plane",
        "repo_dir": "/home/kdlocpanda/Projects/mcp-tunnel-kit",
        "cas_ssh_config_source": "/home/kdlocpanda/.local/share/issue16-dakota-ssh/ssh_config.native",
        "cas_ssh_known_hosts_source": "/home/kdlocpanda/.local/share/issue16-dakota-ssh/known_hosts.native",
        "cas_identity_source": identity,
        "devsy": devsy,
    }


def rendered(profile_value=None, manifest_value=None):
    return json.loads(
        kamal_model.render(profile_value or profile(), manifest_value or manifest())
    )


def test_accessory_model_keeps_private_control_plane_topology_and_order():
    config = rendered()

    assert config["service"] == "mcp-control-plane"
    assert config["proxy"] is False
    assert config["registry"] == {
        "server": "localhost",
        "username": "unused",
        "password": "unused",
    }
    assert list(config["accessories"]) == ["executor", "schema-proxy", "cas", "tunnel"]
    assert [item["service"] for item in config["accessories"].values()] == [
        "mcp-control-plane-executor",
        "mcp-control-plane-schema-proxy",
        "mcp-control-plane-cas",
        "mcp-control-plane-tunnel",
    ]
    assert all(
        item["host"] == "kamal-test-deploy" for item in config["accessories"].values()
    )
    assert [item["network"] for item in config["accessories"].values()] == [
        "mcp-control-plane",
        "mcp-control-plane",
        "host",
        "mcp-control-plane",
    ]


def test_runner_ssh_uses_selected_key_without_agent_or_default_config():
    config = rendered()

    assert config["ssh"] == {
        "user": "kdlocpanda",
        "keys": ["/runner/tmp/kamal_deploy_key"],
        "keys_only": True,
        "forward_agent": False,
        "config": "/runner/tmp/kamal_ssh_config",
    }
    assert "/runner/tmp/kamal_known_hosts" not in json.dumps(config)


def test_executor_keeps_named_volume_loopback_port_and_network_alias():
    executor = rendered()["accessories"]["executor"]

    assert executor["image"].endswith("sha256:" + "b" * 64)
    assert executor["port"] == "127.0.0.1:4312:4312"
    assert "codex-control-plane_executor-data:/app/data" in executor["volumes"]
    assert executor["options"]["network-alias"] == "executor"
    assert executor["env"]["clear"]["EXECUTOR_DATA_DIR"] == "/app/data"


def test_schema_proxy_keeps_independent_image_and_tunnel_dns_alias():
    config = rendered()
    schema = config["accessories"]["schema-proxy"]
    tunnel = config["accessories"]["tunnel"]

    assert schema["image"].endswith("sha256:" + "c" * 64)
    assert schema["image"] != config["accessories"]["cas"]["image"]
    assert schema["options"]["network-alias"] == "executor-schema-proxy"
    assert (
        "executor-schema-proxy:4313"
        in (ROOT / "config/compose-tunnel.yaml").read_text()
    )
    assert "network-alias" not in tunnel.get("options", {})


def test_cas_only_image_override_does_not_repin_schema_proxy():
    images = manifest()
    images["images"]["cas"]["digest"] = "sha256:" + "e" * 64
    images["images"]["cas"]["revision"] = "e" * 40

    config = rendered(manifest_value=images)

    assert config["accessories"]["cas"]["image"].endswith("sha256:" + "e" * 64)
    assert config["accessories"]["schema-proxy"]["image"].endswith("sha256:" + "c" * 64)


def test_checked_in_manifest_is_valid_and_all_images_are_immutable():
    value = json.loads((ROOT / "config/deploy-images.json").read_text())

    refs = kamal_model.validate_manifest(value)

    assert set(refs) == {"cas", "executor", "schema_proxy", "tunnel"}
    assert all("@sha256:" in ref for ref in refs.values())


def test_cas_uses_host_network_pinned_ssh_and_never_mounts_local_socket():
    config = rendered()
    cas = config["accessories"]["cas"]
    volumes = cas["volumes"]

    assert cas["image"].endswith("sha256:" + "a" * 64)
    assert cas["env"]["clear"]["CODEX_ACTION_BRIDGE_GATEWAY"] == "172.30.86.1"
    assert (
        cas["env"]["clear"]["CODEX_ACTION_WORKER_AUTHORITY"]
        == "http://172.30.86.1:8089/worker-authorized"
    )
    assert "/run/codex-action-server/targets.json" in " ".join(volumes)
    assert "/run/codex-ssh/ssh_config" in " ".join(volumes)
    assert "/run/codex-ssh/known_hosts" in " ".join(volumes)
    assert not any("/run/native-codex" in item for item in volumes)
    assert cas["options"]["tmpfs"] == "/tmp:rw,exec,nosuid,nodev,size=256m,mode=1777"


def test_optional_cas_identity_mount_exists_only_when_profile_selects_it():
    without_identity = rendered()["accessories"]["cas"]["volumes"]
    with_identity = rendered(
        profile(identity="/home/kdlocpanda/.local/share/issue16-dakota-ssh/identity")
    )["accessories"]["cas"]["volumes"]

    assert not any(
        item.endswith(":/run/codex-ssh/identity:ro") for item in without_identity
    )
    assert (
        "/home/kdlocpanda/.local/share/issue16-dakota-ssh/identity:/run/codex-ssh/identity:ro"
        in with_identity
    )


def test_tunnel_uses_only_vm_secret_file_mounts_and_healthcheck():
    tunnel = rendered()["accessories"]["tunnel"]
    serialized = json.dumps(tunnel)
    secret_mounts = [item for item in tunnel["volumes"] if "/secrets/" in item]

    assert tunnel["image"].endswith("sha256:" + "d" * 64)
    assert (
        tunnel["cmd"]
        == "/opt/tunnel-kit/tunnel-start.sh /bin/sh /opt/tunnel-kit/tunnel-secrets.sh"
    )
    assert tunnel["options"]["entrypoint"] == "/bin/sh"
    assert tunnel["options"]["log-driver"] == "none"
    assert tunnel["options"]["health-cmd"].endswith("--require-control-plane-poll")
    assert len(secret_mounts) == 3 and all(
        item.endswith(":ro") for item in secret_mounts
    )
    assert "CONTROL_PLANE_API_KEY" not in serialized
    assert "EXECUTOR_PAT" not in serialized


def test_devsy_profile_matches_existing_read_only_mount_targets():
    value = profile(
        devsy={
            "config_source": "/home/kdlocpanda/.devsy/config.yaml",
            "context_dir": "/home/kdlocpanda/.devsy/contexts/default",
            "kubeconfig_source": "/home/kdlocpanda/.kube/config",
            "context": "default",
        }
    )
    cas = rendered(value)["accessories"]["cas"]

    assert cas["env"]["clear"]["DEVSY_HOME"] == "/tmp"
    assert "/home/kdlocpanda/.devsy/config.yaml:/tmp/config.yaml:ro" in cas["volumes"]
    assert (
        "/home/kdlocpanda/.devsy/contexts/default:/tmp/contexts/default:ro"
        in cas["volumes"]
    )
    assert (
        "/home/kdlocpanda/.kube/config:/home/kdlocpanda/.kube/config:ro"
        in cas["volumes"]
    )


@pytest.mark.parametrize(
    "target,mutation",
    [
        ("manifest", lambda value: value["images"]["cas"].update(digest="latest")),
        (
            "manifest",
            lambda value: value["images"]["cas"].update(revision="not-a-commit"),
        ),
        ("profile", lambda value: value["network"].update(gateway="0.0.0.0")),
    ],
)
def test_manifest_and_profile_reject_unpinned_values(target, mutation):
    value = manifest() if target == "manifest" else profile()
    mutation(value)

    with pytest.raises(ValueError):
        if target == "manifest":
            kamal_model.render(profile(), value)
        else:
            kamal_model.render(value, manifest())


def test_profile_rejects_relative_or_unsafe_mount_paths():
    value = profile()
    value["cas_identity_source"] = "relative/key"

    with pytest.raises(ValueError):
        kamal_model.render(value, manifest())


def test_cli_reads_json_request_and_writes_only_valid_config(tmp_path):
    request = tmp_path / "request.json"
    request.write_text(json.dumps({"profile": profile(), "manifest": manifest()}))

    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/kamal_model.py")],
        input=request.read_text(),
        text=True,
        capture_output=True,
        check=True,
    )

    assert json.loads(result.stdout)["service"] == "mcp-control-plane"
    assert result.stderr == ""
