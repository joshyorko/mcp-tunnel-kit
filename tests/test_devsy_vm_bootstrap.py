"""VM host bootstrap contract tests use only synthetic paths and commands."""

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys_path = ROOT / "scripts"


def bootstrap_module():
    spec = importlib.util.find_spec("devsy_vm_bootstrap", [str(sys_path)])
    assert spec is not None, "the VM Devsy bootstrap boundary is missing"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def policy():
    return json.loads((ROOT / "config/devsy-vm-bootstrap.json").read_text())


def bootstrap_class(module):
    result = getattr(module, "VMDevsyBootstrap", None)
    assert result is not None, "the VM Devsy bootstrap coordinator is missing"
    return result


def private_profile(tmp_path):
    home = tmp_path / "operator"
    state = home / ".local/share/control-plane"
    repo = tmp_path / "repo"
    config = home / ".local/share/control-plane/devsy-operator/config.yaml"
    context = home / ".local/share/control-plane/devsy-operator/contexts/default"
    kubeconfig = state / "ror/operator-kubeconfig"
    for directory in (state, state / "ror", repo, repo / "scripts", config.parent, context):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
    (repo / "scripts/host_devsy_service.py").write_text("fixture host starter\n")
    config.write_text("fixture Devsy config")
    config.chmod(0o600)
    kubeconfig.write_text("fixture kubeconfig")
    kubeconfig.chmod(0o600)
    return {
        "repo_dir": str(repo),
        "state_dir": str(state),
        "home": str(home),
        "devsy": {
            "config_source": str(config),
            "context_dir": str(context),
            "kubeconfig_source": str(kubeconfig),
            "context": "default",
        },
        "service_user": "fixture",
        "service_group": "fixture",
        "uid": os.getuid(),
    }


def test_provider_options_bound_main_and_init_containers_to_ror_worker_nodes():
    module = bootstrap_module()
    options = module.provider_options(policy(), "/private/ror/kubeconfig")

    assert options["KUBERNETES_CONTEXT"] == "ror"
    assert options["KUBERNETES_NAMESPACE"] == "devsy"
    assert options["KUBERNETES_CONFIG"] == "/private/ror/kubeconfig"
    assert options["CREATE_NAMESPACE"] == "false"
    assert options["NODE_SELECTOR"] == "node-role.kubernetes.io/worker=true"
    assert options["RESOURCES"] == (
        "requests.cpu=1,requests.memory=1Gi,limits.cpu=2,limits.memory=4Gi"
    )
    assert "name: devsy-init" in options["POD_MANIFEST_TEMPLATE"]
    assert 'cpu: "250m"' in options["POD_MANIFEST_TEMPLATE"]
    assert 'memory: "512Mi"' in options["POD_MANIFEST_TEMPLATE"]
    assert "cpu: \"1\"" in options["POD_MANIFEST_TEMPLATE"]
    assert 'memory: "2Gi"' in options["POD_MANIFEST_TEMPLATE"]
    assert "automountServiceAccountToken: false" in options["POD_MANIFEST_TEMPLATE"]


def test_unit_classifier_accepts_only_absent_managed_or_known_legacy_units():
    module = bootstrap_module()
    desired = b"[Service]\nExecStart=/usr/bin/python3 /private/start-host-devsy.py\n"
    legacy = b"the existing service unit\n"

    assert module.classify_unit(None, desired, "legacy-unit-sha") == "absent"
    assert module.classify_unit(desired, desired, "legacy-unit-sha") == "managed"
    assert module.classify_unit(legacy, desired, hashlib.sha256(legacy).hexdigest()) == "legacy"
    with pytest.raises(module.BootstrapError, match="conflicting systemd unit"):
        module.classify_unit(b"operator-edited unit", desired, "legacy-unit-sha")


def test_managed_bridge_starter_imports_the_checkout_service_module(tmp_path):
    module = bootstrap_module()
    profile = private_profile(tmp_path)
    bootstrap = bootstrap_class(module)(
        profile, policy(),
        unit_template=(ROOT / "config/codex-control-plane-devsy.service.in").read_text(),
        system="Linux", machine="aarch64",
    )

    assert "sys.path.insert(0," in bootstrap.starter_source
    assert str(Path(profile["repo_dir"]) / "scripts") in bootstrap.starter_source
    assert "from host_devsy_service import main" in bootstrap.starter_source


def test_rollback_restores_provider_with_the_previous_verified_cli(tmp_path, monkeypatch):
    module = bootstrap_module()
    profile = private_profile(tmp_path)
    old_binary = Path(profile["home"]) / ".local/bin/devsy"
    old_binary.parent.mkdir(mode=0o700)
    old_binary.write_bytes(b"previous verified Devsy CLI")
    old_binary.chmod(0o755)
    brew_prefix = tmp_path / "linuxbrew/.linuxbrew"
    new_binary = brew_prefix / "bin/devsy"
    new_binary.parent.mkdir(parents=True, mode=0o700)
    new_binary.write_bytes(b"new tap Devsy CLI")
    new_binary.chmod(0o755)
    configured = policy()
    configured["homebrew"]["prefix"] = str(brew_prefix)
    unit_path = tmp_path / "systemd/codex-control-plane-devsy.service"
    unit_path.parent.mkdir(mode=0o700)
    store = Path(profile["state_dir"]) / "deployment"
    store.mkdir(mode=0o700)
    backup_parent = store / "devsy-host-backups"
    backup_parent.mkdir(mode=0o700)
    directory = backup_parent / "fixture"
    directory.mkdir(mode=0o700)
    manifest = {
        "unit_active": False, "unit_enabled": False, "unit_state": "legacy",
        "provider_was_verified": True, "provider_options": {},
        "devsy_path": str(old_binary), "devsy_version": "1.23.0",
        "devsy_sha256": hashlib.sha256(old_binary.read_bytes()).hexdigest(),
        "tap_was_present": False, "files": {
            "unit": False, "starter": False, "bridge_config": False, "receipt": False,
        },
    }
    selected = []
    bootstrap = bootstrap_class(module)(
        profile, configured,
        unit_template=(ROOT / "config/codex-control-plane-devsy.service.in").read_text(),
        system="Linux", machine="aarch64", unit_path=unit_path,
    )
    def command(args, **_kwargs):
        output = "v1.23.0\n" if args[0] == str(old_binary) and args[1:] == ["--version"] else ""
        return subprocess.CompletedProcess(args, 0, output, "")

    bootstrap._command = command
    bootstrap._set_provider_options = lambda binary, *_args: selected.append(Path(binary))

    bootstrap._restore(manifest, directory)

    assert selected == [old_binary]


def test_host_backup_binds_the_vm_source_revision_for_rollback(tmp_path):
    module = bootstrap_module()
    profile = private_profile(tmp_path)
    unit_path = tmp_path / "systemd/codex-control-plane-devsy.service"
    unit_path.parent.mkdir(mode=0o700)
    bootstrap = bootstrap_class(module)(
        profile, policy(),
        unit_template=(ROOT / "config/codex-control-plane-devsy.service.in").read_text(),
        system="Linux", machine="aarch64", unit_path=unit_path,
    )
    state = {
        "service": {"active": False, "enabled": False},
        "unit_state": "absent", "provider": None,
        "brew": {"present": False, "tap": None},
        "devsy": None, "binary": None,
        "kubeconfig": Path(profile["devsy"]["kubeconfig_source"]),
    }

    backup = bootstrap._backup(state, "a" * 40)

    assert backup["manifest"]["source_sha"] == "a" * 40


@pytest.mark.parametrize(
    ("system", "machine"),
    [("Darwin", "aarch64"), ("Linux", "x86_64"), ("Windows", "AMD64")],
)
def test_unsupported_host_is_rejected_before_any_bootstrap_command(system, machine):
    module = bootstrap_module()

    with pytest.raises(module.BootstrapError, match="unsupported host platform"):
        module.validate_platform(system, machine)


def provider_list(options, *, default=True):
    return {
        "kubernetes": {
            "default": default,
            "state": {
                "options": {key: {"value": value} for key, value in options.items()},
            },
        },
    }


def test_provider_identity_drift_fails_while_approved_resource_drift_is_reported():
    module = bootstrap_module()
    inspect_provider_state = getattr(module, "inspect_provider_state", None)
    assert inspect_provider_state is not None, "provider state validation is missing"
    target = module.provider_options(policy(), "/private/ror/kubeconfig")
    legacy = policy()["provider"]["legacy_options"]
    state = inspect_provider_state(
        provider_list(legacy), policy(), "/private/ror/kubeconfig"
    )

    assert state["name"] == "kubernetes"
    assert state["default"] is True
    assert "NODE_SELECTOR" in state["changes"]
    assert "POD_MANIFEST_TEMPLATE" in state["changes"]
    assert "KUBERNETES_CONFIG" in state["changes"]
    assert target["RESOURCES"] == legacy["RESOURCES"]

    wrong_namespace = {**legacy, "KUBERNETES_NAMESPACE": "default"}
    with pytest.raises(module.BootstrapError, match="provider identity drift"):
        inspect_provider_state(
            provider_list(wrong_namespace), policy(), "/private/ror/kubeconfig"
        )

    with pytest.raises(module.BootstrapError, match="provider identity drift"):
        inspect_provider_state(
            provider_list(legacy, default=False), policy(), "/private/ror/kubeconfig"
        )

    wrong_limits = {**legacy, "RESOURCES": "requests.cpu=4,requests.memory=8Gi,limits.cpu=8,limits.memory=15Gi"}
    with pytest.raises(module.BootstrapError, match="resource or credential drift"):
        inspect_provider_state(
            provider_list(wrong_limits), policy(), "/private/ror/kubeconfig"
        )


def test_supported_pi_platform_and_private_credential_permissions(tmp_path):
    module = bootstrap_module()
    module.validate_platform("Linux", "aarch64")

    credential = tmp_path / "operator-kubeconfig"
    credential.write_text("fixture credential data")
    credential.chmod(0o600)
    module.validate_private_file(credential, os.getuid())

    credential.chmod(0o644)
    with pytest.raises(module.BootstrapError, match="ownership or mode mismatch"):
        module.validate_private_file(credential, os.getuid())

    linked = tmp_path / "credential-link"
    linked.symlink_to(credential)
    with pytest.raises(module.BootstrapError, match="ownership or mode mismatch"):
        module.validate_private_file(linked, os.getuid())


def test_rendered_systemd_unit_keeps_the_declared_user_and_binary_identity(tmp_path):
    module = bootstrap_module()
    unit = module.render_unit(
        user="operator", group="operator", repo_dir="/srv/control-plane",
        state_dir="/home/operator/.local/share/control-plane",
        devsy_bin="/home/linuxbrew/.linuxbrew/bin/devsy",
        devsy_home="/home/operator/.local/share/devsy",
        config_source="/home/operator/.local/share/devsy/config.yaml",
        context_dir="/home/operator/.local/share/devsy/contexts/default",
        kubeconfig="/home/operator/.local/share/control-plane/ror/kubeconfig",
    ).decode()

    assert "Type=forking" in unit
    assert "User=operator" in unit
    assert "Group=operator" in unit
    assert "WorkingDirectory=/srv/control-plane" in unit
    assert "DEVSY_MCP_BIN=/home/linuxbrew/.linuxbrew/bin/devsy" in unit
    assert "DEVSY_CONTEXT=default" in unit
    assert "DEVSY_KUBECONFIG_FILE=/home/operator/.local/share/control-plane/ror/kubeconfig" in unit
    assert "PIDFile=/home/operator/.local/share/control-plane/devsy-bridge/systemd.pid" in unit
    assert "ExecStart=/usr/bin/python3 /home/operator/.local/share/control-plane/start-host-devsy.py" in unit
    assert "Restart=on-failure" in unit
    assert "After=network-online.target tailscaled.service docker.service" in unit


def test_systemd_template_rejects_path_injection():
    module = bootstrap_module()
    arguments = {
        "user": "operator", "group": "operator", "repo_dir": "/srv/control-plane",
        "state_dir": "/home/operator/state", "devsy_bin": "/home/brew/bin/devsy",
        "devsy_home": "/home/operator/devsy", "config_source": "/home/operator/devsy/config.yaml",
        "context_dir": "/home/operator/devsy/contexts/default", "kubeconfig": "/home/operator/ror/kubeconfig",
    }

    with pytest.raises(module.BootstrapError, match="unsafe value"):
        module.render_unit(**{**arguments, "user": "operator\nExecStart=/bin/sh"})


def test_missing_private_credential_fails_plan_before_external_commands(tmp_path):
    module = bootstrap_module()
    profile = private_profile(tmp_path)
    Path(profile["devsy"]["kubeconfig_source"]).unlink()
    calls = []
    bootstrap = bootstrap_class(module)(
        profile, policy(), unit_template=(ROOT / "config/codex-control-plane-devsy.service.in").read_text(),
        system="Linux", machine="aarch64",
        runner=lambda *args, **kwargs: calls.append(args)
    )

    with pytest.raises(module.BootstrapError, match="credential/config file is missing"):
        bootstrap.plan()
    assert calls == []


def test_apply_requires_explicit_approval_before_any_external_command(tmp_path):
    module = bootstrap_module()
    calls = []
    bootstrap = bootstrap_class(module)(
        private_profile(tmp_path), policy(),
        unit_template=(ROOT / "config/codex-control-plane-devsy.service.in").read_text(),
        system="Linux", machine="aarch64",
        runner=lambda *args, **kwargs: calls.append(args)
    )

    with pytest.raises(module.BootstrapError, match="explicit Devsy apply approval"):
        bootstrap.apply(approved=False, source_sha="a" * 40)
    assert calls == []


def test_host_bootstrap_apply_twice_converges_without_reapplying_changes(tmp_path):
    module = bootstrap_module()
    profile = private_profile(tmp_path)
    (Path(profile["home"]) / ".local/bin").mkdir(mode=0o700)
    legacy_binary = Path(profile["home"]) / ".local/bin/devsy"
    legacy_binary.write_bytes(b"legacy devsy artifact")
    legacy_binary.chmod(0o755)

    configured = policy()
    configured["devsy"]["legacy_sha256"] = hashlib.sha256(legacy_binary.read_bytes()).hexdigest()
    artifact = b"fixture tap Devsy 1.23.2 artifact"
    target_sha = hashlib.sha256(artifact).hexdigest()
    configured["devsy"]["artifact_sha256"] = {"aarch64": target_sha}
    formula = (
        'class Devsy < Formula\n  version "1.23.2"\n'
        '  on_arm do\n    sha256 "' + target_sha + '"\n  end\nend\n'
    ).encode()
    configured["devsy"]["formula_sha256"] = hashlib.sha256(formula).hexdigest()
    prefix = tmp_path / "linuxbrew/.linuxbrew"
    configured["homebrew"]["prefix"] = str(prefix)
    brew_bin = prefix / "bin/brew"
    brew_bin.parent.mkdir(parents=True, mode=0o700)
    brew_bin.write_text("fixture brew")
    brew_bin.chmod(0o755)
    profile["brew_path"] = str(brew_bin)
    repository = prefix / "Homebrew"
    tap = repository / "Library/Taps/joshyorko/homebrew-tools"
    formula_path = tap / configured["devsy"]["formula_path"]
    formula_path.parent.mkdir(parents=True, mode=0o700)
    formula_path.write_bytes(formula)
    systemd = tmp_path / "systemd"
    systemd.mkdir(mode=0o700)
    unit_path = systemd / "codex-control-plane-devsy.service"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(mode=0o700)
    kubectl_bin = fake_bin / "kubectl"
    kubectl_bin.write_text("fixture kubectl")
    kubectl_bin.chmod(0o755)
    kubeconfig = Path(profile["devsy"]["kubeconfig_source"])
    old_options = dict(configured["provider"]["legacy_options"])
    old_options["KUBERNETES_CONFIG"] = ""

    class FixtureRunner:
        def __init__(self):
            self.calls = []
            self.options = old_options.copy()
            self.active = False
            self.enabled = False
            self.target_binary = prefix / "bin/devsy"

        def __call__(self, args, **_kwargs):
            args = [str(value) for value in args]
            self.calls.append(args)
            output = ""
            if args[0] == str(brew_bin):
                if args[1] == "--prefix":
                    output = str(prefix)
                elif args[1] == "--repository":
                    output = str(repository)
                elif args[1] == "--version":
                    output = "Homebrew 5.1.6"
                elif args[1] == "install":
                    self.target_binary.parent.mkdir(parents=True, exist_ok=True)
                    self.target_binary.write_bytes(artifact)
                    self.target_binary.chmod(0o755)
            elif args[0] == "git":
                if args[-2:] == ["get-url", "origin"]:
                    output = configured["devsy"]["tap_repository"]
                elif "rev-parse" in args:
                    output = configured["devsy"]["tap_revision"]
                elif "status" in args:
                    output = ""
            elif args[0] == str(legacy_binary) or args[0] == str(self.target_binary):
                if args[1:] == ["--version"]:
                    output = "v1.23.0" if args[0] == str(legacy_binary) else "v1.23.2"
                elif args[-2:] == ["provider", "list"]:
                    output = json.dumps({"kubernetes": {
                        "default": True,
                        "state": {"options": {key: {"value": value}
                                              for key, value in self.options.items()}},
                    }})
                elif "set" in args and "provider" in args:
                    for index, value in enumerate(args[:-1]):
                        if value == "--option":
                            key, content = args[index + 1].split("=", 1)
                            self.options[key] = content
            elif args[0] == str(kubectl_bin):
                resource = args[6]
                if resource == "namespace":
                    output = json.dumps({"metadata": {"name": "devsy"}})
                elif resource == "resourcequota,limitrange":
                    output = json.dumps({"items": []})
                elif resource == "nodes":
                    output = json.dumps({"items": [{
                        "metadata": {"name": "ror-worker-01"},
                        "spec": {},
                        "status": {"conditions": [{"type": "Ready", "status": "True"}],
                                   "allocatable": {"cpu": "8", "memory": "15Gi"}},
                    }]})
                elif resource == "pods":
                    output = json.dumps({"items": []})
                elif resource == "storageclass":
                    output = json.dumps({"items": [{
                        "metadata": {"name": "local-path", "annotations": {
                            "storageclass.kubernetes.io/is-default-class": "true"}},
                    }]})
            elif args[:2] == ["systemctl", "show"]:
                output = "\n".join((
                    f"FragmentPath={unit_path}",
                    f"ActiveState={'active' if self.active else 'inactive'}",
                    f"UnitFileState={'enabled' if self.enabled else 'disabled'}",
                    "User=fixture", "Group=fixture",
                    f"ExecStart=/usr/bin/python3 {profile['state_dir']}/start-host-devsy.py",
                ))
            elif args[:3] == ["sudo", "-n", "systemctl"]:
                operation = args[3]
                if operation == "enable":
                    self.enabled = True
                elif operation in ("start", "restart"):
                    self.active = True
                    bridge_dir = Path(profile["state_dir"]) / "devsy-bridge"
                    bridge_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
                    bridge_config = {"binary": str(self.target_binary), "gateway": "127.0.0.1",
                                     "state": str(bridge_dir)}
                    (bridge_dir / "config.json").write_text(json.dumps(bridge_config))
                    (bridge_dir / "config.json").chmod(0o600)
                    (bridge_dir / "process.json").write_text(json.dumps({"pid": os.getpid()}))
                    (bridge_dir / "process.json").chmod(0o600)
                elif operation == "stop":
                    self.active = False
            return subprocess.CompletedProcess(args, 0, output + "\n", "")

    runner = FixtureRunner()
    bootstrap = bootstrap_class(module)(
        profile, configured,
        unit_template=(ROOT / "config/codex-control-plane-devsy.service.in").read_text(),
        runner=runner, fetcher=lambda _url: formula,
        system="Linux", machine="aarch64", unit_path=unit_path,
            env={"PATH": str(fake_bin)},
        process_probe=lambda _config, _receipt: True, health_probe=lambda _config: True,
    )
    planned = bootstrap.plan()
    assert planned["status"] == "changes-required"
    assert not (Path(profile["state_dir"]) / "deployment").exists()
    first = bootstrap.apply(approved=True, source_sha="a" * 40)
    assert first["changed"] is True
    assert first["devsy_version"] == "1.23.2"
    assert unit_path.is_file()
    assert runner.options["NODE_SELECTOR"] == "node-role.kubernetes.io/worker=true"
    assert runner.options["KUBERNETES_CONTEXT"] == "ror"
    assert runner.options["KUBERNETES_NAMESPACE"] == "devsy"

    mutations_before_second = sum(
        1 for args in runner.calls
        if ("install" in args or "set" in args or "start" in args or "restart" in args
            or "enable" in args or "checkout" in args or "fetch" in args)
    )
    second = bootstrap.apply(approved=True, source_sha="a" * 40)
    mutations_after_second = sum(
        1 for args in runner.calls
        if ("install" in args or "set" in args or "start" in args or "restart" in args
            or "enable" in args or "checkout" in args or "fetch" in args)
    )
    assert second["changed"] is False
    assert mutations_after_second == mutations_before_second
