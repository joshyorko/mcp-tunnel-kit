"""VM host bootstrap contract tests use only synthetic paths and commands."""

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
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


def test_tap_origin_matches_optional_git_suffix_without_changing_repository_identity():
    module = bootstrap_module()

    assert module.tap_origin_matches(
        "https://github.com/joshyorko/homebrew-tools",
        "https://github.com/joshyorko/homebrew-tools.git",
    )
    assert not module.tap_origin_matches(
        "https://github.com/other/homebrew-tools",
        "https://github.com/joshyorko/homebrew-tools.git",
    )


def test_tap_tree_copy_preserves_hidden_files_and_modes(tmp_path):
    module = bootstrap_module()
    source = tmp_path / "tap"
    (source / ".git").mkdir(parents=True)
    (source / "Formula").mkdir()
    (source / ".git/config").write_text("remote.origin.url=https://example.invalid/tap\n")
    formula = source / "Formula/devsy.rb"
    formula.write_text("class Devsy < Formula\nend\n")
    formula.chmod(0o640)
    (source / ".ignored-cache").write_text("preserve me\n")
    snapshot = tmp_path / "snapshot"

    before = module.copy_tap_tree(source, snapshot, os.getuid())
    after = module.tap_tree_manifest(snapshot, os.getuid())

    assert before["sha256"] == after["sha256"]
    assert (snapshot / ".git/config").read_text().startswith("remote.origin.url=")
    assert (snapshot / ".ignored-cache").read_text() == "preserve me\n"
    assert (snapshot / "Formula/devsy.rb").stat().st_mode & 0o777 == 0o640


def test_tap_tree_snapshot_rejects_symlinks(tmp_path):
    module = bootstrap_module()
    source = tmp_path / "tap"
    source.mkdir()
    (source / "escape").symlink_to(tmp_path / "outside")

    with pytest.raises(module.BootstrapError, match="unsafe tap snapshot path"):
        module.tap_tree_manifest(source, os.getuid())


def test_tap_tree_restore_preserves_failed_tree_and_restores_snapshot(tmp_path):
    module = bootstrap_module()
    source = tmp_path / "tap"
    source.mkdir()
    (source / ".git").mkdir()
    (source / ".git/HEAD").write_text("before\n")
    snapshot = tmp_path / "snapshot"
    before = module.copy_tap_tree(source, snapshot, os.getuid())
    (source / ".git/HEAD").write_text("partial update\n")
    (source / "partial-artifact").write_text("keep for audit\n")
    failed = tmp_path / "failed-tap"

    result = module.restore_tap_tree(
        snapshot, source, failed, before["sha256"], os.getuid(),
    )

    assert result["restored_sha256"] == before["sha256"]
    assert module.tap_tree_manifest(source, os.getuid())["sha256"] == before["sha256"]
    assert (failed / ".git/HEAD").read_text() == "partial update\n"
    assert (failed / "partial-artifact").read_text() == "keep for audit\n"


def test_issue27_reconciliation_case_is_exact_and_marks_old_backup_unsigned():
    module = bootstrap_module()
    configured = policy()

    case = module.validate_tap_reconciliation_case(configured)

    assert case["case_id"] == "issue-27-tap-523d-to-141f"
    assert case["prior_backup_signed"] is False
    assert case["observed_tap_revision"] == "523d8a0b85db367c34af749eefba81a25dd26768"
    assert case["target_tap_revision"] == configured["devsy"]["tap_revision"]

    changed = json.loads(json.dumps(configured))
    changed["devsy"]["tap_revision"] = "a" * 40
    with pytest.raises(module.BootstrapError, match="incident reconciliation policy mismatch"):
        module.validate_tap_reconciliation_case(changed)


def test_issue27_reconciliation_manifest_requires_absent_tap_and_pinned_legacy_cli():
    module = bootstrap_module()
    configured = policy()
    case = module.validate_tap_reconciliation_case(configured)
    manifest = {
        "schema_version": 1,
        "source_sha": "a" * 40,
        "files": {
            "unit": True, "starter": True, "bridge_config": True,
            "receipt": False, "devsy_config": True, "kubectl": False,
        },
        "unit_active": True, "unit_enabled": True,
        "unit_state": "managed",
        "provider_options": {"KUBERNETES_CONTEXT": "", "NODE_SELECTOR": ""},
        "provider_was_verified": True,
        "tap_was_present": False, "tap_revision": None,
        "devsy_version": "1.23.0",
        "devsy_sha256": configured["devsy"]["legacy_sha256"],
        "devsy_path": "/home/operator/.local/bin/devsy",
        "kubectl_version": None, "kubectl_sha256": None,
    }

    summary = module.validate_tap_reconciliation_manifest(manifest, case, configured)

    assert summary["prior_backup_authenticated"] is False
    assert summary["tap_was_present"] is False

    changed = dict(manifest, tap_was_present=True)
    with pytest.raises(module.BootstrapError, match="prior backup is not the expected baseline"):
        module.validate_tap_reconciliation_manifest(changed, case, configured)


def test_tap_reconciliation_plan_blocks_when_expected_backup_is_missing(tmp_path):
    module, bootstrap, tap, calls, _configured = tap_rollback_fixture(
        tmp_path, origin=policy()["devsy"]["tap_repository"].removesuffix(".git"),
        revision="d" * 40,
    )

    result = bootstrap.tap_reconciliation_plan()

    assert result["ready"] is False
    assert result["status"] == "blocked"
    assert result["mutated"] is False
    assert tap.is_dir()
    assert calls == []


def test_tap_reconciliation_requires_explicit_approval_before_commands(tmp_path):
    module, bootstrap, _tap, calls, _configured, _case = tap_reconciliation_fixture(
        tmp_path, monkeypatch=None,
    )

    with pytest.raises(module.BootstrapError, match="explicit tap reconciliation approval"):
        bootstrap.reconcile_tap(
            approved=False, source_sha="a" * 40, github_run_id="123", github_run_attempt="1",
        )

    assert calls == []


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


def tap_rollback_fixture(tmp_path, *, origin, status="", revision="d" * 40):
    module = bootstrap_module()
    profile = private_profile(tmp_path)
    prefix = tmp_path / "linuxbrew/.linuxbrew"
    brew = prefix / "bin/brew"
    brew.parent.mkdir(parents=True, mode=0o700)
    brew.write_text("fixture brew")
    brew.chmod(0o755)
    repository = prefix / "Homebrew"
    tap = repository / "Library/Taps/joshyorko/homebrew-tools"
    tap.mkdir(parents=True, mode=0o700)
    configured = policy()
    configured["homebrew"]["prefix"] = str(prefix)
    profile["brew_path"] = str(brew)
    calls = []

    def command(args, **_kwargs):
        args = [str(value) for value in args]
        calls.append(args)
        output = ""
        if args[0] == str(brew) and args[1:] == ["--repository"]:
            output = str(repository)
        elif args[0] == str(brew) and args[1:] == ["untap", configured["devsy"]["tap"]]:
            shutil.rmtree(tap)
        elif args[0] == "git" and args[-2:] == ["get-url", "origin"]:
            output = origin
        elif args[0] == "git" and args[-2:] == ["rev-parse", "HEAD"]:
            output = revision
        elif args[0] == "git" and "status" in args:
            output = status
        return subprocess.CompletedProcess(args, 0, output, "")

    bootstrap = bootstrap_class(module)(
        profile, configured,
        unit_template=(ROOT / "config/codex-control-plane-devsy.service.in").read_text(),
        system="Linux", machine="aarch64",
        unit_path=tmp_path / "systemd/codex-control-plane-devsy.service",
        runner=command,
    )
    return module, bootstrap, tap, calls, configured


def tap_reconciliation_fixture(tmp_path, monkeypatch):
    module = bootstrap_module()
    profile = private_profile(tmp_path)
    prefix = tmp_path / "linuxbrew/.linuxbrew"
    brew = prefix / "bin/brew"
    brew.parent.mkdir(parents=True, mode=0o700)
    brew.write_text("fixture brew")
    brew.chmod(0o755)
    repository = prefix / "Homebrew"
    tap = repository / "Library/Taps/joshyorko/homebrew-tools"
    tap.mkdir(parents=True, mode=0o700)
    subprocess.run(["git", "init", "--quiet", str(tap)], check=True)
    subprocess.run(["git", "-C", str(tap), "config", "user.name", "Issue 27 fixture"], check=True)
    subprocess.run(["git", "-C", str(tap), "config", "user.email", "issue27@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(tap), "remote", "add", "origin",
                    policy()["devsy"]["tap_repository"]], check=True)
    formula = tap / "Formula/devsy.rb"
    formula.parent.mkdir()
    formula.write_text("class Devsy < Formula\nend\n")
    marker = tap / "revision.txt"
    marker.write_text("approved target\n")
    subprocess.run(["git", "-C", str(tap), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tap), "commit", "--quiet", "-m", "pinned"], check=True)
    target = subprocess.check_output(["git", "-C", str(tap), "rev-parse", "HEAD"], text=True).strip()
    marker.write_text("observed upstream\n")
    subprocess.run(["git", "-C", str(tap), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tap), "commit", "--quiet", "-m", "observed"], check=True)
    observed = subprocess.check_output(["git", "-C", str(tap), "rev-parse", "HEAD"], text=True).strip()
    configured = policy()
    configured["homebrew"]["prefix"] = str(prefix)
    configured["devsy"]["tap_revision"] = target
    profile["brew_path"] = str(brew)
    source_sha = "a" * 40
    prior_manifest = {
        "schema_version": 1,
        "source_sha": source_sha,
        "files": {"unit": False, "starter": False, "bridge_config": False,
                  "receipt": False, "devsy_config": True, "kubectl": False},
        "unit_active": False,
        "unit_enabled": False,
        "unit_state": "legacy",
        "provider_options": {},
        "provider_was_verified": True,
        "tap_was_present": False,
        "tap_revision": None,
        "devsy_version": configured["devsy"]["legacy_version"],
        "devsy_sha256": configured["devsy"]["legacy_sha256"],
        "devsy_path": str(Path(profile["home"]) / ".local/bin/devsy"),
        "kubectl_version": None,
        "kubectl_sha256": None,
    }
    manifest_bytes = (json.dumps(prior_manifest, sort_keys=True) + "\n").encode()
    case = {
        "case_id": "issue-27-test-reconciliation",
        "failed_run_id": "38586057895",
        "prior_backup_directory": "1791990283017830779",
        "prior_backup_manifest_sha256": module.sha256(manifest_bytes),
        "prior_backup_signed": False,
        "observed_tap_revision": observed,
        "upstream_main_revision": observed,
        "target_tap_revision": target,
    }
    module.ISSUE27_TAP_RECONCILIATION = case
    if monkeypatch is not None:
        monkeypatch.setattr(module, "verify_formula", lambda *_args, **_kwargs: None)
    store = Path(profile["state_dir"]) / "deployment"
    store.mkdir(mode=0o700)
    backup = store / "devsy-host-backups" / case["prior_backup_directory"]
    backup.mkdir(mode=0o700, parents=True)
    (backup / "manifest.json").write_bytes(manifest_bytes)
    (backup / "manifest.json").chmod(0o600)
    calls = []

    def runner(args, **kwargs):
        args = [str(value) for value in args]
        calls.append(args)
        if args[0] == str(brew) and args[1:] == ["--repository"]:
            return subprocess.CompletedProcess(args, 0, str(repository), "")
        if args[0] == "git" and args[-4:] == ["ls-remote", "--heads", "origin", "refs/heads/main"]:
            return subprocess.CompletedProcess(
                args, 0, observed + "\trefs/heads/main\n", "",
            )
        return subprocess.run(args, **kwargs)

    bootstrap = bootstrap_class(module)(
        profile, configured,
        unit_template=(ROOT / "config/codex-control-plane-devsy.service.in").read_text(),
        system="Linux", machine="aarch64",
        unit_path=tmp_path / "systemd/codex-control-plane-devsy.service",
        runner=runner,
    )
    bootstrap._issue27_prior_backup = lambda _case: (
        backup, prior_manifest,
        {"source_sha": source_sha, "tap_was_present": False,
         "prior_backup_authenticated": False},
    )
    return module, bootstrap, tap, calls, configured, case


def test_tap_reconciliation_records_pinned_before_after_and_replay_is_read_only(tmp_path, monkeypatch):
    module, bootstrap, tap, calls, _configured, case = tap_reconciliation_fixture(
        tmp_path, monkeypatch,
    )

    result = bootstrap.reconcile_tap(
        approved=True, source_sha="b" * 40, github_run_id="38610000001", github_run_attempt="1",
    )

    assert result["operation"] == "devsy-tap-reconcile"
    assert result["status"] == "completed"
    assert result["changed"] is True
    assert result["prior_backup_authenticated"] is False
    assert result["tap_before_revision"] == case["observed_tap_revision"]
    assert result["tap_after_revision"] == case["target_tap_revision"]
    assert subprocess.check_output(["git", "-C", str(tap), "rev-parse", "HEAD"], text=True).strip() == case["target_tap_revision"]
    assert subprocess.check_output(["git", "-C", str(tap), "status", "--porcelain"], text=True) == ""
    run_dir = (Path(bootstrap.profile["state_dir"]) / "deployment/devsy-tap-reconciliations"
               / case["case_id"] / "38610000001-1")
    before = json.loads((run_dir / "before.json").read_text())
    after = json.loads((run_dir / "after.json").read_text())
    assert before["tap_before_sha256"] == result["tap_before_sha256"]
    assert before["prior_backup_authenticated"] is False
    assert before["receipt_signature_status"] == "unsigned"
    assert after["tap_after_sha256"] == result["tap_after_sha256"]
    assert after["tap_after_revision"] == case["target_tap_revision"]
    assert all((run_dir / name).stat().st_mode & 0o777 == 0o600
               for name in ("before.json", "after.json"))
    assert not any(call[0].endswith("brew") and len(call) > 1 and call[1] in ("install", "tap", "untap")
                   for call in calls)
    assert not any(call[0] == "sudo" or "systemctl" in call or "provider" in call
                   for call in calls)

    checkout_count = sum(call[-3:-2] == ["checkout"] for call in calls)
    replay = bootstrap.reconcile_tap(
        approved=True, source_sha="b" * 40, github_run_id="38610000002", github_run_attempt="1",
    )

    assert replay["status"] == "already-reconciled"
    assert replay["changed"] is False
    assert sum(call[-3:-2] == ["checkout"] for call in calls) == checkout_count


def test_tap_reconciliation_restores_snapshot_and_keeps_failed_tree_on_postcheckout_error(tmp_path, monkeypatch):
    module, bootstrap, tap, _calls, _configured, case = tap_reconciliation_fixture(
        tmp_path, monkeypatch,
    )
    original = bootstrap._issue27_tap_state
    observations = 0

    def fail_postcheckout(current_case):
        nonlocal observations
        observations += 1
        if observations == 3:
            raise module.BootstrapError("fixture post-checkout failure")
        return original(current_case)

    bootstrap._issue27_tap_state = fail_postcheckout
    before_tree = module.tap_tree_manifest(tap, os.getuid())["sha256"]

    with pytest.raises(module.BootstrapError, match="failed at post-checkout-verification: fixture post-checkout failure; automatic rollback restored the original tap"):
        bootstrap.reconcile_tap(
            approved=True, source_sha="b" * 40, github_run_id="38610000003", github_run_attempt="1",
        )

    assert subprocess.check_output(["git", "-C", str(tap), "rev-parse", "HEAD"], text=True).strip() == case["observed_tap_revision"]
    assert module.tap_tree_manifest(tap, os.getuid())["sha256"] == before_tree
    run_dir = (Path(bootstrap.profile["state_dir"]) / "deployment/devsy-tap-reconciliations"
               / case["case_id"] / "38610000003-1")
    rollback = json.loads((run_dir / "rollback.json").read_text())
    assert rollback["status"] == "restored"
    failed_tree = run_dir / rollback["failed_tree"]
    assert module.tap_tree_manifest(failed_tree, os.getuid())["sha256"] == rollback["failed_tap_sha256"]


def test_tap_reconciliation_rollback_requires_approval_and_restores_only_its_receipted_tree(tmp_path, monkeypatch):
    module, bootstrap, tap, _calls, _configured, case = tap_reconciliation_fixture(
        tmp_path, monkeypatch,
    )
    with pytest.raises(module.BootstrapError, match="explicit tap reconciliation rollback approval"):
        bootstrap.rollback_tap_reconciliation(
            approved=False, github_run_id="38610000004", github_run_attempt="1",
        )

    bootstrap.reconcile_tap(
        approved=True, source_sha="b" * 40, github_run_id="38610000004", github_run_attempt="1",
    )
    result = bootstrap.rollback_tap_reconciliation(
        approved=True, github_run_id="38610000004", github_run_attempt="1",
    )

    assert result["operation"] == "devsy-tap-rollback"
    assert result["restored"] is True
    assert result["tap_revision"] == case["observed_tap_revision"]
    assert subprocess.check_output(["git", "-C", str(tap), "rev-parse", "HEAD"], text=True).strip() == case["observed_tap_revision"]
    with pytest.raises(module.BootstrapError, match="already rolled back"):
        bootstrap.rollback_tap_reconciliation(
            approved=True, github_run_id="38610000004", github_run_attempt="1",
        )


def test_restore_preserves_a_tap_with_unexpected_origin_or_local_edits(tmp_path):
    expected = policy()["devsy"]["tap_repository"]
    cases = (("https://github.com/other/homebrew-tools", ""),
             (expected, " M Formula/devsy.rb\n"))

    for index, (origin, status) in enumerate(cases):
        fixture = tmp_path / f"case-{index}"
        fixture.mkdir()
        module, bootstrap, tap, calls, configured = tap_rollback_fixture(
            fixture, origin=origin, status=status,
        )
        manifest = {"tap_was_present": False, "files": {},
                    "unit_active": False, "unit_enabled": False,
                    "provider_was_verified": False}
        backup = Path(configured["homebrew"]["prefix"]) / "backup"
        backup.mkdir(mode=0o700)

        with pytest.raises(module.BootstrapError, match="rollback refused to remove"):
            bootstrap._restore(manifest, backup)

        assert tap.is_dir()
        brew = Path(configured["homebrew"]["prefix"]) / "bin/brew"
        assert not any(call[:2] == [str(brew), "untap"] for call in calls)


def test_restore_removes_a_clean_tap_missing_from_backup(tmp_path):
    origin = policy()["devsy"]["tap_repository"].removesuffix(".git")
    module, bootstrap, tap, calls, configured = tap_rollback_fixture(
        tmp_path, origin=origin,
    )
    manifest = {"tap_was_present": False, "files": {},
                "unit_active": False, "unit_enabled": False,
                "provider_was_verified": False}
    backup = Path(configured["homebrew"]["prefix"]) / "backup"
    backup.mkdir(mode=0o700)

    bootstrap._restore(manifest, backup)

    assert not tap.exists()
    brew = Path(configured["homebrew"]["prefix"]) / "bin/brew"
    assert [call for call in calls if call[:2] == [str(brew), "untap"]] == [
        [str(brew), "untap", configured["devsy"]["tap"]],
    ]


def test_restore_fails_closed_when_the_tap_remains_without_homebrew(tmp_path):
    origin = policy()["devsy"]["tap_repository"].removesuffix(".git")
    module, bootstrap, tap, _calls, configured = tap_rollback_fixture(
        tmp_path, origin=origin,
    )
    brew = Path(configured["homebrew"]["prefix"]) / "bin/brew"
    brew.unlink()
    bootstrap.env["PATH"] = ""
    manifest = {"tap_was_present": False, "files": {},
                "unit_active": False, "unit_enabled": False,
                "provider_was_verified": False}
    backup = Path(configured["homebrew"]["prefix"]) / "backup"
    backup.mkdir(mode=0o700)

    with pytest.raises(module.BootstrapError, match="cannot verify transaction-created tap"):
        bootstrap._restore(manifest, backup)

    assert tap.is_dir()


def test_tap_state_still_rejects_an_unreceipted_revision(tmp_path):
    expected = policy()["devsy"]["tap_repository"]
    module, bootstrap, tap, _calls, configured = tap_rollback_fixture(
        tmp_path, origin=expected.removesuffix(".git"), revision="d" * 40,
    )
    brew = Path(configured["homebrew"]["prefix"]) / "bin/brew"
    repository = Path(configured["homebrew"]["prefix"]) / "Homebrew"

    with pytest.raises(module.BootstrapError, match="conflicting Josh tools tap state"):
        bootstrap._tap_state(brew, repository, receipt=None)


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
        env={"PATH": ""},
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


def test_declared_systemd_unit_mode_is_not_reduced_by_process_umask(tmp_path):
    module = bootstrap_module()
    profile = private_profile(tmp_path)
    bootstrap = bootstrap_class(module)(
        profile, policy(),
        unit_template=(ROOT / "config/codex-control-plane-devsy.service.in").read_text(),
        system="Linux", machine="aarch64",
    )
    unit = tmp_path / "systemd/codex-control-plane-devsy.service"
    unit.parent.mkdir(mode=0o700)
    old_umask = os.umask(0o077)
    try:
        bootstrap._write_private(unit, b"[Unit]\n", 0o644)
    finally:
        os.umask(old_umask)

    assert unit.stat().st_mode & 0o777 == 0o644


def test_rollback_plan_rejects_symlinked_backup_directory(tmp_path):
    module = bootstrap_module()
    profile = private_profile(tmp_path)
    store = Path(profile["state_dir"]) / "deployment"
    store.mkdir(mode=0o700)
    outside = tmp_path / "outside-backup"
    outside.mkdir(mode=0o700)
    manifest = outside / "manifest.json"
    manifest.write_text(json.dumps({"source_sha": "a" * 40}))
    manifest.chmod(0o600)
    backup = store / "backup-link"
    backup.symlink_to(outside, target_is_directory=True)
    receipt = store / "devsy-host-current.json"
    receipt.write_text(json.dumps({"status": "applied", "backup_dir": str(backup)}))
    receipt.chmod(0o600)
    bootstrap = bootstrap_class(module)(
        profile, policy(),
        unit_template=(ROOT / "config/codex-control-plane-devsy.service.in").read_text(),
        system="Linux", machine="aarch64",
    )

    with pytest.raises(module.BootstrapError, match="private Devsy directory ownership or mode mismatch"):
        bootstrap.rollback_plan()


@pytest.mark.parametrize("machine", ["x86_64", "amd64", "aarch64", "arm64"])
def test_linux_amd64_and_arm64_hosts_are_supported(machine):
    module = bootstrap_module()
    module.validate_platform("Linux", machine)


@pytest.mark.parametrize(
    ("machine", "canonical"),
    [("aarch64", "aarch64"), ("arm64", "aarch64"),
     ("x86_64", "x86_64"), ("amd64", "x86_64")],
)
def test_bootstrap_normalizes_linux_machine_aliases_for_artifact_selection(
        tmp_path, machine, canonical):
    module = bootstrap_module()
    bootstrap = bootstrap_class(module)(
        private_profile(tmp_path), policy(), unit_template="",
        system="Linux", machine=machine,
    )

    assert bootstrap.machine == canonical


def test_devsy_policy_pins_both_homebrew_release_artifacts():
    assert policy()["devsy"]["artifact_sha256"] == {
        "aarch64": "872cd988be2f5c37dc92da684c92fb6e9dd56153963366c1bdb143b78f816ae2",
        "x86_64": "0e9e703662575faa796c933e108bbaa9bcfbcf95046825da9c8eb3cf452e8891",
    }


def test_brew_path_preserves_trusted_launcher_symlink(tmp_path):
    module = bootstrap_module()
    prefix = tmp_path / "linuxbrew/.linuxbrew"
    target = prefix / "Homebrew/bin/brew"
    target.parent.mkdir(parents=True)
    target.write_text("#!/bin/sh\nexit 0\n")
    target.chmod(0o755)
    launcher = prefix / "bin/brew"
    launcher.parent.mkdir(parents=True)
    launcher.symlink_to(target)
    configured = policy()
    configured["homebrew"]["prefix"] = str(prefix)
    bootstrap = bootstrap_class(module)(
        private_profile(tmp_path), configured, unit_template="", starter_source="",
        system="Linux", machine="x86_64", env={"PATH": str(tmp_path / "empty-bin")},
    )

    result = bootstrap._brew_path()

    assert result == launcher.absolute()
    assert result.is_symlink()
    assert result.resolve() == target.resolve()


@pytest.mark.parametrize(
    "escape", ["target-outside", "launcher-outside", "traversal-launcher-inside"])
def test_brew_path_rejects_symlinks_outside_pinned_prefix(tmp_path, escape):
    module = bootstrap_module()
    prefix = tmp_path / "linuxbrew/.linuxbrew"
    outside = tmp_path / "outside"
    inside_target = prefix / "Homebrew/bin/brew"
    outside_target = outside / "brew"
    target = outside_target if escape == "target-outside" else inside_target
    target.parent.mkdir(parents=True)
    outside.mkdir(parents=True, exist_ok=True)
    target.write_text("#!/bin/sh\nexit 0\n")
    target.chmod(0o755)
    if escape == "target-outside":
        launcher = prefix / "bin/brew"
    elif escape == "traversal-launcher-inside":
        launcher = prefix / ".." / ".." / "outside/brew-link"
    else:
        launcher = outside / "brew-link"
    launcher.parent.mkdir(parents=True, exist_ok=True)
    launcher.symlink_to(target)
    configured = policy()
    configured["homebrew"]["prefix"] = str(prefix)
    profile = private_profile(tmp_path)
    if escape != "target-outside":
        profile["brew_path"] = str(launcher)
    bootstrap = bootstrap_class(module)(
        profile, configured, unit_template="", starter_source="",
        system="Linux", machine="x86_64", env={"PATH": str(tmp_path / "empty-bin")},
    )

    with pytest.raises(module.BootstrapError, match="outside the pinned Homebrew prefix"):
        bootstrap._brew_path()


def test_pinned_formula_rejects_wrong_amd64_artifact_digest():
    module = bootstrap_module()
    formula = b'''class Devsy < Formula
  version "1.23.2"
  on_linux do
    on_intel do
      url "https://github.com/joshyorko/homebrew-tools/releases/download/devsy-1.23.2/devsy-linux-amd64"
      sha256 "0e9e703662575faa796c933e108bbaa9bcfbcf95046825da9c8eb3cf452e8891"
    end
    on_arm do
      url "https://github.com/joshyorko/homebrew-tools/releases/download/devsy-1.23.2/devsy-linux-arm64"
      sha256 "872cd988be2f5c37dc92da684c92fb6e9dd56153963366c1bdb143b78f816ae2"
    end
  end
end
'''
    configured = policy()
    configured["devsy"]["artifact_sha256"]["x86_64"] = "f" * 64
    configured["devsy"]["formula_sha256"] = module.sha256(formula)

    with pytest.raises(module.BootstrapError, match="AMD64 checksum"):
        module.verify_formula(formula, configured)


@pytest.mark.parametrize(
    ("system", "machine"),
    [("Darwin", "aarch64"), ("Linux", "i386"), ("Windows", "AMD64")],
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


def test_devsy_plan_reports_observed_state_without_private_config_contents(tmp_path):
    module = bootstrap_module()
    profile = private_profile(tmp_path)
    bootstrap = bootstrap_class(module)(
        profile, policy(),
        unit_template=(ROOT / "config/codex-control-plane-devsy.service.in").read_text(),
        system="Linux", machine="aarch64",
    )
    template = "spec:\n  privateFixture: do-not-publish\n"
    formula = b"pinned formula fixture"
    kubeconfig = "/private/fixture/ror-kubeconfig"
    binary = "/home/operator/.local/bin/devsy"
    state = {
        "changes": ["install-tap-devsy", "configure-ror-provider"],
        "brew": {"present": True, "prefix": "/home/linuxbrew/.linuxbrew",
                 "tap": {"present": True, "revision": "b" * 40}},
        "formula": formula,
        "devsy": {"version": "1.23.0", "sha256": "a" * 64, "path": binary},
        "binary": Path(binary),
        "provider": {"name": "kubernetes", "default": True, "changes": ["RESOURCES"],
                     "options": {
                         "KUBERNETES_CONTEXT": "ror", "KUBERNETES_NAMESPACE": "devsy",
                         "CREATE_NAMESPACE": "true", "NODE_SELECTOR": "",
                         "RESOURCES": "requests.cpu=8,requests.memory=12Gi,limits.cpu=8,limits.memory=12Gi",
                         "KUBERNETES_CONFIG": kubeconfig,
                         "POD_MANIFEST_TEMPLATE": template,
                     }},
        "cluster": {"context": "ror", "namespace": "devsy", "ready_worker_nodes": 0},
        "unit_state": "legacy", "unit_sha256": "c" * 64, "starter_state": "managed",
        "service": {"active": True, "enabled": True},
        "service_properties": {
            "FragmentPath": "/etc/systemd/system/codex-control-plane-devsy.service",
            "User": "operator", "Group": "operator",
            "ExecStart": "/usr/bin/python3 /home/operator/state/start-host-devsy.py",
        },
    }

    plan = bootstrap._public_plan(state)

    assert plan["source_provenance"] == {
        "repository": "devsy-org/devsy", "revision": "0f248a8502ca609e494ec58064556342e30441cb",
        "release": "devsy-1.23.2",
        "artifact_sha256": "872cd988be2f5c37dc92da684c92fb6e9dd56153963366c1bdb143b78f816ae2",
    }
    observed = plan["observed"]
    assert observed["tap_current_revision"] == "b" * 40
    assert observed["formula_sha256"] == module.sha256(formula)
    assert observed["devsy"] == {
        "binary": binary, "version": "1.23.0", "sha256": "a" * 64,
        "matches_pinned_homebrew_binary": False, "source_revision": None,
    }
    assert observed["provider"] == {
        "name": "kubernetes", "default": True, "context": "ror", "namespace": "devsy",
        "create_namespace": "true", "node_selector": "",
        "resources": "requests.cpu=8,requests.memory=12Gi,limits.cpu=8,limits.memory=12Gi",
        "kubeconfig_configured": True,
        "pod_manifest_template_sha256": module.sha256(template.encode()),
    }
    assert observed["systemd"] == {
        "unit_state": "legacy", "unit_sha256": "c" * 64,
        "bridge_starter": "managed", "active": True,
        "enabled": True, "fragment_path": "/etc/systemd/system/codex-control-plane-devsy.service",
        "user": "operator", "group": "operator",
        "exec_start": "/usr/bin/python3 /home/operator/state/start-host-devsy.py",
    }
    assert plan["provider"]["requests"] == {"cpu": "1", "memory": "1Gi"}
    assert plan["provider"]["limits"] == {"cpu": "2", "memory": "4Gi"}
    assert kubeconfig not in json.dumps(plan)
    assert template not in json.dumps(plan)


def test_read_only_plan_reports_cluster_admission_blocker_with_observed_provider(
        tmp_path, monkeypatch):
    module = bootstrap_module()
    profile = private_profile(tmp_path)
    bootstrap = bootstrap_class(module)(
        profile, policy(),
        unit_template=(ROOT / "config/codex-control-plane-devsy.service.in").read_text(),
        system="Linux", machine="aarch64",
    )
    home = Path(profile["home"])
    state_dir = Path(profile["state_dir"])
    repo = Path(profile["repo_dir"])
    kubeconfig = Path(profile["devsy"]["kubeconfig_source"])
    brew = Path("/home/linuxbrew/.linuxbrew/bin/brew")
    binary = Path("/home/linuxbrew/.linuxbrew/bin/devsy")
    options = module.provider_options(policy(), str(kubeconfig))
    provider = {"name": "kubernetes", "default": True, "options": options, "changes": []}
    devsy = {"version": "1.23.2", "sha256": policy()["devsy"]["artifact_sha256"]["aarch64"],
             "path": binary, "provider": provider}
    monkeypatch.setattr(bootstrap, "_validate_inputs", lambda: (home, state_dir, repo, kubeconfig))
    monkeypatch.setattr(bootstrap, "_receipt", lambda: None)
    monkeypatch.setattr(bootstrap, "_homebrew_state", lambda _receipt: {
        "present": True, "brew": str(brew), "prefix": str(brew.parent.parent),
        "tap": {"present": True, "revision": policy()["devsy"]["tap_revision"]},
    })
    monkeypatch.setattr(bootstrap, "_formula_bytes", lambda: b"verified formula")
    monkeypatch.setattr(bootstrap, "_current_unit", lambda: None)
    monkeypatch.setattr(bootstrap, "_desired_unit_from_path", lambda *_args: b"unit")
    monkeypatch.setattr(bootstrap, "_starter_state", lambda _state_dir: "managed")
    monkeypatch.setattr(bootstrap, "_provider_binary", lambda *_args: (binary, devsy))

    def reject_cluster(_kubeconfig):
        raise module.BootstrapError("ROR has no ready worker node matching Devsy selector")

    monkeypatch.setattr(bootstrap, "_cluster_admission", reject_cluster)

    plan = bootstrap.plan()

    assert plan["ready"] is False
    assert plan["status"] == "blocked"
    assert plan["cluster"] == {
        "ready": False, "status": "blocked",
        "reason": "ROR has no ready worker node matching Devsy selector",
    }
    assert plan["observed"]["provider"]["context"] == "ror"
    assert plan["observed"]["provider"]["resources"] == options["RESOURCES"]


def test_apply_rejects_blocked_cluster_before_backing_up_or_mutating(tmp_path, monkeypatch):
    module = bootstrap_module()
    calls = []
    bootstrap = bootstrap_class(module)(
        private_profile(tmp_path), policy(),
        unit_template=(ROOT / "config/codex-control-plane-devsy.service.in").read_text(),
        system="Linux", machine="aarch64", runner=lambda *args, **kwargs: calls.append(args),
    )
    monkeypatch.setattr(bootstrap, "_inspect", lambda: {
        "changes": [], "cluster": {"ready": False, "status": "blocked",
                                   "reason": "ROR has no eligible worker node"},
    })
    monkeypatch.setattr(bootstrap, "_public_plan", lambda _state: {"status": "blocked"})
    backups = []
    monkeypatch.setattr(bootstrap, "_backup", lambda *_args: backups.append(True))

    with pytest.raises(module.BootstrapError, match="ROR admission preflight is blocked"):
        bootstrap.apply(approved=True, source_sha="a" * 40)

    assert backups == []
    assert calls == []


def test_cluster_preflight_stops_before_clusterwide_pod_inventory_without_workers(tmp_path):
    module = bootstrap_module()
    profile = private_profile(tmp_path)
    configured = policy()
    kubectl_artifact = b"fixture pinned kubectl"
    configured["kubectl"]["artifact_sha256"]["aarch64"] = hashlib.sha256(
        kubectl_artifact
    ).hexdigest()
    kubectl_bin = Path(profile["state_dir"]) / "bin/kubectl"
    kubectl_bin.parent.mkdir(mode=0o700)
    kubectl_bin.write_bytes(kubectl_artifact)
    kubectl_bin.chmod(0o755)
    calls = []

    def runner(arguments, **_kwargs):
        calls.append(arguments)
        get_index = arguments.index("get")
        resource = arguments[get_index + 1]
        if resource == "namespace":
            output = json.dumps({"metadata": {"name": "devsy"}})
        elif resource == "resourcequota,limitrange":
            output = json.dumps({"items": []})
        elif resource == "nodes":
            output = json.dumps({"items": []})
        else:
            raise AssertionError(f"unexpected cluster inventory query: {resource}")
        return subprocess.CompletedProcess(arguments, 0, output, "")

    bootstrap = bootstrap_class(module)(
        profile, configured,
        unit_template=(ROOT / "config/codex-control-plane-devsy.service.in").read_text(),
        system="Linux", machine="aarch64", runner=runner, env={"PATH": ""},
    )

    with pytest.raises(module.BootstrapError, match="no ready worker node"):
        bootstrap._cluster_admission(Path(profile["devsy"]["kubeconfig_source"]))

    assert [args[args.index("get") + 1] for args in calls] == [
        "namespace", "resourcequota,limitrange", "nodes",
    ]


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


def test_read_only_plan_represents_missing_pinned_kubectl_without_readiness(
        tmp_path):
    module = bootstrap_module()
    profile = private_profile(tmp_path)
    artifact = b"fixture kubectl v1.36.3"
    digest = hashlib.sha256(artifact).hexdigest()
    configured = policy()
    configured["kubectl"]["artifact_sha256"] = {"x86_64": digest, "aarch64": digest}
    bootstrap = bootstrap_class(module)(
        profile, configured,
        unit_template=(ROOT / "config/codex-control-plane-devsy.service.in").read_text(),
        system="Linux", machine="x86_64", env={"PATH": ""},
    )

    kubectl = bootstrap._kubectl_state()
    state = {
        "changes": ["install-pinned-kubectl"],
        "brew": {"present": True, "prefix": "/home/linuxbrew/.linuxbrew", "tap": None},
        "formula": None, "binary": None, "devsy": None, "provider": None,
        "kubectl": kubectl,
        "cluster": {"ready": False, "status": "blocked",
        "reason": "pinned kubectl is missing; ROR admission preflight was not run"},
        "unit_state": "absent", "starter_state": "absent",
        "service": {"active": False, "enabled": False},
        "service_properties": {}, "unit_sha256": None,
    }

    plan = bootstrap._public_plan(state)

    assert kubectl["status"] == "missing"
    assert kubectl["target_sha256"] == digest
    assert plan["ready"] is False
    assert plan["status"] == "blocked"
    assert plan["cluster"]["reason"] == (
        "pinned kubectl is missing; ROR admission preflight was not run"
    )
    assert plan["observed"]["kubectl"] == {
        "status": "missing", "platform": "x86_64", "version": "1.36.3",
        "sha256": None, "target_sha256": digest,
        "install_location": "private-devsy-state/bin/kubectl",
        "managed_path_present": False,
    }


def test_kubectl_policy_matches_the_verified_cas_release_pin():
    configured = policy()["kubectl"]

    assert configured["version"] == "1.36.3"
    assert configured["source_url"] == (
        "https://dl.k8s.io/release/v1.36.3/bin/linux/{arch}/kubectl"
    )
    assert configured["artifact_sha256"]["x86_64"] == (
        "ebbd080e7c2e275093b55915722043257eb24004363e20acb3c4d71919f88336"
    )
    assert configured["artifact_sha256"]["aarch64"] == (
        "3d86f24401c41ae5a46ac50eef8865fe891d3647d324a0836f6c63757a126e62"
    )
    assert configured["install_location"] == "private-devsy-state/bin/kubectl"


def test_pinned_kubectl_install_is_private_and_idempotent(tmp_path):
    module = bootstrap_module()
    profile = private_profile(tmp_path)
    artifact = b"fixture pinned kubectl v1.36.3"
    configured = policy()
    digest = hashlib.sha256(artifact).hexdigest()
    configured["kubectl"]["artifact_sha256"] = {"x86_64": digest, "aarch64": digest}
    fetched = []
    bootstrap = bootstrap_class(module)(
        profile, configured,
        unit_template=(ROOT / "config/codex-control-plane-devsy.service.in").read_text(),
        system="Linux", machine="x86_64", env={"PATH": ""},
        fetcher=lambda _url: fetched.append(artifact) or artifact,
    )
    target = Path(profile["state_dir"]) / "bin/kubectl"

    first = bootstrap._install_kubectl()
    second = bootstrap._install_kubectl()

    assert first["status"] == second["status"] == "verified"
    assert first["path"] == second["path"] == target
    assert fetched == [artifact]
    assert target.read_bytes() == artifact
    assert target.stat().st_mode & 0o777 == 0o755
    assert target.parent.stat().st_mode & 0o777 == 0o700
    assert target.stat().st_uid == os.getuid()


def test_pinned_kubectl_install_rejects_wrong_sha_without_overwriting(tmp_path):
    module = bootstrap_module()
    profile = private_profile(tmp_path)
    configured = policy()
    configured["kubectl"]["artifact_sha256"] = {
        "x86_64": hashlib.sha256(b"expected").hexdigest(),
        "aarch64": hashlib.sha256(b"expected").hexdigest(),
    }
    bootstrap = bootstrap_class(module)(
        profile, configured,
        unit_template=(ROOT / "config/codex-control-plane-devsy.service.in").read_text(),
        system="Linux", machine="x86_64", env={"PATH": ""},
        fetcher=lambda _url: b"wrong artifact",
    )
    target = Path(profile["state_dir"]) / "bin/kubectl"

    with pytest.raises(module.BootstrapError, match="kubectl checksum mismatch"):
        bootstrap._install_kubectl()
    assert not target.exists()

    target.parent.mkdir(mode=0o700)
    target.write_bytes(b"untrusted existing kubectl")
    target.chmod(0o755)
    with pytest.raises(module.BootstrapError, match="pinned source/hash validation"):
        bootstrap._install_kubectl()
    assert target.read_bytes() == b"untrusted existing kubectl"


def test_apply_rolls_back_staged_kubectl_when_ror_admission_still_blocks(
        tmp_path, monkeypatch):
    module = bootstrap_module()
    profile = private_profile(tmp_path)
    artifact = b"fixture pinned kubectl v1.36.3"
    configured = policy()
    digest = hashlib.sha256(artifact).hexdigest()
    configured["kubectl"]["artifact_sha256"] = {"x86_64": digest, "aarch64": digest}
    calls = []
    bootstrap = bootstrap_class(module)(
        profile, configured,
        unit_template=(ROOT / "config/codex-control-plane-devsy.service.in").read_text(),
        system="Linux", machine="x86_64", env={"PATH": ""},
        runner=lambda args, **_kwargs: calls.append(args),
        fetcher=lambda _url: artifact,
        unit_path=tmp_path / "systemd/codex-control-plane-devsy.service",
    )
    target = Path(profile["state_dir"]) / "bin/kubectl"
    missing_kubectl = bootstrap._kubectl_state()
    initial = {
        "changes": ["install-pinned-kubectl"],
        "cluster": {"ready": False, "status": "blocked",
                    "reason": module.MISSING_KUBECTL_REASON},
        "kubectl": missing_kubectl,
        "service": {"active": False, "enabled": False},
        "unit_state": "absent", "provider": None,
        "brew": {"tap": None}, "devsy": None, "binary": None,
        "state_dir": Path(profile["state_dir"]),
        "kubeconfig": Path(profile["devsy"]["kubeconfig_source"]),
    }
    blocked_after_staging = {
        **initial,
        "changes": [],
        "cluster": {"ready": False, "status": "blocked",
                    "reason": "ROR has no ready worker node matching Devsy selector"},
        "kubectl": {**missing_kubectl, "status": "verified", "sha256": digest},
    }
    inspections = iter((initial, blocked_after_staging))
    monkeypatch.setattr(bootstrap, "_inspect", lambda: next(inspections))

    with pytest.raises(module.BootstrapError, match="staged kubectl was rolled back"):
        bootstrap.apply(approved=True, source_sha="a" * 40)

    assert not target.exists()
    assert calls == []


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
    amd64_artifact = b"fixture tap Devsy 1.23.2 AMD64 artifact"
    amd64_sha = hashlib.sha256(amd64_artifact).hexdigest()
    configured["devsy"]["artifact_sha256"] = {
        "aarch64": target_sha, "x86_64": amd64_sha,
    }
    kubectl_artifact = b"fixture pinned kubectl v1.36.3"
    kubectl_sha = hashlib.sha256(kubectl_artifact).hexdigest()
    configured["kubectl"]["artifact_sha256"] = {
        "aarch64": kubectl_sha, "x86_64": kubectl_sha,
    }
    formula = (
        'class Devsy < Formula\n  version "1.23.2"\n'
        '  on_linux do\n'
        '    on_intel do\n      url "https://github.com/joshyorko/homebrew-tools/releases/download/devsy-1.23.2/devsy-linux-amd64"\n'
        '      sha256 "' + amd64_sha + '"\n    end\n'
        '    on_arm do\n      url "https://github.com/joshyorko/homebrew-tools/releases/download/devsy-1.23.2/devsy-linux-arm64"\n'
        '      sha256 "' + target_sha + '"\n    end\n  end\nend\n'
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
    kubectl_bin = Path(profile["state_dir"]) / "bin/kubectl"
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
    fetched = []
    bootstrap = bootstrap_class(module)(
        profile, configured,
        unit_template=(ROOT / "config/codex-control-plane-devsy.service.in").read_text(),
        runner=runner,
        fetcher=lambda url: (fetched.append(url) or
                             (kubectl_artifact if url.endswith("/kubectl") else formula)),
        system="Linux", machine="aarch64", unit_path=unit_path,
        env={"PATH": ""},
        process_probe=lambda _config, _receipt: True, health_probe=lambda _config: True,
    )
    planned = bootstrap.plan()
    assert planned["ready"] is False
    assert planned["status"] == "blocked"
    assert planned["observed"]["kubectl"]["status"] == "missing"
    assert planned["observed"]["kubectl"]["target_sha256"] == kubectl_sha
    assert "install-pinned-kubectl" in planned["changes"]
    assert not (Path(profile["state_dir"]) / "deployment").exists()
    first = bootstrap.apply(approved=True, source_sha="a" * 40)
    assert first["changed"] is True
    assert first["devsy_version"] == "1.23.2"
    assert first["kubectl_version"] == "1.36.3"
    assert first["kubectl_sha256"] == kubectl_sha
    assert kubectl_bin.read_bytes() == kubectl_artifact
    assert fetched.count(
        "https://dl.k8s.io/release/v1.36.3/bin/linux/arm64/kubectl"
    ) == 1
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

    rolled_back = bootstrap.rollback()
    assert rolled_back["restored"] is True
    assert not kubectl_bin.exists()
    assert runner.options["NODE_SELECTOR"] == ""
