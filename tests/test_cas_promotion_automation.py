import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import textwrap

import pytest


ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import cas_promotion
import propose_cas_promotion


def run_promotion_workflow(tmp_path, *, existing_pr):
    """Run the checked-in shell with local Git and fixture-only GitHub inputs."""
    origin = tmp_path / "origin.git"
    checkout = tmp_path / "checkout"
    environment = {**os.environ, "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
                   "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z"}

    def git(*args, cwd=checkout):
        return subprocess.run(["git", *args], cwd=cwd, env=environment,
                              check=True, capture_output=True, text=True).stdout.strip()

    git("init", "--bare", str(origin), cwd=tmp_path)
    git("init", "--initial-branch=main", str(checkout), cwd=tmp_path)
    git("config", "user.name", "github-actions[bot]")
    git("config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
    (checkout / "config").mkdir()
    (checkout / "config/deploy-images.json").write_text("{}\n")
    (checkout / "scripts").mkdir()
    shutil.copyfile(ROOT / "scripts/cas_promotion_branch.py", checkout / "scripts/cas_promotion_branch.py")
    git("add", ".")
    git("commit", "-m", "Baseline")
    git("remote", "add", "origin", str(origin))
    git("push", "origin", "main")
    git("fetch", "origin", "main")
    revision = "a" * 40
    candidate = {"source_revision": revision,
                 "qualification": {"run_url": "https://github.com/example/actions/runs/1"},
                 "publisher": {"run_url": "https://github.com/example/actions/runs/2"}}
    candidate_file = tmp_path / "candidate.json"
    candidate_file.write_text(json.dumps(candidate))
    if existing_pr:
        git("checkout", "-b", "automation/cas-promotion")
        (checkout / "config/deploy-images.json").write_text('{"candidate":true}\n')
        shutil.copyfile(candidate_file, checkout / "config/cas-promotion.json")
        git("add", "config")
        git("commit", "-m", "Existing candidate")
        git("push", "origin", "automation/cas-promotion")
        git("checkout", "main")
    before = git("ls-remote", "--heads", "origin", "automation/cas-promotion")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    python = bin_dir / "python"
    python.write_text(f"#!{sys.executable}\n" + textwrap.dedent('''\
        import os, pathlib, shutil, sys
        if sys.argv[1:] == ["scripts/propose_cas_promotion.py"]:
            pathlib.Path("config/deploy-images.json").write_text('{"candidate":true}\\n')
            shutil.copyfile(os.environ["CANDIDATE_FILE"], "config/cas-promotion.json")
        else:
            os.execv(sys.executable, [sys.executable, *sys.argv[1:]])
    '''))
    gh = bin_dir / "gh"
    gh.write_text(f"#!{sys.executable}\n" + textwrap.dedent('''\
        import json, os, pathlib, shutil, sys
        if sys.argv[1:3] == ["pr", "list"]:
            print(json.dumps([{"number": 1, "author": {"login": "github-actions[bot]"},
                 "baseRefName": "main", "headRefName": "automation/cas-promotion",
                 "isDraft": True}] if os.environ["EXISTING_PR"] == "1" else []))
        elif sys.argv[1:3] == ["pr", "create"]:
            shutil.copyfile(sys.argv[sys.argv.index("--body-file") + 1], os.environ["PR_BODY"])
        else:
            raise SystemExit("Unexpected GitHub fixture command")
    '''))
    python.chmod(0o755)
    gh.chmod(0o755)
    workflow = (ROOT / ".github/workflows/cas-promotion.yml").read_text()
    shell = textwrap.dedent(workflow.split("        run: |\n")[-1])
    body = tmp_path / "pr-body.md"
    run_environment = {**environment, "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                       "PROMOTION_BRANCH": "automation/cas-promotion", "EXISTING_PR": str(int(existing_pr)),
                       "GITHUB_REPOSITORY": "fixture/repo", "CANDIDATE_FILE": str(candidate_file),
                       "PR_BODY": str(body), "TMPDIR": str(tmp_path),
                       "GIT_AUTHOR_DATE": "2001-01-01T00:00:00Z",
                       "GIT_COMMITTER_DATE": "2001-01-01T00:00:00Z"}
    result = subprocess.run(["bash", "-c", shell], cwd=checkout, env=run_environment,
                            capture_output=True, text=True, timeout=30)
    after = git("ls-remote", "--heads", "origin", "automation/cas-promotion")
    return result, before, after, body, revision


def test_promotion_rerun_keeps_existing_candidate_commit_and_ci(tmp_path):
    result, before, after, _body, _revision = run_promotion_workflow(tmp_path, existing_pr=True)
    assert result.returncode == 0, result.stderr
    assert after == before


def test_promotion_pr_body_preserves_literal_revision_and_file_references(tmp_path):
    result, _before, _after, body, revision = run_promotion_workflow(tmp_path, existing_pr=False)
    assert result.returncode == 0, result.stderr
    text = body.read_text()
    assert f"`{revision}`" in text
    assert "`config/cas-promotion.json`" in text


def promotion_fixture():
    spec=importlib.util.spec_from_file_location("cas_promotion_fixture",ROOT/"tests/test_cas_promotion.py")
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.receipt(),module.proof,module.locator(),module.run_proof


def test_proposer_creates_only_paired_review_files_with_verified_evidence():
    current=json.loads((ROOT/"config/deploy-images.json").read_text())
    handoff,proof,handoff_locator,run_proof=promotion_fixture()
    candidate=propose_cas_promotion.propose(
        current,handoff,verifier=lambda manifest,**_kwargs:proof(manifest),
        run_verifier=run_proof,candidate_verifier=lambda *_args:None,
        handoff_locator=handoff_locator,source_verifier=lambda *_args:{})
    assert candidate is not None
    assert candidate["manifest"]["images"]["cas"]==candidate["manifest"]["images"]["schema_proxy"]
    assert candidate["manifest"]["images"]["executor"]==current["images"]["executor"]
    assert candidate["manifest"]["images"]["tunnel"]==current["images"]["tunnel"]
    assert cas_promotion.validate_deployment_evidence(candidate["evidence"],candidate["manifest"])
    already_current=propose_cas_promotion.propose(
        candidate["manifest"],handoff,verifier=lambda manifest,**_kwargs:proof(manifest),
        run_verifier=run_proof,candidate_verifier=lambda *_args:None,
        handoff_locator=handoff_locator,source_verifier=lambda *_args:{})
    assert already_current is None


def test_missing_handoff_is_no_candidate_and_does_not_write_promotion_files(tmp_path,monkeypatch):
    config=tmp_path/"config"
    config.mkdir()
    manifest=json.loads((ROOT/"config/deploy-images.json").read_text())
    (config/"deploy-images.json").write_text(json.dumps(manifest))
    monkeypatch.setattr(propose_cas_promotion.cas_promotion,"fetch_handoff",lambda:None)
    result=propose_cas_promotion.run(tmp_path)
    assert result=={"status":"no-qualified-release","changed":False}
    assert not (config/"cas-promotion.json").exists()


def test_atomic_promotion_writer_refuses_symlink_targets(tmp_path):
    target=tmp_path/"receipt.json"
    destination=tmp_path/"other.json"
    destination.write_text("{}")
    target.symlink_to(destination)
    with pytest.raises(ValueError,match="unsafe"):
        propose_cas_promotion._atomic_json(target,{"status":"test"})
    assert destination.read_text()=="{}"


def test_pr_lane_is_daily_and_deduplicates_only_a_draft_automation_branch():
    workflow=(ROOT/".github/workflows/cas-promotion.yml").read_text()
    assert "schedule:" in workflow and "17 7 * * *" in workflow
    assert "workflow_dispatch:" in workflow
    assert "github.ref == 'refs/heads/main'" in workflow
    assert "actions/checkout@11d5960a326750d5838078e36cf38b85af677262" in workflow
    assert "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065" in workflow
    assert "contents: write" in workflow and "pull-requests: write" in workflow
    assert "PROMOTION_BRANCH: automation/cas-promotion" in workflow
    assert "cas_promotion_branch.py" in workflow
    assert "--force-with-lease" in workflow
    assert "gh pr create" in workflow and "--draft" in workflow
    assert "enable-auto-merge" not in workflow
    assert "CAS_ARTIFACTS_READ_TOKEN: ${{ secrets.CAS_ARTIFACTS_READ_TOKEN }}" in workflow


def test_production_workflow_remains_manual_approval_gated_and_does_not_auto_deploy():
    workflow=(ROOT/".github/workflows/deploy-control-plane.yml").read_text()
    assert "on:\n  workflow_dispatch:" in workflow
    assert "environment: control-plane-production" in workflow
    assert "refs/heads/main" in workflow
    assert "cas_digest:" not in workflow and "cas_revision:" not in workflow
    assert "push:" not in workflow and "workflow_run:" not in workflow
    assert "CAS_ARTIFACTS_READ_TOKEN: ${{ inputs.operation == 'cas' && secrets.CAS_ARTIFACTS_READ_TOKEN || '' }}" in workflow


def test_local_patchraptor_policy_inherits_central_rules_and_excludes_cas_pair():
    config=json.loads((ROOT/".github/renovate.json5").read_text())
    assert config["extends"]==["github>joshyorko/renovate-config:org-inherited-config"]
    assert config["automerge"] is False
    assert config["platformAutomerge"] is False
    assert config["dependencyDashboardApproval"] is True
    rules=config["packageRules"]
    cas=next(rule for rule in rules if "ghcr.io/joshyorko/codex-action-server" in rule.get("matchPackageNames",[]))
    assert cas["enabled"] is False
    assert "config/deploy-images.json" in cas["matchFileNames"]
    assert cas["automerge"] is False and cas["platformAutomerge"] is False
    images=next(rule for rule in rules if "ghcr.io/usefulsoftwareco/executor-selfhost" in rule.get("matchPackageNames",[]))
    assert images["groupName"]=="Tunnel-kit deployment images"
    assert images["dependencyDashboardApproval"] is True
