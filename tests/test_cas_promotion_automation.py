import importlib.util
import json
from pathlib import Path
import sys

import pytest


ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import cas_promotion
import propose_cas_promotion


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
