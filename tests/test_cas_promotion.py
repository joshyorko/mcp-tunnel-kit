"""Fail-closed tests for the cross-repository qualified CAS handoff."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def seal(value):
    unsigned=dict(value)
    unsigned.pop("receipt_sha256",None)
    value["receipt_sha256"] = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return value


def helper():
    path = ROOT / "scripts/cas_promotion.py"
    spec = importlib.util.spec_from_file_location("cas_promotion", path)
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.path.insert(0, str(ROOT / "scripts"))
    spec.loader.exec_module(module)
    return module


def receipt():
    revision = "a" * 40
    methods = ["codex.list_targets", "codex.list_models", "codex.start_turn"]
    value={
        "schema_version": 1,
        "source": {
            "repository": "joshyorko/codex-action-server",
            "revision": revision,
            "merged": True,
            "commit_url": f"https://github.com/joshyorko/codex-action-server/commit/{revision}",
        },
        "qualification": {
            "status": "qualified",
            "run_url": "https://github.com/joshyorko/codex-action-server/actions/runs/1001",
            "required_ci_url": "https://github.com/joshyorko/codex-action-server/actions/runs/1002",
            "comparison_url": "https://github.com/joshyorko/codex-action-server/compare/b...a",
            "surface": {
                "complete": True,
                "sha256": "0" * 64,
                "methods": [{"name": name, "owner": "typed_action"} for name in methods],
            },
            "method_verdicts": {name: "qualified" for name in methods},
            "behavior_coverage": {
                name: {"result": "passed", "strategy": "isolated_fixture"} for name in methods
            },
            "withheld_methods": [],
        },
        "publication": {
            "status": "published",
            "run_url": "https://github.com/joshyorko/codex-action-server/actions/runs/1003",
            "image_repository": "ghcr.io/joshyorko/codex-action-server",
            "image_tag": "sha-" + revision,
            "digest": "sha256:" + "c" * 64,
            "revision": revision,
            "platform": "linux/amd64",
        },
    }
    surface_rows=sorted(value["qualification"]["surface"]["methods"],key=lambda row:row["name"])
    value["qualification"]["surface"]["sha256"] = hashlib.sha256(
        json.dumps(surface_rows,sort_keys=True,separators=(",", ":")).encode()
    ).hexdigest()
    return seal(value)


def proof(_manifest):
    return {
        "cas": {"digest": "sha256:" + "c" * 64, "revision": "a" * 40,
                "current_main": "d" * 40, "repository": "ghcr.io/joshyorko/codex-action-server",
                "publisher_tag": "sha-" + "a" * 40},
        "schema_proxy": {"digest": "sha256:" + "c" * 64, "revision": "a" * 40,
                         "current_main": "d" * 40, "repository": "ghcr.io/joshyorko/codex-action-server",
                         "publisher_tag": "sha-" + "a" * 40},
    }


def test_schema_is_a_strict_json_schema_contract():
    schema = json.loads((ROOT / ".github/schemas/cas-qualified-release-v1.schema.json").read_text())
    assert schema["properties"]["source"]["properties"]["merged"] == {"const": True}
    assert schema["properties"]["qualification"]["properties"]["withheld_methods"]["maxItems"] == 0
    assert schema["properties"]["publication"]["properties"]["platform"] == {"const": "linux/amd64"}
    assert "receipt_sha256" in schema["required"]


def test_valid_handoff_updates_only_the_cas_schema_proxy_pair_and_has_rollback_proof():
    module = helper()
    current = json.loads((ROOT / "config/deploy-images.json").read_text())
    promoted, verified = module.promote_manifest(
        current, receipt(), verifier=lambda manifest, **_kwargs: proof(manifest),
        run_verifier=lambda _receipt: {}, candidate_verifier=lambda *_args: None,
    )
    assert promoted["images"]["cas"] == promoted["images"]["schema_proxy"]
    assert promoted["images"]["cas"]["digest"] == "sha256:" + "c" * 64
    assert promoted["images"]["cas"]["revision"] == "a" * 40
    assert promoted["images"]["executor"] == current["images"]["executor"]
    assert promoted["images"]["tunnel"] == current["images"]["tunnel"]
    evidence = module.build_evidence(current, promoted, receipt(), verified)
    evidence = module.validate_deployment_evidence(evidence, promoted)
    assert evidence["comparison"]["previous_manifest_digest"] == current["images"]["cas"]["digest"]
    assert evidence["rollback"]["manifest_digest"] == current["images"]["cas"]["digest"]
    assert evidence["qualification"]["method_verdicts"]["codex.start_turn"] == "qualified"


@pytest.mark.parametrize("mutate, message", [
    (lambda r: r.update(schema_version=2), "schema"),
    (lambda r: r["source"].update(merged=False), "merged"),
    (lambda r: r["source"].update(commit_url="https://github.com/joshyorko/codex-action-server/commit/" + "f" * 40), "commit URL"),
    (lambda r: r["qualification"]["surface"].update(complete=False), "surface"),
    (lambda r: r["qualification"]["surface"]["methods"].pop(), "complete consumed surface"),
    (lambda r: r["qualification"]["method_verdicts"].pop("codex.start_turn"), "complete consumed surface"),
    (lambda r: r["qualification"]["method_verdicts"].update({"codex.start_turn": "unqualified"}), "remains unqualified"),
    (lambda r: r["qualification"]["method_verdicts"].update({"codex.start_turn": "unknown"}), "remains unqualified"),
    (lambda r: r["qualification"]["behavior_coverage"].pop("codex.start_turn"), "behavior evidence"),
    (lambda r: r["qualification"]["behavior_coverage"]["codex.start_turn"].update(result="failed"), "behavior evidence"),
    (lambda r: r["qualification"].update(withheld_methods=["codex.experimental"]), "withheld"),
    (lambda r: r["publication"].update(revision="f" * 40), "tag or OCI revision"),
    (lambda r: r["publication"].update(image_tag="latest"), "tag or OCI revision"),
    (lambda r: r["publication"].update(platform="linux/arm64"), "linux/amd64"),
    (lambda r: r["publication"].update(digest="latest"), "digest"),
    (lambda r: r["publication"].update(image_repository="ghcr.io/evil/cas"), "repository"),
    (lambda r: r["publication"].update(run_url="https://github.com/joshyorko/codex-action-server/actions/runs/0"), "run URL"),
])
def test_invalid_or_incomplete_handoff_fails_closed(mutate, message):
    module = helper()
    candidate = receipt()
    mutate(candidate)
    seal(candidate)
    with pytest.raises(module.PromotionError, match=message):
        module.validate_handoff(candidate)


def test_publisher_verification_is_required_before_promotion():
    module = helper()
    current = json.loads((ROOT / "config/deploy-images.json").read_text())
    candidate = receipt()

    def fail(_manifest):
        raise module.PromotionError("publisher verification failed")

    with pytest.raises(module.PromotionError, match="publisher verification"):
        module.promote_manifest(current, candidate, verifier=lambda _manifest, **_kwargs: fail(_manifest),
                                run_verifier=lambda _receipt: {}, candidate_verifier=lambda *_args: None)


@pytest.mark.parametrize("alter", [
    lambda evidence: evidence["image"].update(digest="sha256:" + "d" * 64),
    lambda evidence: evidence["qualification"]["method_verdicts"].update({"codex.start_turn": "unqualified"}),
    lambda evidence: evidence.update(status="pending_review"),
])
def test_deployment_refuses_replayed_or_edited_qualification_evidence(alter):
    module = helper()
    current = json.loads((ROOT / "config/deploy-images.json").read_text())
    promoted, verified = module.promote_manifest(
        current, receipt(), verifier=lambda manifest, **_kwargs: proof(manifest),
        run_verifier=lambda _receipt: {}, candidate_verifier=lambda *_args: None,
    )
    evidence = module.build_evidence(current, promoted, receipt(), verified)
    alter(evidence)
    with pytest.raises(module.PromotionError):
        module.validate_deployment_evidence(evidence, promoted)


def test_fetch_handoff_refuses_alternate_url_before_network(monkeypatch):
    module = helper()
    monkeypatch.setattr(module, "urlopen", lambda *_a, **_k: pytest.fail("unexpected network call"))
    with pytest.raises(module.PromotionError, match="approved source"):
        module.fetch_handoff("https://example.invalid/receipt.json")


def test_action_run_verification_requires_three_successful_exact_main_runs():
    module = helper()
    candidate = receipt()
    seen = []

    def reader(url):
        seen.append(url)
        run_id = url.rsplit("/", 1)[-1]
        path = {
            "1001": ".github/workflows/codex-version-qualification.yml",
            "1002": ".github/workflows/test.yml",
            "1003": ".github/workflows/container.yml",
        }[run_id]
        return {"repository": {"full_name": "joshyorko/codex-action-server"},
                "head_repository": {"full_name":"joshyorko/codex-action-server"},
                "head_sha": "a" * 40, "head_branch": "main", "status": "completed",
                "conclusion": "success", "path": path, "event": "push"}

    result = module.verify_action_runs(candidate, reader=reader)
    assert len(seen) == 3
    assert result["publication"]["path"] == ".github/workflows/container.yml"


@pytest.mark.parametrize("field,value", [
    ("conclusion", "failure"), ("status", "in_progress"), ("head_sha", "f" * 40),
    ("head_branch", "pull/12/merge"),
    ("head_repository", {"full_name":"attacker/codex-action-server"}),
])
def test_action_run_verification_rejects_untrusted_or_non_green_runs(field, value):
    module = helper()
    candidate = receipt()

    def reader(url):
        run_id = url.rsplit("/", 1)[-1]
        info = {"repository": {"full_name": "joshyorko/codex-action-server"},
                "head_repository": {"full_name":"joshyorko/codex-action-server"},
                "head_sha": "a" * 40, "head_branch": "main", "status": "completed",
                "conclusion": "success", "path": ".github/workflows/codex-version-qualification.yml",
                "event": "push"}
        if run_id == "1002":
            info[field] = value
        return info

    with pytest.raises(module.PromotionError):
        module.verify_action_runs(candidate, reader=reader)


def test_handoff_404_is_a_no_candidate_state_not_a_fake_ready_receipt(monkeypatch):
    module = helper()

    def missing(*_args, **_kwargs):
        raise module.HTTPError(module.HANDOFF_URL, 404, "not found", None, None)

    monkeypatch.setattr(module, "urlopen", missing)
    assert module.fetch_handoff() is None


def test_no_new_or_unmerged_receipt_is_not_reported_as_ready():
    module = helper()
    candidate = receipt()
    candidate["source"]["merged"] = False
    seal(candidate)
    with pytest.raises(module.PromotionError):
        module.validate_handoff(candidate)


def test_handoff_checksum_detects_modified_qualification_payload():
    module=helper()
    candidate=receipt()
    candidate["qualification"]["method_verdicts"]["codex.start_turn"]="unqualified"
    with pytest.raises(module.PromotionError,match="checksum"):
        module.validate_handoff(candidate)


def test_surface_digest_rejects_a_changed_native_method_owner():
    module=helper()
    candidate=receipt()
    candidate["qualification"]["surface"]["methods"][0]["owner"]="shared_helper"
    seal(candidate)
    with pytest.raises(module.PromotionError,match="surface checksum"):
        module.validate_handoff(candidate)
