"""Fail-closed tests for the cross-repository qualified CAS handoff."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import zipfile

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


def catalog_fixture():
    return json.loads((ROOT / "tests/fixtures/cas-native-methods-pr26.json").read_text())


def catalog_payload(fixture):
    return {"schema_version": fixture["schema_version"], "methods": fixture["methods"]}


def receipt(method_names=None, *, revision="a" * 40):
    methods = method_names or ["codex.list_targets", "codex.list_models", "codex.start_turn"]
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


def locator():
    module = helper()
    commit_sha = "d" * 40
    return {"repository": module.CAS_REPOSITORY, "path": module.HANDOFF_PATH,
            "commit_sha": commit_sha, "url": module._handoff_url(commit_sha)}


def receipt_archive(value, *, contents=None):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        if contents is None:
            contents = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        bundle.writestr("qualified-release.json", contents)
    return archive.getvalue()


def artifact_listing(archive, *, artifact_id=9001, name="qualified-cas-release-v1", expired=False):
    module = helper()
    return {"total_count": 1, "artifacts": [{
        "id": artifact_id, "name": name, "expired": expired,
        "size_in_bytes": len(archive),
        "digest": "sha256:" + hashlib.sha256(archive).hexdigest(),
        "archive_download_url": (
            f"https://api.github.com/repos/{module.CAS_REPOSITORY}/actions/artifacts/{artifact_id}/zip"
        ),
        "workflow_run": {"id": 1003, "repository_id": 42, "head_repository_id": 42,
                         "head_branch": "main", "head_sha": "a" * 40},
    }]}


def run_proof(value):
    archive = receipt_archive(value)
    contents = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    run_id = value["publication"]["run_url"].rsplit("/", 1)[-1]
    return {"publication_artifact": {
        "run_id": run_id, "artifact_id": 9001, "name": "qualified-cas-release-v1",
        "digest": "sha256:" + hashlib.sha256(archive).hexdigest(),
        "file": "qualified-release.json", "content_sha256": hashlib.sha256(contents).hexdigest(),
        "receipt_sha256": value["receipt_sha256"],
    }}


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
    name = schema["properties"]["qualification"]["properties"]["surface"]["properties"]["methods"]["items"]["properties"]["name"]
    assert name["maxLength"] == 128
    assert "/" in name["pattern"]


def test_valid_handoff_updates_only_the_cas_schema_proxy_pair_and_has_rollback_proof():
    module = helper()
    current = json.loads((ROOT / "config/deploy-images.json").read_text())
    promoted, verified = module.promote_manifest(
        current, receipt(), verifier=lambda manifest, **_kwargs: proof(manifest),
        run_verifier=run_proof, candidate_verifier=lambda *_args: None,
    )
    assert promoted["images"]["cas"] == promoted["images"]["schema_proxy"]
    assert promoted["images"]["cas"]["digest"] == "sha256:" + "c" * 64
    assert promoted["images"]["cas"]["revision"] == "a" * 40
    assert promoted["images"]["executor"] == current["images"]["executor"]
    assert promoted["images"]["tunnel"] == current["images"]["tunnel"]
    evidence = module.build_evidence(current, promoted, receipt(), verified, locator())
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
                                run_verifier=run_proof, candidate_verifier=lambda *_args: None)


@pytest.mark.parametrize("alter", [
    lambda evidence: evidence["image"].update(digest="sha256:" + "d" * 64),
    lambda evidence: evidence["qualification"]["method_verdicts"].update({"codex.start_turn": "unqualified"}),
    lambda evidence: evidence["publisher"]["artifact"].update(digest="sha256:" + "0" * 64),
    lambda evidence: evidence.update(status="pending_review"),
])
def test_deployment_refuses_replayed_or_edited_qualification_evidence(alter):
    module = helper()
    current = json.loads((ROOT / "config/deploy-images.json").read_text())
    promoted, verified = module.promote_manifest(
        current, receipt(), verifier=lambda manifest, **_kwargs: proof(manifest),
        run_verifier=run_proof, candidate_verifier=lambda *_args: None,
    )
    evidence = module.build_evidence(current, promoted, receipt(), verified, locator())
    alter(evidence)
    with pytest.raises(module.PromotionError):
        module.validate_deployment_evidence(evidence, promoted)


@pytest.mark.parametrize("url", [
    "https://example.invalid/receipt.json",
    "https://raw.githubusercontent.com/joshyorko/codex-action-server/main/ci/codex_qualification/qualified-release.json",
    "https://raw.githubusercontent.com/joshyorko/codex-action-server/" + "a" * 40 + "/README.md",
])
def test_raw_handoff_reader_refuses_alternate_url_before_network(monkeypatch, url):
    module = helper()
    monkeypatch.setattr(module, "urlopen", lambda *_a, **_k: pytest.fail("unexpected network call"))
    with pytest.raises(module.PromotionError, match="approved source"):
        module._github_raw_json(url)


def test_artifact_download_uses_cross_repo_read_token_only_for_github_api(monkeypatch):
    module = helper()
    monkeypatch.setenv("CAS_ARTIFACTS_READ_TOKEN", "opaque-test-token")
    requests = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, limit):
            assert limit == module.ARTIFACT_MAX_BYTES + 1
            return b"archive-bytes"

    class Opener:
        def open(self, request, timeout):
            requests.append(request)
            assert timeout == 30
            if len(requests) == 1:
                raise module.HTTPError(
                    request.full_url, 302, "Found",
                    {"Location": "https://release-assets.githubusercontent.com/signed.zip"}, None,
                )
            return Response()

    monkeypatch.setattr(module, "build_opener", lambda *_args: Opener())
    url = f"https://api.github.com/repos/{module.CAS_REPOSITORY}/actions/artifacts/91/zip"
    assert module._github_bytes(url) == b"archive-bytes"
    assert requests[0].headers["Authorization"] == "Bearer opaque-test-token"
    assert "Authorization" not in requests[1].headers


def test_artifact_download_rejects_unapproved_redirect_without_forwarding_token(monkeypatch):
    module = helper()
    monkeypatch.setenv("CAS_ARTIFACTS_READ_TOKEN", "opaque-test-token")
    requests = []

    class Opener:
        def open(self, request, timeout):
            requests.append(request)
            raise module.HTTPError(
                request.full_url, 302, "Found", {"Location": "https://evil.invalid/file.zip"}, None,
            )

    monkeypatch.setattr(module, "build_opener", lambda *_args: Opener())
    url = f"https://api.github.com/repos/{module.CAS_REPOSITORY}/actions/artifacts/91/zip"
    with pytest.raises(module.PromotionError, match="redirect target is not approved"):
        module._github_bytes(url)
    assert len(requests) == 1
    assert requests[0].headers["Authorization"] == "Bearer opaque-test-token"


def test_artifact_download_fails_closed_without_cross_repository_read_credential(monkeypatch):
    module = helper()
    monkeypatch.delenv("CAS_ARTIFACTS_READ_TOKEN", raising=False)
    monkeypatch.setattr(module, "build_opener", lambda *_args: pytest.fail("network before credential check"))
    url = f"https://api.github.com/repos/{module.CAS_REPOSITORY}/actions/artifacts/91/zip"
    with pytest.raises(module.PromotionError, match="cross-repository Actions read credential"):
        module._github_bytes(url)


def test_action_run_verification_requires_three_successful_exact_main_runs():
    module = helper()
    candidate = receipt()
    seen = []
    archive = receipt_archive(candidate)

    def reader(url):
        seen.append(url)
        if url.endswith("/artifacts?per_page=100"):
            return artifact_listing(archive)
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

    result = module.verify_action_runs(
        candidate, reader=reader,
        artifact_bytes_reader=lambda url: archive,
    )
    assert len(seen) == 4
    assert result["publication"]["path"] == ".github/workflows/container.yml"
    assert result["publication_artifact"]["artifact_id"] == 9001
    assert result["publication_artifact"]["receipt_sha256"] == candidate["receipt_sha256"]


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

    def missing(url):
        raise module.HTTPError(url, 404, "not found", None, None)

    fetched = module.fetch_handoff(reader=lambda _url: {"sha": "b" * 40}, raw_reader=missing)
    assert fetched is None


def test_fetch_handoff_resolves_main_and_fetches_only_at_immutable_sha():
    module = helper()
    commit_sha = "b" * 40
    calls = []

    def raw_reader(url):
        calls.append(url)
        return receipt()

    fetched = module.fetch_handoff(reader=lambda _url: {"sha": commit_sha}, raw_reader=raw_reader)
    assert fetched == (receipt(), locator() | {"commit_sha": commit_sha,
                                              "url": module._handoff_url(commit_sha)})
    assert calls == [module._handoff_url(commit_sha)]


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


def test_actual_pr26_catalog_of_58_slash_delimited_methods_is_accepted():
    module = helper()
    catalog = catalog_fixture()
    assert catalog["source_revision"] == "ea1ec468027d20b511d059248335f36fd64e473b"
    candidate = receipt([row["method"] for row in catalog["methods"]],
                        revision=catalog["source_revision"])
    module.validate_handoff_surface_against_catalog(candidate, catalog_payload(catalog))
    assert len(candidate["qualification"]["surface"]["methods"]) == 58
    assert "thread/start" in candidate["qualification"]["method_verdicts"]
    assert "mcpServer/tool/call" in candidate["qualification"]["behavior_coverage"]


def test_truncated_or_self_consistently_forged_surface_fails_source_catalog_check():
    module = helper()
    catalog = catalog_fixture()
    methods = [row["method"] for row in catalog["methods"]]
    truncated = receipt(methods[:-1])
    with pytest.raises(module.PromotionError, match="source-pinned native method catalog"):
        module.validate_handoff_surface_against_catalog(truncated, catalog_payload(catalog))

    forged = receipt(methods[:-1] + ["thread/fake"])
    with pytest.raises(module.PromotionError, match="source-pinned native method catalog"):
        module.validate_handoff_surface_against_catalog(forged, catalog_payload(catalog))


@pytest.mark.parametrize("name", [
    "account/rateLimits/read", "thread/start", "mcpServer/tool/call", "legacy.method_name",
])
def test_method_identifier_grammar_accepts_native_catalog_names(name):
    module = helper()
    assert module.METHOD_RE.fullmatch(name)


@pytest.mark.parametrize("name", ["/thread/start", "thread/", "thread//start", "thread/has space", "a" * 129])
def test_method_identifier_grammar_rejects_malformed_paths(name):
    module = helper()
    assert not module.METHOD_RE.fullmatch(name)


def test_handoff_source_verification_rechecks_receipt_ancestry_and_source_catalog():
    module = helper()
    catalog = catalog_fixture()
    candidate = receipt([row["method"] for row in catalog["methods"]],
                        revision=catalog["source_revision"])
    binding = module.handoff_source_evidence(candidate, locator())
    main_sha = "e" * 40
    api_calls = []

    def reader(url):
        api_calls.append(url)
        if url.endswith("/commits/main"):
            return {"sha": main_sha}
        base = url.rsplit("/compare/", 1)[1].split("...", 1)[0]
        return {"status": "ahead", "base_commit": {"sha": base},
                "merge_base_commit": {"sha": base}}

    def raw_reader(url):
        if url == binding["url"] or url == module._handoff_url(main_sha):
            return candidate
        if url == module._method_catalog_url(candidate["source"]["revision"]):
            return catalog_payload(catalog)
        raise AssertionError("unexpected immutable source URL")

    verified = module.verify_handoff_source(candidate, binding, reader=reader, raw_reader=raw_reader)
    assert verified["commit_sha"] == binding["commit_sha"]
    assert verified["main_sha"] == main_sha
    assert len(api_calls) == 3


def test_handoff_source_verification_rejects_rechecksummed_false_surface_and_changed_bytes():
    module = helper()
    catalog = catalog_fixture()
    methods = [row["method"] for row in catalog["methods"]]
    candidate = receipt(methods)
    binding = module.handoff_source_evidence(candidate, locator())
    main_sha = "e" * 40

    def reader(url):
        if url.endswith("/commits/main"):
            return {"sha": main_sha}
        base = url.rsplit("/compare/", 1)[1].split("...", 1)[0]
        return {"status": "ahead", "base_commit": {"sha": base},
                "merge_base_commit": {"sha": base}}

    forged = receipt(methods[:-1] + ["thread/forged"])
    def raw_reader(url):
        if url == module._method_catalog_url(candidate["source"]["revision"]):
            return catalog
        return forged

    with pytest.raises(module.PromotionError, match="bytes differ"):
        module.verify_handoff_source(candidate, binding, reader=reader, raw_reader=raw_reader)

    def changed_catalog(url):
        if url == module._method_catalog_url(candidate["source"]["revision"]):
            return catalog
        return candidate

    tampered = copy.deepcopy(candidate)
    tampered["qualification"]["method_verdicts"][methods[-1]] = "already_approved"
    seal(tampered)
    tampered_binding = module.handoff_source_evidence(tampered, locator())
    with pytest.raises(module.PromotionError, match="bytes differ"):
        module.verify_handoff_source(tampered, tampered_binding, reader=reader, raw_reader=changed_catalog)


def test_handoff_source_verification_rejects_catalog_omission_and_nonancestor():
    module = helper()
    catalog = catalog_fixture()
    candidate = receipt([row["method"] for row in catalog["methods"]],
                        revision=catalog["source_revision"])
    binding = module.handoff_source_evidence(candidate, locator())
    main_sha = "e" * 40

    def reader(url):
        if url.endswith("/commits/main"):
            return {"sha": main_sha}
        base = url.rsplit("/compare/", 1)[1].split("...", 1)[0]
        return {"status": "diverged", "base_commit": {"sha": base},
                "merge_base_commit": {"sha": "f" * 40}}

    with pytest.raises(module.PromotionError, match="not an ancestor"):
        module.verify_handoff_source(candidate, binding, reader=reader,
                                     raw_reader=lambda _url: pytest.fail("read after ancestry rejection"))

    def valid_reader(url):
        if url.endswith("/commits/main"):
            return {"sha": main_sha}
        base = url.rsplit("/compare/", 1)[1].split("...", 1)[0]
        return {"status": "ahead", "base_commit": {"sha": base},
                "merge_base_commit": {"sha": base}}

    incomplete = copy.deepcopy(catalog)
    incomplete["methods"].pop()
    def raw_reader(url):
        if url == module._method_catalog_url(candidate["source"]["revision"]):
            return catalog_payload(incomplete)
        return candidate
    with pytest.raises(module.PromotionError, match="source-pinned native method catalog"):
        module.verify_handoff_source(candidate, binding, reader=valid_reader, raw_reader=raw_reader)


def test_publisher_run_artifact_binds_receipt_bytes_to_authenticated_run_content():
    module = helper()
    candidate = receipt()
    archive = receipt_archive(candidate)
    listing = artifact_listing(archive)
    result = module.verify_publisher_artifact(
        candidate, run_id="1003", reader=lambda _url: listing,
        bytes_reader=lambda url: archive,
    )
    assert result["run_id"] == "1003"
    assert result["digest"] == listing["artifacts"][0]["digest"]
    assert result["content_sha256"] == hashlib.sha256(
        json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


@pytest.mark.parametrize("alter", [
    lambda listing: listing.update(total_count=0),
    lambda listing: listing["artifacts"].clear(),
    lambda listing: listing["artifacts"][0].update(name="other-artifact"),
    lambda listing: listing["artifacts"][0].update(expired=True),
    lambda listing: listing["artifacts"][0].update(digest="sha256:" + "0" * 64),
    lambda listing: listing["artifacts"][0].update(archive_download_url="https://evil.invalid/archive.zip"),
])
def test_publisher_artifact_refuses_missing_ambiguous_expired_or_untrusted_metadata(alter):
    module = helper()
    candidate = receipt()
    archive = receipt_archive(candidate)
    listing = artifact_listing(archive)
    alter(listing)
    with pytest.raises(module.PromotionError):
        module.verify_publisher_artifact(candidate, run_id="1003",
                                         reader=lambda _url: listing,
                                         bytes_reader=lambda _url: archive)


@pytest.mark.parametrize("field,value", [
    ("id", 1004),
    ("head_branch", "pull/1/merge"),
    ("head_sha", "f" * 40),
    ("repository_id", 7),
])
def test_publisher_artifact_must_be_attached_to_exact_main_source_run(field, value):
    module = helper()
    candidate = receipt()
    archive = receipt_archive(candidate)
    listing = artifact_listing(archive)
    key = "id" if field == "id" else field
    target = listing["artifacts"][0]["workflow_run"] if field != "id" else listing["artifacts"][0]
    target[key] = value
    with pytest.raises(module.PromotionError, match="artifact identity"):
        module.verify_publisher_artifact(candidate, run_id="1003",
                                         reader=lambda _url: listing,
                                         bytes_reader=lambda _url: archive)


def test_publisher_artifact_refuses_digest_mismatch_and_false_rechecksummed_receipt():
    module = helper()
    candidate = receipt()
    archive = receipt_archive(candidate)
    with pytest.raises(module.PromotionError, match="archive digest"):
        module.verify_publisher_artifact(
            candidate, run_id="1003", reader=lambda _url: artifact_listing(archive),
            bytes_reader=lambda _url: archive + b"tampered",
        )

    false_receipt = copy.deepcopy(candidate)
    false_receipt["qualification"]["method_verdicts"]["codex.start_turn"] = "already_approved"
    seal(false_receipt)
    false_archive = receipt_archive(false_receipt)
    with pytest.raises(module.PromotionError, match="differs from the pinned main receipt"):
        module.verify_publisher_artifact(
            candidate, run_id="1003", reader=lambda _url: artifact_listing(false_archive),
            bytes_reader=lambda _url: false_archive,
        )


def test_publisher_artifact_rejects_duplicate_json_keys_even_when_last_value_matches():
    module = helper()
    candidate = receipt()
    serialized = json.dumps(candidate, sort_keys=True, separators=(",", ":"))
    contents = (serialized[:-1] + ',"schema_version":1}').encode()
    archive = receipt_archive(candidate, contents=contents)
    with pytest.raises(module.PromotionError, match="invalid JSON"):
        module.verify_publisher_artifact(
            candidate, run_id="1003", reader=lambda _url: artifact_listing(archive),
            bytes_reader=lambda _url: archive,
        )
