"""Validate the qualified CAS handoff used by the promotion PR lane.

The CAS repository owns native Codex protocol qualification.  This module only
accepts a versioned handoff from that repository, independently verifies the
published image through :mod:`image_provenance`, and updates the protected
production manifest as one CAS/schema-proxy pair.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from image_provenance import verify as verify_image_provenance
from kamal_model import validate_manifest


CAS_REPOSITORY = "joshyorko/codex-action-server"
CAS_IMAGE_REPOSITORY = "ghcr.io/joshyorko/codex-action-server"
HANDOFF_URL = (
    "https://raw.githubusercontent.com/joshyorko/codex-action-server/main/"
    "ci/codex_qualification/qualified-release.json"
)
HANDOFF_MAX_BYTES = 512 * 1024
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
METHOD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.]{0,127}\Z")
RUN_URL_RE = re.compile(
    r"https://github\.com/joshyorko/codex-action-server/actions/runs/[1-9][0-9]*\Z"
)
COMMIT_URL_RE = re.compile(
    r"https://github\.com/joshyorko/codex-action-server/commit/[0-9a-f]{40}\Z"
)
COMPARE_URL_RE = re.compile(
    r"https://github\.com/joshyorko/codex-action-server/compare/[A-Za-z0-9._/-]+\Z"
)
METHOD_VERDICTS = {"qualified", "already_approved"}


class PromotionError(ValueError):
    """A sanitized fail-closed CAS promotion refusal."""


def fetch_handoff(url: str = HANDOFF_URL) -> dict | None:
    """Fetch the public immutable handoff location without sending credentials."""
    if url != HANDOFF_URL:
        raise PromotionError("CAS handoff URL is not the approved source")
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "mcp-tunnel-kit-cas-promotion"})
    try:
        with urlopen(request, timeout=15) as response:
            raw = response.read(HANDOFF_MAX_BYTES + 1)
    except HTTPError as exc:
        if exc.code == 404:
            return None
        raise PromotionError("CAS qualification handoff could not be read") from None
    except (URLError, TimeoutError, OSError):
        raise PromotionError("CAS qualification handoff is unavailable") from None
    if len(raw) > HANDOFF_MAX_BYTES:
        raise PromotionError("CAS qualification handoff is too large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, ValueError):
        raise PromotionError("CAS qualification handoff is invalid JSON") from None
    if not isinstance(value, dict):
        raise PromotionError("CAS qualification handoff is invalid")
    return value


def _required_text(value, pattern, error):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise PromotionError(error)
    return value


def validate_handoff(value: dict) -> dict:
    """Validate the agreed v1 producer contract before making a candidate pin.

    The source SHA and publication fields are rechecked by the publisher
    provenance verifier.  This structure makes qualification completeness and
    CI evidence explicit and rejects partial method matrices.
    """
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "source", "qualification", "publication", "receipt_sha256",
    } or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise PromotionError("Unsupported CAS qualification handoff schema")
    unsigned = dict(value)
    receipt_digest = unsigned.pop("receipt_sha256", None)
    expected_digest = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if (not isinstance(receipt_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", receipt_digest)
            or receipt_digest != expected_digest):
        raise PromotionError("CAS qualification handoff checksum is invalid")

    source = value["source"]
    if (not isinstance(source, dict) or set(source) != {"repository", "revision", "merged", "commit_url"}
            or source.get("repository") != CAS_REPOSITORY or source.get("merged") is not True):
        raise PromotionError("CAS source is not a merged trusted-main revision")
    revision = _required_text(source.get("revision"), SHA_RE, "CAS source revision is invalid")
    if source.get("commit_url") != f"https://github.com/{CAS_REPOSITORY}/commit/{revision}":
        raise PromotionError("CAS source commit URL does not match its revision")

    qualification = value["qualification"]
    if (not isinstance(qualification, dict) or set(qualification) != {
        "status", "run_url", "required_ci_url", "comparison_url", "surface", "method_verdicts",
        "behavior_coverage", "withheld_methods",
    } or qualification.get("status") != "qualified"):
        raise PromotionError("CAS qualification evidence is missing or not qualified")
    for field in ("run_url", "required_ci_url"):
        _required_text(qualification.get(field), RUN_URL_RE, "CAS qualification or CI run URL is invalid")
    _required_text(qualification.get("comparison_url"), COMPARE_URL_RE,
                   "CAS qualification comparison URL is invalid")
    surface = qualification.get("surface")
    if (not isinstance(surface, dict) or set(surface) != {"complete", "sha256", "methods"}
            or surface.get("complete") is not True
            or not isinstance(surface.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", surface["sha256"])
            or not isinstance(surface.get("methods"), list) or not surface["methods"]):
        raise PromotionError("CAS consumed-method surface is incomplete")
    consumed = []
    for row in surface["methods"]:
        if not isinstance(row, dict) or set(row) != {"name", "owner"}:
            raise PromotionError("CAS consumed-method surface entry is invalid")
        name = _required_text(row.get("name"), METHOD_RE, "CAS consumed-method surface entry is invalid")
        owner = row.get("owner")
        if owner not in {"typed_action", "shared_helper"} or name in consumed:
            raise PromotionError("CAS consumed-method surface is ambiguous")
        consumed.append(name)

    verdicts = qualification.get("method_verdicts")
    coverage = qualification.get("behavior_coverage")
    if not isinstance(verdicts, dict) or set(verdicts) != set(consumed):
        raise PromotionError("CAS method qualification matrix does not cover the complete consumed surface")
    if not isinstance(coverage, dict) or set(coverage) != set(consumed):
        raise PromotionError("CAS behavior evidence does not cover the complete consumed surface")
    for method in consumed:
        if verdicts[method] not in METHOD_VERDICTS:
            raise PromotionError("CAS method remains unqualified: " + method)
        behavior = coverage[method]
        if (not isinstance(behavior, dict) or set(behavior) != {"result", "strategy"}
                or behavior.get("result") != "passed"
                or behavior.get("strategy") not in {"native_read_smoke", "isolated_fixture"}):
            raise PromotionError("CAS method behavior evidence is incomplete: " + method)
    surface_payload=sorted(
        ({"name":row["name"],"owner":row["owner"]} for row in surface["methods"]),
        key=lambda row:row["name"])
    expected_surface_sha256=hashlib.sha256(
        json.dumps(surface_payload,sort_keys=True,separators=(",",":")).encode()
    ).hexdigest()
    if surface["sha256"]!=expected_surface_sha256:
        raise PromotionError("CAS consumed-method surface checksum is invalid")
    withheld = qualification.get("withheld_methods")
    if not isinstance(withheld, list) or withheld:
        raise PromotionError("CAS release has withheld or unqualified native methods")

    publication = value["publication"]
    if (not isinstance(publication, dict) or set(publication) != {
        "status", "run_url", "image_repository", "image_tag", "digest", "revision", "platform",
    } or publication.get("status") != "published"):
        raise PromotionError("CAS publisher evidence is missing or incomplete")
    _required_text(publication.get("run_url"), RUN_URL_RE, "CAS publisher run URL is invalid")
    if publication.get("image_repository") != CAS_IMAGE_REPOSITORY:
        raise PromotionError("CAS publisher repository is not approved")
    if publication.get("revision") != revision or publication.get("image_tag") != "sha-" + revision:
        raise PromotionError("CAS publisher image tag or OCI revision does not match the merged source")
    _required_text(publication.get("digest"), DIGEST_RE, "CAS publisher image digest is invalid")
    if publication.get("platform") != "linux/amd64":
        raise PromotionError("CAS publisher image does not declare linux/amd64")

    return copy.deepcopy(value)


def verify_publisher(handoff: dict, *, verifier=verify_image_provenance) -> dict:
    """Independently resolve the publisher tag/digest and trusted main ancestry."""
    receipt = validate_handoff(handoff)
    image = receipt["publication"]
    cas_pin = {"repository": image["image_repository"], "digest": image["digest"],
               "revision": image["revision"]}
    manifest = {"version": 1, "images": {
        "cas": cas_pin,
        "schema_proxy": copy.deepcopy(cas_pin),
        "executor": {"repository": "ghcr.io/usefulsoftwareco/executor-selfhost:2.0.0-beta.12",
                     "digest": "sha256:" + "0" * 64},
        "tunnel": {"repository": "ghcr.io/openai/tunnel-client:v0.0.15",
                   "digest": "sha256:" + "0" * 64},
    }}
    try:
        return verifier(manifest, required_platform="linux/amd64",
                        required_revision=image["revision"])
    except (ValueError, OSError):
        raise PromotionError("CAS publisher verification failed") from None


def _github_json(url: str) -> dict:
    """Read bounded public GitHub Actions evidence without a credential."""
    request = Request(url, headers={"Accept": "application/vnd.github+json",
                                    "X-GitHub-Api-Version": "2022-11-28",
                                    "User-Agent": "mcp-tunnel-kit-cas-promotion"}, method="GET")
    try:
        with urlopen(request, timeout=15) as response:
            raw = response.read(1024 * 1024 + 1)
    except (HTTPError, URLError, TimeoutError, OSError):
        raise PromotionError("CAS workflow evidence could not be verified") from None
    if len(raw) > 1024 * 1024:
        raise PromotionError("CAS workflow evidence response is too large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, ValueError):
        raise PromotionError("CAS workflow evidence response is invalid") from None
    if not isinstance(value, dict):
        raise PromotionError("CAS workflow evidence response is invalid")
    return value


def verify_action_runs(handoff: dict, *, reader=_github_json) -> dict:
    """Confirm the linked qualification, required CI, and publish runs succeeded."""
    receipt = validate_handoff(handoff)
    revision = receipt["source"]["revision"]
    qualification = receipt["qualification"]
    publication = receipt["publication"]
    links = [qualification["run_url"], qualification["required_ci_url"], publication["run_url"]]
    run_ids = [url.rsplit("/", 1)[-1] for url in links]
    if len(set(run_ids)) != 3:
        raise PromotionError("CAS qualification and publication must use three distinct workflow runs")

    results = []
    for url, run_id in zip(links, run_ids):
        info = reader(f"https://api.github.com/repos/{CAS_REPOSITORY}/actions/runs/{run_id}")
        repository = info.get("repository")
        head_repository=info.get("head_repository")
        if (not isinstance(repository, dict) or repository.get("full_name") != CAS_REPOSITORY
                or not isinstance(head_repository,dict) or head_repository.get("full_name")!=CAS_REPOSITORY
                or info.get("head_sha") != revision or info.get("head_branch") != "main"
                or info.get("status") != "completed" or info.get("conclusion") != "success"):
            raise PromotionError("CAS qualification, required CI, or publisher run is not green on merged main")
        results.append({"url": url, "run_id": run_id, "path": info.get("path"),
                        "event": info.get("event"), "conclusion": info.get("conclusion")})

    if results[0]["path"] != ".github/workflows/codex-version-qualification.yml":
        raise PromotionError("CAS qualification run does not use the approved workflow")
    if results[1]["path"] != ".github/workflows/test.yml" or results[1]["event"] != "push":
        raise PromotionError("CAS required CI evidence does not use the main push test workflow")
    if results[2]["path"] != ".github/workflows/container.yml" or results[2]["event"] != "push":
        raise PromotionError("CAS publisher run does not use the trusted main publication workflow")
    approved_paths = {
        ".github/workflows/codex-version-qualification.yml",
        ".github/workflows/container.yml",
        ".github/workflows/test.yml",
    }
    if any(row["path"] not in approved_paths for row in results):
        raise PromotionError("CAS required CI run uses an unapproved workflow")
    return {"qualification": results[0], "required_ci": results[1], "publication": results[2]}


def verify_candidate_is_current_or_newer(current_revision: str, candidate_revision: str,
                                        *, reader=_github_json) -> None:
    """Reject replayed handoffs that would roll the production pin backwards."""
    _required_text(current_revision, SHA_RE, "Current CAS source revision is invalid")
    _required_text(candidate_revision, SHA_RE, "Candidate CAS source revision is invalid")
    if current_revision == candidate_revision:
        return
    url = (f"https://api.github.com/repos/{CAS_REPOSITORY}/compare/"
           f"{current_revision}...{candidate_revision}")
    comparison = reader(url)
    base = comparison.get("base_commit")
    head = comparison.get("merge_base_commit")
    if (comparison.get("status") != "ahead" or not isinstance(base, dict)
            or base.get("sha") != current_revision or not isinstance(head, dict)
            or head.get("sha") != current_revision):
        raise PromotionError("CAS handoff is stale or does not descend from the currently promoted revision")


def promote_manifest(current: dict, handoff: dict, *, verifier=verify_image_provenance,
                     run_verifier=verify_action_runs,
                     candidate_verifier=verify_candidate_is_current_or_newer) -> tuple[dict, dict]:
    """Set both CAS-backed image pins to the same qualified publisher artifact."""
    current_refs = validate_manifest(current)
    receipt = validate_handoff(handoff)
    if current["images"]["cas"] != current["images"]["schema_proxy"]:
        raise PromotionError("Current CAS/schema-proxy rollback generation is not a coherent pair")
    candidate_verifier(current["images"]["cas"]["revision"], receipt["source"]["revision"])
    run_verifier(receipt)
    proof = verify_publisher(receipt, verifier=verifier)
    result = copy.deepcopy(current)
    pin = receipt["publication"]
    paired = {"repository": pin["image_repository"], "digest": pin["digest"],
              "revision": pin["revision"]}
    result["images"]["cas"] = copy.deepcopy(paired)
    result["images"]["schema_proxy"] = copy.deepcopy(paired)
    validate_manifest(result)
    if (current_refs["executor"] != validate_manifest(result)["executor"]
            or current_refs["tunnel"] != validate_manifest(result)["tunnel"]):
        raise PromotionError("CAS promotion changed an unrelated production image")
    return result, proof


def build_evidence(current: dict, promoted: dict, handoff: dict, proof: dict) -> dict:
    """Build the review artifact committed beside the exact promoted manifest."""
    receipt = validate_handoff(handoff)
    prior = current["images"]["cas"]
    target = promoted["images"]["cas"]
    payload = {
        "schema_version": 1,
        "status": "qualified_pending_deploy",
        "source_revision": receipt["source"]["revision"],
        "handoff": receipt,
        "image": {"repository": target["repository"], "digest": target["digest"],
                  "revision": target["revision"], "platform": receipt["publication"]["platform"]},
        "qualification": receipt["qualification"],
        "publisher": {"run_url": receipt["publication"]["run_url"],
                      "tag": receipt["publication"]["image_tag"], "verified_digest": proof["cas"]["digest"],
                      "trusted_ancestor": True},
        "comparison": {"previous_manifest_digest": prior["digest"], "promoted_digest": target["digest"],
                       "schema_proxy_promoted_together": True},
        "rollback": {"manifest_digest": prior["digest"],
                     "source_revision": prior["revision"],
                     "deployment_generation": "resolved from the recorded current generation at deploy time"},
        "unqualified_methods": receipt["qualification"]["withheld_methods"],
    }
    payload["receipt_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return payload


def validate_deployment_evidence(value: dict, manifest: dict) -> dict:
    """Require the merged PR's exact qualification evidence before deploy."""
    expected_fields={"schema_version","status","source_revision","handoff","image",
                     "qualification","publisher","comparison","rollback",
                     "unqualified_methods","receipt_sha256"}
    if (not isinstance(value, dict) or set(value)!=expected_fields
            or type(value.get("schema_version")) is not int or value.get("schema_version") != 1):
        raise PromotionError("CAS promotion evidence is missing or unsupported")
    if value.get("status") != "qualified_pending_deploy":
        raise PromotionError("CAS promotion evidence is not in a deployable state")
    image = value.get("image")
    if (not isinstance(image, dict) or image.get("repository") != CAS_IMAGE_REPOSITORY
            or image.get("digest") != manifest["images"]["cas"]["digest"]
            or image.get("revision") != manifest["images"]["cas"]["revision"]
            or image.get("platform") != "linux/amd64"
            or manifest["images"]["cas"] != manifest["images"]["schema_proxy"]):
        raise PromotionError("CAS promotion evidence does not match the merged CAS/schema-proxy pair")
    comparison=value.get("comparison")
    rollback=value.get("rollback")
    if (not isinstance(comparison,dict)
            or set(comparison)!={"previous_manifest_digest","promoted_digest","schema_proxy_promoted_together"}
            or not isinstance(comparison.get("previous_manifest_digest"),str)
            or not DIGEST_RE.fullmatch(comparison["previous_manifest_digest"])
            or comparison.get("promoted_digest")!=image["digest"]
            or comparison.get("schema_proxy_promoted_together") is not True
            or not isinstance(rollback,dict)
            or set(rollback)!={"manifest_digest","source_revision","deployment_generation"}
            or rollback.get("manifest_digest")!=comparison["previous_manifest_digest"]
            or not isinstance(rollback.get("source_revision"),str)
            or not SHA_RE.fullmatch(rollback["source_revision"])
            or rollback.get("deployment_generation")!="resolved from the recorded current generation at deploy time"):
        raise PromotionError("CAS rollback and paired-image evidence is invalid")
    digest = value.get("receipt_sha256")
    unsigned = dict(value)
    unsigned.pop("receipt_sha256", None)
    expected = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or digest != expected:
        raise PromotionError("CAS promotion evidence integrity check failed")
    # Revalidate the full producer contract; the PR itself is not an authority
    # to convert an unqualified method into a qualified one.
    handoff = validate_handoff(value.get("handoff"))
    if (value.get("source_revision") != handoff["source"]["revision"]
            or value.get("qualification") != handoff["qualification"]
            or value.get("publisher", {}).get("run_url") != handoff["publication"]["run_url"]
            or value.get("publisher", {}).get("tag") != handoff["publication"]["image_tag"]
            or value.get("publisher", {}).get("verified_digest") != image["digest"]):
        raise PromotionError("CAS promotion handoff does not match its reviewed evidence")
    if value.get("publisher",{}).get("trusted_ancestor") is not True:
        raise PromotionError("CAS promotion publisher ancestry is not verified")
    if value.get("unqualified_methods")!=handoff["qualification"]["withheld_methods"]:
        raise PromotionError("CAS promotion omitted its unqualified-method status")
    return copy.deepcopy(value)
