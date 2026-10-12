"""Verify live CAS pins; historical rollbacks must use their recorded proof.

Rechecking an old pin against the moving ``sha-<revision>`` tag would reject a
legitimate rollback if the publisher later republished that tag.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REPOSITORY = "ghcr.io/joshyorko/codex-action-server"
GITHUB_REPOSITORY = "joshyorko/codex-action-server"
GITHUB_API = "https://api.github.com"
REGISTRY = "https://ghcr.io"
TIMEOUT_SECONDS = 10
MANIFEST_ACCEPT = ", ".join((
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
))


class ProvenanceError(ValueError):
    """A sanitized provenance refusal without upstream response details."""


def _json_get(url: str, headers: dict[str, str]) -> dict:
    request = Request(url, headers=headers, method="GET")
    try:
        with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read(2 * 1024 * 1024 + 1)
            if len(body) > 2 * 1024 * 1024:
                raise ProvenanceError("publisher provenance response is too large")
            value = json.loads(body)
    except ProvenanceError:
        raise
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
        raise ProvenanceError("publisher provenance request failed") from None
    if not isinstance(value, dict):
        raise ProvenanceError("publisher provenance response is invalid")
    return value


def _publisher_main(revision: str) -> str:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    head = _json_get(f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/commits/main", headers)
    if not isinstance(head.get('sha'), str) or not re.fullmatch(r'[0-9a-f]{40}', head['sha']):
        raise ProvenanceError('publisher main identity is invalid')
    current_main = head['sha']
    url = f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/compare/{revision}...{current_main}"
    result = _json_get(url, headers)
    base = result.get("base_commit")
    merge_base = result.get("merge_base_commit")
    if (result.get("status") not in ("ahead", "identical")
            or not isinstance(base, dict) or base.get("sha") != revision
            or not isinstance(merge_base, dict) or merge_base.get("sha") != revision
            ):
        raise ProvenanceError("CAS source revision is not an ancestor of publisher main")
    return current_main


def _publisher_digest(revision: str) -> str:
    token_result = _json_get(
        f"{REGISTRY}/token?service=ghcr.io&scope=repository:joshyorko/codex-action-server:pull",
        {"Accept": "application/json"},
    )
    token = token_result.get("token") or token_result.get("access_token")
    if not isinstance(token, str) or not token:
        raise ProvenanceError("public publisher registry token was unavailable")

    url = f"{REGISTRY}/v2/joshyorko/codex-action-server/manifests/sha-{revision}"
    request = Request(url, headers={"Authorization": "Bearer " + token, "Accept": MANIFEST_ACCEPT}, method="GET")
    try:
        with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read(8 * 1024 * 1024 + 1)
            declared = response.headers.get("Docker-Content-Digest")
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise ProvenanceError("publisher image tag could not be resolved") from None
    if len(body) > 8 * 1024 * 1024:
        raise ProvenanceError("publisher image manifest is too large")
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    if declared is not None and declared != digest:
        raise ProvenanceError("publisher image manifest digest is inconsistent")
    try:
        document = json.loads(body)
    except (UnicodeDecodeError, ValueError):
        raise ProvenanceError("publisher image manifest is invalid") from None
    if not isinstance(document, dict) or document.get("schemaVersion") != 2:
        raise ProvenanceError("publisher image manifest is invalid")
    return digest


def verify(manifest: dict) -> dict[str, dict[str, str]]:
    """Return immutable proof for CAS and schema proxy pins, making GETs only."""
    images = manifest.get("images") if isinstance(manifest, dict) else None
    if not isinstance(images, dict):
        raise ProvenanceError("deployment image manifest is invalid")

    pins: dict[tuple[str, str], str] = {}
    for name in ("cas", "schema_proxy"):
        image = images.get(name)
        if not isinstance(image, dict) or image.get("repository") != REPOSITORY:
            raise ProvenanceError("CAS publisher repository is not approved")
        revision = image.get("revision")
        digest = image.get("digest")
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ProvenanceError("CAS source revision is invalid")
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ProvenanceError("CAS image digest is invalid")
        key = (REPOSITORY, revision)
        previous = pins.setdefault(key, digest)
        if previous != digest:
            raise ProvenanceError("identical CAS revisions have conflicting image digests")

    checked: dict[tuple[str, str], tuple[str, str]] = {}
    for repository, revision in pins:
        current_main = _publisher_main(revision)
        publisher_digest = _publisher_digest(revision)
        if publisher_digest != pins[(repository, revision)]:
            raise ProvenanceError("configured CAS digest does not match the publisher tag")
        checked[(repository, revision)] = (publisher_digest, current_main)

    proof = {}
    for name in ("cas", "schema_proxy"):
        image = images[name]
        digest, current_main = checked[(REPOSITORY, image["revision"])]
        proof[name] = {
            "repository": REPOSITORY,
            "revision": image["revision"],
            "digest": digest,
            "publisher_tag": "sha-" + image["revision"],
            "current_main": current_main,
        }
    return proof
