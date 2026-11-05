import importlib.util
import hashlib
import json
import os
from pathlib import Path
from urllib.error import URLError
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "image_provenance_test", ROOT / "scripts/image_provenance.py"
)
provenance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(provenance)


class Response:
    def __init__(self, body, headers=None):
        self.body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit=-1):
        return self.body


def fixture(manifest=None, compare=None, revision_label=None):
    data = json.loads((ROOT / "config/deploy-images.json").read_text())
    calls = []
    revision=data["images"]["cas"]["revision"]
    config_body=json.dumps({"architecture":"amd64","os":"linux","config":{"Labels":{
        "org.opencontainers.image.revision":revision_label or revision}}}).encode()
    config_digest="sha256:"+hashlib.sha256(config_body).hexdigest()
    platform_body=json.dumps({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
                              "config":{"digest":config_digest}}).encode()
    platform_digest="sha256:"+hashlib.sha256(platform_body).hexdigest()
    top=manifest or {"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json",
                     "manifests":[{"digest":platform_digest,
                                   "platform":{"os":"linux","architecture":"amd64"}}]}
    if isinstance(top.get("manifests"),list) and top["manifests"]:
        for row in top["manifests"]:
            if row.get("platform",{}).get("os")=="linux" and row.get("platform",{}).get("architecture")=="amd64":
                row["digest"]=platform_digest
    manifest_body = json.dumps(top).encode()
    manifest_digest = "sha256:" + hashlib.sha256(manifest_body).hexdigest()
    for name in ("cas", "schema_proxy"):
        data["images"][name]["digest"] = manifest_digest

    def open_url(request, timeout):
        calls.append((request, timeout))
        url = request.full_url
        if url.endswith('/commits/main'):
            return Response({'sha': 'f' * 40})
        if "/compare/" in url:
            value = compare or {
                "status": "ahead",
                "base_commit": {"sha": "54278b1ecc3c67d46ebdb25148971814243f51a6"},
                "merge_base_commit": {"sha": "54278b1ecc3c67d46ebdb25148971814243f51a6"},
            }
            return Response(value)
        if url.startswith("https://ghcr.io/token?"):
            return Response({"token": "registry-fixture-token"})
        if "/manifests/sha-" in url:
            return Response(manifest_body, {"Docker-Content-Digest": manifest_digest})
        if url.endswith("/manifests/"+platform_digest):
            return Response(platform_body)
        if url.endswith("/blobs/"+config_digest):
            return Response(config_body)
        raise AssertionError("Unexpected provenance URL")

    return data, calls, open_url, manifest_digest


class ImageProvenanceTests(unittest.TestCase):
    def test_verify_proves_trusted_ancestor_and_publisher_tag_once_for_duplicate_pins(self):
        manifest, calls, open_url, digest = fixture()
        with patch.object(provenance, "urlopen", side_effect=open_url), \
                patch.dict(os.environ, {}, clear=True):
            proof = provenance.verify(manifest)

        self.assertEqual(len(calls), 4)  # main identity, compare, token, manifest
        self.assertTrue(all(timeout <= 10 for _, timeout in calls))
        expected = {
            "repository": "ghcr.io/joshyorko/codex-action-server",
            "revision": "54278b1ecc3c67d46ebdb25148971814243f51a6",
            "digest": digest,
            "publisher_tag": "sha-54278b1ecc3c67d46ebdb25148971814243f51a6",
            "current_main": "f" * 40,
        }
        self.assertEqual(proof["cas"], expected)
        self.assertEqual(proof["schema_proxy"], expected)
        self.assertEqual(set(proof["cas"]), set(expected))

    def test_promotion_verifies_linux_amd64_in_the_published_oci_index(self):
        manifest, calls, open_url, digest = fixture({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [{"digest": "sha256:" + "1" * 64,
                           "platform": {"os": "linux", "architecture": "amd64"}}],
        })
        with patch.object(provenance, "urlopen", side_effect=open_url), \
                patch.dict(os.environ, {}, clear=True):
            proof = provenance.verify(manifest, required_platform="linux/amd64",
                                      required_revision=manifest["images"]["cas"]["revision"])
        self.assertEqual(proof["cas"]["digest"], digest)
        self.assertEqual(proof["cas"]["platform"], "linux/amd64")
        self.assertEqual(len(calls), 6)

    def test_promotion_rejects_oci_revision_label_that_differs_from_handoff(self):
        manifest, _calls, open_url, _digest = fixture()
        with patch.object(provenance, "urlopen", side_effect=open_url), \
                patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(provenance.ProvenanceError, "revision label"):
                provenance.verify(manifest, required_platform="linux/amd64",
                                  required_revision="f" * 40)

    def test_promotion_rejects_published_image_without_amd64_descriptor(self):
        manifest, _calls, open_url, _digest = fixture({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [{"digest": "sha256:" + "1" * 64,
                           "platform": {"os": "linux", "architecture": "arm64"}}],
        })
        with patch.object(provenance, "urlopen", side_effect=open_url), \
                patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(provenance.ProvenanceError, "linux/amd64"):
                provenance.verify(manifest, required_platform="linux/amd64")

    def test_verify_rejects_digest_that_does_not_match_publisher_tag(self):
        manifest, _calls, open_url, _digest = fixture()
        manifest["images"]["cas"]["digest"] = "sha256:" + "1" * 64
        manifest["images"]["schema_proxy"]["digest"] = "sha256:" + "1" * 64
        with patch.object(provenance, "urlopen", side_effect=open_url), \
                patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(provenance.ProvenanceError, "does not match"):
                provenance.verify(manifest)

    def test_verify_rejects_revision_that_is_not_on_trusted_publisher_main(self):
        manifest, calls, open_url, _digest = fixture(compare={
            "status": "diverged",
            "base_commit": {"sha": "54278b1ecc3c67d46ebdb25148971814243f51a6"},
            "merge_base_commit": {"sha": "1" * 40},
            "head_commit": {"sha": "f" * 40},
        })
        with patch.object(provenance, "urlopen", side_effect=open_url), \
                patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(provenance.ProvenanceError, "not an ancestor"):
                provenance.verify(manifest)
        self.assertEqual(len(calls), 2)

    def test_verify_rejects_other_repositories_before_network_access(self):
        manifest, calls, open_url, _digest = fixture()
        manifest["images"]["schema_proxy"]["repository"] = "attacker.invalid/image"
        with patch.object(provenance, "urlopen", side_effect=open_url):
            with self.assertRaisesRegex(provenance.ProvenanceError, "repository is not approved"):
                provenance.verify(manifest)
        self.assertEqual(calls, [])

    def test_optional_github_token_is_used_in_memory_and_never_in_errors(self):
        manifest, calls, open_url, _digest = fixture()
        with patch.object(provenance, "urlopen", side_effect=open_url), \
                patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_fixture_secret"}):
            provenance.verify(manifest)
        compare_request = calls[0][0]
        self.assertEqual(compare_request.get_header("Authorization"), "Bearer ghp_fixture_secret")

        def failed_request(_request, timeout):
            raise URLError("ghp_fixture_secret upstream details")

        with patch.object(provenance, "urlopen", side_effect=failed_request), \
                patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_fixture_secret"}):
            with self.assertRaises(provenance.ProvenanceError) as raised:
                provenance.verify(manifest)
        self.assertNotIn("ghp_fixture_secret", str(raised.exception))

    def test_registry_failures_are_sanitized_and_manifest_header_is_verified(self):
        manifest, _calls, open_url, _digest = fixture()

        def failed_registry(request, timeout):
            if "/compare/" in request.full_url or request.full_url.endswith('/commits/main'):
                return open_url(request, timeout)
            if request.full_url.startswith("https://ghcr.io/token?"):
                return Response({"token": "registry-fixture-secret"})
            raise URLError("registry-fixture-secret upstream response")

        with patch.object(provenance, "urlopen", side_effect=failed_registry), \
                patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(provenance.ProvenanceError) as raised:
                provenance.verify(manifest)
        self.assertNotIn("registry-fixture-secret", str(raised.exception))

        manifest, _calls, open_url, _digest = fixture()

        def wrong_header(request, timeout):
            response = open_url(request, timeout)
            if "/manifests/sha-" in request.full_url:
                response.headers["Docker-Content-Digest"] = "sha256:" + "0" * 64
            return response

        with patch.object(provenance, "urlopen", side_effect=wrong_header), \
                patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(provenance.ProvenanceError, "inconsistent"):
                provenance.verify(manifest)
