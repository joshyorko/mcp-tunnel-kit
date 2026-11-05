#!/usr/bin/env python3
"""Generate the review files for one verified CAS image-promotion PR."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile

import cas_promotion


ROOT = Path(__file__).resolve().parents[1]


def propose(current: dict, handoff: dict, *, verifier=None, run_verifier=None,
            candidate_verifier=None, handoff_locator: dict | None = None,
            source_verifier=None) -> dict | None:
    """Return paired manifest/evidence, or None when the pin is already current."""
    if handoff_locator is None:
        raise cas_promotion.PromotionError("Immutable CAS handoff locator is unavailable")
    source_verifier = source_verifier or cas_promotion.verify_handoff_source
    source_verifier(handoff, cas_promotion.handoff_source_evidence(handoff, handoff_locator))
    kwargs = {}
    if verifier is not None:
        kwargs["verifier"] = verifier
    if run_verifier is not None:
        kwargs["run_verifier"] = run_verifier
    if candidate_verifier is not None:
        kwargs["candidate_verifier"] = candidate_verifier
    promoted, proof = cas_promotion.promote_manifest(current, handoff, **kwargs)
    if (promoted["images"]["cas"] == current["images"]["cas"]
            and promoted["images"]["schema_proxy"] == current["images"]["schema_proxy"]):
        return None
    evidence = cas_promotion.build_evidence(current, promoted, handoff, proof, handoff_locator)
    return {"manifest": promoted, "evidence": evidence}


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("CAS promotion output path is unsafe")
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    descriptor, temporary = tempfile.mkstemp(prefix=".cas-promotion-", dir=path.parent)
    temp_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)


def run(repo: Path = ROOT) -> dict:
    manifest_path = repo / "config/deploy-images.json"
    evidence_path = repo / "config/cas-promotion.json"
    try:
        current = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise cas_promotion.PromotionError("Current deployment image manifest is unavailable") from None
    fetched = cas_promotion.fetch_handoff()
    if fetched is None:
        return {"status": "no-qualified-release", "changed": False}
    handoff, handoff_locator = fetched
    candidate = propose(current, handoff, handoff_locator=handoff_locator)
    if candidate is None:
        return {"status": "already-current", "changed": False}
    _atomic_json(manifest_path, candidate["manifest"])
    _atomic_json(evidence_path, candidate["evidence"])
    return {"status": "candidate", "changed": True,
            "source_revision": candidate["manifest"]["images"]["cas"]["revision"],
            "image_digest": candidate["manifest"]["images"]["cas"]["digest"],
            "qualification_run_url": candidate["evidence"]["qualification"]["run_url"],
            "publisher_run_url": candidate["evidence"]["publisher"]["run_url"]}


def main() -> int:
    try:
        print(json.dumps(run(), sort_keys=True))
    except cas_promotion.PromotionError as error:
        # The workflow only publishes a PR after this succeeds. Never print
        # upstream response bodies or credential-bearing exception details.
        print(json.dumps({"status": "blocked", "reason": str(error)}, sort_keys=True))
        return 1
    except (OSError, ValueError):
        print(json.dumps({"status": "blocked", "reason": "candidate generation or safe write failed"}, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
