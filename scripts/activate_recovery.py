#!/usr/bin/env python3
"""Plan or activate a preserved control-plane generation on an empty VM."""

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile

import deploy_control_plane as deploy


SHA256 = re.compile(r"[a-f0-9]{64}\Z")
SOURCE_SHA = re.compile(r"[a-f0-9]{40}\Z")


def _arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-config", required=True, help="Owned mode-0600 local Kamal SSH configuration")
    parser.add_argument("--instance-profile", required=True, help="Owned mode-0600 private instance profile")
    parser.add_argument("--generation-dir", required=True, help="Absolute prepared-generation directory on the VM")
    parser.add_argument("--original-stopped", action="store_true", help="Attest that the original VM is stopped")
    parser.add_argument("--approve-activation", action="store_true", help="Approve writes and service activation on the replacement VM")
    return parser.parse_args(argv)


def _configure(args):
    generation_dir = Path(args.generation_dir)
    if not generation_dir.is_absolute():
        raise ValueError("Generation directory must be an absolute VM path")
    deploy.configure_local(args.local_config, args.instance_profile)
    deploy.trusted_context(os.environ, local=True)
    return str(generation_dir)


def _validated_plan(value):
    if not isinstance(value, dict) or value.get("ready") is not True:
        raise ValueError("Replacement VM did not pass the read-only activation preflight")
    generation = value.get("generation")
    if not isinstance(generation, dict) or set(generation) != {
        "authority", "identity", "manifest", "publication_proof", "source_sha"
    }:
        raise ValueError("Prepared generation record is invalid")
    if generation["authority"] != "kamal" or not isinstance(generation["identity"], str) or not generation["identity"]:
        raise ValueError("Only a preserved Kamal generation with an exact identity can be activated")
    if not isinstance(generation["source_sha"], str) or not SOURCE_SHA.fullmatch(generation["source_sha"]):
        raise ValueError("Prepared generation source revision is invalid")
    deploy.validate_manifest(generation["manifest"])
    if value.get("expected_identity") != generation["identity"]:
        raise ValueError("Prepared generation identity does not match its receipt")
    if not isinstance(value.get("prepared_manifest_sha256"), str) or not SHA256.fullmatch(value["prepared_manifest_sha256"]):
        raise ValueError("Prepared generation integrity digest is invalid")
    if type(value.get("inventory_count")) is not int or value["inventory_count"] < 1:
        raise ValueError("Prepared generation inventory is empty")
    if value.get("repo_source_sha") != generation["source_sha"]:
        raise ValueError("Replacement repository does not match the captured source revision")
    proof = deploy.prove_images(generation["manifest"], generation)
    return generation, proof, value


def plan(args):
    generation_dir = _configure(args)
    response = deploy.remote("activation-plan", {"generation_dir": generation_dir})
    generation, proof, value = _validated_plan(response)
    return {
        "mode": "PLAN",
        "target_ready": True,
        "source_sha": generation["source_sha"],
        "generation_files": value["inventory_count"],
        "image_provenance": "PASS",
        "image_proof_count": len(proof),
        "original_stopped_attestation_required": True,
        "approve_activation_required": True,
    }, generation, value


def activate(args, generation, prepared):
    generation_dir = str(Path(args.generation_dir))
    manifest = generation["manifest"]
    expected = generation["identity"]
    digest = prepared["prepared_manifest_sha256"]
    phase = "locked-preflight"
    boot_attempted = False
    attempted_services = []
    activation_id = secrets.token_hex(16)
    with tempfile.TemporaryDirectory(prefix="mcp-recovery-activation-") as scratch:
        config = deploy.configuration(scratch, manifest)
        try:
            with deploy.lock():
                locked = deploy.remote("activation-preflight", {"generation_dir": generation_dir})
                if (locked.get("ready") is not True
                        or locked.get("expected_identity") != expected
                        or locked.get("prepared_manifest_sha256") != digest):
                    raise ValueError("Prepared generation or replacement VM changed after PLAN")

                phase = "activation-intent"
                deploy.remote("activation-begin", {
                    "generation_dir": generation_dir,
                    "prepared_manifest_sha256": digest,
                    "expected_identity": expected,
                    "activation_id": activation_id,
                    "original_stopped_attested": True,
                })
                phase = "pinned-image-pull"
                deploy.remote("activation-pull-images", {"manifest": manifest, "activation_id": activation_id})
                phase = "recovered-files-install"
                deploy.remote("activation-install", {
                    "generation_dir": generation_dir,
                    "prepared_manifest_sha256": digest,
                    "activation_id": activation_id,
                })
                phase = "executor-volume-seed"
                deploy.remote("activation-seed", {
                    "generation_dir": generation_dir,
                    "prepared_manifest_sha256": digest,
                    "manifest": manifest,
                    "activation_id": activation_id,
                })
                phase = "private-network"
                deploy.remote("activation-network", {"activation_id": activation_id})
                phase = "recovered-profile-validation"
                deploy.remote("profile")

                for name in deploy.ORDER[:-1]:
                    phase = "boot-" + name
                    boot_attempted = True
                    attempted_services.append(name)
                    deploy.kamal(config, "boot", name)
                    deploy.remote("activation-track", {"activation_id": activation_id, "service": name})
                    deploy.remote("wait", {"owner": "kamal", "service": name})

                phase = "devsy-start"
                deploy.remote("devsy-start")
                phase = "native-and-devsy-smoke"
                deploy.remote("smoke", {"activation_id": activation_id})
                phase = "preserved-identity-check"
                identity = deploy.remote("activation-identity", {"expected_identity": expected,"activation_id":activation_id})
                if identity.get("identity_preserved") is not True:
                    raise ValueError("Recovered Executor identity check failed")

                phase = "boot-tunnel-last"
                boot_attempted = True
                attempted_services.append("tunnel")
                deploy.kamal(config, "boot", "tunnel")
                deploy.remote("activation-track", {"activation_id": activation_id, "service": "tunnel"})
                deploy.remote("wait", {"owner": "kamal", "service": "tunnel"})
                phase = "final-acceptance"
                after = deploy.remote("snapshot")
                if (after.get("authority") != "kamal" or after.get("identity") != expected
                        or after.get("tunnel_count") != 1):
                    raise ValueError("Replacement VM did not reach the captured identity and single-tunnel state")
                smoke = deploy.remote("smoke", {"activation_id": activation_id})
                if (smoke.get("memoryd_discovery") not in ("PASS", "UNREGISTERED", "UNAVAILABLE")
                        or smoke.get("memoryd_restored") is not False):
                    raise ValueError("Recovery smoke did not report MemoryD status")
                receipt = deploy.remote("activation-record", {
                    "activation_id": activation_id,
                    "source_sha": generation["source_sha"],
                    "expected_identity": expected,
                    "identity_preserved": True,
                    "original_stopped_attested": True,
                })
                if (receipt.get("memoryd_discovery") != smoke["memoryd_discovery"]
                        or receipt.get("memoryd_restored") is not False):
                    raise ValueError("Recovery receipt did not match MemoryD smoke status")
                return {
                    "mode": "ACTIVATED",
                    "authority": "kamal",
                    "identity_preserved": True,
                    "single_tunnel": True,
                    "source_sha": generation["source_sha"],
                    "memoryd_discovery": smoke["memoryd_discovery"],
                    "memoryd_restored": False,
                }
        except Exception:
            if boot_attempted:
                try:
                    deploy.remote("activation-cleanup", {
                        "activation_id": activation_id,
                        "attempted_services": attempted_services,
                    })
                except Exception:
                    raise RuntimeError("Activation failed at " + phase + "; accessory cleanup needs operator recovery; restored data and volume were retained") from None
            raise RuntimeError("Activation failed at " + phase + "; restored data and any created Executor volume were retained; no Compose fallback was started") from None


def execute(args):
    if args.original_stopped != args.approve_activation:
        raise ValueError("Activation requires both --original-stopped and --approve-activation; omit both for read-only PLAN")
    summary, generation, prepared = plan(args)
    if not args.original_stopped:
        return summary
    return activate(args, generation, prepared)


def main(argv=None):
    try:
        print(json.dumps(execute(_arguments(argv)), indent=2))
        return 0
    except Exception as error:
        if isinstance(error, (ValueError, RuntimeError)):
            detail = str(error)
        else:
            detail = type(error).__name__
        print(detail, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
