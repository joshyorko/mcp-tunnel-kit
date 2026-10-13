#!/usr/bin/env python3
"""Store and independently verify an age-encrypted control-plane recovery bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import urllib.parse

import control_plane_recovery


class StorageError(RuntimeError):
    """A safe-to-display storage operation failure."""


PROFILE_KEYS = {
    "schema_version",
    "mc_config_dir",
    "minio_alias",
    "bucket",
    "removable_directory",
    "recovery_identity",
    "unlock_identity",
}
CAPTURE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _fail(message: str) -> StorageError:
    return StorageError(message)


def _binary(name: str) -> str:
    for candidate in (Path("/home/linuxbrew/bin") / name,):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    found = shutil.which(name)
    if found:
        return found
    raise _fail(f"Required recovery tool is unavailable: {name}.")


def _run(args, *, output=None) -> bytes:
    try:
        result = subprocess.run(
            list(map(str, args)),
            stdout=output if output is not None else subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=900,
            check=False,
        )
    except Exception:
        raise _fail("Recovery storage or cryptographic operation failed; diagnostic withheld.") from None
    if result.returncode:
        raise _fail("Recovery storage or cryptographic operation failed; diagnostic withheld.")
    return b"" if output is not None else result.stdout


def _owned_regular(path: Path, mode: int | None = None) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError:
        raise _fail("A required private recovery input is unavailable.") from None
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or (mode is not None and stat.S_IMODE(info.st_mode) != mode):
        raise _fail("A required private recovery input has unsafe ownership, type, or permissions.")
    return info


def _private_directory(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError:
        raise _fail("A required private recovery directory is unavailable.") from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise _fail("A required private recovery directory must be operator-owned mode 0700.")
    return info


def _load_profile(profile_path: str | Path, capture_id: str, *, require_identities: bool) -> dict:
    path = Path(profile_path)
    _owned_regular(path, 0o600)
    if not CAPTURE_ID.fullmatch(capture_id) or capture_id in {".", ".."}:
        raise _fail("Capture ID must be one safe path label.")
    try:
        profile = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raise _fail("Storage profile is not valid JSON.") from None
    if not isinstance(profile, dict) or set(profile) - PROFILE_KEYS:
        raise _fail("Storage profile has an unsupported schema.")
    required = PROFILE_KEYS if require_identities else PROFILE_KEYS - {"recovery_identity", "unlock_identity"}
    if not required.issubset(profile) or profile.get("schema_version") != 1:
        raise _fail("Storage profile is missing required schema version 1 fields.")
    text_fields = required - {"schema_version"}
    if any(not isinstance(profile.get(key), str) or not profile[key] for key in text_fields):
        raise _fail("Storage profile fields must be non-empty strings.")
    if "recovery_identity" in profile and not isinstance(profile["recovery_identity"], str):
        raise _fail("Storage profile identity fields must be strings.")
    if "unlock_identity" in profile and not isinstance(profile["unlock_identity"], str):
        raise _fail("Storage profile identity fields must be strings.")
    alias = profile["minio_alias"]
    bucket = profile["bucket"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", alias):
        raise _fail("Storage profile MinIO alias is invalid.")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket) or ".." in bucket:
        raise _fail("Storage profile bucket is invalid.")
    config_dir = Path(profile["mc_config_dir"])
    _private_directory(config_dir)
    try:
        config_files = list(config_dir.iterdir())
    except OSError:
        raise _fail("Private MinIO configuration is unavailable.") from None
    if not config_files:
        raise _fail("Private MinIO configuration is empty.")
    for item in config_files:
        if item.is_dir() and not item.is_symlink():
            # MinIO may keep a private certificate directory; validate files recursively.
            for child in item.rglob("*"):
                if child.is_dir() and not child.is_symlink():
                    continue
                _owned_regular(child, 0o600)
        else:
            _owned_regular(item, 0o600)
    drive_root = Path(profile["removable_directory"])
    try:
        drive_info = drive_root.lstat()
    except OSError:
        raise _fail("Configured removable storage is not mounted or available.") from None
    if not stat.S_ISDIR(drive_info.st_mode) or drive_root.is_symlink():
        raise _fail("Configured removable storage must be an existing directory, not a symlink.")
    if require_identities:
        _owned_regular(Path(profile["recovery_identity"]), 0o600)
        _owned_regular(Path(profile["unlock_identity"]), 0o600)
    return profile


def _mc_base(profile: dict) -> list[str]:
    return [_binary("mc"), "--config-dir", profile["mc_config_dir"]]


def _mc_alias_url(profile: dict) -> str:
    config_path = Path(profile["mc_config_dir"]) / "config.json"
    _owned_regular(config_path, 0o600)
    # Load only the alias endpoint field; never emit credential fields or the config contents.
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
        aliases = data.get("aliases", data.get("hosts", {}))
        metadata = aliases.get(profile["minio_alias"], {})
        url = metadata.get("url")
        parsed = urllib.parse.urlsplit(url) if isinstance(url, str) else None
        if parsed:
            _ = parsed.port
    except Exception:
        parsed = None
    if (
        not parsed
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise _fail("Configured MinIO alias must use a credential-free HTTPS endpoint.")
    return urllib.parse.urlunsplit(("https", parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _check_private_bucket(profile: dict) -> None:
    response = _run(_mc_base(profile) + ["anonymous", "get", f"{profile['minio_alias']}/{profile['bucket']}", "--json"])
    permission = None
    for line in response.splitlines():
        try:
            item = json.loads(line)
            if isinstance(item, dict) and "permission" in item:
                permission = item["permission"]
        except Exception:
            continue
    if permission != "private":
        raise _fail("Recovery bucket is not confirmed private.")


def _remote_prefix(profile: dict, capture_id: str) -> str:
    return f"{profile['minio_alias']}/{profile['bucket']}/{capture_id}"


def _require_empty_prefix(profile: dict, capture_id: str, drive_run: Path) -> None:
    prefix = _remote_prefix(profile, capture_id)
    listing = _run(_mc_base(profile) + ["ls", prefix + "/", "--json"])
    if listing.strip() or drive_run.exists() or drive_run.is_symlink():
        raise _fail("Recovery target already contains data; refusing overwrite.")


def _digest(path: Path) -> str:
    try:
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError:
        raise _fail("A recovery artifact could not be read.") from None


def _sync_file(path: Path) -> None:
    try:
        with path.open("rb") as stream:
            os.fsync(stream.fileno())
    except OSError:
        raise _fail("Recovery artifact could not be synchronized to storage.") from None


def _sync_directory(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        raise _fail("Recovery directory could not be synchronized to storage.") from None


def _write_new(path: Path, body: bytes, *, private: bool) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600 if private else 0o666)
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        raise _fail("Recovery output already exists; refusing overwrite.") from None
    except OSError:
        raise _fail("Recovery output could not be written.") from None


def _copy_verified(source: Path, destination: Path) -> None:
    try:
        with source.open("rb") as src, destination.open("xb") as dst:
            shutil.copyfileobj(src, dst)
            dst.flush()
            os.fsync(dst.fileno())
    except Exception:
        raise _fail("Removable storage copy failed; existing files were retained.") from None
    if _digest(source) != _digest(destination):
        raise _fail("Removable storage readback digest mismatch.")


def _create_private_workdir(path: str | Path) -> Path:
    root = Path(path)
    try:
        parent = root.parent
        if not parent.exists() or parent.is_symlink() or not parent.is_dir() or parent.stat().st_uid != os.getuid():
            raise _fail("Output parent must be an existing operator-owned directory.")
        root.mkdir(mode=0o700)
        root.chmod(0o700)
        _private_directory(root)
        _sync_directory(parent)
    except FileExistsError:
        raise _fail("Output directory already exists; refusing overwrite.") from None
    except StorageError:
        raise
    except Exception:
        raise _fail("A new private output directory could not be created.") from None
    return root


def _json_bytes(value: dict) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _write_receipt(path: Path, receipt: dict) -> None:
    _write_new(path, _json_bytes(receipt), private=True)


def _restore_count(result, stage: Path) -> int:
    if isinstance(result, dict):
        return int(result.get("files", 0))
    if isinstance(result, int):
        return result
    return sum(1 for path in stage.rglob("*") if path.is_file())


def _verify_bundle(bundle: Path, identity: Path):
    return control_plane_recovery.verify_bundle(bundle, identity)


def _restore_bundle(bundle: Path, identity: Path, destination: Path):
    return control_plane_recovery.restore_bundle(bundle, identity, destination)


def _prepare_receipt(profile: dict, capture_id: str, bundle_sha: str, files_compared: int, verification: dict) -> dict:
    prefix = _remote_prefix(profile, capture_id)
    return {
        "schema_version": 1,
        "capture_id": capture_id,
        "minio_alias": profile["minio_alias"],
        "bucket": profile["bucket"],
        "minio_prefix": prefix,
        "bundle_object": prefix + "/control-plane.age",
        "unlock_object": prefix + "/unlock-identity.txt",
        "removable_capture": capture_id,
        "bundle_sha256": bundle_sha,
        "minio_private": True,
        "minio_readback": True,
        "drive_readback": True,
        "two_location_key_recovery": True,
        "restored_files_compared": files_compared,
        "verification": verification,
        "production_services_restarted": False,
        "destructive_live_restore_tested": False,
    }


def publish(profile_path: str | Path, bundle_path: str | Path, capture_id: str, output_dir: str | Path) -> dict:
    profile = _load_profile(profile_path, capture_id, require_identities=True)
    bundle = Path(bundle_path)
    _owned_regular(bundle, 0o600)
    for tool in ("mc", "age", "age-keygen"):
        _binary(tool)
    _mc_alias_url(profile)
    drive_run = Path(profile["removable_directory"]) / capture_id
    _check_private_bucket(profile)
    _require_empty_prefix(profile, capture_id, drive_run)
    # All remote and removable target checks complete before creating local or external outputs.
    output = _create_private_workdir(output_dir)
    bundle_sha = _digest(bundle)
    recipient = _run([_binary("age-keygen"), "-y", profile["unlock_identity"]]).decode("utf-8", errors="strict").strip()
    if not re.fullmatch(r"age1[0-9a-z]+", recipient):
        raise _fail("Unlock identity did not produce a valid age recipient.")
    wrapped = output / "recovery-key.age"
    _run([_binary("age"), "-r", recipient, "-o", wrapped, profile["recovery_identity"]])
    _owned_regular(wrapped)
    wrapped.chmod(0o600)
    _sync_file(wrapped)
    try:
        drive_run.mkdir(mode=0o777)
    except OSError:
        raise _fail("A new removable recovery directory could not be created.") from None
    _copy_verified(bundle, drive_run / "control-plane.age")
    _copy_verified(wrapped, drive_run / "recovery-key.age")
    _sync_directory(drive_run)
    prefix = _remote_prefix(profile, capture_id)
    _run(_mc_base(profile) + ["cp", bundle, prefix + "/control-plane.age", "--json"])
    _run(_mc_base(profile) + ["cp", profile["unlock_identity"], prefix + "/unlock-identity.txt", "--json"])
    readback = output / "minio-readback"
    readback.mkdir(mode=0o700)
    downloaded_bundle = readback / "control-plane.age"
    downloaded_unlock = readback / "unlock-identity.txt"
    _run(_mc_base(profile) + ["cp", prefix + "/control-plane.age", downloaded_bundle, "--json"])
    _run(_mc_base(profile) + ["cp", prefix + "/unlock-identity.txt", downloaded_unlock, "--json"])
    downloaded_bundle.chmod(0o600)
    downloaded_unlock.chmod(0o600)
    _sync_file(downloaded_bundle)
    _sync_file(downloaded_unlock)
    if _digest(downloaded_bundle) != bundle_sha or _digest(downloaded_unlock) != _digest(Path(profile["unlock_identity"])):
        raise _fail("Private MinIO readback digest mismatch.")
    recovered = output / "recovery-identity.txt"
    _run([_binary("age"), "-d", "-i", downloaded_unlock, "-o", recovered, drive_run / "recovery-key.age"])
    _owned_regular(recovered)
    recovered.chmod(0o600)
    _sync_file(recovered)
    verification = _verify_bundle(downloaded_bundle, recovered)
    stage = output / "staged"
    restored = _restore_bundle(downloaded_bundle, recovered, stage)
    files_compared = _restore_count(restored, stage)
    receipt = _prepare_receipt(profile, capture_id, bundle_sha, files_compared, verification)
    _write_receipt(output / "storage-receipt.json", receipt)
    _copy_verified(output / "storage-receipt.json", drive_run / "storage-receipt.json")
    instructions = (
        "CONTROL PLANE RECOVERY\n\n"
        "Keep this drive safe. Do not delete or overwrite these files.\n"
        "The backup and protected recovery key are encrypted. Recovery requires this drive and private MinIO access.\n\n"
        f"MinIO console: {_mc_alias_url(profile)}\n"
        f"Bucket: {profile['bucket']}\n"
        f"Capture: {capture_id}\n"
        "Drive files: control-plane.age, recovery-key.age, storage-receipt.json\n"
        f"MinIO objects: {profile['bucket']}/{capture_id}/control-plane.age and unlock-identity.txt\n"
        "Use docs/RECOVERY.md from mcp-tunnel-kit to verify and stage the restore.\n"
        "Do not start a second production tunnel or overwrite a running control plane.\n"
    ).encode()
    _write_new(drive_run / "START-HERE.txt", instructions, private=False)
    _sync_directory(drive_run)
    _run(_mc_base(profile) + ["cp", output / "storage-receipt.json", prefix + "/storage-receipt.json", "--json"])
    return {"stored_on_drive": True, "stored_in_private_minio": True, "readback_and_staged_restore": True, "files_compared": files_compared}


def verify_stored(profile_path: str | Path, bundle_path: str | Path, capture_id: str, output_dir: str | Path) -> dict:
    profile = _load_profile(profile_path, capture_id, require_identities=False)
    bundle = Path(bundle_path)
    _owned_regular(bundle, 0o600)
    for tool in ("mc", "age"):
        _binary(tool)
    alias_url = _mc_alias_url(profile)
    drive_run = Path(profile["removable_directory"]) / capture_id
    try:
        drive_info = drive_run.lstat()
    except OSError:
        raise _fail("The removable recovery capture is unavailable.") from None
    if not stat.S_ISDIR(drive_info.st_mode) or drive_run.is_symlink():
        raise _fail("The removable recovery capture must be an existing directory, not a symlink.")
    for name in ("control-plane.age", "recovery-key.age"):
        path = drive_run / name
        try:
            info = path.lstat()
        except OSError:
            raise _fail("A required removable recovery artifact is unavailable.") from None
        if not stat.S_ISREG(info.st_mode):
            raise _fail("A removable recovery artifact must be a regular file.")
    expected_sha = _digest(bundle)
    _check_private_bucket(profile)
    output = _create_private_workdir(output_dir)
    prefix = _remote_prefix(profile, capture_id)
    downloaded_bundle = output / "control-plane.age"
    downloaded_unlock = output / "unlock-identity.txt"
    _run(_mc_base(profile) + ["cp", prefix + "/control-plane.age", downloaded_bundle, "--json"])
    _run(_mc_base(profile) + ["cp", prefix + "/unlock-identity.txt", downloaded_unlock, "--json"])
    downloaded_bundle.chmod(0o600)
    downloaded_unlock.chmod(0o600)
    _sync_file(downloaded_bundle)
    _sync_file(downloaded_unlock)
    if _digest(downloaded_bundle) != expected_sha:
        raise _fail("Downloaded encrypted bundle digest mismatch.")
    if _digest(drive_run / "control-plane.age") != expected_sha:
        raise _fail("Removable encrypted bundle digest mismatch.")
    recovered = output / "recovery-identity.txt"
    _run([_binary("age"), "-d", "-i", downloaded_unlock, "-o", recovered, drive_run / "recovery-key.age"])
    _owned_regular(recovered)
    recovered.chmod(0o600)
    _sync_file(recovered)
    verification = _verify_bundle(downloaded_bundle, recovered)
    stage = output / "staged"
    restored = _restore_bundle(downloaded_bundle, recovered, stage)
    files_compared = _restore_count(restored, stage)
    receipt = _prepare_receipt(profile, capture_id, expected_sha, files_compared, verification)
    receipt["minio_console"] = alias_url
    receipt["mode"] = "verify-stored"
    _write_receipt(output / "storage-receipt.json", receipt)
    return {"verified_stored_bundle": True, "two_location_key_recovery": True, "files_compared": files_compared}


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("publish", "Store a recovery bundle in MinIO and on removable media"),
        ("verify-stored", "Recover the decryption identity and stage a stored bundle"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--storage-profile", required=True)
        command.add_argument("--bundle", required=True)
        command.add_argument("--capture-id", required=True)
        command.add_argument("--output-dir", required=True)
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        if args.command == "publish":
            result = publish(args.storage_profile, args.bundle, args.capture_id, args.output_dir)
        else:
            result = verify_stored(args.storage_profile, args.bundle, args.capture_id, args.output_dir)
        print(json.dumps(result, sort_keys=True))
    except StorageError as error:
        print(f"Recovery storage refused: {error}", file=sys.stderr)
        return 2
    except Exception:
        print("Recovery storage failed; diagnostic withheld.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
