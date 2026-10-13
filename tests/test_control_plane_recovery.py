"""Recovery bundles are authenticated before any staged restore is written."""

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import control_plane_recovery as recovery


def archive(path, entries, *, manifest=None):
    """Write a small internal archive fixture with an optional hostile entry."""
    payload = b"fixture payload"
    manifest = manifest or {
        "version": 1,
        "bundle_id": "fixture",
        "members": [
            {
                "name": "alpha",
                "kind": "directory",
                "entries": ["payload/alpha", "payload/alpha/data.txt"],
            }
        ],
        "entries": [
            {"path": "payload/alpha", "type": "directory", "mode": 0o700, "size": 0},
            {
                "path": "payload/alpha/data.txt",
                "type": "file",
                "mode": 0o600,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            },
        ],
    }
    with tarfile.open(path, "w") as handle:
        for name, kind, body in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.mode = 0o600
                info.size = len(body)
                handle.addfile(info, io.BytesIO(body))
            elif kind == "directory":
                info.mode = 0o700
                info.type = tarfile.DIRTYPE
                handle.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = body
                handle.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = body
                handle.addfile(info)
            else:
                handle.addfile(info)
        body = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        info = tarfile.TarInfo("recovery-manifest.json")
        info.mode = 0o600
        info.size = len(body)
        handle.addfile(info, io.BytesIO(body))


def good_entries():
    return [
        ("payload/alpha", "directory", b""),
        ("payload/alpha/data.txt", "file", b"fixture payload"),
    ]


def test_archive_validation_reports_only_logical_inventory(tmp_path):
    source = tmp_path / "plain.tar"
    archive(source, good_entries())

    inventory = recovery.validate_archive(source)

    assert inventory == {"members": ["alpha"], "files": 1}


@pytest.mark.parametrize(
    "hostile",
    [
        ("payload/../escape", "file", b"outside"),
        ("payload/alpha/link", "symlink", "../../escape"),
        ("payload/alpha/link", "hardlink", "payload/alpha/data.txt"),
        ("payload/alpha/data.txt", "file", b"duplicate"),
    ],
)
def test_archive_validation_rejects_traversal_links_and_duplicate_paths(tmp_path, hostile):
    source = tmp_path / "hostile.tar"
    archive(source, [*good_entries(), hostile])

    with pytest.raises(recovery.RecoveryError):
        recovery.validate_archive(source)


def test_archive_validation_rejects_missing_and_digest_mismatch(tmp_path):
    missing = tmp_path / "missing.tar"
    archive(missing, [good_entries()[0]])
    with pytest.raises(recovery.RecoveryError):
        recovery.validate_archive(missing)

    mismatched = tmp_path / "mismatch.tar"
    archive(mismatched, [good_entries()[0], ("payload/alpha/data.txt", "file", b"changed")])
    with pytest.raises(recovery.RecoveryError):
        recovery.validate_archive(mismatched)


def test_export_rejects_identity_file_nested_in_source_without_echoing_paths(tmp_path):
    source = tmp_path / "private-source"
    source.mkdir(mode=0o700)
    identity = source / "age-identity.txt"
    identity.write_text("AGE-SECRET-KEY-1TOPSECRET\n")
    identity.chmod(0o600)
    manifest = {
        "version": 1,
        "bundle_id": "fixture",
        "members": [{"name": "private", "source": str(source), "required": True}],
    }

    with pytest.raises(recovery.RecoveryError) as error:
        recovery.prepare_sources(manifest, exclude_identity=identity)

    assert "TOPSECRET" not in str(error.value)
    assert str(identity) not in str(error.value)


def test_export_rejects_hardlinked_identity_even_outside_source(tmp_path):
    source = tmp_path / "profile.json"
    identity = tmp_path / "age-identity.txt"
    source.write_text('{"profile":"private"}\n')
    source.chmod(0o600)
    os.link(source, identity)
    manifest = {
        "version": 1,
        "bundle_id": "fixture",
        "members": [{"name": "profile", "source": str(source), "required": True}],
    }

    with pytest.raises(recovery.RecoveryError):
        recovery.prepare_sources(manifest, exclude_identity=identity)


def test_export_rejects_identity_used_as_direct_source(tmp_path):
    identity = tmp_path / "age-identity.txt"
    identity.write_text("AGE-SECRET-KEY-1TOPSECRET\n")
    identity.chmod(0o600)
    manifest = {
        "version": 1,
        "bundle_id": "fixture",
        "members": [{"name": "identity", "source": str(identity), "required": True}],
    }

    with pytest.raises(recovery.RecoveryError):
        recovery.prepare_sources(manifest, exclude_identity=identity)


def test_external_source_manifest_cannot_be_archived_as_a_member(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text('{"paths":["/private/source"]}\n')
    manifest_path.chmod(0o600)
    manifest = {
        "version": 1,
        "bundle_id": "fixture",
        "members": [{"name": "manifest", "source": str(manifest_path), "required": True}],
    }

    with pytest.raises(recovery.RecoveryError):
        recovery.prepare_sources(manifest, exclude_manifest=manifest_path)


def test_export_refuses_a_missing_required_source_without_echoing_its_path(tmp_path):
    missing = tmp_path / "private-missing-source"
    manifest = {
        "version": 1,
        "bundle_id": "fixture",
        "members": [{"name": "required", "source": str(missing), "required": True}],
    }

    with pytest.raises(recovery.RecoveryError) as error:
        recovery.prepare_sources(manifest)

    assert str(missing) not in str(error.value)


def test_export_does_not_publish_when_a_required_source_is_missing(tmp_path):
    missing = tmp_path / "private-missing-source"
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "bundle_id": "fixture",
                "members": [{"name": "required", "source": str(missing), "required": True}],
            }
        )
    )
    manifest.chmod(0o600)
    recipient = tmp_path / "recipient.txt"
    recipient.write_text("age1recipient\n")
    bundle = tmp_path / "bundle.age"

    with pytest.raises(recovery.RecoveryError):
        recovery.export_bundle(manifest, recipient, bundle, age_bin="missing-age")

    assert not bundle.exists()


def test_restore_stage_is_private_and_never_overwrites_existing_files(tmp_path):
    archive_path = tmp_path / "plain.tar"
    archive(archive_path, good_entries())
    destination = tmp_path / "stage"

    recovery.restore_archive(archive_path, destination)

    assert (destination / "alpha" / "data.txt").read_bytes() == b"fixture payload"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert stat.S_IMODE((destination / "alpha" / "data.txt").stat().st_mode) == 0o600
    with pytest.raises(recovery.RecoveryError):
        recovery.restore_archive(archive_path, destination)
    assert (destination / "alpha" / "data.txt").read_bytes() == b"fixture payload"


def test_failed_restore_removes_its_partial_staging_tree(tmp_path, monkeypatch):
    archive_path = tmp_path / "plain.tar"
    archive(archive_path, good_entries())
    destination = tmp_path / "stage"
    original = recovery._write_file

    def fail_after_first(path, body, mode):
        original(path, body, mode)
        raise OSError("fixture write failure")

    monkeypatch.setattr(recovery, "_write_file", fail_after_first)
    with pytest.raises(recovery.RecoveryError):
        recovery.restore_archive(archive_path, destination)
    assert not destination.exists()


def test_real_age_roundtrip_and_wrong_key_refusal(tmp_path):
    age = os.environ.get("MCP_RECOVERY_AGE_BIN") or shutil.which("age")
    keygen = shutil.which("age-keygen")
    if not age or not keygen:
        pytest.skip("age and age-keygen are required for the real encryption roundtrip")
    identity = tmp_path / "identity.txt"
    generated = subprocess.run(
        [keygen, "-o", str(identity)], capture_output=True, text=True, check=True
    )
    del generated
    identity.chmod(0o600)
    recipient = tmp_path / "recipient.txt"
    recipient.write_text(recovery.recipient_from_identity(identity, age_keygen_bin=keygen))
    recipient.chmod(0o600)
    source = tmp_path / "source dir"
    source.mkdir(mode=0o700)
    nested = source / "nested dir"
    nested.mkdir(mode=0o700)
    profile = nested / "profile with spaces.json"
    profile.write_text('{"token":"do not print"}\n')
    profile.chmod(0o600)
    runner = source / "runner"
    runner.write_text("#!/bin/sh\nexit 0\n")
    runner.chmod(0o700)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "bundle_id": "fixture",
                    "members": [{"name": "profile", "source": str(source), "required": True}],
            }
        )
    )
    manifest.chmod(0o600)
    bundle = tmp_path / "bundle.age"

    script = Path(__file__).resolve().parents[1] / "scripts" / "control_plane_recovery.py"
    subprocess.run(
        [
            sys.executable,
            str(script),
            "export",
            "--manifest",
            str(manifest),
            "--recipient-file",
            str(recipient),
            "--output",
            str(bundle),
            "--exclude-identity",
            str(identity),
            "--age-bin",
            age,
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    assert stat.S_IMODE(bundle.stat().st_mode) == 0o600
    encrypted_before = bundle.read_bytes()
    with pytest.raises(recovery.RecoveryError):
        recovery.export_bundle(manifest, recipient, bundle, age_bin=age, exclude_identity=identity)
    assert bundle.read_bytes() == encrypted_before
    inspected = subprocess.run(
        [sys.executable, str(script), "inspect", "--bundle", str(bundle), "--identity", str(identity), "--age-bin", age],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(inspected.stdout)["members"] == ["profile"]
    assert str(source) not in inspected.stdout
    assert "do not print" not in inspected.stdout
    verified = subprocess.run(
        [sys.executable, str(script), "verify", "--bundle", str(bundle), "--identity", str(identity), "--age-bin", age],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(verified.stdout) == {
        "verified": True,
        "members": 1,
        "files": 2,
    }
    stage = tmp_path / "stage"
    subprocess.run(
        [
            sys.executable,
            str(script),
            "restore-stage",
            "--bundle",
            str(bundle),
            "--identity",
            str(identity),
            "--destination",
            str(stage),
            "--age-bin",
            age,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert (stage / "profile" / "nested dir" / "profile with spaces.json").read_text() == '{"token":"do not print"}\n'
    assert stat.S_IMODE((stage / "profile" / "nested dir" / "profile with spaces.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((stage / "profile" / "runner").stat().st_mode) == 0o700

    wrong_identity = tmp_path / "wrong-identity.txt"
    subprocess.run([keygen, "-o", str(wrong_identity)], capture_output=True, check=True)
    wrong_identity.chmod(0o600)
    with pytest.raises(recovery.RecoveryError):
        recovery.inspect_bundle(bundle, wrong_identity, age_bin=age)
    wrong_stage = tmp_path / "wrong-key-stage"
    with pytest.raises(recovery.RecoveryError):
        recovery.restore_bundle(bundle, wrong_identity, wrong_stage, age_bin=age)
    assert not wrong_stage.exists()

    corrupted = tmp_path / "corrupted.age"
    corrupted.write_bytes(bundle.read_bytes()[:-1] + bytes([bundle.read_bytes()[-1] ^ 1]))
    corrupted.chmod(0o600)
    with pytest.raises(recovery.RecoveryError):
        recovery.inspect_bundle(corrupted, identity, age_bin=age)
