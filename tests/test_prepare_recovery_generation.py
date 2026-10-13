"""A decrypted collector stage becomes a validated, private VM generation."""

import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tarfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import prepare_recovery_generation as generation


def write_private(path: Path, body: bytes, mode=0o600):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(body)
    path.chmod(mode)


def tar_fixture(path, entries):
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
        for name, kind, body, mode in entries:
            item = tarfile.TarInfo(name)
            item.mode = mode
            item.uid = item.gid = 0
            if kind == "directory":
                item.type = tarfile.DIRTYPE
                archive.addfile(item)
            elif kind == "file":
                item.size = len(body)
                archive.addfile(item, io.BytesIO(body))
            elif kind == "symlink":
                item.type = tarfile.SYMTYPE
                item.linkname = body
                archive.addfile(item)
            elif kind == "hardlink":
                item.type = tarfile.LNKTYPE
                item.linkname = body
                archive.addfile(item)
    path.chmod(0o600)


def database(path):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE receipts (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("INSERT INTO receipts(value) VALUES ('fixture')")
    path.chmod(0o600)


def tree_signature(path):
    rows = []
    for current in sorted(path.rglob("*")):
        relative = current.relative_to(path).as_posix()
        info = current.lstat()
        digest = hashlib.sha256(current.read_bytes()).hexdigest() if stat.S_ISREG(info.st_mode) else None
        rows.append((relative, stat.S_IMODE(info.st_mode), digest))
    return rows


def stage_fixture(
    tmp_path,
    *,
    essential_changes=(),
    executor_changes=(),
    invalid_db=False,
    mapped_path="cas/runtime/workitems.db",
    include_receipts=True,
    receipt_files=True,
):
    root = tmp_path / "restored"
    root.mkdir(mode=0o700)
    (root / "native-endpoint").mkdir(mode=0o700)
    (root / "instance-config").mkdir(mode=0o700)
    (root / "operator-ssh").mkdir(mode=0o700)
    (root / "vm-snapshot").mkdir(mode=0o700)

    for name in (
        "authorized_keys",
        "native-codex-ssh.service",
        "ssh_host_ed25519_key",
        "ssh_host_ed25519_key.pub",
        "sshd_config",
    ):
        write_private(root / "native-endpoint" / name, b"private endpoint fixture\n")
    write_private(root / "native-endpoint" / "native_codex_ssh.py", b"#!/usr/bin/env python3\n", 0o700)
    for name in ("instance.json", "kamal-local.env", "native-ssh.json"):
        write_private(root / "instance-config" / name, b"private instance fixture\n")
    for name in ("identity", "known_hosts", "ssh_config"):
        write_private(root / "operator-ssh" / name, b"private operator SSH fixture\n")

    snapshot_root = root / "vm-snapshot"
    cas_dir = snapshot_root / "cas-databases"
    cas_dir.mkdir(mode=0o700)
    snapshots = [(mapped_path, "010101010101-workitems.db")]
    snapshot_path = cas_dir / snapshots[0][1]
    if invalid_db:
        write_private(snapshot_path, b"not sqlite")
    else:
        database(snapshot_path)
    cas_manifest = {
        "schema_version": 1,
        "databases": [
            {"relative_path": relative, "snapshot": filename}
            for relative, filename in snapshots
        ],
    }
    manifest_bytes = json.dumps(cas_manifest, sort_keys=True).encode() + b"\n"
    write_private(cas_dir / "manifest.json", manifest_bytes)

    executor_entries = [
        ("data", "directory", b"", 0o700),
        ("data/.executor.lock", "file", b"lock\n", 0o600),
        ("data/analytics-secret.key", "file", b"analytics\n", 0o600),
        ("data/auth-secret.key", "file", b"auth\n", 0o600),
        ("data/builds", "directory", b"", 0o700),
        ("data/builds/state.json", "file", b"{\"state\":true}\n", 0o600),
        ("data/start-worker.py", "file", b"#!/usr/bin/env python3\n", 0o700),
        *executor_changes,
    ]
    tar_fixture(snapshot_root / "executor.tar", executor_entries)

    receipt_entries = []
    if include_receipts:
        receipt_entries.append(("cas/receipts", "directory", b"", 0o700))
        if receipt_files:
            receipt_entries.append(("cas/receipts/fixture.json", "file", b"receipt bytes\n", 0o600))
    essential_entries = [
        ("secrets", "directory", b"", 0o700),
        ("secrets/control-plane-api-key", "file", b"synthetic-api-key\n", 0o600),
        ("secrets/control-plane-tunnel-id", "file", b"synthetic-tunnel-id\n", 0o600),
        ("secrets/executor-auth-header", "file", b"synthetic-auth-header\n", 0o600),
        ("secrets/executor-pat", "file", b"synthetic-pat\n", 0o600),
        ("bootstrap", "directory", b"", 0o700),
        ("bootstrap/codex-integration.json", "file", b"{}\n", 0o600),
        ("bootstrap/devsy-integration.json", "file", b"{}\n", 0o600),
        *receipt_entries,
        ("native-ssh", "directory", b"", 0o700),
        ("native-ssh/identity", "file", b"native-identity\n", 0o600),
        ("native-ssh/identity.pub", "file", b"native-public\n", 0o600),
        ("native-ssh/known_hosts", "file", b"pinned-host\n", 0o600),
        ("native-ssh/known_hosts.native", "file", b"pinned-native-host\n", 0o600),
        ("native-ssh/ssh_config", "file", b"Host vm\n", 0o600),
        ("native-ssh/ssh_config.native", "file", b"Host endpoint\n", 0o600),
        ("compose.env", "file", b"SECRET=value\n", 0o600),
        ("cas-targets.json", "file", b"{}\n", 0o600),
        ("cas/dynamic-targets.json", "file", b"{}\n", 0o600),
        ("owner-devsy-scope", "directory", b"", 0o700),
        ("owner-devsy-scope/capability", "file", b"capability\n", 0o600),
        ("owner-devsy-scope/scope.json", "file", b"{}\n", 0o600),
        ("ror", "directory", b"", 0o700),
        ("ror/kubeconfig.json", "file", b"{}\n", 0o600),
        ("ror/operator-kubeconfig.json", "file", b"{}\n", 0o600),
        ("devsy-operator/config.yaml", "file", b"context: default\n", 0o600),
        ("devsy-operator/operator-kubeconfig.json", "file", b"{}\n", 0o600),
        ("devsy-operator/contexts/default/private.json", "file", b"{}\n", 0o600),
        ("start-host-devsy.py", "file", b"#!/usr/bin/env python3\n", 0o700),
        ("deployment/current.json", "file", b"{}\n", 0o600),
        ("deployment/previous.json", "file", b"{}\n", 0o600),
        ("devsy-bridge/scoped-jobs", "directory", b"", 0o700),
        ("devsy-bridge/scoped-jobs/fixture.json", "file", b"{}\n", 0o600),
        ("cas-databases", "directory", b"", 0o700),
        ("cas-databases/manifest.json", "file", manifest_bytes, 0o600),
        (f"cas-databases/{snapshots[0][1]}", "file", snapshot_path.read_bytes(), 0o600),
        *essential_changes,
    ]
    tar_fixture(snapshot_root / "essential.tar", essential_entries)

    executor_sha = hashlib.sha256((snapshot_root / "executor.tar").read_bytes()).hexdigest()
    receipt = {
        "schema_version": 1,
        "capture_kind": "synthetic-fixture",
        "executor_sha256": executor_sha,
        "identity_preserved": True,
        "single_tunnel": True,
        "captured_at_utc": "2026-10-13T00:00:00Z",
        "private_requirements_added": True,
        "generation": {
            "authority": "fixture-authority",
            "identity": "fixture-generation-identity",
            "manifest": {"version": 1, "images": {"fixture": "digest"}},
            "publication_proof": {"cas": {}, "schema_proxy": {}},
            "source_sha": "a" * 40,
        },
    }
    write_private(root / "capture-receipt", json.dumps(receipt).encode() + b"\n")
    return root


def test_prepare_generation_materializes_private_payload_and_validates_it(tmp_path):
    restored = stage_fixture(tmp_path)
    output = tmp_path / "prepared"
    source_before = tree_signature(restored)

    result = generation.prepare_generation(restored, output)

    assert result["schema_version"] == 1
    assert result["generation"]["identity"] == "fixture-generation-identity"
    assert result["expected_identity"] == "fixture-generation-identity"
    assert set(result) == {
        "schema_version",
        "generation_file",
        "generation",
        "expected_identity",
        "inventory",
    }
    assert {row["path"] for row in result["inventory"]} >= {
        "generation.json",
        "vm.env",
        "executor-data",
        "state",
        "native-ssh",
    }
    assert (output / "executor-data" / "builds" / "state.json").read_bytes() == b'{"state":true}\n'
    assert (output / "state" / "secrets" / "executor-pat").read_bytes() == b"synthetic-pat\n"
    assert (output / "native-ssh" / "identity").read_bytes() == b"native-identity\n"
    assert (output / "vm.env").read_bytes() == b"SECRET=value\n"
    assert (output / "state" / "cas" / "runtime" / "workitems.db").exists()
    assert (output / "state" / "cas" / "receipts" / "fixture.json").read_bytes() == b"receipt bytes\n"
    assert not (output / "recovery-inputs").exists()
    assert not any(row["path"].startswith("recovery-inputs/") for row in result["inventory"])
    assert (restored / "operator-ssh" / "identity").exists()
    assert (restored / "native-endpoint" / "ssh_host_ed25519_key").exists()
    output_bytes = b"\n".join(path.read_bytes() for path in output.rglob("*") if path.is_file())
    assert b"private endpoint fixture" not in output_bytes
    assert b"private operator SSH fixture" not in output_bytes
    assert tree_signature(restored) == source_before
    assert not (output / "state" / "cas-databases").exists()
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert stat.S_IMODE((output / "vm.env").stat().st_mode) == 0o600
    assert stat.S_IMODE((output / "state" / "start-host-devsy.py").stat().st_mode) == 0o700
    assert generation.validate_generation(output) == result


@pytest.mark.parametrize(
    "hostile",
    [
        ("../escape", "file", b"escape", 0o600),
        ("data/link", "symlink", "../../outside", 0o700),
        ("data/link", "hardlink", "data/builds/state.json", 0o600),
        ("data/builds/state.json", "file", b"duplicate", 0o600),
        ("data/builds", "file", b"ancestor collision", 0o600),
    ],
)
def test_invalid_nested_archive_is_rejected_before_output_creation(tmp_path, hostile):
    restored = stage_fixture(tmp_path, executor_changes=(hostile,))
    output = tmp_path / "prepared"

    with pytest.raises(generation.GenerationError):
        generation.prepare_generation(restored, output)

    assert not output.exists()


def test_invalid_essential_archive_link_is_rejected_before_output_creation(tmp_path):
    hostile = ("secrets/escape", "symlink", "../../outside", 0o700)
    restored = stage_fixture(tmp_path, essential_changes=(hostile,))
    output = tmp_path / "prepared"

    with pytest.raises(generation.GenerationError):
        generation.prepare_generation(restored, output)

    assert not output.exists()


def test_archive_file_cannot_be_an_implicit_parent(tmp_path):
    conflict = [
        ("data/collision-root", "file", b"file parent", 0o600),
        ("data/collision-root/child", "file", b"child", 0o600),
    ]
    restored = stage_fixture(tmp_path, executor_changes=conflict)
    output = tmp_path / "prepared"

    with pytest.raises(generation.GenerationError):
        generation.prepare_generation(restored, output)

    assert not output.exists()


def test_sqlite_mapping_traversal_is_rejected_before_output_creation(tmp_path):
    restored = stage_fixture(tmp_path, mapped_path="cas/runtime/../../outside.db")
    output = tmp_path / "prepared"

    with pytest.raises(generation.GenerationError):
        generation.prepare_generation(restored, output)

    assert not output.exists()


def test_external_and_archive_sqlite_mappings_must_agree(tmp_path):
    restored = stage_fixture(tmp_path)
    manifest_path = restored / "vm-snapshot" / "cas-databases" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["databases"][0]["snapshot"] = "other-snapshot.db"
    write_private(manifest_path, json.dumps(manifest).encode())
    output = tmp_path / "prepared"

    with pytest.raises(generation.GenerationError):
        generation.prepare_generation(restored, output)

    assert not output.exists()


def test_snapshot_bytes_must_match_the_essential_archive_copy(tmp_path):
    restored = stage_fixture(tmp_path)
    replacement = restored / "vm-snapshot" / "cas-databases" / "010101010101-workitems.db"
    replacement.unlink()
    database(replacement)
    with sqlite3.connect(replacement) as db:
        db.execute("INSERT INTO receipts(value) VALUES ('different snapshot')")
    replacement.chmod(0o600)
    output = tmp_path / "prepared"

    with pytest.raises(generation.GenerationError):
        generation.prepare_generation(restored, output)

    assert not output.exists()


def test_invalid_sqlite_snapshot_is_refused_and_partial_output_removed(tmp_path):
    restored = stage_fixture(tmp_path, invalid_db=True)
    output = tmp_path / "prepared"

    with pytest.raises(generation.GenerationError):
        generation.prepare_generation(restored, output)

    assert not output.exists()


def test_missing_required_secret_or_native_credential_is_refused(tmp_path):
    restored = stage_fixture(tmp_path)
    source_archive = restored / "vm-snapshot" / "essential.tar"
    entries = [
        ("native-ssh", "directory", b"", 0o700),
        ("compose.env", "file", b"SECRET=value\n", 0o600),
    ]
    tar_fixture(source_archive, entries)
    output = tmp_path / "prepared"

    with pytest.raises(generation.GenerationError):
        generation.prepare_generation(restored, output)

    assert not output.exists()


def test_missing_collector_native_endpoint_credential_is_refused(tmp_path):
    restored = stage_fixture(tmp_path)
    (restored / "native-endpoint" / "authorized_keys").unlink()
    output = tmp_path / "prepared"

    with pytest.raises(generation.GenerationError):
        generation.prepare_generation(restored, output)

    assert not output.exists()


def test_missing_explicit_cas_receipts_directory_is_refused(tmp_path):
    restored = stage_fixture(tmp_path, include_receipts=False)
    output = tmp_path / "prepared"

    with pytest.raises(generation.GenerationError):
        generation.prepare_generation(restored, output)

    assert not output.exists()


def test_explicit_empty_cas_receipts_directory_is_preserved(tmp_path):
    restored = stage_fixture(tmp_path, receipt_files=False)
    output = tmp_path / "prepared"

    result = generation.prepare_generation(restored, output)

    assert (output / "state" / "cas" / "receipts").is_dir()
    assert not list((output / "state" / "cas" / "receipts").iterdir())
    assert {row["path"] for row in result["inventory"]} >= {"state/cas/receipts"}
    assert generation.validate_generation(output) == result


def test_manifest_digest_tamper_and_existing_output_are_refused(tmp_path):
    restored = stage_fixture(tmp_path)
    output = tmp_path / "prepared"
    generation.prepare_generation(restored, output)
    with pytest.raises(generation.GenerationError):
        generation.prepare_generation(restored, output)

    target = output / "state" / "secrets" / "executor-pat"
    target.write_bytes(b"tampered\n")
    with pytest.raises(generation.GenerationError):
        generation.validate_generation(output)


def test_partial_output_is_removed_after_write_failure(tmp_path, monkeypatch):
    restored = stage_fixture(tmp_path)
    output = tmp_path / "prepared"
    original = generation._write_file
    count = 0

    def fail_after_first(path, source, mode, expected_hash=None):
        nonlocal count
        original(path, source, mode, expected_hash)
        count += 1
        if count == 1:
            raise OSError("fixture failure")

    monkeypatch.setattr(generation, "_write_file", fail_after_first)
    with pytest.raises(generation.GenerationError):
        generation.prepare_generation(restored, output)
    assert not output.exists()


def test_cli_prepares_and_validates_a_new_generation(tmp_path):
    restored = stage_fixture(tmp_path)
    output = tmp_path / "prepared"
    script = Path(__file__).resolve().parents[1] / "scripts" / "prepare_recovery_generation.py"

    result = subprocess.run(
        [sys.executable, str(script), "--restored-dir", str(restored), "--output-dir", str(output)],
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stdout == "Private recovery generation prepared and validated.\n"
    assert generation.validate_generation(output)["expected_identity"] == "fixture-generation-identity"
