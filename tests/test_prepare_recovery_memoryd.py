"""A recovery generation carries a verified, private MemoryD backup."""

import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

import prepare_recovery_generation as generation
from test_prepare_recovery_generation import stage_fixture, tree_signature, write_private


BACKEND_IMAGE = (
    "ghcr.io/joshyorko/codex-memoryd@sha256:"
    "70465d5250f693d15408fe904d30e3035360d8a46ac6f1caea8c3660eac09996"
)
ADAPTER_IMAGE = "ghcr.io/joshyorko/codex-action-server@sha256:" + "b" * 64
INSTANCE_ID = "cmi_" + "a" * 32
CAPTURED_AT = "2026-10-29T14:00:00Z"
TABLES = (
    "memory_records", "conclusions", "checkpoints", "subjects", "episodes",
    "subject_aliases", "relations", "evidence_ledger", "procedures",
    "memory_sources", "dream_runs", "policy_events",
)


def read_json(path):
    return json.loads(path.read_text())


def write_json(path, value):
    write_private(path, json.dumps(value, sort_keys=True).encode() + b"\n")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def captured_fixture(tmp_path, *, essential_changes=()):
    restored = stage_fixture(tmp_path, essential_changes=essential_changes)
    root = restored / "vm-snapshot" / "memoryd"
    root.mkdir(mode=0o700)
    adapter_dir = root / "adapter"
    adapter_dir.mkdir(mode=0o700)
    backup = root / "backup.db"
    with sqlite3.connect(backup) as db:
        db.execute("CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("INSERT INTO schema_meta VALUES ('schema_version', '13')")
        db.execute("CREATE TABLE instance_metadata (singleton_key TEXT PRIMARY KEY, instance_id TEXT NOT NULL)")
        db.execute("INSERT INTO instance_metadata VALUES ('default', ?)", (INSTANCE_ID,))
        db.execute("CREATE TABLE memory_records (id TEXT, profile_id TEXT, workspace_id TEXT, archived INTEGER, content TEXT)")
        db.executemany("INSERT INTO memory_records VALUES (?, ?, ?, ?, ?)", [
            ("active", "personal", "dakota-codex-only", 0, "synthetic active private content"),
            ("archived", "personal", "dakota-codex-only", 1, "synthetic archived private content"),
        ])
        for name in TABLES[1:]:
            db.execute(f'CREATE TABLE "{name}" (id TEXT)')
    backup.chmod(0o600)
    adapter = adapter_dir / "codex_memoryd_mcp.py"
    write_private(adapter, b"# synthetic pinned adapter\n")
    adapter_hash = sha(adapter)
    write_json(adapter_dir / "artifact.json", {
        "adapter_sha256": adapter_hash, "size_bytes": adapter.stat().st_size,
        "controller_sha": "c" * 40,
    })
    sidecar = {
        "manifest_version": 1, "tool_version": "0.1.0", "created_at": CAPTURED_AT,
        "database_file": "backup.db", "sha256": "sha256:" + sha(backup),
        "size_bytes": backup.stat().st_size, "schema_version": 13,
        "expected_schema_version": 13,
        "tables": [{"table": name, "rows": 2 if name == "memory_records" else 0} for name in TABLES],
    }
    write_json(root / "backup.db.manifest.json", sidecar)
    descriptor = {
        "status": "captured", "backend_image": BACKEND_IMAGE, "adapter_image": ADAPTER_IMAGE,
        "adapter_sha256": adapter_hash, "backup_sha256": sha(backup),
        "backup_manifest_sha256": sha(root / "backup.db.manifest.json"),
        "backup_size_bytes": backup.stat().st_size, "source_instance_id": INSTANCE_ID,
        "record_count": 2, "active_record_count": 1, "archived_record_count": 1,
        "profile": "personal", "workspace": "dakota-codex-only", "captured_at": CAPTURED_AT,
    }
    receipt = read_json(restored / "capture-receipt")
    receipt.update(schema_version=2, memoryd=descriptor)
    write_json(restored / "capture-receipt", receipt)
    return restored, descriptor


def refresh_backup_hashes(restored):
    root = restored / "vm-snapshot" / "memoryd"
    backup = root / "backup.db"
    sidecar_path = root / "backup.db.manifest.json"
    sidecar = read_json(sidecar_path)
    sidecar.update(sha256="sha256:" + sha(backup), size_bytes=backup.stat().st_size)
    write_json(sidecar_path, sidecar)
    receipt_path = restored / "capture-receipt"
    receipt = read_json(receipt_path)
    receipt["memoryd"].update(backup_sha256=sha(backup), backup_size_bytes=backup.stat().st_size,
                              backup_manifest_sha256=sha(sidecar_path))
    write_json(receipt_path, receipt)


def test_captured_memoryd_prepares_verified_backup_and_pinned_adapter_without_mutating_stage(tmp_path):
    restored, descriptor = captured_fixture(tmp_path)
    before = tree_signature(restored)
    output = tmp_path / "prepared"

    result = generation.prepare_generation(restored, output)

    assert result["schema_version"] == 2 and result["memoryd"] == descriptor
    assert read_json(output / "generation.json")["memoryd"] == descriptor
    assert (output / "memoryd/backup.db").read_bytes() == (restored / "vm-snapshot/memoryd/backup.db").read_bytes()
    assert (output / "memoryd/backup.db.manifest.json").read_bytes() == (restored / "vm-snapshot/memoryd/backup.db.manifest.json").read_bytes()
    adapter = output / "state/memoryd-adapter" / descriptor["adapter_sha256"]
    assert sha(adapter / "codex_memoryd_mcp.py") == descriptor["adapter_sha256"]
    assert read_json(output / "state/bootstrap/memoryd-adapter-image.json") == {
        "schema_version": 1, "image": ADAPTER_IMAGE, "adapter_sha256": descriptor["adapter_sha256"]}
    assert generation.validate_generation(output) == result
    assert tree_signature(restored) == before


def test_v2_absent_memoryd_is_explicit_and_has_no_memoryd_payload(tmp_path):
    restored = stage_fixture(tmp_path)
    receipt = read_json(restored / "capture-receipt")
    receipt.update(schema_version=2, memoryd={"status": "absent"})
    write_json(restored / "capture-receipt", receipt)
    output = tmp_path / "prepared"

    result = generation.prepare_generation(restored, output)

    assert result["schema_version"] == 2
    assert result["memoryd"] == {"status": "absent"}
    assert read_json(output / "generation.json")["memoryd"] == {"status": "absent"}
    assert not (output / "memoryd").exists()
    assert generation.validate_generation(output) == result


@pytest.mark.parametrize("broken", [
    "missing_backup", "missing_sidecar", "backup_bytes", "sidecar_bytes", "adapter_bytes",
    "adapter_receipt", "adapter_symlink", "extra_file", "unclaimed_files", "instance",
    "scope", "archive_flag", "database_schema", "record_counts", "sidecar_count",
    "sidecar_schema", "image", "backup_mode", "artifact_mode",
])
def test_incomplete_tampered_or_wrong_scope_memoryd_refuses_before_output(tmp_path, broken):
    restored, descriptor = captured_fixture(tmp_path)
    root = restored / "vm-snapshot/memoryd"
    receipt_path = restored / "capture-receipt"
    receipt = read_json(receipt_path)
    if broken == "missing_backup":
        (root / "backup.db").unlink()
    elif broken == "missing_sidecar":
        (root / "backup.db.manifest.json").unlink()
    elif broken == "backup_bytes":
        write_private(root / "backup.db", b"not sqlite")
    elif broken == "sidecar_bytes":
        write_private(root / "backup.db.manifest.json", b"{}")
    elif broken == "adapter_bytes":
        write_private(root / "adapter/codex_memoryd_mcp.py", b"changed")
    elif broken == "adapter_receipt":
        write_json(root / "adapter/artifact.json", {"adapter_sha256": descriptor["adapter_sha256"],
                   "size_bytes": 999, "controller_sha": "c" * 40})
    elif broken == "adapter_symlink":
        path = root / "adapter/codex_memoryd_mcp.py"
        path.unlink()
        path.symlink_to(root / "backup.db")
    elif broken == "extra_file":
        write_private(root / "unexpected", b"extra")
    elif broken == "unclaimed_files":
        receipt["memoryd"] = {"status": "absent"}
        write_json(receipt_path, receipt)
    elif broken in {"instance", "scope", "archive_flag", "database_schema"}:
        with sqlite3.connect(root / "backup.db") as db:
            if broken == "instance":
                db.execute("UPDATE instance_metadata SET instance_id = ?", ("cmi_" + "d" * 32,))
            elif broken == "scope":
                db.execute("UPDATE memory_records SET workspace_id = 'work' WHERE id = 'active'")
            elif broken == "archive_flag":
                db.execute("UPDATE memory_records SET archived = 2 WHERE id = 'active'")
            else:
                db.execute("UPDATE schema_meta SET value = '12' WHERE key = 'schema_version'")
        refresh_backup_hashes(restored)
    elif broken == "record_counts":
        receipt["memoryd"].update(active_record_count=2, archived_record_count=0)
        write_json(receipt_path, receipt)
    elif broken in {"sidecar_count", "sidecar_schema"}:
        path = root / "backup.db.manifest.json"
        sidecar = read_json(path)
        if broken == "sidecar_count":
            sidecar["tables"][0]["rows"] = 3
        else:
            sidecar["schema_version"] = sidecar["expected_schema_version"] = 12
        write_json(path, sidecar)
        receipt["memoryd"]["backup_manifest_sha256"] = sha(path)
        write_json(receipt_path, receipt)
    elif broken == "image":
        receipt["memoryd"]["adapter_image"] = "docker.io/foreign:latest"
        write_json(receipt_path, receipt)
    elif broken == "backup_mode":
        (root / "backup.db").chmod(0o644)
    else:
        (root / "adapter/artifact.json").chmod(0o644)

    output = tmp_path / "prepared"
    with pytest.raises(generation.GenerationError):
        generation.prepare_generation(restored, output)
    assert not output.exists()


def test_existing_bootstrap_adapter_pin_must_match_captured_adapter(tmp_path):
    wrong_pin = json.dumps({"schema_version": 1, "image": ADAPTER_IMAGE,
                            "adapter_sha256": "e" * 64}).encode()
    restored, _descriptor = captured_fixture(
        tmp_path, essential_changes=[("bootstrap/memoryd-adapter-image.json", "file", wrong_pin, 0o600)])

    with pytest.raises(generation.GenerationError):
        generation.prepare_generation(restored, tmp_path / "prepared")


def test_adapter_pin_schema_version_cannot_be_a_boolean(tmp_path):
    adapter_sha = hashlib.sha256(b"# synthetic pinned adapter\n").hexdigest()
    pin = {"schema_version": True, "image": ADAPTER_IMAGE, "adapter_sha256": adapter_sha}
    restored, _descriptor = captured_fixture(
        tmp_path, essential_changes=[("bootstrap/memoryd-adapter-image.json", "file",
                                      json.dumps(pin).encode(), 0o600)])

    with pytest.raises(generation.GenerationError):
        generation.prepare_generation(restored, tmp_path / "prepared")


def test_archived_adapter_pin_must_have_private_mode(tmp_path):
    adapter_sha = hashlib.sha256(b"# synthetic pinned adapter\n").hexdigest()
    pin = {"schema_version": 1, "image": ADAPTER_IMAGE, "adapter_sha256": adapter_sha}
    restored, _descriptor = captured_fixture(
        tmp_path, essential_changes=[("bootstrap/memoryd-adapter-image.json", "file",
                                      json.dumps(pin).encode(), 0o644)])

    with pytest.raises(generation.GenerationError):
        generation.prepare_generation(restored, tmp_path / "prepared")


def test_matching_existing_bootstrap_adapter_pin_is_preserved(tmp_path):
    adapter_sha = hashlib.sha256(b"# synthetic pinned adapter\n").hexdigest()
    pin = {"schema_version": 1, "image": ADAPTER_IMAGE, "adapter_sha256": adapter_sha}
    restored, _descriptor = captured_fixture(
        tmp_path, essential_changes=[("bootstrap/memoryd-adapter-image.json", "file",
                                      json.dumps(pin).encode(), 0o600)])

    result = generation.prepare_generation(restored, tmp_path / "prepared")

    assert result["memoryd"]["adapter_sha256"] == adapter_sha
    assert read_json(tmp_path / "prepared/state/bootstrap/memoryd-adapter-image.json") == pin


@pytest.mark.parametrize("name", ["memoryd-integration.json", "memoryd-adapter-image.json"])
def test_absent_capture_rejects_a_retained_memoryd_registration_or_pin(tmp_path, name):
    restored = stage_fixture(tmp_path, essential_changes=[("bootstrap/" + name, "file", b"{}", 0o600)])
    receipt_path = restored / "capture-receipt"
    receipt = read_json(receipt_path)
    receipt.update(schema_version=2, memoryd={"status": "absent"})
    write_json(receipt_path, receipt)

    with pytest.raises(generation.GenerationError):
        generation.prepare_generation(restored, tmp_path / "prepared")


def test_prepared_generation_rejects_changed_image_pin_even_with_updated_inventory(tmp_path):
    restored, _descriptor = captured_fixture(tmp_path)
    output = tmp_path / "prepared"
    generation.prepare_generation(restored, output)
    pin = output / "state/bootstrap/memoryd-adapter-image.json"
    document = read_json(pin)
    document["image"] = "ghcr.io/joshyorko/codex-action-server@sha256:" + "f" * 64
    write_json(pin, document)
    manifest_path = output / "prepared-manifest.json"
    manifest = read_json(manifest_path)
    row = next(row for row in manifest["inventory"] if row["path"] == "state/bootstrap/memoryd-adapter-image.json")
    row.update(size=pin.stat().st_size, sha256=sha(pin))
    write_json(manifest_path, manifest)

    with pytest.raises(generation.GenerationError):
        generation.validate_generation(output)


def test_cli_refusal_never_prints_memory_content(tmp_path):
    restored, _descriptor = captured_fixture(tmp_path)
    receipt_path = restored / "capture-receipt"
    receipt = read_json(receipt_path)
    receipt["memoryd"]["workspace"] = "synthetic active private content"
    write_json(receipt_path, receipt)
    script = Path(__file__).resolve().parents[1] / "scripts/prepare_recovery_generation.py"

    result = subprocess.run([sys.executable, str(script), "--restored-dir", str(restored),
                             "--output-dir", str(tmp_path / "prepared")], capture_output=True, text=True)

    assert result.returncode != 0
    assert "synthetic active private content" not in result.stdout + result.stderr
    assert "synthetic archived private content" not in result.stdout + result.stderr
