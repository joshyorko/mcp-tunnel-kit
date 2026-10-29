#!/usr/bin/env python3
"""Materialize a private, integrity-checked recovery generation for later activation."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from typing import BinaryIO


MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 200_000
MAX_FILE_BYTES = 50 * 1024**3
MAX_TOTAL_BYTES = 100 * 1024**3
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
SOURCE_SHA = re.compile(r"[a-f0-9]{40}\Z")
MEMORYD_IMAGE = (
    "ghcr.io/joshyorko/codex-memoryd@sha256:"
    "70465d5250f693d15408fe904d30e3035360d8a46ac6f1caea8c3660eac09996"
)
MEMORYD_ADAPTER_IMAGE = re.compile(r"ghcr\.io/joshyorko/codex-action-server@sha256:[a-f0-9]{64}\Z")
MEMORYD_TABLES = (
    "memory_records", "conclusions", "checkpoints", "subjects", "episodes",
    "subject_aliases", "relations", "evidence_ledger", "procedures",
    "memory_sources", "dream_runs", "policy_events",
)
TOP_LEVEL = {
    "native-endpoint",
    "instance-config",
    "operator-ssh",
    "vm-snapshot",
    "capture-receipt",
}
INPUT_FILE_MODES = {0o600, 0o700}
REQUIRED_INPUTS = {
    "native-endpoint": {
        "authorized_keys",
        "native-codex-ssh.service",
        "native_codex_ssh.py",
        "ssh_host_ed25519_key",
        "ssh_host_ed25519_key.pub",
        "sshd_config",
    },
    "instance-config": {"instance.json", "kamal-local.env", "native-ssh.json"},
    "operator-ssh": {"identity", "known_hosts", "ssh_config"},
}
REQUIRED_STATE_FILES = {
    "secrets/control-plane-api-key",
    "secrets/control-plane-tunnel-id",
    "secrets/executor-auth-header",
    "secrets/executor-pat",
    "bootstrap/codex-integration.json",
    "bootstrap/devsy-integration.json",
    "cas-targets.json",
    "cas/dynamic-targets.json",
    "owner-devsy-scope/capability",
    "owner-devsy-scope/scope.json",
    "ror/kubeconfig.json",
    "ror/operator-kubeconfig.json",
    "devsy-operator/config.yaml",
    "devsy-operator/operator-kubeconfig.json",
    "deployment/current.json",
    "deployment/previous.json",
    "start-host-devsy.py",
}
REQUIRED_STATE_DIRECTORIES = {"cas/receipts"}
REQUIRED_NATIVE_SSH = {
    "identity",
    "identity.pub",
    "known_hosts",
    "known_hosts.native",
    "ssh_config",
    "ssh_config.native",
}
REQUIRED_EXECUTOR_FILES = {".executor.lock", "analytics-secret.key", "auth-secret.key"}


class GenerationError(Exception):
    """An expected refusal with a diagnostic safe to display."""


@dataclass(frozen=True)
class ArchiveEntry:
    path: str
    kind: str
    mode: int
    size: int
    sha256: str | None
    archive_path: str


def _fail(message: str) -> GenerationError:
    return GenerationError(message)


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _read_json(path: Path, *, mode=0o600):
    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != mode
            or info.st_nlink != 1
            or info.st_size > MAX_JSON_BYTES
        ):
            raise _fail("A private recovery JSON input has unsafe ownership, mode, or size.")
        with path.open("rb") as source:
            value = json.load(source, object_pairs_hook=_no_duplicate_keys)
    except GenerationError:
        raise
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        raise _fail("A private recovery JSON input is unreadable or malformed.") from None
    if not isinstance(value, dict):
        raise _fail("A private recovery JSON input must be an object.")
    return value


def _canonical_private_path(path: Path):
    try:
        if path.resolve(strict=True) != path.absolute():
            raise _fail("Recovery input paths cannot traverse symlinks.")
    except OSError:
        raise _fail("A required recovery input is missing or unavailable.") from None


def _private_directory(path: Path):
    _canonical_private_path(path)
    try:
        info = path.lstat()
    except OSError:
        raise _fail("A required private recovery directory is unavailable.") from None
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise _fail("Recovery directories must be operator-owned, non-symlink, mode 0700.")
    return info


def _hash_regular_file(path: Path, *, allowed_modes=INPUT_FILE_MODES):
    _canonical_private_path(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) not in allowed_modes
            or info.st_size > MAX_FILE_BYTES
        ):
            os.close(fd)
            raise _fail("Recovery files must be operator-owned, private regular files.")
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(fd, "rb") as source:
            while block := source.read(1024 * 1024):
                size += len(block)
                if size > MAX_FILE_BYTES:
                    raise _fail("A recovery file exceeds the size limit.")
                digest.update(block)
        if size != info.st_size:
            raise _fail("A recovery file changed while being inspected.")
    except GenerationError:
        raise
    except OSError:
        raise _fail("A required recovery file is missing or unreadable.") from None
    return info, size, digest.hexdigest()


def _safe_relative(raw: str):
    if (
        not isinstance(raw, str)
        or not raw
        or "\\" in raw
        or "\x00" in raw
        or any(ord(char) < 32 for char in raw)
        or "//" in raw
    ):
        raise _fail("A recovery archive contains an unsafe path.")
    if len(raw.encode("utf-8")) > 4096 or any(len(part.encode("utf-8")) > 255 for part in raw.split("/")):
        raise _fail("A recovery archive path exceeds filesystem limits.")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in raw.split("/")):
        raise _fail("A recovery archive contains an unsafe path.")
    return path


def _sanitized_mode(mode: int, kind: str):
    if kind == "directory":
        return 0o700
    return 0o700 if mode & 0o111 else 0o600


def _scan_tar(path: Path):
    _hash_regular_file(path, allowed_modes={0o600})
    entries = {}
    total = 0
    try:
        with tarfile.open(path, mode="r:") as archive:
            for item in archive:
                raw = item.name
                if raw.endswith("/"):
                    if not item.isdir() or raw.endswith("//"):
                        raise _fail("A nested archive contains an unsafe path.")
                    raw = raw[:-1]
                name = _safe_relative(raw).as_posix()
                if name in entries:
                    raise _fail("A nested archive contains duplicate paths.")
                if item.uid < 0 or item.gid < 0:
                    raise _fail("A nested archive contains invalid ownership metadata.")
                if not (item.isfile() or item.isdir()):
                    raise _fail("Nested archives cannot contain links or special files.")
                if item.isdir() and item.size != 0:
                    raise _fail("A nested archive contains an invalid directory.")
                if item.isfile() and (item.size < 0 or item.size > MAX_FILE_BYTES):
                    raise _fail("A nested archive contains an oversized file.")
                mode = stat.S_IMODE(item.mode)
                if mode & 0o022 or mode & 0o7000:
                    raise _fail("A nested archive contains an unsafe source mode.")
                kind = "directory" if item.isdir() else "file"
                digest = None
                if kind == "file":
                    stream = archive.extractfile(item)
                    if stream is None:
                        raise _fail("A nested archive contains an unreadable file.")
                    hasher = hashlib.sha256()
                    consumed = 0
                    while block := stream.read(1024 * 1024):
                        consumed += len(block)
                        hasher.update(block)
                    if consumed != item.size:
                        raise _fail("A nested archive file size does not match its header.")
                    digest = hasher.hexdigest()
                    total += consumed
                    if total > MAX_TOTAL_BYTES:
                        raise _fail("A nested archive exceeds the expanded size limit.")
                entries[name] = ArchiveEntry(
                    name,
                    kind,
                    _sanitized_mode(mode, kind),
                    item.size,
                    digest,
                    item.name,
                )
                if len(entries) > MAX_ARCHIVE_ENTRIES:
                    raise _fail("A nested archive exceeds the entry limit.")
    except GenerationError:
        raise
    except (OSError, tarfile.TarError, EOFError):
        raise _fail("A nested recovery archive is unreadable or corrupt.") from None
    if not entries:
        raise _fail("A required nested recovery archive is empty.")
    _validate_archive_tree(entries)
    return entries


def _validate_archive_tree(entries: dict[str, ArchiveEntry]):
    implicit_directories = set()
    for name, entry in entries.items():
        path = PurePosixPath(name)
        parent = path.parent
        while parent != PurePosixPath("."):
            parent_entry = entries.get(parent.as_posix())
            if parent_entry is None:
                implicit_directories.add(parent.as_posix())
            elif parent_entry.kind != "directory":
                raise _fail("A nested archive has a non-directory parent.")
            parent = parent.parent
    for path in implicit_directories:
        entries[path] = ArchiveEntry(path, "directory", 0o700, 0, None, "")


def _scan_source_tree(source_root: Path, target_root: str):
    _private_directory(source_root)
    plan = []

    def walk(source: Path, relative: PurePosixPath):
        try:
            info = source.lstat()
        except OSError:
            raise _fail("A recovery source changed while being inspected.") from None
        target = (PurePosixPath(target_root) / relative).as_posix()
        if stat.S_ISDIR(info.st_mode):
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise _fail("Recovery directories must be operator-owned and mode 0700.")
            plan.append({"path": target, "type": "directory", "mode": 0o700, "size": 0})
            try:
                children = sorted(source.iterdir(), key=lambda child: child.name)
            except OSError:
                raise _fail("A recovery source directory is unreadable.") from None
            for child in children:
                _safe_relative(child.name)
                walk(child, relative / child.name)
            after = source.lstat()
            if (after.st_dev, after.st_ino) != (info.st_dev, info.st_ino):
                raise _fail("A recovery source changed while being inspected.")
        elif stat.S_ISREG(info.st_mode):
            if info.st_uid != os.getuid() or info.st_nlink != 1:
                raise _fail("Recovery files must be operator-owned and have no hardlinks.")
            if stat.S_IMODE(info.st_mode) not in INPUT_FILE_MODES:
                raise _fail("Recovery files must have mode 0600 or 0700.")
            _, size, digest = _hash_regular_file(source)
            plan.append(
                {
                    "path": target,
                    "type": "file",
                    "mode": _sanitized_mode(info.st_mode, "file"),
                    "size": size,
                    "sha256": digest,
                    "source": source,
                }
            )
        else:
            raise _fail("Recovery trees cannot contain links or special files.")

    walk(source_root, PurePosixPath("."))
    if len(plan) > MAX_ARCHIVE_ENTRIES or sum(
        item["size"] for item in plan if item["type"] == "file"
    ) > MAX_TOTAL_BYTES:
        raise _fail("A private recovery source exceeds the entry or size limit.")
    return plan


def _read_generation_receipt(path: Path, executor_tar: Path):
    receipt = _read_json(path)
    expected_keys = {
        "schema_version",
        "capture_kind",
        "executor_sha256",
        "identity_preserved",
        "single_tunnel",
        "generation",
    }
    if not expected_keys.issubset(receipt) or type(receipt["schema_version"]) is not int or receipt["schema_version"] not in (1, 2):
        raise _fail("The capture receipt has an unsupported schema.")
    if receipt["schema_version"] == 2:
        _validate_memoryd_descriptor(receipt.get("memoryd"))
    if not isinstance(receipt["capture_kind"], str) or not receipt["capture_kind"]:
        raise _fail("The capture receipt has no capture kind.")
    if not isinstance(receipt["executor_sha256"], str) or not SHA256.fullmatch(receipt["executor_sha256"]):
        raise _fail("The capture receipt has an invalid executor snapshot digest.")
    if receipt["identity_preserved"] is not True or receipt["single_tunnel"] is not True:
        raise _fail("The capture receipt does not prove preserved identity and one tunnel.")
    generation = receipt["generation"]
    if not isinstance(generation, dict) or set(generation) != {
        "authority",
        "source_sha",
        "manifest",
        "identity",
        "publication_proof",
    }:
        raise _fail("The capture receipt has an invalid generation record.")
    if not isinstance(generation["authority"], str) or not generation["authority"]:
        raise _fail("The generation record has no deployment authority.")
    if not isinstance(generation["identity"], str) or not generation["identity"]:
        raise _fail("The generation record has no preserved identity.")
    if not isinstance(generation["source_sha"], str) or not SOURCE_SHA.fullmatch(generation["source_sha"]):
        raise _fail("The generation record has an invalid source revision.")
    manifest = generation["manifest"]
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"images", "version"}
        or type(manifest["version"]) is not int
        or manifest["version"] != 1
        or not isinstance(manifest["images"], dict)
        or not manifest["images"]
    ):
        raise _fail("The generation record has no valid image manifest.")
    proof = generation["publication_proof"]
    if not isinstance(proof, dict) or set(proof) != {"cas", "schema_proxy"}:
        raise _fail("The generation record has incomplete publication proofs.")
    _, _, actual_executor_sha = _hash_regular_file(executor_tar, allowed_modes={0o600})
    if actual_executor_sha != receipt["executor_sha256"]:
        raise _fail("The executor archive does not match the capture receipt.")
    return receipt


def _parse_sqlite_manifest(path: Path, *, expected_archive_manifest: dict | None = None):
    manifest = _read_json(path)
    if set(manifest) != {"schema_version", "databases"} or type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise _fail("The CAS snapshot manifest has an unsupported schema.")
    databases = manifest["databases"]
    if not isinstance(databases, list) or not databases or len(databases) > 128:
        raise _fail("The CAS snapshot manifest must map at least one database.")
    relative_paths = set()
    snapshots = set()
    for item in databases:
        if not isinstance(item, dict) or set(item) != {"relative_path", "snapshot"}:
            raise _fail("The CAS snapshot mapping has an invalid schema.")
        relative = item["relative_path"]
        snapshot = item["snapshot"]
        pathspec = _safe_relative(relative)
        snapshot_path = _safe_relative(snapshot) if isinstance(snapshot, str) else None
        if (
            not relative.startswith("cas/runtime/")
            or len(pathspec.parts) < 3
            or not relative.endswith(".db")
            or not isinstance(snapshot, str)
            or snapshot_path is None
            or len(snapshot_path.parts) != 1
            or not snapshot.endswith(".db")
        ):
            raise _fail("The CAS snapshot mapping contains an unsafe database path.")
        if relative in relative_paths or snapshot in snapshots:
            raise _fail("The CAS snapshot mapping contains duplicates.")
        relative_paths.add(relative)
        snapshots.add(snapshot)
    if expected_archive_manifest is not None and manifest != expected_archive_manifest:
        raise _fail("The VM archive and snapshot inputs disagree on CAS database mapping.")
    return manifest


def _validate_sqlite(path: Path):
    try:
        uri = path.as_uri() + "?mode=ro&immutable=1"
        database = sqlite3.connect(uri, uri=True)
        try:
            rows = database.execute("PRAGMA integrity_check").fetchall()
        finally:
            database.close()
    except (sqlite3.Error, OSError):
        raise _fail("A CAS database snapshot failed read-only SQLite validation.") from None
    if rows != [("ok",)]:
        raise _fail("A CAS database snapshot failed read-only SQLite integrity_check.")


def _validate_memoryd_descriptor(value):
    if not isinstance(value, dict):
        raise _fail("The MemoryD capture descriptor is invalid.")
    if value == {"status": "absent"}:
        return
    keys = {
        "status", "backend_image", "adapter_image", "adapter_sha256", "backup_sha256",
        "backup_manifest_sha256", "backup_size_bytes", "source_instance_id", "record_count",
        "active_record_count", "archived_record_count", "profile", "workspace", "captured_at",
    }
    if (set(value) != keys or value.get("status") != "captured"
            or value.get("backend_image") != MEMORYD_IMAGE
            or not isinstance(value.get("adapter_image"), str)
            or not MEMORYD_ADAPTER_IMAGE.fullmatch(value["adapter_image"])
            or any(not isinstance(value.get(key), str) or not SHA256.fullmatch(value[key])
                   for key in ("adapter_sha256", "backup_sha256", "backup_manifest_sha256"))
            or type(value.get("backup_size_bytes")) is not int
            or not 0 < value["backup_size_bytes"] <= MAX_FILE_BYTES
            or not isinstance(value.get("source_instance_id"), str)
            or not re.fullmatch(r"cmi_[a-f0-9]{32}", value["source_instance_id"])
            or any(type(value.get(key)) is not int or value[key] < 0
                   for key in ("record_count", "active_record_count", "archived_record_count"))
            or value["record_count"] != value["active_record_count"] + value["archived_record_count"]
            or value.get("profile") != "personal" or value.get("workspace") != "dakota-codex-only"):
        raise _fail("The MemoryD capture descriptor is invalid.")
    try:
        timestamp = value["captured_at"]
        if not isinstance(timestamp, str) or len(timestamp) > 64:
            raise ValueError
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError
    except (KeyError, ValueError, TypeError):
        raise _fail("The MemoryD backup timestamp is invalid.") from None


def _memoryd_pin(descriptor):
    return {"schema_version": 1, "image": descriptor["adapter_image"],
            "adapter_sha256": descriptor["adapter_sha256"]}


def _matches_memoryd_pin(value, descriptor):
    return (isinstance(value, dict) and type(value.get("schema_version")) is int
            and value == _memoryd_pin(descriptor))


def _memoryd_scope(database, descriptor):
    tables = database.execute(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*'"
    ).fetchall()
    names = {row[0] for row in tables}
    if not {"profiles", "workspaces"}.issubset(names):
        raise _fail("MemoryD backup scope catalogs are missing.")
    for (table,) in tables:
        identifier = '"' + table.replace('"', '""') + '"'
        if table.lower() in {"sessions", "visible_turns"}:
            if database.execute(f"SELECT 1 FROM {identifier} LIMIT 1").fetchone() is not None:
                raise _fail("MemoryD backup contains session history.")
        columns = {row[0].lower(): row[0] for row in database.execute(
            "SELECT name FROM pragma_table_xinfo(?)", (table,)
        )}
        # SQLite and FTS bookkeeping without scope columns carries no scope to
        # validate. A NULL policy-event scope is not proof of a global event.
        checks = {"profile_id": descriptor["profile"], "workspace_id": descriptor["workspace"]}
        if table == "profiles":
            checks["id"] = descriptor["profile"]
        elif table == "workspaces":
            checks["id"] = descriptor["workspace"]
        if table in {"profiles", "workspaces"} and "id" not in columns:
            raise _fail("MemoryD backup scope catalogs are invalid.")
        if table == "workspaces" and "profile_id" not in columns:
            raise _fail("MemoryD backup workspace catalog has no profile binding.")
        for column, expected in checks.items():
            if column not in columns:
                continue
            quoted = '"' + columns[column].replace('"', '""') + '"'
            query = (f"SELECT 1 FROM {identifier} WHERE {quoted} IS NULL "
                     f"OR typeof({quoted}) != 'text' OR {quoted} COLLATE BINARY != ? LIMIT 1")
            if database.execute(query, (expected,)).fetchone() is not None:
                raise _fail("MemoryD backup contains missing or out-of-scope data.")


def _memoryd_database(path: Path, descriptor: dict, manifest: dict):
    try:
        database = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)
        try:
            if database.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise _fail("MemoryD backup integrity validation failed.")
            versions = database.execute("SELECT value FROM schema_meta WHERE key = 'schema_version'").fetchall()
            instances = database.execute("SELECT singleton_key, instance_id FROM instance_metadata").fetchall()
            if versions != [("13",)] or instances != [("default", descriptor["source_instance_id"])]:
                raise _fail("MemoryD backup schema or instance identity does not match its capture.")
            _memoryd_scope(database, descriptor)
            actual = {name: database.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0]
                      for name in MEMORYD_TABLES}
            active = database.execute(
                "SELECT count(*) FROM memory_records WHERE profile_id=? AND workspace_id=? AND archived=0",
                (descriptor["profile"], descriptor["workspace"]),
            ).fetchone()[0]
            archived = database.execute(
                "SELECT count(*) FROM memory_records WHERE profile_id=? AND workspace_id=? AND archived=1",
                (descriptor["profile"], descriptor["workspace"]),
            ).fetchone()[0]
        finally:
            database.close()
    except GenerationError:
        raise
    except (sqlite3.Error, OSError):
        raise _fail("MemoryD backup could not be validated read-only.") from None
    expected = {item["table"]: item["rows"] for item in manifest["tables"]}
    if (actual != expected or actual["memory_records"] != descriptor["record_count"]
            or active != descriptor["active_record_count"]
            or archived != descriptor["archived_record_count"]
            or active + archived != actual["memory_records"]):
        raise _fail("MemoryD backup counts or scope do not match its capture.")


def _validate_memoryd_payload(backup_dir: Path, adapter_dir: Path, descriptor: dict, *, source: bool):
    _validate_memoryd_descriptor(descriptor)
    if descriptor["status"] != "captured":
        raise _fail("MemoryD backup data is not claimed by the capture.")
    _private_directory(backup_dir)
    _private_directory(adapter_dir)
    expected_backup = {"backup.db", "backup.db.manifest.json"} | ({"adapter"} if source else set())
    if ({child.name for child in backup_dir.iterdir()} != expected_backup
            or {child.name for child in adapter_dir.iterdir()} != {"codex_memoryd_mcp.py", "artifact.json"}):
        raise _fail("The MemoryD backup or adapter inventory is incomplete or unexpected.")
    backup = backup_dir / "backup.db"
    sidecar = backup_dir / "backup.db.manifest.json"
    artifact = adapter_dir / "codex_memoryd_mcp.py"
    artifact_receipt = adapter_dir / "artifact.json"
    _, backup_size, backup_hash = _hash_regular_file(backup, allowed_modes={0o600})
    _, _, sidecar_hash = _hash_regular_file(sidecar, allowed_modes={0o600})
    _, adapter_size, adapter_hash = _hash_regular_file(artifact, allowed_modes={0o600})
    _hash_regular_file(artifact_receipt, allowed_modes={0o600})
    if (backup_size != descriptor["backup_size_bytes"] or backup_hash != descriptor["backup_sha256"]
            or sidecar_hash != descriptor["backup_manifest_sha256"]
            or adapter_hash != descriptor["adapter_sha256"] or not 0 < adapter_size <= 1024 * 1024):
        raise _fail("MemoryD backup or adapter digests do not match the capture.")
    artifact_info = _read_json(artifact_receipt)
    if (set(artifact_info) != {"adapter_sha256", "size_bytes", "controller_sha"}
            or artifact_info["adapter_sha256"] != adapter_hash
            or type(artifact_info["size_bytes"]) is not int or artifact_info["size_bytes"] != adapter_size
            or not isinstance(artifact_info["controller_sha"], str)
            or not SOURCE_SHA.fullmatch(artifact_info["controller_sha"])):
        raise _fail("MemoryD adapter receipt does not match the captured artifact.")
    manifest = _read_json(sidecar)
    expected_fields = {"manifest_version", "tool_version", "created_at", "database_file", "sha256",
                       "size_bytes", "schema_version", "expected_schema_version", "tables"}
    tables = manifest.get("tables")
    if (set(manifest) != expected_fields or type(manifest.get("manifest_version")) is not int
            or manifest["manifest_version"] != 1 or manifest.get("tool_version") != "0.1.0"
            or manifest.get("created_at") != descriptor["captured_at"]
            or manifest.get("database_file") != "backup.db"
            or manifest.get("sha256") != "sha256:" + backup_hash
            or type(manifest.get("size_bytes")) is not int or manifest["size_bytes"] != backup_size
            or type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 13
            or type(manifest.get("expected_schema_version")) is not int or manifest["expected_schema_version"] != 13
            or not isinstance(tables, list) or len(tables) != len(MEMORYD_TABLES)):
        raise _fail("The MemoryD backup manifest is invalid.")
    if (any(not isinstance(item, dict) or set(item) != {"table", "rows"}
            or not isinstance(item.get("table"), str) or type(item.get("rows")) is not int
            or item["rows"] < 0 for item in tables)
            or {item["table"] for item in tables} != set(MEMORYD_TABLES)):
        raise _fail("The MemoryD backup manifest table counts are invalid.")
    _memoryd_database(backup, descriptor, manifest)
    # SQLite validation runs immutable and the original snapshot must remain unchanged.
    if _hash_regular_file(backup, allowed_modes={0o600})[2] != backup_hash:
        raise _fail("The MemoryD backup changed during validation.")


def _archive_json(archive_path: Path, entry: ArchiveEntry):
    if entry.kind != "file" or entry.size > MAX_JSON_BYTES:
        raise _fail("The captured MemoryD adapter pin is invalid.")
    try:
        with tarfile.open(archive_path, "r:") as archive:
            member = archive.getmember(entry.archive_path)
            if not member.isfile() or stat.S_IMODE(member.mode) != 0o600:
                raise ValueError
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError
            body = stream.read(MAX_JSON_BYTES + 1)
        if len(body) != entry.size or hashlib.sha256(body).hexdigest() != entry.sha256:
            raise ValueError
        value = json.loads(body, object_pairs_hook=_no_duplicate_keys)
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (OSError, tarfile.TarError, KeyError, ValueError, UnicodeDecodeError):
        raise _fail("The captured MemoryD adapter pin is invalid.") from None


def _add_plan(plan: dict[str, dict], entry: dict):
    path = _safe_relative(entry["path"]).as_posix()
    entry["path"] = path
    if path in plan:
        if entry["type"] == plan[path]["type"] == "directory":
            return
        raise _fail("Recovery inputs collide at a destination path.")
    plan[path] = entry


def _plan_archive(entries: dict[str, ArchiveEntry], archive_path: Path, *, kind: str, plan: dict):
    if kind == "executor":
        root_name = "data"
        root_entry = entries.get(root_name)
        if root_entry is None or root_entry.kind != "directory":
            raise _fail("The executor snapshot must contain one data/ root.")
        for raw_path, item in entries.items():
            if raw_path != root_name and not raw_path.startswith(root_name + "/"):
                raise _fail("The executor snapshot contains files outside data/.")
            relative = PurePosixPath(raw_path).relative_to(PurePosixPath(root_name))
            target = PurePosixPath("executor-data") / relative
            if relative == PurePosixPath("."):
                target = PurePosixPath("executor-data")
            entry = {
                "path": target.as_posix(),
                "type": item.kind,
                "mode": item.mode,
                "size": item.size,
                "sha256": item.sha256,
                "archive_source": (archive_path, item.archive_path),
            }
            _add_plan(plan, entry)
    else:
        for raw_path, item in entries.items():
            raw = PurePosixPath(raw_path)
            if raw.parts[0] == "cas-databases":
                continue
            if raw_path == "compose.env":
                target = PurePosixPath("vm.env")
            elif raw.parts[0] == "native-ssh":
                target = raw
            else:
                target = PurePosixPath("state") / raw
            entry = {
                "path": target.as_posix(),
                "type": item.kind,
                "mode": item.mode,
                "size": item.size,
                "sha256": item.sha256,
                "archive_source": (archive_path, item.archive_path),
            }
            _add_plan(plan, entry)


def _plan_source_tree(plan: dict[str, dict], source_root: Path, target_root: str):
    for entry in _scan_source_tree(source_root, target_root):
        _add_plan(plan, entry)


def _scan_input(restored_dir: Path):
    _private_directory(restored_dir)
    try:
        names = {child.name for child in restored_dir.iterdir()}
    except OSError:
        raise _fail("The collector-produced restore stage cannot be read.") from None
    if names != TOP_LEVEL:
        raise _fail("The restore stage is missing required logical members or contains unknown members.")
    for name in ("native-endpoint", "instance-config", "operator-ssh", "vm-snapshot"):
        _private_directory(restored_dir / name)
    for logical, required in REQUIRED_INPUTS.items():
        source_root = restored_dir / logical
        found = {entry["path"].removeprefix(f"recovery-inputs/{logical}/") for entry in _scan_source_tree(source_root, f"recovery-inputs/{logical}") if entry["type"] == "file"}
        if not required.issubset(found):
            raise _fail("A required private recovery profile or native credential is missing.")
    snapshot_root = restored_dir / "vm-snapshot"
    snapshot_names = {child.name for child in snapshot_root.iterdir()}
    required_snapshot = {"executor.tar", "essential.tar", "cas-databases"}
    cas_dir = snapshot_root / "cas-databases"
    _private_directory(cas_dir)
    executor_tar = snapshot_root / "executor.tar"
    essential_tar = snapshot_root / "essential.tar"
    _hash_regular_file(executor_tar, allowed_modes={0o600})
    _hash_regular_file(essential_tar, allowed_modes={0o600})
    receipt_path = restored_dir / "capture-receipt"
    receipt = _read_generation_receipt(receipt_path, executor_tar)
    memoryd = receipt.get("memoryd") if receipt["schema_version"] == 2 else None
    if memoryd and memoryd["status"] == "captured":
        required_snapshot.add("memoryd")
    if not required_snapshot.issubset(snapshot_names) or snapshot_names - required_snapshot - {"runtime-source.bundle"}:
        raise _fail("The VM snapshot is missing a required archive or contains unknown members.")
    source_bundle = snapshot_root / "runtime-source.bundle"
    if source_bundle.exists():
        _hash_regular_file(source_bundle, allowed_modes={0o600})
        try:
            checked = subprocess.run(
                ["git", "bundle", "list-heads", str(source_bundle)],
                capture_output=True, text=True, timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            raise _fail("The retained runtime source bundle cannot be verified.") from None
        if checked.returncode or checked.stdout.strip() != receipt["generation"]["source_sha"] + " HEAD":
            raise _fail("The retained runtime source bundle does not match the captured source revision.")
    executor_entries = _scan_tar(executor_tar)
    essential_entries = _scan_tar(essential_tar)
    if memoryd is not None:
        pin_entry = essential_entries.get("bootstrap/memoryd-adapter-image.json")
        if any(name == "memoryd-adapter" or name.startswith("memoryd-adapter/") for name in essential_entries):
            raise _fail("MemoryD adapter data must come from the captured artifact.")
        if memoryd["status"] == "captured":
            memoryd_root = snapshot_root / "memoryd"
            _validate_memoryd_payload(memoryd_root, memoryd_root / "adapter", memoryd, source=True)
            if pin_entry and not _matches_memoryd_pin(_archive_json(essential_tar, pin_entry), memoryd):
                raise _fail("The captured MemoryD adapter pin does not match its artifact.")
        elif pin_entry or "bootstrap/memoryd-integration.json" in essential_entries:
            raise _fail("An absent MemoryD capture contains registration or adapter state.")
    external_manifest_path = cas_dir / "manifest.json"
    manifest = _parse_sqlite_manifest(external_manifest_path)
    archive_manifest_entry = essential_entries.get("cas-databases/manifest.json")
    if archive_manifest_entry is None or archive_manifest_entry.kind != "file":
        raise _fail("The essential snapshot is missing its CAS mapping manifest.")
    if archive_manifest_entry.size > MAX_JSON_BYTES:
        raise _fail("The archived CAS mapping exceeds the size limit.")
    with tarfile.open(essential_tar, "r:") as archive:
        stream = archive.extractfile(archive_manifest_entry.archive_path)
        if stream is None:
            raise _fail("The essential snapshot CAS mapping is unreadable.")
        archived_bytes = stream.read(MAX_JSON_BYTES + 1)
        if len(archived_bytes) > MAX_JSON_BYTES:
            raise _fail("The archived CAS mapping exceeds the size limit.")
        archived_manifest = json.loads(archived_bytes, object_pairs_hook=_no_duplicate_keys)
    _parse_sqlite_manifest(external_manifest_path, expected_archive_manifest=archived_manifest)
    expected_cas_entries = {"cas-databases", "cas-databases/manifest.json"}
    sqlite_sources = {}
    for item in manifest["databases"]:
        snapshot_path = cas_dir / item["snapshot"]
        info, size, digest = _hash_regular_file(snapshot_path, allowed_modes={0o600})
        _validate_sqlite(snapshot_path)
        raw_path = f"cas-databases/{item['snapshot']}"
        archive_copy = essential_entries.get(raw_path)
        if archive_copy is None or archive_copy.kind != "file" or archive_copy.sha256 != digest or archive_copy.size != size:
            raise _fail("A CAS snapshot file does not match the essential archive copy.")
        expected_cas_entries.add(raw_path)
        sqlite_sources[item["relative_path"]] = (snapshot_path, size, digest)
    actual_snapshot_inputs = {child.name for child in cas_dir.iterdir()}
    expected_snapshot_inputs = {"manifest.json", *(item["snapshot"] for item in manifest["databases"])}
    if actual_snapshot_inputs != expected_snapshot_inputs:
        raise _fail("The CAS snapshot directory contains missing or unknown files.")
    actual_cas_entries = {
        name for name in essential_entries if name == "cas-databases" or name.startswith("cas-databases/")
    }
    if actual_cas_entries != expected_cas_entries:
        raise _fail("CAS snapshot archives contain missing or unknown files.")
    _required_archive_members(executor_entries, essential_entries)
    return {
        "receipt": receipt,
        "receipt_path": receipt_path,
        "executor_tar": executor_tar,
        "essential_tar": essential_tar,
        "executor_entries": executor_entries,
        "essential_entries": essential_entries,
        "cas_manifest_path": external_manifest_path,
        "cas_manifest": manifest,
        "sqlite_sources": sqlite_sources,
        "memoryd": memoryd,
    }


def _required_archive_members(executor_entries, essential_entries):
    executor_files = {name.removeprefix("data/") for name, entry in executor_entries.items() if entry.kind == "file"}
    if not REQUIRED_EXECUTOR_FILES.issubset(executor_files):
        raise _fail("The executor snapshot is missing required private state or credentials.")
    essential_files = {name for name, entry in essential_entries.items() if entry.kind == "file"}
    required = {"compose.env", *REQUIRED_STATE_FILES}
    required.update(f"native-ssh/{name}" for name in REQUIRED_NATIVE_SSH)
    if not required.issubset(essential_files):
        raise _fail("The essential snapshot is missing required private state or native credentials.")
    for directory in REQUIRED_STATE_DIRECTORIES:
        entry = essential_entries.get(directory)
        if entry is None or entry.kind != "directory" or not entry.archive_path:
            raise _fail("The essential snapshot is missing an explicitly captured state directory.")
    if not any(name.startswith("devsy-bridge/") for name in essential_files):
        raise _fail("The essential snapshot is missing Devsy bridge state.")


def _build_plan(restored_dir: Path, scanned: dict):
    plan = {}
    for root in ("executor-data", "state", "native-ssh"):
        _add_plan(plan, {"path": root, "type": "directory", "mode": 0o700, "size": 0})
    _plan_archive(scanned["executor_entries"], scanned["executor_tar"], kind="executor", plan=plan)
    _plan_archive(scanned["essential_entries"], scanned["essential_tar"], kind="essential", plan=plan)
    if "vm.env" not in plan or plan["vm.env"]["type"] != "file" or plan["vm.env"]["size"] == 0:
        raise _fail("The essential snapshot has no usable Compose environment file.")
    for relative_path, (source, size, digest) in scanned["sqlite_sources"].items():
        target = (PurePosixPath("state") / PurePosixPath(relative_path)).as_posix()
        if target in plan:
            raise _fail("A CAS snapshot collides with existing essential state.")
        _add_plan(plan, {
            "path": target,
            "type": "file",
            "mode": 0o600,
            "size": size,
            "sha256": digest,
            "source": source,
        })
        parent = PurePosixPath(target).parent
        while parent != PurePosixPath("."):
            directory = parent.as_posix()
            if directory not in plan:
                _add_plan(plan, {"path": directory, "type": "directory", "mode": 0o700, "size": 0})
            parent = parent.parent
    memoryd = scanned["memoryd"]
    if memoryd and memoryd["status"] == "captured":
        source = restored_dir / "vm-snapshot/memoryd"
        adapter_target = "state/memoryd-adapter/" + memoryd["adapter_sha256"]
        for directory in ("memoryd", "state/memoryd-adapter", adapter_target):
            _add_plan(plan, {"path": directory, "type": "directory", "mode": 0o700, "size": 0})
        for relative, target in (
            ("backup.db", "memoryd/backup.db"),
            ("backup.db.manifest.json", "memoryd/backup.db.manifest.json"),
            ("adapter/codex_memoryd_mcp.py", adapter_target + "/codex_memoryd_mcp.py"),
            ("adapter/artifact.json", adapter_target + "/artifact.json"),
        ):
            path = source / relative
            _, size, digest = _hash_regular_file(path, allowed_modes={0o600})
            _add_plan(plan, {"path": target, "type": "file", "mode": 0o600,
                             "size": size, "sha256": digest, "source": path})
        pin_path = "state/bootstrap/memoryd-adapter-image.json"
        if pin_path not in plan:
            pin_bytes = _json_bytes(_memoryd_pin(memoryd))
            _add_plan(plan, {"path": pin_path, "type": "file", "mode": 0o600,
                             "size": len(pin_bytes), "sha256": hashlib.sha256(pin_bytes).hexdigest(),
                             "bytes": pin_bytes})
    generation = scanned["receipt"]["generation"]
    generation_doc = {
        "schema_version": scanned["receipt"]["schema_version"],
        "capture_kind": scanned["receipt"]["capture_kind"],
        "executor_sha256": scanned["receipt"]["executor_sha256"],
        "identity_preserved": True,
        "single_tunnel": True,
        "generation": generation,
    }
    if memoryd is not None:
        generation_doc["memoryd"] = memoryd
    generation_bytes = _json_bytes(generation_doc)
    if len(generation_bytes) > MAX_JSON_BYTES:
        raise _fail("Generation metadata exceeds the size limit.")
    _add_plan(plan, {
        "path": "generation.json",
        "type": "file",
        "mode": 0o600,
        "size": len(generation_bytes),
        "sha256": hashlib.sha256(generation_bytes).hexdigest(),
        "bytes": generation_bytes,
    })
    if len(plan) > MAX_ARCHIVE_ENTRIES or sum(
        item["size"] for item in plan.values() if item["type"] == "file"
    ) > MAX_TOTAL_BYTES:
        raise _fail("Prepared generation exceeds the entry or storage limit.")
    return plan, generation_doc


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"


def _write_file(path: Path, source: BinaryIO, mode: int, expected_hash=None):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    digest = hashlib.sha256()
    size = 0
    with os.fdopen(fd, "wb") as destination:
        while block := source.read(1024 * 1024):
            destination.write(block)
            digest.update(block)
            size += len(block)
        destination.flush()
        os.fsync(destination.fileno())
    os.chmod(path, mode, follow_symlinks=False)
    if expected_hash is not None and digest.hexdigest() != expected_hash:
        raise _fail("A recovery source changed while the generation was prepared.")
    return size, digest.hexdigest()


def _write_plan_entry(output: Path, plan_entry: dict):
    target = output / PurePosixPath(plan_entry["path"])
    if plan_entry["type"] == "directory":
        target.mkdir(mode=0o700)
        os.chmod(target, 0o700, follow_symlinks=False)
        return
    if "bytes" in plan_entry:
        source = io.BytesIO(plan_entry["bytes"])
        size, digest = _write_file(target, source, plan_entry["mode"], plan_entry["sha256"])
    elif "archive_source" in plan_entry:
        archive_path, archive_name = plan_entry["archive_source"]
        try:
            with tarfile.open(archive_path, "r:") as archive:
                member = archive.getmember(archive_name)
                if not member.isfile():
                    raise _fail("A validated nested archive member changed type.")
                stream = archive.extractfile(member)
                if stream is None:
                    raise _fail("A validated nested archive member became unreadable.")
                with stream:
                    size, digest = _write_file(target, stream, plan_entry["mode"], plan_entry["sha256"])
        except GenerationError:
            raise
        except (OSError, tarfile.TarError, KeyError):
            raise _fail("A validated nested archive changed while preparing the generation.") from None
    else:
        source_path = plan_entry["source"]
        _, size, _ = _hash_regular_file(source_path)
        fd = os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as source:
            size, digest = _write_file(target, source, plan_entry["mode"], plan_entry["sha256"])
    if size != plan_entry["size"] or digest != plan_entry["sha256"]:
        raise _fail("A recovery source changed while the generation was prepared.")


def _scan_generation_tree(path: Path):
    _private_directory(path)
    rows = []
    total = 0

    def walk(current: Path, relative: PurePosixPath):
        nonlocal total
        try:
            info = current.lstat()
        except OSError:
            raise _fail("Prepared generation changed during validation.") from None
        if stat.S_ISDIR(info.st_mode):
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise _fail("Prepared generation directories must be private and operator-owned.")
            if relative.parts:
                rows.append({"path": relative.as_posix(), "type": "directory", "mode": 0o700, "size": 0})
            for child in sorted(current.iterdir(), key=lambda item: item.name):
                _safe_relative(child.name)
                walk(child, relative / child.name)
        elif stat.S_ISREG(info.st_mode):
            if info.st_uid != os.getuid() or info.st_nlink != 1:
                raise _fail("Prepared generation files must be private operator-owned files.")
            mode = stat.S_IMODE(info.st_mode)
            if mode not in INPUT_FILE_MODES:
                raise _fail("Prepared generation file mode is unsafe.")
            _, size, digest = _hash_regular_file(current)
            row = {"path": relative.as_posix(), "type": "file", "mode": mode, "size": size, "sha256": digest}
            rows.append(row)
            total += size
        else:
            raise _fail("Prepared generations cannot contain links or special files.")
        if len(rows) > MAX_ARCHIVE_ENTRIES or total > MAX_TOTAL_BYTES:
            raise _fail("Prepared generation exceeds the entry or storage limit.")

    try:
        walk(path, PurePosixPath("."))
    except GenerationError:
        raise
    except OSError:
        raise _fail("Prepared generation changed during validation.") from None
    return sorted(rows, key=lambda row: row["path"])


def _validate_generation_document(generation_doc: dict):
    expected_keys = {
        "schema_version",
        "capture_kind",
        "executor_sha256",
        "identity_preserved",
        "single_tunnel",
        "generation",
    }
    if generation_doc.get("schema_version") == 2:
        expected_keys.add("memoryd")
    if set(generation_doc) != expected_keys:
        raise _fail("generation.json has an unsupported schema.")
    _read_generation_receipt_from_value(generation_doc)


def _read_generation_receipt_from_value(receipt: dict):
    expected_keys = {
        "schema_version",
        "capture_kind",
        "executor_sha256",
        "identity_preserved",
        "single_tunnel",
        "generation",
    }
    if not expected_keys.issubset(receipt) or type(receipt["schema_version"]) is not int or receipt["schema_version"] not in (1, 2):
        raise _fail("The preserved capture receipt has an unsupported schema.")
    if receipt["schema_version"] == 2:
        _validate_memoryd_descriptor(receipt.get("memoryd"))
    if not isinstance(receipt["capture_kind"], str) or not receipt["capture_kind"]:
        raise _fail("The preserved capture receipt has no capture kind.")
    if not isinstance(receipt["executor_sha256"], str) or not SHA256.fullmatch(receipt["executor_sha256"]):
        raise _fail("The preserved capture receipt has an invalid executor digest.")
    if receipt["identity_preserved"] is not True or receipt["single_tunnel"] is not True:
        raise _fail("The preserved capture receipt does not prove safe identity state.")
    generation = receipt["generation"]
    if not isinstance(generation, dict) or set(generation) != {
        "authority",
        "source_sha",
        "manifest",
        "identity",
        "publication_proof",
    }:
        raise _fail("The preserved capture receipt has an invalid generation record.")
    if (
        not isinstance(generation["authority"], str)
        or not generation["authority"]
        or not isinstance(generation["identity"], str)
        or not generation["identity"]
        or not isinstance(generation["source_sha"], str)
        or not SOURCE_SHA.fullmatch(generation["source_sha"])
    ):
        raise _fail("The preserved generation record is incomplete.")
    manifest = generation["manifest"]
    proof = generation["publication_proof"]
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"images", "version"}
        or type(manifest["version"]) is not int
        or manifest["version"] != 1
        or not isinstance(manifest["images"], dict)
        or not manifest["images"]
        or not isinstance(proof, dict)
        or set(proof) != {"cas", "schema_proxy"}
    ):
        raise _fail("The preserved generation manifest or publication proofs are incomplete.")
    return receipt


def _validate_generation(path: Path) -> dict:
    """Verify the complete prepared payload and return its manifest contract."""
    path = Path(path)
    rows = _scan_generation_tree(path)
    manifest_path = path / "prepared-manifest.json"
    prepared = _read_json(manifest_path)
    expected_keys = {
        "schema_version",
        "generation_file",
        "generation",
        "expected_identity",
        "inventory",
    }
    if prepared.get("schema_version") == 2:
        expected_keys.add("memoryd")
    if set(prepared) != expected_keys:
        raise _fail("The prepared generation manifest has an unsupported schema.")
    if type(prepared["schema_version"]) is not int or prepared["schema_version"] not in (1, 2):
        raise _fail("The prepared generation manifest version is unsupported.")
    if prepared["generation_file"] != "generation.json":
        raise _fail("The prepared generation has an invalid generation metadata path.")
    generation_doc = _read_json(path / "generation.json")
    if (generation_doc.get("schema_version") != prepared["schema_version"]
            or prepared["generation"] != generation_doc.get("generation")
            or (prepared["schema_version"] == 2 and prepared["memoryd"] != generation_doc.get("memoryd"))):
        raise _fail("Prepared generation metadata does not match its manifest.")
    _validate_generation_document(generation_doc)
    if prepared["expected_identity"] != generation_doc["generation"].get("identity"):
        raise _fail("The prepared generation expected identity does not match its source record.")
    expected_inventory = prepared["inventory"]
    if not isinstance(expected_inventory, list) or not expected_inventory:
        raise _fail("The prepared generation inventory is missing.")
    seen_paths = set()
    for row in expected_inventory:
        if not isinstance(row, dict) or not isinstance(row.get("type"), str):
            raise _fail("The prepared generation inventory contains an invalid entry.")
        row_type = row["type"]
        expected_keys = {"path", "type", "mode", "size", "sha256"} if row_type == "file" else {"path", "type", "mode", "size"}
        if row_type not in {"file", "directory"} or set(row) != expected_keys:
            raise _fail("The prepared generation inventory contains an invalid entry.")
        if not isinstance(row.get("path"), str) or _safe_relative(row["path"]).as_posix() != row["path"]:
            raise _fail("The prepared generation inventory contains an unsafe path.")
        if row["path"] in seen_paths:
            raise _fail("The prepared generation inventory contains duplicate paths.")
        seen_paths.add(row["path"])
        if type(row.get("mode")) is not int or type(row.get("size")) is not int or row["size"] < 0:
            raise _fail("The prepared generation inventory contains invalid metadata.")
        if row_type == "directory" and (row["mode"] != 0o700 or row["size"] != 0):
            raise _fail("The prepared generation inventory contains an unsafe directory.")
        if row_type == "file" and (
            row["mode"] not in INPUT_FILE_MODES
            or row["size"] > MAX_FILE_BYTES
            or not isinstance(row.get("sha256"), str)
            or not SHA256.fullmatch(row["sha256"])
        ):
            raise _fail("The prepared generation inventory contains an unsafe file.")
    if expected_inventory != sorted(expected_inventory, key=lambda row: row.get("path", "")):
        raise _fail("The prepared generation inventory is not sorted.")
    actual_payload = [row for row in rows if row["path"] != "prepared-manifest.json"]
    if actual_payload != expected_inventory:
        raise _fail("Prepared generation paths, modes, sizes, or digests do not match the manifest.")
    required_top = {
        "executor-data",
        "state",
        "native-ssh",
        "vm.env",
        "generation.json",
    }
    if prepared["schema_version"] == 2 and prepared["memoryd"]["status"] == "captured":
        required_top.add("memoryd")
    actual_top = {row["path"].split("/", 1)[0] for row in actual_payload}
    if actual_top != required_top:
        raise _fail("The prepared generation has missing or unexpected top-level members.")
    expected_files = {
        *(f"state/{item}" for item in REQUIRED_STATE_FILES),
        *(f"native-ssh/{item}" for item in REQUIRED_NATIVE_SSH),
        *(f"executor-data/{item}" for item in REQUIRED_EXECUTOR_FILES),
        "vm.env",
    }
    actual_files = {row["path"] for row in actual_payload if row["type"] == "file"}
    if not expected_files.issubset(actual_files):
        raise _fail("The prepared generation is missing required state, secrets, or native credentials.")
    actual_directories = {row["path"] for row in actual_payload if row["type"] == "directory"}
    expected_directories = {f"state/{item}" for item in REQUIRED_STATE_DIRECTORIES}
    if not expected_directories.issubset(actual_directories):
        raise _fail("The prepared generation is missing required captured state directories.")
    row_index = {row["path"]: row for row in actual_payload}
    vm_env = row_index.get("vm.env")
    if vm_env is None or vm_env["type"] != "file" or vm_env["size"] == 0:
        raise _fail("The prepared generation has no usable VM environment file.")
    database_rows = [
        row
        for row in actual_payload
        if row["path"].startswith("state/cas/runtime/")
    ]
    database_files = [row for row in database_rows if row["type"] == "file"]
    if not database_files or any(not row["path"].endswith(".db") for row in database_files):
        raise _fail("Prepared state has no complete CAS SQLite database set.")
    for row in database_files:
        _validate_sqlite(path / row["path"])
    if prepared["schema_version"] == 2:
        memoryd = prepared["memoryd"]
        if memoryd["status"] == "captured":
            adapter_root = path / "state/memoryd-adapter"
            _private_directory(adapter_root)
            if {child.name for child in adapter_root.iterdir()} != {memoryd["adapter_sha256"]}:
                raise _fail("The prepared MemoryD adapter inventory is invalid.")
            _validate_memoryd_payload(path / "memoryd", adapter_root / memoryd["adapter_sha256"], memoryd, source=False)
            if not _matches_memoryd_pin(_read_json(path / "state/bootstrap/memoryd-adapter-image.json"), memoryd):
                raise _fail("The prepared MemoryD adapter pin does not match its artifact.")
        elif any(item in actual_files for item in (
            "state/bootstrap/memoryd-adapter-image.json", "state/bootstrap/memoryd-integration.json"
        )) or "state/memoryd-adapter" in actual_directories:
            raise _fail("An absent MemoryD generation contains registration or adapter state.")
    return prepared


def validate_generation(path: Path) -> dict:
    """Verify the prepared generation; return the validated manifest object."""
    try:
        return _validate_generation(Path(path))
    except GenerationError:
        raise
    except Exception:
        raise _fail("Prepared generation could not be validated.") from None


def _prepare_generation(restored_dir: Path, output_dir: Path) -> dict:
    """Prepare a new private generation without activating or starting any service."""
    restored_dir, output_dir = Path(restored_dir), Path(output_dir)
    scanned = _scan_input(restored_dir)
    parent = output_dir.parent
    _private_directory(parent)
    if output_dir.exists() or output_dir.is_symlink():
        raise _fail("Prepared generation output already exists.")
    plan, generation_doc = _build_plan(restored_dir, scanned)
    output_dir.mkdir(mode=0o700)
    info = output_dir.lstat()
    try:
        os.chmod(output_dir, 0o700, follow_symlinks=False)
        for plan_entry in sorted(
            plan.values(),
            key=lambda entry: (entry["path"].count("/"), entry["path"]),
        ):
            _write_plan_entry(output_dir, plan_entry)
        for relative_path in scanned["sqlite_sources"]:
            _validate_sqlite(output_dir / "state" / PurePosixPath(relative_path))
        inventory = _scan_generation_tree(output_dir)
        prepared = {
            "schema_version": generation_doc["schema_version"],
            "generation_file": "generation.json",
            "generation": generation_doc["generation"],
            "expected_identity": generation_doc["generation"]["identity"],
            "inventory": inventory,
        }
        if generation_doc["schema_version"] == 2:
            prepared["memoryd"] = generation_doc["memoryd"]
        body = _json_bytes(prepared)
        with io.BytesIO(body) as source:
            _write_file(output_dir / "prepared-manifest.json", source, 0o600, hashlib.sha256(body).hexdigest())
        directory_fd = os.open(output_dir, os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return validate_generation(output_dir)
    except Exception as error:
        try:
            current = output_dir.lstat()
            if stat.S_ISDIR(current.st_mode) and (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino):
                shutil.rmtree(output_dir)
        except OSError:
            pass
        if isinstance(error, GenerationError):
            raise
        raise _fail("Prepared generation failed; partial output was removed.") from None


def prepare_generation(restored_dir: Path, output_dir: Path) -> dict:
    """Prepare and validate a new private generation without activation."""
    try:
        return _prepare_generation(Path(restored_dir), Path(output_dir))
    except GenerationError:
        raise
    except Exception:
        raise _fail("Recovery generation could not be prepared.") from None


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--restored-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        prepare_generation(Path(args.restored_dir), Path(args.output_dir))
    except GenerationError as error:
        print(f"Generation refused: {error}", file=sys.stderr)
        return 2
    print("Private recovery generation prepared and validated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
