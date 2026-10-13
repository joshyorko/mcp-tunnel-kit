#!/usr/bin/env python3
"""Create age-encrypted recovery bundles and restore only into private staging."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import selectors
from dataclasses import dataclass
from typing import BinaryIO


MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 200_000
MAX_FILE_BYTES = 50 * 1024**3
MAX_TOTAL_BYTES = 100 * 1024**3
MAX_TAR_BYTES = MAX_TOTAL_BYTES + MAX_ARCHIVE_ENTRIES * 2048 + MAX_MANIFEST_BYTES + 1024**2
MEMBER_NAME = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")


class RecoveryError(Exception):
    """An expected recovery refusal with a diagnostic safe to display."""


@dataclass(frozen=True)
class SourceMember:
    name: str
    root: Path
    kind: str
    entries: tuple[dict, ...]


def _fail(message: str) -> RecoveryError:
    return RecoveryError(message)


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _read_json(path: Path, *, private: bool) -> dict:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise _fail("Recovery input must be an operator-owned regular file.")
        if private and stat.S_IMODE(info.st_mode) != 0o600:
            raise _fail("Recovery manifest must have mode 0600.")
        if info.st_size > MAX_MANIFEST_BYTES:
            raise _fail("Recovery manifest exceeds the size limit.")
        with path.open("rb") as handle:
            value = json.load(handle, object_pairs_hook=_no_duplicate_keys)
    except RecoveryError:
        raise
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        raise _fail("Recovery input is unreadable or malformed.") from None
    if not isinstance(value, dict):
        raise _fail("Recovery input must be a JSON object.")
    return value


def _safe_parent(path: Path) -> Path:
    parent = path.parent
    try:
        info = parent.lstat()
    except OSError:
        raise _fail("Recovery destination parent must already exist privately.") from None
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise _fail("Recovery destination parent must be an operator-owned mode-0700 directory.")
    try:
        if parent.resolve(strict=True) != parent.absolute():
            raise _fail("Recovery destination paths cannot traverse symlinks.")
    except OSError:
        raise _fail("Recovery destination parent is unavailable.") from None
    return parent


def _read_manifest(path: Path) -> dict:
    manifest = _read_json(path, private=True)
    if set(manifest) != {"version", "bundle_id", "members"} or manifest["version"] != 1:
        raise _fail("Recovery manifest has an unsupported schema.")
    if (
        not isinstance(manifest["bundle_id"], str)
        or not manifest["bundle_id"]
        or len(manifest["bundle_id"]) > 128
        or any(ord(char) < 32 for char in manifest["bundle_id"])
    ):
        raise _fail("Recovery manifest has an invalid bundle identifier.")
    members = manifest["members"]
    if not isinstance(members, list) or not members or len(members) > 1024:
        raise _fail("Recovery manifest must name at least one bounded source member.")
    names = set()
    normalized = []
    for member in members:
        if not isinstance(member, dict) or set(member) != {"name", "source", "required"}:
            raise _fail("Recovery manifest member has an invalid schema.")
        name = member["name"]
        source = member["source"]
        if not isinstance(name, str) or not MEMBER_NAME.fullmatch(name) or name in names:
            raise _fail("Recovery manifest contains an invalid or duplicate member label.")
        if not isinstance(source, str) or not os.path.isabs(source):
            raise _fail("Recovery manifest sources must be explicit absolute paths.")
        if member["required"] is not True:
            raise _fail("Every declared recovery source must be required.")
        names.add(name)
        normalized.append({"name": name, "source": Path(source), "required": True})
    manifest["members"] = normalized
    return manifest


def _identity_stat(identity: Path | None):
    if identity is None:
        return None
    try:
        info = identity.lstat()
    except OSError:
        raise _fail("The excluded recovery identity is unavailable.") from None
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise _fail("The excluded recovery identity must be an operator-owned regular file.")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise _fail("The excluded recovery identity must have mode 0600.")
    return info


def _hash_file(path: Path):
    digest = hashlib.sha256()
    size = 0
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            os.close(fd)
            raise _fail("A recovery source changed during inspection.")
        with os.fdopen(fd, "rb") as handle:
            while block := handle.read(1024 * 1024):
                size += len(block)
                if size > MAX_FILE_BYTES:
                    raise _fail("A recovery source exceeds the per-file size limit.")
                digest.update(block)
    except RecoveryError:
        raise
    except OSError:
        raise _fail("A recovery source could not be read safely.") from None
    return digest.hexdigest(), size


def _walk_source(name: str, source: Path, identity_info, manifest_info=None) -> SourceMember:
    try:
        if source.resolve(strict=True) != source.absolute():
            raise _fail("Recovery source paths cannot traverse symlinks.")
        root_info = source.lstat()
    except RecoveryError:
        raise
    except OSError:
        raise _fail("A required recovery source is missing or unreadable.") from None
    if stat.S_ISLNK(root_info.st_mode) or root_info.st_uid != os.getuid():
        raise _fail("Recovery sources must be non-symlink paths owned by the operator.")
    if not (stat.S_ISREG(root_info.st_mode) or stat.S_ISDIR(root_info.st_mode)):
        raise _fail("Recovery sources must be regular files or directories.")
    if identity_info and (root_info.st_dev, root_info.st_ino) == (
        identity_info.st_dev,
        identity_info.st_ino,
    ):
        raise _fail("The excluded recovery identity overlaps a declared source.")
    if manifest_info and (root_info.st_dev, root_info.st_ino) == (
        manifest_info.st_dev,
        manifest_info.st_ino,
    ):
        raise _fail("The external recovery manifest overlaps a declared source.")
    kind = "directory" if stat.S_ISDIR(root_info.st_mode) else "file"
    root = PurePosixPath("payload") / name
    entries = []

    def add(path: Path, archive_path: PurePosixPath):
        try:
            info = path.lstat()
        except OSError:
            raise _fail("A recovery source changed or became unavailable during inspection.") from None
        if stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid():
            raise _fail("Recovery source trees must contain only operator-owned regular files and directories.")
        if identity_info and (info.st_dev, info.st_ino) == (
            identity_info.st_dev,
            identity_info.st_ino,
        ):
            raise _fail("The excluded recovery identity overlaps a declared source.")
        if manifest_info and (info.st_dev, info.st_ino) == (
            manifest_info.st_dev,
            manifest_info.st_ino,
        ):
            raise _fail("The external recovery manifest overlaps a declared source.")
        label = archive_path.as_posix()
        if stat.S_ISDIR(info.st_mode):
            entries.append({"path": label, "type": "directory", "mode": 0o700, "size": 0})
            try:
                children = sorted(path.iterdir(), key=lambda child: child.name)
            except OSError:
                raise _fail("A recovery source directory could not be read safely.") from None
            for child in children:
                if (
                    child.name in {".", ".."}
                    or "/" in child.name
                    or "\\" in child.name
                    or any(ord(char) < 32 for char in child.name)
                ):
                    raise _fail("A recovery source contains an unsafe filename.")
                add(child, archive_path / child.name)
            try:
                after = path.lstat()
            except OSError:
                raise _fail("A recovery source changed during inspection.") from None
            if (after.st_dev, after.st_ino) != (info.st_dev, info.st_ino):
                raise _fail("A recovery source changed during inspection.")
        elif stat.S_ISREG(info.st_mode):
            digest, size = _hash_file(path)
            mode = 0o700 if info.st_mode & 0o111 else 0o600
            entries.append(
                {"path": label, "type": "file", "mode": mode, "size": size, "sha256": digest}
            )
        else:
            raise _fail("Recovery source trees cannot contain links or special files.")

    add(source, root)
    return SourceMember(name, source, kind, tuple(entries))


def prepare_sources(
    manifest: dict,
    *,
    exclude_identity: str | Path | None = None,
    exclude_manifest: str | Path | None = None,
) -> list[SourceMember]:
    """Validate sources and return a stable logical inventory for export."""
    identity = Path(exclude_identity) if exclude_identity is not None else None
    identity_info = _identity_stat(identity)
    manifest_info = _private_input_file(Path(exclude_manifest), mode=0o600) if exclude_manifest is not None else None
    members = []
    for item in manifest.get("members", []):
        source = Path(item["source"])
        if identity is not None:
            try:
                # A key nested below a declared directory is excluded even when hardlinks differ.
                identity_resolved = identity.resolve(strict=True)
                source_resolved = source.resolve(strict=True)
                if source_resolved.is_dir() and identity_resolved.is_relative_to(source_resolved):
                    raise _fail("The excluded recovery identity overlaps a declared source.")
            except RecoveryError:
                raise
            except OSError:
                raise _fail("A recovery source or excluded identity is unavailable.") from None
        if exclude_manifest is not None:
            try:
                manifest_resolved = Path(exclude_manifest).resolve(strict=True)
                source_resolved = source.resolve(strict=True)
                if source_resolved.is_dir() and manifest_resolved.is_relative_to(source_resolved):
                    raise _fail("The external recovery manifest overlaps a declared source.")
            except RecoveryError:
                raise
            except OSError:
                raise _fail("A recovery source or external manifest is unavailable.") from None
        members.append(_walk_source(item["name"], source, identity_info, manifest_info))
    entries = [entry for member in members for entry in member.entries]
    if len(entries) > MAX_ARCHIVE_ENTRIES - 1:
        raise _fail("Recovery source inventory exceeds the entry limit.")
    if sum(entry["size"] for entry in entries) > MAX_TOTAL_BYTES:
        raise _fail("Recovery sources exceed the expanded size limit.")
    return members


def _source_open(path: Path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise _fail("A recovery source could not be reopened safely.") from None
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        os.close(fd)
        raise _fail("A recovery source changed during export.")
    return os.fdopen(fd, "rb")


def _archive_add(handle: tarfile.TarFile, member: SourceMember, entry: dict):
    relative = PurePosixPath(entry["path"]).relative_to(PurePosixPath("payload") / member.name)
    path = member.root.joinpath(*relative.parts)
    info = tarfile.TarInfo(entry["path"])
    info.mode = entry["mode"]
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    if entry["type"] == "directory":
        info.type = tarfile.DIRTYPE
        info.size = 0
        handle.addfile(info)
        return
    info.type = tarfile.REGTYPE
    info.size = entry["size"]
    digest = hashlib.sha256()
    copied = 0
    with _source_open(path) as source:
        source_info = os.fstat(source.fileno())
        info.size = source_info.st_size
        source_mode = 0o700 if source_info.st_mode & 0o111 else 0o600
        if info.size != entry["size"] or source_mode != entry["mode"]:
            raise _fail("A recovery source changed during export.")

        class CheckedReader:
            def read(self, size=-1):
                nonlocal copied
                block = source.read(size)
                copied += len(block)
                digest.update(block)
                return block

        handle.addfile(info, CheckedReader())
    if copied != entry["size"] or digest.hexdigest() != entry["sha256"]:
        raise _fail("A recovery source changed during export.")


def _write_archive(handle: BinaryIO, members: list[SourceMember], bundle_id: str):
    entries = [entry for member in members for entry in member.entries]
    internal = {
        "version": 1,
        "bundle_id": bundle_id,
        "members": [
            {
                "name": member.name,
                "kind": member.kind,
                "entries": [entry["path"] for entry in member.entries],
            }
            for member in members
        ],
        "entries": entries,
    }
    manifest_bytes = json.dumps(internal, sort_keys=True, separators=(",", ":")).encode()
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise _fail("Recovery inventory exceeds the manifest size limit.")
    with tarfile.open(fileobj=handle, mode="w|", format=tarfile.PAX_FORMAT) as tar:
        for member in members:
            for entry in member.entries:
                _archive_add(tar, member, entry)
        info = tarfile.TarInfo("recovery-manifest.json")
        info.mode, info.uid, info.gid, info.mtime = 0o600, 0, 0, 0
        info.size = len(manifest_bytes)
        tar.addfile(info, io.BytesIO(manifest_bytes))


def _age_executable(age_bin: str | Path):
    path = Path(age_bin)
    if not path.is_absolute() and path.parent == Path("."):
        located = shutil.which(str(path))
        if located:
            path = Path(located)
    try:
        path = path.resolve(strict=True)
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
            raise _fail("The configured age executable is unavailable.")
    except OSError:
        raise _fail("The configured age executable is unavailable.") from None
    return str(path)


def recipient_from_identity(identity: str | Path, *, age_keygen_bin="age-keygen") -> str:
    executable = _age_executable(age_keygen_bin)
    info = _identity_stat(Path(identity))
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise _fail("The recovery identity must have mode 0600.")
    try:
        result = subprocess.run(
            [executable, "-y", str(identity)],
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise _fail("The age identity could not be checked.") from None
    if result.returncode != 0:
        raise _fail("The age identity could not be checked.")
    recipient = result.stdout.strip()
    if not recipient.startswith("age1") or len(recipient) > 256:
        raise _fail("The age identity did not produce a valid recipient.")
    return recipient


def _private_input_file(path: Path, *, mode: int | None = None):
    try:
        info = path.lstat()
    except OSError:
        raise _fail("A required recovery input is unavailable.") from None
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise _fail("Recovery inputs must be operator-owned regular files.")
    if mode is not None and stat.S_IMODE(info.st_mode) != mode:
        raise _fail(f"Recovery input must have mode {mode:04o}.")
    return info


def _check_recipient_file(path: Path, identity_info):
    info = _private_input_file(path)
    if identity_info and (info.st_dev, info.st_ino) == (identity_info.st_dev, identity_info.st_ino):
        raise _fail("Recipient input must not be the excluded recovery identity.")
    if info.st_size > 64 * 1024:
        raise _fail("Recipient input exceeds the size limit.")


def export_bundle(
    manifest_path: str | Path,
    recipient_file: str | Path,
    output: str | Path,
    *,
    age_bin="age",
    exclude_identity: str | Path | None = None,
):
    manifest_path, recipient_file, output = Path(manifest_path), Path(recipient_file), Path(output)
    manifest = _read_manifest(manifest_path)
    output_parent = _safe_parent(output)
    if output.exists() or output.is_symlink():
        raise _fail("Encrypted recovery output already exists.")
    identity_info = _identity_stat(Path(exclude_identity)) if exclude_identity else None
    _check_recipient_file(recipient_file, identity_info)
    members = prepare_sources(
        manifest,
        exclude_identity=exclude_identity,
        exclude_manifest=manifest_path,
    )
    executable = _age_executable(age_bin)
    fd, temporary_name = tempfile.mkstemp(prefix=".recovery-", dir=output_parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as encrypted:
            try:
                process = subprocess.Popen(
                    [executable, "-R", str(recipient_file)],
                    stdin=subprocess.PIPE,
                    stdout=encrypted,
                    stderr=subprocess.DEVNULL,
                )
            except OSError:
                raise _fail("The age encryption process could not be started.") from None
            try:
                assert process.stdin is not None
                _write_archive(process.stdin, members, manifest["bundle_id"])
                process.stdin.close()
                status = process.wait(timeout=3600)
            except Exception:
                if process.poll() is None:
                    process.kill()
                process.wait()
                raise
            if status != 0:
                raise _fail("Age encryption failed; no bundle was published.")
            encrypted.flush()
            os.fsync(encrypted.fileno())
        try:
            os.link(temporary, output, follow_symlinks=False)
        except FileExistsError:
            raise _fail("Encrypted recovery output already exists.") from None
        except OSError:
            raise _fail("Encrypted recovery output could not be published safely.") from None
        directory_fd = os.open(output_parent, os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except RecoveryError:
        raise
    except Exception:
        raise _fail("Recovery export failed; no plaintext bundle was published.") from None
    finally:
        temporary.unlink(missing_ok=True)
    return output


def _validated_manifest(tar: tarfile.TarFile):
    seen = set()
    members_by_path = {}
    manifest_member = None
    total = 0
    count = 0
    for member in tar:
        count += 1
        if count > MAX_ARCHIVE_ENTRIES:
            raise _fail("Recovery archive exceeds the entry limit.")
        name = member.name
        if not isinstance(name, str) or "\\" in name or any(ord(char) < 32 for char in name):
            raise _fail("Recovery archive contains an unsafe path.")
        if "//" in name or name.endswith("/"):
            raise _fail("Recovery archive contains an unsafe path.")
        path = PurePosixPath(name)
        if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
            raise _fail("Recovery archive contains an unsafe path.")
        if name in seen:
            raise _fail("Recovery archive contains duplicate paths.")
        seen.add(name)
        if name == "recovery-manifest.json":
            if (
                not member.isfile()
                or member.size > MAX_MANIFEST_BYTES
                or stat.S_IMODE(member.mode) != 0o600
                or member.uid != 0
                or member.gid != 0
            ):
                raise _fail("Recovery archive inventory is invalid.")
            manifest_member = member
            continue
        if not name.startswith("payload/"):
            raise _fail("Recovery archive contains an unknown member.")
        if not (member.isfile() or member.isdir()):
            raise _fail("Recovery archive contains a link or special file.")
        if member.uid != 0 or member.gid != 0:
            raise _fail("Recovery archive contains untrusted ownership metadata.")
        if member.isdir() and member.size != 0:
            raise _fail("Recovery archive contains an invalid directory entry.")
        if member.isfile() and (member.size < 0 or member.size > MAX_FILE_BYTES):
            raise _fail("Recovery archive contains an oversized file.")
        mode = stat.S_IMODE(member.mode)
        if (member.isdir() and mode != 0o700) or (
            member.isfile() and mode not in {0o600, 0o700}
        ):
            raise _fail("Recovery archive contains an unsafe file mode.")
        total += member.size
        if total > MAX_TOTAL_BYTES:
            raise _fail("Recovery archive exceeds the expanded size limit.")
        members_by_path[name] = member
    if manifest_member is None:
        raise _fail("Recovery archive inventory is missing.")
    handle = tar.extractfile(manifest_member)
    try:
        raw_manifest = handle.read(MAX_MANIFEST_BYTES + 1) if handle else b""
        manifest = json.loads(raw_manifest, object_pairs_hook=_no_duplicate_keys)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        raise _fail("Recovery archive inventory is malformed.") from None
    if len(raw_manifest) > MAX_MANIFEST_BYTES or not isinstance(manifest, dict):
        raise _fail("Recovery archive inventory exceeds the size limit.")
    if (
        set(manifest) != {"version", "bundle_id", "members", "entries"}
        or type(manifest["version"]) is not int
        or manifest["version"] != 1
    ):
        raise _fail("Recovery archive inventory has an unsupported schema.")
    if (
        not isinstance(manifest["bundle_id"], str)
        or not manifest["bundle_id"]
        or len(manifest["bundle_id"]) > 128
        or any(ord(char) < 32 for char in manifest["bundle_id"])
    ):
        raise _fail("Recovery archive inventory has an invalid identifier.")
    declared_members = manifest["members"]
    declared_entries = manifest["entries"]
    if not isinstance(declared_members, list) or not declared_members or len(declared_members) > 1024:
        raise _fail("Recovery archive inventory has an invalid member list.")
    if not isinstance(declared_entries, list) or len(declared_entries) != len(members_by_path):
        raise _fail("Recovery archive does not match its declared inventory.")
    names = set()
    paths = set()
    entries_by_path = {}
    for entry in declared_entries:
        if not isinstance(entry, dict) or entry.get("type") not in {"file", "directory"}:
            raise _fail("Recovery archive inventory has an invalid entry.")
        expected_keys = {"path", "type", "mode", "size", "sha256"} if entry["type"] == "file" else {"path", "type", "mode", "size"}
        if set(entry) != expected_keys:
            raise _fail("Recovery archive inventory has an invalid entry.")
        path_name = entry["path"]
        if not isinstance(path_name, str) or path_name in paths or any(ord(char) < 32 for char in path_name):
            raise _fail("Recovery archive inventory contains duplicate paths.")
        paths.add(path_name)
        pathspec = PurePosixPath(path_name)
        if pathspec.is_absolute() or "\\" in path_name or any(part in {"", ".", ".."} for part in pathspec.parts):
            raise _fail("Recovery archive inventory contains an unsafe path.")
        member = members_by_path.get(path_name)
        if (
            member is None
            or type(entry["mode"]) is not int
            or type(entry["size"]) is not int
            or entry["size"] < 0
        ):
            raise _fail("Recovery archive does not match its declared inventory.")
        actual_type = "directory" if member.isdir() else "file"
        if entry["type"] != actual_type or entry["mode"] != stat.S_IMODE(member.mode) or entry["size"] != member.size:
            raise _fail("Recovery archive does not match its declared inventory.")
        if entry["type"] == "file":
            if not isinstance(entry["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", entry["sha256"]):
                raise _fail("Recovery archive inventory has an invalid digest.")
            stream = tar.extractfile(member)
            digest = hashlib.sha256()
            consumed = 0
            if stream is None:
                raise _fail("Recovery archive contains an unreadable file.")
            while block := stream.read(1024 * 1024):
                consumed += len(block)
                digest.update(block)
            if consumed != entry["size"] or digest.hexdigest() != entry["sha256"]:
                raise _fail("Recovery archive digest verification failed.")
        entries_by_path[path_name] = entry
    if paths != set(members_by_path):
        raise _fail("Recovery archive does not match its declared inventory.")
    for member in declared_members:
        if not isinstance(member, dict) or set(member) != {"name", "kind", "entries"}:
            raise _fail("Recovery archive inventory has an invalid member.")
        name, kind, member_paths = member["name"], member["kind"], member["entries"]
        if not isinstance(name, str) or not MEMBER_NAME.fullmatch(name) or name in names:
            raise _fail("Recovery archive inventory has an invalid member label.")
        if (
            kind not in {"file", "directory"}
            or not isinstance(member_paths, list)
            or not member_paths
            or not all(isinstance(item, str) for item in member_paths)
        ):
            raise _fail("Recovery archive inventory has an invalid member.")
        names.add(name)
        expected_root = f"payload/{name}"
        root_entry = entries_by_path.get(expected_root)
        if root_entry is None or root_entry["type"] != kind:
            raise _fail("Recovery archive member root is missing.")
        if kind == "file" and member_paths != [expected_root]:
            raise _fail("Recovery archive file member has an invalid inventory.")
        if kind == "directory" and expected_root not in member_paths:
            raise _fail("Recovery archive directory member has an invalid inventory.")
        if len(member_paths) != len(set(member_paths)):
            raise _fail("Recovery archive member inventory contains duplicates.")
        for name_path in member_paths:
            if name_path not in entries_by_path or not name_path.startswith(expected_root + "/") and name_path != expected_root:
                raise _fail("Recovery archive member inventory escapes its label.")
            parent = PurePosixPath(name_path).parent
            if parent not in {PurePosixPath("."), PurePosixPath("payload")} and parent.as_posix() not in entries_by_path:
                raise _fail("Recovery archive is missing a parent directory.")
            if parent not in {PurePosixPath("."), PurePosixPath("payload")} and entries_by_path[parent.as_posix()]["type"] != "directory":
                raise _fail("Recovery archive has a non-directory parent.")
    if set().union(*(set(member["entries"]) for member in declared_members)) != paths:
        raise _fail("Recovery archive contains undeclared member paths.")
    return manifest


def validate_archive(path: str | Path):
    try:
        if hasattr(path, "read"):
            path.seek(0)
            tar_context = tarfile.open(fileobj=path, mode="r:")
        else:
            tar_context = tarfile.open(path, mode="r:")
        with tar_context as tar:
            manifest = _validated_manifest(tar)
    except RecoveryError:
        raise
    except (OSError, tarfile.TarError, EOFError):
        raise _fail("Recovery archive is unreadable or corrupt.") from None
    return {
        "members": [member["name"] for member in manifest["members"]],
        "files": sum(entry["type"] == "file" for entry in manifest["entries"]),
    }


def _write_file(path: Path, body: BinaryIO, mode: int):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(path, flags, mode)
    with os.fdopen(fd, "wb") as target:
        shutil.copyfileobj(body, target, 1024 * 1024)
        target.flush()
        os.fsync(target.fileno())
    os.chmod(path, mode, follow_symlinks=False)


def restore_archive(archive_path: str | Path, destination: str | Path):
    if not hasattr(archive_path, "read"):
        archive_path = Path(archive_path)
    destination = Path(destination)
    _safe_parent(destination)
    try:
        if hasattr(archive_path, "read"):
            archive_path.seek(0)
            tar_context = tarfile.open(fileobj=archive_path, mode="r:")
        else:
            tar_context = tarfile.open(archive_path, mode="r:")
        with tar_context as tar:
            manifest = _validated_manifest(tar)
            destination.mkdir(mode=0o700)
            os.chmod(destination, 0o700, follow_symlinks=False)
            try:
                for member in manifest["members"]:
                    root = destination / member["name"]
                    prefix = f"payload/{member['name']}"
                    entries = [
                        item
                        for item in manifest["entries"]
                        if item["path"] == prefix or item["path"].startswith(prefix + "/")
                    ]
                    entries.sort(
                        key=lambda item: (
                            item["type"] != "directory",
                            len(PurePosixPath(item["path"]).parts),
                        )
                    )
                    for entry in entries:
                        relative = PurePosixPath(entry["path"]).relative_to(PurePosixPath("payload") / member["name"])
                        target = root.joinpath(*relative.parts)
                        archive_member = tar.getmember(entry["path"])
                        if entry["type"] == "directory":
                            if not target.exists():
                                target.mkdir(mode=0o700)
                            os.chmod(target, 0o700, follow_symlinks=False)
                        else:
                            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                            source = tar.extractfile(archive_member)
                            if source is None:
                                raise _fail("Recovery archive contains an unreadable file.")
                            with source:
                                _write_file(target, source, entry["mode"])
                directory_fd = os.open(destination, os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except Exception:
                shutil.rmtree(destination)
                raise
    except RecoveryError:
        raise
    except FileExistsError:
        raise _fail("Recovery staging destination already exists.") from None
    except Exception:
        raise _fail("Recovery staging failed; partial staging files were removed.") from None
    return destination


def _decrypt_to_temp(bundle: Path, identity: Path, age_bin: str | Path, temporary: BinaryIO):
    executable = _age_executable(age_bin)
    _private_input_file(bundle, mode=0o600)
    identity_info = _private_input_file(identity, mode=0o600)
    del identity_info
    try:
        process = subprocess.Popen(
            [executable, "-d", "-i", str(identity), str(bundle)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        raise _fail("Age decryption failed; bundle was not restored.") from None
    deadline = time.monotonic() + 3600
    written = 0
    try:
        assert process.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _fail("Age decryption exceeded the time limit.")
                events = selector.select(timeout=min(1, remaining))
                if not events:
                    if process.poll() is not None:
                        break
                    continue
                block = os.read(process.stdout.fileno(), 1024 * 1024)
                if not block:
                    break
                written += len(block)
                if written > MAX_TAR_BYTES:
                    raise _fail("Decrypted recovery archive exceeds the size limit.")
                temporary.write(block)
        status = process.wait(timeout=max(0, deadline - time.monotonic()))
    except Exception:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    if status != 0:
        raise _fail("Age decryption failed; bundle was not restored.")
    temporary.flush()
    temporary.seek(0)


def inspect_bundle(bundle: str | Path, identity: str | Path, *, age_bin="age"):
    bundle, identity = Path(bundle), Path(identity)
    try:
        with tempfile.TemporaryFile(mode="w+b") as plaintext:
            _decrypt_to_temp(bundle, identity, age_bin, plaintext)
            return validate_archive(plaintext)
    except RecoveryError:
        raise
    except Exception:
        raise _fail("Recovery bundle inspection failed.") from None


def verify_bundle(bundle: str | Path, identity: str | Path, *, age_bin="age"):
    inventory = inspect_bundle(bundle, identity, age_bin=age_bin)
    return {"verified": True, "members": len(inventory["members"]), "files": inventory["files"]}


def restore_bundle(bundle: str | Path, identity: str | Path, destination: str | Path, *, age_bin="age"):
    bundle, identity, destination = Path(bundle), Path(identity), Path(destination)
    _safe_parent(destination)
    try:
        with tempfile.TemporaryFile(mode="w+b") as plaintext:
            _decrypt_to_temp(bundle, identity, age_bin, plaintext)
            # Complete authenticated archive validation precedes creation of staging files.
            validate_archive(plaintext)
            plaintext.seek(0)
            return restore_archive(plaintext, destination)
    except RecoveryError:
        raise
    except Exception:
        raise _fail("Recovery restore failed; no live files or services were changed.") from None


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export", help="Create an age-encrypted recovery bundle")
    export.add_argument("--manifest", required=True)
    export.add_argument("--recipient-file", required=True)
    export.add_argument("--output", required=True)
    export.add_argument("--exclude-identity")
    export.add_argument("--age-bin", default="age")
    for name in ("inspect", "verify"):
        command = commands.add_parser(name, help=f"Decrypt and {name} a recovery bundle")
        command.add_argument("--bundle", required=True)
        command.add_argument("--identity", required=True)
        command.add_argument("--age-bin", default="age")
    restore = commands.add_parser("restore-stage", help="Restore into a new private staging directory")
    restore.add_argument("--bundle", required=True)
    restore.add_argument("--identity", required=True)
    restore.add_argument("--destination", required=True)
    restore.add_argument("--age-bin", default="age")
    return parser


def main(argv=None):
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "export":
            export_bundle(
                arguments.manifest,
                arguments.recipient_file,
                arguments.output,
                age_bin=arguments.age_bin,
                exclude_identity=arguments.exclude_identity,
            )
            print("Encrypted recovery bundle created.")
        elif arguments.command == "inspect":
            print(json.dumps(inspect_bundle(arguments.bundle, arguments.identity, age_bin=arguments.age_bin), sort_keys=True))
        elif arguments.command == "verify":
            print(json.dumps(verify_bundle(arguments.bundle, arguments.identity, age_bin=arguments.age_bin), sort_keys=True))
        else:
            restore_bundle(arguments.bundle, arguments.identity, arguments.destination, age_bin=arguments.age_bin)
            print("Private recovery staging created.")
    except RecoveryError as error:
        print(f"Recovery refused: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
