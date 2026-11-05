"""Private operator policy transfer; no native calls or service lifecycle."""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile

MAX_BYTES = 65_536
OWNER_UID = 1000


def _invalid():
    raise ValueError("CAS coordination policy is invalid or not private")


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            _invalid()
        value[key] = item
    return value


def parse(raw):
    """Validate the bounded CAS pair contract without retaining message content."""
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        _invalid()
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
    except (ValueError, UnicodeError):
        _invalid()
    if (not isinstance(value, dict) or set(value) != {"pairs"}
            or not isinstance(value["pairs"], list) or len(value["pairs"]) > 64):
        _invalid()
    for pair in value["pairs"]:
        if not isinstance(pair, dict) or set(pair) != {"sender", "recipient"}:
            _invalid()
        for peer in pair.values():
            if not isinstance(peer, dict) or set(peer) != {"target", "cwd", "thread_id"}:
                _invalid()
            for key, limit in (("target", 128), ("cwd", 512), ("thread_id", 128)):
                text = peer[key]
                if (not isinstance(text, str) or not 1 <= len(text) <= limit
                        or any(ord(c) < 32 for c in text)):
                    _invalid()
            cwd = PurePosixPath(peer["cwd"])
            if not cwd.is_absolute() or ".." in cwd.parts or str(cwd) != peer["cwd"]:
                _invalid()
        if (pair["sender"]["target"] != pair["recipient"]["target"]
                or pair["sender"]["thread_id"] == pair["recipient"]["thread_id"]):
            _invalid()
    return value


def _directory(path, owner):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        _invalid()
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(descriptor)
    if info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(descriptor)
        _invalid()
    return descriptor


def read_file(path, *, owner=OWNER_UID):
    """Open a private regular file without following directory/file symlinks."""
    path = Path(path)
    try:
        directory = _directory(path.parent, owner)
        try:
            descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 dir_fd=directory)
            with os.fdopen(descriptor, "rb") as source:
                info = os.fstat(source.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                        or stat.S_IMODE(info.st_mode) not in (0o600, 0o400)
                        or info.st_size > MAX_BYTES):
                    _invalid()
                raw = source.read(MAX_BYTES + 1)
        finally:
            os.close(directory)
        parse(raw)
        return raw
    except OSError:
        _invalid()


def check(directory):
    raw = read_file(Path(directory) / "policy.json")
    return {"sha256": hashlib.sha256(raw).hexdigest(), "pairs": len(parse(raw)["pairs"])}


def read_transfer(source):
    """Bound the JSON-escaped SSH envelope before parsing it."""
    limit = MAX_BYTES * 6 + 1024
    raw = source.read(limit + 1)
    if len(raw) > limit:
        _invalid()
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
    except (ValueError, UnicodeError):
        _invalid()
    return value


def install(directory, raw, *, owner=OWNER_UID):
    """Atomically replace only policy.json in an unchanged private mount directory."""
    value = parse(raw)
    if os.geteuid() != owner:
        _invalid()
    directory = Path(directory)
    parent = _directory(directory.parent, owner)
    os.close(parent)
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        pass
    descriptor = _directory(directory, owner)
    path = directory / "policy.json"
    try:
        if os.path.lexists(path):
            read_file(path, owner=owner)
        fd, temporary = tempfile.mkstemp(prefix=".policy-", dir=directory)
        try:
            with os.fdopen(fd, "wb") as target:
                os.fchmod(target.fileno(), 0o600)
                target.write(raw)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, path)
            os.fsync(descriptor)
        finally:
            if os.path.lexists(temporary):
                os.unlink(temporary)
    finally:
        os.close(descriptor)
    return {"installed": True, "pairs": len(value["pairs"]),
            "sha256": hashlib.sha256(raw).hexdigest()}
