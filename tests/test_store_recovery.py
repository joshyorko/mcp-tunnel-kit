import hashlib
import json
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import store_recovery as storage


@pytest.fixture(autouse=True)
def fake_external_tools(monkeypatch):
    monkeypatch.setattr(storage, "_binary", lambda name: name)


def private_file(path: Path, body: bytes = b"fixture") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(body)
    path.chmod(0o600)
    return path


def write_fixture_download(path: str | Path, body: bytes, tmp_path: Path) -> None:
    target = Path(path)
    assert target.resolve().is_relative_to(tmp_path.resolve())
    target.write_bytes(body)


def profile_fixture(tmp_path: Path, *, identities=True) -> tuple[Path, dict]:
    mc_dir = tmp_path / "mc"
    mc_dir.mkdir(mode=0o700)
    private_file(mc_dir / "config.json", b'{"hosts":{}}')
    values = {
        "schema_version": 1,
        "mc_config_dir": str(mc_dir),
        "minio_alias": "recovery",
        "bucket": "mcp-control-plane-recovery",
        "removable_directory": str(tmp_path / "drive"),
    }
    if identities:
        values["recovery_identity"] = str(private_file(tmp_path / "keys" / "identity-a", b"A-SECRET"))
        values["unlock_identity"] = str(private_file(tmp_path / "keys" / "identity-b", b"B-SECRET"))
    profile = private_file(tmp_path / "storage.json", json.dumps(values).encode())
    (tmp_path / "drive").mkdir(mode=0o700)
    return profile, values


def test_profile_rejects_public_minio_before_any_write(tmp_path, monkeypatch):
    profile, values = profile_fixture(tmp_path)
    bundle = private_file(tmp_path / "control-plane.age", b"ciphertext")
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if "anonymous" in args:
            return b'{"permission":"download"}'
        raise AssertionError("writes must not begin before bucket privacy passes")

    monkeypatch.setattr(storage, "_run", fake_run)
    monkeypatch.setattr(storage, "_mc_alias_url", lambda *_: "https://minio.example")
    with pytest.raises(storage.StorageError, match="private"):
        storage.publish(profile, bundle, "capture-1", tmp_path / "new-work")

    assert not (tmp_path / "new-work").exists()
    assert list((tmp_path / "drive").iterdir()) == []
    assert len(calls) == 1


def test_publish_writes_only_wrapped_a_to_drive_and_proves_both_locations(tmp_path, monkeypatch):
    profile, values = profile_fixture(tmp_path)
    bundle = private_file(tmp_path / "control-plane.age", b"ciphertext")
    remote: dict[str, bytes] = {}
    calls = []

    def fake_run(args, **kwargs):
        calls.append(list(map(str, args)))
        if args[0] == "mc":
            if "anonymous" in args:
                return b'{"permission":"private"}'
            if "ls" in args:
                rest = args[args.index("ls"):]
                prefix = str(rest[1]).rstrip("/") + "/"
                if any(key.startswith(prefix) for key in remote):
                    return b'{"key":"already-there"}\n'
                return b""
            if "cp" in args:
                rest = args[args.index("cp"):]
                source, target = map(str, (rest[1], rest[2]))
                if source.startswith("recovery/"):
                    write_fixture_download(target, remote[source.removeprefix("recovery/")], tmp_path)
                    return b""
                data = Path(source).read_bytes()
                key = target.removeprefix("recovery/")
                remote[key] = data
                return b""
            raise AssertionError(args)
        if args[0] == "age-keygen":
            return b"age1fixture123\n"
        if args[0] == "age":
            output_path = Path(args[args.index("-o") + 1])
            output_path.write_bytes(b"wrapped-A")
            return b""
        raise AssertionError(args[0])

    monkeypatch.setattr(storage, "_run", fake_run)
    monkeypatch.setattr(storage, "_mc_alias_url", lambda *_: "https://minio.example")
    monkeypatch.setattr(storage, "_mc_alias_url", lambda *_: "https://minio.example")
    monkeypatch.setattr(storage, "_verify_bundle", lambda *_: {"verified": True, "members": 2, "files": 3})
    monkeypatch.setattr(storage, "_restore_bundle", lambda *_: 3)

    summary = storage.publish(profile, bundle, "capture-1", tmp_path / "new-work")

    drive_run = tmp_path / "drive" / "capture-1"
    assert {path.name for path in drive_run.iterdir()} == {
        "control-plane.age", "recovery-key.age", "storage-receipt.json", "START-HERE.txt"
    }
    assert (drive_run / "control-plane.age").read_bytes() == bundle.read_bytes()
    assert (drive_run / "recovery-key.age").read_bytes() == b"wrapped-A"
    assert b"A-SECRET" not in b"".join(item.read_bytes() for item in drive_run.iterdir() if item.is_file())
    assert remote["mcp-control-plane-recovery/capture-1/unlock-identity.txt"] == b"B-SECRET"
    assert remote["mcp-control-plane-recovery/capture-1/control-plane.age"] == b"ciphertext"
    assert summary["stored_on_drive"] and summary["stored_in_private_minio"]
    receipt = json.loads((drive_run / "storage-receipt.json").read_text())
    assert receipt["bundle_sha256"] == hashlib.sha256(b"ciphertext").hexdigest()
    assert "A-SECRET" not in json.dumps(receipt)
    assert not any("A-SECRET" in str(arg) for call in calls for arg in call)


def test_publish_refuses_existing_prefix_before_local_output_creation(tmp_path, monkeypatch):
    profile, _ = profile_fixture(tmp_path)
    bundle = private_file(tmp_path / "control-plane.age", b"ciphertext")
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if "anonymous" in args:
            return b'{"permission":"private"}'
        if "ls" in args:
            return b'{"key":"old"}\n'
        raise AssertionError("the publisher must not touch existing objects")

    monkeypatch.setattr(storage, "_run", fake_run)
    monkeypatch.setattr(storage, "_mc_alias_url", lambda *_: "https://minio.example")
    with pytest.raises(storage.StorageError, match="already contains"):
        storage.publish(profile, bundle, "capture-1", tmp_path / "new-work")

    assert not (tmp_path / "new-work").exists()
    assert not (tmp_path / "drive" / "capture-1").exists()


def test_verify_stored_uses_downloaded_b_and_drive_wrapped_a_not_source_a(tmp_path, monkeypatch):
    profile, values = profile_fixture(tmp_path, identities=False)
    values["recovery_identity"] = "/nonexistent/original-A"
    values["unlock_identity"] = "/nonexistent/original-B"
    profile.write_text(json.dumps(values))
    profile.chmod(0o600)
    bundle = private_file(tmp_path / "control-plane.age", b"expected-ciphertext")
    drive_run = tmp_path / "drive" / "capture-1"
    drive_run.mkdir(mode=0o700)
    (drive_run / "control-plane.age").write_bytes(bundle.read_bytes())
    (drive_run / "recovery-key.age").write_bytes(b"wrapped-A")
    remote = {
        "mcp-control-plane-recovery/capture-1/control-plane.age": b"expected-ciphertext",
        "mcp-control-plane-recovery/capture-1/unlock-identity.txt": b"downloaded-B",
    }
    calls = []

    def fake_run(args, **kwargs):
        calls.append(list(map(str, args)))
        if args[0] == "mc":
            if "anonymous" in args:
                return b'{"permission":"private"}'
            if "cp" in args:
                rest = args[args.index("cp"):]
                source, target = map(str, (rest[1], rest[2]))
                write_fixture_download(target, remote[source.removeprefix("recovery/")], tmp_path)
                return b""
            raise AssertionError(args)
        if args[0] == "age":
            assert Path(args[args.index("-i") + 1]).read_bytes() == b"downloaded-B"
            Path(args[args.index("-o") + 1]).write_bytes(b"recovered-A")
            return b""
        raise AssertionError(args[0])

    monkeypatch.setattr(storage, "_run", fake_run)
    monkeypatch.setattr(storage, "_mc_alias_url", lambda *_: "https://minio.example")
    checked = []
    monkeypatch.setattr(storage, "_verify_bundle", lambda bundle_path, identity: checked.append((Path(bundle_path).read_bytes(), Path(identity).read_bytes())) or {"verified": True, "members": 2, "files": 3})
    monkeypatch.setattr(storage, "_restore_bundle", lambda bundle_path, identity, dest: 3)

    summary = storage.verify_stored(profile, bundle, "capture-1", tmp_path / "verify-work")

    assert checked == [(b"expected-ciphertext", b"recovered-A")]
    assert summary["two_location_key_recovery"] is True
    assert not any("original-A" in str(arg) or "original-B" in str(arg) for call in calls for arg in call)
    assert (tmp_path / "verify-work" / "recovery-identity.txt").stat().st_mode & 0o777 == 0o600


def test_verify_stored_rejects_corrupt_download_without_staging(tmp_path, monkeypatch):
    cwd_entries_before = set(Path.cwd().iterdir())
    profile, _ = profile_fixture(tmp_path, identities=False)
    bundle = private_file(tmp_path / "control-plane.age", b"expected")
    drive_run = tmp_path / "drive" / "capture-1"
    drive_run.mkdir(mode=0o700)
    (drive_run / "control-plane.age").write_bytes(bundle.read_bytes())
    (drive_run / "recovery-key.age").write_bytes(b"wrapped-A")
    monkeypatch.setattr(storage, "_mc_alias_url", lambda *_: "https://minio.example")
    def fake_run(args, **kwargs):
        if "anonymous" in args:
            return b'{"permission":"private"}'
        rest = args[args.index("cp"):]
        write_fixture_download(rest[2], b"corrupt", tmp_path)
        return b""

    monkeypatch.setattr(storage, "_run", fake_run)

    with pytest.raises(storage.StorageError, match="digest"):
        storage.verify_stored(profile, bundle, "capture-1", tmp_path / "verify-work")

    assert not (tmp_path / "verify-work" / "staged").exists()
    assert set(Path.cwd().iterdir()) == cwd_entries_before


def test_cli_help_exposes_only_publish_and_verify_stored():
    with pytest.raises(SystemExit) as result:
        storage.main(["--help"])
    assert result.value.code == 0


@pytest.mark.parametrize("url", ["http://minio.example", "https://user:secret@minio.example"])
def test_alias_endpoint_must_be_https_without_userinfo(tmp_path, url):
    profile, values = profile_fixture(tmp_path)
    config = Path(values["mc_config_dir"]) / "config.json"
    config.write_text(json.dumps({"aliases": {"recovery": {"url": url, "accessKey": "fixture", "secretKey": "fixture"}}}))
    config.chmod(0o600)

    with pytest.raises(storage.StorageError, match="HTTPS"):
        storage._mc_alias_url(json.loads(profile.read_text()))


def test_subprocess_failure_withholds_stderr_and_command_values(monkeypatch):
    class Result:
        returncode = 1
        stdout = b""
        stderr = b"sensitive diagnostic"

    monkeypatch.setattr(storage.subprocess, "run", lambda *args, **kwargs: Result())
    with pytest.raises(storage.StorageError) as caught:
        storage._run(["mc", "cp", "private-path"])

    assert "sensitive diagnostic" not in str(caught.value)
    assert "private-path" not in str(caught.value)


@pytest.mark.parametrize("capture_id", ["../escape", "contains space", ".", ""])
def test_capture_id_must_be_one_safe_label(tmp_path, capture_id):
    profile, _ = profile_fixture(tmp_path)
    with pytest.raises(storage.StorageError):
        storage._load_profile(profile, capture_id, require_identities=True)
