"""Host smoke checks keep Devsy preflight independent of native thread identity."""

import json
import os
from pathlib import Path
import re
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import vm_deploy_host as host


DAKOTA_CWD = "/srv/dakota/worktree/mcp-tunnel-kit"
VM_CWD = "/srv/control-plane/mcp-tunnel-kit"
THREAD_ID = "12345678-1234-5678-9abc-def012345678"


class FakeSession:
    def __init__(self, *, expected_cwd=DAKOTA_CWD, expected_thread=THREAD_ID,
                 read_error=None, active_flags=None, unknown_active_flags=False,
                 native_state_authoritative=True, thread_status="notLoaded",
                 connection_target="local", expected_target="local", latest_turn=None):
        self.expected_cwd = expected_cwd
        self.expected_thread = expected_thread
        self.read_error = read_error
        self.active_flags = active_flags or []
        self.unknown_active_flags = unknown_active_flags
        self.native_state_authoritative = native_state_authoritative
        self.thread_status = thread_status
        self.connection_target = connection_target
        self.expected_target = expected_target
        self.latest_turn = latest_turn
        self.calls = []

    def call(self, _method, request):
        code = request["arguments"]["code"]
        match = re.fullmatch(r"return await tools\.codex\.([a-z_]+)\((.*)\);", code)
        assert match, "smoke must call the named Codex tool with a JSON argument"
        name, raw_arguments = match.groups()
        arguments = json.loads(raw_arguments)
        self.calls.append((name, arguments))
        payload = arguments.get("payload", {})
        if name == "get_thread_snapshot":
            if self.read_error:
                content = {"result": None, "error": self.read_error}
            else:
                content = {
                    "result": {
                        "operation": "server/diagnostics",
                        "connection": {"target": self.connection_target},
                        "result": {
                            "target": self.expected_target, "cwd": self.expected_cwd,
                            "thread_id": self.expected_thread,
                            "source": "native-app-server", "thread_status": self.thread_status,
                            "active_flags": self.active_flags,
                            "unknown_active_flags": self.unknown_active_flags,
                            "native_state_authoritative": self.native_state_authoritative,
                            "latest_turn": self.latest_turn,
                        },
                    },
                    "error": None,
                }
        else:
            raise AssertionError(f"unexpected Codex tool: {name}")
        return {"structuredContent": {
            "status": "completed",
            "execution": {"ok": True, "value": {"structuredContent": content}},
        }}


def configured_host(tmp_path, monkeypatch, *, session):
    state = tmp_path / "state"
    profile = {
        "schema_version": 1,
        "deploy_host": {"alias": "control-plane-vm", "address": "203.0.113.10",
                        "user": "operator", "host_key_fingerprint": "SHA256:" + "A" * 43},
        "vm": {
            "repo_dir": VM_CWD,
            "state_dir": str(state),
            "network": {"name": "mcp-control-plane", "subnet": "198.18.0.0/24",
                        "gateway": "198.18.0.1"},
            "native_ssh_dir": str(state / "native-ssh"),
            "devsy": {"config_source": str(state / "devsy/config.yaml"),
                      "context_dir": str(state / "devsy/contexts/default"),
                      "kubeconfig_source": str(state / "ror/operator-kubeconfig"),
                      "context": "default"},
        },
    }
    host.configure_profile(profile)
    fake = SimpleNamespace(
        executor_session=lambda: (object(), session),
        verify_compact=lambda _session: None,
        execution=lambda result: result["structuredContent"],
        read_devsy=lambda _session, _profile: None,
    )
    monkeypatch.setitem(sys.modules, "compose_control", fake)
    monkeypatch.setattr(host, "private", lambda _path: b'{"profile":"fixture"}')
    return fake


def recovery_smoke_host(tmp_path, monkeypatch, *, status="activating", rows=(), volumes=()):
    real_private = host.private
    fake = configured_host(tmp_path, monkeypatch, session=FakeSession())
    monkeypatch.setattr(host, "private", real_private)
    bootstrap = host.STATE / "bootstrap"
    bootstrap.mkdir(mode=0o700, parents=True)
    for name, value in (("devsy-integration.json", {"profile": "fixture"}),
                        ("memoryd-integration.json", {"id": "memoryd"})):
        path = bootstrap / name
        path.write_text(json.dumps(value))
        path.chmod(0o600)
    host.STORE.mkdir(mode=0o700)
    marker = host.STORE / "activation-in-progress.json"
    marker.write_text(json.dumps({
        "schema_version": 1, "activation_id": "c" * 32, "status": status,
        "original_stopped_attested": True, "started_services": ["executor"],
        "source_sha": "a" * 40, "expected_identity": "fixture-preserved-identity",
    }))
    marker.chmod(0o600)

    def run(command, *_args, **_kwargs):
        if command == ["docker", "ps", "-aq"]:
            return b"fixture-container\n" if rows else b""
        if command[:2] == ["docker", "inspect"]:
            return json.dumps(rows).encode()
        if command[:3] == ["docker", "volume", "ls"]:
            return ("\n".join(volumes)).encode()
        raise AssertionError(command)

    def missing_memoryd(_session):
        raise ValueError("MemoryD discovery failed")

    monkeypatch.setattr(host, "run", run)
    fake.search_memoryd = missing_memoryd
    return fake


def test_active_recovery_reports_missing_memoryd_without_skipping_core_checks(tmp_path, monkeypatch):
    fake = recovery_smoke_host(tmp_path, monkeypatch)
    checks = []
    fake.verify_compact = lambda _session: checks.append("executor")
    fake.read_devsy = lambda _session, _profile: checks.append("devsy")

    result = host.smoke({"activation_id": "c" * 32})

    assert checks == ["executor", "devsy"]
    assert result["memoryd_discovery"] == "UNAVAILABLE"
    assert result["memoryd_restored"] is False
    marker = json.loads((host.STORE / "activation-in-progress.json").read_text())
    assert marker["memoryd_discovery"] == "UNAVAILABLE"
    assert marker["memoryd_restored"] is False


def test_normal_smoke_fails_closed_when_registered_memoryd_is_missing(tmp_path, monkeypatch):
    recovery_smoke_host(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="MemoryD discovery failed"):
        host.smoke()


@pytest.mark.parametrize("activation_id,status", [
    ("d" * 32, "activating"), ("c" * 32, "installing"), ("c" * 32, "activated"),
])
def test_recovery_smoke_rejects_wrong_or_inactive_activation(tmp_path, monkeypatch, activation_id, status):
    fake = recovery_smoke_host(tmp_path, monkeypatch, status=status)
    calls = []
    fake.search_memoryd = lambda _session: calls.append("discovery")
    with pytest.raises(ValueError):
        host.smoke({"activation_id": activation_id})
    assert not calls


def test_recovery_smoke_requires_original_stopped_attestation(tmp_path, monkeypatch):
    fake = recovery_smoke_host(tmp_path, monkeypatch)
    fake.search_memoryd = lambda _session: None
    marker_path = host.STORE / "activation-in-progress.json"
    marker = json.loads(marker_path.read_text())
    marker["original_stopped_attested"] = False
    marker_path.write_text(json.dumps(marker))
    with pytest.raises(ValueError, match="authorized activation"):
        host.smoke({"activation_id": "c" * 32})


def test_recovery_smoke_fails_closed_when_memoryd_inventory_cannot_be_read(tmp_path, monkeypatch):
    recovery_smoke_host(tmp_path, monkeypatch)
    monkeypatch.setattr(host, "run", lambda _command: (_ for _ in ()).throw(RuntimeError("inventory failed")))
    with pytest.raises(RuntimeError, match="inventory failed"):
        host.smoke({"activation_id": "c" * 32})


def test_recovery_smoke_rejects_incomplete_docker_inspection(tmp_path, monkeypatch):
    recovery_smoke_host(tmp_path, monkeypatch)
    def run(command):
        if command == ["docker", "ps", "-aq"]:
            return b"fixture-container\n"
        if command[:2] == ["docker", "inspect"]:
            return b"[]"
        raise AssertionError(command)
    monkeypatch.setattr(host, "run", run)
    with pytest.raises(ValueError, match="inventory is invalid"):
        host.smoke({"activation_id": "c" * 32})


@pytest.mark.parametrize("rows,volumes", [
    ([{"Name": "/mcp-control-plane-memoryd", "Config": {"Labels": {}}}], []),
    ([{"Name": "/unrelated-name", "Config": {"Labels": {"service": "mcp-control-plane-memoryd-mcp"}}}], []),
    ([{"Name": "/codex-control-plane-memoryd-1", "Config": {"Labels": {
        "com.docker.compose.project": "codex-control-plane", "com.docker.compose.service": "memoryd"}}}], []),
    ([], ["codex-memoryd-data"]),
])
def test_recovery_smoke_does_not_skip_discovery_when_any_memoryd_state_exists(
        tmp_path, monkeypatch, rows, volumes):
    recovery_smoke_host(tmp_path, monkeypatch, rows=rows, volumes=volumes)
    with pytest.raises(ValueError, match="MemoryD discovery failed"):
        host.smoke({"activation_id": "c" * 32})


def test_recovery_smoke_reports_successful_discovery_without_claiming_restoration(tmp_path, monkeypatch):
    fake = recovery_smoke_host(tmp_path, monkeypatch, volumes=["codex-memoryd-data"])
    fake.search_memoryd = lambda _session: None
    result = host.smoke({"activation_id": "c" * 32})
    assert result["memoryd_discovery"] == "PASS"
    assert result["memoryd_restored"] is False


def test_recovery_smoke_claims_restoration_only_after_verified_data_and_read_only_discovery(tmp_path,monkeypatch):
    fake=recovery_smoke_host(tmp_path,monkeypatch,volumes=['codex-memoryd-data'])
    marker=host.STORE/'activation-in-progress.json'
    value=json.loads(marker.read_text());value['memoryd']={'status':'captured','record_count':3}
    host.write(marker,value)
    monkeypatch.setattr(host,'_verified_memoryd_restore',lambda _marker:{'status':'verified'})
    monkeypatch.setattr(host,'_memoryd_record_count',lambda:3)
    monkeypatch.setattr(host,'_memoryd_cli_json',lambda _args:{'active_profiles':['personal'],
                        'active_workspaces':['dakota-codex-only']})
    fake.search_memoryd=lambda _session:None
    fake.probe_memoryd_reads=lambda _session:{'status':'PASS'}
    fake.probe_memoryd_denials=lambda _url:{'write_blocked':True,'scope_override_blocked':True}
    result=host.smoke({'activation_id':'c'*32})
    assert result['memoryd_discovery']=='PASS' and result['memoryd_restored'] is True


def test_recovery_smoke_reports_unregistered_memoryd_as_not_restored(tmp_path, monkeypatch):
    recovery_smoke_host(tmp_path, monkeypatch)
    (host.STATE / "bootstrap/memoryd-integration.json").unlink()
    result = host.smoke({"activation_id": "c" * 32})
    assert result["memoryd_discovery"] == "UNREGISTERED"
    assert result["memoryd_restored"] is False


def test_smoke_reads_explicit_dakota_tuple_and_not_vm_checkout(tmp_path, monkeypatch):
    session = FakeSession(connection_target="dakota-nvidia", expected_target="dakota-nvidia")
    configured_host(tmp_path, monkeypatch, session=session)

    result = host.smoke({"native_codex": {
        "target": "dakota-nvidia", "cwd": DAKOTA_CWD, "thread_id": THREAD_ID,
    }, "require_native": True})

    assert result["native_read"]["status"] == "PASS"
    assert result["devsy_reads"] == "PASS"
    exact_read = next(args["payload"] for name, args in session.calls
                      if name == "get_thread_snapshot")
    assert exact_read == {"target": "dakota-nvidia", "cwd": DAKOTA_CWD,
                          "thread_id": THREAD_ID}
    assert all(VM_CWD not in json.dumps(args) for _, args in session.calls)


def test_native_read_rejects_wrong_named_connection(tmp_path, monkeypatch):
    session = FakeSession(connection_target="dakota-cpu", expected_target="dakota-nvidia")
    configured_host(tmp_path, monkeypatch, session=session)
    import pytest
    with pytest.raises(ValueError, match="NATIVE_THREAD_IDENTITY_MISMATCH"):
        host.smoke({"native_codex": {
            "target": "dakota-nvidia", "cwd": DAKOTA_CWD, "thread_id": THREAD_ID,
        }, "require_native": True})


def test_native_read_rejects_named_target_cwd_or_thread_mismatch(tmp_path, monkeypatch):
    import pytest
    mismatches = (
        {"expected_target": "dakota-cpu"},
        {"expected_cwd": "/srv/other/worktree"},
        {"expected_thread": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
    )
    for mismatch in mismatches:
        session = FakeSession(connection_target="dakota-nvidia", **mismatch)
        configured_host(tmp_path, monkeypatch, session=session)
        with pytest.raises(ValueError, match="NATIVE_THREAD_IDENTITY_MISMATCH"):
            host.smoke({"native_codex": {
                "target": "dakota-nvidia", "cwd": DAKOTA_CWD, "thread_id": THREAD_ID,
            }, "require_native": True})


def test_native_read_rejects_unsafe_target_name():
    assert host._codex_read_payload({
        "target": "bad target", "cwd": DAKOTA_CWD, "thread_id": THREAD_ID,
    }) is None


def test_non_strict_smoke_reports_redacted_thread_mismatch_after_devsy_reads(
        tmp_path, monkeypatch):
    session = FakeSession(expected_cwd=DAKOTA_CWD)
    fake = configured_host(tmp_path, monkeypatch, session=session)
    devsy_reads = []
    fake.read_devsy = lambda _session, _profile: devsy_reads.append("checked")

    result = host.smoke({"native_codex": {
        "target": "local", "cwd": VM_CWD, "thread_id": THREAD_ID,
    }, "require_native": False})

    assert devsy_reads == ["checked"]
    assert result["native_read"] == {
        "status": "FAIL", "error_code": "NATIVE_THREAD_IDENTITY_MISMATCH",
    }
    assert "home/" not in json.dumps(result)
    assert any(name == "get_thread_snapshot" for name, _ in session.calls)


def test_non_strict_smoke_redacts_structured_thread_error(tmp_path, monkeypatch):
    session = FakeSession(read_error=(
        "Stored thread id/cwd does not match the requested workstream"))
    fake = configured_host(tmp_path, monkeypatch, session=session)
    devsy_reads = []
    fake.read_devsy = lambda _session, _profile: devsy_reads.append("checked")

    result = host.smoke({"native_codex": {
        "target": "local", "cwd": DAKOTA_CWD, "thread_id": THREAD_ID,
    }, "require_native": False})

    assert devsy_reads == ["checked"]
    assert result["native_read"] == {
        "status": "FAIL", "error_code": "THREAD_WORKSTREAM_MISMATCH",
    }
    assert "Stored thread" not in json.dumps(result)
    assert any(name == "get_thread_snapshot" for name, _ in session.calls)


def test_native_snapshot_rejects_active_unknown_or_unverified_state(tmp_path, monkeypatch):
    for index, session in enumerate((
            FakeSession(active_flags=["turn"]),
            FakeSession(unknown_active_flags=True),
            FakeSession(native_state_authoritative=False),
            FakeSession(thread_status="unknown"),
            FakeSession(connection_target="other"))):
        fake = configured_host(tmp_path / str(index), monkeypatch, session=session)
        fake.read_devsy = lambda _session, _profile: None
        result = host.smoke({"native_codex": {
            "target": "local", "cwd": DAKOTA_CWD, "thread_id": THREAD_ID,
        }, "require_native": False})
        assert result["native_read"]["status"] == "FAIL"


def test_native_snapshot_accepts_idle_only_with_completed_latest_turn(
        tmp_path, monkeypatch):
    session = FakeSession(
        thread_status="idle",
        latest_turn={"id": "12345678-1234-5678-9abc-def012345678",
                     "status": "completed", "error_code": None},
    )
    fake = configured_host(tmp_path, monkeypatch, session=session)
    fake.read_devsy = lambda _session, _profile: None

    result = host.smoke({"native_codex": {
        "target": "local", "cwd": DAKOTA_CWD, "thread_id": THREAD_ID,
    }, "require_native": True})

    assert result["native_read"] == {"status": "PASS", "target": "local"}


def test_native_snapshot_rejects_idle_with_missing_or_noncompleted_latest_turn(
        tmp_path, monkeypatch):
    invalid_snapshots = (
        (None, [], False, "NATIVE_THREAD_STATE_UNVERIFIED"),
        ({"id": "12345678-1234-5678-9abc-def012345678", "status": "inProgress",
          "error_code": None}, [], False, "NATIVE_THREAD_STATE_UNVERIFIED"),
        ({"id": "malformed", "status": "completed", "error_code": None}, [], False,
         "NATIVE_THREAD_STATE_UNVERIFIED"),
        ({"id": "12345678-1234-5678-9abc-def012345678", "status": "completed",
          "error_code": "unexpected"}, [], False, "NATIVE_THREAD_STATE_UNVERIFIED"),
        ({"id": "12345678-1234-5678-9abc-def012345678", "status": "completed",
          "error_code": None}, ["turn"], False, "NATIVE_THREAD_ACTIVITY_UNKNOWN"),
        ({"id": "12345678-1234-5678-9abc-def012345678", "status": "completed",
          "error_code": None}, [], True, "NATIVE_THREAD_ACTIVITY_UNKNOWN"),
    )
    for index, (latest_turn, active_flags, unknown_active_flags, error_code) in enumerate(
            invalid_snapshots):
        session = FakeSession(thread_status="idle", latest_turn=latest_turn,
                              active_flags=active_flags,
                              unknown_active_flags=unknown_active_flags)
        fake = configured_host(tmp_path / str(index), monkeypatch, session=session)
        fake.read_devsy = lambda _session, _profile: None

        result = host.smoke({"native_codex": {
            "target": "local", "cwd": DAKOTA_CWD, "thread_id": THREAD_ID,
        }, "require_native": False})

        assert result["native_read"] == {
            "status": "FAIL", "error_code": error_code,
        }


def test_native_snapshot_rejects_active_even_without_active_flags(
        tmp_path, monkeypatch):
    session = FakeSession(
        thread_status="active",
        latest_turn={"id": "12345678-1234-5678-9abc-def012345678",
                     "status": "inProgress", "error_code": None},
    )
    fake = configured_host(tmp_path, monkeypatch, session=session)
    fake.read_devsy = lambda _session, _profile: None

    result = host.smoke({"native_codex": {
        "target": "local", "cwd": DAKOTA_CWD, "thread_id": THREAD_ID,
    }, "require_native": False})

    assert result["native_read"] == {
        "status": "FAIL", "error_code": "NATIVE_THREAD_STATE_UNVERIFIED",
    }


def test_strict_smoke_fails_closed_when_native_tuple_is_missing(tmp_path, monkeypatch):
    session = FakeSession()
    fake = configured_host(tmp_path, monkeypatch, session=session)
    devsy_reads = []
    fake.read_devsy = lambda _session, _profile: devsy_reads.append("checked")

    try:
        host.smoke({"require_native": True})
    except ValueError as exc:
        assert str(exc) == "qualified native read is required"
    else:
        raise AssertionError("strict smoke accepted an unconfigured native tuple")

    assert devsy_reads == ["checked"]
    assert not any(name == "get_thread_snapshot" for name, _ in session.calls)


def test_host_devsy_bootstrap_adapter_uses_validated_vm_paths(tmp_path, monkeypatch):
    import grp
    import pwd
    configured_host(tmp_path, monkeypatch, session=FakeSession())
    policy = json.loads((ROOT / "config/devsy-vm-bootstrap.json").read_text())
    template = (ROOT / "config/codex-control-plane-devsy.service.in").read_text()
    starter = "#!/usr/bin/env python3\n"

    bootstrap = host._devsy_bootstrap({
        "policy": policy, "unit_template": template, "starter_source": starter,
    })

    assert bootstrap.profile["repo_dir"] == VM_CWD
    assert bootstrap.profile["state_dir"] == str(host.STATE)
    assert bootstrap.profile["uid"] == os.getuid()
    assert bootstrap.profile["service_user"] == pwd.getpwuid(os.getuid()).pw_name
    assert bootstrap.profile["service_group"] == grp.getgrgid(os.getgid()).gr_name


def test_devsy_start_restarts_without_rewriting_managed_starter(tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    starter = state / "start-host-devsy.py"
    starter.write_text("approved managed starter\n")
    starter.chmod(0o700)
    calls = []
    monkeypatch.setattr(host, "STATE", state)
    monkeypatch.setattr(host, "run", lambda args, **_kwargs: calls.append(args))

    result = host.devsy_start()

    assert result == {"devsy": "PASS"}
    assert starter.read_text() == "approved managed starter\n"
    assert calls == [["sudo", "-n", "systemctl", "restart", "codex-control-plane-devsy"]]
