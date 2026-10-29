"""Capacity and non-disruption gates for the additive MemoryD deployment."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import vm_deploy_host
import deploy_control_plane


def meminfo(*, total_kb, available_kb):
    return f"MemTotal: {total_kb} kB\nMemAvailable: {available_kb} kB\nSwapTotal: 0 kB\n"


def test_memoryd_gate_blocks_below_threshold_and_reports_minimum_vm_size():
    result = vm_deploy_host.memoryd_resource_gate(
        meminfo(total_kb=8_131_080, available_kb=1_226_960)
    )

    assert result == {
        "ready": False,
        "reason": "insufficient_available_memory",
        "mem_total_kb": 8_131_080,
        "mem_available_kb": 1_226_960,
        "required_available_kb": 1_572_864,
        "swap_total_kb": 0,
        "minimum_vm_ram_gib": 9,
    }


def test_memoryd_gate_accepts_only_when_available_memory_preserves_reserve():
    result = vm_deploy_host.memoryd_resource_gate(
        meminfo(total_kb=9_437_184, available_kb=1_572_864)
    )

    assert result["ready"] is True
    assert result["reason"] == "ready"
    assert result["minimum_vm_ram_gib"] is None


def test_memoryd_preflight_is_read_only_and_stops_on_low_available_memory(monkeypatch):
    commands = []
    monkeypatch.setattr(vm_deploy_host, 'status', lambda: {
        'authority': 'kamal', 'healthy': True, 'tunnel_count': 1,
    })
    monkeypatch.setattr(Path, 'read_text', lambda _self: meminfo(
        total_kb=8_131_080, available_kb=1_226_960))

    def run(args, **_kwargs):
        commands.append(args)
        if args[:3] == ['docker', 'ps', '-aq']:
            return b''
        if args[:3] == ['docker', 'volume', 'ls']:
            return b''
        if args[:2] == ['ss', '-Hln']:
            return b''
        raise AssertionError(f'preflight attempted an unapproved operation: {args[1:]}')

    monkeypatch.setattr(vm_deploy_host, 'run', run)
    result = vm_deploy_host.memoryd_preflight()

    assert result['ready'] is False
    assert result['mutated'] is False
    assert result['reason'] == 'insufficient_available_memory'
    assert result['existing_services_healthy'] is True
    assert result['tunnel_count'] == 1
    assert result['target_container_count'] == 0
    assert result['target_volume_exists'] is False
    assert result['target_listeners'] == []
    assert all(args[0] in ('docker', 'ss') for args in commands)


def test_memoryd_status_reports_absent_without_creating_a_volume_or_marker(tmp_path, monkeypatch):
    monkeypatch.setattr(vm_deploy_host, 'STATE', tmp_path)
    monkeypatch.setattr(vm_deploy_host, 'run', lambda args, **_kwargs: b'')

    result = vm_deploy_host.memoryd_status()

    assert result == {
        'status': 'ABSENT', 'services': {}, 'volume_exists': False, 'app_registered': False,
    }
    assert list(tmp_path.iterdir()) == []


def test_memoryd_deploy_returns_blocked_without_sync_or_kamal_when_capacity_is_low(tmp_path, monkeypatch):
    calls = []

    def remote(action, data=None):
        calls.append(action)
        if action == "status":
            return {"authority": "kamal", "healthy": True, "tunnel_count": 1}
        if action == "snapshot":
            return {"authority": "kamal", "identity": "existing-executor", "inventory": {"executor": {}}, "tunnel_count": 1}
        if action == "memoryd-preflight":
            return {"ready": False, "reason": "insufficient_available_memory", "mem_available_kb": 1_226_960}
        raise AssertionError(f"unexpected mutating or unplanned operation: {action}")

    monkeypatch.setattr(deploy_control_plane, "remote", remote)
    monkeypatch.setattr(deploy_control_plane, "sync_source", lambda _sha: pytest.fail("source sync must not run"))
    monkeypatch.setattr(deploy_control_plane, "kamal", lambda *_args: pytest.fail("Kamal must not run"))

    result = deploy_control_plane.deploy_memoryd("a" * 40, tmp_path)

    assert result["status"] == "BLOCKED"
    assert result["mutated"] is False
    assert result["preflight"]["reason"] == "insufficient_available_memory"
    assert calls == ["status", "snapshot", "memoryd-preflight"]
