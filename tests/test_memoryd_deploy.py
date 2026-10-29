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
