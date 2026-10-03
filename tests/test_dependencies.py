"""Offline readiness must not promise a probe that cannot import its client."""
import importlib.metadata
import importlib.util
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def test_no_site_packages_fails_offline_preflight():
    result = subprocess.run([sys.executable, '-S', str(ROOT / 'codex_mcp_check.py'), '--check-config'], capture_output=True, text=True)
    assert result.returncode == 2
    assert 'dependencies' in result.stderr


def test_wrong_dependency_version_fails(monkeypatch):
    spec = importlib.util.spec_from_file_location('dependency_check', ROOT / 'codex_mcp_check.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(sys, 'argv', ['check', '--check-config'])
    monkeypatch.setattr(importlib.metadata, 'version', lambda name: '0.0.0')
    assert module.main() == 2
