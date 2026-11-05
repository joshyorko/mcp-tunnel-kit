"""A verified VM acceptance tuple follows the deployment, not the controller."""
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import deploy_control_plane as d
import vm_deploy_host as h

TUPLE = {'target': 'dakota-nvidia', 'cwd': '/srv/operator/worktree',
         'thread_id': '12345678-1234-5678-9abc-def012345678'}


def test_explicit_acceptance_does_not_read_saved_settings(monkeypatch):
    monkeypatch.setattr(d, 'remote', lambda *_: pytest.fail('unexpected VM read'))
    assert d.resolve_native_acceptance(TUPLE) == TUPLE


def test_saved_acceptance_is_available_to_any_controller(monkeypatch):
    monkeypatch.setattr(d, 'remote', lambda action: TUPLE if action == 'native-acceptance' else pytest.fail(action))
    assert d.resolve_native_acceptance(None) == TUPLE


@pytest.mark.parametrize('saved', [None, {}, {**TUPLE, 'cwd': '../unsafe'}])
def test_missing_or_invalid_acceptance_names_inputs_before_key_staging(monkeypatch, saved):
    actions = []
    monkeypatch.setattr(d, 'remote', lambda action: actions.append(action) or saved)
    with pytest.raises(RuntimeError, match='NATIVE_TARGET.*NATIVE_CWD.*NATIVE_THREAD_ID'):
        d.resolve_native_acceptance(None)
    assert actions == ['native-acceptance']


def test_acceptance_is_saved_only_after_fresh_native_verification(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    monkeypatch.setattr(h, 'STORE', tmp_path)
    monkeypatch.setattr(h, 'smoke', lambda request: {'native_read': {'status': 'PASS'}})
    assert h.record_native_acceptance(TUPLE) == {'native_acceptance_saved': True}
    path = tmp_path / 'native-acceptance.json'
    assert json.loads(path.read_text()) == TUPLE
    assert path.stat().st_mode & 0o777 == 0o600
    assert h.saved_native_acceptance() == TUPLE


def test_failed_native_verification_does_not_save_acceptance(tmp_path, monkeypatch):
    monkeypatch.setattr(h, 'STORE', tmp_path)
    monkeypatch.setattr(h, 'smoke', lambda request: {'native_read': {'status': 'FAIL'}})
    with pytest.raises(ValueError, match='native'):
        h.record_native_acceptance(TUPLE)
    assert not (tmp_path / 'native-acceptance.json').exists()


def test_missing_acceptance_does_not_prepare_secrets(monkeypatch):
    monkeypatch.setattr(d, 'remote', lambda *_: pytest.fail('secrets were staged'))
    with pytest.raises(RuntimeError, match='NATIVE_TARGET'):
        d.rotate_tunnel_key('fixture-key', {}, '/fixture', None)
