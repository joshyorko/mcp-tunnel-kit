import threading

import pytest

from operator_progress import run_phase


def test_phase_reports_start_and_completion_on_stderr_only(capsys):
    assert run_phase('Checking native access', lambda: 42) == 42
    captured = capsys.readouterr()
    assert not captured.out
    assert 'Checking native access...' in captured.err
    assert 'Checking native access: done' in captured.err


def test_phase_reports_failure_and_preserves_exception(capsys):
    def fail():
        raise ValueError('private detail')
    with pytest.raises(ValueError, match='private detail'):
        run_phase('Publishing configuration', fail)
    captured = capsys.readouterr()
    assert 'Publishing configuration: failed' in captured.err
    assert 'private detail' not in captured.err
    assert not captured.out


def test_long_phase_emits_heartbeat_and_stops_after_completion(monkeypatch, capsys):
    import operator_progress as progress
    heartbeat = threading.Event()
    original = progress.emit
    def emit(message):
        original(message)
        if 'still working' in message:
            heartbeat.set()
    monkeypatch.setattr(progress, 'emit', emit)
    run_phase('Verifying Executor', lambda: heartbeat.wait(2), heartbeat_interval=0.001)
    assert heartbeat.is_set()
    captured = capsys.readouterr()
    assert 'Verifying Executor: still working' in captured.err
    assert captured.err.splitlines()[-1].startswith('Verifying Executor: done')
    assert not captured.out
