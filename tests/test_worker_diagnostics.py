"""Scoped diagnostics never accept a caller-supplied command or another workspace."""
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def helper():
    path = ROOT / 'scripts/worker_diagnostics.py'
    assert path.is_file(), 'Scoped worker diagnostics are missing'
    spec = importlib.util.spec_from_file_location('worker_diagnostics', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def selected(tmp_path):
    source = tmp_path / 'targets.json'
    source.write_text(json.dumps({'targets': {'devsy': {
        'context': 'default', 'provider': 'kubernetes',
        'workspace': 'codex-action-server', 'workspace_uid': 'default-co-f715f'}}}))
    source.chmod(0o600)
    return source


def test_command_and_wrong_identity_are_refused_before_any_upstream_call(tmp_path):
    module = helper()
    source = selected(tmp_path)
    def forbidden(*args):
        raise AssertionError('Wrong workspace reached the upstream')
    for arguments in ({'name': 'other', 'workspace_uid': 'default-co-f715f'},
                      {'name': 'codex-action-server', 'workspace_uid': 'old'},
                      {'name': 'codex-action-server', 'workspace_uid': 'default-co-f715f',
                       'command': ['rm', '-rf', '/']}):
        with pytest.raises(module.DiagnosticError):
            module.diagnose(source, arguments, forbidden, None)


def test_changed_live_uid_is_refused_before_remote_exec(tmp_path):
    module = helper()
    row = {'id': 'codex-action-server', 'uid': 'changed', 'context': 'default',
           'provider': {'name': 'kubernetes'}}
    def call(name, arguments):
        assert name == 'workspace_status'
        return {'structuredContent': row}
    with pytest.raises(module.DiagnosticError):
        module.diagnose(selected(tmp_path),
                        {'name': row['id'], 'workspace_uid': 'default-co-f715f'}, call, None)


def test_fixed_probe_returns_metadata_and_checks_pod_uid_after_exec(tmp_path, monkeypatch):
    import subprocess
    module = helper()
    row = {'id': 'codex-action-server', 'uid': 'default-co-f715f', 'context': 'default',
           'provider': {'name': 'kubernetes', 'options': {
               'KUBERNETES_CONTEXT': {'value': 'ror'},
               'KUBERNETES_NAMESPACE': {'value': 'devsy'},
               'KUBERNETES_CONFIG': {'value': '/fixture/kubeconfig'}}}}
    pod = {'metadata': {'name': 'devsy-default-co-f715f', 'namespace': 'devsy',
                        'uid': 'pod-unique-id', 'labels': {'devsy.sh/workspace-uid': row['uid']}},
           'spec': {'containers': [{'name': 'devsy'}]}, 'status': {'phase': 'Running'}}
    def run(arguments, **kwargs):
        assert arguments[:7] == ['kubectl', '--kubeconfig', '/fixture/kubeconfig',
                                 '--context', 'ror', '-n', 'devsy']
        if arguments[7:9] == ['get', 'pods']:
            stdout = json.dumps({'items': [pod]})
        elif arguments[7] == 'exec':
            assert arguments[8:14] == [pod['metadata']['name'], '-c', 'devsy', '--', '/bin/bash', '-c']
            assert len(arguments) == 15
            stdout = 'codex_binary=present\ncodex_version=codex 0.161.0\nauth_file=absent\nauth_status=authenticated\ndaemon_socket=present\n' + \
                     'daemon_begin\n{"status":"running","version":"0.161.0","secret":"DO_NOT_RETURN"}\ndaemon_end\n'
        else:
            assert arguments[7:9] == ['get', 'pod']
            stdout = json.dumps(pod)
        return subprocess.CompletedProcess(arguments, 0, stdout, '')
    monkeypatch.setattr(module.subprocess, 'run', run)
    report = module.diagnose(selected(tmp_path),
                            {'name': row['id'], 'workspace_uid': row['uid']},
                            lambda *args: {'structuredContent': row}, None)
    assert report['native_daemon'] == {'status': 'running', 'version': '0.161.0'}
    assert report['auth_file'] == 'absent'
    assert report['auth_status'] == 'authenticated'
    assert report['codex_version'] == 'codex 0.161.0'
    assert 'DO_NOT_RETURN' not in json.dumps(report)


def test_nonzero_transport_is_not_a_successful_daemon_probe(tmp_path, monkeypatch):
    import subprocess
    module = helper()
    monkeypatch.setattr(module.subprocess, 'run',
                        lambda args, **kwargs: subprocess.CompletedProcess(args, 1, '', 'PRIVATE'))
    with pytest.raises(module.DiagnosticError, match='transport failed'):
        module._run(['kubectl'], None)
