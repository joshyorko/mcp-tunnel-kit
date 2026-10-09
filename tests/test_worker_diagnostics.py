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


def test_scope_owned_selection_uses_approved_cluster_and_no_static_rebind(tmp_path, monkeypatch):
    module = helper()
    source = selected(tmp_path)
    before = source.read_bytes()
    approved = {'context': 'default', 'provider': 'kubernetes', 'workspace': 'cas-worker-01',
                'workspace_uid': 'default-ca-11111', 'kubernetes_context': 'ror',
                'namespace': 'devsy', 'kubeconfig': '/fixture/kubeconfig'}
    row = {'id': approved['workspace'], 'uid': approved['workspace_uid'], 'context': 'default',
           'provider': {'name': 'kubernetes', 'options': {
               'KUBERNETES_CONTEXT': {'value': 'ror'}, 'KUBERNETES_NAMESPACE': {'value': 'devsy'},
               'KUBERNETES_CONFIG': {'value': '/fixture/kubeconfig'}}}}
    pod = {'metadata': {'name': 'worker-pod', 'namespace': 'devsy', 'uid': 'pod-1',
                       'labels': {'devsy.sh/workspace-uid': approved['workspace_uid']}},
           'spec': {'containers': [{'name': 'devsy'}]}, 'status': {'phase': 'Pending'}}
    monkeypatch.setattr(module, '_run', lambda *args: json.dumps({'items': [pod]}))
    arguments = {'name': approved['workspace'], 'workspace_uid': approved['workspace_uid']}
    report = module.diagnose(source, arguments, lambda *args: {'structuredContent': row}, None, selection=approved)
    assert report['pod_phase'] == 'Pending'
    assert source.read_bytes() == before
    row['provider']['options']['KUBERNETES_CONTEXT']['value'] = 'different'
    monkeypatch.setattr(module, '_run', lambda *args: pytest.fail('Changed cluster must not be queried'))
    with pytest.raises(module.DiagnosticError):
        module.diagnose(source, arguments, lambda *args: {'structuredContent': row}, None, selection=approved)


def test_capacity_probe_returns_only_bounded_numeric_fields(tmp_path, monkeypatch):
    module = helper()
    row = {'id': 'codex-action-server', 'uid': 'default-co-f715f', 'context': 'default',
           'provider': {'name': 'kubernetes', 'options': {'KUBERNETES_CONTEXT': {'value': 'ror'},
             'KUBERNETES_NAMESPACE': {'value': 'devsy'}, 'KUBERNETES_CONFIG': {'value': '/fixture/kubeconfig'}}}}
    pod = {'metadata': {'name': 'worker', 'namespace': 'devsy', 'uid': 'pod-1',
           'labels': {'devsy.sh/workspace-uid': row['uid']}},
           'spec': {'containers': [{'name': 'devsy'}]}, 'status': {'phase': 'Running'}}
    output = 'capacity=' + json.dumps({'cpu_effective_cores': 4.0, 'memory_available_bytes': 1024,
        'workspace_free_bytes': 2048, 'workspace_total_bytes': 4096, 'secret': 'PRIVATE'}) + '\n'
    def run(args, env):
        if 'pods' in args: return json.dumps({'items': [pod]})
        if 'exec' in args: return output
        return json.dumps(pod)
    monkeypatch.setattr(module, '_run', run)
    result = module.diagnose(selected(tmp_path), {'name': row['id'], 'workspace_uid': row['uid']},
                              lambda *args: {'structuredContent': row}, None)
    assert result['capacity']['cpu_effective_cores'] == 4.0
    assert result['capacity']['workspace_free_bytes'] == 2048
    assert 'PRIVATE' not in json.dumps(result)
