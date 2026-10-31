import json
import sys
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import local_kamal as cli
import vm_deploy_host as host


def state(running=True):
    return {'authority': 'kamal', 'healthy': running, 'inventory': {
        name: {'state': 'running' if running else 'exited'} for name in cli.deploy.ORDER}}


@pytest.mark.parametrize('argv,expected', [
    (['accessory', 'deploy'], ('deploy', 'all')),
    (['accessory', 'reboot', 'cas'], ('deploy', 'cas')),
    (['accessory', 'start'], ('start', 'all')),
    (['accessory', 'stop', 'tunnel'], ('stop', 'tunnel')),
    (['status'], ('details', 'all')),
])
def test_local_command_mapping(argv, expected):
    assert cli.parse_command(argv) == expected


@pytest.fixture
def native_cli(monkeypatch, tmp_path):
    from types import SimpleNamespace
    calls = []
    accessories = {name: {'options': {'log-driver': 'none'}}
                   if name in ('schema-proxy', 'tunnel') else {}
                   for name in (*cli.deploy.ORDER, *cli.deploy.MEMORYD_ORDER)}
    config = tmp_path / 'deploy.yml'
    config.write_text(json.dumps({'accessories': accessories}))
    config.chmod(0o600)
    monkeypatch.setattr(cli.deploy, 'configure_local', lambda _: calls.append('configure'))
    monkeypatch.setattr(cli.deploy, 'trusted_context', lambda *_args, **_kwargs: calls.append('trust'))
    monkeypatch.setattr(cli.deploy, 'remote', lambda action: calls.append(action) or
                        {'authority': 'kamal', 'manifest': {}})
    monkeypatch.setattr(cli.deploy, 'configuration', lambda *_: config)
    monkeypatch.setattr(cli.deploy, 'profile', lambda: {'state_dir': '/private/state'})
    def run(argv, **kwargs):
        if '--config-file' in argv:
            assert Path(argv[-1]).stat().st_mode & 0o777 == 0o600
            assert kwargs['env']['KAMAL_PUBLIC_DOCKER_CONFIG'] == '/private/state/deployment/anonymous-docker-config'
        calls.append(argv)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(cli.subprocess, 'run', run)
    return calls


@pytest.mark.parametrize('command', [
    ['accessory', 'logs', 'cas', '--since', '6h', '--lines', '200', '--grep', 'InvalidMessage', '--follow'],
    ['accessory', 'details', 'cas', '--quiet'],
    ['accessory', 'logs', 'memoryd-mcp', '--skip-timestamps'],
])
def test_native_cli_forwards_kamal_diagnostics_verbatim(native_cli, command):
    assert cli.native(command) == 0
    assert native_cli[:3] == ['configure', 'trust', 'current']
    assert native_cli[3][4:-2] == command
    assert native_cli[3][-2] == '--config-file'


@pytest.mark.parametrize('command', [[], ['help'], ['help', 'accessory'], ['version'], ['tree'],
    ['accessory', 'help'], ['accessory', 'logs', '--help'], ['accessory', 'details', '--help']])
def test_native_help_needs_no_remote_or_private_config(native_cli, command):
    assert cli.native(command) == 0
    assert native_cli == [['bundle', 'exec', 'kamal', *command]]


@pytest.mark.parametrize('command', [
    ['-h', 'elsewhere', 'deploy'], ['deploy'], ['app', 'logs'], ['proxy', 'reboot'], ['server', 'exec', 'true'],
    ['accessory', 'reboot', 'cas'], ['accessory', 'stop', 'tunnel'],
    ['accessory', 'remove', 'executor'], ['accessory', 'exec', 'cas', 'true'],
    ['accessory', 'details', '--config-file=elsewhere'],
    ['accessory', 'logs', 'cas', '-celsewhere'],
    ['accessory', 'details', '--config-f', 'elsewhere'],
    ['accessory', 'details', '--hosts=another-host'],
    ['accessory', 'details', '-d', 'production'],
])
def test_native_refuses_unmanaged_operations_and_config_overrides(native_cli, command):
    with pytest.raises(ValueError):
        cli.native(command)
    assert native_cli == []


def test_native_logs_all_skips_disabled_services(native_cli, capsys):
    assert cli.native(['accessory', 'logs', '--lines', '1']) == 0
    assert [command[6] for command in native_cli if isinstance(command, list)] == ['executor', 'cas']
    output = capsys.readouterr().out
    assert 'schema-proxy: logging is disabled' in output
    assert 'tunnel: logging is disabled' in output


def test_native_logs_preserves_exit_status(native_cli, monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(cli.subprocess, 'run', lambda *_a, **_kw: SimpleNamespace(returncode=7))
    assert cli.native(['accessory', 'logs', 'cas']) == 7


def test_native_requires_kamal_ownership(native_cli, monkeypatch):
    monkeypatch.setattr(cli.deploy, 'remote', lambda _: {'authority': 'compose'})
    with pytest.raises(ValueError, match='Kamal ownership'):
        cli.native(['accessory', 'logs', 'cas'])
    assert not any(isinstance(call, list) for call in native_cli)


def test_native_logs_refuses_unknown_service_and_multi_follow(native_cli):
    with pytest.raises(ValueError, match='Unknown'):
        cli.native(['accessory', 'logs', 'another-app'])
    with pytest.raises(ValueError, match='one accessory'):
        cli.native(['accessory', 'logs', '--follow'])
    assert not any(isinstance(call, list) for call in native_cli)


def test_logs_alias_and_native_entrypoint_use_same_cli(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, 'bundle_environment', lambda: None)
    monkeypatch.setattr(cli, 'native', lambda argv: calls.append(argv) or 0)
    assert cli.main(['native', 'accessory', 'logs', 'cas', '--grep', 'failure']) == 0
    assert cli.main(['accessory', 'logs', 'cas', '--grep', 'failure']) == 0
    assert calls == [['accessory', 'logs', 'cas', '--grep', 'failure']] * 2


def test_memoryd_deploy_routes_to_its_capacity_gated_controller():
    assert cli.parse_command(['accessory', 'deploy', 'memoryd']) == ('deploy', 'memoryd')
    assert cli.parse_command(['accessory', 'start', 'memoryd']) == ('start', 'memoryd')
    assert cli.parse_command(['accessory', 'stop', 'memoryd']) == ('stop', 'memoryd')
    assert cli.parse_command(['accessory', 'transfer', 'memoryd']) == ('transfer', 'memoryd')
    assert cli.parse_command(['accessory', 'network', 'memoryd']) == ('network', 'memoryd')
    assert cli.parse_command(['accessory', 'register', 'memoryd']) == ('register', 'memoryd')
    assert cli.parse_command(['accessory', 'reconcile-registration', 'memoryd']) == ('reconcile-registration', 'memoryd')


@pytest.mark.parametrize('command,operation', [
    ('reconcile-update', 'memoryd-rollout-reconcile'),
    ('abort-update', 'memoryd-rollout-abort'),
    ('complete-update', 'memoryd-rollout-complete'),
    ('release-update', 'memoryd-rollout-release'),
])
def test_rollout_recovery_requires_exact_id_and_routes_to_its_controller(command, operation, monkeypatch):
    calls=[]
    monkeypatch.setattr(cli, 'bundle_environment', lambda: None)
    monkeypatch.setattr(cli.deploy, 'configure_local', lambda _path: None)
    monkeypatch.setattr(cli.deploy, 'trusted_context', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli.deploy, 'execute', lambda args: calls.append(args) or {'status': 'fixture'})
    assert cli.main(['accessory', command, 'memoryd']) == 1
    assert cli.main(['accessory', command, 'memoryd', '--rollout-id', 'not-valid']) == 1
    assert cli.main(['accessory', command, 'memoryd', '--rollout-id', 'd' * 32]) == 0
    assert calls[0].operation == operation and calls[0].rollout_id == 'd' * 32


def test_registration_reconciliation_flag_is_forwarded_only_for_that_command(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(cli, 'bundle_environment', lambda: None)
    monkeypatch.setattr(cli.deploy, 'configure_local', lambda _path: None)
    monkeypatch.setattr(cli.deploy, 'trusted_context', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli.deploy, 'execute', lambda args: calls.append(args) or {'status': 'prepared'})
    assert cli.main(['accessory', 'reconcile-registration', 'memoryd', '--confirm-import-quiescent']) == 0
    assert calls[0].operation == 'memoryd-registration-reconcile'
    assert calls[0].confirm_import_quiescent is True
    assert cli.main(['accessory', 'register', 'memoryd', '--confirm-import-quiescent']) == 1
    assert len(calls) == 1


def test_legacy_reconciliation_approval_is_forwarded_only_for_that_command(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, 'bundle_environment', lambda: None)
    monkeypatch.setattr(cli.deploy, 'configure_local', lambda _path: None)
    monkeypatch.setattr(cli.deploy, 'trusted_context', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli.deploy, 'execute', lambda args: calls.append(args) or {'status': 'abandoned'})
    assert cli.main(['accessory', 'reconcile-legacy', 'memoryd', '--approve-legacy-abandon']) == 0
    assert calls[0].operation == 'memoryd-legacy-reconcile'
    assert calls[0].approve_legacy_abandon is True
    assert cli.main(['accessory', 'register', 'memoryd', '--approve-legacy-abandon']) == 1
    assert len(calls) == 1


@pytest.mark.parametrize('services', [
    {'mcp-control-plane-memoryd': {'state': 'running'},
     'mcp-control-plane-memoryd-mcp': {'state': 'running'}},
    {'mcp-control-plane-memoryd': {'state': 'exited'},
     'mcp-control-plane-memoryd-mcp': {'state': 'running'}},
    {'mcp-control-plane-memoryd': {'state': 'running'}},
    {'mcp-control-plane-memoryd-mcp': {'state': 'paused'}},
    {'mcp-control-plane-memoryd': {'state': 'unknown'}},
])
def test_stop_all_refuses_active_or_unknown_memoryd_before_stopping_core(tmp_path, services):
    stopped = []

    def remote(action, data=None):
        if action == 'lifecycle-check':
            return state()
        if action == 'memoryd-inventory':
            return {'services': services, 'volume_exists': True}
        if action == 'current':
            return {'authority': 'kamal', 'manifest': {}, 'identity': 'original'}
        if action == 'status':
            return state(running=False)
        return {}

    with patch.object(cli.deploy, 'lock', return_value=nullcontext()), \
         patch.object(cli.deploy, 'remote', side_effect=remote), \
         patch.object(cli.deploy, 'configuration', return_value=tmp_path / 'deploy.yml'), \
         patch.object(cli.deploy, 'kamal', side_effect=lambda _c, _o, name: stopped.append(name)):
        with pytest.raises(ValueError, match='stop memoryd'):
            cli.lifecycle('stop', 'all')

    assert stopped == []


def test_stop_memoryd_inspects_owned_labels_when_core_is_down(tmp_path, monkeypatch):
    rows = [
        {'Id': 'db', 'Name': '/mcp-control-plane-memoryd',
         'Config': {'Labels': {'service': 'mcp-control-plane-memoryd'}},
         'State': {'Status': 'running', 'Running': True, 'Health': {'Status': 'healthy'}}},
        {'Id': 'bridge', 'Name': '/mcp-control-plane-memoryd-mcp',
         'Config': {'Labels': {'service': 'mcp-control-plane-memoryd-mcp'}},
         'State': {'Status': 'running', 'Running': True, 'Health': {'Status': 'healthy'}}},
    ]
    stopped = []

    def run(args, **_kwargs):
        if args == ['docker', 'ps', '-aq']:
            return b'db bridge'
        if args == ['docker', 'inspect', 'db', 'bridge']:
            return json.dumps(rows).encode()
        if args == ['docker', 'volume', 'ls', '--format', '{{.Name}}']:
            return b'codex-memoryd-data'
        raise AssertionError(f'unexpected command: {args}')

    def remote(action, data=None):
        if action == 'lifecycle-check':
            raise RuntimeError('core unavailable')
        if action == 'memoryd-inventory':
            return host.memoryd_inventory()
        if action == 'current':
            return {'authority': 'kamal', 'manifest': {}}
        raise AssertionError(f'unexpected remote action: {action}')

    def kamal(_config, operation, name):
        stopped.append((operation, name))
        stopped_state = next(row for row in rows if row['Config']['Labels']['service'] ==
                             'mcp-control-plane-' + name)['State']
        stopped_state.update(Status='exited', Running=False)

    monkeypatch.setattr(host, 'STATE', tmp_path)
    monkeypatch.setattr(host, 'run', run)
    monkeypatch.setattr(host, 'memoryd_health', lambda: pytest.fail('core health must not be required'))
    with patch.object(cli.deploy, 'lock', return_value=nullcontext()), \
         patch.object(cli.deploy, 'remote', side_effect=remote), \
         patch.object(cli.deploy, 'configuration', return_value=tmp_path / 'deploy.yml'), \
         patch.object(cli.deploy, 'kamal', side_effect=kamal):
        result = cli.lifecycle('stop', 'memoryd')

    assert stopped == [('stop', 'memoryd-mcp'), ('stop', 'memoryd')]
    assert result['volume_exists'] is True
    assert all(item['state'] == 'exited' for item in result['services'].values())


def test_stop_memoryd_fails_if_an_accessory_remains_running(tmp_path):
    inventory = {'services': {'mcp-control-plane-memoryd': {'state': 'running'}},
                 'volume_exists': True}

    def remote(action, data=None):
        if action == 'current':
            return {'authority': 'kamal', 'manifest': {}}
        if action == 'memoryd-inventory':
            return inventory
        raise AssertionError(f'unexpected remote action: {action}')

    with patch.object(cli.deploy, 'lock', return_value=nullcontext()), \
         patch.object(cli.deploy, 'remote', side_effect=remote), \
         patch.object(cli.deploy, 'configuration', return_value=tmp_path / 'deploy.yml'), \
         patch.object(cli.deploy, 'kamal') as kamal:
        with pytest.raises(RuntimeError, match='did not stop'):
            cli.lifecycle('stop', 'memoryd')

    kamal.assert_called_once_with(tmp_path / 'deploy.yml', 'stop', 'memoryd')
    assert inventory['volume_exists'] is True


@pytest.mark.parametrize('current', [None, {'authority': 'compose'}])
def test_stop_memoryd_refuses_without_accepted_kamal_ownership(current):
    def remote(action, data=None):
        if action == 'current':
            return current
        raise AssertionError(f'unexpected remote action: {action}')

    with patch.object(cli.deploy, 'lock', return_value=nullcontext()), \
         patch.object(cli.deploy, 'remote', side_effect=remote), \
         patch.object(cli.deploy, 'kamal') as kamal:
        with pytest.raises(ValueError, match='accepted Kamal ownership'):
            cli.lifecycle('stop', 'memoryd')
    kamal.assert_not_called()


def test_stop_all_does_not_stop_core_if_memoryd_inventory_fails(tmp_path):
    def remote(action, data=None):
        if action == 'memoryd-inventory':
            raise RuntimeError('inventory unavailable')
        return state()

    with patch.object(cli.deploy, 'lock', return_value=nullcontext()), \
         patch.object(cli.deploy, 'remote', side_effect=remote), \
         patch.object(cli.deploy, 'kamal') as kamal:
        with pytest.raises(RuntimeError, match='inventory unavailable'):
            cli.lifecycle('stop', 'all')
    kamal.assert_not_called()


def test_stop_all_reports_failure_if_memoryd_becomes_active_after_preflight(tmp_path):
    reads = iter([
        {'services': {'mcp-control-plane-memoryd': {'state': 'exited'}}},
        {'services': {'mcp-control-plane-memoryd': {'state': 'running'}}},
    ])

    def remote(action, data=None):
        if action == 'memoryd-inventory':
            return next(reads)
        if action == 'current':
            return {'manifest': {}, 'identity': 'original'}
        return state(running=action == 'lifecycle-check')

    with patch.object(cli.deploy, 'lock', return_value=nullcontext()), \
         patch.object(cli.deploy, 'remote', side_effect=remote), \
         patch.object(cli.deploy, 'configuration', return_value=tmp_path / 'deploy.yml'), \
         patch.object(cli.deploy, 'kamal'):
        with pytest.raises(RuntimeError, match='MemoryD is running'):
            cli.lifecycle('stop', 'all')


@pytest.mark.parametrize('services', [
    {},
    {'mcp-control-plane-memoryd': {'state': 'exited'}},
    {'mcp-control-plane-memoryd': {'state': 'exited'},
     'mcp-control-plane-memoryd-mcp': {'state': 'created'}},
])
def test_stop_all_succeeds_only_with_inactive_memoryd(tmp_path, services):
    operations = []

    def remote(action, data=None):
        if action == 'memoryd-inventory':
            return {'services': services, 'volume_exists': True}
        if action == 'current':
            return {'manifest': {}, 'identity': 'original'}
        return state(running=action == 'lifecycle-check')

    with patch.object(cli.deploy, 'lock', return_value=nullcontext()), \
         patch.object(cli.deploy, 'remote', side_effect=remote), \
         patch.object(cli.deploy, 'configuration', return_value=tmp_path / 'deploy.yml'), \
         patch.object(cli.deploy, 'kamal', side_effect=lambda _c, op, name: operations.append((op, name))):
        result = cli.lifecycle('stop', 'all')

    assert operations == [('stop', 'tunnel'), ('stop', 'cas'),
                          ('stop', 'schema-proxy'), ('stop', 'executor')]
    assert result['memoryd']['services'] == services
    assert result['memoryd']['volume_exists'] is True


@pytest.mark.parametrize('services', [
    {},
    {'mcp-control-plane-memoryd': {'state': 'exited'},
     'mcp-control-plane-memoryd-mcp': {'state': 'exited'}},
])
def test_start_all_does_not_start_absent_or_stopped_memoryd(tmp_path, services):
    calls = []
    initial = json.loads(json.dumps(services))

    def remote(action, data=None):
        calls.append((action, data))
        if action == 'current':
            return {'manifest': {}, 'identity': 'original'}
        if action == 'snapshot':
            return {'identity': 'original'}
        if action == 'memoryd-inventory':
            return {'services': services}
        return state()

    def kamal(_config, operation, name):
        calls.append(('kamal', (operation, name)))
        if name in ('memoryd', 'memoryd-mcp'):
            services['mcp-control-plane-' + name] = {'state': 'running'}

    with patch.object(cli.deploy, 'lock', return_value=nullcontext()), \
         patch.object(cli.deploy, 'remote', side_effect=remote), \
         patch.object(cli.deploy, 'configuration', return_value=tmp_path / 'deploy.yml'), \
         patch.object(cli.deploy, 'kamal', side_effect=kamal):
        cli.lifecycle('start', 'all')

    assert services == initial
    assert calls.count(('kamal', ('start', 'tunnel'))) == 1
    assert calls.index(('identity-check', None)) < calls.index(('kamal', ('start', 'tunnel')))


def test_start_all_refuses_a_tunnel_conflict_that_appears_during_startup(tmp_path):
    started = []
    lifecycle_checks = 0

    def remote(action, data=None):
        nonlocal lifecycle_checks
        if action == 'lifecycle-check':
            lifecycle_checks += 1
            if lifecycle_checks == 2:
                raise ValueError('Duplicate production tunnel identity')
        if action == 'current':
            return {'manifest': {}, 'identity': 'original'}
        if action == 'snapshot':
            return {'identity': 'original'}
        return state()

    with patch.object(cli.deploy, 'lock', return_value=nullcontext()), \
         patch.object(cli.deploy, 'remote', side_effect=remote), \
         patch.object(cli.deploy, 'configuration', return_value=tmp_path / 'deploy.yml'), \
         patch.object(cli.deploy, 'kamal', side_effect=lambda _c, _o, name: started.append(name)):
        with pytest.raises(ValueError, match='Duplicate production tunnel'):
            cli.lifecycle('start', 'all')

    assert started == ['executor', 'schema-proxy', 'cas']


@pytest.mark.parametrize('argv', [
    ['app', 'deploy'], ['accessory', 'remove', 'all'],
    ['accessory', 'deploy', 'tunnel'], ['accessory', 'stop', 'fizzy'],
    ['accessory', 'start', 'all', '--config-file', 'foreign.yml'],
])
def test_other_workloads_and_uncoordinated_redeploy_are_refused(argv):
    with pytest.raises(ValueError):
        cli.parse_command(argv)


@pytest.mark.parametrize('operation', ['start', 'stop'])
def test_full_lifecycle_orders_dependencies_and_waits_before_next_start(operation, tmp_path):
    calls = []
    def remote(action, data=None):
        calls.append((action, data))
        if action == 'current':
            return {'manifest': {}, 'identity': 'original'}
        if action == 'snapshot':
            return {'identity': 'original'}
        if action == 'memoryd-inventory':
            return {'services': {}, 'volume_exists': False}
        return state(running=operation == 'start')
    def kamal(config, action, name):
        calls.append(('kamal', (action, name)))
    with patch.object(cli.deploy, 'lock', return_value=nullcontext()), \
         patch.object(cli.deploy, 'remote', side_effect=remote), \
         patch.object(cli.deploy, 'configuration', return_value=tmp_path / 'deploy.yml'), \
         patch.object(cli.deploy, 'kamal', side_effect=kamal):
        result = cli.lifecycle(operation, 'all')
    names = list(cli.deploy.ORDER)
    if operation == 'stop':
        names.reverse()
    assert [data for action, data in calls if action == 'kamal'] == [(operation, name) for name in names]
    assert calls[0][0] == 'lifecycle-check'
    if operation == 'start':
        assert calls.index(('devsy-ensure', None)) < calls.index(('kamal', ('start', 'executor')))
        assert calls.index(('identity-check', None)) < calls.index(('kamal', ('start', 'tunnel')))
        for i, name in enumerate(names):
            start = calls.index(('kamal', ('start', name)))
            assert calls[start + 1] == ('wait', {'owner': 'kamal', 'service': name})
        assert ('snapshot', None) in calls
    else:
        assert calls.index(('devsy-stop', None)) > calls.index(('kamal', ('stop', 'executor')))
    assert result['operation'] == operation


def test_failed_dependency_health_never_starts_tunnel(tmp_path):
    started = []
    def remote(action, data=None):
        if action == 'current':
            return {'manifest': {}, 'identity': 'original'}
        if action == 'wait':
            raise RuntimeError('unhealthy')
        return state()
    with patch.object(cli.deploy, 'lock', return_value=nullcontext()), \
         patch.object(cli.deploy, 'remote', side_effect=remote), \
         patch.object(cli.deploy, 'configuration', return_value=tmp_path / 'deploy.yml'), \
         patch.object(cli.deploy, 'kamal', side_effect=lambda c, a, n: started.append(n)):
        with pytest.raises(RuntimeError, match='unhealthy'):
            cli.lifecycle('start', 'all')
    assert started == ['executor']


def groups():
    return {'compose': {name: None for name in cli.deploy.ORDER}, 'kamal': {
        name: {'Config': {'Labels': {'service': 'mcp-control-plane-' + name}}}
        for name in cli.deploy.ORDER}}


@pytest.mark.parametrize('conflict', ['compose', 'writer', 'tunnel', 'wrong-label'])
def test_stopped_stack_cannot_start_with_a_competing_owner(conflict):
    inventory = groups()
    if conflict == 'compose':
        inventory['compose']['executor'] = {'State': {'Running': True}}
    if conflict == 'wrong-label':
        inventory['kamal']['cas']['Config']['Labels']['service'] = 'fizzy'
    tunnels = ['/foreign-tunnel'] if conflict == 'tunnel' else []
    writers = b'foreign-executor\n' if conflict == 'writer' else b''
    with patch.object(host, 'private', return_value=b'{"authority":"kamal"}'), \
         patch.object(host, 'inspect', return_value=('compose', inventory, tunnels)), \
         patch.object(host, 'run', return_value=writers), patch.object(host, 'status') as status:
        with pytest.raises(ValueError):
            host.lifecycle_check()
    status.assert_not_called()
