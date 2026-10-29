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


def test_memoryd_deploy_routes_to_its_capacity_gated_controller():
    assert cli.parse_command(['accessory', 'deploy', 'memoryd']) == ('deploy', 'memoryd')
    assert cli.parse_command(['accessory', 'start', 'memoryd']) == ('start', 'memoryd')
    assert cli.parse_command(['accessory', 'stop', 'memoryd']) == ('stop', 'memoryd')
    assert cli.parse_command(['accessory', 'transfer', 'memoryd']) == ('transfer', 'memoryd')
    assert cli.parse_command(['accessory', 'network', 'memoryd']) == ('network', 'memoryd')
    assert cli.parse_command(['accessory', 'register', 'memoryd']) == ('register', 'memoryd')


def test_memoryd_rollback_stops_only_its_accessories_and_preserves_volume(tmp_path):
    calls = []
    status_reads = 0

    def remote(action, data=None):
        calls.append((action, data))
        if action == 'lifecycle-check':
            return {'status': 'PASS'}
        if action == 'current':
            return {'manifest': {}, 'identity': 'existing'}
        if action == 'memoryd-status':
            nonlocal status_reads
            status_reads += 1
            if status_reads == 1:
                return {'status': 'HEALTHY', 'volume_exists': True, 'services': {
                    'mcp-control-plane-memoryd': {'state': 'running'},
                    'mcp-control-plane-memoryd-mcp': {'state': 'running'},
                }}
            return {'status': 'STOPPED', 'volume_exists': True, 'services': {
                'mcp-control-plane-memoryd': {'state': 'exited'},
                'mcp-control-plane-memoryd-mcp': {'state': 'exited'},
            }}
        raise AssertionError(f'unexpected remote action: {action}')

    def kamal(_config, operation, name):
        calls.append(('kamal', (operation, name)))

    with patch.object(cli.deploy, 'lock', return_value=nullcontext()), \
         patch.object(cli.deploy, 'remote', side_effect=remote), \
         patch.object(cli.deploy, 'configuration', return_value=tmp_path / 'deploy.yml'), \
         patch.object(cli.deploy, 'kamal', side_effect=kamal):
        result = cli.lifecycle('stop', 'memoryd')

    assert [data for action, data in calls if action == 'kamal'] == [
        ('stop', 'memoryd-mcp'), ('stop', 'memoryd')
    ]
    assert result['volume_exists'] is True


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
