"""Recovery replaces bridge-specific firewall state without changing its scope."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import vm_deploy_host as host

ACTIVATION = 'c' * 32
NETWORK_ID = '123456789abc' + '0' * 52
NETWORK = {'name': 'mcp-control-plane', 'subnet': '172.30.86.0/24', 'gateway': '172.30.86.1'}
BRIDGE = 'br-123456789abc'
RULE = ['sudo', '-n', 'ufw', 'allow', 'in', 'on', BRIDGE, 'from', '172.30.86.0/24',
        'to', '172.30.86.1', 'port', '8090', 'proto', 'tcp', 'comment',
        'mcp-control-plane MemoryD private bridge']
CHECK = ['sudo', '-n', 'iptables', '-C', 'ufw-user-input', '-i', BRIDGE,
         '-s', '172.30.86.0/24', '-d', '172.30.86.1', '-p', 'tcp', '--dport', '8090', '-j', 'ACCEPT']
CAPTURED = (b'{\n  "bridge": "br-fedcba987654", "subnet": "172.30.86.0/24",\n'
            b'  "gateway": "172.30.86.1", "port": 8090, "created": true,\n'
            b'  "status": "active", "transfer_manifest_sha256": "' + b'a' * 64 + b'"\n}\n')


class FirewallVM:
    def __init__(self):
        self.network = {'Name': NETWORK['name'], 'Id': NETWORK_ID, 'Driver': 'bridge',
                        'Labels': {'mcp-control-plane.owner': 'kamal'}, 'Options': {},
                        'IPAM': {'Config': [{'Subnet': NETWORK['subnet'], 'Gateway': NETWORK['gateway']}]}}
        self.proxy = {'Name': '/mcp-control-plane-schema-proxy',
                      'Config': {'Labels': {'service': 'mcp-control-plane-schema-proxy'}},
                      'State': {'Status': 'running', 'Running': True},
                      'NetworkSettings': {'Networks': {NETWORK['name']: {
                          'NetworkID': NETWORK_ID, 'IPAddress': '172.30.86.4'}}}}
        self.addresses = [{'addr_info': [{'local': NETWORK['gateway'], 'prefixlen': 24}]}]
        self.ufw_active = True
        self.rule_present = False
        self.allow_failure = None
        self.probe_failure = False
        self.allow_calls = 0
        self.probes = 0
        self.commands = []

    def run(self, command, **_kwargs):
        self.commands.append(command)
        if command == ['docker', 'network', 'ls', '-q']:
            return (NETWORK_ID + '\n').encode()
        if command in (['docker', 'network', 'inspect', NETWORK_ID],
                       ['docker', 'network', 'inspect', NETWORK['name']]):
            return json.dumps([self.network]).encode()
        if command == ['ip', '-j', '-4', 'route', 'show']:
            return json.dumps([{'dst': '172.30.86.0/24', 'dev': BRIDGE}]).encode()
        if command == ['ip', '-j', '-4', 'address', 'show', 'dev', BRIDGE]:
            return json.dumps(self.addresses).encode()
        if command == ['docker', 'inspect', 'mcp-control-plane-schema-proxy']:
            return json.dumps([self.proxy]).encode()
        if command == ['sudo', '-n', 'ufw', 'status']:
            return b'Status: active\n' if self.ufw_active else b'Status: inactive\n'
        if command == ['sudo', '-n', 'iptables', '-S', 'ufw-user-input']:
            return b''
        if command == RULE:
            self.allow_calls += 1
            if self.allow_failure != 'before':
                self.rule_present = True
            if self.allow_failure:
                raise RuntimeError('fixture UFW failure')
            return b''
        if (command[:5] == ['docker', 'exec', 'mcp-control-plane-schema-proxy', 'python3', '-c']
                and command[-1] == NETWORK['gateway']):
            assert '(sys.argv[1],8090)' in command[5]
            self.probes += 1
            if self.probe_failure:
                raise RuntimeError('fixture bridge probe failure')
            return b''
        raise AssertionError(f'unexpected VM command: {command!r}')

    def subprocess_run(self, command, **_kwargs):
        assert command == CHECK, f'firewall check must remain private: {command!r}'
        return subprocess.CompletedProcess(command, 0 if self.rule_present else 1, b'', b'')


@pytest.fixture
def recovery(tmp_path, monkeypatch):
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    store = state / 'deployment'
    store.mkdir(mode=0o700)
    bootstrap = state / 'bootstrap'
    bootstrap.mkdir(mode=0o700)
    monkeypatch.setattr(host, 'STATE', state)
    monkeypatch.setattr(host, 'STORE', store)
    monkeypatch.setattr(host, 'NETWORK', NETWORK.copy())
    marker = {'schema_version': 1, 'activation_id': ACTIVATION, 'status': 'activating',
              'original_stopped_attested': True, 'started_services': ['executor', 'schema-proxy', 'cas']}
    host.write(store / 'activation-in-progress.json', marker)
    host.write(bootstrap / 'memoryd-integration.json',
               {'organization': 'org', 'id': 'memoryd', 'url': 'http://172.30.86.1:8090/mcp'})
    (bootstrap / 'memoryd-firewall.json').write_bytes(CAPTURED)
    (bootstrap / 'memoryd-firewall.json').chmod(0o600)
    verified = []
    monkeypatch.setattr(host, '_verified_memoryd_restore', lambda value: verified.append(value), raising=False)
    monkeypatch.setattr(host, 'memoryd_health', lambda *, activation_id: {'status': 'PASS'})
    vm = FirewallVM()
    monkeypatch.setattr(host, 'run', vm.run)
    monkeypatch.setattr(host.subprocess, 'run', vm.subprocess_run)
    return {'state': state, 'store': store, 'bootstrap': bootstrap, 'vm': vm, 'verified': verified}


def activate(recovery):
    return host.activation_memoryd_network({'activation_id': ACTIVATION})


def receipt(recovery):
    return json.loads((recovery['bootstrap'] / 'memoryd-firewall.json').read_text())


def archive(recovery):
    return recovery['bootstrap'] / f'memoryd-firewall-captured-{ACTIVATION}.json'


def test_new_bridge_archives_captured_receipt_and_allows_only_private_traffic(recovery):
    result = activate(recovery)
    assert archive(recovery).read_bytes() == CAPTURED
    assert result['status'] == 'PASS' and result['bridge_reachable'] is True
    assert result['rule_created'] is True and result['rule_owned'] is True
    saved = receipt(recovery)
    assert saved['status'] == 'active' and saved['activation_id'] == ACTIVATION
    assert saved['bridge'] == BRIDGE and saved['subnet'] == '172.30.86.0/24'
    assert saved['gateway'] == '172.30.86.1' and saved['port'] == 8090
    assert saved['captured_receipt_sha256'] == hashlib.sha256(CAPTURED).hexdigest()
    assert recovery['vm'].allow_calls == 1 and recovery['vm'].probes == 1
    assert len(recovery['verified']) == 1


def test_retry_rechecks_rule_and_probe_without_rewriting_archive_or_adding_a_rule(recovery):
    activate(recovery)
    assert activate(recovery)['rule_created'] is False
    assert archive(recovery).read_bytes() == CAPTURED
    assert recovery['vm'].allow_calls == 1 and recovery['vm'].probes == 2
    assert receipt(recovery)['created'] is True


@pytest.mark.parametrize('when', ['before', 'after'])
def test_ufw_failure_keeps_pending_receipt_and_retry_converges(recovery, when):
    vm = recovery['vm']
    vm.allow_failure = when
    with pytest.raises(RuntimeError, match='UFW failure'):
        activate(recovery)
    assert archive(recovery).read_bytes() == CAPTURED
    assert receipt(recovery)['status'] == 'pending' and receipt(recovery)['created'] is True
    assert vm.probes == 0
    vm.allow_failure = None
    activate(recovery)
    assert receipt(recovery)['status'] == 'active'
    assert vm.rule_present and vm.probes == 1
    assert vm.allow_calls == (2 if when == 'before' else 1)


def test_failed_bridge_probe_keeps_rule_and_pending_receipt_for_retry(recovery):
    vm = recovery['vm']
    vm.probe_failure = True
    with pytest.raises(RuntimeError, match='bridge probe failure'):
        activate(recovery)
    assert vm.rule_present and receipt(recovery)['status'] == 'pending'
    vm.probe_failure = False
    activate(recovery)
    assert receipt(recovery)['status'] == 'active' and vm.allow_calls == 1


def test_preexisting_exact_rule_is_never_claimed_as_owned(recovery):
    recovery['vm'].rule_present = True
    result = activate(recovery)
    assert result['rule_created'] is False and result['rule_owned'] is False
    assert receipt(recovery)['created'] is False
    assert recovery['vm'].allow_calls == 0


def test_no_captured_firewall_receipt_creates_only_the_new_receipt(recovery):
    (recovery['bootstrap'] / 'memoryd-firewall.json').unlink()
    activate(recovery)
    assert receipt(recovery)['captured_receipt_sha256'] is None
    assert not archive(recovery).exists()
    assert activate(recovery)['rule_created'] is False


def test_unverified_restore_refuses_before_network_or_receipt_changes(recovery, monkeypatch):
    def refuse(_marker):
        raise ValueError('MemoryD restore was not verified')
    monkeypatch.setattr(host, '_verified_memoryd_restore', refuse)
    with pytest.raises(ValueError, match='not verified'):
        activate(recovery)
    assert recovery['vm'].commands == []
    assert (recovery['bootstrap'] / 'memoryd-firewall.json').read_bytes() == CAPTURED


def test_tampered_archive_blocks_retry_without_touching_existing_rule(recovery):
    activate(recovery)
    archive(recovery).write_bytes(b'tampered\n')
    with pytest.raises(ValueError, match='receipt changed'):
        activate(recovery)
    assert recovery['vm'].allow_calls == 1 and recovery['vm'].probes == 1
    assert receipt(recovery)['status'] == 'active'


@pytest.mark.parametrize('change', ['url', 'owner', 'subnet', 'gateway', 'bridge_address', 'ufw',
                                   'proxy_network', 'proxy_id', 'proxy_state', 'inactive', 'unattested'])
def test_invalid_recovery_or_network_never_changes_firewall(recovery, change):
    vm = recovery['vm']
    if change == 'url':
        host.write(recovery['bootstrap'] / 'memoryd-integration.json',
                   {'organization': 'org', 'id': 'memoryd', 'url': 'http://203.0.113.1:8090/mcp'})
    elif change == 'owner':
        vm.network['Labels'] = {'mcp-control-plane.owner': 'foreign'}
    elif change == 'subnet':
        vm.network['IPAM']['Config'][0]['Subnet'] = '172.30.87.0/24'
    elif change == 'gateway':
        vm.network['IPAM']['Config'][0]['Gateway'] = '172.30.86.2'
    elif change == 'bridge_address':
        vm.addresses[0]['addr_info'][0]['local'] = '172.30.86.2'
    elif change == 'ufw':
        vm.ufw_active = False
    elif change == 'proxy_network':
        vm.proxy['NetworkSettings']['Networks'] = {}
    elif change == 'proxy_id':
        vm.proxy['NetworkSettings']['Networks'][NETWORK['name']]['NetworkID'] = 'f' * 64
    elif change == 'proxy_state':
        vm.proxy['State']['Running'] = False
    else:
        path = recovery['store'] / 'activation-in-progress.json'
        marker = json.loads(path.read_text())
        marker['status' if change == 'inactive' else 'original_stopped_attested'] = (
            'activated' if change == 'inactive' else False)
        host.write(path, marker)
    with pytest.raises(ValueError):
        activate(recovery)
    assert vm.allow_calls == 0 and vm.probes == 0
    assert (recovery['bootstrap'] / 'memoryd-firewall.json').read_bytes() == CAPTURED
    assert not archive(recovery).exists()


def test_archive_conflict_never_overwrites_captured_receipt(recovery):
    path = archive(recovery)
    path.write_bytes(b'foreign receipt\n')
    path.chmod(0o600)
    with pytest.raises(ValueError):
        activate(recovery)
    assert path.read_bytes() == b'foreign receipt\n'
    assert (recovery['bootstrap'] / 'memoryd-firewall.json').read_bytes() == CAPTURED
    assert recovery['vm'].allow_calls == 0


def test_action_rejects_extra_input_before_touching_vm(recovery):
    with pytest.raises(ValueError):
        host.activation_memoryd_network({'activation_id': ACTIVATION, 'bridge': 'eth0'})
    assert recovery['vm'].commands == []


def test_vm_dispatch_accepts_the_activation_id_only(recovery, monkeypatch, capsys):
    monkeypatch.setattr(host, 'invocation_profile', lambda: ('activation-memoryd-network', {}))
    monkeypatch.setattr(host, 'configure_profile', lambda _instance: None)
    monkeypatch.setattr(host.os, 'umask', lambda _mode: None)
    monkeypatch.setattr(sys, 'stdin', io.StringIO(json.dumps({'activation_id': ACTIVATION})))
    host.main()
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'PASS' and result['bridge_reachable'] is True
