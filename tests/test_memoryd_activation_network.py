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
TRANSFER = 'a' * 64
INSTANCE = 'cmi_' + 'd' * 32
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
        self.volume = {'Name': 'codex-memoryd-data', 'Driver': 'local', 'Scope': 'local',
                       'Options': {}, 'Labels': {
                           'mcp-control-plane.recovery-activation': ACTIVATION,
                           'mcp-control-plane.restore-nonce': 'e' * 32}}

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
        if command == ['docker', 'volume', 'inspect', 'codex-memoryd-data']:
            return json.dumps([self.volume]).encode()
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
    real_restore_validator = getattr(host, '_verified_memoryd_restore', None)
    monkeypatch.setattr(host, '_verified_memoryd_restore', lambda value: verified.append(value), raising=False)
    monkeypatch.setattr(host, 'memoryd_health', lambda *, activation_id: {'status': 'PASS'})
    vm = FirewallVM()
    monkeypatch.setattr(host, 'run', vm.run)
    monkeypatch.setattr(host.subprocess, 'run', vm.subprocess_run)
    return {'state': state, 'store': store, 'bootstrap': bootstrap, 'vm': vm, 'verified': verified,
            'real_restore_validator': real_restore_validator}


def activate(recovery):
    return host.activation_memoryd_network({'activation_id': ACTIVATION})


def receipt(recovery):
    return json.loads((recovery['bootstrap'] / 'memoryd-firewall.json').read_text())


def archive(recovery):
    return recovery['bootstrap'] / f'memoryd-firewall-captured-{ACTIVATION}.json'


def finish_activation(recovery, monkeypatch):
    activate(recovery)
    marker_path = recovery['store'] / 'activation-in-progress.json'
    marker = json.loads(marker_path.read_text())
    marker.update(status='activated', memoryd_restored=True, memoryd_discovery='PASS',
                  source_sha='1' * 40, expected_identity='2' * 64,
                  memoryd={'status': 'captured', 'source_instance_id': INSTANCE})
    host.write(marker_path, marker)
    host.write(recovery['store'] / 'recovery-activation.json', {
        'schema_version': 1, 'activation_id': ACTIVATION, 'source_sha': '1' * 40,
        'expected_identity': '2' * 64, 'original_stopped_attested': True,
        'identity_preserved': True, 'memoryd_restored': True, 'memoryd_discovery': 'PASS',
        'recorded_at_ns': 1,
    })
    host.write(recovery['bootstrap'] / f'memoryd-transfer-{TRANSFER}.json', {
        'status': 'complete', 'transfer_manifest_sha256': TRANSFER,
        'source_profile': 'personal', 'source_workspace': 'dakota-codex-only',
        'target_profile': 'personal', 'target_workspace': 'dakota-codex-only',
        'destination_instance_id': INSTANCE, 'imported_record_count': 5,
    })
    monkeypatch.setattr(host, '_memoryd_record_count', lambda: 8)
    monkeypatch.setattr(host, 'memoryd_health', lambda **_kwargs: {'status': 'PASS'})


def test_normal_network_reuses_recovered_receipt_after_memories_grow(recovery, monkeypatch):
    finish_activation(recovery, monkeypatch)
    prior = receipt(recovery)
    result = host.memoryd_network_allow({'transfer_manifest_sha256': TRANSFER})
    assert result['status'] == 'PASS' and result['bridge_reachable'] is True
    assert result['rule_created'] is False and result['rule_owned'] is True
    assert receipt(recovery) == prior and archive(recovery).read_bytes() == CAPTURED
    assert recovery['vm'].allow_calls == 1 and recovery['vm'].probes == 2


def test_normal_network_reinstalls_only_private_rule_without_losing_recovery_provenance(recovery, monkeypatch):
    finish_activation(recovery, monkeypatch)
    prior = receipt(recovery)
    recovery['vm'].rule_present = False
    result = host.memoryd_network_allow({'transfer_manifest_sha256': TRANSFER})
    assert result['rule_created'] is True and result['rule_owned'] is True
    assert receipt(recovery) == prior and archive(recovery).read_bytes() == CAPTURED
    assert recovery['vm'].allow_calls == 2 and recovery['vm'].probes == 2


@pytest.mark.parametrize('when', ['before', 'after', 'probe'])
def test_normal_network_failure_preserves_pending_receipt_and_rule_for_retry(recovery, monkeypatch, when):
    finish_activation(recovery, monkeypatch)
    vm = recovery['vm']
    vm.rule_present = False
    if when == 'probe':
        vm.probe_failure = True
    else:
        vm.allow_failure = when
    with pytest.raises(RuntimeError):
        host.memoryd_network_allow({'transfer_manifest_sha256': TRANSFER})
    assert receipt(recovery)['status'] == 'pending'
    assert archive(recovery).read_bytes() == CAPTURED
    vm.allow_failure = None
    vm.probe_failure = False
    result = host.memoryd_network_allow({'transfer_manifest_sha256': TRANSFER})
    assert result['status'] == 'PASS' and receipt(recovery)['status'] == 'active'
    assert vm.allow_calls == (3 if when == 'before' else 2)


def test_normal_network_never_claims_foreign_preexisting_rule(recovery, monkeypatch):
    recovery['vm'].rule_present = True
    finish_activation(recovery, monkeypatch)
    result = host.memoryd_network_allow({'transfer_manifest_sha256': TRANSFER})
    assert result['rule_owned'] is False and result['rule_created'] is False
    assert receipt(recovery)['created'] is False and recovery['vm'].allow_calls == 0


def test_normal_network_accepts_a_second_recovery_with_intact_receipt_history(recovery, monkeypatch):
    finish_activation(recovery, monkeypatch)
    older_id = 'b' * 32
    older_archive = recovery['bootstrap'] / f'memoryd-firewall-captured-{older_id}.json'
    older_archive.write_bytes(CAPTURED)
    older_archive.chmod(0o600)
    older_receipt = {**receipt(recovery), 'activation_id': older_id,
                     'captured_receipt_sha256': hashlib.sha256(CAPTURED).hexdigest()}
    host.write(archive(recovery), older_receipt)
    current = receipt(recovery)
    current['captured_receipt_sha256'] = hashlib.sha256(archive(recovery).read_bytes()).hexdigest()
    host.write(recovery['bootstrap'] / 'memoryd-firewall.json', current)
    assert host.memoryd_network_allow({'transfer_manifest_sha256': TRANSFER})['status'] == 'PASS'
    assert older_archive.read_bytes() == CAPTURED and receipt(recovery) == current


def test_normal_network_accepts_absent_captured_firewall_receipt(recovery, monkeypatch):
    (recovery['bootstrap'] / 'memoryd-firewall.json').unlink()
    finish_activation(recovery, monkeypatch)
    assert host.memoryd_network_allow({'transfer_manifest_sha256': TRANSFER})['status'] == 'PASS'
    assert receipt(recovery)['captured_receipt_sha256'] is None
    assert not archive(recovery).exists()


def test_normal_network_rejects_different_captured_firewall_transfer(recovery, monkeypatch):
    finish_activation(recovery, monkeypatch)
    old = json.loads(archive(recovery).read_text())
    old['transfer_manifest_sha256'] = 'f' * 64
    host.write(archive(recovery), old)
    current = receipt(recovery)
    current['captured_receipt_sha256'] = hashlib.sha256(archive(recovery).read_bytes()).hexdigest()
    host.write(recovery['bootstrap'] / 'memoryd-firewall.json', current)
    with pytest.raises(ValueError, match='transfer does not match'):
        host.memoryd_network_allow({'transfer_manifest_sha256': TRANSFER})
    assert receipt(recovery) == current and recovery['vm'].allow_calls == 1


@pytest.mark.parametrize('damage', ['transfer_missing', 'transfer_incomplete', 'transfer_instance',
                                  'archive', 'activation_missing', 'activation_unattested',
                                  'marker_incomplete', 'marker_identity', 'volume_unverified'])
def test_normal_network_refuses_unproven_recovered_state(recovery, monkeypatch, damage):
    finish_activation(recovery, monkeypatch)
    transfer_path = recovery['bootstrap'] / f'memoryd-transfer-{TRANSFER}.json'
    activation_path = recovery['store'] / 'recovery-activation.json'
    marker_path = recovery['store'] / 'activation-in-progress.json'
    if damage == 'transfer_missing':
        transfer_path.unlink()
    elif damage in ('transfer_incomplete', 'transfer_instance'):
        value = json.loads(transfer_path.read_text())
        value['status' if damage == 'transfer_incomplete' else 'destination_instance_id'] = (
            'in_progress' if damage == 'transfer_incomplete' else 'cmi_' + 'e' * 32)
        host.write(transfer_path, value)
    elif damage == 'archive':
        archive(recovery).write_bytes(b'tampered\n')
    elif damage == 'activation_missing':
        activation_path.unlink()
    elif damage == 'activation_unattested':
        value = json.loads(activation_path.read_text())
        value['original_stopped_attested'] = False
        host.write(activation_path, value)
    elif damage in ('marker_incomplete', 'marker_identity'):
        value = json.loads(marker_path.read_text())
        if damage == 'marker_incomplete':
            value['status'] = 'activating'
        else:
            value.pop('expected_identity')
            record = json.loads(activation_path.read_text())
            record.pop('expected_identity')
            host.write(activation_path, record)
        host.write(marker_path, value)
    else:
        def refuse(_marker):
            raise ValueError('MemoryD recovery volume ownership could not be verified')
        monkeypatch.setattr(host, '_verified_memoryd_restore', refuse)
    prior = receipt(recovery)
    with pytest.raises((ValueError, FileNotFoundError)):
        host.memoryd_network_allow({'transfer_manifest_sha256': TRANSFER})
    assert receipt(recovery) == prior
    assert recovery['vm'].allow_calls == 1 and recovery['vm'].probes == 1


def test_normal_network_checks_actual_restore_receipt_and_volume_labels(recovery, monkeypatch):
    validator = recovery['real_restore_validator']
    if validator is None:
        pytest.skip('Restore validator is supplied by the recovery integration')
    finish_activation(recovery, monkeypatch)
    marker_path = recovery['store'] / 'activation-in-progress.json'
    marker = json.loads(marker_path.read_text())
    marker['prepared_manifest_sha256'] = 'd' * 64
    marker['memoryd'].update(backup_sha256='f' * 64, record_count=8, active_record_count=7,
                             archived_record_count=1, profile='personal', workspace='dakota-codex-only')
    host.write(marker_path, marker)
    host.write(recovery['store'] / f'memoryd-restore-{ACTIVATION}.json', {
        'schema_version': 1, 'status': 'verified', 'activation_id': ACTIVATION,
        'prepared_manifest_sha256': 'd' * 64, 'backup_sha256': 'f' * 64,
        'source_instance_id': INSTANCE, 'record_count': 8, 'active_record_count': 7,
        'archived_record_count': 1, 'volume': 'codex-memoryd-data', 'owner_nonce': 'e' * 32,
    })
    monkeypatch.setattr(host, '_verified_memoryd_restore', validator)
    assert host.memoryd_network_allow({'transfer_manifest_sha256': TRANSFER})['status'] == 'PASS'
    recovery['vm'].volume['Labels']['mcp-control-plane.restore-nonce'] = 'f' * 32
    with pytest.raises(ValueError, match='volume ownership'):
        host.memoryd_network_allow({'transfer_manifest_sha256': TRANSFER})
    assert recovery['vm'].allow_calls == 1 and recovery['vm'].probes == 2


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
