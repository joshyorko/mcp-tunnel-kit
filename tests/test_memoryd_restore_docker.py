"""Opt-in synthetic Docker proof. Never uses the production MemoryD volume or ports."""

import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import sqlite3
import stat
import subprocess
import threading
import time
from types import SimpleNamespace
import uuid

import pytest

import codex_memoryd_mcp as bridge
import vm_deploy_host as host


pytestmark = pytest.mark.skipif(
    os.environ.get('MCP_MEMORYD_DOCKER_INTEGRATION') != '1',
    reason='set MCP_MEMORYD_DOCKER_INTEGRATION=1 for the disposable Docker fixture',
)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


class DisposableDocker:
    def __init__(self, activation_id, volume):
        self.activation_id = activation_id
        self.volume = volume
        self.prefix = 'mcp-memoryd-fixture-' + activation_id[:16]
        self.names = {kind: self.prefix + '-' + kind for kind in ('prepare', 'probe', 'daemon')}
        self.ids = {}
        self.expected_mounts = {}
        self.helper_name = None
        self.nonce = None
        self.restore_uncertain = False

    @staticmethod
    def docker(*args, timeout=120):
        result = subprocess.run(['docker', *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if result.returncode:
            raise RuntimeError('Synthetic Docker operation failed: ' + ' '.join(args[:2]) + '; output withheld')
        return result.stdout

    def existing(self):
        ids = self.docker('ps', '-aq').decode().split()
        return json.loads(self.docker('inspect', *ids)) if ids else []

    def container(self, name):
        matches = [r for r in self.existing() if r.get('Name', '').lstrip('/') == name]
        if len(matches) > 1:
            raise ValueError('Synthetic container name is not unique')
        return matches[0] if matches else None

    def assert_owned(self, name, *, helper=False):
        row = self.container(name)
        if row is None:
            return None
        labels = row['Config'].get('Labels') or {}
        assert row['Name'].lstrip('/') == name
        assert labels.get('mcp-control-plane.recovery-activation') == self.activation_id
        assert row['Config'].get('Image') == host.MEMORYD_IMAGE
        assert row['HostConfig'].get('NetworkMode') == 'none'
        assert row['HostConfig'].get('PortBindings') in ({}, None)
        assert row['HostConfig'].get('PublishAllPorts') is False
        if helper:
            assert name == self.helper_name and self.nonce
            assert labels.get('mcp-control-plane.restore-nonce') == self.nonce
            assert [m.get('Name') for m in row['Mounts'] if m.get('Type') == 'volume'] == [self.volume]
        else:
            assert name in self.names.values()
            assert labels.get('mcp-control-plane.fixture') == self.activation_id
            assert self.ids.get(name) == row['Id']
            actual_mounts = {(mount['Type'], mount.get('Name') if mount['Type'] == 'volume' else mount['Source'],
                              mount['Destination']) for mount in row['Mounts']}
            assert actual_mounts == self.expected_mounts[name]
        return row

    def remove_container(self, name, *, helper=False):
        row = self.assert_owned(name, helper=helper)
        if row is None:
            return
        cid = row['Id']
        if row['State']['Running']:
            if row['Config']['Entrypoint'] == ['/bin/sleep']:
                lines = self.docker('top', cid, '-eo', 'pid,comm').decode().splitlines()
                if len(lines) != 2 or lines[1].split()[-1:] != ['sleep']:
                    raise ValueError('Synthetic helper may still be writing; retained')
            else:
                assert name == self.names['daemon']
                assert row['Config']['Entrypoint'] == ['/usr/local/bin/codex-memoryd']
            self.docker('stop', '--time', '10', cid)
            row = self.assert_owned(name, helper=helper)
            assert row is not None and row['State']['Running'] is False
        self.assert_owned(name, helper=helper)
        self.docker('rm', cid)
        assert self.container(name) is None
        self.ids.pop(name, None)
        self.expected_mounts.pop(name, None)

    def volume_info(self):
        names = self.docker('volume', 'ls', '--format', '{{.Name}}').decode().splitlines()
        if self.volume not in names:
            return None
        rows = json.loads(self.docker('volume', 'inspect', self.volume))
        assert len(rows) == 1 and rows[0]['Name'] == self.volume
        labels = rows[0].get('Labels') or {}
        assert labels.get('mcp-control-plane.recovery-activation') == self.activation_id
        assert self.nonce and labels.get('mcp-control-plane.restore-nonce') == self.nonce
        return rows[0]

    def cleanup(self):
        for name in self.names.values():
            self.remove_container(name)
        if self.restore_uncertain:
            return
        if self.helper_name:
            self.remove_container(self.helper_name, helper=True)
        if self.volume_info() is not None:
            for row in self.existing():
                if any(m.get('Name') == self.volume for m in row.get('Mounts', [])):
                    raise ValueError('Synthetic volume still has a container; retained')
            self.volume_info()
            self.docker('volume', 'rm', self.volume)

    def create(self, kind, *, mounts, entrypoint, user, command, env=()):
        name = self.names[kind]
        assert self.container(name) is None
        args = ['create', '--pull', 'never', '--name', name, '--network', 'none', '--no-healthcheck',
                '--user', user, '--label', 'mcp-control-plane.fixture=' + self.activation_id,
                '--label', 'mcp-control-plane.recovery-activation=' + self.activation_id]
        for mount in mounts:
            args.extend(['--mount', mount])
        for item in env:
            args.extend(['--env', item])
        args.extend(['--entrypoint', entrypoint, host.MEMORYD_IMAGE, *command])
        cid = self.docker(*args).decode().strip()
        self.ids[name] = cid
        expected = set()
        for mount in mounts:
            fields = dict(item.split('=', 1) for item in mount.split(','))
            expected.add((fields['type'], fields['source'], fields['target']))
        self.expected_mounts[name] = expected
        row = self.assert_owned(name)
        assert row['Id'] == cid and row['State']['Running'] is False
        return cid

    def start(self, kind):
        row = self.assert_owned(self.names[kind])
        assert row is not None and row['State']['Running'] is False
        self.docker('start', row['Id'])
        row = self.assert_owned(self.names[kind])
        assert row is not None and row['State']['Running'] is True
        return row['Id']

    def exec(self, kind, *args):
        row = self.assert_owned(self.names[kind])
        assert row is not None and row['State']['Running'] is True
        return self.docker('exec', row['Id'], *args)


def prepared_fixture(tmp_path, docker):
    prepared = tmp_path / 'prepared'
    memory = prepared / 'memoryd'
    memory.mkdir(parents=True, mode=0o700)
    prepared.chmod(0o700)
    data = tmp_path / 'unused-data'
    data.mkdir(mode=0o700)
    mounts = ['type=bind,source=' + str(tmp_path) + ',target=/fixture',
              'type=bind,source=' + str(data) + ',target=/data']
    docker.create('prepare', mounts=mounts, entrypoint='/bin/sleep',
                  user=f'{os.getuid()}:{os.getgid()}', command=['infinity'])
    docker.start('prepare')
    base = ['/usr/local/bin/codex-memoryd', 'backup', 'create', '--local', '--db', '/fixture/source.db']
    docker.exec('prepare', *base, '--dest', '/fixture/initial.db')
    source = tmp_path / 'source.db'
    with sqlite3.connect(source) as db:
        instance = db.execute("SELECT instance_id FROM instance_metadata WHERE singleton_key='default'").fetchone()[0]
        for archived in (0, 1):
            db.execute('INSERT INTO memory_records '
                       '(id, profile_id, workspace_id, scope, type, content, sensitivity, portability, '
                       'content_hash, created_at, updated_at, archived) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                       ('synthetic-' + str(archived), 'personal', 'dakota-codex-only', 'workspace', 'decision',
                        'synthetic fixture record', 'personal', 'portable', 'synthetic-hash-' + str(archived),
                        '2030-01-01T00:00:00Z', '2030-01-01T00:00:00Z', archived))
    raw = docker.exec('prepare', *base, '--dest', '/fixture/prepared/memoryd/backup.db')
    backup_result = json.loads(raw)
    docker.remove_container(docker.names['prepare'])
    backup = memory / 'backup.db'
    backup_manifest = memory / 'backup.db.manifest.json'
    backup.chmod(0o600)
    backup_manifest.chmod(0o600)
    assert backup_result['manifest']['sha256'] == 'sha256:' + sha(backup)
    assert backup_result['manifest']['size_bytes'] == backup.stat().st_size
    descriptor = {'status': 'captured', 'backend_image': host.MEMORYD_IMAGE,
                  'adapter_image': 'ghcr.io/joshyorko/codex-action-server@sha256:' + 'b' * 64,
                  'adapter_sha256': 'c' * 64, 'backup_sha256': sha(backup),
                  'backup_manifest_sha256': sha(backup_manifest), 'backup_size_bytes': backup.stat().st_size,
                  'source_instance_id': instance, 'record_count': 2, 'active_record_count': 1,
                  'archived_record_count': 1, 'profile': 'personal', 'workspace': 'dakota-codex-only',
                  'captured_at': '2030-01-01T00:00:00Z'}
    prepared_data = {'schema_version': 2, 'generation': {'source_sha': 'd' * 40},
                     'expected_identity': 'synthetic-identity', 'memoryd': descriptor}
    path = prepared / 'prepared-manifest.json'
    path.write_text(json.dumps(prepared_data) + '\n')
    path.chmod(0o600)
    return prepared, prepared_data, sha(path)


def bridge_post(message, backend):
    server_socket, client_socket = socket.socketpair()
    server = SimpleNamespace(backend=backend)
    thread = threading.Thread(target=bridge.McpHandler, args=(server_socket, ('fixture', 0), server), daemon=True)
    thread.start()
    try:
        body = json.dumps(message).encode()
        client_socket.sendall(b'POST /mcp HTTP/1.1\r\nHost: fixture\r\nContent-Type: application/json\r\n'
                              b'Accept: application/json, text/event-stream\r\nConnection: close\r\nContent-Length: '
                              + str(len(body)).encode() + b'\r\n\r\n' + body)
        response = http.client.HTTPResponse(client_socket)
        response.begin()
        assert response.status == 200
        return json.loads(response.read())
    finally:
        client_socket.close()
        thread.join(timeout=10)
        server_socket.close()
        assert not thread.is_alive()


def wait_health(docker):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            value = json.loads(docker.exec('daemon', '/usr/bin/curl', '-fsS', '--max-time', '2',
                                           'http://127.0.0.1:8787/healthz'))
            if value.get('ok') is True:
                return
        except (RuntimeError, json.JSONDecodeError):
            time.sleep(0.25)
    raise ValueError('Synthetic MemoryD daemon did not become healthy')


def check_bridge(docker):
    class Backend:
        def request(self, method, path, payload=None):
            assert method == 'GET' and path == '/v1/status' and payload is None
            return json.loads(docker.exec('daemon', '/usr/bin/curl', '-fsS', '--max-time', '5',
                                          'http://127.0.0.1:8787/v1/status'))

    backend = Backend()
    catalog = bridge_post({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}, backend)['result']['tools']
    assert [tool['name'] for tool in catalog] == ['memory_status', 'memory_recall', 'memory_search']
    assert all(t['annotations']['readOnlyHint'] is True and t['annotations']['destructiveHint'] is False for t in catalog)
    result = bridge_post({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                          'params': {'name': 'memory_status', 'arguments': {}}}, backend)['result']
    assert result['isError'] is False and json.loads(result['content'][0]['text'])['ok'] is True
    denied = bridge_post({'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
                          'params': {'name': 'memory_conclude', 'arguments': {}}}, backend)['result']
    assert denied['isError'] is True


def test_disposable_docker_memoryd_restore_and_restart(tmp_path, monkeypatch):
    assert os.getuid() != 0
    assert Path('/var/run/docker.sock').is_socket()
    tmp_path.chmod(0o700)
    config = tmp_path / 'docker-config'
    config.mkdir(mode=0o700)
    (config / 'config.json').write_text('{}\n')
    (config / 'config.json').chmod(0o600)
    monkeypatch.setenv('DOCKER_CONFIG', str(config))
    monkeypatch.setenv('DOCKER_HOST', 'unix:///var/run/docker.sock')
    monkeypatch.delenv('DOCKER_CONTEXT', raising=False)
    monkeypatch.delenv('DOCKER_AUTH_CONFIG', raising=False)
    activation_id = uuid.uuid4().hex
    volume = 'mcp-memoryd-fixture-' + activation_id
    monkeypatch.setattr(host, 'MEMORYD_VOLUME', volume)
    state = tmp_path / 'state'
    store = state / 'deployment'
    store.mkdir(parents=True, mode=0o700)
    state.chmod(0o700)
    monkeypatch.setattr(host, 'STATE', state)
    monkeypatch.setattr(host, 'STORE', store)
    fixture = DisposableDocker(activation_id, volume)
    assert volume not in fixture.docker('volume', 'ls', '--format', '{{.Name}}').decode().splitlines()
    assert all(fixture.container(name) is None for name in fixture.names.values())
    host._memoryd_restore_inventory()
    try:
        prepared, data, manifest_sha = prepared_fixture(tmp_path, fixture)
        monkeypatch.setattr(host, '_recovery_validator', lambda: lambda _path: data)
        marker = {'schema_version': 1, 'activation_id': activation_id, 'status': 'installing',
                  'source_sha': 'd' * 40, 'expected_identity': 'synthetic-identity', 'memoryd': data['memoryd'],
                  'prepared_manifest_sha256': manifest_sha, 'original_stopped_attested': True}
        host.write(store / 'activation-in-progress.json', marker)
        fixture.restore_uncertain = True
        try:
            result = host.activation_memoryd_restore(str(prepared), manifest_sha, activation_id)
        finally:
            receipt_path = store / f'memoryd-restore-{activation_id}.json'
            if receipt_path.is_file():
                receipt = json.loads(host.private(receipt_path))
                fixture.helper_name = receipt['helper_name']
                fixture.nonce = receipt['owner_nonce']
        assert result['memoryd_restored'] is True and receipt['status'] == 'verified'
        fixture.restore_uncertain = False
        assert fixture.volume_info() is not None
        with pytest.raises(ValueError, match='MemoryD'):
            host.activation_memoryd_restore(str(prepared), manifest_sha, activation_id)
        assert json.loads(host.private(receipt_path)) == receipt
        mount = 'type=volume,source=' + volume + ',target=/data'
        fixture.create('probe', mounts=[mount], entrypoint='/bin/sleep', user='10001:10001', command=['infinity'])
        probe = fixture.start('probe')
        host._memoryd_restore_target(probe, present=True)
        before = tmp_path / 'restored-before-start.db'
        host._memoryd_restore_copy_target(probe, before)
        host._memoryd_restore_private_hash(before, data['memoryd']['backup_sha256'], size=data['memoryd']['backup_size_bytes'])
        host._memoryd_restore_sqlite(before, data['memoryd'])
        fixture.remove_container(fixture.names['probe'])
        fixture.create('daemon', mounts=[mount], entrypoint='/usr/local/bin/codex-memoryd', user='10001:10001',
                       command=['serve'], env=['CODEX_MEMORYD_DB=/data/memory.db', 'CODEX_MEMORYD_BIND=127.0.0.1:8787'])
        fixture.start('daemon')
        wait_health(fixture)
        check_bridge(fixture)
        daemon = fixture.assert_owned(fixture.names['daemon'])
        fixture.docker('restart', '--time', '10', daemon['Id'])
        assert fixture.assert_owned(fixture.names['daemon'])['State']['Running'] is True
        wait_health(fixture)
        check_bridge(fixture)
        daemon = fixture.assert_owned(fixture.names['daemon'])
        fixture.docker('stop', '--time', '10', daemon['Id'])
        assert fixture.assert_owned(fixture.names['daemon'])['State']['Running'] is False
        fixture.create('probe', mounts=[mount], entrypoint='/bin/sleep', user='10001:10001', command=['infinity'])
        probe = fixture.start('probe')
        host._memoryd_restore_target(probe, present=True)
        after = tmp_path / 'restored-after-restart.db'
        host._memoryd_restore_copy_target(probe, after)
        assert stat.S_ISREG(after.lstat().st_mode)
        host._memoryd_restore_sqlite(after, data['memoryd'])
    finally:
        fixture.cleanup()
