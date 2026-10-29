"""Opt-in offline Executor identity proof from an encrypted recovery capture.

MCP_CAPTURED_EXECUTOR_RESTORE=1 opts in. Supply the private bundle and age
identity in MCP_CAPTURED_RECOVERY_BUNDLE and MCP_CAPTURED_RECOVERY_IDENTITY.
This does not activate a control plane, connect a tunnel, or attest the old VM stopped.
"""
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
import uuid

import pytest

import control_plane_recovery as encryption
import kamal_model
import prepare_recovery_generation as generation
import test_memoryd_executor_docker as harness
import test_memoryd_restore_docker as recovery
import vm_deploy_host as host


pytestmark = pytest.mark.skipif(
    os.environ.get('MCP_CAPTURED_EXECUTOR_RESTORE') != '1',
    reason='set MCP_CAPTURED_EXECUTOR_RESTORE=1 and private input paths for the offline Executor fixture',
)


class OfflineDocker(recovery.DisposableDocker):
    @staticmethod
    def docker(*args, timeout=120):
        if args and args[0] == 'create':
            args = ('create', '--log-driver', 'none', *args[1:])
        return recovery.DisposableDocker.docker(*args, timeout=timeout)


class OfflineExecutor(harness.Sidecars):
    def __init__(self, fixture, anchor_id, anchor_name, image):
        super().__init__(fixture, anchor_id)
        self.anchor_id = anchor_id
        self.anchor_name = anchor_name
        self.images['executor'] = image

    def anchor(self):
        row = self.fixture.container(self.anchor_name)
        labels = row['Config'].get('Labels') or {} if row else {}
        if (not row or row['Id'] != self.anchor_id or not row['State']['Running']
                or labels.get('mcp-control-plane.fixture') != self.fixture.activation_id
                or row['Config']['Image'] != harness.ADAPTER_IMAGE or row['Config']['User'] != '1000:1000'
                or row['HostConfig']['NetworkMode'] != 'none' or row['HostConfig']['LogConfig']['Type'] != 'none'
                or row['HostConfig'].get('Privileged') is not False or row['HostConfig'].get('PortBindings')
                or row['HostConfig'].get('PublishAllPorts') or row['Mounts']):
            raise ValueError('Offline namespace ownership changed')
        return row

    def owned(self, kind):
        row = super().owned(kind)
        if row is not None and (row['HostConfig']['LogConfig']['Type'] != 'none'
                                or row['HostConfig'].get('Privileged') is not False
                                or row['Config']['User'] != '1000:1000'):
            raise ValueError('Offline Executor isolation changed')
        return row

    def http(self, request):
        self.anchor()
        parsed = urllib.parse.urlsplit(request['url'])
        if (request['method'] != 'GET' or parsed.scheme != 'http' or parsed.hostname != '127.0.0.1'
                or parsed.port != 4312 or parsed.query or parsed.fragment
                or not (parsed.path in ('/api/context', '/api/auth/self-host/config')
                        or re.fullmatch(r'/api/organizations/[^/]+/inventory', parsed.path))):
            raise ValueError('Unexpected offline Executor request')
        self.uncertain = True
        try:
            result = subprocess.run(['docker', 'exec', '-i', self.anchor_id, 'python3', '-c', harness.HTTP_CLIENT],
                                    input=json.dumps(request).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=75)
        except subprocess.TimeoutExpired:
            raise TimeoutError('Offline HTTP command timed out; fixture retained') from None
        self.uncertain = False
        if result.returncode:
            raise RuntimeError('Offline HTTP request failed; response withheld')
        return json.loads(result.stdout)

    def urlopen(self, request, timeout=15):
        result = self.http({'method': request.get_method(), 'url': request.full_url,
                            'body': None, 'headers': dict(request.header_items())})
        return io.BytesIO(json.dumps(result['data']).encode())

    def wait_ready(self):
        deadline = time.monotonic() + 90
        while True:
            try:
                self.http({'method': 'GET', 'url': 'http://127.0.0.1:4312/api/auth/self-host/config',
                           'body': None, 'headers': {}})
                return
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.5)


def test_captured_executor_identity_restores_offline(monkeypatch):
    bundle = os.environ.get('MCP_CAPTURED_RECOVERY_BUNDLE')
    identity = os.environ.get('MCP_CAPTURED_RECOVERY_IDENTITY')
    if not bundle or not identity:
        pytest.fail('Both private recovery input paths are required.', pytrace=False)
    if os.getuid() != 1000 or os.getgid() != 1000 or not Path('/var/run/docker.sock').is_socket():
        pytest.fail('The fixture requires a UID/GID 1000 local Docker operator.', pytrace=False)

    root = Path(tempfile.mkdtemp(prefix='mcp-captured-executor-fixture-'))
    root.chmod(0o700)
    fixture = None
    sidecars = None
    anchor_id = None
    seed_id = None
    uncertain = False
    failed = None
    retained = False
    phase = 'private input validation'
    token = uuid.uuid4().hex
    anchor_name = 'mcp-executor-offline-anchor-' + token[:16]
    seed_name = 'mcp-executor-offline-seed-' + token[:16]
    try:
        if any(Path(path).resolve(strict=True).is_relative_to(root) for path in (bundle, identity)):
            raise ValueError('An input cannot reside inside the disposable fixture')
        temporary = root / 'temporary'
        temporary.mkdir(mode=0o700)
        monkeypatch.setenv('TMPDIR', str(temporary))
        monkeypatch.setattr(tempfile, 'tempdir', str(temporary))
        config = root / 'docker-config'
        config.mkdir(mode=0o700)
        (config / 'config.json').write_text('{}\n')
        (config / 'config.json').chmod(0o600)
        monkeypatch.setenv('DOCKER_CONFIG', str(config))
        monkeypatch.setenv('DOCKER_HOST', 'unix:///var/run/docker.sock')
        monkeypatch.delenv('DOCKER_CONTEXT', raising=False)
        monkeypatch.delenv('DOCKER_AUTH_CONFIG', raising=False)

        phase = 'encrypted verification and private preparation'
        if encryption.verify_bundle(bundle, identity).get('verified') is not True:
            raise ValueError('Encrypted bundle verification failed')
        staged = root / 'staged'
        encryption.restore_bundle(bundle, identity, staged)
        prepared = root / 'prepared'
        metadata = generation.prepare_generation(staged, prepared)
        if metadata.get('schema_version') != 3 or generation.validate_generation(prepared) != metadata:
            raise ValueError('A validated schema-3 generation is required')
        image = kamal_model.validate_manifest(metadata['generation']['manifest'])['executor']
        result = subprocess.run(['docker', 'image', 'inspect', image], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=30)
        if result.returncode:
            raise ValueError('Captured Executor image is not available locally')
        rows = json.loads(result.stdout)
        if len(rows) != 1 or rows[0].get('Os') != 'linux' or rows[0].get('Architecture') != 'amd64':
            raise ValueError('Captured Executor image architecture is invalid')

        phase = 'offline namespace and empty fixture volume'
        fixture = OfflineDocker(token, 'mcp-unused-' + token)
        if fixture.container(anchor_name) is not None:
            raise ValueError('Offline namespace name already exists')
        uncertain = True
        anchor_id = fixture.docker('create', '--pull', 'never', '--name', anchor_name, '--network', 'none',
                                   '--user', '1000:1000', '--read-only', '--label', 'mcp-control-plane.fixture=' + token,
                                   '--entrypoint', '/bin/sleep', harness.ADAPTER_IMAGE, 'infinity').decode().strip()
        anchor = fixture.container(anchor_name)
        if (not anchor or anchor['Id'] != anchor_id or anchor['State']['Running']
                or (anchor['Config'].get('Labels') or {}).get('mcp-control-plane.fixture') != token
                or anchor['Config']['Image'] != harness.ADAPTER_IMAGE or anchor['Config']['User'] != '1000:1000'
                or anchor['HostConfig']['NetworkMode'] != 'none' or anchor['HostConfig']['LogConfig']['Type'] != 'none'
                or anchor['HostConfig'].get('Privileged') is not False or anchor['HostConfig'].get('PortBindings')
                or anchor['HostConfig'].get('PublishAllPorts') or anchor['Mounts']):
            raise ValueError('Offline namespace create failed')
        fixture.docker('start', anchor_id)
        sidecars = OfflineExecutor(fixture, anchor_id, anchor_name, image)
        sidecars.anchor()
        uncertain = False
        sidecars.create_volume()
        phase = 'copy captured Executor data to disposable volume'
        uncertain = True
        seed_id = fixture.docker('create', '--pull', 'never', '--name', seed_name, '--network', 'none',
                                 '--user', '1000:1000', '--label', 'mcp-control-plane.fixture=' + token,
                                 '--mount', 'type=volume,source=' + sidecars.volume + ',target=/app/data',
                                 '--entrypoint', '/bin/true', image).decode().strip()
        seed = fixture.container(seed_name)
        if (not seed or seed['Id'] != seed_id or seed['State']['Running']
                or (seed['Config'].get('Labels') or {}).get('mcp-control-plane.fixture') != token
                or seed['Config']['Image'] != image or seed['Config']['User'] != '1000:1000'
                or seed['HostConfig']['NetworkMode'] != 'none'
                or seed['HostConfig']['LogConfig']['Type'] != 'none'
                or seed['HostConfig'].get('Privileged') is not False or seed['HostConfig'].get('PortBindings')
                or seed['HostConfig'].get('PublishAllPorts') or len(seed['Mounts']) != 1
                or seed['Mounts'][0].get('Type') != 'volume' or seed['Mounts'][0].get('Name') != sidecars.volume
                or seed['Mounts'][0].get('Destination') != '/app/data' or seed['Mounts'][0].get('RW') is not True):
            raise ValueError('Disposable seed ownership changed')
        archive = fixture.docker('cp', seed_id + ':/app/data', '-')
        with tarfile.open(fileobj=io.BytesIO(archive)) as source:
            members = source.getmembers()
            if len(members) != 1 or members[0].name != 'data' or members[0].uid != 1000 or members[0].gid != 1000:
                raise ValueError('Disposable Executor volume is not empty and correctly owned')
        fixture.docker('cp', '--archive', str(prepared / 'executor-data') + '/.', seed_id + ':/app/data')
        seed = fixture.container(seed_name)
        if not seed or seed['Id'] != seed_id or seed['State']['Running']:
            raise ValueError('Disposable seed changed during copy')
        fixture.docker('rm', seed_id)
        seed_id = None
        uncertain = False

        phase = 'start stock Executor in the offline namespace'
        env = ['DO_NOT_TRACK=1', 'EXECUTOR_DISABLE_ANALYTICS=1', 'HOST=127.0.0.1', 'PORT=4312',
               'BETTER_AUTH_URL=http://127.0.0.1:4312', 'EXECUTOR_DATA_DIR=/app/data']
        arguments = ['--init', '--user', '1000:1000', '--mount',
                     'type=volume,source=' + sidecars.volume + ',target=/app/data']
        for item in env:
            arguments.extend(['--env', item])
        arguments.append(image)
        uncertain = True
        sidecars.create('executor', arguments, {('volume', sidecars.volume, '/app/data', True)})
        uncertain = False
        sidecars.wait_ready()
        phase = 'captured identity verification and restart'
        monkeypatch.setattr(host, 'STATE', prepared / 'state')
        monkeypatch.setattr('urllib.request.urlopen', sidecars.urlopen)
        expected = metadata['generation']['identity']
        uncertain = True
        if host.identity(sidecars.owned('executor')['Id']) != expected:
            raise ValueError('Recovered Executor identity does not match capture')
        uncertain = False
        uncertain = True
        sidecars.restart_executor()
        uncertain = False
        sidecars.wait_ready()
        uncertain = True
        if host.identity(sidecars.owned('executor')['Id']) != expected:
            raise ValueError('Recovered Executor identity changed after restart')
        uncertain = False
    except Exception:
        failed = phase
    finally:
        if fixture is not None:
            try:
                if uncertain:
                    retained = True
                else:
                    if seed_id:
                        seed = fixture.container(seed_name)
                        if not seed or seed['Id'] != seed_id or seed['State']['Running']:
                            raise ValueError('Seed ownership unavailable')
                        fixture.docker('rm', seed_id)
                    if sidecars is not None and not sidecars.cleanup():
                        raise ValueError('Offline Executor cleanup is uncertain')
                    if anchor_id:
                        anchor = fixture.container(anchor_name)
                        if (not anchor or anchor['Id'] != anchor_id
                                or (anchor['Config'].get('Labels') or {}).get('mcp-control-plane.fixture') != token
                                or anchor['Config']['Image'] != harness.ADAPTER_IMAGE
                                or anchor['HostConfig']['NetworkMode'] != 'none' or anchor['Mounts']):
                            raise ValueError('Namespace ownership unavailable')
                        if anchor['State']['Running']:
                            fixture.docker('stop', '--time', '10', anchor_id)
                        fixture.docker('rm', anchor_id)
            except Exception:
                retained = True
        if not retained:
            try:
                shutil.rmtree(root)
            except OSError:
                retained = True
    if failed or retained:
        detail = f' Private fixture retained at {root} for inspection.' if retained else ''
        pytest.fail(f'Captured Executor fixture failed at {failed or "cleanup"}.{detail}', pytrace=False)
    print(json.dumps({'fixture': 'disposable_offline', 'executor_identity_matches_capture': True,
                      'executor_identity_survived_restart': True, 'host_ports_published': False,
                      'tunnel_started': False, 'original_stopped_attestation': False}, sort_keys=True))
