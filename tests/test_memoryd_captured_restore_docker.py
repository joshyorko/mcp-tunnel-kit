"""Opt-in, offline restore of a private encrypted capture into disposable Docker resources.

Set MCP_CAPTURED_MEMORYD_RESTORE=1, MCP_CAPTURED_RECOVERY_BUNDLE and
MCP_CAPTURED_RECOVERY_IDENTITY. The inputs are read only. This is a local
fixture, not a production activation or an original-stopped attestation.
"""
import json
import os
from pathlib import Path
import shutil
import tempfile
import uuid

import pytest

import control_plane_recovery as encryption
import prepare_recovery_generation as generation
import test_memoryd_restore_docker as disposable
import vm_deploy_host as host


pytestmark = pytest.mark.skipif(
    os.environ.get('MCP_CAPTURED_MEMORYD_RESTORE') != '1',
    reason='set MCP_CAPTURED_MEMORYD_RESTORE=1 and private input paths for the offline capture fixture',
)


class OfflineFixture(disposable.DisposableDocker):
    @staticmethod
    def docker(*args, timeout=120):
        if args and args[0] == 'create':
            args = ('create', '--log-driver', 'none', *args[1:])
        return disposable.DisposableDocker.docker(*args, timeout=timeout)

    def assert_owned(self, name, *, helper=False):
        row = super().assert_owned(name, helper=helper)
        if row is not None and not helper and row['HostConfig']['LogConfig']['Type'] != 'none':
            raise ValueError('The disposable container logging policy changed')
        return row


def test_captured_memoryd_restores_into_disposable_offline_volume(monkeypatch):
    bundle = os.environ.get('MCP_CAPTURED_RECOVERY_BUNDLE')
    identity = os.environ.get('MCP_CAPTURED_RECOVERY_IDENTITY')
    if not bundle or not identity:
        pytest.fail('Both private recovery input paths are required.', pytrace=False)
    if os.getuid() == 0 or not Path('/var/run/docker.sock').is_socket():
        pytest.fail('The disposable fixture requires a non-root local Docker operator.', pytrace=False)

    root = Path(tempfile.mkdtemp(prefix='mcp-captured-memoryd-fixture-'))
    root.chmod(0o700)
    fixture = None
    phase = 'private input validation'
    failed = None
    retained = False
    summary = None
    try:
        if any(Path(path).resolve(strict=True).is_relative_to(root) for path in (bundle, identity)):
            raise ValueError('An input cannot reside inside the disposable fixture')
        temporary = root / 'temporary'
        temporary.mkdir(mode=0o700)
        monkeypatch.setenv('TMPDIR', str(temporary))
        monkeypatch.setattr(tempfile, 'tempdir', str(temporary))
        docker_config = root / 'docker-config'
        docker_config.mkdir(mode=0o700)
        (docker_config / 'config.json').write_text('{}\n')
        (docker_config / 'config.json').chmod(0o600)
        monkeypatch.setenv('DOCKER_CONFIG', str(docker_config))
        monkeypatch.setenv('DOCKER_HOST', 'unix:///var/run/docker.sock')
        monkeypatch.delenv('DOCKER_CONTEXT', raising=False)
        monkeypatch.delenv('DOCKER_AUTH_CONFIG', raising=False)

        phase = 'encrypted bundle verification and private staging'
        if encryption.verify_bundle(bundle, identity).get('verified') is not True:
            raise ValueError('Encrypted bundle verification failed')
        staged = root / 'staged'
        encryption.restore_bundle(bundle, identity, staged)
        phase = 'real schema-3 generation preparation'
        prepared = root / 'prepared'
        metadata = generation.prepare_generation(staged, prepared)
        if (metadata.get('schema_version') != 3 or metadata.get('memoryd', {}).get('status') != 'captured'
                or generation.validate_generation(prepared) != metadata):
            raise ValueError('A validated captured MemoryD schema-3 generation is required')

        phase = 'disposable Docker restore preflight'
        activation_id = uuid.uuid4().hex
        volume = 'mcp-memoryd-fixture-' + activation_id
        state = root / 'fixture-state'
        store = state / 'deployment'
        store.mkdir(parents=True, mode=0o700)
        state.chmod(0o700)
        monkeypatch.setattr(host, 'MEMORYD_VOLUME', volume)
        monkeypatch.setattr(host, 'STATE', state)
        monkeypatch.setattr(host, 'STORE', store)
        fixture = OfflineFixture(activation_id, volume)
        host._memoryd_restore_inventory()
        manifest_sha = disposable.sha(prepared / 'prepared-manifest.json')
        marker = {
            'schema_version': 1, 'activation_id': activation_id, 'status': 'installing',
            'source_sha': metadata['generation']['source_sha'], 'expected_identity': metadata['expected_identity'],
            'memoryd': metadata['memoryd'], 'prepared_manifest_sha256': manifest_sha,
            'original_stopped_attested': True,
            'fixture_notice': 'Disposable local fixture only. This is not an original-stopped attestation.',
        }
        host.write(store / 'activation-in-progress.json', marker)

        phase = 'released MemoryD restore into an empty fixture volume'
        fixture.restore_uncertain = True
        try:
            result = host.activation_memoryd_restore(str(prepared), manifest_sha, activation_id)
        finally:
            receipt_path = store / f'memoryd-restore-{activation_id}.json'
            if receipt_path.is_file():
                receipt = json.loads(host.private(receipt_path))
                fixture.helper_name = receipt['helper_name']
                fixture.nonce = receipt['owner_nonce']
        if result.get('memoryd_restored') is not True or receipt.get('status') != 'verified':
            raise ValueError('The isolated MemoryD restore was not verified')
        fixture.restore_uncertain = False
        descriptor = metadata['memoryd']
        mount = 'type=volume,source=' + volume + ',target=/data'

        phase = 'restored database identity and counts'
        fixture.create('probe', mounts=[mount], entrypoint='/bin/sleep', user='10001:10001', command=['infinity'])
        probe = fixture.start('probe')
        before = root / 'restored-before-start.db'
        host._memoryd_restore_copy_target(probe, before)
        host._memoryd_restore_private_hash(before, descriptor['backup_sha256'], size=descriptor['backup_size_bytes'])
        host._memoryd_restore_sqlite(before, descriptor)
        fixture.remove_container(fixture.names['probe'])

        phase = 'offline MemoryD restart'
        fixture.create('daemon', mounts=[mount], entrypoint='/usr/local/bin/codex-memoryd', user='10001:10001',
                       command=['serve'], env=['CODEX_MEMORYD_DB=/data/memory.db', 'CODEX_MEMORYD_BIND=127.0.0.1:8787'])
        daemon_id = fixture.start('daemon')
        disposable.wait_health(fixture)
        if fixture.assert_owned(fixture.names['daemon'])['Id'] != daemon_id:
            raise ValueError('The isolated daemon identity changed')
        fixture.docker('restart', '--time', '10', daemon_id)
        disposable.wait_health(fixture)
        daemon = fixture.assert_owned(fixture.names['daemon'])
        fixture.docker('stop', '--time', '10', daemon['Id'])
        if fixture.assert_owned(fixture.names['daemon'])['State']['Running'] is not False:
            raise ValueError('The isolated daemon did not stop')

        phase = 'post-restart database identity and counts'
        fixture.create('probe', mounts=[mount], entrypoint='/bin/sleep', user='10001:10001', command=['infinity'])
        probe = fixture.start('probe')
        after = root / 'restored-after-restart.db'
        host._memoryd_restore_copy_target(probe, after)
        host._memoryd_restore_sqlite(after, descriptor)
        summary = {
            'fixture': 'disposable_offline', 'schema_version': 3, 'memoryd_restored': True,
            'identity_matches_capture': True, 'record_count': descriptor['record_count'],
            'active_record_count': descriptor['active_record_count'],
            'archived_record_count': descriptor['archived_record_count'], 'restart_verified': True,
            'original_stopped_attestation': False, 'executor_restored': False,
        }
    except Exception:
        failed = phase
    finally:
        if fixture is not None:
            try:
                fixture.cleanup()
                retained = fixture.restore_uncertain
            except Exception:
                retained = True
        if not retained:
            try:
                shutil.rmtree(root)
            except OSError:
                retained = True
    if failed or retained:
        detail = f' Private fixture retained at {root} for inspection.' if retained else ''
        pytest.fail(f'Captured MemoryD fixture failed at {failed or "cleanup"}.{detail}', pytrace=False)
    print(json.dumps(summary, sort_keys=True))
