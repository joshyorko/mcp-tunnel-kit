import io
import hashlib
import json
from contextlib import nullcontext
from pathlib import Path
import tarfile
from unittest.mock import patch

import pytest

from collect_recovery import collect, unpack_snapshot


def archive(path, rows):
    with tarfile.open(path, 'w') as output:
        for name, kind in rows:
            member = tarfile.TarInfo(name)
            if kind == 'link':
                member.type = tarfile.SYMTYPE
                member.linkname = '/tmp/outside'
                output.addfile(member)
            else:
                member.size = 3
                output.addfile(member, io.BytesIO(b'abc'))


@pytest.mark.parametrize('rows', [
    [('vm-snapshot/../../outside', 'file')],
    [('/absolute', 'file')],
    [('vm-snapshot/link', 'link')],
    [('vm-snapshot/file', 'file'), ('vm-snapshot/file', 'file')],
])
def test_vm_transport_validation_precedes_any_extraction(tmp_path, rows):
    source = tmp_path / 'transport.tar'
    destination = tmp_path / 'destination'
    destination.mkdir(mode=0o700)
    archive(source, rows)
    with pytest.raises(ValueError, match='unsafe'):
        unpack_snapshot(source, destination)
    assert list(destination.iterdir()) == []


def test_vm_transport_restores_bytes_with_private_permissions(tmp_path):
    source = tmp_path / 'transport.tar'
    destination = tmp_path / 'destination'
    destination.mkdir(mode=0o700)
    archive(source, [('vm-snapshot/essential.tar', 'file')])
    unpack_snapshot(source, destination)
    restored = destination / 'vm-snapshot/essential.tar'
    assert restored.read_bytes() == b'abc'
    assert restored.stat().st_mode & 0o777 == 0o600


def test_collection_refuses_existing_destination_before_transport(tmp_path):
    tmp_path.chmod(0o700)
    destination = tmp_path / 'existing'
    destination.mkdir(mode=0o700)
    with patch('collect_recovery.deploy.configure_local') as configure:
        with pytest.raises(ValueError, match='new directory'):
            collect(Path('/unused'), Path('/unused'), Path('/unused'), destination)
        configure.assert_not_called()


def test_missing_private_profile_creates_no_capture_directory(tmp_path):
    tmp_path.chmod(0o700)
    destination = tmp_path / 'new'
    with patch('collect_recovery.deploy.configure_local', side_effect=ValueError('missing profile')):
        with pytest.raises(ValueError, match='missing profile'):
            collect(Path('/unused'), Path('/unused'), Path('/unused'), destination)
    assert not destination.exists()


@pytest.mark.parametrize('changed_field', ['authority', 'identity', 'source_sha'])
def test_stale_recorded_generation_refuses_before_backup_and_removes_own_staging(tmp_path, changed_field):
    tmp_path.chmod(0o700)
    requirements = tmp_path / 'requirements.json'
    requirements.write_text('{}')
    requirements.chmod(0o600)
    generation = {'authority': 'kamal', 'identity': 'preserved', 'source_sha': 'a' * 40}
    live = {**generation, changed_field: 'different', 'tunnel_count': 1}
    destination = tmp_path / 'capture'
    with patch('collect_recovery.deploy.configure_local'), patch('collect_recovery.deploy.trusted_context'):
        with patch('collect_recovery.load_native_profile', return_value={'state_dir': str(tmp_path / 'native')}):
            with patch('collect_recovery.copy_private'), patch('collect_recovery.deploy.lock', return_value=nullcontext()):
                with patch('collect_recovery.deploy.remote', side_effect=[generation, live]) as remote:
                    with pytest.raises(ValueError, match='Recorded generation differs'):
                        collect('/unused', '/unused', '/unused', destination, requirements)
                    assert [call.args[0] for call in remote.call_args_list] == ['current', 'snapshot']
    assert not destination.exists()


def test_collection_records_the_explicit_absence_of_memoryd(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    requirements = tmp_path / 'requirements.json'
    requirements.write_text('{}')
    requirements.chmod(0o600)
    source = tmp_path / 'executor.tar'
    source.write_bytes(b'synthetic executor snapshot')
    generation = {'authority': 'kamal', 'identity': 'preserved', 'source_sha': 'a' * 40}
    live = {**generation, 'tunnel_count': 1}
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    snapshot = {'backup': '/vm/state/deployment/backups/123', 'executor_sha256': digest,
                'memoryd': {'status': 'absent'}}
    calls = []

    def remote(action, data=None):
        calls.append((action, data))
        return {'current': generation, 'snapshot': live, 'backup': snapshot}[action]

    def transfer(_command, stdout, **_kwargs):
        with tarfile.open(fileobj=stdout, mode='w') as output:
            output.add(source, arcname='vm-snapshot/executor.tar')
        return type('Result', (), {'returncode': 0})()

    with patch('collect_recovery.deploy.configure_local'), patch('collect_recovery.deploy.trusted_context'), \
         patch('collect_recovery.load_native_profile', return_value={'state_dir': str(tmp_path / 'native')}), \
         patch('collect_recovery.copy_private'), patch('collect_recovery.deploy.lock', return_value=nullcontext()), \
         patch('collect_recovery.deploy.INSTANCE', {'vm': {'state_dir': '/vm/state'}}), \
         patch('collect_recovery.deploy.remote', side_effect=remote), \
         patch('collect_recovery.deploy.ssh_args', return_value=['fixture']), \
         patch('collect_recovery.subprocess.run', side_effect=transfer):
        collect('/unused', '/unused', '/unused', tmp_path / 'capture', requirements)
    receipt = json.loads((tmp_path / 'capture/capture-receipt.json').read_text())
    assert receipt['schema_version'] == 2
    assert receipt['memoryd'] == {'status': 'absent'}
    assert ('backup', {'include_memoryd': True}) in calls
