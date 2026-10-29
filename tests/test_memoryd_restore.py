"""MemoryD recovery must never overwrite or silently accept an uncertain restore."""

import hashlib
import json
import subprocess
import sqlite3

import pytest

import vm_deploy_host as host


def sha(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def recovery(tmp_path, monkeypatch):
    state = tmp_path / "state"
    store = state / "deployment"
    store.mkdir(parents=True, mode=0o700)
    state.chmod(0o700)
    prepared = tmp_path / "prepared"
    payload = prepared / "memoryd"
    payload.mkdir(parents=True, mode=0o700)
    prepared.chmod(0o700)
    backup = payload / "backup.db"
    with sqlite3.connect(backup) as db:
        db.executescript("""
            CREATE TABLE instance_metadata (singleton_key TEXT, instance_id TEXT);
            CREATE TABLE memory_records (profile_id TEXT, workspace_id TEXT, archived INTEGER);
            INSERT INTO instance_metadata VALUES ('default', 'cmi_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
            INSERT INTO memory_records VALUES ('personal', 'dakota-codex-only', 0);
            INSERT INTO memory_records VALUES ('personal', 'dakota-codex-only', 1);
        """)
    backup.chmod(0o600)
    manifest = payload / "backup.db.manifest.json"
    manifest.write_text(json.dumps({"sha256": "sha256:" + sha(backup.read_bytes()),
                                    "size_bytes": backup.stat().st_size}) + '\n')
    manifest.chmod(0o600)
    descriptor = {
        "status": "captured", "backend_image": host.MEMORYD_IMAGE,
        "adapter_image": "ghcr.io/joshyorko/codex-action-server@sha256:" + "b" * 64,
        "adapter_sha256": "c" * 64, "backup_sha256": sha(backup.read_bytes()),
        "backup_manifest_sha256": sha(manifest.read_bytes()), "backup_size_bytes": backup.stat().st_size,
        "source_instance_id": "cmi_" + "a" * 32, "record_count": 2,
        "active_record_count": 1, "archived_record_count": 1,
        "profile": "personal", "workspace": "dakota-codex-only", "captured_at": "2026-10-29T00:00:00Z",
    }
    prepared_data = {"schema_version": 2, "memoryd": descriptor,
                     "generation": {"source_sha": "d" * 40}, "expected_identity": "synthetic"}
    prepared_manifest = prepared / "prepared-manifest.json"
    prepared_manifest.write_text(json.dumps(prepared_data) + "\n")
    prepared_manifest.chmod(0o600)
    manifest_sha = sha(prepared_manifest.read_bytes())
    activation_id = "e" * 32
    marker = {"schema_version": 1, "activation_id": activation_id, "status": "installing",
              "source_sha": "d" * 40, "expected_identity": "synthetic", "memoryd": descriptor,
              "prepared_manifest_sha256": manifest_sha, "original_stopped_attested": True}
    marker_path = store / "activation-in-progress.json"
    marker_path.write_text(json.dumps(marker) + "\n")
    marker_path.chmod(0o600)
    monkeypatch.setattr(host, "STATE", state)
    monkeypatch.setattr(host, "STORE", store)
    monkeypatch.setattr(host, "_recovery_validator", lambda: lambda _path: prepared_data)
    return {"prepared": prepared, "sha": manifest_sha, "id": activation_id, "descriptor": descriptor,
            "store": store, "backup": backup, "manifest": manifest}


def test_existing_volume_refused_before_writing_intent(recovery, monkeypatch):
    commands = []

    def docker(args, **kwargs):
        commands.append(args)
        if args == ['docker', 'ps', '-aq']:
            return b''
        if args == ['docker', 'volume', 'ls', '--format', '{{.Name}}']:
            return b'codex-memoryd-data\n'
        if args == ['ss', '-Hln']:
            return b''
        raise AssertionError(f"unexpected operation: {args}")

    monkeypatch.setattr(host, "run", docker)
    with pytest.raises(ValueError, match="MemoryD"):
        host.activation_memoryd_restore(str(recovery["prepared"]), recovery["sha"], recovery["id"])
    assert not (recovery["store"] / f'memoryd-restore-{recovery["id"]}.json').exists()
    assert not any(args[:3] == ['docker', 'volume', 'create'] for args in commands)


class FakeDocker:
    """A small isolated Docker boundary; the host still checks real SQLite copies."""

    def __init__(self, descriptor):
        self.descriptor = descriptor
        self.volume = None
        self.container = None
        self.files = {}
        self.preview_safe = True
        self.appear_after_preview = False
        self.appear_after_verify = False
        self.sidecar_after_preview = False
        self.foreign_writer_after_preview = False
        self.scratch_changed_after_verify = False
        self.scratch_sidecar_after_verify = False
        self.corrupt_target = False
        self.interrupt_apply = False
        self.inflight = False
        self.apply_calls = 0
        self.preview_calls = 0
        self.foreign = None

    def pipe(self, container, source, destination):
        assert container == 'fixture-container-id'
        self.files[destination] = source.read_bytes()

    def copy_target(self, container, destination):
        assert container == 'fixture-container-id'
        destination.write_bytes(self.files['/data/memory.db'])
        destination.chmod(0o600)

    def run(self, args, **kwargs):
        if args == ['docker', 'ps', '-aq']:
            return ((b'fixture-container-id\n' if self.container else b'') +
                    (b'foreign-id\n' if self.foreign else b''))
        if args == ['docker', 'volume', 'ls', '--format', '{{.Name}}']:
            return b'codex-memoryd-data\n' if self.volume else b''
        if args == ['ss', '-Hln']:
            return b''
        if args[:3] == ['docker', 'image', 'inspect']:
            return json.dumps([{'Id': 'sha256:' + '1' * 64, 'Architecture': 'amd64', 'Os': 'linux',
                                'RepoDigests': [host.MEMORYD_IMAGE]}]).encode()
        if args[:3] == ['docker', 'volume', 'create']:
            assert self.volume is None
            assert args[3:5] == ['--driver', 'local']
            labels = dict(args[i + 1].split('=', 1) for i, x in enumerate(args) if x == '--label')
            self.volume = {'Name': args[-1], 'Labels': labels, 'Driver': 'local', 'Scope': 'local', 'Options': {}}
            return b'codex-memoryd-data\n'
        if args[:3] == ['docker', 'volume', 'inspect']:
            return json.dumps([self.volume]).encode()
        if args[:2] == ['docker', 'create']:
            def opt(name): return args[args.index(name) + 1]
            labels = dict(args[i + 1].split('=', 1) for i, x in enumerate(args) if x == '--label')
            assert opt('--network') == 'none' and opt('--pull') == 'never'
            assert opt('--user') == '10001:10001'
            assert args[-2:] == [host.MEMORYD_IMAGE, 'infinity']
            self.container = {'Id': 'fixture-container-id', 'Name': '/' + opt('--name'),
                              'Image': 'sha256:' + '1' * 64,
                              'Config': {'Image': host.MEMORYD_IMAGE, 'User': '10001:10001', 'Labels': labels,
                                         'Entrypoint': ['/bin/sleep'], 'Cmd': ['infinity'],
                                         'Healthcheck': {'Test': ['NONE']}},
                              'HostConfig': {'NetworkMode': 'none'}, 'State': {'Running': False, 'Paused': False},
                              'Mounts': [{'Name': host.MEMORYD_VOLUME, 'Destination': '/data', 'RW': True}]}
            return b'fixture-container-id\n'
        if args[:2] == ['docker', 'inspect']:
            return json.dumps([self.container if identifier == 'fixture-container-id' else self.foreign
                               for identifier in args[2:]]).encode()
        if args[:2] == ['docker', 'start']:
            self.container['State']['Running'] = True
            return b'fixture-container-id\n'
        if args[:2] == ['docker', 'top']:
            return b'PID COMMAND\n1 sleep\n2 codex-memoryd\n' if self.inflight else b'PID COMMAND\n1 sleep\n'
        if args[:2] == ['docker', 'stop']:
            self.container['State']['Running'] = False
            return b'fixture-container-id\n'
        if args[:2] == ['docker', 'rm']:
            assert not self.container['State']['Running']
            self.container = None
            return b'fixture-container-id\n'
        if args[:2] != ['docker', 'exec']:
            raise AssertionError(f'unexpected command: {args}')
        assert args[2:5] == ['--user', '10001:10001', 'fixture-container-id']
        command = args[5:]
        if command[:2] == ['/bin/mkdir', '-m'] or command[0] == '/usr/bin/sync':
            return b''
        if command[:2] == ['/bin/sh', '-c']:
            if 'TARGET_ABSENT' in command[2]:
                if any(p in self.files for p in ('/data/memory.db', '/data/memory.db-wal', '/data/memory.db-shm', '/data/memory.db-journal')):
                    raise RuntimeError('target exists')
            elif 'TARGET_PRESENT' in command[2]:
                if '/data/memory.db' not in self.files or any(p in self.files for p in ('/data/memory.db-wal', '/data/memory.db-shm', '/data/memory.db-journal')):
                    raise RuntimeError('target invalid')
            elif 'SCRATCH_FILES' in command[2]:
                if any(path not in self.files for path in ('/tmp/restore/backup.db', '/tmp/restore/backup.db.manifest.json')):
                    raise RuntimeError('scratch files missing')
                if any(path in self.files for path in ('/tmp/restore/backup.db-wal', '/tmp/restore/backup.db-shm', '/tmp/restore/backup.db-journal')):
                    raise RuntimeError('scratch sidecar exists')
            else:
                raise AssertionError(f'unexpected shell command: {command}')
            return b''
        if command[0] == '/usr/bin/sha256sum':
            path = command[-1]
            return (sha(self.files[path]) + '  ' + path + '\n').encode()
        if command[0] == '/usr/local/bin/codex-memoryd':
            operation = command[2]
            assert command[1] == 'backup' and '--local' in command and '--db' in command
            verify = {'ok': True, 'digest_matches': True, 'integrity_ok': True, 'schema_matches': True,
                      'manifest': {'sha256': 'sha256:' + self.descriptor['backup_sha256'],
                                   'size_bytes': self.descriptor['backup_size_bytes']}, 'issues': []}
            if operation == 'verify':
                if self.scratch_changed_after_verify:
                    self.files['/tmp/restore/backup.db'] = b'changed'
                if self.scratch_sidecar_after_verify:
                    self.files['/tmp/restore/backup.db-wal'] = b'unknown'
                if self.appear_after_verify:
                    self.files['/data/memory.db'] = b'foreign target'
                return json.dumps(verify).encode()
            assert command[command.index('--target') + 1] == '/data/memory.db'
            if operation == 'restore-preview':
                self.preview_calls += 1
                if '/data/memory.db' in self.files:
                    self.files['/data/memory.db'] = b'mutated by preview'
                    return json.dumps({'safe_to_apply': True, 'target_exists': True, 'verify': verify}).encode()
                if self.appear_after_preview:
                    self.files['/data/memory.db'] = b'foreign target'
                if self.sidecar_after_preview:
                    self.files['/data/memory.db-wal'] = b'foreign wal'
                if self.foreign_writer_after_preview:
                    self.foreign = {'Id': 'foreign-id', 'Name': '/unrelated',
                                    'Config': {'Image': 'busybox', 'Labels': {}},
                                    'Mounts': [{'Name': host.MEMORYD_VOLUME, 'RW': True}]}
                return json.dumps({'safe_to_apply': self.preview_safe, 'target_exists': False, 'verify': verify}).encode()
            assert operation == 'restore-apply'
            self.apply_calls += 1
            if self.interrupt_apply:
                self.files['/data/memory.db'] = b'partial target'
                self.inflight = True
                raise KeyboardInterrupt
            backup = self.files['/tmp/restore/backup.db']
            self.files['/data/memory.db'] = (bytes([backup[0] ^ 1]) + backup[1:]) if self.corrupt_target else backup
            return json.dumps({'restored': True, 'target_path': '/data/memory.db', 'prior_backup': None}).encode()
        raise AssertionError(f'unexpected exec: {command}')


@pytest.fixture
def docker(recovery, monkeypatch):
    fake = FakeDocker(recovery['descriptor'])
    monkeypatch.setattr(host, 'run', fake.run)
    monkeypatch.setattr(host, '_memoryd_restore_pipe', fake.pipe, raising=False)
    monkeypatch.setattr(host, '_memoryd_restore_copy_target', fake.copy_target, raising=False)
    return fake


def activate(recovery):
    return host.activation_memoryd_restore(str(recovery['prepared']), recovery['sha'], recovery['id'])


def read_receipt(recovery):
    return json.loads((recovery['store'] / f'memoryd-restore-{recovery["id"]}.json').read_text())


def test_success_records_verified_receipt_with_exact_restored_bytes(recovery, docker):
    result = activate(recovery)
    assert result['memoryd_restored'] is True
    assert docker.files['/data/memory.db'] == recovery['backup'].read_bytes()
    receipt = read_receipt(recovery)
    assert receipt['status'] == 'verified' and receipt['activation_id'] == recovery['id']
    assert receipt['prepared_manifest_sha256'] == recovery['sha']
    for field in ('backup_sha256', 'source_instance_id', 'record_count', 'active_record_count', 'archived_record_count'):
        assert receipt[field] == recovery['descriptor'][field]
    assert receipt['volume'] == 'codex-memoryd-data'
    assert docker.container is None
    assert docker.volume['Labels']['mcp-control-plane.recovery-activation'] == recovery['id']


def test_unsafe_preview_never_applies_and_preserves_volume(recovery, docker):
    docker.preview_safe = False
    with pytest.raises(ValueError, match='preview'):
        activate(recovery)
    assert docker.apply_calls == 0 and docker.volume is not None
    assert read_receipt(recovery)['status'] == 'intent'


def test_target_that_appears_after_preview_is_not_overwritten(recovery, docker):
    docker.appear_after_preview = True
    with pytest.raises(RuntimeError, match='target exists'):
        activate(recovery)
    assert docker.apply_calls == 0
    assert docker.files['/data/memory.db'] == b'foreign target'
    assert read_receipt(recovery)['status'] == 'intent'


def test_target_that_appears_after_verify_is_not_opened_by_preview(recovery, docker):
    docker.appear_after_verify = True
    with pytest.raises(RuntimeError, match='target exists'):
        activate(recovery)
    assert docker.preview_calls == 0 and docker.apply_calls == 0
    assert docker.files['/data/memory.db'] == b'foreign target'
    assert read_receipt(recovery)['status'] == 'intent'


def test_target_hash_mismatch_preserves_volume_and_does_not_verify(recovery, docker):
    docker.corrupt_target = True
    with pytest.raises(ValueError, match='digest'):
        activate(recovery)
    assert docker.volume is not None and docker.files['/data/memory.db'] != recovery['backup'].read_bytes()
    assert read_receipt(recovery)['status'] == 'intent'


def test_scratch_mutation_during_verify_refuses_before_apply(recovery, docker):
    docker.scratch_changed_after_verify = True
    with pytest.raises(ValueError, match='scratch backup digest'):
        activate(recovery)
    assert docker.apply_calls == 0 and docker.volume is not None
    assert recovery['backup'].read_bytes() != b'changed'
    assert read_receipt(recovery)['status'] == 'intent'


def test_scratch_wal_after_verify_refuses_before_apply(recovery, docker):
    docker.scratch_sidecar_after_verify = True
    with pytest.raises(RuntimeError, match='scratch sidecar'):
        activate(recovery)
    assert docker.apply_calls == 0 and docker.volume is not None
    assert read_receipt(recovery)['status'] == 'intent'


def test_target_wal_that_appears_after_preview_is_not_removed(recovery, docker):
    docker.sidecar_after_preview = True
    with pytest.raises(RuntimeError, match='target exists'):
        activate(recovery)
    assert docker.apply_calls == 0 and docker.files['/data/memory.db-wal'] == b'foreign wal'
    assert read_receipt(recovery)['status'] == 'intent'


def test_other_volume_writer_blocks_apply(recovery, docker):
    docker.foreign_writer_after_preview = True
    with pytest.raises(ValueError, match='writer'):
        activate(recovery)
    assert docker.apply_calls == 0 and docker.volume is not None
    assert read_receipt(recovery)['status'] == 'intent'


def test_interrupted_apply_preserves_volume_and_uncertain_helper(recovery, docker):
    docker.interrupt_apply = True
    with pytest.raises(KeyboardInterrupt):
        activate(recovery)
    assert docker.volume is not None and docker.container is not None
    assert docker.files['/data/memory.db'] == b'partial target'
    assert read_receipt(recovery)['status'] == 'intent'
    with pytest.raises(ValueError, match='MemoryD'):
        activate(recovery)


def test_marker_descriptor_mismatch_refuses_before_any_mutation(recovery, docker):
    marker_path = recovery['store'] / 'activation-in-progress.json'
    marker = json.loads(marker_path.read_text())
    marker['memoryd']['record_count'] = 100
    marker_path.write_text(json.dumps(marker))
    with pytest.raises(ValueError, match='activation'):
        activate(recovery)
    assert docker.volume is None
    assert not (recovery['store'] / f'memoryd-restore-{recovery["id"]}.json').exists()


def test_wrong_scoped_counts_never_publish_verified_receipt(recovery, docker, monkeypatch):
    prepared_path = recovery['prepared'] / 'prepared-manifest.json'
    prepared = json.loads(prepared_path.read_text())
    prepared['memoryd']['active_record_count'] = 2
    prepared['memoryd']['archived_record_count'] = 0
    prepared_path.write_text(json.dumps(prepared) + '\n')
    recovery['sha'] = sha(prepared_path.read_bytes())
    marker_path = recovery['store'] / 'activation-in-progress.json'
    marker = json.loads(marker_path.read_text())
    marker['memoryd'] = prepared['memoryd']
    marker['prepared_manifest_sha256'] = recovery['sha']
    marker_path.write_text(json.dumps(marker) + '\n')
    monkeypatch.setattr(host, '_recovery_validator', lambda: lambda _path: prepared)
    with pytest.raises(ValueError, match='scoped record counts'):
        activate(recovery)
    assert docker.volume is not None and docker.container is not None
    assert read_receipt(recovery)['status'] == 'intent'


def test_occupied_listener_refuses_before_creating_intent(recovery, docker):
    original = docker.run
    def listener(args, **kwargs):
        if args == ['ss', '-Hln']:
            return b'tcp LISTEN 0 128 127.0.0.1:8787 0.0.0.0:*\n'
        return original(args, **kwargs)
    host_run = host.run
    try:
        host.run = listener
        with pytest.raises(ValueError, match='listener'):
            activate(recovery)
    finally:
        host.run = host_run
    assert docker.volume is None
    assert not (recovery['store'] / f'memoryd-restore-{recovery["id"]}.json').exists()


def test_helper_shell_checks_are_valid_posix_shell(monkeypatch):
    scripts = []
    def capture(_helper, *args):
        if args[:2] == ('/bin/sh', '-c'):
            scripts.append(args[2])
        elif args[:2] == ('/usr/bin/sha256sum', '--'):
            return ('a' * 64 + '  ' + args[2] + '\n').encode()
        return b''
    monkeypatch.setattr(host, '_memoryd_restore_exec', capture)
    monkeypatch.setattr(host, '_memoryd_restore_sources', lambda *_: None)
    descriptor = {'backup_sha256': 'a' * 64, 'backup_manifest_sha256': 'a' * 64}
    host._memoryd_restore_target('fixture', present=False)
    host._memoryd_restore_target('fixture', present=True)
    host._memoryd_restore_scratch('fixture', {}, descriptor)
    assert len(scripts) == 3
    for script in scripts:
        assert subprocess.run(['/bin/sh', '-n'], input=script, text=True, capture_output=True).returncode == 0
