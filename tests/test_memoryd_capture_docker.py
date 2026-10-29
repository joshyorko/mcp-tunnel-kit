"""Opt-in disposable Docker proof of the read-only MemoryD WAL snapshot."""

import json
import os
from pathlib import Path
import re
import select
import sqlite3
import subprocess
import tempfile
import uuid

import pytest

import vm_deploy_host as host


IMAGE = os.environ.get('MEMORYD_CAPTURE_DOCKER_IMAGE')
LABEL = 'mcp-tunnel-kit.memoryd-capture-fixture'


@pytest.mark.skipif(not IMAGE, reason='set MEMORYD_CAPTURE_DOCKER_IMAGE to the local pinned adapter image')
def test_readonly_snapshot_against_a_disposable_docker_volume(tmp_path, monkeypatch):
    if not re.fullmatch(r'ghcr\.io/joshyorko/codex-action-server@sha256:[a-f0-9]{64}', IMAGE):
        pytest.fail('Fixture requires a digest-pinned adapter image')
    token = uuid.uuid4().hex
    volume = 'mcp-memoryd-fixture-' + token
    init = 'mcp-memoryd-init-' + token
    writer = 'mcp-memoryd-writer-' + token
    helper = 'mcp-memoryd-helper-' + token
    label = LABEL + '=' + token
    real_run = subprocess.run
    owned_volume = False

    def docker(*args, check=True):
        result = real_run(['docker', *args], capture_output=True, text=True, timeout=60)
        if check and result.returncode:
            raise AssertionError('Synthetic Docker fixture command failed; output withheld')
        return result

    def owned(kind, name):
        if kind == 'volume':
            result = docker('volume', 'inspect', '--format', '{{json .Labels}}', name, check=False)
        else:
            result = docker('inspect', '--format', '{{json .Config.Labels}}', name, check=False)
        if result.returncode:
            return False
        labels = json.loads(result.stdout)
        if not isinstance(labels, dict) or labels.get(LABEL) != token:
            raise AssertionError('Fixture resource ownership mismatch; cleanup refused')
        return True

    try:
        if docker('volume', 'inspect', volume, check=False).returncode == 0:
            pytest.fail('Random fixture volume already exists')
        docker('image', 'inspect', IMAGE)
        docker('volume', 'create', '--label', label, volume)
        owned_volume = owned('volume', volume)
        assert owned_volume
        docker('run', '--rm', '--pull=never', '--network=none', '--read-only',
               '--name', init, '--label', label, '--user', '0:0',
               '--mount', 'type=volume,source=' + volume + ',target=/data',
               '--entrypoint', 'python3', IMAGE, '-c',
               "import os; os.chown('/data', 10001, 10001); os.chmod('/data', 0o700)")
        code = '''import sqlite3, time
db = sqlite3.connect('/data/memory.db')
db.execute('PRAGMA journal_mode=WAL')
db.execute('PRAGMA wal_autocheckpoint=0')
db.execute('CREATE TABLE synthetic (value TEXT)')
db.execute("INSERT INTO synthetic VALUES ('committed')")
db.commit()
print('READY', flush=True)
while True: time.sleep(1)
'''
        docker('run', '--detach', '--pull=never', '--network=none', '--read-only',
               '--name', writer, '--label', label, '--user', '10001:10001',
               '--mount', 'type=volume,source=' + volume + ',target=/data',
               '--entrypoint', 'python3', IMAGE, '-u', '-c', code)
        logs = subprocess.Popen(['docker', 'logs', '--follow', writer], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        try:
            if not select.select([logs.stdout], [], [], 30)[0] or logs.stdout.readline().strip() != 'READY':
                pytest.fail('Synthetic WAL writer did not become ready')
        finally:
            logs.terminate()
            logs.wait(timeout=10)
        docker('exec', '--user', '10001:10001', writer, 'python3', '-c',
               "import os; assert os.path.getsize('/data/memory.db-wal') > 0")

        def tagged_run(command, **kwargs):
            assert command[:2] == ['docker', 'run']
            assert 'type=volume,source=' + volume + ',target=/data,readonly' in command
            return real_run(command[:2] + ['--name', helper, '--label', label] + command[2:], **kwargs)

        with monkeypatch.context() as context:
            context.setattr(host, 'MEMORYD_VOLUME', volume)
            context.setattr(host.subprocess, 'run', tagged_run)
            with tempfile.TemporaryFile(dir=tmp_path) as spool:
                host._memoryd_capture_readonly_snapshot(IMAGE, spool)
                snapshot = tmp_path / 'snapshot.db'
                snapshot.write_bytes(spool.read())
        with sqlite3.connect(snapshot) as database:
            assert database.execute('PRAGMA integrity_check').fetchone() == ('ok',)
            assert database.execute('SELECT count(*) FROM synthetic').fetchone() == (1,)
        docker('exec', '--user', '10001:10001', writer, 'python3', '-c',
               "import os; assert os.path.getsize('/data/memory.db-wal') > 0")
    finally:
        for container in (helper, writer, init):
            if owned('container', container):
                docker('rm', '-f', container)
        if owned_volume and owned('volume', volume):
            docker('volume', 'rm', volume)
