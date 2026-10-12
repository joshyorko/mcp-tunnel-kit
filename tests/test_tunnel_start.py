import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def test_tunnel_waits_for_upstream_before_starting_exact_child(tmp_path):
    tools = tmp_path / 'bin'
    tools.mkdir()
    (tools / 'wget').write_text('''#!/bin/sh
n=0; [ ! -f "$TEST_STATE" ] || n=$(cat "$TEST_STATE")
n=$((n+1)); printf '%s' "$n" > "$TEST_STATE"
[ "$n" -ge 3 ]
''')
    (tools / 'sleep').write_text('#!/bin/sh\nexit 0\n')
    for f in tools.iterdir(): f.chmod(0o700)
    marker = tmp_path / 'started'
    state = tmp_path / 'attempts'
    env = {**os.environ, 'PATH': str(tools)+':'+os.environ['PATH'], 'TEST_STATE': str(state)}
    r = subprocess.run(['sh', str(ROOT/'scripts/tunnel-start.sh'), 'sh', '-c',
                        'test "$(cat "$1")" = 3 && printf started > "$2"', 'child', str(state), str(marker)],
                       env=env, capture_output=True, text=True, timeout=5)
    assert r.returncode == 0 and marker.read_text() == 'started'
    assert r.stdout == r.stderr == ''


def test_tunnel_wrapper_requires_explicit_child():
    assert subprocess.run(['sh', str(ROOT/'scripts/tunnel-start.sh')], capture_output=True).returncode == 2
