"""Exercise the protected workflow's lifecycle argument construction."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


WORKFLOW = Path(__file__).parents[1] / '.github/workflows/deploy-control-plane.yml'


def lifecycle_script():
    text = WORKFLOW.read_text()
    step = text.split('      - name: Remove or rename a native target\n', 1)[1]
    body = step.split('        run: |\n', 1)[1]
    return '\n'.join(line[10:] for line in body.splitlines()) + '\n'


@pytest.mark.parametrize('operation', ['remove', 'rename'])
def test_lifecycle_dispatch_passes_inputs_as_literal_arguments(tmp_path, operation):
    fake = tmp_path / 'bin'
    fake.mkdir()
    python = fake / 'python3'
    python.write_text(f'#!{sys.executable}\nimport sys,json\nprint(json.dumps(sys.argv[1:]))\n')
    python.chmod(0o700)
    injected = 'device$(touch ' + str(tmp_path / 'should-not-exist') + ')'
    env = dict(os.environ, PATH=str(fake) + ':' + os.environ['PATH'],
               NATIVE_OPERATION=operation + '-native', NATIVE_NAME=injected,
               NATIVE_NEW_NAME='dakota-nvidia', NATIVE_TARGET='dakota-nvidia',
               NATIVE_CWD='/work/exact', NATIVE_THREAD_ID='persistent-thread',
               RUNNER_TEMP=str(tmp_path), GITHUB_STEP_SUMMARY=str(tmp_path / 'summary'))
    result = subprocess.run(['bash', '-c', lifecycle_script()], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    args = json.loads(result.stdout.splitlines()[0])
    assert args[0] == 'scripts/native_onboarding_controller.py'
    assert args[args.index('--operation') + 1] == operation
    assert args[args.index('--name') + 1] == injected
    assert args[args.index('--native-target') + 1] == 'dakota-nvidia'
    assert ('--new-name' in args) == (operation == 'rename')
    assert not (tmp_path / 'should-not-exist').exists()


def test_unknown_lifecycle_operation_fails_before_controller(tmp_path):
    env = dict(os.environ, NATIVE_OPERATION='unexpected', RUNNER_TEMP=str(tmp_path))
    result = subprocess.run(['bash', '-c', lifecycle_script()], env=env, capture_output=True, text=True)
    assert result.returncode != 0
    assert not (tmp_path / 'native-lifecycle-receipt.json').exists()
