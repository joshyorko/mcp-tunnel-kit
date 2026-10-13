import subprocess
from unittest.mock import patch

import pytest

import transfer_recovery_generation as transfer


def test_invalid_generation_never_configures_or_calls_transport():
    with patch.object(transfer, 'validate_generation', side_effect=transfer.GenerationError('invalid')):
        with patch.object(transfer.deploy, 'configure_local') as configure:
            with pytest.raises(transfer.GenerationError):
                transfer.transfer('/private/env', '/private/profile', '/private/invalid', '/private/new')
            configure.assert_not_called()


def test_relative_vm_destination_refuses_before_transport():
    with patch.object(transfer, 'validate_generation', return_value={'expected_identity': 'x'}):
        with patch.object(transfer.deploy, 'configure_local'), patch.object(transfer.deploy, 'trusted_context'):
            with patch.object(transfer.subprocess, 'run') as run:
                with pytest.raises(ValueError, match='absolute'):
                    transfer.transfer('/private/env', '/private/profile', '/private/generation', 'relative')
                run.assert_not_called()


def test_remote_generation_path_guard_does_not_create_directories():
    result = subprocess.run(
        ['python3', '-c', transfer.REMOTE, '/tmp/not-an-approved-staging-path', 'unused-validator'],
        input=b'', capture_output=True,
    )
    assert result.returncode != 0
    assert b'Destination must be one new directory' in result.stderr
