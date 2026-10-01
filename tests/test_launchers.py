"""Offline launcher checks; never start a real tunnel or use production keys."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ZSH = os.environ.get('ZSH_BIN') or shutil.which('zsh') or 'zsh'


class LauncherOfflineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.bundle = self.base / 'bundle'
        self.bundle.mkdir()
        for name in (
            'launch-friday.zsh', 'launch-stateless-stub.zsh',
            'friday_mcp_adapter.py', 'friday_contract.py', 'friday_tools.py',
        ):
            shutil.copy2(ROOT / name, self.bundle / name)
        venv_bin = self.bundle / '.venv' / 'bin'
        venv_bin.mkdir(parents=True)
        fixture_python = venv_bin / 'python'
        fixture_python.write_text('#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' "$@"\n')
        fixture_python.chmod(0o700)
        self.marker = self.base / 'tunnel-invocation.json'
        self.client = self.base / 'offline-tunnel-fixture'
        self.client.write_text(
            '#!' + sys.executable + '\n'
            'import json, os, sys\n'
            'from pathlib import Path\n'
            'Path(os.environ["TUNNEL_TEST_MARKER"]).write_text(json.dumps(sys.argv[1:]))\n'
        )
        self.client.chmod(0o700)
        fixture_bin = self.base / 'bin'
        fixture_bin.mkdir()
        (fixture_bin / 'tunnel-client').symlink_to(self.client)
        profile = self.base / 'friday-api.env'
        profile.write_text('API_SERVER_KEY=REPLACE_ME_OFFLINE_FIXTURE\n')
        self.env = {
            'PATH': str(fixture_bin) + os.pathsep + os.environ.get('PATH', os.defpath),
            'HOME': str(self.base / 'home'),
            'TMPDIR': str(self.base),
            'CONTROL_PLANE_API_KEY': 'REPLACE_ME_OFFLINE_FIXTURE',
            'CONTROL_PLANE_TUNNEL_ID': 'REPLACE_ME_OFFLINE_TUNNEL_ID',
            'FRIDAY_API_ENV_FILE': str(profile),
            'FRIDAY_RUN_REGISTRY': str(self.base / 'runs.json'),
            'TUNNEL_CLIENT_BIN': str(self.client),
            'TUNNEL_TEST_MARKER': str(self.marker),
        }

    def run_launcher(self, name, *arguments):
        return subprocess.run(
            [ZSH, str(self.bundle / name), *arguments],
            cwd=self.bundle, env=self.env, capture_output=True, text=True, timeout=5,
        )

    def test_friday_check_uses_checkout_venv_without_invoking_tunnel(self):
        result = self.run_launcher('launch-friday.zsh', '--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('no API request or tunnel was started', result.stdout)
        self.assertFalse(self.marker.exists())
        self.assertFalse((self.base / 'runs.json').exists())

    def test_stateless_check_does_not_invoke_tunnel(self):
        result = self.run_launcher('launch-stateless-stub.zsh', '--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('no tunnel was started', result.stdout)
        self.assertFalse(self.marker.exists())

    def test_launchers_reject_unknown_arguments_before_tunnel(self):
        for name in ('launch-friday.zsh', 'launch-stateless-stub.zsh'):
            with self.subTest(name=name):
                result = self.run_launcher(name, '--invalid-option')
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('usage:', result.stderr)
                self.assertFalse(self.marker.exists())

    def test_friday_launch_uses_env_reference_and_stdio_adapter(self):
        result = self.run_launcher('launch-friday.zsh')
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = json.loads(self.marker.read_text())
        self.assertEqual(arguments[:3], ['run', '--control-plane.api-key', 'env:CONTROL_PLANE_API_KEY'])
        self.assertNotIn(self.env['CONTROL_PLANE_API_KEY'], arguments)
        self.assertIn('127.0.0.1:0', arguments)
        command = arguments[arguments.index('--mcp.command') + 1]
        self.assertIn(str(self.bundle / '.venv' / 'bin' / 'python'), command)
        self.assertIn('friday_mcp_adapter.py,channel=main', command)

    def test_stateless_launch_uses_configured_binary_and_embedded_stub(self):
        result = self.run_launcher('launch-stateless-stub.zsh')
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = json.loads(self.marker.read_text())
        self.assertEqual(arguments[:3], ['run', '--control-plane.api-key', 'env:CONTROL_PLANE_API_KEY'])
        self.assertNotIn(self.env['CONTROL_PLANE_API_KEY'], arguments)
        self.assertIn('--embedded-stateless-mcp-stub', arguments)
        self.assertIn('127.0.0.1:0', arguments)
        self.assertNotIn('--mcp.command', arguments)

    def test_adapter_has_portable_shebang(self):
        self.assertEqual((ROOT / 'friday_mcp_adapter.py').read_text().splitlines()[0], '#!/usr/bin/env python3')


if __name__ == '__main__':
    unittest.main()
