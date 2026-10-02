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
            'launch-codex.zsh', 'launch-stateless-stub.zsh',
            'codex_mcp_check.py',
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
            'if sys.argv[1:] == ["run", "--help"]:\n'
            '    print("--mcp.server-url" if os.environ.get("FIXTURE_HTTP_SUPPORT", "1") == "1" else "--mcp.command")\n'
            '    sys.exit(0)\n'
            'Path(os.environ["TUNNEL_TEST_MARKER"]).write_text(json.dumps(sys.argv[1:]))\n'
        )
        self.client.chmod(0o700)
        fixture_bin = self.base / 'bin'
        fixture_bin.mkdir()
        (fixture_bin / 'tunnel-client').symlink_to(self.client)
        self.env = {
            'PATH': str(fixture_bin) + os.pathsep + os.environ.get('PATH', os.defpath),
            'HOME': str(self.base / 'home'),
            'TMPDIR': str(self.base),
            'CONTROL_PLANE_API_KEY': 'REPLACE_ME_OFFLINE_FIXTURE',
            'CONTROL_PLANE_TUNNEL_ID': 'REPLACE_ME_OFFLINE_TUNNEL_ID',
            'TUNNEL_CLIENT_BIN': str(self.client),
            'TUNNEL_TEST_MARKER': str(self.marker),
        }

    def run_launcher(self, name, *arguments):
        return subprocess.run(
            [ZSH, str(self.bundle / name), *arguments],
            cwd=self.bundle, env=self.env, capture_output=True, text=True, timeout=5,
        )

    def test_codex_check_uses_checkout_venv_without_invoking_tunnel(self):
        result = self.run_launcher('launch-codex.zsh', '--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('no MCP request or tunnel was started', result.stdout)
        self.assertFalse(self.marker.exists())
        self.assertFalse((self.base / 'runs.json').exists())

    def test_stateless_check_does_not_invoke_tunnel(self):
        result = self.run_launcher('launch-stateless-stub.zsh', '--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('no tunnel was started', result.stdout)
        self.assertFalse(self.marker.exists())

    def test_launchers_reject_unknown_arguments_before_tunnel(self):
        for name in ('launch-codex.zsh', 'launch-stateless-stub.zsh'):
            with self.subTest(name=name):
                result = self.run_launcher(name, '--invalid-option')
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('usage:', result.stderr)
                self.assertFalse(self.marker.exists())

    def test_codex_launch_uses_native_codex_http_without_profile_key(self):
        result = self.run_launcher('launch-codex.zsh')
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = json.loads(self.marker.read_text())
        self.assertEqual(arguments[:3], ['run', '--control-plane.api-key', 'env:CONTROL_PLANE_API_KEY'])
        self.assertNotIn(self.env['CONTROL_PLANE_API_KEY'], arguments)
        self.assertIn('127.0.0.1:0', arguments)
        self.assertNotIn('--mcp.command', arguments)
        self.assertEqual(arguments[arguments.index('--mcp.server-url') + 1],
                         'url=http://127.0.0.1:8087/mcp,channel=main')
        self.assertEqual(arguments[arguments.index('--control-plane.tunnel-id') + 1],
                         self.env['CONTROL_PLANE_TUNNEL_ID'])

    def test_stateless_launch_uses_configured_binary_and_embedded_stub(self):
        result = self.run_launcher('launch-stateless-stub.zsh')
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = json.loads(self.marker.read_text())
        self.assertEqual(arguments[:3], ['run', '--control-plane.api-key', 'env:CONTROL_PLANE_API_KEY'])
        self.assertNotIn(self.env['CONTROL_PLANE_API_KEY'], arguments)
        self.assertIn('--embedded-stateless-mcp-stub', arguments)
        self.assertIn('127.0.0.1:0', arguments)
        self.assertNotIn('--mcp.command', arguments)

    def test_codex_url_rejects_secrets_remote_hosts_and_mapping_injection(self):
        for url in ('http://user:secret@127.0.0.1:8087/mcp',
                    'http://example.com/mcp', 'http://127.0.0.1:8087/p/friday',
                    'http://127.0.0.1:8087/mcp?key=secret',
                    'http://127.0.0.1:8087/mcp,channel=other'):
            with self.subTest(url=url):
                self.env['CODEX_MCP_URL'] = url
                result = self.run_launcher('launch-codex.zsh')
                self.assertEqual(result.returncode, 2)
                self.assertNotIn('secret', result.stderr)
                self.assertFalse(self.marker.exists())

    def test_missing_control_plane_credentials_never_invokes_tunnel(self):
        self.env.pop('CONTROL_PLANE_API_KEY')
        result = self.run_launcher('launch-codex.zsh')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_incompatible_tunnel_client_fails_before_launch(self):
        self.env['FIXTURE_HTTP_SUPPORT'] = '0'
        result = self.run_launcher('launch-codex.zsh', '--check')
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.marker.exists())


if __name__ == '__main__':
    unittest.main()
