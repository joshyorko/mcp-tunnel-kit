import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "native_codex_ssh.py"
SPEC = importlib.util.spec_from_file_location("native_codex_ssh", MODULE_PATH)
native = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native)


class NativeCodexSSHTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = Path(self.temp.name) / "private"
        self.state.mkdir(mode=0o700)
        os.chmod(self.state, 0o700)
        self.host_key = self.state / "ssh_host_ed25519_key"
        self.authorized_keys = self.state / "authorized_keys"
        self.pid_file = self.state / "sshd.pid"
        for path in (self.host_key, self.authorized_keys):
            path.write_text("test\n")
            os.chmod(path, 0o600)

    def tearDown(self):
        self.temp.cleanup()

    def render(self, **changes):
        values = dict(
            address="100.81.124.110", port=22222, state_dir=self.state,
            host_key=self.host_key, authorized_keys=self.authorized_keys,
            pid_file=self.pid_file, helper=Path("/opt/native_codex_ssh.py"),
        )
        values.update(changes)
        return native.render_config(**values)

    def test_config_is_tailnet_bound_and_disables_interactive_and_forwarding_features(self):
        config = self.render()
        self.assertIn("ListenAddress 100.81.124.110\n", config)
        self.assertIn("Port 22222\n", config)
        self.assertIn("AllowUsers " + __import__("pwd").getpwuid(os.geteuid()).pw_name + "\n", config)
        for directive in (
            "PasswordAuthentication no", "UsePAM no", "PermitTTY no",
            "DisableForwarding yes", "PermitUserRC no", "PermitUserEnvironment no",
        ):
            self.assertIn(directive, config)
        self.assertIn("ForceCommand /opt/native_codex_ssh.py dispatch", config)
        self.assertNotIn("0.0.0.0", config)

    def test_config_rejects_public_address_privileged_port_and_non_private_state(self):
        for kwargs in (
            {"address": "0.0.0.0"}, {"address": "192.0.2.10"},
            {"address": "10.10.10.106"},
            {"port": 22}, {"port": 65536},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(native.ConfigurationError):
                self.render(**kwargs)
        os.chmod(self.state, 0o755)
        with self.assertRaisesRegex(native.ConfigurationError, "mode 0700"):
            self.render()

    def test_config_rejects_key_mode_or_path_escape(self):
        os.chmod(self.authorized_keys, 0o644)
        with self.assertRaisesRegex(native.ConfigurationError, "authorized keys"):
            self.render()
        os.chmod(self.authorized_keys, 0o600)
        with self.assertRaisesRegex(native.ConfigurationError, "inside the private state"):
            self.render(pid_file=Path("/tmp/native-sshd.pid"))

    def test_dispatch_executes_only_exact_allowlisted_argv_without_shell(self):
        command = " ".join(native.ALLOWED_COMMANDS[1])
        with patch.object(native.os, "execv", side_effect=OSError("sentinel")) as execv:
            with self.assertRaisesRegex(OSError, "sentinel"):
                native.dispatch(command)
        execv.assert_called_once_with(native.CODEX, list(native.ALLOWED_COMMANDS[1]))

    def test_dispatch_rejects_injection_shell_env_and_alternate_socket(self):
        allowed = " ".join(native.ALLOWED_COMMANDS[0])
        rejected = (
            allowed + "; touch /tmp/pwned",
            "env FOO=bar " + allowed,
            native.CODEX + " app-server proxy --sock /tmp/other.sock",
            native.CODEX + " app-server daemon start",
            "",
        )
        with patch.object(native.os, "execv") as execv:
            for command in rejected:
                with self.subTest(command=command):
                    self.assertEqual(native.dispatch(command), 126)
            execv.assert_not_called()

    def test_dispatch_rejects_malformed_shell_quoting(self):
        with patch.object(native.os, "execv") as execv:
            self.assertEqual(native.dispatch("'unterminated"), 126)
            execv.assert_not_called()


if __name__ == "__main__":
    unittest.main()
