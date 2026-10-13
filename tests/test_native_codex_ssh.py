import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch


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
            address="100.100.100.10", port=22222, state_dir=self.state,
            host_key=self.host_key, authorized_keys=self.authorized_keys,
            pid_file=self.pid_file, helper=self.state / "native_codex_ssh.py",
        )
        values.update(changes)
        return native.render_config(**values)

    def test_config_is_tailnet_bound_and_disables_interactive_and_forwarding_features(self):
        config = self.render()
        self.assertIn("ListenAddress 100.100.100.10\n", config)
        self.assertIn("Port 22222\n", config)
        self.assertIn("AllowUsers " + __import__("pwd").getpwuid(os.geteuid()).pw_name + "\n", config)
        for directive in (
            "PasswordAuthentication no", "UsePAM no", "PermitTTY no",
            "DisableForwarding yes", "PermitUserRC no", "PermitUserEnvironment no",
        ):
            self.assertIn(directive, config)
        self.assertIn(f"ForceCommand {self.state}/native_codex_ssh.py dispatch --profile {self.state}/profile.json", config)
        self.assertNotIn("0.0.0.0", config)

    def test_config_rejects_public_address_privileged_port_and_non_private_state(self):
        for kwargs in (
            {"address": "0.0.0.0"}, {"address": "192.0.2.10"},
            {"address": "198.51.100.10"},
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
        codex = Path(self.temp.name) / "codex"
        codex.write_text("#!/bin/sh\nexit 0\n")
        codex.chmod(0o700)
        profile = self.write_profile(codex=codex)
        socket = Path(self.temp.name) / "codex.sock"
        commands = (
            (f"{codex} app-server daemon version", [str(codex), "app-server", "daemon", "version"]),
            (f"{codex} app-server proxy --sock {socket}", [str(codex), "app-server", "proxy", "--sock", str(socket)]),
        )
        with patch.object(native.os, "execv", side_effect=OSError("sentinel")) as execv:
            for command, _ in commands:
                with self.assertRaisesRegex(OSError, "sentinel"):
                    native.dispatch(command, profile=profile)
        self.assertEqual(execv.call_args_list, [
            call(str(codex), argv) for _, argv in commands
        ])

    def test_dispatch_rejects_injection_shell_env_and_alternate_socket(self):
        codex = Path(self.temp.name) / "codex"
        codex.write_text("#!/bin/sh\nexit 0\n")
        codex.chmod(0o700)
        profile = self.write_profile(codex=codex)
        allowed = f"{codex} app-server daemon version"
        rejected = (
            allowed + "; touch /tmp/pwned",
            "env FOO=bar " + allowed,
            f"{codex} app-server proxy --sock /tmp/other.sock",
            f"{codex} app-server daemon start",
            "",
        )
        with patch.object(native.os, "execv") as execv:
            for command in rejected:
                with self.subTest(command=command):
                    self.assertEqual(native.dispatch(command, profile=profile), 126)
            execv.assert_not_called()

    def test_dispatch_rejects_malformed_shell_quoting(self):
        codex = Path(self.temp.name) / "codex"
        codex.write_text("#!/bin/sh\nexit 0\n")
        codex.chmod(0o700)
        profile = self.write_profile(codex=codex)
        with patch.object(native.os, "execv") as execv:
            self.assertEqual(native.dispatch("'unterminated", profile=profile), 126)
            execv.assert_not_called()

    def write_profile(self, *, codex: Path, address: str = "100.100.100.10") -> Path:
        profile = self.state / "profile.json"
        profile.write_text(json.dumps({
            "address": address, "port": 22222, "codex_bin": str(codex),
            "socket": str(Path(self.temp.name) / "codex.sock"),
            "state_dir": str(self.state), "helper": str(self.state / "native_codex_ssh.py"),
        }))
        profile.chmod(0o600)
        return profile

    def test_private_profile_drives_rendered_config_and_exact_dispatch(self):
        codex = Path(self.temp.name) / "codex"
        codex.write_text("#!/bin/sh\nexit 0\n")
        codex.chmod(0o700)
        profile = self.state / "profile.json"
        profile.write_text(json.dumps({
            "address": "100.100.100.10",
            "port": 22222,
            "codex_bin": str(codex),
            "socket": str(Path(self.temp.name) / "codex.sock"),
            "state_dir": str(self.state),
            "helper": str(self.state / "native_codex_ssh.py"),
        }))
        profile.chmod(0o600)

        config = native.render_profile(profile)
        self.assertIn("ListenAddress 100.100.100.10\n", config)
        self.assertIn(f"ForceCommand {self.state}/native_codex_ssh.py dispatch --profile {self.state}/profile.json", config)
        allowed = f"{codex} app-server proxy --sock {Path(self.temp.name) / 'codex.sock'}"
        with patch.object(native.os, "execv", side_effect=OSError("sentinel")) as execv:
            with self.assertRaisesRegex(OSError, "sentinel"):
                native.dispatch(allowed, profile=profile)
        execv.assert_called_once_with(str(codex), [str(codex), "app-server", "proxy", "--sock", str(Path(self.temp.name) / "codex.sock")])

    def test_profile_is_required_private_owned_and_non_symlink(self):
        with self.assertRaises(native.ConfigurationError):
            native.load_profile(self.state / "missing.json")
        profile = self.state / "profile.json"
        profile.write_text("{}")
        profile.chmod(0o644)
        with self.assertRaisesRegex(native.ConfigurationError, "mode 0600"):
            native.load_profile(profile)
        profile.chmod(0o600)
        link = self.state / "link.json"
        link.symlink_to(profile)
        with self.assertRaisesRegex(native.ConfigurationError, "regular non-symlink"):
            native.load_profile(link)

    def test_profile_rejects_non_cgnat_address_and_command_paths(self):
        codex = Path(self.temp.name) / "codex"
        codex.write_text("#!/bin/sh\nexit 0\n")
        codex.chmod(0o700)
        profile = self.write_profile(codex=codex, address="198.51.100.10")
        with self.assertRaisesRegex(native.ConfigurationError, "CGNAT"):
            native.load_profile(profile)
        profile = self.write_profile(codex=codex)
        value = json.loads(profile.read_text())
        value["socket"] = "/tmp/codex.sock;touch /tmp/pwned"
        profile.write_text(json.dumps(value))
        profile.chmod(0o600)
        with self.assertRaisesRegex(native.ConfigurationError, "absolute path"):
            native.load_profile(profile)

    def test_prepare_stages_private_files_without_overwriting_keys_or_service(self):
        codex = Path(self.temp.name) / "codex"
        codex.write_text("#!/bin/sh\nexit 0\n")
        codex.chmod(0o700)
        source = Path(self.temp.name) / "source-profile.json"
        source.write_text(json.dumps({
            "address": "100.100.100.10",
            "port": 22222,
            "codex_bin": str(codex),
            "socket": str(Path(self.temp.name) / "codex.sock"),
            "state_dir": str(self.state),
            "helper": str(self.state / "native_codex_ssh.py"),
        }))
        source.chmod(0o600)
        original_key = self.host_key.read_bytes()

        staged = native.prepare(source, source_tool=MODULE_PATH)
        self.assertEqual(staged, self.state)
        for name in ("profile.json", "sshd_config", "native-codex-ssh.service"):
            path = self.state / name
            self.assertTrue(path.is_file())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.state / "native_codex_ssh.py").stat().st_mode), 0o700)
        self.assertEqual(self.host_key.read_bytes(), original_key)
        self.assertEqual(native.prepare(source, source_tool=MODULE_PATH), self.state)
        self.assertEqual(self.host_key.read_bytes(), original_key)

    def test_prepare_rejects_conflicting_generated_file_without_replacing_it(self):
        codex = Path(self.temp.name) / "codex"
        codex.write_text("#!/bin/sh\nexit 0\n")
        codex.chmod(0o700)
        source = Path(self.temp.name) / "source-profile.json"
        source.write_text(json.dumps({
            "address": "100.100.100.10", "port": 22222,
            "codex_bin": str(codex), "socket": str(Path(self.temp.name) / "codex.sock"),
            "state_dir": str(self.state), "helper": str(self.state / "native_codex_ssh.py"),
        }))
        source.chmod(0o600)
        conflict = self.state / "native-codex-ssh.service"
        conflict.write_text("operator content\n")
        conflict.chmod(0o600)
        with self.assertRaisesRegex(native.ConfigurationError, "already exists with different content"):
            native.prepare(source, source_tool=MODULE_PATH)
        self.assertEqual(conflict.read_text(), "operator content\n")

    def test_prepare_accepts_the_profile_already_in_its_state_directory(self):
        codex = Path(self.temp.name) / "codex"
        codex.write_text("#!/bin/sh\nexit 0\n")
        codex.chmod(0o700)
        profile = self.write_profile(codex=codex)
        original = profile.read_bytes()
        self.assertEqual(native.prepare(profile, source_tool=MODULE_PATH), self.state)
        self.assertEqual(profile.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
