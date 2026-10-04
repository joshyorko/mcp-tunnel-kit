"""Offline onboarding regressions using only synthetic credentials and temp files."""

import importlib.util
import contextlib
import io
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
VALUES = {
    "CONTROL_PLANE_API_KEY": "FIXTURE_API_KEY",
    "CONTROL_PLANE_TUNNEL_ID": "tunnel_" + "a" * 32,
    "EXECUTOR_PAT": "FIXTURE_PAT",
}
FILES = {
    "CONTROL_PLANE_API_KEY": "control-plane-api-key",
    "CONTROL_PLANE_TUNNEL_ID": "control-plane-tunnel-id",
    "EXECUTOR_PAT": "executor-pat",
}


class OnboardingTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("compose_control", ROOT / "scripts/compose_control.py")
        self.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.helper)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.secrets = self.root / "private"
        self.configuration = {"secrets": {
            name: {"file": str(self.secrets / name)}
            for name in (*FILES.values(), "executor-auth-header")
        }}
        for context in (patch.object(self.helper, "ROOT", self.root),
                        patch.dict(os.environ, {}, clear=True),
                        patch.object(self.helper, "compose_rows", return_value=[])):
            context.start()
            self.addCleanup(context.stop)

    def dotenv(self, values=None):
        values = VALUES if values is None else values
        path = self.root / ".env"
        path.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
        return path

    def materialize(self):
        self.assertTrue(callable(getattr(self.helper, "materialize_secrets", None)),
                        "Normal startup needs a noninteractive credential materializer")
        self.helper.materialize_secrets(self.configuration)

    def test_all_three_dotenv_values_become_private_files_and_bearer_header(self):
        dotenv = self.dotenv()
        self.materialize()
        for key, name in FILES.items():
            path = self.secrets / name
            self.assertEqual(path.read_text(), VALUES[key] + "\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.stat().st_uid, os.getuid())
        self.assertEqual((self.secrets / "executor-auth-header").read_text(), "Bearer FIXTURE_PAT\n")
        self.assertEqual(self.secrets.stat().st_mode & 0o777, 0o700)
        self.assertEqual(dotenv.stat().st_mode & 0o777, 0o600)

    def test_explicit_environment_overrides_dotenv(self):
        self.dotenv()
        with patch.dict(os.environ, {"EXECUTOR_PAT": "ENV_FIXTURE_PAT"}):
            self.materialize()
        self.assertEqual((self.secrets / "executor-pat").read_text(), "ENV_FIXTURE_PAT\n")
        self.assertEqual((self.secrets / "executor-auth-header").read_text(), "Bearer ENV_FIXTURE_PAT\n")

    def test_explicit_rotation_replaces_files_atomically_and_cleans_temporary_files(self):
        self.dotenv()
        self.materialize()
        pat = self.secrets / "executor-pat"
        original = pat.open()
        self.addCleanup(original.close)
        self.dotenv({**VALUES, "EXECUTOR_PAT": "ROTATED_FIXTURE_PAT"})
        real_replace = os.replace
        replaced = []
        def replace(source, destination):
            self.assertEqual(Path(source).parent, self.secrets)
            self.assertEqual(Path(source).stat().st_mode & 0o777, 0o600)
            replaced.append(Path(destination).name)
            real_replace(source, destination)
        with patch.object(self.helper.os, "replace", side_effect=replace):
            self.materialize()
        self.assertEqual(original.read(), "FIXTURE_PAT\n")
        self.assertEqual(pat.read_text(), "ROTATED_FIXTURE_PAT\n")
        self.assertEqual(set(replaced), {"executor-pat", "executor-auth-header"})
        self.assertEqual(set(p.name for p in self.secrets.iterdir()), set(self.configuration["secrets"]))

    def test_absent_values_retain_existing_private_files_without_replacement(self):
        self.dotenv()
        self.materialize()
        (self.root / ".env").unlink()
        with patch.object(self.helper.os, "replace", side_effect=AssertionError("Unchanged file replaced")):
            self.materialize()

    def test_invalid_explicit_values_fail_before_any_file_is_rotated(self):
        self.dotenv()
        self.materialize()
        before = {p.name: p.read_bytes() for p in self.secrets.iterdir()}
        for value in ("", " ", "PRIVATE_SENTINEL\nINJECTED", "PRIVATE_SENTINEL\r", "bad token", "é"):
            with self.subTest(value=value), patch.dict(os.environ, {
                "CONTROL_PLANE_API_KEY": "ROTATION_SHOULD_NOT_HAPPEN", "EXECUTOR_PAT": value,
            }):
                with self.assertRaises(self.helper.ControlError) as raised:
                    self.materialize()
                self.assertNotIn("PRIVATE_SENTINEL", str(raised.exception))
                self.assertEqual({p.name: p.read_bytes() for p in self.secrets.iterdir()}, before)

    def test_malformed_dotenv_fails_closed_without_echoing_its_contents(self):
        for line in ('EXECUTOR_PAT="PRIVATE_SENTINEL\nINJECTED"\n',
                     'EXECUTOR_PAT="PRIVATE_SENTINEL\\nINJECTED"\n',
                     'EXECUTOR_PAT=PRIVATE_SENTINEL\rINJECTED\n',
                     'EXECUTOR_PAT=\n', 'EXECUTOR_PAT PRIVATE_SENTINEL\n',
                     'EXECUTOR_PAT=PRIVATE_SENTINEL\nEXECUTOR_PAT=duplicate\n'):
            with self.subTest(line=line):
                self.dotenv({key: value for key, value in VALUES.items() if key != "EXECUTOR_PAT"})
                with (self.root / ".env").open("a") as handle:
                    handle.write(line)
                with self.assertRaises(self.helper.ControlError) as raised:
                    self.materialize()
                self.assertNotIn("PRIVATE_SENTINEL", str(raised.exception))
                self.assertFalse(self.secrets.exists())

    def test_missing_values_are_actionable_and_noninteractive(self):
        with patch.object(self.helper.getpass, "getpass", side_effect=AssertionError("Unexpected prompt")):
            with self.assertRaises(self.helper.ControlError) as raised:
                self.materialize()
        self.assertIn("CONTROL_PLANE_API_KEY", str(raised.exception))
        self.assertIn(".env", str(raised.exception))

    def test_rotation_is_refused_before_any_write_with_active_mounts(self):
        self.dotenv()
        self.materialize()
        self.dotenv({**VALUES, "EXECUTOR_PAT": "ROTATED_FIXTURE_PAT"})
        before = {p.name: p.read_bytes() for p in self.secrets.iterdir()}
        with patch.object(self.helper, "compose_rows", return_value=[{"Service": "tunnel-client", "State": "running"}]):
            with self.assertRaises(self.helper.ControlError):
                self.materialize()
        self.assertEqual({p.name: p.read_bytes() for p in self.secrets.iterdir()}, before)

    def test_normal_up_materializes_before_prepare_and_compose_start(self):
        self.dotenv()
        configuration = {**self.configuration, "services": {
            "codex-action-server": {"image": "ghcr.io/joshyorko/codex-action-server:sha-" + "a" * 40},
        }}
        seen = []
        def prepare(_configuration):
            seen.append("prepare")
            self.assertEqual((self.secrets / "executor-pat").read_text(), "FIXTURE_PAT\n")
            self.assertEqual((self.secrets / "executor-auth-header").read_text(), "Bearer FIXTURE_PAT\n")
        def start(configuration):
            self.assertEqual(seen, ["prepare"])
            self.assertEqual((self.secrets / "executor-auth-header").read_text(), "Bearer FIXTURE_PAT\n")
            seen.append("start-control-plane")
        with patch.object(sys, "argv", ["compose_control.py", "up"]), \
                patch.object(self.helper, "config", return_value=configuration), \
                patch.object(self.helper, "network_preflight"), \
                patch.object(self.helper, "prepare", side_effect=prepare), \
                patch.object(self.helper, "refuse_external_tunnel"), \
                patch.object(self.helper, "status"), \
                patch.object(self.helper, "start_control_plane", side_effect=start), \
                patch.object(self.helper.getpass, "getpass", side_effect=AssertionError("Unexpected prompt")):
            self.assertEqual(self.helper.main(), 0)
        self.assertEqual(seen, ["prepare", "start-control-plane"])

    def test_first_run_needs_no_dotenv_credentials_cas_or_secret_files(self):
        self.dotenv({key: "" for key in VALUES})
        with patch.object(sys, "argv", ["compose_control.py", "first-run"]), \
                patch.object(self.helper, "config", return_value={}), \
                patch.object(self.helper, "network_preflight"), \
                patch.object(self.helper, "credential_dotenv", side_effect=AssertionError("First run read credentials")), \
                patch.object(self.helper, "prepare", side_effect=AssertionError("First run prepared CAS")), \
                patch.object(self.helper, "compose", return_value="") as compose, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(self.helper.main(), 0)
        compose.assert_called_once_with("up", "-d", "--wait", "--wait-timeout", "120", "executor", timeout=150)
        self.assertFalse(self.secrets.exists())
        self.assertIn("browser owner, organization, and PAT", output.getvalue())

    def test_secrets_mode_still_prompts_for_missing_values_and_derives_header(self):
        with patch.object(self.helper.getpass, "getpass", side_effect=list(VALUES.values())) as prompt, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.helper.save_secrets(self.configuration)
        self.assertEqual(prompt.call_count, 3)
        self.assertEqual((self.secrets / "executor-auth-header").read_text(), "Bearer FIXTURE_PAT\n")
        for value in VALUES.values():
            self.assertNotIn(value, output.getvalue())

    def test_existing_blank_or_multiline_private_file_fails_closed(self):
        self.dotenv()
        self.materialize()
        (self.root / ".env").unlink()
        for value in ("", "\n", "FIXTURE_PAT\n\n", "FIXTURE_PAT\r\n", "\nFIXTURE_PAT"):
            with self.subTest(value=value):
                (self.secrets / "executor-pat").write_text(value)
                with self.assertRaises(self.helper.ControlError):
                    self.materialize()

    def test_dotenv_supports_literal_quotes_comments_and_keeps_machine_settings_unchanged(self):
        path = self.dotenv({key: f"'{value}'" for key, value in VALUES.items()})
        settings = '# comment\nCAS_IMAGE=machine-image\nCAS_TARGETS_SOURCE=/operator/targets.json\nCONTROL_PLANE_STATE_DIR=${HOME}/existing-state\nUNKNOWN=$(touch should-not-exist)\n'
        path.write_text(settings + path.read_text())
        before = path.read_bytes()
        self.materialize()
        self.assertEqual(path.read_bytes(), before)
        self.assertNotIn("CAS_IMAGE", os.environ)
        self.assertFalse((self.root / "should-not-exist").exists())

    def test_secret_and_dotenv_symlinks_and_unsafe_private_permissions_are_refused(self):
        self.dotenv()
        self.materialize()
        pat = self.secrets / "executor-pat"
        pat.chmod(0o644)
        with self.assertRaises(self.helper.ControlError):
            self.materialize()
        pat.chmod(0o600)
        original = pat.rename(self.root / "original-pat")
        pat.symlink_to(original)
        with self.assertRaises(self.helper.ControlError):
            self.materialize()
        path = self.root / ".env"
        path.rename(self.root / "original-dotenv")
        path.symlink_to(self.root / "original-dotenv")
        with self.assertRaises(self.helper.ControlError):
            self.materialize()

    def test_normal_up_invalid_input_reports_no_values_and_never_starts(self):
        self.dotenv({**VALUES, "EXECUTOR_PAT": '"PRIVATE_SENTINEL\nINJECTED"'})
        with patch.object(sys, "argv", ["compose_control.py", "up"]), \
                patch.object(self.helper, "config", return_value=self.configuration), \
                patch.object(self.helper, "network_preflight"), \
                patch.object(self.helper, "compose", side_effect=AssertionError("Invalid input reached Compose")), \
                contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(self.helper.main(), 2)
        self.assertNotIn("PRIVATE_SENTINEL", output.getvalue())
        self.assertFalse(self.secrets.exists())

    def test_crlf_dotenv_is_supported_but_crlf_private_credentials_are_rejected(self):
        path = self.dotenv()
        path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
        self.materialize()
        self.assertEqual((self.secrets / "executor-pat").read_text(), "FIXTURE_PAT\n")

    def test_invalid_tunnel_id_rejects_whole_set_without_writes(self):
        self.dotenv({**VALUES, "CONTROL_PLANE_TUNNEL_ID": "PRIVATE_SENTINEL"})
        with self.assertRaises(self.helper.ControlError) as raised:
            self.materialize()
        self.assertNotIn("PRIVATE_SENTINEL", str(raised.exception))
        self.assertFalse(self.secrets.exists())

    def test_interrupted_atomic_rotation_keeps_original_and_leaves_no_temp_file(self):
        self.dotenv()
        self.materialize()
        self.dotenv({**VALUES, "EXECUTOR_PAT": "ROTATED_FIXTURE_PAT"})
        before = {p.name: p.read_bytes() for p in self.secrets.iterdir()}
        with patch.object(self.helper.os, "replace", side_effect=OSError("fixture rename failure")):
            with self.assertRaises(OSError):
                self.materialize()
        self.assertEqual({p.name: p.read_bytes() for p in self.secrets.iterdir()}, before)
        self.materialize()
        self.assertEqual((self.secrets / "executor-auth-header").read_text(), "Bearer ROTATED_FIXTURE_PAT\n")

    def test_explicit_value_repairs_extra_newlines_in_stale_file(self):
        self.dotenv()
        self.materialize()
        path = self.secrets / "executor-pat"
        path.write_text("FIXTURE_PAT\n\n")
        self.materialize()
        self.assertEqual(path.read_text(), "FIXTURE_PAT\n")

    def test_dotenv_is_private_even_when_credential_validation_fails(self):
        path = self.dotenv({**VALUES, "EXECUTOR_PAT": ""})
        path.chmod(0o644)
        with self.assertRaises(self.helper.ControlError):
            self.materialize()
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_unchanged_private_files_do_not_bypass_directory_permissions(self):
        self.dotenv()
        self.materialize()
        self.secrets.chmod(0o777)
        with self.assertRaises(self.helper.ControlError):
            self.materialize()
        self.secrets.chmod(0o700)
        original = self.secrets.rename(self.root / "real-private")
        self.secrets.symlink_to(original, target_is_directory=True)
        with self.assertRaises(self.helper.ControlError):
            self.materialize()

    def test_utf8_bom_does_not_silently_skip_explicit_rotation(self):
        self.dotenv()
        self.materialize()
        (self.root / ".env").write_text("\ufeffCONTROL_PLANE_API_KEY=ROTATED_FIXTURE_KEY\n")
        self.materialize()
        self.assertEqual((self.secrets / "control-plane-api-key").read_text(), "ROTATED_FIXTURE_KEY\n")


if __name__ == "__main__":
    unittest.main()

