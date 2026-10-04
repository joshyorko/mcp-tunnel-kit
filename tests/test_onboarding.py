"""Offline onboarding regressions using only synthetic credentials and temp files."""

import importlib.util
import os
from pathlib import Path
import tempfile
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


if __name__ == "__main__":
    unittest.main()
