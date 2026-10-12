import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
RUBY = shutil.which("ruby")
if RUBY and "/mise/shims/" in RUBY:
    RUBY = None
sys.path.insert(0, str(ROOT / "scripts"))
import deploy_control_plane as controller
import vm_deploy_host as host


class AnonymousDockerConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = self.root / "deployment"
        self.config_dir = self.store / "anonymous-docker-config"
        self.state_patch = patch.object(host, "STORE", self.store)
        self.config_patch = patch.object(host, "PUBLIC_DOCKER_CONFIG", self.config_dir)
        self.state_patch.start()
        self.config_patch.start()

    def tearDown(self):
        self.config_patch.stop()
        self.state_patch.stop()
        self.temp.cleanup()

    def manifest(self):
        return json.loads((ROOT / "config/deploy-images.json").read_text())

    def test_config_is_empty_private_and_refuses_existing_credentials_or_symlinks(self):
        path = host.ensure_anonymous_docker_config()
        self.assertEqual(path, self.config_dir)
        self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        config = path / "config.json"
        self.assertEqual(config.read_bytes(), b"{}\n")
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)

        config.write_text('{"auths":{"ghcr.io":{"auth":"not-empty"}}}')
        config.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "config is unsafe"):
            host.ensure_anonymous_docker_config()

        config.unlink()
        outside = self.root / "outside.json"
        outside.write_text('{"auths":{}}')
        config.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "config is unsafe"):
            host.ensure_anonymous_docker_config()

    def test_public_image_pulls_use_anonymous_config_and_keep_inspect_read_only(self):
        calls = []

        def run(argv, timeout=180, env=None):
            calls.append((argv, timeout, env))
            if argv[1:3] == ["pull", "--platform"]:
                return b""
            revision = self.manifest()["images"]["cas"]["revision"]
            value = [{"Id": "image-id", "Architecture": "amd64", "Os": "linux",
                      "Config": {"Labels": {"org.opencontainers.image.revision": revision}}}]
            return json.dumps(value).encode()

        with patch.object(host, "run", side_effect=run), \
                patch.dict(os.environ, {"DOCKER_CONFIG": "/home/kdlocpanda/.docker",
                                        "DOCKER_AUTH_CONFIG": "fixture-secret"}):
            result = host.images(self.manifest())

        pulls = [call for call in calls if "pull" in call[0]]
        inspections = [call for call in calls if "image" in call[0]]
        self.assertEqual(len(pulls), 4)
        self.assertEqual(len(inspections), 4)
        self.assertEqual(set(result), {"cas", "schema_proxy", "executor", "tunnel"})
        for argv, _timeout, env in pulls:
            self.assertEqual(env["DOCKER_CONFIG"], str(self.config_dir))
            self.assertNotIn("DOCKER_AUTH_CONFIG", env)
            self.assertNotEqual(env["DOCKER_CONFIG"], "/home/kdlocpanda/.docker")
        self.assertTrue(all(env is None for _argv, _timeout, env in inspections))

    def test_compose_rollback_start_is_anonymous_and_starts_bridge_after_compose(self):
        calls = []
        with patch.object(host, "run", side_effect=lambda *args, **kwargs: calls.append((args, kwargs)) or b""), \
                patch.dict(os.environ, {"DOCKER_AUTH_CONFIG": "fixture-secret"}):
            self.assertEqual(host.compose_start(), {"compose_started": True})

        self.assertEqual(calls[0][0][0], ["sudo", "-n", "systemctl", "stop", "codex-control-plane-devsy"])
        compose_args, compose_kwargs = calls[1][0], calls[1][1]
        self.assertEqual(compose_args[0], [str(host.ROOT / "scripts/control-plane-up")])
        self.assertEqual(compose_args[1], 900)
        self.assertEqual(compose_kwargs["env"]["DOCKER_CONFIG"], str(self.config_dir))
        self.assertEqual(compose_kwargs["env"]["DEVSY_MCP_ENABLED"], "false")
        self.assertNotIn("DOCKER_AUTH_CONFIG", compose_kwargs["env"])
        self.assertEqual(calls[2][0][0], ["sudo", "-n", "systemctl", "start", "codex-control-plane-devsy"])

    def test_kamal_invocation_uses_the_sshkit_wrapper_and_vm_config_path(self):
        config_path = str(self.config_dir)
        completed = subprocess.CompletedProcess([], 0, "", "")
        with patch.object(controller, "remote", return_value={"path": config_path}) as remote, \
                patch.object(controller.subprocess, "run", return_value=completed) as run:
            controller.kamal(self.root / "deploy.yml", "reboot", "cas")

        remote.assert_called_once_with("anonymous-docker-config")
        argv = run.call_args.args[0]
        self.assertEqual(argv[:3], ["bundle", "exec", "ruby"])
        self.assertEqual(argv[3], str(ROOT / "scripts/kamal_anonymous.rb"))
        self.assertEqual(argv[4:7], ["accessory", "reboot", "cas"])
        self.assertEqual(run.call_args.kwargs["env"]["KAMAL_PUBLIC_DOCKER_CONFIG"], config_path)

    @unittest.skipUnless(RUBY, "A directly runnable Ruby is unavailable")
    def test_kamal_wrapper_sets_sshkit_default_env_before_running_cli(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / "sshkit.rb").write_text(
                "module SSHKit\n"
                "  Config = Struct.new(:default_env)\n"
                "  def self.config; @config ||= Config.new({}); end\n"
                "end\n"
                "module Gem\n"
                "  def self.bin_path(*); ENV.fetch('FAKE_KAMAL_BIN'); end\n"
                "end\n"
            )
            (directory / "kamal.rb").write_text("# test stub\n")
            fake_cli = directory / "fake-kamal.rb"
            fake_cli.write_text(
                "require 'json'\n"
                "File.write(ENV.fetch('KAMAL_TEST_RESULT'), JSON.generate("
                "'env' => SSHKit.config.default_env, 'argv' => ARGV))\n"
            )
            receipt = directory / "result.json"
            env = {
                **os.environ,
                "KAMAL_PUBLIC_DOCKER_CONFIG": "/home/kdlocpanda/.local/share/codex-control-plane/deployment/anonymous-docker-config",
                "FAKE_KAMAL_BIN": str(fake_cli),
                "KAMAL_TEST_RESULT": str(receipt),
            }
            result = subprocess.run(
                [RUBY, "-I", str(directory), str(ROOT / "scripts/kamal_anonymous.rb"),
                 "accessory", "reboot", "cas"],
                env=env, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            value = json.loads(receipt.read_text())
            self.assertEqual(value["env"]["DOCKER_CONFIG"], env["KAMAL_PUBLIC_DOCKER_CONFIG"])
            self.assertEqual(value["argv"], ["accessory", "reboot", "cas"])


if __name__ == "__main__":
    unittest.main()
