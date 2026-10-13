import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import deploy_control_plane as deploy


class LocalKamalConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.ssh, self.key, self.known, self.env_file, self.vm_pin, self.profile = self.make_config()

    def tearDown(self):
        deploy.SSH, deploy.KEY, deploy.KNOWN = deploy.DEFAULT_SSH, deploy.DEFAULT_KEY, deploy.DEFAULT_KNOWN
        deploy.LOCAL_CONFIGURED = False
        deploy.INSTANCE = None
        deploy.HOST = deploy.VMROOT = deploy.VM_HOST_PIN = None
        self.temp.cleanup()

    def private(self, path, content):
        path.write_text(content)
        path.chmod(0o600)
        return path

    def make_config(self):
        directory = self.root / "ssh"
        directory.mkdir(mode=0o700)
        key = self.private(directory / "identity", "fixture private key\n")
        raw_key = b"local-kamal-host-key-fixture"
        encoded_key = base64.b64encode(raw_key).decode()
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(raw_key).digest()).decode().rstrip("=")
        known = self.private(
            directory / "known_hosts",
            f"vm-test,192.0.2.10 ssh-ed25519 {encoded_key}\n",
        )
        config = self.private(
            directory / "ssh_config",
            f"""Host vm-test
HostName 192.0.2.10
User testuser
IdentityFile {key}
IdentitiesOnly yes
BatchMode yes
ForwardAgent no
StrictHostKeyChecking yes
UserKnownHostsFile {known}
GlobalKnownHostsFile /dev/null
PreferredAuthentications publickey
""",
        )
        profile = self.private(self.root / "instance.json", json.dumps({
            "schema_version": 1,
            "deploy_host": {"alias": "vm-test", "address": "192.0.2.10", "user": "testuser", "host_key_fingerprint": fingerprint},
            "vm": {
                "repo_dir": "/home/testuser/project", "state_dir": "/home/testuser/state",
                "network": {"name": "mcp-test", "subnet": "198.18.0.0/24", "gateway": "198.18.0.1"},
                "native_ssh_dir": "/home/testuser/native-ssh",
                "devsy": {"config_source": "/home/testuser/state/devsy/config.yaml", "context_dir": "/home/testuser/state/devsy/context", "kubeconfig_source": "/home/testuser/state/ror/config.json", "context": "default"}
            }
        }))
        env_file = self.private(
            self.root / ".env.kamal.local",
            f"KAMAL_SSH_CONFIG={config}\nKAMAL_SSH_KEY={key}\nKAMAL_KNOWN_HOSTS={known}\nKAMAL_INSTANCE_PROFILE={profile}\n",
        )
        return config, key, known, env_file, fingerprint, profile

    def configured(self):
        return patch.object(deploy, "VM_HOST_PIN", self.vm_pin)

    def test_loads_only_private_absolute_references_and_uses_private_vm_profile(self):
        with self.configured():
            result = deploy.configure_local(self.env_file)
        self.assertEqual(result, {
            "ssh_config": str(self.ssh),
            "ssh_key": str(self.key),
            "known_hosts": str(self.known),
        })
        self.assertTrue(deploy.LOCAL_CONFIGURED)
        self.assertEqual((deploy.SSH, deploy.KEY, deploy.KNOWN), (self.ssh, self.key, self.known))
        self.assertEqual(deploy.HOST, "vm-test")

    def test_existing_three_ssh_references_use_default_private_profile_path(self):
        config = self.private(self.root / "legacy.env", f"KAMAL_SSH_CONFIG={self.ssh}\nKAMAL_SSH_KEY={self.key}\nKAMAL_KNOWN_HOSTS={self.known}\n")
        with self.configured(), patch.object(deploy, "DEFAULT_INSTANCE_PROFILE", self.profile):
            deploy.configure_local(config)
        self.assertEqual(deploy.HOST, "vm-test")

    def test_rejects_non_private_config_symlink_and_invalid_path_references(self):
        self.env_file.chmod(0o644)
        with self.configured(), self.assertRaisesRegex(ValueError, "ownership/mode"):
            deploy.configure_local(self.env_file)
        self.env_file.chmod(0o600)

        link = self.root / "config-link"
        link.symlink_to(self.env_file)
        with self.configured(), self.assertRaisesRegex(ValueError, "ownership/mode"):
            deploy.configure_local(link)

        self.key.chmod(0o644)
        with self.configured(), self.assertRaisesRegex(ValueError, "ownership/mode"):
            deploy.configure_local(self.env_file)
        self.key.chmod(0o600)

        self.env_file.write_text(
            f"KAMAL_SSH_CONFIG={self.ssh}\nKAMAL_SSH_KEY=relative-key\nKAMAL_KNOWN_HOSTS={self.known}\nKAMAL_INSTANCE_PROFILE={self.profile}\n"
        )
        self.env_file.chmod(0o600)
        with self.configured(), self.assertRaisesRegex(ValueError, "absolute paths"):
            deploy.configure_local(self.env_file)
        self.assertFalse(deploy.LOCAL_CONFIGURED)

    def test_rejects_wrong_host_user_or_pin(self):
        self.ssh.write_text(self.ssh.read_text().replace("User testuser", "User other-user"))
        self.ssh.chmod(0o600)
        with self.configured(), self.assertRaisesRegex(ValueError, "not strictly pinned"):
            deploy.configure_local(self.env_file)

        self.ssh.write_text(self.ssh.read_text().replace("User other-user", "User testuser"))
        self.ssh.chmod(0o600)
        self.known.write_text("vm-test,192.0.2.10 ssh-ed25519 " + base64.b64encode(b"wrong").decode() + "\n")
        self.known.chmod(0o600)
        with self.configured(), self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
            deploy.configure_local(self.env_file)

    def test_local_bypass_requires_explicit_configuration_and_does_not_relax_ci_gates(self):
        with patch.object(deploy.socket, "gethostname", return_value="dakota"), self.assertRaisesRegex(ValueError, "approved ARM64 Pi"):
            deploy.trusted_context({}, local=True)

        with self.configured():
            deploy.configure_local(self.env_file)
            with patch.object(deploy.socket, "gethostname", return_value="dakota"), \
                    patch.object(deploy.os, "uname", return_value=type("U", (), {"machine": "x86_64"})()):
                deploy.trusted_context({}, local=True)

            good_ci = {
                "GITHUB_REPOSITORY": "joshyorko/mcp-tunnel-kit",
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_EVENT_NAME": "workflow_dispatch",
                "RUNNER_NAME": "pi5-01-mcp-control-plane",
            }
            with patch.object(deploy.socket, "gethostname", return_value="dakota"), \
                    patch.object(deploy.os, "uname", return_value=type("U", (), {"machine": "x86_64"})()):
                with self.assertRaisesRegex(ValueError, "approved ARM64 Pi"):
                    deploy.trusted_context(good_ci, local=False)

            with patch.object(deploy.socket, "gethostname", return_value="pi5-01"), \
                    patch.object(deploy.os, "uname", return_value=type("U", (), {"machine": "aarch64"})()):
                with self.assertRaisesRegex(ValueError, "Untrusted workflow"):
                    deploy.trusted_context({**good_ci, "GITHUB_REF": "refs/heads/fork"}, local=False)

    def test_existing_pi_break_glass_still_works_without_local_config(self):
        deploy.configure_instance(self.profile)
        with self.configured(), patch.object(deploy, 'SSH', self.ssh), \
                patch.object(deploy, 'KEY', self.key), patch.object(deploy, 'KNOWN', self.known), \
                patch.object(deploy.socket, 'gethostname', return_value='pi5-01'), \
                patch.object(deploy.os, 'uname', return_value=type('U', (), {'machine': 'aarch64'})()):
            deploy.trusted_context({}, local=True)

    def test_start_is_a_supported_accessory_operation(self):
        with patch.object(deploy, "remote", return_value={"path": "/private/empty-docker-config"}), \
                patch.object(deploy.subprocess, "run", return_value=type("R", (), {"returncode": 0})()):
            deploy.kamal(self.root / "deploy.yml", "start", "executor")

        with self.assertRaisesRegex(ValueError, "Unsupported Kamal operation"):
            deploy.kamal(self.root / "deploy.yml", "deploy", "executor")


if __name__ == "__main__":
    unittest.main()
