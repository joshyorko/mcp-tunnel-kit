"""Source-level guardrails for the production deployment workflow."""

import contextlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import deploy_control_plane as deploy


WORKFLOW = ROOT / ".github/workflows/deploy-control-plane.yml"


class DeployWorkflowTests(unittest.TestCase):
    def test_workflow_is_dispatch_only_and_uses_the_protected_main_runner(self):
        text = WORKFLOW.read_text()
        self.assertRegex(text, r"(?m)^on:\n  workflow_dispatch:$")
        self.assertNotRegex(text, r"(?m)^  (pull_request|pull_request_target|push|workflow_run):")
        self.assertIn("if: github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch'", text)
        self.assertIn("runs-on: [self-hosted, Linux, ARM64, pi5-01, kamal, mcp-control-plane]", text)
        self.assertIn("environment: control-plane-production", text)
        self.assertRegex(text, r"(?ms)^permissions:\n  contents: read\nconcurrency:")
        self.assertIn("cancel-in-progress: false", text)
        self.assertIn("uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd", text)
        self.assertIn("ref: ${{ github.sha }}", text)
        self.assertIn("persist-credentials: false", text)

    def test_workflow_requires_explicit_boolean_for_full_stack_operations_and_has_no_secret_uploads(self):
        text = WORKFLOW.read_text()
        self.assertRegex(text, r"(?ms)^      approve_full_stack:\n.*?^        type: boolean\n        default: false$")
        self.assertIn("FULL_APPROVAL: ${{ inputs.approve_full_stack }}", text)
        self.assertIn('if [ "$FULL_APPROVAL" = true ]; then args+=(--approve-full-stack); fi', text)
        self.assertNotIn("${{ secrets.", text)
        self.assertNotIn("upload-artifact", text)

    def test_runner_source_accepts_only_repository_main_dispatch_on_named_pi(self):
        trusted = {
            "GITHUB_REPOSITORY": "joshyorko/mcp-tunnel-kit",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "RUNNER_NAME": "pi5-01-mcp-control-plane",
        }
        with patch.object(deploy.socket, "gethostname", return_value="pi5-01"), \
                patch.object(deploy.os, "uname", return_value=SimpleNamespace(machine="aarch64")):
            for key in trusted:
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, "Untrusted"):
                    deploy.trusted_context({**trusted, key: "untrusted"})

    def test_ssh_credentials_use_private_fixed_paths_and_strict_client_options(self):
        self.assertEqual(deploy.SSH, Path.home() / ".local/share/mcp-control-plane-deploy/ssh_config")
        self.assertEqual(deploy.KEY, deploy.SSH.parent / "identity")
        self.assertEqual(deploy.KNOWN, deploy.SSH.parent / "known_hosts")
        options = deploy.ssh_args("true")
        self.assertEqual(options[1:3], ["-F", str(deploy.SSH)])
        self.assertIn("StrictHostKeyChecking=yes", options)
        self.assertIn("ForwardAgent=no", options)
        for path in (deploy.SSH, deploy.KEY, deploy.KNOWN):
            self.assertEqual(path.parent, deploy.SSH.parent)

    def test_runner_refuses_ssh_credential_files_with_wrong_mode_or_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            files = [directory / name for name in ("ssh_config", "identity", "known_hosts")]
            for path in files:
                path.write_text("fixture\n")
                path.chmod(0o600)
            trusted = {
                "GITHUB_REPOSITORY": "joshyorko/mcp-tunnel-kit",
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_EVENT_NAME": "workflow_dispatch",
                "RUNNER_NAME": "pi5-01-mcp-control-plane",
            }
            with patch.object(deploy, "SSH", files[0]), \
                    patch.object(deploy, "validate_ssh_config"), \
                    patch.object(deploy, "KEY", files[1]), \
                    patch.object(deploy, "KNOWN", files[2]), \
                    patch.object(deploy.socket, "gethostname", return_value="pi5-01"), \
                    patch.object(deploy.os, "uname", return_value=SimpleNamespace(machine="aarch64")):
                deploy.trusted_context(trusted)
                files[1].chmod(0o644)
                with self.assertRaisesRegex(ValueError, "ownership/mode"):
                    deploy.trusted_context(trusted)
                files[1].unlink()
                files[1].symlink_to(files[0])
                with self.assertRaisesRegex(ValueError, "ownership/mode"):
                    deploy.trusted_context(trusted)

    def test_full_stack_operations_refuse_before_mutation_without_checkbox(self):
        manifest = json.loads((ROOT / "config/deploy-images.json").read_text())
        for operation in ("adopt", "deploy", "rollback"):
            with self.subTest(operation=operation):
                before = {
                    "authority": "compose" if operation == "adopt" else "kamal",
                    "source_sha": "a" * 40,
                    "identity": "same-identity",
                    "inventory": {
                        name: {"image": name}
                        for name in ("executor", "schema-proxy", "cas", "tunnel")
                    },
                }
                current = {**before, "manifest": manifest}

                def remote(action, data=None):
                    if action == "snapshot":
                        return before
                    if action == "current":
                        return current
                    if action == "images":
                        return {"image_ids": {
                            "cas": "cas", "schema_proxy": "schema-proxy",
                            "executor": "executor", "tunnel": "tunnel",
                        }}
                    return {}

                args = SimpleNamespace(
                    local=False, operation=operation, cas_digest="", cas_revision="",
                    approve_full_stack=False,
                )
                with patch.object(deploy, "trusted_context"), \
                        patch.object(deploy, "lock", return_value=contextlib.nullcontext()), \
                        patch.object(deploy, "remote", side_effect=remote) as remote_call, \
                        patch.object(deploy, "kamal") as kamal, \
                        patch.object(deploy, "sync_source") as sync_source, \
                        patch.dict(os.environ, {"GITHUB_SHA": "e" * 40}):
                    with self.assertRaisesRegex(ValueError, "Explicit full-stack approval"):
                        deploy.execute(args)
                self.assertFalse({"backup", "compose-stop", "network", "previous", "commit"} & {
                    call.args[0] for call in remote_call.call_args_list
                })
                kamal.assert_not_called()
                sync_source.assert_not_called()
