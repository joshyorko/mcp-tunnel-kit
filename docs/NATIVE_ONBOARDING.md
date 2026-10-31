# Add a native Codex device

Run onboarding **on the Linux device whose existing Codex daemon CAS should use**.
The central CAS, Executor and tunnel remain the same. No CAS product change or
new image is required.

## Initial controller connection

Clone this repository. Copy `config/kamal-local.env.example` to the ignored
`.env.kamal.local` and supply the three existing private SSH paths. Use a
verified controller host pin, not an unauthenticated `ssh-keyscan` result.
Keep the files owned by your account with mode `0600`. The strict SSH config
format and trust requirements are documented in [VM deployment](VM_DEPLOY.md).

The command retrieves a missing instance profile from the controller through
that pinned connection and checks that it describes the same controller. It
never copies the controller's native SSH private key onto the device.

## One command on the device

```sh
bin/onboard-native --name dakota-cpu
```

The command checks Tailscale, guides you through sudo/browser login if needed,
finds the existing Codex daemon and socket, creates or adopts a restricted
OpenSSH endpoint, enables its user service, exchanges public identities, and
registers the target with the existing central CAS. It then verifies CAS and
Executor reads. A matching rerun verifies the same configuration without key
rotation or service recreation.

Progress appears on stderr before each controller, native-read, Kamal and
verification phase. Slow phases print a heartbeat every 15 seconds and report
their elapsed time when finished. Stdout remains the final JSON result. A
completed lifecycle receipt clears the earlier pending-transaction fields.

For a registration that changes central files, provide an existing surviving
target's exact worktree and persistent thread once. The acceptance target
defaults to `local` for compatibility; select another with `--native-target`:

```sh
bin/onboard-native --name dakota-cpu \
  --native-cwd /absolute/original-dakota/worktree \
  --native-thread-id YOUR_EXISTING_LOCAL_THREAD_UUID
```

These acceptance values are saved in the private endpoint state directory for
future runs and revalidated each time. They refer to the selected existing
target, not necessarily the new device. The deployment gate requires an idle,
completed thread. Onboarding does not start turns or restart native Codex.

Use `--codex-bin` and `--socket` when discovery is ambiguous. `--port` and
`--state-dir` configure a new endpoint; differing existing keys/configuration
produce a conflict instead of being overwritten. The default endpoint state is
`~/.local/state/native-codex-ssh`, and it listens on the device's assigned
Tailscale IPv4 address at TCP port `22222`.

If dependencies are absent, `--install-dependencies` explicitly enables
interactive installation on supported mutable Linux distributions. It does
not layer packages on Bluefin/other immutable hosts. Browser authentication,
sudo passwords and tailnet administrator/device approvals require the operator.
`--non-interactive` reports blockers instead of opening these prompts. Ensure
your tailnet grants allow the controller to reach the selected device/port.
The user SSH service follows the user's systemd session lifecycle; unattended
operation after logout requires an administrator-approved lingering policy.

## Register through GitHub Actions instead

Prepare the endpoint locally and export its public descriptor:

```sh
bin/onboard-native --name dakota-cpu --prepare-only
```

The command reports the private `native-target.json` path. In **Deploy VM
control plane**, choose `onboard-native`; paste that JSON into
`native_descriptor` and supply the acceptance target and its exact cwd/thread.
The protected self-hosted runner uses its existing pinned controller SSH files
and private instance profile. No new GitHub secrets are needed for this
deployment. The descriptor has no private keys, but controls a trusted endpoint;
submit only the descriptor generated on the intended device.

CI performs central registration and verification. It cannot perform a new
device's interactive Tailscale login or activate its local service. Run device
preparation first. Ordinary `cas` deployment continues to reuse the persisted
target map and SSH inputs without registering devices.

## Remove a registration

Run this from any configured controller checkout. The device can be offline:

```sh
bin/onboard-native --operation remove --name dakota-cpu
```

The command reuses saved acceptance settings. If none exist, add
`--native-target`, `--native-cwd`, and `--native-thread-id` for another target
that will remain registered. Removing that acceptance target or the last target
is refused. The operation removes the central CAS registration only. It retains
operator-owned SSH aliases and host pins and reports them in the receipt.
It does not log out Tailscale, stop Codex, disable the device SSH service, or
delete device keys. Repeating a completed removal is a no-op.

## Rename a registration

Rename the old NVIDIA target without recreating its endpoint:

```sh
bin/onboard-native --operation rename --name local --new-name dakota-nvidia \
  --native-target dakota-nvidia \
  --native-cwd /absolute/nvidia/worktree \
  --native-thread-id YOUR_EXISTING_NVIDIA_THREAD_UUID
```

The whole transport entry is preserved, including its existing SSH destination
alias. The command reads the exact thread through `local` before publication and
through `dakota-nvidia` afterward. Rollback restores and verifies `local`.
No daemon restart, key rotation, device-side setup, or re-registration is needed.
A conflicting destination name is refused. A repeated rename is a no-op only
when a completed matching receipt proves it was the same rename.

After rename, this controller saves the successful new acceptance tuple. Update
other controllers' acceptance settings and future workflow inputs to use the
new target name. `local` is a legacy logical name, not a permanent GPU identity.

In **Deploy VM control plane**, use `remove-native` or `rename-native`, set
`native_name`, and set `native_new_name` for a rename. Supply `native_target`
and its exact cwd/thread. For a renamed acceptance target, use its **new** name.
These operations use the same protected runner and transaction as the local CLI.

## Deploy an updated CAS image

The scheduled **Propose qualified CAS image** workflow resolves the versioned
qualification handoff and opens a draft image-update PR when it passes the
method, CI, source, digest and platform checks. Review the paired CAS and
schema-proxy manifest update and its `config/cas-promotion.json` evidence.
Merging the PR does not deploy production. Dispatch **Deploy VM control plane**
with operation `cas` to consume the merged manifest and receipt through the
existing production environment approval. The deployment controller resolves
the current rollback generation itself; do not enter an image digest or source
revision manually.

Native Codex reconciliation is a separate read-only operation. It reports the
installed CLI version, running daemon version and deployed CAS method
qualification as independent facts. The CAS image lane does not install or
restart native daemons.

## Transaction and recovery

Changed registrations, removals and renames retain the native acceptance gate and VM
deployment lock. They validate/probe the endpoint, back up the existing files,
publish complete replacements and recreate **CAS only** with its recorded image
pins. This entails brief CAS downtime. The recreation is necessary because
individual file bind mounts retain old inodes after atomic host replacement.

CAS and Executor must expose the expected target inventory, and the exact native
acceptance check must pass under the post-change name. Failure restores the prior configuration and
recreates CAS and verifies the journaled pre-change name. An interrupted transaction is recovered on a matching-operation rerun;
intervening operator edits stop recovery rather than being overwritten.
Rollback failures are reported explicitly and require inspection of the private
`native-registration` journal under the controller state directory.

Verification requires every expected operator target and rejects the removed
or renamed source name. Unrelated runtime-discovered worker targets may coexist;
their registry and lifecycle are not changed by these operations. Completion
also checks the exact published operator-file hashes.

Successful device runs write `onboarding-receipt.json`. Adopted assets remain
operator-owned. A failed central operation leaves the prepared device endpoint
available for diagnosis and retry. No credentials or private state belong in Git.
