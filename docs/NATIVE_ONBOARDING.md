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

For a registration that changes central files, provide the existing original
`local` target's exact worktree and persistent thread once:

```sh
bin/onboard-native --name dakota-cpu \
  --native-cwd /absolute/original-dakota/worktree \
  --native-thread-id YOUR_EXISTING_LOCAL_THREAD_UUID
```

These acceptance values are saved in the private endpoint state directory for
future runs and revalidated each time. They refer to the existing `local`
target, not the new device. The existing deployment gate requires an idle,
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
`native_descriptor` and supply the original `local` acceptance cwd/thread.
The protected self-hosted runner uses its existing pinned controller SSH files
and private instance profile. No new GitHub secrets are needed for this
deployment. The descriptor has no private keys, but controls a trusted endpoint;
submit only the descriptor generated on the intended device.

CI performs central registration and verification. It cannot perform a new
device's interactive Tailscale login or activate its local service. Run device
preparation first. Ordinary `cas` deployment continues to reuse the persisted
target map and SSH inputs without registering devices.

## Transaction and recovery

Changed registrations retain the existing native acceptance gate and VM
deployment lock. They validate/probe the endpoint, back up the existing files,
publish complete replacements and recreate **CAS only** with its recorded image
pins. This entails brief CAS downtime. The recreation is necessary because
individual file bind mounts retain old inodes after atomic host replacement.

CAS and Executor must resolve/read the new target, and the original native
acceptance check must still pass. Failure restores the prior configuration and
recreates CAS. An interrupted transaction is recovered on a same-target rerun;
intervening operator edits stop recovery rather than being overwritten.
Rollback failures are reported explicitly and require inspection of the private
`native-registration` journal under the controller state directory.

Successful device runs write `onboarding-receipt.json`. Adopted assets remain
operator-owned. A failed central operation leaves the prepared device endpoint
available for diagnosis and retry. No credentials or private state belong in Git.
