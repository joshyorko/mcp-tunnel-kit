# Rebuild a control-plane host

Use this guide to reconnect a Linux controller to a configured control-plane VM or prepare a replacement native SSH endpoint. Use [Recovery](RECOVERY.md) to capture current state or stage an encrypted bundle. This guide does not activate restored state on a replacement VM.

## Keep the existing identity or start a new one

Decide whether you are preserving the current Executor organization, credentials, tunnel ID, and encrypted state. If so, keep the existing VM and state paths. Stop before activating restored VM data. Do not run first-run setup against a preserved Executor volume. Do not start a second tunnel client or Executor writer.

For a new, independent control plane, follow the normal setup in [README.md](../README.md) and [Compose setup](COMPOSE.md). That path creates a new Executor identity and credentials. It does not restore the existing generation.

## Prepare the Bluefin controller and native host

Run these steps on the Bluefin host that has the repository checkout and native Codex app-server. Keep operator files under your user account, outside the checkout, with mode `0600` for files and `0700` for directories.

From the repository root on Bluefin, create the private profile directory and copy each example only when the destination does not already exist:

```sh
profile_dir="$HOME/.config/mcp-control-plane"
install -d -m 0700 "$profile_dir"
for path in "$profile_dir/instance.json" "$profile_dir/native-ssh.json" "$profile_dir/tailnet-requirements.json" "$profile_dir/recovery-storage.json" .env.kamal.local; do
  if [ -e "$path" ] || [ -L "$path" ]; then
    printf 'Refusing to replace existing private input: %s\n' "$path" >&2
    exit 1
  fi
done
install -m 0600 config/instance.example.json "$profile_dir/instance.json"
install -m 0600 config/native-codex-ssh.profile.example.json "$profile_dir/native-ssh.json"
install -m 0600 config/tailnet-requirements.example.json "$profile_dir/tailnet-requirements.json"
install -m 0600 config/recovery-storage.example.json "$profile_dir/recovery-storage.json"
install -m 0600 config/kamal-local.env.example .env.kamal.local
```

Edit the private files for this host. The instance profile holds the VM address, user, trusted host-key fingerprint, repository and state paths, network, native SSH directory, and Devsy paths. The native profile holds the assigned Tailscale address, port, Codex executable, socket, and state directory. The tailnet requirements file records the tailnet name, verified native and VM Tailscale addresses, and the required TCP grant. See the [tailnet requirements template](../config/tailnet-requirements.example.json) and [additive grant example](../config/tailnet-grant.example.json). The example grants one TCP port; do not use it to replace the full tailnet policy. The recovery storage profile points to the private `mc` config, alias, bucket, removable-drive root, and age identity files. Keep it mode `0600`. Set `.env.kamal.local` to the existing SSH config, private key, pinned `known_hosts`, and instance profile paths. Do not put credentials there.

Use the existing trusted SSH identity and host pin when rebuilding only the controller. For a recovered controller, restore `operator-ssh` and `instance-config` from the outer staging tree into new private paths. Keep the SSH identity and host key. Update the local `.env.kamal.local` references and SSH config file paths to match those locations. If a VM or native host was replaced, obtain the new host key through a trusted channel and update the corresponding private pin. Do not use `ssh-keyscan` output as a trust source. See [VM deployment](VM_DEPLOY.md) for the profile-aware direct VM status command and [Native SSH](NATIVE_SSH.md) for the forced-command endpoint.

For a new or replaced Tailscale node, have a tailnet owner enroll it through the normal owner workflow. Record the assigned address. Update the native profile and tailnet requirements file. Restrict the VM public key in native `authorized_keys` to the VM's current Tailscale address. Apply the single required TCP grant through the owner workflow. The example grant is additive; it does not remove existing permissions. Interactive Tailscale SSH is not required. If the native host key changes, verify its fingerprint and update the VM's pinned `known_hosts` entry. A tailnet owner performs enrollment and policy changes. This repository does not change either.

Prepare and validate the native endpoint by following [Native SSH](NATIVE_SSH.md). That command stages configuration and a user service. Install and activate the service only after reviewing the generated files and completing the tailnet grants.

For a replacement native node, preserve the existing dedicated host key and authorized VM public key when the capture includes them. If the address or Codex paths change, use a new private state directory and update the profile before preparation. Add the VM's current Tailscale source address restriction if the VM was replaced. Do not copy the old helper or rendered config over files generated for the new profile. Update the VM's strict host pin only if the native host key changes. For the same host and paths, keep the captured helper, config, and service files together; do not enroll the existing node again or regenerate its host key. The native `prepare` command refuses to replace differing generated files.

Install the isolated Kamal bundle if this checkout does not have it yet, then verify the controller-to-VM connection:

```sh
bin/kamal setup-local
bin/kamal preflight
bin/kamal status
```

`bin/kamal` reads `.env.kamal.local`, which selects the private instance profile. It uses the configured SSH identity and strict host-key checking. Do not bypass the host pin when preflight fails.

## Operate the existing generation

Run lifecycle commands on the Bluefin controller:

```sh
bin/kamal accessory details
bin/kamal accessory stop
bin/kamal accessory start
```

`stop` retains containers and data. `start` checks the recorded Executor identity before it starts the tunnel. A normal start needs no Tailscale re-enrollment or new credentials when the nodes, addresses, keys, and profiles are unchanged. For the Compose-based host setup, use `scripts/control-plane-down`, `scripts/control-plane-up`, and `scripts/control-plane-status` as documented in [README.md](../README.md). Do not use raw Compose lifecycle commands.

If the VM was replaced, do not run deployment or first-run commands until its Docker authority, operator UID/GID `1000:1000`, repository, private state paths, Tailscale membership, and strict SSH pin are ready. The direct VM script accepts `--instance-profile`; its use is documented in [VM deployment](VM_DEPLOY.md). Use the guarded procedure in [Recovery](RECOVERY.md) to activate a preserved generation. This repository does not provision a new VM operating system or migrate file ownership.

## Keep recovery staging separate

Use [Recovery](RECOVERY.md) to collect the current generation, encrypt it, verify it, and restore it into a new staging directory. Restore commands do not write to live paths, start services, or select a production tunnel or Executor. Stop before activation until the guarded procedure maps the staged VM archives and CAS database manifest to the replacement VM's state paths. Stop the existing tunnel and writers before activating reconstructed services.
