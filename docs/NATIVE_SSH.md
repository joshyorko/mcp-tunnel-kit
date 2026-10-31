# Bounded native Codex SSH

For automated device preparation, activation and central CAS registration, use
[native device onboarding](NATIVE_ONBOARDING.md). The steps below describe the
lower-level endpoint preparation helper.

This lane prepares a separate unprivileged OpenSSH daemon for one existing Codex app-server endpoint. It binds only to the configured Tailscale CGNAT IPv4 address and port. It does not install OpenSSH, enroll a device, change tailnet policy, install or activate a service, or change the native Codex daemon. The client must use a dedicated SSH identity and pin the dedicated host key.

The private JSON profile has exactly these fields:

| Field | Meaning |
| --- | --- |
| `address` | This host's assigned Tailscale CGNAT IPv4 address, such as `100.100.100.10` in an example. |
| `port` | Unprivileged TCP port, from `1024` through `65535`. |
| `codex_bin` | Absolute path to the Codex executable. A managed `current` symlink is allowed. |
| `socket` | Absolute path to the one Codex app-server socket. |
| `state_dir` | Existing state directory owned by the user with mode `0700`. |
| `helper` | Exactly `state_dir/native_codex_ssh.py`, the staged forced-command helper. |

The profile itself must be a regular, non-symlink file owned by the current non-root user with mode `0600`. It cannot contain extra fields. `state_dir` must contain the existing `ssh_host_ed25519_key` and `authorized_keys` files, each regular, owned by the current user, and mode `0600`. Preparation never creates or replaces either key file. `codex_bin` and `socket` may resolve through managed symlinks where appropriate; generated private destinations cannot be symlinks.

## Prepare on a fresh host

Run as the unprivileged account that will own the endpoint. Install or otherwise provide `sshd` through the host's supported package setup, and arrange the host's Tailscale enrollment separately. These commands only create the private state directory and key inputs; `prepare` stages files without installing or activating the service.

```sh
state="$HOME/.local/state/native-codex-ssh"
install -d -m 0700 "$state"
ssh-keygen -q -t ed25519 -N '' -f "$state/ssh_host_ed25519_key"
install -m 0600 /dev/null "$state/authorized_keys"
install -m 0600 config/native-codex-ssh.profile.example.json "$state/profile.json"
${EDITOR:-vi} "$state/profile.json"
```

Edit the example values for this host. Set `address` to the address actually assigned to this host by Tailscale, `codex_bin` to the installed Codex executable, `socket` to the configured app-server socket, and both state paths to the directory created above. The example address, account path, executable and socket are fictitious. The helper destination must remain `native_codex_ssh.py` directly inside `state_dir`.

Add only the VM's public key to `authorized_keys`, restricted to the VM's Tailscale address. For example, an entry can begin with `from="100.100.100.20",restrict`; substitute the VM's actual Tailscale address. Arrange the required tailnet ACL or grants so the VM can reach only this host and TCP port. Enrollment and policy changes are operator steps; this tooling does not request or apply them.

Prepare and validate the staged files:

```sh
python3 scripts/native_codex_ssh.py prepare --profile "$state/profile.json"
/usr/bin/sshd -t -f "$state/sshd_config"
ssh-keygen -lf "$state/ssh_host_ed25519_key.pub"
```

`prepare` validates the profile and existing key files, then stages `profile.json`, `sshd_config`, `native_codex_ssh.py`, and `native-codex-ssh.service` under the private state directory. Generated files are mode `0600`, except the executable helper at `0700`. Repeating preparation accepts only identical existing generated files; it never regenerates keys or silently replaces differing files. Use a new private state directory when preparing a changed endpoint. The service file is not installed, enabled, restarted, or otherwise activated.

Before activation, inspect the staged unit and install it as a user service. These commands make the activation boundary explicit:

```sh
unit_dir="$HOME/.config/systemd/user"
install -d -m 0700 "$unit_dir"
install -m 0600 "$state/native-codex-ssh.service" "$unit_dir/native-codex-ssh.service"
systemctl --user daemon-reload
systemctl --user enable --now native-codex-ssh.service
systemctl --user status native-codex-ssh.service
ss -ltn
```

The service needs access to the configured host address and socket path; its `PrivateTmp=no` setting preserves access if the socket resolves beneath `/tmp`. Installing and starting it are operator actions; the preparation command does neither.

On the VM, create a dedicated SSH identity and send only its public key to the host operator:

```sh
install -d -m 0700 "$HOME/.ssh"
ssh-keygen -q -t ed25519 -N '' -f "$HOME/.ssh/native-codex-ssh"
```

Obtain the host public key over a trusted channel, compare its fingerprint to the server's `ssh-keygen -lf` output, and pin it in `known_hosts`; do not treat an unauthenticated `ssh-keyscan` result as a trust anchor. For example, after verifying the copied key's fingerprint:

```sh
host_key="$HOME/host_ssh_ed25519_key.pub"
printf '[100.100.100.10]:22222 %s %s\n' "$(cut -d' ' -f1 "$host_key")" "$(cut -d' ' -f2 "$host_key")" \
  >> "$HOME/.ssh/known_hosts"
```

Keep strict host-key checking enabled. A one-shot version check with the example profile paths is:

```sh
ssh -T -i "$HOME/.ssh/native-codex-ssh" -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -p 22222 operator@100.100.100.10 '/usr/bin/codex app-server daemon version'
```

Use the `codex_bin` and `socket` values from the operator's profile. The forced command accepts exactly these argument vectors from that profile:

- `codex_bin app-server daemon version`
- `codex_bin --version`
- `codex_bin app-server proxy --sock socket`

The helper parses `SSH_ORIGINAL_COMMAND` but never evaluates a shell. Shell syntax, environment assignments, alternate sockets, daemon start commands, and all other commands exit with status `126`. The VM's `native-reconcile` operation uses only the two exact read-only version commands above; it does not restart the service. The daemon grants no TTY, shell, agent, TCP, stream-local, X11, tunnel, user environment, or user RC access.
