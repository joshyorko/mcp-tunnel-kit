# Bounded native Codex SSH

This endpoint is a separate, unprivileged OpenSSH daemon for the VM's persistent Codex connection. It binds only to the Dakota tailnet IPv4 address (`100.81.124.110`) on TCP `22222`. It does not change the system sshd, native Codex daemon, Tailscale identity, or ACL. The client must pin the dedicated host key and keep its VM private key private.

The forced command accepts exactly two parsed argument vectors:

- `/home/kdlocpanda/.codex/packages/app-server-daemon/current/bin/codex app-server daemon version`
- `/home/kdlocpanda/.codex/packages/app-server-daemon/current/bin/codex app-server proxy --sock /home/kdlocpanda/.codex/app-server-control/app-server-control.sock`

The helper uses `shlex.split` only to parse `SSH_ORIGINAL_COMMAND`; it never evaluates a shell. All other commands, including shell syntax, environment assignments, alternate sockets, and daemon start commands, exit with status 126.

## Dakota setup

Run these commands as `kdlocpanda` on Dakota. They prepare example paths and print a config; they do not edit the system sshd or start a service. Keep the state directory at mode `0700` and both key files at mode `0600`.

```sh
state="$HOME/.local/state/native-codex-ssh"
install -d -m 0700 "$state"
ssh-keygen -q -t ed25519 -N '' -f "$state/ssh_host_ed25519_key"
install -m 0600 /dev/null "$state/authorized_keys"
```

Add only the VM's public key with `from="100.75.96.78",restrict` to `authorized_keys`. Render the configuration using the checked-out helper's absolute path:

```sh
python3 /path/to/mcp-tunnel-kit/scripts/native_codex_ssh.py render-config \
  --state-dir "$state" \
  --host-key "$state/ssh_host_ed25519_key" \
  --authorized-keys "$state/authorized_keys" \
  --pid-file "$state/sshd.pid" \
  --helper /path/to/mcp-tunnel-kit/scripts/native_codex_ssh.py \
  > "$state/sshd_config"
chmod 0600 "$state/sshd_config"
```

The renderer requires an existing state directory owned by the current non-root user with mode `0700`, and regular owned host-key and authorized-keys files with mode `0600`. Every daemon state path must be directly inside that directory. Its address must be Tailscale CGNAT IPv4 and its port must be in `1024-65535`.

Install `config/native-codex-ssh.service.example` as a user unit named `native-codex-ssh.service`, adjusting only the state path if needed. The user's existing systemd linger keeps the service manager active after logout. `Restart=on-failure` retries when Tailscale has not assigned the configured address yet. Before enabling it, validate the rendered configuration with `/usr/bin/sshd -t -f "$state/sshd_config"`; inspect the actual bind using `systemctl --user status native-codex-ssh` and `ss -ltn` after operator-controlled startup.

On the VM, configure a dedicated SSH identity and pin the host key in `known_hosts` before use. Do not disable host-key checking or reuse the system SSH identity. The server grants no TTY, shell, agent, TCP, stream-local, X11, tunnel, user environment, or user RC access.
