# VM control-plane deployment

Issue #20 manages Executor, schema proxy, CAS and the original OpenAI tunnel as
Kamal 2.12.0 **accessories**, using GitHub's dedicated `pi5-01-mcp-control-plane`
ARM64 runner. Fizzy's runner/service and the existing Kamal proxy are separate.
Images are published Linux amd64 artifacts; nothing is rebuilt on the Pi.

## Local workstation commands

From this repository on Dakota, `bin/kamal` reads the ignored, private
`.env.kamal.local` and connects **directly to the VM** using the existing SSH key
and pinned host identity. It does not relay through the Pi or GitHub.

```sh
bin/kamal accessory deploy       # full pinned redeploy
bin/kamal accessory deploy cas   # CAS only
bin/kamal accessory stop         # stop this stack; retain containers/data
bin/kamal accessory start        # health-ordered start of existing containers
bin/kamal accessory details      # VM service status
bin/kamal rollback              # previous recorded generation
```

The equivalent shortcuts are `make deploy`, `make cas`, `make down`, `make up`,
`make status`, and `make rollback`. Stop disconnects the production tool connection;
start checks Executor identity before starting the tunnel. Both use the same VM
lock as GitHub deployments. Full start/stop also manages only the stack's existing
host Devsy service. Other applications and Dakota's native Codex are unaffected.

This repository's `accessory deploy` command is an operator alias for the tested
Kamal accessory reboot sequence, with image pins, backup, health checks and
rollback. `bin/kamal deploy` is the same shortcut; it does not build an app image
or invoke Kamal's top-level app/proxy deployment. `start`/`stop` use real Kamal
accessory lifecycle operations and do not pull images or recreate containers.

For another local checkout, use `config/kamal-local.env.example` to create a
0600 `.env.kamal.local` with three absolute file references. The referenced SSH
config, existing key and known-hosts file must also be private (0600), and the
configuration must match the existing VM pin and strict SSH policy. No registry,
tunnel or kubeconfig secrets belong in this local file. `make setup` installs the
locked Kamal bundle under the user's data directory using installed Ruby 3.4.8;
Fizzy's bundle/configuration is not modified. The environment file is parsed as
data, never executed as shell code.

## GitHub operations

Open Actions → **Deploy VM control plane** → **Run workflow**, select **main**.
Only manual main dispatches can use the `control-plane-production` environment.
Every operation has GitHub concurrency serialization and a private VM lock.

- `preflight`: validate host identity, image architecture/OCI source labels,
  existing encrypted identity, catalog, exact Dakota thread and Devsy reads.
- `status`: report the current authority, service inventory and authenticated
  smoke results.
- `adopt`: one-time Compose → Kamal authority handoff. Check the full-stack
  approval box. A retained Executor backup is made before service changes; Compose is stopped
  through its owning lifecycle before any Kamal writer/client starts. The
  independent private network and host Devsy bridge are then qualified, and
  Executor, proxy, CAS and tunnel boot serially with health gates.
- `cas`: restart/update only CAS. With no image input, reuse its current pin.
  To update, supply `sha256:<64hex>` and the matching CAS `<40hex>` source
  revision. All other services retain their own image pins and containers.
- `deploy`: redeploy the recorded four-image generation. Check the full-stack
  approval box. Tunnel stops first; only one Executor writer is used. Tunnel
  starts last after upstream readiness.
- `rollback`: restore the previous successful digest-pinned generation. Check
  the full-stack approval box. Services stop before replacement; identity and
  authenticated smoke must pass. A failed deploy automatically attempts this
  restoration and reports failure rather than accepting unhealthy ownership.

The job summary records the source SHA, runner, VM and operation receipt.
Mutating operation receipts include the backup result where the operation
returns it. No deployment credentials or kubeconfig contents are uploaded.
Fresh worker creation/deletion is never a deployment smoke test.

## Ownership and state

Kamal accessories are named `mcp-control-plane-executor`,
`mcp-control-plane-schema-proxy`, `mcp-control-plane-cas`, and
`mcp-control-plane-tunnel`. The top-level Kamal app/proxy/registry lifecycle is
never invoked. Public image pulls use Kamal's local-registry login no-op and a
dedicated empty Docker config under `deployment/anonymous-docker-config` on the
VM. The same config is used for Compose recovery. Shared Docker registry
credentials are neither used nor replaced.

Executor keeps the original `codex-control-plane_executor-data` named volume.
Existing private VM files remain under
`/home/kdlocpanda/.local/share/codex-control-plane`. CAS mounts its authority state,
UID-bound registry, private operator inputs and SSH key read-only as appropriate.
Executor binds loopback4312, CAS binds the private172.30.86.1 gateway, and no
control-plane listener is added to80/443 or public interfaces.

The host Devsy systemd service loads its existing private bridge config directly,
independent of Compose. The native Dakota proxy uses the dedicated forced-command
SSH endpoint described in [NATIVE_SSH.md](NATIVE_SSH.md), avoiding Tailscale SSH's
periodic check requirement. Tailscale network identity/routes remain unchanged.

After accepted adoption, the authority receipt and Kamal-container checks refuse
old Compose `up/down/restart` entrypoints. They cannot resurrect a second tunnel
or encrypted-volume writer. Volumes, secrets and prior config remain available.

## Bootstrap trust and credentials

The approved runner is repository-scoped on `pi5-01` (`10.10.20.50`), with labels
`self-hosted Linux ARM64 pi5-01 kamal mcp-control-plane`. Ruby 3.4.8 is existing
rbenv tooling; this repository uses an isolated, frozen Bundler 2.6.9/Kamal 2.12.0
bundle. The runner uses `ssh_config`, `identity` and `known_hosts` under
`/home/kdlocpanda/.local/share/mcp-control-plane-deploy` on the Pi; each file is
checked for owner and mode `0600`. SSH runs in batch mode with strict host-key
checking and agent forwarding disabled. The workflow has no pull-request or
fork trigger; the deployment script also requires this repository's main
`workflow_dispatch` on the named ARM64 runner. Use trusted repository operators
only. Deployment runs as VM user `kdlocpanda`, whose Docker authority is required
by Kamal.

The VM ED25519 host key is pinned from the already trusted Dakota connection:
`SHA256:S6qJ1D1sigx5Dj2ZQH5XCP7DspX/gTWJemO9/Q+2Se8`. No deploy-time keyscan or
host-check relaxation is used. Main-only environment policy and manual dispatch
are configured on GitHub. The runner registration token was used privately once;
production secret files were never copied to GitHub.

## Operator break-glass

On the approved Pi, in a trusted main checkout with its deployment bundle loaded:

```sh
export RBENV_VERSION=3.4.8
export PATH="$HOME/.rbenv/bin:$HOME/.rbenv/shims:$PATH"
export BUNDLE_GEMFILE="$PWD/Gemfile.deploy"
export BUNDLE_PATH="$HOME/.local/share/bundle/mcp-control-plane"
python3 scripts/deploy_control_plane.py status --local
python3 scripts/deploy_control_plane.py rollback --local --approve-full-stack
```

This uses the same pins, VM lock and acceptance checks. Do not use `kamal deploy`,
proxy setup, `docker compose down -v`, pruning, blank Executor initialization or
credential rotation. The original Dakota rollback from #16 remains separately
retained; do not start it while the VM production tunnel is live.

For status directly on the VM, run from `/home/kdlocpanda/Projects/mcp-tunnel-kit`:

```sh
python3 scripts/vm_deploy_host.py status
```

After Kamal adoption, an existing accessory can be restarted locally without
the runner. This example restarts only CAS and takes the same VM deployment
lock; if the lock is busy, let the running deployment finish before retrying.

```sh
printf '%s\n' '{"service":"cas"}' | flock -n \
  /home/kdlocpanda/.local/share/codex-control-plane/deployment/deploy.lock \
  python3 scripts/vm_deploy_host.py restart-local
```

This restarts the existing container; image changes and generation rollback use
the approved runner. A failed deployment reports its fixed phase name and whether
automatic rollback succeeded. `automatic rollback FAILED` requires recovery;
it is not a claim that production was restored.

The VM's `deployment/current.json` and `previous.json` record authority, source
and image generations. `deployment/backups` contains private encrypted-volume and
essential-state archives. Digest rollback preserves current application data;
if a future approved image makes incompatible database changes, stop and use the
retained backup with an explicit state-reconciliation decision instead of forcing
old code against a new schema. No automatic data erasure is performed.
