# VM control-plane deployment

For host rebuild and encrypted recovery, see [Rebuild a control-plane host](REBUILD.md) and [Capture and stage recovery](RECOVERY.md). Keep the instance profile outside the checkout as an owned mode-`0600` file. See [the private profile example](../config/instance.example.json) for its schema. The profile-aware VM helper accepts `--instance-profile` and otherwise reads the default private profile. A captured runtime checkout may predate that helper. Run recovery from the updated controller checkout rather than assuming an old VM checkout supports this flag.

Issue #20 manages Executor, schema proxy, CAS and the original OpenAI tunnel as
Kamal 2.12.0 **accessories**, using GitHub's dedicated `pi5-01-mcp-control-plane`
ARM64 runner. Fizzy's runner/service and the existing Kamal proxy are separate.
Images are published Linux amd64 artifacts; nothing is rebuilt on the approved runner.

## Local workstation commands

From this repository on the controller, `bin/kamal` reads the ignored, private
`.env.kamal.local` and connects **directly to the VM** using the existing SSH key
and pinned host identity. It does not relay through the approved runner or GitHub.

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
host Devsy service. Other applications and the host's native Codex are unaffected.

This repository's `accessory deploy` command is an operator alias for the tested
Kamal accessory reboot sequence, with image pins, backup, health checks and
rollback. `bin/kamal deploy` is the same shortcut; it does not build an app image
or invoke Kamal's top-level app/proxy deployment. `start`/`stop` use real Kamal
accessory lifecycle operations and do not pull images or recreate containers.

For another local checkout, use `config/kamal-local.env.example` to create a
0600 `.env.kamal.local` with three required absolute SSH file references and an
optional `KAMAL_INSTANCE_PROFILE` path. If omitted, the profile defaults to
`$HOME/.config/mcp-control-plane/instance.json`. The referenced SSH config,
existing key, known-hosts file, and instance profile must be private (0600), and
the configuration must match the existing VM pin and strict SSH policy. No
registry, tunnel, or kubeconfig secrets belong in this local file. `make setup` installs the
locked Kamal bundle under the user's data directory using installed Ruby 3.4.8;
Fizzy's bundle/configuration is not modified. The environment file is parsed as
data, never executed as shell code.

## GitHub operations

Open Actions → **Deploy VM control plane** → **Run workflow**, select **main**.
Only manual main dispatches can use the `control-plane-production` environment.
Every operation has GitHub concurrency serialization and a private VM lock.
The workflow also accepts an optional operator-supplied Dakota native tuple:
target `local`, exact worktree cwd, and persistent thread id. Full image deploy,
adopt, and CAS acceptance require that tuple and a successful metadata-only
exact read. `preflight` reports native-read status without letting a thread
mismatch block its separate read-only Devsy plan.

- `preflight`: validate host identity, image architecture/OCI source labels,
  existing encrypted identity and Devsy provider plan. It also reports catalog,
  Devsy reads and native-read status independently.
- `status`: report current authority, service inventory, Devsy plan and smoke
  results.
- `devsy-check`: non-mutating host Devsy version, systemd, provider, cluster
  capacity and resource-policy plan. `changes-required` does not apply anything.
- `devsy-apply`: isolated host-only bootstrap/upgrade. Set the **Approve host
  Devsy apply** checkbox and supply a verified native tuple. The workflow pins
  and verifies Homebrew, Josh's tap and the Devsy artifact, applies the private
  ROR Kubernetes provider policy, enables/verifies `codex-control-plane-devsy`,
  checks a real exact Dakota native read, and verifies unchanged Kamal
  accessories, Executor identity and tunnel count. It does not reboot Kamal
  accessories or create workers.
- `devsy-rollback`: host-only restoration of the last successful bootstrap
  snapshot and its source revision. Set the separate **Approve host Devsy
  rollback** checkbox. The native-read status is reported but does not block
  rollback.
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

Protected GitHub image deploys call the host Devsy drift check and refuse to
proceed when the selected binary, unit or provider differs. They never apply
host changes. Local `make cas`, `make up`, restarts, and image redeploys do not
reinstall the CLI, rewrite the unit, or change provider options. For a clean prepared Linux AMD64 or ARM64
VM, OS/user setup, Tailscale enrollment, the authorized ROR namespace, private
Devsy config/context, kubeconfig and cluster prerequisites must already exist;
this repository does not provision them. Keep config and kubeconfig as
VM-local mode-`0600` inputs. Run `devsy-check`, review the plan, then run the
explicit `devsy-apply` workflow operation. If a real clean VM is unavailable,
isolated fixture results must be labeled as fixture-only.

## Ownership and state

Kamal accessories are named `mcp-control-plane-executor`,
`mcp-control-plane-schema-proxy`, `mcp-control-plane-cas`, and
`mcp-control-plane-tunnel`. The top-level Kamal app/proxy/registry lifecycle is
never invoked. Public image pulls use Kamal's local-registry login no-op and a
dedicated empty Docker config under `deployment/anonymous-docker-config` on the
VM. The same config is used for Compose recovery. Shared Docker registry
credentials are neither used nor replaced.

Executor keeps the original `codex-control-plane_executor-data` named volume.
Existing private VM files remain under the state path in the private instance
profile. CAS mounts its authority state,
UID-bound registry, private operator inputs and SSH key read-only as appropriate.
Executor binds loopback4312, CAS binds the configured private gateway, and no
control-plane listener is added to80/443 or public interfaces.

The host Devsy systemd service loads its existing private bridge config directly,
independent of Compose. The native host proxy uses the dedicated forced-command
SSH endpoint described in [NATIVE_SSH.md](NATIVE_SSH.md), avoiding Tailscale SSH's
periodic check requirement. Tailscale network identity/routes remain unchanged.

After accepted adoption, the authority receipt and Kamal-container checks refuse
old Compose `up/down/restart` entrypoints. They cannot resurrect a second tunnel
or encrypted-volume writer. Volumes, secrets and prior config remain available.

## Bootstrap trust and credentials

The approved runner is repository-scoped on `pi5-01`, with labels
`self-hosted Linux ARM64 pi5-01 kamal mcp-control-plane`. Ruby 3.4.8 is existing
rbenv tooling; this repository uses an isolated, frozen Bundler 2.6.9/Kamal 2.12.0
bundle. The runner uses `ssh_config`, `identity` and `known_hosts` under
its private deployment-data directory; each file is checked for owner and mode
`0600`. SSH runs in batch mode with strict host-key
checking and agent forwarding disabled. The workflow has no pull-request or
fork trigger; the deployment script also requires this repository's main
`workflow_dispatch` on the named ARM64 runner. Use trusted repository operators
only. Deployment runs as the configured VM user, whose Docker authority Kamal
requires.

The VM ED25519 host key is pinned in the private `known_hosts` file and checked
against the private instance-profile fingerprint. Obtain a first pin through a
trusted connection. No deploy-time keyscan or host-check relaxation is used.
Main-only environment policy and manual dispatch are configured on GitHub. The
runner registration token was used privately once; production secret files were
never copied to GitHub.

## Operator break-glass

On the approved runner, in a trusted main checkout with its deployment bundle loaded:

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
credential rotation. The original local rollback from #16 remains separately
retained; do not start it while the VM production tunnel is live.

For direct VM status, use a checkout with the profile-aware helper:

```sh
python3 scripts/vm_deploy_host.py status \
  --instance-profile "$HOME/.config/mcp-control-plane/instance.json"
```

After Kamal adoption, an existing accessory can be restarted locally without
the runner. This example restarts only CAS and takes the same VM deployment
lock; if the lock is busy, let the running deployment finish before retrying.

```sh
state_dir="/path/from/private-instance-profile"
printf '%s\n' '{"service":"cas"}' | flock -n \
  "$state_dir/deployment/deploy.lock" \
  python3 scripts/vm_deploy_host.py restart-local \
    --instance-profile "$HOME/.config/mcp-control-plane/instance.json"
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
