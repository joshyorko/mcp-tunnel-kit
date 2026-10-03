# Run the control plane with Compose

Run these commands on the Bluefin host from this checkout. Docker Compose owns
the control-plane containers. Existing native Codex and Devsy state remain
operator-owned.

```text
ChatGPT → official tunnel-client → executor:4312/mcp?elicitation_mode=browser
        → private bridge gateway:8088/mcp → CAS → existing native Codex
```

Executor and the tunnel use the dedicated Compose bridge. CAS uses host
networking to preserve the existing Devsy loopback SSH route. Its API binds only
to the bridge gateway, `172.30.86.1:8088` by default. It never binds to all host
interfaces. Executor's dashboard is published only at `127.0.0.1:4312`.

## Prepare operator paths

Use rootful Linux Docker with Compose, Bash, and Python 3.10 or later. Rootless
engines and user namespace remapping are refused because their host-network and
socket UID boundaries differ. No host packages or
systemd services are installed by this kit. The CAS product image currently
supports Linux amd64.
CAS has a read-only root filesystem, drops all capabilities, and uses
`no-new-privileges`. Its bounded executable `/tmp` and selected private state
mounts remain writable.

For a new checkout, copy `.env.example` to the ignored `.env` and fill in its
non-secret paths. Keep existing `.env` settings when updating a prepared checkout.
`CAS_IMAGE` defaults to the product image published from commit
`45a27a0515bbfc12de278dd03e26751cecb91fc7`, pinned by its immutable digest. The
production file never builds from a neighboring checkout. Executor and tunnel
images are pinned by exact release and immutable digest in `compose.yaml`.

Set `CAS_TARGETS_SOURCE` to your existing operator target JSON. Its `local`
target must have an explicit `socket_path`. Set `NATIVE_CODEX_SOCKET_DIR` to the
resolved socket's parent directory and `CAS_UID` to the socket owner's UID.
The default narrow mount is `/tmp/codex-daemon-1000` at `/run/native-codex`, read
only. The generated private target file changes only `local.socket_path` to
that mounted socket name. The original target file remains untouched.

The state directory and its CAS data, receipts, and Actions Runtime cache must
be owned by that same user, mode 0700. Generated configuration and secret files
must be mode 0600. Setup refuses symlinks and unsafe ownership or permissions.

For an existing Action Server, set `CAS_RUNTIME_DIR` and `CAS_RECEIPTS_DIR` to
its original runtime and receipt directories. They are separate narrow writable
mounts. Do not silently replace retained receipts with a fresh empty store.
Unset defaults create new stores under the private CAS state directory only
for a fresh installation.

Stop the existing Action Server in its own terminal before attaching its
runtime directory to the container. With that writer stopped, back up the
runtime and receipt directories before the runtime upgrade. Keep the original
receipt IDs and history. Do not run two writers against one SQLite datadir,
seed it from a build-time database, or assume an older image can safely undo a
database migration.

Before starting the bridge, the helper checks all host IPv4 routes and Docker
network subnets. It rejects collisions and public subnets. An existing bridge
is retained only when its Compose ownership, subnet, and gateway match. To use
another collision-free private `/24`, set both `CONTROL_PLANE_SUBNET` and its
first usable address in `CONTROL_PLANE_GATEWAY`.

## Create the browser owner and organization

First run starts only the stock Executor. It does not need CAS or tunnel
credentials and does not start the tunnel:

```sh
./scripts/control-plane-up --first-run
```

Open `http://127.0.0.1:4312/` on this workstation. Complete the official
**Set up Executor** form, create the owner and organization, and sign in. Create
an organization-scoped personal access token at **Account > Tokens**,
`http://127.0.0.1:4312/account/tokens`. The browser owns password entry and token
creation.

Save the PAT privately as `executor-pat` in `CONTROL_PLANE_SECRET_DIR`, mode
0600. The example directory is
`$HOME/.local/share/codex-control-plane/secrets`. Do not paste tokens into
command arguments, `.env`, chat, or shell history. The following command can
read the PAT without echoing it and reuse your already-exported existing
control-plane key and tunnel ID:

```sh
./scripts/control-plane-up --secrets
```

The private files are `executor-pat`, `control-plane-api-key`, and
`control-plane-tunnel-id`. Existing files are retained. Setup derives the
private `executor-auth-header` containing the complete bearer header.
The stock tunnel resolves key and header `file:` references. Its minimal
POSIX entrypoint reads only the tunnel ID into the supported environment,
then executes the unchanged stock binary. No credential or tunnel ID enters
its command arguments. Tunnel logs are disabled because stock logs can contain
the tunnel ID. Status reports fixed service state instead.

Executor generates authentication and encryption keys inside the persistent
`codex-control-plane_executor-data` volume at `/app/data`. Preserve the whole
volume. Losing those encryption keys loses access to encrypted stored data.
The foreground CLI's `keys.json` and bearer are unrelated to this browser PAT.

## Include existing Devsy state when needed

For a configured Devsy target, set `DEVSY_HOME`, `DEVSY_CONFIG_FILE`,
`DEVSY_CONTEXT_DIR`, and the provider-referenced `DEVSY_KUBECONFIG_FILE` in `.env`.
Add `compose.devsy.yaml` to `COMPOSE_FILE`:

```sh
COMPOSE_FILE=compose.yaml:compose.devsy.yaml ./scripts/control-plane-up --check
```

That override mounts only the existing configuration file, selected context
directory, and referenced kubeconfig, read only, at their original absolute
paths. `DEVSY_HOME` points at the original configuration parent. Check external
certificate, key, token-file, exec, and auth-provider dependencies before using
this override. If an existing workspace proves it needs selected SSH files,
add only those exact read-only files in an ignored operator Compose override.
Never mount the whole home directory, `.ssh`, Docker socket, or kubeconfig
directory.

No remote workspace or SSH identity is created. The inspected default context
has no workspace records, so remote execution remains unverified and fails
closed until an existing selected workspace and its dependencies are available.
CAS host networking preserves host loopback access. It does not manufacture a
route or bypass the existing target allowlist.

## Start, inspect, and stop

Stop any previous foreground tunnel client in its own terminal and wait for
exit. The preflight refuses a competing local tunnel client. Ensure that no
other machine uses the same existing tunnel ID.

```sh
./scripts/control-plane-up --check
./scripts/control-plane-up
./scripts/control-plane-status
```

The up script validates paths, private files, image identity, socket ownership,
and subnet collisions before starting services. CAS readiness initializes MCP
and discovers its actual catalog. Executor readiness uses its stock native
health command. The bounded `app-ready` job then imports Codex through the
official organization API or retains the matching existing app. It verifies
the stock generated source, authenticated compact MCP, browser `resume` schema,
and Codex discovery before the tunnel starts. It makes no native Codex mutation
or automatic approval.

The generator archive inspected for source validation is revision
`e1c4f014c89c3f27648fd77c728311b6a2767819`. The pulled official image declares
OCI revision `4930a44e9ed7b8556f61984fae7786b4a79344c5`. Live import readback must
prove compatibility. A source mismatch stops bootstrap, reports only the source
hash, and preserves the app for inspection.

The tunnel healthcheck requires liveness, readiness, and a successful
control-plane poll. Healthy services do not prove browser approval or ChatGPT
consumer acceptance.

Before changing targets or token files, stop the stack with
`./scripts/control-plane-down`. Make the changes, then run
`./scripts/control-plane-up`. Active single-file mounts can retain old file
contents after atomic replacement. The helper refuses such updates while CAS,
bootstrap, or tunnel containers are active. An unchanged repeated up retains
the existing files and services.

After one-time setup, the ordinary Compose commands also work:

```sh
docker compose up -d
docker compose down
```

For bounded startup and explicit readiness reporting, use the scripts. To stop
the stack and retain persistent state:

```sh
./scripts/control-plane-down
```

Do not add `--volumes` or delete the private state directory during normal
shutdown. Those operations destroy durable data or credentials. This script
does not stop native Codex, Devsy, or unrelated services.

## Verify browser approval and the consumer

Use the stock CAS image's Python for the harmless target-list probe through the
browser MCP endpoint:

```sh
docker compose run --rm --no-deps --entrypoint python3 app-ready /opt/tunnel-kit/compose_control.py probe
docker compose run --rm --no-deps --entrypoint python3 app-ready /opt/tunnel-kit/compose_control.py resume
```

Exit 3 means a browser approval is pending. Its exact URL and request ID are
kept with the original MCP session ID and negotiated protocol only in the
private bootstrap `browser-approval.json`. Resume reuses that transport identity
without initializing a new session. Open the request in
the signed-in Executor browser and answer it there. Run `resume` afterward.
That call submits only `requestId`; it never supplies `response.action` or an
approval decision. Do not rerun `execute` to continue an existing request.
The pinned server advertises only `requestId` but permits extra JSON properties.
Schema inspection alone does not prove that an agent-supplied decision is
ignored. The live browser gate must confirm that a resume attempt cannot advance
the pending execution before the signed-in browser answers it.

Pending, busy, transport-uncertain, and unavailable continuations retain their
private receipt. An unavailable response can mean a caller/session mismatch,
expiry, consumption, or state lost on restart; it does not authorize replay.
Verify the original session and browser request before retrying resume. A
legacy receipt without transport metadata requires recovery of that original
metadata; never initialize another session to continue it.
Only a confirmed completed result archives the pending receipt as
`browser-approval-terminal-*.json`. Earlier effects are not rolled back. The
helper never retries `execute` automatically.

Reconnect ChatGPT or Jarvis to the same existing tunnel. Verify a fresh catalog
of exactly `skills`, `execute`, and `resume`, Codex discovery through
`tools.search`, and the harmless read with browser approval where requested.
Local tests, container health, and a successful poll do not close this consumer
gate.

## Build only the CAS product for local acceptance

The optional local override uses an explicit CAS source path, defaulting to the
user-approved sibling checkout. It never builds Executor or tunnel-client:

```sh
docker compose -f compose.yaml -f compose.local.yaml build codex-action-server
COMPOSE_FILE=compose.yaml:compose.local.yaml ./scripts/control-plane-up --check
COMPOSE_FILE=compose.yaml:compose.local.yaml ./scripts/control-plane-up
```

Set `CAS_SOURCE_PATH` to another explicit product checkout when necessary.
Production acceptance and release still require the separately published
immutable GHCR artifact. The local image is an acceptance candidate only.

## Check the deployment contract

```sh
.venv/bin/python -m pytest -q
bash -n scripts/control-plane-up scripts/control-plane-down scripts/control-plane-status
sh -n scripts/tunnel-secrets.sh
docker compose --env-file .env.example config --quiet
git diff --check
```

Record these nine live gates against the exact artifacts after a clean stop and
`docker compose up -d`:

| Gate | Required evidence |
| --- | --- |
| 1 | Action Server healthy from actual MCP initialization and discovery |
| 2 | Executor healthy from its native readiness command |
| 3 | Executor discovers the Codex app |
| 4 | `tools.search` finds Codex operations |
| 5 | `list_targets` traverses Executor to Action Server |
| 6 | Tunnel-client connects and records a successful control-plane poll |
| 7 | ChatGPT reaches Executor through the Secure MCP Tunnel |
| 8 | A harmless Codex call pauses, Josh approves in the browser, and the original execution resumes |
| 9 | Compose down stops the stack while host native Codex and persistent Executor and receipt state survive |

Focused tests and image builds do not close these live gates. Remote native
execution is unverified while the selected Devsy context has no workspace.
Keep the deployment draft until every requested gate is proven.
