# Host-native Devsy through Executor

This optional integration exposes the existing host `devsy mcp serve` beside
Codex, through the same Executor-facing Secure MCP Tunnel. It does not install
Devsy, create a provider or workspace, change CAS, or add a scheduler.

```text
one Secure MCP Tunnel → Executor /mcp?elicitation_mode=browser
                         ├─ Codex → managed gateway:8088/mcp → CAS
                         └─ Devsy → managed gateway:8089/mcp → host devsy mcp serve
```

## Why a host adapter

The pinned Executor beta.8 source has
[`stdioRouter`](https://github.com/UsefulSoftwareCo/executor/blob/e1c4f014c89c3f27648fd77c728311b6a2767819/packages/apps/src/implementation/mcp-stdio.ts).
It owns a subprocess in the Executor runtime. It does not provide a host-side
HTTP bridge. Using it inside the container would require moving the binary and
its configuration/authentication into that container.

The repo-owned Python adapter instead executes the explicitly selected host
binary with the fixed argument array `mcp`, `serve`, without a shell. It runs as
the user who runs `control-plane-up`, with that user's host environment and an
explicit working directory. Existing HOME, KUBECONFIG, provider helpers, SSH
agents, certificates and auth stay on the host. An optional DEVSY_HOME override
selects existing configuration; it neither creates nor copies it. Executor gets
only the HTTP MCP URL, never a host home/config/kubeconfig/Docker-socket mount.

## Enable it

Requirements are the existing rootful Linux Compose deployment, Python 3.10+
with Linux pidfd support, and an already working host Devsy installation. Keep
existing `.env` values and private files. Add these non-secret settings:

```dotenv
DEVSY_MCP_ENABLED=true
DEVSY_MCP_BIN=/absolute/path/to/existing/devsy
DEVSY_MCP_CWD=/absolute/existing/host/working/directory
# Only if the normal operator environment does not already select it:
# DEVSY_MCP_HOME=/absolute/path/to/existing/devsy/configuration
```

Use the same host user and environment that already runs Devsy. Then use the
normal commands:

```sh
./scripts/control-plane-up --check
./scripts/control-plane-up
./scripts/control-plane-status
./scripts/control-plane-down
```

Disabled is the default, so existing Codex-only installations do not suddenly
start a new native process. `--check` validates the explicit paths and bridge
configuration without launching Devsy. Both check and normal up materialize the
private credential files using process environment, literal `.env`, then retained
files, in that order. Rotation is refused while affected containers are active.
`--first-run` still starts only Executor without reading credentials or validating
Devsy paths, for browser owner/organization/PAT setup. No systemd unit is installed.

`up` closes the tunnel during validation, starts the private Compose services,
starts or retains the matching host bridge, reruns the one-shot app bootstrap,
and starts the single tunnel only after bootstrap succeeds. Bootstrap discovers
the actual Devsy catalog, imports or retains the `Devsy` app, checks its exact
stock generated approval source, searches the `devsy` namespace and performs
only `provider_list` and `workspace_list`. It also retains and verifies Codex.

Down stops the tunnel first, stops only the recorded host bridge, then stops
Compose. It preserves Executor's volume, both integration receipts, all CAS
state, and host Devsy configuration. Changing bridge code, paths or inherited auth
requires down/up. To disable, set `DEVSY_MCP_ENABLED=false` and run normal up;
the bridge stops while its saved app/receipt stays available for later re-enable.
The retained Devsy app is unavailable while disabled, not silently deleted.

The older `compose.devsy.yaml` override is for CAS's existing remote targets.
It is separate and is not needed for this host-native MCP integration. This
change does not alter that optional CAS configuration.

## Network and approval boundary

The daemon binds exactly the managed Compose gateway, default
`172.30.86.1:8089`, never wildcard, LAN, public or loopback. Startup checks the
managed network's Compose labels, bridge driver, private /24, first-address
gateway, and host-route/network collisions. Direct invocation repeats those
checks. HTTP accepts only managed-subnet or loopback-source requests and rejects
foreign Host headers and browser Origins. Host health probes explicitly source
from numeric loopback to avoid Docker masquerading gateway-to-itself traffic to
another interface. The listening destination remains the managed gateway only;
no LAN address or LAN subnet is allowlisted.

The private gateway is a trusted service seam, like the existing CAS endpoint.
It is not authenticated per host user: every local host user and every container
attached to this managed network must be trusted. Such peers can call known
Devsy tools directly with the Devsy owner's authority. Do not attach untrusted
containers, route/publish this endpoint, or use this on a multi-user untrusted
host. Executor browser approval remains enabled for Devsy mutations. The trusted
Codex app is imported without the redundant Executor approval wrapper; CAS target,
CWD and thread validation and native Codex safety remain unchanged. This adapter
does not invent a second approval service. A deployment requiring hostile-peer
isolation needs a separately designed authenticated transport before enabling.

The adapter ignores Devsy's safety hints and supplies its own policy:

- Read-only: `provider_list`, `workspace_list`, `workspace_status`
- Approval-required through Executor: `workspace_create`, `workspace_start`,
  `workspace_stop`, `workspace_delete`, `workspace_exec`, `provider_add`,
  `provider_delete`, `provider_use`
- Unknown tools are advertised consequential and calls are refused, even after
  an approval, until the repo's allowlist is deliberately updated

Missing or misleading annotations cannot make a Devsy tool safe. Its pinned
stock Executor source wraps destructive tools with
`withApprovals(...always())`. Bootstrap preserves that source and rejects
edited/mismatched Devsy apps. For Codex, bootstrap updates the existing app in
place only when its source exactly matches the previous generator; other edits
remain a hard stop. Neither bootstrap nor health checks approve a mutation.
Executor's external tools remain exactly `execute`, `resume`, and `skills`;
browser resume accepts only `requestId`.

## Failure and lifecycle behavior

The adapter is a small detached host process owned by this checkout, with a
private lock and PID/start-time receipt under the control-plane state directory.
Repeated up retains a healthy matching instance. A stale receipt is recovered;
a live mismatched instance requires down/up. Stop uses a Linux pidfd after
checking command and birth time, avoiding signals to an unrelated reused PID.
There is no automatic daemon restart loop. After a crash, calls fail closed;
run normal up to revalidate and restart it.

Each catalog or call owns a fresh stdio session, with initialization, bounded
pagination, a 2 MiB message limit, at most eight HTTP workers, bounded admission
with 503 on saturation, a 10-second catalog
budget and a 120-second call budget. A child guard enforces its own deadline
and Linux parent-death cleanup, killing its private process group if the bridge
dies. Shutdown closes active sockets and prevents new children. No operation is
automatically retried. A timed-out mutation may have reached its provider;
inspect actual state before deciding whether to retry.

`GET /health` performs real initialization and catalog discovery. It does not
call a workspace tool. Stdout/stderr, request bodies, tool outputs, credentials
and upstream exception details are never logged. Private receipts contain only
paths, process identity and integration identity, not provider credentials.

## Verification and remaining Dakota acceptance

The normal pytest suite tests actual synthetic stdio/HTTP traffic, policy
normalization, unknown-tool refusal, killed-parent cleanup, slow-request
shutdown and two-app retention. `tests/executor_devsy_live.py` runs the pinned
Executor image with disposable fixture credentials and synthetic upstreams. It
checks both imports, restart retention, namespaces, read pass-through and a real
pending browser approval without accepting it or forwarding a mutation.
`tests/devsy_lifecycle_live.py` tests the real daemon on an isolated managed
Docker bridge, including repeated up/down and stale-process recovery.

CI uses no real Devsy provider, native Codex worker, production credentials or
OpenAI tunnel. The existing native tunnel-client tests still require that
binary. CI's browser-approval API check is not rendered-browser acceptance.

Before deployment, the operator still needs to:

1. Review the trusted-host/network boundary and confirm the selected host Devsy
   binary, user, config and provider authentication are the intended existing ones
2. Back up retained Executor/CAS state as in COMPOSE.md, enable the explicit
   paths, and run check then normal up when deployment is authorized
3. Verify the only Devsy listener is the managed gateway on port 8089, exactly
   one tunnel-client runs, and both namespaces appear through the tunnel
4. Confirm provider/workspace list reads succeed through Executor and the
   intended ChatGPT consumer without approval or credential output
5. Confirm a consequential request pauses in the signed-in browser; deny it
   there, never approve a real mutation just to test this integration
6. Run down/up and confirm both app IDs, source/deployments, existing workspaces,
   provider configuration, CAS receipts and Executor state remain unchanged

No Dakota deployment or live mutation is part of this PR.
