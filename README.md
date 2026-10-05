# MCP tunnel kit

The normal path uses Docker Compose and pinned, stock upstream Executor v2:

```text
ChatGPT / Jarvis → OpenAI Secure MCP Tunnel → Executor browser MCP
                 → Codex Action Server → existing native Codex app-servers
```

Run on the Bluefin host with Docker Compose and Python 3.10+. For a new checkout,
copy `.env.example` to the ignored `.env`, preserve/fill the operator paths, and
add `CONTROL_PLANE_API_KEY`, `CONTROL_PLANE_TUNNEL_ID`, and `EXECUTOR_PAT` privately
in your editor. Then run:

```sh
./scripts/control-plane-up
./scripts/control-plane-status
./scripts/control-plane-down
```

Normal startup validates the credentials and prepares private file-backed Docker
secrets automatically. A restored setup with all three credentials needs no
separate `--secrets` step. Keep your existing `.env` when updating a checkout.
Use these wrappers for the stack lifecycle. Raw `docker compose up` and `down`
bypass host Devsy bridge management and startup revalidation.

For a fresh Executor, first run `./scripts/control-plane-up --first-run` without
credentials. Finish the browser owner/organization setup, create the organization
PAT, add it to `.env`, and run normal up. See [Compose setup and
acceptance](docs/COMPOSE.md) for operator paths, credential precedence, rotation,
and browser acceptance.

The stock Executor dashboard is `http://127.0.0.1:4312/`. The tunnel's `main`
channel uses `http://executor:4312/mcp?elicitation_mode=browser` on Compose DNS.
Executor advertises only `skills`, `execute`, and `resume`; Codex tools are found
through codemode. The trusted Codex app has no Executor browser-approval wrapper,
while Devsy mutations remain browser-gated. CAS validation and native Codex
safety are unchanged. The kit does not install systemd services or change native
Codex or Devsy state.

The retained direct Codex launchers are break-glass paths. Stop the Compose
tunnel before using them. [Foreground Executor notes](docs/EXECUTOR.md) describe
the retired setup and its historical evidence.

## Direct Codex break-glass, inactive

The rest of this document describes the retained direct path. It is not the
default. Stop the Executor-facing tunnel before using `./launch-codex.zsh`;
never run both clients on the same tunnel ID. Existing `deploy/` service
templates are historical and are not installed or used for this foreground setup.

Expose the Codex tools from the **already-running** Action Server through the
**existing** tunnel. The launcher uses tunnel-client's native HTTP upstream:

```text
ChatGPT → existing tunnel control plane → tunnel-client
        → http://127.0.0.1:8088/mcp → Action Server → configured Codex target
```

Use `payload.target = "local"` for Codex calls. This kit does not start an Action
Server or Codex app-server, change FRIDAY's targets, or create a registration.
It does not use Hermes's `/p/friday` route or profile key.

`launch-codex.zsh` launches the Codex HTTP integration. `codex_mcp_check.py`
checks local readiness and never starts an MCP server. The former registration
at `friday_mcp_adapter.py:140`, Friday launcher, tool module, run registry logic,
profile-key reader and contracts have been retired. Existing ignored local files
and credentials are not migrated or deleted.

## Requirements and setup

Run on the Bluefin host, or in the same network namespace as the existing
loopback Action Server. Container loopback is not the host's loopback.

- Existing `tunnel-client`, `zsh`, and Python 3.10 or newer.
- Project-local Python environment from `requirements.txt`, with MCP SDK
  `2.0.0` and `httpx` `0.28.1`, for readiness checks and tests.
- Your existing exported `CONTROL_PLANE_API_KEY` and `CONTROL_PLANE_TUNNEL_ID`.
  The launcher passes the key by environment reference, never as a key value.

The inspected binary is `0.0.15+a390c168ff1b2d14e73a95991c186c6aba3ff5a0`.
Its `run --help` documents `--mcp.server-url` with
`url=...,channel=...`. No Python forwarding adapter or new daemon is needed.
Use your existing trusted tunnel-client installation, outside this repository.

For a checkout without a prepared environment, use user-scoped `uv`:

```sh
uv venv .venv
uv pip install --python .venv/bin/python -r requirements.txt pytest==9.1.1
```

If `uv` is unavailable, create a project `.venv` with Python's `venv` module and
install `requirements.txt` there. Do not install packages into the Bluefin base OS.

## Configuration

Keep using the shell configuration that already supplies your existing tunnel
credentials and ID. `config/launcher.example.zsh` is an optional placeholder-only
example; `launcher.local.zsh` remains ignored. Do not overwrite existing local
configuration with placeholders. The launcher does not automatically source it.

| Variable | Purpose/default |
| --- | --- |
| `CONTROL_PLANE_API_KEY` | Existing control-plane credential, exported privately |
| `CONTROL_PLANE_TUNNEL_ID` | Existing registered tunnel ID, unchanged |
| `TUNNEL_CLIENT_BIN` | Defaults to `$HOME/.local/bin/tunnel-client` |
| `CODEX_MCP_URL` | Break-glass only; defaults to `http://127.0.0.1:8088/mcp` |
| `CODEX_CHECK_PYTHON` | Defaults to this checkout's `.venv/bin/python` |

The URL must be numeric loopback HTTP with the exact `/mcp` path. URL credentials,
queries, fragments, whitespace and commas are rejected without echoing the URL.
All `FRIDAY_*` settings are unused by this Codex launch path.

## Tool contract and authority

Native HTTP forwarding exposes the Action Server's actual tool names, input and
output schemas, annotations, structured/text results, metadata and MCP errors.
There is no fixed local tool registration or generic-message translation.
Discovery remains upstream-owned, so additional tools appear in a fresh catalog.

The inspected live catalog contains 20 Codex tools, including `discover_threads`,
`read_thread`, `list_thread_turns`, `list_thread_items`, `start_turn`, `steer_turn`
and `interrupt_turn`. Exact CWD, thread and turn identifiers remain caller inputs
validated by the Action Server. The upstream target allowlist and native
permission/approval handling remain authoritative. This kit does not rewrite
`payload`, inject a target, relax guards, or elevate permissions. Use `local`;
other configured targets remain in the original schemas without config changes.

The live Action Server currently publishes conservative annotations even for its
read operations: `readOnlyHint=false`, `destructiveHint=true`. They are forwarded
unchanged. Do not infer that every exposed operation is harmless.

## Verify before the handoff

```zsh
./launch-codex.zsh --check
.venv/bin/python codex_mcp_check.py --probe --cwd "$PWD"
.venv/bin/python -m unittest discover -s tests -v
zsh -n launch-codex.zsh
zsh -n launch-stateless-stub.zsh
```

`--check` validates offline prerequisites/settings only. It sends no MCP request
and starts no tunnel. `--probe` uses the pinned SDK to initialize local MCP,
list the catalog with pagination, and call `discover_threads` on target `local`
with the exact CWD and limit 1. If a matching thread exists, it calls `read_thread`
with `include_turns=false`. It never resumes, starts, steers or interrupts a
thread, and omits thread contents and raw upstream failures from output.
A successful empty discovery page is still a valid read-only thread query.

Tests use isolated loopback fixtures. Native forwarding cases run the installed
binary against a fake control plane with a dummy ID and fixture credential;
production environment/configuration is not inherited. They never connect to
OpenAI's control plane or the running Action Server. These cases skip explicitly
when tunnel-client is absent. Install it or set `TUNNEL_CLIENT_BIN` to include
those checks. See [CODEX_TEST.md](CODEX_TEST.md) for the evidence boundary.

## Foreground handoff, same tunnel

After fetching the pushed version with a fast-forward-only update, run the
preflight and local probe above in the checkout. Keep the old client running
until the replacement code is ready.

If the old foreground client is still running, press **Ctrl-C in that client's
own terminal**, and wait for it to exit. This stops only that client. Do not use
`pkill`, stop the Action Server, or start a second client on the same tunnel ID.

In a zsh terminal that already has your existing tunnel variables exported,
launch `./launch-codex.zsh` from the updated checkout. If those variables are
kept in your ignored `launcher.local.zsh`, source that existing file first.
Do not enter credential values in command arguments or enable shell tracing.
The launcher runs in the foreground and binds health/admin to loopback on an
ephemeral port. It does not own the upstream services' lifecycles.

## Reconnect ChatGPT and verify the live catalog

After the replacement client is running, delete/reconnect the ChatGPT app using
the **same tunnel**. A fresh MCP initialization and `tools/list` must show Codex
tools such as `discover_threads` and `read_thread`, with their typed `payload`
inputs. `read_thread` requires `target`, `cwd`, and `thread_id`; turn mutations
also require exact turn identifiers. `friday_submit`, `friday_status` and
`friday_stop` must no longer be present.

Inspect the app's refreshed tool metadata, or request a fresh tool listing if
the consumer exposes it. Then ask it to call only `discover_threads` with
`{"payload":{"target":"local","cwd":"<exact absolute checkout path>","limit":1}}`.
Use a path from your local probe. Compare its native response with local results;
do not use resume/start/steer/interrupt tools to test discovery.

Local readiness and loopback fixture forwarding are tested here. Credential
acceptance, routing through your existing live tunnel, and ChatGPT catalog
refresh remain **live verification after your launch and reconnect**. Neither
publishing code nor a local probe proves that remote gate.

The separate `launch-stateless-stub.zsh` remains a transport experiment. Do not
use it for this Codex handoff or concurrently on the same tunnel ID.


## Optional host-native Devsy MCP

[Host-native Devsy setup](docs/HOST_DEVSY.md) adds the existing host Devsy MCP
as a second Executor app through the same single tunnel. It is disabled by
default, uses explicit host paths, and preserves host configuration/authentication.
Only three read tools bypass Executor browser approval; unknown calls fail closed.
