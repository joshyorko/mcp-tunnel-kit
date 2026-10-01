# MCP tunnel kit

The existing Friday MCP adapter and launch scripts, imported from the working
sandbox without moving it or copying its credentials or runtime state.

```text
MCP caller → existing tunnel control plane → tunnel-client
           → stdio Friday adapter → already-running Hermes /p/friday API
```

This kit exposes `friday_submit`, `friday_status`, and `friday_stop`. It also
keeps the separate embedded-stateless-stub launcher for transport experiments.
It does not start Hermes, provision a workspace, implement MemoryD, or introduce
another gateway, scheduler, or tunnel implementation.

**Validation boundary:** Friday submit/status previously passed a live tunnel
test, as reported for the original sandbox. Stop has been tested offline only.
This import's fresh checks use isolated fixtures; no production run was submitted
or stopped. See [FRIDAY_TEST.md](FRIDAY_TEST.md).

## Files

- `friday_mcp_adapter.py`: stdio server, settings validation, and private run registry.
- `friday_tools.py`: submit/status/stop and upstream error/timeout handling.
- `friday_contract.py`: fixed session and input bounds.
- `launch-friday.zsh`: attach the adapter to the existing tunnel.
- `launch-stateless-stub.zsh`: tunnel-client's embedded stateless demo, without Friday.
- `tests/`: original adapter tests plus offline launcher checks.
- `config/`: placeholder-only examples, never live configuration.
- [docs/EXTENDING.md](docs/EXTENDING.md): preserved MemoryD seam and tool rediscovery.

## Requirements

Use the same host/network namespace as the already-running Friday API. The
adapter intentionally accepts only numeric loopback HTTP addresses scoped to
`/p/friday`; it is not a general-purpose remote-URL relay.

You need:

- Python 3.10 or newer. This import was exercised with Python 3.14.7.
- `zsh` on `PATH` (or set `ZSH_BIN` for the test runner).
- Python packages in `requirements.txt`, pinned to the existing adapter's runtime.
- A separately installed, compatible `tunnel-client`. No downloaded binary is
  included. The inspected installation reported version
  `0.0.15+a390c168ff1b2d14e73a95991c186c6aba3ff5a0` and supports
  `--mcp.command`, `--embedded-stateless-mcp-stub`, and loopback ephemeral health.
- Your existing control-plane key and tunnel ID, and Friday's existing
  profile-specific `API_SERVER_KEY`. The two keys serve different purposes.
- An existing tunnel/connector registration and a running Hermes listener that
  serves the Friday profile route. This kit does not configure either service.

Obtain the external tunnel-client binary through your existing trusted
installation process; inspect `tunnel-client --version` and `tunnel-client run
--help` before substituting another release. Do not copy a downloaded executable
into this repository. There is no Docker or Podman dependency in this kit.

### Install Python dependencies

From a fresh checkout:

```sh
git clone https://github.com/joshyorko/mcp-tunnel-kit.git
cd mcp-tunnel-kit
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

With `uv`, the equivalent installation is:

```sh
uv venv .venv
uv pip install --python .venv/bin/python -r requirements.txt
```

The launcher defaults to this checkout's `.venv/bin/python`, not an interpreter
inside a particular Hermes installation. `FRIDAY_BRIDGE_PYTHON` is an explicit
override and must point to an executable with these dependencies installed.
Use checkout/interpreter paths without spaces or commas for the inherited
`--mcp.command` encoding.

## Required local configuration

Copy `config/launcher.example.zsh` to `launcher.local.zsh`, restrict it to your
user (`chmod 600 launcher.local.zsh`), and edit the placeholders locally.
Never launch with placeholder values. The local copy is ignored by Git.

- `CONTROL_PLANE_API_KEY`: existing tunnel control-plane credential, exported
  only in the launching environment; the command passes an `env:` reference.
- `CONTROL_PLANE_TUNNEL_ID`: the existing registered tunnel ID, not a new one
  invented by this kit.
- `TUNNEL_CLIENT_BIN`: optional executable override; default
  `$HOME/.local/bin/tunnel-client` for both launchers.
- `FRIDAY_API_ENV_FILE`: protected file containing Friday's `API_SERVER_KEY`;
  default `$HOME/.hermes/profiles/friday/.env`. The launcher clears any inherited
  `FRIDAY_API_KEY` so the adapter reads this explicitly selected profile file.
  It reads only `API_SERVER_KEY`, without loading other entries or interpolation.
- `FRIDAY_API_BASE_URL`: optional override for your local listener; default
  `http://127.0.0.1:8642/p/friday`. Preserve the `/p/friday` route and loopback
  address. `localhost`, non-loopback hosts, URL credentials, query strings, and
  fragments are rejected.
- `FRIDAY_HTTP_TIMEOUT_SECONDS`: optional timeout; default 30, greater than zero
  and no greater than 120.
- `FRIDAY_RUN_REGISTRY`: optional persistent private path; default
  `$XDG_STATE_HOME/friday-chatgpt-tunnel/runs.json`, or
  `$HOME/.local/state/friday-chatgpt-tunnel/runs.json` without `XDG_STATE_HOME`.

`config/friday-api.env.example` shows the single credential field using a
placeholder. Prefer the existing protected profile file; creating a new local
file does not require changing or rotating the existing credential.

Do not source or copy the entire production profile environment into the kit.
Keep credentials, local settings, run registries, session state, logs, databases,
virtual environments, downloaded binaries, and caches out of commits.

## Offline checks

```zsh
source ./launcher.local.zsh
zsh -n ./launch-friday.zsh
zsh -n ./launch-stateless-stub.zsh
./launch-friday.zsh --check
./launch-stateless-stub.zsh --check
.venv/bin/python -m unittest discover -s tests -v
```

`--check` validates local prerequisites/settings only. It does not contact the
API or start a tunnel, and it is not evidence of credentials being accepted,
upstream reachability, or live tool discovery. The tests use temporary fixture
credentials and registries, a loopback fake HTTP API, and a fixture tunnel binary.
They do not start or restart the real Hermes service or tunnel.

## Launch

When you deliberately choose to run this checkout, source the local configuration
in a `zsh` session and select **one** launcher:

```zsh
source ./launcher.local.zsh
./launch-friday.zsh
```

For the embedded stateless transport demo instead:

```zsh
source ./launcher.local.zsh
./launch-stateless-stub.zsh
```

Both run in the foreground and bind health/admin to loopback with an ephemeral
port. The stub launcher does not start Friday or MemoryD. The Friday launcher
uses the existing API and does not own its lifecycle.

**Do not launch a second client for a tunnel ID already used by the sandbox.**
A migration requires an explicitly planned handoff. Publishing this repository
does not perform that handoff or alter the existing installation. Keep one
adapter process per private run registry; atomic file replacement is not a
cross-process synchronization scheme.

## Shutdown and run cancellation

Press **Ctrl-C in the foreground launcher terminal** to shut down that tunnel
client and its adapter. Do not use a broad process-kill command. Closing the
tunnel does not stop Hermes or prove that submitted Friday runs were cancelled.

For one known run, `friday_stop(run_id)` requests cancellation. A `stopping`
response is acknowledgment, **not terminal execution proof**. Read
`friday_status(run_id)` until the API reports a terminal state. Unknown/unrecorded
run IDs are rejected before an upstream call. Ambiguous POST timeouts are not
retried automatically; preserve the caller's request ID and resolve acceptance
before deciding on another submission.

## Extending and rediscovering tools

`build_server` registers the Friday module through `register_friday_tools`; that
existing per-module registration call is the extension seam. MemoryD is not
implemented. Adding a future module must preserve the Friday tools and their
profile/run restrictions; do not add a parallel gateway for it.

A changed source file is not a changed caller catalog. During an authorized
handoff, restart only the adapter/tunnel instance that needs the new source,
then use a fresh MCP initialization and `tools/list` to verify the actual tool
names and schemas. Refresh/reconnect the consumer if it retains old metadata.
Do not bounce the shared Hermes gateway merely to refresh the tunnel catalog.
See [docs/EXTENDING.md](docs/EXTENDING.md) for the explicit verification sequence.
