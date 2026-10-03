# Executor foreground path

All commands run on the Bluefin host, in the same network namespace as both
loopback servers. Container loopback is different. This kit starts neither the
Action Server nor native Codex, Devsy, Review, Josh Room or MemoryD.

## Pinned installation

The installed host Node is `v26.10.0`. The published CLI is pinned to
`executor@2.0.0-beta.8`, which requires Node >=24.14.0. Its platform runtime and
framework are bundled. There is no Executor source checkout or fork.

```sh
npm install --global executor@2.0.0-beta.8 --include=optional
./launch-executor.zsh --check
```

Do not substitute the moving `beta` tag. The launcher verifies the exact CLI
version and disables its update check. Upstream release sources are pinned at
[e1c4f014c89c3f27648fd77c728311b6a2767819](https://github.com/UsefulSoftwareCo/executor/tree/e1c4f014c89c3f27648fd77c728311b6a2767819).

## Persistent private storage

The launcher sets `EXECUTOR_DATA_DIR=$HOME/.local/share/executor`,
`EXECUTOR_KEY_STORAGE=file` and `EXECUTOR_PORT=4312`. This is upstream's
supported file keystore. The directory is owned by the current user with mode
0700; `keys.json` contains the API and encryption keys with mode 0600. Preserve
the complete data directory, installation metadata and matching keys together.
Never run two Executors against that data directory. Do not delete or rotate
keys as part of troubleshooting; losing the encryption key loses access to
stored encrypted data.

`executor_mcp.py --write-auth-header` writes a private mode-0600
`tunnel-auth-header` file in that directory. The normal tunnel launcher loads
its complete bearer into `EXECUTOR_AUTH_HEADER` without printing it. The
tracked YAML uses `Authorization: env:EXECUTOR_AUTH_HEADER`. Control-plane
credentials use their existing environment reference. Neither credentials nor
the tunnel ID enter the normal launcher's command arguments.

beta.8 prints a secret browser pairing URL during headless startup. Always use
`launch-executor.zsh`, which removes pairing-link lines before foreground output.
Do not enable shell tracing or raw HTTP logging. No credentials are stored in
this repository. Existing shell credentials and tunnel registration are retained.

## Herdr panes

Pane 1 uses the Action Server owner's existing foreground command. That service
must expose `http://127.0.0.1:8088/mcp`. This task does not start or alter it.

Pane 2:

```zsh
/home/kdlocpanda/second_brain/Resources/codex-memory-lab/mcp-tunnel-kit/launch-executor.zsh
```

Executor's MCP endpoint is `http://127.0.0.1:4312/mcp`, requires its bearer and
listens only on numeric loopback. Wait for its ready message before registration.

In the checkout, once the Action Server is available:

```zsh
.venv/bin/python executor_mcp.py --register-codex
.venv/bin/python executor_mcp.py --probe
```

Registration uses beta.8's supported custom MCP import endpoint,
`POST /dashboard/api/apps/import`, with a public, unauthenticated loopback
upstream. It creates the ordinary generated app named **Codex**, namespace
`codex`. Executor's own bearer stays inside the Python HTTP client. The helper
first initializes/discovers the Action Server and refuses to import it while
offline. A private `codex-integration.json` records the returned app ID and URL;
subsequent runs look up dashboard owner `local` and retain that registration.
An existing unrecognized `codex` app
requires inspection instead of an automatic overwrite.

The probe verifies exactly `execute`, `resume` and `skills` externally, then
runs `tools.search` for the `codex` namespace and its thread/target operations.
It calls only `tools.codex.list_targets({})`. If upstream's generated app pauses
for approval, the helper accepts only that exact app/tool/empty input using
Executor's `resume`. It never resumes a native Codex thread or dispatches a worker.
It checks both execution success and the native MCP result, and prints counts
without thread contents or raw failures.

Pane 3, in the shell that already exports the existing tunnel credentials:

```zsh
/home/kdlocpanda/second_brain/Resources/codex-memory-lab/mcp-tunnel-kit/launch-executor-tunnel.zsh --check
/home/kdlocpanda/second_brain/Resources/codex-memory-lab/mcp-tunnel-kit/launch-executor-tunnel.zsh
```

`--check` validates local files/settings and prepares the private header; it
makes no MCP request or tunnel connection. Normal launch refuses if any local
`tunnel-client` is already running. Stop the old client with Ctrl-C in its own
pane and wait for exit before launching this path. Do not use `pkill` or stop
shared services. This local guard does not detect a competing client on another
machine; the operator must ensure the existing tunnel ID is available there too.

Stop each foreground pane with Ctrl-C. No detached service is intended.

## Inactive direct break-glass

After the normal tunnel has stopped, use the same private tunnel variables:

```zsh
CODEX_MCP_URL=http://127.0.0.1:8088/mcp /home/kdlocpanda/second_brain/Resources/codex-memory-lab/mcp-tunnel-kit/launch-codex.zsh
```

This bypasses Executor and advertises the full Action Server catalog. It remains
inactive unless explicitly launched. Both launchers refuse an existing local
client. It uses the same tunnel, not a second
registration. The stateless demo and historical systemd templates are not part
of the normal path.

## Verification and remaining gate

Use the checkout's pinned `requirements.txt` environment. Tests additionally
require `pytest==9.1.1` in that virtual environment, as installed by README's
setup command. No Python packages are installed into the host OS.

```zsh
.venv/bin/python executor_mcp.py --health
./launch-executor-tunnel.zsh --check
.venv/bin/python -m pytest -q
zsh -n launch-executor.zsh launch-executor-tunnel.zsh launch-codex.zsh
git diff --check
```

The tests use isolated loopback MCP/control-plane fixtures and dummy credentials.
They prove actual tunnel-client static-header forwarding and compact catalog
preservation; they do not prove the production tunnel or ChatGPT consumer.
`tunnel-client doctor --config config/executor-tunnel.yaml` validates the normal
config when the private header and tunnel variables are already exported.
Its reachability check can pass with HTTP 401; `--health` separately proves
authenticated Executor MCP initialization.

At setup, port 8088 was offline and left under its owner's control. Executor authenticated MCP,
compact external discovery, private storage and tunnel configuration were checked.
Registration and the read-only Codex call remain pending until its owner starts
the Action Server. No production tunnel was started with an incomplete chain.
After those local gates pass, start only one production tunnel client briefly
and verify its readiness. Reconnect ChatGPT/Jarvis and verify fresh compact
discovery and the harmless read through Executor before claiming remote
end-to-end acceptance.

## Tracked changes

| Path | Change |
| --- | --- |
| `launch-executor.zsh` | Pinned foreground server, private data directory, pairing-link filter |
| `launch-executor-tunnel.zsh` | Normal authenticated tunnel launcher and offline check |
| `config/executor-tunnel.yaml` | Main channel to Executor with private bearer reference |
| `executor_mcp.py` | Private header preparation, ownership check, registration and read-only acceptance |
| `launch-codex.zsh` | Inactive direct 8088 path, competing-client guard, tunnel ID kept out of argv |
| `codex_mcp_check.py` | Direct checker defaults to standalone port 8088 |
| `config/launcher.example.zsh` | Executor settings and labeled break-glass URL |
| `README.md` | Normal topology and foreground pane commands before direct fallback |
| `docs/EXECUTOR.md` | Setup, storage, commands, acceptance and pending gates |
| `docs/EXTENDING.md` | Executor discovery is normal; direct catalog instructions are fallback |
| `docs/STANDALONE_CODEX.md` | Historical handoff/service notes labeled inactive |
| `CODEX_TEST.md` | Historical evidence distinguished from the current chain |
| `tests/test_executor_local.py` | Pairing secrecy, repeat registration and renamed-client detection |
| `tests/test_executor_tunnel.py` | Actual binary/header/compact forwarding and competing-path tests |
| `tests/test_launchers.py` | Updated break-glass port, helper bundle and private-ID assertions |
