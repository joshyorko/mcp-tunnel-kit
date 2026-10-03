# Standalone Codex Action Server

Historical direct-path handoff and supervision notes follow. The current
foreground default is [Tunnel → Executor → Action Server](EXECUTOR.md).
`launch-codex.zsh` is inactive break-glass; do not install the service templates
for the current foreground setup or run both tunnel paths concurrently.

`joshyorko/codex-action-server` owns typed controls and logical target resolution.
This repo owns secure HTTP exposure. No adapter, router, thread registry, or new
MCP tool translation is needed: launch-codex.zsh already uses the tunnel client's
native HTTP upstream support. Keep credentials in the operator shell, not files
committed here or command arguments.

Start the independently installed server alongside the current service on8088.
Then use this kit's exact pinned Python environment:

```sh
export CODEX_MCP_URL=http://127.0.0.1:8088/mcp
.venv/bin/python codex_mcp_check.py --probe --target local --cwd /absolute/local/worktree --require-thread
.venv/bin/python codex_mcp_check.py --probe --target devsy --cwd /absolute/remote/worktree --require-thread
```

These are logical targets configured on the server. The check forwards the same
logical name and rejects responses from a different target. It never resolves
SSH hosts, starts services, writes threads or prints thread contents. --require-thread
makes an empty discovery page fail instead of implying an exact-read proof.

Only after both probes pass, stop the old foreground tunnel-client with Ctrl-C,
then run `./launch-codex.zsh` from this same shell. Preserve the existing control
plane tunnel ID/key. Never run competing clients with the same ID.

Refresh/reconnect the ChatGPT app if the tool catalog is stale. Verify list_targets,
inspect_target, read_server_diagnostics, discover_threads and read_thread for devsy.
The external connection.target must remain the logical name, not a generated host.
Pass a client-generated request_id to dispatch methods and retain it before sending.
After uncertainty use read_dispatch_receipt; never create another thread blindly.

Rollback: stop only the new tunnel-client, set CODEX_MCP_URL back to the prior8087
endpoint, and launch the known working version. Do not restart native Codex/Devsy
or interrupt user threads. A local fixture pass is not hosted ChatGPT acceptance.

## Supervised blue tunnel

`deploy/codex-mcp-blue-tunnel.service` is an optional, uninstalled user-unit
candidate. It requires the standalone `codex-action-server.service`, uses an
explicit 8088 URL, and keeps the old 8087 tunnel independent. Configure literal
paths and the existing **blue** credentials locally using
`deploy/codex-blue.env.example`; never put credentials in Git or chat. The launch
preflight checks the pinned MCP and httpx imports/versions offline before starting
any tunnel. It does not prove upstream health.

Follow the standalone repository's `docs/SUPERVISION.md` for the staged activation
and read-only acceptance sequence. Installation, credential-file setup, service
start/enable/restart, and old-path retirement require operator approval. No such
operation runs as part of this PR or its tests.
