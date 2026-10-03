# Standalone Codex Action Server

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
