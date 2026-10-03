# Upstream tool ownership and rediscovery

The normal tunnel now reaches Executor. Import the Action Server as app `codex`
and discover its tools with `tools.search` through Executor's compact MCP
surface. See [Executor registration and acceptance](EXECUTOR.md). The direct
catalog procedure below applies only to the inactive break-glass launcher.

The Action Server at `CODEX_MCP_URL` owns the tool catalog. `launch-codex.zsh`
binds the existing `main` channel with native `--mcp.server-url` HTTP forwarding.
`codex_mcp_check.py` is a readiness checker, not a registration seam. The
former Friday registration and generic-message bridge have been retired.

Add or change Codex tools in the owning Action Server package, with its own
schemas, permission checks and exact workstream guards. No such package change
is part of this kit. MemoryD is not implemented, and this kit does not silently
combine tool catalogs or introduce a second gateway.

For a catalog change, complete the local probe and fixture tests first. During
an operator-controlled handoff, stop only the affected foreground tunnel client
and launch the updated version on the same ID. Leave shared upstream services
running unless their owner separately requires an update.

Reconnect the consumer, establish fresh MCP initialization and `tools/list`,
follow pagination if present, and inspect names, input/output schemas and
annotations. Then make one read-only `discover_threads` call using target
`local` and an exact known worktree CWD. Do not resume, start, steer or interrupt
threads to validate discovery. Endpoint continuity alone does not prove the
consumer's cached catalog refreshed.

This kit does not claim hot registration or guaranteed automatic consumer
refresh. See README's reconnect procedure and CODEX_TEST.md for the distinction
between local readiness and end-to-end verification.

Protocol reference:
https://modelcontextprotocol.io/specification/2025-11-25/server/tools
