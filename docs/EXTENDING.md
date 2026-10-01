# MemoryD seam and MCP tool rediscovery

`friday_mcp_adapter.py` retains the `build_server` registration seam: it calls
`register_friday_tools` for the existing Friday module, with a comment reserving
an adjacent future module. There is no MemoryD implementation, loader, service,
router, or configuration added in this import.

A later MemoryD module can register its approved tools with the same MCP server.
Keep its configuration/authority separate from Friday's and preserve all three
Friday tool names, the fixed profile/session, run-ID registry restrictions, and
upstream error semantics. Add module/discovery tests before enabling new tools;
that work is outside this publication.

## Rediscovery after adding a tool

1. Run the offline suite and explicitly check the expected discovery schemas.
2. Plan a handoff for the specific foreground tunnel/adapter process. Do not
   start a competing tunnel client or restart the shared Hermes gateway.
3. During the authorized handoff, restart the affected adapter/tunnel so startup
   registration uses the new code.
4. Establish a fresh MCP session, initialize it, and issue `tools/list` against
   the actual tunnel. Follow pagination if a catalog grows. Verify names and
   input schemas; endpoint continuity does not prove catalog freshness.
5. Refresh or reconnect a consuming app that retained old tool metadata, and
   verify its rediscovered tools before attempting the new call.

The protocol provides `tools/list` and, when supported/declared, a
`notifications/tools/list_changed` notification. This kit does not claim runtime
hot registration or guaranteed automatic client refresh. Its offline discovery
check is not evidence that a particular remote consumer refreshed its cache.

Protocol reference:
https://modelcontextprotocol.io/specification/2025-11-25/server/tools
