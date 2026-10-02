# Codex tunnel validation

## Local evidence, 2026-10-02

The running `http://127.0.0.1:8087/mcp` initialized as Action Server with MCP
protocol `2025-11-25`. Live discovery returned 20 actual Codex tools. A bounded
`discover_threads` call with target `local`, this checkout's exact CWD and limit
1 succeeded. Its matching thread was read with `include_turns=false`; contents
were not logged. No thread was started, resumed, steered, interrupted or changed.
No Action Server, Codex app-server or production tunnel client was launched.

All 15 repository tests passed with the installed tunnel-client, including all
five native forwarding cases without skips. Both launchers passed zsh syntax
checks and offline preflight; Python source/tests parsed and Git's whitespace
check passed. The local probe passed again after the Codex file renames.

The installed tunnel-client's `run --help` exposes native HTTP mapping via
`--mcp.server-url`. The launcher uses that path directly. There is no forwarding
adapter that re-registers or changes the upstream contracts.

## Reproduce

Install the pinned requirements into the checkout `.venv`, use the trusted
installed tunnel-client, then run the checks documented in README's
"Verify before the handoff" section.

The suite covers:

- Offline preflight and argument rejection, without contacting a control plane.
- Native HTTP launch with the existing ID and an environment key reference,
  without a Hermes profile file, profile key or stdio adapter.
- URL rejection without echoing URL credentials.
- SDK v2 local initialization, discovery and metadata-only thread reads.
- Read-query failures without dumping upstream responses or continuing to read.
- Actual tunnel-client forwarding through a fixture control plane to a fixture
  MCP endpoint, with production credentials/configuration excluded.
- Catalog fidelity, including future tool names, input/output schemas,
  annotations and metadata; control-plane credentials do not reach upstream MCP.
- JSON and SSE structured results, content blocks and metadata.
- Unchanged CWD guard failures and exact target/CWD/thread/turn arguments.
- JSON-RPC errors and HTTP permission denials, without retrying tool execution.

Fixture servers listen only on ephemeral loopback ports. The fixture binary uses
`tunnel_00000000000000000000000000000000` against that fake control plane only.
It never registers that ID or connects to a production tunnel. Without an
installed tunnel-client, the native integration cases are explicitly skipped;
a skipped run is not native-forwarding evidence.

## Remaining live gate

The active old foreground client was left running. The operator must stop only
that client, launch the pushed Codex-backed version, and reconnect ChatGPT to the
same tunnel. Verify fresh initialization/catalog metadata and a read-only
`discover_threads` query from ChatGPT before claiming end-to-end acceptance.
Local checks do not prove production credential acceptance or refreshed app
metadata. The old Friday bridge's historical validation does not apply to this
Codex path.
