# codex-memoryd MCP integration contract

Tracking issue: [#56](https://github.com/joshyorko/mcp-tunnel-kit/issues/56).
This document records the released runtime constraints for the isolated
codex-memoryd deployment and its read-only Executor app.

## Released runtime

The latest stable release checked for this integration is `v0.1.0`. Its
immutable GHCR image index is
`ghcr.io/joshyorko/codex-memoryd@sha256:70465d5250f693d15408fe904d30e3035360d8a46ac6f1caea8c3660eac09996`;
the Linux AMD64 image manifest is
`sha256:be1b593b6e541de84b990e376231f30f0d6088e15c4060f91af2f3ebd2dab975`.
The release image runs as UID 10001, persists `/data/memory.db`, and defaults
to `0.0.0.0:8787`.

The v0.1.0 HTTP router permits protected `/v1` routes only when its effective
bind is loopback or `declare_loopback_publish` asserts an external loopback
boundary (`src/server.rs`, `src/config.rs`). A health check on `/healthz` does
not prove that `/v1/status`, `/v1/recall`, or `/v1/search` is reachable. Keep
the database API private, do not publish its port, and verify the actual read
routes through the selected private network boundary.

The release exposes MCP over stdio. Its default tool catalog contains only
`memory_status`, `memory_recall`, and `memory_search`; write tools require the
explicit `--write_tools` flag (`src/mcp.rs`). Executor's imported-app flow
requires an MCP URL, so a network transport adapter is needed unless a
supported HTTP MCP transport is added upstream.

## Adapter runtime requirement

The currently pinned CAS image is
`ghcr.io/joshyorko/codex-action-server@sha256:bda7ef55e9d31574aefbd650ec38bfbe993b5adbbfffc15a49a7ca83e6ba26ca`.
Its Python runtime has an `mcp` distribution but does not provide
`mcp.server.fastmcp`. Do not install packages ad hoc on the VM. Any adapter
must use APIs verified in that pinned image or add a reproducible, pinned
dependency and deployment artifact to this repository.

The adapter must expose only the three read-only memory tools, fix the
profile/workspace boundary server-side, and treat retrieved memory as
untrusted evidence. Keep administrative HTTP routes private and do not add a
second tunnel client.

## Activation envelope

The current VM baseline has six vCPUs and 1,226,960 kB `MemAvailable`, with no
swap. Keep the planned memory limits at 256 MiB for codex-memoryd and 128 MiB
for the adapter, with CPU limits of 0.5 and 0.25 respectively. Require at
least 1.5 GiB `MemAvailable` immediately before activation; this preserves a
1 GiB reserve after both services reach their memory limits. Recheck the
existing Executor, CAS, schema proxy, tunnel, and Fizzy containers before and
after any activation.
