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

The current bridge implementation in `scripts/codex_memoryd_mcp.py` uses only
the Python standard library; it does not import FastMCP or install a new
dependency. Its stateless Streamable HTTP endpoint is tested through the
existing tunnel-kit MCP client. Keep that transport contract covered if the
implementation changes.

The adapter must expose only the three read-only memory tools, fix the
profile/workspace boundary server-side, and treat retrieved memory as
untrusted evidence. Keep administrative HTTP routes private and do not add a
second tunnel client.

## Managed service wiring

`compose.memoryd.yaml` is an opt-in overlay; it is not part of the default
control-plane startup. It runs the released database service on host loopback
and the bridge on the existing control-plane bridge gateway, with no published
ports. Set `CODEX_MEMORYD_BIND` and the matching `CODEX_MEMORYD_URL` only after
checking the selected loopback port is free. The deployment runner renders the
same two services as separate Kamal accessories and checks capacity before
source sync or accessory boot. Use `bin/kamal accessory deploy memoryd` for
that managed operation.

`bin/kamal accessory details memoryd` inspects the accessories;
`bin/kamal accessory stop memoryd` stops the bridge before the database and
retains the named `codex-memoryd-data` volume. Starting it again requires both
accessories and that volume to exist. The existing Executor identity and tunnel
are checked before and after deployment.

## Portable transfer

Use codex-memoryd's v1 portable bundle format for instance replication; never
copy the SQLite database. The released v0.1.0 exporter caps a selection at
5,000 root memories, so larger corpora must be split into explicit `--record-id`
chunks. Preview each export and each destination import, verify the bundle
integrity and source/destination scopes, then apply with that import preview's
plan ID. Transfer the bundle bytes over the pinned SSH path and verify their
SHA-256 before import. Preserve the source instance ID and bundle manifest
digests; a repeated import should plan zero creates and exact identity reuse.

## Activation envelope

Keep the planned memory limits at 256 MiB for codex-memoryd and 128 MiB for the
adapter, with CPU limits of 0.5 and 0.25 respectively. The managed deployment
preflight reads live `MemAvailable` and requires at least 1.5 GiB immediately
before activation; this leaves more than a 1 GiB reserve after both services
reach their memory limits. A failed gate reports the current RAM floor and
performs no source sync or accessory boot. Recheck the existing Executor, CAS,
schema proxy, tunnel, and Fizzy containers before and after activation.
