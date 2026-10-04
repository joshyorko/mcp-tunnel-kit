# Luna Factory integration draft

Issue [#7](https://github.com/joshyorko/mcp-tunnel-kit/issues/7) is separate from
[the Luna product](https://github.com/joshyorko/plugins/pull/60). This draft stacks
on kit PR #6 at `d1d055da2e6100a97ffc3a8a96e90267fc646414`. It does not merge,
deploy, restart services, register an app with OpenAI, or start a second tunnel.

## Contract agreed with the product owner

The pinned product is `joshyorko/plugins@9609821752804f11799d04880cd2c7fb7e129333`.
Its existing daemon serves `http://127.0.0.1:8787/mcp`, with strict Host and Origin
checks. MCP 2026 requests use `server/discover`, request metadata and the
`MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` headers. Legacy initialization
also exists. The original loopback endpoint exposes twelve tools, the
`ui://luna-factory/workbench.html` MCP Apps resource, OpenAI global/thread
entrypoints, and app-only settings/refresh controls. The checked-in test snapshot
was obtained from the compiled product, not reconstructed tool schemas.

All run/thread IDs, SQLite history, repository/profile authorization, bounded
limits, claims and idempotency stay in that one product runtime. This kit never
launches a factory or native Codex, creates a second run database, or copies
credentials. Start, steer, cancel and resume forward their original arguments
once. An uncertain dispatch must be reconciled against the original run and
idempotency key; the adapter never replays it.

## Tools and native app are different acceptance tracks

Executor beta.8's outer MCP endpoint exposes `execute`, `resume` and `skills`.
It does not forward the product's MCP Apps resources or global/thread
entrypoints. Tool execution does not prove that a native sidebar works.

The stock MCP router retains `_meta` in full descriptions but removes it from
summaries. It has no app-only visibility filter. Importing the full Luna endpoint
would therefore expose UI/settings controls through model discovery. The
foreground `scripts/luna_bridge.py` adapter presents only the seven model tools
at the verified private gateway, port 8090, `/executor/mcp`:

- Reads: `list_factory_runs`, `get_factory_run`, `get_factory_capabilities`
- Browser approval required: `start_factory`, `steer_factory_run`,
  `cancel_factory_run`, `resume_factory_run`

The adapter rejects app-only and unknown names even when called directly. It
normalizes safety annotations from this explicit name allowlist, preserves
schemas/results, and omits UI links from its tools-only catalog. It does not
serve a second full-MCP route. The canonical product endpoint remains unchanged
and keeps all resources, metadata, settings, sessions and direct app calls.

Native access needs an operator-approved direct registered-app route to the same
loopback runtime. Registration ID, authenticated transport mapping, deep links,
actual ChatGPT rendering and phone behavior remain unproved. Do not replace the
existing Executor tunnel, add a second tunnel, or create another factory to make
this appear complete. No such registration is performed by this draft.

## Trust boundary

The adapter listens only on the verified existing managed Compose gateway.
Only loopback peers and peers on that managed subnet are admitted. Host must
match that exact listener; a supplied Origin must match it too. Requests cannot
select an arbitrary upstream or forward caller authorization, cookies or headers.
The fixed upstream uses numeric loopback and the product's own unchanged guard.

Private addressing is not authentication. Every admitted host/network peer can
call the model tool adapter with the product owner's authority. Executor browser
approval protects the Executor route, not a direct trusted-peer call. App-only
visibility is a UI/discovery rule, not an authentication boundary. Do not activate
this on an untrusted host or shared network. Live activation and any persistent
access change require separate operator approval.

## Draft verification status

Local focused tests currently cover import identity retention, catalog safety,
app-only/unknown rejection, Host/Origin/path/framing guards, exact one-time
forwarding, and preserved synthetic run/thread IDs. The compiled product's
catalog snapshot was read without inference.

Pinned Executor container acceptance and the operator commands are being added
in this draft. The VM has no Docker binary. Baseline full-suite result is 90
passed, 14 missing tunnel-client skips, and two existing AF_UNIX tests blocked by
the VM sandbox. Those failures also precede this integration.

The product's real owner/child execution and native routing proof remain open.
The VM's inherited native home is read-only; no alternate credentials or native
profile were substituted. Keep both PRs draft.

## Pinned upstream evidence

- [MCP router](https://github.com/UsefulSoftwareCo/executor/blob/e1c4f014c89c3f27648fd77c728311b6a2767819/packages/apps/src/implementation/mcp-catalog.ts)
- [Outer MCP server](https://github.com/UsefulSoftwareCo/executor/blob/e1c4f014c89c3f27648fd77c728311b6a2767819/packages/mcp/src/implementation/server.ts)
- [Import API](https://github.com/UsefulSoftwareCo/executor/blob/e1c4f014c89c3f27648fd77c728311b6a2767819/apps/hosted/server/src/contracts/apps.ts)
- [Catalog cache](https://github.com/UsefulSoftwareCo/executor/blob/e1c4f014c89c3f27648fd77c728311b6a2767819/packages/apps/src/implementation/catalog-cache.ts)
