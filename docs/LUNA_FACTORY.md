# Luna Factory through Executor

[Issue #7](https://github.com/joshyorko/mcp-tunnel-kit/issues/7) integrates the
[canonical Luna product](https://github.com/joshyorko/plugins/pull/60). PR #9 was
merged into the old Devsy feature branch, not main. This change recovers that
checkpoint onto main and completes the operator and isolated acceptance paths.
It is rebased onto main `27939ba3312cc5f649c6af9d791ef94d192526a8`, including
its trusted-Codex approval policy.

## One runtime, two acceptance tracks

The product contract is pinned at
`joshyorko/plugins@f2c81429db651c0bfe9da7a22b3853dfb6d9c9ac`.
Its daemon owns the repository/profile allowlists, bounded authority, idempotency,
run/thread identities and SQLite history. It listens on numeric loopback at
`http://127.0.0.1:8787/mcp` and keeps its strict Host/Origin checks. The kit does
not start it, a native Codex process, a second run database, or another tunnel.

Executor beta.8 exposes only `execute`, `resume`, and `skills` at its outer MCP
endpoint. Its router retains tool metadata but does not filter app-only tools
or serve upstream MCP Apps resources. Importing the full Luna endpoint would
expose settings/refresh controls through model discovery. Therefore the foreground
`scripts/luna_bridge.py` serves a tools-only view at the verified managed gateway,
port 8090, path `/executor/mcp`:

- Read-only: `get_factory_capabilities`, `list_factory_runs`, `get_factory_run`
- Browser approval: `start_factory`, `steer_factory_run`, `cancel_factory_run`,
  `resume_factory_run`

The view forwards arguments and complete results once, preserves original IDs,
normalizes approval annotations using an explicit allowlist, rejects app-only and
unknown tools before dispatch, and strips UI links that cannot work on this route.
Executor retains content, structuredContent, isError and _meta; its legacy
result schema drops the MCP 2026 transport discriminator resultType.
Never replay an uncertain mutation: reconcile the original run, thread and
idempotency key. Decision answers must retain the current `pending_decision.id`
as `expected_decision_id`; exact retries use the same ID and message, and stale
or conflicting answers remain product errors. Existing Codex and Devsy imports
retain their identities/source. The trusted Codex app uses main's unwrapped MCP
router: its reads and controls have no redundant Executor browser gate. CAS
validation and native Codex safety remain authoritative. Devsy reads bypass
approval and its mutations remain browser-gated. Luna's mutation gates remain
unchanged. Its isolated acceptance rechecks all three policies after import and
restart.

The shared Codex bootstrap may migrate only the exact legacy generated source
on an authorized import, retaining the app ID and other source files. Read-only
verification fails closed if that migration is still needed; it never deploys.

The canonical endpoint separately keeps twelve tools, the native resource
`ui://luna-factory/workbench.html`, global/thread OpenAI entrypoints, settings and
text fallback. A supported native-app topology is a separately approved direct
registered MCP App transport mapped to that SAME loopback endpoint and history.
The ingress must authenticate its caller and present the endpoint's expected
Host/Origin. Do not weaken Luna's guards, replace the Executor registration, or
silently start another tunnel. Registration/transport configuration and real
phone/desktop deep-link and rendering acceptance require operator authorization
and remain outside these isolated tests. An Executor tool success is not UI proof.

## Trust boundary

The adapter binds only to the existing managed Compose gateway. It accepts that
subnet and loopback peers, exact Host, and absent or exact same-origin Origin.
Callers cannot choose an upstream or forward authentication/cookies/headers.
Upstream traffic uses the fixed numeric-loopback endpoint and MCP 2026 headers.
No repository, native socket, credentials or host home are mounted into Executor.

Private addressing is not authentication. Every admitted host/network peer can
invoke the model-tool adapter with the product owner's authority. Browser approval
protects the Executor route, not a direct trusted-peer call. Activate only on a
trusted host and dedicated managed network. This change is code and tests; it
does not grant live network access or permission to modify production services.

## Initial installation: explicitly approved operator sequence

Prerequisites: existing healthy Compose stack, canonical Luna daemon already
running with the operator's reviewed configuration, pinned product build/UI,
and the existing private Executor PAT and integration receipt directory. Never
replace secrets with examples or run a second tunnel client.

1. Persist `compose.luna.yaml` in the operator's existing `COMPOSE_FILE` setting,
   usually in the private `.env` used by this checkout. If no setting exists, use
   `COMPOSE_FILE=compose.yaml:compose.luna.yaml`. If it already includes Devsy,
   local-build, or other reviewed overlays, retain them in their current order
   and append `compose.luna.yaml` once. Do not replace the rest of `.env` or its
   secrets. Retain this setting for future `control-plane-up`/`down` operations;
   a temporary pair of `-f` arguments would lose Luna's allowlist on the next up.
   Inspect `docker compose config` locally using that persisted file list.
   The overlay only adds gateway port 8090 to Executor's private-origin allowlist
   and passes the managed gateway into the one-shot operator helper. It does not
   alter Codex, Devsy, volumes, or tunnel identity. Review output privately.
2. Applying a new Executor origin allowlist requires recreating Executor ONLY,
   because environment changes do not apply to a running container. Settle all
   outstanding browser approvals first: beta.8 cannot resume them after a process
   restart, even if their IDs were recorded. With explicit restart approval:

   ```sh
   docker compose up -d --no-deps --wait executor
   ```

   Do not use full `control-plane-up`, `down`, `--build`, or restart CAS/native Codex
   merely to add Luna. No automatic restart happens in the import helper.
3. In a separate foreground host terminal, start the tools-only adapter:

   ```sh
   python3 scripts/luna_bridge.py --upstream http://127.0.0.1:8787/mcp
   ```

   It validates the managed network before binding and probes the canonical
   product catalog. Ctrl-C in this terminal stops only this adapter.
4. With explicit authorization to add the Luna Executor app, import once:

   ```sh
   docker compose run --rm --no-deps \
     --entrypoint python3 app-ready /opt/tunnel-kit/compose_control.py luna-import
   ```

   This creates only a missing `LunaFactory` app and writes only its private
   `luna-integration.json` receipt. Repeating it retains that identity. A changed
   organization, URL, source, or duplicate name fails closed. It never redeploys
   source or consumes pending approvals, and status/list reads make no inference.
5. Run read-only verification whenever needed:

   ```sh
   docker compose run --rm --no-deps \
     --entrypoint python3 app-ready /opt/tunnel-kit/compose_control.py luna-verify
   ```

   This never imports an app or writes receipts. It checks the direct seven-tool
   view, retained source/identity, outer MCP contract, scoped search, capabilities
   and one bounded run-list read. To verify a known original run, add
   `-e LUNA_VERIFY_RUN_ID=<existing-run-id>` after `--no-deps`. No start, steer,
   cancel, resume, or native inference is used for operator verification.

## Bounded results

The adapter accepts up to 32 MiB from the canonical runtime so a valid 100-run
history page is not constrained by the operator probe client's 2 MiB ceiling.
It preserves compact UTF-8 in both directions; Unicode is not expanded into
ASCII escape sequences that would exceed the product's 64 KiB input limit.

Executor's outer codemode return/log output has a separate 64 KiB limit. Process
large tool results inside codemode and return only the fields needed. For example:

```js
const response = await tools.lunafactory.list_factory_runs({limit: 100});
return response.structuredContent.runs.slice(0, 5).map(run => ({
  id: run.id, state: run.state, delta: run.delta.slice(0, 240)
}));
```

The operator verifier returns fixed-size validation receipts rather than whole
runs. Hosted acceptance checks all 100 seeded large records inside Executor and
returns a small count/content-integrity result. This proves the large upstream
value is readable without claiming the host can display arbitrary-size output.

## Refresh, upgrade, restart

- Catalog refresh: keep the same imported app and URL. Run `luna-verify`. Stock
  beta.8's supported router cache uses five-minute freshness and retained metadata
  during refresh; after a catalog change, allow expiration then repeat read-only
  discovery. This helper does not claim to force cache invalidation or bypass it.
  Do not reimport/replace apps or restart the stack just to refresh discovery.
- Product upgrade: the product operator owns stopping/upgrading/restarting the
  SAME daemon/config/database and checking its canonical UI. Keep port/URL and
  receipt identity. Rerun compiled contract verification and `luna-verify`; allow
  the Executor catalog freshness window. Only restart the adapter if its code or
  upstream setting changed. Never retry an uncertain dispatched mutation.
- Adapter restart: Ctrl-C only its own foreground terminal, wait for exit, then
  rerun its command. It has no durable run state. Original history remains in Luna.
- Full-stack restart: use the existing Compose runbook only when independently
  required and approved, using the same persisted `COMPOSE_FILE` including the
  Luna overlay and any existing Devsy/local overlays. Settle pending requests BEFORE restarting
  Executor. beta.8 stores suspended executions in memory; hosted acceptance proves
  that a process restart retains app identities/deployments but makes old browser
  reviews and resume calls unavailable. Recording a request ID does not preserve
  its continuation. Preserve the volume, receipts, PAT and original request/session
  evidence. If an interruption already happened, reconcile the original Luna run
  before seeking a new explicit decision. Never automatically rerun execute.
  Durable suspended execution across an Executor restart is unsupported by this
  pinned version and remains an upstream acceptance limitation, not a kit claim.
- Removal: stopping the adapter makes Luna unavailable without touching other
  apps. Removing an import or access allowlist is a separate operator action.

## Reproducible evidence

```sh
python -m pytest -q -rs
python tests/luna_product_contract.py --binary /path/to/luna-factoryd \
  --ui /path/to/bundled/index.html
# Linux Docker, disposable Executor and synthetic owner/token only:
python tests/executor_luna_live.py --binary /path/to/luna-factoryd \
  --ui /path/to/bundled/index.html
```

The contract probe runs the real compiled product against a temporary database,
no repository/profile authority and a deliberately absent native executable. It
checks canonical resources/entrypoints, all twelve tools, the seven-tool view,
exact read/error results and zero status inference. Hosted CI builds the pinned
product and invokes pinned Executor beta.8 from a disposable bridged container,
through a narrowly bound private gateway adapter, to that loopback-only daemon. Four mutations are approved only in
that disposable fixture and must reach the actual product's authorization/run
checks exactly once; no factory or model inference is started. This is integration
proof, not an authorized live owner/child lifecycle test.

Local full-suite baseline: 118 passed, 14 tunnel-client skips, two existing
AF_UNIX sandbox permission failures in `test_target_prepare_rewrites_only_local_socket_and_preserves_original`
and `test_prepare_preserves_selected_existing_runtime_and_receipts`. Docker is absent on this
VM. Hosted exact-head results, rather than this local limitation, govern Docker
acceptance. Keep the PR draft until its review and required acceptance finish.

## Pinned upstream references

- [MCP router](https://github.com/UsefulSoftwareCo/executor/blob/e1c4f014c89c3f27648fd77c728311b6a2767819/packages/apps/src/implementation/mcp-catalog.ts)
- [Outer MCP server](https://github.com/UsefulSoftwareCo/executor/blob/e1c4f014c89c3f27648fd77c728311b6a2767819/packages/mcp/src/implementation/server.ts)
- [Create-only import/source API](https://github.com/UsefulSoftwareCo/executor/blob/e1c4f014c89c3f27648fd77c728311b6a2767819/apps/hosted/server/src/contracts/apps.ts)
- [Catalog freshness](https://github.com/UsefulSoftwareCo/executor/blob/e1c4f014c89c3f27648fd77c728311b6a2767819/packages/apps/src/implementation/catalog-cache.ts)
- [Codemode output budget](https://github.com/UsefulSoftwareCo/executor/blob/e1c4f014c89c3f27648fd77c728311b6a2767819/packages/mcp/src/contracts/execute.ts)
- [In-memory suspended executions](https://github.com/UsefulSoftwareCo/executor/blob/e1c4f014c89c3f27648fd77c728311b6a2767819/packages/mcp/src/implementation/executions.ts)
- [Browser approval contract](https://github.com/UsefulSoftwareCo/executor/blob/e1c4f014c89c3f27648fd77c728311b6a2767819/e2e/tests/pat-mcp.spec.ts)
