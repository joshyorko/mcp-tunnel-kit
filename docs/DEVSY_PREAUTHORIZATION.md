# Owner-scoped Devsy creation without browser approval

Status: owner-approved scope implemented and activated through the authenticated API, with no browser approval or browser credential form. Scoped create/start use a private owner profile; ordinary mutations retain their approvals. No real workspace was created during activation or tests.

## Verified approval source

The bridge assigns mutation hints by exact tool name, not by upstream claims: scripts/devsy_bridge.py:8 and normalize_tool. workspace_create, workspace_start, deletion, arbitrary exec and provider mutations remain destructive. The managed generated app is account-free and applies always() to destructiveHint: scripts/compose_control.py:487, devsy_app_source. The running app source matches this generator, with no explicit router timeout.

Pinned Executor beta.8 source, revision e1c4f014c89c3f27648fd77c728311b6a2767819, defines never() as an approved decision while retaining product access checks: packages/apps/src/approval.ts:19. The policy context contains toolName, decoded toolInput and signal, not authenticated user identity: packages/apps/src/contracts/approval.ts:10. Therefore an input predicate or source-IP check alone cannot prove an owner-only caller. BridgeHandler.allowed currently checks network, Host and Origin, not a credential.

## Supported non-browser operator path

Existing organization-authorized API credentials support app deployment, personal profile creation, credential connection creation and credential submission. Profiles derive owner/subject from authenticated membership; callers cannot supply them. Sources: apps/hosted/server/src/contracts/app-management.ts:14, profiles.ts:47, accounts.ts:181 and accounts.ts:200. Account setup returns a browser form URL, but the authenticated submit API does not require using that form. Use a locally generated capability, not a secret requested in chat or embedded in generated source.

Creating or editing an MCP connection is a different API and requires browser authentication: apps/hosted/server/src/contracts/mcp-connections.ts:64; implementation/auth.ts:128 explicitly rejects Authorization on browser-only endpoints. Reuse the existing authenticated owner connection. Do not forge cookies, change elicitation mode to auto-accept, or introduce a browser prerequisite. If that connection's existing grant excludes the private profile or new tools, activation must stop rather than bypass grant checks.

## Proposed exact authority

Create a separate profile-backed Devsy Worker integration. Its credential is private to the authenticated owner's subject, encrypted by Executor and independently checked by the bridge. Calls without that credential, non-owner profiles, expired/revoked scopes and direct unauthenticated bridge calls must fail before any Devsy process is started. Source IP is an additional network restriction, not identity.

The live bridge currently also exposes raw mutations to private-network peers without credential verification. Authenticating only the new scoped tool would leave that alternate path. Activation must require an owner-bound service credential for all bridge mutations, with raw calls retaining their approval policy. The existing Devsy integration may therefore need a private owner profile too; retain app identity and confirm the connected owner's profile routing in disposable acceptance. Do not deploy a never() exemption while this backplane remains unauthenticated.

The proposed grant permits only the following operations:

- workspace_create_scoped: accept one durable creation intent and return its operation ID promptly.
- workspace_start_scoped: resume only a workspace UID previously proved and recorded for this scope, without force or recreation.
- workspace_status_scoped and creation receipt: read only that scope's operation/resource status.

Each mutation retains readOnlyHint=false and destructiveHint=true. The generated privileged app alone explicitly uses never() for the two scoped mutation names after credential binding. All raw create/start/delete/exec/provider operations retain always(); unknown mutation names remain gated. Off-scope input to the privileged tools is refused, not silently promoted to general exec.

Bind authority to context default; provider kubernetes; Kubernetes context ror; namespace devsy; repository `https://github.com/joshyorko/codex-action-server.git`; source ref `refs/heads/main`; and recipe `.devcontainer/remote-worker/devcontainer.json`. Before accepting each new create, resolve `main` to one commit and fetch the recipe from that exact commit. Persist the commit and recipe hash with the job; retries, reads and starts use that saved snapshot. Freeze and revalidate provider/cluster configuration, not just its human-readable name. Namespace must already exist; cluster-wide mutations are outside the grant. Prefer namespace-restricted Kubernetes credentials and verify real provider behavior before activation.

Names must be an explicit operator-approved finite set of valid DNS labels, with a cap on active workspaces and pending creates. The protected codex-action-server workspace cannot be deleted or recreated by this repair. Approve new worker names separately rather than interpreting its present absence as permission to recreate it. New tools accept only a name from that set and a bounded request ID. They do not accept caller-selected source, recipe, provider options, namespace, force, shell command, volume mounts or cluster operations.

The owner chose a persistent scope with no automatic expiry. It remains revocable: disabling the scope or rotating its private capability denies new submissions. Explicit finite expiries, when configured, still fail closed after expiry. In-flight effects and receipts must be reconciled, not assumed undone.

## False failure and long operations

Executor commits consume-once approval state before dispatch: packages/sdk/src/implementation/tool-approvals.ts:193. Its tools.resume catches downstream execution errors and returns failed/execution-failed: packages/sdk/src/implementation/tools.ts:936. MCP then maps both failed and already-consumed to ApprovalUnavailable: packages/mcp/src/implementation/executions.ts:643. ApprovalUnavailable can therefore mean a failed execution after an accepted approval, not only a missing approval or expired session.

The default MCP client timeout is 30 seconds, configurable up to 300 seconds: packages/apps/src/contracts/mcp.ts:21. The bridge's stdio/child ceiling is 120 seconds; it ignores cancellation notifications and does not roll external effects back. Interpreter active time defaults to 5 minutes, while SDK approval TTL is 15 minutes. The reported roughly 100 seconds is not evidence of a 15-minute approval expiry. The exact timeout/failure behind apr_50fc8ee2-132c-4121-9262-d31e830d570a cannot be recovered from its outward error alone.

Devsy 1.23.0 explicitly documents that create may continue after client timeout. createWorkspace returns only after runUp finishes and then reads WorkspaceConfig: cmd/mcp/tools_workspace.go:287. Historical lifecycle and Kubernetes events independently prove f35f3 was created and started; its hook did not show completion before a later delete operation.

For the future scoped tool, decouple submission from long provisioning. Persist owner/scope, immutable input digest, name and operation ID before starting one owned background task; return accepted immediately. Poll a durable receipt. Duplicate request IDs/names return the same receipt; changed payload is refused. After interruption, reconcile authoritative metadata and provider resources, and never submit another create merely because the result is missing or a record says failed. No extra process retry or automatic deletion is permitted.

## Prepared reconciliation patch

scripts/creation_receipts.py implements private durable receipts, nonblocking per-name submission locks, exact-input conflict checks, refusal to resubmit across bridge restart, and explicit outcome_unknown. It stores no input credentials or raw upstream result. Existing named resources are observed without claiming a new creation. Ordinary receipt queries never invoke a provider. The scoped receipt uses the guarded read-only reconciliation described below. Interrupted unlocked submissions remain uncertain and cannot be replayed. An absent workspace list alone is not permission to erase a receipt.

The bridge integrates this guard into ordinary approved workspace_create and adds the read-only workspace_create_receipt tool. worker_scope.py implements credential admission, short scoped submission, an owned bounded background CLI job, durable status, and UID-fenced start. The generated owner app requires a private capability account and exempts only workspace_create_scoped/workspace_start_scoped. It does not retroactively create receipts for old approvals. Raw creation remains destructive and browser-gated. Nameless raw creates are guarded by exact input fingerprint; the privileged scope always requires a finite approved name. CLI operations outside this bridge are outside its journal.

The change is based on toolkit 884a1996d8b8d3fe4cb6ddb79089f6a931efde60 and published on fix/devsy-create-reconciliation. The canonical owning wrapper manages the deployed bridge. App identity and stock Executor are retained; only the bridge was restarted. Live scope/credential files stay private and are not committed. The checked-in JSON remains a disabled, secret-free example.

## Current inventory and target rebinding

At audit time Executor and the host CLI both list no workspace in default; Kubernetes ror/devsy has zero pods/PVCs. CAS's operator target still pins default-co-f715f and currently returns workspace_not_found. A historical replacement UID default-co-f35f3 would correctly trigger workspace_identity_changed if present. Do not loosen that check or automatically follow the name.

For an explicitly authorized rebind, read the exact existing workspace metadata and uniquely matching Ready pod; verify context/provider/source/recipe, workspace ID/UID and pod UID. Require an expected-old UID plus exact selected new UID, preserve the local target and rollback, and perform a compare-and-swap only on that operator-owned target. Recheck the pod UID and remote DEVSY_WORKSPACE_ID/UID before native access. A creation grant does not implicitly authorize this separate routing change. Current absence blocks rebinding and gives no permission to recreate the protected workspace.

## Acceptance required before permission activation

Prove signed-in owner success with zero browser elicitation, including first use; non-owner/anonymous/expired/revoked/tampered credential refusal; no bypass through direct bridge or account-free app calls; off-scope names/source/recipe/context/namespace refusal; deletion/exec/provider mutations still gated; concurrent submission and lost-response/restart reconciliation produce only one create; and CAS routing never changes without an explicit UID-bound rebind. Use disposable synthetic resources first. Do not use the protected live workspace for destructive testing.

The owner approved the finite names/resource cap/expiry, private profile/capability and scoped creation/start exemption. Activation used organization-authenticated profile/connect/submit and app-deploy APIs without a browser. No public dashboard, Tailscale or global policy disable was introduced.

The approved limits are in devsy-worker-scope.proposed.json:1: only cas-worker-01, at most one active workspace and pending create, a 20-minute bounded provisioning job, and a persistent revocable capability. codex-action-server is protected; target rebinding remains separately authorized. Scoped CLI options disable namespace creation and cluster-role binding, and select the existing namespace's default service account. Frozen provider/cluster file fingerprints refuse drift.

After account setup, discover the current owner profile with tools.search(namespace: devsy, query: scoped). Call workspace_create_scoped with name=cas-worker-01 and a bounded request_id, then poll workspace_status_scoped. While the outcome remains unknown, another request ID returns the same receipt without provisioning. The legacy account-free tool path is replaced by the private owner's profile path.

## Recover a failed scoped creation

Poll `workspace_status_scoped` or `workspace_create_receipt` through the owner profile. For an inactive failed or unknown creation, the bridge checks native Devsy inventory, lifecycle processes, native tasks, and Kubernetes resources. These checks use the approved context and a hash-bound kubeconfig. They never create, delete, or restart provider resources.

Recovery requires an existing namespace with no workloads, services, or persistent volume claims, and no retained volume belonging to that namespace. The kubectl checks emit only metadata for Secrets, ConfigMaps, roles, role bindings, and service accounts; the bridge never retains Secret data. The default service account and root CA ConfigMap are permitted. Other auxiliary objects are retained only if their creation timestamps predate a cutoff from the original operation. New receipts record admission and grant times, so a later grant renewal cannot hide leftovers. This proves retained objects were not newly created by the failed operation; it does not claim their contents were unchanged. Missing permissions, partial resources, active provisioning, configuration drift, or unreadable evidence keep admission blocked.

Legacy receipts without timestamps cannot borrow the current grant's date. They require an operator-evidenced `recovery_cutoff` on the original receipt before preexisting auxiliary objects can be excluded. Preserve the unmodified receipt under `unreconciled_receipt` and record the evidence source. This migration does not change the outcome or permit creation: the same live provider and process checks must still pass.

When absence is proven, the original operation becomes `failed` with `error_code=lifecycle_reconciled_absent` and `new_request_allowed=true`. Its original unknown receipt and diagnostics are retained. `retry_safe=false` still prohibits replaying the old request.

Only when `new_request_allowed=true`, submit one `workspace_create_scoped` call with a fresh request ID. The bridge repeats the absence checks under the admission lock before accepting it. It archives the prior receipt before recording the new operation. Every archived request ID continues to return its old receipt across restarts. Poll the new operation and verify runtime readiness separately. Recovery does not change CAS target mappings or resume parked approvals.

If a completed workspace is later deleted, status performs the same full absence proof. Confirmed absence retires the old workspace and permits a fresh request; the completed receipt remains in `retired_receipt`. A metadata or provider outage alone never retires it. Retired identities lose dynamic CAS authorization immediately.

Scoped jobs use a private temporary directory under their managed job-state directory. The supervisor removes only that directory when the job ends. They do not depend on space in the host's shared `/tmp` for Git inspection.

Each scoped job copies its hash-bound Devsy config into that private directory and disables `SSH_TUNNEL_MODE` in the copy. The provider home and operator config are unchanged. Headless provisioning must exit after readiness, not stay alive serving an inherited interactive SSH tunnel.

## Dynamic worker access

Scoped status verifies the admitted worker's source, pinned commit, recipe, cluster, and UID. The first observed UID is retained for that operation. Diagnostics accept this verified identity without changing the existing operator-pinned diagnostic target. A replacement UID, revoked scope, or changed binding is refused.

Use `workspace_diagnostics` for CPU, available memory, workspace disk, daemon, and login checks. This fixed read-only probe needs no browser approval and uses the UID-checked Kubernetes route. Capacity values are snapshots, not reserved resources. Do not use generic `workspace_exec` for this check: arbitrary command execution remains approval-gated.

The bridge publishes verified workers into a separate private `cas/dynamic-targets.json` registry. Static targets such as `local` and `devsy` are never overwritten. CAS reads the registry on each call and checks the bridge's private `/worker-authorized` endpoint for current scope authorization. Revocation or an unavailable authority blocks dynamic access while static routes remain available. Native Devsy metadata must still match every published cluster and source binding before CAS connects.

Host-network CAS requests to the configured bridge gateway use a loopback source address. The bridge's peer restriction is unchanged; other private authorities use normal routing.

New workers require no per-UID target-file edit or service restart. Enabling the registry reader requires one CAS rollout. An unknown legacy operation without a recorded UID requires evidence-based operator reconciliation before it can be registered; discovering a matching name alone never adopts it.

The pinned disposable Executor test proves API-only private profile setup, zero browser approval on first scoped creation, duplicate suppression, protected-name refusal and ordinary deletion approval. Live discovery/status verifies the activated profile without creating a worker. Real cluster provisioning and starting a stopped worker were not exercised destructively during activation.
