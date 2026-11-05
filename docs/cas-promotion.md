# Qualified CAS promotion handoff

The scheduled promotion lane consumes the v1 receipt uploaded by the CAS publisher workflow:

- Resolve CAS `main` to a full commit SHA and find its exact `container.yml` push run.
- Require that run to be successful, on `main`, and bound to the same source SHA.
- Read the run's artifact named `cas-qualified-release-<source-sha>-<run-id>`, containing `qualified-release.json`.
- Check artifact identity and workflow metadata, hash its downloaded archive against GitHub's artifact digest, and validate the receipt's canonical checksum.
- Fetch `ci/codex_qualification/native_methods.json` and the referenced native qualification fixture at the receipt's source SHA. Require complete catalog coverage and match the native version, upstream asset, binary, fixture digest, and method evidence to those source-pinned inputs.

Public CAS artifact downloads use the existing workflow `GITHUB_TOKEN`, with repository `Actions` read permission. An approved `CAS_ARTIFACTS_READ_TOKEN` secret can override that default; no new credential or GitHub App installation is required. The protected deploy workflow exposes the token only for the explicit `cas` operation, then revalidates the publisher artifact before any CAS mutation. Downloads remain bounded and strip authorization before following the approved signed CDN redirect. Outside Actions, provide an approved read credential through `CAS_ARTIFACTS_READ_TOKEN`.

Workflow metadata and image ancestry checks use that same read token. Metadata requests are restricted to the CAS API, and authorization is not forwarded on redirects. Refusals report the HTTP status and an exhausted rate limit without upstream response bodies or credential details.

Read-only acceptance: unauthenticated artifact download returned HTTP 401. The tunnel-kit workflow's own `GITHUB_TOKEN` downloaded public CAS artifact `13437550029` with HTTP 302 → 200, 1,651 bytes, and a SHA-256 equal to its public artifact metadata (`611d773b072d46ccfbcf8fe44c540b9ba788152fea3a684ef6942cda083e4d60`). The temporary probe was removed after [run 42086790208](https://github.com/joshyorko/mcp-tunnel-kit/actions/runs/42086790208/job/127453953249). This proves public-artifact access, not qualification or publication of a CAS release receipt.

The receipt's own `receipt_sha256` covers canonical compact JSON without that field. It detects accidental edits; it is not treated as provenance. Provenance comes from the successful publisher run on the current main SHA, the run-bound Actions artifact and the independently verified OCI image digest/platform/revision.

The CAS/schema-proxy pair is promoted together in one draft PR. The production deploy path repeats the receipt, catalog, workflow artifact and image checks before the existing environment approval gate. The deployment does not update native Codex daemons.

`native-reconcile` independently checks each registered Dakota CLI/daemon over the pinned SSH endpoint and probes only `read_server_diagnostics` through Executor/CAS. Each RPC result must identify the requested target; failures remain per-device and the report omits raw diagnostic data. This probe does not wake, steer, or interrupt a thread.

## Producer availability

The consumer reports no candidate if the successful current-main publisher run has no qualified receipt artifact, which is the producer's expected outcome when qualification is partial or withheld. It blocks on an expired, malformed, or inconsistent artifact. Existing approvals for exposed experimental methods do not qualify the entire consumed-method catalog. A live promotion requires the CAS producer to publish the complete qualified receipt from trusted main.
