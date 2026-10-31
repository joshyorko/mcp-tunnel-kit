# Qualified CAS promotion handoff

The scheduled promotion lane consumes the v1 receipt uploaded by the CAS publisher workflow:

- Resolve CAS `main` to a full commit SHA and find its exact `container.yml` push run.
- Require that run to be successful, on `main`, and bound to the same source SHA.
- Read the run's artifact named `cas-qualified-release-<source-sha>-<run-id>`, containing `qualified-release.json`.
- Check artifact identity and workflow metadata, hash its downloaded archive against GitHub's artifact digest, and validate the receipt's canonical checksum.
- Fetch `ci/codex_qualification/native_methods.json` and the referenced native qualification fixture at the receipt's source SHA. Require complete catalog coverage and match the native version, upstream asset, binary, fixture digest, and method evidence to those source-pinned inputs.

Downloading a CAS workflow artifact requires a cross-repository credential with read-only `Actions` access to `joshyorko/codex-action-server`. The promotion workflow reads it from the `CAS_ARTIFACTS_READ_TOKEN` secret. The protected deploy workflow exposes it only for the explicit `cas` operation, then revalidates the publisher artifact before any CAS mutation. Both workflows fail closed when it is unavailable. This checkout has no such credential or CAS App installation; none was created for this change.

The receipt's own `receipt_sha256` covers canonical compact JSON without that field. It detects accidental edits; it is not treated as provenance. Provenance comes from the successful publisher run on the current main SHA, the run-bound Actions artifact and the independently verified OCI image digest/platform/revision.

The CAS/schema-proxy pair is promoted together in one draft PR. The production deploy path repeats the receipt, catalog, workflow artifact and image checks before the existing environment approval gate. The deployment does not update native Codex daemons.

## Producer availability

The current consumer reports no candidate if the successful current-main publisher run has no qualified receipt artifact, which is the producer's expected outcome when qualification is partial or withheld. It blocks on an expired, malformed, or inconsistent artifact. CAS PR #26 currently reports only 1/58 methods compatible and 57 withheld, so it cannot generate a promotion PR. End-to-end promotion also requires a read-only cross-repository Actions credential.
