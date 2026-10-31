# Qualified CAS promotion handoff

The scheduled promotion lane consumes one v1 receipt from `joshyorko/codex-action-server`:

- Source file: `ci/codex_qualification/qualified-release.json` on CAS `main`.
- The consumer resolves `main` to a full commit SHA and fetches the file only at that SHA.
- The receipt's `publication.run_url` must be a successful `container.yml` run on `main` at the qualified source revision.
- That publisher run must contain one Actions artifact named `qualified-cas-release-v1` with the file `qualified-release.json`.
- The consumer checks the artifact metadata against the run, hashes the downloaded archive against GitHub's artifact digest, and requires the embedded receipt to equal the pinned source file.
- The consumer fetches `ci/codex_qualification/native_methods.json` at the receipt's exact source revision and requires the receipt matrix to cover that catalog exactly.

Downloading a CAS workflow artifact requires a cross-repository credential with read-only `Actions` access to `joshyorko/codex-action-server`. The scheduled workflow reads it from the `CAS_ARTIFACTS_READ_TOKEN` secret and fails closed when it is unavailable. This checkout has no such credential or CAS App installation; none was created for this change.

The receipt's own `receipt_sha256` covers canonical compact JSON without that field. It detects accidental edits; it is not treated as provenance. Provenance comes from the pinned CAS source and publisher commits, successful workflow records, the authenticated run artifact and the independently verified OCI image digest/platform/revision.

The CAS/schema-proxy pair is promoted together in one draft PR. The production deploy path repeats the receipt, catalog, workflow artifact and image checks before the existing environment approval gate. The deployment does not update native Codex daemons.

## Producer availability

The current consumer blocks if either the main receipt or the publisher artifact is missing, expired, malformed, or inconsistent. CAS PR #26 currently contains neither output, so its draft is not a qualified release and cannot generate a promotion PR. The producer must implement this contract and an owner must authorize the read-only cross-repository Actions credential before end-to-end qualification can pass.
