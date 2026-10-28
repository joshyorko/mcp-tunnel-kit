# Native device onboarding implementation plan

**Goal:** One repeatable device-local command prepares restricted SSH and registers the device with existing CAS. The same central transaction is available to protected GitHub Actions.

**Approved design:** Astra recommendation accepted by Josh on 2026-10-28. Reuse existing daemon, pinned deployment SSH, private profiles, deployment lock and CAS-only Kamal lifecycle. Preserve existing targets and credentials. Browser login and privileged installation remain explicit interactive steps.

- [x] Device setup: tests first; detect enrollment, binaries/socket and prerequisites; adopt or create owned SSH endpoint; activate user service; receipt.
- [x] Central transaction: tests first; validate descriptor and identity, probe endpoint, preserve unrelated configuration, journal atomic replacements and conditional rollback.
- [x] Controller: trusted profile bootstrap, shared local/CI registration, original native acceptance gate, pinned CAS-only refresh and live verification.
- [ ] Delivery: protected workflow operation, concise setup docs, focused/full tests, independent review, PR and merge after checks.

## Verification

Exercise retries, existing-asset adoption, conflicting names/host keys, unavailable dependencies, interrupted writes, rollback conflicts and bind-mount refresh. Verify the existing CPU target using a no-change adoption run. Do not restart native Codex or unrelated accessories. Keep user-owned dirty files out of this branch.

## Validation recorded

- Focused onboarding/workflow checks: 62 passed, 7 subtests.
- Full suite: 845 passed, 16 optional-tool skips, 76 subtests. Direct pinned-Ruby follow-up: 5 passed.
- Workflow YAML parsed with bundled Ruby/Psych; embedded Bash syntax checked.
- Live CPU adoption through bin/onboard-native: changed=false; CAS and Executor PASS.
- Independent review found no remaining release blockers. Changed registrations are covered by transaction tests; live CAS recreation and fresh-device enrollment remain operator acceptance tests.
