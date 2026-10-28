# Native target lifecycle implementation plan

**Goal:** Automate central CAS deregistration and logical rename, including legacy local, while preserving native Codex and device connectivity.

**Design:** Astra recommends preserving the complete target entry on rename, using configurable exact native acceptance tuples, and journaling the before/after tuples so rollback verifies the original name. Removal changes the central target map. Existing transport artifacts remain operator-owned and are retained. Kamal remains the authority; legacy Compose setup is outside this change.

TASK | DEPENDS ON | OWNER | STATE | ACCEPTANCE
--- | --- | --- | --- | ---
Transactions | none | Luna transactions | DONE | idempotent remove/rename, collisions, rollback, pending journal
CLI and gates | none | Luna CLI/gates | DONE | no endpoint setup on lifecycle, named exact-read checks retained
Controller | transaction API | Luna controller | DONE | pre/post/rollback tuples, CAS-only refresh, inventory checks
Actions/docs | CLI contract | parent | DONE | protected dispatch and safe literal inputs
Integration/review | all | parent + fresh Luna | VERIFY | focused/full tests, review, PR checks, merge

## Contracts

- Device CLI: --operation register|remove|rename, --name, --new-name for rename, --native-target plus exact cwd/thread. Default registration remains compatible.
- Lifecycle native tuple selects the post-change acceptance target. A rename of that target derives the old name for pre-change validation. Removal must retain another acceptance target.
- Registration exposes lifecycle_plan/lifecycle_apply and pending actions. Controller queries matching pending journal before rendering, restores journaled files, and verifies journaled pre-change identity.
- Lifecycle operations never enroll/log out Tailscale, inspect local Codex sockets, create/remove local SSH keys, or alter native services.
- Target removal preserves SSH config and host pins because current registrations do not establish deletion ownership. Report retained assets explicitly.
- Native exact cwd/thread, source authority, inactive flags and completed idle turn validation remain unchanged.

## Verification

Baseline onboarding tests: 57 passing. Add transaction fixtures and controller rollback tests for local→dakota-nvidia, removal of CPU target, and retries. Test Actions argument construction with shell syntax in input. Use clean worktree and original repo venv pytest entry point. Do not rename or remove production registrations during implementation; use read-only live inventory if useful. Preserve the five pre-existing dirty files.

## Verification evidence

- Full suite with pinned Ruby and CI-style pytest entry point: 885 passed, 15 optional-tool skips, 76 subtests.
- Final controller/workflow follow-up: 33 passed, including six additional inventory variants.
- Real in-process transaction/controller handshake tests exercise remove and rename.
- Workflow YAML parsed and embedded Bash syntax checked.
- Fresh Luna acceptance review passed; unrelated dynamic worker targets intentionally coexist with the static map.
- No production targets, native services, tailnet membership, or CAS image pins were changed. A separate agent is preparing the Action Server 1.0.4 CAS image.
