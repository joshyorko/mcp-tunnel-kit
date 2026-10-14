# Issue 27 AMD64 Host Bootstrap Implementation Plan

> **For agentic workers:** Use `superpowers:executing-plans` to implement this plan task-by-task. This work has one owner; do not delegate or fan out.

**Goal:** Permit the protected host bootstrap to install the pinned tap-managed Devsy CLI on Linux AMD64 or ARM64, while verifying both architecture-specific release checksums.

**Architecture:** Normalize Linux machine aliases to the formula's `x86_64` or `aarch64` artifact keys. Keep Homebrew host-native and validate both checksums against the exact pinned tap formula; leave the ARM64 Pi runner, prebuilt image flow, ROR worker selector, provider resources, and protected deployment path unchanged.

**Tech Stack:** Python 3, JSON policy, pytest, protected GitHub Actions/Kamal workflow.

**Spec:** GitHub issue #27, “Operator-approved follow-up: AMD64 VM bootstrap repair and one ROR worker” (2026-10-14).

## Global Constraints

- `pi5-01` remains ARM64 and orchestration-only; do not build images there.
- `kamal-test-deploy` remains Linux AMD64 and pulls prebuilt AMD64 GHCR images.
- Install the Devsy CLI natively on the destination VM; keep private state, provider, and systemd ownership unchanged.
- Keep Devsy workers on ROR Kubernetes in `devsy`; do not remove the worker selector or schedule on control-plane/etcd.
- Use the protected GitHub Actions/Kamal path only after source, cluster, identity, approval, and rollback gates pass.
- Bring up at most one requested workspace; do not run coding tasks in it or delete it after readiness.

## Review Focus

- Linux architecture aliases resolve only to the matching pinned artifact; unsupported OS/architecture fails before commands.
- The exact pinned formula version and both architecture checksums are verified.
- Wrong formula or artifact digests fail closed before bootstrap mutation.
- ARM64 Pi orchestration, prebuilt image pulls, and protected deployment ownership remain unchanged.
- ROR selector, resource policy, private kubeconfig, and control-plane scheduling boundary remain intact.
- Homebrew invocation preserves the pinned prefix symlink while rejecting executable paths or resolved targets outside that prefix.

---

### Task 1: Pin both Linux host artifacts

**Files:**
- Modify: `config/devsy-vm-bootstrap.json`
- Modify: `scripts/devsy_vm_bootstrap.py`
- Test: `tests/test_devsy_vm_bootstrap.py`

**Interfaces:**
- Consume the exact AMD64 and ARM64 hashes in the existing pinned `joshyorko/tools/devsy` formula.
- Keep artifact-policy keys canonical as `x86_64` and `aarch64`; accept Linux aliases `amd64` and `arm64`.

- [x] Add tests for Linux AMD64 and ARM64 positives, alias normalization, unsupported platform negatives, and AMD64 formula-digest mismatch.
- [x] Run the focused tests and confirm the AMD64-platform and wrong-digest cases fail for the expected reasons.
- [x] Normalize the host architecture, accept Linux x86_64/AMD64 and aarch64/arm64, and verify both formula checksum blocks.
- [x] Run the focused bootstrap suite and static/credential checks.
- [x] Commit and push the reviewable WIP; open an immediate draft PR linked with `Refs #27`; post its URL, SHA, checks, blockers, and next milestone on issue #27.

### Task 2: Preserve the pinned Homebrew launcher path

**Files:**
- Modify: `scripts/devsy_vm_bootstrap.py`
- Test: `tests/test_devsy_vm_bootstrap.py`

- [x] Add `test_brew_path_preserves_trusted_launcher_symlink` and `test_brew_path_rejects_symlinks_outside_pinned_prefix` for an inside-prefix launcher and both symlink escape directions.
- [x] Run the focused tests; confirm all three cases fail against the current `.resolve()` behavior.
- [x] Return the absolute invocation path without dereferencing it, and require both that path and its resolved target to remain inside the pinned Homebrew prefix.
- [x] Run the full bootstrap test file; 34 tests pass.
- [x] Run staged diff, JSON, credential-like literal, and host-private-path checks.
- [ ] Push a follow-up draft PR and post its URL/SHA/results on issue #27.
- [ ] Run the repository suite and required review/CI; merge through the normal PR path and post the result to issue #27.

### Task 3: Qualify the ROR worker gate and delivery

**Files:**
- Read-only: ROR cluster and provider inventory
- If safe: existing protected workflow and GitHub issue/PR records

- [ ] Read actual node readiness, roles, labels, taints, allocatable/used CPU and memory, namespace quota/policy, and provider authority without exposing credentials.
- [ ] Keep apply and worker provisioning stopped unless a qualified worker node, effective resource limits, identity, rollback, and required environment approvals are verified.
- [ ] Complete repository checks/review and merge under branch protections; use only protected `devsy-check`/`devsy-apply` when every gate passes.
- [ ] If a qualified ROR worker exists, create exactly one owner-authorized workspace, verify Ready and actual surfaced access instructions, then stop. Otherwise record the exact capacity/authority blocker on issue #27.
