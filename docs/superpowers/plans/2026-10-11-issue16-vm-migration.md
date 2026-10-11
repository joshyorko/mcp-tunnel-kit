# Issue 16 VM migration execution plan

Goal: move the existing control plane to kamal-test-deploy, preserving identity and rollback.
Spec: https://github.com/joshyorko/mcp-tunnel-kit/issues/16

Source map: compose.yaml defines private services and mounts; scripts/compose_control.py owns lifecycle/bootstrap; scripts/devsy_bridge.py owns optional provider bridge. CAS src/boundary.py and src/codex_rpc.py own logical targets and SSH RPC; scripts/container_health.py owns container readiness.

- [x] Read full issue, inspect source/status, preserve dirty main, launch two Luna medium workers.
- [ ] Verify pinned Dakota-to-VM and VM-to-Dakota SSH, VM resources/networks/workloads, bounded provider access.
- [x] Lane A: test existing CAS SSH and decouple service health from worker availability where required.
- [x] Lane B: implement private portable Compose, remote target mounts, staging and tunnel-only supported lifecycle; run regression tests.
- [ ] Integrate tested branches, publish PRs/checkpoints, merge per repository policy.
- [ ] Back up essential Executor keys/data, secrets, CAS target/ownership state; verify integrity privately.
- [ ] Stage VM without tunnel; prove catalog, exact native thread read, qualified Devsy read, target-offline service health.
- [ ] Verify independent operator/rollback; stop only Dakota tunnel and confirm exit, start one VM tunnel, prove end-to-end continuity.
- [ ] Only after acceptance stop old Compose control plane; otherwise stop VM tunnel and restore Dakota through supported lifecycle.
- [ ] Record immutable SHAs, image digests, sanitized receipts and precise remaining blockers in issue 16.

Constraints: no native daemon changes, key rotation, public listeners, dual tunnel, broad credentials or cluster privileges, unrelated service changes, or historical debug-log migration. Root alone owns live credentials and cutover. Existing dirty checkout stays untouched.

Preflight outcome: blocked on refused reverse SSH, absent VM SSH identity/trust and missing configured ROR context. CAS image/provider CI is additionally blocked on an unavailable existing ROR image pin. Source is retained for review; no merge, backup, staging or cutover acceptance is claimed.
