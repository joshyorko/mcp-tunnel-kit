# Issue 27 owner provider-binding repair

Use one immutable incident authorization tied to host apply 38637912059. Never rerun host deployment or modify Executor/CAS/tunnel.

1. Reproduce stale provider-config hash and inspect sanitized scoped/legacy records. Done: only provider config differs; scoped record retired, legacy reconciled_scoped, other bindings match.
2. Add tests for a one-time protected plan/apply. Reject scope/policy/credential/receipt/other-binding/CAS mapping drift, active or unknown records, changed provider checksum, replay and failed restart. Verify byte-exact rollback and unchanged capability and records.
3. Add fixed incident manifest, isolated repair module and protected workflow/controller operations. Plan is read-only. Apply takes deployment and admission locks, saves private before snapshot, updates one binding, restarts only the Devsy bridge to refresh its existing fingerprint, authenticates actual scope.load and bridge health, and writes a sanitized receipt. Do not sync runtime source or change approved CLI pin.
4. Run focused/full tests, review immutable diff, require hosted checks and normal protected PR merge. Dispatch protected check then exactly one repair with the qualified idle native tuple.
5. Verify owner status and zero workspaces; create exactly one fresh scoped request only when allowed. Poll durable status and verify pod resources, node, native runtime and auth/access instructions. Stop on ambiguous identity or failure.

Protected check 38640083695 refused historical operator snapshots before mutation. Correct classification must pin the two exact snapshot/archive digest pairs, validate canonical receipt/identity cross-references, and repeat live full absence proof without editing records. After successful repair, hand the single scoped create back to ChatGPT.

Post-rebind owner API responds but retirement fails because the real bridge PATH cannot resolve the private pinned kubectl. Exact native read-only comparison proves that changing only PATH resolves absence verification. Add one fixed, hash-bound systemd drop-in through a protected check/apply with bridge-only stop/start, snapshot, rollback, native scope/actual-process-environment proof and unchanged control-plane/record checks. Never rerun host apply. Notify ChatGPT when fresh owner status allows its one temporary create; retain authorized create/test/delete cleanup requirements.
