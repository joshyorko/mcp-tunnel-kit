# Issue 27 owner provider-binding repair

Use one immutable incident authorization tied to host apply 38637912059. Never rerun host deployment or modify Executor/CAS/tunnel.

1. Reproduce stale provider-config hash and inspect sanitized scoped/legacy records. Done: only provider config differs; scoped record retired, legacy reconciled_scoped, other bindings match.
2. Add tests for a one-time protected plan/apply. Reject scope/policy/credential/receipt/other-binding/CAS mapping drift, active or unknown records, changed provider checksum, replay and failed restart. Verify byte-exact rollback and unchanged capability and records.
3. Add fixed incident manifest, isolated repair module and protected workflow/controller operations. Plan is read-only. Apply takes deployment and admission locks, saves private before snapshot, updates one binding, restarts only the Devsy bridge to refresh its existing fingerprint, authenticates actual scope.load and bridge health, and writes a sanitized receipt. Do not sync runtime source or change approved CLI pin.
4. Run focused/full tests, review immutable diff, require hosted checks and normal protected PR merge. Dispatch protected check then exactly one repair with the qualified idle native tuple.
5. Verify owner status and zero workspaces; create exactly one fresh scoped request only when allowed. Poll durable status and verify pod resources, node, native runtime and auth/access instructions. Stop on ambiguous identity or failure.
