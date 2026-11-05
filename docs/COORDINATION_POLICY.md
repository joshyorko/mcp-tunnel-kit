# Managed CAS coordination policy

CAS's relay requires an operator-owned directional pair policy. Its JSON shape
and native safety contract are documented in
[CAS coordination](https://github.com/joshyorko/codex-action-server/blob/main/docs/COORDINATION.md).
This controller installs and mounts that file; it never creates threads,
starts turns, changes native features or sends messages.

The default has no coordination environment setting or mount. Opt in with the
optional owner-profile field `vm.cas_coordination_policy_dir`, or the protected
workflow's `cas_coordination_policy_dir` input. The input overlays only that
field in memory without rewriting the existing profile or credentials. Choose
a private directory outside the checkout and writable CAS data, normally
`<vm.state_dir>/cas-coordination`.

## Install and enable

1. Prepare a local JSON policy under a mode-0700 directory, owned by the
   current operator and mode 0600 or 0400. Start with an empty `pairs` list
   if native root IDs have not been collected yet.
2. From the owning checkout with its existing private `.env.kamal.local`, run
   `bin/kamal coordination-policy install --directory /absolute/vm/policy-directory --file /absolute/local/policy.json`.
   The VM directory's existing parent must be UID 1000 and mode 0700. The
   pinned, locked controller creates the selected directory if missing and
   atomically installs only `policy.json`. It prints a digest and pair count,
   never the policy body, and changes no service or credential.
3. Run the protected **Deploy VM control plane** workflow on main with the
   reviewed CAS promotion and the same `cas_coordination_policy_dir` input.
   All existing image-pair, provenance, identity and rollback gates apply.
   A same-image CAS promotion is only a no-op if policy selection also matches.

CAS runs as UID:GID 1000:1000. The directory mounts read-only at
`/run/cas-coordination`; only this opt-in adds
`CODEX_ACTION_COORDINATION_POLICY=/run/cas-coordination/policy.json`.
Preflight requires a UID-1000 mode-0700 directory and a regular, non-symlink
UID-1000 policy file, mode 0600 or 0400, at most 64 KiB. Duplicate JSON keys,
malformed shapes, extra peer fields, cross-target pairs, symlink directories
and more than 64 directional pairs are rejected.

Use the same install command for later changes. The read-only directory mount
exposes atomic file replacement to a running CAS without a restart. Do not
replace the directory or edit its file in place. Invalid input leaves the old
policy intact; reconcile an unknown transfer result before repeating it.

## Later promotions

Successful generations record the directory. Later CAS promotions must retain
it in the profile or supply it again through the protected input. Omission or
a different directory fails closed instead of silently disabling the relay.
There is no generic environment, mount or disable override. Automatic rollback
renders the prior generation's policy selection and image pins; an explicitly
approved full-generation rollback may restore a pre-opt-in generation.

Policy contents stay operator-owned and out of receipts, logs and source.
Local fixtures prove transfer/rendering behavior only. Live relay acceptance
still needs two disposable independent roots and actual read/acknowledgement,
with duplicate-effect and negative identity/state checks.
