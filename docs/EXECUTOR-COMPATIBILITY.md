# Executor beta.79 compatibility gate

The official beta.79 MCP surface has six tools. Existing clients of this
repository permit exactly `execute`, `resume`, and `skills`. The strict
`verify_compact` assertion remains unchanged.

The schema adapter has an opt-in `EXECUTOR_SCHEMA_BETA79_LEGACY_SURFACE=1`
boundary for isolated qualification. It requires the exact official six-tool
upstream catalog, returns only the three permitted tools, and rejects direct
calls to `call`, `describe`, `search`, or unknown tools before upstream access.
Malformed/batched requests and unexpected catalogs fail closed. Existing
authentication, sessions, approval payloads and resume-schema handling remain
unchanged. The option is off by default; this source change neither deploys an
adapter nor selects an upgraded image.

## Account and client migration proof

Counts or unchanged account IDs are insufficient. The official migrations
convert installation/profile targets into account targets; they can select the
first account for a single-account requirement, copy apps, change shared-account
ownership, delete unusable links and rewrite connection/grant targets.

For every established permitted profile, retain and compare the exact app,
subject, requirement, provider, cardinality and ordered selected-account tuple
against the migrated user/app requirement metadata. Include profile-to-app-copy
mappings and compare all allowed app/tool/event and selected-account sets.
Reject missing, added, ambiguous or differently owned capabilities. Keep all
evidence and original encrypted state on the owner-managed host.

The documented beta.79 tools use `tools.<app>.<tool>`. There is no documented
legacy `tools.<app>.profiles[profileId]` alias. This repository's owner Devsy
integration still uses that namespace and the `/profiles` API. Do not globally
replace a legacy profile path with the default namespace: it may select a
different account. Existing clients require a reviewed, explicit single-valued
binding to the proven app/subject/account tuple, or a supported client migration
that demonstrably preserves their identity and scope. Until that proof passes,
keep the old server live; the surface filter alone does not authorize rollout.

Use an encrypted stopped-volume backup restored into an isolated clone for
qualification. Retain the untouched original volume and exact prior image/config
for rollback. No new job-app activation or LinkedIn login belongs in this gate.

Official immutable-release references:

- [MCP interface](https://executor.sh/docs/mcp)
- [Profile targets and account links](https://github.com/UsefulSoftwareCo/executor/blob/executor%402.0.0-beta.79/apps/hosted/server/src/implementation/app-account-schema.ts)
- [Personal account migration](https://github.com/UsefulSoftwareCo/executor/blob/executor%402.0.0-beta.79/apps/hosted/server/src/implementation/personal-account-schema.ts)
