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

### Off-by-default public discovery candidate

The working candidate adds only GET routes for
`/.well-known/oauth-protected-resource/mcp` and
`/.well-known/oauth-authorization-server`.
Enablement requires all three explicit settings:
`EXECUTOR_SCHEMA_OAUTH_ISSUER`, `EXECUTOR_SCHEMA_OAUTH_RESOURCE` and
`EXECUTOR_SCHEMA_OAUTH_HOST`, plus
`EXECUTOR_SCHEMA_BETA79_LEGACY_SURFACE=1`. Partial configuration or enabling
metadata without the three-tool filter fails startup. No Compose or live
configuration was changed.

The issuer/resource are exact owner-pinned identities, not values learned from
caller headers. Resource queries accept only a single explicit browser mode and
an optional exact connection identifier. GET query spelling, Host and any Origin
are checked before fixed-upstream access. Unexpected paths/methods, duplicate
Host, credentials, cookies and forwarding headers are refused. HTTP identity
URLs are allowed only for loopback fixtures; remote identities require HTTPS.

Public metadata is fetched without caller credentials, cookies or Origin. The
candidate enforces bounded JSON, no redirects/compression, duplicate-field
rejection, exact resource/issuer/server identities and fixed beta.79 OAuth
endpoint paths. Unverified signed metadata and endpoint aliases are refused.
It neither rewrites metadata nor forwards Set-Cookie or Location. Unknown routes,
including authorization, registration and token requests, remain closed. The
existing execute/resume/skills filter, MCP authentication and approval forwarding
remain unchanged.

Fresh pinned beta.79 public metadata passed through the candidate with no owner
setup, user/app credentials or consent. The pinned native client reached ready
status against a loopback fake control plane; its fixture issuer origin was
explicitly allowed only in that disposable client. The metadata issuer was
`http://127.0.0.1:4312/api/auth`; the device endpoint was verified as
`/api/auth/oauth2/device-authorization`. Six new negative/positive tests and the
existing nine transport/session plus five three-tool tests passed. Independent
working-diff review raised two findings (filter coupling and masked negative
controls), both corrected and tested. This is not merged or deployed acceptance.

The next production step is review/integration of this disabled candidate and
owner verification of the exact issuer/resource/Host and existing private route.
Enablement applies only to qualified beta.79: the strict filter expects its
six-tool upstream and must not be enabled against healthy beta.12.
The current Compose contract fixes the issuer/browser base to VM loopback and
publishes only loopback port 4312; the tunnel targets the schema proxy and
injects a static PAT. Installed native-client help establishes discovery and
static-header support, not browser/consent relay or protected token renewal.
Full Dot OAuth still requires a separately qualified supported route to the
advertised issuer and authorization/token endpoints, protected client refresh,
and same-scope consent. Do not copy fixture origin allowances into deployment,
add a generic proxy, rewrite issuer identity, create a live connection, or request
consent based solely on public discovery readiness.

The route owner must prove exact issuer reachability from the client and owner
browser, connection/browser query propagation, redirects, cookies, PKCE and
registration/token/refresh handling over the existing approved private transport.
No supported complete route is established by this candidate. Rollback retains
the old PAT/config and original beta.12 image/volume, stops the candidate before
restoring the old tunnel, and never opens migrated state with beta.12.
