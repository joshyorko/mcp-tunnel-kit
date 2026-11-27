# Opt-in private MCP app bridge

This repository candidate installs no service, registers no app, and changes no
existing deployment, ingress, network policy or trust configuration. It supports
one fixed private upstream per instance with separate inbound and outbound bearer
credentials and an explicit owner-approved read-tool allowlist.

## Supported boundary

`scripts/private_app_bridge.py:create_app` supports stateless JSON MCP over
HTTP. The upstream must support POST `/mcp`, JSON-RPC 2.0, JSON responses,
initialization and tools discovery/calls without an MCP session ID. Redirects,
SSE and upstream sessions fail closed. TLS verification remains enabled for
HTTPS. Plain HTTP requires an owner-approved encrypted private route.

The destination must be a literal RFC1918 or tailnet IP at `/mcp`, without
credentials, queries or fragments. No caller can select a destination. Upstream
requests use only the configured outbound bearer, Accept, Content-Type and the
caller's MCP protocol version; cookies and other caller headers are not copied.
The allowlist restricts discovery and calls but does not replace upstream auth.

The opt-in foreground launcher binds only the configured RFC1918 /24 gateway
and unprivileged port. Middleware verifies the actual local socket, actual TCP
peer inside that /24 and exact single Host header. Browser Origin and forwarded
identity headers are rejected. Config and credential files require absolute
paths, operator ownership, regular mode-0600 files, no symlinks or hardlinks.
The inbound credential loads at startup; its rotation requires a controlled
restart. The outbound credential file is reread and checked immediately before
each upstream request, so atomic issuer renewals need no listener restart.
Missing or unsafe replacements fail closed without using a cached token.

The config JSON requires `subnet`, `gateway`, `port`, `endpoint`, `read_tools`,
`inbound_token_file`, and `upstream_token_file`. Supply real values only through
approved private configuration, never Git, PR text or logs. After activation
approval, run in the pinned repository Python environment:

```sh
python scripts/private_app_bridge.py --config /approved/private/config.json
```

Access logs, parser logs and startup banners are disabled locally; failures use
fixed diagnostics. No health endpoint claims upstream readiness. Verify
initialization/discovery with approved synthetic fixtures. SIGTERM stops the
foreground service; no existing application or registration is modified.

## Activation handoff

1. Each service owner verifies its live deployed revision, healthy private
   endpoint, exact dialect and owner-approved read-tool allowlist.
2. The resource-server owner confirms verifier readiness and whether an existing
   authorized issuer already matches the trusted key and exact issuer, audience,
   subject, expiry and read scope. Only that issuer's owner can confirm scoped
   issuance, renewal and revocation capability. Do not mint credentials here.
3. If trust is absent or mismatched, stay disabled. Selecting an issuer/key or
   changing verifier trust requires separate owner authorization. Network access,
   a tunnel key or a cookie cannot substitute for app-specific authorization.
4. Verify the private route from the real consumer runtime. An owner then
   installs the reviewed listener with private config/credential files and
   verifies restart/rotation. Never reuse an occupied existing app port.
5. Review only the exact additional consumer origins required for the new
   listeners. The existing Compose consumer uses an exact HTTP-origin allowlist;
   this candidate does not extend it. No wildcard trust or global policy change.
6. Register separate authenticated apps only after all live gates pass. Use
   synthetic reads and verify missing, expired and wrong-app auth rejection.

Operational endpoints, private deployment identities, issuer values and live
service evidence belong in the owners' private handoff, not this public runbook.
This candidate proves neither live routing nor installed consumer acceptance.

Use `config/private-app-bridge.example.json` and
`config/private-app-bridge.service.example` only as operator templates. Each app
needs a distinct protected credential pair, reviewed read allowlist, listener
port, provider identity and Executor account selection. Missing protected files
must keep its unit stopped. Do not substitute placeholder tokens or give one
app the other app's account. Store Executor-side credentials only through its
secure account connection flow, with a provider restricted to the exact bridge
host and port. Never put tokens into app source or tool arguments.

Prepare exact consumer admissions as a separately reviewable deployment delta:
the existing private bridge interface, consumer source, gateway destination and
only that authenticated listener's TCP port. Preserve the default deny policy
and every existing rule. Add only that listener's exact HTTP origin to Executor's
origin allowlist; verify the required restart with the deployment owner first.
Never admit raw upstream forwarding ports. Before installing admissions, qualify
the listener with synthetic credentials and a synthetic upstream: no auth/wrong
app auth rejects, wrong Host/Origin/peer rejects, discovery filters to the exact
read set, a safe synthetic read succeeds and denied calls never reach upstream.
This credential-free preparation is not live app readiness or registration.

Existing Tailscale connectivity can provide the encrypted transport without
reviving a coding service. Peer visibility or SSH reachability alone does not
expose an app bound to remote loopback. Where an approved SSH endpoint already
exists, the minimal candidate is a separately reviewed, pinned SSH local forward
from one exact managed-gateway port to the remote loopback app port over the
existing tailnet. Before installing it, the transport owner must verify host-key
pinning, noninteractive authentication and forwarding permission, and approve
the exact local bind and remote destination. This adapter can then use that fixed
private gateway endpoint with independent app credentials. No forward is started
by this PR. Do not substitute Funnel, public listeners, wildcard forwarding,
re-enrollment or broad ACL changes. Tailnet DNS and HTTPS certificate-name
requirements must also be verified rather than inferred from peer status.

## Synthetic verification

Run with the repository-pinned `aiohttp==3.14.4`:

```sh
python -m unittest discover -s tests -p test_private_app_bridge.py -v
```

Tests cover initialization, notifications, allowed reads, filtered
discovery, unauthorized/write rejection before upstream access, separate auth,
cookie/header isolation, redirect/error/SSE refusal, size/time limits, private
file loading, foreground socket binding and real TCP negative peer/local-bind/
Host/forwarded-header checks. Duplicate Host is sent on the wire because HTTP
clients can normalize it. Address policy alone is substituted for loopback tests;
production policy independently rejects loopback, public/wildcard/non-gateway
binds, broad subnets and privileged ports. Live gateway binding is not claimed.
Atomic outbound-token replacement and missing/unsafe replacement refusal are
also verified without real credentials or an issuer.
