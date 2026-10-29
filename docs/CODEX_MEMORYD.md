# codex-memoryd MCP integration contract

Tracking issue: [#56](https://github.com/joshyorko/mcp-tunnel-kit/issues/56).
This document records the released runtime constraints for the isolated
codex-memoryd deployment and its read-only Executor app.

## Released runtime

The latest stable release checked for this integration is `v0.1.0`. Its
immutable GHCR image index is
`ghcr.io/joshyorko/codex-memoryd@sha256:70465d5250f693d15408fe904d30e3035360d8a46ac6f1caea8c3660eac09996`;
the Linux AMD64 image manifest is
`sha256:be1b593b6e541de84b990e376231f30f0d6088e15c4060f91af2f3ebd2dab975`.
The release image runs as UID 10001, persists `/data/memory.db`, and defaults
to `0.0.0.0:8787`.

The v0.1.0 HTTP router permits protected `/v1` routes only when its effective
bind is loopback or `declare_loopback_publish` asserts an external loopback
boundary (`src/server.rs`, `src/config.rs`). A health check on `/healthz` does
not prove that `/v1/status`, `/v1/recall`, or `/v1/search` is reachable. Keep
the database API private, do not publish its port, and verify the actual read
routes through the selected private network boundary.

The release exposes MCP over stdio. Its default tool catalog contains only
`memory_status`, `memory_recall`, and `memory_search`; write tools require the
explicit `--write_tools` flag (`src/mcp.rs`). Executor's imported-app flow
requires an MCP URL, so a network transport adapter is needed unless a
supported HTTP MCP transport is added upstream.

## Adapter runtime requirement

The opt-in Compose example pins the CAS image
`ghcr.io/joshyorko/codex-action-server@sha256:bda7ef55e9d31574aefbd650ec38bfbe993b5adbbfffc15a49a7ca83e6ba26ca`.
The Kamal deployment uses the CAS image recorded for the existing control
plane. The example image's Python runtime has an `mcp` distribution but does not provide
`mcp.server.fastmcp`. Do not install packages ad hoc on the VM. Any adapter
must use APIs verified in that pinned image or add a reproducible, pinned
dependency and deployment artifact to this repository.

The current bridge implementation in `scripts/codex_memoryd_mcp.py` uses only
the Python standard library; it does not import FastMCP or install a new
dependency. Its stateless Streamable HTTP endpoint is tested through the
existing tunnel-kit MCP client. Keep that transport contract covered if the
implementation changes.

The adapter must expose only the three read-only memory tools, fix the
profile/workspace boundary server-side, and treat retrieved memory as
untrusted evidence. Keep administrative HTTP routes private and do not add a
second tunnel client.

## Managed service wiring

`compose.memoryd.yaml` is an opt-in overlay; it is not part of the default
control-plane startup. It runs the released database service on host loopback
and the bridge on the existing control-plane bridge gateway, with no published
ports. Set `CODEX_MEMORYD_BIND` and the matching `CODEX_MEMORYD_URL` only after
checking the selected loopback port is free. The deployment runner renders the
same two services as separate Kamal accessories and checks capacity before
accessory boot. It stages only the hash-addressed adapter file under the VM's
private deployment state using the pinned SSH path; it does not update the VM's
runtime repository checkout. Use `bin/kamal accessory deploy memoryd` for that
managed operation.

`bin/kamal accessory details memoryd` inspects the accessories;
`bin/kamal accessory stop memoryd` stops the bridge before the database and
retains the named `codex-memoryd-data` volume, even if the core stack is down.
Full-stack `bin/kamal accessory stop` refuses while either MemoryD accessory is
active. Stop MemoryD first, then stop the stack. Full-stack start leaves
MemoryD as it was. To start it again, first start the core stack, then run
`bin/kamal accessory start memoryd`; both accessories and the volume must
exist. The existing Executor identity and tunnel are checked before and after
deployment.

## Portable transfer

Use codex-memoryd's v1 portable bundle format for instance replication; never
copy the SQLite database. The released v0.1.0 exporter caps a selection at
5,000 root memories, so larger corpora must be split into explicit `--record-id`
chunks. Preview each export and each destination import, verify the bundle
integrity and source/destination scopes, then apply with that import preview's
plan ID. Transfer the bundle bytes over the pinned SSH path and verify their
SHA-256 before import. Preserve the source instance ID and bundle manifest
digests; a repeated import should plan zero creates and exact identity reuse.
This transfer selects active records only. It excludes archived MemoryD records
and ChatGPT conversation archives.

Freeze one source cutoff with the official verified backup before chunking.
Export every chunk from that backup, and validate the bundle selections against
its active record IDs. If native files change afterward, keep this snapshot
consistent or create a new backup and regenerate every chunk; do not mix live
source generations in one transfer.

The active manifest is `exports/kamal-test-deploy-transfer-manifest-active.json`
under the isolated MemoryD home. The VM keeps a separate receipt for each
transfer manifest and retains any earlier incomplete receipt. The managed
import streams one verified bundle at a time into the container's writable
temporary filesystem; the container root filesystem remains read-only. Each
bundle must be at most 24 MiB, and temporary free space is checked before each
stage. Before upload, the controller re-exports each selection from a verified
scratch copy of the frozen backup using a pinned Linux v0.1.0 release binary
and compares the content descriptors and policy metadata. Install the official
x86-64 or arm64 release binary, or set `CODEX_MEMORYD_RELEASE_BIN` to its
absolute path; the controller verifies its published-artifact-derived digest.

The adapter's immutable image digest is recorded separately from the CAS
deployment receipt, so a later CAS upgrade does not change the adapter's pin.
Core upgrades first pin a healthy existing adapter. A stopped adapter with a
verified pin can remain stopped. If the pin is missing or the accessories are
partially present, start and verify MemoryD before changing the core deployment.

After import, the managed transfer permits TCP port 8090 only from the owned
private bridge subnet to its gateway, on that bridge interface. It requires an
active UFW firewall and records whether it created the rule. If import completed
before network setup or registration failed, resume with
`bin/kamal accessory network memoryd` and then
`bin/kamal accessory register memoryd`.

Registering an app changes the Executor inventory digest. The managed
registration verifies that every pre-existing app, key, and credential still
matches the recorded identity, saves private copies of the current and previous
deployment receipts, and records the new digest in both receipts. It refuses
unexplained identity drift and can resume an interrupted receipt update.

### Reconcile an interrupted registration before import

If registration reports an importing intent but no unique MemoryD app, it will
not retry the import automatically. On the Bluefin host, use the following
steps from the configured checkout:

1. Verify the previous registration process has exited and the Executor import
   request cannot still complete. Check the Executor dashboard and operator
   logs for an in-flight import. If that cannot be established, do not attest
   or retry. If an app is present, use the normal registration retry instead;
   it still rejects duplicate or unrelated apps.
2. Once the import is quiescent and no MemoryD app is present, run:

   ```zsh
   bin/kamal accessory reconcile-registration memoryd --confirm-import-quiescent
   ```

   The flag attests the first step; the software cannot prove it. The command
   holds the deployment lock, verifies the transfer receipt and recorded
   identity, requires no app receipt or matching app, backs up the private intent,
   and resets it to prepared. It prints the backup path and creates no app.
   The VM's remote action is an internal interface; invoke this locked command.
3. Check the reconciliation result is `prepared`, then separately run
   `bin/kamal accessory register memoryd`. If the reconciliation result is
   unknown, inspect the intent and backup before retrying.

The deployment lock coordinates managed commands; it does not prevent dashboard
changes or a previously issued import from completing. Do not use the attestation
to guess whether either is still in progress.

For rollback, disable the MemoryD app in Executor and run
`bin/kamal accessory stop memoryd`. If the private firewall receipt says this
deployment created the rule, remove only that exact UFW allow using the recorded
bridge, subnet, gateway, and TCP port 8090. The receipt is
`bootstrap/memoryd-firewall.json` under the VM's private state directory. On
the VM, substitute those recorded values into `sudo ufw delete allow in on
<bridge> from <subnet> to <gateway> port 8090 proto tcp` and verify the rule is
gone. This retains the named volume and the verified pre-transfer backup.
Restoring that backup replaces the target database; first back up and verify
the current database, then use the released backup restore command with an
explicit operator decision.

## Activation envelope

Keep the planned memory limits at 256 MiB for codex-memoryd and 128 MiB for the
adapter, with CPU limits of 0.5 and 0.25 respectively. The managed deployment
preflight reads live `MemAvailable` and requires at least 1.5 GiB immediately
before activation; this leaves more than a 1 GiB reserve after both services
reach their memory limits. A failed gate reports the current RAM floor and
performs no source sync or accessory boot. Recheck the existing Executor, CAS,
schema proxy, tunnel, and Fizzy containers before and after activation.
