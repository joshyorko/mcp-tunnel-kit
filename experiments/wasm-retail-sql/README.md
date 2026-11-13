# Run the optional WASM retail SQL lab

This opt-in proof of concept adds three read-only Executor app tools. Nothing in
Compose, Kamal, bootstrap, or the existing apps installs it automatically.
The app executes real SQLite WASM over 50,000 synthetic orders and 100 inventory
rows, generated entirely by SQL with seed `20261112`. It returns category margin,
inventory exposure, and loss outliers as compact JSON for ChatGPT charts.

Owner: the operator who explicitly installs **WASM Retail SQL**. Only this new
app belongs to the experiment. No accounts, credentials, persisted app data,
external API calls, sidecars, or existing-app edits are required.

The explicitly authorized live app-only install succeeded after
[PR #78](https://github.com/joshyorko/mcp-tunnel-kit/pull/78) was published.
Fresh connected-MCP discovery and calls verified
`tools["wasm-retail-sql"].margin({})`, `.inventory({})`, and `.outliers({})`.
All seven deployed source files matched the reviewed payload byte-for-byte;
all three reports matched the disposable beta.12 results. A repeated margin
call returned identical JSON. See [the installation receipt](evidence/live-installation.json)
for app/deployment IDs, discovered signatures, and actual results, and
[source hashes](evidence/source-hashes.json) for the reviewed payload.
No accessory was upgraded or restarted. Visibility in another ChatGPT session
still depends on that session's existing Executor connection and tool discovery.

## Check compatibility

The connected live Executor returned `framework.release({}).version` =
`0.0.1-beta.65` on November 12, 2026. The two upstream release tags contain:

| Host source tag | Tag commit | `packages/apps/package.json` |
| --- | --- | --- |
| `executor@2.0.0-beta.12` | `c64354dd9ffdd30fc62439658f19a71a9df91e54` | `0.0.1-beta.65` |
| `executor@2.0.0-beta.44` | `1ce4e49bfe2a8fc69004a73a1da184c70b685268` | `0.0.1-beta.126` |

The kit base `de027986697e5ca2ef8459df04d464ccd6d8047b` pins beta.12
at digest `sha256:89a2b829150d01bc26305f844159ca8064ea8a4ace047490d09b6a3c8bdcf600`
in `config/deploy-images.json`. This experiment preserves that pin and declares
`apps=0.0.1-beta.65`. The matching live framework supports beta.12 attribution;
it does **not** prove the VM container image identity. In this independent
checkout, `bin/kamal accessory details executor` stopped with
`Local deployment file is unavailable or invalid` because `.env.kamal.local`
is absent. No VM lifecycle operation was performed.

Both tags include `packages/sdk/src/implementation/worker-wasm-build.ts`.
The beta.12 bundler's static WASM import uses its patched
`@cloudflare/worker-bundler@0.2.4` binary asset retention. The stock npm bundler
alone lacks `readBinary`; it is not an equivalent import test. Beta.12 pins
`workerd@1.20260918.1`, which is also the local test dependency here.

DuckDB-Wasm requires a JS Worker plus its WASM bundle. Its `1.30.0` npm package
is approximately 141 MB unpacked. This experiment chooses SQLite to avoid nested
Workers, cross-origin isolation, and asset fetching. The pinned sql.js engine is
approximately 645 KiB. `prepare.mjs` removes Emscripten's unused Node/browser
loaders: otherwise workerd's `WorkerGlobalScope` causes an invalid
`self.location.href` read. It does not change any WASM bytes. `engine.ts` imports
the precompiled module and uses `new WebAssembly.Instance`, never byte compilation
or Code Mode globals. Code Mode only searches and calls the app tools.

## Verify locally

Run from this directory on a Linux development host or in its project container.
These dependencies are checkout-local; no host tool installation is needed.

```sh
npm ci --ignore-scripts --no-audit --no-fund
node prepare.mjs
npm run typecheck
npm test
node pack.mjs
```

`npm test` launches a temporary loopback-only workerd fixture, imports the actual
WASM, checks its SHA-256, runs all three SQL reports, compares deterministic
margin totals, and rejects three SQL writes and an unknown report. It closes the
database after every call and stops its test process. The CI workflow repeats
this test and verifies that generated glue matches the committed file.

For installed beta.12 acceptance, use a **local Unix-socket Docker engine**:

```sh
docker pull ghcr.io/usefulsoftwareco/executor-selfhost:2.0.0-beta.12@sha256:89a2b829150d01bc26305f844159ca8064ea8a4ace047490d09b6a3c8bdcf600
node test-selfhost.mjs
```

This explicit fixture starts only a uniquely named disposable container. It uses
tmpfs data, a synthetic test login, an exact matching `BETTER_AUTH_URL` and Origin,
an ephemeral loopback port, 1 GiB container memory, two CPUs, and no production
mounts. It deploys via the stock organization API, exercises the image's actual
patched dependency installer and WASM plugin, verifies all three tools are
read-only, and calls them. It stops only its own container and does not create or
remove Docker volumes. Results are saved under `.build/selfhost-results.json`.
The image must already be pulled; the script never pulls or upgrades anything.

## Install through the existing Executor connection

Preflight: review the source PR and local/installed acceptance evidence. Read the
connected Executor's `app-authoring` skill. Discover `framework.release`,
`context.get`, `appManagement.create`, and `appManagement.deploy` with
`tools.search`, then read their full signatures with `tools.search.describe`.
Verify the framework is beta.65 and use the organization returned by context.
If either identity differs, stop and reassess compatibility.

`node pack.mjs` produces `.build/files.json`, the **complete reviewed deployment
file list**, and `.build/source-hashes.json`. Tests, dev dependencies, lockfiles,
and operator files are excluded. Pass the parsed files array as data; do not
paste source into shell or JavaScript template literals. Keep these artifacts
with the PR commit used for installation.

Call the discovered `appManagement.create` with `body: {name: "WASM Retail SQL",
files}`. Record the returned app ID; do not overwrite an existing name or app.
Create saves source but does not run it. Then call `appManagement.deploy` with
`path: {organization, app: <new ID>}` and `body: {files}`. Record the deployment
ID and read back `apps.source` to compare every source-file hash. Recheck
`framework.release`. No accessory redeploy or VM credentials are needed for
this explicitly authorized app-only installation.

In a **new** execute, search for `WASM Retail SQL` and use the returned slug:
`tools["<returned-slug>"].margin({})`, `.inventory({})`, or `.outliers({})`.
Read the discovered type signature and call each tool. Each takes an empty
object and returns `{report, chart, columns, rows, provenance}`. Chart axes use
the keys in `chart.x` and `chart.y`; money fields are integer cents. Label charts
as deterministic synthetic data. Inventory is an opening stock snapshot versus
90-day sales, not an actual forecast. Negative revenue models returns/discounts.

Success evidence requires fresh discovery, typed signatures, successful calls,
source hash readback, SQLite version, actual WASM-instance/memory evidence,
expected row counts, `queryOnly: true`, and matching deterministic results.
An app install alone does not prove a separate ChatGPT session can see the app;
that session must search and call it through its existing tunnel connection.

Rollback is app-only: stop calling the app, discover the supported app removal
operation, verify its app ID matches the installation receipt, and remove only
that app. It has no persistent data. Do not roll back Executor, reset its volume,
rotate credentials, change the tunnel ID, or restart other services. If an image
change ever becomes necessary, stop this recipe and use `bin/kamal` with the
existing backup, provenance, preflight, health, and rollback gates.

## Resource and provenance limits

The three queries are fixed; there is no user SQL, file input, URL, row-count,
seed, or blob parameter. SQL performs all generation, aggregation, and ranking.
`PRAGMA query_only=ON` protects the completed in-memory database. Bootstrap writes
are ephemeral and necessary to construct the fixture. SQLite has a 16 MiB hard
allocation limit, an 8 MiB database page limit, a 1 MiB page cache target, and
memory-only temporary storage. Results have at most 10 rows and 16,000 serialized
characters. The module's observed linear memory is checked against 64 MiB.

The 64 MiB check is **not** a custom hard limit on the module's declared linear
memory, and this app does not install a new hard per-call CPU deadline. Work is
bounded by fixed SQL and dataset sizes; the local request watchdog is eight
seconds. Do not extend this interface to arbitrary SQL without engine-level
interrupts, allocation controls, and an independently verified execution budget.

`provenance.json` pins the npm integrity and WASM hash. `prepare.mjs` verifies the
local engine bytes. Returned `wasmSha256` is explicitly marked
`expected-package-artifact`: workerd exposes a precompiled module, not its source
bytes, so it is not a claim that the live tool hashed its own module. Actual
execution evidence is the instantiated module's memory, SQLite version, SQL
results, deterministic fingerprints, and the exact-image installed test.

Sources: [DuckDB deployment](https://duckdb.org/docs/stable/clients/wasm/deploying_duckdb_wasm),
[sql.js](https://github.com/sql-js/sql.js),
[beta.12 source](https://github.com/UsefulSoftwareCo/executor/tree/executor%402.0.0-beta.12),
[beta.44 source](https://github.com/UsefulSoftwareCo/executor/tree/executor%402.0.0-beta.44),
and the kit's [managed VM deployment](../../docs/VM_DEPLOY.md).
