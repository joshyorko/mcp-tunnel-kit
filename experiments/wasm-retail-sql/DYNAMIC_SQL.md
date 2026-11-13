# Submit chat data to SQLite WASM

The opt-in `analyze` query accepts tabular data directly as tool arguments.
It runs real SQLite WASM in the existing app, alongside the unchanged fixed
reports. It requires no account, network request, file upload, or service restart.
Submit only synthetic or otherwise nonsecret data. Chat tool arguments and
results remain part of the conversation; this is not a secret-data channel.

The existing live app was updated through Executor app management after exact
beta.12 tests and independent review. Fresh discovery verified the bounded
input signature, and a new five-row dataset/custom grouped query executed from
chat. All ten deployed files matched the reviewed source; repeated query rows
and the three fixed reports matched. See the [live receipt](evidence/dynamic-live-installation.json),
[exact-host acceptance](evidence/dynamic-beta12-acceptance.json), and
[payload hashes](evidence/dynamic-source-hashes.json).

## Input schema

`tools["wasm-retail-sql"].analyze` accepts exactly these three properties:

| Property | Type and limits |
| --- | --- |
| `columns` | 1–8 objects, each exactly `{name: string, type: "text" \| "number"}` |
| `columns[].name` | Unique lowercase ASCII identifier matching `^[a-z][a-z0-9_]{0,23}$`; SQL grammar keywords, SQLite internal names, and rowid aliases are reserved |
| `rows` | 1–1,000 arrays, each with exactly one cell per column, in column order |
| cell | `null`, a text string of at most 256 characters without NUL, or a finite number between −1e9 and 1e9; non-null cells must match the declared column type |
| `sql` | Nonempty SELECT, at most 1,024 UTF-8 bytes and 128 tokens |
| whole input | At most 65,536 UTF-8 bytes when serialized as JSON; no additional properties |

The discoverable JSON Schema is declared in `dynamic-schema.ts`. Additional
cross-field and total-byte checks are in `select.ts:parseData`. CSV is not
accepted; submit row arrays. Values are parameter-bound, never interpolated.

## SELECT grammar

The only table is `data`. SQL keywords and query identifiers are case-insensitive;
declared column names are lowercase. Accepted structure:

```text
SELECT item [, item ...] FROM data
  [WHERE predicate [AND predicate ...]]
  [GROUP BY column [, column ...]]
  [ORDER BY output_name [ASC|DESC] [, output_name [ASC|DESC]]]
  [LIMIT integer]
```

- At most eight select items. An item is a column with optional `AS alias`, or
  `COUNT`, `SUM`, `AVG`, `MIN`, or `MAX` with mandatory `AS alias`. Output names
  must be distinct safe identifiers.
- `COUNT(*)` is supported. Other aggregate arguments are one column, or up to
  three numeric columns joined by `+` or `-`. `SUM` and `AVG` require numeric
  columns. There are no nested functions, scalar functions, or other arithmetic.
- At most four predicates. Each compares a column with a same-type numeric or
  single-quoted text literal using `= != <> < > <= >=`, or uses `IS [NOT] NULL`.
  A quote inside a text literal is doubled. Literals become bound parameters.
- At most four GROUP BY columns. Every selected nonaggregate column must be
  grouped when aggregates or grouping are present; SQLite bare-column ambiguity
  is rejected.
- At most two ORDER BY keys, each naming an output column or alias.
- LIMIT is 1–100, default 50. No OFFSET. A result of zero rows is valid.

Everything else is rejected, including semicolons, comments, quoted identifiers,
wildcard selection, schema-qualified names, subqueries, joins, CTEs, recursion,
UNION, DISTINCT, HAVING, windows, DDL, DML, ATTACH, PRAGMA, extension loading,
virtual tables, and any non-whitelisted function. The iterative parser produces
a canonical SELECT with quoted validated identifiers and bound literals.
**The submitted SQL string never reaches SQLite.**

## Execution and resource controls

Each call creates an empty in-memory SQLite database. Only trusted bootstrap SQL
creates and fills `data`, using a prepared INSERT. `PRAGMA query_only=ON` is set
and verified before executing the reconstructed SELECT. The database and all
statements close in `finally`; no uploaded data is stored in app-owned storage.

The dynamic database has a 1 MiB page limit, 512 KiB page-cache target, and
memory-only temporary storage. The 16 MiB SQLite allocation ceiling is
engine-global, also applying to the fixed reports. It shares the
pinned WASM engine with the fixed reports; its linear-memory size is checked
against the existing 64 MiB observation limit. That check is not a new hard
linear-memory maximum. Output is at most 100 rows and 32,768 UTF-8 bytes,
with an incremental 30,000-byte row budget.

CPU work is bounded structurally: one scan of at most 1,000 rows, fixed-size
expressions/predicates, and grouping/sorting of at most 1,000 bounded keys.
There is no cross product, user recursion, nested expression expansion, regex,
blob allocator, or arbitrary function. Cancellation is checked before loading,
every 128 inserts, before SELECT, and for every result row. Exact-host and local
test requests have eight-second watchdogs. **Neither those client watchdogs nor
the cooperative signal can preempt a synchronous SQLite instruction.** No hard
per-call CPU timer is claimed. Increasing limits or admitting more SQL requires
a new resource analysis and tests, not only edits to the grammar.

The pinned `sql.js@1.13.0` artifact exports neither SQLite authorizer nor
progress-handler/interrupt APIs. This experiment does not change the WASM or
pretend those guards are active. It reports
`authorizer: "not-exported-by-pinned-sql.js"` and refuses an unexpected artifact
that exposes an unconfigured authorizer. The restrictive parser and canonical
SQL generation are the query authorization boundary; query_only is additional
protection, not a substitute for that boundary.

## Result schema and verification

Results contain `columns: string[]`, `rows: (string|number|null)[][]`, and
`provenance` with SQLite version, expected artifact hash, actual WASM-instance
evidence, input dimensions/byte count, memory bytes, read-only status,
canonical SQL, bound filter parameters, and execution-limit qualifications.
No aggregation is performed in JavaScript. Null aggregates and filtered empty
results follow SQLite semantics. Floating-point values follow SQLite REAL
semantics; use bounded integer cents for money.

Run the commands in `README.md:Verify locally`. The shared
`test/dynamic-cases.mjs` matrix is exercised both by pinned workerd and the
disposable exact beta.12 selfhost through its real tool API. It rejects SQL
escape/bomb attempts, malformed/oversized input, and excessive output. Tests
also cover custom aggregation, bound injection-like cell values, escaped
literals, nulls, maximum row count/column count, and cancellation. Fixed-report
tests still run. Deploy only through the existing Executor app management API
after those checks; retain the app ID and verify existing source ownership
before saving the complete new file list.

When updating through Code Mode, read `appManagement.source` and verify its
revision and contents against the owned app's recorded baseline. Retain unchanged
files remotely, splice in only reviewed updates, and save the **complete** file
list with `appManagement.commit` using that revision as `expected`. Deploy the
returned immutable commit to the same app ID; do not create a replacement app.
Read back the deployed source and compare every file. The source exceeds Code
Mode's 64 KiB output budget: compare bounded file groups within execute and
return only match flags and deployment metadata, rather than returning the
whole source. Preserve `sqlite-glue.js` and the license exactly.
