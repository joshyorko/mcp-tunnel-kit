import { dynamicCases } from './dynamic-cases.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { build } from 'esbuild';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';

test('real workerd executes deterministic read-only WASM SQL with bounded results', { timeout: 30000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'retail-wasm-'));
  let child;
  try {
    const wasm = await readFile('node_modules/sql.js/dist/sql-wasm.wasm');
    const manifest = JSON.parse(await readFile('provenance.json', 'utf8'));
    assert.equal(createHash('sha256').update(wasm).digest('hex'), manifest.wasm.sha256);
    await writeFile(join(directory, 'sql.wasm'), wasm);
    await build({
      entryPoints: ['test/worker.ts'], outfile: join(directory, 'worker.mjs'),
      bundle: true, format: 'esm', platform: 'browser', target: 'es2022',
      define: { 'process': 'undefined' },
      external: ['fs', 'path', 'crypto'],
      plugins: [{ name: 'static-wasm', setup(b) {
        b.onResolve({ filter: /\.wasm$/ }, () => ({ path: './sql.wasm', external: true }));
      }}],
    });
    await writeFile(join(directory, 'config.capnp'), `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
 services = [(name = "app", worker = (
  modules = [(name = "worker.mjs", esModule = embed "worker.mjs"), (name = "sql.wasm", wasm = embed "sql.wasm")],
  compatibilityDate = "2026-09-01"
 ))],
 sockets = [(name = "http", address = "127.0.0.1:0", http = (), service = "app")]
);`);
    const architecture = process.arch === 'x64' ? '64' : process.arch;
    child = spawn(resolve(`node_modules/@cloudflare/workerd-${process.platform}-${architecture}/bin/workerd`),
      ['serve', join(directory, 'config.capnp'), '--control-fd=1']);
    let stderr = '';
    child.stderr.on('data', chunk => { stderr += chunk; });
    const address = await new Promise((accept, reject) => {
      const timer = setTimeout(() => reject(new Error(`workerd did not start: ${stderr}`)), 10000);
      child.on('exit', code => { clearTimeout(timer); reject(new Error(`workerd exited ${code}: ${stderr}`)); });
      child.stdout.on('data', chunk => {
        const match = chunk.toString().match(/"port"\s*:\s*(\d+)/);
        if (match) { clearTimeout(timer); accept(`http://127.0.0.1:${match[1]}`); }
      });
    });
    const call = async path => {
      const response = await fetch(address + path, { signal: AbortSignal.timeout(8000) });
      assert.equal(response.status, 200, (await response.clone().text()) + stderr);
      return response.json();
    };
    const first = await call('/margin');
    const second = await call('/margin');
    assert.deepEqual(first, second);
    assert.equal(first.provenance.engine, 'sqlite-wasm');
    assert.equal(first.provenance.wasmSha256, manifest.wasm.sha256);
    assert.equal(first.provenance.wasmInstance, true);
    assert.equal(first.provenance.queryOnly, true);
    assert.equal(first.provenance.orderRows, 50000);
    assert.equal(first.provenance.inventoryRows, 100);
    assert.ok(first.provenance.memoryBytes <= 64 * 1024 * 1024);
    assert.equal(first.rows.length, 5);
    assert.equal(first.rows.reduce((sum, row) => sum + row.orders, 0), 50000);
    assert.deepEqual(first.rows.map(row => [row.category, row.margin_cents]), [
      ['Office', 19717896], ['Garden', 19705893], ['Sports', 19676864],
      ['Toys', 19675943], ['Home', 19662603],
    ]);
    assert.ok(JSON.stringify(first).length < 16000);
    const outliers = await call('/outliers');
    assert.equal(outliers.rows.length, 10);
    assert.ok(outliers.rows.every(row => row.margin_cents < 0));
    const inventory = await call('/inventory');
    assert.equal(inventory.rows.length, 10);
    assert.ok(inventory.rows.every(row => row.units_sold > row.on_hand));
    assert.deepEqual(await call('/guards'), { writesRefused: 3, unknownReportRefused: true });
    const { input, bombs, badInputs } = dynamicCases();
    const dynamic = async value => fetch(address + '/dynamic', { method: 'POST',
      body: JSON.stringify(value), headers: { 'content-type': 'application/json' }, signal: AbortSignal.timeout(8000) });
    const response = await dynamic(input);
    assert.equal(response.status, 200);
    const data = await response.json();
    assert.deepEqual(data.rows, [['Tea', 100], ['Coffee', 90]]);
    assert.deepEqual(data.columns, ['category', 'margin']);
    assert.equal(data.provenance.queryOnly, true);
    assert.equal(data.provenance.wasmInstance, true);
    assert.equal(data.provenance.authorizer, 'not-exported-by-pinned-sql.js');
    for (const sql of bombs) assert.equal((await dynamic({ ...input, sql })).status, 400, sql);
    for (const value of badInputs) assert.equal((await dynamic(value)).status, 400);
    const maximum = { columns: [{ name: 'value', type: 'number' }],
      rows: Array.from({ length: 1000 }, (_, i) => [i]), sql: 'SELECT SUM(value) AS total FROM data' };
    assert.deepEqual((await (await dynamic(maximum)).json()).rows, [[499500]]);
    const stress = {
      columns: Array.from({ length: 8 }, (_, i) => ({ name: 'field' + i, type: 'number' })),
      rows: Array.from({ length: 1000 }, (_, i) => Array.from({ length: 8 }, (_, j) => (i + j) % 1000)),
      sql: 'SELECT field0, field1, field2, field3, SUM(field4) AS total, AVG(field5) AS average, MIN(field6) AS smallest, MAX(field7) AS largest FROM data GROUP BY field0, field1, field2, field3 ORDER BY total DESC LIMIT 100',
    };
    const stressResult = await (await dynamic(stress)).json();
    assert.equal(stressResult.rows.length, 100);
    assert.equal(stressResult.columns.length, 8);
    const injection = { columns: [{ name: 'label', type: 'text' }],
      rows: [["x'); DROP TABLE data;--"]], sql: 'SELECT label FROM data' };
    assert.deepEqual((await (await dynamic(injection)).json()).rows, injection.rows);
    assert.deepEqual(await call('/cancelled'), { aborted: true });
    const escaped = { ...injection, rows: [["O'Reilly"], ['other'], [null]],
      sql: "SELECT label FROM data WHERE label = 'O''Reilly'" };
    assert.deepEqual((await (await dynamic(escaped)).json()).rows, [["O'Reilly"]]);
    assert.deepEqual((await (await dynamic({ ...escaped, sql: 'SELECT label FROM data WHERE label IS NULL' })).json()).rows, [[null]]);
    assert.deepEqual((await call('/margin')).rows, first.rows);
    assert.deepEqual((await call('/inventory')).rows, inventory.rows);
    assert.deepEqual((await call('/outliers')).rows, outliers.rows);
    await writeFile(join(directory, 'result.json'), JSON.stringify(first));
    console.log(JSON.stringify({ sqliteVersion: first.provenance.sqliteVersion,
      memoryBytes: first.provenance.memoryBytes, rows: first.rows }));
  } finally {
    if (child && child.exitCode === null) {
      child.kill('SIGTERM');
      await new Promise(accept => child.once('exit', accept));
    }
    await rm(directory, { recursive: true, force: true });
  }
});
