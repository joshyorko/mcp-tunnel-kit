import initSqlJs from './sqlite-glue.js';
import wasmModule from 'sql.js/dist/sql-wasm.wasm';
import { reports, setupSql, type Report } from './dataset.js';

const wasmSha256 = '0734155c83e493983d1f2ff5b09a4fab6e35a32e9449c7e4e545756439f62d73';
let instance: WebAssembly.Instance | undefined;
let engine: ReturnType<typeof initSqlJs> | undefined;

function loadEngine() {
  engine ??= initSqlJs({
    instantiateWasm(imports, ready) {
      instance = new WebAssembly.Instance(wasmModule, imports);
      ready(instance);
      return instance.exports;
    },
  });
  return engine;
}

export async function openDatabase() {
  const SQL = await loadEngine();
  const db = new SQL.Database();
  try {
    db.run(setupSql);
    return db;
  } catch (error) {
    db.close();
    throw error;
  }
}

export async function analyze(report: Report) {
  // Also reject untyped callers before allocating the synthetic database.
  if (!Object.hasOwn(reports, report)) throw new Error('Unknown report');
  const selected = reports[report];
  const db = await openDatabase();
  try {
    const memory = instance?.exports.M;
    if (!(memory instanceof WebAssembly.Memory)) throw new Error('Missing WASM memory');
    const sqliteVersion = db.exec('SELECT sqlite_version()')[0]?.values[0]?.[0];
    if (typeof sqliteVersion !== 'string') throw new Error('Missing SQLite version');
    const counts = db.exec('SELECT (SELECT COUNT(*) FROM orders), (SELECT COUNT(*) FROM inventory)')[0]?.values[0];
    if (counts?.[0] !== 50000 || counts[1] !== 100) throw new Error('Dataset count mismatch');
    const result = db.exec(selected.sql)[0];
    if (!result || result.values.length > 10) throw new Error('Result bounds exceeded');
    const rows = result.values.map(values => Object.fromEntries(result.columns.map((column, index) => {
      const value = values[index];
      if (typeof value !== 'string' && (typeof value !== 'number' || !Number.isFinite(value))) {
        throw new Error('Unexpected SQL cell');
      }
      return [column, value];
    })));
    if (memory.buffer.byteLength > 64 * 1024 * 1024) throw new Error('WASM memory budget exceeded');
    const output = {
      report, chart: { kind: 'bar', title: selected.title, x: selected.x, y: selected.y },
      columns: result.columns, rows,
      provenance: {
        engine: 'sqlite-wasm', package: 'sql.js@1.13.0', framework: '0.0.1-beta.65',
        wasmSha256, wasmHashKind: 'expected-package-artifact',
        wasmInstance: instance instanceof WebAssembly.Instance,
        sqliteVersion, memoryBytes: memory.buffer.byteLength,
        datasetVersion: 1, seed: 20261112, orderRows: counts[0], inventoryRows: counts[1],
        queryOnly: db.exec('PRAGMA query_only')[0]?.values[0]?.[0] === 1,
        sql: selected.sql,
      },
    };
    if (JSON.stringify(output).length > 16000) throw new Error('Output budget exceeded');
    return output;
  } finally {
    db.close();
  }
}
