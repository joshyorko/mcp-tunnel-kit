import { createEmptyDatabase, wasmSha256 } from './engine.js';
import { compileSelect, parseData } from './select.js';

export async function analyzeData(input: unknown, signal?: AbortSignal) {
  signal?.throwIfAborted();
  const data = parseData(input);
  const compiled = compileSelect(data.sql, data.columns);
  const runtime = await createEmptyDatabase();
  const { db, memory } = runtime;
  try {
    signal?.throwIfAborted();
    db.run('PRAGMA hard_heap_limit=16777216; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-512; PRAGMA max_page_count=256;');
    db.run('CREATE TABLE "data" (' + data.columns.map(column => '"' + column.name + '" ' + (column.type === 'text' ? 'TEXT' : 'REAL')).join(', ') + ')');
    db.run('BEGIN');
    const insert = db.prepare('INSERT INTO "data" VALUES (' + data.columns.map(() => '?').join(', ') + ')');
    try {
      for (let i = 0; i < data.rows.length; i++) {
        if (i % 128 === 0) signal?.throwIfAborted();
        const row = data.rows[i];
        if (row) insert.run(row);
      }
    } finally { insert.free(); }
    db.run('COMMIT; PRAGMA query_only=ON;');
    if (db.exec('PRAGMA query_only')[0]?.values[0]?.[0] !== 1) throw new Error('Read-only guard unavailable');
    signal?.throwIfAborted();
    const statement = db.prepare(compiled.sql);
    const rows = [];
    let outputBytes = 0;
    let columns: string[];
    try {
      statement.bind(compiled.params);
      columns = statement.getColumnNames();
      while (statement.step()) {
        signal?.throwIfAborted();
        const cells = statement.get().map(cell => {
          if (cell === null || typeof cell === 'string' || (typeof cell === 'number' && Number.isFinite(cell))) return cell;
          throw new Error('Output type rejected');
        });
        outputBytes += new TextEncoder().encode(JSON.stringify(cells)).length;
        if (rows.length >= compiled.limit || outputBytes > 30000) throw new Error('Output byte budget exceeded');
        rows.push(cells);
      }
    } finally { statement.free(); }
    if (memory.buffer.byteLength > 64 * 1024 * 1024) throw new Error('WASM memory budget exceeded');
    const sqliteVersion = db.exec('SELECT sqlite_version()')[0]?.values[0]?.[0];
    if (typeof sqliteVersion !== 'string') throw new Error('SQLite version unavailable');
    const result = {
      columns, rows,
      provenance: {
        engine: 'sqlite-wasm', sqliteVersion,
        wasmSha256, wasmHashKind: 'expected-package-artifact', wasmInstance: runtime.wasmInstance,
        queryOnly: true, authorizer: 'not-exported-by-pinned-sql.js',
        inputRows: data.rows.length, inputColumns: data.columns.length, inputBytes: data.inputBytes,
        memoryBytes: memory.buffer.byteLength, sql: compiled.sql, parameters: compiled.params,
        cpuGuard: 'bounded-single-table-grammar', cancellation: 'cooperative; no synchronous VM preemption',
      },
    };
    if (new TextEncoder().encode(JSON.stringify(result)).length > 32768) throw new Error('Output byte budget exceeded');
    return result;
  } finally { db.close(); }
}
