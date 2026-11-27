export type Cell = string | number | null;
export type Column = { name: string; type: 'text' | 'number' };
const reserved = new Set('select from where and or group by order asc desc limit as sum avg min max count null is not data rowid oid _rowid_'.split(' '));
const identifier = (value: unknown): value is string => typeof value === 'string'
  && /^[a-z][a-z0-9_]{0,23}$/.test(value) && !reserved.has(value) && !value.startsWith('sqlite_');
const reject = (): never => { throw new Error('Input or SELECT is outside the bounded grammar'); };
const quote = (name: string) => '"' + name + '"';

export function parseData(input: unknown) {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) return reject();
  if (Object.keys(input).sort().join(',') !== 'columns,rows,sql'
    || !('columns' in input) || !('rows' in input) || !('sql' in input)) return reject();
  if (!Array.isArray(input.columns) || input.columns.length < 1 || input.columns.length > 8
    || !Array.isArray(input.rows) || input.rows.length < 1 || input.rows.length > 1000
    || typeof input.sql !== 'string' || input.sql.length > 1024) return reject();
  const columns: Column[] = [];
  for (const column of input.columns) {
    if (typeof column !== 'object' || column === null || Array.isArray(column)
      || Object.keys(column).sort().join(',') !== 'name,type'
      || !identifier(column.name) || (column.type !== 'text' && column.type !== 'number')
      || columns.some(existing => existing.name === column.name)) return reject();
    columns.push({ name: column.name, type: column.type });
  }
  const rows: Cell[][] = [];
  let cellBytes = 0;
  for (const row of input.rows) {
    if (!Array.isArray(row) || row.length !== columns.length) return reject();
    const cells: Cell[] = [];
    for (let i = 0; i < row.length; i++) {
      const cell: unknown = row[i];
      if (cell === null) cells.push(null);
      else if (columns[i]?.type === 'text' && typeof cell === 'string' && cell.length <= 256 && !cell.includes('\0')) {
        cells.push(cell);
        cellBytes += new TextEncoder().encode(cell).length;
      } else if (columns[i]?.type === 'number' && typeof cell === 'number' && Number.isFinite(cell) && Math.abs(cell) <= 1e9) {
        cells.push(cell);
      } else return reject();
      if (cellBytes > 65536) return reject();
    }
    rows.push(cells);
  }
  const inputBytes = new TextEncoder().encode(JSON.stringify(input)).length;
  if (inputBytes > 65536) return reject();
  return { columns, rows, sql: input.sql, inputBytes };
}

/** Iterative, finite grammar. Only reconstructed identifiers/operators reach SQL;
 * every WHERE literal is bound. No submitted SQL substring is executed. */
export function compileSelect(sql: string, columns: Column[]) {
  if (new TextEncoder().encode(sql).length > 1024) return reject();
  const tokens: string[] = [];
  const lexer = /\s+|[a-zA-Z_][a-zA-Z_0-9]*|\d+(?:\.\d+)?|'(?:[^']|'')*'|<=|>=|<>|!=|[(),*+\-=<>]/gy;
  let offset = 0;
  while (offset < sql.length) {
    lexer.lastIndex = offset;
    const match = lexer.exec(sql);
    if (!match) return reject();
    offset = lexer.lastIndex;
    if (!/^\s+$/.test(match[0])) tokens.push(match[0]);
    if (tokens.length > 128) return reject();
  }
  let position = 0;
  const peek = () => tokens[position]?.toUpperCase();
  const take = (word: string) => { if (peek() !== word) return false; position++; return true; };
  const expect = (word: string) => { if (!take(word)) reject(); };
  const column = () => {
    const name = tokens[position++]?.toLowerCase();
    const found = columns.find(item => item.name === name);
    if (!found) return reject();
    return found;
  };
  const alias = () => { const name = tokens[position++]?.toLowerCase(); return identifier(name) ? name : reject(); };
  const expressions: string[] = [];
  const outputs: string[] = [];
  const plain: string[] = [];
  let aggregated = false;
  expect('SELECT');
  do {
    if (expressions.length >= 8) return reject();
    const fn = peek();
    let expression: string;
    let name: string;
    if (fn === 'SUM' || fn === 'AVG' || fn === 'MIN' || fn === 'MAX' || fn === 'COUNT') {
      position++;
      expect('(');
      aggregated = true;
      let argument: string;
      if (fn === 'COUNT' && take('*')) argument = '*';
      else {
        const first = column();
        if ((fn === 'SUM' || fn === 'AVG') && first.type !== 'number') return reject();
        argument = quote(first.name);
        let terms = 1;
        while (peek() === '+' || peek() === '-') {
          if (first.type !== 'number' || ++terms > 3) return reject();
          const operator = tokens[position++];
          const next = column();
          if (next.type !== 'number') return reject();
          argument += ' ' + operator + ' ' + quote(next.name);
        }
      }
      expect(')');
      expect('AS');
      name = alias();
      expression = fn + '(' + argument + ')';
    } else {
      const selected = column();
      plain.push(selected.name);
      expression = quote(selected.name);
      name = take('AS') ? alias() : selected.name;
    }
    if (outputs.includes(name)) return reject();
    outputs.push(name);
    expressions.push(expression + ' AS ' + quote(name));
  } while (take(','));
  expect('FROM'); expect('DATA');
  const params: Cell[] = [];
  const predicates: string[] = [];
  if (take('WHERE')) do {
    if (predicates.length >= 4) return reject();
    const selected = column();
    if (take('IS')) {
      const negation = take('NOT'); expect('NULL');
      predicates.push(quote(selected.name) + (negation ? ' IS NOT NULL' : ' IS NULL'));
    } else {
      const op = tokens[position++];
      if (!op || !['=', '!=', '<>', '<', '>', '<=', '>='].includes(op)) return reject();
      const negative = take('-');
      const token = tokens[position++];
      if (!token) return reject();
      let value: Cell;
      if (/^\d+(?:\.\d+)?$/.test(token) && selected.type === 'number') {
        value = Number(token) * (negative ? -1 : 1);
        if (!Number.isFinite(value) || Math.abs(value) > 1e9) return reject();
      } else if (!negative && token.startsWith("'") && selected.type === 'text') {
        value = token.slice(1, -1).replace(/''/g, "'");
        if (value.length > 256 || value.includes('\0')) return reject();
      } else return reject();
      params.push(value);
      predicates.push(quote(selected.name) + ' ' + op + ' ?');
    }
  } while (take('AND'));
  const groups: string[] = [];
  if (take('GROUP')) {
    expect('BY');
    do {
      if (groups.length >= 4) return reject();
      groups.push(column().name);
    } while (take(','));
  }
  if ((aggregated || groups.length > 0) && plain.some(name => !groups.includes(name))) return reject();
  const orders: string[] = [];
  if (take('ORDER')) {
    expect('BY');
    do {
      if (orders.length >= 2) return reject();
      const name = tokens[position++]?.toLowerCase();
      if (!name || !outputs.includes(name)) return reject();
      const direction = take('DESC') ? ' DESC' : (take('ASC'), ' ASC');
      orders.push(quote(name) + direction);
    } while (take(','));
  }
  let limit = 50;
  if (take('LIMIT')) {
    const value = tokens[position++];
    if (!value || !/^\d{1,3}$/.test(value)) return reject();
    limit = Number(value);
    if (limit < 1 || limit > 100) return reject();
  }
  if (position !== tokens.length) return reject();
  return {
    sql: 'SELECT ' + expressions.join(', ') + ' FROM "data"'
      + (predicates.length ? ' WHERE ' + predicates.join(' AND ') : '')
      + (groups.length ? ' GROUP BY ' + groups.map(quote).join(', ') : '')
      + (orders.length ? ' ORDER BY ' + orders.join(', ') : '') + ' LIMIT ' + limit,
    params, limit,
  };
}
