export function dynamicCases() {
    const input = {
      columns: [{ name: 'category', type: 'text' }, { name: 'revenue', type: 'number' }, { name: 'cost', type: 'number' }],
      rows: [['Tea', 120, 70], ['Coffee', 200, 110], ['Tea', 80, 30], ['Coffee', 50, 45]],
      sql: 'SELECT category, SUM(revenue - cost) AS margin FROM data WHERE revenue >= 60 GROUP BY category ORDER BY margin DESC LIMIT 10',
    };
    const bombs = [
      'DELETE FROM data', 'DROP TABLE data', 'INSERT INTO data VALUES(1)', 'UPDATE data SET cost=0',
      'ATTACH DATABASE x AS other', 'PRAGMA query_only=OFF', 'CREATE VIRTUAL TABLE x USING fts5(a)',
      'SELECT load_extension(x) FROM data', 'SELECT randomblob(1000000000) FROM data',
      'SELECT printf(x) FROM data', 'SELECT hex(revenue) FROM data',
      'SELECT category FROM data; DELETE FROM data', 'SELECT category FROM data;',
      'SELECT category FROM data --comment', 'SELECT category FROM data /*comment*/',
      'WITH RECURSIVE x AS (SELECT 1) SELECT * FROM x',
      'SELECT * FROM data', 'SELECT category FROM data CROSS JOIN data',
      'SELECT category FROM data UNION SELECT category FROM data',
      'SELECT (SELECT category FROM data) FROM data', 'SELECT SUM(SUM(revenue)) FROM data',
      'SELECT SUM(revenue) OVER() FROM data', 'SELECT SUM(revenue * revenue) FROM data',
      'SELECT category FROM sqlite_master', 'SELECT category FROM temp.data',
      'SELECT category FROM data ORDER BY random()', 'SELECT category FROM data LIMIT 101',
      'SELECT category FROM data LIMIT 0', 'SELECT category FROM data LIMIT -1',
      'SELECT category FROM data LIMIT 1 OFFSET 2', 'SELECT category FROM data WHERE 1=1 OR 1=1',
      'SELECT category, SUM(revenue) AS x FROM data',
      'SELECT category AS x, revenue AS x FROM data', 'SELECT unknown FROM data',
      'SELECT SUM(category) AS x FROM data', 'SELECT category FROM data WHERE category LIKE x',
      'SELECT category FROM data\u0000', 'SELECT category FROM data ' + ' '.repeat(1100),
    ];
    const badInputs = [
      { ...input, rows: [] },
      { ...input, columns: Array.from({ length: 9 }, (_, i) => ({ name: 'col' + i, type: 'text' })) },
      { ...input, rows: [['x', 1, 2, 3]] },
      { columns: [{ name: 'left_text', type: 'text' }, { name: 'right_text', type: 'text' }],
        rows: Array.from({ length: 100 }, () => ['a'.repeat(200), 'b'.repeat(200)]),
        sql: 'SELECT left_text, right_text FROM data LIMIT 100' },
      { ...input, rows: Array.from({ length: 1001 }, () => ['x', 1, 2]) },
      { ...input, rows: [['x', 'not a number', 2]] },
      { ...input, rows: [['x', 1]] },
      { ...input, rows: [['x'.repeat(257), 1, 2]] },
      { ...input, rows: [['x', 1e10, 2]] },
      { ...input, columns: [{ name: 'x);DROP', type: 'text' }] },
      { ...input, columns: [{ name: 'select', type: 'text' }] },
      { ...input, columns: [{ name: 'x', type: 'text' }, { name: 'X', type: 'text' }] },
      { ...input, rows: Array.from({ length: 1000 }, () => ['x'.repeat(256), 1, 2]) },
      { ...input, secret: 'undeclared field' },
    ];
    return { input, bombs, badInputs };
}
