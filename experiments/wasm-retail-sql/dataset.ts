export const setupSql = `
PRAGMA hard_heap_limit=16777216;
PRAGMA temp_store=MEMORY;
PRAGMA cache_size=-1024;
PRAGMA max_page_count=2048;
CREATE TABLE inventory (
  sku INTEGER PRIMARY KEY, category TEXT NOT NULL,
  unit_cost_cents INTEGER NOT NULL, on_hand INTEGER NOT NULL
);
WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100)
INSERT INTO inventory
SELECT x, CASE (x-1)%5 WHEN 0 THEN 'Home' WHEN 1 THEN 'Garden'
  WHEN 2 THEN 'Office' WHEN 3 THEN 'Sports' ELSE 'Toys' END,
  300+(x*97)%4700, 50+(x*37)%450 FROM n;
CREATE TABLE orders (
  id INTEGER PRIMARY KEY, day INTEGER NOT NULL, sku INTEGER NOT NULL,
  units INTEGER NOT NULL, revenue_cents INTEGER NOT NULL, cost_cents INTEGER NOT NULL
);
WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<50000),
seeded AS (SELECT x, (x*48271+20261112)%2147483647 AS r FROM n),
items AS (SELECT x, r, 1+r%100 AS sku, 1+(r/100)%4 AS units FROM seeded)
INSERT INTO orders
SELECT x, (x-1)%90, items.sku, units,
  units*(unit_cost_cents+200+(r/400)%1200) - CASE WHEN x%997=0 THEN 30000 ELSE 0 END,
  units*unit_cost_cents
FROM items JOIN inventory ON inventory.sku=items.sku;
PRAGMA query_only=ON;
`;

export const reports = {
  margin: {
    title: 'Margin by category', x: 'category', y: 'margin_cents',
    sql: `SELECT i.category, COUNT(*) AS orders, SUM(o.units) AS units,
      SUM(o.revenue_cents) AS revenue_cents, SUM(o.cost_cents) AS cost_cents,
      SUM(o.revenue_cents-o.cost_cents) AS margin_cents,
      ROUND(100.0*SUM(o.revenue_cents-o.cost_cents)/SUM(o.revenue_cents),2) AS margin_pct
      FROM orders o JOIN inventory i ON i.sku=o.sku
      GROUP BY i.category ORDER BY margin_cents DESC, i.category LIMIT 5`,
  },
  inventory: {
    title: 'Inventory exposure: 90-day sales versus snapshot stock', x: 'sku', y: 'units_sold',
    sql: `SELECT i.sku, i.category, i.on_hand, SUM(o.units) AS units_sold,
      ROUND(90.0*i.on_hand/SUM(o.units),2) AS days_cover,
      SUM(o.revenue_cents-o.cost_cents) AS margin_cents
      FROM orders o JOIN inventory i ON i.sku=o.sku
      GROUP BY i.sku HAVING SUM(o.units)>i.on_hand
      ORDER BY days_cover, i.sku LIMIT 10`,
  },
  outliers: {
    title: 'Lowest-margin synthetic orders', x: 'id', y: 'margin_cents',
    sql: `SELECT o.id, o.day, o.sku, i.category, o.units, o.revenue_cents,
      o.cost_cents, o.revenue_cents-o.cost_cents AS margin_cents
      FROM orders o JOIN inventory i ON i.sku=o.sku
      WHERE o.revenue_cents<o.cost_cents
      ORDER BY margin_cents, o.id LIMIT 10`,
  },
};

export type Report = keyof typeof reports;
