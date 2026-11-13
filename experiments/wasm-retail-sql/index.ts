import { defineApp, query, object, router } from 'apps';
import { analyze } from './engine.js';
import { reportOutput } from './output.js';
import { dynamicInput, dynamicOutput } from './dynamic-schema.js';
import { analyzeData } from './dynamic.js';

export default defineApp({ accounts: {} }, {
  tools: router({
    analyze: query({
      description: 'Run a bounded read-only SELECT on chat-supplied NONSECRET tabular data. columns: 1-8 lowercase names/types (text|number); rows: 1-1000 arrays of matching cells (string<=256, finite number within ±1e9, or null); total JSON<=64KiB. Table is data. SELECT columns or COUNT/SUM/AVG/MIN/MAX with AS aliases; aggregate args may add/subtract up to 3 numeric columns. Optional WHERE up to 4 comparisons joined by AND, GROUP BY up to 4 columns, ORDER BY up to 2 output names, LIMIT 1-100 (default50). No other SQL, comments, semicolons, joins, subqueries or functions. Max output32KiB. Work is structurally bounded; cancellation is cooperative, not CPU preemption. Returns columns, row arrays, executed SQL and WASM provenance. Never submit secrets.',
      input: dynamicInput, output: dynamicOutput,
    }, async (ctx, input) => analyzeData(input, ctx.signal)),
    margin: query({
      description: 'Read-only SQLite WASM margin by category over 50,000 deterministic synthetic retail orders. Returns compact chart-ready JSON, exact SQL and WASM provenance; cents are integers.',
      input: object({}), output: reportOutput,
    }, async () => analyze('margin')),
    inventory: query({
      description: 'Read-only SQLite WASM inventory exposure: 90-day synthetic sales versus fixed inventory snapshot. Returns 10 SKUs with lowest days cover, chart-ready JSON and provenance; not an inventory forecast.',
      input: object({}), output: reportOutput,
    }, async () => analyze('inventory')),
    outliers: query({
      description: 'Read-only SQLite WASM report of 10 lowest-margin synthetic orders, including injected return/discount anomalies. Returns chart-ready JSON and provenance.',
      input: object({}), output: reportOutput,
    }, async () => analyze('outliers')),
  }),
});
