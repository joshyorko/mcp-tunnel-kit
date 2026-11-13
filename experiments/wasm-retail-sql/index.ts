import { defineApp, query, object, router } from 'apps';
import { analyze } from './engine.js';
import { reportOutput } from './output.js';

export default defineApp({ accounts: {} }, {
  tools: router({
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
