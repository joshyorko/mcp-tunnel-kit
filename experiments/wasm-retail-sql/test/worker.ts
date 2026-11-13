import { analyze, openDatabase } from '../engine.js';

export default {
  async fetch(request: Request) {
    const path = new URL(request.url).pathname;
    if (path === '/guards') {
      const db = await openDatabase();
      let writesRefused = 0;
      try {
        for (const sql of ['DELETE FROM orders', 'DROP TABLE inventory', 'UPDATE orders SET units=0']) {
          try { db.run(sql); } catch { writesRefused++; }
        }
      } finally { db.close(); }
      let unknownReportRefused = false;
      // @ts-expect-error Deliberately exercise an untyped malicious caller.
      try { await analyze('SELECT randomblob(1000000000)'); } catch { unknownReportRefused = true; }
      return Response.json({ writesRefused, unknownReportRefused });
    }
    switch (path) {
      case '/margin': return Response.json(await analyze('margin'));
      case '/inventory': return Response.json(await analyze('inventory'));
      case '/outliers': return Response.json(await analyze('outliers'));
      default: return new Response('Not found', { status: 404 });
    }
  },
};
