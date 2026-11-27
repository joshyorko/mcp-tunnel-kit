import { array, boolean, json, number, object, record, string } from 'apps';

export const reportOutput = object({
  report: string(),
  chart: object({ kind: string(), title: string(), x: string(), y: string() }),
  columns: array(string()), rows: array(record(json())),
  provenance: object({
    engine: string(), package: string(), framework: string(), wasmSha256: string(),
    wasmHashKind: string(), wasmInstance: boolean(), sqliteVersion: string(), memoryBytes: number(),
    datasetVersion: number(), seed: number(), orderRows: number(), inventoryRows: number(),
    queryOnly: boolean(), sql: string(),
  }),
});
