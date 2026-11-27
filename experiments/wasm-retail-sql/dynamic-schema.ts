import { jsonSchema, object, array, string, json, number, boolean } from 'apps';

export const dynamicInput = jsonSchema({
  type: 'object', additionalProperties: false, required: ['columns', 'rows', 'sql'],
  properties: {
    columns: { type: 'array', minItems: 1, maxItems: 8, items: {
      type: 'object', additionalProperties: false, required: ['name', 'type'], properties: {
        name: { type: 'string', pattern: '^[a-z][a-z0-9_]{0,23}$', maxLength: 24 },
        type: { type: 'string', enum: ['text', 'number'] },
      },
    } },
    rows: { type: 'array', minItems: 1, maxItems: 1000, items: {
      type: 'array', minItems: 1, maxItems: 8, items: { anyOf: [
        { type: 'string', maxLength: 256 }, { type: 'number', minimum: -1000000000, maximum: 1000000000 }, { type: 'null' },
      ] },
    } },
    sql: { type: 'string', minLength: 1, maxLength: 1024 },
  },
});

export const dynamicOutput = object({
  columns: array(string()), rows: array(array(json())),
  provenance: object({
    engine: string(), sqliteVersion: string(), wasmSha256: string(), wasmHashKind: string(),
    wasmInstance: boolean(), queryOnly: boolean(), authorizer: string(),
    inputRows: number(), inputColumns: number(), inputBytes: number(), memoryBytes: number(),
    sql: string(), parameters: array(json()), cpuGuard: string(), cancellation: string(),
  }),
});
