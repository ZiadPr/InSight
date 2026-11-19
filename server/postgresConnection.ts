import { AsyncLocalStorage } from "node:async_hooks";
import { sql } from "drizzle-orm";
import { getDb } from "../db/index.js";

export interface PostgresStatement {
  run(...args: unknown[]): Promise<{ changes: number }>;
  get(...args: unknown[]): Promise<any>;
  all(...args: unknown[]): Promise<any[]>;
}

/** Parameterized SQL bridge for the existing attendance repository. */
export function bindStatement(query: string, args: unknown[]) {
  const values: unknown[] = [];
  const named = args.length === 1 && args[0] !== null && typeof args[0] === "object" && !Array.isArray(args[0])
    ? args[0] as Record<string, unknown> : null;
  let position = 0;
  // Quoted SQL literals are kept verbatim; only unquoted placeholders are bound.
  const text = query.replace(/'(?:''|[^'])*'|@[a-z_][a-z_0-9]*|\?/gi, (token) => {
    if (token.startsWith("'")) return token;
    values.push(token === "?" ? args[position++] : named?.[token.slice(1)]);
    return `$${values.length}`;
  });
  return { text, values };
}

export interface QueryResult { rows: Record<string, unknown>[]; rowCount?: number | null; affectedRows?: number; }
export interface QueryExecutor { execute(query: ReturnType<typeof sql>): Promise<QueryResult>; }
export interface TransactionExecutor extends QueryExecutor {
  transaction<T>(callback: (tx: QueryExecutor) => Promise<T>): Promise<T>;
}
export class PostgresConnection {
  private context = new AsyncLocalStorage<QueryExecutor>();
  constructor(private database?: TransactionExecutor) {}
  private get databaseClient(): TransactionExecutor { return this.database ?? getDb() as TransactionExecutor; }

  prepare(query: string): PostgresStatement {
    const execute = async (args: unknown[]) => {
      const bound = bindStatement(query, args);
      // Drizzle constructs driver parameters instead of interpolating values into SQL.
      const chunks = bound.text.split(/(\$\d+)/g).map((part) => /^\$\d+$/.test(part)
        ? sql`${bound.values[Number(part.slice(1)) - 1]}` : sql.raw(part));
      const result = await (this.context.getStore() ?? this.databaseClient).execute(sql.join(chunks, sql.raw("")));
      // pg returns int8 aggregates as strings. These fields are numeric in the API.
      for (const row of result.rows as Record<string, unknown>[]) {
        for (const key of ["cnt", "checked_in_today", "on_shift_now", "checked_out_today", "late_today", "excused_today", "accounted_active", "exp_ms"]) {
          if (typeof row[key] === "string") row[key] = Number(row[key]);
        }
      }
      return result;
    };
    return {
      run: async (...args) => {
        const result = await execute(args);
        return { changes: result.rowCount ?? result.affectedRows ?? 0 };
      },
      get: async (...args) => (await execute(args)).rows[0],
      all: async (...args) => (await execute(args)).rows,
    };
  }

  transaction<T>(callback: () => Promise<T>): () => Promise<T> {
    return async () => {
      if (this.context.getStore()) return callback();
      return this.databaseClient.transaction(async (tx) => this.context.run(tx, async () => {
        // Serialize repository transactions across all instances, including first boot
        // and competing QR scans, to preserve the original single-writer semantics.
        await tx.execute(sql`SELECT pg_advisory_xact_lock(742916080)`);
        return callback();
      }));
    };
  }
}
