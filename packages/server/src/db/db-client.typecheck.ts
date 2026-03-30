import type { PgDatabase, PgQueryResultHKT, PgTransaction } from "drizzle-orm/pg-core";
import { pgTable, text } from "drizzle-orm/pg-core";
import type { TablesRelationalConfig } from "drizzle-orm/relations";
import { drizzle as drizzlePg } from "drizzle-orm/postgres-js";
import type { CrudOptions } from "../types.js";
import type { Database, DbClient, Transaction } from "./index.js";
import { schemaTables } from "./schema/index.js";

const consumerAccounts = pgTable("consumer_accounts", {
  id: text("id").notNull(),
});

const consumerDb = drizzlePg.mock({
  schema: {
    ...schemaTables,
    consumerAccounts,
  },
});
type ConsumerSchema = typeof consumerDb._.fullSchema;

const _database: Database = consumerDb;
const _client: DbClient = consumerDb;
declare const genericDb: PgDatabase<PgQueryResultHKT, ConsumerSchema, TablesRelationalConfig>;
declare const genericTx: PgTransaction<PgQueryResultHKT, ConsumerSchema, TablesRelationalConfig>;

const _genericDatabase: Database = genericDb;
const _genericClient: DbClient = genericTx;

void consumerDb.transaction(async (tx) => {
  const _transaction: Transaction = tx;
  const _options: CrudOptions = { db: tx };
  return tx;
});

const _genericOptions: CrudOptions = { db: genericTx };
