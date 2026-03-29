import { PGlite } from "@electric-sql/pglite";
import { ltree } from "@electric-sql/pglite/contrib/ltree";
import { drizzle } from "drizzle-orm/pglite";
import * as schema from "../packages/server/src/db/schema/index";
import { bootstrapLocalSchema } from "../packages/server/src/db/bootstrap-local";
import { mustAsync } from "./support/results";

export const TEST_KEY_MATERIAL =
  "ed25519-private/20cbf8e88a4d258a2af3b2ab1132ae6f753e46893eaea2427f732feefba7a8ad";

export async function createTestDb() {
  const db = drizzle(new PGlite({ dataDir: "memory://", extensions: { ltree } }), { schema });
  await mustAsync(bootstrapLocalSchema(db));

  return db;
}

export type TestDb = Awaited<ReturnType<typeof createTestDb>>;
