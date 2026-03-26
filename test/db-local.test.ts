import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { sql } from "drizzle-orm";
import { createAgentPwSchema, createDb, createLocalDb, createQueryHelpers } from "agent.pw/sql";
import { bootstrapLocalSchema } from "../packages/server/src/db/bootstrap-local";
import { must, mustAsync, wrapObjectMethods } from "./support/results";

async function closeLocalDb(db: unknown) {
  await (db as { $client?: { close?: () => Promise<void> } }).$client?.close?.();
}

describe("db entrypoints", () => {
  it("creates postgres-js and local PGlite database handles", async () => {
    const remoteDb = must(createDb("postgres://user:pass@127.0.0.1:5432/agentpw"));
    expect(typeof remoteDb.execute).toBe("function");

    let localDb: unknown;
    const dataDir = await mkdtemp(join(tmpdir(), "agentpw-pglite-"));
    try {
      localDb = await mustAsync(createLocalDb(dataDir));
      const result = await localDb.execute(sql`select 1 as value`);
      expect(result.rows).toEqual([{ value: 1 }]);
    } finally {
      await closeLocalDb(localDb);
      await rm(dataDir, { recursive: true, force: true });
    }
  });

  it("bootstraps the default schema", async () => {
    let db: unknown;
    const dataDir = await mkdtemp(join(tmpdir(), "agentpw-migrate-"));
    try {
      db = await mustAsync(createLocalDb(dataDir));
      await bootstrapLocalSchema(db);

      const result = await db.execute(sql`
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'agentpw'
        ORDER BY table_name
      `);

      expect(result.rows.map((row) => row.table_name)).toEqual(["cred_profiles", "credentials"]);
    } finally {
      await closeLocalDb(db);
      await rm(dataDir, { recursive: true, force: true });
    }
  });

  it("supports custom SQL schemas and table prefixes for embedders", async () => {
    const sqlNamespace = must(
      createAgentPwSchema({
        schema: "connect_data",
        tablePrefix: "smithery_",
      }),
    );
    const remoteDb = must(
      createDb("postgres://user:pass@127.0.0.1:5432/agentpw", {
        sql: sqlNamespace,
      }),
    );
    expect(typeof remoteDb.execute).toBe("function");

    const queries = wrapObjectMethods(must(createQueryHelpers(sqlNamespace)));
    let db: unknown;
    const dataDir = await mkdtemp(join(tmpdir(), "agentpw-custom-schema-"));
    try {
      db = await mustAsync(
        createLocalDb(dataDir, {
          sql: sqlNamespace,
        }),
      );
      await bootstrapLocalSchema(db, {
        sql: sqlNamespace,
      });

      await queries.upsertCredProfile(db, "/github", {
        resourcePatterns: ["https://api.github.com/*"],
        auth: {
          kind: "headers",
          fields: [{ name: "Authorization", label: "Token", prefix: "Bearer " }],
        },
      });
      expect(await queries.getCredProfile(db, "/github")).toEqual(
        expect.objectContaining({
          path: "/github",
          resourcePatterns: ["https://api.github.com/*"],
        }),
      );

      const result = await db.execute(sql`
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'connect_data'
        ORDER BY table_name
      `);

      expect(result.rows.map((row) => row.table_name)).toEqual([
        "smithery_cred_profiles",
        "smithery_credentials",
      ]);
    } finally {
      await closeLocalDb(db);
      await rm(dataDir, { recursive: true, force: true });
    }
  });

  it("migrates legacy credential resources into auth metadata for local schemas", async () => {
    let db: unknown;
    const dataDir = await mkdtemp(join(tmpdir(), "agentpw-legacy-resource-"));
    try {
      db = await mustAsync(createLocalDb(dataDir));
      await db.execute(sql`CREATE SCHEMA IF NOT EXISTS agentpw`);
      await db.execute(
        sql.raw(`
        CREATE TABLE IF NOT EXISTS agentpw.credentials (
          path TEXT PRIMARY KEY,
          resource TEXT NOT NULL DEFAULT '',
          auth JSONB NOT NULL,
          secret BYTEA NOT NULL,
          created_at TIMESTAMP NOT NULL DEFAULT now(),
          updated_at TIMESTAMP NOT NULL DEFAULT now()
        )
      `),
      );
      await db.execute(
        sql.raw(`
        INSERT INTO agentpw.credentials (path, resource, auth, secret)
        VALUES (
          '/acme/connections/legacy',
          'https://api.github.com',
          '{"kind":"headers","label":"Legacy"}'::jsonb,
          '\\x00'::bytea
        )
      `),
      );

      await bootstrapLocalSchema(db);

      const authResult = await db.execute(
        sql.raw(`
        SELECT auth->>'resource' AS resource
        FROM agentpw.credentials
        WHERE path = '/acme/connections/legacy'
      `),
      );
      expect(authResult.rows).toEqual([{ resource: "https://api.github.com" }]);

      const columnResult = await db.execute(
        sql.raw(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'agentpw'
          AND table_name = 'credentials'
        ORDER BY column_name
      `),
      );
      expect(columnResult.rows.map((row) => row.column_name)).not.toContain("resource");
    } finally {
      await closeLocalDb(db);
      await rm(dataDir, { recursive: true, force: true });
    }
  });
});
