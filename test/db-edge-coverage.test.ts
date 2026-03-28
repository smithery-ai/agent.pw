import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sql } from "drizzle-orm";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createDb, createLocalDb, createQueryHelpers } from "agent.pw/sql";
import { bootstrapLocalSchema } from "../packages/server/src/db/bootstrap-local";
import { createTestDb } from "./setup";
import { errorOf, must, mustAsync } from "./support/results";

const tempDirs = new Set<string>();

async function createTempDir(prefix: string) {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  tempDirs.add(dir);
  return dir;
}

async function closeLocalDb(db: unknown) {
  await (db as { $client?: { close?: () => Promise<void> } } | undefined)?.$client?.close?.();
}

afterEach(async () => {
  vi.restoreAllMocks();
  vi.resetModules();
  vi.unstubAllEnvs();
  vi.doUnmock("@electric-sql/pglite");
  vi.doUnmock("@electric-sql/pglite/contrib/ltree");

  for (const dir of tempDirs) {
    await rm(dir, { recursive: true, force: true });
  }
  tempDirs.clear();
});

describe("db edge coverage", () => {
  it("rejects invalid SQL namespaces across the db entrypoints", async () => {
    expect(
      errorOf(createDb("postgres://user:pass@127.0.0.1:5432/agentpw", { sql: { schema: "-" } })),
    ).toEqual(
      expect.objectContaining({
        type: "Input",
        message: "Invalid SQL schema '-'",
      }),
    );
    expect(errorOf(createQueryHelpers({ schema: "-" })).message).toBe("Invalid SQL schema '-'");

    const dir = await createTempDir("agentpw-db-edge-");
    expect(errorOf(await createLocalDb(dir, { sql: { schema: "-" } })).message).toBe(
      "Invalid SQL schema '-'",
    );

    const db = await createTestDb();
    expect(errorOf(await bootstrapLocalSchema(db, { sql: { schema: "-" } })).message).toBe(
      "Invalid SQL schema '-'",
    );
    await closeLocalDb(db);
  });

  it("surfaces bundled asset and module import failures", async () => {
    const missingAssetDir = await createTempDir("agentpw-db-assets-");
    vi.stubEnv("AGENTPW_PGLITE_WASM_PATH", "/tmp/missing-postgres.wasm");
    vi.stubEnv("AGENTPW_PGLITE_DATA_PATH", "/tmp/missing-postgres.data");
    expect(errorOf(await createLocalDb(missingAssetDir)).message).toBe(
      "Failed to read bundled PGlite assets",
    );
    vi.unstubAllEnvs();

    vi.doMock("@electric-sql/pglite", () => {
      throw new Error("mock pglite import failure");
    });
    const dbIndexWithBrokenPglite = await import("../packages/server/src/db/index");
    const brokenImportDir = await createTempDir("agentpw-db-import-");
    expect(errorOf(await dbIndexWithBrokenPglite.createLocalDb(brokenImportDir)).message).toBe(
      "Failed to load @electric-sql/pglite",
    );

    vi.resetModules();
    vi.doUnmock("@electric-sql/pglite");
    vi.doMock("@electric-sql/pglite/contrib/ltree", () => {
      throw new Error("mock ltree import failure");
    });
    const dbIndexWithBrokenLtree = await import("../packages/server/src/db/index");
    const brokenLtreeDir = await createTempDir("agentpw-db-ltree-");
    expect(errorOf(await dbIndexWithBrokenLtree.createLocalDb(brokenLtreeDir)).message).toBe(
      "Failed to load @electric-sql/pglite ltree extension",
    );
  });

  it("validates pre-existing path columns before bootstrapping", async () => {
    let profileDb: unknown;
    const profileDir = await createTempDir("agentpw-db-bootstrap-profile-");
    try {
      profileDb = await mustAsync(createLocalDb(profileDir));
      await profileDb.execute(sql.raw("CREATE EXTENSION IF NOT EXISTS ltree"));
      await profileDb.execute(sql.raw("CREATE SCHEMA IF NOT EXISTS agentpw"));
      await profileDb.execute(
        sql.raw('CREATE TABLE agentpw."cred_profiles" (path text PRIMARY KEY)'),
      );

      expect(errorOf(await bootstrapLocalSchema(profileDb)).message).toBe(
        "Credential profile path column must use ltree; recreate or migrate the local database before bootstrapping",
      );
    } finally {
      await closeLocalDb(profileDb);
    }

    let credentialDb: unknown;
    const credentialDir = await createTempDir("agentpw-db-bootstrap-credential-");
    try {
      credentialDb = await mustAsync(createLocalDb(credentialDir));
      await credentialDb.execute(sql.raw("CREATE EXTENSION IF NOT EXISTS ltree"));
      await credentialDb.execute(sql.raw("CREATE SCHEMA IF NOT EXISTS agentpw"));
      await credentialDb.execute(
        sql.raw('CREATE TABLE agentpw."credentials" (path text PRIMARY KEY)'),
      );

      expect(errorOf(await bootstrapLocalSchema(credentialDb)).message).toBe(
        "Credential path column must use ltree; recreate or migrate the local database before bootstrapping",
      );
    } finally {
      await closeLocalDb(credentialDb);
    }
  }, 15_000);

  it("covers query helper validation and database error mapping", async () => {
    const db = await createTestDb();
    const helpers = must(createQueryHelpers());

    expect(errorOf(await helpers.listCredProfiles(db, { path: "/../bad" })).message).toBe(
      "Invalid path '/../bad'",
    );
    expect(errorOf(await helpers.listCredentials(db, { path: "/../bad" })).message).toBe(
      "Invalid path '/../bad'",
    );
    expect(
      errorOf(await helpers.getMatchingCredProfiles(db, "org.docs", "not-a-url")).message,
    ).toBe("Invalid resource 'not-a-url'");
    expect(
      errorOf(
        await helpers.upsertCredProfile(db, "github", {
          resourcePatterns: ["/relative/*"],
          auth: { kind: "headers", fields: [] },
        }),
      ).message,
    ).toBe("Invalid resource pattern '/relative/*'");

    await db.execute(
      sql.raw(`
      INSERT INTO agentpw.cred_profiles (path, resource_patterns, auth)
      VALUES ('org.broken'::ltree, '["/relative/*"]'::jsonb, '{"kind":"headers","fields":[]}'::jsonb)
    `),
    );
    expect(
      errorOf(await helpers.getMatchingCredProfiles(db, "org.docs", "https://example.com/resource"))
        .message,
    ).toBe("Invalid resource pattern '/relative/*'");

    expect(errorOf(await helpers.getCredProfile(db, "/bad")).message).toBe("Invalid path '/bad'");

    await helpers.upsertCredential(db, {
      path: "org.docs",
      auth: { kind: "headers", resource: "https://docs.example.com" },
      secret: Buffer.from("secret"),
    });
    expect(await helpers.moveCredential(db, "missing.path", "org.next")).toEqual({
      ok: true,
      value: false,
    });

    await closeLocalDb(db);

    let bareDb: unknown;
    const bareDir = await createTempDir("agentpw-db-bare-");
    try {
      bareDb = await mustAsync(createLocalDb(bareDir));
      expect(
        errorOf(await helpers.getMatchingCredProfiles(bareDb, "org.docs", "https://example.com"))
          .message,
      ).toBe("Database query failed");
    } finally {
      await closeLocalDb(bareDb);
    }
  });

  it("supports the postgres-js style column lookup shape during bootstrap", async () => {
    const execute = vi
      .fn()
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([{ udt_name: "ltree" }])
      .mockResolvedValueOnce([{ udt_name: "ltree" }])
      .mockResolvedValue([]);

    const bootstrapped = await bootstrapLocalSchema({ execute } as never);
    expect(bootstrapped.ok).toBe(true);
    expect(execute).toHaveBeenCalled();
  });
});
