import { afterEach, describe, expect, it, vi } from "vitest";
import { createDb, createLocalDb, createQueryHelpers } from "agent.pw/sql";
import { sql } from "drizzle-orm";
import { bootstrapLocalSchema } from "../packages/server/src/db/bootstrap-local";
import type { Database } from "../packages/server/src/db";
import { createTestDb } from "./setup";
import { errorOf, errorOfAsync, must } from "./support/results";

function failingSelect(error: unknown) {
  return {
    select() {
      return {
        from() {
          return {
            where() {
              throw error;
            },
          };
        },
      };
    },
  } as unknown as Database;
}

afterEach(() => {
  vi.resetModules();
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

describe("db coverage", () => {
  it("surfaces sql namespace validation errors from db entrypoints", async () => {
    expect(
      errorOf(
        createDb("postgres://user:pass@127.0.0.1:5432/agentpw", {
          sql: { schema: "bad-schema" },
        }),
      ).message,
    ).toBe("Invalid SQL schema 'bad-schema'");

    expect(
      (await errorOfAsync(
        createLocalDb("memory://", {
          sql: { schema: "bad-schema" },
        }),
      )).message,
    ).toBe("Invalid SQL schema 'bad-schema'");
  });

  it("surfaces bundled asset and import failures from createLocalDb", async () => {
    vi.stubEnv("AGENTPW_PGLITE_WASM_PATH", "/tmp/missing.wasm");
    vi.stubEnv("AGENTPW_PGLITE_DATA_PATH", "/tmp/missing.data");
    expect((await errorOfAsync(createLocalDb("memory://"))).message).toBe(
      "Failed to read bundled PGlite assets",
    );

    vi.resetModules();
    vi.doMock("@electric-sql/pglite", () => {
      throw new Error("pglite import failed");
    });
    const dbModule = await import("../packages/server/src/db/index");
    expect((await errorOfAsync(dbModule.createLocalDb("memory://"))).message).toBe(
      "Failed to load @electric-sql/pglite",
    );

    vi.resetModules();
    vi.unstubAllEnvs();
    vi.doUnmock("@electric-sql/pglite");
    vi.doMock("@electric-sql/pglite/contrib/ltree", () => {
      throw new Error("ltree import failed");
    });
    const ltreeModule = await import("../packages/server/src/db/index");
    expect((await errorOfAsync(ltreeModule.createLocalDb("memory://"))).message).toBe(
      "Failed to load @electric-sql/pglite ltree extension",
    );
  });

  it("validates existing local schemas before bootstrapping", async () => {
    const badProfileDb = {
      async execute() {
        return [{ udt_name: "text" }];
      },
    } as unknown as Database;
    expect((await errorOfAsync(bootstrapLocalSchema(badProfileDb))).message).toBe(
      "Credential profile path column must use ltree; recreate or migrate the local database before bootstrapping",
    );

    let calls = 0;
    const badCredentialDb = {
      async execute() {
        calls += 1;
        if (calls === 3) {
          return [{ udt_name: "ltree" }];
        }
        if (calls === 4) {
          return [{ udt_name: "text" }];
        }
        return [];
      },
    } as unknown as Database;
    expect((await errorOfAsync(bootstrapLocalSchema(badCredentialDb))).message).toBe(
      "Credential path column must use ltree; recreate or migrate the local database before bootstrapping",
    );

    expect(
      (await errorOfAsync(
        bootstrapLocalSchema(badCredentialDb, {
          sql: { schema: "bad-schema" },
        }),
      )).message,
    ).toBe("Invalid SQL schema 'bad-schema'");
  });

  it("maps query helper validation and database failures", async () => {
    expect(errorOf(createQueryHelpers({ schema: "bad-schema" })).message).toBe(
      "Invalid SQL schema 'bad-schema'",
    );

    const helpers = must(createQueryHelpers());
    expect(
      (
        await errorOfAsync(
          helpers.upsertCredential(failingSelect(new Error("unused")), {
            path: "org.docs",
            auth: { kind: "headers", resource: "not-a-url" },
            secret: Buffer.from("secret"),
          }),
        )
      ).message,
    ).toBe("Invalid resource 'not-a-url'");

    expect(
      (
        await errorOfAsync(helpers.getCredProfile(failingSelect(new Error("ltree syntax error")), "/"))
      ).message,
    ).toBe("Invalid path '/'");

    expect(
      (
        await errorOfAsync(
          helpers.getMatchingCredProfiles(
            {
              select() {
                return {
                  from() {
                    throw new Error("db failed");
                  },
                };
              },
            } as unknown as Database,
            "org.docs",
            "https://docs.example.com",
          ),
        )
      ).message,
    ).toBe("Database query failed");

    expect(
      (
        await errorOfAsync(
          helpers.moveCredential(failingSelect(new Error("db failed")), "org.docs", "org.docs.next"),
        )
      ).message,
    ).toBe("Database query failed");
  });

  it("returns resource-pattern and transaction failures from real helpers", async () => {
    const db = await createTestDb();
    const helpers = must(createQueryHelpers());

    await db.execute(sql.raw(`
      INSERT INTO agentpw.cred_profiles (path, resource_patterns, auth)
      VALUES (
        'org.broken'::ltree,
        '["/relative/*"]'::jsonb,
        '{"kind":"headers","fields":[{"name":"Authorization","label":"Token"}]}'::jsonb
      )
    `));

    expect(
      (await errorOfAsync(
        helpers.getMatchingCredProfiles(db, "org.docs", "https://docs.example.com"),
      )).message,
    ).toBe("Invalid resource pattern '/relative/*'");

    await db.execute(sql.raw(`
      INSERT INTO agentpw.credentials (path, auth, secret)
      VALUES ('org.docs'::ltree, '{"kind":"headers"}'::jsonb, decode('00', 'hex'))
    `));

    expect(await helpers.moveCredential(db, "missing.path", "next.path")).toEqual({
      ok: true,
      value: false,
    });

    const transactionFailureDb = {
      ...db,
      async transaction() {
        throw new Error("tx failed");
      },
    } as unknown as Database;
    expect(
      (
        await errorOfAsync(
          helpers.moveCredential(transactionFailureDb, "org.docs", "org.docs.next"),
        )
      ).message,
    ).toBe("Database query failed");
  });
});
