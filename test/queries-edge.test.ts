import { beforeEach, describe, expect, it } from "vitest";
import { createQueryHelpers } from "agent.pw/sql";
import {
  deriveEncryptionKey,
  encryptCredentials,
} from "../packages/server/src/lib/credentials-crypto";
import { BISCUIT_PRIVATE_KEY, createTestDb, type TestDb } from "./setup";
import { must, mustAsync, wrapObjectMethods } from "./support/results";

let db: TestDb;
const queries = wrapObjectMethods(must(createQueryHelpers()));

async function secret(token: string) {
  const encryptionKey = await mustAsync(deriveEncryptionKey(BISCUIT_PRIVATE_KEY));
  return mustAsync(
    encryptCredentials(encryptionKey, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }),
  );
}

beforeEach(async () => {
  db = await createTestDb();
});

describe("query edge cases", () => {
  it("normalizes stored resource patterns on write", async () => {
    await queries.upsertCredProfile(db, "docs", {
      resourcePatterns: [" https://docs.example.com/* "],
      auth: {
        kind: "headers",
        fields: [{ name: "Authorization", label: "Token", prefix: "Bearer " }],
      },
    });

    expect(await queries.getCredProfile(db, "docs")).toEqual(
      expect.objectContaining({
        resourcePatterns: ["https://docs.example.com/*"],
      }),
    );
    expect((await queries.listCredProfiles(db)).map((profile) => profile.path)).toEqual(["docs"]);
    expect(await queries.deleteCredProfile(db, "docs")).toBe(true);
    expect(await queries.deleteCredProfile(db, "docs")).toBe(false);
  });

  it("rejects invalid list paths and returns all rows when no path is provided", async () => {
    await queries.upsertCredential(db, {
      path: "acme.github",
      auth: { kind: "headers", resource: "https://api.github.com" },
      secret: await secret("gh"),
    });
    await queries.upsertCredential(db, {
      path: "acme.team.docs",
      auth: { kind: "oauth", resource: "https://docs.example.com/mcp" },
      secret: await secret("docs"),
    });
    await queries.upsertCredential(db, {
      path: "top",
      auth: { kind: "headers", resource: "https://top.example.com" },
      secret: await secret("top"),
    });

    await expect(queries.listCredProfiles(db, { path: "/../bad" })).rejects.toThrow("Invalid path '/../bad'");
    await expect(queries.listCredentials(db, { path: "/../bad" })).rejects.toThrow("Invalid path '/../bad'");

    expect((await queries.listCredentials(db)).map((row) => row.path)).toEqual([
      "acme.github",
      "acme.team.docs",
      "top",
    ]);
    expect((await queries.listCredentials(db, { path: "acme" })).map((row) => row.path)).toEqual([
      "acme.github",
    ]);
  });

  it("rejects malformed credential auth payloads before writing", async () => {
    await expect(
      Reflect.apply(queries.upsertCredential, queries, [
        db,
        {
          path: "bad.auth",
          auth: "broken",
          secret: await secret("bad"),
        },
      ]),
    ).rejects.toThrow("Invalid credential auth payload");
  });
});
