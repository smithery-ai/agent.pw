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

async function encryptedHeaders(token: string) {
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

describe("query layer", () => {
  it("resolves matching profiles by path depth and resource pattern", async () => {
    await queries.upsertCredProfile(db, "github", {
      resourcePatterns: ["https://api.github.com/*"],
      auth: {
        kind: "oauth",
        clientId: "global-client",
        authorizationUrl: "https://github.com/login/oauth/authorize",
        tokenUrl: "https://github.com/login/oauth/access_token",
      },
      displayName: "GitHub",
    });
    await queries.upsertCredProfile(db, "acme.github", {
      resourcePatterns: ["https://api.github.com/*"],
      auth: {
        kind: "headers",
        fields: [{ name: "Authorization", label: "Token", prefix: "Bearer " }],
      },
      displayName: "Acme GitHub",
    });
    await queries.upsertCredProfile(db, "acme.team.github", {
      resourcePatterns: ["https://api.github.com/repos/*"],
      auth: {
        kind: "headers",
        fields: [{ name: "Authorization", label: "Team token", prefix: "Bearer " }],
      },
      displayName: "Team GitHub",
    });

    expect(await queries.getCredProfile(db, "github")).toEqual(
      expect.objectContaining({
        path: "github",
        resourcePatterns: ["https://api.github.com/*"],
      }),
    );

    expect(
      (
        await queries.getMatchingCredProfiles(
          db,
          "acme.team.connections.docs",
          "https://api.github.com/repos/acme/app",
        )
      ).map((profile) => profile.path),
    ).toEqual(["acme.team.github", "acme.github", "github"]);

    expect(
      (
        await queries.getMatchingCredProfiles(
          db,
          "beta.docs",
          "https://api.github.com/repos/acme/app",
        )
      ).map((profile) => profile.path),
    ).toEqual(["github"]);

    expect(await queries.getMatchingCredProfiles(db, "beta.docs", "https://gitlab.com/api/v4")).toEqual(
      [],
    );
    expect((await queries.listCredProfiles(db, { path: "acme" })).map((profile) => profile.path)).toEqual([
      "acme.github",
    ]);
    expect((await queries.listCredProfiles(db)).map((profile) => profile.path)).toEqual([
      "acme.github",
      "acme.team.github",
      "github",
    ]);
  });

  it("stores credentials by exact path and lists direct children only under a concrete path", async () => {
    await queries.upsertCredential(db, {
      path: "acme.connections.github",
      auth: { kind: "headers", label: "GitHub", resource: "https://api.github.com" },
      secret: await encryptedHeaders("github-token"),
    });
    await queries.upsertCredential(db, {
      path: "acme.connections.team.docs",
      auth: { kind: "oauth", label: "Docs", resource: "https://docs.example.com/mcp" },
      secret: await encryptedHeaders("docs-token"),
    });
    await queries.upsertCredential(db, {
      path: "acme.elsewhere.notion",
      auth: { kind: "headers", label: "Notion", resource: "https://api.notion.com" },
      secret: await encryptedHeaders("notion-token"),
    });

    expect(await queries.getCredential(db, "acme.connections.github")).toEqual(
      expect.objectContaining({
        path: "acme.connections.github",
        auth: expect.objectContaining({
          resource: "https://api.github.com/",
        }),
      }),
    );

    expect(
      (await queries.listCredentials(db, { path: "acme.connections" })).map((row) => row.path),
    ).toEqual(["acme.connections.github"]);
    expect(
      (await queries.listCredentials(db, { path: "acme.connections.team" })).map(
        (row) => row.path,
      ),
    ).toEqual(["acme.connections.team.docs"]);
    expect((await queries.listCredentials(db)).map((row) => row.path)).toEqual([
      "acme.connections.github",
      "acme.connections.team.docs",
      "acme.elsewhere.notion",
    ]);

    expect(
      await queries.moveCredential(
        db,
        "acme.connections.github",
        "acme.connections.github_primary",
      ),
    ).toBe(true);
    expect(
      await queries.moveCredential(
        db,
        "acme.connections.github",
        "acme.connections.github_secondary",
      ),
    ).toBe(false);
    expect(await queries.deleteCredential(db, "acme.connections.github_primary")).toBe(true);
    expect(await queries.deleteCredential(db, "acme.connections.github_primary")).toBe(false);
  });

  it("recursively deletes credentials under a path", async () => {
    await queries.upsertCredential(db, {
      path: "org.a",
      auth: { kind: "headers", resource: "https://a.example.com" },
      secret: await encryptedHeaders("a"),
    });
    await queries.upsertCredential(db, {
      path: "org.b",
      auth: { kind: "headers", resource: "https://b.example.com" },
      secret: await encryptedHeaders("b"),
    });
    await queries.upsertCredential(db, {
      path: "org.b.nested",
      auth: { kind: "headers", resource: "https://nested.example.com" },
      secret: await encryptedHeaders("nested"),
    });
    await queries.upsertCredential(db, {
      path: "other.cred",
      auth: { kind: "headers", resource: "https://other.example.com" },
      secret: await encryptedHeaders("other"),
    });

    expect(await queries.deleteCredential(db, "org", { recursive: true })).toBe(true);
    expect(await queries.getCredential(db, "org.a")).toBeNull();
    expect(await queries.getCredential(db, "org.b")).toBeNull();
    expect(await queries.getCredential(db, "org.b.nested")).toBeNull();
    expect(await queries.getCredential(db, "other.cred")).not.toBeNull();
  });

  it("recursively deletes profiles under a path", async () => {
    await queries.upsertCredProfile(db, "org.github", {
      resourcePatterns: ["https://api.github.com/*"],
      auth: { kind: "oauth" },
    });
    await queries.upsertCredProfile(db, "org.slack", {
      resourcePatterns: ["https://slack.com/api/*"],
      auth: { kind: "headers", fields: [] },
    });
    await queries.upsertCredProfile(db, "other.profile", {
      resourcePatterns: ["https://other.example.com/*"],
      auth: { kind: "headers", fields: [] },
    });

    expect(await queries.deleteCredProfile(db, "org", { recursive: true })).toBe(true);
    expect(await queries.getCredProfile(db, "org.github")).toBeNull();
    expect(await queries.getCredProfile(db, "org.slack")).toBeNull();
    expect(await queries.getCredProfile(db, "other.profile")).not.toBeNull();
  });

  it("non-recursive delete only removes exact path", async () => {
    await queries.upsertCredential(db, {
      path: "parent.child",
      auth: { kind: "headers", resource: "https://child.example.com" },
      secret: await encryptedHeaders("child"),
    });

    expect(await queries.deleteCredential(db, "parent")).toBe(false);
    expect(await queries.getCredential(db, "parent.child")).not.toBeNull();
  });
});
