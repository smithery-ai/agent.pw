import { eq, like, type InferSelectModel } from "drizzle-orm";
import {
  canonicalizePath,
  credentialParentPath,
  isAncestorOrEqual,
  validatePath,
} from "../paths.js";
import {
  anyResourcePatternMatches,
  normalizeResource,
  normalizeResourcePattern,
} from "../resource-patterns.js";
import type { SqlNamespaceOptions } from "../types.js";
import type { Database } from "./index.js";
import {
  coerceSqlNamespace,
  type credentials,
  type credProfiles,
  type AgentPwSqlNamespace,
} from "./schema/index.js";

type DefaultCredProfileModel = InferSelectModel<typeof credProfiles>;
type DefaultCredentialModel = InferSelectModel<typeof credentials>;

type SqlNamespaceInput = SqlNamespaceOptions | AgentPwSqlNamespace;

export type CredProfileRow = DefaultCredProfileModel;
export type CredentialRow = DefaultCredentialModel;

function sortByDeepestPath<T extends { path: string }>(a: T, b: T) {
  const aDepth = a.path.split("/").filter(Boolean).length;
  const bDepth = b.path.split("/").filter(Boolean).length;
  return bDepth - aDepth || a.path.localeCompare(b.path);
}

function normalizeListPath(path: string | undefined) {
  const normalized = canonicalizePath(path ?? "/");
  if (!validatePath(normalized)) {
    throw new Error(`Invalid path '${path}'`);
  }
  return normalized;
}

function normalizeCredentialAuthRecord(auth: Record<string, unknown>) {
  const normalized = JSON.parse(JSON.stringify(auth));
  if (!normalized || typeof normalized !== "object" || Array.isArray(normalized)) {
    throw new Error("Invalid credential auth payload");
  }
  const resource = Reflect.get(normalized, "resource");
  if (typeof resource === "string") {
    Reflect.set(normalized, "resource", normalizeResource(resource));
  }
  return normalized;
}

export function createQueryHelpers(namespaceInput?: SqlNamespaceInput) {
  const sqlNamespace = coerceSqlNamespace(namespaceInput);
  const { credProfiles, credentials } = sqlNamespace.tables;

  async function getCredProfile(db: Database, path: string) {
    const rows = await db.select().from(credProfiles).where(eq(credProfiles.path, path));
    return rows[0] ?? null;
  }

  async function listCredProfiles(
    db: Database,
    options: {
      path?: string;
    } = {},
  ): Promise<CredProfileRow[]> {
    const path = normalizeListPath(options.path);
    const rows =
      path === "/"
        ? await db.select().from(credProfiles)
        : await db
            .select()
            .from(credProfiles)
            .where(like(credProfiles.path, `${path}/%`));

    return rows.sort((a, b) => a.path.localeCompare(b.path));
  }

  async function getMatchingCredProfiles(
    db: Database,
    path: string,
    resource: string,
  ): Promise<CredProfileRow[]> {
    const normalizedPath = canonicalizePath(path);
    const normalizedResource = normalizeResource(resource);
    const rows = await db.select().from(credProfiles);

    return rows
      .filter((profile) => {
        const profileScope = credentialParentPath(profile.path);
        return (
          isAncestorOrEqual(profileScope, normalizedPath) &&
          anyResourcePatternMatches(profile.resourcePatterns, normalizedResource)
        );
      })
      .sort(sortByDeepestPath);
  }

  async function upsertCredProfile(
    db: Database,
    path: string,
    data: {
      resourcePatterns: string[];
      auth: Record<string, unknown>;
      displayName?: string;
      description?: string;
    },
  ) {
    await db
      .insert(credProfiles)
      .values({
        path,
        resourcePatterns: data.resourcePatterns.map(normalizeResourcePattern),
        auth: data.auth,
        displayName: data.displayName ?? null,
        description: data.description ?? null,
      })
      .onConflictDoUpdate({
        target: credProfiles.path,
        set: {
          resourcePatterns: data.resourcePatterns.map(normalizeResourcePattern),
          auth: data.auth,
          displayName: data.displayName ?? null,
          description: data.description ?? null,
          updatedAt: new Date(),
        },
      });
  }

  async function deleteCredProfile(db: Database, path: string) {
    const deleted = await db.delete(credProfiles).where(eq(credProfiles.path, path)).returning();
    return deleted.length > 0;
  }

  async function getCredential(db: Database, path: string) {
    const rows = await db.select().from(credentials).where(eq(credentials.path, path));
    return rows[0] ?? null;
  }

  async function listCredentials(
    db: Database,
    options: {
      path?: string;
    } = {},
  ): Promise<CredentialRow[]> {
    const path = normalizeListPath(options.path);
    const rows =
      path === "/"
        ? await db.select().from(credentials)
        : await db
            .select()
            .from(credentials)
            .where(like(credentials.path, `${path}/%`));

    return rows
      .filter((row) => credentialParentPath(row.path) === path)
      .sort((a, b) => a.path.localeCompare(b.path));
  }

  async function upsertCredential(
    db: Database,
    data: {
      path: string;
      auth: Record<string, unknown>;
      secret: Buffer;
    },
  ) {
    await db
      .insert(credentials)
      .values({
        path: data.path,
        auth: normalizeCredentialAuthRecord(data.auth),
        secret: data.secret,
      })
      .onConflictDoUpdate({
        target: credentials.path,
        set: {
          auth: normalizeCredentialAuthRecord(data.auth),
          secret: data.secret,
          updatedAt: new Date(),
        },
      });
  }

  async function moveCredential(db: Database, fromPath: string, toPath: string) {
    const row = await getCredential(db, fromPath);
    if (!row) {
      return false;
    }

    await db.transaction(async (tx) => {
      await tx.delete(credentials).where(eq(credentials.path, fromPath));
      await tx.insert(credentials).values({
        path: toPath,
        auth: row.auth,
        secret: row.secret,
        createdAt: row.createdAt,
        updatedAt: new Date(),
      });
    });

    return true;
  }

  async function deleteCredential(db: Database, path: string) {
    const deleted = await db.delete(credentials).where(eq(credentials.path, path)).returning();
    return deleted.length > 0;
  }

  return {
    getCredProfile,
    listCredProfiles,
    getMatchingCredProfiles,
    upsertCredProfile,
    deleteCredProfile,
    getCredential,
    listCredentials,
    upsertCredential,
    moveCredential,
    deleteCredential,
  };
}
