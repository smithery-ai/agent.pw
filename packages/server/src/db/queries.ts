import { err, ok, result, type Result } from "okay-error";
import { and, eq, sql, type InferSelectModel } from "drizzle-orm";
import { inputError, internalError } from "../errors.js";
import { isRecord } from "../lib/utils.js";
import {
  assertOptionalPath,
  assertPath,
  credentialParentPath,
  isAncestorOrEqual,
  pathDepth,
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
  type AgentPwSqlNamespace,
  type credentials,
  type credProfiles,
} from "./schema/index.js";

type DefaultCredProfileModel = InferSelectModel<typeof credProfiles>;
type DefaultCredentialModel = InferSelectModel<typeof credentials>;
type SqlNamespaceInput = SqlNamespaceOptions | AgentPwSqlNamespace;

export type CredProfileRow = DefaultCredProfileModel;
export type CredentialRow = DefaultCredentialModel;

interface QueryHelpers {
  getCredProfile(db: Database, path: string): Promise<Result<CredProfileRow | null>>;
  listCredProfiles(
    db: Database,
    options?: {
      path?: string;
    },
  ): Promise<Result<CredProfileRow[]>>;
  getMatchingCredProfiles(
    db: Database,
    path: string,
    resource: string,
  ): Promise<Result<CredProfileRow[]>>;
  upsertCredProfile(
    db: Database,
    path: string,
    data: {
      resourcePatterns: string[];
      auth: Record<string, unknown>;
      displayName?: string;
      description?: string;
    },
  ): Promise<Result<void>>;
  deleteCredProfile(
    db: Database,
    path: string,
    options?: { recursive?: boolean },
  ): Promise<Result<boolean>>;
  getCredential(db: Database, path: string): Promise<Result<CredentialRow | null>>;
  listCredentials(
    db: Database,
    options?: {
      path?: string;
    },
  ): Promise<Result<CredentialRow[]>>;
  upsertCredential(
    db: Database,
    data: {
      path: string;
      auth: Record<string, unknown>;
      secret: Buffer;
    },
  ): Promise<Result<void>>;
  moveCredential(db: Database, fromPath: string, toPath: string): Promise<Result<boolean>>;
  deleteCredential(
    db: Database,
    path: string,
    options?: { recursive?: boolean },
  ): Promise<Result<boolean>>;
}

function sortByDeepestPath<T extends { path: string }>(a: T, b: T) {
  return pathDepth(b.path) - pathDepth(a.path) || a.path.localeCompare(b.path);
}

function normalizeCredentialAuthRecord(auth: Record<string, unknown>) {
  const normalized = result(() => JSON.parse(JSON.stringify(auth)));
  if (!normalized.ok || !isRecord(normalized.value)) {
    return err(inputError("Invalid credential auth payload"));
  }

  const resource = normalized.value.resource;
  if (typeof resource === "string") {
    const normalizedResource = normalizeResource(resource);
    if (!normalizedResource.ok) {
      return normalizedResource;
    }
    normalized.value.resource = normalizedResource.value;
  }

  const profilePath = normalized.value.profilePath;
  if (typeof profilePath === "string") normalized.value.profilePath = profilePath;

  return ok(normalized.value);
}

function isLtreeSyntaxError(error: unknown) {
  if (
    typeof error === "object" &&
    error !== null &&
    "cause" in error &&
    isLtreeSyntaxError(error.cause)
  ) {
    return true;
  }

  return (
    typeof error === "object" &&
    error !== null &&
    "message" in error &&
    typeof error.message === "string" &&
    error.message.includes("ltree syntax error")
  );
}

function mapDbError(source: string, error: unknown, path?: { label: string; value: string }) {
  if (path && isLtreeSyntaxError(error)) {
    return inputError(`Invalid ${path.label} '${path.value}'`, {
      field: path.label,
      value: path.value,
    });
  }

  return internalError("Database query failed", {
    cause: error,
    ...(path ? { path: path.value } : {}),
    source,
  });
}

async function runDb<T>(
  source: string,
  fn: () => Promise<T>,
  path?: { label: string; value: string },
): Promise<Result<T>> {
  try {
    return ok(await fn());
  } catch (error) {
    return err(mapDbError(source, error, path));
  }
}

function directChildrenWhere(pathColumn: { getSQL(): unknown }, path: string) {
  const depth = pathDepth(path);
  return and(
    sql<boolean>`nlevel(${pathColumn}) = ${depth + 1}`,
    sql<boolean>`subpath(${pathColumn}, 0, ${depth}) = ${path}::ltree`,
  );
}

export function createQueryHelpers(namespaceInput?: SqlNamespaceInput) {
  const sqlNamespace = coerceSqlNamespace(namespaceInput);
  if (!sqlNamespace.ok) {
    return sqlNamespace;
  }

  const { credProfiles, credentials } = sqlNamespace.value.tables;

  const helpers: QueryHelpers = {
    async getCredProfile(db, path) {
      return runDb(
        "db.getCredProfile",
        async () => (await db.select().from(credProfiles).where(eq(credProfiles.path, path)))[0] ?? null,
        { label: "path", value: path },
      );
    },

    async listCredProfiles(db, options = {}) {
      const path = assertOptionalPath(options.path, "path");
      if (!path.ok) {
        return path;
      }

      return runDb(
        "db.listCredProfiles",
        async () => {
          const rows =
            path.value === undefined
              ? await db.select().from(credProfiles)
              : await db
                  .select()
                  .from(credProfiles)
                  .where(directChildrenWhere(credProfiles.path, path.value));
          return rows.sort((a, b) => a.path.localeCompare(b.path));
        },
        path.value === undefined ? undefined : { label: "path", value: path.value },
      );
    },

    async getMatchingCredProfiles(db, path, resource) {
      const normalizedResource = normalizeResource(resource);
      if (!normalizedResource.ok) {
        return normalizedResource;
      }

      const normalizedPath = assertPath(path, "path");
      if (!normalizedPath.ok) {
        return normalizedPath;
      }
      const rowsResult = await runDb("db.getMatchingCredProfiles", async () =>
        db.select().from(credProfiles),
      );
      if (!rowsResult.ok) {
        return rowsResult;
      }
      const rows = rowsResult.value;
      const matches: CredProfileRow[] = [];

      for (const profile of rows) {
        const profileScope = credentialParentPath(profile.path);
        if (profileScope && !isAncestorOrEqual(profileScope, normalizedPath.value)) {
          continue;
        }

        const patternMatch = anyResourcePatternMatches(
          profile.resourcePatterns,
          normalizedResource.value,
        );
        if (!patternMatch.ok) {
          return patternMatch;
        }
        if (patternMatch.value) {
          matches.push(profile);
        }
      }

      return ok(matches.sort(sortByDeepestPath));
    },

    async upsertCredProfile(db, path, data) {
      const resourcePatterns: string[] = [];
      for (const pattern of data.resourcePatterns) {
        const normalized = normalizeResourcePattern(pattern);
        if (!normalized.ok) {
          return normalized;
        }
        resourcePatterns.push(normalized.value);
      }

      return runDb(
        "db.upsertCredProfile",
        async () => {
          await db
            .insert(credProfiles)
            .values({
              path,
              resourcePatterns,
              auth: data.auth,
              displayName: data.displayName ?? null,
              description: data.description ?? null,
            })
            .onConflictDoUpdate({
              target: credProfiles.path,
              set: {
                resourcePatterns,
                auth: data.auth,
                displayName: data.displayName ?? null,
                description: data.description ?? null,
                updatedAt: new Date(),
              },
            });
        },
        { label: "path", value: path },
      );
    },

    async deleteCredProfile(db, path, options) {
      const where = options?.recursive
        ? sql<boolean>`${credProfiles.path} <@ ${path}::ltree`
        : eq(credProfiles.path, path);
      return runDb(
        "db.deleteCredProfile",
        async () => (await db.delete(credProfiles).where(where).returning()).length > 0,
        { label: "path", value: path },
      );
    },

    async getCredential(db, path) {
      return runDb(
        "db.getCredential",
        async () => (await db.select().from(credentials).where(eq(credentials.path, path)))[0] ?? null,
        { label: "path", value: path },
      );
    },

    async listCredentials(db, options = {}) {
      const path = assertOptionalPath(options.path, "path");
      if (!path.ok) {
        return path;
      }

      return runDb(
        "db.listCredentials",
        async () => {
          const rows =
            path.value === undefined
              ? await db.select().from(credentials)
              : await db
                  .select()
                  .from(credentials)
                  .where(directChildrenWhere(credentials.path, path.value));
          return rows.sort((a, b) => a.path.localeCompare(b.path));
        },
        path.value === undefined ? undefined : { label: "path", value: path.value },
      );
    },

    async upsertCredential(db, data) {
      const normalizedAuth = normalizeCredentialAuthRecord(data.auth);
      if (!normalizedAuth.ok) {
        return normalizedAuth;
      }

      return runDb(
        "db.upsertCredential",
        async () => {
          await db
            .insert(credentials)
            .values({
              path: data.path,
              auth: normalizedAuth.value,
              secret: data.secret,
            })
            .onConflictDoUpdate({
              target: credentials.path,
              set: {
                auth: normalizedAuth.value,
                secret: data.secret,
                updatedAt: new Date(),
              },
            });
        },
        { label: "path", value: data.path },
      );
    },

    async moveCredential(db, fromPath, toPath) {
      const row = await helpers.getCredential(db, fromPath);
      if (!row.ok) {
        return row;
      }
      if (!row.value) {
        return ok(false);
      }

      const existingRow = row.value;

      const transaction = await runDb(
        "db.moveCredential",
        async () =>
          db.transaction(async (tx) => {
            await tx.delete(credentials).where(eq(credentials.path, fromPath));
            await tx.insert(credentials).values({
              path: toPath,
              auth: existingRow.auth,
              secret: existingRow.secret,
              createdAt: existingRow.createdAt,
              updatedAt: new Date(),
            });
          }),
        { label: "target path", value: toPath },
      );
      if (!transaction.ok) {
        return transaction;
      }

      return ok(true);
    },

    async deleteCredential(db, path, options) {
      const where = options?.recursive
        ? sql<boolean>`${credentials.path} <@ ${path}::ltree`
        : eq(credentials.path, path);
      return runDb(
        "db.deleteCredential",
        async () => (await db.delete(credentials).where(where).returning()).length > 0,
        { label: "path", value: path },
      );
    },
  };

  return ok(helpers);
}
