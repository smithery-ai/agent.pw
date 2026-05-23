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
import type { DbClient } from "./index.js";
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

interface CredentialRefreshMetadata {
  refreshable: boolean;
  expiresAt: Date | null;
  refreshCheckedAt: Date | null;
}

interface QueryHelpers {
  getCredProfile(db: DbClient, path: string): Promise<Result<CredProfileRow | null>>;
  listCredProfiles(
    db: DbClient,
    options?: {
      path?: string;
      recursive?: boolean;
    },
  ): Promise<Result<CredProfileRow[]>>;
  getMatchingCredProfiles(
    db: DbClient,
    path: string,
    resource: string,
  ): Promise<Result<CredProfileRow[]>>;
  upsertCredProfile(
    db: DbClient,
    path: string,
    data: {
      resourcePatterns: string[];
      auth: Record<string, unknown>;
      displayName?: string;
      description?: string;
    },
  ): Promise<Result<CredProfileRow>>;
  deleteCredProfile(
    db: DbClient,
    path: string,
    options?: { recursive?: boolean },
  ): Promise<Result<boolean>>;
  getCredential(db: DbClient, path: string): Promise<Result<CredentialRow | null>>;
  listCredentials(
    db: DbClient,
    options?: {
      path?: string;
      recursive?: boolean;
    },
  ): Promise<Result<CredentialRow[]>>;
  listRefreshCandidates(
    db: DbClient,
    options: {
      expiresBefore: Date;
      unknownExpiryCheckedBefore?: Date;
      limit?: number;
      path?: string;
      recursive?: boolean;
    },
  ): Promise<Result<CredentialRow[]>>;
  upsertCredential(
    db: DbClient,
    data: {
      path: string;
      auth: Record<string, unknown>;
      secret: Buffer;
      refreshMetadata?: CredentialRefreshMetadata;
    },
  ): Promise<Result<CredentialRow>>;
  markRefreshChecked(db: DbClient, path: string, checkedAt: Date): Promise<Result<boolean>>;
  recordRefreshCheck(
    db: DbClient,
    path: string,
    checkedAt: Date,
    expiresAt?: Date | null,
  ): Promise<Result<boolean>>;
  moveCredential(db: DbClient, fromPath: string, toPath: string): Promise<Result<boolean>>;
  deleteCredential(
    db: DbClient,
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

function descendantsWhere(pathColumn: { getSQL(): unknown }, path: string) {
  return sql<boolean>`${pathColumn} <@ ${path}::ltree`;
}

function assertValidDate(value: Date, label: string) {
  if (value instanceof Date && Number.isFinite(value.getTime())) {
    return ok(value);
  }
  return err(inputError(`Invalid ${label}`));
}

function assertLimit(value: number | undefined) {
  if (value === undefined) {
    return ok(100);
  }
  if (Number.isInteger(value) && value > 0 && value <= 1000) {
    return ok(value);
  }
  return err(inputError("Credential refresh candidate limit must be between 1 and 1000"));
}

function assertOptionalNullableDate(value: Date | null | undefined, label: string) {
  if (value === undefined || value === null) {
    return ok(value);
  }
  return assertValidDate(value, label);
}

/**
 * Create the low-level query helpers used by agent.pw.
 *
 * Most applications should prefer `createAgentPw()` and use its higher-level APIs. These helpers
 * are useful when you need direct access to the underlying credential and profile tables.
 */
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
        async () =>
          (await db.select().from(credProfiles).where(eq(credProfiles.path, path)))[0] ?? null,
        { label: "path", value: path },
      );
    },

    async listCredProfiles(db, options = {}) {
      const path = assertOptionalPath(options.path, "path");
      if (!path.ok) {
        return err(path.error);
      }

      return runDb(
        "db.listCredProfiles",
        async () => {
          const where =
            path.value === undefined
              ? undefined
              : options.recursive
                ? descendantsWhere(credProfiles.path, path.value)
                : directChildrenWhere(credProfiles.path, path.value);
          const rows = where
            ? await db.select().from(credProfiles).where(where)
            : await db.select().from(credProfiles);
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
        return err(normalizedPath.error);
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
          return (
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
              })
              .returning()
          )[0];
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
        async () =>
          (await db.select().from(credentials).where(eq(credentials.path, path)))[0] ?? null,
        { label: "path", value: path },
      );
    },

    async listCredentials(db, options = {}) {
      const path = assertOptionalPath(options.path, "path");
      if (!path.ok) {
        return err(path.error);
      }

      return runDb(
        "db.listCredentials",
        async () => {
          const where =
            path.value === undefined
              ? undefined
              : options.recursive
                ? descendantsWhere(credentials.path, path.value)
                : directChildrenWhere(credentials.path, path.value);
          const rows = where
            ? await db.select().from(credentials).where(where)
            : await db.select().from(credentials);
          return rows.sort((a, b) => a.path.localeCompare(b.path));
        },
        path.value === undefined ? undefined : { label: "path", value: path.value },
      );
    },

    async listRefreshCandidates(db, options) {
      const path = assertOptionalPath(options.path, "path");
      /* v8 ignore next 3 -- assertOptionalPath currently preserves inputs; database ltree validation handles syntax errors. */
      if (!path.ok) {
        return err(path.error);
      }
      const expiresBefore = assertValidDate(options.expiresBefore, "expiresBefore");
      if (!expiresBefore.ok) {
        return expiresBefore;
      }
      const unknownExpiryCheckedBefore =
        options.unknownExpiryCheckedBefore === undefined
          ? ok<Date | undefined>(undefined)
          : assertValidDate(options.unknownExpiryCheckedBefore, "unknownExpiryCheckedBefore");
      if (!unknownExpiryCheckedBefore.ok) {
        return unknownExpiryCheckedBefore;
      }
      const limit = assertLimit(options.limit);
      if (!limit.ok) {
        return limit;
      }

      return runDb(
        "db.listRefreshCandidates",
        async () => {
          const pathWhere =
            path.value === undefined
              ? undefined
              : options.recursive
                ? descendantsWhere(credentials.path, path.value)
                : directChildrenWhere(credentials.path, path.value);
          const unknownWhere = unknownExpiryCheckedBefore.value
            ? sql<boolean>`(
                ${credentials.expiresAt} IS NULL
                AND (
                  ${credentials.refreshCheckedAt} IS NULL
                  OR ${credentials.refreshCheckedAt} <= ${unknownExpiryCheckedBefore.value}
                )
              )`
            : sql<boolean>`false`;
          return db
            .select()
            .from(credentials)
            .where(
              and(
                eq(credentials.refreshable, true),
                pathWhere,
                sql<boolean>`(
                  (
                    ${credentials.expiresAt} IS NOT NULL
                    AND ${credentials.expiresAt} <= ${expiresBefore.value}
                  )
                  OR ${unknownWhere}
                )`,
              ),
            )
            .orderBy(
              sql`CASE WHEN ${credentials.expiresAt} IS NULL THEN 1 ELSE 0 END`,
              credentials.expiresAt,
              credentials.refreshCheckedAt,
              sql`${credentials.path}::text`,
            )
            .limit(limit.value);
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
          const values = data.refreshMetadata
            ? {
                path: data.path,
                auth: normalizedAuth.value,
                secret: data.secret,
                refreshable: data.refreshMetadata.refreshable,
                expiresAt: data.refreshMetadata.expiresAt,
                refreshCheckedAt: data.refreshMetadata.refreshCheckedAt,
              }
            : {
                path: data.path,
                auth: normalizedAuth.value,
                secret: data.secret,
              };
          const set = data.refreshMetadata
            ? {
                auth: normalizedAuth.value,
                secret: data.secret,
                refreshable: data.refreshMetadata.refreshable,
                expiresAt: data.refreshMetadata.expiresAt,
                refreshCheckedAt: data.refreshMetadata.refreshCheckedAt,
                updatedAt: new Date(),
              }
            : {
                auth: normalizedAuth.value,
                secret: data.secret,
                updatedAt: new Date(),
              };
          return (
            await db
              .insert(credentials)
              .values(values)
              .onConflictDoUpdate({
                target: credentials.path,
                set,
              })
              .returning()
          )[0];
        },
        { label: "path", value: data.path },
      );
    },

    async markRefreshChecked(db, path, checkedAt) {
      return helpers.recordRefreshCheck(db, path, checkedAt);
    },

    async recordRefreshCheck(db, path, checkedAt, expiresAt) {
      const validCheckedAt = assertValidDate(checkedAt, "checkedAt");
      if (!validCheckedAt.ok) {
        return validCheckedAt;
      }
      const validExpiresAt = assertOptionalNullableDate(expiresAt, "expiresAt");
      if (!validExpiresAt.ok) {
        return validExpiresAt;
      }
      const set =
        validExpiresAt.value === undefined
          ? {
              refreshCheckedAt: validCheckedAt.value,
              updatedAt: new Date(),
            }
          : {
              expiresAt: validExpiresAt.value,
              refreshCheckedAt: validCheckedAt.value,
              updatedAt: new Date(),
            };

      return runDb(
        "db.recordRefreshCheck",
        async () =>
          (
            await db
              .update(credentials)
              .set(set)
              .where(and(eq(credentials.path, path), eq(credentials.refreshable, true)))
              .returning()
          ).length > 0,
        { label: "path", value: path },
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
              refreshable: existingRow.refreshable,
              expiresAt: existingRow.expiresAt,
              refreshCheckedAt: existingRow.refreshCheckedAt,
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
