import { err, ok, result } from "okay-error";
import { eq, like, type InferSelectModel } from "drizzle-orm";
import { inputError, internalError } from "../errors.js";
import { isRecord } from "../lib/utils.js";
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
import type { AgentPwResult, SqlNamespaceOptions } from "../types.js";
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

function sortByDeepestPath<T extends { path: string }>(a: T, b: T) {
  const aDepth = a.path.split("/").filter(Boolean).length;
  const bDepth = b.path.split("/").filter(Boolean).length;
  return bDepth - aDepth || a.path.localeCompare(b.path);
}

function normalizeListPath(path: string | undefined): AgentPwResult<string> {
  const normalized = canonicalizePath(path ?? "/");
  if (!validatePath(normalized)) {
    return err(inputError(`Invalid path '${path}'`, { field: "path", value: path }));
  }
  return ok(normalized);
}

function normalizeCredentialAuthRecord(
  auth: Record<string, unknown>,
): AgentPwResult<Record<string, unknown>> {
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

  return ok(normalized.value);
}

export function createQueryHelpers(namespaceInput?: SqlNamespaceInput) {
  const sqlNamespace = coerceSqlNamespace(namespaceInput);
  if (!sqlNamespace.ok) {
    return sqlNamespace;
  }

  const { credProfiles, credentials } = sqlNamespace.value.tables;

  async function getCredProfile(db: Database, path: string): Promise<AgentPwResult<CredProfileRow | null>> {
    return ok((await db.select().from(credProfiles).where(eq(credProfiles.path, path)))[0] ?? null);
  }

  async function listCredProfiles(
    db: Database,
    options: {
      path?: string;
    } = {},
  ): Promise<AgentPwResult<CredProfileRow[]>> {
    const path = normalizeListPath(options.path);
    if (!path.ok) {
      return path;
    }

    const rows =
      path.value === "/"
        ? await db.select().from(credProfiles)
        : await db.select().from(credProfiles).where(like(credProfiles.path, `${path.value}/%`));

    return ok(rows.sort((a, b) => a.path.localeCompare(b.path)));
  }

  async function getMatchingCredProfiles(
    db: Database,
    path: string,
    resource: string,
  ): Promise<AgentPwResult<CredProfileRow[]>> {
    const normalizedResource = normalizeResource(resource);
    if (!normalizedResource.ok) {
      return normalizedResource;
    }

    const normalizedPath = canonicalizePath(path);
    const rows = await db.select().from(credProfiles);
    const matches: CredProfileRow[] = [];

    for (const profile of rows) {
      const profileScope = credentialParentPath(profile.path);
      if (!isAncestorOrEqual(profileScope, normalizedPath)) {
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
  ): Promise<AgentPwResult<void>> {
    const resourcePatterns: string[] = [];
    for (const pattern of data.resourcePatterns) {
      const normalized = normalizeResourcePattern(pattern);
      if (!normalized.ok) {
        return normalized;
      }
      resourcePatterns.push(normalized.value);
    }

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

    return ok();
  }

  async function deleteCredProfile(db: Database, path: string): Promise<AgentPwResult<boolean>> {
    const deleted = await db.delete(credProfiles).where(eq(credProfiles.path, path)).returning();
    return ok(deleted.length > 0);
  }

  async function getCredential(db: Database, path: string): Promise<AgentPwResult<CredentialRow | null>> {
    return ok((await db.select().from(credentials).where(eq(credentials.path, path)))[0] ?? null);
  }

  async function listCredentials(
    db: Database,
    options: {
      path?: string;
    } = {},
  ): Promise<AgentPwResult<CredentialRow[]>> {
    const path = normalizeListPath(options.path);
    if (!path.ok) {
      return path;
    }

    const rows =
      path.value === "/"
        ? await db.select().from(credentials)
        : await db.select().from(credentials).where(like(credentials.path, `${path.value}/%`));

    return ok(
      rows
        .filter((row) => credentialParentPath(row.path) === path.value)
        .sort((a, b) => a.path.localeCompare(b.path)),
    );
  }

  async function upsertCredential(
    db: Database,
    data: {
      path: string;
      auth: Record<string, unknown>;
      secret: Buffer;
    },
  ): Promise<AgentPwResult<void>> {
    const normalizedAuth = normalizeCredentialAuthRecord(data.auth);
    if (!normalizedAuth.ok) {
      return normalizedAuth;
    }

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

    return ok();
  }

  async function moveCredential(
    db: Database,
    fromPath: string,
    toPath: string,
  ): Promise<AgentPwResult<boolean>> {
    const row = await getCredential(db, fromPath);
    if (!row.ok) {
      return row;
    }
    if (!row.value) {
      return ok(false);
    }

    const existingRow = row.value;

    const transaction = await result(
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
    );
    if (!transaction.ok) {
      return err(
        internalError("Failed to move credential", {
          cause: transaction.error,
          path: fromPath,
          source: "db.moveCredential",
        }),
      );
    }

    return ok(true);
  }

  async function deleteCredential(db: Database, path: string): Promise<AgentPwResult<boolean>> {
    const deleted = await db.delete(credentials).where(eq(credentials.path, path)).returning();
    return ok(deleted.length > 0);
  }

  return ok({
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
  });
}
