import { err, ok } from "okay-error";
import { inputError } from "../../errors.js";
import type { SqlNamespaceOptions } from "../../types.js";
import { defineCredProfilesTable } from "./cred-profiles.js";
import { defineCredentialsTable } from "./credentials.js";
import { pgSchema } from "drizzle-orm/pg-core";

const DEFAULT_SQL_SCHEMA = "agentpw";
const SQL_IDENTIFIER_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

function normalizeSqlIdentifier(value: string, label: string, allowEmpty = false) {
  if (allowEmpty && value.length === 0) {
    return ok(value);
  }
  if (!SQL_IDENTIFIER_PATTERN.test(value)) {
    return err(inputError(`Invalid ${label} '${value}'`, { field: label, value }));
  }
  return ok(value);
}

export interface AgentPwSqlNamespace {
  schema: string;
  tablePrefix: string;
  namespace: ReturnType<typeof pgSchema>;
  tables: {
    credProfiles: ReturnType<typeof defineCredProfilesTable>;
    credentials: ReturnType<typeof defineCredentialsTable>;
  };
  credProfiles: ReturnType<typeof defineCredProfilesTable>;
  credentials: ReturnType<typeof defineCredentialsTable>;
  tableName(baseName: "cred_profiles" | "credentials"): string;
}

function buildAgentPwNamespace(
  namespace: ReturnType<typeof pgSchema>,
  schema: string,
  tablePrefix: string,
): AgentPwSqlNamespace {
  const credProfiles = defineCredProfilesTable(namespace, tablePrefix);
  const credentials = defineCredentialsTable(namespace, tablePrefix);
  const tables = { credProfiles, credentials };

  return {
    schema,
    tablePrefix,
    namespace,
    tables,
    credProfiles,
    credentials,
    tableName(baseName) {
      return `${tablePrefix}${baseName}`;
    },
  };
}

export const agentpwSchema = pgSchema(DEFAULT_SQL_SCHEMA);

export const defaultSqlNamespace = buildAgentPwNamespace(agentpwSchema, DEFAULT_SQL_SCHEMA, "");

export function createAgentPwSchema(options: SqlNamespaceOptions = {}) {
  const schema = normalizeSqlIdentifier(options.schema ?? DEFAULT_SQL_SCHEMA, "SQL schema");
  if (!schema.ok) {
    return schema;
  }

  const tablePrefix = normalizeSqlIdentifier(options.tablePrefix ?? "", "table prefix", true);
  if (!tablePrefix.ok) {
    return tablePrefix;
  }

  if (schema.value === DEFAULT_SQL_SCHEMA && tablePrefix.value.length === 0) {
    return ok(defaultSqlNamespace);
  }

  return ok(buildAgentPwNamespace(pgSchema(schema.value), schema.value, tablePrefix.value));
}

export function coerceSqlNamespace(input?: SqlNamespaceOptions | AgentPwSqlNamespace) {
  if (!input) {
    return ok(defaultSqlNamespace);
  }
  if ("tables" in input) {
    return ok(input);
  }
  return createAgentPwSchema(input);
}
