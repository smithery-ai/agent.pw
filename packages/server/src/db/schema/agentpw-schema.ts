import { pgSchema } from "drizzle-orm/pg-core";
import type { SqlNamespaceOptions } from "../../types.js";
import { defineCredProfilesTable } from "./cred-profiles.js";
import { defineCredentialsTable } from "./credentials.js";

const DEFAULT_SQL_SCHEMA = "agentpw";
const SQL_IDENTIFIER_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

function normalizeSqlIdentifier(value: string, label: string, allowEmpty = false) {
  if (allowEmpty && value.length === 0) {
    return value;
  }
  if (!SQL_IDENTIFIER_PATTERN.test(value)) {
    throw new Error(`Invalid ${label} '${value}'`);
  }
  return value;
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
  const tables = {
    credProfiles,
    credentials,
  };

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

export function createAgentPwSchema(options: SqlNamespaceOptions = {}): AgentPwSqlNamespace {
  const schema = normalizeSqlIdentifier(options.schema ?? DEFAULT_SQL_SCHEMA, "SQL schema");
  const tablePrefix = normalizeSqlIdentifier(options.tablePrefix ?? "", "table prefix", true);

  if (schema === DEFAULT_SQL_SCHEMA && tablePrefix.length === 0) {
    return defaultSqlNamespace;
  }

  return buildAgentPwNamespace(pgSchema(schema), schema, tablePrefix);
}

export function coerceSqlNamespace(
  input?: SqlNamespaceOptions | AgentPwSqlNamespace,
): AgentPwSqlNamespace {
  if (!input) {
    return defaultSqlNamespace;
  }
  if ("tables" in input) {
    return input;
  }
  return createAgentPwSchema(input);
}
