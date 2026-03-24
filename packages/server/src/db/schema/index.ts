import { defaultSqlNamespace } from './agentpw-schema.js'

export { agentpwSchema, coerceSqlNamespace, createAgentPwSchema, defaultSqlNamespace, type AgentPwSqlNamespace } from './agentpw-schema.js'
export const schemaTables = defaultSqlNamespace.tables
export const credProfiles = schemaTables.credProfiles
export const credentials = schemaTables.credentials
