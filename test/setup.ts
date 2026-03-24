import { drizzle } from 'drizzle-orm/pglite'
import * as schema from '../packages/server/src/db/schema/index'
import { bootstrapLocalSchema } from '../packages/server/src/db/bootstrap-local'
import { mintToken } from 'agent.pw/biscuit'
import type { RuleGrant } from '../packages/server/src/types'

export const BISCUIT_PRIVATE_KEY =
  'ed25519-private/20cbf8e88a4d258a2af3b2ab1132ae6f753e46893eaea2427f732feefba7a8ad'

export const TEST_ORG_ID = 'org_test_456'
export const PUBLIC_KEY_HEX =
  'ed25519/e43c506c0d441f5b4e4ccac8c7572ac5b9d3773a3a95c21584164bec11f0d9ab'

function escapeDatalog(value: string) {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

function rightsAtRoot(root: string, actions: string[]): RuleGrant[] {
  return actions.map(action => ({ action, root }))
}

export const ROOT_TOKEN = mintToken(
  BISCUIT_PRIVATE_KEY,
  'local',
  rightsAtRoot('/', ['credential.use', 'credential.manage', 'credential.bootstrap', 'profile.manage']),
  ['home_path("/")'],
)

export const ORG_TOKEN = mintToken(BISCUIT_PRIVATE_KEY, 'user_test_123', rightsAtRoot(`/${TEST_ORG_ID}`, [
  'credential.use',
  'credential.bootstrap',
  'credential.manage',
  'profile.manage',
]), [
  `org_id("${escapeDatalog(TEST_ORG_ID)}")`,
  `home_path("/${escapeDatalog(TEST_ORG_ID)}")`,
])

export function mintTestToken(
  orgId: string,
  actions: string[] = ['credential.use'],
  roots: string[] = [`/${orgId}`],
) {
  const extraFacts = [
    `org_id("${escapeDatalog(orgId)}")`,
    `home_path("/${escapeDatalog(orgId)}")`,
  ]
  return mintToken(
    BISCUIT_PRIVATE_KEY,
    orgId,
    roots.flatMap(root => rightsAtRoot(root, actions)),
    extraFacts,
  )
}

export async function createTestDb() {
  const db = drizzle({ connection: { dataDir: 'memory://' }, schema })
  await bootstrapLocalSchema(db)

  return db
}

export type TestDb = Awaited<ReturnType<typeof createTestDb>>
