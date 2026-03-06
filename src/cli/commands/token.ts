import { getClient } from '../http'

export async function revokeTokenCmd() {
  const client = await getClient()
  await client.tokens.revoke({})
  console.log('Token revoked.')
}
