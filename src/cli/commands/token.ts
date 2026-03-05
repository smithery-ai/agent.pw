import { api } from '../http'

export async function revokeTokenCmd() {
  const res = await api('/tokens/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  })

  if (!res.ok) {
    const body = await res.json().catch(() => ({})) as Record<string, string>
    console.error(`Failed to revoke token: ${body.error ?? res.statusText}`)
    process.exit(1)
  }

  console.log('Token revoked.')
}
