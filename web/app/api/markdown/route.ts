import { fetchCatalog, type CatalogService } from '@/lib/api'

function serviceName(s: CatalogService) {
  return s.displayName ?? s.service
}

export async function GET() {
  const services = await fetchCatalog()
  const ranked = services
    .filter((s) => (s.credentialCount ?? 0) > 0 || !!s.oauthClientId)
    .sort(
      (a, b) =>
        (b.credentialCount ?? 0) - (a.credentialCount ?? 0) ||
        serviceName(a).localeCompare(serviceName(b)),
    )

  const md = [
    '# Warden — Secure auth for AI agents',
    '',
    'Credential vault and API proxy. Agents get revocable tokens — provider secrets never enter agent context.',
    '',
    '## Quick Start',
    '',
    '```',
    'npx agent.pw login',
    'npx agent.pw cred add <service>',
    'npx agent.pw curl agent.pw/proxy/<service>/<hostname>/...',
    '```',
    '',
    '## Available Services',
    '',
    ...ranked.map(
      (s) =>
        `- **${serviceName(s)}** (\`${s.service}\`) — ${s.description ?? 'API service'}`,
    ),
    '',
    '## API',
    '',
    '- `GET /api/catalog` — list services',
    '- `GET /api/catalog/:service` — service details',
    '- `GET /auth/:service` — start auth flow',
    '- `GET /proxy/:service/:hostname/...` — authenticated proxy',
  ].join('\n')

  return new Response(md, {
    headers: { 'Content-Type': 'text/markdown; charset=utf-8' },
  })
}
