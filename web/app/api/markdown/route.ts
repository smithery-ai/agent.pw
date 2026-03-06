import { fetchCatalog, type CatalogService } from '@/lib/api'

function serviceName(s: CatalogService) {
  return s.displayName ?? s.slug
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
    'npx agent.pw curl api.agent.pw/proxy/<slug>/<hostname>/...',
    '```',
    '',
    '## Available Services',
    '',
    ...ranked.map(
      (s) =>
        `- **${serviceName(s)}** (\`${s.slug}\`) — ${s.description ?? 'API service'}`,
    ),
    '',
    '## API',
    '',
    '- `GET /api/catalog` — list services',
    '- `GET /api/catalog/:slug` — service details',
    '- `GET /auth/:slug` — start auth flow',
    '- `GET /proxy/:slug/:hostname/...` — authenticated proxy',
  ].join('\n')

  return new Response(md, {
    headers: { 'Content-Type': 'text/markdown; charset=utf-8' },
  })
}
