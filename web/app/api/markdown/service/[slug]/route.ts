import { fetchService, getApiUrl } from '@/lib/api'

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ slug: string }> },
) {
  const { slug } = await params
  const service = await fetchService(slug)

  if (!service) {
    return new Response('Service not found', { status: 404 })
  }

  const name = service.displayName ?? service.service
  const apiUrl = getApiUrl()

  const md = [
    `# ${name}`,
    '',
    service.description ?? '',
    '',
    '## Connect',
    '',
    `To connect to ${name}, start an auth flow:`,
    '',
    '```',
    `# Start auth flow`,
    `curl ${apiUrl}/auth/${service.service}`,
    '',
    `# Poll for completion`,
    `curl ${apiUrl}/auth/status/{flow_id}`,
    '',
    `# Use the proxy`,
    `curl -H "Authorization: Bearer apw_..." \\`,
    `  ${apiUrl}/proxy/${service.service}/${service.service}/...`,
    '```',
    '',
    `- Hostname: \`${service.service}\``,
    service.docsUrl ? `- Docs: ${service.docsUrl}` : '',
    `- OAuth available: ${service.hasOAuth ? 'Yes' : 'No'}`,
  ]
    .filter(Boolean)
    .join('\n')

  return new Response(md, {
    headers: { 'Content-Type': 'text/markdown; charset=utf-8' },
  })
}
