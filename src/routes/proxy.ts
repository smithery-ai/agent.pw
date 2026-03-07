import { Hono } from 'hono'
import { describeRoute } from 'hono-openapi'
import type { CoreHonoEnv } from '../core/types'
import { handleProxy } from '../proxy'
import { getCredProfile } from '../db/queries'

export const proxyRoutes = new Hono<CoreHonoEnv>()

function upstreamPathFromPrefix(pathname: string, prefix: string) {
  return pathname.slice(prefix.length) || '/'
}

// Primary proxy route:
// - /proxy/{hostname}/{path...}
// - /proxy/{profile_slug}/{hostname}/{path...} (explicit profile override)
proxyRoutes.all('/proxy/*',
  describeRoute({
    tags: ['proxy'],
    summary: 'Proxy request',
    description: 'Forward a request to an upstream service, injecting stored credentials that match the target host.',
    responses: {
      200: { description: 'Upstream response (pass-through)' },
      401: { description: 'Missing or invalid token' },
      403: { description: 'Hostname not allowed or credential policy mismatch' },
      404: { description: 'Credential profile not found' },
    },
  }),
  async c => {
    const url = new URL(c.req.url)
    const relative = url.pathname.slice('/proxy/'.length)
    const segments = relative.split('/').filter(Boolean)

    if (segments.length === 0) {
      return c.json({ error: 'Missing upstream hostname' }, 400)
    }

    let slug: string | undefined
    let hostname = segments[0]
    let prefix = `/proxy/${hostname}`

    if (segments.length >= 2) {
      const explicitProfile = await getCredProfile(c.get('db'), segments[0])
      if (explicitProfile) {
        const allowedHosts = explicitProfile.host
        if (allowedHosts.includes(segments[1])) {
          slug = segments[0]
          hostname = segments[1]
          prefix = `/proxy/${slug}/${hostname}`
        }
      }
    }

    const upstreamPath = upstreamPathFromPrefix(url.pathname, prefix)
    return handleProxy(c, slug, hostname, upstreamPath)
  },
)
