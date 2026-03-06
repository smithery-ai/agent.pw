import { Hono } from 'hono'
import { describeRoute } from 'hono-openapi'
import type { CoreHonoEnv } from '../core/types'
import { handleProxy } from '../proxy'

export const proxyRoutes = new Hono<CoreHonoEnv>()

// Primary proxy route: /proxy/{slug}/{hostname}/{path...}
proxyRoutes.all('/proxy/:slug/:hostname/*',
  describeRoute({
    tags: ['proxy'],
    summary: 'Proxy request',
    description: 'Forward a request to an upstream service, injecting stored credentials. The hostname must be in the service\'s allowedHosts list.',
    responses: {
      200: { description: 'Upstream response (pass-through)' },
      401: { description: 'Missing or invalid token' },
      403: { description: 'Hostname not allowed for this service' },
      404: { description: 'Service or credential not found' },
    },
  }),
  async c => {
    const slug = c.req.param('slug')
    const hostname = c.req.param('hostname')
    const url = new URL(c.req.url)
    const upstreamPath = url.pathname.slice(`/proxy/${slug}/${hostname}`.length) || '/'
    return handleProxy(c, slug, hostname, upstreamPath)
  },
)
