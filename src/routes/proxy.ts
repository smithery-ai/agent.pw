import { Hono } from 'hono'
import type { CoreHonoEnv } from '../core/types'
import { handleProxy } from '../proxy'

export const proxyRoutes = new Hono<CoreHonoEnv>()

// Primary proxy route: /proxy/{slug}/{hostname}/{path...}
proxyRoutes.all('/proxy/:slug/:hostname/*', async c => {
  const slug = c.req.param('slug')
  const hostname = c.req.param('hostname')
  const url = new URL(c.req.url)
  const upstreamPath = url.pathname.slice(`/proxy/${slug}/${hostname}`.length) || '/'
  return handleProxy(c, slug, hostname, upstreamPath)
})
