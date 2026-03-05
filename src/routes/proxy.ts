import { Hono } from 'hono'
import type { CoreHonoEnv } from '../core/types'
import { handleProxy } from '../proxy'
import { RESERVED_PATHS } from '../lib/utils'

export const proxyRoutes = new Hono<CoreHonoEnv>()

// Primary proxy route
proxyRoutes.all('/proxy/:service/*', async c => {
  const serviceName = c.req.param('service')
  const url = new URL(c.req.url)
  const upstreamPath = url.pathname.slice(`/proxy/${serviceName}`.length) || '/'
  return handleProxy(c, serviceName, upstreamPath)
})

// Legacy redirect: /:service/* → /proxy/:service/*
proxyRoutes.all('/:service/*', async c => {
  const service = c.req.param('service')
  if (RESERVED_PATHS.has(service)) return c.notFound()
  const url = new URL(c.req.url)
  const rest = url.pathname.slice(`/${service}`.length)
  return c.redirect(`/proxy/${service}${rest}${url.search}`, 301)
})
