import { Hono } from 'hono'
import type { HonoEnv } from '../types'
import { getDocPage, getService } from '../db/queries'
import { getOrGeneratePage } from './index'
import { wantsJson } from '../discovery'
import { DocPageViewer } from '../ui'

const RESERVED_PATHS = new Set(['auth', 'tokens', 'services', 'vaults', 'keys', 'proxy'])

export function docRoutes() {
  const router = new Hono<HonoEnv>()

  // ─── Meta ──────────────────────────────────────────────────────────────────

  router.get('/:service/_meta.json', async c => {
    const serviceName = c.req.param('service')
    if (RESERVED_PATHS.has(serviceName)) return c.notFound()

    const db = c.get('db')
    const meta = await getDocPage(db, serviceName, '_meta.json')
    if (!meta) return c.json({ error: 'No documentation generated yet' }, 404)

    return c.json(JSON.parse(meta.content!))
  })

  // ─── Doc pages ─────────────────────────────────────────────────────────────

  router.get('/:service/docs/', async c => {
    const serviceName = c.req.param('service')
    if (RESERVED_PATHS.has(serviceName)) return c.notFound()

    const db = c.get('db')
    const svc = await getService(db, serviceName)
    if (!svc) return c.json({ error: `Unknown service: ${serviceName}` }, 404)

    const ctx = {
      db,
      hostname: serviceName,
      service: svc,
      anthropicApiKey: c.env.ANTHROPIC_API_KEY,
      anthropicBaseUrl: c.env.ANTHROPIC_BASE_URL,
      baseUrl: new URL(c.req.url).origin,
      workflow: c.env.DISCOVERY_WORKFLOW,
    }

    const page = await getOrGeneratePage(ctx, 'docs/index.json')
    if (!page) return c.json({ error: 'Documentation not available' }, 404)

    const parsed = JSON.parse(page.content!)
    if (wantsJson(c.req.header('Accept'))) return c.json(parsed)

    return c.html(
      DocPageViewer({
        service: svc,
        docPath: 'docs/index.json',
        content: parsed,
        status: page.status ?? undefined,
      }),
    )
  })

  router.get('/:service/docs/*', async c => {
    const serviceName = c.req.param('service')
    if (RESERVED_PATHS.has(serviceName)) return c.notFound()

    const url = new URL(c.req.url)
    const docPath = url.pathname.slice(`/${serviceName}/`.length)

    const db = c.get('db')
    const svc = await getService(db, serviceName)
    if (!svc) return c.json({ error: `Unknown service: ${serviceName}` }, 404)

    const ctx = {
      db,
      hostname: serviceName,
      service: svc,
      anthropicApiKey: c.env.ANTHROPIC_API_KEY,
      anthropicBaseUrl: c.env.ANTHROPIC_BASE_URL,
      baseUrl: new URL(c.req.url).origin,
      workflow: c.env.DISCOVERY_WORKFLOW,
    }

    const page = await getOrGeneratePage(ctx, docPath)
    if (!page) return c.json({ error: `Page not found: ${docPath}` }, 404)

    const parsed = JSON.parse(page.content!)
    if (wantsJson(c.req.header('Accept'))) return c.json(parsed)

    return c.html(
      DocPageViewer({
        service: svc,
        docPath,
        content: parsed,
        status: page.status ?? undefined,
      }),
    )
  })

  return router
}
