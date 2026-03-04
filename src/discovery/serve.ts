import { Hono } from 'hono'
import type { HonoEnv } from '../types'
import type { PipelineContext } from './types'
import type { Context } from 'hono'
import { getDocPage, getService } from '../db/queries'
import { getOrGeneratePage } from './index'
import { wantsJson } from '../discovery'
import { DocPageViewer } from '../ui'

const RESERVED_PATHS = new Set(['auth', 'tokens', 'services', 'vaults', 'keys', 'proxy'])

function buildPipelineCtx(c: Context<HonoEnv>, serviceName: string, svc: NonNullable<Awaited<ReturnType<typeof getService>>>): PipelineContext {
  return {
    db: c.get('db'),
    hostname: serviceName,
    service: svc,
    anthropicApiKey: c.env.ANTHROPIC_API_KEY,
    anthropicBaseUrl: c.env.ANTHROPIC_BASE_URL,
    awsAccessKeyId: c.env.AWS_ACCESS_KEY_ID,
    awsSecretAccessKey: c.env.AWS_SECRET_ACCESS_KEY,
    awsRegion: c.env.AWS_REGION,
    baseUrl: new URL(c.req.url).origin,
    workflow: c.env.DISCOVERY_WORKFLOW,
  }
}

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

    const page = await getOrGeneratePage(buildPipelineCtx(c, serviceName, svc), 'docs/index.json')
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

    const page = await getOrGeneratePage(buildPipelineCtx(c, serviceName, svc), docPath)
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
