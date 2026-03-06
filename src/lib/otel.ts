import {
  BatchTraceSpanProcessor,
  OTLPExporter,
  instrument,
  type ResolveConfigFn,
} from '@microlabs/otel-cf-workers'
import { logs } from '@opentelemetry/api-logs'
import { OTLPLogExporter } from '@opentelemetry/exporter-logs-otlp-http'
import { resourceFromAttributes } from '@opentelemetry/resources'
import { BatchLogRecordProcessor, LoggerProvider } from '@opentelemetry/sdk-logs'
import { context, trace } from '@opentelemetry/api'

export interface OtelEnv {
  OTEL_EXPORTER_OTLP_ENDPOINT: string
  OTEL_EXPORTER_OTLP_HEADERS: string
}

function parseOtelHeaders(raw?: string): Record<string, string> {
  if (!raw?.trim()) return {}
  const headers: Record<string, string> = {}
  for (const pair of raw.split(',')) {
    const i = pair.indexOf('=')
    if (i > 0) headers[pair.slice(0, i).trim()] = pair.slice(i + 1).trim()
  }
  return headers
}

function createOtelConfig(serviceName: string): ResolveConfigFn {
  return (env, _trigger) => {
    const otelEnv = env as unknown as Partial<OtelEnv>
    const endpoint = otelEnv.OTEL_EXPORTER_OTLP_ENDPOINT?.trim() || ''
    if (!endpoint) {
      console.warn(`[otel] ${serviceName}: OTEL_EXPORTER_OTLP_ENDPOINT not set, traces will not be exported`)
    }
    const headers = parseOtelHeaders(otelEnv.OTEL_EXPORTER_OTLP_HEADERS)
    const exporter = new OTLPExporter({
      url: endpoint ? `${endpoint}/v1/traces` : '',
      headers,
    })
    return {
      spanProcessors: [new BatchTraceSpanProcessor(exporter)],
      service: { name: serviceName, namespace: 'smithery' },
      handlers: { fetch: { acceptTraceContext: true } },
      fetch: {
        includeTraceContext: (request: Request) => !request.url.includes('betterstackdata.com'),
      },
    }
  }
}

function createOtlpLogProcessor(env: Partial<OtelEnv>): BatchLogRecordProcessor | null {
  const endpoint = env.OTEL_EXPORTER_OTLP_ENDPOINT?.trim()
  if (!endpoint) return null
  const headers = parseOtelHeaders(env.OTEL_EXPORTER_OTLP_HEADERS)
  const exporter = new OTLPLogExporter({
    url: `${endpoint}/v1/logs`,
    headers: Object.keys(headers).length > 0 ? headers : undefined,
  })
  return new BatchLogRecordProcessor(exporter)
}

interface WorkerOptions<E> {
  serviceName: string
  fetch: (request: Request, env: E, ctx: ExecutionContext) => Response | Promise<Response>
}

export function createInstrumentedWorker<E = unknown>(options: WorkerOptions<E>) {
  const otelConfig = createOtelConfig(options.serviceName)
  let loggerProvider: LoggerProvider | undefined

  const rawHandler: ExportedHandler<E> = {
    async fetch(request, env, ctx) {
      const rayId = request.headers.get('cf-ray')
      if (rayId) {
        trace.getSpan(context.active())?.setAttribute('cf.ray_id', rayId)
      }

      if (loggerProvider === undefined) {
        const processor = createOtlpLogProcessor(env as Partial<OtelEnv>)
        if (processor) {
          loggerProvider = new LoggerProvider({
            resource: resourceFromAttributes({
              'service.name': options.serviceName,
              'service.namespace': 'smithery',
            }),
            processors: [processor],
          })
          logs.setGlobalLoggerProvider(loggerProvider)
        }
      }

      const response = await options.fetch(request, env, ctx)

      if (loggerProvider) {
        const flush = loggerProvider.forceFlush().catch(() => {})
        const timeout = new Promise<void>(r => setTimeout(r, 5000))
        ctx.waitUntil(Promise.race([flush, timeout]))
      }

      return response
    },
  }

  return {
    handler: instrument(rawHandler as ExportedHandler, otelConfig) as ExportedHandler<E>,
  }
}
