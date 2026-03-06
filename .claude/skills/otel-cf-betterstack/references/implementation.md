# Implementation Reference

## otel.ts — Instrumented Worker Wrapper

This file wraps a CF Worker's fetch handler with OTel tracing and OTLP log export.

```typescript
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

// Parse "Key1=Val1,Key2=Val2" format used by OTEL_EXPORTER_OTLP_HEADERS
function parseOtelHeaders(raw?: string): Record<string, string> {
  if (!raw?.trim()) return {}
  const headers: Record<string, string> = {}
  for (const pair of raw.split(',')) {
    const i = pair.indexOf('=')
    if (i > 0) headers[pair.slice(0, i).trim()] = pair.slice(i + 1).trim()
  }
  return headers
}

// Configure @microlabs/otel-cf-workers for trace export
function createOtelConfig(serviceName: string): ResolveConfigFn {
  return (env, _trigger) => {
    const otelEnv = env as unknown as Partial<OtelEnv>
    const endpoint = otelEnv.OTEL_EXPORTER_OTLP_ENDPOINT?.trim() || ''
    if (!endpoint) {
      console.warn(`[otel] ${serviceName}: OTEL_EXPORTER_OTLP_ENDPOINT not set`)
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
        // Exclude BetterStack endpoint from trace context propagation (unnecessary noise)
        includeTraceContext: (request: Request) =>
          !request.url.includes('betterstackdata.com'),
      },
    }
  }
}

// Create a BatchLogRecordProcessor that exports logs via OTLP
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
      // Attach CF ray ID to the active span
      const rayId = request.headers.get('cf-ray')
      if (rayId) {
        trace.getSpan(context.active())?.setAttribute('cf.ray_id', rayId)
      }

      // Lazily create the LoggerProvider on first request
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

      // Flush logs before the isolate is evicted (5s timeout)
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
```

## logger.ts — Dual-output Logger (stdout + OTLP)

Emits structured JSON to stdout (for wrangler tail / Logpush) and to the OTel LoggerProvider (for OTLP export). Trace context is auto-correlated.

```typescript
import { logs, SeverityNumber } from '@opentelemetry/api-logs'
import { context, trace } from '@opentelemetry/api'

type LogLevel = 'info' | 'warn' | 'error' | 'debug'

export interface Logger {
  info(obj: Record<string, unknown>, msg?: string): void
  info(msg: string): void
  warn(obj: Record<string, unknown>, msg?: string): void
  warn(msg: string): void
  error(obj: Record<string, unknown>, msg?: string): void
  error(msg: string): void
  debug(obj: Record<string, unknown>, msg?: string): void
  debug(msg: string): void
  child(bindings: Record<string, unknown>): Logger
}

const SEVERITY: Record<LogLevel, SeverityNumber> = {
  debug: SeverityNumber.DEBUG,
  info: SeverityNumber.INFO,
  warn: SeverityNumber.WARN,
  error: SeverityNumber.ERROR,
}

function serializeValue(val: unknown): unknown {
  if (val instanceof Error) {
    return { message: val.message, stack: val.stack, name: val.name }
  }
  return val
}

function serializeObject(obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {}
  for (const [key, val] of Object.entries(obj)) {
    result[key] = serializeValue(val)
  }
  return result
}

class OtelLogger implements Logger {
  private service: string
  private bindings: Record<string, unknown>

  constructor(service: string, bindings: Record<string, unknown> = {}) {
    this.service = service
    this.bindings = bindings
  }

  info(objOrMsg: Record<string, unknown> | string, msg?: string) { this._log('info', objOrMsg, msg) }
  warn(objOrMsg: Record<string, unknown> | string, msg?: string) { this._log('warn', objOrMsg, msg) }
  error(objOrMsg: Record<string, unknown> | string, msg?: string) { this._log('error', objOrMsg, msg) }
  debug(objOrMsg: Record<string, unknown> | string, msg?: string) { this._log('debug', objOrMsg, msg) }

  child(bindings: Record<string, unknown>): Logger {
    return new OtelLogger(this.service, { ...this.bindings, ...bindings })
  }

  private _log(level: LogLevel, objOrMsg: Record<string, unknown> | string, msg?: string) {
    const [message, attrs] =
      typeof objOrMsg === 'string'
        ? [objOrMsg, {} as Record<string, unknown>]
        : [msg ?? '', objOrMsg]

    const serialized = serializeObject(attrs)
    const spanContext = trace.getSpan(context.active())?.spanContext()
    const traceSampled = spanContext !== undefined ? (spanContext.traceFlags & 1) === 1 : undefined

    // 1. Stdout (structured JSON)
    console.log(JSON.stringify({
      level, time: new Date().toISOString(), service: this.service, msg: message,
      ...this.bindings, ...serialized,
      ...(traceSampled !== undefined && { 'trace.sampled': traceSampled }),
    }))

    // 2. OTLP log — auto-correlates traceId/spanId from active context
    logs.getLogger(this.service).emit({
      severityNumber: SEVERITY[level],
      severityText: level.toUpperCase(),
      body: message,
      attributes: { service: this.service, ...this.bindings, ...serialized },
    })
  }
}

export function createLogger(service: string) {
  return { logger: new OtelLogger(service) as Logger }
}
```
