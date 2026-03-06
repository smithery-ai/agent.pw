---
name: otel-cf-betterstack
description: >
  Set up OpenTelemetry tracing and logging on Cloudflare Workers with BetterStack as the backend.
  Use when adding observability to a CF Worker, instrumenting a Hono/CF app with OTel,
  exporting traces/logs via OTLP to BetterStack, or querying BetterStack telemetry data.
  Triggers: "add tracing", "set up observability", "OTel on workers", "BetterStack logs",
  "instrument cloudflare worker", "add OpenTelemetry".
---

# OTel on Cloudflare Workers with BetterStack

## Architecture

```
CF Worker → @microlabs/otel-cf-workers (traces) → OTLP/HTTP → BetterStack
         → @opentelemetry/sdk-logs (logs)       → OTLP/HTTP → BetterStack
         → console.log (stdout)                 → CF Logpush / wrangler tail
```

## Quick Setup

### 1. Install dependencies

```bash
npm install @microlabs/otel-cf-workers@1.0.0-rc.52 \
  @opentelemetry/api@^1.9.0 \
  @opentelemetry/api-logs@^0.213.0 \
  @opentelemetry/exporter-logs-otlp-http@^0.213.0 \
  @opentelemetry/resources@^2.6.0 \
  @opentelemetry/sdk-logs@^0.213.0
```

### 2. Create the instrumented worker wrapper

See [references/implementation.md](references/implementation.md) for full annotated code for both the OTel wrapper (`otel.ts`) and the logger (`logger.ts`).

The pattern:
1. `createInstrumentedWorker()` wraps the Worker's `fetch` handler
2. `@microlabs/otel-cf-workers` auto-instruments all outbound `fetch()` as spans
3. A `LoggerProvider` is lazily created on first request, emitting logs via OTLP
4. Logs auto-correlate with the active trace context (traceId/spanId)
5. `loggerProvider.forceFlush()` runs in `ctx.waitUntil()` with a 5s timeout

Entry point usage:
```typescript
import { createInstrumentedWorker } from './otel'
import { createApp } from './app'

const app = createApp()
const { handler } = createInstrumentedWorker<Env>({
  serviceName: 'my-worker',
  fetch: (request, env, ctx) => app.fetch(request, env, ctx),
})
export default handler
```

### 3. Set env vars

Two env vars required (set via `wrangler secret put` or Infisical):

| Variable | Example |
|----------|---------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `https://s1234567.us-east-9.betterstackdata.com` |
| `OTEL_EXPORTER_OTLP_HEADERS` | `Authorization=Bearer <source_token>` |

### 4. Create a BetterStack source

**Critical:** Use the `open_telemetry` platform, NOT `cloudflare_worker`. The `cloudflare_worker` platform only accepts logs — no trace spans will be stored.

Create via BetterStack dashboard: Sources > Create Source > Platform: OpenTelemetry.

The source provides the endpoint URL and bearer token for the env vars above.

## Gotchas

- **Exclude exporter from trace propagation:** Prevent `traceparent` headers from being injected into exporter requests (unnecessary noise). Use: `includeTraceContext: (req) => !req.url.includes('betterstackdata.com')`
- **ClickHouse cluster not ready:** After creating a new BetterStack source, the ClickHouse tables aren't provisioned until the first log is ingested. Send a test log via curl first.
- **Log flushing:** CF Workers have no shutdown hook. Use `ctx.waitUntil(loggerProvider.forceFlush())` with a timeout to ensure logs are sent before the isolate is evicted.

## Querying BetterStack Telemetry

See [references/querying.md](references/querying.md) for ClickHouse SQL patterns for querying logs and spans.
