import { createInstrumentedWorker } from './src/lib/otel'
import { createApp } from './src/managed/app'

const app = createApp()

const { handler } = createInstrumentedWorker<Env>({
  serviceName: 'warden',
  fetch: (request, env, ctx) => app.fetch(request, env, ctx),
})

export default handler
