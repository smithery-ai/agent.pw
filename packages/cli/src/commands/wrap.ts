import { spawn } from 'node:child_process'
import { requestJson } from '../http'
import { resolve } from '../resolve'

interface WrapOptions {
  services?: string[]
  methods?: string[]
  paths?: string[]
  ttl?: string
}

const LOCAL_NO_PROXY_HOSTS = ['127.0.0.1', 'localhost', '::1']

function buildConstraint(opts: WrapOptions) {
  const constraint: Record<string, unknown> = {}

  if (opts.services && opts.services.length > 0) {
    constraint.services = opts.services.length === 1 ? opts.services[0] : opts.services
  }

  if (opts.methods && opts.methods.length > 0) {
    const upper = opts.methods.map(method => method.toUpperCase())
    constraint.methods = upper.length === 1 ? upper[0] : upper
  }

  if (opts.paths && opts.paths.length > 0) {
    constraint.paths = opts.paths.length === 1 ? opts.paths[0] : opts.paths
  }

  if (opts.ttl) {
    constraint.ttl = opts.ttl
  }

  return constraint
}

function hasRestrictions(opts: WrapOptions) {
  return Object.keys(buildConstraint(opts)).length > 0
}

function isLoopbackHost(hostname: string) {
  const normalized = hostname.toLowerCase()
  return normalized === '127.0.0.1' || normalized === 'localhost' || normalized === '::1'
}

function buildProxyUrl(proxyUrl: string, token: string, opts: WrapOptions) {
  const proxy = new URL(proxyUrl)

  if (!hasRestrictions(opts) && isLoopbackHost(proxy.hostname)) {
    return proxy.toString()
  }

  proxy.username = '_'
  proxy.password = token
  return proxy.toString()
}

async function mintRestrictedToken(opts: WrapOptions) {
  const constraint = buildConstraint(opts)

  if (!hasRestrictions(opts)) {
    return null
  }

  const res = await requestJson<{ token: string }>('/tokens/restrict', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ constraints: [constraint] }),
  })

  return res.token
}

function buildEnv(proxyUrl: string) {
  const env = { ...process.env }
  const existingNoProxy = [env.NO_PROXY, env.no_proxy]
    .flatMap(value => value?.split(',') ?? [])
    .map(value => value.trim())
    .filter(Boolean)
  const noProxy = Array.from(new Set([...LOCAL_NO_PROXY_HOSTS, ...existingNoProxy])).join(',')

  env.HTTP_PROXY = proxyUrl
  env.HTTPS_PROXY = proxyUrl
  env.http_proxy = proxyUrl
  env.https_proxy = proxyUrl
  env.NO_PROXY = noProxy
  env.no_proxy = noProxy
  return env
}

function isSignal(value: NodeJS.Signals | number | null): value is NodeJS.Signals {
  return typeof value === 'string'
}

async function spawnChild(command: string, args: string[], env: NodeJS.ProcessEnv) {
  const child = spawn(command, args, {
    stdio: 'inherit',
    env,
  })

  const forwardSignal = (signal: NodeJS.Signals) => {
    if (!child.killed) {
      child.kill(signal)
    }
  }

  process.on('SIGINT', forwardSignal)
  process.on('SIGTERM', forwardSignal)

  try {
    const result = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
      child.on('error', reject)
      child.on('exit', (code, signal) => resolve({ code, signal }))
    })

    if (isSignal(result.signal)) {
      process.kill(process.pid, result.signal)
      return 1
    }

    return result.code ?? 0
  } finally {
    process.off('SIGINT', forwardSignal)
    process.off('SIGTERM', forwardSignal)
  }
}

export async function wrap(args: string[], opts: WrapOptions) {
  if (args.length === 0) {
    console.error('Usage: agent.pw wrap -- <command> [args...]')
    process.exit(1)
  }

  const { url, token } = await resolve()
  const proxyToken = await mintRestrictedToken(opts)
  const proxyUrl = buildProxyUrl(url, proxyToken ?? token, opts)
  const env = buildEnv(proxyUrl)
  const [command, ...commandArgs] = args
  const exitCode = await spawnChild(command, commandArgs, env)
  process.exit(exitCode)
}
