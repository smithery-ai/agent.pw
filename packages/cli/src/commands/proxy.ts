import { spawn } from 'node:child_process'
import { readCliConfig, readTokenStack } from '../config'
import { buildLocalBaseUrl, readLocalConfig } from '../../../server/src/local/config'
import { mintLocalRootToken } from '../../../server/src/local/setup'

const LOCAL_BYPASS_HOSTS = ['127.0.0.1', 'localhost', '::1']

function mergeNoProxy(
  currentValue: string | undefined,
  defaults = LOCAL_BYPASS_HOSTS,
) {
  const values = new Set(
    (currentValue ?? '')
      .split(',')
      .map(item => item.trim())
      .filter(Boolean),
  )

  for (const value of defaults) {
    values.add(value)
  }

  return Array.from(values).join(',')
}

function shellEscape(value: string) {
  return `'${value.replaceAll("'", `'\"'\"'`)}'`
}

function buildProxyUrl(baseUrl: string, token: string) {
  const endpoint = new URL(baseUrl)
  const auth = `agentpw:${encodeURIComponent(token)}@`
  return `${endpoint.protocol}//${auth}${endpoint.host}`
}

export function buildProxyEnvironment(
  baseUrl: string,
  token: string,
  env: NodeJS.ProcessEnv = process.env,
) {
  const proxyUrl = buildProxyUrl(baseUrl, token)
  const upperNoProxy = mergeNoProxy(env.NO_PROXY)
  const lowerNoProxy = mergeNoProxy(env.no_proxy ?? env.NO_PROXY)

  return {
    HTTP_PROXY: proxyUrl,
    HTTPS_PROXY: proxyUrl,
    ALL_PROXY: proxyUrl,
    http_proxy: proxyUrl,
    https_proxy: proxyUrl,
    all_proxy: proxyUrl,
    NO_PROXY: upperNoProxy,
    no_proxy: lowerNoProxy,
  }
}

export function resolveLocalProxySettings() {
  const config = readLocalConfig()
  if (!config) {
    console.error('Local forward-proxy mode requires a local agent.pw daemon.')
    console.error('Run `npx agent.pw start` first, then retry.')
    process.exit(1)
  }

  const cliConfig = readCliConfig()
  const stack = readTokenStack()
  const token = stack.at(-1) ?? cliConfig?.token ?? mintLocalRootToken(config)

  return {
    baseUrl: buildLocalBaseUrl(config.port),
    token,
  }
}

export function normalizeExecArgs(args: string[]) {
  return args[0] === '--' ? args.slice(1) : args
}

export async function proxyEnvCmd() {
  const { baseUrl, token } = resolveLocalProxySettings()
  const proxyEnv = buildProxyEnvironment(baseUrl, token)

  for (const [key, value] of Object.entries(proxyEnv)) {
    console.log(`export ${key}=${shellEscape(value)}`)
  }
}

export async function proxyExecCmd(args: string[]) {
  const command = normalizeExecArgs(args)
  if (command.length === 0) {
    console.error('Usage: agent.pw exec -- <command> [args...]')
    process.exit(1)
  }

  const { baseUrl, token } = resolveLocalProxySettings()
  const proxyEnv = buildProxyEnvironment(baseUrl, token)
  const [file, ...childArgs] = command

  await new Promise<void>((resolve, reject) => {
    const child = spawn(file, childArgs, {
      stdio: 'inherit',
      env: { ...process.env, ...proxyEnv },
    })

    child.once('error', reject)
    child.once('close', code => {
      process.exitCode = code ?? 1
      resolve()
    })
  })
}
