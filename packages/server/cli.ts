#!/usr/bin/env bun

import { fileURLToPath } from 'node:url'
import { readFileSync } from 'node:fs'
import { Command } from 'commander'
import { buildLocalBaseUrl, localAgentPwPaths, readLocalConfig } from './src/local/config'
import { ensureLocalServerDaemon } from './src/local/daemon'
import { ensureLocalConfig } from './src/local/setup'
import {
  getLocalServerStatus,
  probeLocalServer,
  serveLocalServerProcess,
  stopLocalServer,
} from './src/local/runtime'

const program = new Command()
  .name('agent.pw-server')
  .description('Legacy local wrapper for agent.pw')
  .version('0.1.0')

program.addHelpText(
  'beforeAll',
  [
    'Note: `npx .` at the repo root runs the local server wrapper package (`@agent.pw/server`).',
    'For the published OSS CLI, run `cd packages/cli && npx . init`.',
    '',
  ].join('\n'),
)

async function initLocalInstance() {
  const config = await ensureLocalConfig()
  const paths = localAgentPwPaths()
  const cliPath = fileURLToPath(import.meta.url)
  const server = await ensureLocalServerDaemon({
    command: process.execPath,
    args: [cliPath, 'start'],
  }, paths)

  console.log('agent.pw is ready.')
  console.log(`Config: ${paths.configFile}`)
  console.log(`Data:   ${config.dataDir}`)
  console.log(`URL:    ${buildLocalBaseUrl(config.port)}`)
  console.log(server.started ? `State:  started (PID ${server.pid})` : 'State:  running')
  console.log(`Log:    ${server.logFile}`)
  console.log('For the hosted vault onboarding flow, run `cd packages/cli && npx . init`.')
}

program
  .command('init')
  .description('Initialize, repair, and start a local instance')
  .action(initLocalInstance)

program
  .command('start')
  .description('Start the local server in the foreground')
  .action(async () => {
    const config = readLocalConfig()
    if (!config) {
      console.error('agent.pw is not initialized. Run `npx agent.pw init` first.')
      process.exit(1)
    }

    const status = getLocalServerStatus()
    if (status.running) {
      console.error(`agent.pw is already running at ${status.baseUrl} (PID ${status.pid}).`)
      process.exit(1)
    }

    await serveLocalServerProcess(config)
    console.log(`agent.pw local server running on http://127.0.0.1:${config.port}`)
  })

program
  .command('stop')
  .description('Stop the local server')
  .action(async () => {
    const status = getLocalServerStatus()
    if (status.baseUrl && !status.running && (await probeLocalServer(status.baseUrl))) {
      console.log(`agent.pw is reachable at ${status.baseUrl}, but this wrapper is not managing that process.`)
      return
    }

    const stopped = stopLocalServer()
    if (!stopped) {
      console.log('agent.pw is not running.')
      return
    }

    console.log('Stopped local agent.pw server.')
  })

program
  .command('status')
  .description('Show local server status')
  .action(async () => {
    const status = getLocalServerStatus()
    if (!status.configured) {
      console.log('agent.pw is not initialized.')
      console.log('Run `npx agent.pw init` first.')
      return
    }

    console.log(`URL:    ${status.baseUrl}`)
    const reachable = status.baseUrl ? await probeLocalServer(status.baseUrl) : false
    if (reachable && status.pid) {
      console.log(`State:  running (PID ${status.pid})`)
      return
    }

    if (reachable) {
      console.log('State:  reachable (unmanaged)')
      return
    }

    if (status.pid) {
      console.log(`State:  unresponsive (PID ${status.pid})`)
      return
    }

    console.log('State:  stopped')
  })

program
  .command('logs')
  .description('Print the local server log file')
  .action(() => {
    const paths = localAgentPwPaths()
    try {
      const logs = readFileSync(paths.logFile, 'utf8')
      process.stdout.write(logs)
    } catch {
      console.error(`No log file found at ${paths.logFile}.`)
      process.exit(1)
    }
  })

if (process.argv[2] === 'setup') {
  process.argv[2] = 'init'
}

program.parseAsync().catch(err => {
  console.error(err.message ?? err)
  process.exit(1)
})
