#!/usr/bin/env bun

import { readFileSync } from 'node:fs'
import { Command } from 'commander'
import { localAgentPwPaths, readLocalConfig } from './src/local/config'
import { ensureLocalConfig } from './src/local/setup'
import {
  getLocalServerStatus,
  serveLocalServerProcess,
  stopLocalServer,
} from './src/local/runtime'

const program = new Command()
  .name('agent.pw-server')
  .description('Legacy local wrapper for agent.pw')
  .version('0.1.0')

program
  .command('setup')
  .description('Initialize a local instance')
  .action(async () => {
    const config = await ensureLocalConfig()
    const paths = localAgentPwPaths()
    console.log('agent.pw is initialized.')
    console.log(`Config: ${paths.configFile}`)
    console.log(`Data:   ${config.dataDir}`)
    console.log(`URL:    http://127.0.0.1:${config.port}`)
    console.log('Next step: run `npx agent.pw init` or `agent.pw-server start`.')
  })

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
  .action(() => {
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
  .action(() => {
    const status = getLocalServerStatus()
    if (!status.configured) {
      console.log('agent.pw is not initialized.')
      console.log('Run `npx agent.pw init` first.')
      return
    }

    console.log(`URL:    ${status.baseUrl}`)
    console.log(status.running ? `State:  running (PID ${status.pid})` : 'State:  stopped')
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

program.parseAsync().catch(err => {
  console.error(err.message ?? err)
  process.exit(1)
})
