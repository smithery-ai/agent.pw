#!/usr/bin/env bun

const args = process.argv.slice(2)
const command = args[0]

async function main() {
  switch (command) {
    case 'setup': {
      const { setup } = await import('./commands/setup')
      return setup()
    }
    case 'start': {
      const { start } = await import('./commands/start')
      return start()
    }
    case 'stop': {
      const { stop } = await import('./commands/stop')
      return stop()
    }
    case 'login': {
      const hostIndex = args.indexOf('--host')
      const host = hostIndex !== -1 ? args[hostIndex + 1] : undefined
      const { login } = await import('./commands/login')
      return login(host)
    }
    case 'logout': {
      const { logout } = await import('./commands/logout')
      return logout()
    }
    case 'cred':
    case 'credential':
    case 'creds': {
      const subcommand = args[1]
      if (subcommand === 'add') {
        const slug = args[2]
        const valueIndex = args.indexOf('--value')
        const value = valueIndex !== -1 ? args[valueIndex + 1] : undefined
        if (!slug) {
          console.error('Usage: agent.pw cred add <slug> [--value <key>]')
          process.exit(1)
        }
        const { addCred } = await import('./commands/cred')
        return addCred(slug, value)
      }
      if (subcommand === 'remove' || subcommand === 'rm') {
        const slug = args[2]
        if (!slug) {
          console.error('Usage: agent.pw cred remove <slug>')
          process.exit(1)
        }
        const { removeCred } = await import('./commands/cred')
        return removeCred(slug)
      }
      const { listCreds } = await import('./commands/cred')
      return listCreds()
    }
    case 'token': {
      const subcommand = args[1]
      if (subcommand === 'revoke') {
        const { revokeTokenCmd } = await import('./commands/token')
        return revokeTokenCmd()
      }
      console.error('Usage: agent.pw token revoke')
      process.exit(1)
      return
    }
    case 'service':
    case 'services': {
      const subcommand = args[1]
      if (subcommand === 'list' || !subcommand) {
        const { listServices } = await import('./commands/service')
        return listServices()
      } else if (subcommand === 'get') {
        const svc = args[2]
        if (!svc) {
          console.error('Usage: agent.pw service get <slug>')
          process.exit(1)
        }
        const { getServiceCmd } = await import('./commands/service')
        return getServiceCmd(svc)
      } else if (subcommand === 'add') {
        const svc = args[2]
        if (!svc) {
          console.error('Usage: agent.pw service add <slug> --host <hostname> [--file <path>]')
          process.exit(1)
        }
        // Collect all --host values
        const hosts: string[] = []
        for (let i = 3; i < args.length; i++) {
          if (args[i] === '--host' && args[i + 1]) {
            hosts.push(args[i + 1])
            i++ // skip the value
          }
        }
        const fileIndex = args.indexOf('--file')
        const filePath = fileIndex !== -1 ? args[fileIndex + 1] : undefined
        const { addService } = await import('./commands/service')
        return addService(svc, hosts, filePath)
      } else if (subcommand === 'remove' || subcommand === 'rm') {
        const svc = args[2]
        if (!svc) {
          console.error('Usage: agent.pw service remove <slug>')
          process.exit(1)
        }
        const { removeService } = await import('./commands/service')
        return removeService(svc)
      }
      console.error(`Unknown service subcommand: ${subcommand}`)
      console.error('Usage: agent.pw service [list|get|add|remove] ...')
      process.exit(1)
      return
    }
    case 'curl': {
      const { curl } = await import('./commands/curl')
      return curl(args.slice(1))
    }
    case 'status': {
      try {
        const { resolve } = await import('./resolve')
        const { url } = await resolve()
        console.log(`agent.pw available at ${url}`)
      } catch {
        // resolve() already prints error message and exits
      }
      return
    }
    default: {
      console.log('Usage: agent.pw <command>')
      console.log('')
      console.log('Commands:')
      console.log('  login [--host <url>]            Log in to agent.pw (default: https://agent.pw)')
      console.log('  logout                          Log out from agent.pw')
      console.log('  setup                           Set up a local instance (keys, database)')
      console.log('  start                           Start the local proxy server')
      console.log('  stop                            Stop the local proxy server')
      console.log('  status                          Show connection status')
      console.log('  service                         List registered services')
      console.log('  service get <slug>              Show service details')
      console.log('  service add <slug> --host <h>   Register a service')
      console.log('  service remove <slug>           Remove a service')
      console.log('  cred                            List stored credentials')
      console.log('  cred add <slug> [--value <k>]   Add a credential')
      console.log('  cred remove <slug>              Remove a credential')
      console.log('  token revoke                     Revoke the current token')
      console.log('  curl <url> [args...]             Proxy-aware curl wrapper')
      if (command && command !== 'help' && command !== '--help' && command !== '-h') {
        console.error(`\nUnknown command: ${command}`)
        process.exit(1)
      }
    }
  }
}

main().catch(err => {
  console.error(err.message ?? err)
  process.exit(1)
})
