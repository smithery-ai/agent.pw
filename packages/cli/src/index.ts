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
        const target = args[2]
        const valueIndex = args.indexOf('--value')
        const value = valueIndex !== -1 ? args[valueIndex + 1] : undefined
        const slugIndex = args.indexOf('--slug')
        const credentialSlug = slugIndex !== -1 ? args[slugIndex + 1] : undefined
        const authIndex = args.indexOf('--auth')
        const auth = authIndex !== -1 ? args[authIndex + 1] : undefined
        const headers: string[] = []
        for (let i = 3; i < args.length; i++) {
          if ((args[i] === '-H' || args[i] === '--header') && args[i + 1]) {
            headers.push(args[i + 1])
            i++
          }
        }
        if (!target) {
          console.error('Usage: agent.pw cred add <slug-or-host> [--value <key>] [--slug <credential-id>] [--auth headers] [-H "Header: value"]')
          process.exit(1)
        }
        const { addCred } = await import('./commands/cred')
        return addCred(target, value, { auth, credentialSlug, headers })
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
      if (subcommand === 'restrict') {
        const { restrictTokenCmd } = await import('./commands/token')
        return restrictTokenCmd(args.slice(2))
      }
      if (subcommand === 'revoke') {
        const { revokeTokenCmd } = await import('./commands/token')
        return revokeTokenCmd()
      }
      console.error('Usage: agent.pw token <restrict|revoke>')
      process.exit(1)
      return
    }
    case 'profile':
    case 'profiles': {
      const subcommand = args[1]
      if (subcommand === 'list' || !subcommand) {
        const { listProfiles } = await import('./commands/profile')
        return listProfiles()
      } else if (subcommand === 'get') {
        const slug = args[2]
        if (!slug) {
          console.error('Usage: agent.pw profile get <slug>')
          process.exit(1)
        }
        const { getProfileCmd } = await import('./commands/profile')
        return getProfileCmd(slug)
      } else if (subcommand === 'add') {
        const slug = args[2]
        if (!slug) {
          console.error('Usage: agent.pw profile add <slug> --host <hostname> [--file <path>] [--auth headers -H "Header: Prefix {field:Description}"]')
          process.exit(1)
        }
        const hosts: string[] = []
        const headers: string[] = []
        for (let i = 3; i < args.length; i++) {
          if (args[i] === '--host' && args[i + 1]) {
            hosts.push(args[i + 1])
            i++
          } else if ((args[i] === '-H' || args[i] === '--header') && args[i + 1]) {
            headers.push(args[i + 1])
            i++
          }
        }
        const fileIndex = args.indexOf('--file')
        const filePath = fileIndex !== -1 ? args[fileIndex + 1] : undefined
        const authIndex = args.indexOf('--auth')
        const auth = authIndex !== -1 ? args[authIndex + 1] : undefined
        const { addProfile } = await import('./commands/profile')
        return addProfile(slug, hosts, { filePath, auth, headers })
      } else if (subcommand === 'remove' || subcommand === 'rm') {
        const slug = args[2]
        if (!slug) {
          console.error('Usage: agent.pw profile remove <slug>')
          process.exit(1)
        }
        const { removeProfile } = await import('./commands/profile')
        return removeProfile(slug)
      }
      console.error(`Unknown profile subcommand: ${subcommand}`)
      console.error('Usage: agent.pw profile [list|get|add|remove] ...')
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
        const slug = args[2]
        if (!slug) {
          console.error('Usage: agent.pw service get <slug>')
          process.exit(1)
        }
        const { getServiceCmd } = await import('./commands/service')
        return getServiceCmd(slug)
      } else if (subcommand === 'add') {
        const slug = args[2]
        if (!slug) {
          console.error('Usage: agent.pw service add <slug> --host <hostname> [--file <path>] [--auth headers|oauth ...]')
          process.exit(1)
        }
        const hosts: string[] = []
        const headers: string[] = []
        const scopes: string[] = []
        for (let i = 3; i < args.length; i++) {
          if (args[i] === '--host' && args[i + 1]) {
            hosts.push(args[i + 1])
            i++
          } else if ((args[i] === '-H' || args[i] === '--header') && args[i + 1]) {
            headers.push(args[i + 1])
            i++
          } else if (args[i] === '--scope' && args[i + 1]) {
            scopes.push(args[i + 1])
            i++
          }
        }
        const fileIndex = args.indexOf('--file')
        const filePath = fileIndex !== -1 ? args[fileIndex + 1] : undefined
        const authIndex = args.indexOf('--auth')
        const auth = authIndex !== -1 ? args[authIndex + 1] : undefined
        const displayNameIndex = args.indexOf('--display-name')
        const displayName = displayNameIndex !== -1 ? args[displayNameIndex + 1] : undefined
        const descriptionIndex = args.indexOf('--description')
        const description = descriptionIndex !== -1 ? args[descriptionIndex + 1] : undefined
        const docsUrlIndex = args.indexOf('--docs-url')
        const docsUrl = docsUrlIndex !== -1 ? args[docsUrlIndex + 1] : undefined
        const authorizeUrlIndex = args.indexOf('--authorize-url')
        const authorizeUrl = authorizeUrlIndex !== -1 ? args[authorizeUrlIndex + 1] : undefined
        const tokenUrlIndex = args.indexOf('--token-url')
        const tokenUrl = tokenUrlIndex !== -1 ? args[tokenUrlIndex + 1] : undefined
        const identityUrlIndex = args.indexOf('--identity-url')
        const identityUrl = identityUrlIndex !== -1 ? args[identityUrlIndex + 1] : undefined
        const identityPathIndex = args.indexOf('--identity-path')
        const identityPath = identityPathIndex !== -1 ? args[identityPathIndex + 1] : undefined
        const clientIdIndex = args.indexOf('--client-id')
        const clientId = clientIdIndex !== -1 ? args[clientIdIndex + 1] : undefined
        const clientSecretIndex = args.indexOf('--client-secret')
        const clientSecret = clientSecretIndex !== -1 ? args[clientSecretIndex + 1] : undefined
        const { addService } = await import('./commands/service')
        return addService(slug, hosts, {
          filePath,
          auth,
          headers,
          scopes,
          displayName,
          description,
          docsUrl,
          authorizeUrl,
          tokenUrl,
          identityUrl,
          identityPath,
          clientId,
          clientSecret,
        })
      } else if (subcommand === 'remove' || subcommand === 'rm') {
        const slug = args[2]
        if (!slug) {
          console.error('Usage: agent.pw service remove <slug>')
          process.exit(1)
        }
        const { removeService } = await import('./commands/service')
        return removeService(slug)
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
      console.log('  profile                         List credential profiles')
      console.log('  profile get <slug>              Show credential profile details')
      console.log('  profile add <slug> --host <h>   Register a credential profile')
      console.log('    Use --auth headers -H "Authorization: Bearer {api_key:Your API key}" for header forms')
      console.log('  profile remove <slug>           Remove a credential profile')
      console.log('  service                         List service definitions')
      console.log('  service get <slug>              Show service details')
      console.log('  service add <slug> --host <h>   Register a service definition')
      console.log('    Use --auth headers -H "Authorization: Bearer {api_key:Your API key}" for header forms')
      console.log('    Use --auth oauth --authorize-url <url> --token-url <url> [--scope <scope>] for OAuth services')
      console.log('    Optional metadata: --display-name, --description, --docs-url, --identity-url, --identity-path')
      console.log('    Optional managed OAuth: --client-id, --client-secret')
      console.log('  service remove <slug>           Remove a service definition')
      console.log('  cred                            List stored credentials')
      console.log('  cred add <slug-or-host>         Add a credential')
      console.log('  cred remove <slug>              Remove a credential')
      console.log('  token restrict                  Create a restricted child token')
      console.log('    Use --service/--host, --method, --path, and --ttl to attenuate scope')
      console.log('  token revoke                    Revoke the current token')
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
