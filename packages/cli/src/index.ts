#!/usr/bin/env bun

const args = process.argv.slice(2)
const command = args[0]

function hasFlag(flag: string) {
  return args.includes(flag)
}

function showHelp(group?: string) {
  switch (group) {
    case 'profile':
      console.log('Usage: agent.pw profile [subcommand]')
      console.log('')
      console.log('Manage credential profiles.')
      console.log('')
      console.log('Subcommands:')
      console.log('  (none)          List profiles')
      console.log('  get <slug>      Show profile details')
      console.log('  add <slug>      Register a profile')
      console.log('  remove <slug>   Remove a profile')
      console.log('')
      console.log("Run 'agent.pw profile add --help' for add options.")
      return

    case 'profile add':
      console.log('Usage: agent.pw profile add <slug> --host <hostname> [options]')
      console.log('')
      console.log('Options:')
      console.log('  --host <hostname>          Target hostname (repeatable)')
      console.log('  --file <path>              Load profile from JSON file')
      console.log('  --auth headers             Use header-based auth')
      console.log('  --auth oauth               Use OAuth')
      console.log('  -H "Header: Prefix {field:Description}"  Header template')
      console.log('')
      console.log('OAuth options:')
      console.log('  --authorize-url <url>      OAuth authorization URL')
      console.log('  --token-url <url>          OAuth token URL')
      console.log('  --scope <scope>            OAuth scope (repeatable)')
      console.log('  --client-id <id>           Managed OAuth client ID')
      console.log('  --client-secret <secret>   Managed OAuth client secret')
      console.log('')
      console.log('Metadata:')
      console.log('  --display-name <name>      Human-readable name')
      console.log('  --description <text>       Profile description')
      console.log('  --docs-url <url>           Documentation URL')
      console.log('  --identity-url <url>       Identity verification URL')
      console.log('  --identity-path <path>     JSONPath for identity extraction')
      return

    case 'cred':
      console.log('Usage: agent.pw cred [subcommand]')
      console.log('')
      console.log('Manage stored credentials.')
      console.log('')
      console.log('Subcommands:')
      console.log('  (none)                     List credentials')
      console.log('  add <slug-or-host>         Add a credential')
      console.log('  remove <slug>              Remove a credential')
      return

    case 'token':
      console.log('Usage: agent.pw token <subcommand>')
      console.log('')
      console.log('Manage access tokens.')
      console.log('')
      console.log('Subcommands:')
      console.log('  restrict   Create a restricted child token')
      console.log('  revoke     Revoke the current token')
      console.log('')
      console.log('Restrict options:')
      console.log('  --service/--host <host>    Limit to service')
      console.log('  --method <verb>            Limit to HTTP method')
      console.log('  --path <prefix>            Limit to path prefix')
      console.log('  --ttl <duration>           Token lifetime (e.g. 1h)')
      return

    default:
      console.log('Usage: agent.pw <command>')
      console.log('')
      console.log('Commands:')
      console.log('  login      Log in to agent.pw')
      console.log('  logout     Log out')
      console.log('  status     Show connection status')
      console.log('  profile    Manage credential profiles')
      console.log('  cred       Manage stored credentials')
      console.log('  token      Manage access tokens')
      console.log('  curl       Proxy-aware curl wrapper')
      console.log('')
      console.log("Run 'agent.pw <command> --help' for command details.")
      if (command && command !== 'help' && command !== '--help' && command !== '-h') {
        console.error(`\nUnknown command: ${command}`)
        process.exit(1)
      }
  }
}

async function main() {
  switch (command) {
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
      if (subcommand === '--help' || subcommand === '-h') {
        return showHelp('cred')
      }
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
      if (subcommand === '--help' || subcommand === '-h' || !subcommand) {
        return showHelp('token')
      }
      if (subcommand === 'restrict') {
        const { restrictTokenCmd } = await import('./commands/token')
        return restrictTokenCmd(args.slice(2))
      }
      if (subcommand === 'revoke') {
        const { revokeTokenCmd } = await import('./commands/token')
        return revokeTokenCmd()
      }
      console.error(`Unknown token subcommand: ${subcommand}`)
      showHelp('token')
      process.exit(1)
      return
    }
    case 'profile':
    case 'profiles': {
      const subcommand = args[1]
      if (subcommand === '--help' || subcommand === '-h') {
        return showHelp('profile')
      }
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
        if (hasFlag('--help') || hasFlag('-h')) {
          return showHelp('profile add')
        }
        const slug = args[2]
        if (!slug) {
          console.error('Usage: agent.pw profile add <slug> --host <hostname>')
          console.error("Run 'agent.pw profile add --help' for all options.")
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
        const { addProfile } = await import('./commands/profile')
        return addProfile(slug, hosts, {
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
          console.error('Usage: agent.pw profile remove <slug>')
          process.exit(1)
        }
        const { removeProfile } = await import('./commands/profile')
        return removeProfile(slug)
      }
      console.error(`Unknown profile subcommand: ${subcommand}`)
      showHelp('profile')
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
      showHelp()
    }
  }
}

main().catch(err => {
  console.error(err.message ?? err)
  process.exit(1)
})
