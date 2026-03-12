import { Command } from 'commander'
import pkg from '../package.json'

const program = new Command()
  .name('agent.pw')
  .description('Authenticated proxy for APIs\n\nGet started:  npx agent.pw init')
  .version(pkg.version)

function parsePositiveInt(value: string) {
  const parsed = Number.parseInt(value, 10)
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`Invalid limit: ${value}`)
  }
  return parsed
}

function addPaginationOptions(command: Command) {
  return command
    .option('--limit <n>', 'Maximum number of results to return', parsePositiveInt)
    .option('--cursor <cursor>', 'Resume from a prior nextCursor value')
    .option('--all', 'Fetch and print every page')
}

function assertValidPaginationOptions(command: Command) {
  const opts = command.optsWithGlobals() as { all?: boolean; cursor?: string }
  if (opts.all && opts.cursor) {
    throw new Error('--all cannot be combined with --cursor')
  }
}

program
  .command('init')
  .description('Set up agent.pw (login + install skill)')
  .action(async () => {
    const { init } = await import('./commands/init')
    return init()
  })

program
  .command('status')
  .description('Show connection status')
  .action(async () => {
    try {
      const { resolve } = await import('./resolve')
      const { url } = await resolve()
      console.log(`agent.pw available at ${url}`)
    } catch {
      // resolve() already prints error message and exits
    }
  })

program
  .command('login')
  .description('Authenticate with agent.pw (auth only)')
  .option('--host <url>', 'Target host')
  .option('--token <token>', 'Use a pre-minted token instead of browser login')
  .action(async (opts) => {
    const { login } = await import('./commands/login')
    return login(opts.host, opts.token)
  })

program
  .command('logout')
  .description('Log out')
  .action(async () => {
    const { logout } = await import('./commands/logout')
    return logout()
  })

// ─── profile ─────────────────────────────────────────────────────────────────

const profileCmd = program
  .command('profile')
  .description('Manage credential profiles')
addPaginationOptions(profileCmd)
profileCmd
  .action(async (_, cmd) => {
    assertValidPaginationOptions(cmd)
    const { listProfiles } = await import('./commands/profile')
    return listProfiles(cmd.optsWithGlobals())
  })

addPaginationOptions(profileCmd
  .command('list')
  .description('List profiles')
  .action(async (_, cmd) => {
    assertValidPaginationOptions(cmd)
    const { listProfiles } = await import('./commands/profile')
    return listProfiles(cmd.optsWithGlobals())
  }))

profileCmd
  .command('get <slug>')
  .description('Show profile details')
  .action(async (slug) => {
    const { getProfileCmd } = await import('./commands/profile')
    return getProfileCmd(slug)
  })

profileCmd
  .command('add <slug>')
  .description('Register a profile')
  .option('--host <hostname...>', 'Target hostname (repeatable)')
  .option('--file <path>', 'Load profile from JSON file')
  .option('--auth <type>', 'Auth type (headers or oauth)')
  .option('-H, --header <template...>', 'Header template')
  .option('--scope <scope...>', 'OAuth scope (repeatable)')
  .option('--authorize-url <url>', 'OAuth authorization URL')
  .option('--token-url <url>', 'OAuth token URL')
  .option('--client-id <id>', 'Managed OAuth client ID')
  .option('--client-secret <secret>', 'Managed OAuth client secret')
  .option('--display-name <name>', 'Human-readable name')
  .option('--description <text>', 'Profile description')
  .option('--docs-url <url>', 'Documentation URL')
  .option('--identity-url <url>', 'Identity verification URL')
  .option('--identity-path <path>', 'JSONPath for identity extraction')
  .action(async (slug, opts) => {
    const { addProfile } = await import('./commands/profile')
    return addProfile(slug, opts.host ?? [], {
      filePath: opts.file,
      auth: opts.auth,
      headers: opts.header,
      scopes: opts.scope,
      authorizeUrl: opts.authorizeUrl,
      tokenUrl: opts.tokenUrl,
      clientId: opts.clientId,
      clientSecret: opts.clientSecret,
      displayName: opts.displayName,
      description: opts.description,
      docsUrl: opts.docsUrl,
      identityUrl: opts.identityUrl,
      identityPath: opts.identityPath,
    })
  })

profileCmd
  .command('remove <slug>')
  .alias('rm')
  .description('Remove a profile')
  .action(async (slug) => {
    const { removeProfile } = await import('./commands/profile')
    return removeProfile(slug)
  })

// ─── cred ────────────────────────────────────────────────────────────────────

const credCmd = program
  .command('cred')
  .alias('credential')
  .alias('creds')
  .description('Manage stored credentials')
addPaginationOptions(credCmd)
credCmd
  .action(async (_, cmd) => {
    assertValidPaginationOptions(cmd)
    const { listCreds } = await import('./commands/cred')
    return listCreds(cmd.optsWithGlobals())
  })

addPaginationOptions(credCmd
  .command('list')
  .description('List credentials')
  .action(async (_, cmd) => {
    assertValidPaginationOptions(cmd)
    const { listCreds } = await import('./commands/cred')
    return listCreds(cmd.optsWithGlobals())
  }))

credCmd
  .command('add <slug-or-host>')
  .description('Add a credential')
  .option('--value <key>', 'API key value')
  .option('--slug <id>', 'Credential ID')
  .option('--auth <type>', 'Auth type')
  .option('-H, --header <value...>', 'Header value')
  .action(async (target, opts) => {
    const { addCred } = await import('./commands/cred')
    return addCred(target, opts.value, {
      auth: opts.auth,
      credentialName: opts.slug,
      headers: opts.header,
    })
  })

credCmd
  .command('remove <slug>')
  .alias('rm')
  .description('Remove a credential')
  .action(async (slug) => {
    const { removeCred } = await import('./commands/cred')
    return removeCred(slug)
  })

// ─── token ───────────────────────────────────────────────────────────────────

const tokenCmd = program
  .command('token')
  .description('Manage access tokens')
  .action(async () => {
    const { inspectTokenCmd } = await import('./commands/token')
    return inspectTokenCmd()
  })

tokenCmd
  .command('restrict')
  .description('Create a restricted child token')
  .option('--service <host...>', 'Limit to service host')
  .option('--host <host...>', 'Limit to service host')
  .option('--method <verb...>', 'Limit to HTTP method')
  .option('--path <prefix...>', 'Limit to path prefix')
  .option('--ttl <duration>', 'Token lifetime (e.g. 1h)')
  .action(async (opts) => {
    const { restrictTokenCmd } = await import('./commands/token')
    return restrictTokenCmd({
      services: [...(opts.service ?? []), ...(opts.host ?? [])],
      methods: opts.method,
      paths: opts.path,
      ttl: opts.ttl,
    })
  })

tokenCmd
  .command('revoke')
  .description('Revoke the current token')
  .action(async () => {
    const { revokeTokenCmd } = await import('./commands/token')
    return revokeTokenCmd()
  })

tokenCmd
  .command('push')
  .description('Restrict and push token onto the stack')
  .option('--service <host...>', 'Limit to service host')
  .option('--host <host...>', 'Limit to service host')
  .option('--method <verb...>', 'Limit to HTTP method')
  .option('--path <prefix...>', 'Limit to path prefix')
  .option('--ttl <duration>', 'Token lifetime (e.g. 1h)')
  .action(async (opts) => {
    const { pushTokenCmd } = await import('./commands/token')
    return pushTokenCmd({
      services: [...(opts.service ?? []), ...(opts.host ?? [])],
      methods: opts.method,
      paths: opts.path,
      ttl: opts.ttl,
    })
  })

tokenCmd
  .command('pop')
  .description('Pop the top token, revert to previous')
  .action(async () => {
    const { popTokenCmd } = await import('./commands/token')
    return popTokenCmd()
  })

// ─── curl ────────────────────────────────────────────────────────────────────

program
  .command('curl')
  .description('Proxy-aware curl wrapper')
  .allowUnknownOption()
  .allowExcessArguments()
  .action(async (_, cmd) => {
    const { curl } = await import('./commands/curl')
    return curl(cmd.args)
  })

program.parseAsync().catch(err => {
  console.error(err.message ?? err)
  process.exit(1)
})
