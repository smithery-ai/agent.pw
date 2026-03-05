# agent.pw

Open-source credential vault and API proxy for agents. Keeps secrets out of your prompts.

```
Agent ──▶ agent.pw/proxy/api.github.com/user ──▶ api.github.com/user
       (bearer token)                           (real API key injected)
```

## Getting Started (Cloud)

```bash
npx agent.pw login
```

Authenticates with the agent.pw Cloud backend. Services are pre-configured — no setup needed.

Add a credential:

```
npx agent.pw cred add api.linear.app
→ Paste your API key: ****
→ Stored.
```

Use the proxy — `npx agent.pw curl` works like `curl` but injects the bearer token automatically:

```bash
npx agent.pw curl agent.pw/proxy/api.linear.app/graphql \
  -d '{"query":"{ issues { nodes { id title } } }"}'
```

agent.pw looks up `api.linear.app`, injects the stored credential, and proxies the request. The agent never sees the API key.

View stored credentials:

```
npx agent.pw cred

SERVICE                       ADDED
api.linear.app                2d ago
api.github.com                5d ago
```

Credentials are write-only. Agents cannot exfiltrate them.

## Getting Started (Self-Hosted)

```bash
npx agent.pw setup
```

Generates Biscuit signing keys (Ed25519), creates a local PGlite database, and mints a root token. Run `npx agent.pw start` to start the proxy. Everything runs on your machine — no external dependencies.

You start with an empty service table. Add services using the skill in Claude Code or Codex:

```
/add-service api.linear.app
```

The agent reads the API docs, figures out the auth method and headers, and writes the service entry. You approve the result.

Or add manually:

```bash
npx agent.pw service add api.linear.app --file service.json
```

Then add credentials and use the proxy the same way as Cloud — just pointed at your local instance.

The CLI auto-detects which mode you're in. If a local instance is running, commands go there. Otherwise they go to the managed backend. `npx agent.pw status` shows which backend you're connected to.

## Concepts

**Services.** A service defines how a particular API is authenticated. Each entry maps a hostname to its auth configuration: what kind of credentials are accepted (API key, OAuth), which headers to inject, and an OAuth app (client ID + secret) if applicable.

**Credentials.** A credential is the specific secret used to connect to a service — the actual API key or OAuth token. Credentials are stored encrypted and never exposed to agents. When an agent makes a proxied request, agent.pw looks up the credential for that service and injects it into the upstream request.

**Tokens.** On setup, agent.pw mints a bearer token (`wdn_` prefix). The master token has full access to the service table and credential store. Tokens given to agents can be attenuated — scoped to specific services, methods, and TTLs. A restricted token can never gain more power than its parent. Tokens can be revoked instantly. Backed by [Biscuit](https://www.biscuitsec.org/) for cryptographic attenuation.

## CLI Commands

```
npx agent.pw login [--host <url>]              authenticate with Cloud (default: https://agent.pw)
npx agent.pw logout                            log out from agent.pw
npx agent.pw setup                             self-hosted: generate keys, create DB, mint root token
npx agent.pw start                             start the local proxy server
npx agent.pw stop                              stop the local proxy server
npx agent.pw status                            show connected backend + token info

npx agent.pw service                           list configured services
npx agent.pw service get <hostname>            show service details
npx agent.pw service add <hostname> [--file f] register a service
npx agent.pw service remove <hostname>         remove a service

npx agent.pw cred                              list credentials
npx agent.pw cred add <service> [--value <key>] add a credential
npx agent.pw cred remove <service>             remove a credential

npx agent.pw curl <url> [curl flags]           proxy request with auto-injected token
```

## API Reference

```
Proxy:
  ALL  /proxy/:service/*             proxy with injected credentials (bearer token required)

Credentials:
  GET    /credentials                list credentials (org from token)
  PUT    /credentials/:service       store a credential
  DELETE /credentials/:service       remove a credential

Services:
  GET    /services                   list services
  GET    /services/:service          get service details
  PUT    /services/:service          register/update a service
  DELETE /services/:service          remove a service

Tokens:
  POST   /tokens/mint               mint a new token
  POST   /tokens/restrict           attenuate a token (no auth needed)
  POST   /tokens/revoke             revoke a token

Infrastructure:
  GET    /.well-known/jwks.json      Ed25519 public key (JWK format)
```

## Repo Structure

```
agent.pw/
  src/
    core/           ← proxy, vault, tokens (all OSS)
    managed/        ← WorkOS auth, managed OAuth, UI
    routes/         ← API route handlers
    cli/            ← CLI commands
    db/             ← Drizzle schema and queries
    lib/            ← shared utilities, crypto
  entry.local.ts    ← Bun + PGlite entry point
  entry.managed.ts  ← Cloudflare Workers entry point
```

## Development

```bash
pnpm install
pnpm test          # run tests (uses in-memory PGlite — no database needed)
pnpm test:watch    # watch mode
pnpm run build     # typecheck
pnpm run lint      # lint
```

### Database

```bash
pnpm run db:generate   # generate migrations from schema changes
pnpm run db:push       # push schema to database (dev)
```

## License

MIT
