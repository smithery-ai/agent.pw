# agent.pw

Open-source credential vault and API proxy for agents. Keeps secrets out of your prompts.

```
Agent ──▶ agent.pw/proxy/api.github.com/user ──▶ api.github.com/user
       (agentpw-token)                         (real API key injected)
```


## Development CLI setup

```bash
pnpm i
pnpm build
npm link
```

Then run the CLI directly as `agent.pw`.

## Getting Started (Cloud)

```bash
agent.pw login
```

Authenticates with the agent.pw Cloud backend. Services are pre-configured — no setup needed.

List the hosted profile catalog:

```bash
agent.pw profile list
```

Add a credential:

```bash
agent.pw cred add api.linear.app --slug linear
```

Or add a manual header credential for a host that does not have a profile yet:

```bash
agent.pw cred add api.linear.app --auth headers \
  -H "Authorization: Bearer {token:Access token}"
```

The `{token:...}` placeholder is expanded interactively and stored encrypted.

Profile-driven browser auth starts from the proxy itself: the first unauthenticated `401` returns bootstrap headers such as `agentpw-profile` and `agentpw-auth-url`.

Use the proxy. `agent.pw curl` sends your agent token in `agentpw-token` and targets the host-first route:

```
agent.pw curl https://agent.pw/proxy/api.linear.app/graphql \
  -d '{"query":"{ issues { nodes { id title } } }"}'
```

agent.pw matches `api.linear.app`, injects the stored credential, and proxies the request. The agent never sees the API key.

View stored credentials:

```
agent.pw cred

HOST             SLUG        ADDED
api.linear.app   linear      2d ago
api.github.com   github      5d ago
```

Credentials are write-only. Agents cannot exfiltrate them.

## Getting Started (Self-Hosted)

```bash
agent.pw setup
```

Generates Biscuit signing keys (Ed25519), creates a local PGlite database, and mints a root token. Run `agent.pw start` to start the proxy. Everything runs on your machine — no external dependencies.

You start with an empty credential profile table. Add profiles using the skill in Claude Code or Codex:

```
/add-profile api.linear.app
```

The agent reads the API docs, figures out the auth method and headers, and writes the profile entry. You approve the result.

Or add manually:

```bash
agent.pw profile add linear --host api.linear.app --file profile.json
```

Then add credentials and use the same host-first proxy path locally:

```bash
agent.pw cred add api.linear.app --slug linear
agent.pw curl http://localhost:3000/proxy/api.linear.app/graphql \
  -d '{"query":"{ issues { nodes { id title } } }"}'
```

The CLI auto-detects which mode you're in. If a local instance is running, commands go there. Otherwise they go to the managed backend. `agent.pw status` shows which backend you're connected to.

## Concepts

**Credential profiles.** A profile defines how an API is authenticated. It maps one or more hostnames to auth schemes, injected headers, and optional OAuth app metadata. Requests can be routed purely by hostname or with an explicit `/proxy/{profile}/{hostname}/...` override.

**Credentials.** A credential is the specific secret used to connect to a profile or host: an API key, OAuth token, or arbitrary header set. Credentials are stored encrypted and never exposed to agents. When an agent makes a proxied request, agent.pw selects a matching credential for that host and injects it into the upstream request unless the caller already supplied `Authorization`.

**Tokens.** On setup, agent.pw mints a Biscuit token (`apw_` prefix). Send it in the `agentpw-token` header. The root token can manage profiles and credentials. Tokens given to agents can be attenuated by profile or host, method, and TTL. A restricted token can never gain more power than its parent. Tokens can be revoked instantly. Backed by [Biscuit](https://www.biscuitsec.org/) for cryptographic attenuation.

## CLI Commands

```
agent.pw login [--host <url>]              authenticate with Cloud (default: https://agent.pw)
agent.pw logout                            log out from agent.pw
agent.pw setup                             self-hosted: generate keys, create DB, mint root token
agent.pw start                             start the local proxy server
agent.pw stop                              stop the local proxy server
agent.pw status                            show connected backend + token info

agent.pw profile                           list credential profiles
agent.pw profile get <slug>                show profile details
agent.pw profile add <slug> --host <h>     register a profile
agent.pw profile remove <slug>             remove a profile

agent.pw cred                              list credentials
agent.pw cred add <slug-or-host>           add a credential
agent.pw cred remove <slug>                remove a credential

agent.pw token revoke <token>              revoke a token

agent.pw curl <url> [curl flags]           proxy request with auto-injected token
```

## API Reference

```
Proxy:
  ALL  /proxy/{hostname}/{path...}             proxy by upstream host
  ALL  /proxy/{profile}/{hostname}/{path...}   proxy with explicit profile override

  Proxy auth header: agentpw-token
  Optional credential selector: agentpw-credential

Credentials:
  GET    /credentials                list credentials (org from token)
  PUT    /credentials/{slug_or_host} store a credential
  DELETE /credentials/{slug}         remove a credential

Credential Profiles:
  GET    /cred_profiles              list profiles
  GET    /cred_profiles/{slug}       get profile details
  PUT    /cred_profiles/{slug}       register/update a profile
  DELETE /cred_profiles/{slug}       remove a profile

Tokens:
  POST   /tokens/revoke              revoke the caller's token

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
