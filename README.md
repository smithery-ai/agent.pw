# agent.pw

[![npm version](https://img.shields.io/npm/v/agent.pw)](https://www.npmjs.com/package/agent.pw)

The password manager for AI agents. An authenticated proxy that stores credentials and injects them on matching requests — agents never see raw secrets.

<p>
  <a href="https://agent.pw">Website</a> ·
  <a href="#getting-started">Getting Started</a> ·
  <a href="docs/security-model.md">Security Model</a> ·
  <a href="docs/oidc.md">OIDC</a>
</p>

```
Agent ──▶ proxy.agent.pw/api.github.com/user ──▶ api.github.com/user
       (Proxy-Authorization)                  (credential injected)
```

## How It Works

1. Agent sends a normal HTTP request through the proxy
2. agent.pw looks up a stored credential for the target host
3. If found, inject auth headers and forward
4. If not found, forward as-is — if upstream returns 401, bootstrap a credential automatically
5. Agents get scoped, revocable [Biscuit](https://www.biscuitsec.org/) tokens — never raw secrets

## Features

- **Authenticated proxy** — credential injection by target hostname, transparent to the agent
- **Auth bootstrap** — standards-based OAuth discovery (RFC 9728, PKCE, Resource Indicators), with credential profile fallback for non-standard APIs
- **Credential profiles** — templates that describe how to authenticate with a service (OAuth endpoints or header forms)
- **Path-based access** — credentials live in a hierarchical tree; usage flows upward, admin flows downward ([details](docs/security-model.md))
- **Biscuit tokens** — cryptographic attenuation by host, method, path, and TTL; tokens can only be narrowed, never expanded ([details](docs/security-model.md))
- **Token stack** — `token push` / `token pop` for temporary privilege narrowing during agent tasks
- **Write-only credentials** — agents use credentials through the proxy but cannot read the raw secret material
- **Local-first OSS** — run a self-hosted instance with PGlite in one command, then use the hosted vault as an optional browser shell

## Getting Started

```bash
npx agent.pw start
```

That command:

- creates `~/.agent.pw/`
- writes daemon state to `~/.agent.pw/server.json`
- writes CLI connection state to `~/.agent.pw/cli.json`
- initializes a local PGlite database
- mints a local root token for the CLI
- installs a local background service
- offers to install the optional Smithery `agentpw` skill
- opens [agent.pw/vault](https://agent.pw/vault) already connected to your local instance

The hosted vault is optional. Your local daemon is the source of truth, and you can keep working entirely through the CLI.
Running `start` again is safe: it repairs `server.json`, refreshes `cli.json`, and re-registers the local service if needed.

### Local CLI Flow

Add a credential profile and use the proxy:

```bash
agent.pw profile add linear --host api.linear.app \
  --auth headers \
  -H "Authorization: Bearer {api_key:Your Linear API key from Settings > API}"

agent.pw cred add linear
agent.pw curl http://localhost:9315/proxy/api.linear.app/graphql \
  -d '{"query":"{ issues { nodes { id title } } }"}'
```

### Standard Proxy Mode

The local daemon can also act as a standard forward proxy for loopback clients:

```bash
export HTTP_PROXY=http://127.0.0.1:9315
export HTTPS_PROXY=http://127.0.0.1:9315
```

- Plain HTTP proxy-form requests are rewritten into the normal `agent.pw` proxy flow, so stored credentials can still be injected.
- `CONNECT` requests are authenticated, policy-checked, and tunneled directly to the target host.
- Because `CONNECT` carries opaque TLS bytes after the tunnel is established, agent.pw cannot inject HTTPS headers inside a `CONNECT` tunnel without full TLS interception.
- Non-loopback clients should still send `Proxy-Authorization` explicitly. The proxy accepts both `Bearer <token>` and standard Basic proxy credentials.

### Local Service Controls

```bash
agent.pw status
agent.pw logs
agent.pw stop
```

## API

```
ALL    /proxy/{hostname}/{path...}        authenticated proxy
GET    /credentials                       list credentials
PUT    /credentials/{name}                store a credential
DELETE /credentials/{name}                remove a credential
GET    /cred_profiles                     list profiles
PUT    /cred_profiles/{slug}              create/update a profile
DELETE /cred_profiles/{slug}              remove a profile
POST   /tokens/restrict                   attenuate a token
POST   /tokens/inspect                    inspect token facts
POST   /tokens/revoke                     revoke a token
GET    /.well-known/jwks.json             Ed25519 public key (JWK)
```

List endpoints accept `limit` and `cursor` query params and return:

```json
{
  "data": [],
  "hasMore": false,
  "nextCursor": null
}
```

## Development

```bash
pnpm install
pnpm build           # typecheck root package + bundle the CLI package
pnpm test            # run tests (in-memory PGlite)
pnpm run lint        # lint
pnpm run db:generate # generate Drizzle migrations from schema changes
```

## Repo Structure

```
packages/
  server/src/        @agent.pw/server — proxy, credential store, tokens, routes
  cli/src/           agent.pw CLI — local start flow, service controls, and management commands
docs/
  security-model.md  Biscuit tokens, path-based access model, revocation
  oidc.md            OIDC integration guide for trusted services
```

## License

[FSL-1.1-MIT](LICENSE.md) — converts to MIT after two years.
