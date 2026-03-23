# agent.pw

[![npm version](https://img.shields.io/npm/v/agent.pw)](https://www.npmjs.com/package/agent.pw)

Portable auth for AI agents. Store provider credentials once, handle auth flows centrally, and issue scoped access that agents can reuse without seeing raw secrets.

<p>
  <a href="https://agent.pw">Website</a> ·
  <a href="#getting-started">Getting Started</a> ·
  <a href="docs/security-model.md">Security Model</a>
</p>

```
Agent runtime ──▶ agent.pw ──▶ api.github.com/user
                (scoped access)   (provider auth applied)
```

## How It Works

1. A runtime presents scoped access to agent.pw
2. agent.pw looks up a stored credential for the target provider
3. If found, agent.pw applies the provider's auth scheme and sends the request using the provider's native interface
4. If not found, agent.pw returns a structured `WWW-Authenticate: AgentPW ...` challenge that points the caller at an OAuth or manual bootstrap flow
5. Agents get scoped, revocable [Biscuit](https://www.biscuitsec.org/) tokens — and server-minted tokens are tracked for listing, revocation, and usage metadata

## Features

- **Portable auth layer** — store credentials, apply the provider's auth scheme, and keep raw secrets away from agents
- **Structured auth bootstrap** — standards-based OAuth discovery (RFC 9728, PKCE, Resource Indicators), with `AgentPW` auth challenges and manual/profile fallback for non-standard APIs
- **Credential Profiles** — canonical auth definitions for providers (OAuth endpoints, API key/header forms, or manual auth)
- **Path-based access** — credentials live in a hierarchical tree with explicit rights over descendant roots; self-hosted installs can also scope profile defaults by path when they need that control ([details](docs/security-model.md))
- **Tracked Biscuit tokens** — cryptographic attenuation by host, method, path, root, and TTL, with tracked server-minted tokens that can be listed and revoked by ID ([details](docs/security-model.md))
- **Token stack** — `token push`, `token pop`, `token list`, and `token revoke` for temporary privilege narrowing during agent tasks
- **Write-only credentials** — agents use credentials through agent.pw but cannot read the raw secret material
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

Add a Credential Profile and use the wrapper:

```bash
agent.pw profile add linear --host api.linear.app \
  --auth headers \
  -H "Authorization: Bearer {api_key:Your Linear API key from Settings > API}"

agent.pw cred add linear
agent.pw curl https://api.linear.app/graphql \
  -d '{"query":"{ issues { nodes { id title } } }"}'
```

### Standard Proxy Mode

The local daemon can also act as a standard forward proxy for loopback clients:

```bash
eval "$(agent.pw proxy env)"

agent.pw exec -- your-compatible-cli
```

- `agent.pw proxy env` prints shell exports for `HTTP_PROXY`, `HTTPS_PROXY`, and related variables using your current scoped token.
- `agent.pw exec -- ...` runs a command with those env vars already configured.
- Plain HTTP proxy-form requests are rewritten into the normal `agent.pw` proxy flow, so stored credentials can still be injected.
- `CONNECT` requests are authenticated, policy-checked, and tunneled directly to the target host.
- Because `CONNECT` carries opaque TLS bytes after the tunnel is established, agent.pw cannot inject HTTPS headers inside a `CONNECT` tunnel without full TLS interception.
- Some tools therefore still need an explicit wrapper like `agent.pw curl` or a direct `/proxy/...` URL instead of generic proxy env vars.

### Local Service Controls

```bash
agent.pw status
agent.pw logs
agent.pw stop
```

### Tracked Tokens

Mint, list, and revoke tracked access tokens:

```bash
agent.pw token push --host api.linear.app --method GET --path /graphql --ttl 1h
agent.pw token list
agent.pw token revoke <issued-token-id> --reason "rotated in CI"
```

## API

```
ALL    /proxy/{hostname}/{path...}        explicit authenticated proxy transport
GET    /credentials                       list credentials
PUT    /credentials/{name}                store a credential
PATCH  /credentials/{name}                move a credential to a new path
DELETE /credentials/{name}                remove a credential
GET    /cred_profiles                     list profiles
GET    /cred_profiles/{slug}              fetch profile details
PUT    /cred_profiles/{slug}              create/update a profile
DELETE /cred_profiles/{slug}              remove a profile
POST   /tokens                            mint a tracked Biscuit token
GET    /tokens                            list tracked tokens
GET    /tokens/{id}                       fetch tracked token metadata
POST   /tokens/inspect                    inspect token facts
DELETE /tokens/{id}                       revoke a tracked token
GET    /.well-known/jwks.json             Ed25519 public key (JWK)
```

Management routes use `Authorization: Bearer <token>`. Proxy requests use `Proxy-Authorization`.

List endpoints accept `limit` and `cursor` query params and return:

```json
{
  "data": [],
  "hasMore": false,
  "nextCursor": null
}
```

Some credential and profile mutations also require `host`, `profile`, or `path` fields so the server can resolve the exact record or target path.

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
  server/src/        @agent.pw/server — auth/core runtime surface, credential store, tokens, routes
  cli/src/           agent.pw CLI — local start flow, wrappers, proxy helpers, and management commands
docs/
  security-model.md  Biscuit tokens, path-based access model, revocation
```

## License

[FSL-1.1-MIT](LICENSE.md) — converts to MIT after two years.
