# agent.pw

Authenticated proxy for APIs. Stores credentials, injects them on matching requests, and bootstraps new credentials through standards-based discovery or profile-backed fallback.

```
Agent ──▶ proxy.agent.pw/api.github.com/user ──▶ api.github.com/user
       (Proxy-Authorization)                  (credential injected)
```

## The Proxy

agent.pw is an HTTP proxy. Give it a target URL, it handles auth.

```
proxy.agent.pw/api.linear.app/graphql
proxy.agent.pw/api.github.com/repos/owner/repo
proxy.agent.pw/uploads.github.com/repos/owner/repo/releases/1/assets
```

`proxy.agent.pw` is an alias for `api.agent.pw/proxy`. The proxy preserves the native HTTP request shape. Agents make normal GET and POST requests. Unauthenticated endpoints pass through transparently — the proxy only intervenes when it has a stored credential for the target host, or when the upstream returns 401.

### Request Flow

```
1. Agent sends a normal HTTP request through the proxy
2. agent.pw checks for a matching stored credential
3. If a credential exists, inject auth headers and forward
4. If no credential exists, forward the request as-is
5. If the upstream returns 200, return it (unauthenticated endpoint)
6. If the upstream returns 401:
   a. Try standards-based OAuth discovery
   b. If discovery fails, check credential profile registry
   c. If a profile exists, use its bootstrap config
   d. Store the resulting credential
   e. Retry the request
7. If nothing works, return the 401 with instructions
```

### Proxy Authentication

Requests to the proxy carry a Biscuit token (`apw_` prefix) in the `Proxy-Authorization: Bearer ...` header. The proxy strips it before forwarding upstream. If the agent includes explicit HTTP headers (e.g. `Authorization`), they take precedence over credential injection.

### Credential Store

Credentials are matched by target host and injected automatically.

```
CREDENTIALS TABLE
host            target hostname this credential authenticates against
slug            unique ID (auto-generated or user-specified via --slug)
auth            auth config object (kind: oauth → Bearer header, kind: headers → custom header map)
secret          encrypted token / key material
exec_scopes     scopes required to use this credential through the proxy
admin_scopes    scopes required to create, replace, share, or revoke it
```

Each credential is self-describing: it knows how to inject itself. Multiple credentials per host are supported. If more than one credential matches a host for the caller's scopes, the proxy returns an ambiguity error and the agent must specify `agentpw-credential`.

### Auth Bootstrap

When a proxied request returns 401, agent.pw tries to bootstrap a credential:

**Standards-based discovery.** When the target follows OAuth discovery conventions, agent.pw handles it directly: reads `WWW-Authenticate` headers, fetches Protected Resource Metadata (RFC 9728), runs OAuth 2.1 with PKCE, and scopes tokens with Resource Indicators (RFC 8707).

**Credential profile fallback.** When discovery is incomplete, agent.pw checks the credential profile registry for a matching host entry. See [Credential Profiles](#credential-profiles).

**Manual fallback.** Users can always add credentials for any host, with or without a profile:

```bash
agent.pw cred add api.custom-corp.com --auth headers \
  -H "Authorization: Bearer {key:Your API key from the dashboard}"
```

Profiles guide credential setup when available. They never gate it.

## Getting Started (Cloud)

```bash
agent.pw login
```

Authenticates with agent.pw Cloud. Services are pre-configured — no setup needed.

```bash
agent.pw curl proxy.agent.pw/api.linear.app/graphql \
  -d '{"query":"{ issues { nodes { id title } } }"}'
→ no credential found
→ forward raw → 401
→ check cred profiles → managed profile found
→ browser opens → credential stored
→ request retried → works
```

Manual credential flows:

```bash
agent.pw cred add linear
→ Profile found: Linear (api.linear.app)
→ Auth: headers
→ Authorization: Bearer ____
→ Paste your API key: ****
→ Stored as linear/k7x

agent.pw cred add github
→ Profile found: GitHub (api.github.com)
→ Auth: oauth
→ Opening browser... (→ GitHub consent screen → redirect back)
→ Stored as github/m3p
```

View stored credentials:

```
agent.pw cred

HOST             SLUG        AUTH       ADDED
api.linear.app   linear/k7x  headers    2d ago
api.github.com   github/m3p  oauth      5d ago
```

Credentials are write-only. Agents cannot exfiltrate them.

## Getting Started (Self-Hosted)

Install the server package:

```bash
bun add @agent.pw/server
```

Set up and start:

```bash
agent.pw-server setup
```

Generates Biscuit signing keys (Ed25519), creates a local PGlite database, and mints a root token.

```bash
agent.pw-server start
```

Starts the proxy on your machine. Everything runs locally.

Self-hosted starts with an empty credential store and no credential profiles. Standards-based discovery works for compatible APIs. For everything else, add profiles:

```bash
agent.pw profile add linear --host api.linear.app \
  --auth headers \
  -H "Authorization: Bearer {api_key:Your Linear API key from Settings > API}"
```

The `-H` flag follows curl conventions. `{name:description}` syntax defines form fields: `name` is the field ID, `description` is the label shown in CLI prompts.

Then use the proxy locally:

```bash
agent.pw curl http://localhost:9315/proxy/api.linear.app/graphql \
  -d '{"query":"{ issues { nodes { id title } } }"}'
```

The CLI auto-detects the active backend. `agent.pw status` shows which one.

## Concepts

### Credential Profiles

Credential profiles are templates for setting up credentials. They match a target host and supply the auth metadata that discovery would have returned — OAuth endpoints, or a header form definition.

**OAuth config** — for services with OAuth that lack standard discovery:

```yaml
slug: github
host: [api.github.com, uploads.github.com]
auth:
  kind: oauth
  authorize_url: https://github.com/login/oauth/authorize
  token_url: https://github.com/login/oauth/access_token
  scopes: [repo, read:user]
  client_id: <user_provided>
```

**Headers form** — for services that use API keys or custom headers:

```yaml
slug: linear
host: api.linear.app
auth:
  kind: headers
  fields:
    - header: "Authorization"
      prefix: "Bearer "
      name: api_key
      description: "Your Linear API key from Settings > API"
```

The proxy checks credential profiles only when standards-based discovery fails. Profiles are helpful defaults, never gates.

### Tokens (Biscuit)

Biscuit tokens (`apw_` prefix) determine which requests may be made through the proxy and which credentials are accessible.

The root token (generated during setup) has full authority. Restricted tokens are attenuated by target host, method, TTL, or additional Biscuit checks. A restricted token can never gain more authority than its parent.

Credentials carry scope arrays: `exec_scopes` governs proxy use, `admin_scopes` governs management operations. Tokens can also carry `scope("value")` facts directly, with `org_id` remaining as a fallback for older tokens. See [docs/token-design.md](docs/token-design.md) for full details.

## CLI

The CLI (`agent.pw`) manages credentials, profiles, and tokens. It works with both cloud and self-hosted backends.

```
agent.pw <command>

  login      Log in to agent.pw
  logout     Log out
  status     Show connection status
  profile    Manage credential profiles
  cred       Manage stored credentials
  token      Manage access tokens
  curl       Proxy-aware curl wrapper
```

Run `agent.pw <command> --help` for subcommands and options.

When piped (non-TTY), commands output JSONL for machine consumption.

### Self-Hosted Server CLI

The server package (`@agent.pw/server`) includes its own CLI for managing a local instance:

```
agent.pw-server <command>

  setup    Set up a local instance (keys, database)
  start    Start the local proxy server
  stop     Stop the local proxy server
```

## API Reference

```
Proxy:
  ALL  /proxy/{hostname}/{path...}             proxy by upstream host
  ALL  /proxy/{profile}/{hostname}/{path...}   proxy with explicit profile override

  Proxy auth header: Proxy-Authorization: Bearer <token>
  Optional credential selector: agentpw-credential

Credentials:
  GET    /credentials                list credentials
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
  packages/
    server/
      src/                ← @agent.pw/server (core library)
        core/             ← proxy, vault, tokens
        routes/           ← API route handlers
        db/               ← Drizzle schema and queries
        lib/              ← shared utilities, crypto
      cli.ts              ← agent.pw-server CLI (self-hosted)
    cli/                  ← agent.pw CLI (cloud + management, SDK only)
```

## Development

```bash
pnpm install
pnpm build              # typecheck
npm link                # link CLI globally
```

```bash
pnpm test               # run tests (uses in-memory PGlite)
pnpm test:watch         # watch mode
pnpm run lint           # lint
```

### Database

```bash
pnpm run db:generate    # generate migrations from schema changes
```

## License

MIT
