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
2. agent.pw checks for a matching stored credential at the token's path or any ancestor path
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

Every credential lives at a path in a tree (e.g. `/orgs/acme/github`). Credentials are keyed by `(host, path)` — one credential per host per path node.

The proxy matches credentials by walking up the path tree from the token's position. If multiple credentials match a host at different depths, the deepest one wins (most specific). If multiple match at the same depth, the proxy returns a 409 and the caller specifies via the `agentpw-credential` header.

Each credential is self-describing: it knows how to inject itself (OAuth Bearer header or custom header map). Credentials are write-only — agents cannot read the raw secret material.

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
→ check cred profiles → profile found
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
→ Stored credential 'linear' for api.linear.app

agent.pw cred add github
→ Profile found: GitHub (api.github.com)
→ Auth: oauth
→ Opening browser... (→ GitHub consent screen → redirect back)
→ Stored credential 'github' for api.github.com
```

View stored credentials:

```
agent.pw cred

HOST             NAME      PATH                   ADDED
api.linear.app   linear    /orgs/acme/linear      2d ago
api.github.com   github    /orgs/acme/github      5d ago
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

### Path-Based Access

Every credential and profile lives at a path in a tree that encodes organizational hierarchy. Access follows two rules:

**Usage flows upward.** A token can use credentials stored at ancestor paths. An org-level credential is usable by every workspace and user below it, like environment variables in a process tree.

**Admin flows downward.** A token can create, update, and delete credentials at its own path or deeper. A workspace token cannot manage org-level credentials.

See [docs/token-design.md](docs/token-design.md) for the full access model.

### Credential Profiles

Credential profiles are templates for setting up credentials. They match a target host and supply the auth metadata that discovery would have returned — OAuth endpoints, or a header form definition.

**OAuth config** — for services with OAuth that lack standard discovery:

```yaml
path: /github
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
path: /linear
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

The root token (generated during setup) has full authority. Restricted tokens are attenuated by target host, method, path prefix, or TTL. A restricted token can never gain more authority than its parent.

The token's position in the path tree determines which credentials it can use (ancestors) and manage (descendants). See [docs/token-design.md](docs/token-design.md) for full details.

## CLI

The CLI (`agent.pw`) manages credentials, profiles, and tokens. It works with both cloud and self-hosted backends.

```
agent.pw <command>

  login                          Log in to agent.pw
  logout                         Log out
  status                         Show connection status

  profile                        List credential profiles
  profile get <slug>             Show profile details
  profile add <slug>             Register a profile
  profile remove <slug>          Remove a profile

  cred                           List stored credentials
  cred add <slug-or-host>        Add a credential
  cred remove <name>             Remove a credential

  token                          Inspect current token
  token restrict                 Create a restricted child token
  token revoke                   Revoke the current token
  token push                     Restrict + push onto token stack
  token pop                      Revert to previous token

  curl [args...]                 Proxy-aware curl wrapper
```

Key flags for `token restrict` / `token push`:

```
  --service <host...>    Limit to service host(s)
  --method <verb...>     Limit to HTTP method(s)
  --path <prefix...>     Limit to path prefix(es)
  --ttl <duration>       Token lifetime (e.g. 1h, 30m)
```

Run `agent.pw <command> --help` for all options.

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
  GET    /credentials              list credentials accessible to token
  PUT    /credentials/{name}       store a credential
  DELETE /credentials/{name}       remove a credential

Credential Profiles:
  GET    /cred_profiles             list profiles
  GET    /cred_profiles/{slug}      get profile details
  PUT    /cred_profiles/{slug}      create/update a profile
  DELETE /cred_profiles/{slug}      remove a profile

Tokens:
  POST   /tokens/restrict           create an attenuated child token
  POST   /tokens/revoke             revoke the caller's token

Infrastructure:
  GET    /                          health check (profiles + credential counts)
  GET    /.well-known/jwks.json     Ed25519 public key (JWK format)
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
    cli/                  ← agent.pw CLI (cloud + management)
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
