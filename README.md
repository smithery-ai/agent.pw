# agent.pw

Open-source credential vault and API proxy for agents. Keeps secrets out of your prompts.

```
Agent ──▶ agent.pw/proxy/api.github.com/user ──▶ api.github.com/user
       (bearer token)                           (real API key injected)
```

## Getting Started

### Local

```bash
npx agent.pw setup
```

Generates Biscuit signing keys (Ed25519), creates a local database, and starts the proxy at `local.agent.pw`. Everything runs on your machine — no external dependencies.

### Managed

```bash
npx agent.pw login
```

Connects the CLI to `https://agent.pw` (or a self-hosted instance with `--host`).

### Add a credential

```
npx agent.pw cred add api.linear.app
→ Paste your API key: ****
→ Stored.
```

Or non-interactively:

```bash
npx agent.pw cred add api.linear.app --value "lin_api_abc123"
```

Now use the proxy. `npx agent.pw curl` works exactly like `curl` — same flags, same syntax — but injects the bearer token automatically:

```bash
npx agent.pw curl local.agent.pw/proxy/api.linear.app/graphql \
  -d '{"query":"{ issues { nodes { id title } } }"}'
```

agent.pw looks up `api.linear.app`, injects the stored credential, and proxies the request. The agent never sees the Linear API key.

View stored credentials:

```bash
npx agent.pw cred
```

Credentials are write-only. Agents who use the CLI cannot exfiltrate credentials.

### Adding Services

Register a service via CLI:

```bash
npx agent.pw service add api.linear.app --file service.json
```

Or use the skill in Claude Code or Codex:

```
/agentpw-add-service api.linear.app
```

The agent reads the API docs, figures out the auth method and headers, and writes the service entry. You approve the result.

## Concepts

**Services.** A service defines how a particular API is authenticated. Each entry maps a hostname to its auth configuration: what kind of credentials are accepted (API key, OAuth), which headers to inject, and an OAuth app (client ID + secret) if applicable.

**Credentials.** A credential is the specific secret used to connect to a service — the actual API key or OAuth token. Credentials are stored encrypted and never exposed to agents. When an agent makes a proxied request, agent.pw looks up the credential for that service and injects it into the upstream request according to the service's header config.

**Tokens.** On setup, agent.pw mints a bearer token (`wdn_` prefix). The master token has full access to the service table and credential store. Tokens given to agents can be attenuated — scoped to specific services, methods, and TTLs. A restricted token can never gain more power than its parent. Tokens can be revoked instantly. Backed by [Biscuit](https://www.biscuitsec.org/) for cryptographic attenuation.

## CLI Reference

| Command | Description |
|---------|-------------|
| `agent.pw login [--host <url>]` | Log in to agent.pw (default: https://agent.pw) |
| `agent.pw logout` | Log out from agent.pw |
| `agent.pw setup` | Set up a local instance (keys, database) |
| `agent.pw start` | Start the local proxy server |
| `agent.pw stop` | Stop the local proxy server |
| `agent.pw status` | Show connection status |
| `agent.pw service` | List registered services |
| `agent.pw service get <host>` | Show service details |
| `agent.pw service add <host> [--file f]` | Register a service |
| `agent.pw service remove <host>` | Remove a service |
| `agent.pw cred` | List stored credentials |
| `agent.pw cred add <service> [--value <key>]` | Add a credential |
| `agent.pw curl <url> [args...]` | Proxy-aware curl wrapper |

## API Reference

### Proxy

| Method | Path | Description |
|--------|------|-------------|
| `ALL` | `/proxy/:service/*` | Proxy with injected credentials (requires bearer token) |

### Credential Management

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/credentials` | List credentials (org from token) |
| `PUT` | `/credentials/:service` | Store a credential |
| `DELETE` | `/credentials/:service` | Remove a credential |

### Service Catalog

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/services` | List services |
| `GET` | `/services/:service` | Get service details |
| `PUT` | `/services/:service` | Register/update a service |
| `DELETE` | `/services/:service` | Remove a service |

### Tokens

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/tokens/mint` | Mint a new token |
| `POST` | `/tokens/restrict` | Attenuate a token (no auth needed) |
| `POST` | `/tokens/revoke` | Revoke a token |

### Infrastructure

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/.well-known/jwks.json` | Ed25519 public key (JWK format) |

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
