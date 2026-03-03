# Warden

An auth proxy where the URL is the interface. Warden sits between your agents and upstream APIs — it holds the real credentials, enforces fine-grained access control via [Biscuit tokens](https://www.biscuitsec.org/), and handles OAuth/API-key flows so agents never touch raw secrets.

```
Agent ──▶ warden.run/api.github.com/user ──▶ api.github.com/user
       (Biscuit token)                     (real API key injected)
```

## Use with your agent

Paste this into your agent to connect to any API:

```
Connect to {any API} using https://warden.run
```

That's it. The agent will `curl https://warden.run`, read the onboarding guide, and walk you through authenticating in your browser. Your API keys never touch the agent — Warden stores them encrypted and injects them at the proxy layer.

## How it works

The same URL serves both **discovery** and **proxy**:
- No token + `Accept: application/json` → 401 with auth options (for agents)
- No token + browser → HTML landing page with setup buttons
- With token → proxied request to the upstream API

## Self-hosting

### Prerequisites

- Node.js 20+
- PostgreSQL (any provider — Neon, Supabase, local, etc.)

### Setup

```bash
git clone <repo-url> && cd warden
pnpm install
```

#### Secrets (Infisical)

Secrets are managed via [Infisical](https://infisical.com/) under the path `/apps/warden`. Log in once:

```bash
pnpm run secrets:login
```

Then `pnpm run dev` will automatically inject secrets. To export a `.env` file for tools that need one:

```bash
pnpm run secrets:export
```

#### Manual `.env`

If you're not using Infisical, create a `.env` file and use the `:env` script variants:

```bash
DATABASE_URL=postgresql://user:password@localhost:5432/mydb
BISCUIT_PRIVATE_KEY=<generated below>
BASE_URL=http://localhost:3000
```

```bash
pnpm run dev:env    # uses .env instead of Infisical
```

### Bootstrap

Generate a Biscuit keypair and mint your first management token:

```bash
pnpm run setup
```

This prints a root management token with full access. Save it — this is your admin credential for all management operations.

If you already have a `BISCUIT_PRIVATE_KEY` in `.env`, the setup script mints a root token using that key. If not, it generates a new keypair and prints both.

### Database

Push the schema to your Postgres database:

```bash
pnpm run db:push
```

All tables live under a `warden` Postgres schema, so they won't conflict with other tables in the same database.

### Run

```bash
pnpm run dev    # dev server with hot reload
pnpm start      # production
```

Verify it's running:

```bash
curl http://localhost:3000
# Returns the Warden onboarding guide
```

## Concepts

### Vaults

A **vault** is a collection of credentials. Credentials are stored in vaults, keyed by `(vault, service)`. Vaults let you isolate credentials per team, project, or user.

```bash
# Create a vault
curl -X POST http://localhost:3000/vaults \
  -H "Authorization: Bearer $MGMT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"slug": "team-alpha", "displayName": "Team Alpha"}'
```

### Biscuit Tokens

All access control is via Biscuit tokens. There are two kinds:

**Management tokens** carry rights like `manage_services`, `manage_vaults`, and `vault_admin("slug")`. These replace the old admin key concept — there's no shared secret, just attenuable tokens.

**Proxy tokens** carry grant facts that scope which services, methods, and paths an agent can access, and which vault to pull credentials from.

Biscuit tokens can only be **narrowed**, never broadened. Anyone with a token can restrict it further without needing the server's private key.

## How It Works

### 1. Register a service

Tell Warden about an upstream API. The service name is its hostname.

```bash
curl -X PUT http://localhost:3000/services/api.github.com \
  -H "Authorization: Bearer $MGMT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "baseUrl": "https://api.github.com",
    "displayName": "GitHub",
    "supportedAuthMethods": ["oauth", "api_key"],
    "apiType": "rest",
    "docsUrl": "https://docs.github.com/en/rest"
  }'
```

### 2. Create a vault and store a credential

```bash
# Create a vault
curl -X POST http://localhost:3000/vaults \
  -H "Authorization: Bearer $MGMT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"slug": "personal"}'

# Store a credential in the vault
curl -X PUT http://localhost:3000/vaults/personal/credentials/api.github.com \
  -H "Authorization: Bearer $MGMT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"token": "ghp_your_github_token", "identity": "alice"}'
```

### 3. Mint a proxy token

Create a scoped token for an agent, bound to a vault:

```bash
curl -X POST http://localhost:3000/tokens/mint \
  -H "Authorization: Bearer $MGMT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "bindings": {
      "api.github.com": {"vault": "personal"}
    }
  }'
# {"token":"wdn_...","publicKey":"..."}
```

Or use the grants format for more control:

```bash
curl -X POST http://localhost:3000/tokens/mint \
  -H "Authorization: Bearer $MGMT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "grants": [{
      "services": "api.github.com",
      "methods": ["GET"],
      "paths": "/user",
      "vault": "personal",
      "ttl": "1h"
    }]
  }'
```

### 4. Proxy requests

Agents use their token to call upstream APIs through Warden:

```bash
curl http://localhost:3000/api.github.com/user \
  -H "Authorization: Bearer wdn_..."
# → proxied to https://api.github.com/user with the real token injected
```

## Discovery

When an agent hits a service URL without a token, Warden returns discovery info instead of proxying:

```bash
curl http://localhost:3000/api.github.com \
  -H "Accept: application/json"
```

```json
{
  "service": "GitHub",
  "canonical": "api.github.com",
  "description": "REST API for GitHub.",
  "auth_options": [
    {"type": "oauth", "setup_url": "/auth/api.github.com/oauth"},
    {"type": "api_key", "setup_url": "/auth/api.github.com/api-key"}
  ],
  "docs_url": "https://docs.github.com/en/rest"
}
```

The same URL in a browser shows an HTML landing page with buttons to connect.

## Auth Flows

Warden supports a polling-based auth flow so agents can get tokens without copy-paste:

1. Agent discovers a service needs auth → gets `setup_url` from discovery
2. Agent presents the URL to the user (e.g., opens a browser)
3. User completes OAuth or enters an API key in the browser
4. Agent polls `GET /auth/status/{flow_id}` until the token is ready

```bash
# Agent polls for completion
curl http://localhost:3000/auth/status/{flow_id}
# Pending: 202 {"status":"pending"}
# Done:    200 {"status":"completed","token":"wdn_...","identity":"alice"}
```

Auth flows accept a `?vault=` query parameter to control which vault the credential is stored in (defaults to `personal`).

## Token Attenuation

Anyone with a token can restrict it further without needing the server's private key:

```bash
curl -X POST http://localhost:3000/tokens/restrict \
  -H "Content-Type: application/json" \
  -d '{
    "token": "wdn_...",
    "constraints": [{"methods": "GET", "paths": "/user"}]
  }'
```

## API Reference

### Vault Management (requires management token)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/vaults` | Create a vault |
| `GET` | `/vaults` | List vaults (scoped by token) |
| `DELETE` | `/vaults/:slug` | Delete a vault |

### Credential Management (requires vault_admin)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/vaults/:slug/credentials` | List credentials in vault |
| `PUT` | `/vaults/:slug/credentials/:service` | Store a credential |
| `DELETE` | `/vaults/:slug/credentials/:service` | Remove a credential |

### Service Catalog (requires manage_services)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/services` | List services visible to caller |
| `PUT` | `/services/:service` | Register/update a service |
| `DELETE` | `/services/:service` | Remove a service |

### Tokens

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/tokens/mint` | Mint a token (management required) |
| `POST` | `/tokens/restrict` | Attenuate a token (public) |
| `POST` | `/tokens/revoke` | Revoke a token |
| `POST` | `/keys/generate` | Generate an Ed25519 keypair |

### Discovery & Proxy

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Health check |
| `GET` | `/:service` | Discovery (content-negotiated) |
| `ALL` | `/:service/*` | Proxy (requires Biscuit token) |

### Auth Flows

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/auth/:service/oauth` | Start OAuth flow |
| `GET` | `/auth/:service/oauth/callback` | OAuth callback |
| `GET` | `/auth/:service/api-key` | API key entry form |
| `POST` | `/auth/:service/api-key` | Submit API key |
| `GET` | `/auth/status/:flowId` | Poll auth flow status |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `BISCUIT_PRIVATE_KEY` | Yes | Ed25519 private key for minting tokens |
| `BASE_URL` | No | Public URL (defaults to `http://localhost:$PORT`) |
| `PORT` | No | Server port (defaults to `3000`) |

## Development

```bash
pnpm test          # run tests
pnpm test:watch    # watch mode
pnpm run dev       # dev server with hot reload
```

Tests use [PGlite](https://github.com/electric-sql/pglite) for in-memory Postgres — no database setup needed.

### Database Commands

```bash
pnpm run db:push       # push schema to database (dev)
pnpm run db:generate   # generate migration files
pnpm run db:migrate    # run migrations (production)
```

## License

MIT
