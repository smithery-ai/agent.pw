# Auth Proxy

An authenticated HTTP reverse proxy built on Cloudflare Workers. It stores upstream API credentials in D1 and uses [Biscuit tokens](https://www.biscuitsec.org/) for fine-grained, attenuable access control. Clients never see raw API keys -- they present a scoped token, and the proxy injects the right credential into upstream requests.

## Quick Start

```bash
git clone <repo-url> && cd auth-proxy
pnpm install
pnpm run setup   # generates keys, applies D1 migrations
pnpm run dev     # starts local server on http://localhost:8787
```

The setup script generates your `ADMIN_KEY` and `BISCUIT_PRIVATE_KEY`, writes them to `.dev.vars`, and initializes the local D1 database.

## How It Works

```
Client ──▶ Auth Proxy ──▶ Upstream API
        (Biscuit token)   (real API key injected)
```

1. **Register a service** -- tell the proxy about an upstream API (URL, auth method)
2. **Store a credential** -- give the proxy the real API key (stored in D1)
3. **Mint a token** -- create a Biscuit token scoped to specific services, methods, and paths
4. **Proxy requests** -- clients call `/proxy/:service/*` with their token; the proxy authorizes via Biscuit, looks up the credential, and forwards the request

Biscuit tokens can only be **narrowed**, never broadened. An admin mints a broad token, and recipients can further restrict it (e.g., limit to GET-only, or a specific path prefix) without needing the server's private key.

## API Reference

All admin endpoints require `Authorization: Bearer <ADMIN_KEY>`.

### Services

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/admin/services` | List all registered services |
| `PUT` | `/admin/services/:service` | Register or update a service |
| `DELETE` | `/admin/services/:service` | Remove a service |

**PUT body:**
```json
{
  "baseUrl": "https://api.example.com",
  "authMethod": "bearer",
  "headerName": "Authorization",
  "headerScheme": "Bearer",
  "description": "Example API",
  "specUrl": "https://api.example.com/openapi.json"
}
```

`authMethod` options: `bearer` (default), `api_key`, `basic`, `oauth2`

### Credentials

| Method | Path | Description |
|--------|------|-------------|
| `PUT` | `/admin/credentials/:service` | Store a credential |
| `DELETE` | `/admin/credentials/:service/:identity` | Remove a credential |

**PUT body:**
```json
{
  "identity": "default",
  "token": "sk-your-upstream-api-key",
  "metadata": { "team": "backend" },
  "expiresAt": "2025-12-31T00:00:00Z"
}
```

### Tokens

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/admin/tokens/mint` | Admin | Mint a new Biscuit token |
| `POST` | `/admin/tokens/revoke` | Admin | Revoke a token |
| `POST` | `/admin/keys/generate` | Admin | Generate a new Ed25519 key pair |
| `POST` | `/tokens/restrict` | Public | Attenuate an existing token |

**Mint body:**
```json
{
  "grants": [
    {
      "services": "openai",
      "methods": ["GET", "POST"],
      "paths": "/v1/chat/completions",
      "ttl": "1h"
    }
  ]
}
```

**Restrict body** (no admin key needed -- anyone with a token can narrow it):
```json
{
  "token": "vt_...",
  "constraints": [{ "methods": "GET", "paths": "/v1/models" }]
}
```

### Proxy

```
ANY /proxy/:service/*
Authorization: Bearer vt_...
```

The proxy extracts the upstream path, authorizes the Biscuit token against the requested service/method/path, looks up the credential for the token's identity, and forwards the request with the credential injected.

### Discovery

```
GET /services
Authorization: Bearer <admin-key or vt_token>
```

Returns services visible to the caller. Admin sees all; scoped tokens see only what their grants allow.

## Deployment

```bash
# Create D1 database
npx wrangler d1 create auth-proxy-db
# Update database_id in wrangler.toml

# Set secrets
npx wrangler secret put ADMIN_KEY
npx wrangler secret put BISCUIT_PRIVATE_KEY

# Deploy
pnpm run deploy:migrate   # apply D1 migrations remotely
pnpm run deploy            # deploy the worker
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ADMIN_KEY` | Secret key for admin API endpoints (`sk_` prefix recommended) |
| `BISCUIT_PRIVATE_KEY` | Ed25519 private key for minting Biscuit tokens |

## Development

```bash
pnpm test          # run all tests
pnpm run dev       # local dev server (uses .dev.vars for secrets)
```

Tests run inside Cloudflare's workerd runtime via `@cloudflare/vitest-pool-workers`.
