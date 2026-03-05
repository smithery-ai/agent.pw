# Token Design

agent.pw uses [Biscuit](https://www.biscuitsec.org/) tokens — a capability-based authorization format built on public-key cryptography. Tokens are self-contained, offline-verifiable, and support attenuation (narrowing permissions without server involvement).

## Token Format

Tokens are base64-encoded Biscuit tokens with an `apw_` prefix:

```
apw_En0KEwoRCAASDAoBdBIHCAQSAxiACBIkCAASIKo...
```

## Design Principle

**Token = proof of identity. Credentials DB = access control. Attenuation = client-side narrowing.**

The token carries *who you are* (`user()` fact), not *what you can access*. The credentials table determines what services a userId can reach. Attenuation can narrow further (service, method, path, TTL).

## Architecture

A Biscuit token has three layers:

```
┌─────────────────────────────────┐
│  Authority Block (signed)       │  ← Created by the server (private key)
│  - user() identity              │
│  - optional right() capabilities│
├─────────────────────────────────┤
│  Attenuation Block 1 (appended) │  ← Created by anyone (no key needed)
│  - check constraints            │
├─────────────────────────────────┤
│  Attenuation Block N            │  ← Can be chained
└─────────────────────────────────┘
```

- **Authority block**: Written by the server using the Ed25519 private key. Contains the user's identity and optional rights.
- **Attenuation blocks**: Appended by anyone holding the token. Can only add checks that *narrow* permissions — never expand them.
- **Verification**: Anyone with the public key (available at `/.well-known/jwks.json`) can verify the signature and evaluate the Datalog.

## Token Types

### User Token

Identifies who the user is. The credentials DB determines what they can access:

```datalog
user("org_abc123");
```

### Admin Token

Has elevated privileges — can act as any user and manage services:

```datalog
user("local");
right("admin");
right("manage_services");
```

### Root Token

Created during `agent.pw setup`. Admin identity with full management rights:

```datalog
user("local");
right("admin");
right("manage_services");
```

## Rights

| Right | Purpose |
|-------|---------|
| `right("admin")` | Can act as any user via `?user=` param, bypasses credential ownership |
| `right("manage_services")` | Can register/update/delete services |

## Authorization Layers

| Layer | What it controls |
|-------|-----------------|
| Authority block | Identity (who) |
| Credentials DB | What services userId can access (which credentials exist) |
| Attenuation | Client-side narrowing (service, method, path, TTL) |
| Authorizer | Validates token + evaluates attenuation checks |

## Authorization Flow

When a proxy request arrives, the server builds an authorizer with ambient facts from the HTTP request:

```datalog
// Ambient facts (from the request)
resource("api.github.com");
operation("GET");
path("/repos/owner/repo");
time(2026-03-05T12:00:00Z);

// Policies
allow if right("admin");
allow if user($u);
deny if true;
```

The `allow if user($u)` policy passes for any valid token with a user fact. **Actual service authorization happens in the proxy handler** — it checks if the userId has a credential for the requested service. No credential = 404.

Attenuation checks (from appended blocks) are evaluated *before* policies. So an attenuated token with `check if resource($r), ["api.github.com"].contains($r)` will reject requests to other services even though the `allow if user($u)` policy would match.

## Attenuation (Client-Side)

Tokens can be narrowed without server involvement. Attenuation appends a new block with checks:

```datalog
// Restrict to GET only on github, expiring in 1 hour
check if resource($r), ["api.github.com"].contains($r);
check if operation($op), ["GET"].contains($op);
check if time($t), $t <= 2026-03-05T13:00:00Z;
```

Attenuation is a pure cryptographic operation — it requires only the token and the public key. No private key or server call needed:

```typescript
import { restrictToken, getPublicKeyHex } from './biscuit'

const narrowed = restrictToken(originalToken, publicKeyHex, [
  { services: 'api.github.com', methods: 'GET', ttl: '1h' },
])
```

A user with credentials for github+linear can delegate a token attenuated to github-GET-only. The recipient can't access linear or do POST requests, even though the underlying userId has those credentials.

## Revocation

Each block in a Biscuit has a unique revocation ID. The server stores revoked IDs in the `revocations` table. On every request, the middleware checks all block IDs against this table.

`POST /tokens/revoke` revokes the caller's own token (the one in the Authorization header).

## Key Management

- **Private key**: Ed25519, stored server-side only (`BISCUIT_PRIVATE_KEY` env var or `~/.agent.pw/config.json`)
- **Public key**: Exposed at `GET /.well-known/jwks.json` in JWK format
- Token verification, attenuation, and fact extraction all use the public key only
