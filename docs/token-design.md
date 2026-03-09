# Token Design

agent.pw uses [Biscuit](https://www.biscuitsec.org/) tokens — a capability-based authorization format built on public-key cryptography. Tokens are self-contained, offline-verifiable, and support attenuation (narrowing permissions without server involvement).

## Token Format

Tokens are base64-encoded Biscuit tokens with an `apw_` prefix:

```
apw_En0KEwoRCAASDAoBdBIHCAQSAxiACBIkCAASIKo...
```

## Design Principles

**Token = identity plus scope facts. Credential scopes = access control. Attenuation = client-side narrowing.**

The token carries *who you are* plus optional scope facts. Credentials carry scope arrays that determine who can use or manage them. Attenuation narrows further (host, method, path, TTL). All facts are namespaced to `apw` so deployers may extend with additional facts.

**Deployer-defined vocabulary.** agent.pw imposes no required facts like `user_id` or `org_id`. A single-user self-hosted install might use no custom facts at all — the root token has full access. A team gateway might define `team("backend")`. A white-label deployment might define `end_user("customer_1")`. agent.pw is identity-neutral at the core.

## Architecture

A Biscuit token has three layers:

```
┌─────────────────────────────────┐
│  Authority Block (signed)       │  ← Created by the server (private key)
│  - identity facts               │
│  - optional right() capabilities│
├─────────────────────────────────┤
│  Attenuation Block 1 (appended) │  ← Created by anyone (no key needed)
│  - check constraints            │
├─────────────────────────────────┤
│  Attenuation Block N            │  ← Can be chained
└─────────────────────────────────┘
```

- **Authority block**: Written by the server using the Ed25519 private key. Contains identity facts and optional rights.
- **Attenuation blocks**: Appended by anyone holding the token. Can only add checks that *narrow* permissions — never expand them.
- **Verification**: Anyone with the public key (available at `/.well-known/jwks.json`) can verify the signature and evaluate the Datalog.

## Credential-Level Scopes

Each credential carries its own scope arrays:

| Field | Purpose |
|--------|---------|
| `exec_scopes` | Scopes required to use this credential through the proxy |
| `admin_scopes` | Scopes required to create, replace, share, or revoke it |

The proxy extracts scopes from Biscuit token facts and matches credentials whose required scopes are a subset of the caller's scopes.

### Scope Inheritance

Credentials inherit the scope context of the token used to create them unless explicitly overridden. If a token carries `scope("org_id:acme")`, credentials created with that token get `[ "org_id:acme" ]` by default. For older tokens, `org_id("acme")` is treated as a scope fallback.

### Multiple Credentials Per Host

When multiple credentials match a target host, the proxy returns an ambiguity error. The agent can specify a credential explicitly via the `agentpw-credential` header (passing the slug).

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

Credential scope matching happens alongside the token's attenuation checks. Both must pass for the request to proceed.

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

A user with credentials for github+linear can delegate a token attenuated to github-GET-only. The recipient can't access linear or do POST requests, even though the underlying user has those credentials.

### White-Labeling

Product teams can white-label agent.pw for their end users. Create credentials with scopes like `[ "end_user:customer_1" ]`, then mint tokens carrying `scope("end_user:customer_1")`. Each end-user's agent only accesses their credentials. Biscuit attenuation still enforces the request-level narrowing cryptographically.

## Revocation

Each block in a Biscuit has a unique revocation ID. The server stores revoked IDs in the `revocations` table. On every request, the middleware checks all block IDs against this table.

`POST /tokens/revoke` revokes the caller's own token (the one in the `Proxy-Authorization` header).

## Key Management

- **Private key**: Ed25519, stored server-side only (`BISCUIT_PRIVATE_KEY` env var or `~/.agent.pw/config.json`)
- **Public key**: Exposed at `GET /.well-known/jwks.json` in JWK format
- Token verification, attenuation, and fact extraction all use the public key only
