# Security Model

agent.pw uses [Biscuit](https://www.biscuitsec.org/) tokens — a capability-based authorization format built on public-key cryptography. Tokens are self-contained, offline-verifiable, and support attenuation (narrowing permissions without server involvement).

## Token Format

Tokens are base64-encoded Biscuit tokens with an `apw_` prefix:

```
apw_En0KEwoRCAASDAoBdBIHCAQSAxiACBIkCAASIKo...
```

## Design Principles

**Token = identity. Path hierarchy = access control. Attenuation = client-side narrowing.**

The token carries *who you are* (identity facts like `org_id`). The path tree determines which credentials a token can use or manage. Attenuation narrows further (host, method, path, TTL). All facts are namespaced to `apw` so deployers may extend with additional facts.

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

## Path-Based Access Control

Every credential and profile lives at a path in a tree that encodes organizational hierarchy (e.g. `/orgs/acme/linear`). The token's position in the tree — derived from its identity facts — determines what it can access.

### Two Directions

**Usage flows upward.** A token can use credentials stored at ancestor paths. An org-level credential at `/orgs/acme/github` is usable by any token rooted at `/orgs/acme` or deeper (`/orgs/acme/ws/engineering`). Credentials at higher paths are inherited by everyone below, like environment variables in a process tree.

**Admin flows downward.** A token can create, update, and delete credentials at its own path or deeper. A token at `/orgs/acme` can manage `/orgs/acme/github` but cannot manage `/other-org/github`.

### Credential Resolution

When multiple credentials match a target host:

1. **Different depths** — the deepest ancestor wins (most specific).
2. **Same depth** — the proxy returns a 409 conflict. The caller specifies which credential to use via the `agentpw-credential` header.

### Creation

A token can only create objects at its own path or deeper. Global objects (root path `/`) require the master token.

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

Path-based credential resolution happens after token authorization. Both the token's Biscuit checks and the path ancestry rules must pass for the request to proceed.

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

Product teams can white-label agent.pw for their end users by extending the path tree:

```
/orgs/acme                                Acme (agent.pw deployer)
/orgs/acme/customers/bigcorp              BigCorp (Acme's customer)
/orgs/acme/customers/bigcorp/users/alice  Alice (BigCorp's end user)
```

Credentials at `/orgs/acme` are inherited by BigCorp and Alice. BigCorp can override with more specific credentials at their path. Each level attenuates tokens for the level below. Recursive to any depth.

### Token Stack

The CLI supports a token stack for temporary privilege narrowing:

- `token push` — restrict the current token and push it onto a stack
- `token pop` — revert to the previous token

This lets agents temporarily operate with reduced permissions (e.g. restrict to a single host for the duration of a task) and then restore the broader token afterwards.

## Revocation

Each block in a Biscuit has a unique revocation ID. The server stores revoked IDs in the `revocations` table. On every request, the middleware checks all block IDs against this table.

`POST /tokens/revoke` revokes the caller's own token (the one in the `Proxy-Authorization` header).

## Key Management

- **Private key**: Ed25519, stored server-side only (`BISCUIT_PRIVATE_KEY` env var or `~/.agent.pw/config.json`)
- **Public key**: Exposed at `GET /.well-known/jwks.json` in JWK format
- Token verification, attenuation, and fact extraction all use the public key only
