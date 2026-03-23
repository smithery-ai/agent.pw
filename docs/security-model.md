# Security Model

agent.pw uses [Biscuit](https://www.biscuitsec.org/) tokens for identity and attenuation, canonical slash-delimited paths for credential and profile scoping, and a server-side `issued_tokens` ledger for tracked tokens minted through `/tokens`.

## Token Format

Tokens are base64-encoded Biscuit tokens wrapped with an `apw_` transport prefix:

```
apw_En0KEwoRCAASDAoBdBIHCAQSAxiACBIkCAASIKo...
```

Inside the Biscuit, agent.pw uses bare facts only:

```datalog
user_id("usr_123");
org_id("org_acme");
home_path("/org_acme");
right("/org_acme/shared", "credential.use");
right("/org_acme/shared", "credential.bootstrap");
right("/org_acme", "credential.manage");
right("/org_acme", "profile.manage");
scope("repo");
```

The `apw:` / `apw_` fact prefixes are not part of the current model.

## Design Principles

**Identity lives in the token. Authorization is explicit descendant-root access. Attenuation narrows that access further.**

- Tokens carry identity facts plus explicit `right(root, action)` grants.
- `home_path(...)` is optional client-facing metadata for relative path aliases. It is not authority.
- Credentials are authorized by descendant roots, not by implicit ancestor inheritance.
- Each proxied or bootstrap request runs against one active root.
- Credential Profiles describe how to authenticate to a provider. Managed product surfaces usually present them as a flat catalog, while self-hosted installs can still scope profile defaults by path when they need that level of control.
- Management routes are protected twice: the Biscuit authorizer runs on the synthetic `_management` service/action, then route handlers enforce path-based rights such as `credential.manage` or `profile.manage`.

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
- **Verification**: Anyone with the public key (available at `/.well-known/jwks.json`) can verify the signature and evaluate the Biscuit checks.

There are two ways narrowed tokens show up in practice:

- **Offline attenuation** via `restrictToken(...)`: append one more Biscuit block locally, without calling the server.
- **Tracked minting** via `POST /tokens`: the server derives narrower rights from the presented token, mints a fresh Biscuit family, reapplies parent attenuation blocks, applies the requested constraints, and records the result in `issued_tokens`.

## Paths and Rights

Every credential has one canonical leaf path. Self-hosted profiles can also be stored under canonical paths when an installation needs scoped defaults. There are no folder rows in the database; hierarchy is implicit in the path segments.

Examples:

```
/org_acme/shared/github_main
/org_acme/ws_eng/shared/linear_main
/org_acme/ws_eng/user_alice/notion_personal
/linear
```

Canonical storage and policy always use absolute paths starting with `/`.

Client requests may use relative aliases for convenience:

- `agentpw-path`: if it starts with `/`, use it as-is; otherwise resolve it relative to the token's `home_path`
- `agentpw-credential`: if it starts with `/`, use it as-is; otherwise resolve it relative to the selected active root

If a relative reference cannot be resolved because `home_path` is missing or the caller has not selected an active root yet, the proxy returns `409` and requires an absolute path.

The core authorization unit is an explicit root grant:

```datalog
right("/org_acme/shared", "credential.use");
right("/org_acme/shared", "credential.bootstrap");
right("/org_acme", "credential.manage");
right("/org_acme", "profile.manage");
```

A right over a root authorizes actions inside that subtree:

- `credential.use` allows proxied use of matching credentials inside the granted root.
- `credential.bootstrap` allows creation of a new credential inside the granted root.
- `credential.manage` allows mutation of existing credentials inside the granted root.
- `profile.manage` allows mutation of profiles inside the granted root.

There is no implicit upward inheritance for credentials. A token can act only inside roots it was explicitly granted.

`POST /tokens` does not currently require a separate `token.mint` right. It accepts any valid token, but the server can only derive child rights that are already covered by the presented token. `GET /tokens`, `GET /tokens/{id}`, and `DELETE /tokens/{id}` additionally require `credential.manage`.

## Active Root

Every proxied or bootstrap request runs against one active root.

Examples:

```
/org_acme/shared
/org_acme/ws_eng/shared
/org_acme/ws_eng/user_alice
```

Clients may provide it explicitly with `agentpw-path`, using either an absolute path or a relative alias resolved from `home_path`. If a token has multiple eligible roots and the caller does not choose one, the proxy returns `409`.

## Credential Resolution

Within an active root, credential lookup is local and descendant-based:

1. Filter by host.
2. Keep credentials whose path is inside the active root.
3. Choose the deepest matching credential path.
4. If multiple credentials match at the same depth, return `409` and require the caller to disambiguate with `agentpw-credential`.

This is descendant selection, not ancestor inheritance.

## Profile Resolution

Credential Profiles are the auth definitions that describe how to authenticate to a provider. Managed product surfaces usually present them as a flat catalog of provider defaults. The OSS core also allows self-hosted installs to scope profile defaults by path when they want local overrides.

Root-level profiles such as `/linear` and `/github` act as the global defaults.

More specific profiles can narrow those defaults inside a subtree:

```
/linear
/org_acme/linear
/org_acme/ws_eng/linear
```

A profile applies to descendants of `parent(profile.path)`. That means:

- `/org_acme/linear` applies inside `/org_acme/...`
- `/org_acme/ws_eng/linear` applies inside `/org_acme/ws_eng/...`
- `/linear` is the global fallback

Resolution order:

1. Match profiles by slug and host.
2. Keep profiles whose applicable subtree contains the active root.
3. Choose the deepest applicable profile.
4. If none apply locally, fall back to the root-level default.
5. Same-depth conflicts return `409`.

## Authorization Flow

The request pipeline has two layers:

1. **Biscuit attenuation checks**
   Attenuation blocks may narrow by service, HTTP method, URL path prefix, active root, host, or expiry.
2. **agent.pw path authorization**
   The server extracts `right(root, action)` facts from the authority block and enforces descendant semantics in the proxy and route handlers.

Typical attenuation checks look like:

```datalog
check if resource($r), ["api.github.com"].contains($r);
check if operation($op), ["GET"].contains($op);
check if path($p), $p.starts_with("/repos/");
check if requested_root($root), ["/org_acme/shared"].contains($root);
check if time($t), $t <= 2026-03-05T13:00:00Z;
```

For management routes, the same authorizer runs against `_management` instead of the upstream hostname:

```datalog
resource("_management");
action("_management");
path("/tokens");
operation("POST");
allow if user_id($u);
```

That means `/tokens`, `/credentials`, and `/cred_profiles` are still covered by Biscuit checks, not just by database-backed route logic.

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
  {
    services: 'api.github.com',
    methods: 'GET',
    roots: '/org_acme/shared',
    paths: '/repos/',
    ttl: '1h',
  },
])
```

A user with multiple roots can delegate a token narrowed to one host, one method, one active root, and one path prefix. The recipient cannot escape those checks.

The tracked `/tokens` API uses the same constraint vocabulary (`actions`, `hosts`, `roots`, `services`, `methods`, `paths`, `ttl`), but it does not append directly to the presented token. Instead it mints a fresh tracked token family so a revoked child token does not revoke its parent.

### White-Labeling

Product teams can white-label agent.pw for their end users by extending the path tree:

```
/org_acme
/org_acme/customers/bigcorp
/org_acme/customers/bigcorp/users/alice
```

Each level gets explicit roots instead of implicit inheritance. A platform can mint tokens for any combination of descendant roots it wants to expose.

### Token Stack

The CLI supports a token stack for temporary privilege narrowing:

- `token push` — push a provided token, or mint a tracked token from the current token and push it onto the stack
- `token pop` — revert to the previous token
- `token list` — inspect tracked tokens owned by the current identity
- `token revoke <id>` — revoke a tracked token by ID

This lets agents temporarily operate with reduced permissions (for example, restrict to a single host for the duration of a task) and then restore the broader token afterwards. When `token push` is called without restriction flags, it mints and pushes a tracked token with the caller's full currently allowed scope. `token pop` is local-only and does not revoke the issued token.

## Revocation

Each block in a Biscuit has a unique revocation ID. The server stores revoked IDs in the `revocations` table. On every request, the middleware checks all block IDs against this table.

Tracked tokens minted through `POST /tokens` are also recorded in the `issued_tokens` table with their revocation IDs, constraints, rights, and usage metadata. `DELETE /tokens/{id}` revokes a tracked token by ID without requiring the raw bearer token string, and successful authenticated use updates `last_used_at` when the ledger is present.

Because `/tokens` mints a fresh Biscuit family instead of appending directly to the parent token, revoking a tracked child token does not revoke the parent token family.

## Key Management

- **Private key**: Ed25519, stored server-side only (`BISCUIT_PRIVATE_KEY` env var or `~/.agent.pw/server.json`)
- **Public key**: Exposed at `GET /.well-known/jwks.json` in JWK format
- **CLI connection state**: stored separately in `~/.agent.pw/cli.json`
- Token verification, attenuation, and fact extraction all use the public key only
