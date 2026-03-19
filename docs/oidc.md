# OIDC Integration

This guide is for services that want to trust `agent.pw` directly.

`agent.pw` exposes:

- OIDC for login and just-in-time account provisioning
- OAuth for autonomous agent access to your APIs

The two lanes use the same client registration, but they solve different problems:

- the browser lane gives you a standard login flow for a human-facing UI
- the runtime lane gives agents opaque access tokens scoped to your service

## Discovery

Use discovery instead of hard-coding endpoints:

- `GET /.well-known/openid-configuration`
- `GET /.well-known/oauth-authorization-server`

In the managed deployment these are typically:

```txt
https://agent.pw/.well-known/openid-configuration
https://agent.pw/.well-known/oauth-authorization-server
```

Important details:

- the issuer is the exact `issuer` value returned by discovery, not the site root
- today the managed issuer is typically `https://agent.pw/auth`
- use authorization code flow for browser login
- public clients must use PKCE with `S256`
- JWTs are signed with `EdDSA`
- subjects are pairwise by default

## What we need from you

Trusted clients are registered ahead of time today. To enable OIDC, send us:

- your `client_id`
- your `client_secret`, or tell us the client is public and uses PKCE
- your allowed redirect URIs
- the scopes you want `agent.pw` to issue
- optionally, a resource URI if you want agents to request runtime access by `resource=...`

`agent.pw` currently auto-approves consent for trusted clients.

## Login and provisioning

Use the standard authorization-code flow when a human opens your UI and you want to create or link a local account.

### 1. Redirect to the authorization endpoint

Use the endpoint returned by discovery. A typical request looks like:

```txt
GET https://agent.pw/auth/oauth2/authorize?response_type=code&client_id=agentmail-clerk&redirect_uri=https%3A%2F%2Fagentmail.example%2Fcallback&scope=openid%20email%20profile&state=csrf-123&nonce=login-123
```

Public clients also send PKCE parameters:

```txt
code_challenge=...&code_challenge_method=S256
```

### 2. Exchange the code

Use the token endpoint returned by discovery.

Confidential client example:

```bash
curl -X POST https://agent.pw/auth/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -u 'agentmail-clerk:secret-agentmail' \
  -d 'grant_type=authorization_code' \
  -d 'code=AUTH_CODE' \
  -d 'redirect_uri=https://agentmail.example/callback'
```

Public client example:

```bash
curl -X POST https://agent.pw/auth/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code' \
  -d 'client_id=agentmail-public' \
  -d 'code=AUTH_CODE' \
  -d 'redirect_uri=https://agentmail.example/callback' \
  -d 'code_verifier=PKCE_VERIFIER'
```

### 3. Create or link the user

Use the ID token to create or link a local user row.

Recommended handling:

- validate the ID token using the discovered JWKS
- key local users by `iss + sub`
- use `email` and `name` as display and provisioning hints only
- keep your own application state locally

### 4. Claims you should expect

The ID token and userinfo response may include:

- `iss`
- `sub`
- `aud`
- `email`
- `email_verified`
- `name`
- `org_id`
- `workos_user_id`

`iss + sub` is the stable identifier. Do not key accounts by `email`.

## Runtime API access

If your service also exposes APIs for agents, accept service-scoped access tokens minted by `agent.pw`.

For this lane:

- the access token is opaque
- the agent gets it from `agent.pw` via OAuth token exchange
- your service validates it with introspection

### Token exchange request shape

Agents exchange existing `agent.pw` authority for a service token at the token endpoint.

Current request shape:

- `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
- `subject_token` is a managed `agent.pw` token for the user
- `subject_token_type=urn:agentpw:token-type:managed-biscuit`
- `actor_token` is a managed `agent.pw` token that includes `agent_id`
- `actor_token_type=urn:agentpw:token-type:managed-biscuit`
- `audience` is your `client_id`, or `resource` is your registered resource URI
- `scope` is the service-specific scope to issue
- `authorization_details` is optional structured policy context

Example:

```bash
curl -X POST https://agent.pw/auth/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  -d 'subject_token=USER_MANAGED_TOKEN' \
  -d 'subject_token_type=urn:agentpw:token-type:managed-biscuit' \
  -d 'actor_token=AGENT_MANAGED_TOKEN' \
  -d 'actor_token_type=urn:agentpw:token-type:managed-biscuit' \
  -d 'audience=agentmail-api' \
  -d 'scope=mail.read' \
  -d 'authorization_details=[{"type":"mail","actions":["read"],"account":"ada@example.com"}]'
```

### Introspect runtime tokens

Use introspection for runtime access tokens.

Example:

```bash
curl -X POST https://agent.pw/oauth/introspect \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -u 'agentmail-api:secret-agentmail' \
  -d 'token=ACCESS_TOKEN'
```

A successful response includes the current authorization context, for example:

- `active`
- `client_id`
- `sub`
- `act`
- `scope`
- `may_act`
- `authorization_details`
- `email`
- `org_id`

Access-control guidance:

- authorize against `sub` plus the current actor in `act.sub`
- use `scope` for coarse permissions
- use `authorization_details` for action-level restrictions
- treat `email` as descriptive, not as an identifier

## Better Auth example

[Better Auth's SSO plugin](https://better-auth.com/docs/plugins/sso) is a good fit for the browser login lane.

Server setup:

```ts
import { betterAuth } from "better-auth"
import { sso } from "@better-auth/sso"

export const auth = betterAuth({
  trustedOrigins: ["https://agent.pw"],
  plugins: [sso()],
})
```

Register `agent.pw` as an OIDC provider:

```ts
await auth.api.registerSSOProvider({
  body: {
    providerId: "agentpw",
    issuer: "https://agent.pw/auth",
    domain: "agent.pw",
    oidcConfig: {
      clientId: process.env.AGENTPW_CLIENT_ID!,
      clientSecret: process.env.AGENTPW_CLIENT_SECRET!,
    },
  },
  headers: await headers(),
})
```

Start sign-in with the explicit provider ID:

```ts
const result = await authClient.signIn.sso({
  providerId: "agentpw",
  callbackURL: "https://agentmail.example/app",
  scopes: ["openid", "email", "profile"],
})
```

Notes:

- Better Auth will discover the authorization, token, JWKS, and userinfo endpoints from `https://agent.pw/.well-known/openid-configuration`
- `issuer` should match the exact issuer from discovery
- Better Auth covers the browser login lane; for agent API traffic you should still introspect `agent.pw` access tokens
