# Service Vendor Integration

If your service is willing to trust `agent.pw` directly, the simplest integration is OIDC.

That gives you two paths:

- **Direct trust**: your service treats `agent.pw` as the identity provider and accepts OIDC tokens minted for your client.
- **Compatibility mode**: if you are not ready to trust `agent.pw`, users can still reach your service through the `agent.pw` vault and proxy.

This guide is for the direct-trust path.

## What `agent.pw` exposes

`agent.pw` publishes a standard OIDC discovery document:

- `GET /.well-known/openid-configuration`
- `GET /oidc/jwks.json`
- `GET /oidc/authorize`
- `POST /oidc/token`
- `GET /oidc/userinfo`
- `POST /oauth/introspect`

Current behavior:

- `response_type=code`
- `grant_type=authorization_code`
- `client_secret_basic`, `client_secret_post`, or public clients with `S256` PKCE
- pairwise subjects
- `EdDSA` JWT signing

The default scopes are:

- `openid`
- `profile`
- `email`

## What we need from you

Today, trusted services are registered ahead of time on the `agent.pw` side. To enable direct trust, send us:

- your `client_id`
- your `client_secret`, or tell us the client is public and uses PKCE
- your allowed redirect URIs
- the scopes you want `agent.pw` to issue

We attach that to your service profile in `agent.pw`. Once that is configured, agents can use OIDC with your service.

## What you should trust

Treat `agent.pw` as the issuer for your OIDC client.

Use the discovery document instead of hard-coding endpoints. In the managed deployment, the issuer is usually:

```txt
https://agent.pw
```

The discovery document is:

```txt
https://agent.pw/.well-known/openid-configuration
```

Use the issuer you were given for your deployment if it differs from `https://agent.pw`.

## Claims you should expect

`agent.pw` issues:

- an ID token for login
- an access token for API access

Important claims:

- `iss`: the `agent.pw` issuer URL
- `sub`: a pairwise subject, stable for your client only
- `aud`: your `client_id`
- `email`
- `email_verified`
- `name`
- `org_id`

Recommended handling:

- key local users by `iss + sub`
- use `email` and `name` for display and provisioning hints
- do not assume `sub` is stable across different services

## DIY OIDC integration

### 1. Redirect to `agent.pw`

Send the browser to the authorization endpoint from discovery.

Example:

```txt
GET https://agent.pw/oidc/authorize?response_type=code&client_id=agentmail-clerk&redirect_uri=https%3A%2F%2Fagentmail.example%2Fcallback&scope=openid%20email%20profile&state=csrf-123&nonce=login-123
```

If your client is public, also send PKCE parameters:

```txt
code_challenge=...&code_challenge_method=S256
```

### 2. Exchange the code

Exchange the returned code at `/oidc/token`.

Confidential client example:

```bash
curl -X POST https://agent.pw/oidc/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -u 'agentmail-clerk:secret-agentmail' \
  -d 'grant_type=authorization_code' \
  -d 'code=AUTH_CODE' \
  -d 'redirect_uri=https://agentmail.example/callback'
```

Public client example:

```bash
curl -X POST https://agent.pw/oidc/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code' \
  -d 'client_id=agentmail-public' \
  -d 'code=AUTH_CODE' \
  -d 'redirect_uri=https://agentmail.example/callback' \
  -d 'code_verifier=PKCE_VERIFIER'
```

### 3. Create or link the user

Use the ID token claims to create or link the user in your system.

For most products, the right model is just-in-time provisioning:

- validate the token using the discovered JWKS
- look up the user by `iss + sub`
- create the user if they do not exist
- keep your own application state locally

### 4. Use the access token

Use the access token for your APIs. You can validate it locally using the JWKS, or call the introspection endpoint if you prefer an online check.

Example introspection call:

```bash
curl -X POST https://agent.pw/oauth/introspect \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -u 'agentmail-clerk:secret-agentmail' \
  -d 'token=ACCESS_TOKEN'
```

## Better Auth example

[Better Auth's SSO plugin](https://better-auth.com/docs/plugins/sso) can integrate with `agent.pw` using standard OIDC discovery.

Server setup:

```ts
import { betterAuth } from "better-auth"
import { sso } from "@better-auth/sso"

export const auth = betterAuth({
  trustedOrigins: ["https://agent.pw"],
  plugins: [
    sso(),
  ],
})
```

Register `agent.pw` as an OIDC provider:

```ts
await auth.api.registerSSOProvider({
  body: {
    providerId: "agentpw",
    issuer: "https://agent.pw",
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

- Better Auth will discover the authorization, token, JWKS, and userinfo endpoints from `https://agent.pw/.well-known/openid-configuration`.
- `trustedOrigins` must allow the `agent.pw` issuer for discovery to succeed.
- Prefer starting the flow with `providerId: "agentpw"` rather than email-domain discovery.

## When direct trust is not possible

If your service is not ready to trust `agent.pw` directly, users can still use your service through the existing `agent.pw` vault and proxy.

That is the fallback path for:

- raw API keys
- provider OAuth tokens that are not issued by `agent.pw`
- custom header schemes
- services that have not yet adopted direct OIDC trust

If you want to support the cleanest agent experience, direct OIDC trust is the path we recommend.
