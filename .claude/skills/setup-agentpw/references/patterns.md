# Integration Patterns

## Pattern 1: Header-based auth (API keys)

Simplest case — store and resolve headers directly.

```ts
// Store
await unwrap(
  pw.connect.setHeaders({
    path: "tenant.connections.resend",
    resource: "https://api.resend.com/",
    headers: { Authorization: "Bearer re_123" },
  }),
);

// Use
const headers = unwrap(
  await pw.connect.resolveHeaders({ path: "tenant.connections.resend" }),
);
await fetch("https://api.resend.com/emails", { headers });
```

## Pattern 2: OAuth flow with profiles

Define a profile, then use the guided connect flow.

```ts
// 1. Define profile (once, on startup or via admin)
await pw.profiles.put("github", {
  resourcePatterns: ["https://api.github.com/*"],
  displayName: "GitHub",
  auth: {
    kind: "oauth",
    authorizationUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    clientId: process.env.GITHUB_CLIENT_ID!,
    clientSecret: process.env.GITHUB_CLIENT_SECRET!,
    scopes: "repo user",
  },
});

// 2. When a user needs to connect
const prepared = unwrap(
  await pw.connect.prepare({
    path: "tenant.connections.github",
    resource: "https://api.github.com/",
  }),
);

if (prepared.kind === "ready") {
  // Already connected
  return prepared.headers;
}

const option = prepared.options.find((o) => o.kind === "oauth");
if (option) {
  const session = unwrap(
    await pw.connect.startOAuth({
      path: "tenant.connections.github",
      option,
      redirectUri: "https://app.example.com/oauth/callback",
    }),
  );
  // Redirect user to session.authorizationUrl
}

// 3. On callback
const completed = unwrap(
  await pw.connect.completeOAuth({
    callbackUri: callbackUrl, // full URL with code and state
  }),
);

// 4. Resolve headers (refresh handled automatically)
const headers = unwrap(
  await pw.connect.resolveHeaders({ path: "tenant.connections.github" }),
);
```

## Pattern 3: Multi-tenant scoping

Scope API per tenant so credentials are isolated.

```ts
function getApiForTenant(tenantId: string) {
  return pw.scope({
    rights: [
      { action: "credential.use", root: tenantId },
      { action: "credential.connect", root: `${tenantId}.connections` },
    ],
  });
}

// Each tenant can only access their own credentials
const api = getApiForTenant("acme");
await api.connect.resolveHeaders({ path: "acme.connections.github" }); // OK
await api.connect.resolveHeaders({ path: "other.connections.github" }); // Blocked
```

## Pattern 4: Proxy pattern — classify upstream 401s

When proxying requests, detect auth challenges and trigger connection flows.

```ts
const upstream = await fetch(targetUrl, { headers: existingHeaders });

if (upstream.status === 401 || upstream.status === 403) {
  const challenge = unwrap(
    await pw.connect.classifyResponse({
      resource: targetUrl,
      response: upstream,
    }),
  );

  if (challenge.kind === "auth-required") {
    // Trigger connect flow for the user
    const prepared = unwrap(
      await pw.connect.prepare({
        path: credentialPath,
        resource: targetUrl,
        response: upstream,
      }),
    );
    // Present prepared.options to user
  }
}
```

## Pattern 5: Hosted OAuth with web handlers

For apps that want agent.pw to handle OAuth callback routing.

```ts
const pw = unwrap(
  await createAgentPw({
    db,
    encryptionKey,
    flowStore,
    oauthClient: {
      metadata: {
        clientId: "https://app.example.com/.well-known/oauth-client",
        redirectUris: ["https://app.example.com/oauth/callback"],
        clientName: "My App",
        tokenEndpointAuthMethod: "none",
      },
      useDynamicRegistration: true,
    },
  }),
);

const handlers = pw.connect.createWebHandlers({
  callbackPath: "/oauth/callback",
});

// In your router:
app.post("/oauth/start", (req) => handlers.start(req, { path, option }));
app.get("/oauth/callback", (req) => handlers.callback(req));
```

## Pattern 6: Transactions

Cascade credential deletion with other cleanup in a single transaction.

```ts
await db.transaction(async (tx) => {
  await tx.delete(tenants).where(eq(tenants.id, tenantId));
  await pw.credentials.delete(tenantId, { db: tx, recursive: true });
  await pw.profiles.delete(tenantId, { db: tx, recursive: true });
});
```

## Pattern 7: Profile with header fields (for admin UIs)

Define header-entry templates so your UI knows what to ask the user.

```ts
await pw.profiles.put("resend", {
  resourcePatterns: ["https://api.resend.com*"],
  displayName: "Resend",
  auth: {
    kind: "headers",
    label: "Resend API key",
    fields: [
      {
        name: "Authorization",
        label: "API key",
        description: "Your Resend API key from the dashboard",
        prefix: "Bearer ",
        secret: true,
      },
    ],
  },
});

// prepare() returns these fields so your UI can render input forms
const prepared = unwrap(
  await pw.connect.prepare({
    path: "tenant.connections.resend",
    resource: "https://api.resend.com/",
  }),
);
// prepared.options[0].fields => the fields defined above
```
