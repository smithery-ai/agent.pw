import { describe, expect, it } from "vitest";
import {
  ConnectFlowSchema,
  ConnectOAuthOptionSchema,
  OAuthResolvedConfigSchema,
  PendingFlowSchema,
} from "agent.pw";

describe("oauth schemas", () => {
  it("exports oauth schemas and coerces pending flow dates", () => {
    const option = ConnectOAuthOptionSchema.parse({
      kind: "oauth",
      source: "profile",
      resource: "https://api.example.com",
      label: "Example",
      profilePath: "example",
      scopes: ["read"],
    });
    const oauthConfig = OAuthResolvedConfigSchema.parse({
      clientId: "client-123",
      resource: "https://api.example.com",
      clientAuthentication: "none",
    });
    const flow = PendingFlowSchema.parse({
      id: "flow-123",
      path: "org.example",
      credential: {
        profilePath: "example",
      },
      redirectUri: "https://app.example.com/oauth/callback",
      codeVerifier: "verifier-123",
      expiresAt: "2026-03-28T00:00:00.000Z",
      oauthConfig,
    });
    const publicFlow = ConnectFlowSchema.parse({
      flowId: "flow-123",
      path: "org.example",
      resource: "https://api.example.com",
      profilePath: "example",
      expiresAt: "2026-03-28T00:00:00.000Z",
    });

    expect(flow.expiresAt).toBeInstanceOf(Date);
    expect(flow.credential).toEqual({ profilePath: "example" });
    expect(flow.oauthConfig).toEqual(oauthConfig);
    expect(publicFlow.expiresAt).toBeInstanceOf(Date);
  });
});
