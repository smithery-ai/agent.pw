import { describe, it, expect } from "vitest";
import * as oauth from "oauth4webapi";

/**
 * Reproduces the SlideForge/Arcjet issuer mismatch bug.
 *
 * When a server's metadata declares issuer X but the id_token's iss claim
 * is Y (common with OAuth proxies fronting Auth0/WorkOS), oauth4webapi
 * rejects the entire token response — even though the access_token is valid.
 *
 * This test uses a real id_token captured from SlideForge's Auth0 to prove
 * the failure is in oauth4webapi's id_token validation, not in token exchange
 * or storage.
 */

// SlideForge's authorization server metadata (issuer = their domain)
const slideforgeAs: oauth.AuthorizationServer = {
  issuer: "https://api.slideforge.dev",
  authorization_endpoint: "https://api.slideforge.dev/oauth/authorize",
  token_endpoint: "https://api.slideforge.dev/oauth/token",
  // This is what triggers RS256 validation for id_tokens
  id_token_signing_alg_values_supported: ["RS256"],
};

const client: oauth.Client = {
  client_id: "mcp_client_test",
};

// Real id_token from SlideForge's Auth0 (captured via oauth-debug skill).
// iss = "https://dev-t4gsrxy7sn6w3x5b.eu.auth0.com/" (Auth0's issuer)
// But metadata says issuer = "https://api.slideforge.dev" (SlideForge's domain)
const realIdToken =
  "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ikk2TUdVb3E0NVN5UTVmMFpPdWxDVCJ9." +
  "eyJnaXZlbl9uYW1lIjoiQXJqdW4iLCJuaWNrbmFtZSI6ImFyanVua21ybSIsIm5hbWUiOiJBcmp1biIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NMV1hBOWlvQ0RvNzVFRkdoWkNZdDJjaW9xZndielpHSExNWEtQQWp3TWxyTVdOZlZ6cGJRPXM5Ni1jIiwidXBkYXRlZF9hdCI6IjIwMjYtMDQtMDFUMDQ6Mzk6MzguMjc1WiIsImVtYWlsIjoiYXJqdW5rbXJtQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJpc3MiOiJodHRwczovL2Rldi10NGdzcnh5N3NuNnczeDViLmV1LmF1dGgwLmNvbS8iLCJhdWQiOiJmMU1oZExrc2hYOUJieWJGdEF5QWlGRzRaZ1dEQkljYyIsInN1YiI6Imdvb2dsZS1vYXV0aDJ8MTAwMTI1NzgzODg4NzMwNzU5NTczIiwiaWF0IjoxNzc1MDU3NDE4LCJleHAiOjE3NzUwOTM0MTgsInNpZCI6IldaM25MQk94R3pYN25adGo0b1psVDhBcWEzbUlTaVdTIn0." +
  "Tz5l-ytOhZRuW9RdtBg-EAikS4Xp2r64vvLBvL2tsXhOeQV3NrRLv3IfH9j-8R-9U8Qd9vUhFn8sCDKZChy53uBQ6ia3tbe-F2QCI-24GrvJnCYULhvD8dYBXnsZnXTyDp5PckeEA0oztAsSh1H1Hovyy4sgzifwHyiwn0GiPl3cuRXYeBnmaRgOR-hqpzbkr-FDCtJqjxZnPoxxtQOm2xJj5t1BCIluTHuh2kP5KMcOQ2YzTfbEatNCc2tLTAe7pZSvAxJcmR6k1WM3rS2ZwcswRX9hfo8VMyhiHewWqZyxAGMKuFdzK_Db6ch1xH83MaB8CskwAbe-PXCEOY0Uhw";

describe("issuer mismatch repro (SlideForge/Auth0)", () => {
  it("rejects token response containing id_token with mismatched issuer", async () => {
    // Token response with id_token whose iss = Auth0, not SlideForge
    const response = new Response(
      JSON.stringify({
        access_token: "valid-access-token",
        token_type: "Bearer",
        expires_in: 86400,
        id_token: realIdToken,
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );

    // This should fail because oauth4webapi validates id_token.iss against as.issuer
    await expect(
      oauth.processAuthorizationCodeResponse(slideforgeAs, client, response),
    ).rejects.toThrow();
  });

  it("accepts token response WITHOUT id_token", async () => {
    // Same response but without id_token — no issuer validation triggered
    const response = new Response(
      JSON.stringify({
        access_token: "valid-access-token",
        token_type: "Bearer",
        expires_in: 86400,
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );

    const result = await oauth.processAuthorizationCodeResponse(slideforgeAs, client, response);
    expect(result.access_token).toBe("valid-access-token");
  });
});
