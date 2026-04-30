import { err, ok, result } from "okay-error";
import * as oauth from "oauth4webapi";
import { identityGrantSigningFailed, inputError } from "./errors.js";
import type { IdentityGrantOptions, IdentityJwksDocument } from "./types.js";

export const JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
export const IDENTITY_ASSERTION_GRANT_PROFILE = "urn:ietf:params:oauth:grant-profile:id-jag";
export const IDENTITY_ASSERTION_JWT_TYPE = "oauth-id-jag+jwt";

function base64url(value: string) {
  return Buffer.from(new TextEncoder().encode(value)).toString("base64url");
}

function privateJwk<TPrincipal>(options: IdentityGrantOptions<TPrincipal>) {
  return options.signingKey.privateJwk;
}

export function createIdentityJwksDocument<TPrincipal>(
  options: IdentityGrantOptions<TPrincipal> | undefined,
) {
  if (!options) {
    return err(inputError("Identity grant helpers require AgentPwOptions.identityGrant"));
  }
  const jwk = privateJwk(options);
  return ok<IdentityJwksDocument>({
    keys: [
      {
        kty: "RSA",
        n: jwk.n,
        e: jwk.e,
        ...(jwk.kid ? { kid: jwk.kid } : {}),
        alg: options.signingAlg ?? "RS256",
        use: "sig",
      },
    ],
  });
}

export async function importIdentityPrivateKey<TPrincipal>(
  options: IdentityGrantOptions<TPrincipal>,
) {
  const imported = await result(
    crypto.subtle.importKey(
      "jwk",
      privateJwk(options),
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
      },
      false,
      ["sign"],
    ),
  );
  if (!imported.ok) {
    return err(identityGrantSigningFailed(imported.error));
  }
  return ok<oauth.PrivateKey>({
    key: imported.value,
    ...(privateJwk(options).kid ? { kid: privateJwk(options).kid } : {}),
  });
}

export async function signIdentityAssertion<TPrincipal>(input: {
  options: IdentityGrantOptions<TPrincipal>;
  subject: string;
  audience: string;
  clientId: string;
  protectedResource: string;
  scopes: readonly string[];
  now: Date;
}) {
  const imported = await importIdentityPrivateKey(input.options);
  if (!imported.ok) {
    return imported;
  }

  const now = Math.floor(input.now.getTime() / 1000);
  const header = {
    alg: input.options.signingAlg ?? "RS256",
    typ: IDENTITY_ASSERTION_JWT_TYPE,
    ...(privateJwk(input.options).kid ? { kid: privateJwk(input.options).kid } : {}),
  };
  const payload = {
    iss: input.options.issuer,
    sub: input.subject,
    aud: input.audience,
    client_id: input.clientId,
    jti: crypto.randomUUID(),
    exp: now + (input.options.ttlSeconds ?? 60),
    iat: now,
    resource: input.protectedResource,
    ...(input.scopes.length > 0 ? { scope: input.scopes.join(" ") } : {}),
  };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
  const signature = await result(
    crypto.subtle.sign(
      { name: "RSASSA-PKCS1-v1_5" },
      imported.value.key,
      new TextEncoder().encode(signingInput),
    ),
  );
  if (!signature.ok) {
    return err(identityGrantSigningFailed(signature.error));
  }
  return ok(`${signingInput}.${Buffer.from(signature.value).toString("base64url")}`);
}
