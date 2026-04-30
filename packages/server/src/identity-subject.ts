import type { IdentitySubjectResolver } from "./types.js";

function arrayBuffer(value: string | Uint8Array) {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function base64url(value: ArrayBuffer) {
  return Buffer.from(value).toString("base64url");
}

export function pairwiseIdentitySubject(input: {
  secret: string | Uint8Array;
  sector?: "authorization-server" | "resource";
  info?: string;
}): IdentitySubjectResolver<string> {
  return async (subjectInput) => {
    const key = await crypto.subtle.importKey(
      "raw",
      arrayBuffer(input.secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sector =
      input.sector === "resource"
        ? subjectInput.protectedResource
        : subjectInput.authorizationServerIssuer;
    const material = `${input.info ?? "agent.pw.id-jag"}\0${sector}\0${subjectInput.principal}`;
    return base64url(await crypto.subtle.sign("HMAC", key, arrayBuffer(material)));
  };
}
