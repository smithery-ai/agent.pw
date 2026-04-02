import { describe, expect, it } from "vitest";
import {
  authorizationError,
  conflictError,
  cryptoError,
  expiredError,
  inputError,
  internalError,
  isAgentPwError,
  isAuthorizationError,
  isConflictError,
  isCryptoError,
  isExpiredError,
  isInputError,
  isInternalError,
  isNotFoundError,
  isOAuthError,
  isPersistenceError,
  notFoundError,
  oauthError,
  persistenceError,
} from "../packages/server/src/errors";

describe("agent.pw errors", () => {
  it("builds stable discriminated error objects", () => {
    const conflict = conflictError("conflict");
    const input = inputError("input", { field: "path", value: "/" });
    const authorization = authorizationError("credential.use", "acme.connections.docs");

    expect(conflict).toEqual({
      type: "Conflict",
      message: "conflict",
    });

    expect(input).toEqual({
      type: "Input",
      message: "input",
      field: "path",
      value: "/",
    });

    expect(authorization).toEqual({
      type: "Authorization",
      action: "credential.use",
      path: "acme.connections.docs",
      message: "Missing 'credential.use' for 'acme.connections.docs'",
    });
  });

  it("recognizes known error objects", () => {
    const known = internalError("known");
    expect(isAgentPwError(known)).toBe(true);
    expect(isAgentPwError(persistenceError("write", "persist", { path: "org.docs" }))).toBe(true);
    expect(isAgentPwError(new Error("boom"))).toBe(false);
  });

  it("narrows with specific type guards", () => {
    expect(isInputError(inputError("bad"))).toBe(true);
    expect(isInputError(conflictError("no"))).toBe(false);

    expect(isConflictError(conflictError("dup"))).toBe(true);
    expect(isConflictError(inputError("no"))).toBe(false);

    expect(isAuthorizationError(authorizationError("read", "a.b"))).toBe(true);
    expect(isAuthorizationError(inputError("no"))).toBe(false);

    const nf = notFoundError("credential", "gone", { path: "a.b" });
    expect(isNotFoundError(nf)).toBe(true);
    expect(isNotFoundError(nf, "credential")).toBe(true);
    expect(isNotFoundError(nf, "profile")).toBe(false);
    expect(isNotFoundError(inputError("no"))).toBe(false);

    expect(isExpiredError(expiredError("token", "expired"))).toBe(true);
    expect(isExpiredError(inputError("no"))).toBe(false);

    expect(isPersistenceError(persistenceError("write", "fail", { path: "x" }))).toBe(true);
    expect(isPersistenceError(inputError("no"))).toBe(false);

    expect(isOAuthError(oauthError("fail", { code: "oauth/test", retryable: false }))).toBe(true);
    expect(isOAuthError(inputError("no"))).toBe(false);

    expect(isCryptoError(cryptoError("encrypt", "fail"))).toBe(true);
    expect(isCryptoError(inputError("no"))).toBe(false);

    expect(isInternalError(internalError("boom"))).toBe(true);
    expect(isInternalError(inputError("no"))).toBe(false);

    // non-error values
    expect(isNotFoundError(null)).toBe(false);
    expect(isInputError("string")).toBe(false);
  });
});
