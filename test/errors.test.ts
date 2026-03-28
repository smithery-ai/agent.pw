import { describe, expect, it } from "vitest";
import {
  authorizationError,
  conflictError,
  inputError,
  internalError,
  isAgentPwError,
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
});
