import { describe, expect, it } from "vitest";
import {
  authorizationError,
  conflictError,
  inputError,
  internalError,
  isAgentPwError,
  toAgentPwError,
} from "../packages/server/src/errors";

describe("agent.pw errors", () => {
  it("builds stable discriminated error objects", () => {
    const conflict = conflictError("conflict");
    const input = inputError("input", { field: "path", value: "/" });
    const authorization = authorizationError("credential.use", "/acme/connections/docs");

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
      path: "/acme/connections/docs",
      message: "Missing 'credential.use' for '/acme/connections/docs'",
    });
  });

  it("recognizes and normalizes unknown errors", () => {
    const known = internalError("known");
    expect(isAgentPwError(known)).toBe(true);
    expect(toAgentPwError(known)).toBe(known);

    const unknown = toAgentPwError(new Error("boom"));
    expect(unknown).toEqual(
      expect.objectContaining({
        type: "Internal",
        message: "Unexpected internal error",
        cause: expect.any(Error),
      }),
    );
  });
});
