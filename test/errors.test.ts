import { describe, expect, it } from "vitest";
import {
  AgentPwAuthorizationError,
  AgentPwConflictError,
  AgentPwInputError,
} from "../packages/server/src/errors";

describe("agent.pw errors", () => {
  it("assigns stable error names and metadata", () => {
    const conflict = new AgentPwConflictError("conflict");
    const input = new AgentPwInputError("input");
    const authorization = new AgentPwAuthorizationError("credential.use", "/acme/connections/docs");

    expect(conflict).toBeInstanceOf(Error);
    expect(conflict.name).toBe("AgentPwConflictError");
    expect(conflict.message).toBe("conflict");

    expect(input).toBeInstanceOf(Error);
    expect(input.name).toBe("AgentPwInputError");
    expect(input.message).toBe("input");

    expect(authorization).toBeInstanceOf(Error);
    expect(authorization.name).toBe("AgentPwAuthorizationError");
    expect(authorization.action).toBe("credential.use");
    expect(authorization.path).toBe("/acme/connections/docs");
    expect(authorization.message).toBe("Missing 'credential.use' for '/acme/connections/docs'");
  });
});
