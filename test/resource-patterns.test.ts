import { describe, expect, it } from "vitest";
import { AgentPwInputError } from "../packages/server/src/errors";
import {
  anyResourcePatternMatches,
  normalizeResource,
  normalizeResourcePattern,
  resourcePatternMatches,
} from "../packages/server/src/resource-patterns";

describe("resource pattern helpers", () => {
  it("normalizes resources and strips fragments", () => {
    expect(normalizeResource("https://example.com/path#section")).toBe("https://example.com/path");
  });

  it("normalizes wildcard patterns and matches normalized resources", () => {
    expect(normalizeResourcePattern(" https://api.example.com/* ")).toBe(
      "https://api.example.com/*",
    );
    expect(
      resourcePatternMatches("https://api.example.com/*", "https://api.example.com/v1/users#me"),
    ).toBe(true);
    expect(
      anyResourcePatternMatches(
        ["https://auth.example.com/*", "https://api.example.com/*"],
        "https://api.example.com/v1/users",
      ),
    ).toBe(true);
    expect(
      resourcePatternMatches("https://api.example.com/*", "https://files.example.com/v1/users"),
    ).toBe(false);
  });

  it("rejects invalid resources and resource patterns", () => {
    expect(() => normalizeResource("not-a-url")).toThrow(AgentPwInputError);
    expect(() => normalizeResourcePattern("")).toThrow("Resource pattern cannot be empty");
    expect(() => normalizeResourcePattern("/relative/*")).toThrow(
      "Invalid resource pattern '/relative/*'",
    );
  });
});
