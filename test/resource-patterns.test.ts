import { describe, expect, it } from "vitest";
import {
  anyResourcePatternMatches,
  normalizeResource,
  normalizeResourcePattern,
  resourcePatternMatches,
} from "../packages/server/src/resource-patterns";
import { errorOf, must } from "./support/results";

describe("resource pattern helpers", () => {
  it("normalizes resources and strips fragments", () => {
    expect(must(normalizeResource("https://example.com/path#section"))).toBe(
      "https://example.com/path",
    );
  });

  it("normalizes wildcard patterns and matches normalized resources", () => {
    expect(must(normalizeResourcePattern(" https://api.example.com/* "))).toBe(
      "https://api.example.com/*",
    );
    expect(
      must(
        resourcePatternMatches("https://api.example.com/*", "https://api.example.com/v1/users#me"),
      ),
    ).toBe(true);
    expect(
      must(
        anyResourcePatternMatches(
          ["https://auth.example.com/*", "https://api.example.com/*"],
          "https://api.example.com/v1/users",
        ),
      ),
    ).toBe(true);
    expect(
      must(
        resourcePatternMatches("https://api.example.com/*", "https://files.example.com/v1/users"),
      ),
    ).toBe(false);
  });

  it("rejects invalid resources and resource patterns", () => {
    expect(errorOf(normalizeResource("not-a-url"))).toEqual(
      expect.objectContaining({
        type: "Input",
        message: "Invalid resource 'not-a-url'",
      }),
    );
    expect(errorOf(normalizeResourcePattern("")).message).toBe("Resource pattern cannot be empty");
    expect(errorOf(normalizeResourcePattern("/relative/*")).message).toBe(
      "Invalid resource pattern '/relative/*'",
    );
    expect(errorOf(resourcePatternMatches("/relative/*", "https://example.com")).message).toBe(
      "Invalid resource pattern '/relative/*'",
    );
    expect(
      errorOf(resourcePatternMatches("https://api.example.com/*", "not-a-url")).message,
    ).toBe("Invalid resource 'not-a-url'");
    expect(
      errorOf(anyResourcePatternMatches(["/relative/*"], "https://example.com")).message,
    ).toBe("Invalid resource pattern '/relative/*'");
  });
});
