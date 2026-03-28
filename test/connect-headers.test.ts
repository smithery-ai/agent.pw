import { describe, expect, it } from "vitest";
import { mergeHeaders } from "../packages/server/src/lib/connect-headers";

describe("connect header helpers", () => {
  it("merges plain headers with and without preserving existing values", () => {
    expect(
      mergeHeaders({
        existingHeaders: { Authorization: "Bearer old", "X-Trace": "trace-1" },
        headers: { Authorization: "Bearer next", "X-Extra": "extra-1" },
      }),
    ).toEqual({
      Authorization: "Bearer next",
      "X-Extra": "extra-1",
    });

    expect(
      mergeHeaders({
        existingHeaders: { Authorization: "Bearer old", "X-Trace": "trace-1" },
        headers: { Authorization: "Bearer next", "X-Extra": "extra-1" },
        preserveExistingHeaders: true,
      }),
    ).toEqual({
      Authorization: "Bearer next",
      "X-Trace": "trace-1",
      "X-Extra": "extra-1",
    });
  });

  it("preserves only non-auth headers when oauth headers are present", () => {
    expect(
      mergeHeaders({
        existingHeaders: {
          Authorization: "Bearer stale",
          "Proxy-Authorization": "Basic stale",
          "X-Trace": "trace-1",
        },
        headers: {
          Authorization: "Bearer ignored",
          "Proxy-Authorization": "Basic ignored",
          "X-Extra": "extra-1",
        },
        oauthHeaders: {
          Authorization: "Bearer fresh",
          "Proxy-Authorization": "Basic fresh",
          "X-Ignored": "ignored",
        },
        preserveExistingHeaders: true,
      }),
    ).toEqual({
      Authorization: "Bearer fresh",
      "Proxy-Authorization": "Basic fresh",
      "X-Trace": "trace-1",
      "X-Extra": "extra-1",
    });
  });
});
