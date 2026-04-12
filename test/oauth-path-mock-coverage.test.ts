import { err, ok } from "okay-error";
import { afterEach, describe, expect, it, vi } from "vitest";
import { inputError } from "../packages/server/src/errors";
import { errorOf } from "./support/results";

afterEach(() => {
  vi.resetModules();
  vi.restoreAllMocks();
  vi.doUnmock("../packages/server/src/paths.js");
});

describe("oauth path guard coverage", () => {
  it("covers dead assertPath branches in the oauth service", async () => {
    vi.doMock("../packages/server/src/paths.js", async () => {
      const actual = await vi.importActual<typeof import("../packages/server/src/paths")>(
        "../packages/server/src/paths.js",
      );
      return {
        ...actual,
        assertPath(path: string, label: string) {
          return path.startsWith("bad") ? err(inputError(`mock ${label}`)) : ok(path);
        },
      };
    });

    const { createOAuthService, createInMemoryFlowStore } =
      await import("../packages/server/src/oauth");
    const service = createOAuthService({
      flowStore: createInMemoryFlowStore(),
      clock: () => new Date("2026-01-01T00:00:00.000Z"),
      requireCredentialAccess: () => ok("test-encryption-key"),
      getProfile: async () => ok(null),
      getCredential: async () => ok(null),
      putCredential: async () => ok(null as never),
      deleteCredential: async () => ok(true),
    });

    expect(
      errorOf(
        await service.startAuthorization({
          path: "bad.path",
          option: {
            kind: "oauth",
            source: "discovery",
            label: "OAuth",
            resource: "https://resource.example.com",
          },
          redirectUri: "https://app.example.com/oauth/callback",
        }),
      ).message,
    ).toBe("mock path");
    expect(errorOf(await service.refreshCredential("bad.path")).message).toBe("mock path");
    expect(errorOf(await service.disconnect({ path: "bad.path" })).message).toBe("mock path");
  });
});
