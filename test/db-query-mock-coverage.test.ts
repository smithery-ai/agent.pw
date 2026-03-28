import { err, ok } from "okay-error";
import { afterEach, describe, expect, it, vi } from "vitest";
import { inputError } from "../packages/server/src/errors";
import { errorOf, must } from "./support/results";

afterEach(() => {
  vi.resetModules();
  vi.restoreAllMocks();
  vi.doUnmock("../packages/server/src/paths.js");
});

describe("db query helper mock coverage", () => {
  it("covers dead path guards and move transaction failures", async () => {
    vi.doMock("../packages/server/src/paths.js", async () => {
      const actual = await vi.importActual<typeof import("../packages/server/src/paths")>(
        "../packages/server/src/paths.js",
      );
      return {
        ...actual,
        assertPath(path: string, label: string) {
          return path.startsWith("bad") ? err(inputError(`mock ${label}`)) : ok(path);
        },
        assertOptionalPath(path: string | undefined, label: string) {
          return path?.startsWith("bad") ? err(inputError(`mock ${label}`)) : ok(path);
        },
      };
    });

    const { createQueryHelpers } = await import("../packages/server/src/db/queries");
    const helpers = must(createQueryHelpers());

    expect(errorOf(await helpers.listCredProfiles({} as never, { path: "bad.path" })).message).toBe(
      "mock path",
    );
    expect(
      errorOf(await helpers.getMatchingCredProfiles({} as never, "bad.path", "https://ok")).message,
    ).toBe("mock path");
    expect(errorOf(await helpers.listCredentials({} as never, { path: "bad.path" })).message).toBe(
      "mock path",
    );

    const txFailureDb = {
      select() {
        return {
          from() {
            return {
              where() {
                return [
                  {
                    path: "good.path",
                    auth: { kind: "headers" },
                    secret: Buffer.from("secret"),
                    createdAt: new Date("2026-01-01T00:00:00.000Z"),
                    updatedAt: new Date("2026-01-01T00:00:00.000Z"),
                  },
                ];
              },
            };
          },
        };
      },
      async transaction() {
        throw new Error("tx failed");
      },
    };

    expect(
      errorOf(await helpers.moveCredential(txFailureDb as never, "good.path", "next.path")).message,
    ).toBe("Database query failed");
  });
});
