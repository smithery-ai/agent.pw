import { describe, expect, it } from "vitest";
import { coerceSqlNamespace, createAgentPwSchema } from "agent.pw/sql";

describe("sql namespace helpers", () => {
  it("uses the default namespace when none is provided", () => {
    expect(coerceSqlNamespace()).toEqual(
      expect.objectContaining({
        schema: "agentpw",
        tablePrefix: "",
      }),
    );
  });

  it("accepts raw options and prebuilt namespace objects", () => {
    const fromOptions = coerceSqlNamespace({
      schema: "connect_data",
      tablePrefix: "smithery_",
    });
    expect(fromOptions).toEqual(
      expect.objectContaining({
        schema: "connect_data",
        tablePrefix: "smithery_",
      }),
    );
    expect(fromOptions.tableName("cred_profiles")).toBe("smithery_cred_profiles");

    const prebuilt = createAgentPwSchema({
      schema: "connect_data",
      tablePrefix: "smithery_",
    });
    expect(coerceSqlNamespace(prebuilt)).toBe(prebuilt);
  });

  it("rejects invalid schema identifiers and table prefixes", () => {
    expect(() => createAgentPwSchema({ schema: "bad-schema" })).toThrow(
      "Invalid SQL schema 'bad-schema'",
    );
    expect(() => createAgentPwSchema({ tablePrefix: "bad-prefix-" })).toThrow(
      "Invalid table prefix 'bad-prefix-'",
    );
  });
});
