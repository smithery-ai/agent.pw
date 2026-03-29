import { describe, expect, it } from "vitest";
import packageJson from "../package.json";

describe("package surface", () => {
  it("does not expose biscuit helpers", () => {
    const exportKey = `./${"biscuit"}`;
    const dependencyKey = `@smithery/${"biscuit"}`;

    expect(packageJson.exports).not.toHaveProperty(exportKey);
    expect(packageJson.dependencies).not.toHaveProperty(dependencyKey);
  });

  it("declares the GitHub repository for release provenance", () => {
    expect(packageJson.repository).toEqual({
      type: "git",
      url: "git+https://github.com/smithery-ai/agent.pw.git",
    });
  });
});
