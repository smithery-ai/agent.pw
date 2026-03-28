import { describe, expect, it } from "vitest";
import {
  ancestorPaths,
  canonicalizePath,
  credentialName,
  credentialParentPath,
  deepestAncestor,
  isAncestorOrEqual,
  joinCredentialPath,
  pathDepth,
  pathFromTokenFacts,
  publicProfilePath,
  validateCredentialName,
  validatePath,
} from "agent.pw/paths";

describe("path helpers", () => {
  it("validates strict canonical dot paths", () => {
    expect(canonicalizePath("org_alpha.linear")).toBe("org_alpha.linear");

    expect(validatePath("acme.docs")).toBe(true);
    expect(validatePath("github")).toBe(true);
    expect(validatePath("/acme")).toBe(false);
    expect(validatePath("acme..github")).toBe(false);
    expect(validatePath(".acme")).toBe(false);
    expect(validatePath("acme.")).toBe(false);
    expect(validatePath("")).toBe(false);
    expect(validatePath("acme.docs!")).toBe(false);

    expect(isAncestorOrEqual("acme", "acme")).toBe(true);
    expect(isAncestorOrEqual("acme", "acme.linear")).toBe(true);
    expect(isAncestorOrEqual("acme", "acme2.linear")).toBe(false);
    expect(pathFromTokenFacts({ orgId: "org_alpha" })).toBe("org_alpha");
    expect(pathFromTokenFacts({ orgId: null })).toBeNull();
  });

  it("builds credential paths", () => {
    expect(credentialName("org_alpha.linear")).toBe("linear");
    expect(publicProfilePath("github")).toBe("github");
    expect(credentialParentPath("org_alpha.linear")).toBe("org_alpha");
    expect(credentialParentPath("linear")).toBeNull();
    expect(joinCredentialPath(undefined, "github")).toBe("github");
    expect(joinCredentialPath("org_alpha", "github")).toBe("org_alpha.github");
  });

  it("validates credential names and finds ancestor matches", () => {
    expect(validateCredentialName("linear")).toBe(true);
    expect(validateCredentialName("")).toBe(false);
    expect(validateCredentialName("linear/oauth")).toBe(false);
    expect(validateCredentialName("linear.oauth")).toBe(false);
    expect(validateCredentialName(".")).toBe(false);
    expect(validateCredentialName("..")).toBe(false);
    expect(validateCredentialName("linear!")).toBe(false);

    expect(pathDepth("github")).toBe(1);
    expect(pathDepth("org_alpha.ws_engineering.linear")).toBe(3);
    expect(ancestorPaths("org_alpha.ws_engineering.service")).toEqual([
      "org_alpha.ws_engineering.service",
      "org_alpha.ws_engineering",
      "org_alpha",
    ]);

    expect(
      deepestAncestor(
        [{ path: "org_alpha" }, { path: "org_alpha.ws_engineering" }],
        "org_alpha.ws_engineering.linear",
      ),
    ).toEqual({ path: "org_alpha.ws_engineering" });
    expect(deepestAncestor([{ path: "org_beta" }], "org_alpha.ws_engineering.linear")).toBeNull();
  });
});
