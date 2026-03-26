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
  resolvePathReference,
  validateCredentialName,
  validatePath,
} from "agent.pw/paths";

describe("path helpers", () => {
  it("normalizes, validates, and compares canonical paths", () => {
    expect(canonicalizePath("org_alpha/linear")).toBe("/org_alpha/linear");
    expect(canonicalizePath("org_alpha//linear/")).toBe("/org_alpha/linear");
    expect(canonicalizePath("/org_alpha//linear/")).toBe("/org_alpha/linear");

    expect(validatePath("/")).toBe(true);
    expect(validatePath("/org_alpha/linear")).toBe(true);
    expect(validatePath("org_alpha/linear")).toBe(false);
    expect(validatePath("/org_alpha/linear/")).toBe(false);
    expect(validatePath("/org_alpha/../linear")).toBe(false);

    expect(isAncestorOrEqual("/org_alpha", "/org_alpha")).toBe(true);
    expect(isAncestorOrEqual("/", "/org_alpha/linear")).toBe(true);
    expect(isAncestorOrEqual("/org_alpha", "/org_alpha/linear")).toBe(true);
    expect(isAncestorOrEqual("/org_alpha/", "/org_alpha/linear")).toBe(true);
    expect(isAncestorOrEqual("/org_alpha", "/org_alphabet/linear")).toBe(false);
    expect(pathFromTokenFacts({ orgId: "org_alpha" })).toBe("/org_alpha");
    expect(pathFromTokenFacts({ orgId: null })).toBe("/");
  });

  it("builds and resolves credential paths", () => {
    expect(credentialName("/org_alpha/linear")).toBe("linear");
    expect(publicProfilePath("github")).toBe("/github");
    expect(credentialParentPath("/org_alpha/linear")).toBe("/org_alpha");
    expect(credentialParentPath("/linear")).toBe("/");
    expect(joinCredentialPath("/", "github")).toBe("/github");
    expect(joinCredentialPath("/org_alpha", "github")).toBe("/org_alpha/github");

    expect(resolvePathReference("/absolute", "/org_alpha")).toBe("/absolute");
    expect(resolvePathReference("linear", null)).toBeNull();
    expect(resolvePathReference("linear", "/")).toBe("/linear");
    expect(resolvePathReference("/linear", "/org_alpha")).toBe("/linear");
    expect(resolvePathReference("linear", "/org_alpha")).toBe("/org_alpha/linear");
  });

  it("validates credential names and finds ancestor matches", () => {
    expect(validateCredentialName("linear")).toBe(true);
    expect(validateCredentialName("")).toBe(false);
    expect(validateCredentialName("linear/oauth")).toBe(false);
    expect(validateCredentialName("linear.oauth")).toBe(false);
    expect(validateCredentialName(".")).toBe(false);
    expect(validateCredentialName("..")).toBe(false);

    expect(pathDepth("/")).toBe(0);
    expect(pathDepth("/org_alpha/ws_engineering/linear")).toBe(3);
    expect(ancestorPaths("/")).toEqual(["/"]);
    expect(ancestorPaths("/org_alpha//ws_engineering/service/")).toEqual([
      "/org_alpha/ws_engineering/service",
      "/org_alpha/ws_engineering",
      "/org_alpha",
      "/",
    ]);

    expect(
      deepestAncestor(
        [{ path: "/" }, { path: "/org_alpha" }, { path: "/org_alpha/ws_engineering" }],
        "/org_alpha/ws_engineering/linear",
      ),
    ).toEqual({ path: "/org_alpha/ws_engineering" });
    expect(deepestAncestor([{ path: "/org_beta" }], "/org_alpha/ws_engineering/linear")).toBeNull();
  });
});
