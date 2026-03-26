import { afterEach, describe, expect, it, vi } from "vitest";
import {
  RESERVED_PATHS,
  deriveDisplayName,
  errorMessage,
  isRecord,
  lastItem,
  looksLikeHostname,
  randomId,
  relativeTime,
  validateFlowId,
} from "../packages/server/src/lib/utils";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("utils", () => {
  it("formats unknown errors into readable strings", () => {
    expect(errorMessage(new Error("boom"))).toBe("boom");
    expect(errorMessage("plain string")).toBe("plain string");
    expect(errorMessage({ ok: true })).toBe('{"ok":true}');
  });

  it("generates hex ids and validates flow ids", () => {
    expect(randomId()).toMatch(/^[0-9a-f]{48}$/);
    expect(validateFlowId(undefined)).toBeUndefined();
    expect(validateFlowId("short")).toBeUndefined();
    expect(validateFlowId("12345678901234567890123456789012")).toBe(
      "12345678901234567890123456789012",
    );
  });

  it("derives display names and exposes reserved paths", () => {
    expect(deriveDisplayName("api.linear.app")).toBe("Linear");
    expect(deriveDisplayName("www.github.com")).toBe("Github");
    expect(RESERVED_PATHS.has("auth")).toBe(true);
    expect(isRecord({ ok: true })).toBe(true);
    expect(isRecord([])).toBe(false);
    expect(isRecord(null)).toBe(false);
    expect(lastItem(["a", "b", "c"])).toBe("c");
    expect(lastItem([])).toBeUndefined();
  });

  it("formats relative times across each display bucket", () => {
    vi.spyOn(Date, "now").mockReturnValue(new Date("2026-03-10T12:00:00.000Z").getTime());

    expect(relativeTime(new Date("2026-03-10T11:59:45.000Z"))).toBe("just now");
    expect(relativeTime(new Date("2026-03-10T11:55:00.000Z"))).toBe("5 min ago");
    expect(relativeTime(new Date("2026-03-10T09:00:00.000Z"))).toBe("3h ago");
    expect(relativeTime(new Date("2026-03-09T12:00:00.000Z"))).toBe("1 day ago");
    expect(relativeTime(new Date("2026-03-05T12:00:00.000Z"))).toBe("5 days ago");
    expect(relativeTime(new Date("2026-02-08T12:00:00.000Z"))).toBe("1 month ago");
    expect(relativeTime(new Date("2025-12-10T12:00:00.000Z"))).toBe("3 months ago");
  });

  it("distinguishes real hostnames from junk strings", () => {
    expect(looksLikeHostname("api.linear.app")).toBe(true);
    expect(looksLikeHostname("linear")).toBe(false);
    expect(looksLikeHostname(".env")).toBe(false);
    expect(looksLikeHostname("config.json")).toBe(false);
    expect(looksLikeHostname("example.log4")).toBe(false);
  });
});
