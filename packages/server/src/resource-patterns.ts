import { err, ok, result } from "okay-error";
import { inputError } from "./errors.js";
import type { AgentPwResult } from "./types.js";

function escapeRegex(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function normalizeResource(resource: string): AgentPwResult<string> {
  const parsed = result(() => new URL(resource));
  if (!parsed.ok) {
    return err(inputError(`Invalid resource '${resource}'`, { value: resource }));
  }

  parsed.value.hash = "";
  return ok(parsed.value.toString());
}

export function normalizeResourcePattern(pattern: string): AgentPwResult<string> {
  const normalized = pattern.trim();
  if (normalized.length === 0) {
    return err(inputError("Resource pattern cannot be empty", { value: pattern }));
  }

  const [prefix] = normalized.split("*");
  if (prefix && !prefix.includes("://")) {
    return err(inputError(`Invalid resource pattern '${pattern}'`, { value: pattern }));
  }

  return ok(normalized);
}

export function resourcePatternMatches(pattern: string, resource: string): AgentPwResult<boolean> {
  const normalizedPattern = normalizeResourcePattern(pattern);
  if (!normalizedPattern.ok) {
    return normalizedPattern;
  }

  const normalizedResource = normalizeResource(resource);
  if (!normalizedResource.ok) {
    return normalizedResource;
  }

  const regex = new RegExp(
    `^${normalizedPattern.value.split("*").map(escapeRegex).join(".*")}$`,
  );
  return ok(regex.test(normalizedResource.value));
}

export function anyResourcePatternMatches(
  patterns: string[],
  resource: string,
): AgentPwResult<boolean> {
  for (const pattern of patterns) {
    const matches = resourcePatternMatches(pattern, resource);
    if (!matches.ok) {
      return matches;
    }
    if (matches.value) {
      return ok(true);
    }
  }

  return ok(false);
}
