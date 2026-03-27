/**
 * Biscuit token operations for agent.pw integrations.
 *
 * Identity and descendant-rights model:
 * - Authority block: identity and rights facts
 * - Attenuation blocks: checks that narrow service/method/path/TTL
 * - Authorizer: ambient request facts plus bare identity checks
 * - Route handlers evaluate right(root, operation) against canonical object paths
 */

import { err, ok } from "okay-error";
import {
  Biscuit,
  PrivateKey,
  PublicKey,
  AuthorizerBuilder,
  KeyPair,
  SignatureAlgorithm,
} from "@smithery/biscuit";
import { inputError } from "./errors.js";
import type {
  BiscuitSubject,
  BiscuitTokenFacts,
  RuleConstraint,
  RuleGrant,
} from "./types.js";

export const TOKEN_PREFIX = "apw_";

const RUN_LIMITS = {
  max_facts: 1000,
  max_iterations: 100,
  max_time_micro: 5_000_000, // 5s — generous for normal operation
};

const MAX_AUTHORIZE_RETRIES = 2; // first call may trigger WASM JIT and timeout; retry succeeds
function addPrefix(base64: string): string {
  return TOKEN_PREFIX + base64;
}

export function stripPrefix(token: string): string {
  if (token.startsWith(TOKEN_PREFIX)) return token.slice(TOKEN_PREFIX.length);
  return token;
}

export async function hashToken(token: string) {
  const input = new TextEncoder().encode(token);
  const hash = await crypto.subtle.digest("SHA-256", input);
  return Buffer.from(hash).toString("hex");
}

function escapeDatalog(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function toArray<T>(value: T | T[] | undefined): T[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

function normalizeFactStatement(fact: string): string {
  const trimmed = fact.trim();
  if (!trimmed) return "";
  return trimmed.endsWith(";") ? trimmed : `${trimmed};`;
}

export function parseTtlSeconds(ttl: string | number) {
  if (typeof ttl === "number") return ok(ttl);
  if (/^\d+$/.test(ttl)) return ok(parseInt(ttl, 10));
  const match = ttl.match(/^(\d+)(s|m|h|d)$/);
  if (!match) return err(inputError(`Invalid TTL format: ${ttl}`));
  const value = parseInt(match[1], 10);
  const unit = match[2];
  const multiplier = unit === "s" ? 1 : unit === "m" ? 60 : unit === "h" ? 3600 : 86400;
  return ok(value * multiplier);
}

// ─── Attenuation Block Code ─────────────────────────────────────────────────

/**
 * Build attenuation block code from restriction constraints.
 * Each constraint adds a check that the request must match.
 */
function buildAttenuationCode(constraints: RuleConstraint[]) {
  const lines: string[] = [];
  const alternatives: string[] = [];

  for (const c of constraints) {
    const actions = toArray(c.actions);
    const hosts = toArray(c.hosts);
    const roots = toArray(c.roots);
    const services = toArray(c.services);
    const methods = toArray(c.methods);
    const paths = toArray(c.paths);

    const parts: string[] = [];

    if (actions.length > 0) {
      const list = actions.map((action) => `"${escapeDatalog(action)}"`).join(", ");
      parts.push(`action($action), [${list}].contains($action)`);
    }

    if (hosts.length > 0) {
      const list = hosts.map((host) => `"${escapeDatalog(host)}"`).join(", ");
      parts.push(`host($host), [${list}].contains($host)`);
    }

    if (roots.length > 0) {
      const list = roots.map((root) => `"${escapeDatalog(root)}"`).join(", ");
      parts.push(`requested_root($root), [${list}].contains($root)`);
    }

    if (services.length > 0) {
      const list = services.map((s) => `"${escapeDatalog(s)}"`).join(", ");
      parts.push(`resource($r), [${list}].contains($r)`);
    }

    if (methods.length > 0) {
      const list = methods.map((m) => `"${escapeDatalog(m.toUpperCase())}"`).join(", ");
      parts.push(`operation($op), [${list}].contains($op)`);
    }

    if (paths.length > 0) {
      const pathChecks = paths.map((p) => `$p.starts_with("${escapeDatalog(p)}")`).join(" || ");
      parts.push(`path($p), ${pathChecks}`);
    }

    if (parts.length > 0) {
      alternatives.push(parts.join(", "));
    }
  }

  if (alternatives.length === 1) {
    lines.push(`check if ${alternatives[0]};`);
  } else if (alternatives.length > 1) {
    lines.push(`check if\n  ${alternatives.join("\n  or ")};`);
  }

  // Shortest TTL
  let minTtl: number | undefined;
  for (const c of constraints) {
    if (c.ttl !== undefined) {
      const seconds = parseTtlSeconds(c.ttl);
      if (!seconds.ok) return seconds;
      if (minTtl === undefined || seconds.value < minTtl) minTtl = seconds.value;
    }
  }
  if (minTtl !== undefined) {
    const expiry = new Date(Date.now() + minTtl * 1000);
    lines.push(`check if time($t), $t <= ${expiry.toISOString()};`);
  }

  return ok(lines.join("\n"));
}

// ─── Authorizer Code ─────────────────────────────────────────────────────────

/**
 * Build the authorizer code with ambient facts from the HTTP request.
 */
function buildAuthorizerCode(
  service: string,
  method: string,
  path: string,
  context: {
    action?: string;
    host?: string;
    requestedRoot?: string;
  } = {},
): string {
  const lines = [
    `resource("${escapeDatalog(service)}");`,
    `operation("${escapeDatalog(method.toUpperCase())}");`,
    `path("${escapeDatalog(path)}");`,
    `time(${new Date().toISOString()});`,
  ];
  if (context.action) {
    lines.push(`action("${escapeDatalog(context.action)}");`);
  }
  if (context.host) {
    lines.push(`host("${escapeDatalog(context.host)}");`);
  }
  if (context.requestedRoot) {
    lines.push(`requested_root("${escapeDatalog(context.requestedRoot)}");`);
  }
  lines.push("allow if user_id($u);", "allow if org_id($o);", "deny if true;");
  return lines.join("\n");
}

// ─── Public API ──────────────────────────────────────────────────────────────

/** Strip the ed25519/ prefix from a public key hex string */
function stripKeyPrefix(key: string): string {
  return key.replace(/^ed25519\//, "");
}

function parsePublicKey(publicKeyHex: string) {
  return PublicKey.fromString(stripKeyPrefix(publicKeyHex), SignatureAlgorithm.Ed25519);
}

function parseToken(tokenBase64: string, publicKeyHex: string) {
  return Biscuit.fromBase64(stripPrefix(tokenBase64), parsePublicKey(publicKeyHex));
}

export function getPublicKey(privateKeyHex: string) {
  const pk = PrivateKey.fromString(privateKeyHex);
  return KeyPair.fromPrivateKey(pk).getPublicKey();
}

export function getPublicKeyHex(privateKeyHex: string): string {
  return getPublicKey(privateKeyHex).toString();
}

/**
 * Mint a token with identity, optional rights, and optional extra facts.
 *
 * Authority block contains:
 * - user_id("userId") — identity
 * - right("root", "operation") — descendant rights (optional)
 * - arbitrary extra facts (optional)
 */
export function mintToken(
  privateKeyHex: string,
  subject: string,
  rights?: RuleGrant[],
  extraFacts?: string[],
): string {
  const lines: string[] = [];
  lines.push(`user_id("${escapeDatalog(subject)}");`);
  for (const right of rights ?? []) {
    lines.push(`right("${escapeDatalog(right.root)}", "${escapeDatalog(right.action)}");`);
  }
  for (const fact of (extraFacts ?? []).map(normalizeFactStatement)) {
    if (fact) lines.push(fact);
  }

  const code = lines.join("\n");
  const privateKey = PrivateKey.fromString(privateKeyHex);
  const builder = Biscuit.builder();
  builder.addCode(code);
  const token = builder.build(privateKey);
  return addPrefix(token.toBase64());
}

export function restrictToken(
  tokenBase64: string,
  publicKeyHex: string,
  constraints: RuleConstraint[],
) {
  const code = buildAttenuationCode(constraints);
  if (!code.ok) return code;
  if (!code.value) return ok(tokenBase64);

  const token = parseToken(tokenBase64, publicKeyHex);
  const blk = Biscuit.block_builder();
  blk.addCode(code.value);
  const attenuated = token.appendBlock(blk);
  return ok(addPrefix(attenuated.toBase64()));
}

export function extractAuthorityExtraFacts(tokenBase64: string, publicKeyHex: string): string[] {
  const token = parseToken(tokenBase64, publicKeyHex);
  const source = token.getBlockSource(0);
  const extras: string[] = [];

  for (const line of source.split("\n")) {
    const normalized = normalizeFactStatement(line);
    if (!normalized) continue;
    if (/(?:^|[\s,])user_id\("([^"]+)"\)/.test(normalized)) continue;
    if (/(?:^|[\s,])right\("([^"]+)",\s*"([^"]+)"\)/.test(normalized)) continue;
    extras.push(normalized);
  }

  return extras;
}

export function extractAttenuationBlockSources(
  tokenBase64: string,
  publicKeyHex: string,
): string[] {
  const token = parseToken(tokenBase64, publicKeyHex);
  return Array.from({ length: token.countBlocks() - 1 }, (_, index) =>
    token.getBlockSource(index + 1).trim(),
  ).filter((source) => source.length > 0);
}

export function appendTokenBlocks(
  tokenBase64: string,
  publicKeyHex: string,
  blockSources: string[],
): string {
  if (blockSources.length === 0) return tokenBase64;

  let token = parseToken(tokenBase64, publicKeyHex);
  for (const source of blockSources) {
    const trimmed = source.trim();
    if (!trimmed) continue;
    const blk = Biscuit.block_builder();
    blk.addCode(trimmed);
    token = token.appendBlock(blk);
  }

  return addPrefix(token.toBase64());
}

export function mintDescendantToken(
  privateKeyHex: string,
  publicKeyHex: string,
  parentTokenBase64: string,
  rights: RuleGrant[],
  constraints: RuleConstraint[],
) {
  const parentFacts = extractTokenFacts(parentTokenBase64, publicKeyHex);
  const userId = parentFacts.userId ?? parentFacts.orgId;
  if (!userId) {
    return err(inputError("Parent token has no identity"));
  }

  const extraFacts = extractAuthorityExtraFacts(parentTokenBase64, publicKeyHex);
  const parentBlocks = extractAttenuationBlockSources(parentTokenBase64, publicKeyHex);

  const fresh = mintToken(privateKeyHex, userId, rights, extraFacts);
  const rebased = appendTokenBlocks(fresh, publicKeyHex, parentBlocks);
  return restrictToken(rebased, publicKeyHex, constraints);
}

export interface AuthorizationResult {
  authorized: boolean;
  error?: string;
}

export interface AuthorizationContext {
  action?: string;
  host?: string;
  requestedRoot?: string;
}

export function authorizeRequest(
  tokenBase64: string,
  publicKeyHex: string,
  service: string,
  method: string,
  path: string,
  context: AuthorizationContext = {},
): AuthorizationResult {
  const code = buildAuthorizerCode(service, method, path, context);

  // Retry loop: the first authorizeWithLimits call on a cold worker may timeout
  // because WASM JIT compilation is counted against the time limit. The retry
  // succeeds immediately because the compiled code is cached.
  function attemptAuthorize(retriesLeft: number): AuthorizationResult {
    try {
      const token = parseToken(tokenBase64, publicKeyHex);
      const ab = new AuthorizerBuilder();
      ab.addCode(code);
      const auth = ab.buildAuthenticated(token);
      auth.authorizeWithLimits(RUN_LIMITS);
      return { authorized: true };
    } catch (e) {
      const msg = e instanceof Error ? e.message : typeof e === "string" ? e : JSON.stringify(e);
      // Only retry on timeout (WASM JIT warmup), not on logic failures
      if (!msg.includes("Timeout") || retriesLeft <= 1) {
        return { authorized: false, error: msg };
      }
      return attemptAuthorize(retriesLeft - 1);
    }
  }

  return attemptAuthorize(MAX_AUTHORIZE_RETRIES);
}

/**
 * Extract token facts from the authority block.
 * Returns identity, descendant rights, org, and scopes when present.
 */
export function extractTokenFacts(tokenBase64: string, publicKeyHex: string): BiscuitTokenFacts {
  try {
    const token = parseToken(tokenBase64, publicKeyHex);
    const source = token.getBlockSource(0);

    const rights: RuleGrant[] = [];
    let userId: string | null = null;
    let orgId: string | null = null;
    let homePath: string | null = null;
    const scopes: string[] = [];

    for (const line of source.split("\n")) {
      const trimmed = line.trim().replace(/;$/, "");
      const rightMatch = trimmed.match(/(?:^|[\s,])right\("([^"]+)",\s*"([^"]+)"\)/);
      if (rightMatch) {
        rights.push({
          root: rightMatch[1],
          action: rightMatch[2],
        });
      }
      const userMatch = trimmed.match(/(?:^|[\s,])user_id\("([^"]+)"\)/);
      if (userMatch) userId = userMatch[1];
      const orgMatch = trimmed.match(/(?:^|[\s,])org_id\("([^"]+)"\)/);
      if (orgMatch) orgId = orgMatch[1];
      const homeMatch = trimmed.match(/(?:^|[\s,])home_path\("([^"]+)"\)/);
      if (homeMatch) homePath = homeMatch[1];
      const scopeMatch = trimmed.match(/(?:^|[\s,])scope\("([^"]+)"\)/);
      if (scopeMatch) scopes.push(scopeMatch[1]);
    }

    return {
      rights: rights.filter(
        (right, index, all) =>
          all.findIndex(
            (candidate) => candidate.action === right.action && candidate.root === right.root,
          ) === index,
      ),
      userId,
      orgId,
      homePath,
      scopes: [...new Set(scopes)],
    };
  } catch {
    return { rights: [], userId: null, orgId: null, homePath: null, scopes: [] };
  }
}

/**
 * Extract the userId from the token's user_id fact.
 */
export function extractUserId(tokenBase64: string, publicKeyHex: string): string | null {
  const facts = extractTokenFacts(tokenBase64, publicKeyHex);
  return facts.userId ?? facts.orgId;
}

export function getRevocationIds(tokenBase64: string, publicKeyHex: string): string[] {
  const token = parseToken(tokenBase64, publicKeyHex);
  return token.getRevocationIdentifiers().map(String);
}

export function extractTokenExpiry(tokenBase64: string, publicKeyHex: string): Date | null {
  try {
    const token = parseToken(tokenBase64, publicKeyHex);
    const candidates: Date[] = [];

    for (let index = 0; index < token.countBlocks(); index += 1) {
      const source = token.getBlockSource(index);
      for (const line of source.split("\n")) {
        const match = line.match(/\$t\s*<=\s*([0-9]{4}-[0-9]{2}-[0-9]{2}T[^;\s]+)/);
        if (!match) continue;
        const date = new Date(match[1]);
        if (!Number.isNaN(date.getTime())) {
          candidates.push(date);
        }
      }
    }

    if (candidates.length === 0) return null;
    return new Date(Math.min(...candidates.map((candidate) => candidate.getTime())));
  } catch {
    return null;
  }
}

export function generateKeyPairHex(): { privateKey: string; publicKey: string } {
  const kp = new KeyPair(SignatureAlgorithm.Ed25519);
  return {
    privateKey: kp.getPrivateKey().toString(),
    publicKey: kp.getPublicKey().toString(),
  };
}

export function compileRulesToBiscuit(input: {
  privateKeyHex: string;
  subject: string;
  rights?: RuleGrant[];
  constraints?: RuleConstraint[];
  extraFacts?: string[];
}) {
  const minted = mintToken(input.privateKeyHex, input.subject, input.rights, input.extraFacts);
  if (!input.constraints || input.constraints.length === 0) {
    return ok(minted);
  }

  return restrictToken(minted, getPublicKeyHex(input.privateKeyHex), input.constraints);
}

export function subjectFactsToExtraFacts(subject: BiscuitSubject | undefined) {
  const facts: string[] = [];

  if (!subject) {
    return facts;
  }

  if (subject.orgId) {
    facts.push(`org_id("${escapeDatalog(subject.orgId)}");`);
  }
  if (subject.homePath) {
    facts.push(`home_path("${escapeDatalog(subject.homePath)}");`);
  }
  for (const scope of subject.scopes ?? []) {
    facts.push(`scope("${escapeDatalog(scope)}");`);
  }

  return facts;
}
