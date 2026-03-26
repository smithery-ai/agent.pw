import { createAgentPw } from "agent.pw";
import { describe, expect, it } from "vitest";
import {
	AgentPwAuthorizationError,
	AgentPwConflictError,
} from "../packages/server/src/errors";
import { deriveEncryptionKey } from "../packages/server/src/lib/credentials-crypto";
import type { RuleScope } from "../packages/server/src/types";
import { BISCUIT_PRIVATE_KEY, createTestDb } from "./setup";

async function createTestAgent() {
	const db = await createTestDb();
	const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY);
	return createAgentPw({
		db,
		encryptionKey,
	});
}

function rights(rightsList: RuleScope["rights"]): RuleScope {
	return {
		rights: rightsList,
	};
}

function createDiscoveryFetch() {
	const fetchImpl: typeof fetch = async (input) => {
		const url =
			typeof input === "string"
				? input
				: input instanceof URL
					? input.toString()
					: input.url;

		if (url.includes("/.well-known/oauth-protected-resource")) {
			return Response.json({
				resource: "https://docs.example.com/mcp",
				authorization_servers: ["https://accounts.example.com"],
			});
		}

		throw new Error(`Unexpected fetch ${url}`);
	};

	return fetchImpl;
}

describe("createAgentPw", () => {
	it("resolves profiles by path and stores exact-path credentials", async () => {
		const agentPw = await createTestAgent();

		await agentPw.profiles.put("/github", {
			resourcePatterns: ["https://api.github.com/*"],
			auth: {
				kind: "oauth",
				authorizationUrl: "https://github.com/login/oauth/authorize",
				tokenUrl: "https://github.com/login/oauth/access_token",
				clientId: "github-client",
			},
			displayName: "GitHub",
		});
		await agentPw.profiles.put("/acme/github", {
			resourcePatterns: ["https://api.github.com/*"],
			auth: {
				kind: "headers",
				fields: [
					{ name: "Authorization", label: "Access token", prefix: "Bearer " },
				],
			},
			displayName: "Acme GitHub",
		});

		expect(
			await agentPw.profiles.resolve({
				path: "/acme/connections/github_primary",
				resource: "https://api.github.com/repos/acme/app",
			}),
		).toEqual(
			expect.objectContaining({
				path: "/acme/github",
				displayName: "Acme GitHub",
			}),
		);
		expect(
			(await agentPw.profiles.list({ path: "/acme" })).map(
				(profile) => profile.path,
			),
		).toEqual(["/acme/github"]);

		const stored = await agentPw.credentials.put({
			path: "/acme/connections/github_primary",
			resource: "https://api.github.com",
			auth: {
				kind: "headers",
				profilePath: "/acme/github",
				label: "Acme GitHub",
			},
			secret: {
				headers: {
					Authorization: "Bearer github-token",
				},
			},
		});

		expect(stored).toEqual(
			expect.objectContaining({
				path: "/acme/connections/github_primary",
				resource: "https://api.github.com/",
				auth: {
					kind: "headers",
					profilePath: "/acme/github",
					label: "Acme GitHub",
				},
				secret: {
					headers: {
						Authorization: "Bearer github-token",
					},
				},
			}),
		);

		expect(
			await agentPw.credentials.get("/acme/connections/github_primary"),
		).toEqual(
			expect.objectContaining({
				path: "/acme/connections/github_primary",
			}),
		);
		expect(
			(await agentPw.credentials.list({ path: "/acme/connections" })).map(
				(credential) => credential.path,
			),
		).toEqual(["/acme/connections/github_primary"]);

		const ready = await agentPw.connect.prepare({
			path: "/acme/connections/github_primary",
			resource: "https://api.github.com",
		});
		expect(ready.kind).toBe("ready");
		if (ready.kind === "ready") {
			expect(ready.headers).toEqual({ Authorization: "Bearer github-token" });
		}

		await expect(
			agentPw.connect.prepare({
				path: "/acme/connections/github_primary",
				resource: "https://docs.example.com/mcp",
			}),
		).rejects.toThrow(AgentPwConflictError);
	});

	it("guides header-based connections through prepare and saveHeaders", async () => {
		const agentPw = await createTestAgent();

		await agentPw.profiles.put("/resend", {
			resourcePatterns: ["https://api.resend.com*"],
			auth: {
				kind: "headers",
				label: "Resend API key",
				fields: [
					{
						name: "Authorization",
						label: "API key",
						prefix: "Bearer ",
						secret: true,
					},
				],
			},
			displayName: "Resend",
		});

		const prepared = await agentPw.connect.prepare({
			path: "/acme/connections/resend",
			resource: "https://api.resend.com",
		});

		expect(prepared).toEqual({
			kind: "options",
			options: [
				{
					kind: "headers",
					source: "profile",
					resource: "https://api.resend.com/",
					profilePath: "/resend",
					label: "Resend",
					fields: [
						{
							name: "Authorization",
							label: "API key",
							prefix: "Bearer ",
							secret: true,
						},
					],
				},
			],
		});

		if (prepared.kind !== "options") {
			throw new Error("Expected connection options");
		}

		const saved = await agentPw.connect.saveHeaders({
			path: "/acme/connections/resend",
			option: prepared.options[0],
			values: {
				Authorization: "rs_123",
			},
		});

		expect(saved.auth).toEqual({
			kind: "headers",
			profilePath: "/resend",
			label: "Resend",
		});
		expect(saved.secret.headers).toEqual({
			Authorization: "Bearer rs_123",
		});
		expect(
			await agentPw.connect.headers({ path: "/acme/connections/resend" }),
		).toEqual({
			Authorization: "Bearer rs_123",
		});
	});

	it("returns high-level header and unconfigured start results", async () => {
		const agentPw = await createTestAgent();

		await agentPw.profiles.put("/resend", {
			resourcePatterns: ["https://api.resend.com*"],
			auth: {
				kind: "headers",
				label: "Resend API key",
				fields: [
					{
						name: "Authorization",
						label: "API key",
						prefix: "Bearer ",
						secret: true,
					},
				],
			},
			displayName: "Resend",
		});

		expect(
			await agentPw.connect.startForResource({
				path: "/acme/connections/resend",
				resource: "https://api.resend.com",
				redirectUri: "https://app.example.com/oauth/callback",
			}),
		).toEqual({
			kind: "headers",
			option: {
				kind: "headers",
				source: "profile",
				resource: "https://api.resend.com/",
				profilePath: "/resend",
				label: "Resend",
				fields: [
					{
						name: "Authorization",
						label: "API key",
						prefix: "Bearer ",
						secret: true,
					},
				],
			},
			resolution: {
				canonicalResource: "https://api.resend.com/",
				source: "profile",
				reason: "matched-profile",
				profilePath: "/resend",
				option: {
					kind: "headers",
					source: "profile",
					resource: "https://api.resend.com/",
					profilePath: "/resend",
					label: "Resend",
					fields: [
						{
							name: "Authorization",
							label: "API key",
							prefix: "Bearer ",
							secret: true,
						},
					],
				},
			},
		});

		expect(
			await agentPw.connect.startForResource({
				path: "/acme/connections/unconfigured",
				resource: "https://unknown.example.com",
				redirectUri: "https://app.example.com/oauth/callback",
			}),
		).toEqual({
			kind: "unconfigured",
			resolution: {
				canonicalResource: "https://unknown.example.com/",
				source: null,
				reason: "unconfigured",
				profilePath: null,
				option: null,
			},
		});

		await agentPw.connect.saveHeaders({
			path: "/acme/connections/resend",
			option: {
				kind: "headers",
				source: "profile",
				resource: "https://api.resend.com/",
				profilePath: "/resend",
				label: "Resend",
				fields: [
					{
						name: "Authorization",
						label: "API key",
						prefix: "Bearer ",
						secret: true,
					},
				],
			},
			values: {
				Authorization: "rs_ready",
			},
		});

		await expect(
			agentPw.connect.startForResource({
				path: "/acme/connections/resend",
				resource: "https://api.resend.com",
				redirectUri: "https://app.example.com/oauth/callback",
			}),
		).resolves.toEqual(
			expect.objectContaining({
				kind: "ready",
				headers: { Authorization: "Bearer rs_ready" },
				credential: expect.objectContaining({
					path: "/acme/connections/resend",
					auth: {
						kind: "headers",
						profilePath: "/resend",
						label: "Resend",
					},
				}),
				resolution: {
					canonicalResource: "https://api.resend.com/",
					source: null,
					reason: "existing-credential",
					profilePath: "/resend",
					option: null,
				},
			}),
		);
	});

	it("guides existing oauth connections, discovery-first oauth, and profile oauth without scopes", async () => {
		const db = await createTestDb();
		const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY);
		const agentPw = await createAgentPw({
			db,
			encryptionKey,
			oauthFetch: createDiscoveryFetch(),
		});

		await agentPw.credentials.put({
			path: "/acme/connections/docs",
			resource: "https://docs.example.com/mcp",
			auth: {
				kind: "oauth",
				label: "Docs",
			},
			secret: {
				headers: {
					Authorization: "Bearer docs-token",
				},
				oauth: {
					accessToken: "docs-token",
				},
			},
		});

		const ready = await agentPw.connect.prepare({
			path: "/acme/connections/docs",
			resource: "https://docs.example.com/mcp",
		});
		expect(ready.kind).toBe("ready");
		if (ready.kind === "ready") {
			expect(ready.headers).toEqual({ Authorization: "Bearer docs-token" });
		}

		const discovered = await agentPw.connect.prepare({
			path: "/acme/connections/docs_fresh",
			resource: "https://docs.example.com/mcp",
		});
		expect(discovered).toEqual({
			kind: "options",
			options: [
				{
					kind: "oauth",
					source: "discovery",
					resource: "https://docs.example.com/mcp",
					authorizationServer: "https://accounts.example.com",
					label: "OAuth via accounts.example.com",
					scopes: [],
				},
			],
		});

		await agentPw.profiles.put("/no-scopes", {
			resourcePatterns: ["https://oauth-noscopes.example.com/*"],
			auth: {
				kind: "oauth",
				authorizationUrl: "https://oauth-noscopes.example.com/authorize",
				tokenUrl: "https://oauth-noscopes.example.com/token",
				clientId: "oauth-noscope-client",
			},
		});

		const profiled = await agentPw.connect.prepare({
			path: "/acme/connections/no_scopes",
			resource: "https://oauth-noscopes.example.com/api",
		});
		expect(profiled).toEqual({
			kind: "options",
			options: [
				{
					kind: "oauth",
					source: "profile",
					resource: "https://oauth-noscopes.example.com/api",
					profilePath: "/no-scopes",
					label: "no-scopes",
					scopes: undefined,
				},
			],
		});
	});

	it("supports scoped APIs over connect, credentials, and profiles", async () => {
		const agentPw = await createTestAgent();

		await agentPw.profiles.put("/profiles/resend", {
			resourcePatterns: ["https://api.resend.com*"],
			auth: {
				kind: "headers",
				fields: [
					{ name: "Authorization", label: "API key", prefix: "Bearer " },
				],
			},
		});
		await agentPw.credentials.put({
			path: "/acme/connections/resend",
			resource: "https://api.resend.com",
			auth: { kind: "headers", profilePath: "/profiles/resend" },
			secret: { headers: { Authorization: "Bearer resend-token" } },
		});
		await agentPw.credentials.put({
			path: "/beta/connections/docs",
			resource: "https://docs.example.com/mcp",
			auth: { kind: "headers" },
			secret: { headers: { Authorization: "Bearer docs-token" } },
		});

		const api = agentPw.scope(
			rights([
				{ action: "credential.use", root: "/acme" },
				{ action: "credential.read", root: "/acme" },
				{ action: "credential.manage", root: "/acme" },
				{ action: "credential.connect", root: "/acme" },
				{ action: "profile.read", root: "/profiles" },
				{ action: "profile.manage", root: "/profiles" },
			]),
		);

		const allowed = {
			headers: await api.connect.headers({ path: "/acme/connections/resend" }),
			credentials: await api.credentials.list({ path: "/acme/connections" }),
			profiles: await api.profiles.list({ path: "/profiles" }),
		};

		expect(allowed.headers).toEqual({ Authorization: "Bearer resend-token" });
		expect(allowed.credentials.map((credential) => credential.path)).toEqual([
			"/acme/connections/resend",
		]);
		expect(allowed.profiles.map((profile) => profile.path)).toEqual([
			"/profiles/resend",
		]);

		const socket = agentPw.scope(
			rights([{ action: "credential.use", root: "/acme" }]),
		);
		await expect(
			socket.connect.headers({ path: "/acme/connections/resend" }),
		).resolves.toEqual({
			Authorization: "Bearer resend-token",
		});

		await expect(
			agentPw
				.scope(rights([{ action: "credential.connect", root: "/acme" }]))
				.connect.prepare({
					path: "/acme/connections/resend",
					resource: "https://api.resend.com",
				}),
		).rejects.toThrow(AgentPwAuthorizationError);
	});
});
