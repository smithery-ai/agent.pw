import { createAgentPw } from "agent.pw";
import { createInMemoryFlowStore } from "agent.pw/oauth";
import { sql } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import {
	deriveEncryptionKey,
	encryptCredentials,
} from "../packages/server/src/lib/credentials-crypto";
import { createTestDb } from "./setup";

function createProfileFetch() {
	const fetchImpl: typeof fetch = async (input, init) => {
		const url =
			typeof input === "string"
				? input
				: input instanceof URL
					? input.toString()
					: input.url;
		const body =
			init?.body instanceof URLSearchParams
				? init.body
				: new URLSearchParams(
						typeof init?.body === "string" ? init.body : undefined,
					);

		if (url === "https://accounts.example.com/token") {
			if (body.get("grant_type") === "authorization_code") {
				return Response.json({
					access_token: "linear-access-1",
					refresh_token: "linear-refresh-1",
					expires_in: 3600,
					scope: "read write",
					token_type: "Bearer",
				});
			}

			return Response.json({
				access_token: "linear-access-2",
				refresh_token: "linear-refresh-2",
				expires_in: 3600,
				token_type: "Bearer",
			});
		}

		if (url === "https://accounts.example.com/revoke") {
			return new Response(null, { status: 200 });
		}

		throw new Error(`Unexpected fetch ${url}`);
	};

	return fetchImpl;
}

describe("index coverage helpers", () => {
	it("rejects malformed auth payloads and invalid json writes", async () => {
		const db = await createTestDb();
		const encryptionKey = await deriveEncryptionKey(
			"ed25519-private/20cbf8e88a4d258a2af3b2ab1132ae6f753e46893eaea2427f732feefba7a8ad",
		);
		const agentPw = await createAgentPw({
			db,
			encryptionKey,
		});

		await agentPw.profiles.put("/valid", {
			resourcePatterns: ["https://valid.example.com/*"],
			auth: {
				kind: "headers",
				fields: [{ name: "Authorization", label: "Token" }],
			},
		});
		await agentPw.profiles.put("/minimal-oauth", {
			resourcePatterns: ["https://oauth.example.com/*"],
			auth: {
				kind: "oauth",
				clientId: "oauth-client",
			},
		});
		expect(await agentPw.profiles.get("/minimal-oauth")).toEqual(
			expect.objectContaining({
				auth: {
					kind: "oauth",
					label: undefined,
					issuer: undefined,
					authorizationUrl: undefined,
					tokenUrl: undefined,
					revocationUrl: undefined,
					clientId: "oauth-client",
					clientSecret: undefined,
					clientAuthentication: undefined,
					scopes: undefined,
				},
			}),
		);
		await agentPw.profiles.put("/oauth-labeled", {
			resourcePatterns: ["https://oauth2.example.com/*"],
			auth: {
				kind: "oauth",
				label: "OAuth label",
				issuer: "https://oauth2.example.com",
				authorizationUrl: "https://oauth2.example.com/authorize",
				tokenUrl: "https://oauth2.example.com/token",
			},
		});
		expect(await agentPw.profiles.get("/oauth-labeled")).toEqual(
			expect.objectContaining({
				auth: expect.objectContaining({
					label: "OAuth label",
					issuer: "https://oauth2.example.com",
					authorizationUrl: "https://oauth2.example.com/authorize",
					tokenUrl: "https://oauth2.example.com/token",
				}),
			}),
		);
		expect(await agentPw.profiles.delete("/valid")).toBe(true);

		await expect(
			Reflect.apply(agentPw.profiles.put, agentPw.profiles, [
				"/invalid-json",
				{
					resourcePatterns: ["https://invalid.example.com/*"],
					auth: "bad",
				},
			]),
		).rejects.toThrow("Expected JSON object");

		await expect(
			Reflect.apply(agentPw.credentials.put, agentPw.credentials, [
				{
					path: "/invalid/credential",
					resource: "https://invalid.example.com",
					auth: "bad",
					secret: { headers: {} },
				},
			]),
		).rejects.toThrow("Expected JSON object");

		await agentPw.profiles.put("/broken-profile", {
			resourcePatterns: ["https://broken.example.com/*"],
			auth: {
				kind: "headers",
				fields: [{ name: "Authorization", label: "Token" }],
			},
		});
		expect(Array.isArray(await agentPw.profiles.list())).toBe(true);
		await db.execute(
			sql.raw(`
      UPDATE agentpw.cred_profiles
      SET auth = '"broken"'::jsonb
      WHERE path = '/broken-profile'
    `),
		);
		await expect(agentPw.profiles.get("/broken-profile")).rejects.toThrow(
			"Invalid profile auth payload",
		);

		await agentPw.profiles.put("/broken-kind", {
			resourcePatterns: ["https://kind.example.com/*"],
			auth: {
				kind: "headers",
				fields: [{ name: "Authorization", label: "Token" }],
			},
		});
		await db.execute(
			sql.raw(`
      UPDATE agentpw.cred_profiles
      SET auth = '{"kind":"weird"}'::jsonb
      WHERE path = '/broken-kind'
    `),
		);
		await expect(agentPw.profiles.get("/broken-kind")).rejects.toThrow(
			"Invalid profile auth kind",
		);

		await agentPw.profiles.put("/field-fallback", {
			resourcePatterns: ["https://fields.example.com/*"],
			auth: {
				kind: "headers",
				fields: [{ name: "Authorization", label: "Token" }],
			},
		});
		await db.execute(
			sql.raw(`
      UPDATE agentpw.cred_profiles
      SET auth = '{"kind":"headers","fields":[{"name":1,"label":"Bad"},{"name":"X-Invalid","label":1},{"name":"Authorization","label":"Token","description":1,"prefix":1,"secret":"no"}]}'::jsonb
      WHERE path = '/field-fallback'
    `),
		);
		expect(await agentPw.profiles.get("/field-fallback")).toEqual(
			expect.objectContaining({
				auth: {
					kind: "headers",
					label: undefined,
					fields: [
						{
							name: "Authorization",
							label: "Token",
							description: undefined,
							prefix: undefined,
							secret: undefined,
						},
					],
				},
			}),
		);
		await agentPw.profiles.put("/headers-rich", {
			resourcePatterns: ["https://headers-rich.example.com/*"],
			auth: {
				kind: "headers",
				label: "Headers",
				fields: [
					{
						name: "Authorization",
						label: "Token",
						description: "Describe",
						prefix: "Bearer ",
						secret: true,
					},
				],
			},
		});
		expect(await agentPw.profiles.get("/headers-rich")).toEqual(
			expect.objectContaining({
				auth: expect.objectContaining({
					label: "Headers",
					fields: [
						{
							name: "Authorization",
							label: "Token",
							description: "Describe",
							prefix: "Bearer ",
							secret: true,
						},
					],
				}),
			}),
		);

		await agentPw.profiles.put("/field-empty", {
			resourcePatterns: ["https://empty.example.com/*"],
			auth: {
				kind: "headers",
				fields: [{ name: "Authorization", label: "Token" }],
			},
		});
		await db.execute(
			sql.raw(`
      UPDATE agentpw.cred_profiles
      SET auth = '{"kind":"headers","fields":"nope"}'::jsonb
      WHERE path = '/field-empty'
    `),
		);
		expect(await agentPw.profiles.get("/field-empty")).toEqual(
			expect.objectContaining({
				auth: {
					kind: "headers",
					label: undefined,
					fields: [],
				},
			}),
		);

		const secret = await encryptCredentials(encryptionKey, {
			headers: { Authorization: "Bearer broken" },
		});
		await agentPw.credentials.put({
			path: "/broken/credential",
			resource: "https://broken.example.com",
			auth: { kind: "headers" },
			secret,
		});
		await db.execute(
			sql.raw(`
      UPDATE agentpw.credentials
      SET auth = '"broken"'::jsonb
      WHERE path = '/broken/credential'
    `),
		);
		await expect(agentPw.credentials.get("/broken/credential")).rejects.toThrow(
			"Invalid credential auth payload",
		);

		await agentPw.credentials.put({
			path: "/listed/credential",
			resource: "https://listed.example.com",
			auth: { kind: "headers" },
			secret: { headers: { Authorization: "Bearer listed" } },
		});
		expect(await agentPw.credentials.list({ path: "/listed" })).toEqual([
			expect.objectContaining({
				path: "/listed/credential",
				auth: {
					kind: "headers",
					profilePath: null,
					label: null,
					resource: "https://listed.example.com/",
				},
			}),
		]);
		await expect(
			agentPw.credentials.put({
				path: "/broken/headerless",
				auth: { kind: "headers" },
				secret: {},
			}),
		).rejects.toThrow(
			"Credential '/broken/headerless' does not have header-based auth",
		);
		await expect(
			agentPw.credentials.put({
				path: "/broken/envless",
				auth: { kind: "env" },
				secret: { headers: { Authorization: "Bearer wrong" } },
			}),
		).rejects.toThrow("Credential '/broken/envless' does not have env auth");
		expect(Array.isArray(await agentPw.credentials.list())).toBe(true);

		await expect(agentPw.credentials.list({ path: "/../bad" })).rejects.toThrow(
			"Invalid credential path '/../bad'",
		);
		await expect(agentPw.profiles.list({ path: "/../bad" })).rejects.toThrow(
			"Invalid profile path '/../bad'",
		);
	});

	it("covers the authorized facade across connect, credentials, and profiles", async () => {
		const db = await createTestDb();
		const encryptionKey = await deriveEncryptionKey(
			"ed25519-private/20cbf8e88a4d258a2af3b2ab1132ae6f753e46893eaea2427f732feefba7a8ad",
		);
		const agentPw = await createAgentPw({
			db,
			encryptionKey,
			flowStore: createInMemoryFlowStore(),
			oauthFetch: createProfileFetch(),
		});

		await agentPw.profiles.put("/linear", {
			resourcePatterns: ["https://api.linear.app/*"],
			auth: {
				kind: "oauth",
				authorizationUrl: "https://accounts.example.com/authorize",
				tokenUrl: "https://accounts.example.com/token",
				revocationUrl: "https://accounts.example.com/revoke",
				clientId: "linear-client",
				clientSecret: "linear-secret",
				clientAuthentication: "client_secret_post",
				scopes: "read write",
			},
			displayName: "Linear",
		});
		await agentPw.profiles.put("/headers", {
			resourcePatterns: ["https://headers.example.com*"],
			auth: {
				kind: "headers",
				fields: [{ name: "Authorization", label: "Token", prefix: "Bearer " }],
			},
			displayName: "Headers",
		});

		const api = agentPw.scope({
			rights: [
				{ action: "credential.connect", root: "/acme" },
				{ action: "credential.use", root: "/acme" },
				{ action: "credential.read", root: "/acme" },
				{ action: "credential.manage", root: "/acme" },
				{ action: "profile.read", root: "/" },
				{ action: "profile.manage", root: "/" },
			],
		});

		const result = await (async () => {
			const readProfile = await api.profiles.get("/linear");
			await api.profiles.put("/profiles/temp", {
				resourcePatterns: ["https://temp.example.com/*"],
				auth: {
					kind: "headers",
					fields: [{ name: "Authorization", label: "Token" }],
				},
			});
			const allProfiles = await api.profiles.list({ path: "/" });
			await api.profiles.delete("/profiles/temp");

			const prepared = await api.connect.prepare({
				path: "/acme/connections/linear",
				resource: "https://api.linear.app/projects",
			});
			if (prepared.kind !== "options") {
				throw new Error("Expected oauth options");
			}
			const oauthOption = prepared.options[0];
			if (!oauthOption || oauthOption.kind !== "oauth") {
				throw new Error("Expected oauth option");
			}

			await expect(
				api.connect.complete({
					callbackUri: "https://app.example.com/oauth/callback?code=missing",
				}),
			).rejects.toThrow("OAuth callback is missing state");

			await expect(
				api.connect.complete({
					callbackUri:
						"https://app.example.com/oauth/callback?code=missing&state=unknown",
				}),
			).rejects.toThrow("Unknown OAuth flow 'unknown'");
			const missingFlow = await api.connect.getFlow("missing-flow");

			const directSession = await api.connect.start({
				path: "/acme/connections/linear_direct",
				option: oauthOption,
				redirectUri: "https://app.example.com/oauth/callback",
			});
			const session = await api.connect.startFromChallenge({
				path: "/acme/connections/linear",
				option: oauthOption,
				redirectUri: "https://app.example.com/oauth/callback",
			});
			const startedFlow = await api.connect.getFlow(session.flowId);
			const completed = await api.connect.complete({
				callbackUri: `https://app.example.com/oauth/callback?code=code-123&state=${session.flowId}`,
			});
			const preparedReady = await api.connect.prepare({
				path: "/acme/connections/linear",
				resource: "https://api.linear.app/projects",
			});
			const resolvedReady = await api.connect.resolve({
				path: "/acme/connections/linear",
				resource: "https://api.linear.app/projects",
			});
			const startedReady = await api.connect.connect({
				path: "/acme/connections/linear",
				resource: "https://api.linear.app/projects",
				redirectUri: "https://app.example.com/oauth/callback",
			});
			const startedReadyFromChallenge =
				await api.connect.connectFromChallenge({
					path: "/acme/connections/linear",
					resource: "https://api.linear.app/projects",
					redirectUri: "https://app.example.com/oauth/callback",
				});

			const headers = await api.connect.headers({
				path: "/acme/connections/linear",
				refresh: false,
			});
			const readCredential = await api.credentials.get(
				"/acme/connections/linear",
			);
			const listedCredentials = await api.credentials.list({
				path: "/acme/connections",
			});
			const manualPrepared = await api.connect.prepare({
				path: "/acme/connections/headered",
				resource: "https://headers.example.com",
			});
			if (manualPrepared.kind !== "options") {
				throw new Error("Expected header options");
			}
			const headerOption = manualPrepared.options[0];
			if (!headerOption || headerOption.kind !== "headers") {
				throw new Error("Expected header option");
			}
			const savedHeaders = await api.connect.saveHeaders({
				path: "/acme/connections/headered",
				option: headerOption,
				values: { Authorization: "header-token" },
			});
			const savedWithoutProfile = await api.connect.saveHeaders({
				path: "/acme/connections/headered_polyfill",
				option: {
					...headerOption,
					profilePath: undefined,
				},
				values: { Authorization: "header-token-2" },
			});
			const manual = await api.credentials.put({
				path: "/acme/connections/manual",
				resource: "https://manual.example.com",
				auth: { kind: "headers" },
				secret: { headers: { Authorization: "Bearer manual" } },
			});
			const moved = await api.credentials.move(
				"/acme/connections/manual",
				"/acme/connections/manual_next",
			);
			const deleted = await api.credentials.delete(
				"/acme/connections/manual_next",
			);
			const disconnected = await api.connect.disconnect({
				path: "/acme/connections/linear",
				revoke: "access_token",
			});

			return {
				readProfile,
				allProfiles,
				missingFlow,
				directSession,
				startedFlow,
				completed,
				preparedReady,
				resolvedReady,
				startedReady,
				startedReadyFromChallenge,
				headers,
				readCredential,
				listedCredentials,
				savedHeaders,
				savedWithoutProfile,
				manual,
				moved,
				deleted,
				disconnected,
			};
		})();

		expect(result.readProfile?.path).toBe("/linear");
		expect(result.allProfiles.map((profile) => profile.path)).toEqual([
			"/headers",
			"/linear",
			"/profiles/temp",
		]);
		expect(result.missingFlow).toBeNull();
		expect(result.directSession.path).toBe("/acme/connections/linear_direct");
		expect(result.startedFlow).toEqual({
			flowId: expect.any(String),
			path: "/acme/connections/linear",
			resource: "https://api.linear.app/projects",
			option: {
				kind: "oauth",
				source: "profile",
				resource: "https://api.linear.app/projects",
				profilePath: "/linear",
				label: "Linear",
				scopes: ["read", "write"],
			},
			expiresAt: expect.any(Date),
			context: undefined,
			reason: "auth_required",
			requiresUpstreamAuthorization: true,
		});
		expect(result.completed.path).toBe("/acme/connections/linear");
		expect(result.completed.reason).toBe("auth_required");
		expect(result.completed.requiresUpstreamAuthorization).toBe(true);
		expect(result.preparedReady.kind).toBe("ready");
		expect(result.resolvedReady).toEqual({
			canonicalResource: "https://api.linear.app/projects",
			source: null,
			reason: "existing-credential",
			profilePath: "/linear",
			option: null,
		});
		expect(result.startedReady.kind).toBe("ready");
		expect(result.startedReadyFromChallenge.kind).toBe("ready");
		expect(result.headers).toEqual({ Authorization: "Bearer linear-access-1" });
		expect(result.readCredential?.path).toBe("/acme/connections/linear");
		expect(
			result.listedCredentials.map((credential) => credential.path),
		).toEqual(["/acme/connections/linear"]);
		expect(result.savedHeaders.secret.headers).toEqual({
			Authorization: "Bearer header-token",
		});
		expect(result.savedWithoutProfile.auth.profilePath).toBeNull();
		expect(result.manual.path).toBe("/acme/connections/manual");
		expect(result.moved).toBe(true);
		expect(result.deleted).toBe(true);
		expect(result.disconnected).toBe(true);
	});
});
