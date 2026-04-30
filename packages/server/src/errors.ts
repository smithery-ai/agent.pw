import {
  AuthorizationResponseError,
  OperationProcessingError,
  ResponseBodyError,
  WWWAuthenticateChallengeError,
} from "oauth4webapi";

/**
 * Extract a useful message from an unknown error value.
 * For oauth4webapi errors, surfaces the structured cause (expected/actual).
 */
export function errorMessage(error: unknown): string {
  /* v8 ignore start - defensive branches for non-standard error shapes */
  if (!(error instanceof Error)) {
    if (typeof error === "object" && error !== null && "message" in error) {
      const withMessage: { message: unknown } = error;
      return String(withMessage.message);
    }
    return String(error);
  }
  // oauth4webapi errors include { expected, body, attribute } in cause
  const cause: unknown = "cause" in error ? error.cause : undefined;
  if (typeof cause === "object" && cause !== null) {
    const attribute = "attribute" in cause ? cause.attribute : undefined;
    const expected = "expected" in cause ? cause.expected : undefined;
    const body = "body" in cause ? cause.body : undefined;
    if (
      typeof attribute === "string" &&
      typeof expected === "string" &&
      typeof body === "object" &&
      body !== null &&
      attribute in body
    ) {
      const actual = String(Object.getOwnPropertyDescriptor(body, attribute)?.value ?? "undefined");
      return `"${attribute}" is "${actual}" but expected "${expected}"`;
    }
  }
  /* v8 ignore stop */
  return error.message;
}

/**
 * Extract structured details from oauth4webapi typed errors.
 * Merges with any constructor-provided details.
 */
function causeDetails(error: unknown): Record<string, unknown> | undefined {
  /* v8 ignore next 7 -- mocked fetch produces plain Errors, not oauth4webapi typed errors */
  if (error instanceof ResponseBodyError) {
    return {
      oauthError: error.error,
      oauthDescription: error.error_description,
      httpStatus: error.status,
    };
  }
  /* v8 ignore next 6 -- only thrown on real authorization redirect responses */
  if (error instanceof AuthorizationResponseError) {
    return {
      oauthError: error.error,
      oauthDescription: error.error_description,
    };
  }
  /* v8 ignore next 6 -- only thrown on real 401/403 with WWW-Authenticate */
  if (error instanceof WWWAuthenticateChallengeError) {
    return {
      httpStatus: error.status,
      challenges: error.cause.length,
    };
  }
  if (error instanceof OperationProcessingError) {
    /* v8 ignore next -- code is always set in practice */
    return error.code ? { processingCode: error.code } : undefined;
  }
  return undefined;
}

function withCauseDetails(
  error: unknown,
  own?: Record<string, unknown>,
): Record<string, unknown> | undefined {
  const extracted = causeDetails(error);
  if (!extracted && !own) return undefined;
  if (!extracted) return own;
  if (!own) return extracted;
  return { ...own, ...extracted };
}

// OAuth error catalog — named constructors for each failure mode

const RFC_8414 = "https://datatracker.ietf.org/doc/html/rfc8414";
const RFC_9728 = "https://datatracker.ietf.org/doc/html/rfc9728";
const RFC_9728_S3_3 = "https://datatracker.ietf.org/doc/html/rfc9728#section-3.3";
const RFC_7591 = "https://datatracker.ietf.org/doc/html/rfc7591";
const ID_JAG_DRAFT =
  "https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/03/";

export const authServerDiscoveryFetchFailed = (issuer: string, url: string, cause: unknown) =>
  oauthError(
    `Authorization server discovery failed for '${issuer}' at '${url}': ${errorMessage(cause)}`,
    {
      code: "oauth/auth_server_discovery_fetch_failed",
      retryable: false,
      cause,
      details: withCauseDetails(cause, { issuer, url }),
      docUrl: RFC_8414,
    },
  );

export const authServerDiscoveryHttpError = (issuer: string, url: string, status: number) =>
  oauthError(
    `Authorization server discovery failed for '${issuer}' at '${url}' with HTTP ${status}`,
    {
      code: "oauth/auth_server_discovery_http_error",
      retryable: status >= 500,
      details: { issuer, url, status },
      docUrl: RFC_8414,
    },
  );

export const authServerDiscoveryProcessFailed = (cause: unknown) =>
  oauthError(`Failed to process discovery response: ${errorMessage(cause)}`, {
    code: "oauth/auth_server_discovery_process_failed",
    retryable: false,
    cause,
    details: withCauseDetails(cause),
    docUrl: RFC_8414,
  });

export const resourceChallengeParseFailed = (resource: string, cause: unknown) =>
  oauthError(`Failed to parse resource challenge for '${resource}': ${errorMessage(cause)}`, {
    code: "oauth/resource_challenge_parse_failed",
    retryable: false,
    cause,
    details: withCauseDetails(cause, { resource }),
    docUrl: RFC_9728,
  });

export const scopeChallengeParseFailed = (cause: unknown) =>
  oauthError(`Failed to parse scope challenge resource_metadata: ${errorMessage(cause)}`, {
    code: "oauth/scope_challenge_parse_failed",
    retryable: false,
    cause,
    details: withCauseDetails(cause),
    docUrl: RFC_9728,
  });

export const resourceFetchFailed = (resource: string, cause: unknown) =>
  oauthError(`Failed to discover resource '${resource}': ${errorMessage(cause)}`, {
    code: "oauth/resource_fetch_failed",
    retryable: false,
    cause,
    details: withCauseDetails(cause, { resource }),
    docUrl: RFC_9728,
  });

export const resourceMetadataFetchFailed = (url: string, cause: unknown) =>
  oauthError(`Failed to fetch resource metadata at ${url}: ${errorMessage(cause)}`, {
    code: "oauth/resource_metadata_fetch_failed",
    retryable: false,
    cause,
    details: withCauseDetails(cause, { url }),
    docUrl: RFC_9728,
  });

export const resourceMetadataProcessFailed = (resource: string, cause: unknown) =>
  oauthError(`Failed to process resource metadata for '${resource}': ${errorMessage(cause)}`, {
    code: "oauth/resource_metadata_process_failed",
    retryable: false,
    cause,
    details: withCauseDetails(cause, { resource }),
    docUrl: RFC_9728_S3_3,
  });

export const dcrRequestFailed = (cause: unknown) =>
  oauthError(`Dynamic client registration failed: ${errorMessage(cause)}`, {
    code: "oauth/dcr_request_failed",
    retryable: false,
    cause,
    details: withCauseDetails(cause),
    docUrl: RFC_7591,
  });

export const dcrResponseProcessFailed = (cause: unknown) =>
  oauthError(`Failed to process dynamic client registration response: ${errorMessage(cause)}`, {
    code: "oauth/dcr_response_process_failed",
    retryable: false,
    cause,
    details: withCauseDetails(cause),
    docUrl: RFC_7591,
  });

export const refreshTokenRequestFailed = (path: string, cause: unknown) =>
  oauthError(`Failed to refresh credential for '${path}': ${errorMessage(cause)}`, {
    code: "oauth/refresh_token_request_failed",
    retryable: true,
    cause,
    path,
    details: withCauseDetails(cause),
  });

export const refreshTokenResponseFailed = (path: string, cause: unknown) =>
  oauthError(`Failed to process refresh response for '${path}': ${errorMessage(cause)}`, {
    code: "oauth/refresh_token_response_failed",
    retryable: false,
    cause,
    path,
    details: withCauseDetails(cause),
  });

export const authCallbackValidationFailed = (path: string, cause: unknown) =>
  oauthError(`Failed to validate OAuth callback: ${errorMessage(cause)}`, {
    code: "oauth/auth_callback_validation_failed",
    retryable: false,
    cause,
    path,
    details: withCauseDetails(cause),
  });

export const authCodeExchangeFailed = (path: string, cause: unknown) =>
  oauthError(`Failed to exchange authorization code: ${errorMessage(cause)}`, {
    code: "oauth/auth_code_exchange_failed",
    retryable: false,
    cause,
    path,
    details: withCauseDetails(cause),
  });

export const authCodeResponseFailed = (path: string, cause: unknown) =>
  oauthError(`Failed to process authorization code response: ${errorMessage(cause)}`, {
    code: "oauth/auth_code_response_failed",
    retryable: false,
    cause,
    path,
    details: withCauseDetails(cause),
  });

export const revokeTokenFailed = (tokenType: "refresh" | "access", path: string, cause: unknown) =>
  oauthError(`Failed to revoke ${tokenType} token: ${errorMessage(cause)}`, {
    code: `oauth/revoke_${tokenType}_token_failed`,
    retryable: true,
    cause,
    path,
    details: withCauseDetails(cause, { tokenType }),
  });

export const revokeTokenProcessFailed = (
  tokenType: "refresh" | "access",
  path: string,
  cause: unknown,
) =>
  oauthError(`Failed to process ${tokenType} token revocation: ${errorMessage(cause)}`, {
    code: `oauth/revoke_${tokenType}_token_process_failed`,
    retryable: false,
    cause,
    path,
    details: withCauseDetails(cause, { tokenType }),
  });

export const identityGrantMetadataNotFound = (resource: string, cause: unknown) =>
  oauthError(`Identity grant metadata discovery failed for '${resource}': ${errorMessage(cause)}`, {
    code: "oauth/identity_metadata_not_found",
    retryable: false,
    cause,
    details: withCauseDetails(cause, { resource }),
    docUrl: ID_JAG_DRAFT,
  });

export const identityGrantSigningFailed = (cause: unknown) =>
  oauthError(`Identity grant signing failed: ${errorMessage(cause)}`, {
    code: "oauth/identity_signing_failed",
    retryable: false,
    cause,
    details: withCauseDetails(cause),
    docUrl: ID_JAG_DRAFT,
  });

export const identityGrantTokenRequestFailed = (issuer: string, cause: unknown) =>
  oauthError(
    `Identity grant token request failed for authorization server '${issuer}': ${errorMessage(cause)}`,
    {
      code: "oauth/identity_token_request_failed",
      retryable: true,
      cause,
      details: withCauseDetails(cause, { issuer }),
      docUrl: ID_JAG_DRAFT,
    },
  );

export const identityGrantTokenResponseFailed = (issuer: string, cause: unknown) =>
  oauthError(
    `Identity grant token response failed for authorization server '${issuer}': ${errorMessage(cause)}`,
    {
      code: "oauth/identity_token_response_failed",
      retryable: false,
      cause,
      details: withCauseDetails(cause, { issuer }),
      docUrl: ID_JAG_DRAFT,
    },
  );

/** Create a typed validation error for caller-provided input. */
export function inputError(
  message: string,
  data?:
    | { field: string; value: string }
    | { field: string }
    | { value: string }
    | { path: string },
) {
  return { type: "Input" as const, message, ...data };
}

/** Create a typed conflict error for duplicate or ambiguous resources. */
export function conflictError(message: string, data?: { path: string }) {
  return { type: "Conflict" as const, message, ...data };
}

/** Create a typed authorization error for a missing action at a path. */
export function authorizationError(
  action: string,
  path: string,
  message = `Missing '${action}' for '${path}'`,
) {
  return { type: "Authorization" as const, action, path, message };
}

/** Create a typed not-found error for a named resource kind. */
export function notFoundError(resource: string, message: string, data?: { path: string }) {
  return { type: "NotFound" as const, resource, message, ...data };
}

/** Create a typed error for expired credentials, tokens, or flows. */
export function expiredError(resource: string, message: string) {
  return { type: "Expired" as const, resource, message };
}

/** Create a typed persistence error for database read/write failures. */
export function persistenceError(operation: string, message: string, data: { path: string }) {
  return { type: "Persistence" as const, operation, message, ...data };
}

/** Create a typed OAuth lifecycle error for discovery, token, or revocation failures. */
export function oauthError(
  message: string,
  data: {
    code: string;
    retryable: boolean;
    cause?: unknown;
    path?: string;
    details?: Record<string, unknown>;
    docUrl?: string;
  },
) {
  return { type: "OAuth" as const, message, ...data };
}

/** Create a typed crypto error for encryption or decryption failures. */
export function cryptoError(operation: string, message: string, data?: { cause: unknown }) {
  return { type: "Crypto" as const, operation, message, ...data };
}

/** Create a typed internal error for unexpected library failures. */
export function internalError(
  message: string,
  data?:
    | { source: string }
    | { cause: unknown; source: string }
    | { path: string; source: string }
    | { cause: unknown; path: string; source: string },
) {
  return { type: "Internal" as const, message, ...data };
}

export type InputError = ReturnType<typeof inputError>;
export type ConflictError = ReturnType<typeof conflictError>;
export type AuthorizationError = ReturnType<typeof authorizationError>;
export type NotFoundError = ReturnType<typeof notFoundError>;
export type ExpiredError = ReturnType<typeof expiredError>;
export type PersistenceError = ReturnType<typeof persistenceError>;
export type OAuthError = ReturnType<typeof oauthError>;
export type CryptoError = ReturnType<typeof cryptoError>;
export type InternalError = ReturnType<typeof internalError>;

export type AgentPwError =
  | InputError
  | ConflictError
  | AuthorizationError
  | NotFoundError
  | ExpiredError
  | PersistenceError
  | OAuthError
  | CryptoError
  | InternalError;

/** Narrow an unknown value to any typed agent.pw error. */
export function isAgentPwError(error: unknown): error is AgentPwError {
  return (
    typeof error === "object" &&
    error !== null &&
    "type" in error &&
    "message" in error &&
    typeof error.type === "string" &&
    typeof error.message === "string"
  );
}

/** Narrow an unknown value to `InputError`. */
export function isInputError(error: unknown): error is InputError {
  return isAgentPwError(error) && error.type === "Input";
}

/** Narrow an unknown value to `ConflictError`. */
export function isConflictError(error: unknown): error is ConflictError {
  return isAgentPwError(error) && error.type === "Conflict";
}

/** Narrow an unknown value to `AuthorizationError`. */
export function isAuthorizationError(error: unknown): error is AuthorizationError {
  return isAgentPwError(error) && error.type === "Authorization";
}

/** Narrow an unknown value to `NotFoundError`, optionally for a specific resource kind. */
export function isNotFoundError(error: unknown, resource?: string): error is NotFoundError {
  return (
    isAgentPwError(error) &&
    error.type === "NotFound" &&
    (resource === undefined || error.resource === resource)
  );
}

/** Narrow an unknown value to `ExpiredError`. */
export function isExpiredError(error: unknown): error is ExpiredError {
  return isAgentPwError(error) && error.type === "Expired";
}

/** Narrow an unknown value to `PersistenceError`. */
export function isPersistenceError(error: unknown): error is PersistenceError {
  return isAgentPwError(error) && error.type === "Persistence";
}

/** Narrow an unknown value to `OAuthError`. */
export function isOAuthError(error: unknown): error is OAuthError {
  return isAgentPwError(error) && error.type === "OAuth";
}

/** Narrow an unknown value to `CryptoError`. */
export function isCryptoError(error: unknown): error is CryptoError {
  return isAgentPwError(error) && error.type === "Crypto";
}

/** Narrow an unknown value to `InternalError`. */
export function isInternalError(error: unknown): error is InternalError {
  return isAgentPwError(error) && error.type === "Internal";
}
