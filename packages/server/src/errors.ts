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
  stage: string,
  message: string,
  data?: { cause: unknown } | { cause: unknown; path: string },
) {
  return { type: "OAuth" as const, stage, message, ...data };
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
