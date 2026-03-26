import type {
  AgentPwAuthorizationError,
  AgentPwConflictError,
  AgentPwCryptoError,
  AgentPwError,
  AgentPwExpiredError,
  AgentPwInputError,
  AgentPwInternalError,
  AgentPwNotFoundError,
  AgentPwOAuthError,
  AgentPwPersistenceError,
  AgentPwUnsupportedCredentialKindError,
} from "./types.js";

function errorMessage(value: unknown, fallback: string) {
  if (value instanceof Error && value.message) {
    return value.message;
  }
  if (typeof value === "string" && value.length > 0) {
    return value;
  }
  return fallback;
}

export function inputError(
  message: string,
  data: Omit<AgentPwInputError, "message" | "type"> = {},
): AgentPwInputError {
  return { type: "Input", message, ...data };
}

export function conflictError(
  message: string,
  data: Omit<AgentPwConflictError, "message" | "type"> = {},
): AgentPwConflictError {
  return { type: "Conflict", message, ...data };
}

export function authorizationError(
  action: string,
  path: string,
  message = `Missing '${action}' for '${path}'`,
  data: Omit<AgentPwAuthorizationError, "action" | "message" | "path" | "type"> = {},
): AgentPwAuthorizationError {
  return { type: "Authorization", action, path, message, ...data };
}

export function notFoundError(
  resource: string,
  message: string,
  data: Omit<AgentPwNotFoundError, "message" | "resource" | "type"> = {},
): AgentPwNotFoundError {
  return { type: "NotFound", resource, message, ...data };
}

export function expiredError(
  resource: string,
  message: string,
  data: Omit<AgentPwExpiredError, "message" | "resource" | "type"> = {},
): AgentPwExpiredError {
  return { type: "Expired", resource, message, ...data };
}

export function unsupportedCredentialKindError(
  kind: AgentPwUnsupportedCredentialKindError["kind"],
  message: string,
  data: Omit<AgentPwUnsupportedCredentialKindError, "kind" | "message" | "type"> = {},
): AgentPwUnsupportedCredentialKindError {
  return { type: "UnsupportedCredentialKind", kind, message, ...data };
}

export function persistenceError(
  operation: string,
  message: string,
  data: Omit<AgentPwPersistenceError, "message" | "operation" | "type"> = {},
): AgentPwPersistenceError {
  return { type: "Persistence", operation, message, ...data };
}

export function oauthError(
  stage: string,
  message: string,
  data: Omit<AgentPwOAuthError, "message" | "stage" | "type"> = {},
): AgentPwOAuthError {
  return { type: "OAuth", stage, message, ...data };
}

export function cryptoError(
  operation: string,
  message: string,
  data: Omit<AgentPwCryptoError, "message" | "operation" | "type"> = {},
): AgentPwCryptoError {
  return { type: "Crypto", operation, message, ...data };
}

export function internalError(
  message: string,
  data: Omit<AgentPwInternalError, "message" | "type"> = {},
): AgentPwInternalError {
  return { type: "Internal", message, ...data };
}

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

export function toAgentPwError(
  error: unknown,
  fallback: Omit<AgentPwInternalError, "type"> = { message: "Unexpected internal error" },
): AgentPwError {
  if (isAgentPwError(error)) {
    return error;
  }

  return internalError(errorMessage(error, fallback.message), {
    ...fallback,
    cause: fallback.cause ?? error,
  });
}
