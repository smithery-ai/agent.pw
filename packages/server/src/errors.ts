export function inputError(
  message: string,
  data: { cause?: unknown; path?: string; field?: string; value?: string } = {},
) {
  return { type: "Input" as const, message, ...data };
}

export function conflictError(message: string, data: { cause?: unknown; path?: string } = {}) {
  return { type: "Conflict" as const, message, ...data };
}

export function authorizationError(
  action: string,
  path: string,
  message = `Missing '${action}' for '${path}'`,
  data: { cause?: unknown } = {},
) {
  return { type: "Authorization" as const, action, path, message, ...data };
}

export function notFoundError(
  resource: string,
  message: string,
  data: { cause?: unknown; path?: string } = {},
) {
  return { type: "NotFound" as const, resource, message, ...data };
}

export function expiredError(
  resource: string,
  message: string,
  data: { cause?: unknown; path?: string } = {},
) {
  return { type: "Expired" as const, resource, message, ...data };
}

export function unsupportedCredentialKindError(
  kind: "oauth" | "headers" | "env",
  message: string,
  data: { cause?: unknown; path?: string } = {},
) {
  return { type: "UnsupportedCredentialKind" as const, kind, message, ...data };
}

export function persistenceError(
  operation: string,
  message: string,
  data: { cause?: unknown; path?: string } = {},
) {
  return { type: "Persistence" as const, operation, message, ...data };
}

export function oauthError(
  stage: string,
  message: string,
  data: { cause?: unknown; path?: string } = {},
) {
  return { type: "OAuth" as const, stage, message, ...data };
}

export function cryptoError(
  operation: string,
  message: string,
  data: { cause?: unknown; path?: string } = {},
) {
  return { type: "Crypto" as const, operation, message, ...data };
}

export function internalError(
  message: string,
  data: { cause?: unknown; path?: string; source?: string } = {},
) {
  return { type: "Internal" as const, message, ...data };
}

export function isAgentPwError(
  error: unknown,
): error is
  | ReturnType<typeof authorizationError>
  | ReturnType<typeof conflictError>
  | ReturnType<typeof cryptoError>
  | ReturnType<typeof expiredError>
  | ReturnType<typeof inputError>
  | ReturnType<typeof internalError>
  | ReturnType<typeof notFoundError>
  | ReturnType<typeof oauthError>
  | ReturnType<typeof persistenceError>
  | ReturnType<typeof unsupportedCredentialKindError> {
  return (
    typeof error === "object" &&
    error !== null &&
    "type" in error &&
    "message" in error &&
    typeof error.type === "string" &&
    typeof error.message === "string"
  );
}
