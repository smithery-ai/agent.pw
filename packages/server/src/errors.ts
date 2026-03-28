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

export function conflictError(message: string, data?: { path: string }) {
  return { type: "Conflict" as const, message, ...data };
}

export function authorizationError(
  action: string,
  path: string,
  message = `Missing '${action}' for '${path}'`,
) {
  return { type: "Authorization" as const, action, path, message };
}

export function notFoundError(resource: string, message: string, data?: { path: string }) {
  return { type: "NotFound" as const, resource, message, ...data };
}

export function expiredError(resource: string, message: string) {
  return { type: "Expired" as const, resource, message };
}

export function persistenceError(operation: string, message: string, data: { path: string }) {
  return { type: "Persistence" as const, operation, message, ...data };
}

export function oauthError(
  stage: string,
  message: string,
  data?: { cause: unknown } | { cause: unknown; path: string },
) {
  return { type: "OAuth" as const, stage, message, ...data };
}

export function cryptoError(operation: string, message: string, data?: { cause: unknown }) {
  return { type: "Crypto" as const, operation, message, ...data };
}

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
  | ReturnType<typeof persistenceError> {
  return (
    typeof error === "object" &&
    error !== null &&
    "type" in error &&
    "message" in error &&
    typeof error.type === "string" &&
    typeof error.message === "string"
  );
}
