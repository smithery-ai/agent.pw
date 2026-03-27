type ErrorContext = {
  cause?: unknown;
  path?: string;
};

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
  data: ErrorContext & { field?: string; value?: string } = {},
) {
  return { type: "Input" as const, message, ...data };
}

export function conflictError(message: string, data: ErrorContext = {}) {
  return { type: "Conflict" as const, message, ...data };
}

export function authorizationError(
  action: string,
  path: string,
  message = `Missing '${action}' for '${path}'`,
  data: Omit<ErrorContext, "path"> = {},
) {
  return { type: "Authorization" as const, action, path, message, ...data };
}

export function notFoundError(
  resource: string,
  message: string,
  data: ErrorContext = {},
) {
  return { type: "NotFound" as const, resource, message, ...data };
}

export function expiredError(
  resource: string,
  message: string,
  data: ErrorContext = {},
) {
  return { type: "Expired" as const, resource, message, ...data };
}

export function unsupportedCredentialKindError(
  kind: "oauth" | "headers" | "env",
  message: string,
  data: ErrorContext = {},
) {
  return { type: "UnsupportedCredentialKind" as const, kind, message, ...data };
}

export function persistenceError(
  operation: string,
  message: string,
  data: ErrorContext = {},
) {
  return { type: "Persistence" as const, operation, message, ...data };
}

export function oauthError(
  stage: string,
  message: string,
  data: ErrorContext = {},
) {
  return { type: "OAuth" as const, stage, message, ...data };
}

export function cryptoError(
  operation: string,
  message: string,
  data: ErrorContext = {},
) {
  return { type: "Crypto" as const, operation, message, ...data };
}

export function internalError(
  message: string,
  data: ErrorContext & { source?: string } = {},
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

export function toAgentPwError(
  error: unknown,
  fallback: ErrorContext & { message: string; source?: string } = {
    message: "Unexpected internal error",
  },
) {
  if (isAgentPwError(error)) {
    return error;
  }

  return internalError(errorMessage(error, fallback.message), {
    ...fallback,
    cause: fallback.cause ?? error,
  });
}
