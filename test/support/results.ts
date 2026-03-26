import type { Result } from "okay-error";

function errorMessage(error: unknown) {
  if (error instanceof Error && error.message) {
    return error.message;
  }
  if (
    typeof error === "object" &&
    error !== null &&
    "message" in error &&
    typeof error.message === "string"
  ) {
    return error.message;
  }
  return JSON.stringify(error);
}

export function must<T>(result: Result<T, unknown>): T {
  if (result.ok) {
    return result.value;
  }
  throw new Error(errorMessage(result.error));
}

export async function mustAsync<T>(promise: Promise<Result<T, unknown>>): Promise<T> {
  return must(await promise);
}

export function errorOf<E>(result: Result<unknown, E>): E {
  if (!result.ok) {
    return result.error;
  }
  throw new Error("Expected Err result");
}

export async function errorOfAsync<E>(promise: Promise<Result<unknown, E>>): Promise<E> {
  return errorOf(await promise);
}

function wrapMethods<T extends Record<string, unknown>>(value: T): T {
  const wrapped = { ...value } as T;

  for (const [key, member] of Object.entries(value)) {
    if (typeof member !== "function") {
      continue;
    }
    wrapped[key as keyof T] = ((...args: unknown[]) => {
      const next = member.apply(wrapped, args);
      if (next && typeof next === "object" && "ok" in (next as Result<unknown, unknown>)) {
        return must(next as Result<unknown, unknown>);
      }
      if (!next || typeof next !== "object" || typeof (next as Promise<unknown>).then !== "function") {
        return next;
      }
      return (next as Promise<unknown>).then((resolved) => {
        if (resolved && typeof resolved === "object" && "ok" in (resolved as Result<unknown, unknown>)) {
          return must(resolved as Result<unknown, unknown>);
        }
        return resolved;
      });
    }) as T[keyof T];
  }

  return wrapped;
}

export function wrapAgentPw<T extends Record<string, unknown>>(agentPw: T): T {
  const wrapped = {
    ...agentPw,
    connect: wrapMethods(agentPw.connect),
    credentials: wrapMethods(agentPw.credentials),
    profiles: wrapMethods(agentPw.profiles),
    scope(input: unknown) {
      const scoped = agentPw.scope(input);
      return {
        ...scoped,
        connect: wrapMethods(scoped.connect),
        credentials: wrapMethods(scoped.credentials),
        profiles: wrapMethods(scoped.profiles),
      };
    },
  } as T;

  return wrapped;
}

export function wrapObjectMethods<T extends Record<string, unknown>>(value: T): T {
  return wrapMethods(value);
}
