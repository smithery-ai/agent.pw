const AUTH_HEADER_NAMES = new Set(["authorization", "proxy-authorization"]);

function nonAuthHeaders(headers: Record<string, string> | undefined) {
  const merged: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers ?? {})) {
    if (!AUTH_HEADER_NAMES.has(name.toLowerCase())) {
      merged[name] = value;
    }
  }
  return merged;
}

function authHeaders(headers: Record<string, string> | undefined) {
  const merged: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers ?? {})) {
    if (AUTH_HEADER_NAMES.has(name.toLowerCase())) {
      merged[name] = value;
    }
  }
  return merged;
}

export function mergeConnectHeaders(input: {
  existingHeaders?: Record<string, string>;
  headers?: Record<string, string>;
  oauthHeaders?: Record<string, string>;
  preserveExistingHeaders?: boolean;
}) {
  const preserveExistingHeaders = input.preserveExistingHeaders === true;

  if (!input.oauthHeaders) {
    return {
      ...(preserveExistingHeaders ? input.existingHeaders : undefined),
      ...input.headers,
    };
  }

  return {
    ...(preserveExistingHeaders ? nonAuthHeaders(input.existingHeaders) : {}),
    ...nonAuthHeaders(input.headers),
    ...authHeaders(input.oauthHeaders),
  };
}
