import { AgentPwInputError } from './errors.js'
import { canonicalizePath, credentialName, isAncestorOrEqual, joinCredentialPath, validatePath } from './paths.js'
import type {
  AuthTarget,
  BindingRef,
  CredentialPutInput,
  ProfileAuthTarget,
  ResourceAuthTarget,
} from './types.js'

const RESOURCE_TARGET_PREFIX = 'resource:'

function assertPath(path: string, label: string) {
  const normalized = canonicalizePath(path)
  if (!validatePath(normalized) || normalized === '/') {
    throw new AgentPwInputError(`Invalid ${label} '${path}'`)
  }
  return normalized
}

function assertResource(resource: string) {
  let parsed: URL
  try {
    parsed = new URL(resource)
  } catch {
    throw new AgentPwInputError(`Invalid resource '${resource}'`)
  }
  parsed.hash = ''
  return parsed.toString()
}

export function normalizeRoot(root: string, label: string) {
  const normalized = canonicalizePath(root)
  if (!validatePath(normalized)) {
    throw new AgentPwInputError(`Invalid ${label} '${root}'`)
  }
  return normalized
}

export function normalizeAuthTarget(target: AuthTarget): AuthTarget {
  if (target.kind === 'profile') {
    return {
      kind: 'profile',
      profilePath: assertPath(target.profilePath, 'profile path'),
    } satisfies ProfileAuthTarget
  }

  return {
    kind: 'resource',
    resource: assertResource(target.resource),
    authorizationServer: target.authorizationServer ? assertResource(target.authorizationServer) : undefined,
  } satisfies ResourceAuthTarget
}

export function normalizeBindingRef(input: BindingRef) {
  return {
    root: normalizeRoot(input.root, 'binding root'),
    target: input.target !== undefined
      ? normalizeAuthTarget(input.target)
      : {
          kind: 'profile',
          profilePath: assertPath(input.profilePath, 'profile path'),
        } satisfies ProfileAuthTarget,
  }
}

export function normalizeBindingLike(input: {
  root: string
  target?: AuthTarget
  profilePath?: string
}) {
  return {
    root: normalizeRoot(input.root, 'binding root'),
    target: input.target !== undefined
      ? normalizeAuthTarget(input.target)
      : {
          kind: 'profile',
          profilePath: assertPath(input.profilePath ?? '', 'profile path'),
        } satisfies ProfileAuthTarget,
  }
}

export function normalizeCredentialTargetInput(input: CredentialPutInput): AuthTarget {
  return input.target !== undefined
    ? normalizeAuthTarget(input.target)
    : {
        kind: 'profile',
        profilePath: assertPath(input.profilePath, 'profile path'),
      } satisfies ProfileAuthTarget
}

export function authTargetKey(target: AuthTarget) {
  return target.kind === 'profile'
    ? target.profilePath
    : `${RESOURCE_TARGET_PREFIX}${target.resource}`
}

export function authTargetFromKey(key: string): AuthTarget {
  if (key.startsWith(RESOURCE_TARGET_PREFIX)) {
    return {
      kind: 'resource',
      resource: key.slice(RESOURCE_TARGET_PREFIX.length),
    }
  }
  return {
    kind: 'profile',
    profilePath: key,
  }
}

export function authTargetProfilePath(target: AuthTarget) {
  return target.kind === 'profile' ? target.profilePath : null
}

export function resolveBindingCredentialPath(input: {
  root: string
  target: AuthTarget
  credentialPath?: string
}) {
  const credentialPath = input.credentialPath
    ? assertPath(input.credentialPath, 'credential path')
    : input.target.kind === 'profile'
      ? joinCredentialPath(input.root, credentialName(input.target.profilePath))
      : joinCredentialPath(input.root, 'credential')

  if (!isAncestorOrEqual(input.root, credentialPath)) {
    throw new AgentPwInputError(`Credential path '${credentialPath}' is outside root '${input.root}'`)
  }

  return credentialPath
}
