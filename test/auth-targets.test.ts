import { describe, expect, it } from 'vitest'
import {
  authTargetFromKey,
  authTargetKey,
  authTargetProfilePath,
  normalizeAuthTarget,
  normalizeBindingLike,
  normalizeBindingRef,
  normalizeCredentialTargetInput,
  normalizeRoot,
  resolveBindingCredentialPath,
} from '../packages/server/src/auth-targets'

describe('auth targets', () => {
  it('normalizes roots, profile targets, and resource targets', () => {
    expect(normalizeRoot('/org/connection', 'binding root')).toBe('/org/connection')
    expect(normalizeBindingRef({
      root: '/org/connection',
      profilePath: '/github',
    })).toEqual({
      root: '/org/connection',
      target: {
        kind: 'profile',
        profilePath: '/github',
      },
    })

    expect(normalizeBindingLike({
      root: '/org/connection',
      target: {
        kind: 'resource',
        resource: 'https://mcp.example.com/path#fragment',
        authorizationServer: 'https://auth.example.com#fragment',
      },
    })).toEqual({
      root: '/org/connection',
      target: {
        kind: 'resource',
        resource: 'https://mcp.example.com/path',
        authorizationServer: 'https://auth.example.com/',
      },
    })

    expect(normalizeCredentialTargetInput({
      target: {
        kind: 'resource',
        resource: 'https://mcp.example.com',
      },
      secret: {
        headers: {},
      },
    })).toEqual({
      kind: 'resource',
      resource: 'https://mcp.example.com/',
    })
  })

  it('derives keys, profile views, and default credential paths', () => {
    const profileTarget = normalizeAuthTarget({
      kind: 'profile',
      profilePath: '/github',
    })
    const resourceTarget = normalizeAuthTarget({
      kind: 'resource',
      resource: 'https://mcp.example.com',
    })

    expect(authTargetKey(profileTarget)).toBe('/github')
    expect(authTargetKey(resourceTarget)).toBe('resource:https://mcp.example.com/')
    expect(authTargetFromKey('/github')).toEqual(profileTarget)
    expect(authTargetFromKey('resource:https://mcp.example.com/')).toEqual(resourceTarget)
    expect(authTargetProfilePath(profileTarget)).toBe('/github')
    expect(authTargetProfilePath(resourceTarget)).toBeNull()

    expect(resolveBindingCredentialPath({
      root: '/org/connection',
      target: profileTarget,
    })).toBe('/org/connection/github')

    expect(resolveBindingCredentialPath({
      root: '/org/connection',
      target: resourceTarget,
    })).toBe('/org/connection/credential')
  })

  it('rejects invalid paths, resources, and out-of-root credential paths', () => {
    expect(() => normalizeRoot('/bad/../path', 'binding root')).toThrow(
      "Invalid binding root '/bad/../path'",
    )
    expect(() => normalizeBindingRef({
      root: '/org/connection',
      profilePath: '/',
    })).toThrow("Invalid profile path '/'")
    expect(() => normalizeAuthTarget({
      kind: 'resource',
      resource: 'not-a-url',
    })).toThrow("Invalid resource 'not-a-url'")
    expect(() => normalizeBindingLike({
      root: '/org/connection',
    })).toThrow("Invalid profile path ''")

    expect(() => resolveBindingCredentialPath({
      root: '/org/connection',
      target: {
        kind: 'profile',
        profilePath: '/github',
      },
      credentialPath: '/outside/github',
    })).toThrow("Credential path '/outside/github' is outside root '/org/connection'")
  })
})
