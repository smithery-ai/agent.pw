import { AgentPwInputError } from './errors.js'
import { randomId, validateFlowId } from './lib/utils.js'
import { canonicalizePath, validatePath } from './paths.js'

export interface PendingFlow {
  id: string
  root: string
  profilePath: string
  codeVerifier: string
  expiresAt: Date
  identity?: string
}

export interface FlowStore {
  create(flow: PendingFlow): Promise<void>
  get(id: string): Promise<PendingFlow | null>
  complete(id: string, result?: { identity?: string }): Promise<void>
  delete(id: string): Promise<void>
}

function assertResolvablePath(path: string, label: string) {
  const normalized = canonicalizePath(path)
  if (!validatePath(normalized) || normalized === '/') {
    throw new AgentPwInputError(`Invalid ${label} '${path}'`)
  }
  return normalized
}

function defaultExpiry(clock: () => Date) {
  return new Date(clock().getTime() + 10 * 60 * 1000)
}

export function createInMemoryFlowStore(): FlowStore {
  const store = new Map<string, PendingFlow>()

  return {
    async create(flow) {
      store.set(flow.id, flow)
    },
    async get(id) {
      return store.get(id) ?? null
    },
    async complete(id, result) {
      const existing = store.get(id)
      if (!existing) {
        return
      }
      store.set(id, {
        ...existing,
        identity: result?.identity,
      })
    },
    async delete(id) {
      store.delete(id)
    },
  }
}

export function createOAuthService(options: {
  flowStore: FlowStore
  clock: () => Date
}) {
  return {
    async start(input: {
      id?: string
      root: string
      profilePath: string
      codeVerifier?: string
      expiresAt?: Date
    }) {
      const id = validateFlowId(input.id) ?? randomId() + randomId()
      const flow: PendingFlow = {
        id,
        root: assertResolvablePath(input.root, 'binding root'),
        profilePath: assertResolvablePath(input.profilePath, 'profile path'),
        codeVerifier: input.codeVerifier ?? randomId() + randomId(),
        expiresAt: input.expiresAt ?? defaultExpiry(options.clock),
      }
      await options.flowStore.create(flow)
      return flow
    },

    async get(id: string) {
      return options.flowStore.get(id)
    },

    async complete(id: string, result?: { identity?: string }) {
      await options.flowStore.complete(id, result)
    },

    async delete(id: string) {
      await options.flowStore.delete(id)
    },
  }
}
