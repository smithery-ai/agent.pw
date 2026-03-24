export class AgentPwConflictError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'AgentPwConflictError'
  }
}

export class AgentPwInputError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'AgentPwInputError'
  }
}

export class AgentPwAuthorizationError extends Error {
  action: string
  path: string

  constructor(action: string, path: string, message = `Missing '${action}' for '${path}'`) {
    super(message)
    this.name = 'AgentPwAuthorizationError'
    this.action = action
    this.path = path
  }
}
