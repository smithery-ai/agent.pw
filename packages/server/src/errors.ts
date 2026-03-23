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
