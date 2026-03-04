import { Logtail } from '@logtail/edge'

type LogLevel = 'info' | 'warn' | 'error' | 'debug'

export interface Logger {
  info(obj: Record<string, unknown>, msg?: string): void
  info(msg: string): void
  warn(obj: Record<string, unknown>, msg?: string): void
  warn(msg: string): void
  error(obj: Record<string, unknown>, msg?: string): void
  error(msg: string): void
  debug(obj: Record<string, unknown>, msg?: string): void
  debug(msg: string): void
  child(bindings: Record<string, unknown>): Logger
}

class WardenLogger implements Logger {
  private service: string
  private bindings: Record<string, unknown>
  private logtail: Logtail | null

  constructor(service: string, logtail: Logtail | null, bindings: Record<string, unknown> = {}) {
    this.service = service
    this.logtail = logtail
    this.bindings = bindings
  }

  info(objOrMsg: Record<string, unknown> | string, msg?: string) {
    this._log('info', objOrMsg, msg)
  }

  warn(objOrMsg: Record<string, unknown> | string, msg?: string) {
    this._log('warn', objOrMsg, msg)
  }

  error(objOrMsg: Record<string, unknown> | string, msg?: string) {
    this._log('error', objOrMsg, msg)
  }

  debug(objOrMsg: Record<string, unknown> | string, msg?: string) {
    this._log('debug', objOrMsg, msg)
  }

  child(bindings: Record<string, unknown>): Logger {
    return new WardenLogger(this.service, this.logtail, { ...this.bindings, ...bindings })
  }

  private _log(level: LogLevel, objOrMsg: Record<string, unknown> | string, msg?: string) {
    let message: string
    let attrs: Record<string, unknown>

    if (typeof objOrMsg === 'string') {
      message = objOrMsg
      attrs = {}
    } else {
      message = msg ?? ''
      attrs = objOrMsg
    }

    const entry = {
      level,
      time: new Date().toISOString(),
      service: this.service,
      msg: message,
      ...this.bindings,
      ...attrs,
    }

    // Always write structured JSON to stdout
    console.log(JSON.stringify(entry))

    // Send to BetterStack if configured
    if (this.logtail) {
      const logtailLevel = level === 'debug' ? 'info' : level
      this.logtail[logtailLevel](message, { ...this.bindings, ...attrs })
    }
  }
}

export function createLogger(service: string, token?: string) {
  const logtail = token ? new Logtail(token) : null
  const logger: Logger = new WardenLogger(service, logtail)
  const flush = logtail ? () => logtail.flush() : () => Promise.resolve()
  return { logger, flush }
}
