type LogLevel = "info" | "warn" | "error" | "debug";

export interface Logger {
  info(obj: Record<string, unknown>, msg?: string): void;
  info(msg: string): void;
  warn(obj: Record<string, unknown>, msg?: string): void;
  warn(msg: string): void;
  error(obj: Record<string, unknown>, msg?: string): void;
  error(msg: string): void;
  debug(obj: Record<string, unknown>, msg?: string): void;
  debug(msg: string): void;
  child(bindings: Record<string, unknown>): Logger;
}

function serializeValue(val: unknown): unknown {
  if (val instanceof Error) {
    return { message: val.message, stack: val.stack, name: val.name };
  }
  return val;
}

function serializeObject(obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(obj)) {
    result[key] = serializeValue(val);
  }
  return result;
}

class WardenLogger implements Logger {
  private service: string;
  private bindings: Record<string, unknown>;

  constructor(service: string, bindings: Record<string, unknown> = {}) {
    this.service = service;
    this.bindings = bindings;
  }

  info(objOrMsg: Record<string, unknown> | string, msg?: string) {
    this._log("info", objOrMsg, msg);
  }

  warn(objOrMsg: Record<string, unknown> | string, msg?: string) {
    this._log("warn", objOrMsg, msg);
  }

  error(objOrMsg: Record<string, unknown> | string, msg?: string) {
    this._log("error", objOrMsg, msg);
  }

  debug(objOrMsg: Record<string, unknown> | string, msg?: string) {
    this._log("debug", objOrMsg, msg);
  }

  child(bindings: Record<string, unknown>): Logger {
    return new WardenLogger(this.service, { ...this.bindings, ...bindings });
  }

  private _log(level: LogLevel, objOrMsg: Record<string, unknown> | string, msg?: string) {
    const [message, attrs]: [string, Record<string, unknown>] =
      typeof objOrMsg === "string" ? [objOrMsg, {}] : [msg ?? "", objOrMsg];

    const serialized = serializeObject(attrs);

    const entry = {
      level,
      time: new Date().toISOString(),
      service: this.service,
      msg: message,
      ...this.bindings,
      ...serialized,
    };

    console.log(JSON.stringify(entry));
  }
}

export function createLogger(service: string) {
  const logger: Logger = new WardenLogger(service);
  return { logger };
}
