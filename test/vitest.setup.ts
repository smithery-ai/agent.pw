import { createRequire } from "node:module";
import { webcrypto } from "node:crypto";

type ModuleGlobal = typeof globalThis & {
  module?: {
    require: NodeJS.Require;
  };
};

const globalWithModule = globalThis as ModuleGlobal;

if (!globalWithModule.module?.require) {
  globalWithModule.module = {
    require: createRequire(import.meta.url),
  };
}

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    configurable: true,
  });
}
