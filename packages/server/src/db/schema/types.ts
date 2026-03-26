import { customType } from "drizzle-orm/pg-core";

export const bytea = customType<{ data: Buffer }>({
  dataType() {
    return "bytea";
  },
});

export const jsonb = <T>() =>
  customType<{ data: T; driverValue: T | string }>({
    dataType() {
      return "jsonb";
    },
    toDriver(value: T) {
      return JSON.stringify(value);
    },
    fromDriver(value) {
      if (typeof value !== "string") return value;
      try {
        return JSON.parse(value);
      } catch {
        // Older rows may contain a primitive string payload rather than JSON text.
        return value;
      }
    },
  });

export const ltree = customType<{ data: string; driverValue: string }>({
  dataType() {
    return "text";
  },
});
