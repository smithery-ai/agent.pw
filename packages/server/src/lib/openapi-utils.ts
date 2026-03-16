import { z, type ZodType } from 'zod'
import { isRecord } from './utils'

type InjectSchemasOptions = {
  ambiguousSchemas?: Set<string>
}

/**
 * Convert Zod schemas to JSON Schema and inject into OpenAPI spec components.schemas.
 * Also replaces inline schemas in paths with $ref pointers.
 */
export function injectSchemas(
  spec: Record<string, unknown>,
  schemas: ZodType[],
  options?: InjectSchemasOptions,
): void {
  const components = isRecord(spec.components) ? spec.components : {}
  const schemasMap = isRecord(components.schemas) ? components.schemas : {}

  for (const schema of schemas) {
    const jsonSchema = z.toJSONSchema(schema, {
      unrepresentable: 'any',
    })
    if (!isRecord(jsonSchema)) continue

    const id = typeof jsonSchema.id === 'string' ? jsonSchema.id : undefined
    if (!id) continue

    delete jsonSchema.$schema
    delete jsonSchema.id

    // Hoist nested $defs to components.schemas
    if (isRecord(jsonSchema.$defs)) {
      const defs = jsonSchema.$defs
      for (const [defId, defSchema] of Object.entries(defs)) {
        if (!schemasMap[defId]) {
          schemasMap[defId] = defSchema
        }
      }
      delete jsonSchema.$defs
    }

    schemasMap[id] = jsonSchema
  }

  for (const schemaObj of Object.values(schemasMap)) {
    rewriteRefs(schemaObj)
  }

  if (options?.ambiguousSchemas) {
    for (const schemaId of options.ambiguousSchemas) {
      const schema = schemasMap[schemaId]
      if (isRecord(schema) && isRecord(schema.additionalProperties)) {
        schema.additionalProperties['x-stainless-any'] = true
      }
    }
  }

  components.schemas = schemasMap
  spec.components = components

  replaceInlineSchemasWithRefs(isRecord(spec.paths) ? spec.paths : {}, schemasMap)
}

/** Replace inline schemas that have an `id` matching a schema in components.schemas with $ref pointers. */
export function replaceInlineSchemasWithRefs(
  obj: unknown,
  schemas: Record<string, unknown>,
): void {
  if (!isRecord(obj) && !Array.isArray(obj)) return
  if (Array.isArray(obj)) {
    for (const item of obj) replaceInlineSchemasWithRefs(item, schemas)
    return
  }

  const record = obj

  for (const [key, value] of Object.entries(record)) {
    if (!isRecord(value)) continue

    if (typeof value.id === 'string' && schemas[value.id]) {
      record[key] = { $ref: `#/components/schemas/${value.id}` }
    } else {
      replaceInlineSchemasWithRefs(value, schemas)
    }
  }
}

/** Rewrite $refs from #/$defs/... to #/components/schemas/... format. */
export function rewriteRefs(obj: unknown): void {
  if (!isRecord(obj) && !Array.isArray(obj)) return
  if (Array.isArray(obj)) {
    for (const item of obj) rewriteRefs(item)
    return
  }
  const record = obj
  if (record.$ref && typeof record.$ref === 'string' && record.$ref.startsWith('#/$defs/')) {
    record.$ref = record.$ref.replace('#/$defs/', '#/components/schemas/')
  }
  for (const value of Object.values(record)) {
    rewriteRefs(value)
  }
}
