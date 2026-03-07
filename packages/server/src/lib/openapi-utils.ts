import { z, type ZodType } from 'zod'

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
  const components = (spec.components as Record<string, unknown>) || {}
  const schemasMap = (components.schemas as Record<string, unknown>) || {}

  for (const schema of schemas) {
    const jsonSchema = z.toJSONSchema(schema, {
      unrepresentable: 'any',
    }) as Record<string, unknown>

    const id = jsonSchema.id as string | undefined
    if (!id) continue

    delete jsonSchema.$schema
    delete jsonSchema.id

    // Hoist nested $defs to components.schemas
    if (jsonSchema.$defs) {
      const defs = jsonSchema.$defs as Record<string, unknown>
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
      const schema = schemasMap[schemaId] as Record<string, unknown> | undefined
      if (schema?.additionalProperties && typeof schema.additionalProperties === 'object') {
        ;(schema.additionalProperties as Record<string, unknown>)['x-stainless-any'] = true
      }
    }
  }

  components.schemas = schemasMap
  spec.components = components

  replaceInlineSchemasWithRefs(spec.paths as Record<string, unknown>, schemasMap)
}

/** Replace inline schemas that have an `id` matching a schema in components.schemas with $ref pointers. */
export function replaceInlineSchemasWithRefs(
  obj: unknown,
  schemas: Record<string, unknown>,
): void {
  if (!obj || typeof obj !== 'object') return
  if (Array.isArray(obj)) {
    for (const item of obj) replaceInlineSchemasWithRefs(item, schemas)
    return
  }

  const record = obj as Record<string, unknown>

  for (const [key, value] of Object.entries(record)) {
    if (!value || typeof value !== 'object') continue

    const valueRecord = value as Record<string, unknown>

    if (valueRecord.id && typeof valueRecord.id === 'string' && schemas[valueRecord.id]) {
      record[key] = { $ref: `#/components/schemas/${valueRecord.id}` }
    } else {
      replaceInlineSchemasWithRefs(value, schemas)
    }
  }
}

/** Rewrite $refs from #/$defs/... to #/components/schemas/... format. */
export function rewriteRefs(obj: unknown): void {
  if (!obj || typeof obj !== 'object') return
  if (Array.isArray(obj)) {
    for (const item of obj) rewriteRefs(item)
    return
  }
  const record = obj as Record<string, unknown>
  if (record.$ref && typeof record.$ref === 'string' && record.$ref.startsWith('#/$defs/')) {
    record.$ref = record.$ref.replace('#/$defs/', '#/components/schemas/')
  }
  for (const value of Object.values(record)) {
    rewriteRefs(value)
  }
}
