# Querying BetterStack Telemetry

BetterStack stores OTel data in ClickHouse. Query via the BetterStack API or Smithery CLI.

## Table Naming

Each source gets a ClickHouse table ID like `t507485.source_name`. Two virtual tables are created:
- `{table_id}_logs` — log records
- `{table_id}_spans` — trace spans

## Hot Data (< 30 min old)

Use `remote()` function:

```sql
-- Recent logs
SELECT dt, body, severity_text, attributes
FROM remote({table_id}_logs)
WHERE dt > now() - INTERVAL 1 HOUR
ORDER BY dt DESC
LIMIT 20

-- Recent spans
SELECT dt, span_name, duration, status_code, attributes
FROM remote({table_id}_spans)
WHERE dt > now() - INTERVAL 1 HOUR
ORDER BY dt DESC
LIMIT 20

-- Spans for a specific trace
SELECT span_name, duration, status_code, attributes
FROM remote({table_id}_spans)
WHERE trace_id = '<trace_id>'
ORDER BY dt
```

## Cold Data (> 30 min old)

Use `s3Cluster()` with `_row_type` filter:

```sql
-- Historical logs (_row_type = 1)
SELECT dt, body, severity_text, attributes
FROM s3Cluster(primary, {table_id}_s3)
WHERE _row_type = 1
  AND dt > now() - INTERVAL 24 HOUR
ORDER BY dt DESC
LIMIT 50

-- Historical spans (_row_type = 3)
SELECT dt, span_name, duration, status_code
FROM s3Cluster(primary, {table_id}_s3)
WHERE _row_type = 3
  AND dt > now() - INTERVAL 24 HOUR
ORDER BY dt DESC
LIMIT 50
```

## Via Smithery CLI

```bash
# Query logs
smithery tool call betterstack telemetry_query '{
  "query": "SELECT dt, body, severity_text FROM remote(t507485_myapp_logs) WHERE dt > now() - INTERVAL 1 HOUR ORDER BY dt DESC LIMIT 10",
  "source_id": 1234567,
  "table": "t507485.myapp"
}'

# Query spans
smithery tool call betterstack telemetry_query '{
  "query": "SELECT dt, span_name, duration FROM remote(t507485_myapp_spans) WHERE dt > now() - INTERVAL 1 HOUR ORDER BY dt DESC LIMIT 10",
  "source_id": 1234567,
  "table": "t507485.myapp"
}'
```

## Useful Columns

### Logs
| Column | Description |
|--------|-------------|
| `dt` | Timestamp |
| `body` | Log message |
| `severity_text` | INFO, WARN, ERROR, DEBUG |
| `severity_number` | Numeric severity |
| `attributes` | Structured log attributes (Map) |
| `trace_id` | Correlated trace ID |
| `span_id` | Correlated span ID |

### Spans
| Column | Description |
|--------|-------------|
| `dt` | Timestamp |
| `span_name` | Operation name |
| `trace_id` | Trace ID |
| `span_id` | Span ID |
| `parent_span_id` | Parent span |
| `duration` | Duration in nanoseconds |
| `status_code` | OK, ERROR, UNSET |
| `attributes` | Span attributes (Map) |
| `service_name` | Service that emitted the span |
