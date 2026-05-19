# Operations Logging

Tovbase ID emits PII-safe structured access logs through the
`tovbase_id.access` logger.

Each HTTP request log is a compact JSON object with:

- `event`
- `request_id`
- `method`
- `path_template`
- `status_code`
- `duration_ms`
- `failed`

The middleware deliberately does not log request bodies, response bodies, query
strings, API keys, bank headers, raw hashes, DIDs, action ids, receipt ids, or
client IP addresses. Route templates such as `/v1/did/hash/{hash_id}` are used
instead of concrete URL paths whenever a route matches.

Request id behavior:

- If `X-Request-ID` is supplied and is a short printable value, Tovbase echoes
  it in the response.
- Otherwise Tovbase generates a random request id and returns it in
  `x-request-id`.

Disable access logging with:

```text
ACCESS_LOG_ENABLED=false
```

The logs are intended for latency monitoring, request tracing, and operational
alerting without creating a secondary PII or secret store.
