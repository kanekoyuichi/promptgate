# Logging

PromptGate produces two types of logs.

- **Audit logs**: Records scan results. Used for tracing and monitoring in production.
- **Internal warning logs**: Records errors from pattern loading and LLM API calls.

Both use Python's standard `logging` module and can be integrated with existing logging configurations.

---

## Audit logs

### When logs are emitted and at what level

| Condition | Log level |
|-----------|-----------|
| `is_safe=False` (blocked) | `WARNING` |
| `is_safe=True` and `log_all=True` | `INFO` |
| `is_safe=True` and trusted user | `INFO` |
| All other cases (pass, normal user) | Not emitted |

By default, logs are only emitted **when a request is blocked**.

### Message format

```
promptgate.scan verdict=BLOCKED trace_id=abc123 scan_type=input input_hash=d4d10baf risk_score=0.9500 threats=['direct_injection']
```

### Extra fields

Structured data attached to the `LogRecord` for `logging.Handler`. Combined with a JSON handler or external logging service, this provides a machine-readable audit trail.

| Field | Type | Description |
|-------|------|-------------|
| `trace_id` | `str` | Request trace ID (auto-generated UUID if not provided) |
| `tenant_id` | `str \| None` | Tenant identifier set via `PromptGate(tenant_id=...)` |
| `scan_type` | `str` | `"input"` or `"output"` |
| `input_hash` | `str` | First 16 hex digits of SHA-256 of the input text (raw text not included) |
| `input_length` | `int` | Number of characters in the input |
| `user_id` | `str \| None` | User ID passed via `scan(text, user_id=...)` |
| `is_trusted` | `bool` | Whether the user is in the trusted users list |
| `is_safe` | `bool` | Final verdict |
| `risk_score` | `float` | Final risk score (0.0 to 1.0) |
| `threats` | `list[str]` | List of detected threat categories |
| `detector_scores` | `dict[str, float]` | Per-scanner scores (e.g. `{"rule": 0.9}`) |
| `rule_hits` | `list[str]` | Threat types matched by the rule scanner |
| `latency_ms` | `float` | Total scan processing time (ms) |
| `input_text` | `str` | Raw input text (only included when `log_input=True`) |

### Configuration options

```python
gate = PromptGate(
    log_all=True,       # Log all results including safe ones (default: False)
    log_input=True,     # Include raw input text in log extras (default: False)
    tenant_id="app-1",  # Attach tenant identifier to all log entries
)
```

> **On `log_input=True`**: The raw input text is recorded in the log as-is.
> In environments where inputs may contain personal or sensitive information, ensure appropriate log storage and access controls are in place.

### Specifying a trace_id

Pass `trace_id` to `scan()` / `scan_async()` to correlate logs with your application's request IDs.

```python
result = gate.scan(user_input, trace_id=request.headers.get("X-Request-ID"))
```

### Connecting to structured logging

The `extra` fields are passed as attributes on the `LogRecord` and can be accessed in custom handlers.

```python
import logging
import json

class JsonHandler(logging.StreamHandler):
    FIELDS = [
        "trace_id", "tenant_id", "scan_type", "input_hash",
        "is_safe", "risk_score", "threats", "latency_ms",
    ]

    def emit(self, record):
        data = {"level": record.levelname, "message": record.getMessage()}
        for field in self.FIELDS:
            if hasattr(record, field):
                data[field] = getattr(record, field)
        print(json.dumps(data, ensure_ascii=False))

logging.getLogger("promptgate.core").addHandler(JsonHandler())
```

Example output:

```json
{
  "level": "WARNING",
  "message": "promptgate.scan verdict=BLOCKED ...",
  "trace_id": "abc123",
  "scan_type": "input",
  "is_safe": false,
  "risk_score": 0.95,
  "threats": ["direct_injection", "data_exfiltration"],
  "latency_ms": 0.41
}
```

---

## Internal warning logs

Operational issues within the library are emitted at `WARNING` level. These are separate from audit logs.

| Logger name | Emitted when |
|-------------|-------------|
| `promptgate.detectors.rule_based` | YAML pattern compilation failure, rejection of empty-string match patterns, validation failure in `add_rule()` |
| `promptgate.detectors.llm_judge` | LLM API errors (processing continues according to the `llm_on_error` setting) |

When these logs appear, they may indicate a misconfiguration or an external service failure.

---

## Logger name reference

| Logger name | Purpose |
|-------------|---------|
| `promptgate.core` | Audit logs |
| `promptgate.detectors.rule_based` | Rule scanner internal warnings |
| `promptgate.detectors.llm_judge` | LLM scanner internal warnings |

To enable only specific loggers:

```python
import logging

# Emit WARNING and above for audit logs only
logging.getLogger("promptgate.core").setLevel(logging.WARNING)

# Suppress internal warning logs
logging.getLogger("promptgate.detectors").setLevel(logging.ERROR)
```
