# sentinel-agent-websocket-inspector

A WebSocket inspection agent for the Sentinel proxy. Provides security controls for WebSocket traffic including content filtering, schema validation, rate limiting, and size limits.

## Features

### Content Filtering
- **XSS Detection**: Script tags, event handlers, javascript: URIs
- **SQL Injection Detection**: UNION SELECT, tautologies, time-based injection
- **Command Injection Detection**: Shell command chaining, backticks, $() substitution
- **Custom Patterns**: User-defined regex patterns to block

### Schema Validation
- **JSON Schema**: Validate text frames as JSON against a provided schema
- **MessagePack**: Decode and validate binary MessagePack messages

### Rate Limiting
- Messages per second per connection
- Bytes per second per connection
- Burst allowance configuration

### Size Limits
- Maximum text frame size
- Maximum binary frame size
- Maximum total message size

### Modes
- **Block mode**: Drop or close connections on violations
- **Detect-only mode**: Log detections without blocking
- **Fail-open mode**: Allow frames on processing errors

## Installation

```bash
cargo build --release
```

## Usage

```bash
# Basic usage with defaults (XSS, SQLi, command injection enabled)
sentinel-ws-agent --socket /tmp/sentinel-ws.sock

# With rate limiting
sentinel-ws-agent \
  --max-messages-per-sec 100 \
  --max-bytes-per-sec 1048576 \
  --rate-limit-burst 20

# With JSON Schema validation
sentinel-ws-agent --json-schema /path/to/schema.json

# Detect-only mode (log but don't block)
sentinel-ws-agent --block-mode false

# Enable verbose logging
sentinel-ws-agent -v
```

## CLI Options

| Option | Env Var | Description | Default |
|--------|---------|-------------|---------|
| `--socket` | `AGENT_SOCKET` | Unix socket path | `/tmp/sentinel-ws.sock` |
| `--xss-detection` | `WS_XSS` | Enable XSS detection | `true` |
| `--sqli-detection` | `WS_SQLI` | Enable SQLi detection | `true` |
| `--command-injection` | `WS_CMD` | Enable command injection detection | `true` |
| `--custom-patterns` | `WS_PATTERNS` | Comma-separated regex patterns | - |
| `--json-schema` | `WS_JSON_SCHEMA` | Path to JSON Schema file | - |
| `--msgpack-validation` | `WS_MSGPACK` | Enable MessagePack validation | `false` |
| `--max-messages-per-sec` | `WS_RATE_MESSAGES` | Rate limit (messages/sec, 0=unlimited) | `0` |
| `--max-bytes-per-sec` | `WS_RATE_BYTES` | Rate limit (bytes/sec, 0=unlimited) | `0` |
| `--rate-limit-burst` | `WS_RATE_BURST` | Burst allowance | `10` |
| `--max-text-frame-size` | `WS_MAX_TEXT` | Max text frame size (bytes, 0=unlimited) | `0` |
| `--max-binary-frame-size` | `WS_MAX_BINARY` | Max binary frame size (bytes, 0=unlimited) | `0` |
| `--max-message-size` | `WS_MAX_MESSAGE` | Max message size (fragmented, 0=unlimited) | `0` |
| `--block-mode` | `WS_BLOCK_MODE` | Block violations or detect-only | `true` |
| `--fail-open` | `WS_FAIL_OPEN` | Allow on errors | `false` |
| `--log-frames` | `WS_LOG_FRAMES` | Log all WebSocket frames | `false` |
| `--inspect-binary` | `WS_INSPECT_BINARY` | Inspect binary frames | `false` |
| `-v, --verbose` | `VERBOSE` | Enable debug logging | `false` |

## Detection Patterns

### XSS Patterns
- `<script>`, `</script>` - Script tags
- `on*=` - Event handlers (onclick, onerror, etc.)
- `javascript:` - JavaScript URIs
- `data:text/html` - Data URIs with HTML
- `<iframe>`, `<object>`, `<embed>` - Embedded content

### SQL Injection Patterns
- `UNION SELECT` - Union-based injection
- `OR 1=1`, `' OR '` - Tautology attacks
- `--`, `/* */`, `#` - Comment injection
- `SLEEP()`, `BENCHMARK()`, `WAITFOR DELAY` - Time-based injection
- `INFORMATION_SCHEMA` - Schema enumeration

### Command Injection Patterns
- `; cmd`, `| cmd` - Command chaining
- `` `cmd` `` - Backtick execution
- `$(cmd)` - Dollar-paren execution
- `cat /etc/`, `rm -rf` - Dangerous commands
- `/bin/sh -i` - Reverse shell patterns

## WebSocket Close Codes

When blocking, the agent uses RFC 6455 close codes:

| Code | Meaning | Use Case |
|------|---------|----------|
| 1008 | Policy Violation | Security violation (content filtering, rate limit) |
| 1009 | Message Too Big | Frame exceeds size limit |

## Audit Tags

Detections are logged with audit tags:
- `ws-xss` - XSS detection
- `ws-sqli` - SQL injection detection
- `ws-cmd-injection` - Command injection detection
- `ws-custom-pattern` - Custom pattern match
- `ws-schema-invalid` - JSON/MessagePack schema validation failure
- `ws-size-limit` - Frame size limit exceeded
- `ws-rate-limit` - Rate limit exceeded
- `detect-only` - Added when in detect-only mode

## Integration with Sentinel

Configure the agent in your Sentinel proxy configuration:

```yaml
agents:
  websocket-inspector:
    path: /tmp/sentinel-ws.sock
    events:
      - websocket_frame
```

## Development

```bash
# Run tests
cargo test

# Run integration tests only
cargo test --test integration

# Check formatting
cargo fmt --check

# Run linter
cargo clippy
```

## License

Apache-2.0
