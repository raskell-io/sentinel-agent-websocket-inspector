//! WebSocket Inspector Agent for Sentinel proxy.
//!
//! Provides security controls for WebSocket traffic including:
//! - Content filtering (XSS, SQLi, command injection)
//! - JSON Schema validation
//! - MessagePack validation
//! - Rate limiting
//! - Size limits

pub mod config;
pub mod inspection;
pub mod ratelimit;
pub mod validation;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use config::WsInspectorConfig;
use inspection::{ContentInspector, Detection};
use ratelimit::{RateLimitConfig, RateLimitExceeded, RateLimiter};
use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, AuditMetadata, ConfigureEvent, RequestBodyChunkEvent,
    RequestCompleteEvent, RequestHeadersEvent, ResponseBodyChunkEvent, ResponseHeadersEvent,
    WebSocketDecision, WebSocketFrameEvent,
};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use validation::{JsonSchemaValidator, MsgpackValidator};

pub use config::WsInspectorConfig as Config;

use serde::Deserialize;

/// JSON configuration structure for on_configure().
/// Maps kebab-case JSON keys to WsInspectorConfig fields.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct WsInspectorConfigJson {
    /// Enable XSS detection in text frames
    pub xss_detection: Option<bool>,
    /// Enable SQL injection detection in text frames
    pub sqli_detection: Option<bool>,
    /// Enable command injection detection in text frames
    pub command_injection: Option<bool>,
    /// Block mode: true = block violations, false = detect-only
    pub block_mode: Option<bool>,
    /// Fail open: allow frames on processing errors
    pub fail_open: Option<bool>,
    /// Maximum text frame size in bytes (0 = unlimited)
    pub max_text_frame_size: Option<usize>,
    /// Maximum binary frame size in bytes (0 = unlimited)
    pub max_binary_frame_size: Option<usize>,
    /// Maximum messages per second per connection (0 = unlimited)
    pub max_messages_per_sec: Option<u32>,
    /// Maximum bytes per second per connection (0 = unlimited)
    pub max_bytes_per_sec: Option<u64>,
    /// Burst allowance for rate limiting
    pub rate_limit_burst: Option<u32>,
    /// Log all frames for debugging
    pub log_frames: Option<bool>,
    /// Enable MessagePack message decoding and validation
    pub msgpack_validation: Option<bool>,
}

impl WsInspectorConfigJson {
    /// Apply JSON config values to an existing WsInspectorConfig.
    /// Only overrides fields that are explicitly set (Some).
    pub fn apply_to(&self, config: &mut WsInspectorConfig) {
        if let Some(v) = self.xss_detection {
            config.xss_detection = v;
        }
        if let Some(v) = self.sqli_detection {
            config.sqli_detection = v;
        }
        if let Some(v) = self.command_injection {
            config.command_injection = v;
        }
        if let Some(v) = self.block_mode {
            config.block_mode = v;
        }
        if let Some(v) = self.fail_open {
            config.fail_open = v;
        }
        if let Some(v) = self.max_text_frame_size {
            config.max_text_frame_size = v;
        }
        if let Some(v) = self.max_binary_frame_size {
            config.max_binary_frame_size = v;
        }
        if let Some(v) = self.max_messages_per_sec {
            config.max_messages_per_sec = v;
        }
        if let Some(v) = self.max_bytes_per_sec {
            config.max_bytes_per_sec = v;
        }
        if let Some(v) = self.rate_limit_burst {
            config.rate_limit_burst = v;
        }
        if let Some(v) = self.log_frames {
            config.log_frames = v;
        }
        if let Some(v) = self.msgpack_validation {
            config.msgpack_validation = v;
        }
    }
}

/// WebSocket opcode string values
mod opcode {
    pub const CONTINUATION: &str = "continuation";
    pub const TEXT: &str = "text";
    pub const BINARY: &str = "binary";
    pub const CLOSE: &str = "close";
    pub const PING: &str = "ping";
    pub const PONG: &str = "pong";
}

/// WebSocket close codes (RFC 6455)
mod close_code {
    pub const POLICY_VIOLATION: u16 = 1008;
    pub const MESSAGE_TOO_BIG: u16 = 1009;
}

/// Internal state that can be reconfigured at runtime.
struct InspectorState {
    config: WsInspectorConfig,
    content_inspector: ContentInspector,
    json_validator: Option<JsonSchemaValidator>,
    msgpack_validator: Option<MsgpackValidator>,
    rate_limiter: RateLimiter,
}

/// WebSocket Inspector Agent.
pub struct WsInspectorAgent {
    state: RwLock<InspectorState>,
}

impl WsInspectorAgent {
    /// Create a new WebSocket Inspector agent.
    pub fn new(config: WsInspectorConfig) -> anyhow::Result<Self> {
        let state = Self::build_state(config)?;
        Ok(Self {
            state: RwLock::new(state),
        })
    }

    /// Build the internal state from configuration.
    fn build_state(config: WsInspectorConfig) -> anyhow::Result<InspectorState> {
        let content_inspector = ContentInspector::new(config.clone());

        // Load JSON Schema if configured
        let json_validator = if let Some(ref path) = config.json_schema {
            Some(JsonSchemaValidator::from_file(path)?)
        } else {
            None
        };

        // Create MessagePack validator if enabled
        let msgpack_validator = if config.msgpack_validation {
            Some(if let Some(ref jv) = json_validator {
                MsgpackValidator::with_schema(jv.clone())
            } else {
                MsgpackValidator::new()
            })
        } else {
            None
        };

        // Create rate limiter
        let rate_limiter = RateLimiter::new(RateLimitConfig {
            max_messages_per_sec: config.max_messages_per_sec,
            max_bytes_per_sec: config.max_bytes_per_sec,
            burst: config.rate_limit_burst,
            ..Default::default()
        });

        Ok(InspectorState {
            config,
            content_inspector,
            json_validator,
            msgpack_validator,
            rate_limiter,
        })
    }

    /// Reconfigure the agent with new settings.
    /// Only updates fields that are explicitly set in the JSON config.
    async fn reconfigure(&self, json_config: WsInspectorConfigJson) -> anyhow::Result<()> {
        let mut state = self.state.write().await;

        // Apply new config values
        json_config.apply_to(&mut state.config);

        // Rebuild content inspector with updated config
        state.content_inspector = ContentInspector::new(state.config.clone());

        // Rebuild MessagePack validator if setting changed
        if json_config.msgpack_validation.is_some() {
            state.msgpack_validator = if state.config.msgpack_validation {
                Some(if let Some(ref jv) = state.json_validator {
                    MsgpackValidator::with_schema(jv.clone())
                } else {
                    MsgpackValidator::new()
                })
            } else {
                None
            };
        }

        // Rebuild rate limiter if any rate limit settings changed
        if json_config.max_messages_per_sec.is_some()
            || json_config.max_bytes_per_sec.is_some()
            || json_config.rate_limit_burst.is_some()
        {
            state.rate_limiter = RateLimiter::new(RateLimitConfig {
                max_messages_per_sec: state.config.max_messages_per_sec,
                max_bytes_per_sec: state.config.max_bytes_per_sec,
                burst: state.config.rate_limit_burst,
                ..Default::default()
            });
        }

        info!("Agent reconfigured successfully");
        Ok(())
    }

    /// Process a WebSocket frame and return a decision.
    async fn process_frame(&self, event: &WebSocketFrameEvent) -> AgentResponse {
        let correlation_id = &event.correlation_id;
        let direction = if event.client_to_server {
            "client→server"
        } else {
            "server→client"
        };

        // Acquire read lock for accessing state
        let state = self.state.read().await;

        if state.config.log_frames {
            info!(
                correlation_id = %correlation_id,
                opcode = %event.opcode,
                direction = direction,
                frame_index = event.frame_index,
                fin = event.fin,
                data_len = event.data.len(),
                "WebSocket frame"
            );
        }

        // Decode frame data from base64
        let data = match BASE64.decode(&event.data) {
            Ok(d) => d,
            Err(e) => {
                warn!(error = %e, "Failed to decode frame data");
                return Self::handle_error_static(state.config.fail_open, "decode-error");
            }
        };

        // Check size limits
        if let Some(response) =
            Self::check_size_limits_static(&state.config, &event.opcode, data.len())
        {
            return response;
        }

        // Check rate limits
        let result = state
            .rate_limiter
            .check_and_record(correlation_id, data.len() as u64)
            .await;

        if !result.allowed {
            let exceeded_type = match result.exceeded {
                Some(RateLimitExceeded::Messages) => "messages",
                Some(RateLimitExceeded::Bytes) => "bytes",
                None => "unknown",
            };

            debug!(
                correlation_id = %correlation_id,
                exceeded = exceeded_type,
                message_count = result.message_count,
                bytes_count = result.bytes_count,
                "Rate limit exceeded"
            );

            if state.config.block_mode {
                return AgentResponse::default_allow()
                    .with_websocket_decision(WebSocketDecision::Close {
                        code: close_code::POLICY_VIOLATION,
                        reason: format!("Rate limit exceeded: {}", exceeded_type),
                    })
                    .with_audit(AuditMetadata {
                        tags: vec!["ws-rate-limit".to_string()],
                        ..Default::default()
                    });
            } else {
                return AgentResponse::websocket_allow().with_audit(AuditMetadata {
                    tags: vec!["ws-rate-limit".to_string(), "detect-only".to_string()],
                    ..Default::default()
                });
            }
        }

        // Skip inspection for control frames
        if is_control_frame(&event.opcode) {
            return AgentResponse::websocket_allow();
        }

        // Inspect content based on opcode
        let mut all_detections = Vec::new();
        let mut validation_errors = Vec::new();

        match event.opcode.as_str() {
            opcode::TEXT | opcode::CONTINUATION => {
                // Text frame - inspect as string
                if let Ok(text) = std::str::from_utf8(&data) {
                    // Content inspection
                    let detections = state.content_inspector.inspect_text(text);
                    all_detections.extend(detections);

                    // JSON Schema validation
                    if let Some(ref validator) = state.json_validator {
                        let result = validator.validate_str(text);
                        if !result.valid {
                            validation_errors.extend(result.errors);
                        }
                    }
                }
            }
            opcode::BINARY => {
                // Binary frame
                // Content inspection (if enabled for binary)
                let detections = state.content_inspector.inspect_binary(&data);
                all_detections.extend(detections);

                // MessagePack validation
                if let Some(ref validator) = state.msgpack_validator {
                    let result = validator.validate(&data);
                    if !result.valid {
                        validation_errors.extend(result.errors);
                    }
                }
            }
            _ => {}
        }

        // Build response based on detections
        if !all_detections.is_empty() {
            return Self::handle_detections_static(&state.config, &all_detections, correlation_id);
        }

        if !validation_errors.is_empty() {
            return Self::handle_validation_errors_static(
                &state.config,
                &validation_errors,
                correlation_id,
            );
        }

        AgentResponse::websocket_allow()
    }

    /// Check size limits for a frame (static version).
    fn check_size_limits_static(
        config: &WsInspectorConfig,
        opcode: &str,
        size: usize,
    ) -> Option<AgentResponse> {
        let limit = match opcode {
            opcode::TEXT | opcode::CONTINUATION => config.max_text_frame_size,
            opcode::BINARY => config.max_binary_frame_size,
            _ => 0,
        };

        if limit > 0 && size > limit {
            debug!(
                opcode = opcode,
                size = size,
                limit = limit,
                "Frame exceeds size limit"
            );

            if config.block_mode {
                return Some(
                    AgentResponse::default_allow()
                        .with_websocket_decision(WebSocketDecision::Close {
                            code: close_code::MESSAGE_TOO_BIG,
                            reason: "Message too large".to_string(),
                        })
                        .with_audit(AuditMetadata {
                            tags: vec!["ws-size-limit".to_string()],
                            ..Default::default()
                        }),
                );
            } else {
                return Some(
                    AgentResponse::websocket_allow().with_audit(AuditMetadata {
                        tags: vec!["ws-size-limit".to_string(), "detect-only".to_string()],
                        ..Default::default()
                    }),
                );
            }
        }

        None
    }

    /// Handle content detections (static version).
    fn handle_detections_static(
        config: &WsInspectorConfig,
        detections: &[Detection],
        correlation_id: &str,
    ) -> AgentResponse {
        let tags: Vec<String> = detections
            .iter()
            .map(|d| d.detection_type.audit_tag().to_string())
            .collect();

        let rule_ids: Vec<String> = detections.iter().map(|d| d.pattern_id.clone()).collect();

        info!(
            correlation_id = %correlation_id,
            detections = ?rule_ids,
            "Content detections found"
        );

        if config.block_mode {
            AgentResponse::default_allow()
                .with_websocket_decision(WebSocketDecision::Drop)
                .with_audit(AuditMetadata {
                    tags,
                    rule_ids,
                    ..Default::default()
                })
        } else {
            let mut tags = tags;
            tags.push("detect-only".to_string());
            AgentResponse::websocket_allow().with_audit(AuditMetadata {
                tags,
                rule_ids,
                ..Default::default()
            })
        }
    }

    /// Handle schema validation errors (static version).
    fn handle_validation_errors_static(
        config: &WsInspectorConfig,
        errors: &[String],
        correlation_id: &str,
    ) -> AgentResponse {
        info!(
            correlation_id = %correlation_id,
            errors = ?errors,
            "Schema validation failed"
        );

        if config.block_mode {
            AgentResponse::default_allow()
                .with_websocket_decision(WebSocketDecision::Drop)
                .with_audit(AuditMetadata {
                    tags: vec!["ws-schema-invalid".to_string()],
                    reason_codes: errors.to_vec(),
                    ..Default::default()
                })
        } else {
            AgentResponse::websocket_allow().with_audit(AuditMetadata {
                tags: vec!["ws-schema-invalid".to_string(), "detect-only".to_string()],
                reason_codes: errors.to_vec(),
                ..Default::default()
            })
        }
    }

    /// Handle processing errors (static version).
    fn handle_error_static(fail_open: bool, error_type: &str) -> AgentResponse {
        if fail_open {
            AgentResponse::websocket_allow().with_audit(AuditMetadata {
                tags: vec!["ws-error".to_string(), "fail-open".to_string()],
                reason_codes: vec![error_type.to_string()],
                ..Default::default()
            })
        } else {
            AgentResponse::default_allow()
                .with_websocket_decision(WebSocketDecision::Drop)
                .with_audit(AuditMetadata {
                    tags: vec!["ws-error".to_string()],
                    reason_codes: vec![error_type.to_string()],
                    ..Default::default()
                })
        }
    }
}

/// Check if opcode is a control frame (close, ping, pong)
fn is_control_frame(opcode: &str) -> bool {
    matches!(opcode, opcode::CLOSE | opcode::PING | opcode::PONG)
}

#[async_trait]
impl AgentHandler for WsInspectorAgent {
    async fn on_configure(&self, event: ConfigureEvent) -> AgentResponse {
        info!(
            agent_id = %event.agent_id,
            "Received configuration event"
        );

        // Parse the JSON config
        let json_config: WsInspectorConfigJson = match serde_json::from_value(event.config) {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "Failed to parse configuration");
                return AgentResponse::block(
                    500,
                    Some(format!("Invalid agent configuration: {}", e)),
                );
            }
        };

        // Apply the configuration
        if let Err(e) = self.reconfigure(json_config).await {
            warn!(error = %e, "Failed to apply configuration");
            return AgentResponse::block(
                500,
                Some(format!("Failed to apply configuration: {}", e)),
            );
        }

        AgentResponse::default_allow()
    }

    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        // WebSocket inspector only handles WebSocket frames
        AgentResponse::default_allow()
    }

    async fn on_request_body_chunk(&self, _event: RequestBodyChunkEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_response_headers(&self, _event: ResponseHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_response_body_chunk(&self, _event: ResponseBodyChunkEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_request_complete(&self, _event: RequestCompleteEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse {
        self.process_frame(&event).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> WsInspectorConfig {
        WsInspectorConfig {
            xss_detection: true,
            sqli_detection: true,
            command_injection: true,
            block_mode: true,
            ..Default::default()
        }
    }

    fn make_text_frame(data: &str, client_to_server: bool) -> WebSocketFrameEvent {
        WebSocketFrameEvent {
            correlation_id: "test-123".to_string(),
            opcode: "text".to_string(),
            data: BASE64.encode(data),
            client_to_server,
            frame_index: 0,
            fin: true,
            route_id: None,
            client_ip: "127.0.0.1".to_string(),
        }
    }

    #[tokio::test]
    async fn test_clean_message() {
        let agent = WsInspectorAgent::new(test_config()).unwrap();
        let event = make_text_frame("Hello, world!", true);
        let response = agent.on_websocket_frame(event).await;

        assert!(matches!(
            response.websocket_decision,
            Some(WebSocketDecision::Allow)
        ));
    }

    #[tokio::test]
    async fn test_xss_detection() {
        let agent = WsInspectorAgent::new(test_config()).unwrap();
        let event = make_text_frame("<script>alert(1)</script>", true);
        let response = agent.on_websocket_frame(event).await;

        assert!(matches!(
            response.websocket_decision,
            Some(WebSocketDecision::Drop)
        ));
        assert!(response.audit.tags.contains(&"ws-xss".to_string()));
    }

    #[tokio::test]
    async fn test_sqli_detection() {
        let agent = WsInspectorAgent::new(test_config()).unwrap();
        let event = make_text_frame("UNION SELECT * FROM users", true);
        let response = agent.on_websocket_frame(event).await;

        assert!(matches!(
            response.websocket_decision,
            Some(WebSocketDecision::Drop)
        ));
        assert!(response.audit.tags.contains(&"ws-sqli".to_string()));
    }

    #[tokio::test]
    async fn test_detect_only_mode() {
        let config = WsInspectorConfig {
            xss_detection: true,
            block_mode: false, // Detect only
            ..Default::default()
        };
        let agent = WsInspectorAgent::new(config).unwrap();
        let event = make_text_frame("<script>alert(1)</script>", true);
        let response = agent.on_websocket_frame(event).await;

        // Should allow but with detection tags
        assert!(matches!(
            response.websocket_decision,
            Some(WebSocketDecision::Allow)
        ));
        assert!(response.audit.tags.contains(&"ws-xss".to_string()));
        assert!(response.audit.tags.contains(&"detect-only".to_string()));
    }

    #[tokio::test]
    async fn test_size_limit() {
        let config = WsInspectorConfig {
            max_text_frame_size: 10, // Very small limit
            block_mode: true,
            ..Default::default()
        };
        let agent = WsInspectorAgent::new(config).unwrap();
        let event = make_text_frame("This message is way too long", true);
        let response = agent.on_websocket_frame(event).await;

        assert!(matches!(
            response.websocket_decision,
            Some(WebSocketDecision::Close { code: 1009, .. })
        ));
        assert!(response.audit.tags.contains(&"ws-size-limit".to_string()));
    }

    #[tokio::test]
    async fn test_disabled_detection() {
        let config = WsInspectorConfig {
            xss_detection: false,
            sqli_detection: false,
            command_injection: false,
            ..Default::default()
        };
        let agent = WsInspectorAgent::new(config).unwrap();
        let event = make_text_frame("<script>UNION SELECT; ls</script>", true);
        let response = agent.on_websocket_frame(event).await;

        // Should allow since all detection is disabled
        assert!(matches!(
            response.websocket_decision,
            Some(WebSocketDecision::Allow)
        ));
    }

    #[tokio::test]
    async fn test_on_configure_updates_settings() {
        // Start with XSS detection enabled
        let config = WsInspectorConfig {
            xss_detection: true,
            block_mode: true,
            ..Default::default()
        };
        let agent = WsInspectorAgent::new(config).unwrap();

        // Verify XSS is blocked initially
        let event = make_text_frame("<script>alert(1)</script>", true);
        let response = agent.on_websocket_frame(event.clone()).await;
        assert!(matches!(
            response.websocket_decision,
            Some(WebSocketDecision::Drop)
        ));

        // Configure to disable XSS detection
        let configure_event = ConfigureEvent {
            agent_id: "test-agent".to_string(),
            config: serde_json::json!({
                "xss-detection": false
            }),
        };
        let response = agent.on_configure(configure_event).await;
        assert!(matches!(response.decision, sentinel_agent_protocol::Decision::Allow));

        // Verify XSS is now allowed
        let event = make_text_frame("<script>alert(1)</script>", true);
        let response = agent.on_websocket_frame(event).await;
        assert!(matches!(
            response.websocket_decision,
            Some(WebSocketDecision::Allow)
        ));
    }

    #[tokio::test]
    async fn test_on_configure_block_mode() {
        let config = WsInspectorConfig {
            xss_detection: true,
            block_mode: true, // Initially blocking
            ..Default::default()
        };
        let agent = WsInspectorAgent::new(config).unwrap();

        // Verify XSS is blocked initially
        let event = make_text_frame("<script>alert(1)</script>", true);
        let response = agent.on_websocket_frame(event.clone()).await;
        assert!(matches!(
            response.websocket_decision,
            Some(WebSocketDecision::Drop)
        ));

        // Configure to detect-only mode
        let configure_event = ConfigureEvent {
            agent_id: "test-agent".to_string(),
            config: serde_json::json!({
                "block-mode": false
            }),
        };
        let response = agent.on_configure(configure_event).await;
        assert!(matches!(response.decision, sentinel_agent_protocol::Decision::Allow));

        // Verify XSS is detected but allowed (detect-only mode)
        let event = make_text_frame("<script>alert(1)</script>", true);
        let response = agent.on_websocket_frame(event).await;
        assert!(matches!(
            response.websocket_decision,
            Some(WebSocketDecision::Allow)
        ));
        assert!(response.audit.tags.contains(&"ws-xss".to_string()));
        assert!(response.audit.tags.contains(&"detect-only".to_string()));
    }

    #[tokio::test]
    async fn test_on_configure_invalid_json() {
        let config = WsInspectorConfig::default();
        let agent = WsInspectorAgent::new(config).unwrap();

        // Send invalid config type (array instead of object)
        let configure_event = ConfigureEvent {
            agent_id: "test-agent".to_string(),
            config: serde_json::json!([1, 2, 3]),
        };
        let response = agent.on_configure(configure_event).await;

        // Should return a block response with error
        assert!(matches!(
            response.decision,
            sentinel_agent_protocol::Decision::Block { status: 500, .. }
        ));
    }
}
