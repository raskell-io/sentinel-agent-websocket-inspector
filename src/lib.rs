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
    AgentHandler, AgentResponse, AuditMetadata, RequestBodyChunkEvent, RequestCompleteEvent,
    RequestHeadersEvent, ResponseBodyChunkEvent, ResponseHeadersEvent, WebSocketDecision,
    WebSocketFrameEvent,
};
use tracing::{debug, info, warn};
use validation::{JsonSchemaValidator, MsgpackValidator};

pub use config::WsInspectorConfig as Config;

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

/// WebSocket Inspector Agent.
pub struct WsInspectorAgent {
    config: WsInspectorConfig,
    content_inspector: ContentInspector,
    json_validator: Option<JsonSchemaValidator>,
    msgpack_validator: Option<MsgpackValidator>,
    rate_limiter: RateLimiter,
}

impl WsInspectorAgent {
    /// Create a new WebSocket Inspector agent.
    pub fn new(config: WsInspectorConfig) -> anyhow::Result<Self> {
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

        Ok(Self {
            config,
            content_inspector,
            json_validator,
            msgpack_validator,
            rate_limiter,
        })
    }

    /// Process a WebSocket frame and return a decision.
    async fn process_frame(&self, event: &WebSocketFrameEvent) -> AgentResponse {
        let correlation_id = &event.correlation_id;
        let direction = if event.client_to_server {
            "client→server"
        } else {
            "server→client"
        };

        if self.config.log_frames {
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
                return self.handle_error("decode-error");
            }
        };

        // Check size limits
        if let Some(response) = self.check_size_limits(&event.opcode, data.len()) {
            return response;
        }

        // Check rate limits
        if let Some(response) = self.check_rate_limits(correlation_id, data.len() as u64).await {
            return response;
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
                    let detections = self.content_inspector.inspect_text(text);
                    all_detections.extend(detections);

                    // JSON Schema validation
                    if let Some(ref validator) = self.json_validator {
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
                let detections = self.content_inspector.inspect_binary(&data);
                all_detections.extend(detections);

                // MessagePack validation
                if let Some(ref validator) = self.msgpack_validator {
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
            return self.handle_detections(&all_detections, correlation_id);
        }

        if !validation_errors.is_empty() {
            return self.handle_validation_errors(&validation_errors, correlation_id);
        }

        AgentResponse::websocket_allow()
    }

    /// Check size limits for a frame.
    fn check_size_limits(&self, opcode: &str, size: usize) -> Option<AgentResponse> {
        let limit = match opcode {
            opcode::TEXT | opcode::CONTINUATION => self.config.max_text_frame_size,
            opcode::BINARY => self.config.max_binary_frame_size,
            _ => 0,
        };

        if limit > 0 && size > limit {
            debug!(
                opcode = opcode,
                size = size,
                limit = limit,
                "Frame exceeds size limit"
            );

            if self.config.block_mode {
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

    /// Check rate limits for a connection.
    async fn check_rate_limits(
        &self,
        correlation_id: &str,
        message_bytes: u64,
    ) -> Option<AgentResponse> {
        let result = self
            .rate_limiter
            .check_and_record(correlation_id, message_bytes)
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

            if self.config.block_mode {
                return Some(
                    AgentResponse::default_allow()
                        .with_websocket_decision(WebSocketDecision::Close {
                            code: close_code::POLICY_VIOLATION,
                            reason: format!("Rate limit exceeded: {}", exceeded_type),
                        })
                        .with_audit(AuditMetadata {
                            tags: vec!["ws-rate-limit".to_string()],
                            ..Default::default()
                        }),
                );
            } else {
                return Some(
                    AgentResponse::websocket_allow().with_audit(AuditMetadata {
                        tags: vec!["ws-rate-limit".to_string(), "detect-only".to_string()],
                        ..Default::default()
                    }),
                );
            }
        }

        None
    }

    /// Handle content detections.
    fn handle_detections(&self, detections: &[Detection], correlation_id: &str) -> AgentResponse {
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

        if self.config.block_mode {
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

    /// Handle schema validation errors.
    fn handle_validation_errors(&self, errors: &[String], correlation_id: &str) -> AgentResponse {
        info!(
            correlation_id = %correlation_id,
            errors = ?errors,
            "Schema validation failed"
        );

        if self.config.block_mode {
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

    /// Handle processing errors.
    fn handle_error(&self, error_type: &str) -> AgentResponse {
        if self.config.fail_open {
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

// Allow sharing the agent across threads
unsafe impl Send for WsInspectorAgent {}
unsafe impl Sync for WsInspectorAgent {}

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
}
