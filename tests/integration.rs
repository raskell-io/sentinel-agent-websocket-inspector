//! Integration tests for the WebSocket Inspector agent using the sentinel-agent-protocol.
//!
//! These tests spin up an actual AgentServer and connect via AgentClient
//! to verify the full protocol flow.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use sentinel_agent_protocol::{
    AgentClient, AgentServer, EventType, WebSocketDecision, WebSocketFrameEvent,
};
use sentinel_agent_websocket_inspector::{Config, WsInspectorAgent};
use std::time::Duration;
use tempfile::tempdir;

/// Helper to start an agent server and return the socket path
async fn start_test_server(config: Config) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempdir().expect("Failed to create temp dir");
    let socket_path = dir.path().join("ws-test.sock");

    let agent = WsInspectorAgent::new(config).expect("Failed to create agent");
    let server = AgentServer::new("test-ws", socket_path.clone(), Box::new(agent));

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    (dir, socket_path)
}

/// Create a client connected to the test server
async fn create_client(socket_path: &std::path::Path) -> AgentClient {
    AgentClient::unix_socket("test-client", socket_path, Duration::from_secs(5))
        .await
        .expect("Failed to connect to agent")
}

/// Create a text frame event
fn make_text_frame(correlation_id: &str, data: &str, client_to_server: bool) -> WebSocketFrameEvent {
    WebSocketFrameEvent {
        correlation_id: correlation_id.to_string(),
        opcode: "text".to_string(),
        data: BASE64.encode(data),
        client_to_server,
        frame_index: 0,
        fin: true,
        route_id: None,
        client_ip: "127.0.0.1".to_string(),
    }
}

/// Create a binary frame event
fn make_binary_frame(
    correlation_id: &str,
    data: &[u8],
    client_to_server: bool,
) -> WebSocketFrameEvent {
    WebSocketFrameEvent {
        correlation_id: correlation_id.to_string(),
        opcode: "binary".to_string(),
        data: BASE64.encode(data),
        client_to_server,
        frame_index: 0,
        fin: true,
        route_id: None,
        client_ip: "127.0.0.1".to_string(),
    }
}

/// Check if WebSocket decision is Allow
fn is_allow(decision: &Option<WebSocketDecision>) -> bool {
    matches!(decision, Some(WebSocketDecision::Allow))
}

/// Check if WebSocket decision is Drop
fn is_drop(decision: &Option<WebSocketDecision>) -> bool {
    matches!(decision, Some(WebSocketDecision::Drop))
}

/// Check if WebSocket decision is Close with specific code
fn is_close_with_code(decision: &Option<WebSocketDecision>, expected_code: u16) -> bool {
    matches!(
        decision,
        Some(WebSocketDecision::Close { code, .. }) if *code == expected_code
    )
}

// =============================================================================
// Clean Message Tests
// =============================================================================

#[tokio::test]
async fn test_clean_text_message() {
    let config = Config {
        xss_detection: true,
        sqli_detection: true,
        command_injection: true,
        block_mode: true,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    let event = make_text_frame("test-1", "Hello, world!", true);
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.websocket_decision));
    assert!(response.audit.tags.is_empty());
}

#[tokio::test]
async fn test_clean_json_message() {
    let config = Config::default();

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    let json_msg = r#"{"type": "chat", "message": "Hello", "timestamp": 1234567890}"#;
    let event = make_text_frame("test-2", json_msg, true);
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.websocket_decision));
}

// =============================================================================
// XSS Detection Tests
// =============================================================================

#[tokio::test]
async fn test_xss_script_tag_blocked() {
    let config = Config {
        xss_detection: true,
        block_mode: true,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    let event = make_text_frame("test-xss-1", "<script>alert(1)</script>", true);
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    assert!(is_drop(&response.websocket_decision));
    assert!(response.audit.tags.contains(&"ws-xss".to_string()));
}

#[tokio::test]
async fn test_xss_event_handler_blocked() {
    let config = Config {
        xss_detection: true,
        block_mode: true,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    let event = make_text_frame("test-xss-2", "onclick=alert(document.cookie)", true);
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    assert!(is_drop(&response.websocket_decision));
    assert!(response.audit.tags.contains(&"ws-xss".to_string()));
}

#[tokio::test]
async fn test_xss_javascript_uri_blocked() {
    let config = Config {
        xss_detection: true,
        block_mode: true,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    let event = make_text_frame("test-xss-3", "javascript:alert(1)", true);
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    assert!(is_drop(&response.websocket_decision));
    assert!(response.audit.tags.contains(&"ws-xss".to_string()));
}

// =============================================================================
// SQL Injection Detection Tests
// =============================================================================

#[tokio::test]
async fn test_sqli_union_select_blocked() {
    let config = Config {
        sqli_detection: true,
        block_mode: true,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    let event = make_text_frame("test-sqli-1", "UNION SELECT * FROM users", true);
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    assert!(is_drop(&response.websocket_decision));
    assert!(response.audit.tags.contains(&"ws-sqli".to_string()));
}

#[tokio::test]
async fn test_sqli_or_tautology_blocked() {
    let config = Config {
        sqli_detection: true,
        block_mode: true,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    let event = make_text_frame("test-sqli-2", "' OR '1'='1", true);
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    assert!(is_drop(&response.websocket_decision));
    assert!(response.audit.tags.contains(&"ws-sqli".to_string()));
}

#[tokio::test]
async fn test_sqli_time_based_blocked() {
    let config = Config {
        sqli_detection: true,
        block_mode: true,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    let event = make_text_frame("test-sqli-3", "1; WAITFOR DELAY '00:00:10'", true);
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    assert!(is_drop(&response.websocket_decision));
    assert!(response.audit.tags.contains(&"ws-sqli".to_string()));
}

// =============================================================================
// Command Injection Detection Tests
// =============================================================================

#[tokio::test]
async fn test_cmd_injection_semicolon_blocked() {
    let config = Config {
        command_injection: true,
        block_mode: true,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    let event = make_text_frame("test-cmd-1", "; ls -la /etc/passwd", true);
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    assert!(is_drop(&response.websocket_decision));
    assert!(response.audit.tags.contains(&"ws-cmd-injection".to_string()));
}

#[tokio::test]
async fn test_cmd_injection_pipe_blocked() {
    let config = Config {
        command_injection: true,
        block_mode: true,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    let event = make_text_frame("test-cmd-2", "| cat /etc/shadow", true);
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    assert!(is_drop(&response.websocket_decision));
    assert!(response.audit.tags.contains(&"ws-cmd-injection".to_string()));
}

#[tokio::test]
async fn test_cmd_injection_backtick_blocked() {
    let config = Config {
        command_injection: true,
        block_mode: true,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    let event = make_text_frame("test-cmd-3", "`id`", true);
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    assert!(is_drop(&response.websocket_decision));
    assert!(response.audit.tags.contains(&"ws-cmd-injection".to_string()));
}

// =============================================================================
// Detect-Only Mode Tests
// =============================================================================

#[tokio::test]
async fn test_detect_only_allows_with_tags() {
    let config = Config {
        xss_detection: true,
        sqli_detection: true,
        block_mode: false, // Detect only
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    let event = make_text_frame("test-detect", "<script>UNION SELECT</script>", true);
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    // Should allow but with detection tags
    assert!(is_allow(&response.websocket_decision));
    assert!(response.audit.tags.contains(&"detect-only".to_string()));
    // Should have XSS detection tag (first match wins)
    assert!(
        response.audit.tags.contains(&"ws-xss".to_string())
            || response.audit.tags.contains(&"ws-sqli".to_string())
    );
}

// =============================================================================
// Size Limit Tests
// =============================================================================

#[tokio::test]
async fn test_text_frame_size_limit() {
    let config = Config {
        max_text_frame_size: 100, // 100 bytes max
        block_mode: true,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    // Create a message that exceeds the limit
    let large_message = "x".repeat(200);
    let event = make_text_frame("test-size", &large_message, true);
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    // Should close with MESSAGE_TOO_BIG (1009)
    assert!(is_close_with_code(&response.websocket_decision, 1009));
    assert!(response.audit.tags.contains(&"ws-size-limit".to_string()));
}

#[tokio::test]
async fn test_binary_frame_size_limit() {
    let config = Config {
        max_binary_frame_size: 50,
        block_mode: true,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    // Create binary data that exceeds the limit
    let large_data = vec![0u8; 100];
    let event = make_binary_frame("test-binary-size", &large_data, true);
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    // Should close with MESSAGE_TOO_BIG (1009)
    assert!(is_close_with_code(&response.websocket_decision, 1009));
    assert!(response.audit.tags.contains(&"ws-size-limit".to_string()));
}

// =============================================================================
// Rate Limit Tests
// =============================================================================

#[tokio::test]
async fn test_rate_limit_messages_per_sec() {
    let config = Config {
        max_messages_per_sec: 3,
        rate_limit_burst: 0,
        block_mode: true,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    // Send 3 messages - should all be allowed
    for i in 0..3 {
        let event = make_text_frame("rate-test-1", &format!("msg {}", i), true);
        let response = client
            .send_event(EventType::WebSocketFrame, &event)
            .await
            .expect("Failed to send event");
        assert!(is_allow(&response.websocket_decision), "Message {} should be allowed", i);
    }

    // 4th message should be rate limited
    let event = make_text_frame("rate-test-1", "msg 3", true);
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    assert!(is_close_with_code(&response.websocket_decision, 1008)); // POLICY_VIOLATION
    assert!(response.audit.tags.contains(&"ws-rate-limit".to_string()));
}

#[tokio::test]
async fn test_rate_limit_separate_connections() {
    let config = Config {
        max_messages_per_sec: 2,
        rate_limit_burst: 0,
        block_mode: true,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    // Connection 1: Use up the limit
    for _ in 0..2 {
        let event = make_text_frame("conn-1", "msg", true);
        client
            .send_event(EventType::WebSocketFrame, &event)
            .await
            .expect("Failed to send event");
    }

    // Connection 1: 3rd message should be rate limited
    let event = make_text_frame("conn-1", "msg", true);
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");
    assert!(is_close_with_code(&response.websocket_decision, 1008));

    // Connection 2: Should still be allowed
    let event = make_text_frame("conn-2", "msg", true);
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");
    assert!(is_allow(&response.websocket_decision));
}

// =============================================================================
// Detection Disabled Tests
// =============================================================================

#[tokio::test]
async fn test_xss_disabled_allows_attack() {
    let config = Config {
        xss_detection: false,
        sqli_detection: false,
        command_injection: false,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    let event = make_text_frame("test-disabled", "<script>UNION SELECT `id`</script>", true);
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    // Should allow since all detection is disabled
    assert!(is_allow(&response.websocket_decision));
    assert!(response.audit.tags.is_empty());
}

// =============================================================================
// Direction Tests
// =============================================================================

#[tokio::test]
async fn test_server_to_client_inspection() {
    let config = Config {
        xss_detection: true,
        block_mode: true,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    // Server to client message with XSS
    let event = make_text_frame("test-s2c", "<script>bad</script>", false); // false = server→client
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    // Should still detect and block
    assert!(is_drop(&response.websocket_decision));
    assert!(response.audit.tags.contains(&"ws-xss".to_string()));
}

// =============================================================================
// Control Frame Tests
// =============================================================================

#[tokio::test]
async fn test_ping_frame_allowed() {
    let config = Config {
        xss_detection: true,
        sqli_detection: true,
        block_mode: true,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    let event = WebSocketFrameEvent {
        correlation_id: "test-ping".to_string(),
        opcode: "ping".to_string(),
        data: BASE64.encode("<script>"), // Even with XSS payload
        client_to_server: true,
        frame_index: 0,
        fin: true,
        route_id: None,
        client_ip: "127.0.0.1".to_string(),
    };

    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    // Control frames should always be allowed
    assert!(is_allow(&response.websocket_decision));
}

#[tokio::test]
async fn test_pong_frame_allowed() {
    let config = Config {
        xss_detection: true,
        block_mode: true,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    let event = WebSocketFrameEvent {
        correlation_id: "test-pong".to_string(),
        opcode: "pong".to_string(),
        data: BASE64.encode(""),
        client_to_server: false,
        frame_index: 0,
        fin: true,
        route_id: None,
        client_ip: "127.0.0.1".to_string(),
    };

    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.websocket_decision));
}

#[tokio::test]
async fn test_close_frame_allowed() {
    let config = Config {
        xss_detection: true,
        block_mode: true,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    let event = WebSocketFrameEvent {
        correlation_id: "test-close".to_string(),
        opcode: "close".to_string(),
        data: BASE64.encode([0x03, 0xe8]), // 1000 = normal close
        client_to_server: true,
        frame_index: 0,
        fin: true,
        route_id: None,
        client_ip: "127.0.0.1".to_string(),
    };

    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.websocket_decision));
}

// =============================================================================
// Custom Pattern Tests
// =============================================================================

#[tokio::test]
async fn test_custom_pattern_blocked() {
    let config = Config {
        custom_patterns: vec!["secret-api-key-\\d+".to_string()],
        block_mode: true,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    let event = make_text_frame("test-custom", "token: secret-api-key-12345", true);
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    assert!(is_drop(&response.websocket_decision));
    assert!(response.audit.tags.contains(&"ws-custom-pattern".to_string()));
}

// =============================================================================
// Binary Frame Inspection Tests
// =============================================================================

#[tokio::test]
async fn test_binary_inspection_disabled_by_default() {
    let config = Config {
        xss_detection: true,
        inspect_binary: false, // Default
        block_mode: true,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    // Binary frame with XSS-like content
    let event = make_binary_frame("test-binary", b"<script>alert(1)</script>", true);
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    // Binary frames don't get content inspection by default
    assert!(is_allow(&response.websocket_decision));
}

#[tokio::test]
async fn test_binary_inspection_enabled() {
    let config = Config {
        xss_detection: true,
        inspect_binary: true,
        block_mode: true,
        ..Default::default()
    };

    let (_dir, socket_path) = start_test_server(config).await;
    let mut client = create_client(&socket_path).await;

    // Binary frame with XSS content
    let event = make_binary_frame("test-binary-2", b"<script>alert(1)</script>", true);
    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Failed to send event");

    // Should detect XSS when binary inspection is enabled
    assert!(is_drop(&response.websocket_decision));
    assert!(response.audit.tags.contains(&"ws-xss".to_string()));
}
