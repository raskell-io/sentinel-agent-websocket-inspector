//! Content inspection for WebSocket text and binary frames.

use super::patterns::PatternMatcher;
use crate::config::WsInspectorConfig;

/// Type of detection found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectionType {
    Xss,
    Sqli,
    CommandInjection,
    Custom,
}

impl DetectionType {
    /// Get the audit tag for this detection type.
    pub fn audit_tag(&self) -> &'static str {
        match self {
            DetectionType::Xss => "ws-xss",
            DetectionType::Sqli => "ws-sqli",
            DetectionType::CommandInjection => "ws-cmd-injection",
            DetectionType::Custom => "ws-custom-pattern",
        }
    }
}

/// A detection result from content inspection.
#[derive(Debug, Clone)]
pub struct Detection {
    /// Type of detection
    pub detection_type: DetectionType,
    /// Pattern or rule ID that matched
    pub pattern_id: String,
}

impl Detection {
    pub fn new(detection_type: DetectionType, pattern_id: impl Into<String>) -> Self {
        Self {
            detection_type,
            pattern_id: pattern_id.into(),
        }
    }
}

/// Content inspector for WebSocket frames.
pub struct ContentInspector {
    config: WsInspectorConfig,
    matcher: PatternMatcher,
}

impl ContentInspector {
    /// Create a new content inspector with the given configuration.
    pub fn new(config: WsInspectorConfig) -> Self {
        let matcher = PatternMatcher::new(config.custom_patterns.clone());
        Self { config, matcher }
    }

    /// Inspect text content for malicious patterns.
    /// Returns all detections found.
    pub fn inspect_text(&self, text: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        // XSS detection
        if self.config.xss_detection {
            if let Some(pattern_id) = self.matcher.check_xss(text) {
                detections.push(Detection::new(DetectionType::Xss, pattern_id));
            }
        }

        // SQL injection detection
        if self.config.sqli_detection {
            if let Some(pattern_id) = self.matcher.check_sqli(text) {
                detections.push(Detection::new(DetectionType::Sqli, pattern_id));
            }
        }

        // Command injection detection
        if self.config.command_injection {
            if let Some(pattern_id) = self.matcher.check_command_injection(text) {
                detections.push(Detection::new(DetectionType::CommandInjection, pattern_id));
            }
        }

        // Custom patterns
        if let Some(pattern_id) = self.matcher.check_custom(text) {
            detections.push(Detection::new(DetectionType::Custom, pattern_id));
        }

        detections
    }

    /// Inspect binary content for malicious patterns.
    /// Attempts to decode as UTF-8 first, then inspects.
    pub fn inspect_binary(&self, data: &[u8]) -> Vec<Detection> {
        if !self.config.inspect_binary {
            return Vec::new();
        }

        // Try to decode as UTF-8
        match std::str::from_utf8(data) {
            Ok(text) => self.inspect_text(text),
            Err(_) => {
                // Could add binary pattern matching here in the future
                Vec::new()
            }
        }
    }

    /// Check if content inspection is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.has_content_filtering()
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
            custom_patterns: vec![r"password=\w+".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn test_xss_detection() {
        let inspector = ContentInspector::new(test_config());
        let detections = inspector.inspect_text("<script>alert(1)</script>");

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].detection_type, DetectionType::Xss);
    }

    #[test]
    fn test_sqli_detection() {
        let inspector = ContentInspector::new(test_config());
        let detections = inspector.inspect_text("UNION SELECT * FROM users");

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].detection_type, DetectionType::Sqli);
    }

    #[test]
    fn test_command_injection_detection() {
        let inspector = ContentInspector::new(test_config());
        let detections = inspector.inspect_text("; rm -rf /");

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].detection_type, DetectionType::CommandInjection);
    }

    #[test]
    fn test_custom_pattern_detection() {
        let inspector = ContentInspector::new(test_config());
        let detections = inspector.inspect_text("password=secret123");

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].detection_type, DetectionType::Custom);
    }

    #[test]
    fn test_clean_content() {
        let inspector = ContentInspector::new(test_config());
        let detections = inspector.inspect_text("Hello, this is a normal message!");

        assert!(detections.is_empty());
    }

    #[test]
    fn test_multiple_detections() {
        let inspector = ContentInspector::new(test_config());
        // This text contains both XSS and command injection
        let detections = inspector.inspect_text("<script>; ls</script>");

        assert!(detections.len() >= 2);
    }

    #[test]
    fn test_disabled_detection() {
        let config = WsInspectorConfig {
            xss_detection: false,
            sqli_detection: false,
            command_injection: false,
            custom_patterns: vec![],
            ..Default::default()
        };
        let inspector = ContentInspector::new(config);
        let detections = inspector.inspect_text("<script>UNION SELECT; ls</script>");

        assert!(detections.is_empty());
    }
}
