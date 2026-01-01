//! Regex pattern matching for content inspection.

use regex::Regex;
use std::sync::OnceLock;

/// XSS detection patterns
static XSS_PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();

/// SQL injection detection patterns
static SQLI_PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();

/// Command injection detection patterns
static CMD_PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();

fn get_xss_patterns() -> &'static Vec<(Regex, &'static str)> {
    XSS_PATTERNS.get_or_init(|| {
        vec![
            // Script tags
            (
                Regex::new(r"(?i)<\s*script").unwrap(),
                "xss-script-tag",
            ),
            (
                Regex::new(r"(?i)</\s*script").unwrap(),
                "xss-script-close",
            ),
            // Event handlers
            (
                Regex::new(r"(?i)\bon\w+\s*=").unwrap(),
                "xss-event-handler",
            ),
            // JavaScript URI
            (
                Regex::new(r"(?i)javascript\s*:").unwrap(),
                "xss-javascript-uri",
            ),
            // Data URI with HTML
            (
                Regex::new(r"(?i)data\s*:\s*text/html").unwrap(),
                "xss-data-uri",
            ),
            // VBScript (for completeness)
            (
                Regex::new(r"(?i)vbscript\s*:").unwrap(),
                "xss-vbscript-uri",
            ),
            // Expression (old IE)
            (
                Regex::new(r"(?i)expression\s*\(").unwrap(),
                "xss-expression",
            ),
            // SVG onload
            (
                Regex::new(r"(?i)<\s*svg[^>]*\s+onload\s*=").unwrap(),
                "xss-svg-onload",
            ),
            // Iframe injection
            (
                Regex::new(r"(?i)<\s*iframe").unwrap(),
                "xss-iframe",
            ),
            // Object/embed tags
            (
                Regex::new(r"(?i)<\s*(object|embed)").unwrap(),
                "xss-object-embed",
            ),
        ]
    })
}

fn get_sqli_patterns() -> &'static Vec<(Regex, &'static str)> {
    SQLI_PATTERNS.get_or_init(|| {
        vec![
            // UNION-based injection
            (
                Regex::new(r"(?i)\bUNION\s+(ALL\s+)?SELECT\b").unwrap(),
                "sqli-union-select",
            ),
            // Tautology attacks
            (
                Regex::new(r"(?i)\bOR\s+1\s*=\s*1").unwrap(),
                "sqli-or-1eq1",
            ),
            (
                Regex::new(r"(?i)'\s*OR\s*'").unwrap(),
                "sqli-or-string-eq",
            ),
            (
                Regex::new(r"(?i)\bAND\s+1\s*=\s*1").unwrap(),
                "sqli-and-1eq1",
            ),
            // Comment injection
            (
                Regex::new(r"--\s*$").unwrap(),
                "sqli-comment-dash",
            ),
            (
                Regex::new(r"/\*.*\*/").unwrap(),
                "sqli-comment-block",
            ),
            (
                Regex::new(r"#\s*$").unwrap(),
                "sqli-comment-hash",
            ),
            // Time-based blind injection
            (
                Regex::new(r"(?i)\bSLEEP\s*\(").unwrap(),
                "sqli-sleep",
            ),
            (
                Regex::new(r"(?i)\bBENCHMARK\s*\(").unwrap(),
                "sqli-benchmark",
            ),
            (
                Regex::new(r"(?i)\bWAITFOR\s+DELAY\b").unwrap(),
                "sqli-waitfor",
            ),
            // Stacked queries
            (
                Regex::new(r";\s*(DROP|DELETE|UPDATE|INSERT|ALTER|CREATE|TRUNCATE)\b").unwrap(),
                "sqli-stacked-query",
            ),
            // Information schema access
            (
                Regex::new(r"(?i)\bINFORMATION_SCHEMA\b").unwrap(),
                "sqli-info-schema",
            ),
            // Hex encoding
            (
                Regex::new(r"(?i)0x[0-9a-f]+").unwrap(),
                "sqli-hex-encoding",
            ),
        ]
    })
}

fn get_cmd_patterns() -> &'static Vec<(Regex, &'static str)> {
    CMD_PATTERNS.get_or_init(|| {
        vec![
            // Shell command chaining
            (
                Regex::new(r";\s*\w+").unwrap(),
                "cmd-semicolon-chain",
            ),
            (
                Regex::new(r"\|\s*\w+").unwrap(),
                "cmd-pipe-chain",
            ),
            (
                Regex::new(r"&&\s*\w+").unwrap(),
                "cmd-and-chain",
            ),
            (
                Regex::new(r"\|\|\s*\w+").unwrap(),
                "cmd-or-chain",
            ),
            // Command substitution
            (
                Regex::new(r"`[^`]+`").unwrap(),
                "cmd-backtick",
            ),
            (
                Regex::new(r"\$\([^)]+\)").unwrap(),
                "cmd-dollar-paren",
            ),
            // Common dangerous commands
            (
                Regex::new(r"(?i)\b(cat|head|tail|less|more)\s+/etc/").unwrap(),
                "cmd-etc-access",
            ),
            (
                Regex::new(r"(?i)\b(rm|del|rmdir)\s+-[rf]").unwrap(),
                "cmd-destructive",
            ),
            (
                Regex::new(r"(?i)\b(wget|curl)\s+http").unwrap(),
                "cmd-download",
            ),
            (
                Regex::new(r"(?i)\b(nc|netcat|ncat)\s+-").unwrap(),
                "cmd-netcat",
            ),
            // Reverse shell patterns
            (
                Regex::new(r"(?i)/bin/(ba)?sh\s+-[ic]").unwrap(),
                "cmd-reverse-shell",
            ),
            (
                Regex::new(r"(?i)\bexec\s+\d+<>/dev/tcp/").unwrap(),
                "cmd-bash-reverse",
            ),
        ]
    })
}

/// Pattern matcher for content inspection.
pub struct PatternMatcher {
    custom_patterns: Vec<(Regex, String)>,
}

impl PatternMatcher {
    /// Create a new pattern matcher with optional custom patterns.
    pub fn new(custom_patterns: Vec<String>) -> Self {
        let compiled: Vec<(Regex, String)> = custom_patterns
            .into_iter()
            .enumerate()
            .filter_map(|(i, pattern)| {
                match Regex::new(&pattern) {
                    Ok(re) => Some((re, format!("custom-{}", i))),
                    Err(e) => {
                        tracing::warn!(pattern = %pattern, error = %e, "Invalid custom pattern");
                        None
                    }
                }
            })
            .collect();

        Self {
            custom_patterns: compiled,
        }
    }

    /// Check for XSS patterns in text.
    pub fn check_xss(&self, text: &str) -> Option<&'static str> {
        for (pattern, name) in get_xss_patterns() {
            if pattern.is_match(text) {
                return Some(name);
            }
        }
        None
    }

    /// Check for SQL injection patterns in text.
    pub fn check_sqli(&self, text: &str) -> Option<&'static str> {
        for (pattern, name) in get_sqli_patterns() {
            if pattern.is_match(text) {
                return Some(name);
            }
        }
        None
    }

    /// Check for command injection patterns in text.
    pub fn check_command_injection(&self, text: &str) -> Option<&'static str> {
        for (pattern, name) in get_cmd_patterns() {
            if pattern.is_match(text) {
                return Some(name);
            }
        }
        None
    }

    /// Check for custom patterns in text.
    pub fn check_custom(&self, text: &str) -> Option<String> {
        for (pattern, name) in &self.custom_patterns {
            if pattern.is_match(text) {
                return Some(name.clone());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xss_detection() {
        let matcher = PatternMatcher::new(vec![]);

        // Should detect
        assert!(matcher.check_xss("<script>alert(1)</script>").is_some());
        assert!(matcher.check_xss("onclick=alert(1)").is_some());
        assert!(matcher.check_xss("javascript:alert(1)").is_some());
        assert!(matcher.check_xss("<iframe src=x>").is_some());

        // Should not detect
        assert!(matcher.check_xss("Hello, world!").is_none());
        assert!(matcher.check_xss("SELECT * FROM users").is_none());
    }

    #[test]
    fn test_sqli_detection() {
        let matcher = PatternMatcher::new(vec![]);

        // Should detect
        assert!(matcher.check_sqli("UNION SELECT * FROM users").is_some());
        assert!(matcher.check_sqli("1' OR '1'='1").is_some());
        assert!(matcher.check_sqli("1; DROP TABLE users--").is_some());
        assert!(matcher.check_sqli("SLEEP(5)").is_some());

        // Should not detect
        assert!(matcher.check_sqli("Hello, world!").is_none());
        assert!(matcher.check_sqli("<script>alert(1)</script>").is_none());
    }

    #[test]
    fn test_command_injection_detection() {
        let matcher = PatternMatcher::new(vec![]);

        // Should detect
        assert!(matcher.check_command_injection("; ls -la").is_some());
        assert!(matcher.check_command_injection("| cat /etc/passwd").is_some());
        assert!(matcher.check_command_injection("`whoami`").is_some());
        assert!(matcher.check_command_injection("$(id)").is_some());

        // Should not detect
        assert!(matcher.check_command_injection("Hello, world!").is_none());
    }

    #[test]
    fn test_custom_patterns() {
        let matcher = PatternMatcher::new(vec![
            r"secret-key-\d+".to_string(),
            r"password=\w+".to_string(),
        ]);

        assert!(matcher.check_custom("secret-key-12345").is_some());
        assert!(matcher.check_custom("password=hunter2").is_some());
        assert!(matcher.check_custom("Hello, world!").is_none());
    }
}
