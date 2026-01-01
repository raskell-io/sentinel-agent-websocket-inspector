//! JSON Schema validation for WebSocket messages.

use super::ValidationResult;
use jsonschema::JSONSchema;
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;

/// JSON Schema validator for WebSocket messages.
pub struct JsonSchemaValidator {
    schema: Arc<JSONSchema>,
}

impl JsonSchemaValidator {
    /// Create a new validator from a schema file.
    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())?;
        let schema: Value = serde_json::from_str(&content)?;
        Self::from_schema(schema)
    }

    /// Create a new validator from a JSON schema value.
    pub fn from_schema(schema: Value) -> anyhow::Result<Self> {
        let compiled = JSONSchema::compile(&schema)
            .map_err(|e| anyhow::anyhow!("Invalid JSON Schema: {}", e))?;

        Ok(Self {
            schema: Arc::new(compiled),
        })
    }

    /// Validate a JSON string against the schema.
    pub fn validate_str(&self, json_str: &str) -> ValidationResult {
        // First, try to parse the JSON
        let value: Value = match serde_json::from_str(json_str) {
            Ok(v) => v,
            Err(e) => {
                return ValidationResult::invalid(vec![format!("Invalid JSON: {}", e)]);
            }
        };

        self.validate(&value)
    }

    /// Validate a JSON value against the schema.
    pub fn validate(&self, value: &Value) -> ValidationResult {
        let result = self.schema.validate(value);

        if result.is_ok() {
            ValidationResult::valid()
        } else {
            let errors: Vec<String> = self
                .schema
                .validate(value)
                .err()
                .into_iter()
                .flatten()
                .map(|e| format!("{} at {}", e, e.instance_path))
                .collect();

            ValidationResult::invalid(errors)
        }
    }
}

impl Clone for JsonSchemaValidator {
    fn clone(&self) -> Self {
        Self {
            schema: Arc::clone(&self.schema),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_schema() -> Value {
        json!({
            "type": "object",
            "required": ["type", "data"],
            "properties": {
                "type": {
                    "type": "string",
                    "enum": ["message", "ping", "pong"]
                },
                "data": {
                    "type": "object"
                },
                "timestamp": {
                    "type": "integer",
                    "minimum": 0
                }
            }
        })
    }

    #[test]
    fn test_valid_message() {
        let validator = JsonSchemaValidator::from_schema(test_schema()).unwrap();
        let result = validator.validate_str(r#"{"type": "message", "data": {}}"#);
        assert!(result.valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_invalid_message_missing_required() {
        let validator = JsonSchemaValidator::from_schema(test_schema()).unwrap();
        let result = validator.validate_str(r#"{"type": "message"}"#);
        assert!(!result.valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_invalid_message_wrong_type() {
        let validator = JsonSchemaValidator::from_schema(test_schema()).unwrap();
        let result = validator.validate_str(r#"{"type": "invalid", "data": {}}"#);
        assert!(!result.valid);
    }

    #[test]
    fn test_invalid_json() {
        let validator = JsonSchemaValidator::from_schema(test_schema()).unwrap();
        let result = validator.validate_str("not json at all");
        assert!(!result.valid);
        assert!(result.errors[0].contains("Invalid JSON"));
    }

    #[test]
    fn test_optional_field_validation() {
        let validator = JsonSchemaValidator::from_schema(test_schema()).unwrap();

        // Valid with optional field
        let result =
            validator.validate_str(r#"{"type": "message", "data": {}, "timestamp": 12345}"#);
        assert!(result.valid);

        // Invalid: negative timestamp
        let result =
            validator.validate_str(r#"{"type": "message", "data": {}, "timestamp": -1}"#);
        assert!(!result.valid);
    }
}
