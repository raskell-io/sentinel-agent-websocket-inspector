//! MessagePack validation for WebSocket binary messages.

use super::ValidationResult;
use serde_json::Value;

/// MessagePack validator for WebSocket binary messages.
#[derive(Clone, Default)]
pub struct MsgpackValidator {
    /// Optional JSON Schema validator for decoded messages
    json_validator: Option<super::JsonSchemaValidator>,
}

impl MsgpackValidator {
    /// Create a new MessagePack validator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a MessagePack validator with JSON Schema validation for decoded content.
    pub fn with_schema(validator: super::JsonSchemaValidator) -> Self {
        Self {
            json_validator: Some(validator),
        }
    }

    /// Decode and validate a MessagePack binary message.
    pub fn validate(&self, data: &[u8]) -> ValidationResult {
        // Try to decode MessagePack to JSON Value
        let value: Value = match rmp_serde::from_slice(data) {
            Ok(v) => v,
            Err(e) => {
                return ValidationResult::invalid(vec![format!("Invalid MessagePack: {}", e)]);
            }
        };

        // If we have a JSON schema validator, validate against it
        if let Some(ref validator) = self.json_validator {
            validator.validate(&value)
        } else {
            // Just check that it's valid MessagePack
            ValidationResult::valid()
        }
    }

    /// Decode MessagePack to JSON for inspection.
    pub fn decode_to_json(&self, data: &[u8]) -> Option<Value> {
        rmp_serde::from_slice(data).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_valid_msgpack() {
        let validator = MsgpackValidator::new();

        // Create a valid MessagePack message
        let value = json!({"type": "message", "data": "hello"});
        let encoded = rmp_serde::to_vec(&value).unwrap();

        let result = validator.validate(&encoded);
        assert!(result.valid);
    }

    #[test]
    fn test_invalid_msgpack() {
        let validator = MsgpackValidator::new();

        // Invalid MessagePack data - truncated array header
        let result = validator.validate(&[0xDD, 0x00, 0x00]); // Array32 with incomplete length
        assert!(!result.valid);
        assert!(result.errors[0].contains("Invalid MessagePack"));
    }

    #[test]
    fn test_decode_to_json() {
        let validator = MsgpackValidator::new();

        let value = json!({"key": "value", "number": 42});
        let encoded = rmp_serde::to_vec(&value).unwrap();

        let decoded = validator.decode_to_json(&encoded);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), value);
    }

    #[test]
    fn test_with_schema_validation() {
        let schema = json!({
            "type": "object",
            "required": ["type"],
            "properties": {
                "type": {"type": "string"}
            }
        });

        let json_validator =
            super::super::JsonSchemaValidator::from_schema(schema).unwrap();
        let validator = MsgpackValidator::with_schema(json_validator);

        // Valid message
        let valid_msg = json!({"type": "test"});
        let encoded = rmp_serde::to_vec(&valid_msg).unwrap();
        let result = validator.validate(&encoded);
        assert!(result.valid);

        // Invalid message (missing required field)
        let invalid_msg = json!({"other": "field"});
        let encoded = rmp_serde::to_vec(&invalid_msg).unwrap();
        let result = validator.validate(&encoded);
        assert!(!result.valid);
    }
}
