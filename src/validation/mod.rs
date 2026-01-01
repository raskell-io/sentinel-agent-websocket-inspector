//! Message validation for WebSocket frames.

mod json_schema;
mod msgpack;

pub use json_schema::JsonSchemaValidator;
pub use msgpack::MsgpackValidator;

/// Result of schema validation.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the message is valid
    pub valid: bool,
    /// Validation errors if any
    pub errors: Vec<String>,
}

impl ValidationResult {
    pub fn valid() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
        }
    }

    pub fn invalid(errors: Vec<String>) -> Self {
        Self {
            valid: false,
            errors,
        }
    }
}
