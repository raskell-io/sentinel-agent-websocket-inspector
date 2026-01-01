//! Content inspection for WebSocket frames.

mod content;
mod patterns;

pub use content::{ContentInspector, Detection, DetectionType};
pub use patterns::PatternMatcher;
