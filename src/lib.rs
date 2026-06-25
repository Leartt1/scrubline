//! scrubline — secrets and PII never leave the pipe.
//!
//! A streaming, structured-log-aware redaction filter: read a stream on stdin,
//! mask secrets/tokens/PII, write the cleaned stream to stdout. Never buffers
//! the whole stream.

pub mod detector;
pub mod engine;
pub mod entropy;
pub mod hook;
pub mod json;
pub mod keys;
pub mod logfmt;
pub mod mask;
pub mod patterns;
pub mod span;
