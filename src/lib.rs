//! scrubline — secrets and PII never leave the pipe.
//!
//! A streaming, structured-log-aware redaction filter: read a stream on stdin,
//! mask secrets/tokens/PII, write the cleaned stream to stdout. Never buffers
//! the whole stream.
