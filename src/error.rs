//! Error types for SXURL encoding and decoding operations.

use thiserror::Error;

/// Errors that can occur during SXURL encoding or decoding operations.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum SxurlError {
    /// The URL scheme is not supported. Only https, http, and ftp are supported.
    #[error("Invalid scheme: only https, http, and ftp are supported")]
    InvalidScheme,

    /// The host is not a valid DNS name or is an IP address.
    #[error("Host must be a valid DNS name, not an IP address")]
    HostNotDns,

    /// The hostname exceeds the maximum allowed length of 255 bytes.
    #[error("Hostname exceeds maximum length of 255 bytes")]
    HostTooLong,

    /// A DNS label is invalid (empty, too long, or contains invalid characters).
    #[error("Invalid DNS label: {0}")]
    InvalidLabel(String),

    /// A DNS label contains invalid characters.
    #[error("DNS label contains invalid characters")]
    InvalidCharacter,

    /// The port number is invalid (must be 1-65535).
    #[error("Invalid port number: must be between 1 and 65535")]
    InvalidPort,

    /// URL parsing failed.
    #[error("URL parsing failed: {0}")]
    ParseError(String),

    /// URL parsing failed using the url crate.
    #[error("URL parsing error: {0}")]
    UrlParseError(String),

    /// The SXURL string has invalid length (must be 64 hex characters).
    #[error("Invalid SXURL length: expected 64 hex characters")]
    InvalidLength,

    /// The SXURL string contains non-hexadecimal characters.
    #[error("SXURL contains invalid hex characters")]
    InvalidHexCharacter,

    /// The SXURL header format is invalid.
    #[error("Invalid SXURL header format")]
    InvalidHeader,

    /// The SXURL version is not supported.
    #[error("Unsupported SXURL version: {0}")]
    UnsupportedVersion(u16),

    /// A reserved bit is set in the SXURL header.
    #[error("Reserved bit is set in SXURL header")]
    ReservedBitSet,

    /// Port presence flag doesn't match the port field.
    #[error("Port presence flag doesn't match port field")]
    PortFlagMismatch,

    /// SHA-256 hashing operation failed.
    #[error("SHA-256 hashing failed")]
    HashingError,

    /// An unexpected internal error occurred.
    #[error("Internal error occurred")]
    InternalError,
}

impl From<url::ParseError> for SxurlError {
    fn from(err: url::ParseError) -> Self {
        SxurlError::UrlParseError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        assert_eq!(
            SxurlError::InvalidScheme.to_string(),
            "Invalid scheme: only https, http, and ftp are supported"
        );

        assert_eq!(
            SxurlError::HostTooLong.to_string(),
            "Hostname exceeds maximum length of 255 bytes"
        );
    }

    #[test]
    fn test_error_equality() {
        assert_eq!(SxurlError::InvalidScheme, SxurlError::InvalidScheme);
        assert_ne!(SxurlError::InvalidScheme, SxurlError::HostNotDns);
    }

    #[test]
    fn test_url_parse_error_conversion() {
        let url_error = url::ParseError::EmptyHost;
        let sxurl_error: SxurlError = url_error.into();

        match sxurl_error {
            SxurlError::UrlParseError(_) => (),
            _ => panic!("Expected UrlParseError variant"),
        }
    }
}