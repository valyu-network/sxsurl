//! SXURL encoding functionality.
//!
//! This module provides the main API for encoding URLs into SXURL format.

use crate::error::SxurlError;
use crate::normalizer::normalize_url;
use crate::psl::extract_url_components;
use crate::packer::{pack_sxurl, sxurl_to_hex};

/// Encode a URL string into SXURL format.
///
/// This is the main entry point for SXURL encoding. It takes a URL string,
/// normalizes it, extracts components, and packs them into the 256-bit SXURL format.
///
/// # Arguments
///
/// * `url` - The URL string to encode
///
/// # Returns
///
/// Returns the SXURL as a 32-byte array, or an error if encoding fails.
///
/// # Examples
///
/// ```
/// use sxurl::encode_url;
///
/// let sxurl_bytes = encode_url("https://example.com/path?q=test").unwrap();
/// assert_eq!(sxurl_bytes.len(), 32);
/// ```
pub fn encode_url(url: &str) -> Result<[u8; 32], SxurlError> {
    // Step 1: Normalize the URL
    let normalized_url = normalize_url(url)?;

    // Step 2: Extract components
    let components = extract_url_components(&normalized_url)?;

    // Step 3: Pack into SXURL format
    pack_sxurl(&components)
}

/// Encode a URL string into SXURL hex format.
///
/// This is a convenience function that encodes a URL and returns the result
/// as a 64-character hex string.
///
/// # Arguments
///
/// * `url` - The URL string to encode
///
/// # Returns
///
/// Returns the SXURL as a 64-character hex string, or an error if encoding fails.
///
/// # Examples
///
/// ```
/// use sxurl::encode_url_to_hex;
///
/// let sxurl_hex = encode_url_to_hex("https://example.com/").unwrap();
/// assert_eq!(sxurl_hex.len(), 64);
/// assert!(sxurl_hex.starts_with("100")); // HTTPS with no flags
/// ```
pub fn encode_url_to_hex(url: &str) -> Result<String, SxurlError> {
    let sxurl_bytes = encode_url(url)?;
    Ok(sxurl_to_hex(&sxurl_bytes))
}

/// SXURL encoder with configurable options.
///
/// This struct provides a more flexible encoding interface with options
/// for different encoding behaviors.
pub struct SxurlEncoder {
    // Future: Add configuration options like custom PSL, hash truncation, etc.
}

impl SxurlEncoder {
    /// Create a new SXURL encoder with default settings.
    pub fn new() -> Self {
        Self {}
    }

    /// Encode a URL using this encoder's configuration.
    pub fn encode(&self, url: &str) -> Result<[u8; 32], SxurlError> {
        encode_url(url)
    }

    /// Encode a URL to hex format using this encoder's configuration.
    pub fn encode_to_hex(&self, url: &str) -> Result<String, SxurlError> {
        encode_url_to_hex(url)
    }
}

impl Default for SxurlEncoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_url_basic() {
        let result = encode_url("https://example.com/");
        assert!(result.is_ok());

        let sxurl = result.unwrap();
        assert_eq!(sxurl.len(), 32);
    }

    #[test]
    fn test_encode_url_to_hex() {
        let result = encode_url_to_hex("https://example.com/");
        assert!(result.is_ok());

        let hex = result.unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.starts_with("100")); // HTTPS with no flags
    }

    #[test]
    fn test_encode_url_with_params() {
        let result = encode_url_to_hex("https://google.com/search?q=test");
        assert!(result.is_ok());

        let hex = result.unwrap();
        assert!(hex.starts_with("108")); // HTTPS with params flag
    }

    #[test]
    fn test_encode_invalid_scheme() {
        let result = encode_url("ws://example.com/");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SxurlError::InvalidScheme));
    }

    #[test]
    fn test_encoder_struct() {
        let encoder = SxurlEncoder::new();
        let result = encoder.encode_to_hex("https://docs.rs/");
        assert!(result.is_ok());

        let hex = result.unwrap();
        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn test_encoder_default() {
        let encoder = SxurlEncoder::default();
        let result = encoder.encode("https://example.com/");
        assert!(result.is_ok());
    }

    #[test]
    fn test_normalize_and_encode() {
        // Test that normalization works correctly during encoding
        let result1 = encode_url_to_hex("HTTPS://EXAMPLE.COM/Path");
        let result2 = encode_url_to_hex("https://example.com/Path");

        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert_eq!(result1.unwrap(), result2.unwrap());
    }

    #[test]
    fn test_idna_encoding() {
        // Test that IDNA domains work
        let result = encode_url("https://café.com/test");
        assert!(result.is_ok());
    }

    #[test]
    fn test_psl_integration() {
        // Test that PSL splitting works correctly
        let result = encode_url_to_hex("https://api.example.co.uk/test");
        assert!(result.is_ok());

        // Should have subdomain flag set
        let hex = result.unwrap();
        let header_bits = u16::from_str_radix(&hex[0..3], 16).unwrap();
        let sub_present = (header_bits & (1 << 4)) != 0;
        assert!(sub_present, "Subdomain flag should be set for api.example.co.uk");
    }
}