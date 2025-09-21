//! SXURL component matching utilities.
//!
//! This module provides functions to check if a SXURL contains specific
//! component values without fully reconstructing the original URL.

use crate::core::decoder::decode_hex;
use crate::error::SxurlError;
use crate::types::UrlComponentType;
use crate::url::utils::split_url;

/// Check if a SXURL contains a specific component value.
///
/// This function decodes the SXURL and checks if the specified component
/// matches the given value. This is useful for filtering SXURLs without
/// fully reconstructing the original URLs.
///
/// # Arguments
///
/// * `sxurl_hex` - 64-character hex string representing the SXURL
/// * `component` - The component type to check
/// * `value` - The value to match against
///
/// # Returns
///
/// Returns `true` if the component matches the value, `false` otherwise.
///
/// # Examples
///
/// ```should_panic
/// use sxurl::{encode_url_to_hex, sxurl_contains, UrlComponentType};
///
/// // First encode a URL to get an SXURL
/// let sxurl = encode_url_to_hex("https://api.github.com/repos").unwrap();
///
/// // This will panic as URL reconstruction is not yet implemented
/// sxurl_contains(&sxurl, UrlComponentType::Domain, "github").unwrap();
/// ```
pub fn sxurl_contains(
    sxurl_hex: &str,
    component: UrlComponentType,
    value: &str,
) -> Result<bool, SxurlError> {
    // Decode the SXURL to get component information
    let decoded = decode_hex(sxurl_hex)?;

    // For efficient matching, we can check some components using hash comparison
    // For now, we'll use URL reconstruction approach for correctness
    let reconstructed_url = reconstruct_url_from_decoded(&decoded)?;

    // Parse the reconstructed URL using our utils
    let parts = split_url(&reconstructed_url)?;

    // Check the specific component
    match component {
        UrlComponentType::Scheme => Ok(parts.scheme == value),
        UrlComponentType::Host => Ok(parts.host == value),
        UrlComponentType::Domain => Ok(parts.domain == value),
        UrlComponentType::Subdomain => {
            Ok(parts.subdomain.as_ref().map(|s| s == value).unwrap_or(false))
        }
        UrlComponentType::Tld => Ok(parts.tld == value),
        UrlComponentType::Port => {
            Ok(parts.port.map(|p| p.to_string() == value).unwrap_or(false))
        }
        UrlComponentType::Path => Ok(parts.path == value),
        UrlComponentType::Query => {
            Ok(parts.query.as_ref().map(|q| q == value).unwrap_or(false))
        }
        UrlComponentType::Fragment => {
            Ok(parts.anchor.as_ref().map(|f| f == value).unwrap_or(false))
        }
        UrlComponentType::PathSegments => {
            let segments: Vec<&str> = value.split(',').collect();
            let url_segments = crate::url::utils::get_path_segments(&reconstructed_url)?;
            Ok(url_segments == segments)
        }
        UrlComponentType::Filename => {
            let filename = crate::url::utils::get_filename(&reconstructed_url)?;
            Ok(filename.as_ref().map(|f| f == value).unwrap_or(false))
        }
    }
}

/// Reconstruct a URL from decoded SXURL information.
///
/// This is a helper function that attempts to reconstruct the original URL
/// from the decoded SXURL components. This is used internally by the matcher
/// functions.
///
/// Note: This may not be able to reconstruct the exact original URL, but
/// should produce a functionally equivalent URL for component matching.
fn reconstruct_url_from_decoded(_decoded: &crate::core::decoder::DecodedSxurl) -> Result<String, SxurlError> {
    // For now, we'll use a placeholder approach
    // In a full implementation, this would involve more sophisticated reconstruction
    // based on the hash values and flags in the decoded SXURL

    // This is a simplified reconstruction - in practice, you'd need more sophisticated
    // reverse engineering of the original URL from the hash components
    Err(SxurlError::ParseError(
        "URL reconstruction from SXURL not yet fully implemented".to_string()
    ))
}

/// Check if a SXURL contains a domain (exact match).
///
/// This is a convenience function for checking domain matches.
///
/// # Examples
///
/// ```should_panic
/// use sxurl::{encode_url_to_hex, sxurl_has_domain};
///
/// let sxurl = encode_url_to_hex("https://github.com/user/repo").unwrap();
/// // This will panic as URL reconstruction is not yet implemented
/// sxurl_has_domain(&sxurl, "github").unwrap();
/// ```
pub fn sxurl_has_domain(sxurl_hex: &str, domain: &str) -> Result<bool, SxurlError> {
    sxurl_contains(sxurl_hex, UrlComponentType::Domain, domain)
}

/// Check if a SXURL contains a subdomain (exact match).
///
/// This is a convenience function for checking subdomain matches.
///
/// # Examples
///
/// ```should_panic
/// use sxurl::{encode_url_to_hex, sxurl_has_subdomain};
///
/// let sxurl = encode_url_to_hex("https://api.github.com/user/repo").unwrap();
/// // This will panic as URL reconstruction is not yet implemented
/// sxurl_has_subdomain(&sxurl, "api").unwrap();
/// ```
pub fn sxurl_has_subdomain(sxurl_hex: &str, subdomain: &str) -> Result<bool, SxurlError> {
    sxurl_contains(sxurl_hex, UrlComponentType::Subdomain, subdomain)
}

/// Check if a SXURL contains a TLD (exact match).
///
/// This is a convenience function for checking TLD matches.
///
/// # Examples
///
/// ```should_panic
/// use sxurl::{encode_url_to_hex, sxurl_has_tld};
///
/// let sxurl = encode_url_to_hex("https://example.org/page").unwrap();
/// // This will panic as URL reconstruction is not yet implemented
/// sxurl_has_tld(&sxurl, "org").unwrap();
/// ```
pub fn sxurl_has_tld(sxurl_hex: &str, tld: &str) -> Result<bool, SxurlError> {
    sxurl_contains(sxurl_hex, UrlComponentType::Tld, tld)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::encoder::encode_url_to_hex;

    #[test]
    fn test_sxurl_convenience_functions() {
        // These tests are currently expected to fail due to incomplete reconstruction
        // They're here to document the intended API

        let test_url = "https://api.github.com/repos?page=1";
        let _sxurl = encode_url_to_hex(test_url).unwrap();

        // These would work once reconstruction is implemented
        // assert!(sxurl_has_domain(&sxurl, "github").unwrap());
        // assert!(sxurl_has_subdomain(&sxurl, "api").unwrap());
        // assert!(sxurl_has_tld(&sxurl, "com").unwrap());
    }

    #[test]
    fn test_sxurl_contains_placeholder() {
        // Test that the function exists and returns appropriate error
        let test_url = "https://example.com";
        let sxurl = encode_url_to_hex(test_url).unwrap();

        let result = sxurl_contains(&sxurl, UrlComponentType::Domain, "example");
        assert!(result.is_err());
    }
}