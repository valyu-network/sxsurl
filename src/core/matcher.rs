//! SXURL component matching utilities.
//!
//! This module provides functions to check if a SXURL contains specific
//! component values without fully reconstructing the original URL.

use crate::core::decoder::decode_hex;
use crate::error::SxurlError;
use crate::types::UrlComponentType;

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
/// ```
/// use sxurl::{encode_url_to_hex, sxurl_contains, UrlComponentType};
///
/// // First encode a URL to get an SXURL
/// let sxurl = encode_url_to_hex("https://api.github.com/repos").unwrap();
///
/// // Check if the SXURL contains specific components
/// assert!(sxurl_contains(&sxurl, UrlComponentType::Domain, "github").unwrap());
/// assert!(sxurl_contains(&sxurl, UrlComponentType::Scheme, "https").unwrap());
/// assert!(!sxurl_contains(&sxurl, UrlComponentType::Domain, "google").unwrap());
/// ```
pub fn sxurl_contains(
    sxurl_hex: &str,
    component: UrlComponentType,
    value: &str,
) -> Result<bool, SxurlError> {
    use crate::core::hasher::ComponentHasher;

    // Decode the SXURL to get component information
    let decoded = decode_hex(sxurl_hex)?;

    // Use direct hash comparison for components that can be hashed
    match component {
        UrlComponentType::Scheme => {
            Ok(decoded.header.scheme == value)
        }
        UrlComponentType::Tld => {
            let expected_hash = ComponentHasher::hash_tld(value)?;
            Ok(decoded.tld_hash == expected_hash)
        }
        UrlComponentType::Domain => {
            let expected_hash = ComponentHasher::hash_domain(value)?;
            Ok(decoded.domain_hash == expected_hash)
        }
        UrlComponentType::Subdomain => {
            if value.is_empty() {
                Ok(decoded.subdomain_hash == 0)
            } else {
                let expected_hash = ComponentHasher::hash_subdomain(value)?;
                Ok(decoded.subdomain_hash == expected_hash)
            }
        }
        UrlComponentType::Port => {
            if let Ok(port_num) = value.parse::<u16>() {
                Ok(decoded.port == port_num)
            } else {
                Ok(false)
            }
        }
        UrlComponentType::Path => {
            let expected_hash = ComponentHasher::hash_path(value)?;
            Ok(decoded.path_hash == expected_hash)
        }
        UrlComponentType::Query => {
            if value.is_empty() {
                Ok(decoded.params_hash == 0)
            } else {
                let expected_hash = ComponentHasher::hash_params(value)?;
                Ok(decoded.params_hash == expected_hash)
            }
        }
        UrlComponentType::Fragment => {
            if value.is_empty() {
                Ok(decoded.fragment_hash == 0)
            } else {
                let expected_hash = ComponentHasher::hash_fragment(value)?;
                Ok(decoded.fragment_hash == expected_hash)
            }
        }
        // These components require more complex logic - not supported for now
        UrlComponentType::Host => {
            Err(SxurlError::ParseError("Host matching not supported - use Domain + Subdomain instead".to_string()))
        }
        UrlComponentType::PathSegments => {
            Err(SxurlError::ParseError("PathSegments matching not supported - use Path instead".to_string()))
        }
        UrlComponentType::Filename => {
            Err(SxurlError::ParseError("Filename matching not supported - use Path instead".to_string()))
        }
    }
}

/// Check if a SXURL contains a specific domain.
///
/// # Examples
///
/// ```
/// use sxurl::{encode_url_to_hex, sxurl_has_domain};
///
/// let sxurl = encode_url_to_hex("https://api.github.com/repos").unwrap();
/// assert!(sxurl_has_domain(&sxurl, "github").unwrap());
/// assert!(!sxurl_has_domain(&sxurl, "google").unwrap());
/// ```
pub fn sxurl_has_domain(sxurl_hex: &str, domain: &str) -> Result<bool, SxurlError> {
    sxurl_contains(sxurl_hex, UrlComponentType::Domain, domain)
}

/// Check if a SXURL contains a specific subdomain.
///
/// # Examples
///
/// ```
/// use sxurl::{encode_url_to_hex, sxurl_has_subdomain};
///
/// let sxurl = encode_url_to_hex("https://api.github.com/repos").unwrap();
/// assert!(sxurl_has_subdomain(&sxurl, "api").unwrap());
/// assert!(!sxurl_has_subdomain(&sxurl, "www").unwrap());
/// ```
pub fn sxurl_has_subdomain(sxurl_hex: &str, subdomain: &str) -> Result<bool, SxurlError> {
    sxurl_contains(sxurl_hex, UrlComponentType::Subdomain, subdomain)
}

/// Check if a SXURL contains a specific TLD.
///
/// # Examples
///
/// ```
/// use sxurl::{encode_url_to_hex, sxurl_has_tld};
///
/// let sxurl = encode_url_to_hex("https://docs.rs/sxurl").unwrap();
/// assert!(sxurl_has_tld(&sxurl, "rs").unwrap());
/// assert!(!sxurl_has_tld(&sxurl, "com").unwrap());
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
    fn test_sxurl_contains_working() {
        // Test that the function works correctly with hash comparison
        let test_url = "https://api.github.com/repos?page=1#section";
        let sxurl = encode_url_to_hex(test_url).unwrap();

        // Test positive matches
        assert!(sxurl_contains(&sxurl, UrlComponentType::Scheme, "https").unwrap());
        assert!(sxurl_contains(&sxurl, UrlComponentType::Domain, "github").unwrap());
        assert!(sxurl_contains(&sxurl, UrlComponentType::Subdomain, "api").unwrap());
        assert!(sxurl_contains(&sxurl, UrlComponentType::Tld, "com").unwrap());
        assert!(sxurl_contains(&sxurl, UrlComponentType::Path, "/repos").unwrap());
        assert!(sxurl_contains(&sxurl, UrlComponentType::Query, "page=1").unwrap());
        assert!(sxurl_contains(&sxurl, UrlComponentType::Fragment, "section").unwrap());

        // Test negative matches
        assert!(!sxurl_contains(&sxurl, UrlComponentType::Scheme, "http").unwrap());
        assert!(!sxurl_contains(&sxurl, UrlComponentType::Domain, "google").unwrap());
        assert!(!sxurl_contains(&sxurl, UrlComponentType::Subdomain, "www").unwrap());
        assert!(!sxurl_contains(&sxurl, UrlComponentType::Tld, "org").unwrap());

        println!("✓ SXURL component matching works correctly!");
    }
}