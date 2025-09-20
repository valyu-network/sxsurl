//! Bit packing functionality for SXURL 256-bit format.
//!
//! This module handles packing URL components into the fixed 256-bit SXURL format
//! according to the specification layout.

use crate::error::SxurlError;
use crate::types::UrlComponents;
use crate::core::hasher::ComponentHasher;

/// Pack URL components into a 256-bit SXURL identifier.
///
/// The SXURL format layout (256 bits total = 64 hex chars) according to SXURL.md specification:
/// - header: [0..3) (3 hex chars = 12 bits) - Version(4) + Scheme(3) + Flags(5)
/// - tld_h: [3..7) (4 hex chars = 16 bits)
/// - domain_h: [7..22) (15 hex chars = 60 bits)
/// - sub_h: [22..30) (8 hex chars = 32 bits)
/// - port: [30..34) (4 hex chars = 16 bits)
/// - path_h: [34..49) (15 hex chars = 60 bits)
/// - params_h: [49..58) (9 hex chars = 36 bits)
/// - frag_h: [58..64) (6 hex chars = 24 bits)
pub fn pack_sxurl(components: &UrlComponents) -> Result<[u8; 32], SxurlError> {
    // Hash all components
    let tld_hash = ComponentHasher::hash_tld(&components.tld)?;
    let domain_hash = ComponentHasher::hash_domain(&components.domain)?;
    let subdomain_hash = if components.subdomain.is_empty() {
        0
    } else {
        ComponentHasher::hash_subdomain(&components.subdomain)?
    };
    let path_hash = ComponentHasher::hash_path(&components.path)?;
    let params_hash = if components.query.is_empty() {
        0
    } else {
        ComponentHasher::hash_params(&components.query)?
    };
    let fragment_hash = if components.fragment.is_empty() {
        0
    } else {
        ComponentHasher::hash_fragment(&components.fragment)?
    };

    // Create header according to SXURL.md specification
    let scheme_code = match components.scheme.as_str() {
        "https" => 0u64,
        "http" => 1u64,
        "ftp" => 2u64,
        _ => return Err(SxurlError::InvalidScheme),
    };

    // Build flags (5 bits): sub_present(4), params_present(3), frag_present(2), port_present(1), reserved(0)
    let flags =
        (if !components.subdomain.is_empty() { 1u64 } else { 0u64 }) << 4 |
        (if !components.query.is_empty() { 1u64 } else { 0u64 }) << 3 |
        (if !components.fragment.is_empty() { 1u64 } else { 0u64 }) << 2 |
        (if components.port != get_default_port(&components.scheme) { 1u64 } else { 0u64 }) << 1;
        // bit 0 is reserved and always 0

    // Build header: version(4 bits) + scheme(3 bits) + flags(5 bits) = 12 bits total
    let header_value = (1u64 << 8) | (scheme_code << 5) | flags;

    // Build hex string by concatenating each component in proper hex format
    let mut hex_string = String::with_capacity(64);

    // Header: 3 hex chars (12 bits)
    hex_string.push_str(&format!("{:03x}", header_value));

    // TLD hash: 4 hex chars (16 bits)
    hex_string.push_str(&format!("{:04x}", tld_hash));

    // Domain hash: 15 hex chars (60 bits)
    hex_string.push_str(&format!("{:015x}", domain_hash));

    // Subdomain hash: 8 hex chars (32 bits)
    hex_string.push_str(&format!("{:08x}", subdomain_hash));

    // Port: 4 hex chars (16 bits)
    hex_string.push_str(&format!("{:04x}", components.port));

    // Path hash: 15 hex chars (60 bits)
    hex_string.push_str(&format!("{:015x}", path_hash));

    // Params hash: 9 hex chars (36 bits)
    hex_string.push_str(&format!("{:09x}", params_hash));

    // Fragment hash: 6 hex chars (24 bits)
    hex_string.push_str(&format!("{:06x}", fragment_hash));

    // Verify we have exactly 64 hex characters
    if hex_string.len() != 64 {
        return Err(SxurlError::InternalError);
    }

    // Convert hex string to bytes
    hex_to_sxurl(&hex_string)
}


/// Get the default port for a scheme.
fn get_default_port(scheme: &str) -> u16 {
    match scheme {
        "http" => 80,
        "https" => 443,
        "ftp" => 21,
        _ => 0,
    }
}

/// Convert a 256-bit SXURL to a hex string.
pub fn sxurl_to_hex(sxurl: &[u8; 32]) -> String {
    hex::encode(sxurl)
}

/// Parse a hex string to a 256-bit SXURL.
pub fn hex_to_sxurl(hex_str: &str) -> Result<[u8; 32], SxurlError> {
    if hex_str.len() != 64 {
        return Err(SxurlError::InvalidLength);
    }

    let bytes = hex::decode(hex_str)
        .map_err(|_| SxurlError::InvalidHexCharacter)?;

    if bytes.len() != 32 {
        return Err(SxurlError::InvalidLength);
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_sxurl_hex_conversion() {
        let sxurl = [0u8; 32];
        let hex = sxurl_to_hex(&sxurl);
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, "0".repeat(64));

        let parsed = hex_to_sxurl(&hex).unwrap();
        assert_eq!(parsed, sxurl);
    }

    #[test]
    fn test_pack_sxurl_basic() {
        let components = UrlComponents::new(
            "https".to_string(),
            "com".to_string(),
            "example".to_string(),
            "".to_string(),
            443,
            "/".to_string(),
            "".to_string(),
            "".to_string(),
        );

        let result = pack_sxurl(&components);
        assert!(result.is_ok());

        let sxurl = result.unwrap();
        assert_eq!(sxurl.len(), 32);

        // Convert to hex and verify format
        let hex = sxurl_to_hex(&sxurl);
        assert_eq!(hex.len(), 64);

        // For HTTPS with no flags, header should start with "100"
        assert!(hex.starts_with("100"), "HTTPS with no flags should start with '100', got: {}", &hex[0..3]);

        println!("SXURL for https://example.com/: {}", hex);
    }

    #[test]
    fn test_pack_sxurl_with_params() {
        let components = UrlComponents::new(
            "https".to_string(),
            "com".to_string(),
            "google".to_string(),
            "".to_string(),
            443,
            "/search".to_string(),
            "q=test".to_string(),
            "".to_string(),
        );

        let result = pack_sxurl(&components);
        assert!(result.is_ok());

        let sxurl = result.unwrap();
        let hex = sxurl_to_hex(&sxurl);

        // For HTTPS with params present, header should start with "108"
        assert!(hex.starts_with("108"), "HTTPS with params should start with '108', got: {}", &hex[0..3]);

        println!("SXURL for https://google.com/search?q=test: {}", hex);
    }
}