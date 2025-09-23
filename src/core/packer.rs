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

    // Create scheme code according to v2 specification
    let scheme_code = match components.scheme.as_str() {
        "https" => 0u8,
        "http" => 1u8,
        "ftp" => 2u8,
        _ => return Err(SxurlError::InvalidScheme),
    };

    // Build flags (8 bits): sub(7), port(6), path(5), params(4), frag(3), reserved(2:0)
    let path_present = !components.path.is_empty() && components.path != "/";
    let port_present = components.port != get_default_port(&components.scheme);

    let flags =
        (if !components.subdomain.is_empty() { 1u8 } else { 0u8 }) << 7 |
        (if port_present { 1u8 } else { 0u8 }) << 6 |
        (if path_present { 1u8 } else { 0u8 }) << 5 |
        (if !components.query.is_empty() { 1u8 } else { 0u8 }) << 4 |
        (if !components.fragment.is_empty() { 1u8 } else { 0u8 }) << 3;
        // bits 2, 1, 0 are reserved and always 0

    // Build hex string by concatenating each component in v2 format
    let mut hex_string = String::with_capacity(64);

    // v2 format: scheme(1) + reserved(1) + tld(7) + domain(15) + sub(8) + flags(2) + port(4) + path(13) + query(8) + frag(5)

    // Scheme: 1 hex char (4 bits)
    hex_string.push_str(&format!("{:01x}", scheme_code));

    // Reserved: 1 hex char (4 bits) - always 0
    hex_string.push_str("0");

    // TLD hash: 7 hex chars (28 bits)
    hex_string.push_str(&format!("{:07x}", tld_hash));

    // Domain hash: 15 hex chars (60 bits)
    hex_string.push_str(&format!("{:015x}", domain_hash));

    // Subdomain hash: 8 hex chars (32 bits)
    hex_string.push_str(&format!("{:08x}", subdomain_hash));

    // Flags: 2 hex chars (8 bits)
    hex_string.push_str(&format!("{:02x}", flags));

    // Port: 4 hex chars (16 bits)
    hex_string.push_str(&format!("{:04x}", components.port));

    // Path hash: 13 hex chars (52 bits)
    hex_string.push_str(&format!("{:013x}", path_hash));

    // Query hash: 8 hex chars (32 bits)
    hex_string.push_str(&format!("{:08x}", params_hash));

    // Fragment hash: 5 hex chars (20 bits)
    hex_string.push_str(&format!("{:05x}", fragment_hash));

    // Verify we have exactly 64 hex characters
    if hex_string.len() != 64 {
        return Err(SxurlError::InternalError);
    }

    // Convert hex string to bytes
    hex_to_sxurl(&hex_string)
}

/// Pack URL components into SXURL format using pre-computed hash values.
///
/// This function is optimized for cases where hash values have already been computed,
/// avoiding duplicate hashing operations. Used internally for efficient encoding
/// of both domain and full SXURLs.
///
/// # Arguments
///
/// * `components` - The URL components (for metadata like scheme, port)
/// * `tld_hash` - Pre-computed TLD hash
/// * `domain_hash` - Pre-computed domain hash
/// * `subdomain_hash` - Pre-computed subdomain hash
/// * `path_hash` - Pre-computed path hash
/// * `params_hash` - Pre-computed params hash
/// * `fragment_hash` - Pre-computed fragment hash
///
/// # Returns
///
/// Returns the SXURL as a 32-byte array.
pub fn pack_sxurl_with_hashes(
    components: &UrlComponents,
    tld_hash: u64,
    domain_hash: u64,
    subdomain_hash: u64,
    path_hash: u64,
    params_hash: u64,
    fragment_hash: u64,
) -> Result<[u8; 32], SxurlError> {
    // Create scheme code according to v2 specification
    let scheme_code = match components.scheme.as_str() {
        "https" => 0u8,
        "http" => 1u8,
        "ftp" => 2u8,
        _ => return Err(SxurlError::InvalidScheme),
    };

    // Build flags (8 bits): sub(7), port(6), path(5), params(4), frag(3), reserved(2:0)
    let path_present = !components.path.is_empty() && components.path != "/";
    let port_present = components.port != get_default_port(&components.scheme);

    let flags =
        (if !components.subdomain.is_empty() { 1u8 } else { 0u8 }) << 7 |
        (if port_present { 1u8 } else { 0u8 }) << 6 |
        (if path_present { 1u8 } else { 0u8 }) << 5 |
        (if !components.query.is_empty() { 1u8 } else { 0u8 }) << 4 |
        (if !components.fragment.is_empty() { 1u8 } else { 0u8 }) << 3;
        // bits 2, 1, 0 are reserved and always 0

    // Build hex string by concatenating each component in v2 format
    let mut hex_string = String::with_capacity(64);

    // v2 format: scheme(1) + reserved(1) + tld(7) + domain(15) + sub(8) + flags(2) + port(4) + path(13) + query(8) + frag(5)

    // Scheme: 1 hex char (4 bits)
    hex_string.push_str(&format!("{:01x}", scheme_code));

    // Reserved: 1 hex char (4 bits) - always 0
    hex_string.push_str("0");

    // TLD hash: 7 hex chars (28 bits)
    hex_string.push_str(&format!("{:07x}", tld_hash));

    // Domain hash: 15 hex chars (60 bits)
    hex_string.push_str(&format!("{:015x}", domain_hash));

    // Subdomain hash: 8 hex chars (32 bits)
    hex_string.push_str(&format!("{:08x}", subdomain_hash));

    // Flags: 2 hex chars (8 bits)
    hex_string.push_str(&format!("{:02x}", flags));

    // Port: 4 hex chars (16 bits)
    hex_string.push_str(&format!("{:04x}", components.port));

    // Path hash: 13 hex chars (52 bits)
    hex_string.push_str(&format!("{:013x}", path_hash));

    // Query hash: 8 hex chars (32 bits)
    hex_string.push_str(&format!("{:08x}", params_hash));

    // Fragment hash: 5 hex chars (20 bits)
    hex_string.push_str(&format!("{:05x}", fragment_hash));

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

        // For HTTPS (scheme=0) + reserved(0) should start with "00"
        assert!(hex.starts_with("00"), "HTTPS v2 should start with '00', got: {}", &hex[0..2]);

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

        // For HTTPS with params present: scheme=0, reserved=0, then TLD hash starts
        // Flags will be at position 32 hex chars in with params flag (bit 4) set
        assert!(hex.starts_with("00"), "HTTPS v2 should start with '00', got: {}", &hex[0..2]);

        println!("SXURL for https://google.com/search?q=test: {}", hex);
    }

    #[test]
    fn test_v2_format_positions() {
        let components = UrlComponents::new(
            "http".to_string(),    // scheme = 1
            "com".to_string(),     // TLD
            "example".to_string(),  // domain
            "api".to_string(),     // subdomain (present)
            8080,                  // port (non-default)
            "/v1/users".to_string(), // path (present)
            "limit=10".to_string(), // query (present)
            "section1".to_string(), // fragment (present)
        );

        let result = pack_sxurl(&components);
        assert!(result.is_ok());

        let hex = sxurl_to_hex(&result.unwrap());
        assert_eq!(hex.len(), 64);

        println!("✓ v2 format test:");
        println!("  Full SXURL: {}", hex);
        println!("  Positions breakdown:");
        println!("    [0:1]   Scheme:    {} (http=1)", &hex[0..1]);
        println!("    [1:2]   Reserved:  {} (always 0)", &hex[1..2]);
        println!("    [2:9]   TLD:       {} (28-bit)", &hex[2..9]);
        println!("    [9:24]  Domain:    {} (60-bit)", &hex[9..24]);
        println!("    [24:32] Subdomain: {} (32-bit)", &hex[24..32]);
        println!("    [32:34] Flags:     {} (8-bit)", &hex[32..34]);
        println!("    [34:38] Port:      {} (16-bit)", &hex[34..38]);
        println!("    [38:51] Path:      {} (52-bit)", &hex[38..51]);
        println!("    [51:59] Query:     {} (32-bit)", &hex[51..59]);
        println!("    [59:64] Fragment:  {} (20-bit)", &hex[59..64]);

        // Verify scheme
        assert_eq!(&hex[0..1], "1", "HTTP scheme should be 1");

        // Verify reserved
        assert_eq!(&hex[1..2], "0", "Reserved should be 0");

        // Verify port encoding (8080 = 0x1F90)
        assert_eq!(&hex[34..38], "1f90", "Port 8080 should encode as 1f90");

        // Parse flags manually: sub(7)=1, port(6)=1, path(5)=1, params(4)=1, frag(3)=1 = 0xF8
        let flags_hex = &hex[32..34];
        let flags = u8::from_str_radix(flags_hex, 16).unwrap();
        assert_eq!(flags & 0x80, 0x80, "Subdomain flag should be set");
        assert_eq!(flags & 0x40, 0x40, "Port flag should be set");
        assert_eq!(flags & 0x20, 0x20, "Path flag should be set");
        assert_eq!(flags & 0x10, 0x10, "Params flag should be set");
        assert_eq!(flags & 0x08, 0x08, "Fragment flag should be set");
    }
}