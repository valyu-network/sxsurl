//! SXURL decoding functionality.
//!
//! This module provides functions to decode SXURL identifiers and extract
//! their component information.

use crate::error::SxurlError;
use crate::types::SxurlHeader;
use crate::packer::hex_to_sxurl;

/// Decoded SXURL information.
///
/// This struct contains all the information that can be extracted from an SXURL
/// identifier, including the header and component hashes.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedSxurl {
    /// Header information (version, scheme, flags)
    pub header: SxurlHeader,
    /// TLD hash (16 bits)
    pub tld_hash: u64,
    /// Domain hash (60 bits)
    pub domain_hash: u64,
    /// Subdomain hash (32 bits, 0 if not present)
    pub subdomain_hash: u64,
    /// Port number (16 bits, 0 if default)
    pub port: u16,
    /// Path hash (60 bits)
    pub path_hash: u64,
    /// Query parameters hash (36 bits, 0 if not present)
    pub params_hash: u64,
    /// Fragment hash (24 bits, 0 if not present)
    pub fragment_hash: u64,
}

impl DecodedSxurl {
    /// Get the hex slice for the TLD hash.
    pub fn tld_hex_slice(&self) -> String {
        format!("{:04x}", self.tld_hash)
    }

    /// Get the hex slice for the domain hash.
    pub fn domain_hex_slice(&self) -> String {
        format!("{:015x}", self.domain_hash)
    }

    /// Get the hex slice for the subdomain hash.
    pub fn subdomain_hex_slice(&self) -> String {
        format!("{:08x}", self.subdomain_hash)
    }

    /// Get the hex slice for the port.
    pub fn port_hex_slice(&self) -> String {
        format!("{:04x}", self.port)
    }

    /// Get the hex slice for the path hash.
    pub fn path_hex_slice(&self) -> String {
        format!("{:015x}", self.path_hash)
    }

    /// Get the hex slice for the params hash.
    pub fn params_hex_slice(&self) -> String {
        format!("{:09x}", self.params_hash)
    }

    /// Get the hex slice for the fragment hash.
    pub fn fragment_hex_slice(&self) -> String {
        format!("{:06x}", self.fragment_hash)
    }
}

/// Decode SXURL from a hex string.
///
/// # Arguments
///
/// * `hex_str` - 64-character hex string representing the SXURL
///
/// # Returns
///
/// Returns decoded SXURL information or an error if decoding fails.
///
/// # Examples
///
/// ```
/// use sxurl::decode_hex;
///
/// let hex = "1002397f4018b8efa86c31440f00a9000098911d784580332c354b043a29e356";
/// let decoded = decode_hex(hex).unwrap();
/// assert_eq!(decoded.header.scheme, "https");
/// ```
pub fn decode_hex(hex_str: &str) -> Result<DecodedSxurl, SxurlError> {
    let sxurl_bytes = hex_to_sxurl(hex_str)?;
    decode_bytes(&sxurl_bytes)
}

/// Decode SXURL from a 32-byte array.
///
/// # Arguments
///
/// * `sxurl_bytes` - 32-byte array representing the SXURL
///
/// # Returns
///
/// Returns decoded SXURL information or an error if decoding fails.
pub fn decode_bytes(sxurl_bytes: &[u8; 32]) -> Result<DecodedSxurl, SxurlError> {
    // Convert back to hex for easier parsing (since we built it with hex)
    let hex_str = hex::encode(sxurl_bytes);

    // Parse each component from the hex string according to SXURL spec positions
    // header: [0..3) (3 hex chars = 12 bits)
    // tld_h: [3..7) (4 hex chars = 16 bits)
    // domain_h: [7..22) (15 hex chars = 60 bits)
    // sub_h: [22..30) (8 hex chars = 32 bits)
    // port: [30..34) (4 hex chars = 16 bits)
    // path_h: [34..49) (15 hex chars = 60 bits)
    // params_h: [49..58) (9 hex chars = 36 bits)
    // frag_h: [58..64) (6 hex chars = 24 bits)

    // Parse header (12 bits)
    let header_hex = &hex_str[0..3];
    let header_value = u16::from_str_radix(header_hex, 16)
        .map_err(|_| SxurlError::InvalidHexCharacter)?;

    // Extract version (bits 8-11, top 4 bits)
    let version = (header_value >> 8) & 0xF;
    if version != 1 {
        return Err(SxurlError::UnsupportedVersion(version));
    }

    // Extract scheme (bits 5-7, 3 bits)
    let scheme_code = (header_value >> 5) & 0x7;
    let scheme = match scheme_code {
        0 => "https".to_string(),
        1 => "http".to_string(),
        2 => "ftp".to_string(),
        _ => return Err(SxurlError::InvalidScheme),
    };

    // Extract flags (bits 0-4, 5 bits)
    let flags = header_value & 0x1F;
    let sub_present = (flags & (1 << 4)) != 0;
    let params_present = (flags & (1 << 3)) != 0;
    let frag_present = (flags & (1 << 2)) != 0;
    let port_present = (flags & (1 << 1)) != 0;

    let header = SxurlHeader::new(scheme, sub_present, params_present, frag_present, port_present);

    // Parse TLD hash (16 bits)
    let tld_hash = u64::from_str_radix(&hex_str[3..7], 16)
        .map_err(|_| SxurlError::InvalidHexCharacter)?;

    // Parse domain hash (60 bits)
    let domain_hash = u64::from_str_radix(&hex_str[7..22], 16)
        .map_err(|_| SxurlError::InvalidHexCharacter)?;

    // Parse subdomain hash (32 bits)
    let subdomain_hash = u64::from_str_radix(&hex_str[22..30], 16)
        .map_err(|_| SxurlError::InvalidHexCharacter)?;

    // Parse port (16 bits)
    let port = u16::from_str_radix(&hex_str[30..34], 16)
        .map_err(|_| SxurlError::InvalidHexCharacter)?;

    // Parse path hash (60 bits)
    let path_hash = u64::from_str_radix(&hex_str[34..49], 16)
        .map_err(|_| SxurlError::InvalidHexCharacter)?;

    // Parse params hash (36 bits)
    let params_hash = u64::from_str_radix(&hex_str[49..58], 16)
        .map_err(|_| SxurlError::InvalidHexCharacter)?;

    // Parse fragment hash (24 bits)
    let fragment_hash = u64::from_str_radix(&hex_str[58..64], 16)
        .map_err(|_| SxurlError::InvalidHexCharacter)?;

    Ok(DecodedSxurl {
        header,
        tld_hash,
        domain_hash,
        subdomain_hash,
        port,
        path_hash,
        params_hash,
        fragment_hash,
    })
}

/// Check if an SXURL matches a given component hash.
///
/// This is useful for filtering SXURLs by specific components.
///
/// # Arguments
///
/// * `sxurl_hex` - The SXURL as a hex string
/// * `component` - The component type ("tld", "domain", "sub", "path", "params", "frag")
/// * `value` - The value to hash and compare
///
/// # Returns
///
/// Returns true if the component hash matches, false otherwise.
///
/// # Examples
///
/// ```
/// use sxurl::matches_component;
///
/// let sxurl_hex = "1002397f4018b8efa86c31440f00a9000098911d784580332c354b043a29e356";
/// let is_rs_tld = matches_component(sxurl_hex, "tld", "rs").unwrap();
/// assert!(is_rs_tld);
/// ```
pub fn matches_component(sxurl_hex: &str, component: &str, value: &str) -> Result<bool, SxurlError> {
    use crate::hasher::ComponentHasher;

    let decoded = decode_hex(sxurl_hex)?;

    let component_hash = match component {
        "tld" => {
            let expected = ComponentHasher::hash_tld(value)?;
            decoded.tld_hash == expected
        }
        "domain" => {
            let expected = ComponentHasher::hash_domain(value)?;
            decoded.domain_hash == expected
        }
        "sub" => {
            if value.is_empty() {
                decoded.subdomain_hash == 0
            } else {
                let expected = ComponentHasher::hash_subdomain(value)?;
                decoded.subdomain_hash == expected
            }
        }
        "path" => {
            let expected = ComponentHasher::hash_path(value)?;
            decoded.path_hash == expected
        }
        "params" => {
            if value.is_empty() {
                decoded.params_hash == 0
            } else {
                let expected = ComponentHasher::hash_params(value)?;
                decoded.params_hash == expected
            }
        }
        "frag" => {
            if value.is_empty() {
                decoded.fragment_hash == 0
            } else {
                let expected = ComponentHasher::hash_fragment(value)?;
                decoded.fragment_hash == expected
            }
        }
        _ => return Err(SxurlError::InternalError),
    };

    Ok(component_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder::encode_url_to_hex;

    #[test]
    fn test_decode_basic() {
        // Encode a URL and then decode it
        let url = "https://example.com/";
        let hex = encode_url_to_hex(url).unwrap();
        let decoded = decode_hex(&hex).unwrap();

        assert_eq!(decoded.header.version, 1);
        assert_eq!(decoded.header.scheme, "https");
        assert!(!decoded.header.sub_present);
        assert!(!decoded.header.params_present);
        assert!(!decoded.header.frag_present);
        assert!(!decoded.header.port_present);
    }

    #[test]
    fn test_decode_with_flags() {
        let url = "https://api.example.com:8443/search?q=test#results";
        let hex = encode_url_to_hex(url).unwrap();
        let decoded = decode_hex(&hex).unwrap();

        assert_eq!(decoded.header.scheme, "https");
        assert!(decoded.header.sub_present);
        assert!(decoded.header.params_present);
        assert!(decoded.header.frag_present);
        assert!(decoded.header.port_present);
        assert_eq!(decoded.port, 8443);
    }

    #[test]
    fn test_hex_slices() {
        let url = "https://docs.rs/";
        let hex = encode_url_to_hex(url).unwrap();
        let decoded = decode_hex(&hex).unwrap();

        // Test that hex slices have correct lengths
        assert_eq!(decoded.tld_hex_slice().len(), 4);
        assert_eq!(decoded.domain_hex_slice().len(), 15);
        assert_eq!(decoded.subdomain_hex_slice().len(), 8);
        assert_eq!(decoded.port_hex_slice().len(), 4);
        assert_eq!(decoded.path_hex_slice().len(), 15);
        assert_eq!(decoded.params_hex_slice().len(), 9);
        assert_eq!(decoded.fragment_hex_slice().len(), 6);
    }

    #[test]
    fn test_matches_component() {
        let url = "https://docs.rs/";
        let hex = encode_url_to_hex(url).unwrap();

        assert!(matches_component(&hex, "tld", "rs").unwrap());
        assert!(matches_component(&hex, "domain", "docs").unwrap());
        assert!(matches_component(&hex, "sub", "").unwrap());
        assert!(matches_component(&hex, "path", "/").unwrap());

        assert!(!matches_component(&hex, "tld", "com").unwrap());
        assert!(!matches_component(&hex, "domain", "google").unwrap());
    }

    #[test]
    fn test_decode_invalid_hex() {
        let result = decode_hex("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_wrong_length() {
        let result = decode_hex("123456"); // Too short
        assert!(result.is_err());
    }

    #[test]
    fn test_round_trip() {
        let url = "https://api.example.co.uk:8443/search?q=test#results";
        let hex = encode_url_to_hex(url).unwrap();
        let decoded = decode_hex(&hex).unwrap();

        // Verify we can extract all the information correctly
        assert_eq!(decoded.header.scheme, "https");
        assert!(decoded.header.sub_present);
        assert!(decoded.header.params_present);
        assert!(decoded.header.frag_present);
        assert!(decoded.header.port_present);
        assert_eq!(decoded.port, 8443);
    }
}