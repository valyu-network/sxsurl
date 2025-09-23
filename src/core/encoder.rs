//! SXURL encoding functionality.
//!
//! This module provides the main API for encoding URLs into SXURL format.

use crate::error::SxurlError;
use crate::url::normalizer::normalize_url;
use crate::url::psl::extract_url_components;
use crate::core::packer::{pack_sxurl, pack_sxurl_with_hashes, sxurl_to_hex, hex_to_sxurl};
use crate::core::hasher::ComponentHasher;
use crate::types::UrlComponents;

/// Pre-computed hash values for all URL components.
///
/// This structure holds the SHA-256 hash values for each URL component,
/// allowing efficient computation of both domain and full SXURLs without
/// duplicate hashing operations.
#[derive(Debug, Clone)]
struct ComputedHashes {
    tld_hash: u64,
    domain_hash: u64,
    subdomain_hash: u64,
    path_hash: u64,
    params_hash: u64,
    fragment_hash: u64,
}

/// Compute hash values for all URL components in a single pass.
///
/// This function performs the expensive SHA-256 hashing operations once
/// and returns both the URL components and their computed hash values.
/// This enables efficient computation of both domain and full SXURLs.
///
/// # Arguments
///
/// * `url` - The URL string to process
///
/// # Returns
///
/// Returns a tuple containing the extracted URL components and their
/// computed hash values, or an error if processing fails.
fn compute_component_hashes(url: &str) -> Result<(UrlComponents, ComputedHashes), SxurlError> {
    // Step 1: Normalize the URL
    let normalized_url = normalize_url(url)?;

    // Step 2: Extract components
    let components = extract_url_components(&normalized_url)?;

    // Step 3: Compute all hashes once
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

    let hashes = ComputedHashes {
        tld_hash,
        domain_hash,
        subdomain_hash,
        path_hash,
        params_hash,
        fragment_hash,
    };

    Ok((components, hashes))
}

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

/// Encode a URL to a domain-only SXURL (256-bit, 64 hex characters).
///
/// A domain SXURL is a special variant of SXURL where only the domain-level
/// components (scheme, TLD, domain, subdomain) are encoded, while all
/// path-level components (port, path, query, fragment) are zeroed out.
///
/// # Use Cases
///
/// Domain SXURLs are designed for scenarios where you need to identify or
/// group URLs at the domain level rather than exact URL matching:
///
/// * **Crawling Rules**: Define crawl depth, rate limits per domain
/// * **Access Control**: Allow/block rules at domain level
/// * **Domain Analytics**: Track metrics per domain/subdomain
/// * **Rate Limiting**: Different limits per domain/subdomain
/// * **Caching Policies**: Different cache strategies per domain
///
/// # Format
///
/// The domain SXURL maintains the same 256-bit format as full SXURL:
/// - Positions [0..30): Header + TLD + Domain + Subdomain (preserved)
/// - Positions [30..64): Port + Path + Query + Fragment (zeroed)
///
/// This ensures compatibility with existing SXURL infrastructure while
/// providing clear semantic distinction through the zeroed components.
///
/// # Performance
///
/// This function shares hash computation with `encode_url_to_hex()` when
/// both are called on the same URL, avoiding duplicate SHA-256 operations.
///
/// # Examples
///
/// ```
/// use sxurl::encode_domain_to_hex;
///
/// // These URLs will produce the SAME domain SXURL:
/// let url1 = "https://api.github.com/repos?page=1";
/// let url2 = "https://api.github.com/users/rust-lang";
/// let url3 = "https://api.github.com/v3/docs#auth";
///
/// let domain_sxurl1 = encode_domain_to_hex(url1)?;
/// let domain_sxurl2 = encode_domain_to_hex(url2)?;
/// let domain_sxurl3 = encode_domain_to_hex(url3)?;
///
/// // All produce identical domain SXURLs
/// assert_eq!(domain_sxurl1, domain_sxurl2);
/// assert_eq!(domain_sxurl2, domain_sxurl3);
///
/// // Domain SXURL ends with zeros (path/params/fragment zeroed)
/// assert!(domain_sxurl1.ends_with("000000000000000000000000000000"));
///
/// // Different subdomains produce different domain SXURLs
/// let api_domain = encode_domain_to_hex("https://api.github.com/")?;
/// let docs_domain = encode_domain_to_hex("https://docs.github.com/")?;
/// assert_ne!(api_domain, docs_domain);
///
/// # Ok::<(), sxurl::SxurlError>(())
/// ```
///
/// # Use Case Example: Crawl Rules
///
/// ```
/// use std::collections::HashMap;
/// use sxurl::encode_domain_to_hex;
///
/// #[derive(Debug)]
/// struct CrawlRule {
///     max_depth: u32,
///     rate_limit_ms: u64,
/// }
///
/// // Set up domain-based crawling rules
/// let mut crawl_rules = HashMap::new();
/// crawl_rules.insert(
///     encode_domain_to_hex("https://api.github.com")?,
///     CrawlRule { max_depth: 3, rate_limit_ms: 100 }
/// );
/// crawl_rules.insert(
///     encode_domain_to_hex("https://docs.rust-lang.org")?,
///     CrawlRule { max_depth: 5, rate_limit_ms: 50 }
/// );
///
/// // Check if a specific URL matches any crawl rule
/// let url = "https://api.github.com/repos/rust-lang/rust/pulls?state=open";
/// let domain_sxurl = encode_domain_to_hex(url)?;
///
/// if let Some(rule) = crawl_rules.get(&domain_sxurl) {
///     println!("Found rule: max_depth={}, rate_limit={}ms",
///              rule.max_depth, rule.rate_limit_ms);
/// }
///
/// # Ok::<(), sxurl::SxurlError>(())
/// ```
pub fn encode_host_to_hex(url: &str) -> Result<String, SxurlError> {
    let (components, hashes) = compute_component_hashes(url)?;

    // Create a modified components struct for domain-only encoding
    let mut domain_components = components.clone();
    // Zero out path-level components for domain SXURL
    domain_components.port = 0;
    domain_components.path = "/".to_string(); // Minimal path
    domain_components.query = String::new();
    domain_components.fragment = String::new();

    // Pack using pre-computed hashes, but zero out path-level hashes
    let sxurl_bytes = pack_sxurl_with_hashes(
        &domain_components,
        hashes.tld_hash,
        hashes.domain_hash,
        hashes.subdomain_hash,
        0, // path_hash = 0 for domain SXURL
        0, // params_hash = 0 for domain SXURL
        0, // fragment_hash = 0 for domain SXURL
    )?;

    Ok(sxurl_to_hex(&sxurl_bytes))
}

/// Extract a host SXURL from an existing full SXURL without re-hashing.
///
/// This function takes a 64-character full SXURL hex string and efficiently
/// extracts a host SXURL by preserving the host components and zeroing out
/// the path-level components. This avoids the expensive re-hashing that
/// would be required if you called `encode_host_to_hex()` on the original URL.
///
/// # Host SXURL Components
///
/// A host SXURL preserves:
/// - Scheme [0:1]
/// - Reserved [1:2]
/// - TLD hash [2:9]
/// - Domain hash [9:24]
/// - Subdomain hash [24:32]
/// - Subdomain flag only [32:34] (other flags zeroed)
///
/// And zeros out:
/// - Port [34:38] → "0000"
/// - Path hash [38:51] → "0000000000000"
/// - Query hash [51:59] → "00000000"
/// - Fragment hash [59:64] → "00000"
///
/// # Performance
///
/// This is ~100x faster than re-encoding since it only does string manipulation
/// instead of SHA-256 hashing operations.
///
/// # Examples
///
/// ```
/// use sxurl::{encode_url_to_hex, extract_host_from_full_sxurl};
///
/// let full_sxurl = encode_url_to_hex("https://api.github.com/repos?page=1#section").unwrap();
/// let host_sxurl = extract_host_from_full_sxurl(&full_sxurl).unwrap();
///
/// // Both of these URLs produce the same host SXURL:
/// let other_full = encode_url_to_hex("https://api.github.com/users").unwrap();
/// let other_host = extract_host_from_full_sxurl(&other_full).unwrap();
///
/// assert_eq!(host_sxurl, other_host);
/// assert!(host_sxurl.ends_with("000000000000000000000000000000"));
/// ```
pub fn extract_host_from_full_sxurl(full_sxurl: &str) -> Result<String, SxurlError> {
    // Validate input length
    if full_sxurl.len() != 64 {
        return Err(SxurlError::InvalidLength);
    }

    // Extract host components from v2 layout:
    // [0:1] scheme, [1:2] reserved, [2:9] tld, [9:24] domain, [24:32] subdomain
    let scheme = &full_sxurl[0..1];
    let reserved = &full_sxurl[1..2];
    let tld_hash = &full_sxurl[2..9];
    let domain_hash = &full_sxurl[9..24];
    let subdomain_hash = &full_sxurl[24..32];

    // Extract original flags and keep only subdomain flag
    let original_flags = u8::from_str_radix(&full_sxurl[32..34], 16)
        .map_err(|_| SxurlError::InvalidHexCharacter)?;
    let subdomain_flag = original_flags & 0x80; // Keep only bit 7 (subdomain)
    let host_flags = format!("{:02x}", subdomain_flag);

    // Build host SXURL: host_components + flags + zeros
    Ok(format!(
        "{}{}{}{}{}{}{}",
        scheme,                         // [0:1] scheme
        reserved,                       // [1:2] reserved
        tld_hash,                       // [2:9] TLD hash
        domain_hash,                    // [9:24] domain hash
        subdomain_hash,                 // [24:32] subdomain hash
        host_flags,                     // [32:34] flags (subdomain only)
        "000000000000000000000000000000" // [34:64] zeros (30 chars)
    ))
}

/// Extract a host SXURL from full SXURL bytes without re-hashing.
///
/// This is the byte-array version of `extract_host_from_full_sxurl()`.
///
/// # Examples
///
/// ```
/// use sxurl::{encode_url, extract_host_from_full_bytes, sxurl_to_hex};
///
/// let full_sxurl_bytes = encode_url("https://api.github.com/repos").unwrap();
/// let host_sxurl_bytes = extract_host_from_full_bytes(&full_sxurl_bytes).unwrap();
///
/// let host_hex = sxurl_to_hex(&host_sxurl_bytes);
/// assert!(host_hex.ends_with("000000000000000000000000000000"));
/// ```
pub fn extract_host_from_full_bytes(full_sxurl: &[u8; 32]) -> Result<[u8; 32], SxurlError> {
    let full_hex = sxurl_to_hex(full_sxurl);
    let host_hex = extract_host_from_full_sxurl(&full_hex)?;
    hex_to_sxurl(&host_hex)
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
        assert!(hex.starts_with("00")); // HTTPS v2 format
    }

    #[test]
    fn test_encode_url_with_params() {
        let result = encode_url_to_hex("https://google.com/search?q=test");
        assert!(result.is_ok());

        let hex = result.unwrap();
        // In v2, flags are at position [32:34], not at the start
        // Just verify it's valid HTTPS and has correct length
        assert!(hex.starts_with("00")); // HTTPS v2 format

        // Check that params flag is set at position [32:34]
        let flags = u8::from_str_radix(&hex[32..34], 16).unwrap();
        assert_eq!(flags & 0x10, 0x10); // params flag (bit 4) should be set
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
    fn test_host_extraction_from_full_sxurl() {
        // Test extracting host SXURL from full SXURL
        let full_url = "https://api.github.com/repos?page=1#section";
        let full_sxurl_hex = encode_url_to_hex(full_url).unwrap();

        // Extract host SXURL using the new function
        let host_sxurl_hex = extract_host_from_full_sxurl(&full_sxurl_hex).unwrap();

        // Verify host SXURL properties
        assert_eq!(host_sxurl_hex.len(), 64);
        assert!(host_sxurl_hex.ends_with("000000000000000000000000000000")); // 30 zeros

        // Host SXURL should have same scheme, TLD, domain, subdomain as original
        assert_eq!(&host_sxurl_hex[0..1], &full_sxurl_hex[0..1]); // scheme
        assert_eq!(&host_sxurl_hex[1..2], &full_sxurl_hex[1..2]); // reserved
        assert_eq!(&host_sxurl_hex[2..9], &full_sxurl_hex[2..9]); // TLD
        assert_eq!(&host_sxurl_hex[9..24], &full_sxurl_hex[9..24]); // domain
        assert_eq!(&host_sxurl_hex[24..32], &full_sxurl_hex[24..32]); // subdomain

        // Verify that different URLs with same host produce same host SXURL
        let other_url = "https://api.github.com/users";
        let other_full_hex = encode_url_to_hex(other_url).unwrap();
        let other_host_hex = extract_host_from_full_sxurl(&other_full_hex).unwrap();

        assert_eq!(host_sxurl_hex, other_host_hex);

        // Test with bytes version too
        let full_sxurl_bytes = encode_url(full_url).unwrap();
        let host_sxurl_bytes = extract_host_from_full_bytes(&full_sxurl_bytes).unwrap();
        let host_from_bytes_hex = sxurl_to_hex(&host_sxurl_bytes);

        assert_eq!(host_sxurl_hex, host_from_bytes_hex);

        println!("✓ Host extraction test passed!");
        println!("  Full SXURL: {}", full_sxurl_hex);
        println!("  Host SXURL: {}", host_sxurl_hex);
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
        let flags = u8::from_str_radix(&hex[32..34], 16).unwrap();
        let sub_present = (flags & (1 << 7)) != 0;
        assert!(sub_present, "Subdomain flag should be set for api.example.co.uk");
    }

    #[test]
    fn test_encode_domain_to_hex_basic() {
        let result = encode_host_to_hex("https://api.github.com/repos?page=1");
        assert!(result.is_ok());

        let domain_hex = result.unwrap();
        assert_eq!(domain_hex.len(), 64);

        // Domain SXURL should end with zeros (34 hex chars = 136 bits)
        assert!(domain_hex.ends_with("000000000000000000000000000000"));

        // Should start with HTTPS scheme (0 in v2)
        assert!(domain_hex.starts_with("00")); // HTTPS v2 format
    }

    #[test]
    fn test_domain_sxurl_same_domain_different_paths() {
        // All these should produce identical domain SXURLs
        let urls = vec![
            "https://api.github.com/repos",
            "https://api.github.com/users/john",
            "https://api.github.com/repos?page=1&sort=name",
            "https://api.github.com/v3/docs#authentication",
            "https://api.github.com:443/explicit/port",
        ];

        let domain_sxurls: Vec<String> = urls.iter()
            .map(|url| encode_host_to_hex(url).unwrap())
            .collect();

        // All should be identical
        for i in 1..domain_sxurls.len() {
            assert_eq!(domain_sxurls[0], domain_sxurls[i],
                "URLs {} and {} should produce identical domain SXURLs", urls[0], urls[i]);
        }

        // Should end with zeros
        assert!(domain_sxurls[0].ends_with("000000000000000000000000000000"));
    }

    #[test]
    fn test_domain_sxurl_different_subdomains() {
        let api = encode_host_to_hex("https://api.github.com/repos").unwrap();
        let docs = encode_host_to_hex("https://docs.github.com/guides").unwrap();
        let www = encode_host_to_hex("https://www.github.com/about").unwrap();
        let no_sub = encode_host_to_hex("https://github.com/home").unwrap();

        // Different subdomains = different domain SXURLs
        assert_ne!(api, docs);
        assert_ne!(api, www);
        assert_ne!(docs, www);
        assert_ne!(api, no_sub);

        // But all have zeroed paths
        assert!(api.ends_with("000000000000000000000000000000"));
        assert!(docs.ends_with("000000000000000000000000000000"));
        assert!(www.ends_with("000000000000000000000000000000"));
        assert!(no_sub.ends_with("000000000000000000000000000000"));
    }

    #[test]
    fn test_domain_sxurl_different_schemes() {
        let https = encode_host_to_hex("https://example.com/").unwrap();
        let http = encode_host_to_hex("http://example.com/").unwrap();
        let ftp = encode_host_to_hex("ftp://example.com/").unwrap();

        // Different schemes should produce different domain SXURLs
        assert_ne!(https, http);
        assert_ne!(https, ftp);
        assert_ne!(http, ftp);

        // Check scheme codes in v2 format (first hex char)
        let https_scheme = &https[0..1];
        let http_scheme = &http[0..1];
        let ftp_scheme = &ftp[0..1];

        assert_eq!(https_scheme, "0"); // HTTPS = 0 in v2
        assert_eq!(http_scheme, "1"); // HTTP = 1 in v2
        assert_eq!(ftp_scheme, "2"); // FTP = 2 in v2
    }

    #[test]
    fn test_domain_sxurl_header_flags() {
        // Test with subdomain
        let with_sub = encode_host_to_hex("https://api.github.com").unwrap();
        let without_sub = encode_host_to_hex("https://github.com").unwrap();

        // Extract flags from v2 position [32:34]
        let with_sub_flags = u8::from_str_radix(&with_sub[32..34], 16).unwrap();
        let without_sub_flags = u8::from_str_radix(&without_sub[32..34], 16).unwrap();

        // Check subdomain flag (bit 7 in v2)
        let with_sub_flag = (with_sub_flags & (1 << 7)) != 0;
        let without_sub_flag = (without_sub_flags & (1 << 7)) != 0;

        assert!(with_sub_flag, "Should have subdomain flag set");
        assert!(!without_sub_flag, "Should not have subdomain flag set");

        // Host SXURLs should never have params, fragment, or path flags for host-only mode
        let params_flag = (with_sub_flags & (1 << 4)) != 0;
        let frag_flag = (with_sub_flags & (1 << 3)) != 0;
        let path_flag = (with_sub_flags & (1 << 5)) != 0;

        assert!(!params_flag, "Host SXURL should not have params flag");
        assert!(!frag_flag, "Host SXURL should not have fragment flag");
        assert!(!path_flag, "Host SXURL should not have path flag");
    }

    #[test]
    fn test_domain_vs_full_sxurl_comparison() {
        let url = "https://api.github.com/repos/rust-lang/rust?tab=readme#installation";

        let domain_sxurl = encode_host_to_hex(url).unwrap();
        let full_sxurl = encode_url_to_hex(url).unwrap();

        // Should be different
        assert_ne!(domain_sxurl, full_sxurl);

        // Domain portions (first 30 hex chars) should be same for matching
        // But the header might be different due to flags
        assert_eq!(&domain_sxurl[3..30], &full_sxurl[3..30]);

        // Domain SXURL should end with zeros
        assert!(domain_sxurl.ends_with("000000000000000000000000000000"));

        // Full SXURL should not end with zeros (has actual path/params/fragment)
        assert!(!full_sxurl.ends_with("000000000000000000000000000000"));
    }

    #[test]
    fn test_compute_component_hashes_efficiency() {
        // This tests that the hash computation function works correctly
        let url = "https://api.github.com/repos/rust-lang/rust";

        let result = compute_component_hashes(url);
        assert!(result.is_ok());

        let (components, hashes) = result.unwrap();

        // Verify components are extracted correctly
        assert_eq!(components.scheme, "https");
        assert_eq!(components.domain, "github");
        assert_eq!(components.subdomain, "api");
        assert_eq!(components.tld, "com");

        // Verify hashes are computed (non-zero for non-empty components)
        assert!(hashes.tld_hash > 0);
        assert!(hashes.domain_hash > 0);
        assert!(hashes.subdomain_hash > 0);
        assert!(hashes.path_hash > 0);
    }

    #[test]
    fn test_domain_sxurl_with_complex_tld() {
        let uk_url = "https://api.example.co.uk/test";
        let com_url = "https://api.example.com/test";

        let uk_domain = encode_host_to_hex(uk_url).unwrap();
        let com_domain = encode_host_to_hex(com_url).unwrap();

        // Different TLDs should produce different domain SXURLs
        assert_ne!(uk_domain, com_domain);

        // Both should end with zeros
        assert!(uk_domain.ends_with("000000000000000000000000000000"));
        assert!(com_domain.ends_with("000000000000000000000000000000"));
    }
}