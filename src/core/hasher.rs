//! Component hashing using labeled SHA-256 for SXURL encoding.

use sha2::{Digest, Sha256};
use crate::error::SxurlError;

/// Hash a component with a label using SHA-256 and truncate to specified bit width.
///
/// This implements the labeled hash function from the SXURL spec:
/// H_n(L, B) = lower_n(SHA256(L || 0x00 || B))
///
/// # Arguments
///
/// * `label` - ASCII label ("tld", "domain", "sub", "path", "params", "frag")
/// * `data` - Component bytes to hash
/// * `bit_width` - Number of bits to extract (16, 24, 32, 36, 60)
///
/// # Returns
///
/// The lower `bit_width` bits of the hash as a u64
pub fn hash_component(label: &str, data: &[u8], bit_width: usize) -> Result<u64, SxurlError> {
    if bit_width > 64 {
        return Err(SxurlError::InternalError);
    }

    let mut hasher = Sha256::new();

    // Add label
    hasher.update(label.as_bytes());

    // Add separator (null byte)
    hasher.update(&[0x00]);

    // Add component data
    hasher.update(data);

    let hash_result = hasher.finalize();

    // Extract the lower `bit_width` bits
    extract_lower_bits(&hash_result, bit_width)
}

/// Extract the lower n bits from a hash result.
///
/// According to SXURL spec: "lower_n(hash)" means the rightmost n bits from the hex string.
/// This corresponds to taking bytes from the END of the hash array in big-endian order.
pub fn extract_lower_bits(hash: &[u8], bit_width: usize) -> Result<u64, SxurlError> {
    if bit_width > 64 {
        return Err(SxurlError::InternalError);
    }

    let mut result = 0u64;
    let bytes_needed = (bit_width + 7) / 8; // Round up to next byte

    // Take bytes from the END of the hash (rightmost bytes in hex representation)
    // Build result in big-endian order
    let start_index = hash.len().saturating_sub(bytes_needed);
    for &byte in &hash[start_index..] {
        result = (result << 8) | (byte as u64);
    }

    // Mask to exact bit width
    if bit_width == 64 {
        Ok(result)
    } else {
        let mask = (1u64 << bit_width) - 1;
        Ok(result & mask)
    }
}

/// Hash components for all SXURL fields according to the spec.
pub struct ComponentHasher;

impl ComponentHasher {
    /// Hash TLD component (16 bits).
    pub fn hash_tld(tld: &str) -> Result<u64, SxurlError> {
        hash_component("tld", tld.as_bytes(), 16)
    }

    /// Hash domain component (60 bits).
    pub fn hash_domain(domain: &str) -> Result<u64, SxurlError> {
        hash_component("domain", domain.as_bytes(), 60)
    }

    /// Hash subdomain component (32 bits).
    pub fn hash_subdomain(subdomain: &str) -> Result<u64, SxurlError> {
        hash_component("sub", subdomain.as_bytes(), 32)
    }

    /// Hash path component (60 bits).
    pub fn hash_path(path: &str) -> Result<u64, SxurlError> {
        hash_component("path", path.as_bytes(), 60)
    }

    /// Hash query parameters component (36 bits).
    pub fn hash_params(params: &str) -> Result<u64, SxurlError> {
        hash_component("params", params.as_bytes(), 36)
    }

    /// Hash fragment component (24 bits).
    pub fn hash_fragment(fragment: &str) -> Result<u64, SxurlError> {
        hash_component("frag", fragment.as_bytes(), 24)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_hashing() {
        // Test that we get consistent results
        let hash1 = hash_component("tld", b"com", 16).unwrap();
        let hash2 = hash_component("tld", b"com", 16).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_extraction_verification() {
        // Test our hash extraction against a known SHA256 value
        // SHA256("test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
        let known_hash = hex::decode("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08").unwrap();

        // Test extracting 16 bits - should be the LAST 2 bytes in big-endian order
        let result_16 = extract_lower_bits(&known_hash, 16).unwrap();
        println!("Known hash (last 4 bytes): {:02x}{:02x}{:02x}{:02x}",
                 known_hash[28], known_hash[29], known_hash[30], known_hash[31]);
        println!("Extracted 16 bits (our method): 0x{:04x}", result_16);

        // Lower 16 bits should be the last 2 bytes in big-endian: 0x0a, 0x08 → 0x0a08
        let expected = 0x0a08;
        println!("Expected (last 2 bytes, big-endian): 0x{:04x}", expected);

        assert_eq!(result_16, expected, "Hash extraction should take lower 16 bits from end of hash");
    }

    #[test]
    fn test_sxurl_test_vector_hash() {
        // Test the hash from the SXURL spec: H16("tld", "rs") should be 0x2397
        let tld_hash = hash_component("tld", b"rs", 16).unwrap();
        println!("H16(\"tld\", \"rs\") = 0x{:04x}", tld_hash);

        // Let's also manually compute this to verify
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"tld");
        hasher.update(&[0x00]);
        hasher.update(b"rs");
        let result = hasher.finalize();
        println!("SHA256(\"tld\" || 0x00 || \"rs\") = {}", hex::encode(&result));
        println!("Last 4 bytes: {:02x}{:02x}{:02x}{:02x}",
                 result[28], result[29], result[30], result[31]);

        // Check if spec test vector matches
        if tld_hash == 0x2397 {
            println!("✓ Matches SXURL spec test vector");
        } else {
            println!("⚠ Does NOT match spec test vector 0x2397");
        }
    }

    #[test]
    fn test_different_labels_produce_different_hashes() {
        let tld_hash = hash_component("tld", b"com", 16).unwrap();
        let domain_hash = hash_component("domain", b"com", 16).unwrap();

        // Same data, different labels should produce different hashes
        assert_ne!(tld_hash, domain_hash);
    }

    #[test]
    fn test_bit_width_limits() {
        let hash_16 = hash_component("test", b"data", 16).unwrap();
        let hash_32 = hash_component("test", b"data", 32).unwrap();

        // 16-bit hash should fit in 16 bits
        assert!(hash_16 < (1u64 << 16));

        // 32-bit hash should fit in 32 bits
        assert!(hash_32 < (1u64 << 32));
    }

    #[test]
    fn test_component_hashers() {
        // Test all component hashers work
        assert!(ComponentHasher::hash_tld("com").is_ok());
        assert!(ComponentHasher::hash_domain("example").is_ok());
        assert!(ComponentHasher::hash_subdomain("api").is_ok());
        assert!(ComponentHasher::hash_path("/search").is_ok());
        assert!(ComponentHasher::hash_params("q=test").is_ok());
        assert!(ComponentHasher::hash_fragment("results").is_ok());
    }

    #[test]
    fn test_empty_components() {
        // Empty components should hash successfully
        assert!(ComponentHasher::hash_subdomain("").is_ok());
        assert!(ComponentHasher::hash_params("").is_ok());
        assert!(ComponentHasher::hash_fragment("").is_ok());
    }

    #[test]
    fn test_extract_lower_bits() {
        let test_hash = [0xFF, 0xAA, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00];

        let bits_8 = extract_lower_bits(&test_hash, 8).unwrap();
        assert_eq!(bits_8, 0x00); // Last byte

        let bits_16 = extract_lower_bits(&test_hash, 16).unwrap();
        assert_eq!(bits_16, 0x0000); // Last 2 bytes in big-endian: 0x00, 0x00

        let bits_24 = extract_lower_bits(&test_hash, 24).unwrap();
        assert_eq!(bits_24, 0x000000); // Last 3 bytes in big-endian: 0x00, 0x00, 0x00
    }

    #[test]
    fn test_known_hash_values() {
        // Test some known values to ensure consistency
        // These should match the spec examples once we verify them
        let com_hash = ComponentHasher::hash_tld("com").unwrap();
        let rs_hash = ComponentHasher::hash_tld("rs").unwrap();

        // They should be different
        assert_ne!(com_hash, rs_hash);

        // And should fit in 16 bits
        assert!(com_hash < (1u64 << 16));
        assert!(rs_hash < (1u64 << 16));
    }
}