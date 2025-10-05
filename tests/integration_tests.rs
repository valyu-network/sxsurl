//! Integration tests for SXURL implementation.
//!
//! These tests verify that the implementation matches the SXURL specification exactly.

use sxurl::*;

#[test]
fn test_spec_hash_vectors() {
    // Test all hash vectors for v2 spec with corrected labels
    assert_eq!(ComponentHasher::hash_tld("rs").unwrap(), 0x4817c7e); // 28-bit
    assert_eq!(ComponentHasher::hash_domain("docs").unwrap(), 0x16ca8efb818406f); // 60-bit
    assert_eq!(ComponentHasher::hash_subdomain("").unwrap(), 0x989781e3); // 32-bit with label "subdomain"
    assert_eq!(ComponentHasher::hash_path("/").unwrap(), 0x35884d71189f9); // 52-bit (v2)
    assert_eq!(ComponentHasher::hash_params("").unwrap(), 0x6b4de8c2); // 32-bit (v2) with label "query"
    assert_eq!(ComponentHasher::hash_fragment("").unwrap(), 0x22060); // 20-bit (v2) with label "fragment"
}

#[test]
fn test_docs_rs_complete_sxurl() {
    // Test the complete example from the spec: https://docs.rs/
    let url = "https://docs.rs/";
    let normalized = normalize_url(url).unwrap();
    let components = extract_url_components(&normalized).unwrap();
    let sxurl_bytes = pack_sxurl(&components).unwrap();
    let hex = sxurl_to_hex(&sxurl_bytes);

    let expected = "004817c7e16ca8efb818406f000000000001bb35884d71189f90000000000000"; // v2 format with corrected hash extraction
    assert_eq!(hex, expected);
}

#[test]
fn test_header_construction() {
    // Test header for HTTPS with no flags
    let url = "https://docs.rs/";
    let normalized = normalize_url(url).unwrap();
    let components = extract_url_components(&normalized).unwrap();
    let sxurl_bytes = pack_sxurl(&components).unwrap();
    let hex = sxurl_to_hex(&sxurl_bytes);

    // In v2: scheme should be "0" (https) and reserved should be "0"
    assert_eq!(&hex[0..2], "00"); // scheme=0 (https), reserved=0
}

#[test]
fn test_header_with_flags() {
    // Test v2 format with flags at position [32:34] and scheme at [0:1]
    let test_cases = vec![
        ("https://api.example.com/", "0", "80"),           // https, subdomain flag (bit 7)
        ("https://example.com/search?q=test", "0", "30"),  // https, path flag (bit 5) + params flag (bit 4)
        ("https://example.com/#results", "0", "08"),       // https, fragment flag (bit 3)
        ("https://example.com:8443/", "0", "40"),          // https, port flag (bit 6)
        ("http://api.example.com:8080/search?q=test#results", "1", "f8"), // http, all flags
    ];

    for (url, expected_scheme, expected_flags) in test_cases {
        let normalized = normalize_url(url).unwrap();
        let components = extract_url_components(&normalized).unwrap();
        let sxurl_bytes = pack_sxurl(&components).unwrap();
        let hex = sxurl_to_hex(&sxurl_bytes);

        assert_eq!(&hex[0..1], expected_scheme, "Scheme mismatch for URL: {}", url);
        assert_eq!(&hex[32..34], expected_flags, "Flags mismatch for URL: {}", url);
    }
}

#[test]
fn test_url_normalization() {
    // Test that normalization works correctly
    let test_cases = vec![
        ("HTTPS://EXAMPLE.COM/Path", "https://example.com/Path"),
        ("https://DOCS.RS/", "https://docs.rs/"),
        ("HTTP://Test.Example.ORG/", "http://test.example.org/"),
    ];

    for (input, expected) in test_cases {
        let normalized = normalize_url(input).unwrap();
        assert_eq!(normalized.as_str(), expected);
    }
}

#[test]
fn test_psl_domain_splitting() {
    // Test Public Suffix List domain splitting
    let test_cases = vec![
        ("example.com", ("com", "example", "")),
        ("api.example.com", ("com", "example", "api")),
        ("docs.rs", ("rs", "docs", "")),
        ("example.co.uk", ("co.uk", "example", "")),
        ("api.example.co.uk", ("co.uk", "example", "api")),
        ("v2.api.example.com", ("com", "example", "v2.api")),
    ];

    for (host, (expected_tld, expected_domain, expected_sub)) in test_cases {
        let (tld, domain, subdomain) = split_host_with_psl(host).unwrap();
        assert_eq!(tld, expected_tld, "TLD mismatch for {}", host);
        assert_eq!(domain, expected_domain, "Domain mismatch for {}", host);
        assert_eq!(subdomain, expected_sub, "Subdomain mismatch for {}", host);
    }
}

#[test]
fn test_port_handling() {
    // Test default port handling
    let test_cases = vec![
        ("https://example.com/", 443, false),        // Default HTTPS port
        ("http://example.com/", 80, false),          // Default HTTP port
        ("https://example.com:443/", 443, false),    // Explicit default port
        ("https://example.com:8443/", 8443, true),   // Non-default port
        ("http://example.com:8080/", 8080, true),    // Non-default port
    ];

    for (url, expected_port, port_flag_should_be_set) in test_cases {
        let normalized = normalize_url(url).unwrap();
        let components = extract_url_components(&normalized).unwrap();

        assert_eq!(components.port, expected_port);

        // Check if port flag is set correctly in the SXURL (v2 format)
        let sxurl_bytes = pack_sxurl(&components).unwrap();
        let hex = sxurl_to_hex(&sxurl_bytes);
        let flags = u8::from_str_radix(&hex[32..34], 16).unwrap();
        let port_present = (flags & (1 << 6)) != 0; // bit 6 for port in v2

        assert_eq!(port_present, port_flag_should_be_set, "Port flag mismatch for {}", url);
    }
}

#[test]
fn test_hash_consistency() {
    // Test that same input always produces same hash
    let test_cases = vec![
        ("tld", "com"),
        ("domain", "example"),
        ("sub", "api"),
        ("path", "/search"),
        ("params", "q=test"),
        ("frag", "results"),
    ];

    for (label, data) in test_cases {
        let hash1 = hash_component(label, data.as_bytes(), 32).unwrap();
        let hash2 = hash_component(label, data.as_bytes(), 32).unwrap();
        assert_eq!(hash1, hash2, "Hash inconsistency for {}:'{}'", label, data);
    }
}

#[test]
fn test_hash_label_separation() {
    // Test that different labels produce different hashes for same data
    let data = "com";
    let tld_hash = hash_component("tld", data.as_bytes(), 16).unwrap();
    let domain_hash = hash_component("domain", data.as_bytes(), 16).unwrap();

    assert_ne!(tld_hash, domain_hash, "Same data with different labels should produce different hashes");
}

#[test]
fn test_bit_width_masking() {
    // Test that bit width masking works correctly
    let hash1 = hash_component("test", b"data", 16).unwrap();
    let hash2 = hash_component("test", b"data", 32).unwrap();

    // 16-bit hash should fit in 16 bits
    assert!(hash1 < (1u64 << 16), "16-bit hash should fit in 16 bits");

    // 32-bit hash should fit in 32 bits
    assert!(hash2 < (1u64 << 32), "32-bit hash should fit in 32 bits");
}

#[test]
fn test_hex_slice_positions() {
    // Test that hex slices are at correct positions
    let url = "https://api.example.com:8443/search?q=test#results";
    let normalized = normalize_url(url).unwrap();
    let components = extract_url_components(&normalized).unwrap();
    let sxurl_bytes = pack_sxurl(&components).unwrap();
    let hex = sxurl_to_hex(&sxurl_bytes);

    assert_eq!(hex.len(), 64, "SXURL should be exactly 64 hex characters");

    // Test slice extraction
    let header = &hex[0..3];
    let tld_slice = &hex[3..7];
    let domain_slice = &hex[7..22];
    let subdomain_slice = &hex[22..30];
    let port_slice = &hex[30..34];
    let path_slice = &hex[34..49];
    let params_slice = &hex[49..58];
    let fragment_slice = &hex[58..64];

    // Verify lengths
    assert_eq!(header.len(), 3);
    assert_eq!(tld_slice.len(), 4);
    assert_eq!(domain_slice.len(), 15);
    assert_eq!(subdomain_slice.len(), 8);
    assert_eq!(port_slice.len(), 4);
    assert_eq!(path_slice.len(), 15);
    assert_eq!(params_slice.len(), 9);
    assert_eq!(fragment_slice.len(), 6);
}

#[test]
fn test_encoder_api() {
    // Test the high-level encoder API
    let url = "https://docs.rs/";

    // Test direct function
    let sxurl_bytes = encode_url(url).unwrap();
    assert_eq!(sxurl_bytes.len(), 32);

    // Test hex function
    let sxurl_hex = encode_url_to_hex(url).unwrap();
    assert_eq!(sxurl_hex.len(), 64);
    assert_eq!(sxurl_hex, "004817c7e16ca8efb818406f000000000001bb35884d71189f90000000000000"); // v2 format

    // Test encoder struct
    let encoder = SxurlEncoder::new();
    let sxurl_bytes2 = encoder.encode(url).unwrap();
    let sxurl_hex2 = encoder.encode_to_hex(url).unwrap();

    assert_eq!(sxurl_bytes, sxurl_bytes2);
    assert_eq!(sxurl_hex, sxurl_hex2);
}

#[test]
fn test_invalid_schemes() {
    // Test that invalid schemes are rejected
    let invalid_urls = vec![
        "ws://example.com/",
        "fts://example.com/",      // typo
        "htps://example.com/",     // typo
        "file:///path/to/file",
        "mailto:test@example.com",
    ];

    for url in invalid_urls {
        let result = normalize_url(url);
        assert!(result.is_err(), "Should reject invalid scheme: {}", url);
    }
}

#[test]
fn test_valid_schemes() {
    // Test that valid schemes are accepted
    let valid_urls = vec![
        ("https://example.com/", "https"),
        ("http://example.com/", "http"),
        ("ftp://example.com/", "ftp"),
    ];

    for (url, expected_scheme) in valid_urls {
        let normalized = normalize_url(url).unwrap();
        let components = extract_url_components(&normalized).unwrap();
        assert_eq!(components.scheme, expected_scheme);
    }
}

#[test]
fn test_empty_components() {
    // Test handling of empty components
    let url = "https://example.com/";
    let normalized = normalize_url(url).unwrap();
    let components = extract_url_components(&normalized).unwrap();

    assert_eq!(components.subdomain, "");
    assert_eq!(components.query, "");
    assert_eq!(components.fragment, "");

    // Empty components should still hash successfully
    assert!(ComponentHasher::hash_subdomain("").is_ok());
    assert!(ComponentHasher::hash_params("").is_ok());
    assert!(ComponentHasher::hash_fragment("").is_ok());
}

#[test]
fn test_idna_domains() {
    // Test IDNA domain normalization
    let url = "https://café.com/test";
    let normalized = normalize_url(url).unwrap();

    // Should be normalized to ASCII
    assert!(normalized.host_str().unwrap().is_ascii());
}

#[test]
fn test_round_trip_consistency() {
    // Test that same URL always produces same SXURL
    let urls = vec![
        "https://example.com/",
        "https://api.example.com/search?q=test",
        "http://docs.rs/",
        "https://www.google.com/search?q=rust&hl=en",
        "ftp://files.example.org/pub/",
    ];

    for url in urls {
        let sxurl1 = encode_url_to_hex(url).unwrap();
        let sxurl2 = encode_url_to_hex(url).unwrap();
        assert_eq!(sxurl1, sxurl2, "Round-trip inconsistency for {}", url);
    }
}

#[test]
fn test_hex_conversion() {
    // Test hex conversion functions
    let sxurl_bytes = [0u8; 32];
    let hex = sxurl_to_hex(&sxurl_bytes);
    assert_eq!(hex.len(), 64);
    assert_eq!(hex, "0".repeat(64));

    let parsed = hex_to_sxurl(&hex).unwrap();
    assert_eq!(parsed, sxurl_bytes);
}

#[test]
fn test_hex_validation() {
    // Test hex string validation
    let invalid_hex_strings = vec![
        "123".to_string(),                    // Too short
        "g".to_owned() + &"0".repeat(63),     // Invalid character
        "0".repeat(66),                       // Too long
    ];

    for invalid_hex in &invalid_hex_strings {
        let result = hex_to_sxurl(&invalid_hex);
        assert!(result.is_err(), "Should reject invalid hex: {}", invalid_hex);
    }
}

#[test]
fn test_complex_urls() {
    // Test complex real-world URLs
    let complex_urls = vec![
        "https://api.github.com/repos/rust-lang/rust",
        "https://docs.rs/serde/1.0.136/serde/",
        "https://crates.io/search?q=async",
        "https://www.rust-lang.org/learn/get-started#installing-rust",
        "http://archive.ubuntu.com/ubuntu/dists/",
    ];

    for url in complex_urls {
        let result = encode_url_to_hex(url);
        assert!(result.is_ok(), "Should handle complex URL: {}", url);

        let hex = result.unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()), "Should be valid hex");
    }
}

#[test]
fn test_spec_compliance() {
    // Final compliance test against the full spec example
    let url = "https://docs.rs/";
    let sxurl = encode_url_to_hex(url).unwrap();

    // This is the v2 spec value with corrected hash extraction
    let spec_expected = "004817c7e16ca8efb818406f000000000001bb35884d71189f90000000000000";

    assert_eq!(sxurl, spec_expected, "Implementation must match SXURL v2 spec exactly");
}