//! Tests for SXURL bit packing and format validation.

use sxurl::*;

#[test]
fn test_header_packing() {
    // Test header construction for different scenarios
    struct TestCase {
        scheme: &'static str,
        has_subdomain: bool,
        has_params: bool,
        has_fragment: bool,
        has_custom_port: bool,
        expected_header: &'static str,
    }

    let test_cases = vec![
        TestCase {
            scheme: "https",
            has_subdomain: false,
            has_params: false,
            has_fragment: false,
            has_custom_port: false,
            expected_header: "00", // v2: scheme=0, reserved=0
        },
        TestCase {
            scheme: "http",
            has_subdomain: false,
            has_params: false,
            has_fragment: false,
            has_custom_port: false,
            expected_header: "10", // v2: scheme=1, reserved=0
        },
        TestCase {
            scheme: "ftp",
            has_subdomain: false,
            has_params: false,
            has_fragment: false,
            has_custom_port: false,
            expected_header: "20", // v2: scheme=2, reserved=0
        },
        TestCase {
            scheme: "https",
            has_subdomain: true,
            has_params: false,
            has_fragment: false,
            has_custom_port: false,
            expected_header: "00", // v2: scheme=0, reserved=0 (flags are at [32:34])
        },
        TestCase {
            scheme: "https",
            has_subdomain: false,
            has_params: true,
            has_fragment: false,
            has_custom_port: false,
            expected_header: "00", // v2: scheme=0, reserved=0 (flags are at [32:34])
        },
        TestCase {
            scheme: "https",
            has_subdomain: false,
            has_params: false,
            has_fragment: true,
            has_custom_port: false,
            expected_header: "00", // v2: scheme=0, reserved=0 (flags are at [32:34])
        },
        TestCase {
            scheme: "https",
            has_subdomain: false,
            has_params: false,
            has_fragment: false,
            has_custom_port: true,
            expected_header: "00", // v2: scheme=0, reserved=0 (flags are at [32:34])
        },
    ];

    for test_case in test_cases {
        let mut url = format!("{}://example.com", test_case.scheme);

        if test_case.has_subdomain {
            url = format!("{}://api.example.com", test_case.scheme);
        }

        if test_case.has_custom_port {
            url = format!("{}:8080", url);
        }

        url += "/";

        if test_case.has_params {
            url += "?q=test";
        }

        if test_case.has_fragment {
            url += "#section";
        }

        let normalized = normalize_url(&url).unwrap();
        let components = extract_url_components(&normalized).unwrap();
        let sxurl_bytes = pack_sxurl(&components).unwrap();
        let hex = sxurl_to_hex(&sxurl_bytes);

        assert_eq!(
            &hex[0..2], // v2: check scheme+reserved at [0:2)
            test_case.expected_header,
            "Header mismatch for URL: {} (expected {}, got {})",
            url,
            test_case.expected_header,
            &hex[0..2]
        );
    }
}

#[test]
fn test_port_encoding() {
    // Test that ports are encoded correctly in hex
    let test_cases = vec![
        (80, "0050"),
        (443, "01bb"),
        (8080, "1f90"),
        (8443, "20fb"),
        (3000, "0bb8"),
        (65535, "ffff"),
    ];

    for (port, expected_hex) in test_cases {
        let url = format!("https://example.com:{}/", port);
        let normalized = normalize_url(&url).unwrap();
        let components = extract_url_components(&normalized).unwrap();
        let sxurl_bytes = pack_sxurl(&components).unwrap();
        let hex = sxurl_to_hex(&sxurl_bytes);

        let port_slice = &hex[34..38]; // Correct v2 position for port
        assert_eq!(port_slice, expected_hex, "Port encoding mismatch for port {}", port);
    }
}

#[test]
fn test_hex_slice_boundaries() {
    // Test that all hex slices have correct boundaries and lengths
    let url = "https://api.example.com:8443/search?q=test#results";
    let normalized = normalize_url(url).unwrap();
    let components = extract_url_components(&normalized).unwrap();
    let sxurl_bytes = pack_sxurl(&components).unwrap();
    let hex = sxurl_to_hex(&sxurl_bytes);

    // Test slice boundaries according to spec
    let slices = vec![
        ("Header", 0, 3, 3),
        ("TLD", 3, 7, 4),
        ("Domain", 7, 22, 15),
        ("Subdomain", 22, 30, 8),
        ("Port", 30, 34, 4),
        ("Path", 34, 49, 15),
        ("Params", 49, 58, 9),
        ("Fragment", 58, 64, 6),
    ];

    for (name, start, end, expected_len) in slices {
        let slice = &hex[start..end];
        assert_eq!(
            slice.len(),
            expected_len,
            "{} slice has wrong length: {} (expected {})",
            name,
            slice.len(),
            expected_len
        );

        // All slices should be valid hex
        assert!(
            slice.chars().all(|c| c.is_ascii_hexdigit()),
            "{} slice contains non-hex characters: {}",
            name,
            slice
        );
    }

    // Total length should be exactly 64
    assert_eq!(hex.len(), 64);
}

#[test]
fn test_empty_component_packing() {
    // Test that empty components are packed correctly
    let url = "https://example.com/";
    let normalized = normalize_url(url).unwrap();
    let components = extract_url_components(&normalized).unwrap();

    // Verify components are empty as expected
    assert_eq!(components.subdomain, "");
    assert_eq!(components.query, "");
    assert_eq!(components.fragment, "");

    let sxurl_bytes = pack_sxurl(&components).unwrap();
    let hex = sxurl_to_hex(&sxurl_bytes);

    // Empty subdomain should be zero (not hashed) - correct v2 position [24:32)
    let subdomain_slice = &hex[24..32];
    assert_eq!(subdomain_slice, "00000000");

    // Empty params should be zero (not hashed) - correct v2 position [51:59)
    let params_slice = &hex[51..59];
    assert_eq!(params_slice, "00000000");

    // Empty fragment should be zero (not hashed) - correct v2 position [59:64)
    let fragment_slice = &hex[59..64];
    assert_eq!(fragment_slice, "00000");
}

#[test]
fn test_bit_packing_determinism() {
    // Test that packing is deterministic
    let url = "https://docs.rs/";
    let normalized = normalize_url(url).unwrap();
    let components = extract_url_components(&normalized).unwrap();

    let sxurl1 = pack_sxurl(&components).unwrap();
    let sxurl2 = pack_sxurl(&components).unwrap();

    assert_eq!(sxurl1, sxurl2, "Bit packing should be deterministic");

    let hex1 = sxurl_to_hex(&sxurl1);
    let hex2 = sxurl_to_hex(&sxurl2);

    assert_eq!(hex1, hex2, "Hex conversion should be deterministic");
}

#[test]
fn test_sxurl_length() {
    // Test that SXURL is always exactly 32 bytes / 64 hex chars
    let test_urls = vec![
        "https://a.b/",
        "https://very-long-domain-name.example.org/very/long/path/with/many/segments?very=long&query=parameters&with=multiple&values#very-long-fragment-identifier",
        "http://x.y/",
        "ftp://files.example.com/pub/",
    ];

    for url in test_urls {
        let normalized = normalize_url(url).unwrap();
        let components = extract_url_components(&normalized).unwrap();
        let sxurl_bytes = pack_sxurl(&components).unwrap();
        let hex = sxurl_to_hex(&sxurl_bytes);

        assert_eq!(sxurl_bytes.len(), 32, "SXURL should be exactly 32 bytes for: {}", url);
        assert_eq!(hex.len(), 64, "SXURL hex should be exactly 64 characters for: {}", url);
    }
}

#[test]
fn test_hex_character_validity() {
    // Test that all hex output uses only valid lowercase hex characters
    let url = "https://api.example.com:8443/search?q=test#results";
    let normalized = normalize_url(url).unwrap();
    let components = extract_url_components(&normalized).unwrap();
    let sxurl_bytes = pack_sxurl(&components).unwrap();
    let hex = sxurl_to_hex(&sxurl_bytes);

    for (i, c) in hex.chars().enumerate() {
        assert!(
            c.is_ascii_hexdigit(),
            "Character at position {} is not a hex digit: '{}'",
            i,
            c
        );
    }
}

#[test]
fn test_hex_round_trip() {
    // Test hex_to_sxurl and sxurl_to_hex round trip
    let url = "https://docs.rs/";
    let normalized = normalize_url(url).unwrap();
    let components = extract_url_components(&normalized).unwrap();
    let original_bytes = pack_sxurl(&components).unwrap();

    let hex = sxurl_to_hex(&original_bytes);
    let reconstructed_bytes = hex_to_sxurl(&hex).unwrap();

    assert_eq!(original_bytes, reconstructed_bytes, "Hex round trip should preserve bytes");
}

#[test]
fn test_invalid_hex_input() {
    // Test that invalid hex strings are rejected
    let invalid_hex_strings = vec![
        "123".to_string(),                     // Too short
        "12345".to_string(),                   // Odd length
        "g".to_owned() + &"0".repeat(63),      // Invalid character
        "0".repeat(66),                        // Too long
        "".to_string(),                        // Empty
    ];

    for invalid_hex in &invalid_hex_strings {
        let result = hex_to_sxurl(&invalid_hex);
        assert!(result.is_err(), "Should reject invalid hex: '{}'", invalid_hex);
    }
}

#[test]
fn test_valid_hex_input() {
    // Test that valid hex strings are accepted
    let valid_hex = "1002397f4018b8efa86c310000000001bb98911d784580332000000000000000";
    let result = hex_to_sxurl(valid_hex);
    assert!(result.is_ok(), "Should accept valid hex");

    let bytes = result.unwrap();
    assert_eq!(bytes.len(), 32);

    // Round trip should work
    let hex_again = sxurl_to_hex(&bytes);
    assert_eq!(hex_again, valid_hex);
}

#[test]
fn test_spec_compliance_exact() {
    // Test the exact spec example
    let url = "https://docs.rs/";
    let sxurl_hex = encode_url_to_hex(url).unwrap();
    let expected = "004817c7e16ca8efb818406f000000000001bb35884d71189f90000000000000";

    assert_eq!(sxurl_hex, expected, "Must match spec exactly");

    // Verify each component slice for v2 format with corrected values
    let expected_slices = vec![
        ("Scheme+Reserved", 0, 2, "00"),
        ("TLD", 2, 9, "4817c7e"),
        ("Domain", 9, 24, "16ca8efb818406f"),
        ("Subdomain", 24, 32, "00000000"),
        ("Flags", 32, 34, "00"),
        ("Port", 34, 38, "01bb"),
        ("Path", 38, 51, "35884d71189f9"),
        ("Params", 51, 59, "00000000"),
        ("Fragment", 59, 64, "00000"),
    ];

    for (name, start, end, expected_value) in expected_slices {
        let actual_value = &sxurl_hex[start..end];
        assert_eq!(
            actual_value,
            expected_value,
            "{} slice mismatch: got '{}', expected '{}'",
            name,
            actual_value,
            expected_value
        );
    }
}

#[test]
fn test_flag_bits_exact() {
    // Test exact flag bit patterns
    struct FlagTest {
        url: &'static str,
        expected_flags_binary: &'static str,
        expected_flags_value: u8,
    }

    let flag_tests = vec![
        FlagTest {
            url: "https://example.com/",
            expected_flags_binary: "00000000", // v2: no flags set
            expected_flags_value: 0,
        },
        FlagTest {
            url: "https://api.example.com/",
            expected_flags_binary: "10000000", // v2: bit 7 = subdomain
            expected_flags_value: 128,
        },
        FlagTest {
            url: "https://example.com/?q=test",
            expected_flags_binary: "00010000", // v2: bit 4 = query
            expected_flags_value: 16,
        },
        FlagTest {
            url: "https://example.com/#section",
            expected_flags_binary: "00001000", // v2: bit 3 = fragment
            expected_flags_value: 8,
        },
        FlagTest {
            url: "https://example.com:8080/",
            expected_flags_binary: "01000000", // v2: bit 6 = port
            expected_flags_value: 64,
        },
        FlagTest {
            url: "https://api.example.com:8080/search?q=test#results",
            expected_flags_binary: "11111000", // v2: bits 7,6,5,4,3 = sub,port,path,query,frag
            expected_flags_value: 248,
        },
    ];

    for test in flag_tests {
        let sxurl_hex = encode_url_to_hex(test.url).unwrap();
        let flags_hex = &sxurl_hex[32..34]; // v2: flags are at [32:34]
        let flags = u8::from_str_radix(flags_hex, 16).unwrap();
        assert_eq!(
            flags,
            test.expected_flags_value,
            "Flag value mismatch for {}: expected {}, got {}",
            test.url,
            test.expected_flags_value,
            flags
        );

        // Verify individual flag bits
        let sub_present = (flags & 0x10) != 0;
        let params_present = (flags & 0x08) != 0;
        let frag_present = (flags & 0x04) != 0;
        let port_present = (flags & 0x02) != 0;
        let reserved = (flags & 0x01) != 0;

        assert!(!reserved, "Reserved bit should always be 0 for {}", test.url);

        println!(
            "URL: {} -> Flags: {} (sub:{} params:{} frag:{} port:{})",
            test.url,
            test.expected_flags_binary,
            sub_present,
            params_present,
            frag_present,
            port_present
        );
    }
}