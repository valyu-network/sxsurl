//! Detailed tests for hash extraction and component hashing.

use sxurl::*;
use sha2::{Sha256, Digest};

#[test]
fn test_hash_extraction_methods() {
    // Test hash extraction with known SHA256 values
    let test_cases = vec![
        ("tld\x00rs", 16, 0x2397),
        ("domain\x00docs", 60, 0xf4018b8efa86c31),
        ("sub\x00", 32, 0x440f00a9),
        ("path\x00/", 60, 0x98911d784580332),
        ("params\x00", 36, 0xc354b043a),
        ("frag\x00", 24, 0x29e356),
    ];

    for (input, bits, expected) in test_cases {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let hash = hasher.finalize();

        // Test our extraction function
        let result = extract_lower_bits(&hash, bits).unwrap();
        assert_eq!(result, expected, "Hash extraction failed for input: {:?}", input);
    }
}

#[test]
fn test_bit_width_edge_cases() {
    // Test various bit widths
    let test_hash = [0xFF; 32]; // All bits set

    let test_cases = vec![
        (1, 1),
        (8, 255),
        (16, 65535),
        (24, 16777215),
        (32, 4294967295),
        (36, 68719476735),
        (60, 1152921504606846975),
    ];

    for (bits, expected_max) in test_cases {
        let result = extract_lower_bits(&test_hash, bits).unwrap();
        assert_eq!(result, expected_max, "Bit masking failed for {} bits", bits);
    }
}

#[test]
fn test_hash_endianness() {
    // Test that we extract from the correct end with correct endianness
    let test_hash = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ];

    // Extract from the end in big-endian order
    let result_16 = extract_lower_bits(&test_hash, 16).unwrap();
    assert_eq!(result_16, 0xEEFF); // Last 2 bytes: EE FF

    let result_32 = extract_lower_bits(&test_hash, 32).unwrap();
    assert_eq!(result_32, 0xCCDDEEFF); // Last 4 bytes: CC DD EE FF
}

#[test]
fn test_component_hasher_determinism() {
    // Test that component hashers are deterministic
    for _ in 0..10 {
        assert_eq!(ComponentHasher::hash_tld("rs").unwrap(), 0x2397);
        assert_eq!(ComponentHasher::hash_domain("docs").unwrap(), 0xf4018b8efa86c31);
        assert_eq!(ComponentHasher::hash_subdomain("").unwrap(), 0x440f00a9);
    }
}

#[test]
fn test_manual_hash_calculation() {
    // Manually verify the H16("tld", "rs") calculation
    let mut hasher = Sha256::new();
    hasher.update(b"tld");
    hasher.update(&[0x00]);
    hasher.update(b"rs");
    let hash = hasher.finalize();

    // Should be: a015df3b1d0e2e1091a8f9a4d87025c8e1874e0660b2030d7e7c81c4bd512397
    let expected_hash = "a015df3b1d0e2e1091a8f9a4d87025c8e1874e0660b2030d7e7c81c4bd512397";
    assert_eq!(hex::encode(&hash), expected_hash);

    // Extract lower 16 bits: last 2 bytes 23 97 = 0x2397
    let lower_16 = extract_lower_bits(&hash, 16).unwrap();
    assert_eq!(lower_16, 0x2397);
}

#[test]
fn test_all_spec_hash_values() {
    // Test all the specific hash values claimed in the spec
    struct TestCase {
        label: &'static str,
        data: &'static str,
        bits: usize,
        expected: u64,
    }

    let test_cases = [
        TestCase { label: "tld", data: "rs", bits: 16, expected: 0x2397 },
        TestCase { label: "domain", data: "docs", bits: 60, expected: 0xf4018b8efa86c31 },
        TestCase { label: "sub", data: "", bits: 32, expected: 0x440f00a9 },
        TestCase { label: "path", data: "/", bits: 60, expected: 0x98911d784580332 },
        TestCase { label: "params", data: "", bits: 36, expected: 0xc354b043a },
        TestCase { label: "frag", data: "", bits: 24, expected: 0x29e356 },
    ];

    for test_case in &test_cases {
        let result = hash_component(test_case.label, test_case.data.as_bytes(), test_case.bits).unwrap();
        assert_eq!(
            result,
            test_case.expected,
            "H{}('{}', '{}') should be 0x{:x}, got 0x{:x}",
            test_case.bits,
            test_case.label,
            test_case.data,
            test_case.expected,
            result
        );
    }
}

#[test]
fn test_empty_string_hashes() {
    // Test that empty strings hash consistently
    let empty_sub = ComponentHasher::hash_subdomain("").unwrap();
    let empty_params = ComponentHasher::hash_params("").unwrap();
    let empty_frag = ComponentHasher::hash_fragment("").unwrap();

    // These should be the specific values from the spec
    assert_eq!(empty_sub, 0x440f00a9);
    assert_eq!(empty_params, 0xc354b043a);
    assert_eq!(empty_frag, 0x29e356);

    // They should be different from each other (different labels)
    assert_ne!(empty_sub, empty_params);
    assert_ne!(empty_params, empty_frag);
    assert_ne!(empty_sub, empty_frag);
}

#[test]
fn test_hash_collision_resistance() {
    // Test that similar inputs produce different hashes
    let test_cases = vec![
        ("com", "co"),
        ("example", "examples"),
        ("api", "api2"),
        ("/", "/index"),
        ("q=test", "q=tests"),
    ];

    for (input1, input2) in test_cases {
        let hash1 = hash_component("test", input1.as_bytes(), 32).unwrap();
        let hash2 = hash_component("test", input2.as_bytes(), 32).unwrap();
        assert_ne!(hash1, hash2, "Similar inputs '{}' and '{}' should produce different hashes", input1, input2);
    }
}

#[test]
fn test_bit_width_error_handling() {
    // Test that invalid bit widths are rejected
    let test_hash = [0xFF; 32];

    let result = extract_lower_bits(&test_hash, 65); // Too many bits
    assert!(result.is_err());

    let result = extract_lower_bits(&test_hash, 0); // Zero bits should work
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}