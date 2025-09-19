fn main() {
    println!("SXURL Implementation Test Suite");
    println!("===============================");

    // Test hash functions against SXURL spec test vectors
    println!("\n1. Testing hash functions against spec:");

    // Test the spec test vector: H16("tld", "rs") should be 0x2397
    println!("  H16(\"tld\", \"rs\"):");
    let rs_hash = sxurl::ComponentHasher::hash_tld("rs").unwrap();
    println!("    Result: 0x{:04x}", rs_hash);
    if rs_hash == 0x2397 {
        println!("    ✓ Matches SXURL spec test vector");
    } else {
        println!("    ⚠ Does NOT match spec test vector 0x2397");
    }

    // Test consistency and determinism
    let com_hash1 = sxurl::ComponentHasher::hash_tld("com").unwrap();
    let com_hash2 = sxurl::ComponentHasher::hash_tld("com").unwrap();
    println!("  Consistency check: {} ✓", com_hash1 == com_hash2);

    // Test label separation
    let tld_com = sxurl::hash_component("tld", b"com", 16).unwrap();
    let domain_com = sxurl::hash_component("domain", b"com", 16).unwrap();
    println!("  Label separation: {} ✓", tld_com != domain_com);

    // Test URL normalization
    println!("\n2. Testing URL normalization:");
    let test_urls = vec![
        "HTTPS://EXAMPLE.COM/Path",
        "https://café.com/test",
        "https://docs.rs/",
    ];

    for test_url in test_urls {
        println!("  {}", test_url);
        match sxurl::normalize_url(test_url) {
            Ok(normalized) => println!("    → {}", normalized.as_str()),
            Err(e) => println!("    ✗ Error: {}", e),
        }
    }

    // Test invalid schemes
    println!("  Invalid schemes:");
    let invalid_urls = vec!["ws://example.com", "ftp://test.com"];
    for invalid_url in invalid_urls {
        match sxurl::normalize_url(invalid_url) {
            Ok(_) => println!("    {} ✗ Unexpectedly succeeded", invalid_url),
            Err(_) => println!("    {} ✓ Correctly rejected", invalid_url),
        }
    }

    // Test PSL domain splitting
    println!("\n3. Testing PSL domain splitting:");
    let test_hosts = vec![
        ("example.com", "com", "example", ""),
        ("api.example.com", "com", "example", "api"),
        ("docs.rs", "rs", "docs", ""),
        ("example.co.uk", "co.uk", "example", ""),
        ("api.example.co.uk", "co.uk", "example", "api"),
    ];

    for (host, expected_tld, expected_domain, expected_sub) in test_hosts {
        print!("  {} → ", host);
        match sxurl::split_host_with_psl(host) {
            Ok((tld, domain, subdomain)) => {
                let correct = tld == expected_tld && domain == expected_domain && subdomain == expected_sub;
                println!("tld:'{}' domain:'{}' sub:'{}' {}", tld, domain, subdomain, if correct { "✓" } else { "✗" });
            }
            Err(e) => println!("✗ Error: {}", e),
        }
    }

    // Test SXURL spec examples
    println!("\n4. Testing SXURL spec examples:");

    // Test case A: https://docs.rs/
    let docs_rs_url = "https://docs.rs/";
    println!("  Example A: {}", docs_rs_url);
    match sxurl::normalize_url(docs_rs_url) {
        Ok(normalized) => {
            match sxurl::extract_url_components(&normalized) {
                Ok(components) => {
                    match sxurl::pack_sxurl(&components) {
                        Ok(sxurl_bytes) => {
                            let hex = sxurl::sxurl_to_hex(&sxurl_bytes);
                            println!("    SXURL: {}", hex);

                            // Expected from spec: 1002397f4018b8efa86c31440f00a9000098911d784580332c354b043a29e356
                            let expected = "1002397f4018b8efa86c31440f00a9000098911d784580332c354b043a29e356";
                            if hex == expected {
                                println!("    ✓ Matches SXURL spec exactly");
                            } else {
                                println!("    ⚠ Does NOT match spec");
                                println!("    Expected: {}", expected);
                            }
                        }
                        Err(e) => println!("    ✗ Packing error: {}", e),
                    }
                }
                Err(e) => println!("    ✗ Component extraction error: {}", e),
            }
        }
        Err(e) => println!("    ✗ Normalization error: {}", e),
    }

    // Test basic SXURL packing
    println!("\n5. Testing basic SXURL packing:");

    let test_cases = vec![
        ("https://example.com/", "100"), // HTTPS, no flags
        ("https://google.com/search?q=test", "108"), // HTTPS, params present
    ];

    for (url, expected_header) in test_cases {
        println!("  {}", url);
        match sxurl::normalize_url(url) {
            Ok(normalized) => {
                match sxurl::extract_url_components(&normalized) {
                    Ok(components) => {
                        match sxurl::pack_sxurl(&components) {
                            Ok(sxurl_bytes) => {
                                let hex = sxurl::sxurl_to_hex(&sxurl_bytes);
                                let header = &hex[0..3];
                                println!("    SXURL: {}", hex);
                                if header == expected_header {
                                    println!("    ✓ Header {} correct", header);
                                } else {
                                    println!("    ✗ Header {} ≠ expected {}", header, expected_header);
                                }
                            }
                            Err(e) => println!("    ✗ Packing failed: {}", e),
                        }
                    }
                    Err(e) => println!("    ✗ Component extraction failed: {}", e),
                }
            }
            Err(e) => println!("    ✗ Normalization failed: {}", e),
        }
    }

    // Comprehensive worked example
    println!("\n6. Comprehensive Worked Example - Testing All Bits:");
    println!("================================================");

    let test_url = "https://docs.rs/";
    println!("Working through: {}", test_url);

    // Step 1: Parse and normalize
    println!("\nStep 1: Parse and normalize URL");
    match sxurl::normalize_url(test_url) {
        Ok(normalized) => {
            println!("  Normalized: {}", normalized.as_str());

            // Step 2: Extract components
            println!("\nStep 2: Extract URL components");
            match sxurl::extract_url_components(&normalized) {
                Ok(components) => {
                    println!("  Scheme: '{}'", components.scheme);
                    println!("  TLD: '{}'", components.tld);
                    println!("  Domain: '{}'", components.domain);
                    println!("  Subdomain: '{}'", components.subdomain);
                    println!("  Port: {}", components.port);
                    println!("  Path: '{}'", components.path);
                    println!("  Query: '{}'", components.query);
                    println!("  Fragment: '{}'", components.fragment);

                    // Step 3: Test individual hash functions
                    println!("\nStep 3: Test component hashing");

                    // Test TLD hash (should be 0x2397 for "rs")
                    let tld_hash = sxurl::ComponentHasher::hash_tld(&components.tld).unwrap();
                    println!("  H16('tld', '{}') = 0x{:04x}", components.tld, tld_hash);
                    if tld_hash == 0x2397 {
                        println!("    ✓ Matches spec test vector");
                    } else {
                        println!("    ⚠ Expected 0x2397 from spec");
                    }

                    // Test domain hash
                    let domain_hash = sxurl::ComponentHasher::hash_domain(&components.domain).unwrap();
                    println!("  H60('domain', '{}') = 0x{:015x}", components.domain, domain_hash);

                    // Test subdomain hash (empty)
                    let sub_hash = sxurl::ComponentHasher::hash_subdomain(&components.subdomain).unwrap();
                    println!("  H32('sub', '{}') = 0x{:08x}", components.subdomain, sub_hash);

                    // Test path hash
                    let path_hash = sxurl::ComponentHasher::hash_path(&components.path).unwrap();
                    println!("  H60('path', '{}') = 0x{:015x}", components.path, path_hash);

                    // Test params hash (empty)
                    let params_hash = sxurl::ComponentHasher::hash_params(&components.query).unwrap();
                    println!("  H36('params', '{}') = 0x{:09x}", components.query, params_hash);

                    // Test fragment hash (empty)
                    let frag_hash = sxurl::ComponentHasher::hash_fragment(&components.fragment).unwrap();
                    println!("  H24('frag', '{}') = 0x{:06x}", components.fragment, frag_hash);

                    // Step 4: Test header construction
                    println!("\nStep 4: Test header construction");

                    let scheme_code = match components.scheme.as_str() {
                        "https" => 0u64,
                        "http" => 1u64,
                        "ftp" => 2u64,
                        _ => panic!("Invalid scheme"),
                    };
                    println!("  Scheme '{}' -> code {}", components.scheme, scheme_code);

                    let flags =
                        (if !components.subdomain.is_empty() { 1u64 } else { 0u64 }) << 4 |
                        (if !components.query.is_empty() { 1u64 } else { 0u64 }) << 3 |
                        (if !components.fragment.is_empty() { 1u64 } else { 0u64 }) << 2 |
                        (if components.port != 443 { 1u64 } else { 0u64 }) << 1; // Default HTTPS port

                    println!("  Flags calculation:");
                    println!("    sub_present: {} (subdomain='{}')", !components.subdomain.is_empty(), components.subdomain);
                    println!("    params_present: {} (query='{}')", !components.query.is_empty(), components.query);
                    println!("    frag_present: {} (fragment='{}')", !components.fragment.is_empty(), components.fragment);
                    println!("    port_present: {} (port={}, default=443)", components.port != 443, components.port);
                    println!("    Flags value: 0b{:05b} = 0x{:x}", flags, flags);

                    let header_value = (1u64 << 8) | (scheme_code << 5) | flags;
                    println!("  Header: version(1) + scheme({}) + flags({}) = 0x{:03x}", scheme_code, flags, header_value);

                    // Step 5: Test bit packing
                    println!("\nStep 5: Test SXURL bit packing");

                    match sxurl::pack_sxurl(&components) {
                        Ok(sxurl_bytes) => {
                            let hex = sxurl::sxurl_to_hex(&sxurl_bytes);
                            println!("  Packed SXURL: {}", hex);

                            // Verify hex slice breakdown
                            println!("\nStep 6: Verify hex slice breakdown");
                            println!("  Header     [0:3]:   '{}'", &hex[0..3]);
                            println!("  TLD        [3:7]:   '{}'", &hex[3..7]);
                            println!("  Domain     [7:22]:  '{}'", &hex[7..22]);
                            println!("  Subdomain  [22:30]: '{}'", &hex[22..30]);
                            println!("  Port       [30:34]: '{}'", &hex[30..34]);
                            println!("  Path       [34:49]: '{}'", &hex[34..49]);
                            println!("  Params     [49:58]: '{}'", &hex[49..58]);
                            println!("  Fragment   [58:64]: '{}'", &hex[58..64]);

                            // Verify against expected values
                            println!("\nStep 7: Verify against expected values");
                            let expected_hex = "1002397f4018b8efa86c31440f00a9000098911d784580332c354b043a29e356";
                            println!("  Expected:  {}", expected_hex);
                            println!("  Actual:    {}", hex);

                            if hex == expected_hex {
                                println!("  ✅ PERFECT MATCH - Implementation correct!");
                            } else {
                                println!("  ❌ MISMATCH - Let's compare slice by slice:");

                                let slices = vec![
                                    ("Header", 0, 3),
                                    ("TLD", 3, 7),
                                    ("Domain", 7, 22),
                                    ("Subdomain", 22, 30),
                                    ("Port", 30, 34),
                                    ("Path", 34, 49),
                                    ("Params", 49, 58),
                                    ("Fragment", 58, 64),
                                ];

                                for (name, start, end) in slices {
                                    let expected_slice = &expected_hex[start..end];
                                    let actual_slice = &hex[start..end];
                                    if expected_slice == actual_slice {
                                        println!("    {} ✓: {}", name, actual_slice);
                                    } else {
                                        println!("    {} ❌: got '{}', expected '{}'", name, actual_slice, expected_slice);
                                    }
                                }
                            }
                        }
                        Err(e) => println!("  ❌ Packing failed: {}", e),
                    }
                }
                Err(e) => println!("  ❌ Component extraction failed: {}", e),
            }
        }
        Err(e) => println!("  ❌ Normalization failed: {}", e),
    }

    // Manual verification of spec values
    println!("\n7. Manual Verification of Spec Hash Values:");
    println!("==========================================");

    // Let's manually verify each hash step by step
    use sha2::{Sha256, Digest};

    println!("Testing H16('tld', 'rs') step by step:");

    // Step 1: Build the input string
    let mut hasher = Sha256::new();
    hasher.update(b"tld");     // Label
    hasher.update(&[0x00]);    // Separator
    hasher.update(b"rs");      // Data
    let hash_result = hasher.finalize();

    println!("  Input: 'tld' || 0x00 || 'rs'");
    println!("  SHA256: {}", hex::encode(&hash_result));

    // Step 2: Extract lower 16 bits
    println!("  First 8 bytes: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
             hash_result[0], hash_result[1], hash_result[2], hash_result[3],
             hash_result[4], hash_result[5], hash_result[6], hash_result[7]);

    // Extract 16 bits (2 bytes) from beginning, little-endian
    let lower_16 = (hash_result[1] as u16) << 8 | (hash_result[0] as u16);
    println!("  Lower 16 bits (little-endian): 0x{:04x}", lower_16);
    println!("  Spec claims: 0x2397");

    if lower_16 == 0x2397 {
        println!("  ✓ Our calculation matches spec");
    } else {
        println!("  ⚠ Our calculation differs from spec");
    }

    // Test the other hashes too
    println!("\nTesting other component hashes:");

    let test_cases = vec![
        ("domain", "docs", 60, 0xf4018b8efa86c31u64),
        ("sub", "", 32, 0x440f00a9u64),
        ("path", "/", 60, 0x98911d784580332u64),
        ("params", "", 36, 0xc354b043au64),
        ("frag", "", 24, 0x29e356u64),
    ];

    for (label, data, bits, expected) in test_cases {
        let mut hasher = Sha256::new();
        hasher.update(label.as_bytes());
        hasher.update(&[0x00]);
        hasher.update(data.as_bytes());
        let hash = hasher.finalize();

        println!("  H{}('{}', '{}'): SHA256 = {}", bits, label, data, hex::encode(&hash));

        // Extract lower n bits
        let bytes_needed = (bits + 7) / 8;
        let mut result = 0u64;
        for (i, &byte) in hash.iter().take(bytes_needed).enumerate() {
            result |= (byte as u64) << (i * 8);
        }
        let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
        result &= mask;

        println!("    Our calculation: 0x{:x}", result);
        println!("    Spec claims: 0x{:x}", expected);
        if result == expected {
            println!("    ✓ Match");
        } else {
            println!("    ⚠ Different");
        }
    }

    // Test header construction
    println!("\nTesting header construction:");
    println!("  Version: 1 (0001)");
    println!("  Scheme: https -> 0 (000)");
    println!("  Flags: no sub/params/frag/port -> 0 (00000)");
    let header = (1u16 << 8) | (0u16 << 5) | 0u16;
    println!("  Header: (1 << 8) | (0 << 5) | 0 = 0x{:03x}", header);
    println!("  Spec claims: 0x100");

    if header == 0x100 {
        println!("  ✓ Header calculation matches spec");
    } else {
        println!("  ⚠ Header calculation differs from spec");
    }

    // Detailed byte extraction analysis
    println!("\n8. Detailed Byte Extraction Analysis:");
    println!("====================================");

    let test_cases = vec![
        ("tld", "rs", 16),
        ("domain", "docs", 60),
        ("sub", "", 32),
        ("path", "/", 60),
        ("params", "", 36),
        ("frag", "", 24),
    ];

    for (label, data, bits) in test_cases {
        println!("\n--- H{}('{}', '{}') ---", bits, label, data);

        // Calculate SHA256
        let mut hasher = Sha256::new();
        hasher.update(label.as_bytes());
        hasher.update(&[0x00]);
        hasher.update(data.as_bytes());
        let hash = hasher.finalize();

        println!("SHA256: {}", hex::encode(&hash));

        // Show all 32 bytes with positions
        println!("Byte positions:");
        for chunk in hash.chunks(8) {
            let offset = chunk.as_ptr() as usize - hash.as_ptr() as usize;
            print!("  [{:2}-{:2}]: ", offset, offset + chunk.len() - 1);
            for &byte in chunk {
                print!("{:02x} ", byte);
            }
            println!();
        }

        let bytes_needed = (bits + 7) / 8;
        println!("Need {} bytes for {} bits", bytes_needed, bits);

        // Method 1: Our current implementation (from beginning, little-endian)
        println!("\nMethod 1 - From BEGINNING (little-endian):");
        let mut result1 = 0u64;
        print!("  Taking bytes: ");
        for (i, &byte) in hash.iter().take(bytes_needed).enumerate() {
            print!("[{}]=0x{:02x} ", i, byte);
            result1 |= (byte as u64) << (i * 8);
        }
        let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
        result1 &= mask;
        println!("\n  Result: 0x{:x} (masked to {} bits)", result1, bits);

        // Method 2: From end (big-endian style)
        println!("\nMethod 2 - From END (big-endian style):");
        let mut result2 = 0u64;
        let start_index = hash.len().saturating_sub(bytes_needed);
        print!("  Taking bytes: ");
        for (i, &byte) in hash[start_index..].iter().enumerate() {
            print!("[{}]=0x{:02x} ", start_index + i, byte);
            result2 = (result2 << 8) | (byte as u64);
        }
        result2 &= mask;
        println!("\n  Result: 0x{:x} (masked to {} bits)", result2, bits);

        // Method 3: From end (little-endian)
        println!("\nMethod 3 - From END (little-endian):");
        let mut result3 = 0u64;
        print!("  Taking bytes: ");
        for (i, &byte) in hash[start_index..].iter().enumerate() {
            print!("[{}]=0x{:02x} ", start_index + i, byte);
            result3 |= (byte as u64) << (i * 8);
        }
        result3 &= mask;
        println!("\n  Result: 0x{:x} (masked to {} bits)", result3, bits);

        // Show spec's claimed value
        let spec_values = [
            ("tld", "rs", 0x2397u64),
            ("domain", "docs", 0xf4018b8efa86c31u64),
            ("sub", "", 0x440f00a9u64),
            ("path", "/", 0x98911d784580332u64),
            ("params", "", 0xc354b043au64),
            ("frag", "", 0x29e356u64),
        ];

        if let Some((_, _, spec_value)) = spec_values.iter().find(|(l, d, _)| *l == label && *d == data) {
            println!("\nSpec claims: 0x{:x}", spec_value);

            if result1 == *spec_value {
                println!("✓ Method 1 matches spec");
            }
            if result2 == *spec_value {
                println!("✓ Method 2 matches spec");
            }
            if result3 == *spec_value {
                println!("✓ Method 3 matches spec");
            }

            if result1 != *spec_value && result2 != *spec_value && result3 != *spec_value {
                println!("⚠ None of our methods match the spec!");

                // Let's try to find where the spec value appears in the hash
                println!("Searching for spec value in hash...");

                // Convert spec value to bytes and search
                let spec_bytes = spec_value.to_le_bytes();
                let spec_bytes_be = spec_value.to_be_bytes();

                for i in 0..=(hash.len().saturating_sub(bytes_needed)) {
                    let slice = &hash[i..i+bytes_needed];

                    // Try little-endian interpretation
                    let mut test_val = 0u64;
                    for (j, &byte) in slice.iter().enumerate() {
                        test_val |= (byte as u64) << (j * 8);
                    }
                    test_val &= mask;

                    if test_val == *spec_value {
                        print!("  Found at bytes [{}..{}] (little-endian): ", i, i+bytes_needed-1);
                        for &byte in slice {
                            print!("{:02x} ", byte);
                        }
                        println!();
                    }

                    // Try big-endian interpretation
                    let mut test_val_be = 0u64;
                    for &byte in slice {
                        test_val_be = (test_val_be << 8) | (byte as u64);
                    }
                    test_val_be &= mask;

                    if test_val_be == *spec_value {
                        print!("  Found at bytes [{}..{}] (big-endian): ", i, i+bytes_needed-1);
                        for &byte in slice {
                            print!("{:02x} ", byte);
                        }
                        println!();
                    }
                }
            }
        }

        println!("{}", "-".repeat(50));
    }

    // Debug specific failing case
    println!("\n8. Debug Failing Test Case:");
    println!("============================");

    let failing_url = "http://api.example.com:8080/search?q=test#results";
    println!("Debugging: {}", failing_url);

    match sxurl::normalize_url(failing_url) {
        Ok(normalized) => {
            println!("  Normalized: {}", normalized.as_str());
            println!("  Scheme: {}", normalized.scheme());
            println!("  Port from URL: {:?}", normalized.port());

            match sxurl::extract_url_components(&normalized) {
                Ok(components) => {
                    println!("  Components:");
                    println!("    scheme: '{}'", components.scheme);
                    println!("    subdomain: '{}'", components.subdomain);
                    println!("    query: '{}'", components.query);
                    println!("    fragment: '{}'", components.fragment);
                    println!("    port: {}", components.port);

                    // Check default port logic
                    let default_port = match components.scheme.as_str() {
                        "http" => 80,
                        "https" => 443,
                        "ftp" => 21,
                        _ => 0,
                    };
                    println!("    default port for '{}': {}", components.scheme, default_port);
                    println!("    port_present should be: {}", components.port != default_port);

                    // Manually calculate flags
                    let sub_present = !components.subdomain.is_empty();
                    let params_present = !components.query.is_empty();
                    let frag_present = !components.fragment.is_empty();
                    let port_present = components.port != default_port;

                    let flags =
                        (if sub_present { 1u64 } else { 0u64 }) << 4 |
                        (if params_present { 1u64 } else { 0u64 }) << 3 |
                        (if frag_present { 1u64 } else { 0u64 }) << 2 |
                        (if port_present { 1u64 } else { 0u64 }) << 1;

                    println!("    Flags calculation:");
                    println!("      sub_present: {} ({})", sub_present, if sub_present { 1 } else { 0 });
                    println!("      params_present: {} ({})", params_present, if params_present { 1 } else { 0 });
                    println!("      frag_present: {} ({})", frag_present, if frag_present { 1 } else { 0 });
                    println!("      port_present: {} ({})", port_present, if port_present { 1 } else { 0 });
                    println!("      flags value: 0b{:05b} = 0x{:x}", flags, flags);

                    let scheme_code = match components.scheme.as_str() {
                        "https" => 0u64,
                        "http" => 1u64,
                        "ftp" => 2u64,
                        _ => panic!("Invalid scheme"),
                    };

                    let header_value = (1u64 << 8) | (scheme_code << 5) | flags;
                    println!("    Expected header: 0x{:03x}", header_value);

                    // Generate actual SXURL and check
                    match sxurl::pack_sxurl(&components) {
                        Ok(sxurl_bytes) => {
                            let hex = sxurl::sxurl_to_hex(&sxurl_bytes);
                            println!("  Actual SXURL: {}", hex);
                            println!("  Actual header: {}", &hex[0..3]);
                        }
                        Err(e) => println!("  Packing error: {}", e),
                    }
                }
                Err(e) => println!("  Component extraction error: {}", e),
            }
        }
        Err(e) => println!("  Normalization error: {}", e),
    }

    println!("\n===============================");
    println!("Test suite complete!");
    println!("{}", sxurl::placeholder());
}
