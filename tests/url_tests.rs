//! Tests for URL normalization, validation, and component extraction.

use sxurl::*;

#[test]
fn test_url_normalization_basic() {
    let test_cases = vec![
        ("HTTPS://EXAMPLE.COM/", "https://example.com/"),
        ("HTTP://DOCS.RS/PATH", "http://docs.rs/PATH"),
        ("https://Example.Org/Test", "https://example.org/Test"),
        ("FTP://FILES.EXAMPLE.COM/", "ftp://files.example.com/"),
    ];

    for (input, expected) in test_cases {
        let result = normalize_url(input).unwrap();
        assert_eq!(result.as_str(), expected, "Normalization failed for: {}", input);
    }
}

#[test]
fn test_url_normalization_idna() {
    // Test IDNA normalization for international domains
    let test_cases = vec![
        "https://café.com/",
        "https://москва.рф/",
        "https://日本.jp/",
    ];

    for url in test_cases {
        let result = normalize_url(url);
        assert!(result.is_ok(), "IDNA normalization should work for: {}", url);

        let normalized = result.unwrap();
        assert!(normalized.host_str().unwrap().is_ascii(), "Host should be ASCII after IDNA: {}", url);
    }
}

#[test]
fn test_scheme_validation() {
    // Valid schemes
    let valid_schemes = vec![
        "https://example.com/",
        "http://example.com/",
        "ftp://example.com/",
    ];

    for url in valid_schemes {
        let result = normalize_url(url);
        assert!(result.is_ok(), "Should accept valid scheme: {}", url);
    }

    // Invalid schemes
    let invalid_schemes = vec![
        "ws://example.com/",
        "file:///path",
        "mailto:test@example.com",
        "data:text/plain,hello",
        "javascript:alert('test')",
    ];

    for url in invalid_schemes {
        let result = normalize_url(url);
        assert!(result.is_err(), "Should reject invalid scheme: {}", url);
    }
}

#[test]
fn test_component_extraction() {
    let test_cases = vec![
        (
            "https://docs.rs/",
            UrlComponents {
                scheme: "https".to_string(),
                tld: "rs".to_string(),
                domain: "docs".to_string(),
                subdomain: "".to_string(),
                port: 443,
                path: "/".to_string(),
                query: "".to_string(),
                fragment: "".to_string(),
            }
        ),
        (
            "http://api.example.com:8080/search?q=test#results",
            UrlComponents {
                scheme: "http".to_string(),
                tld: "com".to_string(),
                domain: "example".to_string(),
                subdomain: "api".to_string(),
                port: 8080,
                path: "/search".to_string(),
                query: "q=test".to_string(),
                fragment: "results".to_string(),
            }
        ),
    ];

    for (url, expected) in test_cases {
        let normalized = normalize_url(url).unwrap();
        let components = extract_url_components(&normalized).unwrap();

        assert_eq!(components.scheme, expected.scheme, "Scheme mismatch for: {}", url);
        assert_eq!(components.tld, expected.tld, "TLD mismatch for: {}", url);
        assert_eq!(components.domain, expected.domain, "Domain mismatch for: {}", url);
        assert_eq!(components.subdomain, expected.subdomain, "Subdomain mismatch for: {}", url);
        assert_eq!(components.port, expected.port, "Port mismatch for: {}", url);
        assert_eq!(components.path, expected.path, "Path mismatch for: {}", url);
        assert_eq!(components.query, expected.query, "Query mismatch for: {}", url);
        assert_eq!(components.fragment, expected.fragment, "Fragment mismatch for: {}", url);
    }
}

#[test]
fn test_default_ports() {
    let test_cases = vec![
        ("https://example.com/", 443),
        ("http://example.com/", 80),
        ("ftp://example.com/", 21),
        ("https://example.com:443/", 443),  // Explicit default
        ("https://example.com:8443/", 8443), // Non-default
    ];

    for (url, expected_port) in test_cases {
        let normalized = normalize_url(url).unwrap();
        let components = extract_url_components(&normalized).unwrap();
        assert_eq!(components.port, expected_port, "Port mismatch for: {}", url);
    }
}

#[test]
fn test_path_preservation() {
    // Test that paths are preserved exactly (no normalization)
    let test_cases = vec![
        ("https://example.com/path", "/path"),
        ("https://example.com/path/", "/path/"),
        ("https://example.com/path%20with%20spaces", "/path%20with%20spaces"),
        ("https://example.com/path?query", "/path"),
        ("https://example.com/", "/"),
        ("https://example.com", "/"),
    ];

    for (url, expected_path) in test_cases {
        let normalized = normalize_url(url).unwrap();
        let components = extract_url_components(&normalized).unwrap();
        assert_eq!(components.path, expected_path, "Path mismatch for: {}", url);
    }
}

#[test]
fn test_query_preservation() {
    // Test that query parameters are preserved exactly
    let test_cases = vec![
        ("https://example.com/?q=test", "q=test"),
        ("https://example.com/?q=test&lang=en", "q=test&lang=en"),
        ("https://example.com/?q=hello%20world", "q=hello%20world"),
        ("https://example.com/", ""),
        ("https://example.com/?", ""),
    ];

    for (url, expected_query) in test_cases {
        let normalized = normalize_url(url).unwrap();
        let components = extract_url_components(&normalized).unwrap();
        assert_eq!(components.query, expected_query, "Query mismatch for: {}", url);
    }
}

#[test]
fn test_fragment_preservation() {
    // Test that fragments are preserved exactly
    let test_cases = vec![
        ("https://example.com/#section", "section"),
        ("https://example.com/#section%20one", "section%20one"),
        ("https://example.com/", ""),
        ("https://example.com/#", ""),
    ];

    for (url, expected_fragment) in test_cases {
        let normalized = normalize_url(url).unwrap();
        let components = extract_url_components(&normalized).unwrap();
        assert_eq!(components.fragment, expected_fragment, "Fragment mismatch for: {}", url);
    }
}

#[test]
fn test_invalid_urls() {
    let invalid_urls = vec![
        "not-a-url",
        "://example.com",
        "https://",
        "https:///path",
        "",
    ];

    for url in invalid_urls {
        let result = normalize_url(url);
        assert!(result.is_err(), "Should reject invalid URL: {}", url);
    }
}

#[test]
fn test_ip_address_rejection() {
    // SXURL spec only supports DNS names, not IP addresses
    let ip_urls = vec![
        "https://192.168.1.1/",
        "http://127.0.0.1:8080/",
        "https://[::1]/",
        "https://[2001:db8::1]/",
    ];

    for url in ip_urls {
        let result = normalize_url(url);
        // Note: This depends on implementation - the spec says DNS names only
        // but url crate might parse IP addresses successfully
        if result.is_ok() {
            let components_result = extract_url_components(&result.unwrap());
            // PSL extraction should fail for IP addresses
            assert!(components_result.is_err(), "Should reject IP address: {}", url);
        }
    }
}

#[test]
fn test_host_validation() {
    // Test that host validation works correctly
    let valid_hosts = vec![
        "example.com",
        "sub.example.com",
        "a.b.c.example.com",
        "test-domain.org",
        "123example.com",
    ];

    for host in valid_hosts {
        let url = format!("https://{}/", host);
        let result = normalize_url(&url);
        assert!(result.is_ok(), "Should accept valid host: {}", host);
    }

    // Invalid hosts (these might not all be caught by url crate, but PSL should handle them)
    let invalid_hosts = vec![
        "-example.com",      // starts with hyphen
        "example-.com",      // ends with hyphen
        ".example.com",      // starts with dot
        "example..com",      // double dot
        "ex ample.com",      // space
    ];

    for host in invalid_hosts {
        let url = format!("https://{}/", host);
        let result = normalize_url(&url);
        // Some invalid hosts might be accepted by url crate but rejected later
        if result.is_ok() {
            let components_result = extract_url_components(&result.unwrap());
            // Either normalization or component extraction should fail
            assert!(components_result.is_err(), "Should reject invalid host: {}", host);
        }
    }
}

#[test]
fn test_case_insensitive_normalization() {
    // Test that scheme and host are normalized to lowercase
    let test_cases = vec![
        ("HTTPS://EXAMPLE.COM/Path", "https", "example.com"),
        ("HTTP://DOCS.RS/", "http", "docs.rs"),
        ("FTP://Files.Example.ORG/", "ftp", "files.example.org"),
    ];

    for (url, expected_scheme, expected_host) in test_cases {
        let normalized = normalize_url(url).unwrap();
        assert_eq!(normalized.scheme(), expected_scheme);
        assert_eq!(normalized.host_str().unwrap(), expected_host);
    }
}

#[test]
fn test_url_components_new() {
    // Test the UrlComponents::new constructor
    let components = UrlComponents::new(
        "https".to_string(),
        "com".to_string(),
        "example".to_string(),
        "api".to_string(),
        8443,
        "/search".to_string(),
        "q=test".to_string(),
        "results".to_string(),
    );

    assert_eq!(components.scheme, "https");
    assert_eq!(components.tld, "com");
    assert_eq!(components.domain, "example");
    assert_eq!(components.subdomain, "api");
    assert_eq!(components.port, 8443);
    assert_eq!(components.path, "/search");
    assert_eq!(components.query, "q=test");
    assert_eq!(components.fragment, "results");
}

#[test]
fn test_complex_real_world_urls() {
    // Test some complex real-world URLs
    let complex_urls = vec![
        "https://docs.rs/serde/1.0.136/serde/de/trait.Deserialize.html",
        "https://github.com/rust-lang/rust/blob/master/library/std/src/lib.rs",
        "https://crates.io/search?q=async&sort=downloads",
        "https://play.rust-lang.org/?version=stable&mode=debug&edition=2021",
        "https://www.rust-lang.org/learn/get-started#installing-rust",
    ];

    for url in complex_urls {
        let normalized = normalize_url(url).unwrap();
        let components = extract_url_components(&normalized).unwrap();

        // Basic sanity checks
        assert!(!components.scheme.is_empty());
        assert!(!components.tld.is_empty());
        assert!(!components.domain.is_empty());
        assert!(!components.path.is_empty());

        println!("Processed: {} -> TLD:{} Domain:{} Sub:{}",
                url, components.tld, components.domain, components.subdomain);
    }
}