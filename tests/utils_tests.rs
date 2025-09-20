//! Integration tests for URL utilities.

use sxurl::{split_url, parse_query, get_anchor, strip_anchor, join_url_path, is_https};

#[test]
fn test_url_parsing_integration() {
    let url = "https://api.github.com/repos?page=1&sort=name#readme";

    // Test split_url
    let parts = split_url(url).unwrap();
    assert_eq!(parts.scheme, "https");
    assert_eq!(parts.host, "api.github.com");
    assert_eq!(parts.domain, "github");
    assert_eq!(parts.subdomain, Some("api".to_string()));
    assert_eq!(parts.path, "/repos");
    assert_eq!(parts.query, Some("page=1&sort=name".to_string()));
    assert_eq!(parts.anchor, Some("readme".to_string()));
    assert_eq!(parts.tld, "com");
}

#[test]
fn test_query_parameter_parsing() {
    let url = "https://search.example.com/results?q=rust&page=2&sort=relevance";

    let params = parse_query(url).unwrap();
    assert_eq!(params.get("q"), Some(&"rust".to_string()));
    assert_eq!(params.get("page"), Some(&"2".to_string()));
    assert_eq!(params.get("sort"), Some(&"relevance".to_string()));
    assert_eq!(params.len(), 3);
}

#[test]
fn test_anchor_operations() {
    let url_with_anchor = "https://docs.rs/serde#examples";
    let url_without_anchor = "https://docs.rs/serde";

    // Test get_anchor
    let anchor = get_anchor(url_with_anchor).unwrap();
    assert_eq!(anchor, Some("examples".to_string()));

    let no_anchor = get_anchor(url_without_anchor).unwrap();
    assert_eq!(no_anchor, None);

    // Test strip_anchor
    let stripped = strip_anchor(url_with_anchor).unwrap();
    assert_eq!(stripped, "https://docs.rs/serde");
}

#[test]
fn test_url_joining() {
    let base = "https://api.example.com/v1";
    let path = "users";

    let joined = join_url_path(base, path).unwrap();
    assert_eq!(joined, "https://api.example.com/v1/users");

    // Test with trailing slash
    let base_with_slash = "https://api.example.com/v1/";
    let joined2 = join_url_path(base_with_slash, path).unwrap();
    assert_eq!(joined2, "https://api.example.com/v1/users");
}

#[test]
fn test_scheme_detection() {
    assert!(is_https("https://example.com"));
    assert!(is_https("https://api.example.com/path?query=1#anchor"));
    assert!(!is_https("http://example.com"));
    assert!(!is_https("ftp://files.example.com"));
}

#[test]
fn test_complex_domains() {
    // Test complex TLD
    let parts = split_url("https://example.co.uk/path").unwrap();
    assert_eq!(parts.domain, "example");
    assert_eq!(parts.tld, "co.uk");
    assert_eq!(parts.subdomain, None);

    // Test subdomain with complex TLD
    let parts2 = split_url("https://api.example.co.uk/path").unwrap();
    assert_eq!(parts2.domain, "example");
    assert_eq!(parts2.tld, "co.uk");
    assert_eq!(parts2.subdomain, Some("api".to_string()));
}

#[test]
fn test_empty_components() {
    let minimal_url = "https://example.com";

    let parts = split_url(minimal_url).unwrap();
    assert_eq!(parts.scheme, "https");
    assert_eq!(parts.host, "example.com");
    assert_eq!(parts.domain, "example");
    assert_eq!(parts.tld, "com");
    assert_eq!(parts.subdomain, None);
    assert_eq!(parts.path, "/");
    assert_eq!(parts.query, None);
    assert_eq!(parts.anchor, None);

    let params = parse_query(minimal_url).unwrap();
    assert!(params.is_empty());
}