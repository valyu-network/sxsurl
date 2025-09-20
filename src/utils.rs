//! Essential URL parsing and manipulation utilities.
//!
//! This module provides convenient functions for common URL operations that aren't
//! easily available in the standard `url` crate or require combining multiple operations.

use url::Url;
use crate::error::SxurlError;
use crate::psl::split_host_with_psl;
use std::collections::HashMap;

/// Complete URL parts extracted from a URL string.
#[derive(Debug, Clone, PartialEq)]
pub struct UrlParts {
    /// URL scheme (https, http, ftp)
    pub scheme: String,
    /// Full hostname (api.example.com)
    pub host: String,
    /// Port number (if specified or non-default)
    pub port: Option<u16>,
    /// Path component (/api/v1/users)
    pub path: String,
    /// Query string without the '?' (foo=bar&baz=qux)
    pub query: Option<String>,
    /// Anchor/fragment without the '#' (section1)
    pub anchor: Option<String>,
    /// Domain name only (example)
    pub domain: String,
    /// Top-level domain (com, org, co.uk)
    pub tld: String,
    /// Subdomain if present (api, www)
    pub subdomain: Option<String>,
}

/// Parse a URL into all its components at once.
///
/// This is more convenient than calling multiple methods on a `Url` object
/// and provides domain splitting using the Public Suffix List.
///
/// # Examples
///
/// ```
/// use sxurl::utils::split_url;
///
/// let parts = split_url("https://api.github.com/repos?page=1#readme").unwrap();
/// assert_eq!(parts.scheme, "https");
/// assert_eq!(parts.domain, "github");
/// assert_eq!(parts.subdomain, Some("api".to_string()));
/// assert_eq!(parts.anchor, Some("readme".to_string()));
/// ```
pub fn split_url(url: &str) -> Result<UrlParts, SxurlError> {
    let parsed = Url::parse(url)?;

    // Get basic components
    let scheme = parsed.scheme().to_string();
    let host = parsed.host_str().ok_or(SxurlError::HostNotDns)?.to_string();
    let port = parsed.port();
    let path = parsed.path().to_string();
    let query = parsed.query().map(|q| q.to_string());
    let anchor = parsed.fragment().map(|f| f.to_string());

    // Split domain using PSL
    let (tld, domain, subdomain_str) = split_host_with_psl(&host)?;
    let subdomain = if subdomain_str.is_empty() {
        None
    } else {
        Some(subdomain_str)
    };

    Ok(UrlParts {
        scheme,
        host,
        port,
        path,
        query,
        anchor,
        domain,
        tld,
        subdomain,
    })
}

/// Split a URL's domain into subdomain, domain, and TLD parts.
///
/// Uses the Public Suffix List for accurate domain splitting.
///
/// # Examples
///
/// ```
/// use sxurl::utils::split_domain;
///
/// let (sub, domain, tld) = split_domain("https://api.github.com").unwrap();
/// assert_eq!(sub, Some("api".to_string()));
/// assert_eq!(domain, "github");
/// assert_eq!(tld, "com");
/// ```
///
/// # Returns
///
/// Returns `(subdomain, domain, tld)` where subdomain is `None` if not present.
pub fn split_domain(url: &str) -> Result<(Option<String>, String, String), SxurlError> {
    let parsed = Url::parse(url)?;
    let host = parsed.host_str().ok_or(SxurlError::HostNotDns)?;

    let (tld, domain, subdomain_str) = split_host_with_psl(host)?;
    let subdomain = if subdomain_str.is_empty() {
        None
    } else {
        Some(subdomain_str)
    };

    Ok((subdomain, domain, tld))
}

/// Split a URL's path into segments.
///
/// Removes empty segments and decodes percent-encoded characters.
///
/// # Examples
///
/// ```
/// use sxurl::utils::get_path_segments;
///
/// let segments = get_path_segments("https://example.com/api/v1/users").unwrap();
/// assert_eq!(segments, vec!["api", "v1", "users"]);
/// ```
pub fn get_path_segments(url: &str) -> Result<Vec<String>, SxurlError> {
    let parsed = Url::parse(url)?;
    Ok(parsed.path_segments()
        .unwrap_or_else(|| "".split('/'))
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect())
}

/// Extract the filename from a URL path.
///
/// Returns the last path segment if it appears to be a filename
/// (contains a dot or is the last non-empty segment).
///
/// # Examples
///
/// ```
/// use sxurl::utils::get_filename;
///
/// let filename = get_filename("https://example.com/docs/file.pdf").unwrap();
/// assert_eq!(filename, Some("file.pdf".to_string()));
///
/// let no_file = get_filename("https://example.com/api/users/").unwrap();
/// assert_eq!(no_file, None);
/// ```
pub fn get_filename(url: &str) -> Result<Option<String>, SxurlError> {
    let segments = get_path_segments(url)?;

    if let Some(last) = segments.last() {
        // Consider it a filename if it has an extension or is the only segment
        if last.contains('.') || segments.len() == 1 {
            Ok(Some(last.clone()))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

/// Parse query string into a HashMap of key-value pairs.
///
/// Handles URL decoding of both keys and values.
///
/// # Examples
///
/// ```
/// use sxurl::utils::parse_query;
///
/// let params = parse_query("https://example.com?foo=bar&page=1").unwrap();
/// assert_eq!(params.get("foo"), Some(&"bar".to_string()));
/// assert_eq!(params.get("page"), Some(&"1".to_string()));
/// ```
pub fn parse_query(url: &str) -> Result<HashMap<String, String>, SxurlError> {
    let parsed = Url::parse(url)?;

    let mut params = HashMap::new();
    for (key, value) in parsed.query_pairs() {
        params.insert(key.to_string(), value.to_string());
    }

    Ok(params)
}

/// Get a specific query parameter value.
///
/// # Examples
///
/// ```
/// use sxurl::utils::get_query_value;
///
/// let value = get_query_value("https://example.com?page=2&sort=name", "page").unwrap();
/// assert_eq!(value, Some("2".to_string()));
///
/// let missing = get_query_value("https://example.com?page=2", "missing").unwrap();
/// assert_eq!(missing, None);
/// ```
pub fn get_query_value(url: &str, key: &str) -> Result<Option<String>, SxurlError> {
    let params = parse_query(url)?;
    Ok(params.get(key).cloned())
}

/// Get the anchor (fragment) from a URL.
///
/// Returns the fragment component without the '#' character.
///
/// # Examples
///
/// ```
/// use sxurl::utils::get_anchor;
///
/// let anchor = get_anchor("https://docs.rs/serde#examples").unwrap();
/// assert_eq!(anchor, Some("examples".to_string()));
///
/// let no_anchor = get_anchor("https://example.com").unwrap();
/// assert_eq!(no_anchor, None);
/// ```
pub fn get_anchor(url: &str) -> Result<Option<String>, SxurlError> {
    let parsed = Url::parse(url)?;
    Ok(parsed.fragment().map(|f| f.to_string()))
}

/// Remove the anchor (fragment) from a URL.
///
/// # Examples
///
/// ```
/// use sxurl::utils::strip_anchor;
///
/// let clean = strip_anchor("https://example.com/page#section").unwrap();
/// assert_eq!(clean, "https://example.com/page");
/// ```
pub fn strip_anchor(url: &str) -> Result<String, SxurlError> {
    let mut parsed = Url::parse(url)?;
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

/// Join a base URL with a path segment.
///
/// Properly handles trailing slashes and relative path resolution.
///
/// # Examples
///
/// ```
/// use sxurl::utils::join_url_path;
///
/// let url1 = join_url_path("https://api.example.com/v1", "users").unwrap();
/// assert_eq!(url1, "https://api.example.com/v1/users");
///
/// let url2 = join_url_path("https://api.example.com/v1/", "users").unwrap();
/// assert_eq!(url2, "https://api.example.com/v1/users");
/// ```
pub fn join_url_path(base_url: &str, path: &str) -> Result<String, SxurlError> {
    let base = Url::parse(base_url)?;
    let joined = base.join(path)?;
    Ok(joined.to_string())
}

/// Check if a URL uses HTTPS scheme.
///
/// # Examples
///
/// ```
/// use sxurl::utils::is_https;
///
/// assert!(is_https("https://example.com"));
/// assert!(!is_https("http://example.com"));
/// ```
pub fn is_https(url: &str) -> bool {
    url.starts_with("https://")
}

/// Check if a URL has a query string.
///
/// # Examples
///
/// ```
/// use sxurl::utils::has_query;
///
/// assert!(has_query("https://example.com?foo=bar"));
/// assert!(!has_query("https://example.com"));
/// ```
pub fn has_query(url: &str) -> bool {
    url.contains('?')
}

/// Check if a URL has an anchor (fragment).
///
/// # Examples
///
/// ```
/// use sxurl::utils::has_anchor;
///
/// assert!(has_anchor("https://example.com#section"));
/// assert!(!has_anchor("https://example.com"));
/// ```
pub fn has_anchor(url: &str) -> bool {
    url.contains('#')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_url_complete() {
        let parts = split_url("https://api.github.com:443/repos?page=1&sort=name#readme").unwrap();

        assert_eq!(parts.scheme, "https");
        assert_eq!(parts.host, "api.github.com");
        assert_eq!(parts.port, Some(443));
        assert_eq!(parts.path, "/repos");
        assert_eq!(parts.query, Some("page=1&sort=name".to_string()));
        assert_eq!(parts.anchor, Some("readme".to_string()));
        assert_eq!(parts.domain, "github");
        assert_eq!(parts.tld, "com");
        assert_eq!(parts.subdomain, Some("api".to_string()));
    }

    #[test]
    fn test_split_url_minimal() {
        let parts = split_url("https://example.com").unwrap();

        assert_eq!(parts.scheme, "https");
        assert_eq!(parts.host, "example.com");
        assert_eq!(parts.port, None);
        assert_eq!(parts.path, "/");
        assert_eq!(parts.query, None);
        assert_eq!(parts.anchor, None);
        assert_eq!(parts.domain, "example");
        assert_eq!(parts.tld, "com");
        assert_eq!(parts.subdomain, None);
    }

    #[test]
    fn test_split_domain() {
        let (sub, domain, tld) = split_domain("https://api.github.com").unwrap();
        assert_eq!(sub, Some("api".to_string()));
        assert_eq!(domain, "github");
        assert_eq!(tld, "com");

        let (sub2, domain2, tld2) = split_domain("https://example.co.uk").unwrap();
        assert_eq!(sub2, None);
        assert_eq!(domain2, "example");
        assert_eq!(tld2, "co.uk");
    }

    #[test]
    fn test_get_path_segments() {
        let segments = get_path_segments("https://example.com/api/v1/users").unwrap();
        assert_eq!(segments, vec!["api", "v1", "users"]);

        let empty = get_path_segments("https://example.com/").unwrap();
        assert_eq!(empty, Vec::<String>::new());
    }

    #[test]
    fn test_get_filename() {
        let filename = get_filename("https://example.com/docs/file.pdf").unwrap();
        assert_eq!(filename, Some("file.pdf".to_string()));

        let no_file = get_filename("https://example.com/api/users/").unwrap();
        assert_eq!(no_file, None);

        let single_segment = get_filename("https://example.com/file").unwrap();
        assert_eq!(single_segment, Some("file".to_string()));
    }

    #[test]
    fn test_parse_query() {
        let params = parse_query("https://example.com?foo=bar&page=1").unwrap();
        assert_eq!(params.get("foo"), Some(&"bar".to_string()));
        assert_eq!(params.get("page"), Some(&"1".to_string()));

        let empty = parse_query("https://example.com").unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_get_query_value() {
        let value = get_query_value("https://example.com?page=2&sort=name", "page").unwrap();
        assert_eq!(value, Some("2".to_string()));

        let missing = get_query_value("https://example.com?page=2", "missing").unwrap();
        assert_eq!(missing, None);
    }

    #[test]
    fn test_anchor_operations() {
        let anchor = get_anchor("https://docs.rs/serde#examples").unwrap();
        assert_eq!(anchor, Some("examples".to_string()));

        let no_anchor = get_anchor("https://example.com").unwrap();
        assert_eq!(no_anchor, None);

        let clean = strip_anchor("https://example.com/page#section").unwrap();
        assert_eq!(clean, "https://example.com/page");
    }

    #[test]
    fn test_join_url_path() {
        let url1 = join_url_path("https://api.example.com/v1", "users").unwrap();
        assert_eq!(url1, "https://api.example.com/v1/users");

        let url2 = join_url_path("https://api.example.com/v1/", "users").unwrap();
        assert_eq!(url2, "https://api.example.com/v1/users");

        let url3 = join_url_path("https://api.example.com", "../other").unwrap();
        assert_eq!(url3, "https://api.example.com/other");
    }

    #[test]
    fn test_url_checks() {
        assert!(is_https("https://example.com"));
        assert!(!is_https("http://example.com"));

        assert!(has_query("https://example.com?foo=bar"));
        assert!(!has_query("https://example.com"));

        assert!(has_anchor("https://example.com#section"));
        assert!(!has_anchor("https://example.com"));
    }
}