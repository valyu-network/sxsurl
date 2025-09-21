//! Essential URL parsing and manipulation utilities.
//!
//! This module provides convenient functions for common URL operations that aren't
//! easily available in the standard `url` crate or require combining multiple operations.

use url::Url;
use crate::error::SxurlError;
use crate::types::UrlComponentType;
use crate::url::psl::split_host_with_psl;
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
/// use sxurl::split_url;
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

    // Handle port - if explicitly specified in URL, include it even if it's the default
    let port = if url.contains(&format!("{}:", &host)) {
        // Port is explicitly specified in the URL
        Some(parsed.port().unwrap_or_else(|| {
            // If parsed.port() is None but we detected a colon, it's a default port
            match scheme.as_str() {
                "https" => 443,
                "http" => 80,
                "ftp" => 21,
                _ => 80,
            }
        }))
    } else {
        parsed.port()
    };

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
/// use sxurl::split_domain;
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
/// use sxurl::get_path_segments;
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
/// use sxurl::get_filename;
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
/// use sxurl::parse_query;
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
/// use sxurl::get_query_value;
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
/// use sxurl::get_anchor;
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
/// use sxurl::strip_anchor;
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
/// use sxurl::join_url_path;
///
/// let url1 = join_url_path("https://api.example.com/v1", "users").unwrap();
/// assert_eq!(url1, "https://api.example.com/v1/users");
///
/// let url2 = join_url_path("https://api.example.com/v1/", "users").unwrap();
/// assert_eq!(url2, "https://api.example.com/v1/users");
/// ```
pub fn join_url_path(base_url: &str, path: &str) -> Result<String, SxurlError> {
    let mut base = Url::parse(base_url)?;

    // Ensure the base path ends with a slash for proper joining
    let mut base_path = base.path().to_string();
    if !base_path.ends_with('/') {
        base_path.push('/');
        base.set_path(&base_path);
    }

    let joined = base.join(path)?;
    Ok(joined.to_string())
}

/// Check if a URL uses HTTPS scheme.
///
/// # Examples
///
/// ```
/// use sxurl::is_https;
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
/// use sxurl::has_query;
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
/// use sxurl::has_anchor;
///
/// assert!(has_anchor("https://example.com#section"));
/// assert!(!has_anchor("https://example.com"));
/// ```
pub fn has_anchor(url: &str) -> bool {
    url.contains('#')
}

/// Extract a specific component from a URL.
///
/// This is a unified interface for extracting any URL component using an enum.
/// It internally uses `split_url()` and extracts the requested component.
///
/// # Arguments
///
/// * `url` - The URL to parse
/// * `component` - The component type to extract
///
/// # Returns
///
/// Returns the requested component as a string, or `None` if the component
/// is not present in the URL (e.g., no subdomain, no query, etc.).
///
/// # Examples
///
/// ```
/// use sxurl::{get_url_component, UrlComponentType};
///
/// let url = "https://api.github.com:443/repos?page=1#readme";
///
/// let scheme = get_url_component(url, UrlComponentType::Scheme).unwrap();
/// assert_eq!(scheme, Some("https".to_string()));
///
/// let domain = get_url_component(url, UrlComponentType::Domain).unwrap();
/// assert_eq!(domain, Some("github".to_string()));
///
/// let subdomain = get_url_component(url, UrlComponentType::Subdomain).unwrap();
/// assert_eq!(subdomain, Some("api".to_string()));
///
/// let port = get_url_component(url, UrlComponentType::Port).unwrap();
/// assert_eq!(port, Some("443".to_string()));
/// ```
pub fn get_url_component(url: &str, component: UrlComponentType) -> Result<Option<String>, SxurlError> {
    let parts = split_url(url)?;

    match component {
        UrlComponentType::Scheme => Ok(Some(parts.scheme)),
        UrlComponentType::Host => Ok(Some(parts.host)),
        UrlComponentType::Domain => Ok(Some(parts.domain)),
        UrlComponentType::Subdomain => Ok(parts.subdomain),
        UrlComponentType::Tld => Ok(Some(parts.tld)),
        UrlComponentType::Port => Ok(parts.port.map(|p| p.to_string())),
        UrlComponentType::Path => Ok(Some(parts.path)),
        UrlComponentType::Query => Ok(parts.query),
        UrlComponentType::Fragment => Ok(parts.anchor),
        UrlComponentType::PathSegments => {
            let segments = get_path_segments(url)?;
            if segments.is_empty() {
                Ok(None)
            } else {
                Ok(Some(segments.join(",")))
            }
        }
        UrlComponentType::Filename => get_filename(url),
    }
}

/// Remove a specific component from a URL.
///
/// This function removes the specified component from the URL and returns
/// the modified URL string. Some components cannot be removed (scheme, host, domain, tld)
/// as they would result in an invalid URL.
///
/// # Arguments
///
/// * `url` - The URL to modify
/// * `component` - The component type to remove
///
/// # Returns
///
/// Returns the modified URL string with the component removed.
///
/// # Examples
///
/// ```
/// use sxurl::{strip_url_component, UrlComponentType};
///
/// let clean = strip_url_component("https://api.github.com:443/repos?page=1#readme",
///                                 UrlComponentType::Query).unwrap();
/// assert_eq!(clean, "https://api.github.com/repos#readme");
///
/// let no_anchor = strip_url_component("https://example.com/page#section",
///                                     UrlComponentType::Fragment).unwrap();
/// assert_eq!(no_anchor, "https://example.com/page");
/// ```
pub fn strip_url_component(url: &str, component: UrlComponentType) -> Result<String, SxurlError> {
    let mut parsed = Url::parse(url)?;

    match component {
        UrlComponentType::Scheme => {
            return Err(SxurlError::ParseError("Cannot remove scheme from URL".to_string()));
        }
        UrlComponentType::Host | UrlComponentType::Domain | UrlComponentType::Tld => {
            return Err(SxurlError::ParseError("Cannot remove host/domain/tld from URL".to_string()));
        }
        UrlComponentType::Subdomain => {
            // Get current host and try to remove subdomain
            let parts = split_url(url)?;
            if parts.subdomain.is_some() {
                let new_host = format!("{}.{}", parts.domain, parts.tld);
                parsed.set_host(Some(&new_host))?;
            }
        }
        UrlComponentType::Port => {
            parsed.set_port(None).map_err(|_| SxurlError::ParseError("Failed to remove port".to_string()))?;
        }
        UrlComponentType::Path => {
            parsed.set_path("/");
        }
        UrlComponentType::Query => {
            parsed.set_query(None);
        }
        UrlComponentType::Fragment => {
            parsed.set_fragment(None);
        }
        UrlComponentType::PathSegments => {
            // Remove all path segments, keeping just "/"
            parsed.set_path("/");
        }
        UrlComponentType::Filename => {
            // Remove filename from path but keep directory structure
            let segments = get_path_segments(url)?;
            if !segments.is_empty() {
                // Check if last segment is a filename (has extension or is single segment)
                let last = segments.last().unwrap();
                if last.contains('.') || segments.len() == 1 {
                    // Remove the filename
                    let dir_segments = &segments[..segments.len() - 1];
                    let new_path = if dir_segments.is_empty() {
                        "/".to_string()
                    } else {
                        format!("/{}/", dir_segments.join("/"))
                    };
                    parsed.set_path(&new_path);
                }
            }
        }
    }

    Ok(parsed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::UrlComponentType;

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

    #[test]
    fn test_get_url_component() {
        let url = "https://api.github.com:443/repos?page=1#readme";

        // Test basic components
        assert_eq!(
            get_url_component(url, UrlComponentType::Scheme).unwrap(),
            Some("https".to_string())
        );
        assert_eq!(
            get_url_component(url, UrlComponentType::Host).unwrap(),
            Some("api.github.com".to_string())
        );
        assert_eq!(
            get_url_component(url, UrlComponentType::Domain).unwrap(),
            Some("github".to_string())
        );
        assert_eq!(
            get_url_component(url, UrlComponentType::Subdomain).unwrap(),
            Some("api".to_string())
        );
        assert_eq!(
            get_url_component(url, UrlComponentType::Tld).unwrap(),
            Some("com".to_string())
        );
        assert_eq!(
            get_url_component(url, UrlComponentType::Port).unwrap(),
            Some("443".to_string())
        );
        assert_eq!(
            get_url_component(url, UrlComponentType::Path).unwrap(),
            Some("/repos".to_string())
        );
        assert_eq!(
            get_url_component(url, UrlComponentType::Query).unwrap(),
            Some("page=1".to_string())
        );
        assert_eq!(
            get_url_component(url, UrlComponentType::Fragment).unwrap(),
            Some("readme".to_string())
        );

        // Test URL without optional components
        let simple_url = "https://example.com/";
        assert_eq!(
            get_url_component(simple_url, UrlComponentType::Subdomain).unwrap(),
            None
        );
        assert_eq!(
            get_url_component(simple_url, UrlComponentType::Port).unwrap(),
            None
        );
        assert_eq!(
            get_url_component(simple_url, UrlComponentType::Query).unwrap(),
            None
        );
        assert_eq!(
            get_url_component(simple_url, UrlComponentType::Fragment).unwrap(),
            None
        );

        // Test path segments
        let path_url = "https://example.com/api/v1/users";
        assert_eq!(
            get_url_component(path_url, UrlComponentType::PathSegments).unwrap(),
            Some("api,v1,users".to_string())
        );

        // Test filename
        let file_url = "https://example.com/docs/manual.pdf";
        assert_eq!(
            get_url_component(file_url, UrlComponentType::Filename).unwrap(),
            Some("manual.pdf".to_string())
        );
    }

    #[test]
    fn test_strip_url_component() {
        let url = "https://api.github.com:443/repos?page=1#readme";

        // Test removing query
        let no_query = strip_url_component(url, UrlComponentType::Query).unwrap();
        assert_eq!(no_query, "https://api.github.com/repos#readme");

        // Test removing fragment
        let no_fragment = strip_url_component(url, UrlComponentType::Fragment).unwrap();
        assert_eq!(no_fragment, "https://api.github.com/repos?page=1");

        // Test removing port
        let no_port = strip_url_component(url, UrlComponentType::Port).unwrap();
        assert_eq!(no_port, "https://api.github.com/repos?page=1#readme");

        // Test removing path
        let no_path = strip_url_component(url, UrlComponentType::Path).unwrap();
        assert_eq!(no_path, "https://api.github.com/?page=1#readme");

        // Test removing subdomain
        let no_subdomain = strip_url_component(url, UrlComponentType::Subdomain).unwrap();
        assert_eq!(no_subdomain, "https://github.com/repos?page=1#readme");

        // Test removing filename
        let file_url = "https://example.com/docs/manual.pdf";
        let no_filename = strip_url_component(file_url, UrlComponentType::Filename).unwrap();
        assert_eq!(no_filename, "https://example.com/docs/");

        // Test error cases - cannot remove essential components
        assert!(strip_url_component(url, UrlComponentType::Scheme).is_err());
        assert!(strip_url_component(url, UrlComponentType::Host).is_err());
        assert!(strip_url_component(url, UrlComponentType::Domain).is_err());
        assert!(strip_url_component(url, UrlComponentType::Tld).is_err());
    }

    #[test]
    fn test_component_functions_consistency() {
        let url = "https://api.github.com:443/repos?page=1#readme";

        // Verify that get_url_component returns the same as individual functions
        assert_eq!(
            get_url_component(url, UrlComponentType::Fragment).unwrap(),
            get_anchor(url).unwrap()
        );

        // Verify query component extraction matches
        let query_component = get_url_component(url, UrlComponentType::Query).unwrap();
        let parsed_query = parse_query(url).unwrap();
        assert_eq!(query_component, Some("page=1".to_string()));
        assert_eq!(parsed_query.get("page"), Some(&"1".to_string()));

        let expected_segments = get_path_segments(url).unwrap();
        let expected_segments_str: Vec<&str> = expected_segments.iter().map(|s| s.as_str()).collect();
        let actual_segments_str = get_url_component(url, UrlComponentType::PathSegments).unwrap().unwrap();
        let actual_segments: Vec<&str> = actual_segments_str.split(',').collect();
        assert_eq!(actual_segments, expected_segments_str);

        // Test that stripping and checking work together
        let no_anchor = strip_url_component(url, UrlComponentType::Fragment).unwrap();
        assert_eq!(
            get_url_component(&no_anchor, UrlComponentType::Fragment).unwrap(),
            None
        );
    }
}