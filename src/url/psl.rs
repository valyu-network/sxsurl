//! Public Suffix List integration for proper domain splitting.

use psl::{Psl, List};
use crate::error::SxurlError;

/// Split a hostname into TLD, domain, and subdomain using the Public Suffix List.
///
/// According to the SXURL spec:
/// - `tld`: the public suffix (can be multi-label like "co.uk")
/// - `domain`: registrable label immediately left of the TLD
/// - `subdomain`: everything left of the domain, joined with dots
///
/// If PSL processing fails, falls back to simple rightmost-label-as-TLD.
pub fn split_host_with_psl(host: &str) -> Result<(String, String, String), SxurlError> {
    // Try to use PSL first
    if let Ok((tld, domain, subdomain)) = split_with_psl(host) {
        return Ok((tld, domain, subdomain));
    }

    // Fallback to simple splitting
    split_host_fallback(host)
}

/// Split hostname using the Public Suffix List.
fn split_with_psl(host: &str) -> Result<(String, String, String), SxurlError> {
    // Get the public suffix (TLD)
    let suffix = List.suffix(host.as_bytes())
        .ok_or(SxurlError::HostNotDns)?;
    let tld = std::str::from_utf8(suffix.as_bytes())
        .map_err(|_| SxurlError::HostNotDns)?
        .to_string();

    // Get the registrable domain (the full domain that can be registered)
    let domain_obj = List.domain(host.as_bytes())
        .ok_or(SxurlError::HostNotDns)?;
    let registrable = std::str::from_utf8(domain_obj.as_bytes())
        .map_err(|_| SxurlError::HostNotDns)?;

    // Extract the domain part by removing the TLD and the dot
    if !registrable.ends_with(&tld) {
        return Err(SxurlError::HostNotDns);
    }

    let domain_part = if tld.len() < registrable.len() {
        let without_tld = &registrable[..registrable.len() - tld.len()];
        if without_tld.ends_with('.') {
            &without_tld[..without_tld.len() - 1]
        } else {
            without_tld
        }
    } else {
        return Err(SxurlError::HostNotDns);
    };

    // Calculate subdomain: everything before the registrable domain
    let subdomain = if host.len() > registrable.len() {
        let before_registrable = &host[..host.len() - registrable.len()];
        if before_registrable.ends_with('.') {
            before_registrable[..before_registrable.len() - 1].to_string()
        } else {
            before_registrable.to_string()
        }
    } else {
        String::new()
    };

    Ok((tld, domain_part.to_string(), subdomain))
}

/// Fallback splitting when PSL is not available or fails.
///
/// Uses simple rule: rightmost label is TLD, second-to-rightmost is domain,
/// everything else is subdomain.
fn split_host_fallback(host: &str) -> Result<(String, String, String), SxurlError> {
    let labels: Vec<&str> = host.split('.').collect();

    if labels.len() < 2 {
        return Err(SxurlError::InvalidLabel("Host must have at least 2 labels".to_string()));
    }

    let tld = labels.last().unwrap().to_string();
    let domain = labels[labels.len() - 2].to_string();

    let subdomain = if labels.len() > 2 {
        labels[..labels.len() - 2].join(".")
    } else {
        String::new()
    };

    Ok((tld, domain, subdomain))
}

/// Create URL components from a normalized URL.
///
/// This function uses the PSL parsing for host splitting but maintains
/// the original port behavior to avoid breaking existing encoder/decoder logic.
pub fn extract_url_components(url: &url::Url) -> Result<crate::types::UrlComponents, SxurlError> {
    // Get the host and split it using PSL
    let host = url.host_str().ok_or(SxurlError::HostNotDns)?;
    let (tld, domain, subdomain) = split_host_with_psl(host)?;

    // Extract other components using original logic
    let scheme = url.scheme().to_string();
    let port = url.port().unwrap_or_else(|| {
        match url.scheme() {
            "http" => 80,
            "https" => 443,
            "ftp" => 21,
            _ => 0, // Unknown scheme, keep 0 as fallback
        }
    });
    let path = url.path().to_string();
    let query = url.query().unwrap_or("").to_string();
    let fragment = url.fragment().unwrap_or("").to_string();

    Ok(crate::types::UrlComponents::new(
        scheme,
        tld,
        domain,
        subdomain,
        port,
        path,
        query,
        fragment,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    #[test]
    fn test_simple_domain_splitting() {
        let (tld, domain, subdomain) = split_host_with_psl("example.com").unwrap();
        assert_eq!(tld, "com");
        assert_eq!(domain, "example");
        assert_eq!(subdomain, "");
    }

    #[test]
    fn test_subdomain_splitting() {
        let (tld, domain, subdomain) = split_host_with_psl("api.example.com").unwrap();
        assert_eq!(tld, "com");
        assert_eq!(domain, "example");
        assert_eq!(subdomain, "api");
    }

    #[test]
    fn test_multi_level_subdomain() {
        let (tld, domain, subdomain) = split_host_with_psl("v2.api.example.com").unwrap();
        assert_eq!(tld, "com");
        assert_eq!(domain, "example");
        assert_eq!(subdomain, "v2.api");
    }

    #[test]
    fn test_complex_tld() {
        // co.uk is a multi-label TLD
        let (tld, domain, subdomain) = split_host_with_psl("example.co.uk").unwrap();
        assert_eq!(tld, "co.uk");
        assert_eq!(domain, "example");
        assert_eq!(subdomain, "");
    }

    #[test]
    fn test_complex_tld_with_subdomain() {
        let (tld, domain, subdomain) = split_host_with_psl("api.example.co.uk").unwrap();
        assert_eq!(tld, "co.uk");
        assert_eq!(domain, "example");
        assert_eq!(subdomain, "api");
    }

    #[test]
    fn test_fallback_splitting() {
        // Test the fallback mechanism directly
        let (tld, domain, subdomain) = split_host_fallback("test.example.com").unwrap();
        assert_eq!(tld, "com");
        assert_eq!(domain, "example");
        assert_eq!(subdomain, "test");
    }

    #[test]
    fn test_extract_url_components() {
        let url = Url::parse("https://api.example.com:8443/search?q=test#results").unwrap();
        let components = extract_url_components(&url).unwrap();

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
    fn test_minimal_domain() {
        let result = split_host_with_psl("com");
        assert!(result.is_err()); // Single label should fail
    }

    #[test]
    fn test_international_domain() {
        // These should work with PSL
        let (tld, domain, subdomain) = split_host_with_psl("example.de").unwrap();
        assert_eq!(tld, "de");
        assert_eq!(domain, "example");
        assert_eq!(subdomain, "");
    }
}