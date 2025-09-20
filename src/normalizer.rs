//! URL normalization functions for SXURL encoding.

use url::Url;
use crate::error::SxurlError;

/// Normalize a URL according to SXURL requirements.
///
/// This function:
/// 1. Converts scheme and host to lowercase
/// 2. Applies IDNA UTS-46 conversion to the host
/// 3. Validates host format and length constraints
/// 4. Leaves path, query, and fragment as raw bytes (no normalization)
pub fn normalize_url(url_str: &str) -> Result<Url, SxurlError> {
    // Reject obviously malformed URLs with empty hosts
    if url_str.contains("://") {
        let parts: Vec<&str> = url_str.splitn(2, "://").collect();
        if parts.len() == 2 {
            let after_scheme = parts[1];
            // Check if there's nothing or only slashes/paths after ://
            if after_scheme.is_empty() || after_scheme.starts_with('/') {
                return Err(SxurlError::HostNotDns);
            }
        }
    }

    // Parse the URL first
    let url = Url::parse(url_str)?;

    // Check for missing or empty host explicitly
    let host_str = match url.host_str() {
        Some(host) if !host.is_empty() => host,
        _ => return Err(SxurlError::HostNotDns),
    };

    // Validate scheme early
    match url.scheme() {
        "https" | "http" | "ftp" => {},
        _ => return Err(SxurlError::InvalidScheme),
    }

    // Get the host and normalize it
    let normalized_host = normalize_host(host_str)?;

    // Reconstruct URL with normalized host
    let mut reconstructed = String::new();
    reconstructed.push_str(url.scheme());
    reconstructed.push_str("://");

    let username = url.username();
    if !username.is_empty() {
        reconstructed.push_str(username);
        if let Some(password) = url.password() {
            reconstructed.push(':');
            reconstructed.push_str(password);
        }
        reconstructed.push('@');
    }

    reconstructed.push_str(&normalized_host);

    if let Some(port) = url.port() {
        reconstructed.push(':');
        reconstructed.push_str(&port.to_string());
    }

    reconstructed.push_str(url.path());

    if let Some(query) = url.query() {
        reconstructed.push('?');
        reconstructed.push_str(query);
    }

    if let Some(fragment) = url.fragment() {
        reconstructed.push('#');
        reconstructed.push_str(fragment);
    }

    // Parse the reconstructed URL
    Ok(Url::parse(&reconstructed)?)
}

/// Normalize a hostname according to SXURL requirements.
///
/// This function:
/// 1. Converts to lowercase
/// 2. Applies IDNA UTS-46 ASCII conversion
/// 3. Validates DNS label constraints
pub fn normalize_host(host: &str) -> Result<String, SxurlError> {
    // Convert to lowercase first
    let lowercase_host = host.to_lowercase();

    // Apply IDNA conversion to ASCII
    let ascii_host = match idna::domain_to_ascii(&lowercase_host) {
        Ok(ascii) => ascii,
        Err(_) => return Err(SxurlError::HostNotDns),
    };

    // Validate the normalized host
    validate_host(&ascii_host)?;

    Ok(ascii_host)
}

/// Validate a hostname according to DNS rules and SXURL constraints.
pub fn validate_host(host: &str) -> Result<(), SxurlError> {
    // Check total hostname length
    if host.len() > 255 {
        return Err(SxurlError::HostTooLong);
    }

    if host.is_empty() {
        return Err(SxurlError::InvalidLabel("Empty hostname".to_string()));
    }

    // Reject IP addresses - SXURL only supports DNS names
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Err(SxurlError::HostNotDns);
    }

    // Reject IPv6 addresses (contain colons)
    if host.contains(':') {
        return Err(SxurlError::HostNotDns);
    }

    // Split into labels and validate each
    let labels: Vec<&str> = host.split('.').collect();

    for label in &labels {
        validate_dns_label(label)?;
    }

    // Must have at least one label
    if labels.is_empty() {
        return Err(SxurlError::InvalidLabel("No labels in hostname".to_string()));
    }

    Ok(())
}

/// Validate a single DNS label according to RFC specifications.
pub fn validate_dns_label(label: &str) -> Result<(), SxurlError> {
    // Check label length (1-63 bytes)
    if label.is_empty() {
        return Err(SxurlError::InvalidLabel("Empty label".to_string()));
    }

    if label.len() > 63 {
        return Err(SxurlError::InvalidLabel(format!("Label too long: {}", label.len())));
    }

    // Check for valid characters (letters, digits, hyphens)
    for ch in label.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '-' {
            return Err(SxurlError::InvalidCharacter);
        }
    }

    // Cannot start or end with hyphen
    if label.starts_with('-') || label.ends_with('-') {
        return Err(SxurlError::InvalidLabel("Label cannot start or end with hyphen".to_string()));
    }

    Ok(())
}

/// Extract raw components from a normalized URL for SXURL processing.
pub fn extract_raw_components(url: &Url) -> Result<(String, String, String), SxurlError> {
    let path = url.path().to_string();
    let query = url.query().unwrap_or("").to_string();
    let fragment = url.fragment().unwrap_or("").to_string();

    Ok((path, query, fragment))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_basic_url() {
        let url = normalize_url("HTTPS://EXAMPLE.COM/PATH").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str().unwrap(), "example.com");
        assert_eq!(url.path(), "/PATH"); // Path should not be normalized
    }

    #[test]
    fn test_invalid_scheme() {
        let result = normalize_url("ws://example.com");
        assert_eq!(result.unwrap_err(), SxurlError::InvalidScheme);
    }

    #[test]
    fn test_host_normalization() {
        assert_eq!(normalize_host("EXAMPLE.COM").unwrap(), "example.com");
        assert_eq!(normalize_host("Test-Site.ORG").unwrap(), "test-site.org");
    }

    #[test]
    fn test_host_validation() {
        // Valid hosts
        assert!(validate_host("example.com").is_ok());
        assert!(validate_host("test-site.org").is_ok());
        assert!(validate_host("a.b.c.d.e").is_ok());

        // Invalid hosts
        assert!(validate_host("").is_err()); // Empty
        assert!(validate_host(&"a".repeat(256)).is_err()); // Too long
        assert!(validate_host("-invalid.com").is_err()); // Starts with hyphen
        assert!(validate_host("invalid-.com").is_err()); // Ends with hyphen
    }

    #[test]
    fn test_dns_label_validation() {
        // Valid labels
        assert!(validate_dns_label("example").is_ok());
        assert!(validate_dns_label("test-site").is_ok());
        assert!(validate_dns_label("a1b2c3").is_ok());

        // Invalid labels
        assert!(validate_dns_label("").is_err()); // Empty
        assert!(validate_dns_label(&"a".repeat(64)).is_err()); // Too long
        assert!(validate_dns_label("-invalid").is_err()); // Starts with hyphen
        assert!(validate_dns_label("invalid-").is_err()); // Ends with hyphen
        assert!(validate_dns_label("test.label").is_err()); // Contains dot
        assert!(validate_dns_label("test_label").is_err()); // Contains underscore
    }

    #[test]
    fn test_extract_raw_components() {
        let url = Url::parse("https://example.com/path?query=value#fragment").unwrap();
        let (path, query, fragment) = extract_raw_components(&url).unwrap();

        assert_eq!(path, "/path");
        assert_eq!(query, "query=value");
        assert_eq!(fragment, "fragment");
    }

    #[test]
    fn test_extract_components_with_empty_parts() {
        let url = Url::parse("https://example.com/").unwrap();
        let (path, query, fragment) = extract_raw_components(&url).unwrap();

        assert_eq!(path, "/");
        assert_eq!(query, "");
        assert_eq!(fragment, "");
    }

    #[test]
    fn test_normalize_preserves_raw_components() {
        // Path, query, and fragment should NOT be normalized (kept as raw bytes)
        let url = normalize_url("https://example.com/Path%20With%20Spaces?query=value%20with%20spaces#frag%20ment").unwrap();

        assert_eq!(url.path(), "/Path%20With%20Spaces");
        assert_eq!(url.query().unwrap(), "query=value%20with%20spaces");
        assert_eq!(url.fragment().unwrap(), "frag%20ment");
    }
}