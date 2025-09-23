//! Core data structures for SXURL encoding and decoding.

/// Information extracted from an SXURL header.
#[derive(Debug, Clone, PartialEq)]
pub struct SxurlHeader {
    /// URL scheme (https, http, or ftp)
    pub scheme: String,
    /// Whether subdomain is present
    pub sub_present: bool,
    /// Whether query parameters are present
    pub params_present: bool,
    /// Whether fragment is present
    pub frag_present: bool,
    /// Whether port is explicitly specified
    pub port_present: bool,
}

impl SxurlHeader {
    /// Create a new SXURL header with the given parameters.
    pub fn new(
        scheme: String,
        sub_present: bool,
        params_present: bool,
        frag_present: bool,
        port_present: bool,
    ) -> Self {
        Self {
            scheme,
            sub_present,
            params_present,
            frag_present,
            port_present,
        }
    }

    /// Get the scheme code for encoding (https=0, http=1, ftp=2).
    pub fn scheme_code(&self) -> u8 {
        match self.scheme.as_str() {
            "https" => 0,
            "http" => 1,
            "ftp" => 2,
            _ => unreachable!("Invalid scheme should be caught during validation"),
        }
    }

    /// Create header from scheme code.
    pub fn scheme_from_code(code: u8) -> Option<String> {
        match code {
            0 => Some("https".to_string()),
            1 => Some("http".to_string()),
            2 => Some("ftp".to_string()),
            _ => None,
        }
    }

    /// Pack header flags into an 8-bit value.
    /// v2 flag positions: sub(7), port(6), path(5), params(4), frag(3), reserved(2:0)
    pub fn pack_flags(&self, path_present: bool) -> u8 {
        let mut flags = 0u8;

        if self.sub_present {
            flags |= 1 << 7;  // bit 7
        }
        if self.port_present {
            flags |= 1 << 6;  // bit 6
        }
        if path_present {
            flags |= 1 << 5;  // bit 5
        }
        if self.params_present {
            flags |= 1 << 4;  // bit 4
        }
        if self.frag_present {
            flags |= 1 << 3;  // bit 3
        }
        // bits 2, 1, 0 are reserved

        flags
    }

    /// Unpack header flags from an 8-bit value.
    /// v2 flag positions: sub(7), port(6), path(5), params(4), frag(3), reserved(2:0)
    pub fn unpack_flags(flags: u8) -> (bool, bool, bool, bool, bool) {
        let sub_present = (flags & (1 << 7)) != 0;
        let port_present = (flags & (1 << 6)) != 0;
        let path_present = (flags & (1 << 5)) != 0;
        let params_present = (flags & (1 << 4)) != 0;
        let frag_present = (flags & (1 << 3)) != 0;

        (sub_present, port_present, path_present, params_present, frag_present)
    }
}

/// URL components extracted during parsing.
#[derive(Debug, Clone, PartialEq)]
pub struct UrlComponents {
    /// URL scheme (https, http, ftp)
    pub scheme: String,
    /// Top-level domain (e.g., "com", "org")
    pub tld: String,
    /// Registrable domain (e.g., "example")
    pub domain: String,
    /// Subdomain (e.g., "api.v2" or empty string)
    pub subdomain: String,
    /// Port number (0 if not specified)
    pub port: u16,
    /// Path including leading slash (e.g., "/search")
    pub path: String,
    /// Query string without leading ? (e.g., "q=test")
    pub query: String,
    /// Fragment without leading # (e.g., "results")
    pub fragment: String,
}

impl UrlComponents {
    /// Create new URL components.
    pub fn new(
        scheme: String,
        tld: String,
        domain: String,
        subdomain: String,
        port: u16,
        path: String,
        query: String,
        fragment: String,
    ) -> Self {
        Self {
            scheme,
            tld,
            domain,
            subdomain,
            port,
            path,
            query,
            fragment,
        }
    }

    /// Check if subdomain is present.
    pub fn has_subdomain(&self) -> bool {
        !self.subdomain.is_empty()
    }

    /// Check if query parameters are present.
    pub fn has_params(&self) -> bool {
        !self.query.is_empty()
    }

    /// Check if fragment is present.
    pub fn has_fragment(&self) -> bool {
        !self.fragment.is_empty()
    }

    /// Check if port is explicitly specified.
    pub fn has_port(&self) -> bool {
        self.port != 0
    }
}

/// Enum for specifying which URL component to extract or manipulate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlComponentType {
    /// URL scheme (https, http, ftp)
    Scheme,
    /// Full hostname (api.example.com)
    Host,
    /// Domain name only (example)
    Domain,
    /// Subdomain if present (api)
    Subdomain,
    /// Top-level domain (com, org, co.uk)
    Tld,
    /// Port number
    Port,
    /// Path component (/api/v1/users)
    Path,
    /// Query string (foo=bar&baz=qux)
    Query,
    /// Fragment/anchor (section1)
    Fragment,
    /// Path segments as vector (["api", "v1", "users"])
    PathSegments,
    /// Filename from path (file.pdf)
    Filename,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sxurl_header_creation() {
        let header = SxurlHeader::new(
            "https".to_string(),
            true,  // subdomain present
            false, // no params
            true,  // fragment present
            false, // no port
        );

        assert_eq!(header.scheme, "https");
        assert!(header.sub_present);
        assert!(!header.params_present);
        assert!(header.frag_present);
        assert!(!header.port_present);
    }

    #[test]
    fn test_scheme_codes() {
        let https_header = SxurlHeader::new("https".to_string(), false, false, false, false);
        let http_header = SxurlHeader::new("http".to_string(), false, false, false, false);
        let ftp_header = SxurlHeader::new("ftp".to_string(), false, false, false, false);

        assert_eq!(https_header.scheme_code(), 0);
        assert_eq!(http_header.scheme_code(), 1);
        assert_eq!(ftp_header.scheme_code(), 2);
    }

    #[test]
    fn test_scheme_from_code() {
        assert_eq!(SxurlHeader::scheme_from_code(0), Some("https".to_string()));
        assert_eq!(SxurlHeader::scheme_from_code(1), Some("http".to_string()));
        assert_eq!(SxurlHeader::scheme_from_code(2), Some("ftp".to_string()));
        assert_eq!(SxurlHeader::scheme_from_code(3), None);
    }

    #[test]
    fn test_v2_flag_packing() {
        let header = SxurlHeader::new(
            "https".to_string(),
            true,  // subdomain present
            true,  // params present
            false, // no fragment
            true,  // port present
        );

        // Test flag packing with path present
        let flags = header.pack_flags(true);

        // Expected: sub(7)=1, port(6)=1, path(5)=1, params(4)=1, frag(3)=0
        // Binary: 11110000 = 0xF0
        assert_eq!(flags, 0xF0, "Expected flags 0xF0, got 0x{:02x}", flags);

        // Test flag unpacking
        let (sub, port, path, params, frag) = SxurlHeader::unpack_flags(flags);
        assert!(sub, "Subdomain flag should be set");
        assert!(port, "Port flag should be set");
        assert!(path, "Path flag should be set");
        assert!(params, "Params flag should be set");
        assert!(!frag, "Fragment flag should not be set");

        println!("✓ v2 flag packing verified:");
        println!("  Input: sub={}, port={}, path={}, params={}, frag={}",
                 header.sub_present, header.port_present, true, header.params_present, header.frag_present);
        println!("  Packed: 0x{:02x}", flags);
        println!("  Unpacked: sub={}, port={}, path={}, params={}, frag={}", sub, port, path, params, frag);
    }

    #[test]
    fn test_url_components() {
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

        assert!(components.has_subdomain());
        assert!(components.has_params());
        assert!(components.has_fragment());
        assert!(components.has_port());
    }

    #[test]
    fn test_url_components_empty() {
        let components = UrlComponents::new(
            "https".to_string(),
            "com".to_string(),
            "example".to_string(),
            "".to_string(),
            0,
            "/".to_string(),
            "".to_string(),
            "".to_string(),
        );

        assert!(!components.has_subdomain());
        assert!(!components.has_params());
        assert!(!components.has_fragment());
        assert!(!components.has_port());
    }
}