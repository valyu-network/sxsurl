//! SXURL - Fixed-length, sliceable URL identifier system
//!
//! "Sixerl" is a fixed-length, sliceable URL identifier system for efficient database storage and querying.
//!
//! This crate provides a way to convert URLs into fixed 256-bit identifiers
//! where each URL component occupies a fixed position in the resulting hex string.
//!
//! # Features
//!
//! - **Fixed-length**: All SXURL identifiers are exactly 256 bits (64 hex characters)
//! - **Sliceable**: Each URL component has a fixed position for substring filtering
//! - **Deterministic**: Same input always produces the same output
//! - **Collision-resistant**: Uses SHA-256 hashing for component fingerprinting
//! - **Standards-compliant**: Supports IDNA, Public Suffix List, and standard URL schemes
//!
//! # Quick Start
//!
//! ```
//! use sxurl::{encode_url_to_hex, decode_hex, matches_component, split_url, parse_query};
//!
//! // Encode a URL to SXURL
//! let sxurl_hex = encode_url_to_hex("https://docs.rs/sxurl")?;
//! println!("SXURL: {}", sxurl_hex); // 64 hex characters
//!
//! // Decode and inspect
//! let decoded = decode_hex(&sxurl_hex)?;
//! println!("Scheme: {}", decoded.header.scheme);
//!
//! // Filter by component
//! let is_rs_tld = matches_component(&sxurl_hex, "tld", "rs")?;
//! assert!(is_rs_tld);
//!
//! // Parse URL into components
//! let parts = split_url("https://api.github.com/repos?page=1#readme")?;
//! println!("Domain: {}, Subdomain: {:?}", parts.domain, parts.subdomain);
//! println!("Anchor: {:?}", parts.anchor);
//!
//! // Work with query parameters
//! let params = parse_query("https://example.com?foo=bar&page=2")?;
//! println!("Page: {:?}", params.get("page"));
//! # Ok::<(), sxurl::SxurlError>(())
//! ```
//!
//! # SXURL Format
//!
//! The 256-bit SXURL has this fixed layout:
//!
//! | Component  | Hex Range | Bits | Description |
//! |------------|-----------|------|-------------|
//! | header     | [0..3)    | 12   | Version, scheme, flags |
//! | tld_hash   | [3..7)    | 16   | Top-level domain hash |
//! | domain_hash| [7..22)   | 60   | Domain name hash |
//! | sub_hash   | [22..30)  | 32   | Subdomain hash |
//! | port       | [30..34)  | 16   | Port number |
//! | path_hash  | [34..49)  | 60   | Path hash |
//! | params_hash| [49..58)  | 36   | Query parameters hash |
//! | frag_hash  | [58..64)  | 24   | Fragment hash |
//!
//! # Supported URL Schemes
//!
//! - `https` (scheme code 0)
//! - `http` (scheme code 1)
//! - `ftp` (scheme code 2)
//!
//! # Error Handling
//!
//! All functions return `Result<T, SxurlError>`. Common error cases:
//!
//! - Unsupported URL schemes (only https, http, ftp supported)
//! - Invalid hostnames or IP addresses
//! - Malformed URLs or SXURL hex strings

// Re-export main encoding functions
pub use core::{encode_url, encode_url_to_hex, SxurlEncoder};

// Re-export main decoding functions
pub use core::{decode_hex, decode_bytes, matches_component, DecodedSxurl};

// Re-export essential URL utilities
pub use url::{
    split_url, split_domain, get_path_segments, get_filename,
    parse_query, get_query_value, get_anchor, strip_anchor,
    join_url_path, is_https, has_query, has_anchor, UrlParts
};

// Re-export public types
pub use error::SxurlError;
pub use types::{SxurlHeader, UrlComponents};
pub use core::{hash_component, ComponentHasher, extract_lower_bits};
pub use url::{normalize_url, normalize_host, validate_host};
pub use url::{split_host_with_psl, extract_url_components};
pub use core::{pack_sxurl, sxurl_to_hex, hex_to_sxurl};

// Module declarations
pub mod error;
pub mod types;
pub mod core;
pub mod url;

