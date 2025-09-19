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
//! use sxurl::{encode_url_to_hex, decode_hex, matches_component};
//!
//! // Encode a URL
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
pub use encoder::{encode_url, encode_url_to_hex, SxurlEncoder};

// Re-export main decoding functions
pub use decoder::{decode_hex, decode_bytes, matches_component, DecodedSxurl};

// Re-export public types
pub use error::SxurlError;
pub use types::{SxurlHeader, UrlComponents};
pub use hasher::{hash_component, ComponentHasher, extract_lower_bits};
pub use normalizer::{normalize_url, normalize_host, validate_host};
pub use psl::{split_host_with_psl, extract_url_components};
pub use packer::{pack_sxurl, sxurl_to_hex, hex_to_sxurl};

// Module declarations
pub mod error;
pub mod types;
pub mod hasher;
pub mod normalizer;
pub mod psl;
pub mod packer;
pub mod encoder;
pub mod decoder;

// Placeholder public functions - will be implemented in later stages
pub fn placeholder() -> &'static str {
    "SXURL library - implementation in progress"
}