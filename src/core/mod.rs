//! Core SXURL encoding and decoding functionality.
//!
//! This module contains the main SXURL operations:
//! - Encoding URLs to SXURL format
//! - Decoding SXURL back to components
//! - Bit packing and unpacking
//! - Cryptographic hashing functions

pub mod encoder;
pub mod decoder;
pub mod matcher;
pub mod packer;
pub mod hasher;

// Re-export main functionality
pub use encoder::{encode_url, encode_url_to_hex, SxurlEncoder};
pub use decoder::{decode_hex, decode_bytes, matches_component, DecodedSxurl};
pub use matcher::{sxurl_contains, sxurl_has_domain, sxurl_has_subdomain, sxurl_has_tld};
pub use packer::{pack_sxurl, sxurl_to_hex, hex_to_sxurl};
pub use hasher::{hash_component, ComponentHasher, extract_lower_bits};