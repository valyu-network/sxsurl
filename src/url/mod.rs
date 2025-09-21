//! URL processing and manipulation utilities.
//!
//! This module contains URL-related functionality:
//! - URL normalization and validation
//! - Public Suffix List (PSL) domain parsing
//! - URL component extraction and manipulation
//! - URL parsing utilities

pub mod normalizer;
pub mod psl;
pub mod utils;

// Re-export main functionality
pub use normalizer::{normalize_url, normalize_host, validate_host};
pub use psl::{split_host_with_psl, extract_url_components};
pub use utils::{
    split_url, split_domain, get_path_segments, get_filename,
    parse_query, get_query_value, get_anchor, strip_anchor,
    join_url_path, is_https, has_query, has_anchor, UrlParts,
    get_url_component, strip_url_component
};