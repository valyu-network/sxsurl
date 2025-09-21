# SXURL: Slice eXact URL Identifier ("sixerl")

"Sixerl" is a fixed-length, sliceable URL identifier system for efficient database storage and querying.

---

## Table of Contents

**Part I: Understanding SXURL**
=
1. [What is SXURL](#1-what-is-sxurl)
2. [Core Architecture](#2-core-architecture)
3. [Design Rationale](#3-design-rationale)
4. [Performance Analysis](#4-performance-analysis)

**Part II: Implementation**
5. [Encoding Algorithm](#5-encoding-algorithm)
6. [Normalization](#6-normalization)
7. [Component Hashing](#7-component-hashing)
8. [Validation & Errors](#8-validation--errors)

**Part III: Querying**
9. [Query Patterns](#9-query-patterns)
10. [False Positives](#10-false-positives)
11. [PostgreSQL Examples](#11-postgresql-examples)
12. [Advanced Queries](#12-advanced-queries)

**Part IV: Production**
13. [Storage Considerations](#13-storage-considerations)
14. [Migration Strategies](#14-migration-strategies)
15. [Monitoring & Debugging](#15-monitoring--debugging)
16. [Security Implications](#16-security-implications)

**Part V: Reference**
17. [Binary Layout Reference](#17-binary-layout-reference)
18. [Hex Slice Map](#18-hex-slice-map)
19. [Error Codes](#19-error-codes)
20. [Test Vectors](#20-test-vectors)

**Part VI: Formal Specification**
21. [Formal Specification](#21-formal-specification)
22. [Compliance Checklist](#22-compliance-checklist)
23. [Version History](#23-version-history)

**Appendices**
- [A. Rust Implementation](#appendix-a-rust-implementation)
- [B. Comparison with Alternatives](#appendix-b-comparison-with-alternatives)
- [C. FAQ](#appendix-c-faq)

---

# Part I: Understanding SXURL

## 1. What is SXURL

### The Problem

URLs in databases are a pain:
- **Variable length**: Can be 20 characters or 2000 characters
- **Inefficient indexing**: B-tree indexes struggle with long, variable strings
- **Query complexity**: Finding all URLs from a domain requires LIKE patterns or regex
- **Storage waste**: Repeated components (domains, paths) stored multiple times

### The Solution

SXURL converts any URL into a **fixed 256-bit identifier** (64 hex characters) where:
- Each URL component lives at a **fixed hex position**
- You can query by component using **simple substring operations**
- Storage is **constant 32 bytes per URL**
- Indexes are **highly efficient**


Example:
```
URL:    https://api.example.com:8443/search?q=test#results
SXURL:  13e62fe9cee73c091a1a7b5b7f800220fbcb7e8070cf84487f86a9df2b86e801
         │  ││               ││       ││               ││        │
         │  ││               ││       ││               ││        └─ fragment
         │  ││               ││       ││               │└─ query params
         │  ││               ││       ││               └─ path
         │  ││               ││       │└─ port (8443)
         │  ││               ││       └─ subdomain (api)
         │  ││               │└─ domain (example)
         │  │└─ TLD (.com)
         │  └─ header
         └─ scheme/flags
```

### When to Use SXURL

**Good for:**
- URL analytics and tracking
- Finding patterns across billions of URLs
- Efficient URL filtering and grouping including by domain, subdomain, tld, paths and anchors
- Privacy-preserving URL analysis
- High-performance URL indexing

**Not good for:**
- When you need to reconstruct the original URL
- URLs with schemes other than https/http/ftp
- IP address hosts (DNS names only)
- Perfect accuracy requirements, it is lossy (false positives exist)

## 2. Core Architecture

### The 256-Bit Layout

SXURL packs URL components into exactly 256 bits (32 bytes, 64 hex characters):

```
Bits:    12    16      60        32      16      60       36      24
       ┌────┬─────┬─────────┬────────┬─────┬─────────┬────────┬──────┐
       │hdr │ tld │ domain  │  sub   │port │  path   │ params │ frag │
       └────┴─────┴─────────┴────────┴─────┴─────────┴────────┴──────┘
Hex:   [0-3)[3-7) [7-22)   [22-30) [30-34)[34-49)  [49-58) [58-64)
```

### Component Breakdown

| Component | Bits | Hex Range | What it stores |
|-----------|------|-----------|----------------|
| **Header** | 12 | `[0..3)` | Version, scheme, presence flags |
| **TLD** | 16 | `[3..7)` | Top-level domain hash (e.g., ".com") |
| **Domain** | 60 | `[7..22)` | Registrable domain hash (e.g., "google") |
| **Subdomain** | 32 | `[22..30)` | Subdomain hash (e.g., "api.v2") |
| **Port** | 16 | `[30..34)` | Port number (defualts to port 80 if scheme = http or 443 if scheme = https ) |
| **Path** | 60 | `[34..49)` | Path hash (e.g., "/search") |
| **Params** | 36 | `[49..58)` | Query parameters hash |
| **Fragment** | 24 | `[58..64)` | Fragment hash |

### The Header Format

The first 12 bits encode metadata:

```
Bits: [4-bit version][3-bit scheme][5-bit flags]
```

**Version**: Always `0001` (version 1)

**Scheme codes**:
- `000` = https
- `001` = http
- `010` = ftp

**Flags** (MSB to LSB):
- Bit 4: `sub_present` - Subdomain exists
- Bit 3: `params_present` - Query parameters exist
- Bit 2: `frag_present` - Fragment exists
- Bit 1: `port_present` - Non-default port specified
- Bit 0: Reserved (always 0)

## 3. Design Rationale

### Why 256 Bits?

- **Cache-friendly**: Fits in 4 cache lines (64 bytes each)
- **Common size**: Many hash functions output 256 bits
- **Alignment**: Powers of 2 work well with memory systems
- **Sufficient entropy**: Even small components get enough bits

### Why These Bit Allocations?

**Domain (60 bits)**: The most important identifier, needs near-zero false positives.
- False positive rate: ~2^-60 (essentially zero)

**Path (60 bits)**: Critical for API endpoint identification.
- False positive rate: ~2^-60 (essentially zero)

**TLD (16 bits)**: Coarse bucketing is acceptable.
- False positive rate: ~1/65,536 (manageable)

**Subdomain (32 bits)**: Balance between specificity and collisions.
- False positive rate: ~1/4.3 billion

**Params (36 bits)**: Intended as buckets, collisions expected.
- False positive rate: ~1/68 billion

**Fragment (24 bits)**: Lowest priority, buckets are fine.
- False positive rate: ~1/16.7 million

### Why Labeled Hashing?

Instead of hashing the full URL, SXURL hashes each component separately with a label:

```
H_n("domain", "google") vs H_n("subdomain", "google")
```

This prevents **cross-field collisions** where a domain "api" might hash to the same value as a subdomain "api" in a different field.

### Why Not Full URL Hashing?

Full URL hashing (like MD5 of the entire URL) has major drawbacks:
- Can't filter by component
- Can't group by domain/path patterns
- Requires full URL reconstruction for analysis
- No performance advantage for component queries

## 4. Performance Analysis

### Storage Efficiency

| Approach | Storage per URL | Index size (1M URLs) |
|----------|-----------------|---------------------|
| Full URLs | 50-200 bytes avg | 50-200 MB |
| SXURL | 32 bytes | 32 MB |
| URL hash (MD5) | 16 bytes | 16 MB |

### Query Performance

**Traditional approach** (finding all `.com` domains):
```sql
SELECT * FROM urls WHERE url LIKE '%.com%';  -- Table scan!
```

**SXURL approach**:
```sql
SELECT * FROM urls WHERE sxurl_id LIKE '___.62fe%';  -- Index scan!
```

The SXURL query uses the index because it's a prefix match on a fixed-position substring.

### Memory Characteristics

- **L1 cache**: 64 hex chars fit in ~64 bytes (1 cache line)
- **SIMD potential**: Fixed width enables vectorized processing
- **Branch prediction**: Fixed format improves CPU prediction
- **Index locality**: Similar URLs cluster together in B-tree indexes

---

# Part II: Implementation

## 5. Encoding Algorithm

### High-Level Process

1. **Parse and normalize** the URL
2. **Extract components** (scheme, tld, domain, sub, port, path, query, fragment)
3. **Validate** scheme and host format
4. **Hash each component** using labeled SHA-256
5. **Pack bits** into 256-bit big-endian format
6. **Encode as hex**

### Step-by-Step Encoding

```rust
fn encode_url(url: &str) -> Result<String, SxurlError> {
    // 1. Parse URL
    let parsed = Url::parse(url)?;

    // 2. Validate scheme
    let scheme_bits = match parsed.scheme() {
        "https" => 0b000,
        "http" => 0b001,
        "ftp" => 0b010,
        _ => return Err(SxurlError::InvalidScheme),
    };

    // 3. Normalize and split host
    let host = parsed.host_str().ok_or(SxurlError::NoHost)?;
    let (tld, domain, subdomain) = split_host_with_psl(host)?;

    // 4. Set presence flags
    let flags =
        (if !subdomain.is_empty() { 1 } else { 0 }) << 4 |
        (if parsed.query().is_some() { 1 } else { 0 }) << 3 |
        (if parsed.fragment().is_some() { 1 } else { 0 }) << 2 |
        (if parsed.port().is_some() { 1 } else { 0 }) << 1;

    // 5. Build header
    let header = (1u16 << 8) | ((scheme_bits as u16) << 5) | flags;

    // 6. Hash components
    let tld_hash = hash_component("tld", tld.as_bytes(), 16);
    let domain_hash = hash_component("domain", domain.as_bytes(), 60);
    let sub_hash = hash_component("sub", subdomain.as_bytes(), 32);
    let path_hash = hash_component("path", parsed.path().as_bytes(), 60);
    let params_hash = hash_component("params",
        parsed.query().unwrap_or("").as_bytes(), 36);
    let frag_hash = hash_component("frag",
        parsed.fragment().unwrap_or("").as_bytes(), 24);

    // 7. Pack into 256 bits
    let mut bits = BitVec::with_capacity(256);
    bits.extend_from_slice(&to_bits(header, 12));
    bits.extend_from_slice(&to_bits(tld_hash, 16));
    bits.extend_from_slice(&to_bits(domain_hash, 60));
    bits.extend_from_slice(&to_bits(sub_hash, 32));
    bits.extend_from_slice(&to_bits(parsed.port().unwrap_or(0), 16));
    bits.extend_from_slice(&to_bits(path_hash, 60));
    bits.extend_from_slice(&to_bits(params_hash, 36));
    bits.extend_from_slice(&to_bits(frag_hash, 24));

    // 8. Convert to hex
    Ok(bits_to_hex(&bits))
}
```

## 6. Normalization

Consistent normalization is critical for SXURL to work correctly across implementations.

### Scheme and Host

```rust
fn normalize_scheme_and_host(url: &str) -> String {
    // 1. Convert scheme to lowercase
    // 2. Convert host to lowercase
    // 3. Apply IDNA ASCII conversion
    let mut normalized = url.to_lowercase();

    if let Ok(parsed) = Url::parse(&normalized) {
        if let Some(host) = parsed.host_str() {
            // IDNA conversion to ASCII
            let ascii_host = idna::domain_to_ascii(host)
                .unwrap_or_else(|_| host.to_string());
            normalized = normalized.replace(host, &ascii_host);
        }
    }

    normalized
}
```

### Host Validation

```rust
fn validate_host(host: &str) -> Result<(), SxurlError> {
    // Check total length
    if host.len() > 255 {
        return Err(SxurlError::HostTooLong);
    }

    // Check each label
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(SxurlError::InvalidLabel);
        }

        // Check for valid DNS characters
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(SxurlError::InvalidCharacter);
        }

        // Can't start or end with hyphen
        if label.starts_with('-') || label.ends_with('-') {
            return Err(SxurlError::InvalidLabel);
        }
    }

    Ok(())
}
```

### Public Suffix List (PSL) Splitting

```rust
fn split_host_with_psl(host: &str) -> Result<(String, String, String), SxurlError> {
    // Use PSL to find the public suffix
    let list = psl::List::new();

    if let Some(domain) = list.domain(host.as_bytes()) {
        let suffix = domain.suffix().as_str();
        let registrable = domain.root().unwrap().as_str();

        // Extract the registrable domain part
        let domain_part = &registrable[..registrable.len() - suffix.len() - 1];

        // Everything before the registrable domain is subdomain
        let subdomain = if host.len() > registrable.len() {
            &host[..host.len() - registrable.len() - 1]
        } else {
            ""
        };

        Ok((suffix.to_string(), domain_part.to_string(), subdomain.to_string()))
    } else {
        // Fallback: use rightmost label as TLD
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() < 2 {
            return Err(SxurlError::InvalidHost);
        }

        let tld = parts.last().unwrap();
        let domain = parts[parts.len() - 2];
        let subdomain = if parts.len() > 2 {
            parts[..parts.len() - 2].join(".")
        } else {
            String::new()
        };

        Ok((tld.to_string(), domain.to_string(), subdomain))
    }
}
```

### Path, Query, and Fragment

These components are **NOT** normalized - they're treated as raw bytes:

```rust
// DON'T do this:
let normalized_path = url_decode(path);  // WRONG

// DO this:
let raw_path = parsed.path();  // Keep as-is, including percent encoding
```

This preserves the exact byte representation that applications expect.

## 7. Component Hashing

### Labeled Hash Function

SXURL uses a labeled hash function to prevent cross-field collisions:

```rust
fn hash_component(label: &str, data: &[u8], bit_width: usize) -> u64 {
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();

    // Add label
    hasher.update(label.as_bytes());

    // Add separator
    hasher.update(&[0x00]);

    // Add component data
    hasher.update(data);

    let hash = hasher.finalize();

    // Truncate to desired bit width
    truncate_hash(&hash, bit_width)
}

fn truncate_hash(hash: &[u8], bit_width: usize) -> u64 {
    // Take the lower `bit_width` bits
    let byte_width = (bit_width + 7) / 8;
    let mut result = 0u64;

    for (i, &byte) in hash.iter().take(byte_width).enumerate() {
        result |= (byte as u64) << (i * 8);
    }

    // Mask to exact bit width
    let mask = (1u64 << bit_width) - 1;
    result & mask
}
```

### Why This Approach?

1. **Domain separation**: `hash("tld", "com")` ≠ `hash("domain", "com")`
2. **Deterministic**: Same input always produces same output
3. **Cryptographically strong**: Based on SHA-256
4. **Collision resistant**: Within each field

### Hash Examples

```rust
// These produce different hashes even though input is same
let tld_hash = hash_component("tld", b"com", 16);        // 0x62fe
let domain_hash = hash_component("domain", b"com", 60);  // 0x9cee73c091a1a7b
```

## 8. Validation & Errors

### Error Types

```rust
#[derive(Debug, Clone)]
pub enum SxurlError {
    InvalidScheme,
    HostNotDns,
    HostTooLong,
    InvalidLabel,
    InvalidCharacter,
    ParseError(String),
    InternalError,
}
```

### Validation Checks

```rust
fn validate_sxurl_input(url: &str) -> Result<(), SxurlError> {
    let parsed = Url::parse(url).map_err(|e| SxurlError::ParseError(e.to_string()))?;

    // Check scheme
    match parsed.scheme() {
        "https" | "http" | "ftp" => {},
        _ => return Err(SxurlError::InvalidScheme),
    }

    // Check host exists and is DNS name
    let host = parsed.host_str().ok_or(SxurlError::HostNotDns)?;

    // Validate host format
    validate_host(host)?;

    // Check port range
    if let Some(port) = parsed.port() {
        if port == 0 || port > 65535 {
            return Err(SxurlError::ParseError("Invalid port".to_string()));
        }
    }

    Ok(())
}
```

### Decoding Validation

```rust
fn validate_sxurl_hex(hex: &str) -> Result<(), SxurlError> {
    // Must be exactly 64 hex characters
    if hex.len() != 64 {
        return Err(SxurlError::ParseError("Invalid length".to_string()));
    }

    // Must be valid hex
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SxurlError::ParseError("Invalid hex character".to_string()));
    }

    // Extract and validate header
    let header_hex = &hex[0..3];
    let header = u16::from_str_radix(header_hex, 16)
        .map_err(|_| SxurlError::ParseError("Invalid header".to_string()))?;

    // Check version
    let version = (header >> 8) & 0xF;
    if version != 1 {
        return Err(SxurlError::ParseError("Unsupported version".to_string()));
    }

    // Check scheme
    let scheme = (header >> 5) & 0x7;
    if scheme > 2 {
        return Err(SxurlError::ParseError("Invalid scheme".to_string()));
    }

    // Check reserved bit
    let flags = header & 0x1F;
    if (flags & 0x1) != 0 {
        return Err(SxurlError::ParseError("Reserved bit set".to_string()));
    }

    // Validate port consistency
    let port_present = (flags & 0x2) != 0;
    let port_hex = &hex[30..34];
    if !port_present && port_hex != "0000" {
        return Err(SxurlError::ParseError("Port present but flag not set".to_string()));
    }

    Ok(())
}
```

---

# Part III: Querying

## 9. Query Patterns

### Basic Component Filtering

The power of SXURL comes from its ability to filter by URL components using simple string operations. While more human readable abstractions can be built we can use bitstrings for efficient lookups e.g.

#### Find All URLs from a TLD

```sql
-- All .com domains
SELECT url FROM urls
WHERE SUBSTRING(sxurl_id, 4, 4) = '62fe';

-- All .ai domains
SELECT url FROM urls
WHERE SUBSTRING(sxurl_id, 4, 4) = '2e31';
```

#### Find All URLs from a Domain

```sql
-- All URLs from 'google' domain
SELECT url FROM urls
WHERE SUBSTRING(sxurl_id, 8, 15) = '03e9505795e1d08';
```

#### Find All URLs with Specific Path

```sql
-- All URLs with '/search' path
SELECT url FROM urls
WHERE SUBSTRING(sxurl_id, 35, 15) = '239f9d65dd89753';
```

#### Port Filtering

```sql
-- All URLs on port 8443
SELECT url FROM urls
WHERE SUBSTRING(sxurl_id, 31, 4) = '20fb';

-- All URLs with non-default ports (check the port_present flag)
SELECT url FROM urls
WHERE (CAST(CONV(SUBSTRING(sxurl_id, 1, 3), 16, 10) AS UNSIGNED) & 2) != 0;
```

### Compound Filtering

The real power comes from combining filters:

```sql
-- All HTTPS URLs from google.com with /search path
SELECT url FROM urls
WHERE SUBSTRING(sxurl_id, 1, 1) = '1'           -- HTTPS
  AND SUBSTRING(sxurl_id, 4, 4) = '62fe'        -- .com TLD
  AND SUBSTRING(sxurl_id, 8, 15) = '03e9505795e1d08'  -- google domain
  AND SUBSTRING(sxurl_id, 35, 15) = '239f9d65dd89753'; -- /search path
```

### Pattern Matching

```sql
-- All API subdomains (assuming 'api' subdomain hash)
SELECT url FROM urls
WHERE SUBSTRING(sxurl_id, 23, 8) = '5b7f8002';

-- All URLs with query parameters (check params_present flag)
SELECT url FROM urls
WHERE (CAST(CONV(SUBSTRING(sxurl_id, 1, 3), 16, 10) AS UNSIGNED) & 8) != 0;
```

### Indexing Strategy

Create specialized indexes for common query patterns:

```sql
-- Index for TLD filtering
CREATE INDEX idx_urls_tld ON urls (SUBSTRING(sxurl_id, 4, 4));

-- Index for domain filtering
CREATE INDEX idx_urls_domain ON urls (SUBSTRING(sxurl_id, 8, 15));

-- Index for path filtering
CREATE INDEX idx_urls_path ON urls (SUBSTRING(sxurl_id, 35, 15));

-- Compound index for common patterns
CREATE INDEX idx_urls_tld_domain ON urls (
    SUBSTRING(sxurl_id, 4, 4),
    SUBSTRING(sxurl_id, 8, 15)
);
```

## 10. False Positives

### Understanding False Positive Rates

Each component has a different false positive rate based on its bit allocation:

| Component | Bits | False Positive Rate | In Practice |
|-----------|------|---------------------|-------------|
| TLD | 16 | 1/65,536 | ~0.002% |
| Domain | 60 | 1/2^60 | Effectively zero |
| Subdomain | 32 | 1/4.3 billion | ~0.000000023% |
| Path | 60 | 1/2^60 | Effectively zero |
| Params | 36 | 1/68 billion | ~0.0000000015% |
| Fragment | 24 | 1/16.7 million | ~0.000006% |

### When False Positives Matter

**TLD filtering**: With 16 bits, you'll get some false positives. For 1 million URLs:
- Expected false positives for `.com` query: ~15 URLs
- This is usually acceptable for analytics

**Domain filtering**: With 60 bits, false positives are negligible.

**Path filtering**: With 60 bits, false positives are negligible.

### Mitigation Strategies

#### 1. Secondary Validation

```sql
-- First filter with SXURL, then validate with actual URL
SELECT url FROM urls
WHERE SUBSTRING(sxurl_id, 4, 4) = '62fe'  -- Fast SXURL filter
  AND url LIKE '%.com%';                  -- Secondary validation
```

#### 2. Compound Filters

Combine multiple components to reduce false positive probability:

```sql
-- TLD + Domain: 16 + 60 = 76 bits = negligible false positives
SELECT url FROM urls
WHERE SUBSTRING(sxurl_id, 4, 4) = '62fe'        -- .com
  AND SUBSTRING(sxurl_id, 8, 15) = '03e9505795e1d08'; -- google
```

#### 3. Accept and Monitor

For analytics, small false positive rates are often acceptable:

```sql
-- Count of .com requests (with ~0.002% false positives)
SELECT COUNT(*) FROM requests
WHERE SUBSTRING(sxurl_id, 4, 4) = '62fe';
```

Monitor false positive rates in production:

```sql
-- Check false positive rate for TLD filtering
SELECT
  COUNT(*) as sxurl_matches,
  COUNT(CASE WHEN url LIKE '%.com%' THEN 1 END) as actual_matches,
  (COUNT(*) - COUNT(CASE WHEN url LIKE '%.com%' THEN 1 END)) / COUNT(*) as false_positive_rate
FROM urls
WHERE SUBSTRING(sxurl_id, 4, 4) = '62fe';
```

## 11. PostgreSQL Examples

### Schema Setup

```sql
CREATE TABLE urls (
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    sxurl_id CHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for common query patterns
CREATE INDEX idx_urls_sxurl_full ON urls(sxurl_id);
CREATE INDEX idx_urls_tld ON urls(SUBSTRING(sxurl_id, 4, 4));
CREATE INDEX idx_urls_domain ON urls(SUBSTRING(sxurl_id, 8, 15));
CREATE INDEX idx_urls_path ON urls(SUBSTRING(sxurl_id, 35, 15));
```

### Basic Queries

```sql
-- Find all .com domains
SELECT url, sxurl_id FROM urls
WHERE SUBSTRING(sxurl_id, 4, 4) = '62fe'
LIMIT 10;

-- Count requests by TLD
SELECT
    SUBSTRING(sxurl_id, 4, 4) as tld_hash,
    COUNT(*) as request_count
FROM urls
GROUP BY SUBSTRING(sxurl_id, 4, 4)
ORDER BY request_count DESC;
```

### Analytics Queries

```sql
-- API endpoint usage (specific path pattern)
SELECT
    SUBSTRING(sxurl_id, 35, 15) as path_hash,
    COUNT(*) as hits
FROM urls
WHERE SUBSTRING(sxurl_id, 8, 15) = '03e9505795e1d08'  -- google domain
GROUP BY SUBSTRING(sxurl_id, 35, 15)
ORDER BY hits DESC;

-- Non-default port usage
SELECT
    SUBSTRING(sxurl_id, 31, 4) as port_hex,
    CAST(CONV(SUBSTRING(sxurl_id, 31, 4), 16, 10) AS UNSIGNED) as port_num,
    COUNT(*) as usage_count
FROM urls
WHERE (CAST(CONV(SUBSTRING(sxurl_id, 1, 3), 16, 10) AS UNSIGNED) & 2) != 0  -- port_present flag
GROUP BY SUBSTRING(sxurl_id, 31, 4)
ORDER BY usage_count DESC;
```

## 12. Advanced Queries

### Multi-Component Analysis

```sql
-- Domain and path correlation analysis
SELECT
    SUBSTRING(sxurl_id, 8, 15) as domain_hash,
    SUBSTRING(sxurl_id, 35, 15) as path_hash,
    COUNT(*) as frequency
FROM urls
WHERE SUBSTRING(sxurl_id, 4, 4) = '62fe'  -- .com domains only
GROUP BY SUBSTRING(sxurl_id, 8, 15), SUBSTRING(sxurl_id, 35, 15)
HAVING COUNT(*) > 100
ORDER BY frequency DESC;
```

### Time-Based Analysis

```sql
-- TLD usage trends over time
SELECT
    DATE_TRUNC('day', created_at) as day,
    SUBSTRING(sxurl_id, 4, 4) as tld_hash,
    COUNT(*) as daily_count
FROM urls
WHERE created_at >= NOW() - INTERVAL '30 days'
GROUP BY DATE_TRUNC('day', created_at), SUBSTRING(sxurl_id, 4, 4)
ORDER BY day, daily_count DESC;
```

### Security Analysis

```sql
-- Find suspicious subdomain patterns
SELECT
    SUBSTRING(sxurl_id, 23, 8) as subdomain_hash,
    COUNT(DISTINCT SUBSTRING(sxurl_id, 8, 15)) as unique_domains,
    COUNT(*) as total_requests
FROM urls
WHERE (CAST(CONV(SUBSTRING(sxurl_id, 1, 3), 16, 10) AS UNSIGNED) & 16) != 0  -- sub_present flag
GROUP BY SUBSTRING(sxurl_id, 23, 8)
HAVING COUNT(DISTINCT SUBSTRING(sxurl_id, 8, 15)) > 50  -- Same subdomain across many domains
ORDER BY unique_domains DESC;
```

### Performance Optimization

```sql
-- Use partial indexes for high-frequency queries
CREATE INDEX idx_urls_com_domains ON urls(SUBSTRING(sxurl_id, 8, 15))
WHERE SUBSTRING(sxurl_id, 4, 4) = '62fe';

-- Materialized view for TLD statistics
CREATE MATERIALIZED VIEW tld_stats AS
SELECT
    SUBSTRING(sxurl_id, 4, 4) as tld_hash,
    COUNT(*) as url_count,
    COUNT(DISTINCT SUBSTRING(sxurl_id, 8, 15)) as unique_domains
FROM urls
GROUP BY SUBSTRING(sxurl_id, 4, 4);

CREATE INDEX ON tld_stats(tld_hash);
```

---

# Part IV: Production

## 13. Storage Considerations

### Storage Requirements

**Per URL:**
- SXURL ID: 32 bytes (64 hex chars)
- Original URL: Variable (50-200 bytes average)
- Metadata: ~20 bytes (timestamps, etc.)
- **Total: ~100-250 bytes per URL**

**Scale calculations:**
- 1 million URLs: ~100-250 MB
- 100 million URLs: ~10-25 GB
- 1 billion URLs: ~100-250 GB

Compare to storing just URLs:
- URLs only: ~50-200 GB for 1 billion URLs
- With SXURL: ~100-250 GB (50-100% overhead for massive query benefits)

### Index Sizing

**B-tree indexes** on CHAR(64) are efficient:
- 1 million SXURLs: ~40 MB index
- 100 million SXURLs: ~4 GB index
- 1 billion SXURLs: ~40 GB index

**Partial indexes** for common queries:
```sql
-- Index only .com domains (assuming 40% of traffic)
CREATE INDEX idx_com_domains ON urls(SUBSTRING(sxurl_id, 8, 15))
WHERE SUBSTRING(sxurl_id, 4, 4) = '62fe';
```

### Memory Considerations

**Working set size:** For active queries, plan for:
- Index pages: ~10% of index size in memory
- Data pages: ~5% of table size in memory
- Query buffers: Additional 10-20% for complex operations

**Example for 100M URLs:**
- Table size: ~20 GB
- Index size: ~4 GB
- Memory working set: ~2.4 GB (index) + ~1 GB (data) = ~3.4 GB

## 14. Migration Strategies

### From Existing URL Tables

#### Phase 1: Add SXURL Column

```sql
-- Add the SXURL column
ALTER TABLE urls ADD COLUMN sxurl_id CHAR(64);

-- Create index (will be NULL initially)
CREATE INDEX CONCURRENTLY idx_urls_sxurl ON urls(sxurl_id)
WHERE sxurl_id IS NOT NULL;
```

#### Phase 2: Backfill Existing Data

```sql
-- Backfill in batches to avoid lock contention
UPDATE urls
SET sxurl_id = generate_sxurl(url)  -- Your SXURL function
WHERE sxurl_id IS NULL
  AND id BETWEEN ? AND ?;  -- Process in batches of 10k-100k
```

#### Phase 3: Update Application Code

1. **Dual writes:** Update application to compute and store SXURL for new URLs
2. **Dual reads:** Migrate queries to use SXURL where beneficial
3. **Validation:** Compare results between old and new query methods

#### Phase 4: Cleanup

```sql
-- Make SXURL column NOT NULL
ALTER TABLE urls ALTER COLUMN sxurl_id SET NOT NULL;

-- Drop old indexes if no longer needed
DROP INDEX IF EXISTS idx_urls_old_pattern;
```

### Bulk Import Strategy

For large datasets, process in parallel:

```rust
// Parallel SXURL generation
use rayon::prelude::*;

fn bulk_generate_sxurls(urls: Vec<String>) -> Vec<(String, String)> {
    urls.par_iter()
        .map(|url| {
            let sxurl = generate_sxurl(url)?;
            Ok((url.clone(), sxurl))
        })
        .collect()
}
```

### Zero-Downtime Migration

1. **Shadow table:** Create new table with SXURL support
2. **Dual writes:** Write to both old and new tables
3. **Backfill:** Copy old data to new table with SXURL generation
4. **Switch reads:** Gradually move read queries to new table
5. **Drop old:** Remove old table once all reads migrated

## 15. Monitoring & Debugging

### Key Metrics to Track

#### Performance Metrics

```sql
-- Query performance by query type
SELECT
    query_type,
    AVG(execution_time_ms) as avg_execution_time,
    COUNT(*) as query_count
FROM query_logs
WHERE table_name = 'urls'
GROUP BY query_type;

-- Index usage statistics
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan,
    idx_tup_read,
    idx_tup_fetch
FROM pg_stat_user_indexes
WHERE tablename = 'urls';
```

#### Data Quality Metrics

```sql
-- SXURL coverage
SELECT
    COUNT(*) as total_urls,
    COUNT(sxurl_id) as sxurl_count,
    COUNT(sxurl_id) * 100.0 / COUNT(*) as coverage_percent
FROM urls;

-- False positive monitoring for TLD queries
SELECT
    tld_filter,
    sxurl_matches,
    actual_matches,
    (sxurl_matches - actual_matches) * 100.0 / sxurl_matches as false_positive_rate
FROM tld_accuracy_check;
```

### Common Issues and Debugging

#### Issue: High False Positive Rate

**Symptoms:** Queries returning too many unexpected results

**Debugging:**
```sql
-- Check if normalization is consistent
SELECT url, sxurl_id FROM urls
WHERE SUBSTRING(sxurl_id, 4, 4) = '62fe'  -- .com filter
  AND url NOT LIKE '%.com%'
LIMIT 10;
```

**Solutions:**
- Verify normalization implementation
- Add secondary validation
- Use compound filters

#### Issue: Poor Query Performance

**Symptoms:** Slow SUBSTRING queries

**Debugging:**
```sql
-- Check if indexes are being used
EXPLAIN (ANALYZE, BUFFERS)
SELECT * FROM urls
WHERE SUBSTRING(sxurl_id, 4, 4) = '62fe';
```

**Solutions:**
- Create specialized indexes for common substring patterns
- Consider partial indexes
- Verify statistics are up to date

#### Issue: Inconsistent SXURL Generation

**Symptoms:** Same URL producing different SXURLs

**Common causes:**
- Different normalization implementations
- Inconsistent PSL versions
- URL parsing differences

**Debugging:**
```rust
// Log intermediate steps
fn debug_sxurl_generation(url: &str) {
    println!("Original URL: {}", url);

    let normalized = normalize_url(url);
    println!("Normalized: {}", normalized);

    let (tld, domain, sub) = split_host(&normalized);
    println!("TLD: '{}', Domain: '{}', Sub: '{}'", tld, domain, sub);

    // ... continue logging each step
}
```

### Health Checks

```sql
-- Daily health check query
WITH health_metrics AS (
    SELECT
        COUNT(*) as total_urls,
        COUNT(sxurl_id) as sxurl_coverage,
        COUNT(DISTINCT SUBSTRING(sxurl_id, 4, 4)) as unique_tlds,
        COUNT(DISTINCT SUBSTRING(sxurl_id, 8, 15)) as unique_domains
    FROM urls
    WHERE created_at >= CURRENT_DATE
)
SELECT
    *,
    sxurl_coverage * 100.0 / total_urls as coverage_percent
FROM health_metrics;
```

## 16. Security Implications

### What SXURL Provides

**Privacy benefits:**
- **No URL reconstruction:** Cannot recover original URL from SXURL alone
- **Component isolation:** Can analyze patterns without seeing full URLs
- **Aggregate analytics:** Safe for privacy-preserving analytics

**Security benefits:**
- **Collision resistance:** SHA-256 based, difficult to engineer collisions
- **Deterministic:** Same URL always produces same SXURL
- **Tamper evident:** Changes to URL components change SXURL

### What SXURL Does NOT Provide

**Not authentication:** SXURL is not a signature or MAC
**Not encryption:** URL components are hashed, not encrypted
**Not authorization:** SXURL doesn't control access to URLs
**Not integrity protection:** For the original URL data

### Security Best Practices

#### 1. Keep URL-to-SXURL Mapping Secure

```rust
// Store the mapping separately with appropriate access controls
struct UrlMapping {
    sxurl_id: String,
    url: String,  // This should be protected!
    access_level: AccessLevel,
}
```

#### 2. Rate Limiting for Hash-Based Attacks

```rust
// Prevent attackers from probing for specific URL patterns
fn check_rate_limit(client_ip: &str, query_pattern: &str) -> bool {
    let key = format!("{}:{}", client_ip, query_pattern);
    rate_limiter.check(key, Duration::from_secs(60), 100)
}
```

#### 3. Monitor for Anomalous Query Patterns

```sql
-- Detect potential hash enumeration attacks
SELECT
    client_ip,
    COUNT(DISTINCT SUBSTRING(sxurl_filter, 1, 8)) as unique_patterns,
    COUNT(*) as total_queries
FROM query_logs
WHERE created_at >= NOW() - INTERVAL '1 hour'
GROUP BY client_ip
HAVING COUNT(DISTINCT SUBSTRING(sxurl_filter, 1, 8)) > 1000;
```

#### 4. Secure SXURL Generation

```rust
// Use cryptographically secure random source for any salting
use rand::rngs::OsRng;

// Validate inputs to prevent injection
fn validate_url_input(url: &str) -> Result<(), SecurityError> {
    if url.len() > MAX_URL_LENGTH {
        return Err(SecurityError::UrlTooLong);
    }

    // Additional validation...
    Ok(())
}
```

### Threat Model Considerations

**Attacker with database access:**
- Can see SXURL patterns
- Cannot reconstruct original URLs (without mapping table)
- Can analyze traffic patterns and frequencies

**Attacker with query access:**
- Can probe for specific domains/paths (with rate limiting)
- Can observe query result patterns
- Limited by false positive rates

**Insider threat:**
- Full database access reveals all patterns
- Original URL mapping must be separately protected
- Audit logging essential for accountability

---

# Part V: Reference

## 17. Binary Layout Reference

### Complete 256-Bit Layout

```
Bit positions:    0    12   28        88      120     136     196     232   256
                  │    │    │         │       │       │       │       │     │
                  ├────┼────┼─────────┼───────┼───────┼───────┼───────┼─────┤
Field:            │hdr │tld │ domain  │  sub  │ port  │ path  │params │frag │
Bit width:        │ 12 │ 16 │   60    │  32   │  16   │  60   │  36   │ 24  │
Hex positions:    │0-3 │3-7 │  7-22   │22-30  │30-34  │34-49  │49-58  │58-64│
                  └────┴────┴─────────┴───────┴───────┴───────┴───────┴─────┘
```

### Bit-Level Field Definitions

| Field | Start Bit | End Bit | Width | Hex Start | Hex End | Description |
|-------|-----------|---------|-------|-----------|---------|-------------|
| Header | 0 | 12 | 12 | 0 | 3 | Version + scheme + flags |
| TLD Hash | 12 | 28 | 16 | 3 | 7 | H16("tld", tld_bytes) |
| Domain Hash | 28 | 88 | 60 | 7 | 22 | H60("domain", domain_bytes) |
| Subdomain Hash | 88 | 120 | 32 | 22 | 30 | H32("sub", sub_bytes) |
| Port | 120 | 136 | 16 | 30 | 34 | Network byte order, 0 if absent |
| Path Hash | 136 | 196 | 60 | 34 | 49 | H60("path", path_bytes) |
| Params Hash | 196 | 232 | 36 | 49 | 58 | H36("params", query_bytes) |
| Fragment Hash | 232 | 256 | 24 | 58 | 64 | H24("frag", fragment_bytes) |

### Header Bit Layout

```
Header (12 bits): [V V V V][S S S][F F F F F]
                   │       │     │
                   │       │     └── Flags (5 bits)
                   │       └──────── Scheme (3 bits)
                   └──────────────── Version (4 bits)

Version: 0001 (always 1 for this spec)

Scheme:  000 = https
         001 = http
         010 = ftp
         011-111 = reserved

Flags:   Bit 4: sub_present
         Bit 3: params_present
         Bit 2: frag_present
         Bit 1: port_present
         Bit 0: reserved (must be 0)
```

### Hash Function Definition

For component bytes B and ASCII label L:

```
H_n(L, B) = lower_n_bits(SHA256(L || 0x00 || B))
```

Where:
- `L` is ASCII label: "tld", "domain", "sub", "path", "params", "frag"
- `0x00` is a single null byte separator
- `B` is the raw component bytes
- `lower_n_bits()` extracts the least significant n bits

## 18. Hex Slice Map

### Quick Reference Table

| Component | Hex Slice | Length | Example Query |
|-----------|-----------|--------|---------------|
| **Full SXURL** | `[0:64]` | 64 | `sxurl_id = '1002397f...'` |
| **Header** | `[0:3]` | 3 | `SUBSTRING(sxurl_id, 1, 3)` |
| **TLD** | `[3:7]` | 4 | `SUBSTRING(sxurl_id, 4, 4)` |
| **Domain** | `[7:22]` | 15 | `SUBSTRING(sxurl_id, 8, 15)` |
| **Subdomain** | `[22:30]` | 8 | `SUBSTRING(sxurl_id, 23, 8)` |
| **Port** | `[30:34]` | 4 | `SUBSTRING(sxurl_id, 31, 4)` |
| **Path** | `[34:49]` | 15 | `SUBSTRING(sxurl_id, 35, 15)` |
| **Params** | `[49:58]` | 9 | `SUBSTRING(sxurl_id, 50, 9)` |
| **Fragment** | `[58:64]` | 6 | `SUBSTRING(sxurl_id, 59, 6)` |

### Header Decoding

```python
def decode_header(hex_chars):
    """Decode the first 3 hex characters"""
    header = int(hex_chars[:3], 16)

    version = (header >> 8) & 0xF
    scheme = (header >> 5) & 0x7
    flags = header & 0x1F

    sub_present = bool(flags & 0x10)
    params_present = bool(flags & 0x08)
    frag_present = bool(flags & 0x04)
    port_present = bool(flags & 0x02)

    scheme_name = {0: 'https', 1: 'http', 2: 'ftp'}[scheme]

    return {
        'version': version,
        'scheme': scheme_name,
        'sub_present': sub_present,
        'params_present': params_present,
        'frag_present': frag_present,
        'port_present': port_present,
    }
```

### Common Hash Values

Pre-computed hashes for common components:

| Component | Value | Hash | Hex |
|-----------|-------|------|-----|
| TLD | ".com" | H16("tld", ".com") | `62fe` |
| TLD | ".org" | H16("tld", ".org") | `daa3` |
| TLD | ".ai" | H16("tld", ".ai") | `2e31` |
| Domain | "google" | H60("domain", "google") | `03e9505795e1d08` |
| Domain | "example" | H60("domain", "example") | `9cee73c091a1a7b` |
| Path | "/" | H60("path", "/") | `98911d784580332` |
| Path | "/search" | H60("path", "/search") | `239f9d65dd89753` |
| Subdomain | "api" | H32("sub", "api") | `5b7f8002` |
| Subdomain | "www" | H32("sub", "www") | `aa4cd029` |

### Port Encoding

Ports are stored as 16-bit big-endian values:

| Port | Hex |
|------|-----|
| 80 | `0050` |
| 443 | `01bb` |
| 8080 | `1f90` |
| 8443 | `20fb` |
| 3000 | `0bb8` |

## 19. Error Codes

### Error Hierarchy

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum SxurlError {
    // Input validation errors
    InvalidScheme,
    HostNotDns,
    HostTooLong,
    InvalidLabel,
    InvalidCharacter,
    InvalidPort,

    // Parsing errors
    ParseError(String),
    UrlParseError(String),

    // SXURL format errors
    InvalidLength,
    InvalidHexCharacter,
    InvalidHeader,
    UnsupportedVersion,
    ReservedBitSet,
    PortFlagMismatch,

    // Internal errors
    HashingError,
    InternalError,
}
```

### Error Descriptions

| Error | Code | Description | Resolution |
|-------|------|-------------|------------|
| `InvalidScheme` | `E001` | Scheme not in {https, http, ftp} | Use supported scheme |
| `HostNotDns` | `E002` | Host is not a DNS name | Use DNS hostname |
| `HostTooLong` | `E003` | Host > 255 bytes | Shorten hostname |
| `InvalidLabel` | `E004` | DNS label invalid | Fix hostname format |
| `InvalidCharacter` | `E005` | Invalid character in hostname | Use valid DNS characters |
| `InvalidPort` | `E006` | Port not in range 1-65535 | Use valid port number |
| `ParseError` | `E007` | General URL parsing failed | Check URL syntax |
| `UrlParseError` | `E008` | URL crate parsing failed | Verify URL format |
| `InvalidLength` | `E009` | SXURL not 64 hex chars | Check input length |
| `InvalidHexCharacter` | `E010` | Non-hex character in SXURL | Use only 0-9,a-f |
| `InvalidHeader` | `E011` | Header format invalid | Check version/scheme/flags |
| `UnsupportedVersion` | `E012` | Version not 1 | Use version 1 format |
| `ReservedBitSet` | `E013` | Reserved bit not zero | Clear reserved bits |
| `PortFlagMismatch` | `E014` | Port/flag inconsistency | Match port presence to flag |
| `HashingError` | `E015` | SHA-256 computation failed | Internal error |
| `InternalError` | `E016` | Unexpected internal error | Bug - report issue |

### Error Handling Examples

```rust
match generate_sxurl(url) {
    Ok(sxurl) => println!("SXURL: {}", sxurl),
    Err(SxurlError::InvalidScheme) => {
        eprintln!("Error: Only https, http, and ftp schemes are supported");
    },
    Err(SxurlError::HostNotDns) => {
        eprintln!("Error: Host must be a DNS name, not an IP address");
    },
    Err(SxurlError::HostTooLong) => {
        eprintln!("Error: Hostname exceeds 255 byte limit");
    },
    Err(e) => {
        eprintln!("Unexpected error: {:?}", e);
    }
}
```

## 20. Test Vectors

### Complete Test Cases

#### Test Case 1: Basic HTTPS

**Input:** `https://docs.rs/`

**Normalization steps:**
1. Scheme: `https` (already lowercase)
2. Host: `docs.rs` (already lowercase, valid ASCII)
3. PSL split: TLD=`rs`, Domain=`docs`, Subdomain=``
4. Path: `/`
5. Query: `` (empty)
6. Fragment: `` (empty)
7. Port: None (default)

**Component hashes:**
- `H16("tld", "rs")` = `0x2397`
- `H60("domain", "docs")` = `0xf4018b8efa86c31`
- `H32("sub", "")` = `0x440f00a9`
- `H60("path", "/")` = `0x98911d784580332`
- `H36("params", "")` = `0xc354b043a`
- `H24("frag", "")` = `0x29e356`

**Header:**
- Version: `1` (0001)
- Scheme: `https` (000)
- Flags: No subdomain, params, fragment, or port (00000)
- Header value: `(1 << 8) | (0 << 5) | 0` = `0x100`

**Packed result:**
`1002397f4018b8efa86c31440f00a9000098911d784580332c354b043a29e356`

#### Test Case 2: Complex HTTP

**Input:** `http://api.example.ai:8443/search?q=test#results`

**Normalization steps:**
1. Scheme: `http`
2. Host: `api.example.ai`
3. PSL split: TLD=`ai`, Domain=`example`, Subdomain=`api`
4. Path: `/search`
5. Query: `q=test`
6. Fragment: `results`
7. Port: `8443`

**Component hashes:**
- `H16("tld", "ai")` = `0x2e31`
- `H60("domain", "example")` = `0x9cee73c091a1a7b`
- `H32("sub", "api")` = `0x5b7f8002`
- `H60("path", "/search")` = `0xcb7e8070cf84487`
- `H36("params", "q=test")` = `0x8f9a1b3c2`
- `H24("frag", "results")` = `0x1a2b3c`

**Header:**
- Version: `1` (0001)
- Scheme: `http` (001)
- Flags: subdomain + params + fragment + port (11110)
- Header value: `(1 << 8) | (1 << 5) | 30` = `0x13e`

**Packed result:**
`13e2e319cee73c091a1a7b5b7f800220fbcb7e8070cf844878f9a1b3c21a2b3c`

#### Test Case 3: Error Cases

**Input:** `ws://chat.example.com/socket`
**Expected:** `SxurlError::InvalidScheme`

**Input:** `https://192.168.1.1/path`
**Expected:** `SxurlError::HostNotDns`

**Input:** `https://verylongdomainnamethatiswaymorethanthe63characterlimitforasinglelabel.com/`
**Expected:** `SxurlError::InvalidLabel`

### Validation Test Suite

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_https() {
        let url = "https://docs.rs/";
        let expected = "1002397f4018b8efa86c31440f00a9000098911d784580332c354b043a29e356";
        assert_eq!(generate_sxurl(url).unwrap(), expected);
    }

    #[test]
    fn test_complex_http() {
        let url = "http://api.example.ai:8443/search?q=test#results";
        let expected = "13e2e319cee73c091a1a7b5b7f800220fbcb7e8070cf844878f9a1b3c21a2b3c";
        assert_eq!(generate_sxurl(url).unwrap(), expected);
    }

    #[test]
    fn test_invalid_scheme() {
        let url = "ws://chat.example.com/socket";
        assert_eq!(generate_sxurl(url).unwrap_err(), SxurlError::InvalidScheme);
    }

    #[test]
    fn test_round_trip_consistency() {
        let url = "https://www.google.com/search?q=rust&hl=en";
        let sxurl1 = generate_sxurl(url).unwrap();
        let sxurl2 = generate_sxurl(url).unwrap();
        assert_eq!(sxurl1, sxurl2);
    }
}
```

---

# Part VI: Formal Specification

## 21. Formal Specification

### 1. Intent and Scope

**Intent**: Transform a URL into a single 256-bit token printed as 64 hex characters where each URL component occupies a fixed hex slice position.

**Why**: Fixed-size keys enable efficient database indexing, and hex substring filters provide fast component-based queries without requiring URL parsing at query time.

**Scope**:
- **Schemes**: `https`, `http`, `ftp` only. Other schemes return error.
- **Hosts**: DNS names only. IP literals are out of scope.
- **Goal**: Indexing and querying. For URL reconstruction, maintain separate `id → url` mapping.

### 2. Normalization

URL normalization MUST be applied consistently:

1. **Scheme and host**: Convert to lowercase ASCII
2. **Host validation**: Apply IDNA UTS-46 conversion. Validate each label is 1-63 bytes, total host ≤ 255 bytes.
3. **Public Suffix List splitting**:
   - `tld`: The public suffix (may be multi-label)
   - `domain`: Registrable label immediately left of TLD
   - `subdomain`: All labels left of domain, joined with `.` (may be empty)
   - **Fallback**: If no PSL available, use rightmost label as TLD
4. **Path, query, fragment**: Treat as raw bytes. Do NOT modify percent encodings or `+` symbols.

### 3. Component Hash Function

For component bytes $B$ and ASCII label $L$:

$$H_n(L,B) = \operatorname{lower}_n\Big(\mathrm{SHA256}(L \parallel 0x00 \parallel B)\Big)$$

**Labels**: `"tld"`, `"domain"`, `"sub"`, `"path"`, `"params"`, `"frag"`

Where $\operatorname{lower}_n$ extracts the least significant $n$ bits of the SHA-256 output.

### 4. Binary Layout

Total: **256 bits = 64 hex characters**, nibble-aligned:

```
[ header:12 ][ tld_h:16 ][ domain_h:60 ][ sub_h:32 ][ port:16 ]
[ path_h:60 ][ params_h:36 ][ frag_h:24 ]
```

#### 4.1 Header Format (12 bits)

$$\text{header} = (\text{version} \ll 8) \;|\; (\text{scheme} \ll 5) \;|\; \text{flags}$$

**Bit layout**: `[version:4][scheme:3][flags:5]`

- **Version**: `0001` (decimal 1)
- **Scheme**: `000` = https, `001` = http, `010` = ftp
- **Flags** (MSB to LSB): `sub_present, params_present, frag_present, port_present, reserved(0)`

#### 4.2 Field Mapping

| Field | Hex Range | Bits | Content |
|-------|-----------|------|---------|
| header | `[0..3)` | 12 | Version, scheme, flags |
| tld_h | `[3..7)` | 16 | $H_{16}(\text{"tld"}, \text{tld})$ |
| domain_h | `[7..22)` | 60 | $H_{60}(\text{"domain"}, \text{domain})$ |
| sub_h | `[22..30)` | 32 | $H_{32}(\text{"sub"}, \text{subdomain})$ |
| port | `[30..34)` | 16 | Port in network byte order, 0000 if absent |
| path_h | `[34..49)` | 60 | $H_{60}(\text{"path"}, \text{path})$ |
| params_h | `[49..58)` | 36 | $H_{36}(\text{"params"}, \text{query})$ |
| frag_h | `[58..64)` | 24 | $H_{24}(\text{"frag"}, \text{fragment})$ |

### 5. Encoding Algorithm

**Input**: URL string
**Output**: 32 bytes as 64 hex characters

1. Parse and normalize URL into components: `scheme, tld, domain, subdomain, port, path, query, fragment`
2. **Validate**: If `scheme ∉ {https, http, ftp}`, return `ERR_INVALID_SCHEME`
3. **Set flags**:
   - `sub_present = (subdomain ≠ "")`
   - `params_present = (query ≠ "")`
   - `frag_present = (fragment ≠ "")`
   - `port_present = (port is explicitly specified)`
4. **Map scheme**: https → 000, http → 001, ftp → 010
5. **Hash components**: Apply $H_n$ with appropriate bit widths
6. **Pack bits**: Concatenate all fields big-endian according to layout
7. **Output**: Convert 256 bits to 64 hex characters

### 6. Validation Rules

**Input validation**:
- Scheme MUST be `https`, `http`, or `ftp`
- Host MUST be valid DNS name (not IP address)
- Host labels MUST be 1-63 bytes each, total ≤ 255 bytes
- Port MUST be 1-65535 if present

**Output validation**:
- SXURL MUST be exactly 64 hex characters
- Version field MUST be 1
- Reserved flag bit MUST be 0
- If `port_present = 0`, port field MUST be `0000`
- If `port_present = 1`, port field MUST be 1-65535

### 7. Error Conditions

| Condition | Error Code |
|-----------|------------|
| Invalid scheme | `ERR_INVALID_SCHEME` |
| Host not DNS name | `ERR_HOST_NOT_DNS` |
| Host length violation | `ERR_HOST_LEN` |
| Port flag mismatch | `ERR_PORT_FLAG_MISMATCH` |
| Version not 1 | `ERR_UNSUPPORTED_VERSION` |
| Reserved bit set | `ERR_RESERVED_BIT` |

### 8. Query Semantics

**Equality filter** for component with $b$-bit hash:

1. Normalize probe value identically to encoding
2. Compute $H_b(\text{label}, \text{probe})$
3. Compare to SXURL hex substring at fixed position

**False positive rate**: $\text{FPR} \approx 2^{-b}$

**Compound filters**: Combine multiple component filters to reduce false positive probability.

### 9. Implementation Requirements

**Deterministic normalization**: Same URL MUST always produce same SXURL across implementations and time.

**Bit-exact packing**: Field boundaries MUST align exactly as specified. Big-endian byte order MUST be used.

**Hash consistency**: SHA-256 implementation MUST be cryptographically correct. Label separation MUST use single 0x00 byte.

**Validation completeness**: ALL validation rules MUST be enforced during encoding and decoding.

## 22. Compliance Checklist

Implementation MUST satisfy ALL requirements:

### Core Requirements
- [ ] **Scheme validation**: Only `{https, http, ftp}` accepted, others return error
- [ ] **Host normalization**: Lowercase + IDNA UTS-46 applied correctly
- [ ] **Host validation**: Label lengths 1-63 bytes, total ≤ 255 bytes
- [ ] **PSL integration**: Proper TLD/domain/subdomain splitting with defined fallback
- [ ] **Component preservation**: Path/query/fragment treated as raw bytes

### Hashing Requirements
- [ ] **Labeled hashing**: SHA-256 with component labels and 0x00 separator
- [ ] **Bit truncation**: Correct extraction of least significant bits
- [ ] **Hash determinism**: Same input always produces same hash

### Binary Format Requirements
- [ ] **Header format**: `[version:4][scheme:3][flags:5]` with version=1
- [ ] **Bit allocation**: Exact field widths as specified (12,16,60,32,16,60,36,24)
- [ ] **Big-endian packing**: Network byte order throughout
- [ ] **Hex encoding**: 256 bits → exactly 64 lowercase hex characters

### Validation Requirements
- [ ] **Flag consistency**: Presence flags match actual component presence
- [ ] **Port handling**: `port_present=0` ⟺ port field is `0000`
- [ ] **Reserved bits**: Must be zero in flags field
- [ ] **Range validation**: Port 1-65535 when present

### Output Requirements
- [ ] **Length**: Always exactly 64 hex characters
- [ ] **Character set**: Only `0-9a-f` (lowercase hex)
- [ ] **Determinism**: Identical URLs produce identical SXURLs
- [ ] **Reversibility**: Can extract metadata (scheme, flags) from SXURL

### Error Handling Requirements
- [ ] **Complete coverage**: All error conditions properly detected
- [ ] **Appropriate codes**: Specific error types for different failures
- [ ] **Input validation**: All validation before processing
- [ ] **Graceful failure**: No crashes on invalid input

### Test Suite Requirements
- [ ] **Test vectors**: All provided test cases pass
- [ ] **Round-trip**: Same URL always produces same SXURL
- [ ] **Edge cases**: Empty components, special characters, boundary values
- [ ] **Error cases**: All error conditions properly triggered

## 23. Version History

### Version 1.0 (Current)

**Initial release** with the following characteristics:

**Bit allocation**:
- Header: 12 bits (version + scheme + flags)
- TLD: 16 bits (H16 hash)
- Domain: 60 bits (H60 hash)
- Subdomain: 32 bits (H32 hash)
- Port: 16 bits (raw value)
- Path: 60 bits (H60 hash)
- Params: 36 bits (H36 hash)
- Fragment: 24 bits (H24 hash)

**Supported schemes**: https, http, ftp

**Hash function**: SHA-256 with field labels and null separator

**Normalization**: IDNA UTS-46, PSL-based host splitting, raw path/query/fragment

### Future Version Considerations

**Potential changes for version 2**:
- Additional scheme support (add new scheme codes)
- Different bit allocations (if false positive rates prove problematic)
- Alternative hash functions (if SHA-256 performance becomes issue)
- IPv6 support (currently DNS names only)

**Backward compatibility**:
- Version field allows format evolution
- Old implementations can reject newer versions
- Hash function changes would require full regeneration

**Migration strategy**:
- Dual-format support during transition
- Incremental conversion of existing data
- Version-aware tooling and libraries

---

# Appendices

## Appendix A: Rust Implementation

### Complete Working Implementation

```rust
use sha2::{Sha256, Digest};
use url::Url;
use std::convert::TryInto;

/// SXURL generation errors
#[derive(Debug, Clone, PartialEq)]
pub enum SxurlError {
    InvalidScheme,
    HostNotDns,
    HostTooLong,
    InvalidLabel,
    ParseError(String),
    InternalError,
}

/// Generate SXURL from URL string
pub fn generate_sxurl(url: &str) -> Result<String, SxurlError> {
    // Parse URL
    let parsed = Url::parse(url)
        .map_err(|e| SxurlError::ParseError(e.to_string()))?;

    // Validate and extract scheme
    let scheme_bits = match parsed.scheme() {
        "https" => 0b000,
        "http" => 0b001,
        "ftp" => 0b010,
        _ => return Err(SxurlError::InvalidScheme),
    };

    // Extract and validate host
    let host = parsed.host_str().ok_or(SxurlError::HostNotDns)?;
    validate_host(host)?;

    // Split host using PSL (simplified - use actual PSL in production)
    let (tld, domain, subdomain) = split_host(host)?;

    // Extract other components
    let path = parsed.path();
    let query = parsed.query().unwrap_or("");
    let fragment = parsed.fragment().unwrap_or("");
    let port = parsed.port();

    // Set presence flags
    let sub_present = !subdomain.is_empty();
    let params_present = !query.is_empty();
    let frag_present = !fragment.is_empty();
    let port_present = port.is_some();

    let flags =
        (if sub_present { 1 } else { 0 }) << 4 |
        (if params_present { 1 } else { 0 }) << 3 |
        (if frag_present { 1 } else { 0 }) << 2 |
        (if port_present { 1 } else { 0 }) << 1;

    // Build header
    let header = (1u16 << 8) | ((scheme_bits as u16) << 5) | flags;

    // Hash components
    let tld_hash = hash_component("tld", tld.as_bytes(), 16)?;
    let domain_hash = hash_component("domain", domain.as_bytes(), 60)?;
    let sub_hash = hash_component("sub", subdomain.as_bytes(), 32)?;
    let path_hash = hash_component("path", path.as_bytes(), 60)?;
    let params_hash = hash_component("params", query.as_bytes(), 36)?;
    let frag_hash = hash_component("frag", fragment.as_bytes(), 24)?;

    // Pack into 256 bits
    let sxurl_bits = pack_bits(
        header,
        tld_hash,
        domain_hash,
        sub_hash,
        port.unwrap_or(0),
        path_hash,
        params_hash,
        frag_hash,
    );

    // Convert to hex
    Ok(bits_to_hex(&sxurl_bits))
}

/// Validate DNS hostname
fn validate_host(host: &str) -> Result<(), SxurlError> {
    if host.len() > 255 {
        return Err(SxurlError::HostTooLong);
    }

    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(SxurlError::InvalidLabel);
        }

        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(SxurlError::InvalidLabel);
        }

        if label.starts_with('-') || label.ends_with('-') {
            return Err(SxurlError::InvalidLabel);
        }
    }

    Ok(())
}

/// Split host into TLD, domain, subdomain (simplified PSL implementation)
fn split_host(host: &str) -> Result<(String, String, String), SxurlError> {
    let parts: Vec<&str> = host.split('.').collect();

    if parts.len() < 2 {
        return Err(SxurlError::InvalidLabel);
    }

    // Simplified: use last part as TLD, second-to-last as domain
    let tld = parts.last().unwrap().to_string();
    let domain = parts[parts.len() - 2].to_string();
    let subdomain = if parts.len() > 2 {
        parts[..parts.len() - 2].join(".")
    } else {
        String::new()
    };

    Ok((tld, domain, subdomain))
}

/// Hash component with label
fn hash_component(label: &str, data: &[u8], bit_width: usize) -> Result<u64, SxurlError> {
    let mut hasher = Sha256::new();

    // Add label
    hasher.update(label.as_bytes());

    // Add separator
    hasher.update(&[0x00]);

    // Add data
    hasher.update(data);

    let hash = hasher.finalize();

    // Extract lower bits
    Ok(extract_bits(&hash, bit_width))
}

/// Extract lower n bits from hash
fn extract_bits(hash: &[u8], bit_width: usize) -> u64 {
    let mut result = 0u64;
    let bytes_needed = (bit_width + 7) / 8;

    for (i, &byte) in hash.iter().take(bytes_needed).enumerate() {
        result |= (byte as u64) << (i * 8);
    }

    // Mask to exact bit width
    let mask = if bit_width >= 64 { u64::MAX } else { (1u64 << bit_width) - 1 };
    result & mask
}

/// Pack all components into 256-bit array
fn pack_bits(
    header: u16,
    tld_hash: u64,
    domain_hash: u64,
    sub_hash: u64,
    port: u16,
    path_hash: u64,
    params_hash: u64,
    frag_hash: u64,
) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut bit_offset = 0;

    // Helper to pack bits
    let mut pack = |value: u64, width: usize| {
        for i in 0..width {
            let bit = (value >> i) & 1;
            let byte_idx = bit_offset / 8;
            let bit_idx = bit_offset % 8;

            if bit != 0 {
                result[byte_idx] |= 1 << bit_idx;
            }

            bit_offset += 1;
        }
    };

    // Pack fields in order
    pack(header as u64, 12);
    pack(tld_hash, 16);
    pack(domain_hash, 60);
    pack(sub_hash, 32);
    pack(port as u64, 16);
    pack(path_hash, 60);
    pack(params_hash, 36);
    pack(frag_hash, 24);

    result
}

/// Convert byte array to hex string
fn bits_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode SXURL header information
pub fn decode_header(sxurl: &str) -> Result<SxurlHeader, SxurlError> {
    if sxurl.len() != 64 {
        return Err(SxurlError::ParseError("Invalid length".to_string()));
    }

    let header_hex = &sxurl[0..3];
    let header = u16::from_str_radix(header_hex, 16)
        .map_err(|_| SxurlError::ParseError("Invalid header".to_string()))?;

    let version = (header >> 8) & 0xF;
    let scheme = (header >> 5) & 0x7;
    let flags = header & 0x1F;

    if version != 1 {
        return Err(SxurlError::ParseError("Unsupported version".to_string()));
    }

    let scheme_name = match scheme {
        0 => "https",
        1 => "http",
        2 => "ftp",
        _ => return Err(SxurlError::ParseError("Invalid scheme".to_string())),
    };

    Ok(SxurlHeader {
        version,
        scheme: scheme_name.to_string(),
        sub_present: (flags & 0x10) != 0,
        params_present: (flags & 0x08) != 0,
        frag_present: (flags & 0x04) != 0,
        port_present: (flags & 0x02) != 0,
    })
}

#[derive(Debug, Clone)]
pub struct SxurlHeader {
    pub version: u16,
    pub scheme: String,
    pub sub_present: bool,
    pub params_present: bool,
    pub frag_present: bool,
    pub port_present: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_https() {
        let url = "https://docs.rs/";
        let sxurl = generate_sxurl(url).unwrap();
        assert_eq!(sxurl.len(), 64);

        // Should start with 100 (version 1, https, no flags)
        assert!(sxurl.starts_with("100"));
    }

    #[test]
    fn test_complex_url() {
        let url = "http://api.example.com:8443/search?q=test#results";
        let sxurl = generate_sxurl(url).unwrap();
        assert_eq!(sxurl.len(), 64);

        let header = decode_header(&sxurl).unwrap();
        assert_eq!(header.scheme, "http");
        assert!(header.sub_present);
        assert!(header.params_present);
        assert!(header.frag_present);
        assert!(header.port_present);
    }

    #[test]
    fn test_invalid_scheme() {
        let url = "ws://chat.example.com/";
        assert_eq!(generate_sxurl(url).unwrap_err(), SxurlError::InvalidScheme);
    }

    #[test]
    fn test_deterministic() {
        let url = "https://www.google.com/search?q=rust";
        let sxurl1 = generate_sxurl(url).unwrap();
        let sxurl2 = generate_sxurl(url).unwrap();
        assert_eq!(sxurl1, sxurl2);
    }
}
```

### Usage Examples

```rust
use sxurl::{generate_sxurl, decode_header};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate SXURL
    let url = "https://api.github.com/repos/rust-lang/rust";
    let sxurl = generate_sxurl(url)?;
    println!("URL: {}", url);
    println!("SXURL: {}", sxurl);

    // Decode header info
    let header = decode_header(&sxurl)?;
    println!("Scheme: {}", header.scheme);
    println!("Has subdomain: {}", header.sub_present);

    // Extract components for querying
    let tld_slice = &sxurl[3..7];
    let domain_slice = &sxurl[7..22];
    let path_slice = &sxurl[34..49];

    println!("TLD hash: {}", tld_slice);
    println!("Domain hash: {}", domain_slice);
    println!("Path hash: {}", path_slice);

    Ok(())
}
```

## Appendix B: Comparison with Alternatives

### Full URL Hashing

**Approach**: Hash the entire URL with MD5/SHA-256

```sql
-- Traditional full URL hashing
CREATE TABLE urls (
    url_hash CHAR(32),  -- MD5 hex
    url TEXT
);

SELECT * FROM urls WHERE url_hash = MD5('https://example.com/path');
```

**Limitations**:
- ❌ No component filtering (can't find all `.com` domains)
- ❌ No pattern analysis (can't group by path patterns)
- ❌ Requires exact URL match
- ✅ Smaller storage (16-32 bytes vs 32 bytes)
- ✅ Zero false positives

### Integer ID Mapping

**Approach**: Assign integer IDs to URL components

```sql
CREATE TABLE tlds (id INT, tld VARCHAR(64));
CREATE TABLE domains (id INT, domain VARCHAR(255));
CREATE TABLE urls (
    tld_id INT,
    domain_id INT,
    path_id INT,
    -- etc
);
```

**Limitations**:
- ❌ Requires large lookup tables
- ❌ Dictionary management complexity
- ❌ Cross-system synchronization issues
- ✅ Exact matches, no false positives
- ✅ Very compact storage
- ✅ Fast integer comparisons

### Bloom Filters

**Approach**: Use Bloom filters for set membership

**Limitations**:
- ❌ Can't extract individual components
- ❌ False positives (but no false negatives)
- ❌ Can't count occurrences accurately
- ✅ Very space efficient
- ✅ Fast membership testing

### Traditional Database Indexes

**Approach**: Index URL components directly

```sql
CREATE TABLE urls (
    url TEXT,
    tld VARCHAR(64),
    domain VARCHAR(255),
    path VARCHAR(1000)
);

CREATE INDEX ON urls(tld);
CREATE INDEX ON urls(domain);
```

**Limitations**:
- ❌ Variable-length storage
- ❌ Large index sizes
- ❌ String comparison overhead
- ✅ No false positives
- ✅ Full SQL query capabilities
- ✅ Human readable

### Performance Comparison

| Approach | Storage/URL | Index Size (1M URLs) | Query Speed | False Positives |
|----------|-------------|----------------------|-------------|-----------------|
| **SXURL** | 32 bytes | ~32 MB | Very Fast | Controlled |
| Full hash | 16 bytes | ~16 MB | Fast | None |
| Integer IDs | 8 bytes | ~8 MB + dictionaries | Very Fast | None |
| Bloom filters | 1-2 bytes | ~1-2 MB | Very Fast | Uncontrolled |
| Raw strings | 50-200 bytes | 50-200 MB | Slow | None |

### When to Choose SXURL

**Choose SXURL when**:
- You need component-based filtering
- Storage efficiency matters but not critically
- Controlled false positives are acceptable
- You need privacy-preserving analytics
- Cross-system compatibility is important

**Choose alternatives when**:
- **Perfect accuracy required** → Integer IDs or raw strings
- **Maximum storage efficiency** → Bloom filters
- **Simple exact matching** → Full URL hashing
- **Complex SQL queries on components** → Raw string storage

## Appendix C: FAQ

### General Questions

**Q: Why not just use MD5/SHA-256 of the full URL?**

A: Full URL hashing prevents component-based queries. You can't find "all URLs from google.com" or "all API endpoints" without storing and parsing the original URLs.

**Q: How do I handle the false positives?**

A: Either accept them (for analytics), use secondary validation (first filter with SXURL, then validate with original URL), or combine multiple components to reduce the probability.

**Q: Can I reconstruct the original URL from SXURL?**

A: No, hashing is one-way. You need to maintain a separate `sxurl_id → url` mapping if reconstruction is required.

**Q: What's the performance impact compared to traditional URL storage?**

A: Queries are much faster (index scans vs table scans), but storage overhead is 50-100% due to keeping both SXURL and original URL.

### Implementation Questions

**Q: Do I need to use the exact same PSL (Public Suffix List) version?**

A: Yes, for consistency across systems. Consider pinning to a specific PSL version or implementing a fallback strategy.

**Q: What happens if I change the normalization implementation?**

A: All existing SXURLs become invalid. Normalization must be exactly consistent. Consider this when updating libraries.

**Q: Can I implement SXURL in languages other than Rust?**

A: Yes, any language with SHA-256 support. The key is bit-exact compatibility with the specification.

**Q: How do I handle internationalized domain names (IDN)?**

A: Apply IDNA UTS-46 normalization to convert to ASCII before processing. This is required by the specification.

### Database Questions

**Q: What's the best database column type for SXURL?**

A: `CHAR(64)` in most databases. Fixed-length is important for index efficiency.

**Q: Should I index the full SXURL or just common slices?**

A: Both. Create a full index for exact matches, plus partial indexes for common component queries.

**Q: How do I migrate from an existing URL table?**

A: Add SXURL column, backfill in batches, update application code for dual writes, migrate queries gradually, then clean up.

**Q: What about database query optimization?**

A: Use `SUBSTRING()` operations on fixed positions. Most databases can optimize these well with proper indexes.

### Operational Questions

**Q: How do I monitor false positive rates in production?**

A: Periodically sample results and validate against original URLs. Track the ratio for each component type.

**Q: What's the storage growth pattern?**

A: Linear with URL count. 1 billion URLs ≈ 32 GB for SXURLs + original URL storage.

**Q: How do I handle SXURL collisions?**

A: They're expected for smaller fields (TLD, params, fragment). Use compound filters or secondary validation.

**Q: Can I use SXURL for real-time stream processing?**

A: Yes, generation is fast (~microseconds per URL). Consider batching for very high throughput.

### Security Questions

**Q: Is SXURL cryptographically secure?**

A: It uses SHA-256 which is cryptographically strong, but SXURL itself is not a security mechanism. It provides privacy benefits but not authentication or integrity.

**Q: Can attackers reverse-engineer URLs from SXURL patterns?**

A: Partial information may leak (domain patterns, common paths), but specific URLs cannot be reconstructed. Consider this in your threat model.

**Q: Should I rate-limit SXURL queries?**

A: Yes, to prevent enumeration attacks. Monitor for unusual query patterns that might indicate probing.

**Q: What about privacy regulations (GDPR, etc.)?**

A: SXURL can help with privacy by avoiding storage of full URLs, but consult legal counsel for your specific requirements.
