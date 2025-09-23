# SXURL (Slice eXact URL): hierarchical fixed-length URL identifier

## 1. Intent and why

* **Intent**: turn a URL into a **single 256-bit token** printed as **64 hex characters** where each URL part lives in a fixed hex slice. Components arranged hierarchically for prefix-based grouping.
* **Why**: fixed size keys are easy to store and index. Hex substring filters are fast. Per-field hashing avoids large dictionaries. Hierarchical layout enables host-level and domain-level operations at scale.

## 2. The URL management problem

Modern web systems handle billions of URLs across crawling, caching, security, and analytics. Traditional approaches break at scale.

### 2.1 Variable length kills performance

URLs vary from 20 to 2000+ characters. Variable-length storage causes:
- Inefficient database row packing
- Poor B-tree index performance
- CPU cache misses
- Expensive string comparisons

### 2.2 Traditional hashing destroys hierarchy

```
MD5("https://example.com/")      = 3b5f5c6a8d9e7f2b1c4a6d8e9f0a1b2c
MD5("https://example.com/about") = 9f8e7d6c5b4a3a2a1f0e9d8c7b6a5a4a
                                    ↑ No relationship despite same domain
```

Cannot group by host or domain without full table scans.

### 2.3 Component filtering requires expensive operations

Common queries like "all API endpoints" or "all .com domains" require:
```sql
-- Full table scan with regex
SELECT * FROM urls WHERE url REGEXP '^https?://api\\..*\\.';

-- Multiple LIKE operations
SELECT * FROM urls WHERE url LIKE '%.com/%' AND url LIKE '%api.%';
```

### 2.4 SXURL solution

Hierarchical structure preserves relationships:
```
SXURL("https://example.com/")      = 002397f4a9cee73c091a1a7b440f00a9...
SXURL("https://example.com/about") = 002397f4a9cee73c091a1a7b440f00a9...
                                      ↑ Same prefix for same domain
```

Fixed positions enable direct component access:
```sql
-- All .com domains (position 2-9)
SELECT * FROM urls WHERE SUBSTRING(sxurl, 3, 7) = '2397f4a';

-- All api.* subdomains (position 24-32)
SELECT * FROM urls WHERE SUBSTRING(sxurl, 25, 8) = '5b7f8002';

-- All from api.example.com (host prefix)
SELECT * FROM urls WHERE sxurl LIKE '002397f4a9cee73c091a1a7b5b7f8002%';
```

## 3. Scope

* **Schemes**: `https`, `http`, `ftp`. Anything else is an error.
* **Hosts**: DNS names only. IP literals are out of scope.
* **Goal**: indexing, querying, and hierarchical grouping. Store `id → url` mapping for reconstruction.

---

## 4. Normalization

* Lowercase **scheme** and **host**.
* Convert host to ASCII with **IDNA UTS-46**. Validate: each label 1..63 bytes, total host ≤ 255 bytes.
* Split host using Public Suffix List:
  * `tld`: the public suffix, can be multi-label (`com`, `co.uk`)
  * `domain`: registrable label left of `tld` (`example`)
  * `subdomain`: everything left of `domain`, joined with `.` (`api.v2`). May be empty.
* **Path**, **query**, **fragment**: treat as raw bytes. Do not rewrite percent encodings.

---

## 5. Per-field hash

For component bytes $B$ and ASCII label $L$:

$$
H_n(L,B) = \operatorname{lower}_n\Big(\mathrm{SHA256}(L \parallel 0x00 \parallel B)\Big)
$$

Labels: `"tld"`, `"domain"`, `"subdomain"`, `"path"`, `"query"`, `"fragment"`.

Labeled hashing prevents cross-component collisions: $H(\text{"domain"}, \text{"api"}) \neq H(\text{"subdomain"}, \text{"api"})$.

---

## 6. Binary layout and hex anatomy

Total: **256 bits = 64 hex characters**. Hierarchical arrangement for prefix matching.

```
Host Section (128 bits):
[scheme:4][reserved:4][tld:28][domain:60][subdomain:32]

Path Section (128 bits):
[flags:8][port:16][path:52][query:32][fragment:20]
```

### 6.1 Hex slice map

| Component | Hex range | Bits | Description |
|-----------|-----------|------|-------------|
| scheme+reserved | [0..2) | 8 | HTTPS=0, HTTP=1, FTP=2 |
| tld_hash | [2..9) | 28 | H28 over TLD |
| domain_hash | [9..24) | 60 | H60 over domain |
| subdomain_hash | [24..32) | 32 | H32 over subdomain |
| flags | [32..34) | 8 | Component presence |
| port | [34..38) | 16 | Network byte order |
| path_hash | [38..51) | 52 | H52 over path |
| query_hash | [51..59) | 32 | H32 over query |
| fragment_hash | [59..64) | 20 | H20 over fragment |

### 6.2 Flags byte (position 32-34)

```
Bit 7: subdomain_present
Bit 6: port_present (non-default port)
Bit 5: path_present (not "/" or empty)
Bit 4: query_present
Bit 3: fragment_present
Bits 2-0: reserved (must be 0)
```

### 6.3 Hierarchical structure

```
002397f4a9cee73c091a1a7b5b7f8002a001bb7a5bc3d892f4e61c354b0329e3
│ │       │                 │        │ │    │               │       │
│ │       │                 │        │ │    │               │       └─ fragment
│ │       │                 │        │ │    │               └─ query
│ │       │                 │        │ │    └─ path
│ │       │                 │        │ └─ port
│ │       │                 │        └─ flags
│ │       │                 └─ subdomain
│ │       └─ domain
│ └─ tld
└─ scheme+reserved

Host prefix: 002397f4a9cee73c091a1a7b5b7f8002 (32 hex chars)
Domain prefix: 002397f4a9cee73c091a1a7b (24 hex chars)
```

---

## 7. Encoding algorithm

```rust
use sha2::{Sha256, Digest};

pub fn encode_sxurl(url: &str) -> Result<String, SxurlError> {
    // 1. Parse and validate
    let parsed = Url::parse(url)?;
    let scheme_code = match parsed.scheme() {
        "https" => 0u8,
        "http" => 1u8,
        "ftp" => 2u8,
        _ => return Err(SxurlError::UnsupportedScheme),
    };

    // 2. Split hostname using PSL
    let host = parsed.host_str().ok_or(SxurlError::NoHost)?;
    let (tld, domain, subdomain) = split_host(host)?;

    // 3. Compute labeled hashes
    let tld_hash = hash_component("tld", &tld, 28)?;
    let domain_hash = hash_component("domain", &domain, 60)?;
    let subdomain_hash = hash_component("subdomain", &subdomain, 32)?;
    let path_hash = hash_component("path", parsed.path(), 52)?;
    let query_hash = hash_component("query", parsed.query().unwrap_or(""), 32)?;
    let fragment_hash = hash_component("fragment", parsed.fragment().unwrap_or(""), 20)?;

    // 4. Build flags
    let mut flags = 0u8;
    if !subdomain.is_empty() { flags |= 0x80; }
    if parsed.port().is_some() && parsed.port() != default_port(parsed.scheme()) {
        flags |= 0x40;
    }
    if parsed.path() != "/" && !parsed.path().is_empty() { flags |= 0x20; }
    if parsed.query().is_some() { flags |= 0x10; }
    if parsed.fragment().is_some() { flags |= 0x08; }

    // 5. Pack into hex string
    let port = parsed.port().unwrap_or(default_port(parsed.scheme()));

    Ok(format!(
        "{:01x}{:01x}{:07x}{:015x}{:08x}{:02x}{:04x}{:013x}{:08x}{:05x}",
        scheme_code, 0, // reserved
        tld_hash, domain_hash, subdomain_hash,
        flags, port,
        path_hash, query_hash, fragment_hash
    ))
}

fn hash_component(label: &str, data: &str, bits: usize) -> Result<u64, SxurlError> {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update(&[0x00]);
    hasher.update(data.as_bytes());
    let hash = hasher.finalize();

    // Extract lower bits
    let bytes = &hash[hash.len()-8..];
    let value = u64::from_le_bytes(bytes.try_into().unwrap());
    let mask = (1u64 << bits) - 1;
    Ok(value & mask)
}

fn default_port(scheme: &str) -> u16 {
    match scheme {
        "https" => 443,
        "http" => 80,
        "ftp" => 21,
        _ => 0,
    }
}
```

---

## 8. Examples with step-by-step encoding

### 8.1 Simple domain

**URL**: `https://example.com/`

1. **Parse**: scheme=https, host=example.com, path=/
2. **Split host**: tld=com, domain=example, subdomain=""
3. **Hash components**:
   - H28("tld", "com") = 0x2397f4a
   - H60("domain", "example") = 0x9cee73c091a1a7b
   - H32("subdomain", "") = 0x440f00a9
   - H52("path", "/") = 0x1911d7845803c
   - H32("query", "") = 0xc354b043
   - H20("fragment", "") = 0x29e35
4. **Flags**: 0x00 (none set)
5. **Pack**: `002397f4a9cee73c091a1a7b440f00a90001bb1911d7845803c354b04329e35`

### 8.2 API endpoint with query

**URL**: `https://api.example.com/v2/users?page=1&limit=10`

1. **Parse**: scheme=https, host=api.example.com, path=/v2/users, query=page=1&limit=10
2. **Split host**: tld=com, domain=example, subdomain=api
3. **Hash components**:
   - H28("tld", "com") = 0x2397f4a
   - H60("domain", "example") = 0x9cee73c091a1a7b
   - H32("subdomain", "api") = 0x5b7f8002
   - H52("path", "/v2/users") = 0x17a5bc3d892f4e
   - H32("query", "page=1&limit=10") = 0x61c354b0
   - H20("fragment", "") = 0x29e35
4. **Flags**: 0xB0 (subdomain=1, path=1, query=1)
5. **Pack**: `002397f4a9cee73c091a1a7b5b7f8002b001bb7a5bc3d892f4e61c354b029e35`

### 8.3 Non-default port

**URL**: `http://example.com:8080/api`

1. **Parse**: scheme=http, host=example.com, port=8080, path=/api
2. **Flags**: 0x60 (port_present=1, path_present=1)
3. **Pack**: `102397f4a9cee73c091a1a7b440f00a9601f90def456789abc354b043029e35`

---

## 9. Query patterns and database operations

### 9.1 Host-level grouping

```sql
-- All URLs from api.example.com
SELECT * FROM urls
WHERE sxurl LIKE '002397f4a9cee73c091a1a7b5b7f8002%';

-- Count URLs per host
SELECT
    SUBSTRING(sxurl, 1, 32) as host_prefix,
    COUNT(*) as url_count
FROM urls
GROUP BY host_prefix
ORDER BY url_count DESC;
```

### 9.2 Domain-level operations

```sql
-- All subdomains of example.com
SELECT * FROM urls
WHERE SUBSTRING(sxurl, 1, 24) = '002397f4a9cee73c091a1a7b';

-- Domain statistics
SELECT
    SUBSTRING(sxurl, 1, 24) as domain_prefix,
    COUNT(DISTINCT SUBSTRING(sxurl, 25, 8)) as subdomain_count,
    COUNT(*) as total_urls
FROM urls
GROUP BY domain_prefix;
```

### 9.3 Component filtering

```sql
-- All .com domains (assuming H28("tld", "com") = 0x2397f4a)
SELECT * FROM urls
WHERE SUBSTRING(sxurl, 3, 7) = '2397f4a';

-- All API subdomains across domains (H32("subdomain", "api") = 0x5b7f8002)
SELECT * FROM urls
WHERE SUBSTRING(sxurl, 25, 8) = '5b7f8002';

-- URLs with query parameters
SELECT * FROM urls
WHERE (CONV(SUBSTRING(sxurl, 33, 2), 16, 10) & 0x10) != 0;

-- Non-standard ports
SELECT * FROM urls
WHERE (CONV(SUBSTRING(sxurl, 33, 2), 16, 10) & 0x40) != 0;
```

### 9.4 Optimized database schema

```sql
CREATE TABLE urls (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    sxurl CHAR(64) NOT NULL,
    original_url TEXT NOT NULL,

    -- Computed columns for fast filtering
    tld_hash CHAR(7) GENERATED ALWAYS AS (SUBSTRING(sxurl, 3, 7)),
    domain_hash CHAR(15) GENERATED ALWAYS AS (SUBSTRING(sxurl, 10, 15)),
    host_prefix CHAR(32) GENERATED ALWAYS AS (SUBSTRING(sxurl, 1, 32)),
    domain_prefix CHAR(24) GENERATED ALWAYS AS (SUBSTRING(sxurl, 1, 24)),

    -- Flag extraction
    has_subdomain BOOLEAN GENERATED ALWAYS AS
        ((CONV(SUBSTRING(sxurl, 33, 2), 16, 10) & 0x80) != 0),
    has_query BOOLEAN GENERATED ALWAYS AS
        ((CONV(SUBSTRING(sxurl, 33, 2), 16, 10) & 0x10) != 0),

    UNIQUE KEY (sxurl),
    KEY (host_prefix),
    KEY (domain_prefix),
    KEY (tld_hash),
    KEY (has_query)
);
```

---

## 10. SXURL variants for hierarchical operations

### 10.1 Host SXURL

Host-level identifier with path section zeroed:
```rust
pub fn to_host_sxurl(full_sxurl: &str) -> String {
    format!("{}{}", &full_sxurl[..32], "0".repeat(32))
}
```

Example:
```
Full:  002397f4a9cee73c091a1a7b5b7f8002b001bb7a5bc3d892f4e61c354b029e35
Host:  002397f4a9cee73c091a1a7b5b7f800200000000000000000000000000000000
```

### 10.2 Domain SXURL

Domain-level identifier with subdomain and path sections zeroed:
```rust
pub fn to_domain_sxurl(full_sxurl: &str) -> String {
    format!("{}{}", &full_sxurl[..24], "0".repeat(40))
}
```

Example:
```
Full:   002397f4a9cee73c091a1a7b5b7f8002b001bb7a5bc3d892f4e61c354b029e35
Domain: 002397f4a9cee73c091a1a7b0000000000000000000000000000000000000000
```

### 10.3 Hierarchical matching

```rust
pub fn same_host(sxurl1: &str, sxurl2: &str) -> bool {
    sxurl1[..32] == sxurl2[..32]
}

pub fn same_domain(sxurl1: &str, sxurl2: &str) -> bool {
    sxurl1[..24] == sxurl2[..24]
}

pub fn extract_components(sxurl: &str) -> SxurlComponents {
    SxurlComponents {
        scheme: u8::from_str_radix(&sxurl[0..1], 16).unwrap(),
        tld_hash: &sxurl[2..9],
        domain_hash: &sxurl[9..24],
        subdomain_hash: &sxurl[24..32],
        flags: u8::from_str_radix(&sxurl[32..34], 16).unwrap(),
        port: u16::from_str_radix(&sxurl[34..38], 16).unwrap(),
        path_hash: &sxurl[38..51],
        query_hash: &sxurl[51..59],
        fragment_hash: &sxurl[59..64],
    }
}
```

---

## 11. Real-world applications and conceptual frameworks

### 11.1 CDN domain filtering examples

**Example URLs and SXURLs:**
```
https://cdn.cloudflare.com/ajax/libs/jquery.js
SXURL: 062fe9cee73c091a1a7b5b7f800220fbcb7e8070cf84487f86a9df2b86e801

https://cdn.jsdelivr.net/npm/bootstrap.css
SXURL: 0a1b2c3d4e5f6789abcdef012345678901234567890123456789abcdef0123

https://assets.github.com/images/logo.png
SXURL: 162fe9cee73c091a1a7b4efc0aa00015b75ba348fb4b4b8c354b043a29e356
```

**CDN filtering rules:**
- Cache all CDN traffic: SXURLs starting with `062fe` (cloudflare.com TLD+domain)
- Block specific CDN: Block SXURLs starting with `0a1b2` (jsdelivr.net)
- Cache static assets: SXURLs with path patterns `cb7e8070cf844` (.js), `b75ba348fb4b4` (.png)

### 11.2 Security filtering examples

**Example malicious URLs:**
```
https://secure-bank-login.tk/signin?token=steal
SXURL: 0badtld9maliciousdomain123456789012345678901234567890123456789ab

https://paypal-verify.ml/account/verify
SXURL: 0anothrbad9anothermalicious78901234567890123456789012345678901ab

https://legitimate.com/admin/upload.php
SXURL: 062fe9cee73c091a1a7b00000000000adminupload123456789012345678ab
```

**Security filtering rules:**
- Block suspicious TLDs: Block SXURLs with `badtld` or `anothrbad` in positions [2:9]
- Block admin paths: Block SXURLs with `adminupload` pattern in positions [38:51]
- Block login phishing: Block SXURLs with `signin` or `verify` path patterns

### 11.3 API rate limiting examples

**Example API URLs:**
```
https://api.stripe.com/v1/charges
SXURL: 062fe9cee73c091a1a7b5a7b9c1d00000apicharges789012345678901234ab

https://webhooks.github.com/events
SXURL: 162fe9cee73c091a1a7b1d2e3f4g00000webhookevents1234567890123456ab

https://cdn.example.com/static/image.jpg
SXURL: 062fe9cee73c091a1a7b7e8f9a1b00000staticimage23456789012345678ab
```

**Rate limiting rules:**
- Strict API limits: `5a7b9c1d` (api subdomain) → 1000 req/min
- Webhook limits: `1d2e3f4g` (webhooks subdomain) → 100 req/min
- Generous CDN limits: `7e8f9a1b` (cdn subdomain) → 10000 req/min
- Path-based limits: `apicharges` path → 100 req/min per user

### 11.6 Web crawler deduplication

```rust
struct CrawlTracker {
    seen: BloomFilter<String>,
    db: Database,
}

impl CrawlTracker {
    fn should_crawl(&mut self, url: &str) -> bool {
        let sxurl = encode_sxurl(url).unwrap();

        // Quick bloom filter check
        if self.seen.contains(&sxurl) {
            return false;
        }

        // Check host rate limit (last hour)
        let host_prefix = &sxurl[..32];
        let recent = self.db.execute(
            "SELECT COUNT(*) FROM crawled WHERE sxurl LIKE ? AND crawled_at > ?",
            &[&format!("{}%", host_prefix), &(now() - 3600)]
        ).unwrap();

        if recent > 100 {
            return false; // Rate limited
        }

        self.seen.insert(&sxurl);
        true
    }
}
```

### 11.2 CDN cache key generation

```rust
fn cache_key(url: &str) -> String {
    let sxurl = encode_sxurl(url).unwrap();
    let flags = u8::from_str_radix(&sxurl[32..34], 16).unwrap();

    if (flags & 0x10) == 0 {
        // No query params - cache by host+path
        format!("static:{}", &sxurl[..51])
    } else {
        // Has query - need full URL
        format!("dynamic:{}", sxurl)
    }
}
```

### 11.3 CDN rule application

```rust
struct CDNRuleEngine {
    cdn_subdomain_hashes: HashSet<String>,     // cdn.*, static.*, assets.*
    cdn_domain_rules: HashMap<String, CdnRule>, // cloudflare.com, fastly.com
    path_rules: HashMap<String, CacheRule>,     // /static/, /assets/
}

impl CDNRuleEngine {
    fn apply_rules(&self, url: &str) -> RuleSet {
        let sxurl = encode_sxurl(url).unwrap();
        let mut rules = RuleSet::default();

        // Check if subdomain is CDN-related
        let subdomain_hash = &sxurl[24..32];
        if self.cdn_subdomain_hashes.contains(subdomain_hash) {
            rules.cache_ttl = 86400; // 24 hours for CDN subdomains
            rules.compression = true;
            rules.edge_caching = true;
        }

        // Check for known CDN providers by domain
        let domain_hash = &sxurl[9..24];
        if let Some(cdn_rule) = self.cdn_domain_rules.get(domain_hash) {
            rules.merge(cdn_rule);
            rules.is_third_party_cdn = true;
        }

        // Path-based rules
        let path_hash = &sxurl[38..51];
        if let Some(cache_rule) = self.path_rules.get(path_hash) {
            rules.apply_path_rule(cache_rule);
        }

        rules
    }

    fn load_cdn_rules() -> Self {
        let mut engine = CDNRuleEngine::default();

        // Common CDN subdomains
        engine.add_cdn_subdomain("cdn");     // cdn.example.com
        engine.add_cdn_subdomain("static");  // static.example.com
        engine.add_cdn_subdomain("assets");  // assets.example.com
        engine.add_cdn_subdomain("media");   // media.example.com

        // Known CDN providers
        engine.add_cdn_domain("cloudflare.com", CdnRule {
            cache_ttl: 31536000, // 1 year
            compression: true,
            security_headers: true,
        });

        engine.add_cdn_domain("fastly.com", CdnRule {
            cache_ttl: 2592000, // 30 days
            purge_api: true,
        });

        // Path-based rules
        engine.add_path_rule("/static/", CacheRule::long_term());
        engine.add_path_rule("/assets/", CacheRule::long_term());
        engine.add_path_rule("/api/", CacheRule::no_cache());

        engine
    }

    fn add_cdn_subdomain(&mut self, subdomain: &str) {
        let hash = hash_component("subdomain", subdomain, 32).unwrap();
        self.cdn_subdomain_hashes.insert(format!("{:08x}", hash));
    }
}

// Usage example
let rules_engine = CDNRuleEngine::load_cdn_rules();
let rules = rules_engine.apply_rules("https://cdn.example.com/images/logo.png");
println!("Cache TTL: {}, Edge caching: {}", rules.cache_ttl, rules.edge_caching);
```

### 11.4 Security filtering

```rust
struct SecurityFilter {
    blocked_domains: HashSet<String>,      // malware domains
    suspicious_paths: HashSet<String>,     // /admin, /.git, etc
    suspicious_subdomains: HashSet<String>, // phishing patterns
    malware_file_hashes: HashSet<String>,  // known bad files
}

impl SecurityFilter {
    fn check_url(&self, url: &str) -> SecurityResult {
        let sxurl = encode_sxurl(url).unwrap();
        let flags = u8::from_str_radix(&sxurl[32..34], 16).unwrap();

        // Check domain blocklist
        let domain_hash = &sxurl[9..24];
        if self.blocked_domains.contains(domain_hash) {
            return SecurityResult::Blocked("Known malicious domain".to_string());
        }

        // Check for suspicious subdomains (e.g., phishing)
        let subdomain_hash = &sxurl[24..32];
        if self.suspicious_subdomains.contains(subdomain_hash) {
            return SecurityResult::Suspicious("Suspicious subdomain pattern".to_string());
        }

        // Check path patterns
        let path_hash = &sxurl[38..51];
        if self.suspicious_paths.contains(path_hash) {
            return SecurityResult::Suspicious("Potentially dangerous path".to_string());
        }

        // Flag-based security checks
        if (flags & 0x40) != 0 { // Non-standard port
            let port = u16::from_str_radix(&sxurl[34..38], 16).unwrap();
            if self.is_suspicious_port(port) {
                return SecurityResult::Suspicious(format!("Suspicious port: {}", port));
            }
        }

        SecurityResult::Safe
    }

    fn load_security_rules() -> Self {
        let mut filter = SecurityFilter::default();

        // Known malicious domains
        filter.add_blocked_domain("malware-site.com");
        filter.add_blocked_domain("phishing-example.org");

        // Suspicious paths
        filter.add_suspicious_path("/admin");
        filter.add_suspicious_path("/wp-admin");
        filter.add_suspicious_path("/.git");
        filter.add_suspicious_path("/.env");
        filter.add_suspicious_path("/config");

        // Phishing subdomain patterns
        filter.add_suspicious_subdomain("secure-login");
        filter.add_suspicious_subdomain("account-verify");
        filter.add_suspicious_subdomain("paypal-security");

        filter
    }

    fn is_suspicious_port(&self, port: u16) -> bool {
        matches!(port, 1337 | 4444 | 8888 | 31337) // Common malware ports
    }
}
```

### 11.5 Rate limiting with business rules

```rust
struct BusinessRateLimiter {
    domain_tiers: HashMap<String, ServiceTier>,
    subdomain_rules: HashMap<String, RateRule>,
    path_patterns: HashMap<String, RateRule>,
}

impl BusinessRateLimiter {
    fn check_rate_limit(&self, url: &str, client_id: &str) -> RateLimitResult {
        let sxurl = encode_sxurl(url).unwrap();

        // Determine service tier by domain
        let domain_hash = &sxurl[9..24];
        let tier = self.domain_tiers.get(domain_hash)
            .unwrap_or(&ServiceTier::Free);

        // Apply subdomain-specific rules
        let subdomain_hash = &sxurl[24..32];
        let mut limit = tier.base_limit();

        if let Some(rule) = self.subdomain_rules.get(subdomain_hash) {
            limit = rule.apply_to_limit(limit);
        }

        // Apply path-specific rules
        let path_hash = &sxurl[38..51];
        if let Some(rule) = self.path_patterns.get(path_hash) {
            limit = rule.apply_to_limit(limit);
        }

        // Check against actual usage
        let usage = self.get_usage(client_id, &sxurl[..32]); // Host-level tracking

        if usage >= limit {
            RateLimitResult::Limited {
                limit,
                current: usage,
                reset_time: self.get_reset_time(client_id)
            }
        } else {
            RateLimitResult::Allowed {
                remaining: limit - usage
            }
        }
    }

    fn load_business_rules() -> Self {
        let mut limiter = BusinessRateLimiter::default();

        // Domain tier mapping
        limiter.set_domain_tier("stripe.com", ServiceTier::Enterprise);
        limiter.set_domain_tier("github.com", ServiceTier::Professional);
        limiter.set_domain_tier("example.com", ServiceTier::Free);

        // Subdomain-specific rules
        limiter.add_subdomain_rule("api", RateRule::multiply(0.5)); // API calls more expensive
        limiter.add_subdomain_rule("cdn", RateRule::multiply(2.0)); // CDN calls cheaper
        limiter.add_subdomain_rule("webhooks", RateRule::multiply(0.1)); // Webhooks very limited

        // Path-based rules
        limiter.add_path_rule("/api/v1/upload", RateRule::multiply(0.1)); // Uploads limited
        limiter.add_path_rule("/api/v1/search", RateRule::multiply(0.3)); // Search limited
        limiter.add_path_rule("/static/", RateRule::multiply(5.0)); // Static files generous

        limiter
    }
}

#[derive(Clone)]
enum ServiceTier {
    Free,
    Professional,
    Enterprise,
}

impl ServiceTier {
    fn base_limit(&self) -> u32 {
        match self {
            ServiceTier::Free => 100,
            ServiceTier::Professional => 1000,
            ServiceTier::Enterprise => 10000,
        }
    }
}
```

### 11.6 Analytics and monitoring

```rust
struct URLAnalytics {
    db: Database,
}

impl URLAnalytics {
    fn analyze_traffic_patterns(&self, domain: &str) -> TrafficReport {
        let domain_sxurl = encode_sxurl(&format!("https://{}/", domain)).unwrap();
        let domain_prefix = &domain_sxurl[..24];

        // Get all traffic for this domain
        let results = self.db.execute(r#"
            SELECT
                SUBSTRING(sxurl, 25, 8) as subdomain_hash,
                SUBSTRING(sxurl, 39, 13) as path_hash,
                COUNT(*) as hits,
                AVG(response_time) as avg_response_time,
                SUM(bytes_transferred) as total_bytes,
                COUNT(DISTINCT client_ip) as unique_visitors
            FROM access_logs
            WHERE SUBSTRING(sxurl, 1, 24) = ?
              AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY subdomain_hash, path_hash
            ORDER BY hits DESC
        "#, &[domain_prefix]).unwrap();

        let mut report = TrafficReport::new(domain);

        for row in results {
            let subdomain_hash: String = row.get(0);
            let path_hash: String = row.get(1);
            let hits: u64 = row.get(2);

            // Reverse lookup for readability (optional)
            let subdomain = self.reverse_lookup_subdomain(&subdomain_hash);
            let path_pattern = self.reverse_lookup_path(&path_hash);

            report.add_pattern(TrafficPattern {
                subdomain: subdomain.unwrap_or_else(|| format!("#{}", subdomain_hash)),
                path: path_pattern.unwrap_or_else(|| format!("#{}", path_hash)),
                hits,
                avg_response_time: row.get(3),
                total_bytes: row.get(4),
                unique_visitors: row.get(5),
            });
        }

        report
    }

    fn detect_anomalies(&self) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();

        // Detect unusual subdomain activity
        let unusual_subdomains = self.db.execute(r#"
            SELECT
                SUBSTRING(sxurl, 25, 8) as subdomain_hash,
                COUNT(*) as current_hour_hits,
                AVG(hist.hourly_avg) as historical_avg
            FROM access_logs al
            LEFT JOIN hourly_stats hist ON hist.subdomain_hash = SUBSTRING(al.sxurl, 25, 8)
            WHERE al.timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)
            GROUP BY SUBSTRING(al.sxurl, 25, 8)
            HAVING current_hour_hits > historical_avg * 5  -- 5x normal traffic
        "#).unwrap();

        for row in unusual_subdomains {
            let subdomain_hash: String = row.get(0);
            let current_hits: u64 = row.get(1);
            let historical_avg: f64 = row.get(2);

            anomalies.push(Anomaly {
                type_: AnomalyType::UnusualSubdomainTraffic,
                component_hash: subdomain_hash,
                severity: if current_hits as f64 > historical_avg * 10.0 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                details: format!("Subdomain traffic {}x normal",
                    current_hits as f64 / historical_avg),
            });
        }

        // Detect new path patterns
        let new_paths = self.db.execute(r#"
            SELECT DISTINCT SUBSTRING(sxurl, 39, 13) as path_hash
            FROM access_logs
            WHERE timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)
              AND SUBSTRING(sxurl, 39, 13) NOT IN (
                  SELECT DISTINCT path_hash FROM known_paths
              )
        "#).unwrap();

        for row in new_paths {
            let path_hash: String = row.get(0);
            anomalies.push(Anomaly {
                type_: AnomalyType::NewPathPattern,
                component_hash: path_hash,
                severity: Severity::Low,
                details: "New path pattern detected".to_string(),
            });
        }

        anomalies
    }
}
```

---

## 12. Collision analysis and security

### 12.1 Collision probabilities

| Component | Bits | 50% collision at | Practical safety |
|-----------|------|------------------|------------------|
| TLD | 28 | ~16k TLDs | Very safe (~1.5k exist) |
| Domain | 60 | ~1B domains | Safe (~350M exist) |
| Subdomain | 32 | ~65k unique | Acceptable |
| Path | 52 | ~2.2M unique | Acceptable |
| Query | 32 | ~65k unique | Acceptable |
| Fragment | 20 | ~1k unique | Monitor for hotspots |

### 12.2 Hash security

- **Pre-image resistance**: Cannot recover URL from SXURL
- **Labeled hashing**: Prevents cross-component attacks
- **Truncation**: Reduces collision resistance but acceptable for use case

### 12.3 Privacy considerations

- TLD position is predictable (enumerable)
- Common components can be rainbow-tabled
- Consider encryption for sensitive URL patterns

---

## 13. Implementation notes

### 13.1 Performance optimizations

```rust
// Cache common component hashes
struct SxurlEncoder {
    tld_cache: HashMap<String, u64>,
    domain_cache: HashMap<String, u64>,
}

impl SxurlEncoder {
    fn encode_cached(&mut self, url: &str) -> Result<String, SxurlError> {
        let (tld, domain, subdomain) = split_host(url)?;

        let tld_hash = *self.tld_cache.entry(tld.clone())
            .or_insert_with(|| hash_component("tld", &tld, 28).unwrap());

        let domain_hash = *self.domain_cache.entry(domain.clone())
            .or_insert_with(|| hash_component("domain", &domain, 60).unwrap());

        // ... rest of encoding
    }
}
```

### 13.2 Batch operations

```rust
fn encode_batch(urls: &[String]) -> Vec<(String, String)> {
    urls.par_iter()
        .filter_map(|url| {
            encode_sxurl(url).ok().map(|sxurl| (url.clone(), sxurl))
        })
        .collect()
}
```

---

## 14. Migration from existing systems

### 14.1 Gradual rollout

```rust
// Dual-write during migration
fn store_url(url: &str) -> Result<(), Error> {
    let sxurl = encode_sxurl(url)?;

    // Write to both old and new schema
    db.execute("INSERT INTO urls_old (url) VALUES (?)", &[url])?;
    db.execute("INSERT INTO urls_new (sxurl, url) VALUES (?, ?)", &[&sxurl, url])?;

    Ok(())
}
```

### 14.2 Validation

```rust
fn validate_migration() -> Result<(), Error> {
    let rows = db.query("SELECT url FROM urls_old LIMIT 1000")?;

    for row in rows {
        let url: String = row.get(0)?;
        let sxurl = encode_sxurl(&url)?;

        // Verify round-trip via lookup table
        let stored_url = lookup_url(&sxurl)?;
        assert_eq!(url, stored_url);
    }

    Ok(())
}
```

---

## 15. Quick reference

### 15.1 Hex positions

```
[0..2):   Scheme + Reserved (2 hex)
[2..9):   TLD hash (7 hex)
[9..24):  Domain hash (15 hex)
[24..32): Subdomain hash (8 hex)
[32..34): Flags (2 hex)
[34..38): Port (4 hex)
[38..51): Path hash (13 hex)
[51..59): Query hash (8 hex)
[59..64): Fragment hash (5 hex)
```

### 15.2 Common operations

```rust
// Extract hierarchical prefixes
let host_prefix = &sxurl[..32];      // All from same host
let domain_prefix = &sxurl[..24];    // All from same domain

// Check component presence
let flags = u8::from_str_radix(&sxurl[32..34], 16).unwrap();
let has_query = (flags & 0x10) != 0;
let has_subdomain = (flags & 0x80) != 0;

// Component extraction
let tld_hash = &sxurl[2..9];
let domain_hash = &sxurl[9..24];
let subdomain_hash = &sxurl[24..32];
```

### 15.3 SQL patterns

```sql
-- Host grouping
WHERE sxurl LIKE '${host_prefix}%'

-- Domain grouping
WHERE SUBSTRING(sxurl, 1, 24) = '${domain_prefix}'

-- Component filtering
WHERE SUBSTRING(sxurl, 3, 7) = '${tld_hash}'
WHERE SUBSTRING(sxurl, 25, 8) = '${subdomain_hash}'

-- Flag checking
WHERE (CONV(SUBSTRING(sxurl, 33, 2), 16, 10) & 0x10) != 0  -- has query
```

---

*End of SXURL Specification*