# CLAUDE.md - Rust Development Guidelines

This file provides comprehensive guidance to Claude Code when working with Rust code in this repository.

## Core Development Philosophy

### KISS (Keep It Simple, Stupid)
Simplicity should be a key goal in design. Choose straightforward solutions over complex ones whenever possible. Simple solutions are easier to understand, maintain, and debug. Leverage Rust's type system to make invalid states unrepresentable rather than adding runtime complexity.

### YAGNI (You Aren't Gonna Need It)
Avoid building functionality on speculation. Implement features only when they are needed, not when you anticipate they might be useful in the future. Rust's zero-cost abstractions make it easier to refactor later when needed.

## Design Principles

- **Dependency Inversion**: High-level modules should not depend on low-level modules. Both should depend on abstractions (traits).
- **Open/Closed Principle**: Software entities should be open for extension but closed for modification.
- **Single Responsibility**: Each function, struct, and module should have one clear purpose.
- **Fail Fast**: Use Rust's type system and `Result`/`Option` types to make errors explicit and handle them early.

## 🧱 Code Structure & Modularity

### File and Function Limits
- Never create a file longer than 500 lines of code. If approaching this limit, refactor by splitting into modules.
- Functions should be under 50 lines with a single, clear responsibility.
- Structs and their implementations should be under 200 lines and represent a single concept or entity.
- Organize code into clearly separated modules, grouped by feature or responsibility.
- Line length should be max 100 characters (configured in `rustfmt.toml`).

### Project Architecture
Follow strict vertical slice architecture with tests living next to the code they test:

```
src/
    main.rs
    lib.rs
    
    # Core modules
    database/
        mod.rs
        connection.rs
        models.rs
        
    auth/
        mod.rs
        authentication.rs
        authorization.rs
        
    # Feature slices
    features/
        user_management/
            mod.rs
            handlers.rs
            validators.rs
            
        payment_processing/
            mod.rs
            processor.rs
            gateway.rs

tests/
    integration/
        auth_tests.rs
        user_management_tests.rs
    
    fixtures/
        mod.rs
        test_data.rs

# Unit tests in same files as code
# src/auth/authentication.rs includes:
# #[cfg(test)]
# mod tests { ... }
```

## 🛠️ Development Environment

### Cargo Package Management
This project uses Cargo for Rust package and dependency management.

```bash
# Create new project
cargo new my_project
cargo new my_library --lib

# Build project
cargo build
cargo build --release

# Run project
cargo run
cargo run --bin specific_binary

# Add dependencies
cargo add serde --features derive
cargo add tokio --features full
cargo add sqlx --features postgres,runtime-tokio-rustls

# Add development dependencies
cargo add --dev proptest
cargo add --dev criterion --features html_reports

# Remove a dependency
# Edit Cargo.toml manually, then run:
cargo check

# Update dependencies
cargo update

# Run with specific features
cargo run --features "feature1,feature2"

# Cross-compilation
cargo build --target x86_64-pc-windows-gnu
```

### Development Commands

```bash
# Run all tests
cargo test

# Run specific tests with verbose output
cargo test test_module -- --nocapture

# Run tests with coverage (requires cargo-tarpaulin)
cargo install cargo-tarpaulin
cargo tarpaulin --out Html

# Format code
cargo fmt

# Check code without building
cargo check

# Lint with Clippy
cargo clippy
cargo clippy -- -D warnings  # Treat warnings as errors

# Generate documentation
cargo doc --open
cargo doc --no-deps --open  # Only local crate docs

# Run benchmarks
cargo bench

# Security audit
cargo install cargo-audit
cargo audit

# Check for unused dependencies
cargo install cargo-udeps
cargo +nightly udeps
```

## 📋 Style & Conventions

### Rust Style Guide
Follow the official Rust style guide with these specific choices:
- Line length: 100 characters (set in `rustfmt.toml`)
- Use `rustfmt` for consistent formatting
- Always run `cargo clippy` and fix warnings
- Use meaningful names even if they're longer
- Prefer explicit return types over type inference for public APIs
- Use `#![warn(clippy::all)]` and `#![warn(clippy::pedantic)]` in lib.rs

### rustfmt.toml Configuration
```toml
max_width = 100
tab_spaces = 4
use_small_heuristics = "Default"
imports_granularity = "Crate"
group_imports = "StdExternalCrate"
```

### Documentation Standards
Use Rust's built-in documentation comments for all public items:

```rust
/// Calculate the discounted price for a product.
/// 
/// # Arguments
/// 
/// * `price` - Original price of the product
/// * `discount_percent` - Discount percentage (0.0-100.0)
/// * `min_amount` - Minimum allowed final price
/// 
/// # Returns
/// 
/// Final price after applying discount
/// 
/// # Errors
/// 
/// Returns `ValidationError` if:
/// - `discount_percent` is not between 0.0 and 100.0
/// - Final price would be below `min_amount`
/// 
/// # Examples
/// 
/// ```
/// use rust_decimal::Decimal;
/// use std::str::FromStr;
/// 
/// let price = Decimal::from_str("100.00").unwrap();
/// let result = calculate_discount(price, 20.0, Decimal::from_str("0.01").unwrap())?;
/// assert_eq!(result, Decimal::from_str("80.00").unwrap());
/// ```
pub fn calculate_discount(
    price: Decimal,
    discount_percent: f64,
    min_amount: Decimal,
) -> Result<Decimal, ValidationError> {
    // Implementation here
}
```

### Naming Conventions
- Variables and functions: `snake_case`
- Types (structs, enums, traits): `PascalCase`
- Constants: `SCREAMING_SNAKE_CASE`
- Modules: `snake_case`
- Crate names: `kebab-case` (in Cargo.toml)

## 🧪 Testing Strategy

### Test-Driven Development (TDD)
1. **Write the test first** - Define expected behavior before implementation
2. **Watch it fail** - Ensure the test actually tests something
3. **Write minimal code** - Just enough to make the test pass
4. **Refactor** - Improve code while keeping tests green
5. **Repeat** - One test at a time

### Testing Best Practices

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    
    #[test]
    fn test_user_can_update_email_when_valid() {
        // Arrange
        let mut user = User::new("Test User", "test@example.com").unwrap();
        let new_email = "newemail@example.com";
        
        // Act
        let result = user.update_email(new_email);
        
        // Assert
        assert!(result.is_ok());
        assert_eq!(user.email(), new_email);
    }
    
    #[test]
    fn test_user_update_email_fails_with_invalid_format() {
        let mut user = User::new("Test User", "test@example.com").unwrap();
        
        let result = user.update_email("not-an-email");
        
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Invalid email format");
    }
    
    // Property-based testing with proptest
    proptest! {
        #[test]
        fn test_price_calculation_never_negative(
            price in 0.0f64..10000.0,
            discount in 0.0f64..100.0
        ) {
            let result = calculate_discount_f64(price, discount);
            prop_assert!(result >= 0.0);
        }
    }
}

// Integration tests in tests/ directory
#[tokio::test]
async fn test_full_user_registration_flow() {
    let app = spawn_test_app().await;
    
    let response = app
        .post_user(&serde_json::json!({
            "name": "Test User",
            "email": "test@example.com"
        }))
        .await;
        
    assert_eq!(response.status(), 201);
    
    let user: User = response.json().await;
    assert_eq!(user.name(), "Test User");
}
```

### Test Organization
- **Unit tests**: In `#[cfg(test)]` modules within source files
- **Integration tests**: In `tests/` directory
- **Documentation tests**: In doc comments (automatically tested)
- **Benchmark tests**: In `benches/` directory
- Use `cargo test --doc` to test documentation examples
- Aim for 80%+ code coverage on critical paths

## 🚨 Error Handling

### Result and Option Best Practices

```rust
// Create domain-specific error types
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PaymentError {
    #[error("Insufficient funds: required {required}, available {available}")]
    InsufficientFunds { required: Decimal, available: Decimal },
    
    #[error("Payment gateway error: {0}")]
    GatewayError(String),
    
    #[error("Invalid payment amount: {0}")]
    InvalidAmount(Decimal),
    
    #[error("Database error")]
    DatabaseError(#[from] sqlx::Error),
}

// Use Result for fallible operations
pub fn process_payment(
    account: &Account,
    amount: Decimal,
) -> Result<PaymentResult, PaymentError> {
    if account.balance < amount {
        return Err(PaymentError::InsufficientFunds {
            required: amount,
            available: account.balance,
        });
    }
    
    // Process payment...
    Ok(PaymentResult::success())
}

// Use the ? operator for error propagation
pub async fn handle_payment_request(
    request: PaymentRequest,
) -> Result<PaymentResponse, PaymentError> {
    let account = get_account(&request.account_id).await?;
    let result = process_payment(&account, request.amount)?;
    save_payment_record(&result).await?;
    
    Ok(PaymentResponse::from(result))
}

// Use Option for values that might be absent
pub fn find_user_by_email(email: &str) -> Option<User> {
    // Search implementation...
}

// Combine Option and Result appropriately
pub fn get_user_balance(user_id: UserId) -> Result<Option<Decimal>, DatabaseError> {
    let user = find_user(user_id)?; // Result from database
    Ok(user.map(|u| u.balance)) // Option if user exists
}
```

### Logging Strategy

```rust
use tracing::{info, warn, error, debug, instrument};

#[instrument(skip(database))]
pub async fn create_user(
    database: &Database,
    request: CreateUserRequest,
) -> Result<User, UserError> {
    debug!("Creating user with email: {}", request.email);
    
    let user = User::new(request.name, request.email)
        .map_err(|e| {
            warn!("Invalid user data: {}", e);
            UserError::ValidationFailed(e)
        })?;
    
    match database.save_user(&user).await {
        Ok(saved_user) => {
            info!(user_id = %saved_user.id, "User created successfully");
            Ok(saved_user)
        }
        Err(e) => {
            error!("Failed to save user: {}", e);
            Err(UserError::DatabaseError(e))
        }
    }
}
```

## 🔧 Configuration Management

### Environment Variables and Settings

```rust
use serde::{Deserialize, Serialize};
use config::{Config, ConfigError, Environment, File};

#[derive(Debug, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub timeout_seconds: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Settings {
    pub app_name: String,
    pub debug: bool,
    pub port: u16,
    pub database: DatabaseConfig,
    pub redis_url: String,
    pub api_key: String,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let mut config = Config::builder()
            // Start with default values
            .set_default("app_name", "MyApp")?
            .set_default("debug", false)?
            .set_default("port", 8080)?
            // Add settings from config file
            .add_source(File::with_name("config/default"))
            .add_source(
                File::with_name(&format!("config/{}", get_environment()))
                    .required(false)
            )
            // Override with environment variables
            .add_source(Environment::with_prefix("APP").separator("__"))
            .build()?;
            
        config.try_deserialize()
    }
}

fn get_environment() -> String {
    std::env::var("APP_ENVIRONMENT").unwrap_or_else(|_| "development".into())
}

// Usage with lazy_static or once_cell
use once_cell::sync::Lazy;

pub static SETTINGS: Lazy<Settings> = Lazy::new(|| {
    Settings::new().expect("Failed to load configuration")
});
```

## 🏗️ Data Models and Validation

### Example with Serde and Validation

```rust
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};
use rust_decimal::Decimal;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct ProductBase {
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    
    pub description: Option<String>,
    
    #[validate(custom = "validate_price")]
    pub price: Decimal,
    
    #[validate(length(min = 1))]
    pub category: String,
    
    pub tags: Vec<String>,
}

fn validate_price(price: &Decimal) -> Result<(), ValidationError> {
    if *price <= Decimal::ZERO {
        return Err(ValidationError::new("price_positive"));
    }
    if *price > Decimal::new(1_000_000, 2) {
        return Err(ValidationError::new("price_too_large"));
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct ProductCreate {
    #[serde(flatten)]
    #[validate]
    pub base: ProductBase,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct ProductUpdate {
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
    
    pub description: Option<String>,
    
    #[validate(custom = "validate_optional_price")]
    pub price: Option<Decimal>,
    
    #[validate(length(min = 1))]
    pub category: Option<String>,
    
    pub tags: Option<Vec<String>>,
}

fn validate_optional_price(price: &Option<Decimal>) -> Result<(), ValidationError> {
    if let Some(p) = price {
        validate_price(p)?;
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Product {
    pub id: Uuid,
    
    #[serde(flatten)]
    pub base: ProductBase,
    
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

impl Product {
    pub fn new(create_data: ProductCreate) -> Result<Self, ValidationError> {
        create_data.validate()?;
        
        Ok(Self {
            id: Uuid::new_v4(),
            base: create_data.base,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_active: true,
        })
    }
    
    pub fn update(&mut self, update_data: ProductUpdate) -> Result<(), ValidationError> {
        update_data.validate()?;
        
        if let Some(name) = update_data.name {
            self.base.name = name;
        }
        if let Some(description) = update_data.description {
            self.base.description = Some(description);
        }
        if let Some(price) = update_data.price {
            self.base.price = price;
        }
        if let Some(category) = update_data.category {
            self.base.category = category;
        }
        if let Some(tags) = update_data.tags {
            self.base.tags = tags;
        }
        
        self.updated_at = Utc::now();
        Ok(())
    }
}
```

## 🔄 Git Workflow

### Branch Strategy
- `main` - Production-ready code
- `develop` - Integration branch for features
- `feature/*` - New features
- `fix/*` - Bug fixes
- `docs/*` - Documentation updates
- `refactor/*` - Code refactoring
- `test/*` - Test additions or fixes

### Commit Message Format
Never include "claude code" or "written by claude code" in commit messages.

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Example:
```
feat(auth): add two-factor authentication

Implement TOTP generation and validation using the `totp-rs` crate
Add QR code generation for authenticator apps using `qrcode` crate
Update User struct with 2FA fields
Add comprehensive tests for 2FA flow

Closes #123
```

## 🗄️ Database Integration

### SQLx Best Practices

```rust
use sqlx::{PgPool, Row};
use uuid::Uuid;
use chrono::{DateTime, Utc};

// Use compile-time checked queries
pub async fn get_user_by_id(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<User>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT id, name, email, created_at FROM users WHERE id = $1",
        user_id
    )
    .fetch_optional(pool)
    .await?;
    
    match row {
        Some(r) => Ok(Some(User {
            id: r.id,
            name: r.name,
            email: r.email,
            created_at: r.created_at,
        })),
        None => Ok(None),
    }
}

// Use transactions for complex operations
pub async fn create_user_with_profile(
    pool: &PgPool,
    user_data: CreateUserRequest,
    profile_data: CreateProfileRequest,
) -> Result<User, AppError> {
    let mut tx = pool.begin().await?;
    
    let user = sqlx::query_as!(
        User,
        "INSERT INTO users (name, email) VALUES ($1, $2) RETURNING *",
        user_data.name,
        user_data.email
    )
    .fetch_one(&mut *tx)
    .await?;
    
    sqlx::query!(
        "INSERT INTO profiles (user_id, bio, avatar_url) VALUES ($1, $2, $3)",
        user.id,
        profile_data.bio,
        profile_data.avatar_url
    )
    .execute(&mut *tx)
    .await?;
    
    tx.commit().await?;
    Ok(user)
}
```

### Database Migrations

```sql
-- migrations/001_initial.up.sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR NOT NULL,
    email VARCHAR UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- migrations/001_initial.down.sql
DROP TABLE users;
```

## 📝 Documentation Standards

### Code Documentation
- Every public module should have module-level documentation
- Public functions, structs, and traits must have complete documentation
- Complex logic should have inline comments
- Keep `README.md` updated with setup instructions and examples
- Maintain `CHANGELOG.md` for version history

### API Documentation with Axum

```rust
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use utoipa::{OpenApi, ToSchema};

#[derive(OpenApi)]
#[openapi(
    paths(
        list_products,
        get_product,
        create_product,
    ),
    components(
        schemas(Product, ProductCreate, ProductListQuery)
    ),
    tags(
        (name = "products", description = "Product management API")
    )
)]
pub struct ApiDoc;

/// List all products with optional filtering
#[utoipa::path(
    get,
    path = "/products",
    params(ProductListQuery),
    responses(
        (status = 200, description = "List of products", body = Vec<Product>),
        (status = 400, description = "Invalid query parameters"),
    ),
    tag = "products"
)]
pub async fn list_products(
    Query(params): Query<ProductListQuery>,
    State(app_state): State<AppState>,
) -> Result<Json<Vec<Product>>, AppError> {
    let products = app_state
        .product_service
        .list_products(params)
        .await?;
    
    Ok(Json(products))
}
```

## 🚀 Performance Considerations

### Optimization Guidelines
- Profile before optimizing - use `cargo flamegraph` or `perf`
- Use `Arc<T>` for shared ownership, `Rc<T>` for single-threaded
- Prefer `&str` over `String` for function parameters when possible
- Use iterators and iterator chains for data processing
- Consider `rayon` for data parallelism
- Use `async`/`await` for I/O-bound operations
- Cache expensive computations with `memoize` or `cached`

### Example Optimization

```rust
use std::sync::Arc;
use tokio::sync::RwLock;
use memoize::memoize;
use rayon::prelude::*;

// Memoize expensive calculations
#[memoize]
fn expensive_calculation(n: u64) -> u64 {
    // Complex computation here
    (0..n).map(|i| i * i).sum()
}

// Use async streams for large datasets
use futures::stream::{Stream, StreamExt};

pub fn process_large_dataset() -> impl Stream<Item = ProcessedData> {
    futures::stream::iter(large_dataset_source())
        .map(|item| process_item(item))
        .buffer_unordered(10) // Process up to 10 items concurrently
}

// Parallel processing with rayon
pub fn parallel_computation(data: Vec<ComplexData>) -> Vec<Result> {
    data.par_iter()
        .map(|item| expensive_operation(item))
        .collect()
}

// Efficient string operations
pub fn build_report(items: &[Item]) -> String {
    let capacity = items.len() * 50; // Estimate capacity
    let mut report = String::with_capacity(capacity);
    
    for item in items {
        use std::fmt::Write;
        writeln!(report, "{}: {}", item.name, item.value).unwrap();
    }
    
    report
}
```

## 🛡️ Security Best Practices

### Security Guidelines
- Never commit secrets - use environment variables
- Validate all user input with proper types and validation
- Use parameterized queries for database operations
- Implement rate limiting for APIs
- Keep dependencies updated with `cargo audit`
- Use HTTPS for all external communications
- Implement proper authentication and authorization

### Example Security Implementation

```rust
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use secrecy::{Secret, SecretString};
use ring::rand::{SecureRandom, SystemRandom};

pub struct PasswordManager {
    argon2: Argon2<'static>,
}

impl PasswordManager {
    pub fn new() -> Self {
        Self {
            argon2: Argon2::default(),
        }
    }
    
    pub fn hash_password(&self, password: SecretString) -> Result<String, PasswordError> {
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = self.argon2
            .hash_password(password.expose_secret().as_bytes(), &salt)?
            .to_string();
            
        Ok(password_hash)
    }
    
    pub fn verify_password(
        &self,
        password: SecretString,
        hash: &str,
    ) -> Result<bool, PasswordError> {
        let parsed_hash = PasswordHash::new(hash)?;
        Ok(self.argon2
            .verify_password(password.expose_secret().as_bytes(), &parsed_hash)
            .is_ok())
    }
}

pub fn generate_secure_token(length: usize) -> Result<String, TokenError> {
    let mut token_bytes = vec![0u8; length];
    let rng = SystemRandom::new();
    rng.fill(&mut token_bytes)
        .map_err(|_| TokenError::GenerationFailed)?;
    
    Ok(base64::encode_config(token_bytes, base64::URL_SAFE_NO_PAD))
}

// Rate limiting with governor
use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;

pub fn create_rate_limiter() -> RateLimiter<String, governor::state::InMemoryState, governor::clock::DefaultClock> {
    RateLimiter::keyed(
        Quota::per_second(NonZeroU32::new(10).unwrap())
    )
}
```

## 🔍 Debugging Tools

### Debugging Commands

```bash
# Debug build with symbols
cargo build

# Debug with GDB
rust-gdb target/debug/my_program

# Debug with LLDB
rust-lldb target/debug/my_program

# Memory debugging with Valgrind (Linux)
cargo install cargo-valgrind
cargo valgrind run

# Performance profiling
cargo install flamegraph
cargo flamegraph --bin my_program

# Heap profiling
cargo install cargo-profdata
cargo profdata -- --bin my_program

# Address sanitizer
RUSTFLAGS="-Z sanitizer=address" cargo run --target x86_64-unknown-linux-gnu

# Thread sanitizer
RUSTFLAGS="-Z sanitizer=thread" cargo run --target x86_64-unknown-linux-gnu
```

### Debug Logging

```rust
use tracing::{debug, info, warn, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub fn init_tracing() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into())
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();
}

// Use structured logging
#[tracing::instrument]
pub async fn process_user_request(user_id: Uuid, request: UserRequest) {
    debug!(user_id = %user_id, "Processing user request");
    
    match validate_request(&request) {
        Ok(_) => info!("Request validation successful"),
        Err(e) => {
            warn!(error = %e, "Request validation failed");
            return;
        }
    }
    
    // Process request...
}
```

## 📊 Monitoring and Observability

### Metrics and Tracing

```rust
use metrics::{counter, histogram, gauge};
use tracing::{instrument, Span};

#[instrument(skip(database))]
pub async fn handle_request(request: Request, database: &Database) -> Result<Response, AppError> {
    let _timer = histogram!("request_duration_seconds").start_timer();
    counter!("requests_total", 1, "method" => request.method.to_string());
    
    let span = Span::current();
    span.record("user_id", &request.user_id.to_string());
    
    match process_request(request, database).await {
        Ok(response) => {
            counter!("requests_successful", 1);
            Ok(response)
        }
        Err(e) => {
            counter!("requests_failed", 1, "error_type" => e.error_type());
            error!(error = %e, "Request processing failed");
            Err(e)
        }
    }
}

// Health checks
pub async fn health_check(State(app_state): State<AppState>) -> Result<Json<HealthStatus>, StatusCode> {
    let db_healthy = app_state.database.ping().await.is_ok();
    let redis_healthy = app_state.redis.ping().await.is_ok();
    
    let status = HealthStatus {
        healthy: db_healthy && redis_healthy,
        database: db_healthy,
        redis: redis_healthy,
        timestamp: Utc::now(),
    };
    
    gauge!("health_status", if status.healthy { 1.0 } else { 0.0 });
    
    if status.healthy {
        Ok(Json(status))
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}
```

## 📚 Useful Resources

### Essential Tools
- [Cargo Book](https://doc.rust-lang.org/cargo/)
- [Rustfmt](https://github.com/rust-lang/rustfmt)
- [Clippy](https://github.com/rust-lang/rust-clippy)
- [Rust Analyzer](https://rust-analyzer.github.io/)

### Key Crates
- **Web**: `axum`, `warp`, `actix-web`
- **Async**: `tokio`, `async-std`
- **Serialization**: `serde`
- **Database**: `sqlx`, `diesel`
- **HTTP Client**: `reqwest`
- **Logging**: `tracing`, `log`
- **Error Handling**: `thiserror`, `anyhow`
- **Configuration**: `config`, `figment`
- **Testing**: `proptest`, `criterion`
- **CLI**: `clap`

### Rust Best Practices
- [The Rust Programming Language Book](https://doc.rust-lang.org/book/)
- [Rust by Example](https://doc.rust-lang.org/rust-by-example/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [The Cargo Book](https://doc.rust-lang.org/cargo/)
- [Async Programming in Rust](https://rust-lang.github.io/async-book/)

## 📦 Crates.io Publishing Guidelines

### Package Metadata Requirements
For publishing to crates.io, ensure Cargo.toml includes:

```toml
[package]
name = "your-crate"
version = "0.1.0"
edition = "2021"
authors = ["Your Name <email@example.com>"]
description = "Clear, concise description (under 200 chars)"
documentation = "https://docs.rs/your-crate"
repository = "https://github.com/username/repo"
homepage = "https://github.com/username/repo"
license = "MIT OR Apache-2.0"
readme = "README.md"
keywords = ["max", "5", "keywords", "here", "relevant"]
categories = ["relevant", "categories"]

# Optional but recommended
exclude = [
    ".github/*",
    "tests/fixtures/*",
    "docs/*"
]

[badges]
maintenance = { status = "actively-developed" }
```

### Documentation Standards for docs.rs
- Every public item MUST have documentation
- Include at least one working example in lib.rs docstring
- Use `#![warn(missing_docs)]` in lib.rs
- Test all examples with `cargo test --doc`

### README.md Requirements
```markdown
# Crate Name

[![Crates.io](https://img.shields.io/crates/v/your-crate.svg)](https://crates.io/crates/your-crate)
[![Documentation](https://docs.rs/your-crate/badge.svg)](https://docs.rs/your-crate)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

Brief description of what the crate does.

## Installation

```toml
[dependencies]
your-crate = "0.1"
```

## Quick Start

```rust
use your_crate::main_function;

fn main() {
    // Simple example here
}
```

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
```

### Iterative Development Workflow
This project follows an iterative development approach:

1. **Implement module by module** - Each module should be immediately testable
2. **User testing at each step** - After implementing each module:
   - User runs `cargo run` to test functionality
   - Verify output matches expected behavior
   - Fix any issues before proceeding
3. **Main.rs as test harness** - Use main.rs to test each component as it's built:
   ```rust
   fn main() {
       // Test current module functionality
       let result = current_module::test_function();
       println!("Result: {:?}", result);
   }
   ```
4. **Incremental validation** - Each step should produce working, testable code
5. **No gold-plating** - Implement only what's needed for the current step

### Pre-Publishing Checklist
```bash
# 1. Format and lint
cargo fmt
cargo clippy -- -D warnings

# 2. Test everything
cargo test
cargo test --doc
cargo doc --no-deps

# 3. Check package
cargo package --dry-run
cargo package --list

# 4. Security audit
cargo audit

# 5. Final validation
cargo publish --dry-run

# 6. Publish
cargo publish
```

### License Files
Create both LICENSE-MIT and LICENSE-APACHE files in the repository root.

## ⚠️ Important Notes

- **NEVER ASSUME OR GUESS** - When in doubt, ask for clarification
- Always verify crate versions and compatibility before use
- Keep `CLAUDE.md` updated when adding new patterns or dependencies
- Test your code - No feature is complete without tests
- Document your decisions - Future developers (including yourself) will thank you
- Use `cargo clippy` religiously - it catches many common mistakes
- Prefer compile-time errors over runtime errors
- Leverage Rust's type system to make invalid states unrepresentable
- **Follow iterative development** - Each step must be testable with `cargo run`