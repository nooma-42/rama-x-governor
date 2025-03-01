# rama-x-governor

This is a community contributed Rate limiting for `rama` applications using the [governor](https://docs.rs/governor/latest/governor/) crate.

This crate provides a `GovernorPolicy` that can be used with Rama's `LimitLayer` for rate limiting HTTP requests or any other kind of request.

## Features

- Type-safe builder pattern that ensures valid configuration at compile time
- Efficient rate limiting with configurable requests per second/minute
- Support for burst allowances
- Automatic garbage collection of stale rate limit entries
- Support for keyed rate limiting (e.g., by IP address)
- Seamless integration with Rama's `LimitLayer`

## Usage

```rust
use std::time::Duration;
use rama::layer::limit::LimitLayer;
use rama_x_governor::GovernorPolicy;

// Create a rate limiter that allows 2 requests per second with burst of 5
let governor = GovernorPolicy::builder()
    .per_second(2)  // This transitions the builder to the Initialized state
    .burst_size(5)  // Only available after quota is set
    .gc_interval(Duration::from_secs(60))
    .build();

// Apply the rate limiter to your service
let service = LimitLayer::new(governor).layer(your_service);
```

### IP-based Rate Limiting

```rust
use std::net::IpAddr;
use rama_x_governor::GovernorPolicy;

// Create an IP-based rate limiter
let governor = GovernorPolicy::builder()
    .per_second(1)
    .burst_size(2)
    .gc_interval(Duration::from_secs(60))
    .build_with_keyer(|req: &str| {
        // In a real application, extract the IP from the request
        "127.0.0.1".parse::<IpAddr>().unwrap()
    });
```

## Examples

Check out the examples directory for complete working examples:

- `http_rate_limit.rs` - Basic HTTP rate limiting
- `ip_rate_limit.rs` - IP-based rate limiting

## Attribution

This project is inspired by the work of the [tower-governor](https://github.com/benwis/tower-governor).

## About Rama

🦙 Rama (ラマ) is a modular service framework for the 🦀 Rust language to move and transform your network packets.

The reasons behind the creation of rama can be read in [the "Why Rama" chapter](https://ramaproxy.org/book/why_rama).

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
