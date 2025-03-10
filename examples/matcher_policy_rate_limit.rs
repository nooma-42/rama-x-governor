//! Matcher-Based Policy Map Rate Limiting Example
//!
//! This example demonstrates how to use Rama's Matcher system with GovernorPolicy
//! to create sophisticated rate limiting rules similar to the approach used in the
//! reference example.
//!
//! ```sh
//! cargo run --example matcher_policy_rate_limit --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start on http://127.0.0.1:3003 with endpoints that have different
//! rate limits based on various request characteristics:
//! - Local IPs get higher limits
//! - Specific paths get different limits
//! - Different HTTP methods get different limits

use std::{net::SocketAddr, sync::Arc, time::Duration};

use rama::{
    Context, Layer,
    error::BoxError,
    http::{IntoResponse, Request, Response, StatusCode, matcher::HttpMatcher, server::HttpServer},
    layer::limit::{LimitLayer, policy::LimitReached},
    net::stream::matcher::SocketMatcher,
    rt::Executor,
};
use rama_x_governor::GovernorPolicy;

use std::convert::Infallible;

use rama::{
    http::{HeaderName, HeaderValue, response::Json},
    layer::{MapResultLayer, TraceErrLayer},
    service::service_fn,
};
use serde_json::json;

async fn slow_endpoint(_: Context<()>) -> impl IntoResponse {
    // Simulate a slow endpoint
    tokio::time::sleep(Duration::from_secs(2)).await;
    "Slow response (2 second delay)"
}

#[tokio::main]
async fn main() {
    let exec = Executor::default();

    HttpServer::auto(exec)
        .listen(
            "0.0.0.0:62008",
            (
                MapResultLayer::new(|result: Result<Response, BoxError>| match result {
                    Ok(response) => Ok(response),
                    Err(box_error) => {
                        if box_error.downcast_ref::<LimitReached>().is_some() {
                            Ok((
                                [(
                                    HeaderName::from_static("x-proxy-error"),
                                    HeaderValue::from_static("rate-limit-reached"),
                                )],
                                StatusCode::TOO_MANY_REQUESTS,
                            )
                                .into_response())
                        } else {
                            Ok((
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(json!({
                                    "error": box_error.to_string(),
                                })),
                            )
                                .into_response())
                        }
                    }
                }),
                TraceErrLayer::new(),
                // using the [`Either`] combinator you can make tree-like structures,
                // to make as complex rate limiting logic as you wish.
                //
                // For more then 2 variants you can use [`Either3`], [`Either4`], and so on.
                // Keep it as simple as possible for your own sanity however...
                LimitLayer::new(Arc::new(vec![
                    // Local IPs get a higher limit (10 req/sec)
                    (
                        HttpMatcher::socket(SocketMatcher::loopback()),
                        Some(
                            GovernorPolicy::builder()
                                .per_second(10)
                                .burst_size(20)
                                .build(),
                        ),
                    ),
                    // External IPs get a lower limit (2 req/sec)
                    (
                        HttpMatcher::socket(SocketMatcher::loopback()).negate(),
                        Some(
                            GovernorPolicy::builder()
                                .per_second(2)
                                .burst_size(5)
                                .build(),
                        ),
                    ),
                    // Admin endpoints are unlimited
                    (HttpMatcher::path("/admin/*"), None),
                    // API endpoints get a medium limit (3 req/sec)
                    (
                        HttpMatcher::path("/api/*"),
                        Some(
                            GovernorPolicy::builder()
                                .per_second(3)
                                .burst_size(5)
                                .build(),
                        ),
                    ),
                    // Slow endpoints get a very strict limit (1 req/sec)
                    (
                        HttpMatcher::path("*/slow"),
                        Some(
                            GovernorPolicy::builder()
                                .per_second(1)
                                .burst_size(2)
                                .build(),
                        ),
                    ),
                ])),
            )
                .layer(service_fn(|req: Request| async move {
                    if req.uri().path().ends_with("/slow") {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    }
                    Ok::<_, Infallible>(
                        Json(json!({
                            "method": req.method().as_str(),
                            "path": req.uri().path(),
                        }))
                        .into_response(),
                    )
                })),
        )
        .await
        .unwrap();
}
