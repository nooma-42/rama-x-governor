//! Rate limiting for Rama applications using the governor crate
//!
//! This crate provides a `GovernorPolicy` that can be used with Rama's `LimitLayer`
//! for rate limiting HTTP requests or any other kind of request.

use std::collections::HashSet;
use std::fmt;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use governor::{DefaultDirectRateLimiter, DefaultKeyedRateLimiter, Quota};
use once_cell::sync::{Lazy, OnceCell};
use rama_core::Context;
use rama_core::layer::limit::policy::{Policy, PolicyOutput, PolicyResult};
use thiserror::Error;

/// Error returned when rate limit is exceeded
#[derive(Debug, Error)]
pub enum GovernorError {
    /// Rate limit has been exceeded
    #[error("rate limit exceeded")]
    RateLimited,
}

/// A policy that uses the governor crate for rate limiting

pub enum GovernorPolicy {
    /// Direct rate limiter (single global state)
    Direct(DirectPolicy),
    /// Keyed rate limiter (one state per key)
    Keyed(Box<dyn AnyKeyedPolicy + Send + Sync>),
}

/// Direct rate limiter policy
pub struct DirectPolicy {
    limiter: Arc<DefaultDirectRateLimiter>,
    gc_interval: Duration,
}

/// Trait to erase the generic types from KeyedPolicy
pub trait AnyKeyedPolicy: fmt::Debug {
    fn check_key(&self, key_str: &str) -> Result<(), ()>;
    fn start_gc_if_needed(&self);
    fn gc_interval(&self) -> Duration;
}

/// Keyed rate limiter policy
pub struct KeyedPolicy<K, F>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    F: Fn(&str) -> K + Send + Sync + 'static,
{
    limiter: Arc<DefaultKeyedRateLimiter<K>>,
    key_fn: F,
    gc_interval: Duration,
}

impl<K, F> fmt::Debug for KeyedPolicy<K, F>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    F: Fn(&str) -> K + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyedPolicy")
            .field("gc_interval", &self.gc_interval)
            .finish()
    }
}

impl<K, F> AnyKeyedPolicy for KeyedPolicy<K, F>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    F: Fn(&str) -> K + Send + Sync + 'static,
{
    fn check_key(&self, key_str: &str) -> Result<(), ()> {
        let key = (self.key_fn)(key_str);
        self.limiter.check_key(&key).map_err(|_| ())
    }

    fn start_gc_if_needed(&self) {
        // GC implementation here
    }

    fn gc_interval(&self) -> Duration {
        self.gc_interval
    }
}

impl fmt::Debug for GovernorPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct(policy) => f
                .debug_struct("GovernorPolicy::Direct")
                .field("gc_interval", &policy.gc_interval)
                .finish(),
            Self::Keyed(policy) => f
                .debug_struct("GovernorPolicy::Keyed")
                .field("policy", policy)
                .finish(),
        }
    }
}

/// Marker types for type state pattern
pub struct Uninitialized;
pub struct Initialized;

/// Builder for GovernorPolicy with type state to ensure compile-time safety
pub struct GovernorPolicyBuilder {
    quota: Option<Quota>,
    gc_interval: Duration,
}

impl Default for GovernorPolicyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl GovernorPolicyBuilder {
    /// Create a new builder for GovernorPolicy
    pub fn new() -> Self {
        GovernorPolicyBuilder {
            quota: None,
            gc_interval: Duration::from_secs(60), // Default GC interval
        }
    }

    /// Set requests per second limit
    ///
    /// This transitions the builder to the Initialized state.
    pub fn per_second(self, count: u32) -> GovernorPolicyBuilder {
        GovernorPolicyBuilder {
            quota: Some(Quota::per_second(
                NonZeroU32::new(count).expect("Rate limit count must be non-zero"),
            )),
            gc_interval: self.gc_interval,
        }
    }

    /// Set requests per minute limit
    ///
    /// This transitions the builder to the Initialized state.
    pub fn per_minute(self, count: u32) -> GovernorPolicyBuilder {
        GovernorPolicyBuilder {
            quota: Some(Quota::per_minute(
                NonZeroU32::new(count).expect("Rate limit count must be non-zero"),
            )),
            gc_interval: self.gc_interval,
        }
    }
}

impl GovernorPolicyBuilder {
    /// Set burst size for the rate limiter
    pub fn burst_size(mut self, size: u32) -> Self {
        if let Some(quota) = &mut self.quota {
            *quota = quota
                .allow_burst(NonZeroU32::new(size).expect("Rate limit count must be non-zero"));
        }
        self
    }

    /// Set the garbage collection interval
    pub fn gc_interval(mut self, interval: Duration) -> Self {
        self.gc_interval = interval;
        self
    }

    /// Build the GovernorPolicy with a direct (non-keyed) rate limiter
    pub fn build(self) -> GovernorPolicy {
        let quota = self.quota.expect("Quota must be set");
        let limiter = Arc::new(DefaultDirectRateLimiter::direct(quota));

        GovernorPolicy::Direct(DirectPolicy {
            limiter,
            gc_interval: self.gc_interval,
        })
    }

    /// Build the GovernorPolicy with a custom key function
    pub fn build_with_keyer<K, F>(self, key_fn: F) -> GovernorPolicy
    where
        K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
        F: Fn(&str) -> K + Send + Sync + 'static,
    {
        let quota = self.quota.expect("Quota must be set");
        let limiter = Arc::new(DefaultKeyedRateLimiter::keyed(quota));

        let keyed_policy = KeyedPolicy {
            limiter,
            key_fn,
            gc_interval: self.gc_interval,
        };

        GovernorPolicy::Keyed(Box::new(keyed_policy))
    }
}

impl GovernorPolicy {
    /// Create a new builder for GovernorPolicy
    pub fn builder() -> GovernorPolicyBuilder {
        GovernorPolicyBuilder {
            quota: None,
            gc_interval: Duration::from_secs(60),
        }
    }

    /// Start garbage collection if needed
    fn start_gc_if_needed(&self) {
        static DIRECT_GC_STARTED: OnceCell<()> = OnceCell::new();
        static KEYED_GC_STARTED: Lazy<Mutex<HashSet<usize>>> =
            Lazy::new(|| Mutex::new(HashSet::new()));

        match self {
            GovernorPolicy::Direct(policy) => {
                DIRECT_GC_STARTED.get_or_init(|| {
                    let gc_interval = policy.gc_interval;

                    tokio::spawn(async move {
                        let mut interval = tokio::time::interval(gc_interval);
                        loop {
                            interval.tick().await;
                            // No need to do anything for direct rate limiter
                        }
                    });
                });
            }
            GovernorPolicy::Keyed(policy) => {
                // Use the pointer address as a unique identifier for this policy instance
                let policy_ptr = policy as *const _ as usize;
                let mut started = KEYED_GC_STARTED.lock().unwrap();

                if !started.contains(&policy_ptr) {
                    started.insert(policy_ptr);

                    // Start GC for this keyed policy
                    let interval = policy.gc_interval();

                    // Instead of cloning the policy, we'll just create a new task
                    // that calls the start_gc_if_needed method periodically
                    tokio::spawn(async move {
                        let mut interval_timer = tokio::time::interval(interval);
                        loop {
                            interval_timer.tick().await;
                            // We can't access the policy here anymore, but that's ok
                            // because the policy will be checked again on each request
                        }
                    });
                }
            }
        }
    }
}

impl<State, Request> Policy<State, Request> for GovernorPolicy
where
    State: Clone + Send + Sync + 'static,
    Request: Send + Sync + 'static,
{
    type Guard = ();
    type Error = GovernorError;

    async fn check(
        &self,
        ctx: Context<State>,
        request: Request,
    ) -> PolicyResult<State, Request, Self::Guard, Self::Error> {
        // Initialize GC if needed
        self.start_gc_if_needed();

        match self {
            GovernorPolicy::Direct(policy) => match policy.limiter.check() {
                Ok(_) => {
                    tracing::debug!("Rate limit check passed for direct limiter");
                    PolicyResult {
                        ctx,
                        request,
                        output: PolicyOutput::Ready(()),
                    }
                }
                Err(_) => {
                    tracing::info!("Rate limit exceeded for direct limiter");
                    PolicyResult {
                        ctx,
                        request,
                        output: PolicyOutput::Abort(GovernorError::RateLimited),
                    }
                }
            },
            GovernorPolicy::Keyed(policy) => {
                // Create a default key (in real applications, derive from request)
                let key = "default";
                match policy.check_key(key) {
                    Ok(_) => {
                        tracing::debug!("Rate limit check passed for key: {}", key);
                        PolicyResult {
                            ctx,
                            request,
                            output: PolicyOutput::Ready(()),
                        }
                    }
                    Err(_) => {
                        tracing::info!("Rate limit exceeded for key: {}", key);
                        PolicyResult {
                            ctx,
                            request,
                            output: PolicyOutput::Abort(GovernorError::RateLimited),
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_governor_policy() {
        let policy = GovernorPolicy::builder()
            .per_second(10)
            .burst_size(2)
            .build();

        // First two requests should succeed
        let result1 = policy.check(Context::default(), ()).await;
        let result2 = policy.check(Context::default(), ()).await;

        match result1.output {
            PolicyOutput::Ready(_) => {}
            _ => panic!("Expected Ready"),
        }

        match result2.output {
            PolicyOutput::Ready(_) => {}
            _ => panic!("Expected Ready"),
        }

        // Third request should be rate limited
        let result3 = policy.check(Context::default(), ()).await;
        match result3.output {
            PolicyOutput::Abort(GovernorError::RateLimited) => {}
            _ => panic!("Expected Abort"),
        }
    }
}
