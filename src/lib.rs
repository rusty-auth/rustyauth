//! RustyAuth authentication service library.
//!
//! The `rustyauth` binary composes these modules into a running process, and
//! the integration tests exercise the same surface. Protocol handlers live in
//! `auth`; durable state belongs to `store`; key material and token issuance
//! belong to `jwt`.

pub mod analytics;
pub mod analytics_archive;
pub mod analytics_rpc;
pub mod analytics_store;
pub mod app_state;
pub mod auth;
pub mod backup;
pub mod cli;
pub mod config;
pub mod event_rpc;
pub mod fleet_rpc;
pub mod identity_rpc;
pub mod jwt;
pub mod management_rpc;
pub mod metrics_rpc;
pub mod operator_auth;
pub mod organization_rpc;
pub mod rate_limit;
pub mod rpc;
pub mod service_account_rpc;
pub mod store;
pub mod telemetry;
#[cfg(any(test, feature = "benchmark-tools"))]
pub mod webauthn_soft;
pub mod webhook;
mod webhook_rpc;

pub mod proto {
    connectrpc::include_generated!();
}
