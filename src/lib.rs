//! RustyAuth authentication service library.
//!
//! The `rustyauth` binary composes these modules into a running process, and
//! the integration tests exercise the same surface. Protocol handlers live in
//! `auth`; durable state belongs to `store`; key material and token issuance
//! belong to `jwt`.

pub mod app_state;
pub mod auth;
pub mod backup;
pub mod cli;
pub mod config;
pub mod event_rpc;
pub mod identity_rpc;
pub mod jwt;
pub mod operator_auth;
pub mod organization_rpc;
pub mod rate_limit;
pub mod rpc;
pub mod service_account_rpc;
pub mod store;
#[cfg(test)]
mod webauthn_soft;

pub mod proto {
    connectrpc::include_generated!();
}
