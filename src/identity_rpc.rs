//! Private gRPC identity control plane.
//!
//! Domain users are converted to `IdentityRecord` before they cross this
//! boundary. That safe view deliberately omits stored WebAuthn credentials,
//! counters, session versions, and every other authentication secret.

mod errors;
mod projection;
mod service;
mod source;
mod validation;

pub(crate) use self::service::IdentityRpc;
