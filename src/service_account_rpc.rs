//! Scoped non-human principals and one-time service credentials.
//!
//! The facade only wires the submodules together: dependency seams live in
//! `ports`, the Connect handlers in `handlers`, and request validation,
//! pagination, proto projection and error mapping beside them.

mod errors;
mod handlers;
mod pagination;
mod ports;
pub(crate) mod projection;
mod validation;

pub(crate) use self::handlers::ServiceAccountRpc;
