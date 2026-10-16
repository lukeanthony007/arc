//! Experimental encrypted snapshot storage. Not a frozen or audited protocol.

#[cfg(not(target_os = "linux"))]
compile_error!("arc-exp-1 currently requires Linux filesystem semantics");

pub mod app;
pub mod bundle;
pub mod crypto;
pub mod format;
pub mod store;
