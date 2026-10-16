//! Experimental encrypted snapshot storage. Not a frozen or audited protocol.

#[cfg(not(target_os = "linux"))]
compile_error!("arc-exp-1 currently requires Linux filesystem semantics");

pub mod app;
pub mod bluetooth;
pub mod bundle;
pub mod constrained;
pub mod crypto;
pub mod devices;
pub mod diagnostics;
pub mod enrollment;
pub mod format;
pub mod fragments;
pub mod history;
pub(crate) mod membership;
pub mod network;
pub mod policy;
pub mod recovery;
pub mod store;
