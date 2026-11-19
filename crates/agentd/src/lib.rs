#![deny(unsafe_code)]
#![deny(missing_docs)]

//! Host-side pieces of the agent daemon shared with administrative tools.
//!
//! The daemon binary owns polling, configuration, and the worker loop. This
//! library exposes the handler registry, the durable module store, and the
//! capability-gated Wasm host so `adminctl` and tests can exercise the exact
//! same host the daemon uses.

pub mod artifacts;
pub mod handlers;
pub mod limits;
pub mod plugins;
pub mod production;
pub mod resilience;
