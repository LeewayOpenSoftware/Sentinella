//! Web protection: the sentinelld side of the `dnsguard` filtering DNS
//! proxy.
//!
//! # The invariant this module exists to keep
//!
//! An NRPT rule points the whole machine's DNS at our listener, lives in
//! the registry, and SURVIVES REBOOTS. So the dangerous state is not "the
//! proxy is broken" — it is "the rule is installed and the proxy is not
//! answering", which is a machine with no name resolution at all, across
//! every subsequent boot, for a user who cannot search for the fix because
//! search does not resolve.
//!
//! Therefore: **the rule may exist only while the daemon is PROVEN
//! healthy.** The daemon adds it after a passing self-test; a boot-time
//! reconciler, running out of process and independent of this service,
//! removes it whenever that precondition is not observably true. Under any
//! uncertainty the system degrades to "no filtering", never to "no DNS".
//!
//! # Two states that are not the same state
//!
//! - `config.web_protection.enabled` — USER INTENT. Persisted in TOML.
//! - `status.nrpt_installed` — A FACT ABOUT THE SYSTEM. Read from the
//!   registry, never inferred from intent.
//!
//! They come apart in normal operation: while the daemon starts, after a
//! failed self-test, after a crash, during an upgrade, during an MSI
//! rollback. Every surface that reports on web protection reports BOTH,
//! and nothing derives one from the other.
//!
//! # What is here
//!
//! The whole daemon side, including rule installation. `enabled = false`
//! by default; when enabled and healthy this DOES point the machine's DNS
//! at the local proxy.
//!
//! Two hard preconditions gate that, and both are in `rule.rs`: the
//! four-step self-test must pass, and the boot reconciler's scheduled task
//! must exist and be enabled. The second is why a development build
//! installs nothing — `cargo run` has no MSI, so no task, so no rule.
//!
//! Three mechanisms can take the rule away, and they cover different
//! failures: `stop()` on orderly shutdown, the watchdog while the daemon
//! runs but the proxy stops working, and the out-of-process boot
//! reconciler for everything else — crash, kill, disabled service,
//! quarantined binary, power loss.

pub mod config;
pub mod lists;
pub mod rule;
pub mod service;
pub mod status;
pub mod upstreams;

pub use config::WebProtectionConfig;
pub use service::{WebProtection, WebProtectionHandle, spawn_retry};
#[allow(unused_imports)] // re-exported for ipc::state::web_protection_status
pub use status::WebProtectionStatus;
