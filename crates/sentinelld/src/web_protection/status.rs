//! The status surface: what web protection actually IS right now, as
//! opposed to what the user asked for.

use serde::{Deserialize, Serialize};

/// Why the proxy is not serving, when it is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyState {
    /// `enabled = false`, or the config failed validation and was forced
    /// off. Nothing is running and nothing is meant to be.
    Disabled,
    /// Enabled, but the listener could not bind — most often because
    /// something else already owns `127.0.0.1:53`.
    BindFailed,
    /// Bound, but the four-step self-test did not pass. The proxy is NOT
    /// serving: we do not run a listener we could not prove works,
    /// because `rule::install` installs an NRPT rule on the strength of it.
    SelfTestFailed,
    /// Bound, self-tested, serving.
    Serving,
}

/// A point-in-time answer to "what is web protection doing?".
///
/// Reports INTENT and FACT as separate fields on purpose. A caller that
/// wants to know whether the machine's DNS is currently going through us
/// must read `nrpt_installed`; a caller that wants to know what the user
/// asked for reads `enabled`. Rendering only one of them is how a UI ends
/// up claiming protection that is not there.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebProtectionStatus {
    /// User intent, straight from config.
    pub enabled: bool,
    /// Whether an NRPT rule of ours is present on the system RIGHT NOW,
    /// discovered rather than inferred. `None` means we could not tell —
    /// which is NOT the same as `Some(false)` and must never be rendered
    /// as "not installed".
    pub nrpt_installed: Option<bool>,
    /// What the listener is doing.
    pub state: ProxyState,
    /// Address actually bound, when serving.
    pub listen: Option<String>,
    /// Upstreams currently in force (after discovery). Read LIVE from the
    /// proxy's upstream handle while serving: the refresher swaps the list
    /// on network change, and reporting the start-time copy showed the
    /// machine resolvers it had already abandoned.
    pub upstreams: Vec<String>,
    /// Healthy upstreams over total. While serving this is live too: the
    /// watchdog probes each upstream directly and `healthy` is
    /// `total - degraded`. When not serving it is the last self-test's
    /// count (which is all there is to know).
    pub upstreams_healthy: usize,
    pub upstreams_total: usize,
    /// Upstreams the watchdog's direct probes currently cannot reach.
    /// ADDITIVE (wave-1): older readers ignore it. Round-robin has no
    /// failover, so every entry here is a share of the machine's queries
    /// SERVFAILing — surfaced, never auto-removed from the active list.
    pub upstreams_degraded: Vec<String>,
    /// The watchdog fired: it judged the proxy unhealthy and removed (or
    /// tried to remove) the NRPT rule. ADDITIVE (wave-1). `state` stays
    /// `Serving` — the listener is still up, it is the machine's DNS that
    /// no longer goes through it — so this fact needs its own field.
    pub watchdog_fired: bool,
    /// Rules loaded into the filter engine.
    pub rules_loaded: u64,
    /// Human-readable detail. Empty only when serving with nothing to
    /// report; set on refusals, on degraded upstreams, and when the
    /// watchdog fired. Also carries the retry schedule while a refused
    /// start is being retried.
    pub detail: String,
    /// Counters, when serving.
    pub queries: u64,
    pub blocked: u64,
    pub cache_hits: u64,
    pub upstream_errors: u64,
}

impl WebProtectionStatus {
    /// The status of a daemon where web protection is off. `nrpt_installed`
    /// is `None` rather than `Some(false)`: with no rule GUID in hand there
    /// is nothing to query the registry FOR, and claiming "not installed"
    /// would be the kind of confident-but-false statement this project
    /// keeps getting bitten by. (A rule orphaned by a previous run is not
    /// this function's business — `service::reconcile_orphan_rule` handles
    /// it on every non-serving path.)
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            nrpt_installed: None,
            state: ProxyState::Disabled,
            listen: None,
            upstreams: Vec::new(),
            upstreams_healthy: 0,
            upstreams_total: 0,
            upstreams_degraded: Vec::new(),
            watchdog_fired: false,
            rules_loaded: 0,
            detail: String::new(),
            queries: 0,
            blocked: 0,
            cache_hits: 0,
            upstream_errors: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The status must survive the IPC round trip: it is returned as JSON
    /// and the GUI reads the two states separately. A rename here without
    /// a GUI change shows up as a silently missing field, so the shape is
    /// pinned.
    #[test]
    fn status_serializes_with_both_states_distinguishable() {
        let s = WebProtectionStatus::disabled();
        let v = serde_json::to_value(&s).expect("status must serialize");
        assert_eq!(v["enabled"], serde_json::json!(false));
        // null, NOT false — "we do not know" is a third value and the UI
        // must be able to tell it from "not installed".
        assert!(
            v["nrpt_installed"].is_null(),
            "unknown NRPT state must serialize as null, got {}",
            v["nrpt_installed"]
        );
        assert_eq!(v["state"], serde_json::json!("disabled"));
        for k in [
            "listen",
            "upstreams",
            "upstreams_healthy",
            "upstreams_total",
            "upstreams_degraded",
            "watchdog_fired",
            "rules_loaded",
            "detail",
            "queries",
            "blocked",
            "cache_hits",
            "upstream_errors",
        ] {
            assert!(v.get(k).is_some(), "status is missing field {k}");
        }
        // The additive wave-1 fields must be additive in SHAPE too: a
        // reader that predates them ignores them, a reader that expects
        // them gets these types.
        assert_eq!(v["watchdog_fired"], serde_json::json!(false));
        assert_eq!(v["upstreams_degraded"], serde_json::json!([]));
    }

    #[test]
    fn disabled_status_does_not_claim_to_know_about_nrpt() {
        let s = WebProtectionStatus::disabled();
        assert!(!s.enabled);
        assert_eq!(s.state, ProxyState::Disabled);
        assert_eq!(
            s.nrpt_installed, None,
            "unknown must not be reported as not-installed"
        );
    }
}
