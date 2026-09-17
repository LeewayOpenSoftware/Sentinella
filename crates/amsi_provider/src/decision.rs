//! AMSI verdict mapping and the fail-open policy, in one testable place.
//!
//! Deliberately free of Windows types: the whole point is that the policy
//! "anything that is not a positive block returns NOT_DETECTED" can be
//! asserted by ordinary unit tests on any platform. `com` converts the
//! resulting [`ProviderDecision`] into a real `AMSI_RESULT`.

/// AMSI_RESULT_DETECTED — tell AMSI to block execution.
pub const AMSI_RESULT_DETECTED_I32: i32 = 32768;
/// AMSI_RESULT_NOT_DETECTED — allow. Also our fail-open value.
pub const AMSI_RESULT_NOT_DETECTED_I32: i32 = 1;

/// The only two outcomes the provider ever returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderDecision {
    /// Malicious: block.
    Detected,
    /// Clean, unknown, OR any failure — allow (fail open).
    NotDetected,
}

impl ProviderDecision {
    /// The raw `AMSI_RESULT` value this maps to.
    pub fn amsi_result_i32(self) -> i32 {
        match self {
            ProviderDecision::Detected => AMSI_RESULT_DETECTED_I32,
            ProviderDecision::NotDetected => AMSI_RESULT_NOT_DETECTED_I32,
        }
    }
}

/// A verdict as returned by the daemon's `runtime.scan_buffer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaemonVerdict {
    pub score: u32,
    pub should_block: bool,
}

/// Map a *successful* daemon verdict. Only an explicit block blocks.
pub fn decision_from_verdict(v: DaemonVerdict) -> ProviderDecision {
    if v.should_block {
        ProviderDecision::Detected
    } else {
        ProviderDecision::NotDetected
    }
}

/// Map the full IPC outcome, failure included. `None` means the daemon did
/// not return a usable verdict in time (timeout, not running, unreachable,
/// malformed reply, or a panic that was caught) — the fail-open path.
pub fn decision_from_outcome(outcome: Option<DaemonVerdict>) -> ProviderDecision {
    match outcome {
        Some(v) => decision_from_verdict(v),
        None => ProviderDecision::NotDetected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_verdict_detects() {
        let d = decision_from_verdict(DaemonVerdict { score: 95, should_block: true });
        assert_eq!(d, ProviderDecision::Detected);
        assert_eq!(d.amsi_result_i32(), AMSI_RESULT_DETECTED_I32);
    }

    #[test]
    fn clean_verdict_allows() {
        let d = decision_from_verdict(DaemonVerdict { score: 10, should_block: false });
        assert_eq!(d, ProviderDecision::NotDetected);
        assert_eq!(d.amsi_result_i32(), AMSI_RESULT_NOT_DETECTED_I32);
    }

    #[test]
    fn high_score_without_block_flag_still_allows() {
        // The daemon owns the block threshold; the provider never
        // second-guesses it by blocking on score alone.
        let d = decision_from_verdict(DaemonVerdict { score: 79, should_block: false });
        assert_eq!(d, ProviderDecision::NotDetected);
    }

    #[test]
    fn no_verdict_fails_open() {
        // Timeout / daemon down / unreachable / parse error / caught panic.
        assert_eq!(decision_from_outcome(None), ProviderDecision::NotDetected);
        assert_eq!(
            decision_from_outcome(None).amsi_result_i32(),
            AMSI_RESULT_NOT_DETECTED_I32
        );
    }

    #[test]
    fn present_block_outcome_detects() {
        let d = decision_from_outcome(Some(DaemonVerdict { score: 88, should_block: true }));
        assert_eq!(d, ProviderDecision::Detected);
    }
}
