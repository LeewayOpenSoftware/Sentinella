//! ConvergenceLedger — single source of truth for post-ARGUS score shaping.
//!
//! All post-ARGUS score additions go through the ledger instead of ad-hoc
//! `.score = score.saturating_add(...)` calls scattered across scan paths.
//!
//! Flow:
//!   1. ARGUS produces base score + findings + explanation
//!   2. Post-ARGUS evidence (ADS, persistence, PLM, trust, drift, ecosystem)
//!      adds findings to the ledger via `add_evidence()`
//!   3. `finalize()` applies the post-ARGUS cap, recomputes verdict
//!   4. `patch_explanation()` synchronizes the structured explanation
//!
//! Safety:
//!   - Post-ARGUS cap only scales post-ARGUS findings (tracked by index).
//!   - ARGUS base findings are NEVER modified — forensic weights preserved.
//!   - Trust discount NEVER applied when ClamAV is positive.
//!
//! The ledger is per-file, created fresh for each scan, not shared state.

/// Maximum score contribution from post-ARGUS sources combined.
/// Prevents runaway amplification from stacking ADS + persistence + PLM + ecosystem.
const POST_ARGUS_CAP: u32 = 40;

/// A post-ARGUS evidence entry with its index into the findings vec.
struct PostAddition {
    /// Label for attribution display (e.g. "ADS", "Persistence", "PLM").
    source: &'static str,
    /// Original weight before any cap scaling.
    original_weight: u32,
    /// Index into `self.findings` where this finding lives.
    finding_index: usize,
}

/// Tracks all score adjustments after the base ARGUS analysis.
pub struct ConvergenceLedger {
    /// Base score from ARGUS (immutable after creation).
    pub base_score: u32,
    /// All findings (ARGUS base + post-ARGUS additions).
    pub findings: Vec<argus::Finding>,
    /// Post-ARGUS additions with finding indices for targeted scaling.
    post_additions: Vec<PostAddition>,
    /// Trust discount applied (negative adjustment).
    pub trust_discount: u32,
    /// Whether ClamAV detected this as infected (trust never suppresses).
    clamav_positive: bool,
    /// Guard: true after finalize() called. Prevents double-scaling.
    finalized: bool,
}

/// Per-finding sanity cap — no single post-ARGUS finding may contribute
/// more than this in raw weight. R4-CV5: prevents one rogue caller from
/// blowing out `raw_post` and bypassing the global cap via integer
/// overflow.
const MAX_SINGLE_POST_WEIGHT: u32 = POST_ARGUS_CAP;

/// Score values must fit 0..=100. R4-CV9: clamp ingest so a misbehaving
/// ARGUS engine version (e.g. one that emitted `score=999`) cannot poison
/// downstream verdict mapping.
const MAX_VALID_SCORE: u32 = 100;

impl ConvergenceLedger {
    /// Create a ledger from an ARGUS verdict.
    pub fn new(verdict: &argus::verdict::ArgusVerdict, clamav_positive: bool) -> Self {
        Self {
            // R4-CV9: clamp base_score to the documented 0..=100 range.
            base_score: verdict.score.min(MAX_VALID_SCORE),
            findings: verdict.findings.clone(),
            post_additions: Vec::new(),
            trust_discount: 0,
            clamav_positive,
            finalized: false,
        }
    }

    /// Add post-ARGUS evidence. The finding is appended; its index is tracked
    /// so that cap scaling targets ONLY post-ARGUS findings.
    ///
    /// Panics (debug) / no-ops (release) if called after `finalize()`.
    pub fn add_evidence(&mut self, source: &'static str, mut finding: argus::Finding) {
        debug_assert!(!self.finalized, "add_evidence() called after finalize()");
        if self.finalized {
            return;
        }

        // R4-CV5: clamp per-finding weight before tracking. A single
        // weight=u32::MAX entry would overflow raw_post (panic in debug,
        // wrap in release → cap silently bypassed and POST_ARGUS_CAP=40
        // could become 39 or 0).
        if finding.weight > MAX_SINGLE_POST_WEIGHT {
            tracing::warn!(
                source,
                weight = finding.weight,
                cap = MAX_SINGLE_POST_WEIGHT,
                "convergence: post-ARGUS finding weight exceeds per-finding cap — clamped"
            );
            finding.weight = MAX_SINGLE_POST_WEIGHT;
        }

        let weight = finding.weight;
        let idx = self.findings.len();
        self.findings.push(finding);
        self.post_additions.push(PostAddition {
            source,
            original_weight: weight,
            finding_index: idx,
        });
    }

    /// Apply trust discount (reduces score for familiar entities).
    /// NEVER applied when ClamAV is positive.
    /// No-ops if called after `finalize()`.
    ///
    /// R4-CV1: all production callers invoke this exactly once per ledger,
    /// so the merge policy below only matters if a future caller adds a
    /// second call. On a repeat call we keep the LARGEST discount seen.
    /// Note the direction of risk honestly: the discount SUBTRACTS from the
    /// final score (`before_trust.saturating_sub(self.trust_discount)`), so
    /// a larger discount is the MORE suppressive value — max() is sticky
    /// toward suppression, not away from it. It exists to make the merge
    /// deterministic (order-independent) and to keep the tested
    /// `apply_trust_discount(8) + apply_trust_discount(0)` sequence at
    /// discount=8, NOT as an integrity defence. Producers of `discount`
    /// must therefore remain trusted paths (trust-DB lookups), never
    /// attacker-influenced input — a bogus large discount would stick.
    pub fn apply_trust_discount(&mut self, discount: u32, finding: Option<argus::Finding>) {
        debug_assert!(
            !self.finalized,
            "apply_trust_discount() called after finalize()"
        );
        if self.finalized {
            return;
        }

        // R4-CV11: previously, when ClamAV was positive we still pushed the
        // trust finding into `findings` even though the discount itself was
        // rejected — producing UX where the verdict explanation listed a
        // "Trusted, no action" reason on a confirmed malware hit. Now we
        // drop the trust finding entirely when the discount is suppressed
        // so the explanation stays coherent.
        if self.clamav_positive {
            return;
        }
        if discount > 0 {
            // R4-CV8: clamp so attribution()'s `-(trust_discount as i32)`
            // cannot hit i32::MIN and panic on negation.
            let capped = discount.min(MAX_VALID_SCORE);
            self.trust_discount = self.trust_discount.max(capped);
        }
        if let Some(f) = finding {
            self.findings.push(f);
        }
    }

    /// Finalize: apply post-ARGUS cap, compute final score.
    ///
    /// Returns (final_score, verdict, explanation_text).
    ///
    /// IMPORTANT: only post-ARGUS findings (tracked by index) are scaled.
    /// ARGUS base findings are NEVER modified.
    pub fn finalize(&mut self) -> (u32, argus::verdict::Verdict, String) {
        // Idempotency guard: if already finalized, recompute score from
        // current (already-scaled) finding weights without re-scaling.
        if self.finalized {
            // R4-CV6: saturating accumulation. Plain `.sum()` panics in
            // debug if total exceeds u32::MAX, wraps in release.
            let post_sum: u32 = self
                .post_additions
                .iter()
                .filter_map(|a| self.findings.get(a.finding_index))
                .map(|f| f.weight)
                .fold(0u32, |acc, w| acc.saturating_add(w))
                .min(POST_ARGUS_CAP);
            let score = self
                .base_score
                .saturating_add(post_sum)
                .saturating_sub(self.trust_discount)
                .min(MAX_VALID_SCORE);
            let verdict = argus::verdict::Verdict::from_score(score);
            let explanation = self.build_explanation(score, &verdict);
            return (score, verdict, explanation);
        }
        self.finalized = true;

        // R4-CV6: saturating sum to prevent overflow panics if many
        // findings somehow slip past add_evidence's per-finding clamp.
        let raw_post: u32 = self
            .post_additions
            .iter()
            .map(|a| a.original_weight)
            .fold(0u32, |acc, w| acc.saturating_add(w));
        let capped_post = raw_post.min(POST_ARGUS_CAP);

        // R4-CV4: cap enforcement was previously *proportional scaling*
        // (each finding × ratio, round). With a flood of weight-1 findings
        // (ratio ≈ 0.4) every finding rounded to 0 → the entire post-ARGUS
        // signal was suppressed. An attacker could **dilute** a strong
        // weight-30 ADS finding by attaching dozens of weight-1 noise
        // findings, dragging the strong evidence down to 0 too.
        //
        // New strategy: priority-truncation. Sort post-additions DESCENDING
        // by original_weight, keep them at full weight until the cap is
        // hit, then truncate / zero the remainder. Preserves the strongest
        // evidence intact; weakest noise is what gets dropped.
        if raw_post > POST_ARGUS_CAP {
            // Sort indices by original weight DESC, then by source order for
            // determinism.
            let mut order: Vec<usize> = (0..self.post_additions.len()).collect();
            order.sort_by(|&a, &b| {
                self.post_additions[b]
                    .original_weight
                    .cmp(&self.post_additions[a].original_weight)
                    .then(a.cmp(&b))
            });

            let mut remaining = POST_ARGUS_CAP;
            for pos in &order {
                let add = &self.post_additions[*pos];
                let idx = add.finding_index;
                if let Some(f) = self.findings.get_mut(idx) {
                    if remaining == 0 {
                        f.weight = 0;
                    } else if f.weight <= remaining {
                        remaining -= f.weight;
                        // weight unchanged.
                    } else {
                        f.weight = remaining;
                        remaining = 0;
                    }
                }
            }

            let scaled_sum = POST_ARGUS_CAP - remaining;
            let actual_post = scaled_sum.min(POST_ARGUS_CAP);
            let before_trust = self.base_score.saturating_add(actual_post);
            let final_score = before_trust.saturating_sub(self.trust_discount).min(MAX_VALID_SCORE);
            let verdict = argus::verdict::Verdict::from_score(final_score);
            let explanation = self.build_explanation(final_score, &verdict);
            return (final_score, verdict, explanation);
        }

        // Final score = base + capped_post - trust_discount, clamped [0, 100].
        let before_trust = self.base_score.saturating_add(capped_post);
        let final_score = before_trust.saturating_sub(self.trust_discount).min(MAX_VALID_SCORE);

        let verdict = argus::verdict::Verdict::from_score(final_score);
        let explanation = self.build_explanation(final_score, &verdict);

        (final_score, verdict, explanation)
    }

    /// Build a coherent explanation from the final findings and score.
    fn build_explanation(&self, score: u32, verdict: &argus::verdict::Verdict) -> String {
        if self.findings.is_empty() {
            return format!("Score {score}/100 — no findings.");
        }

        let mut sorted: Vec<&argus::Finding> =
            self.findings.iter().filter(|f| f.weight > 0).collect();
        sorted.sort_by(|a, b| b.weight.cmp(&a.weight));

        let top: Vec<String> = sorted
            .iter()
            .take(5)
            .map(|f| format!("[{:?}] {} (+{})", f.layer, f.description, f.weight))
            .collect();

        let base_line = if self.trust_discount > 0 {
            format!(
                "Score {score}/100 ({verdict:?}) — base {}, trust -{}",
                self.base_score, self.trust_discount
            )
        } else {
            format!("Score {score}/100 ({verdict:?})")
        };

        if top.is_empty() {
            base_line
        } else {
            format!("{base_line}: {}", top.join("; "))
        }
    }

    /// Patch the structured VerdictExplanation to reflect the full converged state.
    ///
    /// Idempotent: safe to call multiple times. Replaces post-ARGUS entries
    /// rather than appending, using a marker prefix to identify ledger-sourced reasons.
    ///
    /// Synchronizes:
    ///   - raw_score, final_score
    ///   - suspicion_reasons (ARGUS originals preserved, ledger entries replaced)
    ///   - trust_reasons (ledger discount replaced)
    ///   - confidence_label
    pub fn patch_explanation(
        &self,
        explanation: &mut argus::verdict::VerdictExplanation,
        final_score: u32,
    ) {
        // R4-CV14: a single zero-width space is trivially smuggled inside
        // attacker-influenced strings (YARA rule descriptions, persistence
        // names, etc.) and would then be misidentified as a ledger entry
        // and wiped on the next patch_explanation call — letting an
        // attacker erase their own evidence trail from the verdict
        // display. Use a longer, structured sentinel that combines an
        // unlikely zero-width-joiner pair with an ASCII tag so any
        // collision requires the attacker to deliberately stage this
        // exact sequence (and even then we strip it on output).
        const LEDGER_PREFIX: &str = "\u{200B}\u{200D}LDG\u{200D}\u{200B}";

        // raw_score = base + uncapped post (total evidence weight before discount).
        // R4-CV7: saturating accumulation to prevent overflow.
        let raw_post: u32 = self
            .post_additions
            .iter()
            .map(|a| a.original_weight)
            .fold(0u32, |acc, w| acc.saturating_add(w));
        explanation.raw_score = self.base_score.saturating_add(raw_post);
        explanation.final_score = final_score;

        // Remove previous ledger-sourced reasons (idempotency).
        explanation
            .suspicion_reasons
            .retain(|r| !r.starts_with(LEDGER_PREFIX));
        explanation
            .trust_reasons
            .retain(|r| !r.starts_with(LEDGER_PREFIX));

        // Append post-ARGUS suspicion reasons with actual (post-scaling) weights.
        for addition in &self.post_additions {
            let actual_weight = self
                .findings
                .get(addition.finding_index)
                .map(|f| f.weight)
                .unwrap_or(0);
            if actual_weight > 0 {
                explanation.suspicion_reasons.push(format!(
                    "{LEDGER_PREFIX}{} +{}",
                    addition.source, actual_weight
                ));
            }
        }

        // Trust discount.
        if self.trust_discount > 0 {
            explanation.trust_reasons.push(format!(
                "{LEDGER_PREFIX}Trust graph familiar: -{}",
                self.trust_discount
            ));
        }

        // Recompute confidence label from final converged score.
        explanation.confidence_label = argus::verdict::ConfidenceLabel::from_context(
            final_score,
            explanation.signer.is_some(),
            explanation.recognized_software.is_some(),
            explanation.installer_discount_applied,
        );
    }

    /// Get convergence attribution for ecosystem storage.
    pub fn attribution(
        &self,
        final_score: u32,
        drift_esc: u32,
        eco_esc: u32,
        recurrence: u32,
    ) -> crate::ecosystem::ConvergenceAttribution {
        // R4-CV8: `-(u32 as i32)` panics in debug if the u32 sits above
        // i32::MAX (negation of i32::MIN). Convert via i64 then clamp so
        // the result always fits a signed 32-bit slot. Trust discount is
        // also already capped to MAX_VALID_SCORE in apply_trust_discount,
        // but defence in depth.
        let trust_adjustment: i32 = -((self.trust_discount.min(MAX_VALID_SCORE) as i64)
            .min(i32::MAX as i64) as i32);

        crate::ecosystem::ConvergenceAttribution {
            base_argus: self.base_score,
            trust_adjustment,
            drift_escalation: drift_esc,
            ecosystem_escalation: eco_esc,
            recurrence_bonus: recurrence,
            final_convergence: final_score,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus::Finding;
    use argus::verdict::{Layer, Severity, Verdict};

    fn make_verdict(score: u32, findings: Vec<Finding>) -> argus::verdict::ArgusVerdict {
        argus::verdict::ArgusVerdict {
            path: "test.exe".into(),
            file_size: 1000,
            sha256: "abc".into(),
            mime_type: None,
            score,
            verdict: Verdict::from_score(score),
            findings,
            analysis_time_us: 0,
            engine_version: "test",
            timestamp: 0,
            explanation: argus::verdict::VerdictExplanation::default(),
            timing: None,
        }
    }

    fn base_finding(layer: Layer, weight: u32) -> Finding {
        Finding {
            layer,
            severity: Severity::Medium,
            weight,
            description: format!("base finding w={weight}"),
            technical_detail: None,
        }
    }

    fn post_finding(layer: Layer, weight: u32, desc: &str) -> Finding {
        Finding {
            layer,
            severity: Severity::Medium,
            weight,
            description: desc.into(),
            technical_detail: None,
        }
    }

    #[test]
    fn base_findings_never_scaled() {
        // ARGUS base: Context finding with weight 12.
        let ctx = base_finding(Layer::Context, 12);
        let verdict = make_verdict(40, vec![ctx]);
        let mut ledger = ConvergenceLedger::new(&verdict, false);

        // Add post-ARGUS: 50 points total (exceeds POST_ARGUS_CAP=40).
        ledger.add_evidence(
            "ADS",
            post_finding(Layer::AlternateDataStream, 20, "ADS content"),
        );
        ledger.add_evidence(
            "Persistence",
            post_finding(Layer::Persistence, 15, "Run key"),
        );
        ledger.add_evidence("PLM", post_finding(Layer::Context, 15, "Lineage chain"));

        let (final_score, _, _) = ledger.finalize();

        // Base Context finding at index 0 must keep original weight=12.
        assert_eq!(
            ledger.findings[0].weight, 12,
            "base finding weight corrupted"
        );
        // Final score = 40 (base) + 40 (capped) - 0 (trust) = 80.
        assert_eq!(final_score, 80);
        // Post-ARGUS findings should be scaled down.
        let post_total: u32 = ledger.findings[1..].iter().map(|f| f.weight).sum();
        assert!(
            post_total <= POST_ARGUS_CAP,
            "post-ARGUS total {post_total} exceeds cap"
        );
    }

    #[test]
    fn post_argus_cap_applied() {
        let verdict = make_verdict(30, vec![]);
        let mut ledger = ConvergenceLedger::new(&verdict, false);

        ledger.add_evidence("A", post_finding(Layer::Persistence, 20, "a"));
        ledger.add_evidence("B", post_finding(Layer::Context, 20, "b"));
        ledger.add_evidence("C", post_finding(Layer::AlternateDataStream, 20, "c"));

        let (final_score, _, _) = ledger.finalize();
        // Raw 60 → capped. Score ≤ 30 + 40 = 70 (rounding may give slightly less).
        assert!(final_score <= 70, "score {final_score} exceeds 30+cap");
        assert!(
            final_score >= 65,
            "score {final_score} too low — cap not applied correctly"
        );
        // Post-ARGUS sum must respect cap.
        let post_sum: u32 = ledger.findings.iter().map(|f| f.weight).sum();
        assert!(
            post_sum <= POST_ARGUS_CAP,
            "post sum {post_sum} exceeds cap"
        );
    }

    #[test]
    fn trust_discount_applied() {
        let verdict = make_verdict(50, vec![]);
        let mut ledger = ConvergenceLedger::new(&verdict, false);
        ledger.apply_trust_discount(8, None);

        let (final_score, _, _) = ledger.finalize();
        assert_eq!(final_score, 42);
    }

    #[test]
    fn trust_discount_blocked_when_clamav_positive() {
        let verdict = make_verdict(50, vec![]);
        let mut ledger = ConvergenceLedger::new(&verdict, true);
        ledger.apply_trust_discount(8, None);

        let (final_score, _, _) = ledger.finalize();
        // Trust discount NOT applied — ClamAV positive.
        assert_eq!(final_score, 50);
    }

    #[test]
    fn no_post_argus_means_no_cap() {
        let verdict = make_verdict(60, vec![base_finding(Layer::StructuralAnalysis, 30)]);
        let mut ledger = ConvergenceLedger::new(&verdict, false);

        let (final_score, _, _) = ledger.finalize();
        assert_eq!(final_score, 60);
        // Base finding untouched.
        assert_eq!(ledger.findings[0].weight, 30);
    }

    #[test]
    fn patch_explanation_synchronizes_fields() {
        let verdict = make_verdict(40, vec![]);
        let mut ledger = ConvergenceLedger::new(&verdict, false);
        ledger.add_evidence(
            "Persistence",
            post_finding(Layer::Persistence, 10, "Run key"),
        );
        ledger.apply_trust_discount(5, None);

        let (final_score, _, _) = ledger.finalize();

        let mut explanation = argus::verdict::VerdictExplanation::default();
        ledger.patch_explanation(&mut explanation, final_score);

        assert_eq!(explanation.final_score, final_score);
        assert_eq!(explanation.raw_score, 50); // 40 base + 10 post.
        assert!(
            explanation
                .suspicion_reasons
                .iter()
                .any(|r| r.contains("Persistence")),
            "missing Persistence reason in {:?}",
            explanation.suspicion_reasons
        );
        assert!(
            explanation
                .trust_reasons
                .iter()
                .any(|r| r.contains("Trust graph")),
            "missing Trust graph reason in {:?}",
            explanation.trust_reasons
        );
    }

    #[test]
    fn score_clamped_at_100() {
        let verdict = make_verdict(90, vec![]);
        let mut ledger = ConvergenceLedger::new(&verdict, false);
        ledger.add_evidence("A", post_finding(Layer::Persistence, 30, "a"));

        let (final_score, _, _) = ledger.finalize();
        assert!(final_score <= 100);
    }

    // ── Stress tests ──────────────────────────────────────

    #[test]
    fn cap_exact_with_100_small_findings() {
        // 100 findings of weight 1 each = raw 100, cap 40.
        // Proportional: each → round(1 * 0.4) = round(0.4) = 0.
        // Sum after rounding = 0. Score = base only.
        // This is correct — many trivial findings shouldn't amplify.
        let verdict = make_verdict(30, vec![]);
        let mut ledger = ConvergenceLedger::new(&verdict, false);
        for i in 0..100 {
            ledger.add_evidence("flood", post_finding(Layer::Context, 1, &format!("f{i}")));
        }

        let (final_score, _, _) = ledger.finalize();
        // Post-ARGUS sum must NOT exceed cap.
        let post_sum: u32 = ledger.findings.iter().map(|f| f.weight).sum();
        assert!(
            post_sum <= POST_ARGUS_CAP + 30, // +30 for base
            "total {post_sum} exceeds base(30) + cap(40)"
        );
        assert!(final_score <= 70, "score {final_score} exceeds 30+40=70");
    }

    #[test]
    fn cap_exact_with_50_weight_1_findings() {
        // 50 × 1 = 50 raw, cap = 40, ratio = 0.8.
        // Each → round(0.8) = 1 → sum would be 50. Must trim to 40.
        let verdict = make_verdict(20, vec![]);
        let mut ledger = ConvergenceLedger::new(&verdict, false);
        for i in 0..50 {
            ledger.add_evidence("x", post_finding(Layer::Persistence, 1, &format!("p{i}")));
        }

        let (final_score, _, _) = ledger.finalize();
        let post_sum: u32 = ledger.findings.iter().map(|f| f.weight).sum();
        assert!(
            post_sum <= POST_ARGUS_CAP,
            "post-ARGUS sum {post_sum} exceeds cap {POST_ARGUS_CAP}"
        );
        assert!(final_score <= 60, "score {final_score} exceeds 20+40=60");
    }

    #[test]
    fn cap_exact_mixed_weights() {
        // Mixed: 10×3 + 5×2 + 20×1 = 30+10+20 = 60, cap=40.
        let verdict = make_verdict(10, vec![]);
        let mut ledger = ConvergenceLedger::new(&verdict, false);
        for i in 0..10 {
            ledger.add_evidence("A", post_finding(Layer::Context, 3, &format!("a{i}")));
        }
        for i in 0..5 {
            ledger.add_evidence("B", post_finding(Layer::Persistence, 2, &format!("b{i}")));
        }
        for i in 0..20 {
            ledger.add_evidence(
                "C",
                post_finding(Layer::AlternateDataStream, 1, &format!("c{i}")),
            );
        }

        let (final_score, _, _) = ledger.finalize();
        let post_sum: u32 = ledger.findings.iter().map(|f| f.weight).sum();
        assert!(
            post_sum <= POST_ARGUS_CAP,
            "post-ARGUS sum {post_sum} exceeds cap {POST_ARGUS_CAP}"
        );
        assert!(final_score <= 50, "score {final_score} exceeds 10+40=50");
    }

    #[test]
    fn cap_exact_under_cap_no_trim() {
        // 3 findings totalling 30 — under cap, no scaling should occur.
        let verdict = make_verdict(20, vec![]);
        let mut ledger = ConvergenceLedger::new(&verdict, false);
        ledger.add_evidence("A", post_finding(Layer::Persistence, 10, "a"));
        ledger.add_evidence("B", post_finding(Layer::Context, 10, "b"));
        ledger.add_evidence("C", post_finding(Layer::AlternateDataStream, 10, "c"));

        let (final_score, _, _) = ledger.finalize();
        // No cap hit — weights preserved exactly.
        assert_eq!(ledger.findings[0].weight, 10);
        assert_eq!(ledger.findings[1].weight, 10);
        assert_eq!(ledger.findings[2].weight, 10);
        assert_eq!(final_score, 50); // 20 + 30.
    }

    #[test]
    fn finalize_twice_same_result() {
        let verdict = make_verdict(30, vec![]);
        let mut ledger = ConvergenceLedger::new(&verdict, false);
        ledger.add_evidence("A", post_finding(Layer::Persistence, 20, "a"));
        ledger.add_evidence("B", post_finding(Layer::Context, 20, "b"));
        ledger.add_evidence("C", post_finding(Layer::AlternateDataStream, 20, "c"));

        let (score1, v1, _) = ledger.finalize();
        let (score2, v2, _) = ledger.finalize();

        assert_eq!(score1, score2, "double finalize changed score");
        assert_eq!(
            format!("{v1:?}"),
            format!("{v2:?}"),
            "double finalize changed verdict"
        );
        // Weights unchanged by second call.
        let weights1: Vec<u32> = ledger.findings.iter().map(|f| f.weight).collect();
        let (score3, _, _) = ledger.finalize();
        let weights2: Vec<u32> = ledger.findings.iter().map(|f| f.weight).collect();
        assert_eq!(score2, score3);
        assert_eq!(weights1, weights2, "triple finalize changed weights");
    }

    #[test]
    fn explanation_omits_zero_weight_reasons() {
        // Many small findings that scale to 0 should not appear in explanation.
        let verdict = make_verdict(30, vec![]);
        let mut ledger = ConvergenceLedger::new(&verdict, false);
        for i in 0..100 {
            ledger.add_evidence("tiny", post_finding(Layer::Context, 1, &format!("t{i}")));
        }
        let (final_score, _, _) = ledger.finalize();
        let mut explanation = argus::verdict::VerdictExplanation::default();
        ledger.patch_explanation(&mut explanation, final_score);
        // No "+0" entries in suspicion reasons.
        assert!(
            !explanation
                .suspicion_reasons
                .iter()
                .any(|r| r.contains("+0")),
            "explanation contains +0 entries: {:?}",
            explanation.suspicion_reasons
        );
    }

    #[test]
    #[should_panic(expected = "add_evidence() called after finalize()")]
    fn add_evidence_after_finalize_panics_in_debug() {
        let verdict = make_verdict(30, vec![]);
        let mut ledger = ConvergenceLedger::new(&verdict, false);
        ledger.add_evidence("A", post_finding(Layer::Persistence, 10, "a"));
        let _ = ledger.finalize();

        // This should panic in debug mode (debug_assert).
        ledger.add_evidence("B", post_finding(Layer::Context, 20, "b"));
    }

    #[test]
    fn patch_explanation_idempotent() {
        let verdict = make_verdict(40, vec![]);
        let mut ledger = ConvergenceLedger::new(&verdict, false);
        ledger.add_evidence(
            "Persistence",
            post_finding(Layer::Persistence, 10, "Run key"),
        );
        ledger.apply_trust_discount(5, None);
        let (final_score, _, _) = ledger.finalize();

        let mut explanation = argus::verdict::VerdictExplanation::default();

        // Call patch_explanation 3 times.
        ledger.patch_explanation(&mut explanation, final_score);
        let reasons1 = explanation.suspicion_reasons.len();
        let trust1 = explanation.trust_reasons.len();

        ledger.patch_explanation(&mut explanation, final_score);
        let reasons2 = explanation.suspicion_reasons.len();
        let trust2 = explanation.trust_reasons.len();

        ledger.patch_explanation(&mut explanation, final_score);
        let reasons3 = explanation.suspicion_reasons.len();
        let trust3 = explanation.trust_reasons.len();

        assert_eq!(
            reasons1, reasons2,
            "patch_explanation duplicated suspicion reasons"
        );
        assert_eq!(reasons2, reasons3);
        assert_eq!(trust1, trust2, "patch_explanation duplicated trust reasons");
        assert_eq!(trust2, trust3);
    }

    #[test]
    fn base_context_finding_survives_post_context_scaling() {
        // Base ARGUS has a Context finding (weight=15).
        // Post-ARGUS also has Context findings that need scaling.
        // Base finding must NOT be touched.
        let verdict = make_verdict(50, vec![base_finding(Layer::Context, 15)]);
        let mut ledger = ConvergenceLedger::new(&verdict, false);

        // Add 60 points of post-ARGUS Context findings.
        for i in 0..6 {
            ledger.add_evidence(
                "PLM",
                post_finding(Layer::Context, 10, &format!("chain{i}")),
            );
        }

        let (final_score, _, _) = ledger.finalize();
        // Base finding at index 0 must be exactly 15.
        assert_eq!(
            ledger.findings[0].weight, 15,
            "base Context finding corrupted"
        );
        // Post findings scaled.
        let post_sum: u32 = ledger.findings[1..].iter().map(|f| f.weight).sum();
        assert!(post_sum <= POST_ARGUS_CAP, "post sum {post_sum} > cap");
        assert!(final_score <= 90);
    }

    // ── R4 round 2 regression tests ──────────────────────────

    #[test]
    fn r4_cv5_single_finding_weight_clamped() {
        // u32::MAX weight on one finding would overflow raw_post sum.
        // add_evidence must clamp to MAX_SINGLE_POST_WEIGHT.
        let verdict = make_verdict(50, vec![]);
        let mut ledger = ConvergenceLedger::new(&verdict, false);
        ledger.add_evidence(
            "ROGUE",
            post_finding(Layer::Persistence, u32::MAX, "huge"),
        );
        // The stored finding's weight must be clamped, not u32::MAX.
        assert!(
            ledger.findings[0].weight <= POST_ARGUS_CAP,
            "rogue weight not clamped: {}",
            ledger.findings[0].weight
        );
        let (final_score, _, _) = ledger.finalize();
        // Final score must not overflow past 100.
        assert!(final_score <= 100, "score {final_score} > 100");
    }

    #[test]
    fn r4_cv6_many_findings_no_overflow_panic() {
        // Many findings each at the per-finding cap should not panic
        // when summed (saturating_add).
        let verdict = make_verdict(0, vec![]);
        let mut ledger = ConvergenceLedger::new(&verdict, false);
        for i in 0..1000 {
            ledger.add_evidence(
                "flood",
                post_finding(Layer::Context, POST_ARGUS_CAP, &format!("f{i}")),
            );
        }
        // Must not panic.
        let (final_score, _, _) = ledger.finalize();
        assert!(final_score <= 100);
    }

    #[test]
    fn r4_cv9_base_score_clamped_to_100() {
        // If ARGUS hands us a score > 100 (engine bug), clamp to 100.
        let verdict = make_verdict(999, vec![]);
        let ledger = ConvergenceLedger::new(&verdict, false);
        assert_eq!(ledger.base_score, 100, "base_score not clamped");
    }

    #[test]
    fn r4_cv11_trust_finding_dropped_when_clamav_positive() {
        let verdict = make_verdict(80, vec![]);
        let mut ledger = ConvergenceLedger::new(&verdict, true);
        let trust_f = post_finding(Layer::Context, 0, "trusted, no action");
        ledger.apply_trust_discount(10, Some(trust_f));
        // ClamAV positive → trust finding must NOT appear in findings.
        assert!(
            ledger.findings.is_empty(),
            "trust finding leaked into clamav-positive verdict"
        );
        assert_eq!(ledger.trust_discount, 0, "discount applied despite ClamAV");
    }

    #[test]
    fn r4_cv8_attribution_no_panic_on_max_discount() {
        // Even with a maxed-out (clamped to 100) trust discount the
        // i32 negation must not panic.
        let verdict = make_verdict(50, vec![]);
        let mut ledger = ConvergenceLedger::new(&verdict, false);
        ledger.apply_trust_discount(u32::MAX, None);
        let attr = ledger.attribution(0, 0, 0, 0);
        assert!(
            attr.trust_adjustment <= 0,
            "trust_adjustment should be non-positive"
        );
        assert!(
            attr.trust_adjustment >= -(MAX_VALID_SCORE as i32),
            "trust_adjustment beyond clamp: {}",
            attr.trust_adjustment
        );
    }

    #[test]
    fn r4_cv1_late_zero_discount_does_not_clear_earlier() {
        let verdict = make_verdict(50, vec![]);
        let mut ledger = ConvergenceLedger::new(&verdict, false);
        ledger.apply_trust_discount(8, None);
        ledger.apply_trust_discount(0, None); // adversary-controlled later call
        assert_eq!(ledger.trust_discount, 8, "earlier discount was overwritten");
    }
}
