//! `settings.full_config` — complete daemon configuration exposed to the GUI.
//!
//! v0.1.8 added a "full" mirror of the daemon's `Config` struct so the
//! Settings page can render every TOML knob with proper types, not just
//! the ~12 keys the old [`crate::settings::Settings`] surface exposed.
//!
//! # Design
//!
//! - Mirrors the daemon's `crate::config::Config` field-by-field.
//!   Conversions live on the daemon side (`impl From<&Config> for FullConfig`).
//! - `#[serde(default)]` everywhere — newer daemon versions can add fields
//!   without breaking older GUIs (and vice-versa).
//! - `developer.password_sha256` is **deliberately not mirrored** — the
//!   wire schema cannot carry it at all. Provisioning is out-of-band.
//! - Nested config structs (`FullFishConfig`, `FullSandboxConfig`, etc.)
//!   carry the configuration knobs only — never runtime stats.
//!
//! # Security: critical fields
//!
//! The settings.set_full handler MUST refuse to mutate the fields listed in
//! [`CRITICAL_FIELDS`]. Those are kill-vector fields (exclusions,
//! watched roots, trusted hashes, etc.) and travel via the elevated
//! `protection.set_critical` IPC method, which the GUI gates behind a UAC
//! prompt + challenge token.
//!
//! # Restart requirements
//!
//! Not every field can be applied while the daemon is running. The GUI
//! calls `settings.restart_requirements` to learn which keys flip a
//! "needs restart" pill. Three buckets — see [`RestartRequirement`].

use serde::{Deserialize, Serialize};

// ─── Restart requirements ───────────────────────────────────────────

/// What action is required for a config field change to take effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RestartRequirement {
    /// Applies immediately on save (most threshold/timing knobs).
    #[default]
    None,
    /// Requires the daemon to recompile the ClamAV engine.
    /// (exclusions, signature-provider switch, trusted hashes)
    EngineReload,
    /// Requires `sc stop SentinellaDaemon && sc start SentinellaDaemon`.
    /// (log_level, clamav_isolation, powershell bridge, scheduler enable,
    /// plus every knob the daemon COPIES into `AppState` at startup — see
    /// the second `DaemonRestart` arm in [`restart_requirement`])
    DaemonRestart,
}

/// Static lookup: field path (top-level or `nested.field`) → restart requirement.
///
/// GUI uses this to render the per-field "needs restart" pill and to
/// batch the "Restart now" footer button. The field paths match the
/// FullConfig serde names exactly.
pub fn restart_requirement(field_path: &str) -> RestartRequirement {
    use RestartRequirement::*;
    match field_path {
        // ── EngineReload (mpool rebuild required) ─────
        // `excluded_detections` and `trusted_hashes` are NOT here any more:
        // `protection.set_critical` pushes both into the running daemon
        // (`load_detection_exclusions` / `load_trusted_hashes`) the moment it
        // saves, so telling the user to reload the engine asks for work that
        // has already happened — and, worse, implies the old value is still
        // in force until they do, which is exactly backwards for a hash the
        // admin just REMOVED from the allowlist.
        "excluded_paths"
        | "excluded_extensions"
        | "enhanced_signature_provider"
        | "max_file_size_mb"
        | "scan_archives"
        | "heuristic_alerts" => EngineReload,

        // Hot-applied by protection.set_critical, which mirrors them into
        // AppState on save.
        "excluded_detections" | "trusted_hashes" => None,

        // ── DaemonRestart (process-lifecycle state) ───
        "log_level"
        | "clamav_isolation"
        | "powershell_bridge_enabled"
        | "powershell_poll_seconds"
        | "scheduled_scan_enabled"
        | "argus_worker_enabled"
        | "scan.argus_worker_enabled"
        | "fish.enabled"
        | "sandbox.enabled" => DaemonRestart,

        // ── web_protection.*: no hot apply exists ──
        //
        // Changing enabled/listen/upstreams re-plumbs where the machine's
        // DNS goes, and nothing re-reads the section on a live daemon.
        // Claiming `None` here would put a "saved, applies immediately"
        // pill next to a value the running proxy never picks up — and a
        // half-applied DNS change is exactly how an NRPT rule ends up
        // pointing at a dead listener. DaemonRestart is the honest
        // answer until a hot path is built; build it and move these in
        // the SAME commit.
        "web_protection.enabled"
        | "web_protection.listen"
        | "web_protection.upstreams"
        | "web_protection.block_response"
        | "web_protection.health_check_name"
        | "web_protection.blocklists"
        | "web_protection.allowlist"
        | "web_protection.log_queries" => DaemonRestart,

        // ── DaemonRestart (value is COPIED at startup) ─
        //
        // These are saved to the TOML the moment the user hits save, but the
        // running daemon keeps the copy it took at boot. `None` here would be
        // a lie told next to a threshold the user just lowered *because* they
        // wanted it to bite sooner — and unlike a missed hot-apply, the pill
        // at least tells them what to do about it.
        //
        // - performance.*: `AppState::performance_config` is a plain field
        //   with no interior mutability; the pressure evaluator borrows it
        //   directly, so nothing can replace it on a live daemon.
        // - clamav_worker_timeout_sec: reaches the scan path only through
        //   `AppState::set_clamav_subprocess`, called once from `main()` and
        //   only when isolation is already "subprocess".
        //
        // Neither is covered by `AppState::refresh_hot_config`. If you add
        // one, move that entry back to the `None` bucket in the SAME commit:
        // an over-reported restart pill is merely noisy, but a `None` that
        // never applies is a setting that silently lies.
        "performance.memory_profile"
        | "performance.memory_warning_mb"
        | "performance.memory_critical_mb"
        | "performance.external_argus_under_pressure"
        | "performance.max_resident_workers_on_pressure"
        | "clamav_worker_timeout_sec" => DaemonRestart,

        // Everything else is hot-applied.
        //
        // For the ones the daemon caches rather than re-reads per use —
        // signature-staleness thresholds, scan.orchestrator_* routing flags,
        // and every fish.* threshold (owned by a `MutationWindow` built from
        // the config) — "hot-applied" is true ONLY because
        // `AppState::refresh_hot_config` runs after each successful config
        // write. Drop that call and these silently become boot-only values
        // while the GUI keeps promising the save was enough.
        _ => None,
    }
}

// ─── Critical fields (kill-vector defense) ──────────────────────────

/// Field paths that `settings.set_full` MUST NOT mutate. Mutation requires
/// the elevated `protection.set_critical` IPC method, which itself
/// requires a challenge token plus (GUI-side) a UAC prompt.
///
/// Adding to this list = strictly more locked down. Removing from this list
/// is a security regression — don't, without a written rationale.
pub const CRITICAL_FIELDS: &[&str] = &[
    // ── Protection state (existing) ─────────────────
    "realtime_enabled",
    "auto_quarantine",
    // ── Worker hijack vectors ───────────────────────
    "argus_worker_enabled",
    "argus_worker_path",
    "scan.argus_worker_enabled",
    "scan.argus_worker_path",
    // ── Detection-suppression kill vectors ──────────
    // (excluded_detections=[""] silences ALL detections; an empty
    //  realtime_roots blinds the watcher; trusted_hashes whitelists
    //  specific malware; etc.)
    "excluded_paths",
    "excluded_extensions",
    "excluded_detections",
    "trusted_hashes",
    "realtime_roots",
    "heuristic_alerts",
    "idle_scan_enabled",
    "scheduled_scan_enabled",
    "enhanced_signature_provider",
    // ── v0.1.9 additions (audit finding HIGH-2 / LOW-19) ──
    // Ransomware shield + behavioural sandbox + ClamAV isolation
    // are kill-vector knobs too. Flipping fish.active_response to
    // "observe" silently disables ransomware enforcement; flipping
    // sandbox.enabled disables behavioural detonation; downgrading
    // clamav_isolation from "subprocess" to "in_process" re-exposes
    // the daemon to in-engine memory-corruption CVEs.
    "fish.enabled",
    "fish.observe_only",
    "fish.active_response",
    "sandbox.enabled",
    "clamav_isolation",
    // ── Web protection (DNS filtering) — the WHOLE section ──
    // enabled/listen/upstreams decide whether the machine's DNS is
    // routed into the local proxy at all: a bad write there is how an
    // NRPT rule ends up pointing at a dead listener, which is "no DNS"
    // — the one failure mode this subsystem must never produce.
    // blocklists/allowlist are the filtering equivalent of
    // excluded_detections/trusted_hashes: emptying blocklists or
    // allowlisting a malicious domain is detection suppression. The
    // remaining knobs travel with the section so the
    // protection.set_critical handler applies it atomically instead of
    // as split-brain halves.
    "web_protection.enabled",
    "web_protection.listen",
    "web_protection.upstreams",
    "web_protection.block_response",
    "web_protection.health_check_name",
    "web_protection.blocklists",
    "web_protection.allowlist",
    "web_protection.log_queries",
];

/// True if the given field path is in [`CRITICAL_FIELDS`].
pub fn is_critical(field_path: &str) -> bool {
    CRITICAL_FIELDS.contains(&field_path)
}

// ─── FullConfig — full daemon config mirror ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FullConfig {
    // ── Real-time protection ─────────────────────────
    pub realtime_enabled: bool,
    pub realtime_roots: Vec<String>,

    // ── Scan limits ──────────────────────────────────
    pub max_file_size_mb: u64,
    pub scan_archives: bool,
    pub heuristic_alerts: bool,

    // ── Updates ──────────────────────────────────────
    pub auto_update: bool,
    pub update_interval_hours: u32,
    pub signature_stale_days: u32,
    /// Age (days) at which staleness is worth INTERRUPTING the user.
    /// Far larger than signature_stale_days, which only tints a card.
    pub signature_stale_notify_days: u32,
    pub update_mirror: String,

    // ── Quarantine ───────────────────────────────────
    pub quarantine_retention_days: u32,
    pub auto_quarantine: bool,

    // ── Exclusions ───────────────────────────────────
    pub excluded_paths: Vec<String>,
    pub excluded_extensions: Vec<String>,
    pub excluded_detections: Vec<String>,
    pub trusted_hashes: Vec<String>,

    // ── Enhanced signature provider ──────────────────
    pub enhanced_signature_provider: String,

    // ── Logging ──────────────────────────────────────
    pub log_level: String,

    // ── Scheduler ────────────────────────────────────
    pub scheduled_scan_enabled: bool,
    pub scheduled_scan_hour: u32,
    pub scheduled_scan_type: String,

    // ── Startup ──────────────────────────────────────
    pub startup_critical_scan: bool,

    // ── PowerShell bridge ────────────────────────────
    pub powershell_bridge_enabled: bool,
    pub powershell_poll_seconds: u64,

    // ── Idle scanner ─────────────────────────────────
    pub idle_scan_enabled: bool,
    pub idle_scan_start_delay_secs: u64,
    pub idle_scan_on_battery: bool,
    pub idle_scan_cpu_pause_threshold: u32,
    pub idle_scan_max_file_size_mb: u64,
    pub idle_scan_fullscreen_pause: bool,
    pub idle_scan_disk_latency_pause_ms: u64,
    pub idle_scan_max_files_per_session: u64,
    pub idle_scan_slow_delay_min_ms: u64,
    pub idle_scan_slow_delay_max_ms: u64,
    pub idle_scan_normal_delay_min_ms: u64,
    pub idle_scan_normal_delay_max_ms: u64,
    pub idle_scan_fast_delay_min_ms: u64,
    pub idle_scan_fast_delay_max_ms: u64,

    // ── ARGUS worker (top-level) ─────────────────────
    pub argus_worker_enabled: bool,
    pub argus_worker_path: String,
    pub argus_worker_timeout_sec: u64,

    // ── ClamAV isolation ─────────────────────────────
    pub clamav_isolation: String,
    pub clamav_worker_timeout_sec: u64,

    // ── Nested sub-configs ───────────────────────────
    pub scan: FullScanConfig,
    pub performance: FullPerformanceConfig,
    pub fish: FullFishConfig,
    pub sandbox: FullSandboxConfig,
    pub developer: DeveloperConfigPublic,
    /// DNS-layer web protection. OPTIONAL on the wire, unlike every
    /// sibling section — this is the fix for the absent-vs-default trap
    /// that kept [web_protection] off FullConfig entirely:
    ///
    /// - `None` (key absent, or explicit null) = the client made NO
    ///   statement about the section. `serde(default)` on a plain
    ///   section struct would materialise defaults here, which the
    ///   daemon then cannot tell apart from a client that genuinely
    ///   asked for defaults — and every field in this section is
    ///   CRITICAL, so an older GUI PUTting a FullConfig without the
    ///   key would either get every unrelated save rejected as a
    ///   kill-vector mutation (stored config differs from defaults) or,
    ///   worse, have defaults written over the user's blocklists and
    ///   upstreams. `None` carries neither risk: the daemon ignores it.
    /// - `Some(section)` = an explicit statement. Every field must
    ///   match the stored config or `settings.set_full` rejects the
    ///   whole request; mutation travels via `protection.set_critical`.
    pub web_protection: Option<FullWebProtectionConfig>,
}

impl Default for FullConfig {
    fn default() -> Self {
        Self {
            realtime_enabled: true,
            realtime_roots: Vec::new(),

            max_file_size_mb: 512,
            scan_archives: true,
            heuristic_alerts: true,

            auto_update: true,
            update_interval_hours: 4,
            signature_stale_days: 3,
            signature_stale_notify_days: 14,
            update_mirror: "database.clamav.net".into(),

            quarantine_retention_days: 90,
            auto_quarantine: true,

            excluded_paths: Vec::new(),
            excluded_extensions: Vec::new(),
            excluded_detections: Vec::new(),
            trusted_hashes: Vec::new(),

            enhanced_signature_provider: "none".into(),

            log_level: "info".into(),

            scheduled_scan_enabled: true,
            scheduled_scan_hour: 3,
            scheduled_scan_type: "quick".into(),

            startup_critical_scan: true,

            powershell_bridge_enabled: false,
            powershell_poll_seconds: 5,

            idle_scan_enabled: true,
            idle_scan_start_delay_secs: 300,
            idle_scan_on_battery: false,
            idle_scan_cpu_pause_threshold: 50,
            idle_scan_max_file_size_mb: 256,
            idle_scan_fullscreen_pause: true,
            idle_scan_disk_latency_pause_ms: 50,
            idle_scan_max_files_per_session: 10_000,
            idle_scan_slow_delay_min_ms: 1500,
            idle_scan_slow_delay_max_ms: 2500,
            idle_scan_normal_delay_min_ms: 400,
            idle_scan_normal_delay_max_ms: 1000,
            idle_scan_fast_delay_min_ms: 100,
            idle_scan_fast_delay_max_ms: 300,

            argus_worker_enabled: false,
            argus_worker_path: "argusd.exe".into(),
            argus_worker_timeout_sec: 15,

            clamav_isolation: "in_process".into(),
            clamav_worker_timeout_sec: 30,

            scan: FullScanConfig::default(),
            performance: FullPerformanceConfig::default(),
            fish: FullFishConfig::default(),
            sandbox: FullSandboxConfig::default(),
            developer: DeveloperConfigPublic::default(),
            // None = "no statement about the section" — the daemon ignores
            // it on apply. A `Some(default)` here would be a claim that the
            // user's [web_protection] IS the default, which `critical_diff`
            // would then enforce against any non-default stored config.
            web_protection: None,
        }
    }
}

// ─── Nested sub-configs ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FullScanConfig {
    pub argus_worker_enabled: bool,
    pub argus_worker_path: String,
    pub argus_worker_timeout_sec: u64,
    pub orchestrator_file_scan_enabled: bool,
    pub orchestrator_folder_scan_enabled: bool,
    pub orchestrator_quick_scan_enabled: bool,
    pub orchestrator_full_scan_enabled: bool,
}

impl Default for FullScanConfig {
    fn default() -> Self {
        Self {
            argus_worker_enabled: false,
            argus_worker_path: "argusd.exe".into(),
            argus_worker_timeout_sec: 15,
            orchestrator_file_scan_enabled: false,
            orchestrator_folder_scan_enabled: false,
            orchestrator_quick_scan_enabled: false,
            orchestrator_full_scan_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FullPerformanceConfig {
    pub memory_profile: String,
    pub memory_warning_mb: u64,
    pub memory_critical_mb: u64,
    pub external_argus_under_pressure: bool,
    pub max_resident_workers_on_pressure: u32,
}

impl Default for FullPerformanceConfig {
    fn default() -> Self {
        Self {
            memory_profile: "normal".into(),
            memory_warning_mb: 1500,
            memory_critical_mb: 2500,
            external_argus_under_pressure: true,
            max_resident_workers_on_pressure: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FullFishConfig {
    pub enabled: bool,
    pub observe_only: bool,
    pub window_seconds: u64,
    pub rename_threshold: u32,
    pub rewrite_threshold: u32,
    pub ext_mutation_threshold: u32,
    pub slow_burn_window_secs: u64,
    pub slow_burn_threshold: u32,
    pub entropy_delta_threshold: f64,
    pub alert_cooldown_seconds: u64,
    /// "observe" | "suspend" | "terminate"
    pub active_response: String,
}

impl Default for FullFishConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            observe_only: true,
            window_seconds: 30,
            rename_threshold: 50,
            rewrite_threshold: 200,
            ext_mutation_threshold: 5,
            slow_burn_window_secs: 600,
            slow_burn_threshold: 250,
            entropy_delta_threshold: 0.20,
            alert_cooldown_seconds: 60,
            active_response: "observe".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FullSandboxConfig {
    pub enabled: bool,
    /// "experimental" | "production"
    pub mode: String,
    pub timeout_sec: u64,
    pub min_score: u32,
    pub max_score: u32,
}

impl Default for FullSandboxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: "experimental".into(),
            timeout_sec: 10,
            min_score: 26,
            max_score: 75,
        }
    }
}

/// Mirror of the daemon's `web_protection::WebProtectionConfig` — same
/// names, same types as the TOML section. Defaults here match the daemon
/// struct's `Default` exactly.
///
/// Unlike the other nested sections this one sits behind an `Option` at
/// the `FullConfig` level — see the `web_protection` field's doc comment
/// for the absent-vs-default semantics. Every field is in
/// [`CRITICAL_FIELDS`], so `settings.set_full` can never mutate any of
/// them; they are mirrored so the GUI can RENDER the section and so an
/// elevated `protection.set_critical` flow has a typed shape to send.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FullWebProtectionConfig {
    pub enabled: bool,
    /// IPv4 loopback :53 only when enabled — see the daemon's
    /// WebProtectionConfig docs for why nothing else can serve.
    pub listen: String,
    /// "system" or explicit IP:port entries.
    pub upstreams: Vec<String>,
    /// "nxdomain" (default) or "zero_ip".
    pub block_response: String,
    pub health_check_name: String,
    /// Each entry is `path` or `path|suffix`.
    pub blocklists: Vec<String>,
    /// Bare name = exact host, leading dot = suffix rule.
    pub allowlist: Vec<String>,
    pub log_queries: bool,
}

impl Default for FullWebProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "127.0.0.1:53".into(),
            upstreams: vec!["system".into()],
            block_response: "nxdomain".into(),
            health_check_name: "example.com".into(),
            blocklists: Vec::new(),
            allowlist: Vec::new(),
            log_queries: false,
        }
    }
}

/// Public projection of `DeveloperConfig`. Deliberately omits
/// `password_sha256` — provisioning is out-of-band only.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DeveloperConfigPublic {
    pub enabled: bool,
    pub telemetry_enabled: bool,
    pub telemetry_max_kb: u64,
}

impl Default for DeveloperConfigPublic {
    fn default() -> Self {
        Self {
            enabled: false,
            telemetry_enabled: true,
            telemetry_max_kb: 2048,
        }
    }
}

// ─── Restart-requirement map endpoint payload ────────────────────────

/// Response for `settings.restart_requirements` — maps every field path
/// to its [`RestartRequirement`]. Returned as a flat object keyed by
/// the same paths used in [`restart_requirement`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartRequirementMap {
    pub fields: std::collections::HashMap<String, RestartRequirement>,
}

impl RestartRequirementMap {
    /// Build the map by enumerating every known FullConfig field path.
    /// Adding a new field here is the single place to update — keeps
    /// the GUI's pill rendering in sync with the actual restart story.
    pub fn build() -> Self {
        let paths: &[&str] = &[
            // Top-level
            "realtime_enabled",
            "realtime_roots",
            "max_file_size_mb",
            "scan_archives",
            "heuristic_alerts",
            "auto_update",
            "update_interval_hours",
            "signature_stale_days",
            "signature_stale_notify_days",
            "update_mirror",
            "quarantine_retention_days",
            "auto_quarantine",
            "excluded_paths",
            "excluded_extensions",
            "excluded_detections",
            "trusted_hashes",
            "enhanced_signature_provider",
            "log_level",
            "scheduled_scan_enabled",
            "scheduled_scan_hour",
            "scheduled_scan_type",
            "startup_critical_scan",
            "powershell_bridge_enabled",
            "powershell_poll_seconds",
            "idle_scan_enabled",
            "idle_scan_start_delay_secs",
            "idle_scan_on_battery",
            "idle_scan_cpu_pause_threshold",
            "idle_scan_max_file_size_mb",
            "idle_scan_fullscreen_pause",
            "idle_scan_disk_latency_pause_ms",
            "idle_scan_max_files_per_session",
            "idle_scan_slow_delay_min_ms",
            "idle_scan_slow_delay_max_ms",
            "idle_scan_normal_delay_min_ms",
            "idle_scan_normal_delay_max_ms",
            "idle_scan_fast_delay_min_ms",
            "idle_scan_fast_delay_max_ms",
            "argus_worker_enabled",
            "argus_worker_path",
            "argus_worker_timeout_sec",
            "clamav_isolation",
            "clamav_worker_timeout_sec",
            // scan.*
            "scan.argus_worker_enabled",
            "scan.argus_worker_path",
            "scan.argus_worker_timeout_sec",
            "scan.orchestrator_file_scan_enabled",
            "scan.orchestrator_folder_scan_enabled",
            "scan.orchestrator_quick_scan_enabled",
            "scan.orchestrator_full_scan_enabled",
            // performance.*
            "performance.memory_profile",
            "performance.memory_warning_mb",
            "performance.memory_critical_mb",
            "performance.external_argus_under_pressure",
            "performance.max_resident_workers_on_pressure",
            // fish.*
            "fish.enabled",
            "fish.observe_only",
            "fish.window_seconds",
            "fish.rename_threshold",
            "fish.rewrite_threshold",
            "fish.ext_mutation_threshold",
            "fish.slow_burn_window_secs",
            "fish.slow_burn_threshold",
            "fish.entropy_delta_threshold",
            "fish.alert_cooldown_seconds",
            "fish.active_response",
            // sandbox.*
            "sandbox.enabled",
            "sandbox.mode",
            "sandbox.timeout_sec",
            "sandbox.min_score",
            "sandbox.max_score",
            // developer.* (public projection only)
            "developer.enabled",
            "developer.telemetry_enabled",
            "developer.telemetry_max_kb",
            // web_protection.* — every field DaemonRestart (no hot path)
            "web_protection.enabled",
            "web_protection.listen",
            "web_protection.upstreams",
            "web_protection.block_response",
            "web_protection.health_check_name",
            "web_protection.blocklists",
            "web_protection.allowlist",
            "web_protection.log_queries",
        ];
        let mut fields = std::collections::HashMap::with_capacity(paths.len());
        for p in paths {
            fields.insert((*p).to_string(), restart_requirement(p));
        }
        Self { fields }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_roundtrip_through_json() {
        let cfg = FullConfig::default();
        let json = serde_json::to_string(&cfg).expect("serialize");
        let parsed: FullConfig = serde_json::from_str(&json).expect("deserialize");
        // Spot-check a few representative fields.
        assert_eq!(parsed.realtime_enabled, true);
        assert_eq!(parsed.max_file_size_mb, 512);
        assert_eq!(parsed.fish.window_seconds, 30);
        assert_eq!(parsed.sandbox.min_score, 26);
        assert_eq!(parsed.performance.memory_profile, "normal");
        assert_eq!(parsed.developer.telemetry_max_kb, 2048);
    }

    #[test]
    fn restart_requirement_classification() {
        assert_eq!(
            restart_requirement("excluded_paths"),
            RestartRequirement::EngineReload
        );
        assert_eq!(
            restart_requirement("log_level"),
            RestartRequirement::DaemonRestart
        );
        assert_eq!(
            restart_requirement("idle_scan_cpu_pause_threshold"),
            RestartRequirement::None
        );
        // Unknown field → safe default (no restart needed).
        assert_eq!(
            restart_requirement("not_a_real_field"),
            RestartRequirement::None
        );
    }

    /// Every field below is read out of a copy the daemon takes at startup
    /// and has no refresher, so classifying any of them `None` puts a
    /// "saved, applies immediately" pill next to a value the running daemon
    /// is still ignoring. This list is a PIN, not a proof — the proof lives
    /// in the daemon crate (`AppState::performance_config` is a plain field;
    /// `AppState::set_clamav_subprocess` is reachable only from `main()`),
    /// and neither is reached by `AppState::refresh_hot_config`. When one of
    /// them does get a hot-apply, delete its line here in the same commit as
    /// the move out of the `DaemonRestart` arm.
    #[test]
    fn boot_copied_fields_are_not_advertised_as_hot_applied() {
        for field in [
            "performance.memory_profile",
            "performance.memory_warning_mb",
            "performance.memory_critical_mb",
            "performance.external_argus_under_pressure",
            "performance.max_resident_workers_on_pressure",
            "clamav_worker_timeout_sec",
        ] {
            assert_eq!(
                restart_requirement(field),
                RestartRequirement::DaemonRestart,
                "{field} is copied at daemon start — a `None` pill tells the \
                 user a threshold is live when the running daemon still has \
                 its boot value"
            );
        }
    }

    #[test]
    fn critical_fields_cover_known_kill_vectors() {
        // These are the kill-vector fields the old settings.set handler
        // already pinned — they MUST all be in CRITICAL_FIELDS so the
        // new settings.set_full handler refuses to mutate them too.
        for field in [
            "realtime_enabled",
            "auto_quarantine",
            "excluded_paths",
            "excluded_extensions",
            "excluded_detections",
            "trusted_hashes",
            "realtime_roots",
            "heuristic_alerts",
            "idle_scan_enabled",
            "scheduled_scan_enabled",
            "enhanced_signature_provider",
            "argus_worker_path",
            "argus_worker_enabled",
        ] {
            assert!(
                is_critical(field),
                "{field} must be in CRITICAL_FIELDS — kill-vector regression"
            );
        }
    }

    #[test]
    fn v019_audit_fields_added_to_critical() {
        // v0.1.9 audit fix (HIGH-2 / LOW-19): ransomware shield, behavioural
        // sandbox, and ClamAV isolation are kill-vector knobs. Each
        // explicitly named here so a careless future edit that drops them
        // back to non-critical fails the test and re-opens the audit hole.
        for field in [
            "fish.enabled",
            "fish.observe_only",
            "fish.active_response",
            "sandbox.enabled",
            "clamav_isolation",
        ] {
            assert!(
                is_critical(field),
                "{field} must stay in CRITICAL_FIELDS — v0.1.9 ransomware-shield / sandbox / isolation regression"
            );
        }
    }

    #[test]
    fn web_protection_section_is_optional_on_the_wire() {
        // Absent key → None, NOT a defaulted section. This pins the
        // absent-vs-default semantics: an older/partial client PUTting a
        // FullConfig without the section must not have one materialised
        // out of serde defaults — the daemon relies on `None` meaning
        // "no statement, leave the stored [web_protection] alone".
        let parsed: FullConfig = serde_json::from_str("{}").expect("empty payload parses");
        assert!(parsed.web_protection.is_none());
        // Explicit null means the same thing.
        let parsed: FullConfig =
            serde_json::from_str(r#"{"web_protection":null}"#).expect("null parses");
        assert!(parsed.web_protection.is_none());
        // FullConfig::default() carries None and serializes back to it.
        let json = serde_json::to_string(&FullConfig::default()).expect("serialize");
        let parsed: FullConfig = serde_json::from_str(&json).expect("deserialize");
        assert!(parsed.web_protection.is_none());

        // A present section round-trips with its values intact.
        let mut cfg = FullConfig::default();
        cfg.web_protection = Some(FullWebProtectionConfig {
            enabled: true,
            upstreams: vec!["9.9.9.9:53".into()],
            block_response: "zero_ip".into(),
            blocklists: vec!["C:\\feeds\\md.txt|suffix".into()],
            allowlist: vec![".corp.example.com".into()],
            log_queries: true,
            ..FullWebProtectionConfig::default()
        });
        let json = serde_json::to_string(&cfg).expect("serialize");
        let parsed: FullConfig = serde_json::from_str(&json).expect("deserialize");
        let section = parsed.web_protection.expect("section must round-trip");
        assert!(section.enabled);
        assert_eq!(section.listen, "127.0.0.1:53");
        assert_eq!(section.upstreams, vec!["9.9.9.9:53"]);
        assert_eq!(section.block_response, "zero_ip");
        assert_eq!(section.health_check_name, "example.com");
        assert_eq!(section.blocklists, vec!["C:\\feeds\\md.txt|suffix"]);
        assert_eq!(section.allowlist, vec![".corp.example.com"]);
        assert!(section.log_queries);
    }

    #[test]
    fn web_protection_fields_are_critical_and_restart_bound() {
        // Every web_protection.* field is a kill vector (DNS routing +
        // filtering suppression) AND has no hot-apply path: classifying
        // any of them `None` promises a live change the running daemon
        // never picks up. Named explicitly so a careless edit that drops
        // one fails here instead of reopening the gap.
        for field in [
            "web_protection.enabled",
            "web_protection.listen",
            "web_protection.upstreams",
            "web_protection.block_response",
            "web_protection.health_check_name",
            "web_protection.blocklists",
            "web_protection.allowlist",
            "web_protection.log_queries",
        ] {
            assert!(
                is_critical(field),
                "{field} must be in CRITICAL_FIELDS — kill-vector regression"
            );
            assert_eq!(
                restart_requirement(field),
                RestartRequirement::DaemonRestart,
                "{field} has no hot path — a None pill would lie about applying live"
            );
            assert_eq!(
                RestartRequirementMap::build().fields.get(field).copied(),
                Some(RestartRequirement::DaemonRestart),
                "{field} must appear in the restart-requirements map"
            );
        }
    }

    #[test]
    fn restart_requirement_map_is_well_formed() {
        let map = RestartRequirementMap::build();
        // Sanity: covers at least 60 fields.
        assert!(
            map.fields.len() >= 60,
            "restart_requirements map missing fields: {}",
            map.fields.len()
        );
        // Spot-check a few entries.
        assert_eq!(
            map.fields.get("excluded_paths").copied(),
            Some(RestartRequirement::EngineReload)
        );
        assert_eq!(
            map.fields.get("log_level").copied(),
            Some(RestartRequirement::DaemonRestart)
        );
        assert_eq!(
            map.fields.get("idle_scan_cpu_pause_threshold").copied(),
            Some(RestartRequirement::None)
        );
    }

    #[test]
    fn developer_public_excludes_password_hash() {
        // Compile-time guarantee: DeveloperConfigPublic has no `password_sha256`
        // field. This test exists as documentation — if someone adds the field
        // back, the assertion fails on the field-list check below.
        let cfg = FullConfig::default();
        let json = serde_json::to_string(&cfg.developer).unwrap();
        assert!(
            !json.contains("password_sha256"),
            "DeveloperConfigPublic must NEVER carry the password hash on the wire"
        );
    }
}
