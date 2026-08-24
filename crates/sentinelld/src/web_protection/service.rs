//! Starting, holding and stopping the DNS proxy.
//!
//! # The ordering that must not be got wrong
//!
//! `dnsguard::proxy::Proxy::run` takes `self` BY VALUE. Every accessor —
//! `counters()`, `engine_handle()`, `upstreams_handle()` — is `&self` and
//! becomes uncallable the moment the serving future is spawned. So the
//! handles are captured first, and the natural-looking alternative does not
//! compile (`error[E0382]: borrow of moved value`). That is deliberate on
//! dnsguard's part: it is the same move that makes it impossible to run the
//! self-test concurrently with the serving loops, which would put two
//! `recv_from` calls on one socket and mislabel real user queries as
//! synthetic.
//!
//! # Why a failed self-test means NOT serving
//!
//! It would be friendlier to bind, fail the self-test, and serve anyway so
//! the user can poke at it. We do not, because `start` installs an NRPT
//! rule on exactly this signal (see `rule::install`) — and a listener we could not prove
//! works is the precise thing that must never end up with the machine's DNS
//! pointed at it. Refusing to serve keeps "enabled but not working" in the
//! degrade-to-no-filtering direction.
//!
//! # A refusal is not the end of the shift
//!
//! Boot-time transients — Wi-Fi not up yet, port 53 still held by a
//! shutting-down DNS Client, upstreams not answering while DHCP settles —
//! all surface here as refusals. A refusal classified TRANSIENT is retried
//! by a spawned task with capped exponential backoff (see [`spawn_retry`]);
//! only CONFIG-shaped failures (an address we can never parse, an engine
//! that cannot decide the canary) give up, because those are not going to
//! fix themselves. Rule installation stays gated behind a passing
//! self-test on the attempt that finally serves — the bind-before-rule
//! invariant is per-attempt, exactly as before.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use dnsguard::filter::{FilterEngine, ListKind};
use dnsguard::proxy::{
    BlockResponse, Counters, NoopDecisionHook, Proxy, ProxyConfig, UpstreamsHandle,
};
use tokio::sync::{Mutex, Notify, watch};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use super::config::{self, WebProtectionConfig};
use super::rule::WatchdogState;
use super::status::{ProxyState, WebProtectionStatus};
use super::upstreams;

/// The READ-ONLY half of the subsystem, shareable with the IPC layer.
///
/// WHY THIS IS SEPARATE. The IPC handler needs the status, and `AppState`
/// is `Arc`-shared by the server, its per-connection tasks and the Ctrl+C
/// task — it outlives process exit, which is why `plm/mod.rs:910-922`
/// documents that `Drop` is unreachable for anything it owns. Putting the
/// subsystem itself in `AppState` would therefore make `stop()` unable to
/// take `&mut`, and `stop()` MUST be a rendezvous (it removes the NRPT
/// rule during shutdown; removing it while the sockets are still bound
/// leaves the machine's DNS pointed at a listener that is going away). So
/// the owner keeps the shutdown side and shares this.
///
/// Everything here is either fixed at start or read through an `Arc` the
/// serving loops also hold, so it is always live without a lock of ours.
pub struct WebProtectionHandle {
    /// `enabled` AS OF START. A config edit since then is deliberately not
    /// reflected: it has not taken effect either, and reporting the edited
    /// value would claim a state the daemon is not in.
    enabled: bool,
    state: ProxyState,
    detail: String,
    listen: Option<SocketAddr>,
    /// The start-time upstream list — a FALLBACK read, used only when
    /// there is no live handle (refused starts). While serving, status
    /// reads the live list through `upstreams_handle` instead: the
    /// refresher swaps it on network change, and a fossil copy reported
    /// resolvers the machine had already abandoned for the life of the
    /// daemon.
    resolved_upstreams: Vec<SocketAddr>,
    upstreams_healthy: usize,
    upstreams_total: usize,
    rules_loaded: u64,
    counters: Option<Arc<Counters>>,
    engine: Option<Arc<RwLock<FilterEngine>>>,
    /// The NRPT rule GUID in force, if one was installed. `None` means no
    /// rule — which is a normal, safe state, not a failure.
    rule_guid: Option<String>,
    /// Live upstream list, present while serving. `UpstreamsHandle` is a
    /// cheap `Arc` clone over the proxy's own state, so holding it here
    /// keeps nothing alive that would not live anyway.
    upstreams_handle: Option<UpstreamsHandle>,
    /// The watchdog's live health facts (degraded upstreams, fired),
    /// present while the watchdog runs.
    watchdog: Option<Arc<RwLock<WatchdogState>>>,
    /// The BOOT config, kept so a refreshed blocklist can rebuild the
    /// engine live. Reloads use THIS, never a fresh disk read: the on-disk
    /// section may carry allowlist/blocklists edits the wire protocol
    /// classifies as DaemonRestart, and hot-applying those here would be
    /// half a restart (split-brain — the hazard full_config.rs warns about).
    /// `None` on handles that never started (disabled/refused), which have
    /// no engine to rebuild into either.
    boot_config: Option<WebProtectionConfig>,
}

impl WebProtectionHandle {
    /// The proxy's shared engine slot, when one exists (serving, or a
    /// self-test-failed start that kept the engine for status). A
    /// whole-engine swap under this write lock is live on the NEXT query —
    /// the serving loop takes `engine.read()` per query and `decide` runs
    /// before the cache lookup — so a refreshed blocklist takes effect with
    /// no listener restart and no dnsguard change.
    pub fn engine_handle(&self) -> Option<Arc<RwLock<FilterEngine>>> {
        self.engine.clone()
    }

    /// The config the running engine was built from. Live reloads MUST
    /// rebuild from this boot-time copy, never from disk — see the field.
    pub fn boot_config(&self) -> Option<&WebProtectionConfig> {
        self.boot_config.as_ref()
    }

    /// A point-in-time status, reading live counters when serving.
    pub fn status(&self) -> WebProtectionStatus {
        let snap = self.counters.as_ref().map(|c| c.snapshot());
        // Live where a live source exists, fossil where it does not.
        let upstreams: Vec<SocketAddr> = match &self.upstreams_handle {
            Some(h) => h.get(),
            None => self.resolved_upstreams.clone(),
        };
        let wd = self
            .watchdog
            .as_ref()
            .map(|w| w.read().unwrap_or_else(|p| p.into_inner()));
        let degraded: Vec<SocketAddr> = wd.as_ref().map(|w| w.degraded_upstreams.clone()).unwrap_or_default();
        let watchdog_fired = wd.as_ref().is_some_and(|w| w.fired);
        let (upstreams_total, upstreams_healthy) = if wd.is_some() {
            // The watchdog only exists while serving, and serving required
            // EVERY upstream healthy at self-test — so "total minus the
            // ones currently failing direct probes" is the honest count.
            (upstreams.len(), upstreams.len().saturating_sub(degraded.len()))
        } else {
            (self.upstreams_total, self.upstreams_healthy)
        };
        // Detail precedence: a refusal reason (set at construction) beats
        // the watchdog's news, which beats the all-clear empty string.
        let detail = if !self.detail.is_empty() {
            self.detail.clone()
        } else if watchdog_fired {
            wd.as_ref().map(|w| w.fired_reason.clone()).unwrap_or_default()
        } else if !degraded.is_empty() {
            format!(
                "{} of {} upstreams not answering: {} — their round-robin share of queries is \
                 failing; the active list is left unchanged",
                degraded.len(),
                upstreams_total,
                degraded.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ")
            )
        } else {
            String::new()
        };
        WebProtectionStatus {
            enabled: self.enabled,
            // Read from the system, never inferred from config. `None`
            // still means "could not tell", which is not `Some(false)`.
            nrpt_installed: super::rule::installed_now(self.rule_guid.as_deref()),
            // Live, like nrpt_installed, and through the same tri-state
            // seam (read error = None, never Some(false)): GPO state can
            // change mid-session and decides whether an installed rule
            // filters anything at all.
            gpo_nrpt_present: super::status::gpo_nrpt_present_now(),
            state: self.state,
            listen: self.listen.map(|a| a.to_string()),
            upstreams: upstreams.iter().map(|a| a.to_string()).collect(),
            upstreams_healthy,
            upstreams_total,
            upstreams_degraded: degraded.iter().map(|a| a.to_string()).collect(),
            watchdog_fired,
            rules_loaded: self
                .engine
                .as_ref()
                .map(|e| e.read().unwrap_or_else(|p| p.into_inner()).rule_count() as u64)
                .unwrap_or(self.rules_loaded),
            detail,
            queries: snap.as_ref().map(|s| s.queries).unwrap_or(0),
            blocked: snap.as_ref().map(|s| s.blocked).unwrap_or(0),
            cache_hits: snap.as_ref().map(|s| s.cache_hits).unwrap_or(0),
            upstream_errors: snap.as_ref().map(|s| s.upstream_errors).unwrap_or(0),
        }
    }
}

/// Whether a refused start is worth retrying (audit F2).
///
/// The distinction that matters: TRANSIENT failures are properties of the
/// moment (network not up, port not free yet, upstreams not answering
/// while the link settles) and can clear on their own; CONFIG failures
/// are properties of the configuration or the build (an unparseable
/// listen address, an engine that cannot decide its own canary) and no
/// amount of waiting fixes them. Retrying the first kind turns a boot
/// race into a delayed feature; retrying the second would be a busy log
/// forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefusalKind {
    /// Not transient: retrying cannot help. No retry task is armed.
    Config,
    /// Transient: retry with capped exponential backoff.
    Transient,
}

/// Discovery failures are read from the LIVE system, so they can all
/// change under us — adapters come up, DHCP lands, a VPN connects. Even
/// `OnlyLoopback` sits on the boundary: it asks the operator for explicit
/// upstreams, but it also clears the moment the adapter DNS is fixed, and
/// a retry notices. Refusals install nothing, so retrying is cheap and
/// safe in both directions.
fn classify_discovery(_e: &upstreams::DiscoveryError) -> RefusalKind {
    RefusalKind::Transient
}

/// The self-test's ENGINE step failing is not a network event: it means
/// `FilterEngine::new()` did not decide the built-in canary as Block,
/// which no amount of waiting repairs. Everything else a self-test can
/// fail on is reachability — transient by definition.
fn classify_self_test(report: &dnsguard::proxy::SelfTestReport) -> RefusalKind {
    if report.engine_ok {
        RefusalKind::Transient
    } else {
        RefusalKind::Config
    }
}

/// A running (or refused) web-protection subsystem.
///
/// Holding this holds the proxy alive: dropping `shutdown` signals the
/// serving loops to stop.
pub struct WebProtection {
    handle: Arc<WebProtectionHandle>,
    /// `Some` exactly when this subsystem is a refused start; the kind
    /// tells [`spawn_retry`] whether waiting can help. `None` for serving
    /// and for `enabled = false` (which is not a refusal at all).
    refusal: Option<RefusalKind>,
    watchdog: Option<tokio::task::JoinHandle<()>>,
    /// Periodic upstream re-discovery. Aborted in `stop`, like the watchdog.
    ///
    /// The `UpstreamsHandle` lives INSIDE this task, not beside it. A copy
    /// was kept here once, `#[allow(dead_code)]`, with a comment promising a
    /// future consumer — which is how the stale-upstream outage stayed
    /// invisible for a release: the field made the wiring look done. There
    /// is nothing for an owner-side copy to do (the handle is `Clone` over
    /// an `Arc` the proxy holds, so holding one keeps nothing alive), so the
    /// only holder is the only caller.
    refresher: Option<tokio::task::JoinHandle<()>>,

    /// Dropping or sending on this stops the serving loops. This is the
    /// daemon's FIRST `watch` channel — every other subsystem here polls an
    /// `AtomicBool` — so the sender must be kept alive for as long as the
    /// proxy should serve. Storing it in the struct is what does that.
    shutdown: Option<watch::Sender<bool>>,
    task: Option<JoinHandle<std::io::Result<()>>>,
}

/// Upstream re-discovery lives in `upstreams::spawn_upstream_refresh` —
/// an event-driven `NotifyIpInterfaceChange` subscription with a 5-min poll
/// fallback (replaced the 30 s poll; same keep-previous-on-error invariant).

/// Remove a rule that some PREVIOUS run of this daemon installed, when this
/// run is not going to serve.
///
/// THE HOLE THIS FILLS. `stop()` removes the rule on an orderly shutdown, and
/// the boot reconciler removes it at the next boot. Nothing covered the gap
/// between them: the daemon dying without running `stop()` and then being
/// restarted IN THE SAME BOOT. That is not exotic — the SCM restarts the
/// service on failure after 5 s, and the installer's PREINSTALL hook
/// `taskkill /F`s the daemon on every upgrade. If the restarted process then
/// refuses to serve for any reason (no adapters up yet on a laptop resuming,
/// port taken, self-test fail), the old rule stayed live in the registry
/// pointing every name on the machine at a port with nothing behind it, and
/// the new process had `rule_guid: None` so `stop()` would not remove it
/// either — the daemon was structurally incapable of ever taking it away.
/// The machine had no DNS until a reboot, which is the one outcome this
/// design says must never happen.
///
/// Best-effort by construction: a failure here leaves us exactly where we
/// already were, so it logs and moves on rather than blocking startup.
fn reconcile_orphan_rule(reason: &str) {
    let state_file = nrpt::default_state_file();
    let Some(guid) = nrpt::recorded_guid(&state_file) else {
        return;
    };
    match nrpt::rule_exists(&guid) {
        Ok(false) => {}
        Ok(true) => {
            warn!(
                %guid, reason,
                "web protection: a rule from a previous run is still live and this run is not \
                 serving — removing it so the machine keeps working DNS"
            );
            match super::rule::remove(&guid) {
                Ok(()) => info!(%guid, "web protection: orphaned rule removed"),
                Err(e) => error!(
                    %guid, %e,
                    "web protection: COULD NOT remove the orphaned rule — DNS on this machine is \
                     pointed at a port we are not serving; the boot reconciler is the backstop"
                ),
            }
        }
        Err(e) => warn!(
            %guid, %e,
            "web protection: could not tell whether a previous rule is still live"
        ),
    }
}

impl WebProtection {
    /// Not enabled, nothing running. Cheap and infallible.
    ///
    /// Still reconciles: `enabled = false` is one of the ways a live rule
    /// from a previous run gets orphaned (the user turned it off, or
    /// validation forced it off, while a rule was installed).
    pub fn disabled() -> Self {
        reconcile_orphan_rule("web protection disabled");
        Self::inert(false, ProxyState::Disabled, String::new(), None, None)
    }

    /// Enabled but refused, with the reason. `enabled` stays TRUE: the user
    /// did ask for this, and a status that reported `enabled: false` here
    /// would hide the refusal behind what looks like an untouched setting.
    fn refused(state: ProxyState, detail: impl Into<String>, kind: RefusalKind) -> Self {
        let detail = detail.into();
        reconcile_orphan_rule(&detail);
        Self::inert(true, state, detail, None, Some(kind))
    }

    fn inert(
        enabled: bool,
        state: ProxyState,
        detail: String,
        listen: Option<SocketAddr>,
        refusal: Option<RefusalKind>,
    ) -> Self {
        Self {
            handle: Arc::new(WebProtectionHandle {
                enabled,
                state,
                detail,
                listen,
                resolved_upstreams: Vec::new(),
                upstreams_healthy: 0,
                upstreams_total: 0,
                rules_loaded: 0,
                counters: None,
                engine: None,
                rule_guid: None,
                upstreams_handle: None,
                watchdog: None,
                boot_config: None,
            }),
            refusal,
            watchdog: None,
            refresher: None,
            shutdown: None,
            task: None,
        }
    }

    /// Share the read-only half with the IPC layer. See
    /// [`WebProtectionHandle`] for why this is not just `&self`.
    pub fn handle(&self) -> Arc<WebProtectionHandle> {
        Arc::clone(&self.handle)
    }

    /// Bring web protection up, or explain precisely why not.
    ///
    /// Never returns an error: a daemon that will not start because its DNS
    /// filter could not is worse than one that starts with filtering off.
    /// The refusal is reported through [`Self::status`] and the log.
    pub async fn start(cfg: &WebProtectionConfig) -> Self {
        if !cfg.enabled {
            return Self::disabled();
        }

        // Validation has already forced `enabled = false` on a malformed
        // listen, so this parse cannot realistically fail — but unwrapping
        // here would make a future validation gap a panic in a service.
        let listen: SocketAddr = match cfg.listen.parse() {
            Ok(a) => a,
            Err(e) => {
                error!(listen = %cfg.listen, %e, "web protection: unparseable listen address");
                // Config-shaped: no retry — the string will not parse any
                // better in five minutes.
                return Self::refused(ProxyState::Disabled, format!("listen: {e}"), RefusalKind::Config);
            }
        };

        let resolved = match upstreams::resolve(&cfg.upstreams, listen) {
            Ok(u) => u,
            Err(e) => {
                warn!(%e, "web protection: no usable upstreams — not starting");
                return Self::refused(ProxyState::Disabled, e.to_string(), classify_discovery(&e));
            }
        };
        info!(
            upstreams = ?resolved,
            "web protection: resolved upstreams"
        );

        // FilterEngine::new(), NEVER default(). `default()` is the derived
        // empty engine and carries no rules — not even the canary — which
        // would make the self-test's engine step false forever and, worse,
        // would block nothing while reporting success.
        let mut engine = FilterEngine::new();
        let rules_loaded = load_lists(&mut engine, cfg);

        let proxy_cfg = ProxyConfig {
            listen,
            upstreams: resolved.clone(),
            block_response: match cfg.block_response.as_str() {
                config::BLOCK_RESPONSE_ZERO_IP => BlockResponse::ZeroIp,
                _ => BlockResponse::Nxdomain,
            },
            health_check_name: cfg.health_check_name.clone(),
            ..ProxyConfig::default()
        };

        // NoopDecisionHook: no query logging in this commit. `log_queries`
        // is accepted in config so a user's setting is never silently
        // dropped, but the storage it needs — a retention-capped table
        // behind the authenticated IPC tier — does not exist yet, and
        // inventing an unbounded one would be worse than not logging at
        // all: this is browsing history.
        let proxy = match Proxy::bind(proxy_cfg, engine, Arc::new(NoopDecisionHook)).await {
            Ok(p) => p,
            Err(e) => {
                // Overwhelmingly the "something else owns 53" case — and at
                // boot that something can be the DNS Client itself, still
                // holding the port while the stack comes up. Transient:
                // retried (see spawn_retry); the log line says what owns
                // the port in the persistent case.
                error!(%listen, %e, "web protection: bind failed — not starting");
                return Self::refused(ProxyState::BindFailed, format!("bind {listen}: {e}"), RefusalKind::Transient);
            }
        };

        // CAPTURE BEFORE RUN. These are `&self` methods and `run` consumes
        // the proxy; taking them afterwards does not compile.
        let counters = proxy.counters();
        let engine_handle = proxy.engine_handle();
        let upstreams_handle = proxy.upstreams_handle();
        let bound = proxy.local_addr();

        // The four-step gate. Runs while nothing else is serving these
        // sockets — self_test spawns its own private loops, which is why it
        // must never overlap `run`.
        let report = proxy.self_test().await;
        if !report.ok() {
            error!(
                detail = %report.detail,
                engine_ok = report.engine_ok,
                upstream_ok = report.upstream_ok,
                filter_ok = report.filter_ok,
                tcp_ok = report.tcp_ok,
                "web protection: self-test failed — NOT serving"
            );
            // This path builds its handle by hand rather than through
            // `inert` (it keeps the engine handle so status can distinguish
            // "rules did not load" from "upstream is dead"), so it needs the
            // reconcile call explicitly. Bound socket or not, we are not
            // serving, and a rule pointing here would black-hole DNS.
            reconcile_orphan_rule("self-test failed");
            return Self {
                handle: Arc::new(WebProtectionHandle {
                    enabled: true,
                    state: ProxyState::SelfTestFailed,
                    detail: report.detail.clone(),
                    listen: Some(bound),
                    resolved_upstreams: resolved,
                    upstreams_healthy: report.upstreams_healthy,
                    upstreams_total: report.upstreams_total,
                    rules_loaded,
                    // The engine handle survives so status can still report
                    // how many rules loaded — useful for telling "the list
                    // did not load" apart from "the upstream is dead".
                    counters: None,
                    engine: Some(engine_handle),
                    rule_guid: None,
                    upstreams_handle: None,
                    watchdog: None,
                    boot_config: Some(cfg.clone()),
                }),
                refusal: Some(classify_self_test(&report)),
                watchdog: None,
                refresher: None,
                shutdown: None,
                task: None,
            };
        }

        let (tx, rx) = watch::channel(false);
        // Spawned BEFORE `proxy.run` consumes the proxy, and given its own
        // shutdown receiver so it dies with the rest of the service rather
        // than outliving it and pushing upstreams at a stopped proxy.
        let refresher = upstreams::spawn_upstream_refresh(
            cfg.upstreams.clone(),
            listen,
            // Cheap Arc-clone over the proxy's state; the handle also goes
            // to the watchdog and the status surface below.
            upstreams_handle.clone(),
            tx.subscribe(),
        );
        let task = tokio::spawn(proxy.run(rx));

        // GPO NRPT rules (HKLM\...\DNSClient\DnsPolicyConfig) make local
        // rules INERT: the OS evaluates the GPO table instead and no query
        // reaches this proxy. Do NOT refuse to run — GPO state can change
        // under us (gpupdate, domain join/leave), and surfacing rather
        // than blocking is the design ("don't silently degrade",
        // WEB_PROTECTION_DESIGN.md) — but say it loudly, or this daemon
        // self-tests green, installs its rule, reports Serving, and
        // filters nothing.
        match nrpt::gpo_nrpt_present() {
            Ok(true) => warn!(
                "web protection: GPO DNS policy (NRPT) rules are present — Windows IGNORES local \
                 NRPT rules on this machine, so web protection is INEFFECTIVE even though the \
                 rule installs and the proxy serves (surfaced in status as gpo_nrpt_present)"
            ),
            Ok(false) => {}
            Err(e) => warn!(
                %e,
                "web protection: could not read the GPO DNS policy container — cannot tell \
                 whether local NRPT rules are inert on this machine"
            ),
        }

        // ONLY NOW, with the self-test passed and the listener serving, may
        // a rule be installed. `install` enforces the other hard
        // precondition itself — the boot reconciler's task must exist,
        // because it is the only thing that removes the rule when this
        // process is not around to.
        //
        // A refusal here is SAFE: it costs filtering, never DNS. So it is a
        // warning and the proxy keeps serving; anyone who wants to use it
        // can still point a resolver at it by hand.
        let (rule_guid, watchdog, watchdog_state) = match super::rule::install(bound, nrpt::recorded_guid(&nrpt::default_state_file())) {
            Ok(guid) => {
                let wd_state = Arc::new(RwLock::new(WatchdogState::default()));
                let wd = super::rule::spawn_watchdog(
                    guid.clone(),
                    bound,
                    Arc::clone(&counters),
                    Arc::clone(&engine_handle),
                    upstreams_handle.clone(),
                    cfg.health_check_name.clone(),
                    Arc::clone(&wd_state),
                    tx.subscribe(),
                );
                (Some(guid), Some(wd), Some(wd_state))
            }
            Err(e) => {
                warn!(%e, "web protection: serving, but NO NRPT rule installed — the machine's DNS does not go through this proxy");
                (None, None, None)
            }
        };

        info!(
            %bound,
            upstreams = report.upstreams_total,
            rules = rules_loaded,
            nrpt = rule_guid.is_some(),
            "web protection: serving"
        );

        Self {
            handle: Arc::new(WebProtectionHandle {
                enabled: true,
                state: ProxyState::Serving,
                detail: String::new(),
                listen: Some(bound),
                resolved_upstreams: resolved,
                upstreams_healthy: report.upstreams_healthy,
                upstreams_total: report.upstreams_total,
                rules_loaded,
                counters: Some(counters),
                engine: Some(engine_handle),
                rule_guid,
                upstreams_handle: Some(upstreams_handle),
                watchdog: watchdog_state,
                boot_config: Some(cfg.clone()),
            }),
            refusal: None,
            watchdog,
            refresher: Some(refresher),
            shutdown: Some(tx),
            task: Some(task),
        }
    }

    /// Stop serving and WAIT for the loops to finish.
    ///
    /// This is a rendezvous, not a flag store. Every other `stop()` in this
    /// crate — Scheduler, RealtimeWatcher, IdleScanner — just sets an
    /// `AtomicBool` and returns, which is fine for them and will NOT be
    /// fine here: shutdown removes the NRPT rule, and removing it while
    /// the sockets are still bound would leave a window where the
    /// machine's DNS points at a listener that is going away. The join is
    /// bounded because the SCM stop budget is 30 s in total.
    ///
    /// Does NOT cover the retry task: it is not ours (it outlives any one
    /// `WebProtection` attempt by design). The owner calls
    /// [`RetryGuard::shutdown`] BEFORE this — see main.rs.
    pub async fn stop(&mut self) {
        // RULE FIRST, SOCKETS SECOND. Between these two the machine
        // resolves through its normal upstreams while we are still
        // answering, which is harmless. The reverse order leaves a window
        // where the rule points at sockets that are already closed — the
        // exact state this whole design exists to prevent, reached during
        // an ORDERLY shutdown, which would be an embarrassing way to get
        // there.
        if let Some(guid) = self.handle.rule_guid.clone()
            && let Err(e) = super::rule::remove(&guid)
        {
            error!(%e, %guid, "web protection: could not remove the NRPT rule on shutdown — \
                 the boot reconciler will remove it at next startup");
        }
        let Some(tx) = self.shutdown.take() else {
            return;
        };
        let _ = tx.send(true);
        if let Some(wd) = self.watchdog.take() {
            wd.abort();
        }
        // Same treatment as the watchdog: it holds an UpstreamsHandle into a
        // proxy that is going away, and its `watch` receiver would otherwise
        // let it survive one more sleep and push a list at a stopped proxy.
        if let Some(rf) = self.refresher.take() {
            rf.abort();
        }
        if let Some(task) = self.task.take() {
            match tokio::time::timeout(std::time::Duration::from_secs(5), task).await {
                Ok(Ok(_)) => info!("web protection: stopped"),
                Ok(Err(e)) => warn!(%e, "web protection: serving task ended abnormally"),
                Err(_) => warn!("web protection: serving task did not stop within 5s"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Retrying a refused start (audit F2)
// ---------------------------------------------------------------------------
//
// `start` refuses as one shot; without a retry, a transient boot condition
// (Wi-Fi not up, port 53 slow to free, DHCP still settling) disabled the
// feature until someone restarted the service BY HAND — and "enabled but
// silently off forever" is the worst status a security feature can wear.
// The loop below is spawned (never blocks daemon startup), bounded in its
// delays, and gives up only on config-shaped failures.

/// The delay before retry attempt `attempt` (0-based), WITHOUT jitter:
/// 30s doubling to a 5-minute cap. Pure so the sequence is testable.
fn base_backoff(attempt: u32) -> Duration {
    const BASE_SECS: u64 = 30;
    const CAP_SECS: u64 = 5 * 60;
    // 30 << 4 = 480 is the first shift past the cap, so clamping the shift
    // there also keeps it out of overflow territory forever.
    Duration::from_secs((BASE_SECS << attempt.min(4)).min(CAP_SECS))
}

/// ±20% jitter so machines that all failed at the same boot do not retry
/// in lockstep. Entropy from a fresh RandomState seed — no clock, same
/// trick as `rule::rand_id`.
fn jittered(base: Duration, salt: u32) -> Duration {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u32(salt);
    let base_ms = base.as_millis() as u64;
    let spread = base_ms / 5;
    Duration::from_millis(base_ms - spread + h.finish() % (2 * spread + 1))
}

/// Handle to the spawned retry loop. Dropping it does NOT stop the loop
/// (a dropped JoinHandle detaches); call [`RetryGuard::shutdown`].
pub struct RetryGuard {
    /// Checked after every attempt: the post-attempt swap must not happen
    /// once the daemon is going down.
    flag: Arc<std::sync::atomic::AtomicBool>,
    /// Wakes the loop out of its backoff sleep.
    wake: Arc<Notify>,
    task: JoinHandle<()>,
}

impl RetryGuard {
    /// Stop the retry loop and WAIT for it to be done.
    ///
    /// The join (not a bare abort) is what makes this safe: an in-flight
    /// attempt is allowed to finish, sees the flag, and — if it just
    /// started serving — stops itself cleanly, rule first, exactly like
    /// `WebProtection::stop`. Abort on timeout is the last resort: the one
    /// unsafe window it opens (killed between a successful attempt and the
    /// swap, rule possibly installed) is covered by the boot reconciler
    /// and by `reconcile_orphan_rule` at next start. Bounded at 10s
    /// against the SCM's 30s total stop budget (`stop()` needs 5s more).
    pub async fn shutdown(self) {
        self.flag.store(true, std::sync::atomic::Ordering::Relaxed);
        self.wake.notify_one();
        let mut task = self.task;
        if tokio::time::timeout(Duration::from_secs(10), &mut task)
            .await
            .is_err()
        {
            warn!("web protection: retry task did not exit within 10s — aborting");
            task.abort();
            let _ = task.await;
        }
    }
}

/// Arm bounded retries for a refused start. Returns `None` — no task
/// spawned — when the current subsystem is serving, disabled, or refused
/// for a CONFIG-shaped reason (waiting cannot parse an address better).
///
/// `current` is the owner's handle on the subsystem: a successful retry
/// SWAPS the new serving subsystem in (the old inert one is dropped —
/// safe, it holds nothing live) and publishes its handle through
/// `publish` so the IPC status surface follows. Every failed attempt also
/// republishes, with the retry schedule in `detail`. Rule installation
/// stays gated behind each attempt's own self-test, and every failed
/// attempt runs `reconcile_orphan_rule` — both inside `start`, unchanged.
pub async fn spawn_retry(
    current: Arc<Mutex<WebProtection>>,
    cfg: WebProtectionConfig,
    publish: watch::Sender<Arc<WebProtectionHandle>>,
) -> Option<RetryGuard> {
    if current.lock().await.refusal != Some(RefusalKind::Transient) {
        return None;
    }
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let wake = Arc::new(Notify::new());
    let (f, w) = (Arc::clone(&flag), Arc::clone(&wake));
    let task = tokio::spawn(async move {
        let mut attempt = 0u32;
        let mut delay = jittered(base_backoff(0), 0);
        loop {
            tokio::select! {
                _ = w.notified() => return,
                _ = tokio::time::sleep(delay) => {}
            }
            attempt += 1;
            let mut next = WebProtection::start(&cfg).await;

            // The daemon is going down: do NOT swap. If the attempt just
            // started serving (rule possibly installed), take it back
            // down through the orderly path — rule first, sockets second.
            if f.load(std::sync::atomic::Ordering::Relaxed) {
                next.stop().await;
                return;
            }

            let succeeded = next.handle.state == ProxyState::Serving;
            let retryable = next.refusal == Some(RefusalKind::Transient);
            if !succeeded && retryable {
                // Surface the schedule in the status the operator sees.
                delay = jittered(base_backoff(attempt), attempt);
                if let Some(h) = Arc::get_mut(&mut next.handle) {
                    h.detail = format!(
                        "{} — retrying (attempt {attempt}; next in ~{}s)",
                        h.detail,
                        delay.as_secs()
                    );
                }
            }
            let handle = next.handle();
            *current.lock().await = next;
            let _ = publish.send(handle);
            if succeeded {
                info!(attempt, "web protection: retry succeeded — serving");
                return;
            }
            if !retryable {
                warn!(attempt, "web protection: failure is not transient — giving up");
                return;
            }
        }
    });
    Some(RetryGuard { flag, wake, task })
}

/// Apply a finished update-cycle list refresh to the RUNNING proxy: when
/// the refresh CHANGED the managed lists, rebuild the filter engine from
/// the BOOT config and swap it in whole. Returns `Some(rules_loaded)` on a
/// swap, `None` when nothing was done — an unchanged refresh, or no engine
/// slot (disabled/refused starts have nothing serving to swap into).
///
/// WHY A WHOLE-ENGINE SWAP NEEDS NO RESTART. The serving loops take
/// `engine.read()` per query (dnsguard `proxy.rs`) and `decide` runs BEFORE
/// the cache lookup, so the swapped engine filters the very next query —
/// block answers are synthesized pre-cache and never cached, so there is no
/// stale-block residue either. The writer waits only for in-flight
/// DECISIONS (microseconds), never for in-flight upstream exchanges: a
/// query already forwarding does not re-decide.
///
/// THE TWO LOAD-BEARING DETAILS, pinned by tests:
/// - `FilterEngine::new()`, NEVER `default()`: `default()` carries no
///   canary, and the watchdog decides the canary through this same handle —
///   a canary-less swap makes it tear down the NRPT rule (fail-safe
///   direction, self-inflicted cause).
/// - poisoning tolerance on the write lock, matching the readers.
///
/// Two engines coexist briefly (old readers finish while new queries see
/// the new engine); at ~100k rules that is tens of MB for the swap window.
pub(crate) fn apply_refresh_report(
    handle: &WebProtectionHandle,
    report: super::lists::RefreshReport,
) -> Option<u64> {
    if !report.changed {
        return None;
    }
    let slot = handle.engine_handle()?;
    let boot_cfg = handle.boot_config()?;
    // Build OFF-LOCK: parsing a ~100k-rule list under the write lock would
    // stall every query for the duration. The swap itself is one move.
    let mut new_engine = FilterEngine::new();
    let rules = load_lists(&mut new_engine, boot_cfg);
    *slot.write().unwrap_or_else(|p| p.into_inner()) = new_engine;
    Some(rules)
}

/// Load the configured lists into a fresh engine, returning the rule count.
///
/// Used at startup AND by the live reload swap ([`apply_refresh_report`]).
/// Failures are warned and skipped rather than aborting startup: a
/// missing blocklist file means less filtering, and less filtering is the
/// direction this subsystem is allowed to fail in.
pub(crate) fn load_lists(engine: &mut FilterEngine, cfg: &WebProtectionConfig) -> u64 {
    for entry in &cfg.allowlist {
        // Config syntax: bare = exact, leading dot = suffix. `false` here
        // means the operator's rule vanished, which is a config error and
        // must be loud — not a debug line.
        if !engine.add_allow_rule(entry) {
            warn!(entry = %entry, "web_protection.allowlist entry is malformed — IGNORED");
        }
    }
    for spec in &cfg.blocklists {
        // `path` or `path|suffix`; the exact/suffix policy is a property of
        // the SOURCE, never of the data.
        let (path, suffix) = match spec.split_once('|') {
            Some((p, "suffix")) => (p, true),
            Some((p, "exact")) => (p, false),
            Some((p, other)) => {
                warn!(spec = %spec, policy = %other, "unknown blocklist policy — using exact");
                (p, false)
            }
            None => (spec.as_str(), false),
        };
        match std::fs::File::open(path) {
            Ok(f) => {
                let reader = std::io::BufReader::new(f);
                let policy = if suffix {
                    dnsguard::filter::DomainListPolicy::Suffix
                } else {
                    dnsguard::filter::DomainListPolicy::Exact
                };
                let res = if path.ends_with(".hosts") || path.ends_with("hosts") {
                    engine.load_hosts(ListKind::Block, reader)
                } else {
                    engine.load_domain_list(ListKind::Block, reader, policy)
                };
                match res {
                    Ok(stats) => {
                        if stats.truncated {
                            warn!(
                                path = %path,
                                rules = stats.rules_added,
                                "blocklist hit a load budget and was TRUNCATED — protection is partial"
                            );
                        }
                        if stats.hosts_rejected != 0 {
                            warn!(
                                path = %path,
                                rejected = stats.hosts_rejected,
                                "blocklist contained malformed entries that were dropped"
                            );
                        }
                        info!(path = %path, rules = stats.rules_added, "blocklist loaded");
                    }
                    Err(e) => warn!(path = %path, %e, "blocklist read failed — SKIPPED"),
                }
            }
            Err(e) => warn!(path = %path, %e, "blocklist not readable — SKIPPED"),
        }
    }
    engine.rule_count() as u64
}


#[cfg(test)]
mod tests {
    use super::*;
    use dnsguard::proxy::SelfTestReport;

    fn cfg_with(listen: &str, upstreams: &[&str]) -> WebProtectionConfig {
        WebProtectionConfig {
            enabled: true,
            listen: listen.into(),
            upstreams: upstreams.iter().map(|s| s.to_string()).collect(),
            ..WebProtectionConfig::default()
        }
    }

    fn report(engine_ok: bool) -> SelfTestReport {
        SelfTestReport {
            engine_ok,
            upstream_ok: false,
            filter_ok: false,
            tcp_ok: false,
            upstreams_healthy: 0,
            upstreams_total: 1,
            detail: String::new(),
        }
    }

    /// The backoff schedule the retry loop runs on: starts prompt (boot
    /// transients clear in seconds), doubles, and caps at five minutes so
    /// a permanent transient (a dead upstream the operator never fixes)
    /// costs one attempt per cap-interval, forever but cheaply.
    #[test]
    fn backoff_doubles_to_the_cap() {
        let seq: Vec<u64> = (0..7).map(|a| base_backoff(a).as_secs()).collect();
        assert_eq!(seq, vec![30, 60, 120, 240, 300, 300, 300]);
    }

    /// Jitter must stay inside ±20% and never produce zero (a zero delay
    /// would spin the retry loop).
    #[test]
    fn jitter_stays_within_twenty_percent() {
        let base = Duration::from_secs(300);
        for salt in 0..50 {
            let j = jittered(base, salt);
            assert!(j >= Duration::from_secs(240), "too low: {j:?}");
            assert!(j <= Duration::from_secs(360), "too high: {j:?}");
        }
    }

    /// The give-up classification: an engine that cannot decide its own
    /// canary is a build/code problem (no retry); everything else a
    /// self-test fails on is reachability (retry).
    #[test]
    fn self_test_classification_splits_code_from_network() {
        assert_eq!(classify_self_test(&report(true)), RefusalKind::Transient);
        assert_eq!(classify_self_test(&report(false)), RefusalKind::Config);
    }

    /// Discovery failures are read from the live system and can clear on
    /// their own — all of them retry. (OnlyLoopback asks for operator
    /// action, but it also clears the moment the adapter DNS is fixed;
    /// see classify_discovery.)
    #[test]
    fn discovery_failures_are_all_retryable() {
        for e in [
            upstreams::DiscoveryError::QueryFailed("x".into()),
            upstreams::DiscoveryError::NoneConfigured,
            upstreams::DiscoveryError::OnlyLoopback { dropped: 1 },
        ] {
            assert_eq!(classify_discovery(&e), RefusalKind::Transient);
        }
    }

    /// THE audit-F2 property: a config-shaped refusal must NOT arm a
    /// retry task. An unparseable listen will not parse any better in
    /// five minutes; a retry loop over it would be a busy log forever.
    #[tokio::test]
    async fn a_config_shaped_refusal_is_not_retried() {
        // Validation normally forces enabled=false on this input; calling
        // start directly proves the retry layer itself classifies right.
        let wp = WebProtection::start(&cfg_with("not-an-address", &["192.0.2.1:53"])).await;
        assert_eq!(wp.handle.state, ProxyState::Disabled);
        assert_eq!(wp.refusal, Some(RefusalKind::Config));
        let wp = Arc::new(Mutex::new(wp));
        let (tx, _rx) = watch::channel(wp.lock().await.handle());
        assert!(
            spawn_retry(Arc::clone(&wp), cfg_with("not-an-address", &["192.0.2.1:53"]), tx)
                .await
                .is_none(),
            "config-shaped failure must not arm a retry"
        );
        // And a plain disabled subsystem must not either.
        let off = Arc::new(Mutex::new(WebProtection::disabled()));
        let (tx2, _rx2) = watch::channel(off.lock().await.handle());
        assert!(spawn_retry(off, WebProtectionConfig::default(), tx2).await.is_none());
    }

    /// The other half: a transient refusal (port taken — the boot-race
    /// shape) MUST arm a retry, and the guard must stop the loop promptly
    /// (the first backoff sleep is 30s; this test would hang without the
    /// wake).
    #[tokio::test]
    async fn a_transient_refusal_arms_a_retry_that_shutdown_stops() {
        // Hold a UDP port so Proxy::bind fails with AddrInUse.
        let blocker = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let taken = blocker.local_addr().unwrap();
        let cfg = cfg_with(&taken.to_string(), &["192.0.2.1:53"]);
        let wp = WebProtection::start(&cfg).await;
        assert_eq!(wp.handle.state, ProxyState::BindFailed);
        assert_eq!(wp.refusal, Some(RefusalKind::Transient));
        let wp = Arc::new(Mutex::new(wp));
        let (tx, _rx) = watch::channel(wp.lock().await.handle());
        let guard = spawn_retry(Arc::clone(&wp), cfg, tx)
            .await
            .expect("a transient refusal must arm a retry");
        tokio::time::timeout(Duration::from_secs(5), guard.shutdown())
            .await
            .expect("retry shutdown must be prompt, not one backoff period");
    }

    async fn bound_proxy(upstreams: Vec<SocketAddr>) -> Proxy {
        let cfg = ProxyConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            upstreams,
            ..ProxyConfig::default()
        };
        Proxy::bind(cfg, FilterEngine::new(), Arc::new(NoopDecisionHook))
            .await
            .expect("ephemeral bind")
    }

    /// REGRESSION (audit F4): the status used to report the start-time
    /// upstream list forever, though the refresher swaps the live list on
    /// network change. Status must read through the handle.
    #[tokio::test]
    async fn status_reads_the_live_upstream_list() {
        let proxy = bound_proxy(vec!["192.0.2.1:53".parse().unwrap()]).await;
        let uh = proxy.upstreams_handle();
        let wd = Arc::new(RwLock::new(WatchdogState::default()));
        let handle = WebProtectionHandle {
            enabled: true,
            state: ProxyState::Serving,
            detail: String::new(),
            listen: None,
            resolved_upstreams: Vec::new(),
            upstreams_healthy: 0,
            upstreams_total: 0,
            rules_loaded: 0,
            counters: None,
            engine: None,
            rule_guid: None,
            upstreams_handle: Some(uh.clone()),
            watchdog: Some(wd),
            boot_config: None,
        };
        assert_eq!(handle.status().upstreams, vec!["192.0.2.1:53"]);
        uh.set(vec!["192.0.2.2:53".parse().unwrap(), "192.0.2.3:53".parse().unwrap()])
            .unwrap();
        let s = handle.status();
        assert_eq!(
            s.upstreams,
            vec!["192.0.2.2:53".to_string(), "192.0.2.3:53".to_string()],
            "status must follow the live list, not the start-time copy"
        );
        assert_eq!(s.upstreams_total, 2);
        assert_eq!(s.upstreams_healthy, 2, "nothing probed-degraded yet");
    }

    /// Refused starts have no live handle: the fossil fields are the
    /// fallback and must still be reported (that is all there is to know).
    #[tokio::test]
    async fn status_falls_back_to_the_start_time_copy_when_not_serving() {
        let proxy = bound_proxy(vec!["192.0.2.1:53".parse().unwrap()]).await;
        let _ = proxy.upstreams_handle();
        let handle = WebProtectionHandle {
            enabled: true,
            state: ProxyState::SelfTestFailed,
            detail: "x".into(),
            listen: None,
            resolved_upstreams: vec!["192.0.2.9:53".parse().unwrap()],
            upstreams_healthy: 1,
            upstreams_total: 2,
            rules_loaded: 0,
            counters: None,
            engine: None,
            rule_guid: None,
            upstreams_handle: None,
            watchdog: None,
            boot_config: None,
        };
        let s = handle.status();
        assert_eq!(s.upstreams, vec!["192.0.2.9:53"]);
        assert_eq!(s.upstreams_total, 2);
        assert_eq!(s.upstreams_healthy, 1);
        assert!(!s.watchdog_fired);
        assert!(s.upstreams_degraded.is_empty());
    }

    /// Degraded upstreams surface in status — live, while `state` stays
    /// Serving (audit F3): healthy = total - degraded, the detail names
    /// the dead ones, and the refusal detail (if any) still wins.
    #[tokio::test]
    async fn degraded_upstreams_are_surfaced_in_status() {
        let proxy = bound_proxy(vec![
            "192.0.2.1:53".parse().unwrap(),
            "192.0.2.2:53".parse().unwrap(),
        ])
        .await;
        let wd = Arc::new(RwLock::new(WatchdogState {
            degraded_upstreams: vec!["192.0.2.2:53".parse().unwrap()],
            fired: false,
            fired_reason: String::new(),
        }));
        let handle = WebProtectionHandle {
            enabled: true,
            state: ProxyState::Serving,
            detail: String::new(),
            listen: None,
            resolved_upstreams: Vec::new(),
            upstreams_healthy: 0,
            upstreams_total: 0,
            rules_loaded: 0,
            counters: None,
            engine: None,
            rule_guid: None,
            upstreams_handle: Some(proxy.upstreams_handle()),
            watchdog: Some(wd),
            boot_config: None,
        };
        let s = handle.status();
        assert_eq!(s.upstreams_degraded, vec!["192.0.2.2:53"]);
        assert_eq!(s.upstreams_healthy, 1);
        assert_eq!(s.upstreams_total, 2);
        assert!(!s.watchdog_fired);
        assert!(s.detail.contains("192.0.2.2:53"), "detail must name the dead upstream: {}", s.detail);
        assert_eq!(s.state, ProxyState::Serving, "degraded is not a new state");
    }

    /// A fired watchdog surfaces through the additive field plus detail,
    /// WITHOUT a new ProxyState variant (the GUI keys rendering on the
    /// existing four).
    #[tokio::test]
    async fn a_fired_watchdog_is_surfaced_without_a_state_change() {
        let proxy = bound_proxy(vec!["192.0.2.1:53".parse().unwrap()]).await;
        let wd = Arc::new(RwLock::new(WatchdogState {
            degraded_upstreams: Vec::new(),
            fired: true,
            fired_reason: "watchdog fired (the proxy stopped answering): rule removed".into(),
        }));
        let handle = WebProtectionHandle {
            enabled: true,
            state: ProxyState::Serving,
            detail: String::new(),
            listen: None,
            resolved_upstreams: Vec::new(),
            upstreams_healthy: 0,
            upstreams_total: 0,
            rules_loaded: 0,
            counters: None,
            engine: None,
            rule_guid: None,
            upstreams_handle: Some(proxy.upstreams_handle()),
            watchdog: Some(wd),
            boot_config: None,
        };
        let s = handle.status();
        assert!(s.watchdog_fired);
        assert!(s.detail.contains("watchdog fired"), "{}", s.detail);
        assert_eq!(s.state, ProxyState::Serving);
    }

    // ------------------------------------------------------------------
    // Live list reload (update-cycle engine swap)
    // ------------------------------------------------------------------

    use crate::web_protection::lists::RefreshReport;
    use dnsguard::filter::{CANARY_DOMAIN, Decision};

    /// A handle whose engine slot is a REAL bound proxy's — the very `Arc`
    /// the serving loop takes a read lock on per query — with `boot_config`
    /// attached, in the shape `start` publishes.
    fn serving_handle(cfg: WebProtectionConfig, slot: Arc<RwLock<FilterEngine>>) -> WebProtectionHandle {
        WebProtectionHandle {
            enabled: true,
            state: ProxyState::Serving,
            detail: String::new(),
            listen: None,
            resolved_upstreams: Vec::new(),
            upstreams_healthy: 0,
            upstreams_total: 0,
            rules_loaded: 0,
            counters: None,
            engine: Some(slot),
            rule_guid: None,
            upstreams_handle: None,
            watchdog: None,
            boot_config: Some(cfg),
        }
    }

    fn write_list(contents: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sentinella-wp-reload-test-{}-{}.hosts",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn decide(slot: &Arc<RwLock<FilterEngine>>, name: &str) -> Decision {
        slot.read().unwrap_or_else(|p| p.into_inner()).decide(name)
    }

    /// (i) THE feature: a refreshed list takes effect on the RUNNING proxy
    /// with no restart. The slot comes from a real bound `Proxy`, so
    /// swapping through the handle and then deciding THROUGH THE SAME ARC
    /// is exactly what the next live query does (the serving loop reads
    /// this Arc per query and decides before the cache lookup). A full DNS
    /// round-trip harness — `run()` plus crafted wire packets — would add
    /// the network without adding coverage of the swap itself, so the
    /// Arc-level boundary is the operative one.
    #[tokio::test]
    async fn a_swap_through_the_handle_is_live_on_the_next_decision() {
        let proxy = bound_proxy(vec!["192.0.2.1:53".parse().unwrap()]).await;
        let slot = proxy.engine_handle();
        assert_eq!(decide(&slot, "ads.example"), Decision::Allow, "nothing blocks it yet");

        let list = write_list(b"0.0.0.0 ads.example\n");
        let cfg = WebProtectionConfig {
            blocklists: vec![list.to_string_lossy().into_owned()],
            ..WebProtectionConfig::default()
        };
        let handle = serving_handle(cfg, Arc::clone(&slot));
        let rules = apply_refresh_report(&handle, RefreshReport { changed: true })
            .expect("a changed report on a serving handle must swap");
        assert!(rules >= 2, "canary plus one block rule, got {rules}");

        assert_eq!(
            decide(&slot, "ads.example"),
            Decision::Block,
            "the next query through the SAME Arc must see the new rule — no restart"
        );
        let _ = std::fs::remove_file(&list);
    }

    /// (ii) The swapped-in engine is built with `new()`, NEVER `default()`:
    /// the canary must still decide Block after the swap, or the watchdog —
    /// which decides the canary through this same handle — tears down the
    /// NRPT rule and takes the feature down with it. Fails if the swap
    /// engine is ever built with `default()`.
    #[tokio::test]
    async fn the_swapped_engine_keeps_the_canary() {
        let proxy = bound_proxy(vec!["192.0.2.1:53".parse().unwrap()]).await;
        let slot = proxy.engine_handle();
        let handle = serving_handle(WebProtectionConfig::default(), Arc::clone(&slot));
        apply_refresh_report(&handle, RefreshReport { changed: true }).unwrap();
        assert_eq!(
            decide(&slot, CANARY_DOMAIN),
            Decision::Block,
            "a canary-less swap makes the watchdog pull the NRPT rule"
        );
    }

    /// (iii) changed=false performs NO swap: the gate lives inside
    /// `apply_refresh_report`, so this pins the production call path, not a
    /// test-side `if`. Reverting the gate makes the swap happen and flips
    /// both assertions.
    #[tokio::test]
    async fn an_unchanged_report_performs_no_swap() {
        let proxy = bound_proxy(vec!["192.0.2.1:53".parse().unwrap()]).await;
        let slot = proxy.engine_handle();
        // A boot config whose list WOULD block this name if a swap happened.
        let list = write_list(b"0.0.0.0 must-not-load.example\n");
        let cfg = WebProtectionConfig {
            blocklists: vec![list.to_string_lossy().into_owned()],
            ..WebProtectionConfig::default()
        };
        let before = slot.read().unwrap_or_else(|p| p.into_inner()).rule_count();
        let handle = serving_handle(cfg, Arc::clone(&slot));
        assert_eq!(apply_refresh_report(&handle, RefreshReport { changed: false }), None);
        assert_eq!(
            slot.read().unwrap_or_else(|p| p.into_inner()).rule_count(),
            before,
            "an unchanged refresh must not rebuild the engine"
        );
        assert_eq!(decide(&slot, "must-not-load.example"), Decision::Allow);
        let _ = std::fs::remove_file(&list);
    }

    /// (iv) The reload rebuilds from the BOOT config — including its
    /// allowlist: a boot-allowlisted name stays allowed after the swap even
    /// though the refreshed list blocks it. The control name proves the
    /// blocklist really loaded (without it, a swap that loaded NOTHING would
    /// also report Allow for the allowlisted name).
    #[tokio::test]
    async fn the_swap_preserves_boot_allowlist_precedence() {
        let proxy = bound_proxy(vec!["192.0.2.1:53".parse().unwrap()]).await;
        let slot = proxy.engine_handle();
        let list = write_list(b"0.0.0.0 good.example\n0.0.0.0 bad.example\n");
        let cfg = WebProtectionConfig {
            allowlist: vec!["good.example".into()],
            blocklists: vec![list.to_string_lossy().into_owned()],
            ..WebProtectionConfig::default()
        };
        let handle = serving_handle(cfg, Arc::clone(&slot));
        apply_refresh_report(&handle, RefreshReport { changed: true }).unwrap();
        assert_eq!(
            decide(&slot, "bad.example"),
            Decision::Block,
            "control: the refreshed blocklist must actually be in force"
        );
        assert_eq!(
            decide(&slot, "good.example"),
            Decision::Allow,
            "the boot allowlist must win over a refreshed blocklist"
        );
        let _ = std::fs::remove_file(&list);
    }
}
