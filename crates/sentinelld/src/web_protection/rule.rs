//! Installing, watching and removing the NRPT rule.
//!
//! This is the file where the product can break a machine's DNS, so the
//! rules it follows are written down rather than implied.
//!
//! # Preconditions, both hard
//!
//! 1. The four-step self-test passed. A rule pointing at a listener we
//!    could not prove works is the whole hazard.
//! 2. The boot reconciler's scheduled task exists. It is the only thing
//!    that removes the rule when this process is not around to do it —
//!    after a crash, a kill, a disabled service, a quarantined binary, a
//!    power loss. Installing without it means a rule that can outlive
//!    every mechanism able to undo it.
//!
//! # Orderings, both of which strand a rule if reversed
//!
//! INSTALL: record the GUID, THEN write the rule. A crash between the two
//! leaves a recorded GUID naming nothing, which the reconciler cleans up
//! harmlessly. The reverse leaves a rule nothing can name.
//!
//! SHUTDOWN: remove the rule, THEN stop serving. Between those two the
//! machine resolves through its normal upstreams while we are still
//! answering — harmless. The reverse leaves a window where the rule points
//! at sockets that are already closed.
//!
//! # There is no "fail open" here, and there cannot be
//!
//! The rule we install carries exactly ONE server: our own proxy. An NRPT
//! rule overrides the adapter's DNS configuration for every matching name —
//! that is what NRPT is for — so there is no secondary to fall back to.
//! Leaving a rule in place when the proxy has died therefore yields NO DNS,
//! not unfiltered DNS. An earlier version of this file offered exactly that
//! as the "fail open" option; see `config.rs` for why the knob is gone.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use dnsguard::filter::{CANARY_DOMAIN, Decision, FilterEngine};
use dnsguard::proxy::{Counters, UpstreamsHandle, is_canary_signature};
use dnsguard::wire;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{error, info, warn};

use super::config::DNS_PORT;

/// How often the watchdog asks whether we are still working.
///
/// The reconciler covers the boot case; this covers the one it cannot —
/// the daemon alive while the serving path is broken. Without it a proxy
/// that dies mid-session leaves the machine without DNS until the next
/// reboot.
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(20);

/// Consecutive failures before acting.
///
/// One failed check is not proof of death. NOTE, because the comment here
/// used to claim otherwise: the canary signature and the counter delta are
/// NOT independent corroboration. Under UDP overload the shed path answers
/// SERVFAIL without ever reaching `handle_query`, so neither the signature
/// nor the counter bump happens — both halves fail together, and a local
/// process can drive the proxy into shedding at will. Measured: one
/// unprivileged process with eight sender tasks flipped a healthy proxy to
/// `answered=false, moved=false` within one tick. The strike counter is
/// what absorbs that, so it must stay generous.
const WATCHDOG_STRIKES: u32 = 3;

const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// The resolution probe emits a REAL upstream query, so it runs on every
/// Nth tick rather than every one: at 20s intervals that is one extra
/// outbound query per minute, which is noise next to ordinary browsing.
/// The per-upstream direct probes share this cadence (and add one query
/// per upstream per round).
const RESOLVE_EVERY: u64 = 3;

/// More patience than the canary probe: this one waits on an upstream
/// across the real network, not on a loopback short-circuit.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);

/// Re-prove the boot reconciler's scheduled task every Nth tick: at 20s
/// intervals this is a 5-minute cadence. The task is checked once at
/// install, but Task Scheduler is user- and malware-writable all session
/// long, and a mid-session delete otherwise leaves a live rule whose
/// only remover is this process — unnoticed until the crash it was
/// registered for.
const RECONCILER_CHECK_EVERY: u64 = 15;

/// Live health facts maintained by the watchdog, read by the status
/// surface. Written ONLY here, so status never invents its own idea of
/// health, and never cleared once `fired` is set — the task exits right
/// after firing, and a fired watchdog is a fact about the session.
#[derive(Debug, Default)]
pub struct WatchdogState {
    /// Upstreams that failed the most recent direct probe round. Empty
    /// means "everything answered (or no round has run yet)" — not a
    /// promise about the next query.
    pub degraded_upstreams: Vec<SocketAddr>,
    /// The watchdog judged the proxy unhealthy and tore the rule down
    /// (or tried to). Terminal for this session.
    pub fired: bool,
    /// Why it fired, phrased for the status detail.
    pub fired_reason: String,
}

/// The three independent strike counters, kept together so the accounting
/// is testable without spawning anything.
///
/// INDEPENDENT is the whole point (they used to share one counter): the
/// serving probe runs every tick but the resolution probe only every
/// RESOLVE_EVERY-th, and the skipped ticks reported `resolving = true` —
/// so with a proxy that answers the canary while resolving nothing, the
/// sequence was strike, reset, reset, strike, reset, reset. `strikes`
/// could never exceed 1 against a threshold of WATCHDOG_STRIKES (3), and
/// the exact failure the resolution probe was added to catch could never
/// remove the rule. A skipped resolution tick is NOT evidence of health,
/// so it must leave the counter untouched rather than clear it.
#[derive(Debug, Default)]
struct Strikes {
    /// Canary probe failed (modulo the busy-is-not-dead rescue).
    serve: u32,
    /// The listener could not resolve the health-check name.
    resolve: u32,
    /// The boot reconciler's scheduled task is gone mid-session.
    reconciler: u32,
}

impl Strikes {
    fn record_serving(&mut self, serving: bool) {
        if serving {
            self.serve = 0;
        } else {
            self.serve += 1;
        }
    }

    /// `None` means the probe did not run this tick — NOT that it passed.
    fn record_resolve(&mut self, resolving: Option<bool>) {
        match resolving {
            Some(true) => self.resolve = 0,
            Some(false) => self.resolve += 1,
            None => {}
        }
    }

    /// `None` means the re-check did not run this tick. A task that came
    /// BACK clears the strikes: the backstop exists again, which is all
    /// this counter asks.
    fn record_reconciler(&mut self, present: Option<bool>) {
        match present {
            Some(true) => self.reconciler = 0,
            Some(false) => self.reconciler += 1,
            None => {}
        }
    }

    fn worst(&self) -> u32 {
        self.serve.max(self.resolve).max(self.reconciler)
    }
}

/// Install the rule, honouring both preconditions and the record-first
/// ordering. Returns the GUID actually in force.
///
/// Refusing is always safe here: it costs FILTERING, never DNS.
pub fn install(listen: SocketAddr, existing: Option<String>) -> Result<String, String> {
    // SECOND GATE on the port. Config validation refuses a non-53 listen,
    // and this refuses it again, because the failure is invisible: the rule
    // records only the IP, so a proxy on 5353 installs a rule the DNS
    // Client queries on 53 — where nothing is listening — while the
    // watchdog probes the address we BOUND and reports healthy. Two gates
    // because one of them is a config file a user edits.
    if listen.port() != DNS_PORT {
        return Err(format!(
            "refusing to install a rule for a proxy on port {}: NRPT records only the IP and \
             the DNS Client always queries {DNS_PORT}",
            listen.port()
        ));
    }
    // THIRD GATE, same shape as the port one and for the same reason: the
    // rule records a bare IP, and the Windows DNS Client resolves through it
    // over whichever transport the address implies. A proxy bound on an IPv6
    // loopback would install a rule the client cannot use the way this design
    // assumes, and the watchdog would still probe the address we bound and
    // report healthy — a rule that looks installed and working while the
    // machine cannot resolve. IPv4 is what the reconciler probes and what the
    // canary signature is defined over, so anything else is refused rather
    // than half-supported.
    if !listen.is_ipv4() {
        return Err(format!(
            "refusing to install a rule for a proxy on {listen}: web protection is IPv4-only, \
             and the reconciler probes 127.0.0.1"
        ));
    }
    if !nrpt::reconciler_task_installed() {
        return Err(
            "the boot reconciler task is not registered, so nothing could remove this rule if \
             the service stopped. Reinstall Sentinella; the installer registers it. \
             (Running from a development build? That is expected — web protection installs no \
             rule without it.)"
                .into(),
        );
    }

    // One rule per installation: reuse the recorded GUID so a restart
    // rewrites its own rule instead of accumulating a new one each time.
    let guid = existing.unwrap_or_else(new_guid);

    // RECORD FIRST. A crash between here and the write leaves a GUID naming
    // nothing, which the reconciler tidies away; the reverse order leaves a
    // rule that nothing can name.
    let state_file = nrpt::default_state_file();
    nrpt::record_guid(&state_file, &guid).map_err(|e| format!("cannot record rule GUID: {e}"))?;

    // Only the IP goes into the rule — NRPT has nowhere to put a port. The
    // gate above is what makes that correct.
    let servers: Vec<IpAddr> = vec![listen.ip()];
    nrpt::install_rule(&guid, nrpt::NAMESPACE_ALL, &servers)
        .map_err(|e| format!("cannot install NRPT rule: {e}"))?;

    info!(
        %guid,
        %listen,
        "web protection: NRPT rule installed — the machine's DNS now goes through this proxy"
    );
    Ok(guid)
}

/// Remove the rule and forget it. Idempotent, and safe to call when no rule
/// was ever installed.
pub fn remove(guid: &str) -> Result<(), String> {
    nrpt::remove_rule(guid).map_err(|e| format!("cannot remove NRPT rule: {e}"))?;
    // Rule first, record second — the reverse leaves a moment where the
    // rule exists and nothing names it.
    let _ = nrpt::clear_guid(&nrpt::default_state_file());
    info!(%guid, "web protection: NRPT rule removed — DNS restored to system defaults");
    Ok(())
}

/// Is a rule of ours present RIGHT NOW? Read from the system, never
/// inferred from configuration. `None` means we could not tell, which is
/// not the same as absent.
pub fn installed_now(guid: Option<&str>) -> Option<bool> {
    let guid = guid?;
    nrpt::rule_exists(guid).ok()
}

/// Watch the listener and tear the rule down if it stops working.
///
/// # It asks THREE different questions, because no two of them answer the third
///
/// The canary is short-circuited inside `handle_query` BEFORE
/// decide/cache/forward. That is what makes its signature unforgeable — and
/// exactly what makes it useless as evidence that DNS works. A proxy whose
/// every upstream is dead answers the canary perfectly while SERVFAILing
/// every real name. Measured on this branch: canary signature ok, counter
/// moved, and `www.microsoft.com` returning SERVFAIL with zero answers,
/// indefinitely, with every guard reporting green.
///
/// So the canary probe proves "our process is serving this socket", and a
/// periodic RESOLUTION probe proves "and it can actually resolve". Neither
/// alone is enough, and the first alone is what an earlier version of this
/// file certified as healthy.
///
/// The third question is asked of the SCHEDULER, not the proxy: is the boot
/// reconciler's task still registered? It is the only thing that removes
/// the rule when this process cannot, and a mid-session deletion (user
/// cleanup, "optimizer" tools, malware) used to leave a live rule with no
/// backstop, unnoticed. Every RECONCILER_CHECK_EVERY ticks the watchdog
/// re-proves it; gone counts as a strike — removing the rule when the
/// backstop is gone is the fail-safe direction, because a rule nothing
/// else can remove may only exist while this process is provably healthy.
///
/// # Per-upstream health is surfaced, never mutated
///
/// The resolution probe goes through the listener, and the listener
/// round-robins without failover — so with one of two upstreams dead the
/// probe fails only its unlucky half of ticks and `resolve_strikes` keeps
/// resetting: ~50% of the machine's queries SERVFAIL forever, undetected.
/// So every RESOLVE_EVERY ticks each upstream is ALSO probed DIRECTLY
/// (the same query shape the self-test's step (ii) uses; `forward_via` is
/// private to dnsguard, so the probe here is a local equivalent built on
/// the public `wire` helpers). Failures are written to `WatchdogState`
/// for the status surface. The upstream list itself is NOT touched:
/// dropping a dead-but-coming-back resolver is a policy decision, and the
/// refresher already owns list mutation. Rule-removal strikes still come
/// only from the through-listener probe, unchanged: persistent listener
/// failure (which is what ALL upstreams dead looks like) removes the
/// rule, partial failure does not.
#[allow(clippy::too_many_arguments)] // one subsystem's worth of shared state; a bundle struct would just rename the list
pub fn spawn_watchdog(
    guid: String,
    listen: SocketAddr,
    counters: Arc<Counters>,
    engine: Arc<RwLock<FilterEngine>>,
    upstreams: UpstreamsHandle,
    health_check_name: String,
    state: Arc<RwLock<WatchdogState>>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut strikes = Strikes::default();
        let mut tick = 0u64;
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(WATCHDOG_INTERVAL) => {}
            }
            tick += 1;

            let before = counters.snapshot();
            let answered = probe_canary(listen).await;
            let after = counters.snapshot();
            let moved = after.canary_probes > before.canary_probes;
            // The signature alone can be forged by whatever owns the port;
            // the counter delta proves OUR process served it. See the note
            // on WATCHDOG_STRIKES for why these two fail together rather
            // than independently.
            let mut serving = answered && moved;

            // BUSY IS NOT DEAD. If the probe failed but the process is
            // visibly still doing work, it is shedding, not gone — and a
            // shed probe is byte-identical to a dead one from out here.
            //
            // This is not hypothetical: an unprivileged local process can
            // saturate the UDP in-flight pool at will, which knocks out
            // BOTH halves of the check above at once (the shed path answers
            // SERVFAIL without ever reaching handle_query, so no signature
            // and no counter bump). Without this clause, any local process
            // could hold that for a minute and make the watchdog remove the
            // rule — permanently disabling web protection until a restart.
            //
            // Deliberately asymmetric: this can only ever RESCUE a strike,
            // never cause one. A genuinely dead serving task moves no
            // counters at all, so it still strikes normally.
            if !serving && (after.queries > before.queries || after.shed > before.shed) {
                warn!(
                    shed_delta = after.shed - before.shed,
                    "web protection: canary probe failed but the proxy is still serving traffic \
                         — treating as overload, not death"
                );
                serving = true;
            }

            let ran_resolve_probe = tick.is_multiple_of(RESOLVE_EVERY);
            let mut resolving = None;
            if ran_resolve_probe {
                resolving = Some(if health_name_is_allowed(&engine, &health_check_name) {
                    probe_resolves(listen, &health_check_name).await
                } else {
                    // A `zero_ip` block answer is NOERROR with one A record,
                    // so if the engine blocks this name the probe cannot
                    // tell a block from a resolution. Skip rather than
                    // guess — and say so, because it means this half of the
                    // check is not running.
                    warn!(
                        name = %health_check_name,
                        "web protection: health_check_name is blocked by the filter, so the \
                         watchdog cannot verify resolution — pick a name you never block"
                    );
                    true
                });

                // EVERY upstream, probed DIRECTLY (bypassing the listener,
                // so the filter's decision on the health name is irrelevant
                // here): round-robin without failover means one dead
                // upstream breaks its share of the machine's queries while
                // the through-listener probe above keeps passing on the
                // healthy half. Sequential with RESOLVE_TIMEOUT each —
                // bounded by (upstream count × 3s), and upstream lists are
                // short (one per adapter, usually two total).
                let current = upstreams.get();
                let mut degraded: Vec<SocketAddr> = Vec::new();
                for up in &current {
                    if !probe_resolves(*up, &health_check_name).await {
                        degraded.push(*up);
                    }
                }
                {
                    let mut ws = state.write().unwrap_or_else(|p| p.into_inner());
                    if ws.degraded_upstreams != degraded {
                        if degraded.is_empty() {
                            info!("web protection: all upstreams answering again");
                        } else {
                            warn!(
                                degraded = ?degraded,
                                total = current.len(),
                                "web protection: upstream(s) not answering direct probes — \
                                 their round-robin share of queries is SERVFAILing (surfaced \
                                 in status; the active list is NOT mutated)"
                            );
                        }
                        ws.degraded_upstreams = degraded;
                    }
                }
            }

            // Re-prove the remover. Checked once at install, but the task
            // can be deleted at any moment after; without this the rule
            // would outlive the only out-of-process mechanism able to
            // remove it, and nobody would know.
            let reconciler_present = if tick.is_multiple_of(RECONCILER_CHECK_EVERY) {
                let present = nrpt::reconciler_task_installed();
                if !present {
                    error!(
                        "web protection: the boot reconciler's scheduled task is GONE \
                         mid-session — nothing out-of-process could remove the NRPT rule \
                         after a crash; counting this toward rule removal"
                    );
                }
                Some(present)
            } else {
                None
            };

            strikes.record_serving(serving);
            strikes.record_resolve(resolving);
            strikes.record_reconciler(reconciler_present);
            let worst = strikes.worst();
            if worst == 0 {
                continue;
            }
            warn!(
                strikes = worst,
                serve_strikes = strikes.serve,
                resolve_strikes = strikes.resolve,
                reconciler_strikes = strikes.reconciler,
                answered,
                counter_moved = moved,
                resolving = ?resolving,
                "web protection: watchdog check failed"
            );
            if worst < WATCHDOG_STRIKES {
                continue;
            }

            let cause = if strikes.reconciler >= WATCHDOG_STRIKES {
                "the boot reconciler task is gone"
            } else if strikes.serve >= WATCHDOG_STRIKES {
                "the proxy stopped answering"
            } else {
                "the proxy resolves nothing"
            };
            error!(
                %guid,
                cause,
                "web protection: unhealthy for {}s — removing the NRPT rule so the machine \
                 keeps working DNS",
                WATCHDOG_INTERVAL.as_secs() * WATCHDOG_STRIKES as u64
            );
            let fired_reason = match remove(&guid) {
                Ok(()) => format!(
                    "watchdog fired ({cause}): the NRPT rule was removed and DNS is back on \
                     system defaults — filtering is OFF"
                ),
                Err(e) => {
                    // The rule is still live and we could not remove it.
                    // The boot reconciler is the backstop; say so rather
                    // than pretending this was handled.
                    error!(%e, "web protection: COULD NOT remove the rule — the boot reconciler will \
                                remove it at next startup");
                    format!(
                        "watchdog fired ({cause}) but the NRPT rule could NOT be removed: {e} — \
                         the boot reconciler is the backstop at next startup"
                    )
                }
            };
            {
                let mut ws = state.write().unwrap_or_else(|p| p.into_inner());
                ws.fired = true;
                ws.fired_reason = fired_reason;
            }
            return;
        }
    })
}

/// Can a NOERROR answer for this name be read as proof of resolution?
///
/// Only if the engine ALLOWS it. A `zero_ip` block answer is NOERROR with
/// one A record and is otherwise indistinguishable from a real resolution —
/// the same trap the proxy's own self-test step (iii)(c) had to close.
fn health_name_is_allowed(engine: &Arc<RwLock<FilterEngine>>, name: &str) -> bool {
    let e = engine.read().unwrap_or_else(|p| p.into_inner());
    e.decide(name) == Decision::Allow
}

/// One canary probe against the public address.
async fn probe_canary(addr: SocketAddr) -> bool {
    let Ok(sock) = UdpSocket::bind("127.0.0.1:0").await else {
        return false;
    };
    if sock.connect(addr).await.is_err() {
        return false;
    }
    let id = rand_id();
    // build_query emits no EDNS0 OPT, which the signature check requires:
    // the proxy appends an OPT whenever the requester sent one, and that
    // moves the trailing rdata the check looks at.
    let Some(q) = wire::build_query(id, CANARY_DOMAIN, wire::TYPE_A, wire::CLASS_IN) else {
        return false;
    };
    if sock.send(&q).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 1500];
    match tokio::time::timeout(PROBE_TIMEOUT, sock.recv(&mut buf)).await {
        Ok(Ok(n)) => is_canary_signature(&buf[..n], id),
        _ => false,
    }
}

/// Ask a DNS server to actually RESOLVE a name, and require a real answer.
///
/// Used two ways: against the LISTENER (the watchdog's resolution probe —
/// proves the serving path end to end) and against each UPSTREAM directly
/// (the per-upstream health round — proves reachability, bypassing the
/// listener and therefore the filter, so the engine's decision on the
/// health-check name is irrelevant for the second use).
async fn probe_resolves(addr: SocketAddr, name: &str) -> bool {
    let Ok(sock) = UdpSocket::bind("127.0.0.1:0").await else {
        return false;
    };
    if sock.connect(addr).await.is_err() {
        return false;
    }
    let id = rand_id();
    let Some(q) = wire::build_query(id, name, wire::TYPE_A, wire::CLASS_IN) else {
        return false;
    };
    if sock.send(&q).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 1500];
    let n = match tokio::time::timeout(RESOLVE_TIMEOUT, sock.recv(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return false,
    };
    let resp = &buf[..n];
    if resp.len() < wire::HEADER_LEN || u16::from_be_bytes([resp[0], resp[1]]) != id {
        return false;
    }
    let rcode = (u16::from_be_bytes([resp[2], resp[3]]) & 0x000F) as u8;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    // NOERROR alone is not resolution: NODATA is NOERROR with no answers,
    // and so is the shape a dead-upstream proxy would love to return.
    rcode == wire::RCODE_NOERROR && ancount >= 1
}

fn rand_id() -> u16 {
    // Loopback, connected socket: this only needs to differ between probes
    // so a late reply to a previous one cannot satisfy the current check.
    // Two ingredients, each carrying its half of that: a process-global
    // counter guarantees probe-to-probe difference, and a fresh RandomState
    // (randomly seeded per construction) makes the id unguessable to
    // whatever else owns a socket. An earlier version hashed
    // `SystemTime::now().elapsed()` — ~0 by construction — so the counter
    // half was silently absent.
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(SEQ.fetch_add(1, Ordering::Relaxed));
    (h.finish() >> 16) as u16
}

fn new_guid() -> String {
    format!("{{{}}}", uuid::Uuid::new_v4()).to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_guids_are_the_shape_nrpt_accepts() {
        for _ in 0..8 {
            let g = new_guid();
            assert!(
                nrpt::validate_guid(&g).is_ok(),
                "generated GUID is not registry-safe: {g}"
            );
        }
    }

    #[test]
    fn generated_guids_differ() {
        assert_ne!(new_guid(), new_guid());
    }

    /// REGRESSION. A non-53 listen used to reach `install_rule`, which
    /// records only the IP — so the DNS Client would query 53 where nothing
    /// listens, while the watchdog probed the bound port and reported
    /// healthy. Config validation refuses it now, and so does this, because
    /// the config is a file a user edits.
    #[test]
    fn install_refuses_any_port_but_53() {
        for port in [5353u16, 5300, 1, 65535] {
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let err = install(addr, None).expect_err("must refuse a non-53 listen");
            assert!(
                err.contains("NRPT records only the IP"),
                "the refusal must name the reason: {err}"
            );
        }
    }

    /// The precondition must hold even when everything else is fine. On a
    /// development machine the task is absent, so this is also what stops
    /// `cargo run` from installing a rule nothing would clean up.
    #[test]
    fn install_refuses_without_the_reconciler_task() {
        if nrpt::reconciler_task_installed() {
            return;
        }
        let err = install("127.0.0.1:53".parse().unwrap(), None)
            .expect_err("must refuse with no reconciler task");
        assert!(
            err.contains("reconciler task is not registered"),
            "the refusal must say WHY: {err}"
        );
    }

    /// Probing something that is not a DNS server must be false, not a
    /// hang: the watchdog runs forever and a stuck probe would stop it
    /// noticing anything again.
    #[tokio::test]
    async fn probe_of_a_dead_port_is_false_and_bounded() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead = sock.local_addr().unwrap();
        drop(sock);
        let started = std::time::Instant::now();
        assert!(!probe_canary(dead).await);
        assert!(started.elapsed() < PROBE_TIMEOUT * 3);
    }

    /// THE FINDING THIS TEST EXISTS FOR: a proxy that answers the canary
    /// but resolves nothing used to pass every guard. The resolution probe
    /// must reject NODATA (NOERROR with zero answers) and SERVFAIL, which
    /// is exactly the shape a dead-upstream proxy returns.
    #[tokio::test]
    async fn resolution_probe_rejects_answers_that_are_not_resolutions() {
        for (label, rcode, ancount) in [
            ("SERVFAIL", 2u8, 0u16),
            ("NODATA (NOERROR, no answers)", 0, 0),
            ("NXDOMAIN", 3, 0),
        ] {
            let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let addr = server.local_addr().unwrap();
            std::thread::spawn(move || {
                let mut buf = [0u8; 1500];
                if let Ok((n, peer)) = server.recv_from(&mut buf) {
                    let mut resp = buf[..n].to_vec();
                    if resp.len() >= 8 {
                        resp[2] = 0x81;
                        resp[3] = rcode;
                        resp[6..8].copy_from_slice(&ancount.to_be_bytes());
                    }
                    let _ = server.send_to(&resp, peer);
                }
            });
            assert!(
                !probe_resolves(addr, "example.com").await,
                "{label} must not count as a resolution"
            );
        }
    }

    /// A blocked health-check name makes the resolution probe unable to
    /// distinguish a block from a resolution, so the watchdog must detect
    /// that rather than trusting the answer.
    #[test]
    fn a_blocked_health_name_is_detected() {
        let mut e = FilterEngine::new();
        assert!(e.add_block("blocked.example"));
        let engine = Arc::new(RwLock::new(e));
        assert!(!health_name_is_allowed(&engine, "blocked.example"));
        assert!(health_name_is_allowed(&engine, "example.com"));
    }

    /// A minute of no answers is the threshold. Pinned so a later tweak to
    /// either constant cannot silently make the watchdog trigger-happy
    /// (removing the rule during a load spike) or useless.
    #[test]
    fn watchdog_threshold_is_about_a_minute() {
        let total = WATCHDOG_INTERVAL * WATCHDOG_STRIKES;
        assert!(total >= Duration::from_secs(45), "too twitchy: {total:?}");
        assert!(total <= Duration::from_secs(120), "too slow: {total:?}");
    }

    /// The reconciler re-check cadence: minutes, not seconds (Task
    /// Scheduler reads are not free) and not hours (a deleted backstop is
    /// a live rule with no out-of-process remover).
    #[test]
    fn reconciler_recheck_cadence_is_a_few_minutes() {
        let total = WATCHDOG_INTERVAL * RECONCILER_CHECK_EVERY as u32;
        assert!(total >= Duration::from_secs(60), "too twitchy: {total:?}");
        assert!(total <= Duration::from_secs(15 * 60), "too slow: {total:?}");
    }

    /// REGRESSION PIN for the shared-counter bug: a skipped resolution
    /// tick must leave the resolve counter UNTOUCHED, or a proxy that
    /// answers the canary while resolving nothing accumulates strike,
    /// reset, reset forever and can never reach the threshold.
    #[test]
    fn a_skipped_resolve_tick_is_not_evidence_of_health() {
        let mut s = Strikes::default();
        s.record_resolve(Some(false));
        s.record_resolve(None);
        s.record_resolve(None);
        assert_eq!(s.resolve, 1, "skipped ticks must not clear the strike");
        s.record_resolve(Some(false));
        s.record_resolve(Some(false));
        assert!(s.worst() >= WATCHDOG_STRIKES, "persistent failure must trip");
        s.record_resolve(Some(true));
        assert_eq!(s.worst(), 0, "a real success resets");
    }

    /// The reconciler counter: a gone task strikes toward removal (fail-
    /// safe), a task that comes back clears it, and a tick that did not
    /// re-check changes nothing.
    #[test]
    fn a_gone_reconciler_counts_toward_rule_removal() {
        let mut s = Strikes::default();
        s.record_reconciler(None);
        assert_eq!(s.worst(), 0, "no re-check this tick, no opinion");
        for _ in 0..WATCHDOG_STRIKES {
            s.record_reconciler(Some(false));
        }
        assert!(s.worst() >= WATCHDOG_STRIKES);
        s.record_reconciler(Some(true));
        assert_eq!(s.worst(), 0, "the backstop is back — strikes clear");
    }

    /// Serving and reconciler failures are independent counters: the
    /// busy-is-not-dead rescue cannot mask a missing reconciler, and a
    /// healthy proxy does not excuse it either.
    #[test]
    fn strike_counters_are_independent() {
        let mut s = Strikes::default();
        s.record_serving(false);
        s.record_reconciler(Some(false));
        s.record_serving(true); // rescued/recovered serving...
        assert_eq!(s.serve, 0);
        assert_eq!(s.reconciler, 1, "...must not clear the reconciler strike");
    }

    /// A direct probe must ACCEPT a real resolution — the rejection shapes
    /// are covered above, but a probe that rejects everything would mark
    /// every upstream degraded on a healthy machine.
    #[tokio::test]
    async fn resolution_probe_accepts_a_real_answer() {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            if let Ok((n, peer)) = server.recv_from(&mut buf) {
                let mut resp = buf[..n].to_vec();
                if resp.len() >= 8 {
                    resp[2] = 0x81;
                    resp[3] = 0; // NOERROR
                    resp[6..8].copy_from_slice(&1u16.to_be_bytes()); // ancount 1
                }
                let _ = server.send_to(&resp, peer);
            }
        });
        assert!(probe_resolves(addr, "example.com").await);
    }
}
