//! Discovering the machine's real DNS servers.
//!
//! `upstreams = ["system"]` means "whatever the active adapters are
//! configured to use". There is no registry location that answers this
//! correctly across DHCP, VPN tunnels and per-interface overrides —
//! `GetAdaptersAddresses` is the supported way, and it is what the DNS
//! Client itself resolves against.
//!
//! # The filter that matters
//!
//! A DNS server entry pointing at OUR OWN listener is an infinite loop:
//! one client query becomes an in-flight query to ourselves, which becomes
//! another, until the in-flight pool is saturated and every query on the
//! machine SERVFAILs. Measured on the crate under test: with
//! `max_in_flight = 64`, ONE client query produced 65 internal queries in
//! 26 ms.
//!
//! This is not a theoretical shape. `127.0.0.1` is the normal adapter DNS
//! on any machine that has ever run dnscrypt-proxy, Acrylic, a local
//! Pi-hole, or a previous install of this product. So loopback entries are
//! dropped, and if that leaves nothing we report NO upstreams rather than
//! inventing one — the design forbids a hardcoded public resolver, and a
//! resolver silently pointed somewhere the operator did not choose is
//! worse than a resolver that refuses to start.
//!
//! Dropped ENTRY BY ENTRY, by the same test `dnsguard` applies at bind
//! (see `is_self_referential`). The two halves of one safety rule have to
//! agree: dnsguard rejects the whole list on one bad address, so anything
//! this filter lets through and dnsguard then refuses costs us every good
//! upstream that was in the list alongside it.
//!
//! # Keeping the list current
//!
//! The resolved list goes stale the moment the network changes — a VPN
//! connect replaces the machine's resolvers in one step. This module also
//! owns the watcher that re-resolves on `NotifyIpInterfaceChange` events
//! (with a slow poll as the fallback) and pushes the result through
//! `UpstreamsHandle::set`, which keeps the previous list on error:
//! stale-but-working beats empty.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use dnsguard::proxy::UpstreamsHandle;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// DNS is always port 53 here: adapter configuration carries no port, and
/// NRPT's `NameServers` has no port syntax either.
const DNS_PORT: u16 = 53;

/// Windows hands out these site-local IPv6 anycast addresses as
/// PLACEHOLDERS on interfaces with no real IPv6 DNS configured. They are
/// deprecated (RFC 3879) and forwarding to them times out, which would
/// make `upstream_ok` false on a machine whose IPv4 DNS is perfectly
/// healthy. Recognised and dropped.
const IPV6_PLACEHOLDER_PREFIX: [u16; 4] = [0xfec0, 0, 0, 0xffff];

/// Why discovery produced nothing usable. Distinguished because the fixes
/// differ: "no adapters" is a machine problem, "only loopback" is a
/// configuration problem the operator can solve by naming upstreams
/// explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    /// The API call itself failed.
    QueryFailed(String),
    /// No up, non-loopback adapter reported any DNS server.
    NoneConfigured,
    /// Every discovered server was dropped by the safety filters
    /// (loopback self-reference, link-local fossil — the variant name
    /// predates the link-local drop and covers the common case).
    OnlyLoopback { dropped: usize },
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QueryFailed(e) => write!(f, "adapter enumeration failed: {e}"),
            Self::NoneConfigured => write!(f, "no active adapter reports a DNS server"),
            Self::OnlyLoopback { dropped } => write!(
                f,
                "all {dropped} configured DNS server(s) are unusable as upstreams \
                 (loopback — forwarding to them would point this proxy at itself — \
                 or link-local fossils); \
                 set web_protection.upstreams explicitly"
            ),
        }
    }
}

/// Resolve the configured `upstreams` list into concrete addresses.
///
/// `"system"` expands to discovery; explicit `IP:port` entries pass
/// through. Order is preserved and duplicates are removed, because
/// `pick_upstream` is round-robin and a duplicated entry would silently
/// get double the share of queries.
pub fn resolve(configured: &[String], listen: SocketAddr) -> Result<Vec<SocketAddr>, DiscoveryError> {
    let mut out: Vec<SocketAddr> = Vec::new();
    let mut discovery_error: Option<DiscoveryError> = None;

    for entry in configured {
        if entry == super::config::UPSTREAM_SYSTEM {
            match discover(listen) {
                Ok(found) => push_unique(&mut out, found),
                // Hold the error: an explicit entry later in the list may
                // still make the config workable, and refusing then would
                // be worse than the operator's stated intent.
                Err(e) => discovery_error = Some(e),
            }
        } else if let Ok(addr) = entry.parse::<SocketAddr>() {
            push_unique(&mut out, vec![addr]);
        } else {
            // Config validation already rejects this shape and forces the
            // section off; reaching here means validation was bypassed.
            warn!(entry = %entry, "web_protection upstream is not IP:port — ignored");
        }
    }

    if out.is_empty() {
        return Err(discovery_error.unwrap_or(DiscoveryError::NoneConfigured));
    }
    Ok(out)
}

fn push_unique(out: &mut Vec<SocketAddr>, more: Vec<SocketAddr>) {
    for a in more {
        if !out.contains(&a) {
            out.push(a);
        }
    }
}

/// Enumerate the machine's DNS servers, dropping the ones we must not
/// forward to.
pub fn discover(listen: SocketAddr) -> Result<Vec<SocketAddr>, DiscoveryError> {
    let raw = platform::enumerate_dns_servers().map_err(DiscoveryError::QueryFailed)?;
    if raw.is_empty() {
        return Err(DiscoveryError::NoneConfigured);
    }
    let total = raw.len();
    let kept = filter_usable(raw, listen);
    if kept.is_empty() {
        return Err(DiscoveryError::OnlyLoopback { dropped: total });
    }
    debug!(
        found = total,
        kept = kept.len(),
        "discovered system DNS servers"
    );
    Ok(kept)
}

/// The filtering half, split out so it is testable without a network
/// stack. Takes bare IPs (adapter config has no port) and returns
/// `SocketAddr`s on 53.
fn filter_usable(raw: Vec<IpAddr>, listen: SocketAddr) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for ip in raw {
        if is_ipv6_placeholder(&ip) {
            debug!(%ip, "dropping IPv6 site-local DNS placeholder");
            continue;
        }
        if ip.is_unspecified() || ip.is_multicast() {
            debug!(%ip, "dropping unusable DNS server address");
            continue;
        }
        // LINK-LOCAL is dropped: 169.254/16 appears when DHCP failed, and
        // fe80::/10 is interface-scoped — on a roaming laptop both are
        // stale-network fossils that answer nothing while costing every
        // query routed to them a full upstream timeout. ULA (fc00::/7) is
        // KEPT, deliberately: unlike link-local it is routable site-local
        // space, so a resolver at a ULA address is a deliberate deployment
        // (corporate internal DNS, IPv6-only home networks), and dropping
        // it would leave those networks with no filtering at all.
        if is_link_local(&ip) {
            debug!(%ip, "dropping link-local DNS server (stale-network fossil)");
            continue;
        }
        let addr = SocketAddr::new(ip, DNS_PORT);
        // THE LOOP GUARD. A loopback DNS server on our own port is us, and
        // even a loopback server on a DIFFERENT port is a local resolver
        // that may itself be configured to point back here. We keep the
        // latter — it is a legitimate chained-resolver setup and refusing
        // it would break dnscrypt users — but never the former.
        if is_self_referential(addr, listen) {
            warn!(%ip, %listen, "dropping DNS server that is this proxy itself");
            continue;
        }
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    out
}

/// Would `dnsguard` refuse this upstream as self-referential?
///
/// THIS MUST MATCH `dnsguard::proxy::validate_upstreams` EXACTLY, because
/// the two run in sequence and the narrower one runs FIRST. `filter_usable`
/// used to drop only the exact `ip:53 == listen` match, so `[::1]` or
/// `127.0.0.2` survived discovery on a machine that had once run
/// dnscrypt-proxy / AdGuard Home / a host Pi-hole (they configure both
/// families, and 127/8 is all loopback). `Proxy::bind` then rejected the
/// WHOLE list on that one entry and web protection refused to start —
/// throwing away the perfectly usable LAN resolver that was sitting next to
/// it. Dropping the entry keeps the list; rejecting it loses the list.
///
/// The rule is about the LISTEN PORT, not about loopback: a local resolver
/// on some other port is a legitimate chained setup and must survive.
fn is_self_referential(upstream: SocketAddr, listen: SocketAddr) -> bool {
    upstream == listen
        || (listen.port() != 0
            && upstream.port() == listen.port()
            && upstream.ip().is_loopback()
            && (listen.ip().is_loopback() || listen.ip().is_unspecified()))
}

fn is_ipv6_placeholder(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            seg[0..4] == IPV6_PLACEHOLDER_PREFIX
        }
        IpAddr::V4(_) => false,
    }
}

/// IPv4 169.254.0.0/16 and IPv6 fe80::/10 — interface-scoped addresses
/// that outlive the network they belonged to. See the drop site in
/// `filter_usable` for why these go and ULA stays.
fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_unicast_link_local(),
    }
}

// ---------------------------------------------------------------------------
// Change-driven re-resolution
// ---------------------------------------------------------------------------

/// Fallback poll interval, now that the subscription is the fast path.
///
/// `NotifyIpInterfaceChange` covers interface up/down and address
/// arrivals — the VPN-connect case that made the 30 s poll hurt. What it
/// does not reliably cover is a DNS-server-only rewrite that changes no
/// interface state (some VPN clients edit adapter DNS directly), and a
/// subscription that failed to register at startup. This poll backstops
/// those holes, so the worst-case staleness window is this interval. Five
/// minutes: real changes now arrive by event within seconds, so polling
/// faster buys nothing, and `GetAdaptersAddresses` is cheap but not free.
const FALLBACK_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// How long after the first event of a burst the batched re-resolve
/// fires. See [`BurstCoalescer`] for why a fixed window and not a
/// debounce. Two seconds covers the interface-up → address → DNS-written
/// sequence a single VPN connect raises, without making a real change
/// wait long enough to matter.
const CHANGE_SETTLE: Duration = Duration::from_secs(2);

/// Collapses a network-change event storm into at most one re-resolve
/// per `settle` window.
///
/// A single VPN connect raises several `NotifyIpInterfaceChange` calls —
/// tunnel interface up, address assigned, DNS servers written — seconds
/// apart, and a Wi-Fi roam can flap an adapter repeatedly before it
/// settles. Resolving on every event would hammer discovery and push
/// half-formed lists (adapter up, its DNS not yet written) at the proxy.
///
/// Fixed window, NOT a debounce: the first event ARMS the coalescer and
/// later events while armed are absorbed without moving the deadline. A
/// debounce that extended on every event could be starved forever by a
/// flapping interface; here a continuous storm still fires no later than
/// `settle` after its first event.
struct BurstCoalescer {
    settle: Duration,
    armed_until: Option<Instant>,
}

impl BurstCoalescer {
    fn new(settle: Duration) -> Self {
        Self {
            settle,
            armed_until: None,
        }
    }

    /// Record a change event at `now`. Events while armed are absorbed:
    /// the deadline does NOT move, which is the property that bounds
    /// re-resolves to one per `settle` no matter how long the storm runs.
    fn signal(&mut self, now: Instant) {
        if self.armed_until.is_none() {
            self.armed_until = Some(now + self.settle);
        }
    }

    /// When the batched re-resolve is due; `None` means no pending events.
    fn due(&self) -> Option<Instant> {
        self.armed_until
    }

    /// Mark the batched re-resolve as done; the next event arms a fresh
    /// window.
    fn fired(&mut self) {
        self.armed_until = None;
    }
}

/// Receive from the subscription channel if there is one; never complete
/// otherwise. The latter is the poll-only shape (no subscription), where
/// the fallback interval and shutdown are the only live `select!` arms.
async fn next_change(rx: &mut Option<mpsc::Receiver<()>>) -> Option<()> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// Re-discover upstreams and push them at the proxy, driven by
/// `NotifyIpInterfaceChange` events with a slow poll as the fallback.
///
/// WHY EVENTS FIRST. The 30 s poll this replaces left the machine
/// forwarding to dead resolvers for up to 30 s on every VPN connect,
/// Wi-Fi roam or dock — and the NRPT rule routes EVERY name on the
/// machine at us, so that is 30 s of machine-wide resolution failure.
/// The interface-change subscription delivers the same signal in
/// seconds; the poll stays, slower, for what the subscription cannot see
/// (DNS-only rewrites) or in case it fails to register.
///
/// Conservative in exactly the way the poll was: `UpstreamsHandle::set`
/// validates and KEEPS THE PREVIOUS LIST on error, and a failed
/// re-discovery is logged and skipped, so a change event mid-roam — every
/// adapter briefly down — can never leave the proxy with no resolver.
/// Stale-but-working beats empty: degrade to no filtering, never to no
/// DNS.
pub fn spawn_upstream_refresh(
    configured: Vec<String>,
    listen: SocketAddr,
    handle: UpstreamsHandle,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Capacity 1: one pending signal already says "the interface table
        // changed"; a second pending copy adds nothing. The bound is what
        // lets the FFI callback stay allocation- and wait-free.
        let (tx, rx) = mpsc::channel::<()>(1);
        let _subscription = match platform::subscribe_interface_changes(tx) {
            Ok(s) => Some(s),
            Err(e) => {
                warn!(%e, "web protection: interface-change subscription failed — polling only");
                None
            }
        };
        // The receiver is only meaningful while a subscription holds the
        // sender; in the poll-only shape the arm never completes.
        let mut events = _subscription.as_ref().map(|_| rx);
        let mut coalescer = BurstCoalescer::new(CHANGE_SETTLE);
        // First tick one interval out: the service resolves at startup
        // before spawning us, so an immediate tick would re-resolve the
        // same list.
        let mut fallback = tokio::time::interval_at(
            tokio::time::Instant::now() + FALLBACK_REFRESH_INTERVAL,
            FALLBACK_REFRESH_INTERVAL,
        );
        let mut current: Vec<SocketAddr> = Vec::new();
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                signal = next_change(&mut events) => {
                    if signal.is_none() {
                        // The sender lives in the subscription we hold, so
                        // this cannot happen; drop the arm rather than
                        // busy-loop on a closed channel if it ever does.
                        events = None;
                        continue;
                    }
                    coalescer.signal(Instant::now());
                    let Some(due) = coalescer.due() else {
                        // signal() arms an unarmed coalescer, so this is
                        // unreachable; skip the cycle rather than panic in
                        // a service if that ever stops being true.
                        continue;
                    };
                    tokio::select! {
                        _ = shutdown.changed() => return,
                        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(due)) => {}
                    }
                    // Absorb whatever piled up during the settle window —
                    // the re-resolve below covers all of it.
                    if let Some(rx) = events.as_mut() {
                        while rx.try_recv().is_ok() {}
                    }
                    coalescer.fired();
                }
                _ = fallback.tick() => {}
            }
            let discovered = match resolve(&configured, listen) {
                Ok(u) => u,
                Err(e) => {
                    // Keep serving with what we have. An empty list here
                    // would be worse than a stale one.
                    warn!(%e, "web protection: upstream re-discovery failed — keeping the current list");
                    continue;
                }
            };
            if discovered == current {
                continue;
            }
            match handle.set(discovered.clone()) {
                Ok(()) => {
                    info!(
                        upstreams = ?discovered,
                        "web protection: upstream list changed — proxy updated"
                    );
                    current = discovered;
                }
                Err(e) => warn!(
                    %e,
                    "web protection: rediscovered upstreams were rejected — keeping the current list"
                ),
            }
        }
    })
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::c_void;
    use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, HANDLE, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        CancelMibChangeNotify2, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_FRIENDLY_NAME,
        GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, GetAdaptersAddresses,
        IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH, MIB_IPINTERFACE_ROW,
        MIB_NOTIFICATION_TYPE, NotifyIpInterfaceChange,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6};

    /// Bounded retry on the grow-the-buffer dance. Between two calls the
    /// adapter set can change and the required size can grow again; three
    /// attempts is generous, and a bound means a machine churning through
    /// VPN connects can never spin here forever.
    const MAX_ATTEMPTS: usize = 3;
    /// MSDN recommends 15 KB as the starting allocation.
    const INITIAL_BUF: usize = 15 * 1024;
    /// Refuse to keep growing past this. A legitimate answer is a few tens
    /// of KB; anything larger means something is wrong and we would rather
    /// report a failure than allocate unboundedly inside a service.
    const MAX_BUF: usize = 4 * 1024 * 1024;

    pub fn enumerate_dns_servers() -> Result<Vec<IpAddr>, String> {
        // SKIP_UNICAST/ANYCAST/MULTICAST/FRIENDLY_NAME: we want ONLY the
        // DNS server lists, and every skipped section is memory the API
        // does not have to write and we do not have to walk.
        let flags = GAA_FLAG_SKIP_UNICAST
            | GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_FRIENDLY_NAME;

        let mut size = INITIAL_BUF as u32;
        for _ in 0..MAX_ATTEMPTS {
            if size as usize > MAX_BUF {
                return Err(format!("adapter table exceeds {MAX_BUF} bytes"));
            }
            // IP_ADAPTER_ADDRESSES_LH has pointer alignment; a Vec<u8>
            // gives us no such guarantee, so allocate a Vec of the struct
            // and use it as a byte buffer.
            let count = (size as usize).div_ceil(std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>());
            let mut buf: Vec<IP_ADAPTER_ADDRESSES_LH> = Vec::with_capacity(count.max(1));
            let ptr = buf.as_mut_ptr();

            // SAFETY: `ptr` is a valid, properly aligned allocation of at
            // least `size` bytes (count * size_of rounds up). The API
            // either fills it and returns NO_ERROR, or writes nothing and
            // returns ERROR_BUFFER_OVERFLOW with the needed size in
            // `size`. We only read the buffer in the NO_ERROR case.
            let rc = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC.0 as u32,
                    flags,
                    Some(std::ptr::null_mut::<c_void>()),
                    Some(ptr),
                    &mut size,
                )
            };

            match windows::Win32::Foundation::WIN32_ERROR(rc) {
                NO_ERROR => {
                    // SAFETY: the call succeeded, so the API wrote a
                    // NULL-terminated linked list starting at `ptr`.
                    return Ok(unsafe { walk_adapters(ptr) });
                }
                ERROR_BUFFER_OVERFLOW => {
                    // `size` now holds the required length; loop and retry.
                    continue;
                }
                other => {
                    return Err(format!("GetAdaptersAddresses failed: {}", other.0));
                }
            }
        }
        Err(format!(
            "GetAdaptersAddresses did not settle in {MAX_ATTEMPTS} attempts"
        ))
    }

    /// SAFETY: `head` must be either null or the start of a valid
    /// NULL-terminated `IP_ADAPTER_ADDRESSES_LH` list written by
    /// `GetAdaptersAddresses`, and must outlive this call.
    unsafe fn walk_adapters(head: *const IP_ADAPTER_ADDRESSES_LH) -> Vec<IpAddr> {
        let mut out = Vec::new();
        let mut adapter = head;
        while !adapter.is_null() {
            let a = unsafe { &*adapter };

            // Only adapters that are actually up. A disconnected NIC keeps
            // its stale DNS servers in the table, and forwarding to them
            // just burns the upstream timeout on every query.
            let usable = a.OperStatus == IfOperStatusUp
                && a.IfType != IF_TYPE_SOFTWARE_LOOPBACK;
            if usable {
                let mut dns = a.FirstDnsServerAddress;
                while !dns.is_null() {
                    let d = unsafe { &*dns };
                    if let Some(ip) = unsafe { sockaddr_to_ip(d.Address.lpSockaddr as *const _) } {
                        out.push(ip);
                    }
                    dns = d.Next;
                }
            }
            adapter = a.Next;
        }
        out
    }

    /// SAFETY: `sa` must be null or point to a valid `SOCKADDR` whose
    /// `sa_family` correctly describes the storage behind it.
    unsafe fn sockaddr_to_ip(sa: *const windows::Win32::Networking::WinSock::SOCKADDR) -> Option<IpAddr> {
        if sa.is_null() {
            return None;
        }
        let family = unsafe { (*sa).sa_family };
        if family == AF_INET {
            let v4 = unsafe { &*(sa as *const SOCKADDR_IN) };
            // S_un is a union of byte/word/dword views of the same 4 bytes.
            let octets = unsafe { v4.sin_addr.S_un.S_addr }.to_ne_bytes();
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        } else if family == AF_INET6 {
            let v6 = unsafe { &*(sa as *const SOCKADDR_IN6) };
            let octets = unsafe { v6.sin6_addr.u.Byte };
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        } else {
            None
        }
    }

    /// RAII token for a `NotifyIpInterfaceChange` registration. Held by
    /// the watcher task; dropping it cancels the registration.
    pub struct ChangeSubscription {
        handle: HANDLE,
    }

    // SAFETY: `HANDLE` is a plain pointer value naming process-global
    // iphlpapi state — it is not thread-affine, and the callback context
    // (the leaked sender) stays valid for the life of the process, so
    // moving this token into the watcher task moves nothing thread-bound.
    unsafe impl Send for ChangeSubscription {}

    impl Drop for ChangeSubscription {
        fn drop(&mut self) {
            // SAFETY: `handle` came from a successful
            // `NotifyIpInterfaceChange` and is cancelled exactly once,
            // here. The windows crate exposes `CancelMibChangeNotify2`,
            // which is what the `CancelIpInterfaceChangeNotify` macro maps
            // to. The callback context was LEAKED, so a callback already
            // in flight cannot touch freed memory no matter how it races
            // this cancellation.
            unsafe {
                let _ = CancelMibChangeNotify2(self.handle);
            }
        }
    }

    /// Register `tx` to be signalled on every IP interface change.
    ///
    /// The sender is `Box::leak`ed and handed to iphlpapi as the callback
    /// context. Leaking is deliberate: `CancelMibChangeNotify2`'s
    /// documentation does not state whether a callback already in flight
    /// has returned when the call completes, so freeing the box on drop
    /// would open a use-after-free window in a service. One leaked
    /// `Sender` per subscription — and subscriptions are created once per
    /// daemon start — is the cheap direction.
    pub fn subscribe_interface_changes(
        tx: mpsc::Sender<()>,
    ) -> Result<ChangeSubscription, String> {
        let ctx = Box::leak(Box::new(tx));
        let ctx_ptr = ctx as *mut mpsc::Sender<()>;
        let mut handle = HANDLE::default();
        // SAFETY: `ctx_ptr` points at the live, never-freed sender leaked
        // above, so it is valid for every callback this registration can
        // ever make. `handle` is valid out-memory for the duration of the
        // call. AF_UNSPEC subscribes for both address families;
        // initial_notification = false because the service resolves once
        // at startup before spawning the watcher — an initial notification
        // would only re-resolve the same list.
        let rc = unsafe {
            NotifyIpInterfaceChange(
                AF_UNSPEC,
                Some(on_interface_change),
                Some(ctx_ptr.cast::<c_void>()),
                false,
                &mut handle,
            )
        };
        if rc != NO_ERROR {
            // SAFETY: the registration failed, so no callback can ever
            // receive this pointer; reclaiming the leaked box is safe.
            unsafe { drop(Box::from_raw(ctx_ptr)) };
            return Err(format!("NotifyIpInterfaceChange failed: {}", rc.0));
        }
        Ok(ChangeSubscription { handle })
    }

    /// Called by iphlpapi, on its own thread, when the IP interface table
    /// changes. The discipline is the point: NO allocation, NO locks, NO
    /// logging, NOTHING that can panic — a crash here crashes the service
    /// from a network flap, and blocking here stalls iphlpapi's
    /// notification thread. A `try_send` that finds the channel full is
    /// dropped on purpose: the one pending signal already covers every
    /// change queued behind it.
    unsafe extern "system" fn on_interface_change(
        callercontext: *const c_void,
        _row: *const MIB_IPINTERFACE_ROW,
        _notificationtype: MIB_NOTIFICATION_TYPE,
    ) {
        if callercontext.is_null() {
            return;
        }
        // SAFETY: `callercontext` is the `Box::leak`ed `mpsc::Sender<()>`
        // registered in `subscribe_interface_changes`. Being leaked, it is
        // valid for the rest of the process, so the dereference cannot
        // race `ChangeSubscription`'s drop. The reference is shared and
        // lives only for this call; `try_send` takes `&self`.
        let tx = unsafe { &*callercontext.cast::<mpsc::Sender<()>>() };
        let _ = tx.try_send(());
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    pub fn enumerate_dns_servers() -> Result<Vec<IpAddr>, String> {
        Err("adapter DNS discovery is only implemented on Windows".into())
    }

    /// Never constructed: the subscription is Windows-only, matching
    /// discovery itself. The watcher falls back to polling when
    /// `subscribe_interface_changes` errors, which here is always.
    pub struct ChangeSubscription;

    pub fn subscribe_interface_changes(
        _tx: mpsc::Sender<()>,
    ) -> Result<ChangeSubscription, String> {
        Err("interface-change subscription is only implemented on Windows".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listen53() -> SocketAddr {
        "127.0.0.1:53".parse().unwrap()
    }

    /// THE defect this filter exists for. A machine that has ever run a
    /// local resolver keeps 127.0.0.1 as its adapter DNS; forwarding there
    /// while we ARE 127.0.0.1:53 turns one client query into a
    /// pool-saturating storm against ourselves.
    #[test]
    fn our_own_listen_address_is_never_an_upstream() {
        let raw = vec![
            "127.0.0.1".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
        ];
        let kept = filter_usable(raw, listen53());
        assert_eq!(kept, vec!["192.168.1.1:53".parse::<SocketAddr>().unwrap()]);
    }

    /// REGRESSION. The filter used to compare against `listen` for exact
    /// equality, so a leftover `::1` or `127.0.0.2` adapter entry survived
    /// discovery — and `Proxy::bind` then rejected the ENTIRE list on it,
    /// taking the usable LAN resolver down with it. Web protection reported
    /// BindFailed on a machine whose DNS was perfectly serviceable.
    ///
    /// Both shapes are ordinary leftovers: removing dnscrypt-proxy /
    /// AdGuard Home / a host Pi-hole leaves loopback DNS configured on both
    /// families, and every address in 127/8 is loopback.
    #[test]
    fn any_loopback_alias_on_our_port_is_dropped_not_the_whole_list() {
        for leftover in ["::1", "127.0.0.2", "127.44.0.9"] {
            let raw = vec![
                leftover.parse().unwrap(),
                "192.168.1.1".parse().unwrap(),
            ];
            let kept = filter_usable(raw, listen53());
            assert_eq!(
                kept,
                vec!["192.168.1.1:53".parse::<SocketAddr>().unwrap()],
                "{leftover}: dnsguard would refuse the whole list over this entry"
            );
        }
    }

    /// The filter and `dnsguard::proxy::validate_upstreams` are one rule in
    /// two places, and the narrower one runs first. Anything this predicate
    /// calls safe must still be safe there.
    #[test]
    fn the_self_reference_test_matches_dnsguards() {
        let listen: SocketAddr = "127.0.0.1:53".parse().unwrap();
        for refused in ["127.0.0.1:53", "127.0.0.2:53", "[::1]:53"] {
            assert!(
                is_self_referential(refused.parse().unwrap(), listen),
                "{refused} is refused by dnsguard at bind"
            );
        }
        for allowed in ["127.0.0.1:5353", "192.168.1.1:53", "[2001:db8::1]:53"] {
            assert!(
                !is_self_referential(allowed.parse().unwrap(), listen),
                "{allowed} is accepted by dnsguard and must not be dropped here"
            );
        }
        // A wildcard listener receives loopback traffic, so dnsguard treats
        // loopback-on-the-listen-port as self-referential there too.
        let wildcard: SocketAddr = "0.0.0.0:53".parse().unwrap();
        assert!(is_self_referential("127.0.0.1:53".parse().unwrap(), wildcard));
        // Port 0 means the port is not chosen yet: only identity counts.
        let ephemeral: SocketAddr = "127.0.0.1:0".parse().unwrap();
        assert!(is_self_referential(ephemeral, ephemeral));
        assert!(!is_self_referential("127.0.0.1:53".parse().unwrap(), ephemeral));
    }

    /// A loopback resolver on a DIFFERENT port is a legitimate chained
    /// setup (dnscrypt-proxy on 5353, say) and must survive — dropping it
    /// would break those users for no safety gain.
    #[test]
    fn a_loopback_resolver_on_another_port_is_kept() {
        let listen: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let kept = filter_usable(vec!["127.0.0.1".parse().unwrap()], listen);
        assert_eq!(
            kept,
            vec!["127.0.0.1:53".parse::<SocketAddr>().unwrap()],
            "only the exact self-reference is a loop"
        );
    }

    #[test]
    fn ipv6_site_local_placeholders_are_dropped() {
        let raw = vec![
            "fec0:0:0:ffff::1".parse().unwrap(),
            "fec0:0:0:ffff::2".parse().unwrap(),
            "fec0:0:0:ffff::3".parse().unwrap(),
            "2001:4860:4860::8888".parse().unwrap(),
        ];
        let kept = filter_usable(raw, listen53());
        assert_eq!(
            kept,
            vec!["[2001:4860:4860::8888]:53".parse::<SocketAddr>().unwrap()],
            "the three Windows placeholders must not become upstreams"
        );
    }

    #[test]
    fn unspecified_and_multicast_are_dropped() {
        let raw = vec![
            "0.0.0.0".parse().unwrap(),
            "224.0.0.251".parse().unwrap(),
            "9.9.9.9".parse().unwrap(),
        ];
        let kept = filter_usable(raw, listen53());
        assert_eq!(kept, vec!["9.9.9.9:53".parse::<SocketAddr>().unwrap()]);
    }

    /// Link-local resolvers are stale-network fossils (169.254/16 = DHCP
    /// failure, fe80::/10 = interface-scoped) and must be dropped entry by
    /// entry — never taking the usable resolver next to them down.
    #[test]
    fn link_local_resolvers_are_dropped() {
        let raw = vec![
            "169.254.1.1".parse().unwrap(),
            "fe80::1".parse().unwrap(),
            "fe80::a0ff:fe01:2345".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
        ];
        let kept = filter_usable(raw, listen53());
        assert_eq!(
            kept,
            vec!["192.168.1.1:53".parse::<SocketAddr>().unwrap()],
            "link-local entries must not become upstreams"
        );
    }

    /// ULA (fc00::/7) is KEPT: routable site-local space where an internal
    /// resolver is a deliberate deployment, unlike link-local. Dropping it
    /// would un-filter ULA-only networks.
    #[test]
    fn ula_resolvers_are_kept() {
        let raw = vec!["fd00::1".parse().unwrap(), "fc12:3456::53".parse().unwrap()];
        let kept = filter_usable(raw, listen53());
        assert_eq!(
            kept,
            vec![
                "[fd00::1]:53".parse::<SocketAddr>().unwrap(),
                "[fc12:3456::53]:53".parse::<SocketAddr>().unwrap()
            ],
            "ULA is site-local but routable — a legitimate internal resolver"
        );
    }

    /// Round-robin gives each entry an equal share, so a duplicate would
    /// silently double one server's load.
    #[test]
    fn duplicates_collapse_preserving_order() {
        let raw = vec![
            "1.1.1.1".parse().unwrap(),
            "9.9.9.9".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
        ];
        let kept = filter_usable(raw, listen53());
        assert_eq!(
            kept,
            vec![
                "1.1.1.1:53".parse::<SocketAddr>().unwrap(),
                "9.9.9.9:53".parse::<SocketAddr>().unwrap()
            ]
        );
    }

    /// Explicit entries must not be silently replaced by discovery, and
    /// discovery failing must not discard them.
    #[test]
    fn explicit_upstreams_survive_a_failed_discovery() {
        let out = resolve(
            &["system".into(), "9.9.9.9:53".into()],
            "127.0.0.1:53".parse().unwrap(),
        );
        // Discovery may or may not find anything on the build machine; the
        // explicit entry must be present either way.
        let out = out.expect("an explicit upstream must keep the config usable");
        assert!(
            out.contains(&"9.9.9.9:53".parse::<SocketAddr>().unwrap()),
            "explicit upstream dropped: {out:?}"
        );
    }

    #[test]
    fn only_loopback_reports_the_actionable_error() {
        // filter_usable drops it; discover() turns that into the error
        // that names the fix rather than a bare "none configured".
        let kept = filter_usable(vec!["127.0.0.1".parse().unwrap()], listen53());
        assert!(kept.is_empty());
        let e = DiscoveryError::OnlyLoopback { dropped: 1 };
        assert!(
            e.to_string().contains("set web_protection.upstreams explicitly"),
            "the error must tell the operator what to do: {e}"
        );
    }

    /// Real discovery against the live machine. IGNORED by default because
    /// it asserts on whatever this box's adapters happen to say — but it is
    /// the only thing that exercises the unsafe FFI, so run it by hand when
    /// touching `platform`:
    ///
    ///   cargo test -p sentinelld real_discovery -- --ignored --nocapture
    #[test]
    #[ignore = "environment-dependent: exercises the live GetAdaptersAddresses FFI"]
    fn real_discovery_against_this_machine() {
        match discover(listen53()) {
            Ok(found) => {
                println!("discovered {} upstream(s):", found.len());
                for a in &found {
                    println!("  {a}");
                }
                assert!(!found.is_empty());
                for a in &found {
                    assert_eq!(a.port(), 53, "adapter DNS is always port 53");
                    assert_ne!(*a, listen53(), "self-reference must never survive");
                }
            }
            Err(e) => println!("no usable upstreams on this machine: {e}"),
        }
    }

    /// No hardcoded public resolver, ever: an empty result is an error,
    /// not a silent substitution.
    #[test]
    fn empty_configured_list_is_an_error_not_a_default() {
        let out = resolve(&[], "127.0.0.1:53".parse().unwrap());
        assert!(matches!(out, Err(DiscoveryError::NoneConfigured)));
    }

    // ------------------------------------------------------------------
    // BurstCoalescer
    // ------------------------------------------------------------------

    /// One signal arms the window; more signals inside it are absorbed
    /// without moving the deadline, and firing disarms. This is the
    /// "one re-resolve per burst" property.
    #[test]
    fn a_burst_collapses_to_one_fire_at_the_settle_deadline() {
        let base = Instant::now();
        let settle = Duration::from_secs(2);
        let mut c = BurstCoalescer::new(settle);
        assert_eq!(c.due(), None, "no events, nothing due");

        c.signal(base);
        assert_eq!(c.due(), Some(base + settle));

        c.signal(base + Duration::from_millis(500));
        c.signal(base + Duration::from_millis(1999));
        assert_eq!(
            c.due(),
            Some(base + settle),
            "events inside the window must be absorbed, not extend it"
        );

        c.fired();
        assert_eq!(c.due(), None, "fired means nothing pending");
    }

    /// A flapping interface produces an ENDLESS stream of events spaced
    /// closer than the settle window. A debounce (extend on every event)
    /// would never fire; this coalescer must fire no later than `settle`
    /// after the first event — stale upstreams for 2 s during a flap is
    /// fine, stale forever is the outage this subsystem exists to kill.
    #[test]
    fn a_continuous_storm_still_fires_within_one_settle_window() {
        let base = Instant::now();
        let settle = Duration::from_secs(2);
        let mut c = BurstCoalescer::new(settle);
        for i in 0..100 {
            c.signal(base + Duration::from_millis(i * 100));
        }
        assert_eq!(c.due(), Some(base + settle));
    }

    /// After a fire, the next event starts a NEW window from its own
    /// arrival — at most one re-resolve per settle window, indefinitely.
    #[test]
    fn after_firing_the_next_event_arms_a_fresh_window() {
        let base = Instant::now();
        let mut c = BurstCoalescer::new(Duration::from_secs(2));
        c.signal(base);
        c.fired();
        c.signal(base + Duration::from_secs(5));
        assert_eq!(c.due(), Some(base + Duration::from_secs(7)));
    }

    /// The live FFI check: register a real subscription against this
    /// machine's iphlpapi and drop it, proving the register/cancel path
    /// runs cleanly. Requires Windows with a working network stack (any
    /// normal install). Actually TRIGGERING the callback needs a network
    /// change, which a unit test cannot stage — the callback body is a
    /// `try_send` and nothing else, and storm behaviour is covered by the
    /// BurstCoalescer tests above.
    ///
    ///   cargo test -p sentinelld subscription_registers -- --ignored
    #[cfg(windows)]
    #[test]
    #[ignore = "live FFI: registers against the real iphlpapi notification surface"]
    fn subscription_registers_and_cancels_cleanly() {
        let (tx, _rx) = mpsc::channel(1);
        let sub = platform::subscribe_interface_changes(tx)
            .expect("NotifyIpInterfaceChange registers on any working Windows network stack");
        drop(sub); // must not hang or crash; cancellation is synchronous
    }
}
