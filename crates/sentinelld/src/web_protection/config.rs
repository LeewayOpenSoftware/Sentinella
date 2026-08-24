//! `[web_protection]` configuration.
//!
//! POLARITY WARNING, read before changing anything here. Every other
//! config section in this crate has the property that turning a field OFF
//! is the harm — an attacker disabling realtime protection, say. This
//! section is the opposite: **turning it ON when the proxy cannot serve is
//! the harm, and turning it OFF is the emergency fix.** A DNS proxy the
//! machine has been pointed at, which is not answering, is a machine with
//! no name resolution at all. Design principle, from the review that
//! produced this module: *under any uncertainty the system must degrade to
//! "no filtering", never to "no DNS".*
//!
//! That is why `validate` here does NOT follow the crate's usual
//! clamp-and-warn convention. Resetting a malformed `listen` to a
//! plausible default (the pattern used by `update_mirror`,
//! `clamav_isolation`, `sandbox.mode` and friends) would leave the section
//! looking configured and let `rule::install` put an NRPT rule in on the
//! strength of it. Invalid input FORCES `enabled = false`, following the
//! one existing precedent that does the same — developer mode without a
//! provisioned password.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use tracing::warn;

/// What the proxy answers for a blocked name.
///
/// Mirrors `dnsguard::proxy::BlockResponse`; kept as a string in TOML so
/// the config surface does not depend on the crate's enum layout.
pub const BLOCK_RESPONSE_NXDOMAIN: &str = "nxdomain";
pub const BLOCK_RESPONSE_ZERO_IP: &str = "zero_ip";

// on_proxy_failure USED TO LIVE HERE, with values "remove_rule" and
// "fallback". It has been REMOVED, and the option must not come back in
// that shape.
//
// "fallback" was documented as "fail open: unfiltered DNS via the NRPT
// secondary". There is no NRPT secondary. The rule this daemon installs
// carries exactly ONE server - our own proxy (see rule.rs) - and an NRPT
// rule overrides the adapter's DNS configuration for every matching name.
// That is the entire purpose of NRPT. So leaving the rule in place when
// the proxy has died does not yield unfiltered DNS; it yields NO DNS.
//
// The polarity was therefore inverted: the option a careful operator picks
// BECAUSE it sounds like the safe one was the one that broke the machine.
// A single-server catch-all rule has no coherent "fail open" mode, so
// there is nothing to choose between and the key is gone.
//
// Making it real would mean writing the discovered system upstreams into
// GenericDNSServers as additional entries - at which cost the DNS Client
// would use them OPPORTUNISTICALLY while the proxy is healthy, which is a
// silent filtering bypass. That trade is worse than not having the option.

/// The only port an NRPT rule can route to: `NameServers` has no port
/// syntax, so the Windows DNS Client always queries 53.
pub const DNS_PORT: u16 = 53;

/// Upstream source: `"system"` means discover from the active adapters.
pub const UPSTREAM_SYSTEM: &str = "system";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebProtectionConfig {
    /// USER INTENT — not a statement about the world.
    ///
    /// This is deliberately NOT the same thing as "an NRPT rule is
    /// installed". The two are tracked separately because they come apart
    /// constantly and in normal operation: while the daemon is starting,
    /// after a failed self-test, after a crash, during an upgrade, during
    /// an MSI rollback. Deriving either from the other is how a machine
    /// ends up believing it is protected while its DNS is broken, or the
    /// reverse. The runtime fact lives in
    /// [`super::status::WebProtectionStatus::nrpt_installed`] and is read
    /// from the system, never from this field.
    pub enabled: bool,

    /// Address the proxy listens on. MUST be IPv4 loopback on port 53 when
    /// `enabled`: NRPT `NameServers` carries no port syntax, so the DNS
    /// Client always queries 53, and the rule records only the IP; and
    /// every health probe in the stack — self-test, watchdog, boot
    /// reconciler — is AF_INET, so an IPv6 listener can never be proven
    /// healthy. Anything else forces `enabled = false` — see
    /// [`Self::validate`].
    pub listen: String,

    /// `"system"` to discover from active adapters, or explicit
    /// `IP:port` entries. An empty list with `listen`-relative discovery
    /// failing is a hard disable: a resolver with no upstream is a lie.
    pub upstreams: Vec<String>,

    /// `"nxdomain"` (default) or `"zero_ip"`.
    pub block_response: String,

    /// Name the self-test resolves to prove the serving path works.
    /// MUST be a name you never intend to block: the self-test requires
    /// the engine to decide it `Allow`, because a `zero_ip` block answer
    /// is NOERROR-with-an-A-record and is otherwise indistinguishable
    /// from a real resolution.
    pub health_check_name: String,

    /// Extra blocklist files to load at startup, beyond the built-in
    /// canary. Each entry is `path` or `path|suffix` — the per-source
    /// exact/suffix policy is a property of the SOURCE, never of the data
    /// (design §4), and `suffix` is correct only for dedicated
    /// malware-domain feeds.
    pub blocklists: Vec<String>,

    /// Allowlist entries in config syntax: a bare name is an exact-host
    /// rule, a leading dot (`.example.com`) is a suffix rule.
    pub allowlist: Vec<String>,

    /// Record per-query decisions for the authenticated IPC surface.
    /// Off by default — this is browsing history.
    pub log_queries: bool,
}

impl Default for WebProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "127.0.0.1:53".into(),
            upstreams: vec![UPSTREAM_SYSTEM.into()],
            block_response: BLOCK_RESPONSE_NXDOMAIN.into(),
            health_check_name: "example.com".into(),
            blocklists: Vec::new(),
            allowlist: Vec::new(),
            log_queries: false,
        }
    }
}

impl WebProtectionConfig {
    /// Validate, forcing `enabled = false` on anything malformed.
    ///
    /// Every branch that disables says WHY at `warn!` level, because the
    /// user's visible symptom is "I turned it on and nothing happened" and
    /// the log is the only place that distinguishes the causes.
    pub fn validate(&mut self) {
        // Non-enabling fields are clamped as usual; only the ones that
        // could produce a live-but-wrong proxy force a disable.
        if !matches!(
            self.block_response.as_str(),
            BLOCK_RESPONSE_NXDOMAIN | BLOCK_RESPONSE_ZERO_IP
        ) {
            warn!(
                value = %self.block_response,
                "web_protection.block_response invalid — using nxdomain"
            );
            self.block_response = BLOCK_RESPONSE_NXDOMAIN.into();
        }
        if !self.enabled {
            return;
        }

        // From here down, every failure DISABLES rather than substitutes.
        if let Err(reason) = self.check_enablable() {
            warn!(%reason, "web_protection.enabled=true but the config cannot serve — disabling");
            self.enabled = false;
        }
    }

    /// The conditions under which `enabled = true` can be honoured.
    /// Split out so it is testable without going through `warn!`.
    ///
    /// `pub(crate)` because `protection.set_critical` runs this as a
    /// composite gate on the merged section: an IPC write whose RESULT is
    /// `enabled = true` with an unservable config is rejected with this
    /// reason instead of being saved and then silently force-disabled by
    /// [`Self::validate`].
    pub(crate) fn check_enablable(&self) -> Result<(), String> {
        let addr: SocketAddr = self
            .listen
            .parse()
            .map_err(|_| format!("listen {:?} is not a valid IP:port", self.listen))?;
        if !addr.ip().is_loopback() {
            // A non-loopback listener turns the AV into an open resolver
            // for the whole network.
            return Err(format!("listen {addr} is not a loopback address"));
        }
        // IPv4 LOOPBACK, EXACTLY. `[::1]:53` is loopback and on port 53, so
        // it used to pass here — and then could never work, because every
        // probe in the stack is AF_INET and cannot send to an AF_INET6
        // address: dnsguard's self-test binds
        // `UdpSocket::bind(Ipv4Addr::LOCALHOST:0)` before probing the
        // listener, the watchdog binds `127.0.0.1:0`, and the boot
        // reconciler has `127.0.0.1:53` compiled in (it must not read our
        // config, or it could be pointed away from the thing it checks).
        // The visible symptom was SelfTestFailed forever with nothing in
        // the detail naming the address family. Refusing here says why.
        if !addr.is_ipv4() {
            return Err(format!(
                "listen {addr} is IPv6 - the self-test, the watchdog and the boot reconciler all \
                 probe over IPv4 loopback, so an IPv6 listener can never be proven healthy. \
                 Use 127.0.0.1:{DNS_PORT}"
            ));
        }
        // PORT 53, EXACTLY. NRPT `NameServers` carries no port syntax, so
        // the Windows DNS Client always queries 53 - and `install` writes
        // only the IP into the rule, discarding whatever port we bound.
        // Listening anywhere else therefore installs a rule pointing at a
        // port with nothing on it, and the watchdog would not notice
        // because it probes the address we BOUND, not the one the DNS
        // Client uses. Every other port is refused here, and `install`
        // refuses again as a second gate.
        if addr.port() != DNS_PORT {
            return Err(format!(
                "listen port {} cannot be reached through NRPT - it carries no port syntax, \
                     so the DNS Client always queries {DNS_PORT}",
                addr.port()
            ));
        }

        if self.upstreams.is_empty() {
            return Err("upstreams is empty — a resolver with no upstream is a lie".into());
        }
        for u in &self.upstreams {
            if u == UPSTREAM_SYSTEM {
                continue;
            }
            let up: SocketAddr = u
                .parse()
                .map_err(|_| format!("upstream {u:?} is not a valid IP:port"))?;
            // Self-reference is an infinite loop that saturates the
            // in-flight pool on the first query. dnsguard refuses it at
            // bind too; catching it here gives a better message and keeps
            // the daemon from starting a proxy it knows is broken.
            if up == addr {
                return Err(format!("upstream {up} is the listen address"));
            }
        }

        if self.health_check_name.trim().is_empty() {
            return Err("health_check_name is empty".into());
        }
        if self.health_check_name.contains('\\') {
            // dnsguard's query builder is escape-unaware, so a backslash
            // would silently probe a different name than configured.
            return Err(format!(
                "health_check_name {:?} contains a backslash escape",
                self.health_check_name
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled() -> WebProtectionConfig {
        WebProtectionConfig {
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn default_is_off_and_survives_validation() {
        let mut c = WebProtectionConfig::default();
        c.validate();
        assert!(!c.enabled);
        assert_eq!(c.listen, "127.0.0.1:53");
        assert_eq!(c.upstreams, vec![UPSTREAM_SYSTEM.to_string()]);
    }

    #[test]
    fn a_valid_enabled_config_stays_enabled() {
        let mut c = enabled();
        c.validate();
        assert!(c.enabled, "a valid config must not be disabled");
    }

    /// The whole point of this module: malformed input must DISABLE, not
    /// be substituted into something that looks configured. The crate's
    /// usual convention would turn each of these into a working-looking
    /// proxy that `rule::install` would put an NRPT rule in for.
    #[test]
    fn malformed_input_disables_rather_than_substituting() {
        type Mutate = fn(&mut WebProtectionConfig);
        let cases: &[(&str, Mutate)] = &[
            ("garbage listen", |c| c.listen = "not-an-address".into()),
            ("non-loopback listen", |c| c.listen = "0.0.0.0:53".into()),
            ("port 0", |c| c.listen = "127.0.0.1:0".into()),
            ("non-53 port", |c| c.listen = "127.0.0.1:5353".into()),
            ("empty upstreams", |c| c.upstreams.clear()),
            ("garbage upstream", |c| c.upstreams = vec!["1.1.1.1".into()]),
            ("self-referential upstream", |c| {
                c.upstreams = vec!["127.0.0.1:53".into()]
            }),
            ("empty health name", |c| c.health_check_name = "  ".into()),
            ("escaped health name", |c| {
                c.health_check_name = "ex\\ample.com".into()
            }),
        ];
        for (name, mutate) in cases {
            let mut c = enabled();
            mutate(&mut c);
            c.validate();
            assert!(!c.enabled, "{name}: must force enabled=false");
            // And it must NOT have been silently rewritten into something
            // that would pass a second validate().
            let before = c.clone();
            c.validate();
            assert!(!c.enabled, "{name}: must stay disabled");
            assert_eq!(before.listen, c.listen, "{name}: no silent substitution");
        }
    }

    /// `system` is the default upstream and must not be mistaken for a
    /// malformed address.
    #[test]
    fn system_upstream_is_not_an_address() {
        let mut c = enabled();
        c.upstreams = vec![UPSTREAM_SYSTEM.into(), "9.9.9.9:53".into()];
        c.validate();
        assert!(c.enabled);
    }

    /// `block_response` DOES follow the crate's clamp convention: it cannot
    /// produce a live-but-wrong proxy, only a differently-shaped answer.
    #[test]
    fn block_response_clamps_without_disabling() {
        let mut c = enabled();
        c.block_response = "explode".into();
        c.validate();
        assert!(c.enabled, "an unknown enum value must not disable the feature");
        assert_eq!(c.block_response, BLOCK_RESPONSE_NXDOMAIN);
    }

    /// REGRESSION. A non-53 listen used to survive validation. The rule
    /// records only the IP, so the DNS Client would query 53 where nothing
    /// listens — while the watchdog probed the port we BOUND and reported
    /// healthy. Both doc comments claimed this was already enforced.
    #[test]
    fn only_port_53_can_be_enabled() {
        for bad in ["127.0.0.1:5353", "127.0.0.1:5300", "[::1]:4444", "127.0.0.2:1"] {
            let mut c = enabled();
            c.listen = bad.into();
            c.validate();
            assert!(!c.enabled, "{bad}: NRPT cannot route to a non-53 port");
        }
        // ...and IPv4 loopback:53 stays enabled. 127/8 is all loopback, so
        // an alias is as serviceable as .1.
        for good in ["127.0.0.1:53", "127.0.0.53:53"] {
            let mut c = enabled();
            c.listen = good.into();
            c.validate();
            assert!(c.enabled, "{good}: must remain usable");
        }
    }

    /// REGRESSION. `[::1]:53` used to validate — it is loopback and it is
    /// port 53 — and could then never serve: dnsguard's self-test probes
    /// the listener from an AF_INET socket, so `canary_ok` and `filter_ok`
    /// are false whatever the proxy does, and `service.rs` refuses to serve
    /// on a failed self-test. The old test asserted only that `enabled`
    /// survived validation, which it did, all the way to a permanent
    /// SelfTestFailed.
    #[test]
    fn an_ipv6_listener_cannot_be_enabled() {
        // `::1` is refused as IPv6; the IPv4-mapped form is refused one
        // check earlier, because `Ipv6Addr::is_loopback` is true only for
        // `::1`. Both must end up disabled.
        for v6 in ["[::1]:53", "[::ffff:127.0.0.1]:53"] {
            let mut c = enabled();
            c.listen = v6.into();
            c.validate();
            assert!(!c.enabled, "{v6}: must not be enabled");
        }
        // The refusal has to name the cause: "it stopped working" with no
        // mention of the address family is the whole failure being fixed.
        let mut c = enabled();
        c.listen = "[::1]:53".into();
        let why = c.check_enablable().expect_err("must refuse");
        assert!(why.contains("IPv6"), "the reason must name the cause: {why}");
    }
}
