import { useState, useEffect } from "react";
import {
  AlertTriangle, CheckCircle, Globe, HelpCircle, Info,
  Loader2, PowerOff, Server, WifiOff, XCircle,
} from "lucide-react";
import { Card } from "../components/Card";
import { getWebProtectionStatus } from "../api/sentinella";
import type { ProxyState, WebProtectionStatus } from "../types/sentinella";
import { t } from "../i18n";

const STATE_META: Record<ProxyState, { labelKey: string; color: string }> = {
  serving: { labelKey: "wp.state_serving", color: "var(--green)" },
  bind_failed: { labelKey: "wp.state_bind_failed", color: "var(--red)" },
  self_test_failed: { labelKey: "wp.state_self_test_failed", color: "var(--amber)" },
  disabled: { labelKey: "wp.state_disabled", color: "var(--t3)" },
};

/** Unknown future ProxyState variant — a newer daemon must never white-screen this page. */
const FALLBACK_META = { labelKey: "wp.state_unknown", color: "var(--t3)" };

/**
 * The hero card's true state, which is NOT always `s.state`.
 *
 * `s.state` describes the PROXY LISTENER only (bind/self-test/serving) —
 * it says nothing about whether the NRPT rule is actually installed right
 * now. After the watchdog fires and removes the rule, the listener can
 * still legitimately report `serving` (the process is up and healthy),
 * which would render a reassuring green "Serving" headline over a machine
 * that is, right now, not filtering anything — the exact contradiction
 * the Track C UI audit flagged for TopBar vs Scan. `off` and `watchdog`
 * are computed FIRST and take priority over the raw `state` lookup so the
 * headline always matches what's actually true.
 */
type Hero = { kind: "off" } | { kind: "watchdog" } | { kind: "state"; state: ProxyState };

function deriveHero(s: WebProtectionStatus): Hero {
  if (!s.enabled) return { kind: "off" };
  if (s.watchdog_fired) return { kind: "watchdog" };
  return { kind: "state", state: s.state };
}

/**
 * DaemonError's Display (gui/src-tauri/src/daemon_client.rs) formats RPC
 * failures as "RPC error {code}: {message}"; no numeric code is plumbed
 * through invoke, so the page matches on that stable prefix. -32601 is
 * "unknown method" — the daemon predates webprotection.status.
 */
function isUnknownMethodError(err: string): boolean {
  return err.includes("RPC error -32601");
}

/**
 * Web protection status page. READ-ONLY in this wave: the daemon accepts
 * web_protection.* mutations through protection.set_critical, but every
 * field is DaemonRestart-classified (nothing hot-applies) and no toggle
 * UI is built here yet — the footer card still points at sentinelld.toml
 * + daemon restart instead of offering a dead toggle.
 *
 * The page renders INTENT (`enabled`, what config asked for) and FACT
 * (`nrpt_installed`, whether the system DNS rule exists right now) as
 * separate elements. `nrpt_installed === null` is "the daemon could not
 * tell" and gets its own rendering — coercing it to false would claim
 * "no rule installed" when we simply do not know.
 */
export function WebProtectionPage() {
  const [status, setStatus] = useState<WebProtectionStatus | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStatus = () => {
      getWebProtectionStatus()
        .then((s) => { setStatus(s); setErr(null); })
        .catch((e) => setErr(String(e)))
        .finally(() => setLoading(false));
    };
    fetchStatus();
    const interval = setInterval(fetchStatus, 10_000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !status) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 size={20} className="text-[rgb(var(--accent))] animate-spin" />
      </div>
    );
  }

  if (err && !status) {
    // The daemon WAS reached but predates webprotection.status — say so
    // instead of the generic "could not reach" lie.
    const outdated = isUnknownMethodError(err);
    return (
      <Card className="text-center py-10">
        <WifiOff size={20} className="mx-auto text-[rgb(var(--amber))] mb-3" />
        <p className="text-[13px] text-[rgb(var(--t3))]">
          {t(outdated ? "wp.error_outdated" : "wp.error")}
        </p>
      </Card>
    );
  }

  const s = status!;
  const hero = deriveHero(s);
  // `?? FALLBACK_META`: STATE_META covers today's four ProxyState variants;
  // a newer daemon can add one, and indexing it must not throw during render.
  const stateMeta = STATE_META[s.state] ?? FALLBACK_META;
  const cv = hero.kind === "off" ? "var(--t3)" : hero.kind === "watchdog" ? "var(--amber)" : stateMeta.color;
  const heroTitle = hero.kind === "off" ? t("wp.off_title") : hero.kind === "watchdog" ? t("wp.watchdog_title") : t(stateMeta.labelKey);
  const heroIcon = hero.kind === "off" ? <PowerOff size={26} /> : hero.kind === "watchdog" ? <AlertTriangle size={26} /> : <Globe size={26} />;
  // Off/watchdog get their own explanatory copy; every other state keeps
  // showing the daemon's own `detail` string, same as before.
  const heroDesc = hero.kind === "off" ? t("wp.off_desc") : hero.kind === "watchdog" ? t("wp.watchdog_desc") : s.detail;

  return (
    <div className="page-stack">
      {/* State header — what the listener is doing, plus user intent.
          Uses `hero`, not raw `s.state`, so a watchdog-removed rule never
          reads as a reassuring green "Serving" (see deriveHero above). */}
      <Card className={`border-[rgb(${cv})]/12`}>
        <div className="flex items-start gap-5">
          <div
            className="flex h-14 w-14 flex-shrink-0 items-center justify-center rounded"
            style={{ background: `rgba(${cv}, 0.08)`, color: `rgb(${cv})` }}
          >
            {heroIcon}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex flex-wrap items-center gap-3">
              <h3 className="text-[20px] font-bold" style={{ color: `rgb(${cv})` }}>
                {heroTitle}
              </h3>
              <span className={`text-[10px] px-2.5 py-1 rounded-full ${
                s.enabled
                  ? "bg-[rgb(var(--accent))]/8 text-[rgb(var(--accent))]"
                  : "bg-[rgb(var(--raised))]/20 text-[rgb(var(--t3))]"
              }`}>
                {s.enabled ? t("wp.intent_on") : t("wp.intent_off")}
              </span>
            </div>
            {heroDesc && (
              <p className="text-[13px] text-[rgb(var(--t2))] mt-2 leading-relaxed">{heroDesc}</p>
            )}
            {s.state === "bind_failed" && (
              <div className="flex items-start gap-2 mt-3 rounded-xl bg-[rgb(var(--red))]/5 px-4 py-3">
                <AlertTriangle size={14} className="mt-0.5 flex-shrink-0 text-[rgb(var(--red))]" />
                <p className="text-[12px] leading-relaxed text-[rgb(var(--t2))]">{t("wp.bind_hint")}</p>
              </div>
            )}
            {s.listen && (
              <p className="text-[11px] text-[rgb(var(--t3))] mt-2 font-mono">
                {t("wp.listen")} {s.listen}
              </p>
            )}
          </div>
        </div>
      </Card>

      {/* Everything below reports on a running proxy — while the feature
          is off there is nothing for these to say, and a wall of
          zeroed/empty cards under a big "Web protection is off" headline
          reads as something being broken rather than simply not enabled. */}
      {s.enabled && (
        <>
          {/* GPO NRPT present — the OS evaluates the GPO table INSTEAD of
              local rules, so an installed rule filters NOTHING. `=== true`
              only: null/undefined (could not tell, or an older daemon) must
              never claim this. */}
          {s.gpo_nrpt_present === true && (
            <Card className="border-[rgb(var(--amber))]/25">
              <div className="flex items-start gap-3">
                <AlertTriangle size={16} className="mt-0.5 flex-shrink-0 text-[rgb(var(--amber))]" />
                <div>
                  <p className="text-[13px] font-semibold text-[rgb(var(--amber))]">{t("wp.gpo_title")}</p>
                  <p className="text-[12px] leading-relaxed text-[rgb(var(--t2))] mt-1">{t("wp.gpo_desc")}</p>
                </div>
              </div>
            </Card>
          )}

          {/* Degraded upstreams — named, not just counted (audit finding:
              the aggregate healthy/total count already existed, but which
              specific server was unreachable did not). Filtering itself is
              still active here — this is a partial issue, not the
              watchdog's full-stop case above. */}
          {(s.upstreams_degraded?.length ?? 0) > 0 && (
            <Card className="border-[rgb(var(--amber))]/25">
              <div className="flex items-start gap-3">
                <AlertTriangle size={16} className="mt-0.5 flex-shrink-0 text-[rgb(var(--amber))]" />
                <div className="flex-1 min-w-0">
                  <p className="text-[13px] font-semibold text-[rgb(var(--amber))]">{t("wp.upstreams_degraded_title")}</p>
                  <p className="text-[12px] leading-relaxed text-[rgb(var(--t2))] mt-1">{t("wp.upstreams_degraded_desc")}</p>
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {s.upstreams_degraded!.map((u) => (
                      <span key={u} className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[rgb(var(--amber))]/8 text-[rgb(var(--amber))]">
                        {u}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </Card>
          )}

          {/* NRPT rule — the FACT of whether system DNS goes through us.
              Three states, deliberately: live / absent / unknown. */}
          <Card>
            <h4 className="text-[15px] font-semibold mb-4">{t("wp.nrpt_title")}</h4>
            {s.nrpt_installed === true && (
              <NrptRow
                icon={<CheckCircle size={15} />}
                color="var(--green)"
                title={t("wp.nrpt_live")}
                desc={t("wp.nrpt_live_desc")}
              />
            )}
            {s.nrpt_installed === false && (
              <NrptRow
                icon={<XCircle size={15} />}
                color="var(--amber)"
                title={t("wp.nrpt_absent")}
                desc={t("wp.nrpt_absent_desc")}
              />
            )}
            {s.nrpt_installed === null && (
              <NrptRow
                icon={<HelpCircle size={15} />}
                color="var(--t3)"
                title={t("wp.nrpt_unknown")}
                desc={t("wp.nrpt_unknown_desc")}
              />
            )}
          </Card>

          {/* Filter engine counters */}
          <Card>
            <div className="flex items-center gap-3 mb-5">
              <div className="flex h-8 w-8 items-center justify-center rounded-xl bg-[rgb(var(--accent))]/8">
                <Server size={15} className="text-[rgb(var(--accent))]" />
              </div>
              <div>
                <h4 className="text-[13px] font-semibold">{t("wp.stats_title")}</h4>
                <p className="text-[10px] text-[rgb(var(--t3))] mt-0.5">
                  {s.upstreams_total > 0
                    ? t("wp.upstreams_healthy")
                        .replace("{healthy}", String(s.upstreams_healthy))
                        .replace("{total}", String(s.upstreams_total))
                    : t("common.unavailable")}
                </p>
              </div>
            </div>
            <div className="grid grid-cols-2 xl:grid-cols-5 gap-3">
              <StatBox label={t("wp.rules_loaded")} value={s.rules_loaded.toLocaleString()} />
              <StatBox label={t("wp.queries")} value={s.queries.toLocaleString()} />
              <StatBox label={t("wp.blocked")} value={s.blocked.toLocaleString()} highlight={s.blocked > 0} />
              <StatBox label={t("wp.cache_hits")} value={s.cache_hits.toLocaleString()} />
              <StatBox label={t("wp.upstream_errors")} value={s.upstream_errors.toLocaleString()} warn={s.upstream_errors > 0} />
            </div>
            {s.upstreams.length > 0 && (
              <div className="mt-4">
                <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[rgb(var(--t3))]/40 mb-2">
                  {t("wp.upstreams")}
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {s.upstreams.map((u) => (
                    <span key={u} className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[rgb(var(--raised))]/20 text-[rgb(var(--t3))]">
                      {u}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </Card>
        </>
      )}

      {/* Why there is no toggle here — the truth today. */}
      <Card className="border-[rgb(var(--accent))]/10">
        <div className="flex items-start gap-3">
          <Info size={15} className="mt-0.5 flex-shrink-0 text-[rgb(var(--accent))]" />
          <div>
            <p className="text-[13px] font-semibold">{t("wp.no_toggle_title")}</p>
            <p className="text-[12px] leading-relaxed text-[rgb(var(--t3))] mt-1">{t("wp.no_toggle_note")}</p>
          </div>
        </div>
      </Card>
    </div>
  );
}

function NrptRow({ icon, color, title, desc }: {
  icon: React.ReactNode;
  color: string;
  title: string;
  desc: string;
}) {
  return (
    <div className="flex items-start gap-4 rounded-xl px-4 py-3" style={{ background: `rgba(${color}, 0.05)` }}>
      <div
        className="mt-0.5 flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg"
        style={{ background: `rgba(${color}, 0.1)`, color: `rgb(${color})` }}
      >
        {icon}
      </div>
      <div className="min-w-0 flex-1">
        <p className="text-[13px] font-semibold" style={{ color: `rgb(${color})` }}>{title}</p>
        <p className="mt-1 text-[11px] leading-relaxed text-[rgb(var(--t3))]">{desc}</p>
      </div>
    </div>
  );
}

function StatBox({ label, value, highlight, warn }: {
  label: string;
  value: string;
  highlight?: boolean;
  warn?: boolean;
}) {
  const color = warn ? "var(--amber)" : highlight ? "var(--green)" : "var(--t1)";
  return (
    <div className="rounded-xl bg-[rgb(var(--raised))]/15 px-3.5 py-2.5">
      <p className="text-[10px] text-[rgb(var(--t3))] uppercase tracking-wider">{label}</p>
      <p className="text-[15px] font-bold mt-1" style={{ color: `rgb(${color})` }}>{value}</p>
    </div>
  );
}
