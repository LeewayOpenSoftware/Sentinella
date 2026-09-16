import {
  Activity,
  AlertCircle,
  AlertTriangle,
  Archive,
  CheckCircle,
  Clock,
  Database,
  Eye,
  Globe,
  Loader2,
  RefreshCw,
  Search,
  ShieldOff,
  WifiOff,
  Zap,
} from "lucide-react";
import { useState, useEffect } from "react";
import { Card } from "../components/Card";
import { ShieldIcon } from "../components/ShieldIcon";
import { useDaemonContext } from "../hooks/DaemonContext";
import { startQuickScan, startSignatureUpdate, getRuntimeIntelligence, getTrustStatus, getWebProtectionStatus } from "../api/sentinella";
import { t } from "../i18n";
import type { Page } from "../components/Sidebar";
import type { RuntimeIntelligenceStatus, TrustGraphStatus, WebProtectionStatus } from "../types/sentinella";

export function Dashboard({ onNavigate }: { onNavigate: (p: Page) => void }) {
  const { data, connected, connectionState, loading, error, lastRefresh, refresh } = useDaemonContext();
  // Service alive, pipe not up: the daemon is loading its signature DB.
  // The hero below must read "starting", never "broken" - a fresh install
  // spends minutes here and this is the first screen the user ever sees.
  const starting = connectionState === "service_starting";

  if (loading && !data) {
    return (
      <div className="flex flex-col items-center py-32">
        <Loader2 size={24} className="mb-4 animate-spin text-[rgb(var(--accent))]" />
        <p className="text-[13px] text-[rgb(var(--t3))]">{t("dash.connecting")}</p>
      </div>
    );
  }

  if (!connected && !data) {
    return (
      <div className="page-stack">
        <Card className={starting ? "border-[rgb(var(--accent))]/12" : "border-[rgb(var(--amber))]/12"}>
          <div className="grid gap-6 xl:grid-cols-[minmax(0,1.6fr)_320px] xl:items-start">
            <div className="flex items-start gap-5">
              <div className={`flex h-16 w-16 flex-shrink-0 items-center justify-center rounded ${starting ? "bg-[rgb(var(--accent))]/8 text-[rgb(var(--accent))]" : "bg-[rgb(var(--amber))]/8 text-[rgb(var(--amber))]"}`}>
                {starting ? <Loader2 size={28} className="animate-spin" /> : <WifiOff size={28} />}
              </div>
              <div className="flex min-w-0 flex-col gap-3">
                <h3 className="text-[24px] font-bold leading-tight">{starting ? t("dash.starting") : t("dash.not_connected")}</h3>
                <p className="max-w-xl text-[14px] leading-relaxed text-[rgb(var(--t2))]">
                  {starting ? t("dash.starting_desc") : t("dash.not_connected_desc")}
                </p>
                {!starting && error && (
                  <div className="flex items-center gap-2 text-[12px] text-[rgb(var(--red))]">
                    <AlertCircle size={14} />
                    <span>{error}</span>
                  </div>
                )}
              </div>
            </div>
            <div className="flex flex-col gap-4">
              <div className="rounded border border-[rgb(var(--border))]/15 bg-[rgb(var(--raised))]/25 p-4">
                <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[rgb(var(--t3))]">{t("dash.endpoint")}</p>
                <p className="mt-2 break-all font-mono text-[12px] text-[rgb(var(--t2))]">\\.\pipe\sentinelld</p>
              </div>
              <button
                onClick={refresh}
                className="rounded-xl bg-[rgb(var(--accent))] px-5 py-3 text-[13px] font-semibold text-white shadow-sm shadow-[rgb(var(--accent))]/15 hover:opacity-90 cursor-pointer"
              >
                {t("dash.retry")}
              </button>
            </div>
          </div>
        </Card>

        <div className="card-grid-4">
          <StatusTile
            label={t("tile.realtime")}
            value={t("dash.unavailable")}
            sub={t("dash.watcher_offline")}
            color="amber"
            icon={<Eye size={18} />}
          />
          <StatusTile
            label={t("tile.engine")}
            value={starting ? t("dash.starting_tile") : t("tile.disconnected")}
            sub={starting ? t("dash.loading_signatures") : t("dash.daemon_unreachable")}
            color={starting ? "accent" : "red"}
            icon={starting ? <Loader2 size={18} className="animate-spin" /> : <ShieldOff size={18} />}
          />
          <StatusTile
            label={t("tile.signatures")}
            value={t("common.unknown")}
            sub={t("dash.db_state_unavailable")}
            color="amber"
            icon={<Database size={18} />}
          />
          <StatusTile
            label={t("dash.last_update")}
            value={t("common.never")}
            sub={t("dash.no_sync")}
            color="amber"
            icon={<Clock size={18} />}
          />
        </div>

        <section className="section-stack">
          <div className="flex flex-col gap-2">
            <h4 className="text-[15px] font-semibold">{t("dash.quick_actions")}</h4>
            <p className="text-[12px] text-[rgb(var(--t3))]">{t("dash.quick_actions_offline")}</p>
          </div>
          <div className="card-grid-4">
            <ActionTile
              icon={<Search size={20} />}
              label={t("scan.file")}
              description={t("dash.scan_file_desc")}
              onClick={() => onNavigate("scan")}
            />
            <ActionTile icon={<Zap size={20} />} label={t("scan.quick")} description={t("dash.requires_daemon")} />
            <ActionTile icon={<RefreshCw size={20} />} label={t("nav.update")} description={t("dash.retry_sigs_desc")} />
            <ActionTile
              icon={<Archive size={20} />}
              label={t("scan.quarantine_action")}
              description={t("dash.review_isolated")}
              onClick={() => onNavigate("quarantine")}
            />
          </div>
        </section>
      </div>
    );
  }

  const engine = data!.engine;
  const watcher = data!.watcher;
  const stats = data!.stats;
  const activity = data!.activity;
  const idle = data!.idleScanner;
  const isReady = engine.state === "ready";
  const lastDbUpdate = engine.last_update ? new Date(engine.last_update * 1000).toLocaleString() : t("common.never");
  const lastSeen = lastRefresh ? lastRefresh.toLocaleTimeString() : t("tile.waiting");
  const dbVersion = engine.db_version ? `v${engine.db_version}` : t("dash.unavailable");

  return (
    <div className="page-stack">
      {/* Notifications now live in TopBar — dashboard content starts clean */}

      <Card className={isReady ? "border-[rgb(var(--green))]/12" : "border-[rgb(var(--red))]/12"}>
        <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_auto] xl:items-start">
          {/* Left: status + quick actions */}
          <div>
            <div className="flex items-start gap-4 mb-4">
              <div
                className={`flex h-12 w-12 flex-shrink-0 items-center justify-center rounded ${
                  isReady ? "bg-[rgb(var(--green))]/8 text-[rgb(var(--green))]" : "bg-[rgb(var(--red))]/8 text-[rgb(var(--red))]"
                }`}
              >
                <ShieldIcon icon={isReady ? "protected" : "threat"} size={28} className={`brightness-0 invert ${isReady ? "opacity-80" : "opacity-60"}`} />
              </div>
              <div className="flex min-w-0 flex-col gap-1.5">
                <h3 className="text-[20px] font-bold leading-tight">
                  {isReady ? t("dash.protected") : t("dash.attention")}
                </h3>
                <p className="max-w-lg text-[12px] leading-relaxed text-[rgb(var(--t2))]">
                  {engine.signature_count > 0
                    ? `ARGUS ${t("argus.astra")}. ${t("dash.database_prefix")} ${dbVersion}.`
                    : t("dash.no_sigs_loaded")}
                </p>
                <div className="flex flex-wrap items-center gap-2 text-[10px] text-[rgb(var(--t3))]">
                  <span className="rounded-full bg-[rgb(var(--raised))]/25 px-2 py-0.5">
                    {t("dash.engine_prefix")} {engine.engine_version}
                  </span>
                  <span className="rounded-full bg-[rgb(var(--raised))]/25 px-2 py-0.5">
                    {t("dash.watcher_prefix")} {watcher.mode.replace("_", " ")}
                  </span>
                  {/* v0.1.7 Phase 2 — reload phase pill. Does NOT flip the
                      shield to degraded; the previous engine is still
                      serving scans while the new one compiles. */}
                  {engine.reload_phase === "compiling" || engine.reload_phase === "activating" ? (
                    <span
                      className="rounded-full bg-[rgb(var(--accent))]/15 px-2 py-0.5 text-[rgb(var(--accent))]"
                      title={t("dash.reloading_hint")}
                    >
                      {t("dash.reloading")}
                    </span>
                  ) : null}
                  {engine.reload_phase === "failed" ? (
                    <span
                      className="rounded-full bg-[rgb(var(--amber))]/15 px-2 py-0.5 text-[rgb(var(--amber))]"
                      title={t("dash.reload_failed_hint")}
                    >
                      {t("dash.reload_failed")}
                    </span>
                  ) : null}
                </div>
              </div>
            </div>
            {/* Quick actions — inline with helper */}
            <div className="mt-3">
              <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[rgb(var(--t3))]/40 mb-2">
                {t("dash.quick_actions")}
              </p>
              <div className="flex flex-wrap gap-2">
                <button
                  onClick={() => onNavigate("scan")}
                  className="flex items-center gap-2.5 rounded-xl border border-[rgb(var(--border))]/15 bg-[rgb(var(--surface))] px-4 py-2.5 text-left hover:bg-[rgb(var(--raised))]/25 hover:text-[rgb(var(--t1))] cursor-pointer group"
                >
                  <Search size={14} className="text-[rgb(var(--t3))] group-hover:text-[rgb(var(--t2))]" />
                  <div>
                    <p className="text-[12px] font-medium text-[rgb(var(--t2))]">{t("scan.file")}</p>
                    <p className="text-[9px] text-[rgb(var(--t3))]/50">{t("dash.select_scan_one")}</p>
                  </div>
                </button>
                <button
                  onClick={() => {
                    startQuickScan().catch((e) => console.error("Quick scan failed:", e));
                    onNavigate("scan");
                  }}
                  className="flex items-center gap-2.5 rounded-xl border border-[rgb(var(--accent))]/16 bg-[rgb(var(--accent))]/6 px-4 py-2.5 text-left hover:bg-[rgb(var(--accent))]/10 cursor-pointer"
                >
                  <Zap size={14} className="text-[rgb(var(--accent))]" />
                  <div>
                    <p className="text-[12px] font-semibold text-[rgb(var(--accent))]">{t("scan.quick")}</p>
                    <p className="text-[9px] text-[rgb(var(--accent))]/50">{t("dash.scan_common_folders")}</p>
                  </div>
                </button>
                <button
                  onClick={() => onNavigate("quarantine")}
                  className="flex items-center gap-2.5 rounded-xl border border-[rgb(var(--border))]/15 bg-[rgb(var(--surface))] px-4 py-2.5 text-left hover:bg-[rgb(var(--raised))]/25 hover:text-[rgb(var(--t1))] cursor-pointer group"
                >
                  <Archive size={14} className="text-[rgb(var(--t3))] group-hover:text-[rgb(var(--t2))]" />
                  <div>
                    <p className="text-[12px] font-medium text-[rgb(var(--t2))]">{t("nav.quarantine")}</p>
                    <p className="text-[9px] text-[rgb(var(--t3))]/50">{t("dash.inspect_isolated")}</p>
                  </div>
                </button>
              </div>
            </div>
          </div>
          {/* Right: refresh + database updated with update button */}
          <div className="grid gap-3 xl:min-w-[240px]">
            <HeroDetail label={t("dash.last_refresh")} value={lastSeen} sub={t("dash.ui_heartbeat")} />
            <div className="rounded border border-[rgb(var(--border))]/15 bg-[rgb(var(--raised))]/20 p-3 flex items-center gap-3">
              <div className="flex-1 min-w-0">
                <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[rgb(var(--t3))]">{t("dash.db_updated")}</p>
                <p className="mt-1.5 text-[14px] font-semibold text-[rgb(var(--t1))]">{lastDbUpdate}</p>
                <p className="mt-0.5 text-[10px] text-[rgb(var(--t3))]">{t("dash.last_sync")}</p>
              </div>
              <button
                onClick={() => { startSignatureUpdate().catch(() => {}); }}
                className="flex-shrink-0 w-9 h-9 rounded-xl bg-[rgb(var(--accent))]/8 flex items-center justify-center text-[rgb(var(--accent))] hover:bg-[rgb(var(--accent))]/15 cursor-pointer"
                title={t("update.check")}
              >
                <RefreshCw size={15} />
              </button>
            </div>
          </div>
        </div>
      </Card>

      <div className="card-grid-5">
        <StatusTile
          label={t("tile.realtime")}
          value={watcher.enabled ? t("tile.active") : t("tile.disabled")}
          sub={watcher.enabled ? `${watcher.events_per_sec} ${t("dash.events_per_sec_suffix")}` : t("tile.watcher_inactive")}
          color={watcher.enabled ? "green" : "amber"}
          icon={<Eye size={18} />}
        />
        <StatusTile
          label={t("tile.background")}
          value={idle.state === "disabled" ? t("tile.off")
            : idle.state.startsWith("scanning") ? t("tile.scanning")
            : idle.state.startsWith("paused") ? t("tile.paused")
            : idle.state === "completed" ? t("tile.done")
            : t("tile.waiting")}
          sub={idle.state === "disabled" ? t("dash.idle_disabled")
            : idle.state.startsWith("scanning") ? `${idle.files_scanned_session} ${t("dash.files_suffix")} · ${idle.current_target || "..."}`
            : idle.state.startsWith("paused") ? idle.last_pause_reason.replace("_", " ")
            : idle.state === "completed" ? `${idle.files_scanned_session} ${t("dash.files_checked")}`
            : t("dash.waiting_capacity")}
          color={idle.state === "disabled" ? "amber"
            : idle.state.startsWith("scanning") ? "green"
            : idle.state === "completed" ? "green"
            : "accent"}
          icon={<Search size={18} />}
        />
        <StatusTile
          label={t("tile.argus")}
          value={stats.argus_active_layers > 0 ? `${stats.argus_active_layers} ${t("argus.layers_suffix")}` : t("tile.active")}
          sub={stats.argus_yara_rules > 0
            ? `${stats.argus_yara_rules} ${t("argus.rules_suffix")} · ${stats.argus_files_analyzed} ${t("argus.analyzed_suffix")}`
            : stats.argus_files_analyzed > 0
              ? `${stats.argus_files_analyzed} ${t("argus.files_analyzed_suffix")}`
              : t("argus.heuristic_ready")}
          color="accent"
          icon={<Zap size={18} />}
        />
        <StatusTile
          label={t("tile.signatures")}
          value={engine.signature_count > 0 ? engine.signature_count.toLocaleString() : "0"}
          sub={`${t("dash.database_prefix")} ${dbVersion}`}
          color={engine.signature_count > 0 ? "green" : "amber"}
          icon={<Database size={18} />}
        />
        <WebProtectionTile onNavigate={onNavigate} />
      </div>

      {/* ARGUS + Runtime Intelligence — side by side */}
      <div className="card-grid-2">
        {/* ARGUS Intelligence */}
        <div className="glass-card px-6 py-5">
          <div className="flex items-center gap-3 mb-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-xl bg-[rgb(var(--accent))]/8">
              <Zap size={15} className="text-[rgb(var(--accent))]" />
            </div>
            <div>
              <h4 className="text-[13px] font-semibold">{t("argus.intelligence")} · ASTRA</h4>
              <p className="text-[10px] text-[rgb(var(--t3))] mt-0.5">
                v{stats.argus_version} · {stats.argus_active_layers} {t("argus.layers_suffix")} · {stats.argus_yara_rules} {t("argus.rules_suffix")}
              </p>
            </div>
          </div>
          {stats.argus_yara_rules > 0 && (
            <div className="flex flex-wrap gap-1.5 mb-3">
              {[
                t("argus.pack_stealer"), t("argus.pack_script"), t("argus.pack_deception"),
                t("argus.pack_github"), t("argus.pack_lolbin"), t("argus.pack_documents"),
                t("argus.pack_persistence"),
              ].map((pack) => (
                <span key={pack} className="text-[9px] px-2 py-0.5 rounded-full bg-[rgb(var(--raised))]/20 text-[rgb(var(--t3))] whitespace-nowrap">
                  {pack}
                </span>
              ))}
            </div>
          )}
          {stats.argus_files_analyzed > 0 && (
            <p className="text-[11px] text-[rgb(var(--t3))]">
              {stats.argus_files_analyzed.toLocaleString()} {t("argus.files_analyzed")}
            </p>
          )}
        </div>

        {/* Runtime Intelligence */}
        <RuntimeIntelligenceCard />
      </div>

      {/* Behavioral Familiarity */}
      <BehavioralFamiliarityCard />

      <Card>
        <div className="mb-5 flex items-center justify-between gap-4">
          <div>
            <h4 className="text-[15px] font-semibold">{t("dash.recent_activity")}</h4>
            <p className="mt-1 text-[12px] text-[rgb(var(--t3))]">{t("dash.recent_activity_desc")}</p>
          </div>
          <button
            onClick={() => onNavigate("history")}
            className="rounded-xl border border-[rgb(var(--accent))]/15 px-3 py-2 text-[11px] font-semibold text-[rgb(var(--accent))] hover:bg-[rgb(var(--accent))]/6 cursor-pointer"
          >
            {t("dash.view_history")}
          </button>
        </div>
        {activity.length > 0 ? (
          <div className="space-y-2">
            {activity.slice(0, 5).map((entry) => {
              const state = entry.category.includes("scan")
                ? "scan"
                : entry.category.includes("threat")
                  ? "threat"
                  : "neutral";
              return (
                <div key={entry.event_id} className="flex items-start gap-4 rounded-xl px-4 py-3 hover:bg-[rgb(var(--raised))]/20 transition-colors">
                  <div
                    className={`mt-0.5 flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-xl ${
                      state === "scan"
                        ? "bg-[rgb(var(--green))]/8 text-[rgb(var(--green))]"
                        : state === "threat"
                          ? "bg-[rgb(var(--red))]/8 text-[rgb(var(--red))]"
                          : "bg-[rgb(var(--raised))]/40 text-[rgb(var(--t3))]"
                    }`}
                  >
                    {state === "scan" ? <CheckCircle size={15} /> : state === "threat" ? <AlertTriangle size={15} /> : <Activity size={15} />}
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-[13px] font-medium">{entry.title}</p>
                    {entry.message && <p className="mt-1 text-[11px] text-[rgb(var(--t3))]">{entry.message}</p>}
                  </div>
                  <span className="mt-1 flex-shrink-0 text-[10px] text-[rgb(var(--t3))]" title={new Date(entry.timestamp * 1000).toLocaleString()}>
                    {formatRelativeTime(entry.timestamp)}
                  </span>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="flex flex-col items-center py-10 text-center">
            <Clock size={32} className="mb-3 text-[rgb(var(--t3))]/20" />
            <p className="text-[14px] font-medium text-[rgb(var(--t2))]">{t("dash.no_activity")}</p>
            <p className="mt-1 text-[12px] text-[rgb(var(--t3))]">{t("dash.no_activity_desc")}</p>
          </div>
        )}
      </Card>
    </div>
  );
}

function formatRelativeTime(unixSeconds: number): string {
  const diff = Math.floor(Date.now() / 1000 - unixSeconds);
  if (diff < 60) return t("notif.just_now");
  if (diff < 3600) return t("notif.minutes_ago").replace("{n}", String(Math.floor(diff / 60)));
  if (diff < 86400) return t("notif.hours_ago").replace("{n}", String(Math.floor(diff / 3600)));
  return t("notif.days_ago").replace("{n}", String(Math.floor(diff / 86400)));
}

function HeroDetail({ label, value, sub }: { label: string; value: string; sub: string }) {
  return (
    <div className="rounded border border-[rgb(var(--border))]/15 bg-[rgb(var(--raised))]/20 p-4">
      <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[rgb(var(--t3))]">{label}</p>
      <p className="mt-2 text-[15px] font-semibold text-[rgb(var(--t1))]">{value}</p>
      <p className="mt-1 text-[11px] text-[rgb(var(--t3))]">{sub}</p>
    </div>
  );
}

function StatusTile({
  label,
  value,
  sub,
  color,
  icon,
  onClick,
}: {
  label: string;
  value: string;
  sub: string;
  color: "accent" | "green" | "amber" | "red" | "neutral";
  icon: React.ReactNode;
  onClick?: () => void;
}) {
  const palette = {
    accent: "var(--accent)",
    green: "var(--green)",
    amber: "var(--amber)",
    red: "var(--red)",
    neutral: "var(--t3)",
  }[color];

  return (
    <div
      className={`glass-card flex flex-col gap-2 px-5 py-4 h-full ${onClick ? "cursor-pointer hover:bg-[rgb(var(--raised))]/15 transition-colors" : ""}`}
      onClick={onClick}
    >
      {/* Header: icon + label */}
      <div className="flex items-center gap-2.5">
        <div
          className="flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-md"
          style={{ background: `rgba(${palette}, 0.08)`, color: `rgb(${palette})` }}
        >
          {icon}
        </div>
        <p className="text-[10px] font-semibold uppercase tracking-[0.14em]" style={{ color: `rgba(${palette}, 0.65)` }}>
          {label}
        </p>
      </div>
      {/* Value */}
      <p className="text-[22px] font-bold leading-tight text-[rgb(var(--t1))]">{value}</p>
      {/* Subtitle */}
      <p className="text-[11px] leading-snug text-[rgb(var(--t3))]">{sub}</p>
    </div>
  );
}

function ActionTile({
  icon,
  label,
  description,
  accent,
  onClick,
}: {
  icon: React.ReactNode;
  label: string;
  description: string;
  accent?: boolean;
  onClick?: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex h-full min-h-[130px] w-full flex-col items-start gap-4 rounded border p-6 text-left transition-colors cursor-pointer ${
        accent
          ? "border-[rgb(var(--accent))]/16 bg-[rgb(var(--accent))]/6 text-[rgb(var(--accent))] hover:bg-[rgb(var(--accent))]/10"
          : "border-[rgb(var(--border))]/15 bg-[rgb(var(--surface))] text-[rgb(var(--t2))] hover:bg-[rgb(var(--raised))]/25 hover:text-[rgb(var(--t1))]"
      }`}
    >
      <div
        className={`flex h-10 w-10 items-center justify-center rounded-xl ${
          accent ? "bg-[rgb(var(--accent))]/10" : "bg-[rgb(var(--raised))]/40"
        }`}
      >
        {icon}
      </div>
      <div className="min-w-0">
        <p className="text-[13px] font-semibold text-current">{label}</p>
        <p className="mt-1 text-[11px] leading-relaxed text-[rgb(var(--t3))]">{description}</p>
      </div>
    </button>
  );
}

// ── Runtime Intelligence compact card ─────────────────────────

function RuntimeIntelligenceCard() {
  const [ri, setRi] = useState<RuntimeIntelligenceStatus | null>(null);
  const { connected } = useDaemonContext();

  useEffect(() => {
    if (!connected) return;
    getRuntimeIntelligence().then(setRi).catch(() => {});
    const interval = setInterval(() => {
      getRuntimeIntelligence().then(setRi).catch(() => {});
    }, 10000); // Refresh every 10s.
    return () => clearInterval(interval);
  }, [connected]);

  if (!ri) return null;

  const plmActive = ri.plm?.enabled;
  const psEnabled = ri.powershell?.enabled;
  const psEvents = ri.powershell?.events_scanned ?? 0;
  const plmNodes = ri.plm?.nodes ?? 0;
  const plmChains = ri.plm?.suspicious_chains ?? 0;
  const recentEvents = ri.powershell?.recent_events ?? [];

  // Don't show if everything is disabled and no data.
  if (!plmActive && !psEnabled && recentEvents.length === 0) return null;

  return (
    <div className="glass-card px-7 py-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-xl bg-[rgb(var(--accent))]/8">
            <Activity size={15} className="text-[rgb(var(--accent))]" />
          </div>
          <div>
            <h4 className="text-[13px] font-semibold">{t("dash.runtime_intelligence")}</h4>
            <p className="text-[10px] text-[rgb(var(--t3))] mt-0.5">{t("dash.runtime_intel_desc")}</p>
          </div>
        </div>
        <span className={`text-[10px] px-2.5 py-1 rounded-full ${
          ri.plm?.etw_running
            ? "bg-[rgb(var(--green))]/8 text-[rgb(var(--green))]"
            : plmActive
              ? "bg-[rgb(var(--accent))]/8 text-[rgb(var(--accent))]"
              : "bg-[rgb(var(--raised))]/20 text-[rgb(var(--t3))]"
        }`}>
          {ri.plm?.etw_running ? t("dash.plm_etw_realtime") : plmActive ? t("dash.plm_snapshot") : t("dash.plm_standby")}
        </span>
      </div>

      {/* Compact stats row */}
      <div className="grid grid-cols-4 gap-4 mb-4">
        <MiniStat label={ri.plm?.mode === "Etw" ? t("dash.plm_etw") : t("dash.plm_nodes")} value={plmNodes} />
        <MiniStat label={t("dash.ps_buffers")} value={psEvents} />
        <MiniStat label={t("dash.suspicious_chains")} value={plmChains} color={plmChains > 0 ? "amber" : undefined} />
        <MiniStat label="SBL" value={ri.powershell?.sbl_available ? t("common.available") : t("common.unavailable")} />
      </div>

      {/* Recent events (if any) */}
      {recentEvents.length > 0 && (
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[rgb(var(--t3))]/40 mb-2">
            {t("dash.recent_runtime_events")}
          </p>
          <div className="space-y-1.5">
            {recentEvents.slice(-5).reverse().map((evt, i) => (
              <div key={i} className="flex items-center gap-3 text-[11px] py-1.5 px-2 rounded-lg hover:bg-[rgb(var(--raised))]/10">
                <span className={`w-6 text-right font-mono font-bold ${evt.score >= 50 ? "text-[rgb(var(--amber))]" : evt.score > 0 ? "text-[rgb(var(--t2))]" : "text-[rgb(var(--t3))]/40"}`}>
                  {evt.score}
                </span>
                <span className="text-[rgb(var(--t3))]/60 w-16 flex-shrink-0">{evt.language}</span>
                <span className="text-[rgb(var(--t2))] truncate flex-1 min-w-0">{evt.content_name}</span>
                {evt.findings_count > 0 && (
                  <span className="text-[10px] text-[rgb(var(--amber))] flex-shrink-0">{evt.findings_count} findings</span>
                )}
                {evt.lineage_summary && (
                  <span className="text-[10px] text-[rgb(var(--accent))]/60 truncate max-w-[150px] flex-shrink-0" title={evt.lineage_summary}>
                    {evt.lineage_summary}
                  </span>
                )}
                <span className="text-[9px] text-[rgb(var(--green))]/50 flex-shrink-0">observe</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Disabled states */}
      {!psEnabled && (
        <p className="text-[10px] text-[rgb(var(--t3))]/40 mt-2">
          PowerShell bridge disabled · enable in sentinelld.toml
        </p>
      )}
    </div>
  );
}

function MiniStat({ label, value, color }: { label: string; value: string | number; color?: string }) {
  const c = color === "amber" ? "var(--amber)" : "var(--t1)";
  return (
    <div>
      <p className="text-[18px] font-bold" style={{ color: `rgb(${c})` }}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </p>
      <p className="text-[10px] text-[rgb(var(--t3))] mt-0.5">{label}</p>
    </div>
  );
}

// ── Behavioral Familiarity card ───────────────────────────

function BehavioralFamiliarityCard() {
  const [ts, setTs] = useState<TrustGraphStatus | null>(null);
  const { connected } = useDaemonContext();

  useEffect(() => {
    if (!connected) return;
    getTrustStatus().then(setTs).catch(() => {});
    const interval = setInterval(() => {
      getTrustStatus().then(setTs).catch(() => {});
    }, 15000);
    return () => clearInterval(interval);
  }, [connected]);

  if (!ts || !ts.nodes) return null;

  const drifts = ts.recent_drift_events ?? [];

  return (
    <div className="glass-card px-7 py-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-xl bg-[rgb(var(--accent))]/8">
            <Eye size={15} className="text-[rgb(var(--accent))]" />
          </div>
          <div>
            <h4 className="text-[13px] font-semibold">{t("dash.behavioral_familiarity")}</h4>
            <p className="text-[10px] text-[rgb(var(--t3))] mt-0.5">{t("dash.behavioral_memory_desc")}</p>
          </div>
        </div>
        {ts.drift_events_24h > 0 && (
          <span className="text-[10px] px-2.5 py-1 rounded-full bg-[rgb(var(--amber))]/8 text-[rgb(var(--amber))]">
            {ts.drift_events_24h} drift{ts.drift_events_24h > 1 ? "s" : ""} today
          </span>
        )}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-4">
        <MiniStat label={t("dash.trust_stable")} value={ts.stable_nodes} />
        <MiniStat label={t("dash.trust_rare")} value={ts.rare_nodes} color={ts.rare_nodes > 10 ? "amber" : undefined} />
        <MiniStat label={t("dash.trust_recent")} value={ts.recently_seen} />
        <MiniStat label={t("dash.trust_drifts")} value={ts.drift_events_total} color={ts.drift_events_total > 0 ? "amber" : undefined} />
      </div>

      {/* Recent drift events */}
      {drifts.length > 0 && (
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[rgb(var(--t3))]/40 mb-2">
            Recent behavioral drift
          </p>
          <div className="space-y-1.5">
            {drifts.slice(0, 5).map((d, i) => (
              <div key={i} className="flex items-start gap-3 text-[11px] py-1.5 px-2 rounded-lg bg-[rgb(var(--amber))]/3">
                <span className="text-[rgb(var(--amber))] font-bold flex-shrink-0 w-5 text-right">+{d.weight}</span>
                <div className="min-w-0 flex-1">
                  <p className="text-[rgb(var(--t2))] truncate">{d.explanation}</p>
                  <p className="text-[9px] text-[rgb(var(--t3))]/50 mt-0.5 truncate">{d.entity}</p>
                </div>
                <span className="text-[9px] text-[rgb(var(--t3))]/40 flex-shrink-0">{d.type}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Web Protection tile ─────────────────────────────────────

/**
 * Colours by the COMBINATION of proxy state and NRPT fact, never by
 * `enabled` alone: a green tile on intent alone would claim protection
 * while the system DNS rule is absent — the exact failure the
 * intent/fact split in WebProtectionStatus exists to prevent.
 */
function WebProtectionTile({ onNavigate }: { onNavigate: (p: Page) => void }) {
  const [wp, setWp] = useState<WebProtectionStatus | null>(null);
  const { connected } = useDaemonContext();

  useEffect(() => {
    if (!connected) return;
    getWebProtectionStatus().then(setWp).catch(() => {});
    const interval = setInterval(() => {
      getWebProtectionStatus().then(setWp).catch(() => {});
    }, 10000);
    return () => clearInterval(interval);
  }, [connected]);

  if (!wp) return null;

  let value: string;
  let sub: string;
  let color: "accent" | "green" | "amber" | "red" | "neutral";

  if (wp.state === "serving" && wp.nrpt_installed === true && wp.gpo_nrpt_present === true) {
    // Rule installed but INERT: GPO NRPT policy is evaluated instead of
    // local rules, so no query reaches the proxy. Amber, not green —
    // reporting "active" here is the exact lie this field exists to catch.
    // `=== true` only: unknown (null/undefined) must not claim this.
    color = "amber";
    value = t("wp.tile_gpo");
    sub = t("wp.tile_gpo_sub");
  } else if (wp.state === "serving" && wp.nrpt_installed === true) {
    // Proxy serving AND the system DNS rule is live — actually filtering.
    color = "green";
    value = t("tile.active");
    sub = `${wp.rules_loaded.toLocaleString()} ${t("wp.tile_rules_suffix")}`;
  } else if (wp.state === "serving" && wp.nrpt_installed === false) {
    // Serving, but Windows is not sending DNS through us.
    color = "amber";
    value = t("wp.tile_no_rule");
    sub = t("wp.tile_no_rule_sub");
  } else if (wp.state === "serving") {
    // nrpt_installed === null: "could not tell" — not green, not absent.
    color = "amber";
    value = t("wp.tile_unverified");
    sub = t("wp.tile_unverified_sub");
  } else if (wp.state === "bind_failed") {
    color = "red";
    value = t("wp.tile_bind");
    sub = t("wp.tile_bind_sub");
  } else if (wp.state === "self_test_failed") {
    color = "amber";
    value = t("wp.tile_self_test");
    sub = wp.detail || t("wp.tile_unverified_sub");
  } else if (wp.enabled) {
    // Config asked for protection but nothing is running (e.g. the config
    // failed validation and was forced off) — worth a warning.
    color = "amber";
    value = t("tile.off");
    sub = wp.detail || t("wp.tile_disabled_sub");
  } else {
    color = "neutral";
    value = t("tile.off");
    sub = t("wp.tile_disabled_sub");
  }

  return (
    <StatusTile
      label={t("nav.webprotection")}
      value={value}
      sub={sub}
      color={color}
      icon={<Globe size={18} />}
      onClick={() => onNavigate("webprotection")}
    />
  );
}
