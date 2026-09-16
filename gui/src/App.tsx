import { useState, useEffect, useMemo, useRef, useCallback } from "react";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { AppShell } from "./components/AppShell";
import { TopBarNotice } from "./components/ui";
import { startSignatureUpdate } from "./api/sentinella";
import { initLocale, t } from "./i18n";
import { DaemonProvider } from "./hooks/DaemonContext";
import type { Page } from "./components/Sidebar";
import { Dashboard } from "./pages/Dashboard";
import { ScanPage } from "./pages/Scan";
import { QuarantinePage } from "./pages/Quarantine";
import { HistoryPage } from "./pages/History";
import { UpdatePage } from "./pages/Update";
import { SettingsPage } from "./pages/Settings";
import { AboutPage } from "./pages/About";
import { NotificationsPage } from "./pages/Notifications";
import { IntelligencePage } from "./pages/Intelligence";
import { WebProtectionPage } from "./pages/WebProtection";
import { FirstRunWizard, isFirstRunComplete } from "./pages/FirstRun";
import { useDaemon } from "./hooks/useDaemon";
import "./App.css";

/**
 * "quick" → "Quick". Fills the `{type}` slot in the notice.scan_* templates.
 * Empty when the daemon reports no scan_type; the caller trims the result so
 * the sentence still reads ("Scan in progress" rather than " scan in progress").
 */
function scanTypeLabel(type: string | null | undefined): string {
  if (!type) return "";
  return type.charAt(0).toUpperCase() + type.slice(1);
}

function App() {
  const [page, setPage] = useState<Page>("dashboard");
  const [droppedFile, setDroppedFile] = useState<string | null>(null);
  const [showWizard, setShowWizard] = useState(!isFirstRunComplete());
  const daemon = useDaemon();

  // Initialize locale from saved preference or browser language.
  useEffect(() => { initLocale(); }, []);

  // Disable right-click context menu + dev shortcuts in all modes.
  useEffect(() => {
    const blockMenu = (e: MouseEvent) => e.preventDefault();
    const blockKeys = (e: KeyboardEvent) => {
      if (e.key === "F12") e.preventDefault();
      if (e.ctrlKey && e.shiftKey && (e.key === "I" || e.key === "J")) e.preventDefault();
      if (e.ctrlKey && e.key === "u") e.preventDefault();
    };
    document.addEventListener("contextmenu", blockMenu);
    document.addEventListener("keydown", blockKeys);
    return () => {
      document.removeEventListener("contextmenu", blockMenu);
      document.removeEventListener("keydown", blockKeys);
    };
  }, []);

  // Restore persisted theme + accent color on startup.
  useEffect(() => {
    const savedTheme = localStorage.getItem("sentinella-theme");
    if (savedTheme === "light" || savedTheme === "dark") {
      document.documentElement.setAttribute("data-theme", savedTheme);
    }
    const colors = ["#3b82f6", "#14b8a6", "#a855f7", "#ec4899", "#f97316", "#06b6d4"];
    const savedIdx = localStorage.getItem("sentinella-accent-idx");
    if (savedIdx) {
      const idx = parseInt(savedIdx);
      if (idx >= 0 && idx < colors.length) {
        const hex = colors[idx];
        const r = parseInt(hex.slice(1, 3), 16);
        const g = parseInt(hex.slice(3, 5), 16);
        const b = parseInt(hex.slice(5, 7), 16);
        document.documentElement.style.setProperty("--accent", `${r} ${g} ${b}`);
      }
    }
  }, []);

  // Drag-and-drop.
  useEffect(() => {
    if (showWizard) return;
    const webview = getCurrentWebviewWindow();
    const unlisten = webview.onDragDropEvent((event) => {
      if (event.payload.type === "drop") {
        const paths = event.payload.paths;
        if (paths.length > 0) {
          setDroppedFile(paths[0]);
          setPage("scan");
        }
      }
    });
    return () => { unlisten.then((fn) => fn()); };
  }, [showWizard]);

  const consumeDroppedFile = () => {
    const file = droppedFile;
    setDroppedFile(null);
    return file;
  };

  // ── Scan completion notice (auto-dismiss after 15s) ─────
  const [scanDoneNotice, setScanDoneNotice] = useState<{ type: string; files: number; threats: number } | null>(null);
  const scanDoneTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const prevScanRunningRef = useRef(false);

  useEffect(() => {
    const scan = daemon.data?.scan;
    if (!scan) return;

    const wasRunning = prevScanRunningRef.current;
    const isRunning = scan.running;
    prevScanRunningRef.current = isRunning;

    // Detect scan completion transition.
    if (wasRunning && !isRunning && scan.state === "completed") {
      setScanDoneNotice({
        // "" when the daemon reports no type — scanTypeLabel/{type} handle it.
        type: scan.scan_type ?? "",
        files: scan.files_scanned,
        threats: scan.threats_found,
      });
      // Auto-dismiss after 15 seconds.
      if (scanDoneTimerRef.current) clearTimeout(scanDoneTimerRef.current);
      scanDoneTimerRef.current = setTimeout(() => setScanDoneNotice(null), 15_000);
    }
  }, [daemon.data?.scan?.running, daemon.data?.scan?.state]);

  // Clean up timer on unmount.
  useEffect(() => () => { if (scanDoneTimerRef.current) clearTimeout(scanDoneTimerRef.current); }, []);

  const dismissScanDone = useCallback(() => {
    setScanDoneNotice(null);
    if (scanDoneTimerRef.current) clearTimeout(scanDoneTimerRef.current);
  }, []);

  // ── TopBar notices — up to 3, priority-ordered ────────
  const topNotices = useMemo(() => {
    const notices: React.ReactNode[] = [];

    // Priority 1: connection/protection state (max 1).
    //
    // v0.1.8: the disconnect notice is driven SOLELY by the supervisor's
    // connectionState now. Previously a parallel `!daemon.connected`
    // branch fired the same notice from a different signal (engine.state
    // === "error" + signature_count === 0), and the two could disagree
    // when IPC was busy under heavy trust_graph / FISH load — the user
    // saw "Daemon disconnected" flicker every few seconds even though
    // the daemon was healthy. Supervisor escalates Recovering →
    // Degraded → Disconnected on its own after sustained failure, which
    // is what we want for this notice anyway.
    const cs = daemon.connectionState;
    if (cs === "service_starting") {
      // The service is alive and loading its signature DB. An info line,
      // not a warning: nothing is wrong, and the first boot spends minutes
      // here compiling 176 MB of databases. This used to fall through to
      // "daemon disconnected", which made every fresh install look broken
      // on the first screen the user ever saw.
      notices.push(<TopBarNotice key="service-starting" variant="info" message={t("notice.service_starting")} dismissKey="service-starting" />);
    } else if (cs === "recovering") {
      notices.push(<TopBarNotice key="recovering" variant="info" message={t("notice.recovering")} dismissKey="recovering" />);
    } else if (cs === "degraded") {
      notices.push(<TopBarNotice key="degraded-recovery" variant="warning" message={t("notice.degraded_recovery")} dismissKey="degraded-recovery" />);
    } else if (cs === "user_disabled") {
      notices.push(<TopBarNotice key="user-disabled" variant="error" message={t("notice.user_disabled")} dismissKey="user-disabled" />);
    } else if (cs === "disconnected") {
      notices.push(<TopBarNotice key="disconnected" variant="warning" message={t("notice.disconnected")} dismissKey="disconnected" />);
    } else {
      const recoveryAudit = daemon.data?.stats && (daemon.data.stats as any).daemon_mode === "audit";
      if (recoveryAudit) {
        notices.push(<TopBarNotice key="audit" variant="warning" message={t("notice.audit_mode")} dismissKey="audit-mode" />);
      }

      const stats = daemon.data?.stats;
      if (stats) {
        const ps = stats.protection_state;
        if (ps === "degraded" || ps === "minimal") {
          // protection_detail is daemon-authored English; when it is empty we
          // at least fall back to a translated headline rather than a literal.
          notices.push(<TopBarNotice key="degraded" variant="warning" message={stats.protection_detail || t("notify.protection_degraded")} dismissKey="degraded" />);
        }
        // v0.1.8 bug fixes for the v0.1.7 banner pile-up:
        //   - "Signatures never updated" was a hardcoded English string
        //     (now goes through t() so Spanish/etc. translate)
        //   - The banner fired when db_stale=true AND db_stale_hours=0,
        //     which on the daemon side happens when effective_ts is None
        //     (newest_signature_db_mtime_secs() returned None at startup
        //     before file detection completed). Even though the user
        //     clearly had a signature database loaded (signature_count
        //     >> 0), the banner shouted "never updated". GUARD: if the
        //     daemon reports ANY signatures loaded, suppress the
        //     "never updated" case — the daemon DID load them from
        //     somewhere, so they can't be never-updated. Stale-by-time
        //     banners still fire normally.
        //
        // That guard only covers stats the daemon actually ANSWERED with. The
        // other producer of {db_stale: true, hours: 0, signature_count: 0} is
        // fetchDashboard's synthetic fallback for a timed-out stats.runtime,
        // which is byte-identical to a genuinely empty database and would fire
        // this banner on a machine holding a current signature DB. useDaemon
        // no longer commits that snapshot (setData is gated on
        // uptime_secs > 0), so every `stats` reaching here is a real daemon
        // reply — drop that gate and this banner starts lying again.
        const sigCount = stats.signature_count ?? 0;
        const reallyNeverUpdated =
          stats.db_stale && stats.db_stale_hours === 0 && sigCount === 0;
        const showStaleBanner =
          stats.db_stale &&
          (stats.db_stale_hours > 0 || reallyNeverUpdated) &&
          notices.length < 3;
        if (showStaleBanner) {
          const msg = stats.db_stale_hours > 24
            ? t("notice.signatures_days_old").replace("{n}", String(Math.floor(stats.db_stale_hours / 24)))
            : stats.db_stale_hours > 0
              ? t("notice.signatures_hours_old").replace("{n}", String(stats.db_stale_hours))
              : t("notice.never_updated");
          notices.push(
            <TopBarNotice
              key="stale-db"
              variant="warning"
              message={msg}
              dismissKey="stale-db"
              actions={
                <button
                  onClick={() => { startSignatureUpdate().catch(() => {}); }}
                  className="text-[10px] font-semibold text-[rgb(var(--accent))] hover:underline cursor-pointer whitespace-nowrap"
                >
                  {t("notice.update_now")}
                </button>
              }
            />
          );
        }
      }

      // Web protection: only worth a banner for a user who actually turned
      // it on — the feature ships disabled by default, and a "protection
      // stopped" banner for a feature nobody enabled would be exactly the
      // fearware this project's notices otherwise avoid.
      const wp = daemon.data?.webProtection;
      if (wp?.enabled && notices.length < 3) {
        if (wp.watchdog_fired) {
          notices.push(
            <TopBarNotice
              key="wp-watchdog"
              variant="warning"
              message={t("notice.web_protection_stopped")}
              dismissKey="wp-watchdog"
              actions={
                <button
                  onClick={() => setPage("webprotection")}
                  className="text-[10px] font-semibold text-[rgb(var(--accent))] hover:underline cursor-pointer whitespace-nowrap"
                >
                  {t("notice.view_web_protection")}
                </button>
              }
            />
          );
        } else if ((wp.upstreams_degraded?.length ?? 0) > 0) {
          notices.push(
            <TopBarNotice
              key="wp-degraded"
              variant="warning"
              message={t("notice.web_protection_degraded")}
              dismissKey="wp-degraded"
              actions={
                <button
                  onClick={() => setPage("webprotection")}
                  className="text-[10px] font-semibold text-[rgb(var(--accent))] hover:underline cursor-pointer whitespace-nowrap"
                >
                  {t("notice.view_web_protection")}
                </button>
              }
            />
          );
        }
      }
    }

    // Priority 2: active scan progress.
    const scan = daemon.data?.scan;
    if (scan?.running && notices.length < 3) {
      const label = scanTypeLabel(scan.scan_type);
      notices.push(
        <TopBarNotice
          key="scan-running"
          variant="info"
          message={t("notice.scan_progress").replace("{type}", label).trim()}
          actions={
            <button
              onClick={() => setPage("scan")}
              className="text-[10px] font-semibold text-[rgb(var(--accent))] hover:underline cursor-pointer whitespace-nowrap"
            >
              {t("notice.view_progress")}
            </button>
          }
        />
      );
    }

    // Priority 3: scan completed (auto-dismissing).
    if (scanDoneNotice && !scan?.running && notices.length < 3) {
      // The {threats} templates carry their own plural form per locale
      // ("threat(s)", "minaccia/minacce", …) — do NOT append an English "s".
      const label = scanTypeLabel(scanDoneNotice.type);
      const msg = (scanDoneNotice.threats > 0
        ? t("notice.scan_done_threats")
            .replace("{type}", label)
            .replace("{threats}", String(scanDoneNotice.threats))
        : t("notice.scan_done_clean")
            .replace("{type}", label)
            .replace("{files}", scanDoneNotice.files.toLocaleString())
      ).trim();
      notices.push(
        <TopBarNotice
          key="scan-done"
          variant={scanDoneNotice.threats > 0 ? "error" : "success"}
          message={msg}
          onDismiss={dismissScanDone}
          actions={
            scanDoneNotice.threats > 0 ? (
              <button
                onClick={() => { setPage("quarantine"); dismissScanDone(); }}
                className="text-[10px] font-semibold text-[rgb(var(--accent))] hover:underline cursor-pointer whitespace-nowrap"
              >
                {t("notice.view_quarantine")}
              </button>
            ) : undefined
          }
        />
      );
    }

    return notices;
  }, [daemon.connected, daemon.connectionState, daemon.data?.stats, daemon.data?.scan, daemon.data?.webProtection, scanDoneNotice, dismissScanDone]);

  // First-run wizard gate.
  if (showWizard) {
    return (
      <ErrorBoundary>
        <FirstRunWizard onComplete={() => setShowWizard(false)} />
      </ErrorBoundary>
    );
  }

  return (
    <ErrorBoundary>
      <DaemonProvider value={daemon}>
        <AppShell
          currentPage={page}
          onNavigate={setPage}
          connected={daemon.connected}
          starting={daemon.connectionState === "service_starting"}
          onRefresh={daemon.refresh}
          notices={topNotices}
        >
          {page === "dashboard" && <Dashboard onNavigate={setPage} />}
          {page === "scan" && <ScanPage droppedFile={droppedFile} onConsumeDroppedFile={consumeDroppedFile} connected={daemon.connected} engineStatus={daemon.data?.engine ?? null} />}
          {page === "quarantine" && <QuarantinePage />}
          {page === "history" && <HistoryPage />}
          {page === "update" && <UpdatePage />}
          {page === "settings" && <SettingsPage />}

          {page === "notifications" && <NotificationsPage />}
          {page === "intelligence" && <IntelligencePage />}
          {page === "webprotection" && <WebProtectionPage />}
          {page === "about" && <AboutPage />}
        </AppShell>
      </DaemonProvider>
    </ErrorBoundary>
  );
}

export default App;
