import { useState, useEffect, useCallback, useRef } from "react";
import type { DashboardData, ConnectionState } from "../api/sentinella";
import { fetchDashboard, getConnectionState } from "../api/sentinella";
import {
  notifyScanComplete,
  notifySignaturesStale,
  notifyProtectionDegraded,
  notifyRealtimeUnavailable,
  notifyWebProtectionUnavailable,
  notifyWebProtectionDegraded,
  notifyQuarantined,
} from "../notifications";
// v0.1.9 audit HIGH-3 fix: invalidate the Settings page's module-scope
// defaults + restart_requirements caches whenever the daemon goes from
// disconnected back to connected — the daemon binary may have changed
// across the gap (tray restart, service auto-restart, scheduled
// update reload), and the cached schema metadata could be stale.
import { invalidateSettingsCache } from "../pages/Settings/hooks/useFullConfig";

const POLL_INTERVAL = 5000; // 5 seconds
// v0.1.8: bumped 3 -> 6 to absorb heavier daemon work bursts
// (trust_graph integrity checks + FISH detector + idle scanner all
// firing concurrently on busy systems can briefly starve the IPC
// thread). 6 × 5s ≈ 30 s of failure before flipping the badge.
const DISCONNECT_THRESHOLD = 6;
// Debounce isConnected (the engine-status-based check) the same way.
// Without this, ONE engine.status timeout flipped connected=false
// instantly because each call has its own .catch fallback that returns
// engine.state="error"+signature_count=0 — the negative case bypassed
// failCountRef entirely. Now isConnected only flips false after
// CONNECTED_DEBOUNCE consecutive engine-status failures.
const CONNECTED_DEBOUNCE = 3;

/**
 * True when `result.quarantine` can be trusted as the daemon's real list.
 *
 * `getQuarantineItems()` swallows failures into `[]` (quarantine.list is
 * auth-gated and IPC can be busy mid-reload), so an empty array on its own is
 * ambiguous. `stats.quarantine_count` arrives from a separate IPC call and
 * counts exactly the same rows the list returns (`status = 'quarantined'`, see
 * db::quarantine_count / db::list_quarantine), so:
 *   list non-empty            → real
 *   list empty + count === 0  → really empty
 *   list empty + count > 0    → the call failed, ignore this snapshot
 * Only meaningful on a poll where the stats block itself is real — callers
 * gate on `healthyThisPoll`, which requires `statsAreReal`.
 */
function quarantineListIsReliable(result: DashboardData): boolean {
  if (result.quarantine.length > 0) return true;
  return (result.stats?.quarantine_count ?? 0) === 0;
}

export interface DaemonState {
  data: DashboardData | null;
  connected: boolean;
  /** Richer connection state from supervisor. */
  connectionState: ConnectionState;
  loading: boolean;
  error: string | null;
  lastRefresh: Date | null;
  refresh: () => void;
}

export function useDaemon(): DaemonState {
  const [data, setData] = useState<DashboardData | null>(null);
  const [connected, setConnected] = useState(false);
  const [connectionState, setConnectionState] = useState<ConnectionState>("connecting");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const failCountRef = useRef(0);
  // v0.1.8: separate counter for engine-status-based "connected" flag.
  // Bumped on each poll where engine.state==="error" + signature_count===0;
  // reset on any healthy poll. UI flips false only when ≥ CONNECTED_DEBOUNCE.
  const disconnectCountRef = useRef(0);
  // Monotonic refresh id. Each refresh() call bumps it and captures the value;
  // state writes only commit if the captured id is still the latest. Closes a
  // race where two overlapping refreshes (e.g. quick visibility toggle, or a
  // manual `refresh()` racing the 5s poll) could let an older response land
  // AFTER a newer one — pinning the UI to stale "scanning" / connection state.
  const refreshIdRef = useRef(0);

  // ── State transition tracking for notifications ─────────
  const prevRef = useRef<{
    scanRunning: boolean;
    scanThreats: number;
    scanFiles: number;
    scanType: string;
    updateState: string;
    updateError: string | null;
    dbStaleNotify: boolean;
    protectionState: string;
    watcherActive: boolean;
    /**
     * The daemon's `disabled()` status shape always carries
     * `watchdog_fired: false` (there is no watchdog running to have fired),
     * so these are already naturally `false` on every poll where the
     * feature is off — no separate "was it enabled last time" guard is
     * needed; plain edge-detection below is enough, same as `watcherActive`.
     */
    webProtectionWatchdogFired: boolean;
    webProtectionUpstreamsDegraded: boolean;
    /**
     * False until `quarantineIds` was built from a quarantine.list we could
     * actually trust. The notification loop refuses to diff against an
     * unseeded baseline — see the seeding block at the end of refresh().
     */
    quarantineSeeded: boolean;
    quarantineCount: number;
    quarantineIds: Set<string>;
  } | null>(null);

  const refresh = useCallback(async () => {
    const myId = ++refreshIdRef.current;
    const isLatest = () => refreshIdRef.current === myId;

    // Check supervisor connection state (fast, always available).
    const supervisorState = await getConnectionState().catch(() => "disconnected" as ConnectionState);
    if (!isLatest()) return;
    setConnectionState(supervisorState);

    try {
      const result = await fetchDashboard();
      if (!isLatest()) return; // A newer refresh already landed — drop ours.
      // v0.1.9 audit MED-7: half-dead detection.
      //
      // fetchDashboard wraps each of 9 IPC calls in its own .catch()
      // returning a synthetic fallback, so Promise.all never throws.
      // Previously healthyThisPoll was just the engine signal, which
      // meant: if getEngineStatus succeeded (cached/fast) but every
      // OTHER endpoint silently fell back (uptime=0, watcher=false,
      // quarantine=[]), connected stayed TRUE and the UI rendered a
      // green badge over a zeroed dashboard. The author's own
      // `statsAreReal = stats.uptime_secs > 0` guard later in this
      // file is the smoking gun that this fallback shape is known to
      // happen in practice. Now we require BOTH signals — engine OK
      // AND stats are real — before calling the connection healthy.
      const engineHealthy =
        result.engine.state !== "error" || result.engine.signature_count > 0;
      const statsAreReal = (result.stats?.uptime_secs ?? 0) > 0;
      const healthyThisPoll = engineHealthy && statsAreReal;
      // Debounce the disconnect flip — see CONNECTED_DEBOUNCE comment.
      if (healthyThisPoll) {
        // v0.1.9 audit HIGH-3: if we just transitioned from
        // disconnected→connected, the daemon may have hot-restarted with
        // a new binary — invalidate the Settings cache so the next mount
        // re-fetches defaults + restart_requirements against the new
        // schema. Cheap no-op if the cache was already empty.
        setConnected((prev) => {
          if (!prev) {
            invalidateSettingsCache();
          }
          return true;
        });
        disconnectCountRef.current = 0;
      } else {
        disconnectCountRef.current += 1;
        if (disconnectCountRef.current >= CONNECTED_DEBOUNCE) {
          setConnected(false);
        }
      }
      // Never commit the synthetic disconnect snapshot into shared state.
      //
      // fetchDashboard catches each of its 9 calls individually, so when
      // stats.runtime doesn't answer it substitutes a zeroed RuntimeStats
      // (uptime 0, signature_count 0, db_stale true, db_stale_hours 0,
      // protection_state "unprotected") that carries no marker saying it is
      // synthetic. Committing it had two visible sinks:
      //   - A daemon that never came up still produced non-null `data`, so
      //     Dashboard's `!connected && !data` offline card (WifiOff, pipe
      //     hint, Retry) was unreachable and the user got a dashboard of
      //     zeros instead.
      //   - ONE timed-out poll on a healthy machine matched
      //     `db_stale && db_stale_hours === 0 && signature_count === 0`
      //     exactly, so App.tsx raised the red "Signatures have never been
      //     updated" banner over a fully loaded signature database.
      // Keeping the last real snapshot (or null, if we never had one) is both
      // honest and strictly more useful than zeros.
      //
      // The gate is `statsAreReal`, NOT `healthyThisPoll`: a reachable daemon
      // whose engine failed to load still has real stats, and that state must
      // stay visible on the dashboard instead of hiding behind "not connected".
      if (statsAreReal) {
        setData(result);
        setLastRefresh(new Date());
      }
      setError(null);
      failCountRef.current = 0; // Reset hard-failure counter on any successful fetchDashboard.

      // ── Detect transitions → fire notifications ───────
      const prev = prevRef.current;

      // Signatures stale enough to be worth interrupting for.
      //
      // NOT inside the `prev &&` block below, and deliberately so. Every
      // other notification here is about an EVENT that happens while the app
      // is watching (a scan finished, the watcher died), so "no previous
      // state = nothing to compare = stay quiet" is right for them. This one
      // is about a CONDITION that latches true and stays true for weeks. The
      // dominant real case is a user opening Sentinella on a machine whose
      // signatures are already months old — exactly the case they asked to be
      // told about. Requiring a false→true edge with `prev` seeded from the
      // first poll made that case unreachable: the condition was already true
      // before we started looking. Treating a missing `prev` as "not stale"
      // lets the first healthy poll fire; dedupeCheck's 24h window in
      // notifySignaturesStale stops it repeating.
      if (healthyThisPoll && statsAreReal && result.stats.db_stale_notify && !(prev?.dbStaleNotify ?? false)) {
        notifySignaturesStale(Math.floor((result.stats.db_stale_hours ?? 0) / 24));
      }

      if (prev && healthyThisPoll) {
        // Scan completed with threats.
        if (prev.scanRunning && !result.scan.running && result.scan.state === "completed") {
          notifyScanComplete(
            result.scan.threats_found,
            result.scan.files_scanned,
            result.scan.scan_type || "scan",
          );
        }

        // (The staleness notification lives above this block — it must fire
        // on the first poll too. See the comment there.)

        // Protection degraded — only notify if we're actually connected.
        // Transient IPC failures produce fallback stats with "unprotected" which
        // is a false positive. Only fire if the daemon is genuinely reachable
        // and reports degraded state.
        const ps = result.stats.protection_state;
        // `statsAreReal` (fallback has uptime=0) comes from the enclosing
        // scope. It used to be re-declared here, which shadowed the outer
        // binding and put every earlier line in this block inside its
        // temporal dead zone — the staleness check above reads it.
        if (statsAreReal && prev.protectionState === "fully_protected" && ps !== "fully_protected") {
          notifyProtectionDegraded(result.stats.protection_detail || "");
        }

        // Watcher went down — same guard.
        if (statsAreReal && prev.watcherActive && !result.stats.watcher_active) {
          notifyRealtimeUnavailable();
        }

        // Web protection's watchdog fired (rule removed, DNS reverted to
        // normal) or an upstream degraded — same false→true edge-detection
        // pattern as the watcher check above.
        const wp = result.webProtection;
        if (!prev.webProtectionWatchdogFired && wp.watchdog_fired) {
          notifyWebProtectionUnavailable();
        } else if (!prev.webProtectionUpstreamsDegraded && (wp.upstreams_degraded?.length ?? 0) > 0) {
          // else-if: a fired watchdog already implies degraded upstreams
          // in most real cases and is the more severe fact — one toast,
          // not two, for the same underlying event.
          notifyWebProtectionDegraded();
        }

        // New quarantine items (watcher auto-quarantine). Two guards:
        //  - `quarantineSeeded`: never diff against a baseline that was itself
        //    built from a failed quarantine.list. Without it, one transient
        //    failure on the FIRST poll seeded an empty set and every
        //    pre-existing quarantine entry toasted as freshly caught on poll 2
        //    — the same phantom flash the seeding block below was written to
        //    stop, just one poll earlier than it covered.
        //  - `qReliable`: an N>0 → empty drop is the transient blip, not a
        //    real clear.
        const qReliable = quarantineListIsReliable(result);
        if (prev.quarantineSeeded && qReliable) {
          for (const q of result.quarantine) {
            if (!prev.quarantineIds.has(q.id)) {
              notifyQuarantined(q.signature, q.original_path);
            }
          }
        }
      }

      // Update prev state — ONLY from a genuinely-connected poll. During an
      // engine reload the dashboard briefly reports disconnected/fallback data
      // (engine=error, signature_count=0, empty quarantine list). Overwriting
      // prev with that wiped `quarantineIds`, so on the next reconnect poll the
      // existing (old) quarantine items were all "not in prev" → re-fired a
      // tray toast as if freshly caught. Preserving the last-good snapshot
      // across the reload blip stops the phantom flash (and likewise keeps
      // scan/update/protection transitions measured against real state).
      if (healthyThisPoll) {
        // Preserve the last-good quarantine set when the list looks like a
        // transient empty-blip (see qReliable above), so the dedup survives the
        // reload churn instead of re-flagging old items as new on recovery.
        const prevSnap = prevRef.current;
        const qReliable = quarantineListIsReliable(result);
        prevRef.current = {
          scanRunning: result.scan.running,
          scanThreats: result.scan.threats_found,
          scanFiles: result.scan.files_scanned,
          scanType: result.scan.scan_type || "",
          updateState: result.update.state,
          updateError: result.update.last_error ?? null,
          dbStaleNotify: result.stats.db_stale_notify ?? false,
          protectionState: result.stats.protection_state,
          watcherActive: result.stats.watcher_active,
          webProtectionWatchdogFired: result.webProtection.watchdog_fired ?? false,
          webProtectionUpstreamsDegraded: (result.webProtection.upstreams_degraded?.length ?? 0) > 0,
          // Latches once the list has been seen for real. The rest of the
          // snapshot still seeds on this poll, so a permanently-failing
          // quarantine.list only silences quarantine toasts — scan/protection
          // transitions keep working.
          quarantineSeeded: qReliable || (prevSnap?.quarantineSeeded ?? false),
          quarantineCount: qReliable
            ? result.quarantine.length
            : (prevSnap?.quarantineCount ?? 0),
          quarantineIds: qReliable
            ? new Set(result.quarantine.map(q => q.id))
            : (prevSnap?.quarantineIds ?? new Set()),
        };
      }
    } catch (e) {
      if (!isLatest()) return;
      failCountRef.current += 1;
      // Only show disconnected after multiple consecutive failures.
      // Prevents flicker during heavy scans when pipe is temporarily busy.
      if (failCountRef.current >= DISCONNECT_THRESHOLD) {
        console.error("[useDaemon] fetchDashboard failed:", e);
        setConnected(false);
        setError(String(e));
      }
      // Keep showing last known data during transient failures.
    } finally {
      if (isLatest()) setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Initial fetch.
    refresh();

    // Polling — pauses when window is hidden/minimized.
    const startPolling = () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
      intervalRef.current = setInterval(refresh, POLL_INTERVAL);
    };
    const stopPolling = () => {
      if (intervalRef.current) { clearInterval(intervalRef.current); intervalRef.current = null; }
    };
    const onVisibility = () => {
      if (document.hidden) { stopPolling(); } else { refresh(); startPolling(); }
    };

    startPolling();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      stopPolling();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [refresh]);

  return { data, connected, connectionState, loading, error, lastRefresh, refresh };
}
