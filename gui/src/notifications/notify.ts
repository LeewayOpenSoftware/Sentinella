// Centralized notification dispatch — calm, meaningful Windows toasts.
//
// Philosophy: notify only when the user needs to know.
// No fearware. No spam. No exclamation marks.
//
// Hardened with:
// - Deduplication (5-min cooldown per unique event)
// - Storm control (aggregate rapid-fire events)
// - Severity threshold
// - Local history recording

import { sendNotification, isPermissionGranted, requestPermission } from "@tauri-apps/plugin-notification";
import { loadNotificationSettings, meetsMinSeverity, type NotificationSeverity } from "./settings";
import { dedupeCheck, stormControlled } from "./dedupe";
import { recordNotification } from "./history";
import { t, tf } from "../i18n";

// ── Permission ────────────────────────────────────────────────

let permissionGranted: boolean | null = null;

async function ensurePermission(): Promise<boolean> {
  if (permissionGranted !== null) return permissionGranted;
  try {
    permissionGranted = await isPermissionGranted();
    if (!permissionGranted) {
      const result = await requestPermission();
      permissionGranted = result === "granted";
    }
  } catch {
    permissionGranted = false;
  }
  return permissionGranted;
}

// ── Core dispatch ─────────────────────────────────────────────

async function send(title: string, body: string): Promise<void> {
  const ok = await ensurePermission();
  if (!ok) return;
  try {
    sendNotification({ title, body });
  } catch {
    // Notification failure must never crash the app.
  }
}

type Gate = "onThreat" | "onQuarantine" | "onUpdateFailure" | "onDegraded" | "onScanComplete";

function shouldNotify(gate: Gate, severity: NotificationSeverity): boolean {
  const s = loadNotificationSettings();
  if (!s.enabled || s.quietMode) return false;
  if (!s[gate]) return false;
  if (!meetsMinSeverity(severity, s.minSeverity)) return false;
  return true;
}

// ── Public API ────────────────────────────────────────────────

/** A threat was detected (ClamAV or ARGUS). */
export function notifyThreatDetected(virusName: string, filePath: string): void {
  if (!shouldNotify("onThreat", "threat")) return;

  const dedupeKey = `threat:${virusName}:${filePath}`;
  const fileName = filePath.split(/[/\\]/).pop() || filePath;

  stormControlled(
    "threat",
    () => {
      if (!dedupeCheck(dedupeKey)) return;
      send(t("notify.threat_detected"), t("notify.body_threat").replace("{virus}", virusName).replace("{file}", fileName));
      recordNotification("threat", t("notify.threat_detected"), filePath);
    },
    (count) => {
      send(t("notify.multiple_threats"), t("notify.body_storm").replace("{count}", String(count)));
      recordNotification("threat_storm", `${count} threats detected`);
    },
  );
}

/** A file was successfully quarantined. */
export function notifyQuarantined(virusName: string, filePath: string): void {
  if (!shouldNotify("onQuarantine", "threat")) return;

  const dedupeKey = `quarantine:${filePath}`;
  const fileName = filePath.split(/[/\\]/).pop() || filePath;

  stormControlled(
    "quarantine",
    () => {
      if (!dedupeCheck(dedupeKey)) return;
      send(t("notify.file_quarantined"), t("notify.body_quarantined").replace("{file}", fileName).replace("{virus}", virusName));
      recordNotification("quarantine", t("notify.file_quarantined"), filePath);
    },
    (count) => {
      send(t("notify.files_quarantined"), t("notify.body_quar_storm").replace("{count}", String(count)));
      recordNotification("quarantine_storm", `${count} files quarantined`);
    },
  );
}

/** Quarantine failed — user needs to know. */
export function notifyQuarantineFailed(filePath: string, reason: string): void {
  if (!shouldNotify("onQuarantine", "critical")) return;
  const dedupeKey = `quarantine_fail:${filePath}`;
  if (!dedupeCheck(dedupeKey)) return;

  const fileName = filePath.split(/[/\\]/).pop() || filePath;
  send(t("notify.quarantine_failed"), `${t("notify.quarantine_failed")}: ${fileName} — ${reason}`);
  recordNotification("quarantine_failed", t("notify.quarantine_failed"), filePath);
}

/** Scan completed with threats. Clean scans are silent. */
export function notifyScanComplete(threats: number, filesScanned: number, scanType: string): void {
  if (threats === 0) return;
  if (!shouldNotify("onScanComplete", "warning")) return;

  const dedupeKey = `scan_complete:${scanType}:${threats}`;
  if (!dedupeCheck(dedupeKey, 60_000)) return; // 1-min cooldown for scan completion

  // Every other toast here goes through the locale table; this one was built
  // from English literals, so a Chinese user got an English toast in an
  // otherwise Chinese app. The two keys below are not in the locale files yet
  // — tf() keeps today's English text and picks up the translations the
  // instant they land. `{threats}` carries its own plural form per locale, so
  // no English "s" is appended.
  // Callers pass "scan" when the daemon reported no type; "quick" → "Quick".
  const label = scanType === "scan" || !scanType
    ? ""
    : scanType.charAt(0).toUpperCase() + scanType.slice(1);
  const title = tf("notify.scan_complete", "{type} scan complete")
    .replace("{type}", label)
    .trim();
  const body = tf("notify.body_scan_complete", "{threats} threat(s) found in {files} files.")
    .replace("{threats}", String(threats))
    .replace("{files}", filesScanned.toLocaleString());
  send(title, body);
  recordNotification("scan_complete", `${title} — ${body}`);
}

/**
 * Signatures are old enough to be worth interrupting the user.
 *
 * This REPLACED a notification that fired whenever a freshclam run failed.
 * That was the wrong event: a single failed fetch is transient (slow mirror,
 * Wi-Fi drop, machine suspended mid-download), the updater now retries it,
 * and the next scheduled cycle is hours away at most — so the user was being
 * interrupted about something that had already fixed itself, with no action
 * available to them. Signature AGE is the fact they can actually act on, and
 * the daemon only sets `db_stale_notify` once it crosses
 * `signature_stale_notify_days` (default 14). Failed attempts are still
 * recorded in the activity log for diagnosis; they just no longer shout.
 *
 * Kept on the `onUpdateFailure` gate: it is the same user preference
 * ("tell me about signature update problems"), now attached to the event
 * that deserves it, so anyone who had already switched it off stays quiet.
 */
export function notifySignaturesStale(days: number): void {
  if (!shouldNotify("onUpdateFailure", "warning")) return;
  // 24h cooldown: while the condition persists this could otherwise re-fire
  // on the transition guard after any daemon reconnect.
  if (!dedupeCheck("signatures_stale", 24 * 60 * 60 * 1000)) return;

  const title = t("notify.signatures_stale");
  send(title, t("notify.signatures_stale_body").replace("{n}", String(days)));
  recordNotification("signatures_stale", title);
}

/** Protection state degraded or unavailable. */
export function notifyProtectionDegraded(detail: string): void {
  if (!shouldNotify("onDegraded", "critical")) return;
  if (!dedupeCheck("protection_degraded")) return;

  send(t("notify.protection_degraded"), detail || t("notify.protection_degraded"));
  recordNotification("protection_degraded", t("notify.protection_degraded"));
}

/** Realtime protection unavailable. */
export function notifyRealtimeUnavailable(): void {
  if (!shouldNotify("onDegraded", "critical")) return;
  if (!dedupeCheck("realtime_unavailable")) return;

  send(t("notify.realtime_unavailable"), t("notify.body_realtime"));
  recordNotification("realtime_unavailable", t("notify.realtime_unavailable"));
}

/**
 * Web protection's watchdog removed the DNS filtering rule because the
 * proxy stopped answering reliably — the machine's DNS reverted to
 * normal (unfiltered) resolution. Same gate/severity/dedupe pattern as
 * `notifyRealtimeUnavailable`: this is the DNS-filtering equivalent of
 * the file watcher going down.
 */
export function notifyWebProtectionUnavailable(): void {
  if (!shouldNotify("onDegraded", "critical")) return;
  if (!dedupeCheck("web_protection_unavailable")) return;

  send(t("notify.web_protection_unavailable"), t("notify.body_web_protection_unavailable"));
  recordNotification("web_protection_unavailable", t("notify.web_protection_unavailable"));
}

/**
 * One or more DNS servers used by web protection stopped responding.
 * Filtering itself is still active — this is a partial degradation, not
 * a loss of protection — so it is a lower severity than
 * `notifyWebProtectionUnavailable`.
 */
export function notifyWebProtectionDegraded(): void {
  if (!shouldNotify("onDegraded", "warning")) return;
  if (!dedupeCheck("web_protection_degraded")) return;

  send(t("notify.web_protection_degraded"), t("notify.body_web_protection_degraded"));
  recordNotification("web_protection_degraded", t("notify.web_protection_degraded"));
}

/** First-run signature update completed. */
export function notifyFirstRunUpdateComplete(sigCount: number): void {
  if (!loadNotificationSettings().enabled) return;
  if (!dedupeCheck("first_run_complete")) return;

  // Title was translated, body was an English literal. notify.body_ready is
  // not in the locale files yet — see notifyScanComplete for the same pattern.
  send(
    t("notify.ready"),
    tf("notify.body_ready", "{count} signatures loaded.").replace(
      "{count}",
      sigCount.toLocaleString(),
    ),
  );
  recordNotification("first_run_complete", t("notify.ready"));
}

/** First-run signature update failed. */
export function notifyFirstRunUpdateFailed(): void {
  if (!loadNotificationSettings().enabled) return;
  if (!dedupeCheck("first_run_failed")) return;

  send(t("notify.sig_download_failed"), t("notify.sig_download_failed"));
  recordNotification("first_run_failed", t("notify.sig_download_failed"));
}
