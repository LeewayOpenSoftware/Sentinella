export {
  notifyThreatDetected,
  notifyQuarantined,
  notifyQuarantineFailed,
  notifyScanComplete,
  notifySignaturesStale,
  notifyProtectionDegraded,
  notifyRealtimeUnavailable,
  notifyWebProtectionUnavailable,
  notifyWebProtectionDegraded,
  notifyFirstRunUpdateComplete,
  notifyFirstRunUpdateFailed,
} from "./notify";

export {
  loadNotificationSettings,
  saveNotificationSettings,
  type NotificationSettings,
  type NotificationSeverity,
} from "./settings";

export {
  loadHistory as loadNotificationHistory,
  clearHistory as clearNotificationHistory,
  type NotificationRecord,
} from "./history";
