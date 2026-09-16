import { useState, useEffect, useCallback } from "react";
import { RotateCcw, Trash2, FileWarning, ChevronDown, ChevronUp, Loader2, WifiOff, AlertTriangle, CheckCircle2, XCircle, FolderOpen } from "lucide-react";
import { ShieldIcon } from "../components/ShieldIcon";
import { Card } from "../components/Card";
import { getQuarantineItems, restoreQuarantine, deleteQuarantine, reportSafe, restoreQuarantineAs } from "../api/sentinella";
import { save } from "@tauri-apps/plugin-dialog";
import type { QuarantineEntry } from "../types/sentinella";
import { t } from "../i18n";
import { ShieldCheck } from "lucide-react";

type Toast = { type: "success" | "error"; message: string };
type ConfirmAction = { type: "restore" | "delete" | "restore_safe"; item: QuarantineEntry };

export function QuarantinePage() {
  const [items, setItems] = useState<QuarantineEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string|null>(null);
  const [expanded, setExpanded] = useState<string|null>(null);
  const [toast, setToast] = useState<Toast|null>(null);
  const [busy, setBusy] = useState<string|null>(null);
  const [confirm, setConfirm] = useState<ConfirmAction|null>(null);

  const refresh = useCallback(() => {
    getQuarantineItems()
      .then(r => { setItems(r); setErr(null); })
      .catch(e => setErr(String(e)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  // Auto-dismiss toast.
  useEffect(() => {
    if (!toast) return;
    const tid = setTimeout(() => setToast(null), 4000);
    return () => clearTimeout(tid);
  }, [toast]);

  const handleRestore = async (item: QuarantineEntry) => {
    setBusy(item.id);
    try {
      const result = await restoreQuarantine(item.id);
      if (result.ok) {
        setToast({ type: "success", message: `${t("quar.restored_to")} ${result.restored_to || item.original_path}` });
      } else {
        setToast({ type: "error", message: result.error || t("quar.restore_failed") });
      }
    } catch (e) {
      setToast({ type: "error", message: String(e) });
    }
    setBusy(null);
    setExpanded(null);
    setConfirm(null);
    refresh();
  };

  const handleDelete = async (item: QuarantineEntry) => {
    setBusy(item.id);
    try {
      const result = await deleteQuarantine(item.id);
      if (result.ok) {
        setToast({ type: "success", message: t("quar.deleted_success") });
      } else {
        setToast({ type: "error", message: result.error || t("quar.delete_failed") });
      }
    } catch (e) {
      setToast({ type: "error", message: String(e) });
    }
    setBusy(null);
    setExpanded(null);
    setConfirm(null);
    refresh();
  };

  const handleRestoreSafe = async (item: QuarantineEntry) => {
    setBusy(item.id);
    try {
      const result = await restoreQuarantine(item.id);
      if (result.ok) {
        // Record as likely FP in calibration DB.
        await reportSafe(item.id, item.sha256, item.original_path, item.signature).catch(() => {});
        setToast({ type: "success", message: t("quar.restored_reported_safe") });
      } else {
        setToast({ type: "error", message: result.error || t("quar.restore_failed") });
      }
    } catch (e) {
      setToast({ type: "error", message: String(e) });
    }
    setBusy(null);
    setExpanded(null);
    setConfirm(null);
    refresh();
  };

  const handleRestoreAs = async (item: QuarantineEntry) => {
    const fileName = item.original_path.split('\\').pop() || "restored_file";
    const dest = await save({
      defaultPath: fileName,
      title: t("quar.restore_dialog_title"),
    });
    if (!dest) return;
    setBusy(item.id);
    try {
      const result = await restoreQuarantineAs(item.id, dest);
      if (result.ok) {
        setToast({ type: "success", message: `${t("quar.restored_to")} ${result.restored_to || dest}` });
      } else {
        setToast({ type: "error", message: result.error || t("quar.restore_failed") });
      }
    } catch (e) {
      setToast({ type: "error", message: String(e) });
    }
    setBusy(null);
    setConfirm(null);
    refresh();
  };

  if (loading) return <div className="flex items-center justify-center py-20"><Loader2 size={20} className="text-[rgb(var(--accent))] animate-spin"/></div>;
  if (err) return <Card className="text-center py-10"><WifiOff size={20} className="mx-auto text-[rgb(var(--amber))] mb-3"/><p className="text-[13px] text-[rgb(var(--t3))]">{t("quar.daemon_error")}</p></Card>;

  return (
    <div className="page-stack">
      {/* Toast notification */}
      {toast && (
        <div className={`fixed top-6 right-6 z-50 flex items-center gap-2.5 px-5 py-3 rounded shadow-xl text-[13px] font-medium animate-in slide-in-from-right ${
          toast.type === "success"
            ? "bg-[rgb(var(--green))]/12 text-[rgb(var(--green))] border border-[rgb(var(--green))]/15"
            : "bg-[rgb(var(--red))]/12 text-[rgb(var(--red))] border border-[rgb(var(--red))]/15"
        }`}>
          {toast.type === "success" ? <CheckCircle2 size={15}/> : <XCircle size={15}/>}
          <span className="max-w-xs truncate">{toast.message}</span>
          <button onClick={() => setToast(null)} className="ml-2 opacity-50 hover:opacity-100 cursor-pointer">×</button>
        </div>
      )}

      {/* Confirmation dialog */}
      {confirm && (
        <div className="fixed inset-0 bg-black/40 z-40 flex items-center justify-center">
          <div className="glass-card p-6 max-w-md w-full mx-4">
            <div className="flex items-start gap-3 mb-4">
              <AlertTriangle size={20} className={confirm.type === "delete" ? "text-[rgb(var(--red))] mt-0.5" : "text-[rgb(var(--amber))] mt-0.5"}/>
              <div>
                <h3 className="text-[15px] font-semibold mb-1.5">
                  {confirm.type === "restore_safe" ? t("quar.report_safe_question")
                    : confirm.type === "restore" ? t("quar.restore_question")
                    : t("quar.delete_question")}
                </h3>
                <p className="text-[12px] text-[rgb(var(--t2))] leading-relaxed mb-2">
                  {confirm.type === "restore_safe"
                    ? t("quar.report_safe_warning")
                    : confirm.type === "restore"
                      ? t("quar.restore_warning")
                      : t("quar.delete_warning")}
                </p>
                <div className="text-[11px] text-[rgb(var(--t3))] bg-[rgb(var(--raised))]/15 px-3 py-2 rounded-lg">
                  <p className="font-mono truncate">{confirm.item.original_path.split('\\').pop()}</p>
                  <p className="mt-0.5">{confirm.item.signature}</p>
                </div>
              </div>
            </div>
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => setConfirm(null)}
                disabled={!!busy}
                className="text-[12px] font-medium px-5 py-2.5 rounded-xl bg-[rgb(var(--raised))]/20 text-[rgb(var(--t2))] cursor-pointer disabled:opacity-30"
              >{t("common.cancel")}</button>
              <button
                onClick={() =>
                  confirm.type === "restore_safe" ? handleRestoreSafe(confirm.item)
                  : confirm.type === "restore" ? handleRestore(confirm.item)
                  : handleDelete(confirm.item)
                }
                disabled={!!busy}
                className={`text-[12px] font-medium px-5 py-2.5 rounded-xl flex items-center gap-1.5 cursor-pointer disabled:opacity-30 ${
                  confirm.type === "delete"
                    ? "bg-[rgb(var(--red))]/12 text-[rgb(var(--red))]"
                    : confirm.type === "restore_safe"
                      ? "bg-[rgb(var(--green))]/12 text-[rgb(var(--green))]"
                      : "bg-[rgb(var(--amber))]/12 text-[rgb(var(--amber))]"
                }`}
              >
                {busy ? <Loader2 size={12} className="animate-spin"/>
                  : confirm.type === "restore_safe" ? <ShieldCheck size={12}/>
                  : confirm.type === "restore" ? <RotateCcw size={12}/>
                  : <Trash2 size={12}/>}
                {confirm.type === "restore_safe" ? t("quar.report_safe_confirm")
                  : confirm.type === "restore" ? t("quar.restore_file")
                  : t("quar.delete_forever")}
              </button>
            </div>
          </div>
        </div>
      )}

      {items.length === 0 ? (
        <Card className="text-center py-14">
          <div className="mx-auto w-fit mb-4"><ShieldIcon icon="quarantine" size={36} className="brightness-0 invert opacity-40" /></div>
          <h3 className="text-[18px] font-semibold mb-2">{t("quar.empty_title")}</h3>
          <p className="text-[13px] text-[rgb(var(--t2))] max-w-sm mx-auto leading-relaxed">
            {t("quar.empty_long")}
          </p>
        </Card>
      ) : (
        <Card>
          <div className="flex items-center justify-between px-1 pb-3 mb-1 border-b border-[rgb(var(--border))]/6">
            <p className="text-[12px] text-[rgb(var(--t3))]">{t("quar.quarantined_items").replace("{count}", String(items.length))}</p>
          </div>
          {items.map((item, idx) => {
            const exp = expanded === item.id;
            const isBusy = busy === item.id;
            const isArgus = item.signature.startsWith("ARGUS/");
            const scoreMatch = item.signature.match(/\[(\d+)\/100\]/);
            const score = scoreMatch ? parseInt(scoreMatch[1]) : null;
            const cleanSignature = item.signature.replace(/\s*\[\d+\/100\]/, "");
            return (
              <div key={item.id} className={idx > 0 ? "border-t border-[rgb(var(--border))]/8" : ""}>
                <button onClick={() => setExpanded(exp ? null : item.id)} className="w-full flex items-center gap-4 py-4 text-left cursor-pointer hover:bg-[rgb(var(--raised))]/10 transition-colors px-1 rounded-lg">
                  <FileWarning size={16} className="text-[rgb(var(--red))] flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-[13px] font-medium">{item.original_path.split('\\').pop()}</p>
                    <p className="text-[11px] text-[rgb(var(--t3))]/40 truncate">{cleanSignature}</p>
                  </div>
                  {score !== null && (
                    <span className="text-[9px] font-semibold uppercase px-1.5 py-0.5 rounded bg-[rgb(var(--amber))]/8 text-[rgb(var(--amber))] flex-shrink-0" title={t("quar.argus_score_tooltip")}>
                      {score}/100
                    </span>
                  )}
                  <span className={`text-[9px] font-semibold uppercase px-1.5 py-0.5 rounded flex-shrink-0 ${isArgus ? "bg-[rgb(var(--amber))]/8 text-[rgb(var(--amber))]" : "bg-[rgb(var(--red))]/8 text-[rgb(var(--red))]"}`}>
                    {isArgus ? t("scan.heuristic") : t("scan.signature")}
                  </span>
                  <p className="text-[11px] text-[rgb(var(--t3))]/30">{new Date(item.quarantined_at * 1000).toLocaleDateString()}</p>
                  {exp ? <ChevronUp size={14} className="text-[rgb(var(--t3))]/25"/> : <ChevronDown size={14} className="text-[rgb(var(--t3))]/25"/>}
                </button>
                {exp && (
                  <div className="pb-4 pl-10">
                    <div className="mb-4 grid gap-x-8 gap-y-3 text-[12px] md:grid-cols-2">
                      <div><p className="text-[rgb(var(--t3))]/30 text-[10px] uppercase">{t("quar.label_path")}</p><p className="font-medium truncate">{item.original_path}</p></div>
                      <div><p className="text-[rgb(var(--t3))]/30 text-[10px] uppercase">{t("quar.label_detection")}</p><p className="font-medium">{cleanSignature}</p></div>
                      <div><p className="text-[rgb(var(--t3))]/30 text-[10px] uppercase">{t("quar.label_sha256")}</p><p className="font-mono text-[11px]">{item.sha256.slice(0, 24)}...</p></div>
                      <div><p className="text-[rgb(var(--t3))]/30 text-[10px] uppercase">{t("quar.label_size")}</p><p className="font-medium">{item.original_size.toLocaleString()} {t("quar.bytes")}</p></div>
                    </div>
                    <p className="mb-4 text-[11px] leading-relaxed text-[rgb(var(--t3))]">
                      {isArgus
                        ? (score !== null ? t("quar.why_argus_scored").replace("{score}", String(score)) : t("quar.why_argus"))
                        : t("quar.why_signature")}
                    </p>
                    <div className="flex gap-3 flex-wrap">
                      <button
                        disabled={!item.restorable || isBusy}
                        onClick={() => setConfirm({ type: "restore", item })}
                        className="text-[11px] font-medium px-4 py-2 rounded-xl bg-[rgb(var(--raised))]/25 text-[rgb(var(--t2))] flex items-center gap-1.5 cursor-pointer disabled:opacity-30"
                        title={!item.restorable ? t("quar.not_restorable") : t("quar.restore_tooltip")}
                      >
                        {isBusy ? <Loader2 size={12} className="animate-spin"/> : <RotateCcw size={12}/>}
                        {t("quar.restore")}
                      </button>
                      <button
                        disabled={!item.restorable || isBusy}
                        onClick={() => handleRestoreAs(item)}
                        className="text-[11px] font-medium px-4 py-2 rounded-xl bg-[rgb(var(--raised))]/25 text-[rgb(var(--t2))] flex items-center gap-1.5 cursor-pointer disabled:opacity-30"
                        title={t("quar.restore_as_tooltip")}
                      >
                        {isBusy ? <Loader2 size={12} className="animate-spin"/> : <FolderOpen size={12}/>}
                        {t("quar.restore_as")}
                      </button>
                      <button
                        disabled={!item.restorable || isBusy}
                        onClick={() => setConfirm({ type: "restore_safe", item })}
                        className="text-[11px] font-medium px-4 py-2 rounded-xl bg-[rgb(var(--green))]/6 text-[rgb(var(--green))] flex items-center gap-1.5 cursor-pointer disabled:opacity-30"
                        title={t("quar.report_safe_tooltip")}
                      >
                        <ShieldCheck size={12}/>{t("quar.report_safe")}
                      </button>
                      <button
                        disabled={isBusy}
                        onClick={() => setConfirm({ type: "delete", item })}
                        className="text-[11px] font-medium px-4 py-2 rounded-xl bg-[rgb(var(--red))]/6 text-[rgb(var(--red))] flex items-center gap-1.5 cursor-pointer disabled:opacity-30"
                      >
                        <Trash2 size={12}/>{t("quar.delete")}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </Card>
      )}
    </div>
  );
}
