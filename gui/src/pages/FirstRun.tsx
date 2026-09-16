import { useState, useEffect } from "react";
import {
  Shield, CheckCircle, RefreshCw, Search, Loader2, WifiOff, Zap, ArrowRight,
} from "lucide-react";
import { Card } from "../components/Card";
import { getEngineStatus, startSignatureUpdate, getUpdateStatus, startQuickScan } from "../api/sentinella";
import { notifyFirstRunUpdateComplete, notifyFirstRunUpdateFailed } from "../notifications";
import { tf } from "../i18n";
import type { EngineStatus } from "../types/sentinella";

// The wizard is the FIRST screen a user ever sees, and it renders before they
// can reach the language selector (Settings → Appearance is behind it), so a
// ja-JP / ru-RU machine used to get an entirely English onboarding even though
// initLocale() had already detected the locale.
//
// None of the `firstrun.*` keys exist in the locale files yet, so every string
// goes through tf(key, english) — identical output today, translated the
// moment the keys are added, and never a raw "firstrun.foo" on screen.
type Step = "welcome" | "signatures" | "scan" | "done";

const STORAGE_KEY = "sentinella-first-run-complete";

/** Check if first-run wizard has been completed. */
export function isFirstRunComplete(): boolean {
  return localStorage.getItem(STORAGE_KEY) === "true";
}

/** Mark first-run as complete. */
function markComplete() {
  localStorage.setItem(STORAGE_KEY, "true");
}

function StepDots({ current }: { current: 0 | 1 | 2 }) {
  return (
    <div className="flex items-center justify-center gap-2 mb-8" aria-hidden="true">
      {[0, 1, 2].map((i) => (
        <span
          key={i}
          className={`h-1.5 rounded-full transition-all duration-300 ${
            i === current ? "w-6 bg-[rgb(var(--accent))]" : "w-1.5 bg-[rgb(var(--raised))]/60"
          }`}
        />
      ))}
    </div>
  );
}

export function FirstRunWizard({ onComplete }: { onComplete: () => void }) {
  const [step, setStep] = useState<Step>("welcome");
  const [engine, setEngine] = useState<EngineStatus | null>(null);
  const [connected, setConnected] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [updateDone, setUpdateDone] = useState(false);
  const [scanning, setScanning] = useState(false);

  // Check daemon connection.
  useEffect(() => {
    const check = () => {
      getEngineStatus()
        .then((e) => { setEngine(e); setConnected(true); })
        .catch(() => setConnected(false));
    };
    check();
    const interval = setInterval(check, 3000);
    return () => clearInterval(interval);
  }, []);

  // Poll update status while updating.
  useEffect(() => {
    if (!updating) return;
    const poll = setInterval(() => {
      getUpdateStatus()
        .then((s) => {
          if (s.state === "idle" || s.state === "error") {
            setUpdating(false);
            setUpdateDone(true);
            // Refresh engine status + notify.
            getEngineStatus().then((e) => {
              setEngine(e);
              if (s.state === "error") {
                notifyFirstRunUpdateFailed();
              } else if (e.signature_count > 0) {
                notifyFirstRunUpdateComplete(e.signature_count);
              }
            }).catch(() => {});
          }
        })
        .catch(() => {});
    }, 2000);
    return () => clearInterval(poll);
  }, [updating]);

  const hasSigs = (engine?.signature_count ?? 0) > 0;

  const finish = () => {
    markComplete();
    onComplete();
  };

  return (
    <div className="flex h-screen items-center justify-center bg-[rgb(var(--base))]">
      <div className="w-full max-w-lg px-6">

        <StepDots current={step === "welcome" ? 0 : step === "signatures" ? 1 : 2} />

        {/* ── Welcome ── */}
        {step === "welcome" && (
          <div className="text-center animate-in fade-in">
            <div className="flex h-20 w-20 mx-auto items-center justify-center rounded-3xl bg-gradient-to-br from-[rgb(var(--accent))] to-[rgb(var(--accent))]/60 mb-8 shadow-lg shadow-[rgb(var(--accent))]/10">
              <Shield size={36} className="text-white" />
            </div>
            <h1 className="text-[28px] font-bold text-[rgb(var(--t1))] mb-3">
              {tf("firstrun.welcome_title", "Welcome to Sentinella")}
            </h1>
            <p className="text-[14px] text-[rgb(var(--t2))] leading-relaxed mb-2">
              {tf("firstrun.welcome_desc", "Local-first antivirus powered by ClamAV signatures and the ARGUS heuristic intelligence engine.")}
            </p>
            <p className="text-[12px] text-[rgb(var(--t3))] leading-relaxed mb-10">
              {tf("firstrun.welcome_privacy", "Everything runs on your machine. No cloud dependency. No telemetry. Full transparency.")}
            </p>

            {!connected ? (
              <div className="flex items-center justify-center gap-3 text-[13px] text-[rgb(var(--amber))] mb-6">
                <WifiOff size={16} />
                <span>{tf("firstrun.waiting_daemon", "Waiting for daemon connection...")}</span>
                <Loader2 size={14} className="animate-spin" />
              </div>
            ) : (
              <>
                <button onClick={() => setStep("signatures")}
                  className="flex items-center justify-center gap-2.5 mx-auto px-8 py-3.5 rounded-xl bg-[rgb(var(--accent))] text-white text-[14px] font-semibold hover:opacity-90 cursor-pointer shadow-sm shadow-[rgb(var(--accent))]/15">
                  {tf("firstrun.get_started", "Get Started")} <ArrowRight size={16} />
                </button>
                <button onClick={finish}
                  className="mx-auto mt-5 block text-[12px] text-[rgb(var(--t3))] hover:text-[rgb(var(--t1))] cursor-pointer">
                  {tf("firstrun.skip_setup", "Skip setup")}
                </button>
              </>
            )}
          </div>
        )}

        {/* ── Signatures ── */}
        {step === "signatures" && (
          <div className="animate-in fade-in">
            <div className="flex items-center gap-3 mb-6">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[rgb(var(--accent))]/8">
                <RefreshCw size={18} className="text-[rgb(var(--accent))]" />
              </div>
              <div>
                <h2 className="text-[18px] font-bold">{tf("firstrun.signatures_title", "Signature Database")}</h2>
                <p className="text-[12px] text-[rgb(var(--t3))] mt-0.5">{tf("firstrun.step_1", "Step 1 of 2")}</p>
              </div>
            </div>

            <Card>
              {hasSigs && !updating ? (
                <div className="flex items-center gap-4">
                  <CheckCircle size={20} className="text-[rgb(var(--green))] flex-shrink-0" />
                  <div className="flex-1">
                    <p className="text-[14px] font-semibold text-[rgb(var(--green))]">{tf("firstrun.sigs_loaded", "Signatures Loaded")}</p>
                    <p className="text-[12px] text-[rgb(var(--t3))] mt-1">
                      {tf("firstrun.sigs_active", "{n} virus definitions active.").replace("{n}", engine!.signature_count.toLocaleString())}
                    </p>
                  </div>
                </div>
              ) : updating ? (
                <div className="flex items-center gap-4">
                  <Loader2 size={20} className="text-[rgb(var(--accent))] animate-spin flex-shrink-0" />
                  <div className="flex-1">
                    <p className="text-[14px] font-semibold">{tf("firstrun.updating", "Updating Signatures...")}</p>
                    <p className="text-[12px] text-[rgb(var(--t3))] mt-1">
                      {tf("firstrun.updating_desc", "Downloading the latest virus definitions. This may take a minute.")}
                    </p>
                  </div>
                </div>
              ) : updateDone ? (
                <div className="flex items-center gap-4">
                  <CheckCircle size={20} className="text-[rgb(var(--green))] flex-shrink-0" />
                  <div className="flex-1">
                    <p className="text-[14px] font-semibold text-[rgb(var(--green))]">{tf("firstrun.update_done", "Update Complete")}</p>
                    <p className="text-[12px] text-[rgb(var(--t3))] mt-1">
                      {engine?.signature_count
                        ? tf("firstrun.update_done_count", "{n} signatures loaded.").replace("{n}", engine.signature_count.toLocaleString())
                        : tf("firstrun.update_done_generic", "Database updated.")}
                    </p>
                  </div>
                </div>
              ) : (
                <div>
                  <p className="text-[14px] font-semibold text-[rgb(var(--amber))]">{tf("firstrun.no_sigs", "No Signatures Found")}</p>
                  <p className="text-[12px] text-[rgb(var(--t3))] mt-1 mb-4">
                    {tf("firstrun.no_sigs_desc", "Sentinella needs virus definitions to detect threats. We strongly recommend updating now.")}
                  </p>
                  <button onClick={() => {
                    setUpdating(true);
                    startSignatureUpdate().catch(() => setUpdating(false));
                  }} className="px-5 py-2.5 rounded-xl bg-[rgb(var(--accent))] text-white text-[13px] font-semibold hover:opacity-90 cursor-pointer">
                    {tf("firstrun.update_now", "Update Signatures Now")}
                  </button>
                </div>
              )}
            </Card>

            <div className="flex justify-between mt-8">
              <button onClick={() => setStep("welcome")}
                className="text-[12px] text-[rgb(var(--t3))] hover:text-[rgb(var(--t1))] cursor-pointer">
                {tf("firstrun.back", "Back")}
              </button>
              <button onClick={() => setStep("scan")} disabled={updating}
                className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-[rgb(var(--accent))] text-white text-[13px] font-semibold hover:opacity-90 cursor-pointer disabled:opacity-40">
                {tf("firstrun.continue", "Continue")} <ArrowRight size={14} />
              </button>
            </div>
          </div>
        )}

        {/* ── Optional Scan ── */}
        {step === "scan" && (
          <div className="animate-in fade-in">
            <div className="flex items-center gap-3 mb-6">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[rgb(var(--accent))]/8">
                <Search size={18} className="text-[rgb(var(--accent))]" />
              </div>
              <div>
                <h2 className="text-[18px] font-bold">{tf("firstrun.scan_title", "Initial Scan")}</h2>
                <p className="text-[12px] text-[rgb(var(--t3))] mt-0.5">{tf("firstrun.step_2", "Step 2 of 2 — Optional")}</p>
              </div>
            </div>

            <Card>
              {scanning ? (
                <div className="flex items-center gap-4">
                  <Loader2 size={20} className="text-[rgb(var(--accent))] animate-spin flex-shrink-0" />
                  <div className="flex-1">
                    <p className="text-[14px] font-semibold">{tf("firstrun.scan_started", "Quick Scan Started")}</p>
                    <p className="text-[12px] text-[rgb(var(--t3))] mt-1">
                      {tf("firstrun.scan_started_desc", "Scanning Downloads, Desktop, and Temp folders. You can monitor progress from the Dashboard.")}
                    </p>
                  </div>
                </div>
              ) : (
                <div>
                  <p className="text-[14px] font-semibold">{tf("firstrun.scan_prompt", "Run a Quick Scan?")}</p>
                  <p className="text-[12px] text-[rgb(var(--t3))] mt-1 mb-4 leading-relaxed">
                    {tf("firstrun.scan_prompt_desc", "A quick scan checks your Downloads, Desktop, and Temp folders for threats. This is optional — you can always scan later from the Scan page.")}
                  </p>
                  <button onClick={() => {
                    setScanning(true);
                    startQuickScan().catch(() => {});
                  }} className="flex items-center gap-2 px-5 py-2.5 rounded-xl border border-[rgb(var(--accent))]/20 text-[rgb(var(--accent))] text-[13px] font-semibold hover:bg-[rgb(var(--accent))]/5 cursor-pointer">
                    <Zap size={14} /> {tf("firstrun.run_quick_scan", "Run Quick Scan")}
                  </button>
                </div>
              )}
            </Card>

            <div className="flex justify-between mt-8">
              <button onClick={() => setStep("signatures")}
                className="text-[12px] text-[rgb(var(--t3))] hover:text-[rgb(var(--t1))] cursor-pointer">
                {tf("firstrun.back", "Back")}
              </button>
              <button onClick={finish}
                className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-[rgb(var(--accent))] text-white text-[13px] font-semibold hover:opacity-90 cursor-pointer">
                {scanning
                  ? tf("firstrun.continue_dashboard", "Continue to Dashboard")
                  : tf("firstrun.finish", "Finish Setup")} <ArrowRight size={14} />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
