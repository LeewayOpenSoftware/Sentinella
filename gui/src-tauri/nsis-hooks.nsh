; Sentinella NSIS installer hooks
; Runs with elevated privileges during install/uninstall.
;
; INSTDIR     = where Tauri installs the GUI app (e.g., C:\Program Files\Sentinella)
; Resources   = resolved to $SENTI_DAEMON\*
; PROGRAMDATA = C:\ProgramData\Sentinella (PathManager root in installed mode)

!macro NSIS_HOOK_PREINSTALL
  ; ORDER IS LOAD-BEARING, for the same reason it is in PREUNINSTALL.
  ;
  ; An UPGRADE does not run the old uninstaller: installer.nsi skips it in
  ; update mode, and the non-uninstall radio choice skips it interactively.
  ; So NSIS_HOOK_PREUNINSTALL — which holds the careful --remove ladder — is
  ; NOT executed on the upgrade path. This hook is the only thing that runs.
  ;
  ; It used to `taskkill /F` sentinelld.exe first. That destroys the only
  ; in-process path that removes the NRPT rule (WebProtection::stop), so
  ; every upgrade left a catch-all rule routing all DNS at a port whose
  ; listener had just been killed. For the length of the install the machine
  ; had NO DNS, and if the install then aborted it stayed that way until the
  ; next reboot, with the service already deleted.
  ;
  ; So: ask nicely first, and remove the rule explicitly before resorting to
  ; force.

  ; 1. Graceful stop. Lets the daemon run its own shutdown, which removes the
  ;    rule and is the only path that also stops the proxy cleanly.
  nsExec::ExecToLog 'sc stop SentinellaDaemon'
  Sleep 3000

  ; 2. Belt and braces: remove the rule out-of-process, whether or not the
  ;    daemon was running or managed to do it itself. This is the OLD
  ;    install's binary — PREINSTALL runs before Tauri overwrites files, so
  ;    it is still on disk. Missing (fresh install, or an older version that
  ;    predates the reconciler) is fine: there is no rule to remove.
  IfFileExists "$INSTDIR\daemon\sentinella-dnsreconcile.exe" 0 +3
    nsExec::ExecToLog '"$INSTDIR\daemon\sentinella-dnsreconcile.exe" --remove'
    Goto senti_rule_check
  IfFileExists "$INSTDIR\resources\daemon\sentinella-dnsreconcile.exe" 0 senti_rule_done
    nsExec::ExecToLog '"$INSTDIR\resources\daemon\sentinella-dnsreconcile.exe" --remove'
  senti_rule_check:
  Pop $0
  StrCmp $0 "0" senti_rule_done 0
    ; The removal FAILED and this is an UPGRADE, so warn, don't abort —
    ; the asymmetry with PREUNINSTALL (which aborts on the same failure)
    ; is deliberate. An aborted uninstall leaves the old product fully in
    ; place, reconciler task included, so the next boot repairs itself.
    ; An aborted upgrade leaves the OLD daemon already stopped and deleted
    ; below, the rule live, and nothing new installed — the worst version
    ; of the state. Continuing installs the new daemon, whose startup
    ; reconcile_orphan_rule removes a stale rule in-session, and the boot
    ; reconciler backstops that on the next reboot.
    ;
    ; Note exit 3 means "an orphan-pattern rule is present, surfaced, not
    ; deleted" — the message below covers it, because that state also ends
    ; with a human reading the log.
    IfSilent senti_rule_done 0
      MessageBox MB_ICONEXCLAMATION|MB_OK "Sentinella's old DNS policy rule could not be fully removed before the upgrade (code $0).$\n$\nThe upgrade will continue; the new installation removes a leftover rule automatically at startup. If name resolution is broken afterwards, reboot - the boot-time reconciler removes the rule.$\n$\nDetails: %ProgramData%\Sentinella\logs\dnsreconcile.log"
  senti_rule_done:

  ; 3. Only now force. Otherwise Windows keeps sentinelld.exe locked and NSIS
  ;    leaves the previous engine binary installed.
  nsExec::ExecToLog 'taskkill /F /IM gui.exe'
  nsExec::ExecToLog 'taskkill /F /IM Sentinella.exe'
  nsExec::ExecToLog 'taskkill /F /IM sentinelld.exe'
  nsExec::ExecToLog 'taskkill /F /IM argusd.exe'
  nsExec::ExecToLog 'taskkill /F /IM freshclam.exe'
  nsExec::ExecToLog 'sc delete SentinellaDaemon'
  Sleep 3000
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; Resolve ProgramData via env var (handles non-C: system drives).
  Var /GLOBAL SENTI_DATA
  Var /GLOBAL SENTI_DAEMON
  Var /GLOBAL SENTI_PD
  ReadEnvStr $SENTI_PD "ProgramData"
  StrCmp $SENTI_PD "" 0 +2
    StrCpy $SENTI_PD "C:\ProgramData"
  StrCpy $SENTI_DATA "$SENTI_PD\Sentinella"
  ; Tauri 2 NSIS unpacks bundle.resources to $INSTDIR\daemon (mapping preserved).
  ; Fallback to $INSTDIR\resources\daemon in case Tauri version changes behavior.
  StrCpy $SENTI_DAEMON "$INSTDIR\daemon"
  IfFileExists "$SENTI_DAEMON\sentinelld.exe" +2 0
    StrCpy $SENTI_DAEMON "$INSTDIR\resources\daemon"

  ; === Create ProgramData directory structure ===
  CreateDirectory "$SENTI_DATA"
  CreateDirectory "$SENTI_DATA\config"
  CreateDirectory "$SENTI_DATA\signatures"
  CreateDirectory "$SENTI_DATA\state"
  CreateDirectory "$SENTI_DATA\logs"
  CreateDirectory "$SENTI_DATA\quarantine"
  CreateDirectory "$SENTI_DATA\cache"
  CreateDirectory "$SENTI_DATA\argus"
  CreateDirectory "$SENTI_DATA\argus\rules"
  CreateDirectory "$SENTI_DATA\argus\rules\yara"
  CreateDirectory "$SENTI_DATA\argus\manifests"
  CreateDirectory "$SENTI_DATA\rules"
  CreateDirectory "$SENTI_DATA\rules\dns"
  CreateDirectory "$SENTI_DATA\rules\dns\managed"
  CreateDirectory "$SENTI_DATA\clamav_tmp"
  CreateDirectory "$SENTI_DATA\diagnostics"
  CreateDirectory "$SENTI_DATA\enhanced_signatures"
  CreateDirectory "$SENTI_DATA\update_staging"

  ; === Copy config templates (don't overwrite existing) ===
  IfFileExists "$SENTI_DATA\config\freshclam.conf" +2 0
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\config\freshclam.conf" "$SENTI_DATA\config\"
  IfFileExists "$SENTI_DATA\config\sentinelld.toml" +2 0
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\config\sentinelld.toml" "$SENTI_DATA\config\"

  ; === [web_protection] default section (append only if absent) ===
  ; The shipped template has no [web_protection] section, so without this
  ; a user who enables web protection filters with the compiled-in canary
  ; only: neither the vendored seed nor the managed copy is referenced by
  ; any default config (audit unit-3 F4). enabled=false is deliberate and
  ; load-bearing: the NRPT rule must never appear before explicit opt-in
  ; (degrade to no filtering, never no DNS). listen/upstreams/
  ; health_check_name match the daemon defaults (web_protection/config.rs)
  ; so the written section validates clean.
  ;
  ; Probe-then-append, never clobber. The whole-file guard above already
  ; never overwrites sentinelld.toml, and this extends the same semantics
  ; to a file the template grew into: a user-edited section (custom
  ; upstreams, corporate allowlist, enabled=true) survives every upgrade
  ; untouched.
  ;
  ; The daemon-side alternative — load_lists falling back to the managed
  ; path when blocklists is empty — was considered and NOT taken: wiring
  ; the path explicitly here keeps "which list filters me" visible in the
  ; config the user edits, and lists.rs deliberately deferred that
  ; fallback. One mechanism, not two.
  Var /GLOBAL SENTI_WP_SECTION
  StrCpy $SENTI_WP_SECTION "0"
  FileOpen $0 "$SENTI_DATA\config\sentinelld.toml" r
  IfErrors senti_wp_probe_done
  senti_wp_read:
    FileRead $0 $1
    IfErrors senti_wp_probe_close
  senti_wp_ltrim:
    StrCpy $2 $1 1
    StrCmp $2 " " senti_wp_drop
    StrCmp $2 "$\t" senti_wp_drop
    Goto senti_wp_compare
  senti_wp_drop:
    StrCpy $1 $1 "" 1
    StrCmp $1 "" senti_wp_read senti_wp_ltrim
  senti_wp_compare:
    StrCpy $2 $1 16
    StrCmp $2 "[web_protection]" 0 senti_wp_read
    StrCpy $SENTI_WP_SECTION "1"
  senti_wp_probe_close:
    FileClose $0
  senti_wp_probe_done:

  StrCmp $SENTI_WP_SECTION "1" senti_wp_done 0
  FileOpen $0 "$SENTI_DATA\config\sentinelld.toml" a
  IfErrors senti_wp_done
    ; The leading blank line guards a file with no trailing newline; TOML
    ; tolerates blank lines. The template is LF, so the appended lines are
    ; LF too — mixed endings in one config are a needless surprise.
    FileWrite $0 "$\n"
    FileWrite $0 "[web_protection]$\n"
    FileWrite $0 "enabled = false$\n"
    FileWrite $0 'listen = "127.0.0.1:53"$\n'
    FileWrite $0 'upstreams = ["system"]$\n'
    FileWrite $0 'block_response = "nxdomain"$\n'
    FileWrite $0 'health_check_name = "example.com"$\n'
    ; Single-quoted TOML literal string: backslashes need no escaping.
    FileWrite $0 "blocklists = ['$SENTI_DATA\rules\dns\managed\stevenblack.hosts']$\n"
    FileWrite $0 "allowlist = []$\n"
    FileWrite $0 "log_queries = false$\n"
    FileClose $0
  senti_wp_done:

  ; === Copy YARA rules ===
  CopyFiles /SILENT "$SENTI_DAEMON\runtime\argus\rules\yara\*.yar" "$SENTI_DATA\argus\rules\yara\"

  ; === Copy manifests ===
  CopyFiles /SILENT "$SENTI_DAEMON\runtime\argus\manifests\*.*" "$SENTI_DATA\argus\manifests\"

  ; === Copy IOC hashes ===
  CopyFiles /SILENT "$SENTI_DAEMON\runtime\rules\*.*" "$SENTI_DATA\rules\"

  ; === Copy the bundled DNS blocklist (only if absent) ===
  ; Same per-file guard as the bootstrap signature databases below, for
  ; the same reason: an upgrade must never overwrite a list the user
  ; replaced. This is the OFFLINE SEED — the daemon's managed-list fetcher
  ; refreshes its own copy under rules\dns\managed\ on each update cycle,
  ; so the guard costs no freshness. The wildcard copy above does not
  ; reach subdirectories, so this file needs its own copy.
  IfFileExists "$SENTI_DATA\rules\dns\stevenblack.hosts" senti_dns_done 0
  IfFileExists "$SENTI_DAEMON\runtime\rules\dns\stevenblack.hosts" 0 senti_dns_done
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\rules\dns\stevenblack.hosts" "$SENTI_DATA\rules\dns\"
  senti_dns_done:

  ; === Seed the MANAGED copy of the DNS blocklist (only if absent) ===
  ; The [web_protection] section above points blocklists at the managed
  ; path, which the daemon's fetcher refreshes on each update cycle. Until
  ; the first successful fetch that file does not exist, so first-enable
  ; on an offline machine would filter canary-only; seeding it from the
  ; vendored copy closes that window. Same per-file guard as every other
  ; seed in this hook, for the same reason: an upgrade must never
  ; overwrite a copy the fetcher (or the user) has already refreshed.
  IfFileExists "$SENTI_DATA\rules\dns\managed\stevenblack.hosts" senti_dns_managed_done 0
  IfFileExists "$SENTI_DAEMON\runtime\rules\dns\stevenblack.hosts" 0 senti_dns_managed_done
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\rules\dns\stevenblack.hosts" "$SENTI_DATA\rules\dns\managed\"
  senti_dns_managed_done:

  ; === Copy bootstrap ClamAV signatures (per database, only if absent) ===
  ; This avoids overwriting newer signatures from a previous install/freshclam.
  ;
  ; EACH DATABASE IS GATED SEPARATELY. Gating all of them behind main.* — as
  ; this used to — makes a bundle that ships no daily database permanent: main
  ; is present afterwards, so every later install skips the whole block too,
  ; and an offline machine never gets ClamAV's recent-malware coverage at all.
  ; That is not hypothetical; the 0.1.13 bundle shipped without a daily DB.
  ;
  ; Both extensions are tested on BOTH sides. freshclam replaces a .cvd with
  ; an incremental .cld in place, so "already present" must accept .cld or a
  ; stale bootstrap .cvd lands beside a newer .cld → mixed-version DB; and the
  ; bundle may carry either, because it is staged from a tree freshclam has
  ; already updated. .cvd wins when the bundle somehow holds both, so we never
  ; install two generations of the same database.
  Var /GLOBAL SENTI_BOOTSTRAPPED
  StrCpy $SENTI_BOOTSTRAPPED "0"

  IfFileExists "$SENTI_DATA\signatures\main.cvd" senti_main_done 0
  IfFileExists "$SENTI_DATA\signatures\main.cld" senti_main_done 0
  IfFileExists "$SENTI_DAEMON\runtime\signatures_bootstrap\main.cvd" 0 senti_main_cld
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\signatures_bootstrap\main.cvd" "$SENTI_DATA\signatures\"
    StrCpy $SENTI_BOOTSTRAPPED "1"
    Goto senti_main_done
  senti_main_cld:
  IfFileExists "$SENTI_DAEMON\runtime\signatures_bootstrap\main.cld" 0 senti_main_done
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\signatures_bootstrap\main.cld" "$SENTI_DATA\signatures\"
    StrCpy $SENTI_BOOTSTRAPPED "1"
  senti_main_done:

  IfFileExists "$SENTI_DATA\signatures\daily.cvd" senti_daily_done 0
  IfFileExists "$SENTI_DATA\signatures\daily.cld" senti_daily_done 0
  IfFileExists "$SENTI_DAEMON\runtime\signatures_bootstrap\daily.cvd" 0 senti_daily_cld
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\signatures_bootstrap\daily.cvd" "$SENTI_DATA\signatures\"
    StrCpy $SENTI_BOOTSTRAPPED "1"
    Goto senti_daily_done
  senti_daily_cld:
  IfFileExists "$SENTI_DAEMON\runtime\signatures_bootstrap\daily.cld" 0 senti_daily_done
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\signatures_bootstrap\daily.cld" "$SENTI_DATA\signatures\"
    StrCpy $SENTI_BOOTSTRAPPED "1"
  senti_daily_done:

  IfFileExists "$SENTI_DATA\signatures\bytecode.cvd" senti_bytecode_done 0
  IfFileExists "$SENTI_DATA\signatures\bytecode.cld" senti_bytecode_done 0
  IfFileExists "$SENTI_DAEMON\runtime\signatures_bootstrap\bytecode.cvd" 0 senti_bytecode_cld
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\signatures_bootstrap\bytecode.cvd" "$SENTI_DATA\signatures\"
    StrCpy $SENTI_BOOTSTRAPPED "1"
    Goto senti_bytecode_done
  senti_bytecode_cld:
  IfFileExists "$SENTI_DAEMON\runtime\signatures_bootstrap\bytecode.cld" 0 senti_bytecode_done
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\signatures_bootstrap\bytecode.cld" "$SENTI_DATA\signatures\"
    StrCpy $SENTI_BOOTSTRAPPED "1"
  senti_bytecode_done:

  ; The .sign files are ClamAV's external signatures for the databases above,
  ; so they only travel when a database actually did. Dropping them next to a
  ; machine's own freshclam-updated DBs would leave sign files naming versions
  ; that are no longer there.
  StrCmp $SENTI_BOOTSTRAPPED "0" senti_sign_done 0
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\signatures_bootstrap\*.sign" "$SENTI_DATA\signatures\"
  senti_sign_done:

  ; freshclam.dat is deliberately NOT copied, even though the bundle carries
  ; one. That file stores the UUID libfreshclam puts in the User-Agent of
  ; every CDN request, so shipping one prebuilt copy makes the entire install
  ; base present to ClamAV's CDN as a single client: one shared rate-limit
  ; bucket for everyone, and one correlatable identity handed to a third
  ; party. Absent, freshclam generates a UUID per machine on first run.
  ; (ClamAV's own Docker images delete this file for the same reason —
  ; third_party/clamav/NEWS.md.)

  ; === Stop existing service if running (upgrade scenario) ===
  ; ASK FIRST WHETHER THERE IS A SERVICE AT ALL. sc query exits 1060 for
  ; "service does not exist". The poll below only tests the query OUTPUT for
  ; ": 1 " (STOPPED) through findstr, and a 1060 error message contains no
  ; ": 1 " either — so "never installed" looked exactly like "still stopping"
  ; and every clean install sat through the full 30s cap, plus the 15s delete
  ; cap, in front of a frozen progress bar before anything happened.
  nsExec::Exec 'cmd /c sc query SentinellaDaemon'
  Pop $0
  StrCmp $0 "1060" senti_service_absent 0

  ; Poll until STATE != RUNNING/STOP_PENDING. Slow IO machines need >2s for
  ; clean stop after libclamav.dll DLL flush; old fixed Sleep 2000 raced ahead
  ; and the subsequent sc delete then went into DELETE_PENDING, breaking
  ; sc create on next install. Cap at 30s.
  nsExec::ExecToLog 'sc stop SentinellaDaemon'
  Var /GLOBAL STOP_TRIES
  StrCpy $STOP_TRIES 0
  poll_stopped:
    Sleep 1000
    IntOp $STOP_TRIES $STOP_TRIES + 1
    nsExec::Exec 'cmd /c sc query SentinellaDaemon | findstr /C:": 1 "'
    Pop $0
    StrCmp $0 "0" stopped_ok 0
    IntCmp $STOP_TRIES 30 stopped_ok 0 stopped_ok
    Goto poll_stopped
  stopped_ok:

  ; === Delete old service if exists (upgrade) ===
  nsExec::ExecToLog 'sc delete SentinellaDaemon'
  ; Poll until "service does not exist" (exit 1060). Cap at 15s.
  Var /GLOBAL DEL_TRIES
  StrCpy $DEL_TRIES 0
  poll_deleted:
    Sleep 1000
    IntOp $DEL_TRIES $DEL_TRIES + 1
    nsExec::Exec 'cmd /c sc query SentinellaDaemon'
    Pop $0
    StrCmp $0 "1060" deleted_ok 0
    IntCmp $DEL_TRIES 15 deleted_ok 0 deleted_ok
    Goto poll_deleted
  deleted_ok:
  senti_service_absent:

  ; === Register Windows service (no --foreground → uses Windows Service API) ===
  ; The result IS checked. It used to be neither popped nor tested, so an
  ; sc create that failed — 1072 (marked for deletion) after the poll above
  ; times out on a wedged daemon is the realistic one — produced an installer
  ; that reported complete success and a machine with an antivirus and no
  ; service behind it: no realtime protection, and no error anywhere but the
  ; scrollback of the details pane.
  nsExec::ExecToLog 'sc create SentinellaDaemon binPath= "\"$SENTI_DAEMON\sentinelld.exe\" --log-level info --runtime-root \"$SENTI_DATA\" --dll-dir \"$SENTI_DAEMON\" --db-dir \"$SENTI_DATA\signatures\"" DisplayName= "Sentinella Protection Service" start= delayed-auto obj= "LocalSystem"'
  Pop $0
  StrCmp $0 "0" senti_service_ready 0
    ; Non-zero is not automatically fatal: 1073 "service already exists" means
    ; the delete never completed, and that service's binPath is the very file
    ; we just overwrote, so it runs the new daemon. Ask sc what actually
    ; exists rather than enumerating error codes — either a service is
    ; registered under this name or it is not.
    nsExec::Exec 'cmd /c sc query SentinellaDaemon'
    Pop $1
    StrCmp $1 "0" senti_service_ready 0
      ; Silent installs (the Tauri updater runs this with /S) must not block
      ; on a MessageBox nobody can click; the exit code is how they find out.
      SetErrorLevel 1
      IfSilent senti_service_ready 0
        MessageBox MB_ICONSTOP|MB_OK "Sentinella could not register its protection service (sc create failed, code $0).$\n$\nThe application is installed but real-time protection is NOT running. Reboot and run this installer again.$\n$\nDetails: %ProgramData%\Sentinella\logs"
  senti_service_ready:

  ; === Set service description ===
  nsExec::ExecToLog 'sc description SentinellaDaemon "Sentinella antivirus daemon with ClamAV signatures and ARGUS heuristic intelligence engine."'

  ; === Configure failure recovery: restart on failure ===
  nsExec::ExecToLog 'sc failure SentinellaDaemon reset= 86400 actions= restart/5000/restart/10000/restart/30000'

  ; Signature updates are handled by the daemon scheduler (every N hours).
  ; Bootstrap signatures shipped with installer get user protected immediately.

  ; === Start the service ===
  ; 1056 = already running (the service survived the stop poll above).
  ; A failure here is recoverable on its own — start= delayed-auto means
  ; Windows starts it at the next boot — but silence left the user believing
  ; real-time protection was live right now, which it is not.
  nsExec::ExecToLog 'sc start SentinellaDaemon'
  Pop $0
  StrCmp $0 "0" senti_service_started 0
  StrCmp $0 "1056" senti_service_started 0
    IfSilent senti_service_started 0
      MessageBox MB_ICONEXCLAMATION|MB_OK "Sentinella is installed, but its protection service did not start (code $0).$\n$\nProtection will start automatically at the next reboot. To start it now, run as administrator:$\n  sc start SentinellaDaemon"
  senti_service_started:

  ; === Register the boot-time NRPT reconciler task ===
  ;
  ; WHY THIS IS HERE AND NOT IN THE DAEMON. Web protection points the whole
  ; machine's DNS at a local proxy using a Name Resolution Policy Table rule.
  ; That rule lives in the registry and SURVIVES REBOOTS, while the service
  ; above is delayed-auto. So the dangerous state is not "the proxy crashed"
  ; - it is "the rule is installed and nothing is answering", which is a
  ; machine with no name resolution at all, on every subsequent boot, for a
  ; user who cannot search for the fix because search does not resolve.
  ;
  ; The reconciler runs at startup, before the daemon, and removes the rule
  ; unless the proxy answers with a signature only it can produce. It is the
  ; ONLY thing that removes rules when the daemon is not around. Registering
  ; it at INSTALL time is what makes it exist before the first rule can: the
  ; daemon refuses to install a rule while this task is missing or disabled.
  ;
  ; The binary registers its own task (the task XML must name its absolute
  ; path, which only the running exe knows) and writes settings that the
  ; schtasks command line cannot express - DisallowStartIfOnBatteries alone
  ; would stop a laptop from ever reconciling.
  ;
  ; A failure here is SAFE: no task means the daemon refuses to install a
  ; rule, so web protection stays off. Logged, not fatal.
  nsExec::ExecToLog '"$SENTI_DAEMON\sentinella-dnsreconcile.exe" --install-task'

  ; === Register GUI autostart at login (per-machine, all users) ===
  ; HKLM Run key: launches Sentinella.exe at user login.
  ; --minimized so it starts in tray without showing main window.
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "Sentinella" '"$INSTDIR\Sentinella.exe" --minimized'

!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; === Remove autostart registry entry ===
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "Sentinella"

  ; === Kill GUI if running (so files can be deleted) ===
  nsExec::ExecToLog 'taskkill /F /IM Sentinella.exe'
  Sleep 500

  ; === Stop and remove service ===
  ; Stopping first gives the daemon its own chance to remove the rule
  ; cleanly, before we do it the blunt way below.
  nsExec::ExecToLog 'sc stop SentinellaDaemon'
  Sleep 3000
  nsExec::ExecToLog 'sc delete SentinellaDaemon'
  Sleep 1000

  ; === Remove the NRPT rule, THEN its reconciler task ===
  ;
  ; ORDER IS LOAD-BEARING and this is the only place it can be enforced:
  ; both must happen BEFORE the uninstaller deletes the files, because the
  ; executable that knows how to do either is one of those files. Removing
  ; the task first would delete the remover while a rule is still live;
  ; letting the files go first would delete both.
  Var /GLOBAL SENTI_UNINST_DAEMON
  StrCpy $SENTI_UNINST_DAEMON "$INSTDIR\daemon"
  IfFileExists "$SENTI_UNINST_DAEMON\sentinella-dnsreconcile.exe" +2 0
    StrCpy $SENTI_UNINST_DAEMON "$INSTDIR\resources\daemon"

  IfFileExists "$SENTI_UNINST_DAEMON\sentinella-dnsreconcile.exe" 0 no_reconciler
    nsExec::ExecToLog '"$SENTI_UNINST_DAEMON\sentinella-dnsreconcile.exe" --remove'
    Pop $0
    StrCmp $0 "0" rule_gone 0
      ; The rule could NOT be removed and this machine's DNS is currently
      ; pointed at a proxy we are about to delete. Aborting is the
      ; unfriendly-but-recoverable outcome; continuing is the unrecoverable
      ; one - the reconciler task and its binary would both go, leaving a
      ; rule nothing can ever undo.
      ;
      ; Everything stays in place, so the next boot's reconciler removes the
      ; rule and a retried uninstall then succeeds.
      ;
      ; A silent uninstall (Uninstall.exe /S) has nobody to click OK, and an
      ; unguarded MessageBox there hangs the uninstaller forever. Abort is
      ; the same decision without the wait.
      IfSilent senti_uninst_abort 0
        MessageBox MB_ICONSTOP|MB_OK "Sentinella could not remove its DNS policy rule.$\n$\nUninstalling now would leave this machine unable to resolve names. Please reboot and run the uninstaller again - Sentinella removes the rule automatically at startup.$\n$\nDetails: %ProgramData%\Sentinella\logs\dnsreconcile.log"
      senti_uninst_abort:
      Abort
    rule_gone:
    ; Only now, with the rule provably gone, may the remover be removed.
    ; The binary refuses this itself if a rule is somehow still present.
    nsExec::ExecToLog '"$SENTI_UNINST_DAEMON\sentinella-dnsreconcile.exe" --remove-task'
    Goto senti_uninst_rule_done

  no_reconciler:
    ; The remover is gone but a rule may not be. This used to be a bare label:
    ; the uninstall skipped both steps in silence and deleted everything
    ; anyway, which is the one unrecoverable outcome — a live catch-all rule
    ; with the product, its reconciler, and its scheduled task all removed,
    ; and no reboot that fixes it because the thing the boot task ran is gone.
    ;
    ; We cannot query the registry for the rule without the binary, but the
    ; GUID state file is written BEFORE the rule is ever created, so its
    ; presence is a sound over-approximation of "a rule may exist". Its
    ; absence proves none was.
    Var /GLOBAL SENTI_UNINST_PD
    ReadEnvStr $SENTI_UNINST_PD "ProgramData"
    StrCmp $SENTI_UNINST_PD "" 0 +2
      StrCpy $SENTI_UNINST_PD "C:\ProgramData"
    ; Same silent-run reasoning as above, and MB_DEFBUTTON2 already says what
    ; the answer is when nobody is there to give one: do not continue.
    IfFileExists "$SENTI_UNINST_PD\Sentinella\state\nrpt-rule.guid" 0 senti_uninst_no_rule
      IfSilent senti_uninst_maybe_rule_abort 0
        MessageBox MB_ICONSTOP|MB_YESNO|MB_DEFBUTTON2 "Sentinella cannot find sentinella-dnsreconcile.exe, which is the only tool that can remove its DNS policy rule.$\n$\nThis machine may currently route all DNS through Sentinella. Uninstalling now could leave it unable to resolve names, with nothing left to undo it.$\n$\nRepair or reinstall Sentinella first, then uninstall.$\n$\nContinue anyway?" IDYES senti_uninst_rule_done
      senti_uninst_maybe_rule_abort:
      Abort

  senti_uninst_no_rule:
    ; No GUID file proves no rule was ever created, so nothing can be
    ; stranded by removing the boot task here — and something must, or the
    ; task outlives the uninstall: a startup entry pointing into the
    ; directory about to be deleted, failing on every boot, forever. The exe
    ; that owns the task is precisely the file that is missing, so schtasks
    ; is the only remover left. By absolute path for the same reason
    ; task.rs resolves it that way: never let PATH decide.
    ;
    ; Deliberately NOT done on the IDYES path above. There a rule may still
    ; be live, and the task is the one thing that could still undo it if the
    ; user restores the binary.
    nsExec::ExecToLog '"$SYSDIR\schtasks.exe" /Delete /TN "\Sentinella\DnsReconcile" /F'

  senti_uninst_rule_done:
!macroend
