# Sentinella AMSI Provider

**Crate:** `crates/amsi_provider` (`sentinella_amsi_provider.dll`) ·
**Branch:** `feat/amsi-provider` · **Track F**

The AMSI provider gives Sentinella **pre-execution** inspection of script
content — deobfuscated PowerShell, `wscript`/`cscript` (JScript/VBScript),
`mshta`, Office VBA macros, WMI, and the .NET in-memory loader. Until now
Sentinella only saw threats *after* a file existed on disk; AMSI is the only
user-mode way to see script content *before* it runs, with no kernel driver.

## 1. What it is and how it plugs in

An AMSI provider is an **in-process COM server**. When any process calls
`AmsiScanBuffer`/`AmsiScanString`, Windows loads every registered provider
DLL *into that process* and calls its `IAntimalwareProvider::Scan`. So this
DLL runs inside Word, PowerShell, `wscript`, etc. — not inside our service.

```
 host process (powershell.exe)                     Sentinella daemon
 ┌───────────────────────────┐                    ┌────────────────────┐
 │ AmsiScanBuffer(script)     │                    │ sentinelld          │
 │   → our provider DLL       │  named pipe RPC    │  runtime.scan_buffer│
 │     IAntimalwareProvider   │ ─────────────────► │   → ARGUS runtime   │
 │       ::Scan(stream)       │  \\.\pipe\         │     profile verdict │
 │   ◄ AMSI_RESULT            │ ◄───────────────── │  {score,should_block}│
 └───────────────────────────┘   (250 ms budget)  └────────────────────┘
```

The DLL implements `IAntimalwareProvider` (`Scan`, `CloseSession`,
`DisplayName`) plus an `IClassFactory` and the standard COM `Dll*` exports.
It reads the script bytes from the `IAmsiStream` — from the `CONTENT_ADDRESS`
buffer when available, otherwise via `IAmsiStream::Read` (both bounded by
`MAX_CONTENT`) — plus the `APP_NAME` / `CONTENT_NAME` attributes, and
forwards them to the daemon. **The engine never loads into the host
process** — the verdict comes back over IPC.

### Content encoding (important)

AMSI does not expose the content's text encoding. PowerShell submits its
buffer as **UTF-16LE**; other hosts commonly submit UTF-8/ASCII. Decoding
UTF-16LE as UTF-8 is silently destructive — the NUL high byte of each ASCII
code unit is a valid UTF-8 `U+0000`, so `Invoke-Expression` would reach the
daemon as `I\0n\0v\0o\0k\0e\0-\0…` and no rule would match. The provider
therefore **detects the encoding** (`decode::looks_like_utf16le`: even
length + a strong majority of NUL high-bytes, or a UTF-16LE BOM) and decodes
UTF-16LE properly, falling back to UTF-8 otherwise.

### Reuse, not reinvention

- The verdict path reuses the daemon's existing `runtime.scan_buffer` IPC
  method (ARGUS "runtime" profile: YARA-heavy, no PE/archive parsing,
  tightly time-boxed) — see `crates/sentinelld/src/amsi/mod.rs` and
  `crates/sentinelld/src/ipc/mod.rs`.
- The transport reuses the same framing every other client uses: a 4-byte
  big-endian length prefix + JSON over `\\.\pipe\sentinelld`, authenticated
  with the `%ProgramData%\Sentinella\state\ipc_secret` value. No new channel.
- The provider now also passes `source_pid`, which activates the daemon's
  PLM lineage boost (it was previously dead — `source_pid` was hardcoded 0).

The old `AmsiMonitor` in `amsi/mod.rs` (a never-instantiated ETW-consumer
sketch) is **not** used; this is the COM-provider approach it anticipated.
Its live helpers (`scan_runtime_buffer`, `ScriptLanguage`) are reused.

## 2. Failure model — this path fails OPEN (by design)

Everywhere else in Sentinella the rule is fail **closed**. The AMSI path is
the deliberate exception, and the reason is blunt: this code runs inside the
user's Word and PowerShell. If the daemon is slow, stopped, mid-restart, or
unreachable, **blocking the host is worse than missing one detection** — a
hung provider hangs the user's editor. So:

- Every `Scan` returns within a hard **250 ms** wall-clock budget. The
  daemon round-trip runs on a small **fixed pool** of persistent workers
  (`executor`), never a thread per scan — PowerShell scans almost every
  command, so spawn-per-call would be high-frequency thread creation inside
  the host. If a scan overruns, we return `NOT_DETECTED`.
- A **circuit breaker** protects the host from a wedged daemon: after a few
  consecutive budget overruns it short-circuits to `NOT_DETECTED` for a
  cool-down window without touching a worker, so a stuck daemon cannot pile
  up blocked threads. When all workers are saturated the scan is shed
  (also `NOT_DETECTED`).
- Any error — no daemon, pipe error, malformed reply, RPC error, missing
  auth secret — returns `NOT_DETECTED`.
- `Scan` is wrapped in `catch_unwind`; a panic can never unwind into the
  host. A caught panic returns `NOT_DETECTED`.
- Only an explicit `should_block` verdict from the daemon returns
  `AMSI_RESULT_DETECTED` (32768). The provider never blocks on score alone.

This single exception is documented here so it does not read as a violation
of the project-wide fail-closed rule.

### Time budget

| Stage | Bound |
|-------|-------|
| Whole `Scan` (host-visible) | 250 ms hard cap, then fail open |
| Content forwarded | ≤ 1 MiB (larger buffers skipped → NOT_DETECTED) |
| Daemon ARGUS runtime profile | its own budget (≈1–2 s YARA), but capped by the 250 ms above |

If real-world telemetry shows the 250 ms is too tight or too loose, it is a
single `const SCAN_BUDGET` in `com.rs`.

## 3. Registration / unregistration

Two HKLM writes, both requiring admin, both machine-global:

1. `HKLM\SOFTWARE\Classes\CLSID\{53E6920C-21B6-4826-9752-81485B3CBA2A}\InprocServer32`
   → the DLL path, `ThreadingModel = Both`.
2. `HKLM\SOFTWARE\Microsoft\AMSI\Providers\{53E6920C-21B6-4826-9752-81485B3CBA2A}`
   → enrols the CLSID as an AMSI provider.

The CLSID is fixed (`registration::PROVIDER_CLSID`); it must never change or
existing installs would orphan. Three equivalent ways to register:

```powershell
# a) operator script (elevated)
pwsh scripts\amsi-register.ps1 -DllPath "C:\Program Files\Sentinella\sentinella_amsi_provider.dll"
pwsh scripts\amsi-register.ps1 -Unregister

# b) COM self-registration (elevated)
regsvr32 sentinella_amsi_provider.dll
regsvr32 /u sentinella_amsi_provider.dll
```

Providers are loaded when a host process **starts**, so open a fresh
PowerShell after registering.

### Registration status on the human's machine (DONE 2026-09-16)

With the human's authorisation, the provider **is registered** on their real
machine. The release DLL was copied to `C:\Program Files\Sentinella\` (so the
registered path survives a `target/` clean) and both keys were written and
verified:

```
HKLM\SOFTWARE\Classes\CLSID\{53E6920C-21B6-4826-9752-81485B3CBA2A}\InprocServer32
    = C:\Program Files\Sentinella\sentinella_amsi_provider.dll
HKLM\SOFTWARE\Microsoft\AMSI\Providers\{53E6920C-21B6-4826-9752-81485B3CBA2A}
    = Sentinella AMSI Provider
```

Confirmed live: a fresh PowerShell lists `sentinella_amsi_provider.dll` among
its loaded modules (alongside `amsi.dll`) and runs normally — no hang, no
crash. The standard AMSI test string returned `ScriptContainedMaliciousContent`
while the daemon was up.

**Attribution caveat.** Defender is also a registered AMSI provider, so a
block seen at the host cannot, by itself, be credited to us — the verdict may
come from Defender. The daemon-side counters added in §5.1 (`requests_total`
via the `origin == "amsi"` path) are how we show a scan actually reached
**our** provider. Defender must not be disabled to test this (it is the real
AV on the machine).

**Reversion:** to remove the registration, run elevated:

```powershell
pwsh scripts\amsi-register.ps1 -Unregister    # or: regsvr32 /u sentinella_amsi_provider.dll
```

## 4. Manual verification (needs a real machine + admin)

1. Ensure `sentinelld` is running and healthy (the IPC pipe answers).
2. Register the DLL (section 3), elevated.
3. Open a **new** PowerShell and run the standard AMSI test string:

   ```powershell
   'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'
   ```

   With a rule that scores it as malicious, a working provider makes the
   host report the content as blocked. To confirm the provider is merely
   *loaded* even without a matching rule, watch the daemon log for a
   `runtime.scan_buffer` call arriving from the host PID when a script runs.
4. Fail-open check: stop `sentinelld`, run a script in a new PowerShell —
   it must run **without hanging** (the provider times out and returns
   NOT_DETECTED).

## 5. What is tested automatically vs. what needs a machine

Automated (`cargo test -p amsi_provider`, 28 tests), no COM host required:

- **Content decode** (`decode`): a UTF-16LE `Invoke-Expression` buffer
  decodes to the real string (and the old UTF-8 path is shown NOT to contain
  it); BOM stripping; UTF-8 ASCII and UTF-8 multibyte pass through unchanged;
  odd-length falls back to UTF-8.
- **Verdict mapping / fail-open policy** (`decision`): block → DETECTED;
  clean/high-score-without-block → NOT_DETECTED; **no verdict → NOT_DETECTED**.
- **Executor** (`executor`): the circuit breaker opens after the timeout
  threshold and reopens/closes on cool-down and success; a fast job returns
  its value; a slow job fails open within the budget; the pool recovers
  after a single timeout (one slow scan does not wedge the next).
- **Request/response framing** (`client`): `runtime.scan_buffer` request is
  well-formed JSON-RPC with auth and `origin:"amsi"`; responses (block/clean/
  rpc-error/`ok:false`/garbage) parse to the right verdict or to fail-open.
- **Registration strings** (`registration`): CLSID shape, subkeys, and the
  `.reg` body (InprocServer32, ThreadingModel, AMSI\Providers, DLL path).
- **App→language mapping** (`lib`).

**Cannot** be tested in CI / here (needs a real Windows machine + admin, and
is out of scope for automated tests):

- The actual COM registration writing to HKLM.
- Windows loading the DLL into a host and invoking `Scan` through a real
  `IAmsiStream` (the attribute reads and the vtable wiring are typed against
  `windows` 0.61 and compile, but the end-to-end AMSI load is unverified
  here).
- Behaviour under a real host (Word/PowerShell) and real detection latency.

## 6. Build note

`crates/amsi_provider` builds against `windows` 0.61 (the rest of the tree
pins 0.58). 0.58's AMSI `#[implement]` bindings are internally inconsistent
with its implement macro for `IAntimalwareProvider`; 0.61 fixed that. The
crate is isolated (`cdylib`), so this does not change any other crate. It is
built as `crate-type = ["cdylib", "rlib"]` — the cdylib is the provider DLL,
the rlib lets the pure logic be unit-tested.

## 7. Open items

- End-to-end validation on a real machine (section 4) — needs authorisation
  to register.
- Surfacing "provider registered / loaded" status to the GUI (today
  `ipc/state.rs` reports AMSI as not registered). A read-only registry probe
  for the CLSID would make that honest; deferred to avoid scope creep into
  the daemon status surface.
- Tuning `SCAN_BUDGET` and the daemon runtime profile from field latency.
