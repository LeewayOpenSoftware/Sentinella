# Sentinella Signed-Update Recovery — September 2026

**Branch:** `feat/signed-update-recovery` · **Track D**

This document traces Sentinella's signed-update machinery end to end,
records the state of the signing key, gives the exact release procedure a
human runs to publish an update, demonstrates that the unhappy paths fail
**closed**, and lists what remains open.

There are **two independent update mechanisms**. Keeping them apart is the
first requirement for reasoning about either.

| # | Mechanism | What it updates | Trust anchor | Where it verifies |
|---|-----------|-----------------|--------------|-------------------|
| A | Tauri app updater (minisign / rsign2) | `sentinella.exe` + shipped daemon binaries, delivered as the NSIS installer | minisign public key embedded in `tauri.conf.json` | inside `tauri-plugin-updater`, at install time |
| B | Signature-source pipeline | ClamAV virus-definition DB (freshclam) and optional third-party signature packs | pinned SHA-256 hashes in a per-provider `manifest.json` | `crates/sentinelld/src/engine/update_pipeline.rs`, in the SYSTEM daemon |

Mechanism **A** is the "signed update" the task targets. Mechanism **B**
is where security finding **SR-08** lives.

---

## 1. Mechanism A — the minisign-signed app updater

### 1.1 Who signs, with what, and what the signature covers

- The signer is the human running the release, using the private key at
  `keys/sentinella-update.key` (an rsign2 / minisign Ed25519 secret key).
- The signature covers **the NSIS installer** (`Sentinella_<version>_x64-setup.exe`)
  as a whole. Minisign signs a BLAKE2b prehash of the file, so any change
  to the installer invalidates it.
- The public counterpart is `keys/sentinella-update.key.pub`. Its content
  (Tauri stores the pubkey as base64 of the whole minisign pubkey file) is
  embedded verbatim in `gui/src-tauri/tauri.conf.json` under
  `plugins.updater.pubkey`. **Verified in this pass: the embedded pubkey is
  byte-for-byte equal to `keys/sentinella-update.key.pub`** (key id
  `69ED7D8BA3A5B866`). The signing key and the verifying key are a matched
  pair.

### 1.2 Who verifies, and where the public key lives

Verification is done by `tauri-plugin-updater` (the `minisign-verify`
crate) on the client, at the moment an update is downloaded and before it
is applied. The public key it checks against is the one baked into
`tauri.conf.json` at build time — it is not fetched at runtime, so a
tampered server cannot supply its own key.

Wiring, confirmed present and connected:

- `gui/src-tauri/Cargo.toml` → `tauri-plugin-updater = "2"`.
- `gui/src-tauri/src/lib.rs:992` → `.plugin(tauri_plugin_updater::Builder::new().build())`.
- `gui/src/components/AppUpdater.tsx` → calls `check()` / `downloadAndInstall()`
  from `@tauri-apps/plugin-updater`; rendered from `gui/src/pages/Update.tsx:312`.
- `tauri.conf.json` → `bundle.createUpdaterArtifacts = true`,
  `plugins.updater.endpoints = [ ".../releases/latest/download/latest.json" ]`.

### 1.3 What happens on the unhappy path

- **Invalid signature / tampered installer:** `minisign-verify` fails; the
  plugin refuses to apply the update. Demonstrated below.
- **Wrong key:** the signature carries a key id; a mismatch is rejected
  before any cryptographic check. Demonstrated below.
- **Missing manifest / missing `.sig`:** the release scripts refuse to
  produce a manifest without a signature (§1.5), and a client with no
  valid manifest simply finds no update.
- **Downgrade:** `tauri-plugin-updater` compares the manifest `version`
  against the running version (semver) and only offers an update when the
  remote version is strictly newer. An equal or older `latest.json` is
  reported as "up to date", never installed.

### 1.4 State of the signing key — no passphrase (expected, not a bug)

`keys/sentinella-update.key` is a minisign "encrypted secret key" whose
KDF parameters are **zero**, i.e. it is stored with an **empty
passphrase**. This is the state the human remembered as "an encrypted
password with no password". It is the **expected** configuration and is
**not** a defect to fix in this work:

- It lets the release be cut non-interactively (no password prompt).
- The residual risk is that anyone who can read the key file can sign a
  Sentinella update. The mitigation in place is file-system custody:
  `keys/` is gitignored (`.gitignore` lines 78–79, "Signing keys (NEVER
  commit)") and `git ls-files keys/` is empty — the key has never been
  committed. Confirm this stays true.
- Adding a passphrase later is possible but is a **design decision**
  (it reintroduces the Windows empty-password CLI hazard documented in
  `scripts/release-build.ps1`) and must be raised before doing it.

### 1.5 Release procedure — what the human runs

One entry point drives the whole pipeline:

```powershell
# 1. Point at the signing key for THIS shell (the step that goes missing
#    between releases — see the preflight note).
$env:TAURI_SIGNING_PRIVATE_KEY = "C:\Users\Nicolas\Desktop\sentinella\keys\sentinella-update.key"
# (no _PASSWORD is set: the key's passphrase is empty)

# 2. Run the pipeline: preflight -> bundle -> sign -> verify -> manifest.
pwsh scripts\release-build.ps1
#   re-run only sign/verify/manifest against an existing bundle:
pwsh scripts\release-build.ps1 -SkipBundle
```

Then publish **all three** artifacts from
`gui/src-tauri/target/release/bundle/nsis/` —
`Sentinella_<version>_x64-setup.exe`, its `.sig`, and `latest.json` — as
assets on a GitHub release tagged `v<version>`, and make sure it is the
**latest** release (not a draft/pre-release), because the updater fetches
`releases/latest/download/latest.json`.

Why the pipeline is a script and not `a && b && c` (all three hazards are
real and were hit on 0.1.13):

1. **`tauri build` cannot sign non-interactively with this key.** On
   Windows an env var cannot be set to empty, so
   `TAURI_SIGNING_PRIVATE_KEY_PASSWORD=""` deletes itself and the bundler
   falls back to an interactive prompt and hangs. The script bundles
   **without** the key in the environment (the bundler then produces a
   complete installer and exits nonzero over the missing key — expected)
   and signs as a separate `tauri signer sign --password=` step.
2. **The bundler exits 0 even when it did not sign.** `verify-updater-signature.ps1`
   asserts a non-empty `.sig` sits beside this version's installer, so an
   unsigned build fails the release instead of shipping.
3. **`latest.json` was hand-written and went stale.** `generate-update-manifest.ps1`
   regenerates it from what is actually on disk (version from
   `tauri.conf.json`, signature read from the `.sig` the build just
   produced, URL derived from the version) and refuses to emit a manifest
   whose signature does not name this installer.

`preflight-staging-versions.ps1` runs first and fails fast if
`TAURI_SIGNING_PRIVATE_KEY` is unset while the config wants a signature —
the single most common way a release goes out unsigned.

### 1.6 Was it broken? — recovery status

The mechanism is **wired and functional**. The historical breakage (0.1.13
cut unsigned twice, the passphrase-prompt hang, and a stale hand-written
`latest.json`) was already addressed by the three release scripts above,
which are the recovery. This pass **verified** that recovery rather than
re-doing it: pubkey ↔ key-pair match confirmed, plugin/endpoint/UI wiring
confirmed present, and the signature path exercised end to end with the
real key (§3). No disconnection was found in mechanism A.

---

## 2. Mechanism B — signature-source pipeline and SR-08

### 2.1 What it does

`SignatureUpdateManager` (`update_pipeline.rs`) downloads per-provider
signature files, then verifies them against a `manifest.json` fetched from
the provider over **HTTPS only** (plain HTTP is rejected). The manifest
pins each file's SHA-256; verification is two-directional (every manifest
file must be present and match, and every staged file must be pinned by
the manifest). Any manifest error **fails closed** to official-ClamAV-only
— including HTTP 404/403 — and activation is atomic.

### 2.2 SR-08 (open, medium) — manifest without signature or rollback control

Per `docs/SECURITY_REVIEW_2026-09.md`, SR-08: `ProviderManifest`
(`update_pipeline.rs`) carries **no independent signature** and, before
this pass, **no anti-rollback** — the declared `version` was only logged,
never compared. HTTPS + hashes reject transport corruption but not a
**compromised provider** substituting files+manifest together, nor the
**replay of a genuine older manifest**.

### 2.3 What this pass changed — anti-rollback (the replay half)

Added a monotonic, persistent anti-rollback check
(`enforce_anti_rollback`), wired into `fetch_and_verify_manifest` **after**
the provider-id, hash and coverage checks pass:

- A per-provider ledger (`enhanced_versions.json`, stored next to the
  active enhanced-signatures directory, never CWD-relative) records the
  `updated_at` of the last manifest each provider was accepted at.
- A manifest whose `updated_at` is **strictly older** than the recorded
  point is **refused as a downgrade**.
- **Fails closed:** an `updated_at` that is not a parseable ISO-8601
  date/date-time is refused rather than accepted. An **equal** timestamp is
  allowed, so a retry after a transient activation failure can re-activate
  the identical, hash-pinned set.

**What this closes and what it does not.** It closes the *replay* half of
SR-08: a stale mirror, a cache, or an on-path actor who cannot forge fresh
metadata can no longer roll a provider back to older signatures. It does
**not** defend against a provider that is itself compromised and can forge
`updated_at` forward — because the manifest is unsigned, the anti-rollback
anchor is itself attacker-controllable in that threat model. Fully closing
SR-08 requires an **independently signed provider manifest** (see §4).

---

## 3. Demonstration (reproducible)

### 3.1 Mechanism A — minisign signature verification, real production key

Offline, using the same `minisign-verify` library `tauri-plugin-updater`
uses, against the real embedded public key
(`gui/src-tauri/tauri.conf.json`) and a signature produced by the real
private key with `cargo-tauri signer sign -f keys/sentinella-update.key -p ""`:

| Case | Input | Result |
|------|-------|--------|
| Valid signature | installer bytes + its `.sig` | **ACCEPT** |
| Tampered payload | one byte flipped in the installer | **REJECT** — "signature verification failed" |
| Tampered signature | corrupted `.sig` body | **REJECT** — "signature verification failed" |
| Wrong key | signature from a throwaway key | **REJECT** — "created with a different key" |

These use only throwaway files in a scratch directory; no key material was
copied, printed, or committed, and no tracked file was touched.

### 3.2 Mechanism B — pipeline accept / reject / downgrade (cargo tests)

`crates/sentinelld/src/engine/update_pipeline.rs` tests (run with
`cargo test -p sentinelld --bin sentinelld update_pipeline`, 11 pass):

- **Accept valid:** `manifest_parse`, `verify_rejects_*` confirm a
  well-formed, hash-matching set is accepted and format checks hold.
- **Reject tampered/invalid:** `verify_rejects_bad_hash`,
  `verify_rejects_oversize`, `verify_rejects_empty`.
- **Reject downgrade:** `anti_rollback_rejects_older_downgrade`, plus
  `anti_rollback_accepts_first_and_newer`, `anti_rollback_allows_equal_for_retry`,
  `anti_rollback_fails_closed_on_unparseable_time`, `anti_rollback_is_per_provider`.

---

## 4. Open items / decisions for the human

1. **Provider-manifest signing (finishes SR-08).** Fully closing SR-08
   needs each provider manifest signed under an independent trust anchor,
   with a monotonic version and expiry that are themselves authenticated,
   plus a rotation/recovery policy. This changes the manifest **format** and
   introduces key-distribution decisions, so it was **not** done here — it
   needs sign-off. `.audit/fix-agent-19.md` already deferred it.
2. **Signing-key passphrase.** The key is intentionally passphrase-less
   (§1.4). Adding a passphrase is a deliberate trade-off against the
   non-interactive release flow; raise before changing.
3. **Stale procedure doc.** `docs/WORKING_STATE_v0.1.0.md` reportedly still
   tells the releaser to set `TAURI_SIGNING_PRIVATE_KEY_PATH`, which
   `tauri build` does not read and which yields an **unsigned** build.
   The scripts guard against it, but the doc should be corrected to
   `TAURI_SIGNING_PRIVATE_KEY`.
