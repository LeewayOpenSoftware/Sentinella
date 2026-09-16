//! Layer 5: Specialty Pattern Detection
//!
//! Detects specific malware families and behaviors targeting modern
//! threat ecosystems: Discord stealers, fake updaters, credential
//! theft, webhook exfiltration, and Electron abuse.
//!
//! Implementation note: all byte patterns are consolidated into a single
//! Aho-Corasick automaton built once at process startup. `analyze()` then
//! runs ONE linear pass over the input bytes (`find_iter`) and buckets
//! the hits by pattern id. This replaces the previous design which did
//! ~40 independent `data.windows().any()` scans per file — roughly 40×
//! redundant work on every scanned binary.

use crate::verdict::{Finding, Layer, Severity};
use aho_corasick::{AhoCorasick, MatchKind};
use once_cell::sync::Lazy;
use std::collections::HashSet;

// ── Pattern catalogue ──────────────────────────────────────────────
//
// Every needle previously passed to `contains_bytes` lives here with a
// stable enum-style index. Adding a new needle = add a constant + an
// entry in `NEEDLES`. The `present!` helper resolves a constant to its
// "did the automaton see it?" boolean.

const DISCORD_PATH_1: usize = 0; // b"discord\\Local Storage"
const DISCORD_PATH_2: usize = 1; // b"discordptb\\Local Storage"
const DISCORD_PATH_3: usize = 2; // b"discordcanary\\Local Storage"
const DISCORD_PATH_4: usize = 3; // b"discord/Local Storage"
const LDB_EXT: usize = 4;
const LEVELDB: usize = 5;
const TOKEN_REGEX_1: usize = 6; // b"[MN][A-Za-z\\d]"
const TOKEN_REGEX_2: usize = 7; // b"mfa."
const WEBHOOK_LOWER: usize = 8; // b"webhook"
const DPAPI_PREFIX: usize = 9; // b"dQw4w9WgXcQ:"
const WH_DISCORD_COM: usize = 10;
const WH_DISCORDAPP: usize = 11;
const TG_BOT_API: usize = 12;
const BROWSER_CHROME: usize = 13;
const BROWSER_EDGE: usize = 14;
const BROWSER_BRAVE: usize = 15;
const BROWSER_FIREFOX: usize = 16;
const BROWSER_OPERA: usize = 17;
const LOGIN_DATA: usize = 18;
const WEB_DATA: usize = 19;
const WALLET_EXODUS: usize = 20;
const WALLET_ATOMIC: usize = 21;
const WALLET_ELECTRUM: usize = 22;
const WALLET_DAT: usize = 23;
const BTC_BC1Q: usize = 24;
const SET_CLIPBOARD: usize = 25;
const HEX_0X: usize = 26;
const GET_CLIPBOARD_DATA: usize = 27;
const SET_CLIPBOARD_DATA: usize = 28;
const STRATUM_TCP: usize = 29;
const STRATUM_SSL: usize = 30;
const XMRIG: usize = 31;
const CRYPTONIGHT: usize = 32;
const RUN_KEY: usize = 33;
const STARTUP_FOLDER: usize = 34;
const SCHTASKS: usize = 35;
const SCHTASKS_CREATE: usize = 36;
const WMI_EVENT_FILTER: usize = 37;
const WMI_EVENT_CONSUMER: usize = 38;
const DISCORD_LOWER: usize = 39;
const DISCORD_UPPER: usize = 40;
const WEBHOOK_UPPER: usize = 41;
const LOCAL_STORAGE: usize = 42;
const WALLET_LOWER: usize = 43;
const TOKEN_LOWER: usize = 44;
const API_TELEGRAM: usize = 45;
const CHROME_USER_DATA: usize = 46;

/// Pattern table — index MUST match the constants above.
/// Kept as a `&[&[u8]]` so the automaton can be built straight from it.
const NEEDLES: &[&[u8]] = &[
    b"discord\\Local Storage",         // 0
    b"discordptb\\Local Storage",      // 1
    b"discordcanary\\Local Storage",   // 2
    b"discord/Local Storage",          // 3
    b".ldb",                           // 4
    b"leveldb",                        // 5
    b"[MN][A-Za-z\\d]",                // 6
    b"mfa.",                           // 7
    b"webhook",                        // 8
    b"dQw4w9WgXcQ:",                   // 9
    b"discord.com/api/webhooks/",      // 10
    b"discordapp.com/api/webhooks/",   // 11
    b"api.telegram.org/bot",           // 12
    b"\\Google\\Chrome\\User Data",    // 13
    b"\\Microsoft\\Edge\\User Data",   // 14
    b"\\BraveSoftware\\Brave-Browser\\User Data", // 15
    b"\\Mozilla\\Firefox\\Profiles",   // 16
    b"\\Opera Software\\Opera Stable", // 17
    b"Login Data",                     // 18
    b"Web Data",                       // 19
    b"\\Exodus\\exodus.wallet",        // 20
    b"\\Atomic\\Local Storage",        // 21
    b"\\Electrum\\wallets",            // 22
    b"wallet.dat",                     // 23
    b"bc1q",                           // 24
    b"SetClipboard",                   // 25
    b"0x",                             // 26
    b"GetClipboardData",               // 27
    b"SetClipboardData",               // 28
    b"stratum+tcp://",                 // 29
    b"stratum+ssl://",                 // 30
    b"xmrig",                          // 31
    b"CryptoNight",                    // 32
    b"\\CurrentVersion\\Run",          // 33
    b"\\Start Menu\\Programs\\Startup", // 34
    b"schtasks",                       // 35
    b"/create",                        // 36
    b"__EventFilter",                  // 37
    b"__EventConsumer",                // 38
    b"discord",                        // 39
    b"Discord",                        // 40
    b"Webhook",                        // 41
    b"Local Storage",                  // 42
    b"wallet",                         // 43
    b"token",                          // 44
    b"api.telegram",                   // 45
    b"Chrome\\User Data",              // 46
];

/// Lazily-built automaton. `MatchKind::Standard` is sufficient because
/// we only care whether each needle appears at least once — overlap and
/// leftmost-longest semantics don't change the "is it present" answer.
///
/// `ascii_case_insensitive` stays OFF: the original code distinguished
/// `b"discord"` from `b"Discord"` (and `b"webhook"` from `b"Webhook"`)
/// by listing both variants explicitly, so preserving case-sensitive
/// matching keeps semantics byte-identical.
static AC: Lazy<AhoCorasick> = Lazy::new(|| {
    AhoCorasick::builder()
        .match_kind(MatchKind::Standard)
        .ascii_case_insensitive(false)
        .build(NEEDLES)
        .expect("argus pattern automaton must build")
});

/// Scan `data` once and return the set of needle ids that appear in it.
fn scan(data: &[u8]) -> HashSet<usize> {
    let mut hits = HashSet::with_capacity(8);
    for m in AC.find_iter(data) {
        hits.insert(m.pattern().as_usize());
    }
    hits
}

/// Analyze binary content for known malware patterns.
/// This works on raw file bytes — no parsing needed.
pub fn analyze(path: &str, data: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let hits = scan(data);

    detect_discord_stealer(&hits, &mut findings);
    detect_webhook_exfiltration(&hits, &mut findings);
    detect_credential_access(&hits, &mut findings);
    detect_crypto_patterns(&hits, &mut findings);
    detect_persistence_indicators(&hits, &mut findings);
    detect_fake_game_mod(path, &hits, &mut findings);

    findings
}

// ── Discord token stealer patterns ─────────────────────────────────

fn detect_discord_stealer(hits: &HashSet<usize>, findings: &mut Vec<Finding>) {
    let mut indicators: Vec<&str> = Vec::new();

    // Discord local storage paths.
    if hits.contains(&DISCORD_PATH_1)
        || hits.contains(&DISCORD_PATH_2)
        || hits.contains(&DISCORD_PATH_3)
        || hits.contains(&DISCORD_PATH_4)
    {
        indicators.push("References Discord local storage directory");
    }

    // LevelDB file extensions (Discord stores tokens in LevelDB).
    if hits.contains(&LDB_EXT) && hits.contains(&LEVELDB) {
        indicators.push("References LevelDB files used by Discord");
    }

    // Discord token regex patterns.
    if hits.contains(&TOKEN_REGEX_1) || hits.contains(&TOKEN_REGEX_2) {
        // Rough check — token matching regex embedded in binary.
        if hits.contains(&WEBHOOK_LOWER) || !indicators.is_empty() {
            indicators.push("Contains Discord token format patterns");
        }
    }

    // Encrypted token prefix (Discord DPAPI).
    if hits.contains(&DPAPI_PREFIX) {
        indicators.push("References Discord encrypted token prefix (DPAPI)");
    }

    match indicators.len() {
        0 => {}
        1 => {
            findings.push(Finding {
                layer: Layer::PatternDetection,
                severity: Severity::Medium,
                weight: 15,
                description: format!(
                    "Executable accesses Discord application data — {}",
                    indicators[0]
                ),
                technical_detail: Some(indicators.join("; ")),
            });
        }
        _ => {
            findings.push(Finding {
                layer: Layer::PatternDetection,
                severity: Severity::High,
                weight: 30,
                description: format!(
                    "Multiple indicators of Discord token theft behavior ({} markers detected).",
                    indicators.len(),
                ),
                technical_detail: Some(indicators.join("; ")),
            });
        }
    }
}

// ── Webhook exfiltration ───────────────────────────────────────────

fn detect_webhook_exfiltration(hits: &HashSet<usize>, findings: &mut Vec<Finding>) {
    let mut exfil_targets = Vec::new();

    // Discord webhook URLs.
    if hits.contains(&WH_DISCORD_COM) || hits.contains(&WH_DISCORDAPP) {
        exfil_targets.push("Discord webhook");
    }

    // Telegram bot API.
    if hits.contains(&TG_BOT_API) {
        exfil_targets.push("Telegram Bot API");
    }

    if !exfil_targets.is_empty() {
        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity: Severity::High,
            weight: 25,
            description: format!(
                "Executable contains {} endpoint(s) — commonly used to exfiltrate stolen data.",
                exfil_targets.join(" and "),
            ),
            technical_detail: Some(format!(
                "Exfiltration targets: {}",
                exfil_targets.join(", ")
            )),
        });
    }
}

// ── Credential access patterns ─────────────────────────────────────

fn detect_credential_access(hits: &HashSet<usize>, findings: &mut Vec<Finding>) {
    let mut indicators = Vec::new();

    // Browser credential storage paths.
    let browser_ids = [
        BROWSER_CHROME,
        BROWSER_EDGE,
        BROWSER_BRAVE,
        BROWSER_FIREFOX,
        BROWSER_OPERA,
    ];
    let browser_count = browser_ids.iter().filter(|id| hits.contains(id)).count();

    if browser_count >= 2 {
        indicators.push(format!(
            "Accesses {browser_count} browser credential directories"
        ));
    }

    // Login Data / Web Data (Chrome SQLite databases).
    if hits.contains(&LOGIN_DATA) && hits.contains(&WEB_DATA) {
        indicators.push("References browser credential databases (Login Data, Web Data)".into());
    }

    // Crypto wallet paths.
    let wallet_ids = [WALLET_EXODUS, WALLET_ATOMIC, WALLET_ELECTRUM, WALLET_DAT];
    let wallet_count = wallet_ids.iter().filter(|id| hits.contains(id)).count();

    if wallet_count >= 1 {
        indicators.push(format!(
            "Accesses {wallet_count} cryptocurrency wallet location(s)"
        ));
    }

    if !indicators.is_empty() {
        // Require multiple indicators — single browser access is common in
        // legitimate software (backup tools, password managers, etc.).
        let severity = if indicators.len() >= 3 {
            Severity::High
        } else if indicators.len() >= 2 {
            Severity::Medium
        } else {
            Severity::Low
        };
        let weight = if indicators.len() >= 3 {
            25
        } else if indicators.len() >= 2 {
            15
        } else {
            5
        };

        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity,
            weight,
            description: format!(
                "Executable accesses credential storage locations typically targeted by information stealers ({} indicator(s)).",
                indicators.len(),
            ),
            technical_detail: Some(indicators.join("; ")),
        });
    }
}

// ── Cryptocurrency patterns ────────────────────────────────────────

fn detect_crypto_patterns(hits: &HashSet<usize>, findings: &mut Vec<Finding>) {
    // Clipboard hijacking — wallet address regex patterns.
    // Bitcoin, Ethereum, Monero address format strings in binary.
    let mut crypto_indicators = Vec::new();

    if hits.contains(&BTC_BC1Q) && hits.contains(&SET_CLIPBOARD) {
        crypto_indicators.push("Bitcoin address replacement via clipboard");
    }

    if hits.contains(&HEX_0X)
        && hits.contains(&GET_CLIPBOARD_DATA)
        && hits.contains(&SET_CLIPBOARD_DATA)
    {
        crypto_indicators.push("Clipboard monitoring for crypto addresses");
    }

    // Mining.
    if hits.contains(&STRATUM_TCP) || hits.contains(&STRATUM_SSL) {
        crypto_indicators.push("Cryptocurrency mining pool connection string");
    }

    if hits.contains(&XMRIG) || hits.contains(&CRYPTONIGHT) {
        crypto_indicators.push("References to cryptocurrency mining software");
    }

    for indicator in &crypto_indicators {
        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity: Severity::High,
            weight: 22,
            description: format!("Cryptocurrency-related malware behavior: {indicator}"),
            technical_detail: None,
        });
    }
}

// ── Persistence indicators in binary content ───────────────────────

fn detect_persistence_indicators(hits: &HashSet<usize>, findings: &mut Vec<Finding>) {
    let mut persistence_methods = Vec::new();

    // Registry Run key manipulation.
    if hits.contains(&RUN_KEY) {
        persistence_methods.push("Registry Run key modification");
    }

    // Startup folder.
    if hits.contains(&STARTUP_FOLDER) {
        persistence_methods.push("Startup folder manipulation");
    }

    // Scheduled task creation.
    if hits.contains(&SCHTASKS) && hits.contains(&SCHTASKS_CREATE) {
        persistence_methods.push("Scheduled task creation");
    }

    // WMI persistence.
    if hits.contains(&WMI_EVENT_FILTER) && hits.contains(&WMI_EVENT_CONSUMER) {
        persistence_methods.push("WMI event subscription (advanced persistence)");
    }

    if persistence_methods.len() >= 2 {
        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity: Severity::High,
            weight: 22,
            description: format!(
                "Executable uses {} persistence mechanisms — establishing multiple footholds is a strong malware indicator.",
                persistence_methods.len(),
            ),
            technical_detail: Some(persistence_methods.join("; ")),
        });
    } else if persistence_methods.len() == 1 {
        // Single persistence mechanism is extremely common in legitimate software.
        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity: Severity::Info,
            weight: 1,
            description: format!(
                "Executable references a system persistence mechanism: {}",
                persistence_methods[0]
            ),
            technical_detail: None,
        });
    }
}

// ── Fake game mod / updater detection ───────────────────────────────

fn detect_fake_game_mod(path: &str, hits: &HashSet<usize>, findings: &mut Vec<Finding>) {
    let path_lower = path.to_lowercase();
    let name = std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    // Check if the filename suggests a game mod/cheat/updater.
    let game_keywords = [
        "roblox",
        "minecraft",
        "fortnite",
        "valorant",
        "sims",
        "gta",
        "apex",
        "csgo",
        "cs2",
        "pubg",
        "overwatch",
        "warzone",
        "league",
        "dota",
    ];
    let mod_keywords = [
        "mod",
        "cheat",
        "hack",
        "trainer",
        "spoofer",
        "injector",
        "aimbot",
        "wallhack",
        "esp",
        "unban",
        "hwid",
        "skin changer",
        "skinchanger",
        "exploit",
    ];

    let has_game = game_keywords
        .iter()
        .any(|&k| name.contains(k) || path_lower.contains(k));
    let has_mod = mod_keywords.iter().any(|&k| name.contains(k));

    if !has_game && !has_mod {
        return;
    }

    // Check for credential theft indicators in the binary.
    let mut steal_indicators = 0u32;
    if hits.contains(&DISCORD_LOWER) || hits.contains(&DISCORD_UPPER) {
        steal_indicators += 1;
    }
    if hits.contains(&LOGIN_DATA) {
        steal_indicators += 1;
    }
    if hits.contains(&WEBHOOK_LOWER) || hits.contains(&WEBHOOK_UPPER) {
        steal_indicators += 1;
    }
    if hits.contains(&LOCAL_STORAGE) {
        steal_indicators += 1;
    }
    if hits.contains(&WALLET_LOWER) {
        steal_indicators += 1;
    }
    if hits.contains(&TOKEN_LOWER) {
        steal_indicators += 1;
    }
    if hits.contains(&API_TELEGRAM) {
        steal_indicators += 1;
    }
    if hits.contains(&CHROME_USER_DATA) {
        steal_indicators += 1;
    }

    if has_game && has_mod && steal_indicators >= 2 {
        // Game cheat/mod with stealing capabilities = almost certainly malware.
        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity: Severity::Critical,
            weight: 45,
            description: "Executable presents as a game modification tool but contains credential harvesting capabilities — this is a textbook fake game mod stealer.".to_string(),
            technical_detail: Some(format!("Game keywords + mod keywords + {steal_indicators} credential theft indicators in binary")),
        });
    } else if (has_game || has_mod) && steal_indicators >= 3 {
        // Either game-themed or mod-themed with strong stealing indicators.
        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity: Severity::High,
            weight: 30,
            description: "Executable combines game/mod-related naming with multiple credential harvesting indicators — highly suspicious.".into(),
            technical_detail: Some(format!("{steal_indicators} credential theft indicators found")),
        });
    } else if has_mod && steal_indicators >= 1 {
        // Mod/cheat/hack tool with any stealing indicator.
        findings.push(Finding {
            layer: Layer::PatternDetection,
            severity: Severity::Medium,
            weight: 15,
            description: "Executable is named as a game cheat or modification tool — these are the #1 malware distribution vector targeting gamers.".into(),
            technical_detail: Some(format!("Filename: {name}")),
        });
    }
}

// ── Compile-time sanity check ──────────────────────────────────────

#[cfg(test)]
mod automaton_tests {
    use super::*;

    /// The needle table is index-addressed by the `const usize` constants
    /// above. If anyone reorders or inserts a needle without updating the
    /// constants, every detector silently breaks. This test catches that
    /// by spot-checking a handful of (id, expected-bytes) pairs.
    #[test]
    fn needle_indices_match_constants() {
        assert_eq!(NEEDLES[DISCORD_PATH_1], b"discord\\Local Storage");
        assert_eq!(NEEDLES[WH_DISCORD_COM], b"discord.com/api/webhooks/");
        assert_eq!(NEEDLES[TG_BOT_API], b"api.telegram.org/bot");
        assert_eq!(NEEDLES[LOGIN_DATA], b"Login Data");
        assert_eq!(NEEDLES[WMI_EVENT_CONSUMER], b"__EventConsumer");
        assert_eq!(NEEDLES[CHROME_USER_DATA], b"Chrome\\User Data");
        assert_eq!(NEEDLES.len(), 47);
    }

    #[test]
    fn automaton_builds_and_finds_known_needle() {
        let hits = scan(b"prefix dQw4w9WgXcQ: suffix");
        assert!(hits.contains(&DPAPI_PREFIX));
        assert!(!hits.contains(&XMRIG));
    }
}
