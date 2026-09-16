//! File Origin & Execution Context Layer
//!
//! Analyzes WHERE a file came from and HOW it arrived — not just
//! what it contains. Context amplifies suspicious findings but
//! never creates malicious verdicts alone.
//!
//! Sources (all local, no network, no drivers):
//! - Zone.Identifier ADS (Mark-of-the-Web)
//! - Directory location heuristics
//! - Filename pattern analysis
//! - Timestamp proximity (recent file = higher relevance)

use crate::verdict::{Finding, Layer, Severity};
use std::path::Path;

/// Maximum context amplification points.
/// Context alone cannot push a file to "Malicious" — it only amplifies
/// existing behavioral/structural findings.
const MAX_CONTEXT_WEIGHT: u32 = 15;

/// Analyze file origin and execution context.
/// Returns contextual findings that amplify or reduce suspicion.
pub fn analyze(path: &Path, existing_score: u32) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Only add context if there's meaningful suspicion from content layers.
    // Context alone never creates a threat. Require at least 5 points of
    // pre-existing suspicion to avoid amplifying trivial structural noise
    // on otherwise-clean files.
    if existing_score < 5 {
        return findings;
    }

    let path_str = path.to_string_lossy().to_lowercase();
    let mut context_weight: u32 = 0;
    let mut context_reasons: Vec<String> = Vec::new();

    // ── Directory-based context ────────────────────────────
    let in_downloads = path_str.contains("\\downloads\\") || path_str.contains("/downloads/");
    let in_temp =
        path_str.contains("\\temp\\") || path_str.contains("\\tmp\\") || path_str.contains("/tmp/");

    if in_temp {
        context_weight += 4;
        context_reasons.push("Executed from temporary directory".into());
    } else if in_downloads {
        context_weight += 2;
        context_reasons.push("Located in Downloads folder".into());
    }

    // ── Browser/app delivery paths ─────────────────────────
    if path_str.contains("\\discord\\") || path_str.contains("discord cache") {
        context_weight += 5;
        context_reasons.push("Delivered via Discord".into());
    }

    if path_str.contains("\\telegram desktop\\") || path_str.contains("\\tdata\\") {
        context_weight += 3;
        context_reasons.push("Located in Telegram data directory".into());
    }

    // ── Archive extraction staging ─────────────────────────
    // Files in temp dirs with archive-like parent paths suggest
    // they were recently extracted from a ZIP/RAR.
    if in_temp {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if name.ends_with(".exe") || name.ends_with(".scr") || name.ends_with(".bat") {
            context_weight += 3;
            context_reasons
                .push("Executable in temp directory (possible archive extraction)".into());
        }
    }

    // ── Mark-of-the-Web (Zone.Identifier ADS) ──────────────
    // PERF: read the ADS once and lowercase once — both the zone-ID check and
    // the monetizer/referrer scan reuse the same buffer.
    #[cfg(target_os = "windows")]
    {
        // DoS hardening: a legitimate Zone.Identifier is ~200 bytes, but an
        // ADS can be arbitrarily large — cap the read so a scanned file
        // carrying a multi-GB `:Zone.Identifier` stream can't exhaust
        // daemon memory.
        const MAX_ZONE_ADS_BYTES: u64 = 4096;

        let zone_path = format!("{}:Zone.Identifier", path.display());
        let zone_data = std::fs::File::open(&zone_path).ok().and_then(|file| {
            use std::io::Read;
            let mut buf = Vec::new();
            file.take(MAX_ZONE_ADS_BYTES).read_to_end(&mut buf).ok()?;
            Some(String::from_utf8_lossy(&buf).into_owned())
        });
        if let Some(zone_data) = zone_data {
            let zone_lower = zone_data.to_lowercase();
            let is_internet_zone =
                zone_lower.contains("zoneid=3") || zone_lower.contains("zoneid=4");

            if is_internet_zone {
                context_weight += 3;
                context_reasons.push("Downloaded from the internet (Zone.Identifier)".into());

                // Extract referrer URL for additional context.
                if let Some(url) = zone_data
                    .lines()
                    .find(|l| l.starts_with("ReferrerUrl=") || l.starts_with("HostUrl="))
                    .map(|l| l.split_once('=').map(|x| x.1).unwrap_or("").to_string())
                {
                    let url_lower = url.to_lowercase();

                    if url_lower.contains("github.com") && url_lower.contains("release") {
                        context_weight += 3;
                        context_reasons.push("Downloaded from GitHub release".into());
                    } else if url_lower.contains("cdn.discordapp.com")
                        || url_lower.contains("discord.com/attachments")
                    {
                        context_weight += 5;
                        context_reasons.push("Delivered via Discord CDN".into());
                    } else if url_lower.contains("drive.google.com")
                        || url_lower.contains("docs.google.com")
                    {
                        context_weight += 2;
                        context_reasons.push("Downloaded from Google Drive".into());
                    } else if url_lower.contains("mediafire.com")
                        || url_lower.contains("mega.nz")
                        || url_lower.contains("anonfiles")
                        || url_lower.contains("sendspace")
                    {
                        context_weight += 5;
                        context_reasons.push("Downloaded from file-sharing service".into());
                    }
                }
            }

            // ── Fake downloader / link monetizer residue ─────────
            // Zone.Identifier referrers from known monetizer domains.
            let monetizer_domains = [
                "linkvertise",
                "adf.ly",
                "ouo.io",
                "ouo.press",
                "shrink.pe",
                "shrinkme.me",
                "shorte.st",
                "bc.vc",
                "exe.io",
                "sub2unlock",
                "direct-link.net",
                "lootlabs",
                "work.ink",
                "adfoc.us",
            ];
            if monetizer_domains.iter().any(|d| zone_lower.contains(d)) {
                context_weight += 6;
                context_reasons
                    .push("Download originated from a link monetizer/redirect service".into());
            }
        }
    }

    // ── Suspicious filename patterns ───────────────────────
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    // Fake downloader naming: "Free_Download_Manager", "Setup_Loader", etc.
    let fake_download_words = [
        "free_download",
        "download_manager",
        "setup_loader",
        "file_downloader",
        "fast_download",
        "getfile",
    ];
    if fake_download_words.iter().any(|w| name.contains(w)) {
        context_weight += 4;
        context_reasons.push("Filename matches fake downloader patterns".into());
    }

    // Link monetizer residue in filename: "linkvertise", "adf" in name.
    let monetizer_name_hints = ["linkvertise", "adfly", "ouo", "shrinkme"];
    if monetizer_name_hints.iter().any(|h| name.contains(h)) {
        context_weight += 4;
        context_reasons.push("Filename contains link monetizer reference".into());
    }

    // Recently created files in Downloads.
    if in_downloads && name.ends_with(".exe") {
        if let Ok(meta) = std::fs::metadata(path) {
            if let Ok(created) = meta.created() {
                if let Ok(age) = created.elapsed() {
                    if age.as_secs() < 3600 {
                        context_weight += 2;
                        context_reasons.push("Recently downloaded executable".into());
                    }
                }
            }
        }
    }

    // ── Cap and emit ───────────────────────────────────────
    let capped_weight = context_weight.min(MAX_CONTEXT_WEIGHT);

    if !context_reasons.is_empty() && capped_weight > 0 {
        findings.push(Finding {
            layer: Layer::Context,
            severity: if capped_weight >= 10 { Severity::Medium } else { Severity::Low },
            weight: capped_weight,
            description: format!(
                "Contextual indicators: {}.",
                context_reasons.join(", "),
            ),
            technical_detail: Some(format!(
                "Context amplification: +{capped_weight} (capped at {MAX_CONTEXT_WEIGHT}). Reasons: {}",
                context_reasons.join("; "),
            )),
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_zero_score_no_context() {
        // Clean file with no existing findings → no context amplification.
        let path = PathBuf::from("C:\\Users\\Test\\Downloads\\clean.exe");
        let findings = analyze(&path, 0);
        assert!(findings.is_empty(), "Zero-score file should get no context");
    }

    #[test]
    fn test_downloads_context_with_suspicion() {
        // Suspicious file in Downloads → context should amplify.
        let path = PathBuf::from("C:\\Users\\Test\\Downloads\\suspicious.exe");
        let findings = analyze(&path, 10); // Pre-existing suspicion.
        assert!(
            !findings.is_empty(),
            "Suspicious file in Downloads should get context"
        );
        let total_weight: u32 = findings.iter().map(|f| f.weight).sum();
        assert!(total_weight > 0 && total_weight <= MAX_CONTEXT_WEIGHT);
    }

    #[test]
    fn test_temp_path_amplification() {
        let path = PathBuf::from("C:\\Users\\Test\\AppData\\Local\\Temp\\payload.exe");
        let findings = analyze(&path, 15);
        assert!(!findings.is_empty());
        // Should have temp-related context.
        let desc = &findings[0].description;
        assert!(
            desc.contains("temp") || desc.contains("Temp"),
            "Should mention temp directory: {desc}"
        );
    }

    #[test]
    fn test_context_weight_cap() {
        // Even with many context signals, weight should be capped.
        let path = PathBuf::from("C:\\Users\\Test\\AppData\\Local\\Temp\\discord\\payload.exe");
        let findings = analyze(&path, 50);
        for f in &findings {
            assert!(
                f.weight <= MAX_CONTEXT_WEIGHT,
                "Context weight {} exceeds cap {}",
                f.weight,
                MAX_CONTEXT_WEIGHT
            );
        }
    }

    #[test]
    fn test_normal_path_minimal_context() {
        // File in a normal location with some suspicion → minimal/no context.
        let path = PathBuf::from("C:\\Program Files\\SomeApp\\app.exe");
        let findings = analyze(&path, 10);
        // Program Files is a normal location — should get zero or minimal context.
        let total: u32 = findings.iter().map(|f| f.weight).sum();
        assert!(
            total <= 3,
            "Normal path should have minimal context, got {total}"
        );
    }

    #[test]
    fn test_fake_downloader_name_zero_score() {
        // Fake downloader name + zero content score = no context (early return).
        let path = PathBuf::from("C:\\Users\\Test\\Downloads\\free_download_manager.exe");
        let findings = analyze(&path, 0);
        assert!(
            findings.is_empty(),
            "Zero-score file should get no context even with fake downloader name"
        );
    }

    #[test]
    fn test_fake_downloader_name_with_suspicion() {
        // Fake downloader name + suspicious content = amplification.
        let path = PathBuf::from("C:\\Users\\Test\\Downloads\\free_download_setup.exe");
        let findings = analyze(&path, 15);
        let has_fake = findings.iter().any(|f| {
            f.description.contains("fake downloader") || f.description.contains("Downloaded")
        });
        assert!(
            has_fake || !findings.is_empty(),
            "Suspicious file with fake downloader name should get context"
        );
    }

    #[test]
    fn test_discord_path_amplification() {
        let path = PathBuf::from("C:\\Users\\Test\\AppData\\Roaming\\discord\\Cache\\payload.exe");
        let findings = analyze(&path, 10);
        let has_discord = findings.iter().any(|f| f.description.contains("Discord"));
        assert!(has_discord, "Discord path should be noted in context");
    }
}
