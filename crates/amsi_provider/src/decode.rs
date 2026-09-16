//! AMSI content decoding (Finding 1).
//!
//! AMSI does not expose the content's text encoding — there is no such
//! `AMSI_ATTRIBUTE`. PowerShell submits its script buffer as **UTF-16LE**
//! (a .NET string), while other hosts commonly submit UTF-8/ASCII.
//!
//! Decoding everything as UTF-8 silently destroys PowerShell content: the
//! NUL high byte of each ASCII UTF-16 code unit is a *valid* UTF-8 U+0000,
//! so `from_utf8_lossy` does not error or insert replacement chars — it
//! yields `"I\0n\0v\0o\0k\0e\0-\0E\0x\0..."`. No signature, YARA rule or
//! pattern in the engine matches that, so the provider "works" (loads,
//! answers, increments counters) yet detects nothing from the single most
//! important AMSI source. This module detects UTF-16LE and decodes it.

/// Decode an AMSI content buffer to text, detecting UTF-16LE vs UTF-8.
pub fn decode_amsi_content(content: &[u8]) -> String {
    if looks_like_utf16le(content) {
        let units: Vec<u16> = content
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let mut s = String::from_utf16_lossy(&units);
        if s.starts_with('\u{feff}') {
            s.remove(0); // strip a leading BOM
        }
        s
    } else {
        String::from_utf8_lossy(content).into_owned()
    }
}

/// Heuristic: does this buffer look like UTF-16LE text? AMSI gives no
/// encoding attribute, so we infer from the byte pattern.
///
/// Script content is ASCII-dominated, and ASCII in UTF-16LE puts a NUL in
/// every odd (high) byte. UTF-8/ASCII text contains no NUL bytes at all, so
/// a strong majority of NUL high-bytes is a reliable UTF-16LE signal that
/// never misfires on the common UTF-8 case.
pub fn looks_like_utf16le(b: &[u8]) -> bool {
    if b.len() < 2 || b.len() % 2 != 0 {
        return false;
    }
    if b[0] == 0xFF && b[1] == 0xFE {
        return true; // explicit UTF-16LE BOM
    }
    let units = b.len() / 2;
    let sample = units.min(512);
    let mut odd_nul = 0usize;
    for i in 0..sample {
        if b[i * 2 + 1] == 0 {
            odd_nul += 1;
        }
    }
    odd_nul * 100 >= sample * 60
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    #[test]
    fn utf16le_powershell_decodes_correctly() {
        let bytes = utf16le("Invoke-Expression");
        assert!(looks_like_utf16le(&bytes));
        assert_eq!(decode_amsi_content(&bytes), "Invoke-Expression");
    }

    #[test]
    fn the_old_utf8_path_was_broken() {
        // This is exactly the bug Finding 1 describes: the previous code did
        // String::from_utf8_lossy on the UTF-16LE buffer, which does NOT
        // contain the literal string an engine rule would match.
        let bytes = utf16le("Invoke-Expression");
        let old = String::from_utf8_lossy(&bytes);
        assert!(!old.contains("Invoke-Expression"));
        // The fix restores it.
        assert!(decode_amsi_content(&bytes).contains("Invoke-Expression"));
    }

    #[test]
    fn utf16le_with_bom_is_stripped() {
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(utf16le("whoami"));
        assert_eq!(decode_amsi_content(&bytes), "whoami");
    }

    #[test]
    fn utf8_ascii_is_unchanged() {
        let s = "Write-Host 'hello'; Get-Date";
        assert!(!looks_like_utf16le(s.as_bytes()));
        assert_eq!(decode_amsi_content(s.as_bytes()), s);
    }

    #[test]
    fn utf8_multibyte_is_unchanged() {
        // Non-ASCII UTF-8 must not be mistaken for UTF-16LE.
        let s = "café ☃ résumé";
        assert!(!looks_like_utf16le(s.as_bytes()));
        assert_eq!(decode_amsi_content(s.as_bytes()), s);
    }

    #[test]
    fn odd_length_falls_back_to_utf8() {
        // Not a whole number of 16-bit units -> cannot be UTF-16.
        let b = b"abc";
        assert!(!looks_like_utf16le(b));
        assert_eq!(decode_amsi_content(b), "abc");
    }

    #[test]
    fn empty_is_empty() {
        assert_eq!(decode_amsi_content(&[]), "");
        assert!(!looks_like_utf16le(&[]));
    }
}
