//! COM + AMSI registration facts and artifact generation.
//!
//! Registering an AMSI provider is two HKLM writes: a normal COM CLSID
//! `InprocServer32` pointing at this DLL, and an entry under
//! `SOFTWARE\Microsoft\AMSI\Providers\{CLSID}` that tells AMSI to load it.
//! Both live under HKLM, so both need admin and both are GLOBAL actions.
//! The registry *writes* themselves live in `com::DllRegisterServer` /
//! `DllUnregisterServer` (Windows only). Everything here is pure string /
//! path construction so it can be tested and so the `.reg` file and the
//! PowerShell helper can be generated without touching the registry.

/// Stable CLSID of the Sentinella AMSI provider. Generated once; must stay
/// constant across releases or every registered install would orphan.
pub const PROVIDER_CLSID: &str = "{53E6920C-21B6-4826-9752-81485B3CBA2A}";

/// CLSID as a bare u128 for `windows_core::GUID::from_u128`.
pub const PROVIDER_CLSID_U128: u128 = 0x53E6920C_21B6_4826_9752_81485B3CBA2A;

/// Human-readable provider name (shown by AMSI diagnostics / `DisplayName`).
pub const PROVIDER_DISPLAY_NAME: &str = "Sentinella AMSI Provider";

/// HKLM subkey of the COM class's in-process server.
pub fn clsid_inproc_subkey() -> String {
    format!(r"SOFTWARE\Classes\CLSID\{PROVIDER_CLSID}\InprocServer32")
}

/// HKLM subkey of the COM class root (default value = display name).
pub fn clsid_root_subkey() -> String {
    format!(r"SOFTWARE\Classes\CLSID\{PROVIDER_CLSID}")
}

/// HKLM subkey that enrols the CLSID as an AMSI provider.
pub fn amsi_provider_subkey() -> String {
    format!(r"SOFTWARE\Microsoft\AMSI\Providers\{PROVIDER_CLSID}")
}

/// Build a `.reg` file that registers the provider for `dll_path`.
pub fn reg_file_contents(dll_path: &str) -> String {
    let dll = dll_path.replace('\\', r"\\");
    format!(
        "Windows Registry Editor Version 5.00\r\n\
\r\n\
[HKEY_LOCAL_MACHINE\\{root}]\r\n\
@=\"{name}\"\r\n\
\r\n\
[HKEY_LOCAL_MACHINE\\{inproc}]\r\n\
@=\"{dll}\"\r\n\
\"ThreadingModel\"=\"Both\"\r\n\
\r\n\
[HKEY_LOCAL_MACHINE\\{amsi}]\r\n\
@=\"{name}\"\r\n",
        root = clsid_root_subkey().replace('\\', r"\\"),
        inproc = clsid_inproc_subkey().replace('\\', r"\\"),
        amsi = amsi_provider_subkey().replace('\\', r"\\"),
        name = PROVIDER_DISPLAY_NAME,
        dll = dll,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clsid_is_well_formed() {
        assert!(PROVIDER_CLSID.starts_with('{') && PROVIDER_CLSID.ends_with('}'));
        assert_eq!(PROVIDER_CLSID.len(), 38); // {8-4-4-4-12}
    }

    #[test]
    fn u128_matches_string() {
        // Reconstruct the dashed hex from the u128 and compare (case-insensitive).
        let hex = format!("{PROVIDER_CLSID_U128:032X}");
        let dashed = format!(
            "{{{}-{}-{}-{}-{}}}",
            &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32]
        );
        assert_eq!(dashed, PROVIDER_CLSID);
    }

    #[test]
    fn subkeys_are_correct() {
        assert!(clsid_inproc_subkey().ends_with(r"\InprocServer32"));
        assert!(clsid_inproc_subkey().contains(PROVIDER_CLSID));
        assert_eq!(
            amsi_provider_subkey(),
            format!(r"SOFTWARE\Microsoft\AMSI\Providers\{PROVIDER_CLSID}")
        );
    }

    #[test]
    fn reg_file_has_all_three_keys_and_dll() {
        let reg = reg_file_contents(r"C:\Program Files\Sentinella\sentinella_amsi_provider.dll");
        assert!(reg.starts_with("Windows Registry Editor Version 5.00"));
        assert!(reg.contains(r"CLSID\\{53E6920C-21B6-4826-9752-81485B3CBA2A}\\InprocServer32"));
        assert!(reg.contains(r"AMSI\\Providers\\{53E6920C-21B6-4826-9752-81485B3CBA2A}"));
        assert!(reg.contains(r"ThreadingModel"));
        // DLL path is backslash-escaped for .reg syntax.
        assert!(reg.contains(r"C:\\Program Files\\Sentinella\\sentinella_amsi_provider.dll"));
    }
}
