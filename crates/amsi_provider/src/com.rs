//! Windows COM surface: the `IAntimalwareProvider` implementation, its
//! class factory, and the `Dll*` entry points Windows calls. Windows-only,
//! built against the `windows` 0.61 `#[implement]` contract.
//!
//! Everything here is thin glue over the pure logic in `decision`,
//! `budget`, `client` and `registration`. The crate-doc rules are enforced
//! at exactly one place each:
//! - `Scan` wraps its whole body in `catch_unwind` (never panic into the
//!   host) and returns `Ok(NOT_DETECTED)` on any failure (fail open).
//! - the daemon round-trip runs under [`budget::run_with_budget`].

use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::time::Duration;

use windows::core::{implement, BOOL, GUID, HRESULT, Interface, IUnknown, PCWSTR, PWSTR, Ref, Result};
use windows::Win32::Foundation::{
    CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, E_FAIL, E_POINTER, E_UNEXPECTED, HINSTANCE,
    HMODULE, S_FALSE, S_OK,
};
use windows::Win32::System::Antimalware::{
    IAmsiStream, IAntimalwareProvider, IAntimalwareProvider_Impl, AMSI_ATTRIBUTE,
    AMSI_ATTRIBUTE_APP_NAME, AMSI_ATTRIBUTE_CONTENT_ADDRESS, AMSI_ATTRIBUTE_CONTENT_NAME,
    AMSI_ATTRIBUTE_CONTENT_SIZE, AMSI_RESULT,
};
use windows::Win32::System::Com::{CoTaskMemAlloc, IClassFactory, IClassFactory_Impl};
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE,
    KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ,
};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

use crate::budget::run_with_budget;
use crate::client;
use crate::decision::{decision_from_outcome, ProviderDecision};
use crate::registration;

/// Hard wall-clock budget for the whole daemon round-trip. Miss it and we
/// return NOT_DETECTED — blocking the host on a slow/dead daemon is worse
/// than missing one detection.
const SCAN_BUDGET: Duration = Duration::from_millis(250);

/// Upper bound on script content we forward (matches the daemon's own
/// runtime-buffer cap and the IPC frame limit).
const MAX_CONTENT: usize = 1024 * 1024;

/// CLSID this DLL serves.
const CLSID_PROVIDER: GUID = GUID::from_u128(registration::PROVIDER_CLSID_U128);

/// Live COM object + lock counts, for `DllCanUnloadNow`.
static OBJECTS: AtomicUsize = AtomicUsize::new(0);
static LOCKS: AtomicUsize = AtomicUsize::new(0);

/// This DLL's module handle, captured in `DllMain`, used to resolve the
/// DLL's own path at registration time.
static MODULE_HANDLE: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(core::ptr::null_mut());

// ── The provider ────────────────────────────────────────────────────

#[implement(IAntimalwareProvider)]
struct SentinellaAmsiProvider;

impl SentinellaAmsiProvider {
    fn new() -> Self {
        OBJECTS.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

impl Drop for SentinellaAmsiProvider {
    fn drop(&mut self) {
        OBJECTS.fetch_sub(1, Ordering::SeqCst);
    }
}

impl IAntimalwareProvider_Impl for SentinellaAmsiProvider_Impl {
    fn Scan(&self, stream: Ref<'_, IAmsiStream>) -> Result<AMSI_RESULT> {
        let stream = match stream.as_ref() {
            Some(s) => s,
            None => return Ok(AMSI_RESULT(ProviderDecision::NotDetected.amsi_result_i32())),
        };

        // The whole body is panic-guarded: a panic here would unwind into
        // Word/PowerShell. Any failure resolves to NOT_DETECTED.
        let decision = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            let size = attr_u64(stream, AMSI_ATTRIBUTE_CONTENT_SIZE).unwrap_or(0) as usize;
            if size == 0 || size > MAX_CONTENT {
                return ProviderDecision::NotDetected;
            }
            let addr = match attr_u64(stream, AMSI_ATTRIBUTE_CONTENT_ADDRESS) {
                Some(a) if a != 0 => a as *const u8,
                _ => return ProviderDecision::NotDetected,
            };
            let content = std::slice::from_raw_parts(addr, size);
            let text = String::from_utf8_lossy(content).into_owned();
            let app = attr_wstr(stream, AMSI_ATTRIBUTE_APP_NAME).unwrap_or_default();
            let name = attr_wstr(stream, AMSI_ATTRIBUTE_CONTENT_NAME).unwrap_or_default();
            let language = crate::language_from_app(&app);
            let pid = std::process::id();

            let outcome = run_with_budget(SCAN_BUDGET, move || {
                client::scan_once(&text, language, &app, &name, pid)
            })
            .flatten();

            decision_from_outcome(outcome)
        }))
        .unwrap_or(ProviderDecision::NotDetected);

        Ok(AMSI_RESULT(decision.amsi_result_i32()))
    }

    fn CloseSession(&self, _session: u64) {
        // Stateless provider: nothing to tear down per session.
    }

    fn DisplayName(&self) -> Result<PWSTR> {
        Ok(unsafe { pwstr_alloc(registration::PROVIDER_DISPLAY_NAME) })
    }
}

// ── AMSI stream attribute helpers ───────────────────────────────────

/// Read a small fixed-width numeric attribute (CONTENT_SIZE / _ADDRESS).
unsafe fn attr_u64(stream: &IAmsiStream, attr: AMSI_ATTRIBUTE) -> Option<u64> {
    let mut buf = [0u8; 8];
    let mut ret: u32 = 0;
    unsafe { stream.GetAttribute(attr, &mut buf, &mut ret).ok()? };
    let n = ret as usize;
    if n == 0 || n > 8 {
        return None;
    }
    let mut b = [0u8; 8];
    b[..n].copy_from_slice(&buf[..n]);
    Some(u64::from_ne_bytes(b))
}

/// Read a UTF-16 string attribute (APP_NAME / CONTENT_NAME).
unsafe fn attr_wstr(stream: &IAmsiStream, attr: AMSI_ATTRIBUTE) -> Option<String> {
    let mut buf = vec![0u8; 1024];
    let mut ret: u32 = 0;
    if unsafe { stream.GetAttribute(attr, &mut buf, &mut ret) }.is_err() {
        return None;
    }
    let n = (ret as usize).min(buf.len());
    if n < 2 {
        return None;
    }
    let u16s: Vec<u16> = buf[..n]
        .chunks_exact(2)
        .map(|c| u16::from_ne_bytes([c[0], c[1]]))
        .collect();
    let end = u16s.iter().position(|&c| c == 0).unwrap_or(u16s.len());
    Some(String::from_utf16_lossy(&u16s[..end]))
}

/// Allocate a `PWSTR` with `CoTaskMemAlloc` (the AMSI host frees it with
/// `CoTaskMemFree`).
unsafe fn pwstr_alloc(s: &str) -> PWSTR {
    let mut w: Vec<u16> = s.encode_utf16().collect();
    w.push(0);
    let p = unsafe { CoTaskMemAlloc(w.len() * 2) } as *mut u16;
    if p.is_null() {
        return PWSTR::null();
    }
    unsafe { core::ptr::copy_nonoverlapping(w.as_ptr(), p, w.len()) };
    PWSTR(p)
}

// ── Class factory ───────────────────────────────────────────────────

#[implement(IClassFactory)]
struct ProviderFactory;

impl IClassFactory_Impl for ProviderFactory_Impl {
    fn CreateInstance(
        &self,
        outer: Ref<'_, IUnknown>,
        iid: *const GUID,
        object: *mut *mut core::ffi::c_void,
    ) -> Result<()> {
        if object.is_null() {
            return E_POINTER.ok();
        }
        unsafe { *object = core::ptr::null_mut() };
        if !outer.is_null() {
            return CLASS_E_NOAGGREGATION.ok();
        }
        let provider: IAntimalwareProvider = SentinellaAmsiProvider::new().into();
        unsafe { provider.query(iid, object).ok() }
    }

    fn LockServer(&self, lock: BOOL) -> Result<()> {
        if lock.as_bool() {
            LOCKS.fetch_add(1, Ordering::SeqCst);
        } else {
            LOCKS.fetch_sub(1, Ordering::SeqCst);
        }
        Ok(())
    }
}

// ── DLL entry points ────────────────────────────────────────────────

/// DLL entry point: capture our module handle for path resolution.
#[unsafe(no_mangle)]
extern "system" fn DllMain(hinst: HINSTANCE, reason: u32, _reserved: *mut core::ffi::c_void) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        MODULE_HANDLE.store(hinst.0, Ordering::SeqCst);
    }
    BOOL(1)
}

/// COM class-object factory hand-out.
#[unsafe(no_mangle)]
extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut core::ffi::c_void,
) -> HRESULT {
    std::panic::catch_unwind(|| unsafe {
        if ppv.is_null() {
            return E_POINTER;
        }
        *ppv = core::ptr::null_mut();
        if rclsid.is_null() || riid.is_null() {
            return E_POINTER;
        }
        if *rclsid != CLSID_PROVIDER {
            return CLASS_E_CLASSNOTAVAILABLE;
        }
        let factory: IClassFactory = ProviderFactory.into();
        factory.query(riid, ppv)
    })
    .unwrap_or(E_UNEXPECTED)
}

/// COM asks whether the DLL can be unloaded.
#[unsafe(no_mangle)]
extern "system" fn DllCanUnloadNow() -> HRESULT {
    if OBJECTS.load(Ordering::SeqCst) == 0 && LOCKS.load(Ordering::SeqCst) == 0 {
        S_OK
    } else {
        S_FALSE
    }
}

/// Self-registration (`regsvr32 sentinella_amsi_provider.dll`). Writes the
/// CLSID InprocServer32 and the AMSI-provider enrolment under HKLM. Needs
/// admin. See docs/AMSI_PROVIDER.md — do not run against a machine without
/// authorisation.
#[unsafe(no_mangle)]
extern "system" fn DllRegisterServer() -> HRESULT {
    let ok = std::panic::catch_unwind(|| unsafe {
        let dll = match dll_path() {
            Some(p) => p,
            None => return false,
        };
        let root = match create_key(&registration::clsid_root_subkey()) {
            Some(k) => k,
            None => return false,
        };
        let ok_root = set_sz(root, None, registration::PROVIDER_DISPLAY_NAME);
        let _ = RegCloseKey(root);

        let inproc = match create_key(&registration::clsid_inproc_subkey()) {
            Some(k) => k,
            None => return false,
        };
        let ok_inproc =
            set_sz(inproc, None, &dll) && set_sz(inproc, Some("ThreadingModel"), "Both");
        let _ = RegCloseKey(inproc);

        let amsi = match create_key(&registration::amsi_provider_subkey()) {
            Some(k) => k,
            None => return false,
        };
        let ok_amsi = set_sz(amsi, None, registration::PROVIDER_DISPLAY_NAME);
        let _ = RegCloseKey(amsi);

        ok_root && ok_inproc && ok_amsi
    })
    .unwrap_or(false);

    if ok { S_OK } else { E_FAIL }
}

/// Self-unregistration (`regsvr32 /u`). Removes both HKLM keys.
#[unsafe(no_mangle)]
extern "system" fn DllUnregisterServer() -> HRESULT {
    let _ = std::panic::catch_unwind(|| unsafe {
        let clsid = wide(&registration::clsid_root_subkey());
        let _ = RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(clsid.as_ptr()));
        let amsi = wide(&registration::amsi_provider_subkey());
        let _ = RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(amsi.as_ptr()));
    });
    S_OK
}

// ── Registry helpers ────────────────────────────────────────────────

/// UTF-16, null-terminated.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// This DLL's full path, from the handle captured in `DllMain`.
unsafe fn dll_path() -> Option<String> {
    let ptr = MODULE_HANDLE.load(Ordering::SeqCst);
    if ptr.is_null() {
        return None;
    }
    let mut buf = [0u16; 1024];
    let n = unsafe { GetModuleFileNameW(Some(HMODULE(ptr)), &mut buf) } as usize;
    if n == 0 || n >= buf.len() {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..n]))
}

unsafe fn create_key(subkey: &str) -> Option<HKEY> {
    let w = wide(subkey);
    let mut hkey = HKEY(core::ptr::null_mut());
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(w.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
    };
    if rc.0 == 0 { Some(hkey) } else { None }
}

unsafe fn set_sz(hkey: HKEY, name: Option<&str>, data: &str) -> bool {
    let wd = wide(data);
    let bytes = unsafe { std::slice::from_raw_parts(wd.as_ptr() as *const u8, wd.len() * 2) };
    let rc = match name {
        Some(n) => {
            let wn = wide(n);
            unsafe { RegSetValueExW(hkey, PCWSTR(wn.as_ptr()), None, REG_SZ, Some(bytes)) }
        }
        None => unsafe { RegSetValueExW(hkey, PCWSTR::null(), None, REG_SZ, Some(bytes)) },
    };
    rc.0 == 0
}
