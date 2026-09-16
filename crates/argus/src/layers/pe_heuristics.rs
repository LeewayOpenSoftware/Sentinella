//! Layer 2: PE/ELF Structural Heuristics
//!
//! Analyzes portable executable structure for anomalies that indicate
//! malicious modification, packing, or suspicious construction.

use crate::verdict::{Finding, Layer, Severity};
use goblin::pe::PE;

/// Suspicious Windows API imports that indicate potentially malicious behavior.
const SUSPICIOUS_IMPORTS: &[(&str, &str, u32)] = &[
    // (function_name, description, weight)
    ("VirtualAllocEx", "Remote memory allocation", 8),
    ("WriteProcessMemory", "Cross-process memory write", 10),
    (
        "CreateRemoteThread",
        "Remote thread creation (code injection)",
        12,
    ),
    ("NtUnmapViewOfSection", "Process hollowing technique", 15),
    ("SetWindowsHookExA", "Global keyboard/mouse hooking", 8),
    ("SetWindowsHookExW", "Global keyboard/mouse hooking", 8),
    ("NtQueueApcThread", "APC injection", 10),
    ("RtlCreateUserThread", "Low-level thread creation", 10),
    (
        "MiniDumpWriteDump",
        "Process memory dumping (credential theft)",
        12,
    ),
    (
        "CryptUnprotectData",
        "DPAPI decryption (credential access)",
        10,
    ),
    ("AdjustTokenPrivileges", "Privilege escalation", 6),
    ("OpenProcessToken", "Token manipulation", 5),
    ("InternetOpenUrlA", "Direct URL download", 4),
    ("URLDownloadToFileA", "File download from URL", 6),
    ("URLDownloadToFileW", "File download from URL", 6),
    ("ShellExecuteA", "Process execution", 3),
    ("WinExec", "Legacy process execution", 5),
    // Exploit-related APIs.
    (
        "NtAllocateVirtualMemory",
        "Direct NT memory allocation (hook bypass)",
        8,
    ),
    (
        "NtWriteVirtualMemory",
        "Direct NT memory write (hook bypass)",
        10,
    ),
    (
        "NtProtectVirtualMemory",
        "Direct NT memory protection change",
        8,
    ),
    (
        "NtCreateThreadEx",
        "Direct NT thread creation (hook bypass)",
        10,
    ),
    (
        "RtlCaptureContext",
        "Thread context capture (ROP/stack pivot)",
        6,
    ),
    (
        "SetThreadContext",
        "Thread context modification (exploit technique)",
        8,
    ),
    (
        "GetThreadContext",
        "Thread context read (debugger/exploit)",
        4,
    ),
    // Privilege escalation / token impersonation APIs.
    (
        "DuplicateTokenEx",
        "Token duplication (privilege escalation)",
        8,
    ),
    (
        "CreateProcessWithTokenW",
        "Process creation with impersonated token",
        10,
    ),
    // Service manipulation APIs.
    ("OpenSCManagerA", "Service manager access", 5),
    ("CreateServiceA", "Service installation", 8),
];

/// Analyze PE structural characteristics for anomalies.
pub fn analyze(pe: &PE, data: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();

    analyze_sections(pe, data, &mut findings);
    analyze_imports(pe, data.len(), &mut findings);
    analyze_import_combinations(pe, &mut findings);
    analyze_header(pe, &mut findings);
    analyze_resources(pe, data, &mut findings);
    analyze_overlay(pe, data, &mut findings);
    analyze_section_names(pe, &mut findings);

    findings
}

// ── Section analysis ───────────────────────────────────────────────

fn analyze_sections(pe: &PE, data: &[u8], findings: &mut Vec<Finding>) {
    let sections = &pe.sections;

    if sections.is_empty() {
        return;
    }

    // Check for writable + executable sections (W^X violation).
    for section in sections {
        let name = section_name(section);
        let chars = section.characteristics;
        let writable = chars & 0x8000_0000 != 0; // IMAGE_SCN_MEM_WRITE
        let executable = chars & 0x2000_0000 != 0; // IMAGE_SCN_MEM_EXECUTE

        if writable && executable {
            findings.push(Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Low,
                weight: 5,
                description: "Executable section with write permissions — common in installers and self-extracting archives, also used by packed malware.".into(),
                technical_detail: Some(format!("Section '{name}' has both WRITE and EXECUTE flags (0x{chars:08X})")),
            });
        }
    }

    // Check for sections with zero raw size but non-zero virtual size.
    for section in sections {
        let name = section_name(section);
        let raw = section.size_of_raw_data;
        let virt = section.virtual_size;

        if raw == 0 && virt > 0 && virt > 4096 {
            findings.push(Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Info,
                weight: 3,
                description: "Section exists only in memory with no data on disk — used by packers to allocate decompression space.".into(),
                technical_detail: Some(format!("Section '{name}': raw_size=0, virtual_size={virt}")),
            });
        }
    }

    // Calculate per-section entropy.
    for section in sections {
        let name = section_name(section);
        let offset = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        // Defensive: untrusted PE header fields (pointer + size are u32).
        // `offset + size` wraps on 32-bit usize when attacker sets both to
        // u32::MAX → wrapped tiny value passes `<= data.len()` → OOB slice.
        let end = match offset.checked_add(size) {
            Some(e) if e <= data.len() => e,
            _ => continue,
        };
        if size < 256 {
            continue;
        }

        let section_data = &data[offset..end];
        let ent = entropy::shannon_entropy(section_data);

        if ent > 7.5 {
            // Very high entropy (>7.5) is more suspicious — likely encrypted.
            findings.push(Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Low,
                weight: 6,
                description: "Executable section has near-random entropy, indicating encrypted or heavily compressed content.".into(),
                technical_detail: Some(format!("Section '{name}': entropy {ent:.2}/8.0 ({size} bytes)")),
            });
        } else if ent > 7.0 && size > 100_000 {
            // Elevated entropy in large sections — common in compressed installers.
            findings.push(Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Info,
                weight: 2,
                description:
                    "Executable section has elevated entropy, consistent with compressed data."
                        .into(),
                technical_detail: Some(format!(
                    "Section '{name}': entropy {ent:.2}/8.0 ({size} bytes)"
                )),
            });
        }
    }

    // Entry point in unusual section.
    // Defensive: pe.entry is u64 — truncating to u32 silently drops the high
    // bits, so an attacker-controlled entry above u32::MAX would alias an
    // arbitrary low RVA. Bail out instead of misclassifying.
    let ep_rva = match u32::try_from(pe.entry) {
        Ok(v) => v,
        Err(_) => return,
    };
    if ep_rva > 0 {
        for (i, section) in sections.iter().enumerate() {
            let start = section.virtual_address;
            // Defensive: untrusted PE header fields — virtual_address +
            // virtual_size can wrap u32 (both attacker-controlled). A wrap to
            // a tiny `end` would silently include the entry point in the range
            // check below. Treat overflow as "section does not contain EP".
            let end = match start.checked_add(section.virtual_size) {
                Some(e) => e,
                None => continue,
            };
            if ep_rva >= start && ep_rva < end && i == sections.len() - 1 && sections.len() > 2 {
                let name = section_name(section);
                findings.push(Finding {
                    layer: Layer::StructuralAnalysis,
                    severity: Severity::Info,
                    weight: 3,
                    description: "Entry point resides in the last section — unusual for standard compilers, common in packed executables.".into(),
                    technical_detail: Some(format!("Entry point RVA 0x{ep_rva:08X} in last section '{name}'")),
                });
                break;
            }
        }
    }
}

// ── Import analysis ────────────────────────────────────────────────

fn analyze_imports(pe: &PE, file_size: usize, findings: &mut Vec<Finding>) {
    let imports = &pe.imports;
    let total_functions: usize = imports.len();
    let unique_dlls: std::collections::HashSet<&str> =
        imports.iter().map(|imp| imp.dll).collect();

    // Very few imports — suspicious if binary is large.
    if total_functions <= 5 && total_functions > 0 {
        // Check if it's only LoadLibrary/GetProcAddress (runtime resolution).
        let has_loadlib = imports.iter().any(|i| i.name.contains("LoadLibrary"));
        let has_getproc = imports.iter().any(|i| i.name.contains("GetProcAddress"));

        if has_loadlib && has_getproc {
            // Large files (>5MB) with few imports are usually frameworks/installers, not packed malware.
            let weight = if file_size > 5_000_000 { 4 } else { 8 };
            findings.push(Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Low,
                weight,
                description: "Executable resolves functions at runtime instead of declaring them — common in plugins and installers, also used to hide capabilities.".into(),
                technical_detail: Some(format!(
                    "Only {total_functions} imports from {0} DLL(s); includes LoadLibrary + GetProcAddress",
                    unique_dlls.len(),
                )),
            });
        } else {
            findings.push(Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Info,
                weight: 3,
                description:
                    "Small import table — common in installers and self-contained binaries.".into(),
                technical_detail: Some(format!(
                    "{total_functions} imports from {} DLL(s)",
                    unique_dlls.len()
                )),
            });
        }
    }

    // Check for suspicious individual imports.
    let mut suspicious_count = 0u32;
    let mut suspicious_weight = 0u32;
    let mut suspicious_details = Vec::new();

    for import in imports {
        let func_name: &str = import.name.as_ref();
        if func_name.is_empty() {
            continue;
        }

        for &(pattern, desc, weight) in SUSPICIOUS_IMPORTS {
            if func_name == pattern {
                suspicious_count += 1;
                suspicious_weight += weight;
                suspicious_details.push(format!("{func_name} ({desc})"));
            }
        }
    }

    // Only flag if multiple suspicious imports are found together (3+ needed).
    // Many legitimate programs import VirtualAlloc, OpenProcessToken, etc.
    if suspicious_count >= 3 {
        let capped_weight = (suspicious_weight / 2).min(20); // Halve raw weight, cap at 20.
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: if suspicious_count >= 5 { Severity::High } else { Severity::Medium },
            weight: capped_weight,
            description: format!(
                "Executable imports {suspicious_count} functions commonly associated with code injection, credential theft, or process manipulation.",
            ),
            technical_detail: Some(suspicious_details.join(", ")),
        });
    }

    // No imports at all (possible shellcode or fully packed).
    if total_functions == 0 {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Low,
            weight: 8,
            description: "Executable has no visible import table — all functionality is resolved at runtime or the file may be shellcode.".into(),
            technical_detail: Some("Empty import directory".into()),
        });
    }
}

// ── Header analysis ────────────────────────────────────────────────

fn analyze_header(pe: &PE, findings: &mut Vec<Finding>) {
    let header = &pe.header;

    // Check PE timestamp for anomalies.
    let coff = header.coff_header.time_date_stamp;
    if coff == 0 {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Low,
            weight: 3,
            description: "PE timestamp is zeroed — the compilation date was intentionally removed."
                .into(),
            technical_detail: Some("TimeDateStamp: 0x00000000".into()),
        });
    } else if coff > 2_000_000_000 {
        // Timestamp after ~2033 is suspicious (future date).
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Low,
            weight: 5,
            description: "PE timestamp is set to a future date — possibly forged.".into(),
            technical_detail: Some(format!("TimeDateStamp: 0x{coff:08X}")),
        });
    }

    // Check if it's a "big" unsigned binary (>500KB) with no certificate table.
    let has_cert = pe
        .header
        .optional_header
        .map(|oh| {
            oh.data_directories
                .get_certificate_table()
                .is_some_and(|ct| ct.size > 0)
        })
        .unwrap_or(false);

    if !has_cert {
        if pe
            .sections
            .iter()
            .map(|s| s.size_of_raw_data as u64)
            .sum::<u64>()
            > 500_000
        {
            findings.push(Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Info,
                weight: 2,
                description: "Large executable has no digital signature — cannot verify publisher authenticity.".into(),
                technical_detail: Some("No Authenticode certificate found".into()),
            });
        }
    }
}

// ── Resource analysis ──────────────────────────────────────────────

fn analyze_resources(pe: &PE, data: &[u8], findings: &mut Vec<Finding>) {
    // Check resource section (typically named .rsrc) for high entropy.
    for section in &pe.sections {
        let name = section_name(section);
        if name != ".rsrc" {
            continue;
        }

        let offset = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        // Defensive: see `analyze_sections` for the rationale on checked_add.
        let end = match offset.checked_add(size) {
            Some(e) if e <= data.len() => e,
            _ => continue,
        };
        if size < 100_000 {
            continue;
        }

        let ent = entropy::shannon_entropy(&data[offset..end]);
        if ent > 7.0 {
            findings.push(Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 12,
                description: "Resource section contains high-entropy data — may embed an encrypted or compressed payload.".into(),
                technical_detail: Some(format!("Section .rsrc: {size} bytes, entropy {ent:.2}/8.0")),
            });
        }
    }
}

// ── Overlay analysis ───────────────────────────────────────────────

fn analyze_overlay(pe: &PE, data: &[u8], findings: &mut Vec<Finding>) {
    // Calculate where the PE ends (last section's raw data end).
    // Defensive: `pointer_to_raw_data + size_of_raw_data` is u32+u32 from
    // attacker-controlled PE headers — wraps silently on overflow. Use
    // checked_add and skip any wrapping section instead of letting a wrapped
    // small `pe_end` smuggle a section's raw range into the "overlay" tail.
    let pe_end = pe
        .sections
        .iter()
        .filter_map(|s| s.pointer_to_raw_data.checked_add(s.size_of_raw_data))
        .map(|v| v as usize)
        .max()
        .unwrap_or(0);

    if pe_end > 0 && pe_end < data.len() {
        let overlay_size = data.len() - pe_end;

        if overlay_size > 10_000 {
            let overlay_data = &data[pe_end..];
            let ent = entropy::shannon_entropy(overlay_data);

            let (severity, weight, desc) = if overlay_size > 1_000_000 && ent > 7.5 {
                (
                    Severity::Low,
                    5,
                    "Large encrypted overlay appended after PE structure — common in installers, also used for hidden payloads.",
                )
            } else if overlay_size > 1_000_000 {
                (
                    Severity::Info,
                    2,
                    "Large overlay appended after PE structure — typical of installers and self-extracting archives.",
                )
            } else {
                (
                    Severity::Info,
                    0,
                    "Small overlay data appended after PE structure.",
                )
            };

            if weight > 0 {
                findings.push(Finding {
                    layer: Layer::StructuralAnalysis,
                    severity,
                    weight,
                    description: desc.into(),
                    technical_detail: Some(format!(
                        "Overlay: {overlay_size} bytes at offset 0x{pe_end:08X}, entropy {ent:.2}/8.0",
                    )),
                });
            }
        }
    }
}

// ── Import combination analysis ────────────────────────────────────
// Certain import COMBINATIONS are far more suspicious than individual
// imports. A binary that imports both WriteProcessMemory AND
// CreateRemoteThread is almost certainly doing code injection.

fn analyze_import_combinations(pe: &PE, findings: &mut Vec<Finding>) {
    let imports: std::collections::HashSet<&str> =
        pe.imports.iter().map(|i| i.name.as_ref()).collect();

    // Code injection pattern: allocate + write + execute in remote process.
    let has_inject = imports.contains("VirtualAllocEx")
        && (imports.contains("WriteProcessMemory") || imports.contains("NtWriteVirtualMemory"))
        && (imports.contains("CreateRemoteThread")
            || imports.contains("RtlCreateUserThread")
            || imports.contains("NtQueueApcThread"));

    if has_inject {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::High,
            weight: 30,
            description: "Executable imports the complete code injection triad (allocate + write + execute in remote process) — a strong indicator of process injection capability.".into(),
            technical_detail: Some("VirtualAllocEx + WriteProcessMemory + CreateRemoteThread/NtQueueApcThread".into()),
        });
    }

    // Process hollowing pattern.
    let has_hollowing = imports.contains("NtUnmapViewOfSection")
        && (imports.contains("WriteProcessMemory") || imports.contains("NtWriteVirtualMemory"));

    if has_hollowing && !has_inject {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::High,
            weight: 30,
            description: "Executable imports functions associated with process hollowing — a technique to replace a legitimate process with malicious code.".into(),
            technical_detail: Some("NtUnmapViewOfSection + WriteProcessMemory".into()),
        });
    }

    // Credential dumping pattern.
    let has_cred_dump = imports.contains("MiniDumpWriteDump")
        && (imports.contains("OpenProcess") || imports.contains("OpenProcessToken"));

    if has_cred_dump {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::High,
            weight: 25,
            description: "Executable imports functions for process memory dumping — commonly used for credential extraction (similar to Mimikatz behavior).".into(),
            technical_detail: Some("MiniDumpWriteDump + OpenProcess/OpenProcessToken".into()),
        });
    }

    // Anti-debugging pattern.
    let has_antidebug = (imports.contains("IsDebuggerPresent")
        || imports.contains("CheckRemoteDebuggerPresent"))
        && (imports.contains("NtQueryInformationProcess")
            || imports.contains("OutputDebugStringA"));

    if has_antidebug {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Medium,
            weight: 12,
            description: "Executable implements anti-debugging checks — common in both DRM-protected software and malware trying to evade analysis.".into(),
            technical_detail: Some("IsDebuggerPresent/CheckRemoteDebuggerPresent + NtQueryInformationProcess".into()),
        });
    }

    // ── Exploit Blocker Phase B: exploitation-related imports ──

    // DEP bypass — changing memory protection to allow code execution.
    let has_dep_bypass = imports.contains("VirtualProtect")
        && (imports.contains("VirtualAlloc") || imports.contains("HeapCreate"));
    if has_dep_bypass && (has_inject || has_hollowing) {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::High,
            weight: 20,
            description: "Memory protection manipulation combined with injection — possible DEP bypass for shellcode execution.".into(),
            technical_detail: Some("VirtualProtect + VirtualAlloc + injection APIs".into()),
        });
    }

    // ROP-related: context capture + continuation (stack pivoting).
    let has_rop = (imports.contains("RtlCaptureContext") || imports.contains("GetThreadContext"))
        && (imports.contains("NtContinue") || imports.contains("SetThreadContext"));
    if has_rop {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::High,
            weight: 22,
            description:
                "Thread context manipulation APIs — used in ROP chains and stack pivoting exploits."
                    .into(),
            technical_detail: Some(
                "RtlCaptureContext/GetThreadContext + NtContinue/SetThreadContext".into(),
            ),
        });
    }

    // Executable heap — code execution from heap (heap spray, JIT spray).
    if imports.contains("HeapCreate") && imports.contains("VirtualProtect") {
        // Only flag if combined with other suspicious behavior.
        if imports.contains("WriteProcessMemory") || imports.contains("VirtualAllocEx") {
            findings.push(Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 15,
                description: "Executable heap creation + memory protection changes — possible heap spray or JIT spray technique.".into(),
                technical_detail: Some("HeapCreate + VirtualProtect + remote memory APIs".into()),
            });
        }
    }

    // NTDLL direct syscall pattern — bypassing user-mode hooks.
    let has_direct_syscall = imports.contains("NtAllocateVirtualMemory")
        || imports.contains("NtWriteVirtualMemory")
        || imports.contains("NtProtectVirtualMemory")
        || imports.contains("NtCreateThreadEx");
    if has_direct_syscall {
        let nt_count = [
            imports.contains("NtAllocateVirtualMemory"),
            imports.contains("NtWriteVirtualMemory"),
            imports.contains("NtProtectVirtualMemory"),
            imports.contains("NtCreateThreadEx"),
        ]
        .iter()
        .filter(|&&b| b)
        .count();
        if nt_count >= 2 {
            findings.push(Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::High,
                weight: 18,
                description: format!("Imports {nt_count} direct NT syscall functions — bypasses user-mode API hooks used by security software."),
                technical_detail: Some("NtAllocateVirtualMemory/NtWriteVirtualMemory/NtProtectVirtualMemory/NtCreateThreadEx".into()),
            });
        }
    }

    // Parent process spoofing.
    if imports.contains("UpdateProcThreadAttribute")
        && (imports.contains("CreateProcessA") || imports.contains("CreateProcessW"))
    {
        if imports.contains("InitializeProcThreadAttributeList") {
            findings.push(Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 14,
                description: "Process attribute manipulation — can be used for parent process spoofing to evade detection.".into(),
                technical_detail: Some("InitializeProcThreadAttributeList + UpdateProcThreadAttribute + CreateProcess".into()),
            });
        }
    }

    // DLL side-loading indicators.
    // LoadLibrary + GetProcAddress is extremely common in legitimate software,
    // so only flag when combined with injection or evasion imports.
    let has_dll_sideload = (imports.contains("LoadLibraryA") || imports.contains("LoadLibraryW"))
        && imports.contains("GetProcAddress")
        && (imports.contains("WriteFile")
            || imports.contains("CreateFileA")
            || imports.contains("CreateFileW"));
    if has_dll_sideload && (has_inject || has_hollowing || has_direct_syscall || has_antidebug) {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Medium,
            weight: 8,
            description: "DLL side-loading pattern — runtime library loading combined with file writes and injection/evasion APIs suggests DLL hijacking.".into(),
            technical_detail: Some("LoadLibrary + GetProcAddress + file write APIs + injection/evasion imports".into()),
        });
    }

    // Token impersonation chain — privilege escalation via stolen tokens.
    let has_token_impersonation = imports.contains("OpenProcessToken")
        && imports.contains("DuplicateTokenEx")
        && (imports.contains("CreateProcessWithTokenW")
            || imports.contains("ImpersonateLoggedOnUser"));
    if has_token_impersonation {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::High,
            weight: 20,
            description: "Token impersonation chain — opens a process token, duplicates it, and creates a process or impersonates a user with the stolen token. Strong indicator of privilege escalation.".into(),
            technical_detail: Some("OpenProcessToken + DuplicateTokenEx + CreateProcessWithTokenW/ImpersonateLoggedOnUser".into()),
        });
    }

    // Service manipulation — persistence via service installation.
    let has_service_manipulation = (imports.contains("OpenSCManagerA")
        || imports.contains("OpenSCManagerW"))
        && (imports.contains("CreateServiceA")
            || imports.contains("CreateServiceW")
            || imports.contains("ChangeServiceConfigA"));
    if has_service_manipulation {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Medium,
            weight: 15,
            description: "Service manipulation — opens the service control manager and creates or modifies a service. Used for persistence via service installation.".into(),
            technical_detail: Some("OpenSCManager + CreateService/ChangeServiceConfig".into()),
        });
    }
}

// ── Section name anomaly detection ────────────────────────────────
// Standard compilers produce well-known section names. Random or
// garbage section names are a strong indicator of packing or tampering.

fn analyze_section_names(pe: &PE, findings: &mut Vec<Finding>) {
    // Known legitimate section names (case-insensitive).
    let standard_names = [
        ".text",
        ".rdata",
        ".data",
        ".rsrc",
        ".reloc",
        ".pdata",
        ".idata",
        ".edata",
        ".tls",
        ".bss",
        ".crt",
        ".debug",
        ".xdata",
        ".didat",
        ".sxdata",
        ".gfids",
        ".00cfg",
        "code",
        "data",     // Borland/Delphi
        ".textbss", // MinGW
        ".ndata",
        ".nsis",       // NSIS installer
        ".qtmetad",    // Qt framework
        ".go.buildid", // Go binaries
        ".symtab",     // Go/Rust symbol table
        ".strtab",     // Go/Rust string table
        ".note",       // ELF note (sometimes in PE via cross-compile)
        ".buildid",    // Go build ID
        ".rust",       // Rust metadata
    ];

    let mut anomalous_sections = Vec::new();

    for section in &pe.sections {
        let name = section_name(section);
        if name.is_empty() {
            continue;
        }

        let name_lower = name.to_lowercase();

        // Skip known packer sections (handled by packer layer).
        if name_lower.starts_with("upx")
            || name_lower.starts_with(".vmp")
            || name_lower.starts_with(".themida")
            || name_lower.starts_with(".aspack")
            || name_lower.starts_with(".mpress")
            || name_lower.starts_with(".enigma")
            || name_lower.starts_with(".nsp")
            || name_lower.starts_with(".petite")
            || name_lower.starts_with("confuserex")
        {
            continue; // Packer layer handles these.
        }

        // Check if name is standard.
        let is_standard = standard_names.iter().any(|&s| name_lower == s);
        if is_standard {
            continue;
        }

        // Check if name looks like garbage (non-printable or random characters).
        let non_printable = name.bytes().filter(|&b| !(0x20..=0x7E).contains(&b)).count();
        let has_garbage = non_printable > 0
            || (name.len() >= 4
                && !name.contains('.')
                && name.chars().all(|c| c.is_ascii_alphanumeric()));

        if has_garbage && name.len() >= 3 {
            anomalous_sections.push(name.clone());
        }
    }

    if anomalous_sections.len() >= 2 {
        findings.push(Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Medium,
            weight: 10,
            description: format!(
                "Executable has {} sections with non-standard names — may indicate manual tampering or custom packing.",
                anomalous_sections.len(),
            ),
            technical_detail: Some(format!("Anomalous sections: [{}]", anomalous_sections.join(", "))),
        });
    }
}

// ── Helpers ────────────────────────────────────────────────────────

fn section_name(section: &goblin::pe::section_table::SectionTable) -> String {
    let raw = &section.name;
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).to_string()
}
