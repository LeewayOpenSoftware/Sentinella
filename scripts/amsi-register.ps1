# amsi-register.ps1 -- register / unregister the Sentinella AMSI provider.
#
# An AMSI provider is an in-process COM server. Registering it is TWO HKLM
# writes (a COM CLSID InprocServer32 + an AMSI Providers enrolment), both of
# which need administrator rights and are GLOBAL, machine-wide actions. This
# script is the operator-facing way to do it; the DLL also self-registers
# via `regsvr32` (DllRegisterServer/DllUnregisterServer), which does exactly
# the same writes.
#
# SAFETY: do NOT run this against a machine without authorisation. Registering
# an AMSI provider makes Windows load sentinella_amsi_provider.dll into every
# process that calls AmsiScanBuffer (PowerShell, Office, wscript, ...). Verify
# the daemon is healthy first; a broken provider degrades to fail-open (see
# docs/AMSI_PROVIDER.md) but you still want the round-trip working.
#
# Usage (elevated):
#   pwsh scripts\amsi-register.ps1 -DllPath "C:\Program Files\Sentinella\sentinella_amsi_provider.dll"
#   pwsh scripts\amsi-register.ps1 -Unregister
#   pwsh scripts\amsi-register.ps1 -DllPath ... -WhatIf   # print, change nothing

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$DllPath,
    [switch]$Unregister
)

# Keep this CLSID in lock-step with crates/amsi_provider/src/registration.rs.
$Clsid = '{53E6920C-21B6-4826-9752-81485B3CBA2A}'
$Name  = 'Sentinella AMSI Provider'
$ClsidKey = "HKLM:\SOFTWARE\Classes\CLSID\$Clsid"
$InprocKey = "$ClsidKey\InprocServer32"
$AmsiKey  = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\$Clsid"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[amsi-register] FAILED: must run elevated (HKLM write)." -ForegroundColor Red
        exit 1
    }
}

if ($Unregister) {
    Assert-Admin
    foreach ($k in @($AmsiKey, $ClsidKey)) {
        if (Test-Path $k) {
            if ($PSCmdlet.ShouldProcess($k, 'Remove')) {
                Remove-Item -Path $k -Recurse -Force
                Write-Host "[amsi-register] removed $k" -ForegroundColor Green
            }
        } else {
            Write-Host "[amsi-register] not present: $k" -ForegroundColor Yellow
        }
    }
    exit 0
}

if ([string]::IsNullOrWhiteSpace($DllPath)) {
    Write-Host "[amsi-register] FAILED: -DllPath is required to register." -ForegroundColor Red
    exit 1
}
if (-not (Test-Path -LiteralPath $DllPath)) {
    Write-Host "[amsi-register] FAILED: DLL not found at $DllPath" -ForegroundColor Red
    exit 1
}
$DllPath = (Resolve-Path -LiteralPath $DllPath).Path

Assert-Admin

if ($PSCmdlet.ShouldProcess($ClsidKey, "register COM class -> $DllPath")) {
    New-Item -Path $ClsidKey -Force | Out-Null
    Set-ItemProperty -Path $ClsidKey -Name '(default)' -Value $Name
    New-Item -Path $InprocKey -Force | Out-Null
    Set-ItemProperty -Path $InprocKey -Name '(default)' -Value $DllPath
    Set-ItemProperty -Path $InprocKey -Name 'ThreadingModel' -Value 'Both'
    Write-Host "[amsi-register] CLSID + InprocServer32 written" -ForegroundColor Green
}
if ($PSCmdlet.ShouldProcess($AmsiKey, 'enrol as AMSI provider')) {
    New-Item -Path $AmsiKey -Force | Out-Null
    Set-ItemProperty -Path $AmsiKey -Name '(default)' -Value $Name
    Write-Host "[amsi-register] enrolled under AMSI\Providers" -ForegroundColor Green
}

Write-Host ""
Write-Host "[amsi-register] DONE. Providers load on the NEXT start of each host" -ForegroundColor Green
Write-Host "                process (open a fresh PowerShell to test). Verify with" -ForegroundColor Green
Write-Host "                the AMSI test string -- see docs\AMSI_PROVIDER.md." -ForegroundColor Green
