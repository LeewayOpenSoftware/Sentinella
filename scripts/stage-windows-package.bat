@echo off
:: ============================================================
:: Sentinella — Stage Windows Release Package
:: ============================================================
:: Copies all release artifacts into release/staging/windows/
:: for WiX installer build or manual distribution.
::
:: Requires: cargo build --release && cd gui && pnpm build
:: ============================================================

set "ROOT=%~dp0.."
set "STAGE=%ROOT%\release\staging\windows"
set "TARGET=%ROOT%\target\release"
set "BUILD=%ROOT%\build\clamav"

echo.
echo  ==========================================
echo   Sentinella Package Staging
echo  ==========================================
echo.

:: Clean previous staging.
if exist "%STAGE%" rmdir /s /q "%STAGE%"
mkdir "%STAGE%"
mkdir "%STAGE%\runtime\config"
mkdir "%STAGE%\runtime\argus\rules\yara"
mkdir "%STAGE%\runtime\argus\manifests"
mkdir "%STAGE%\runtime\rules"
mkdir "%STAGE%\runtime\rules\dns"
mkdir "%STAGE%\runtime\signatures_bootstrap"
mkdir "%STAGE%\certs"
mkdir "%STAGE%\scripts"

:: ── Core binaries ──
echo  [1/8] Core binaries...
if exist "%TARGET%\sentinelld.exe" (
    copy /Y "%TARGET%\sentinelld.exe" "%STAGE%\" >nul
    echo        sentinelld.exe OK
) else (
    echo        [WARN] sentinelld.exe not found — run: cargo build --release -p sentinelld
)

if exist "%TARGET%\sentinella.exe" (
    copy /Y "%TARGET%\sentinella.exe" "%STAGE%\" >nul
    echo        sentinella.exe CLI OK
) else (
    echo        [WARN] sentinella.exe CLI not found
)

if exist "%TARGET%\argusd.exe" (
    copy /Y "%TARGET%\argusd.exe" "%STAGE%\" >nul
    echo        argusd.exe OK
) else (
    echo        [WARN] argusd.exe not found - run: cargo build --release -p argusd
)

if exist "%TARGET%\sentinella-dnsreconcile.exe" (
    copy /Y "%TARGET%\sentinella-dnsreconcile.exe" "%STAGE%\" >nul
    echo        sentinella-dnsreconcile.exe OK
) else (
    echo        [WARN] sentinella-dnsreconcile.exe not found - run: cargo build --release -p sentinella-dnsreconcile
)

:: ── ClamAV DLLs ──
echo  [2/8] ClamAV DLLs...
set "DLL_FOUND=0"
for %%D in (libclamav libclammspack libfreshclam) do (
    if exist "%BUILD%\%%D\Release\%%D.dll" (
        copy /Y "%BUILD%\%%D\Release\%%D.dll" "%STAGE%\" >nul
        set /a DLL_FOUND+=1
    ) else if exist "%TARGET%\%%D.dll" (
        copy /Y "%TARGET%\%%D.dll" "%STAGE%\" >nul
        set /a DLL_FOUND+=1
    )
)
echo        %DLL_FOUND% DLL(s) copied

:: ClamAV transitive runtime dependencies.
:: libclamav.dll/freshclam.exe will not load without these beside them.
set "CLAMAV_RUNTIME=%BUILD%\clamscan\Release"
if not exist "%CLAMAV_RUNTIME%\zlib1.dll" set "CLAMAV_RUNTIME=%BUILD%\freshclam\Release"
for %%D in (
    zlib1.dll
    bz2.dll
    iconv-2.dll
    json-c.dll
    libcrypto-3-x64.dll
    libcurl.dll
    libssl-3-x64.dll
    libxml2.dll
    pcre2-8.dll
    pthreadVC3.dll
) do (
    if exist "%CLAMAV_RUNTIME%\%%D" (
        copy /Y "%CLAMAV_RUNTIME%\%%D" "%STAGE%\" >nul
        echo        %%D OK
    ) else (
        echo        [WARN] %%D not found
    )
)

:: freshclam.exe
if exist "%BUILD%\freshclam\Release\freshclam.exe" (
    copy /Y "%BUILD%\freshclam\Release\freshclam.exe" "%STAGE%\" >nul
    echo        freshclam.exe OK
) else if exist "%TARGET%\freshclam.exe" (
    copy /Y "%TARGET%\freshclam.exe" "%STAGE%\" >nul
    echo        freshclam.exe OK
) else (
    echo        [WARN] freshclam.exe not found
)

:: ── Certs ──
echo  [3/8] TLS certificates...
if exist "%ROOT%\third_party\clamav\certs" (
    xcopy /E /I /Q "%ROOT%\third_party\clamav\certs" "%STAGE%\certs" >nul 2>&1
    echo        certs/ OK
) else (
    echo        [WARN] certs not found
)

:: ── ARGUS intelligence packs ──
echo  [4/8] ARGUS intelligence packs...
xcopy /E /I /Q "%ROOT%\runtime\argus\rules\yara" "%STAGE%\runtime\argus\rules\yara" >nul 2>&1
copy /Y "%ROOT%\runtime\argus\manifests\pack_manifest.json" "%STAGE%\runtime\argus\manifests\" >nul 2>&1
copy /Y "%ROOT%\runtime\rules\ioc_hashes.txt" "%STAGE%\runtime\rules\" >nul 2>&1
echo        YARA rules + IOC hashes + manifest OK

:: Bootstrap ClamAV signatures
echo  [5/9] Bootstrap signatures...
set "SIG_SOURCE=%ROOT%\runtime\signatures"
REM .cvd OR .cld. freshclam ships .cvd but applies incremental updates as
REM .cld, so on any machine that has ever run an update, daily is daily.cld --
REM and this only ever looked for .cvd. That is why the shipped bundle carries
REM main.cvd and bytecode.cvd and NO daily at all: the one database that
REM actually changes every day was silently skipped on every release.
if not exist "%SIG_SOURCE%\main.cvd" if not exist "%SIG_SOURCE%\main.cld" set "SIG_SOURCE=C:\ProgramData\Sentinella\signatures"
set "SIG_HAVE_MAIN="
if exist "%SIG_SOURCE%\main.cvd" set "SIG_HAVE_MAIN=1"
if exist "%SIG_SOURCE%\main.cld" set "SIG_HAVE_MAIN=1"
if defined SIG_HAVE_MAIN (
    for %%D in (main daily bytecode) do (
        if exist "%SIG_SOURCE%\%%D.cvd" (
            copy /Y "%SIG_SOURCE%\%%D.cvd" "%STAGE%\runtime\signatures_bootstrap\" >nul
        ) else (
            if exist "%SIG_SOURCE%\%%D.cld" copy /Y "%SIG_SOURCE%\%%D.cld" "%STAGE%\runtime\signatures_bootstrap\" >nul
        )
    )
    if exist "%SIG_SOURCE%\*.sign" copy /Y "%SIG_SOURCE%\*.sign" "%STAGE%\runtime\signatures_bootstrap\" >nul
    REM freshclam.dat is deliberately NOT staged: nsis-hooks.nsh already
    REM refuses to install it (it is THIS build machine's mirror state, and
    REM handing it to another machine misreports what that machine has), so
    REM bundling it only inflated the installer.
    echo        main/daily/bytecode OK
) else (
    echo        [WARN] Bootstrap signatures not found
)

:: ── Bundled DNS blocklist (web-protection starter) ──
:: Required content, not optional: the installer seeds it into
:: ProgramData and the sanity script demands it in the bundle, so a
:: missing source here is a broken release, not a warning.
echo  [5b/9] DNS blocklist...
if exist "%ROOT%\runtime\rules\dns\stevenblack.hosts" (
    copy /Y "%ROOT%\runtime\rules\dns\stevenblack.hosts" "%STAGE%\runtime\rules\dns\" >nul
    echo        stevenblack.hosts OK
) else (
    echo        [FAIL] runtime\rules\dns\stevenblack.hosts not found — web-protection starter list is required content
    echo.
    echo  Staging FAILED: bundled DNS blocklist missing.
    exit /b 1
)

:: ── Config templates ──
echo  [6/9] Config templates...
if exist "%ROOT%\installer\windows\freshclam.conf.template" (
    copy /Y "%ROOT%\installer\windows\freshclam.conf.template" "%STAGE%\runtime\config\freshclam.conf" >nul
) else (
    echo DatabaseDirectory C:\ProgramData\Sentinella\signatures > "%STAGE%\runtime\config\freshclam.conf"
    echo UpdateLogFile C:\ProgramData\Sentinella\logs\freshclam.log >> "%STAGE%\runtime\config\freshclam.conf"
)
:: Generate a default sentinelld.toml if not present.
if not exist "%STAGE%\runtime\config\sentinelld.toml" (
    echo # Sentinella daemon configuration > "%STAGE%\runtime\config\sentinelld.toml"
    echo # Generated by packaging script >> "%STAGE%\runtime\config\sentinelld.toml"
)
echo        Config templates OK

:: ── Icons / assets ──
echo  [7/9] Assets...
if exist "%ROOT%\gui\src-tauri\icons\icon.ico" (
    copy /Y "%ROOT%\gui\src-tauri\icons\icon.ico" "%STAGE%\sentinella.ico" >nul
    echo        icon OK
)

:: ── Legal ──
echo  [8/9] Legal files...
if exist "%ROOT%\LICENSE" copy /Y "%ROOT%\LICENSE" "%STAGE%\" >nul
if exist "%ROOT%\NOTICE" copy /Y "%ROOT%\NOTICE" "%STAGE%\" >nul
if exist "%ROOT%\NOTICE.md" copy /Y "%ROOT%\NOTICE.md" "%STAGE%\" >nul
echo        LICENSE/NOTICE OK

:: ── Scripts ──
echo  [9/9] Scripts...
copy /Y "%ROOT%\scripts\install-service-windows.bat" "%STAGE%\scripts\" >nul 2>&1
copy /Y "%ROOT%\scripts\uninstall-service-windows.bat" "%STAGE%\scripts\" >nul 2>&1
copy /Y "%ROOT%\scripts\install-shell-menu.bat" "%STAGE%\scripts\" >nul 2>&1
echo        Service/shell scripts OK

echo.
echo  ==========================================
echo   Staging complete: %STAGE%
echo  ==========================================
echo.
dir "%STAGE%" /b
echo.
if "%1"=="" pause
