# run_demo.ps1 — standalone demo runner (requires argus_agent already running via dashboard)
#
# Usage: run as Administrator from the repo root, or double-click after building.
# The dashboard (start_dashboard.bat) must be running first so argus_agent is active.

$ErrorActionPreference = 'Stop'

# ── Locate build output directory ────────────────────────────────────────────
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$candidates  = @(
    "$projectRoot\build\bin",
    "$projectRoot\build\bin\Debug",
    "$projectRoot\build\bin\Release",
    "$projectRoot\build\bin\RelWithDebInfo"
)
$bindir = $candidates | Where-Object { Test-Path (Join-Path $_ "test_target.exe") } | Select-Object -First 1

if (-not $bindir) {
    Write-Error "Cannot find test_target.exe. Build the project first (cmake --build build)."
    exit 1
}
Write-Host "Using binaries from: $bindir"

# ── Start test_target with redirected stdin ───────────────────────────────────
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName         = "$bindir\test_target.exe"
$psi.WorkingDirectory = $bindir
$psi.UseShellExecute  = $false
$psi.RedirectStandardInput  = $true
$psi.RedirectStandardOutput = $true
$targetProc = [System.Diagnostics.Process]::Start($psi)
$targetPid  = $targetProc.Id
Write-Host "test_target started — PID $targetPid"

Start-Sleep 2

# ── Inject hook DLL ───────────────────────────────────────────────────────────
$injResult = & "$bindir\injector.exe" $targetPid "$bindir\argus_hook.dll"
Write-Host "Injector: $injResult"

Start-Sleep 2

# ── Trigger Trinity sequence (ALLOC → WRITE → PROTECT → YARA detect) ─────────
$targetProc.StandardInput.WriteLine("")   # step 1: proceed past first pause
Start-Sleep 5
$targetProc.StandardInput.WriteLine("")   # step 2: exit test_target

Start-Sleep 2
Write-Host "Demo complete. PID was $targetPid"
