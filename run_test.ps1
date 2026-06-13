# run_test.ps1 — standalone end-to-end test (starts its own argus_agent)
#
# Usage: run as Administrator from the repo root after building.
# Writes agent and target output to build\bin\*_output2.txt for inspection.

$ErrorActionPreference = 'Stop'

# ── Locate build output directory ────────────────────────────────────────────
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$candidates  = @(
    "$projectRoot\build\bin",
    "$projectRoot\build\bin\Debug",
    "$projectRoot\build\bin\Release",
    "$projectRoot\build\bin\RelWithDebInfo"
)
$bindir = $candidates | Where-Object { Test-Path (Join-Path $_ "argus_agent.exe") } | Select-Object -First 1

if (-not $bindir) {
    Write-Error "Cannot find argus_agent.exe. Build the project first (cmake --build build)."
    exit 1
}
Write-Host "Using binaries from: $bindir"

$agentLog  = "$bindir\agent_output2.txt"
$targetLog = "$bindir\target_output2.txt"
Remove-Item $agentLog  -ErrorAction SilentlyContinue
Remove-Item $targetLog -ErrorAction SilentlyContinue

# ── Start argus_agent ─────────────────────────────────────────────────────────
$agentProc = Start-Process -FilePath "$bindir\argus_agent.exe" `
    -PassThru -NoNewWindow `
    -RedirectStandardOutput $agentLog `
    -WorkingDirectory $bindir
Write-Host "argus_agent started — PID $($agentProc.Id)"
Start-Sleep 3

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

# ── Trigger Trinity sequence ──────────────────────────────────────────────────
$targetProc.StandardInput.WriteLine("")   # proceed past first pause
Start-Sleep 5

$targetProc.StandardInput.WriteLine("")   # exit test_target
Start-Sleep 2

# ── Collect output ────────────────────────────────────────────────────────────
$targetOut = $targetProc.StandardOutput.ReadToEnd()
$targetOut | Out-File $targetLog -Encoding utf8

$agentProc | Stop-Process -Force

Write-Host ""
Write-Host "Done. Output files:"
Write-Host "  Agent  : $agentLog"
Write-Host "  Target : $targetLog"
