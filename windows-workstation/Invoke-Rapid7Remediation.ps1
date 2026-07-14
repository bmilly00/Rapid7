<#
.SYNOPSIS
    One-command remediation for this Rapid7 InsightVM finding batch on a
    Windows workstation. Run from an elevated PowerShell.

.DESCRIPTION
    Runs the individual remediation scripts in .\scripts\ in a sensible
    order, logs everything to %ProgramData%\Rapid7Remediation\<timestamp>\,
    and keeps registry backups for rollback.

    Finding -> step mapping:
      CVE-2013-3900 (MS13-098 WinVerifyTrust)          -> 01-Fix-CVE-2013-3900.ps1
      TLS/SSL weak MAC / static key / 3DES / no strong -> 03-Harden-TLS.ps1
      FortiClient CVE-2025-54660 (FG-IR-25-844)        -> 04-Check-FortiClient.ps1
      (optional defense-in-depth hardening)            -> 05-Optional-Mitigations.ps1
      ALL CVE-2026-* Windows findings (15 CVEs)        -> 02-Install-WindowsUpdates.ps1
                                                          (runs LAST - it is the slow one)

    Each script is also usable standalone; run any of them with -ReportOnly
    to audit without changing anything.

.PARAMETER ReportOnly
    Audit-only run of every step: shows what is missing/non-compliant and
    what would be changed. Does not require admin. Makes NO changes.

.PARAMETER IncludeOptionalMitigations
    Also run 05-Optional-Mitigations.ps1 (Remote Assistance off, SMB1 off,
    SMB signing, NTLMv2-only, RDP NLA/TLS). Recommended, but read its help
    for possible side effects with very old NAS/printers first.

.PARAMETER IncludeCbcCompatSuites
    Passed to the TLS step: also allow ECDHE CBC SHA-2 suites (compatibility
    with older clients; still fixes all four TLS findings).

.PARAMETER DisableLegacyClientTls
    Passed to the TLS step: additionally disable TLS 1.0/1.1 for OUTBOUND
    (client) connections from this PC.

.PARAMETER AttemptFortiClientWingetUpgrade
    Passed to the FortiClient step: try 'winget upgrade Fortinet.FortiClientVPN'
    if a vulnerable version is found (free VPN edition only).

.PARAMETER SkipCertPaddingFix
.PARAMETER SkipTlsHardening
.PARAMETER SkipFortiClientCheck
.PARAMETER SkipWindowsUpdate
    Skip the corresponding step.

.PARAMETER AutoReboot
    Reboot automatically 60 seconds after the run completes (needed for the
    registry/TLS changes and installed updates to take effect). Without it,
    reboot manually afterwards.

.EXAMPLE
    .\Invoke-Rapid7Remediation.ps1 -ReportOnly
    # Audit first - see what would change.

.EXAMPLE
    .\Invoke-Rapid7Remediation.ps1
    # Fix everything (reboot manually afterwards).

.EXAMPLE
    .\Invoke-Rapid7Remediation.ps1 -IncludeOptionalMitigations -AttemptFortiClientWingetUpgrade -AutoReboot
    # The works, then reboot automatically.
#>
[CmdletBinding()]
param(
    [switch]$ReportOnly,
    [switch]$IncludeOptionalMitigations,
    [switch]$IncludeCbcCompatSuites,
    [switch]$DisableLegacyClientTls,
    [switch]$AttemptFortiClientWingetUpgrade,
    [switch]$SkipCertPaddingFix,
    [switch]$SkipTlsHardening,
    [switch]$SkipFortiClientCheck,
    [switch]$SkipWindowsUpdate,
    [switch]$AutoReboot
)

$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$scriptDir = Join-Path $PSScriptRoot 'scripts'
if (-not (Test-Path $scriptDir)) {
    throw "Cannot find the 'scripts' folder next to this script ($scriptDir). Copy the whole windows-workstation folder to the PC."
}

if (-not $ReportOnly -and -not (Test-IsAdministrator)) {
    throw 'Run this from an elevated PowerShell (Run as administrator), or use -ReportOnly to audit without changes.'
}

$workDir = $null
$transcriptStarted = $false
if (-not $ReportOnly) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $workDir = Join-Path $env:ProgramData "Rapid7Remediation\$stamp"
    New-Item -Path $workDir -ItemType Directory -Force | Out-Null
    Start-Transcript -Path (Join-Path $workDir 'remediation.log') | Out-Null
    $transcriptStarted = $true
}

try {
    Write-Host '==========================================================================='
    Write-Host ' Rapid7 finding remediation - Windows workstation batch (Jan/Feb 2026)'
    Write-Host ('  Mode        : ' + $(if ($ReportOnly) { 'REPORT-ONLY (no changes)' } else { 'APPLY' }))
    if ($workDir) { Write-Host ('  Log/backups : ' + $workDir) }
    Write-Host '==========================================================================='

    # Build the step list. Windows Update runs LAST (slowest step).
    $steps = @()
    if (-not $SkipCertPaddingFix) {
        $steps += [pscustomobject]@{
            Name   = 'CVE-2013-3900 WinVerifyTrust padding check'
            Script = '01-Fix-CVE-2013-3900.ps1'
            Params = @{ ReportOnly = [bool]$ReportOnly }
        }
    }
    if (-not $SkipTlsHardening) {
        $tlsParams = @{
            ReportOnly             = [bool]$ReportOnly
            IncludeCbcCompatSuites = [bool]$IncludeCbcCompatSuites
            DisableLegacyClientTls = [bool]$DisableLegacyClientTls
        }
        if ($workDir) { $tlsParams['BackupDirectory'] = (Join-Path $workDir 'tls-backup') }
        $steps += [pscustomobject]@{
            Name   = 'TLS/SSL cipher findings (SCHANNEL hardening)'
            Script = '03-Harden-TLS.ps1'
            Params = $tlsParams
        }
    }
    if (-not $SkipFortiClientCheck) {
        $steps += [pscustomobject]@{
            Name   = 'FortiClient CVE-2025-54660 version check'
            Script = '04-Check-FortiClient.ps1'
            Params = @{ ReportOnly = [bool]$ReportOnly; AttemptWingetUpgrade = [bool]$AttemptFortiClientWingetUpgrade }
        }
    }
    if ($IncludeOptionalMitigations) {
        $steps += [pscustomobject]@{
            Name   = 'Optional defense-in-depth mitigations'
            Script = '05-Optional-Mitigations.ps1'
            Params = @{ ReportOnly = [bool]$ReportOnly }
        }
    }
    if (-not $SkipWindowsUpdate) {
        $steps += [pscustomobject]@{
            Name   = 'Windows Update (all CVE-2026-* findings)'
            Script = '02-Install-WindowsUpdates.ps1'
            Params = @{ ReportOnly = [bool]$ReportOnly }
        }
    }

    if ($steps.Count -eq 0) {
        Write-Host 'Every step was skipped - nothing to do.' -ForegroundColor Yellow
        return
    }

    $results = @()
    $stepNumber = 0
    foreach ($step in $steps) {
        $stepNumber++
        Write-Host ''
        Write-Host ("### Step {0}/{1}: {2}" -f $stepNumber, $steps.Count, $step.Name) -ForegroundColor Magenta
        $scriptPath = Join-Path $scriptDir $step.Script
        try {
            $stepParams = $step.Params
            & $scriptPath @stepParams
            $results += [pscustomobject]@{ Step = $step.Name; Status = 'COMPLETED' }
        } catch {
            Write-Host ("[ERROR] {0}" -f $_.Exception.Message) -ForegroundColor Red
            $results += [pscustomobject]@{ Step = $step.Name; Status = ('FAILED: ' + $_.Exception.Message) }
        }
    }

    Write-Host ''
    Write-Host '=============================== SUMMARY ==================================='
    foreach ($r in $results) {
        $color = if ($r.Status -eq 'COMPLETED') { 'Green' } else { 'Red' }
        Write-Host (" {0,-48} {1}" -f $r.Step, $r.Status) -ForegroundColor $color
    }
    Write-Host '==========================================================================='
    if ($ReportOnly) {
        Write-Host 'Report-only run - nothing was changed.' -ForegroundColor Yellow
        Write-Host 'Next: re-run without -ReportOnly from an elevated PowerShell to remediate.'
    } else {
        Write-Host ("Log and registry backups: {0}" -f $workDir)
        Write-Host 'A REBOOT IS REQUIRED for the registry/TLS changes and installed updates to fully take effect.' -ForegroundColor Yellow
        Write-Host 'After the reboot: run  .\Invoke-Rapid7Remediation.ps1 -ReportOnly  to verify, then re-scan the asset in InsightVM.'
    }
} finally {
    if ($transcriptStarted) { Stop-Transcript | Out-Null }
}

if ($AutoReboot -and -not $ReportOnly) {
    Write-Host 'AutoReboot requested - restarting in 60 seconds (run "shutdown /a" to abort)...' -ForegroundColor Yellow
    shutdown.exe /r /t 60 /c "Rapid7 vulnerability remediation - reboot to apply changes"
}
