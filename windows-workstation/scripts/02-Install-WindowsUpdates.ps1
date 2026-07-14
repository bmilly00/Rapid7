<#
.SYNOPSIS
    Installs all missing Windows updates via the built-in Windows Update Agent
    (WUA) COM API. No external modules required.

.DESCRIPTION
    Remediates every Rapid7 finding in this batch that is fixed by a Windows
    cumulative update. The January 2026 and February 2026 cumulative updates
    (installing the LATEST cumulative update supersedes both) fix:

      CVE-2026-20819  Windows Virtualization-Based Security (VBS) info disclosure
      CVE-2026-20823  Windows File Explorer information disclosure
      CVE-2026-20824  Windows Remote Assistance security feature bypass
      CVE-2026-20825  Windows Hyper-V information disclosure
      CVE-2026-20827  TWINUI subsystem information disclosure
      CVE-2026-20828  Windows rndismp6.sys information disclosure
      CVE-2026-20829  TPM Trustlet information disclosure
      CVE-2026-20834  Windows spoofing
      CVE-2026-20835  Capability Access Management Service (camsvc) info disclosure
      CVE-2026-20839  Windows Client-Side Caching (CSC) info disclosure
      CVE-2026-20862  Windows Management Services information disclosure
      CVE-2026-20927  Windows SMB Server denial of service
      CVE-2026-20936  Windows NDIS information disclosure
      CVE-2026-20962  DRTM information disclosure
      CVE-2026-21249  Windows NTLM spoofing (February 2026)

    There is no configuration workaround that fully fixes these - the
    cumulative update IS the remediation. (05-Optional-Mitigations.ps1 offers
    defense-in-depth hardening on top, but is not a substitute.)

.PARAMETER ReportOnly
    List missing updates and pending-reboot state without installing anything.

.PARAMETER AutoReboot
    Reboot automatically (60-second warning) if an installed update requires it.

.EXAMPLE
    .\02-Install-WindowsUpdates.ps1 -ReportOnly
.EXAMPLE
    .\02-Install-WindowsUpdates.ps1
#>
[CmdletBinding()]
param(
    [switch]$ReportOnly,
    [switch]$AutoReboot
)

$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-PendingReboot {
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
}

Write-Host ''
Write-Host '=== Windows Update (fixes all CVE-2026-* findings in this batch) ===' -ForegroundColor Cyan

$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Write-Host ("OS: {0} {1} (build {2}.{3})" -f $cv.ProductName, $cv.DisplayVersion, $cv.CurrentBuild, $cv.UBR)

if (Test-PendingReboot) {
    Write-Host '[WARN] A reboot from a previous update is already pending on this machine.' -ForegroundColor Yellow
}

if (-not $ReportOnly) {
    if (-not (Test-IsAdministrator)) {
        throw 'Administrator rights are required to install updates. Re-run from an elevated PowerShell.'
    }
    $svc = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.StartType -eq 'Disabled') { Set-Service -Name wuauserv -StartupType Manual }
        if ($svc.Status -ne 'Running') { Start-Service -Name wuauserv }
    }
}

Write-Host 'Searching for missing updates (this can take several minutes)...'
$session = New-Object -ComObject 'Microsoft.Update.Session'
$searcher = $session.CreateUpdateSearcher()
$searchResult = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")

if ($searchResult.Updates.Count -eq 0) {
    Write-Host '[OK] No missing updates - Windows is fully patched.' -ForegroundColor Green
    Write-Host '     If Rapid7 still flags the CVE-2026-* findings, reboot (if pending) and re-scan the asset.'
    return
}

Write-Host ("Missing updates: {0}" -f $searchResult.Updates.Count) -ForegroundColor Yellow

$toInstall = New-Object -ComObject 'Microsoft.Update.UpdateColl'
$titles = @()
foreach ($update in $searchResult.Updates) {
    $kb = ''
    foreach ($k in $update.KBArticleIDs) { $kb += "KB$k " }
    if ($update.InstallationBehavior.CanRequestUserInput) {
        Write-Host ("  [SKIP]    {0}{1} (requires user input - install via Settings > Windows Update)" -f $kb, $update.Title) -ForegroundColor Yellow
        continue
    }
    Write-Host ("  [PENDING] {0}{1}" -f $kb, $update.Title)
    if (-not $update.EulaAccepted) { $update.AcceptEula() }
    [void]$toInstall.Add($update)
    $titles += $update.Title
}

if ($ReportOnly) {
    Write-Host '[REPORT-ONLY] Nothing installed. Re-run without -ReportOnly to install.' -ForegroundColor Yellow
    return
}

if ($toInstall.Count -eq 0) {
    Write-Host '[WARN] No updates can be installed without user interaction. Use Settings > Windows Update.' -ForegroundColor Yellow
    return
}

Write-Host 'Downloading updates...'
$downloader = $session.CreateUpdateDownloader()
$downloader.Updates = $toInstall
$dlResult = $downloader.Download()
if ($dlResult.ResultCode -ne 2) {
    Write-Host ("[WARN] Download finished with result code {0} (2 = success). Continuing with what downloaded." -f $dlResult.ResultCode) -ForegroundColor Yellow
}

Write-Host 'Installing updates (do NOT power off)...'
$installer = $session.CreateUpdateInstaller()
$installer.Updates = $toInstall
$installResult = $installer.Install()

$resultText = @{ 0 = 'NotStarted'; 1 = 'InProgress'; 2 = 'Succeeded'; 3 = 'SucceededWithErrors'; 4 = 'Failed'; 5 = 'Aborted' }
for ($i = 0; $i -lt $toInstall.Count; $i++) {
    $rc = [int]$installResult.GetUpdateResult($i).ResultCode
    $tag = if ($rc -eq 2) { '[OK]     ' } elseif ($rc -eq 3) { '[PARTIAL]' } else { '[FAIL]   ' }
    Write-Host ("  {0} {1} -> {2}" -f $tag, $titles[$i], $resultText[$rc])
}
Write-Host ("Overall install result: {0}" -f $resultText[[int]$installResult.ResultCode])

if ($installResult.RebootRequired) {
    if ($AutoReboot) {
        Write-Host 'Reboot required - restarting in 60 seconds (run "shutdown /a" to abort)...' -ForegroundColor Yellow
        shutdown.exe /r /t 60 /c "Windows Update - Rapid7 remediation reboot"
    } else {
        Write-Host '[ACTION REQUIRED] Reboot this machine to finish installing updates, then re-scan.' -ForegroundColor Yellow
    }
} else {
    Write-Host 'Installer did not request a reboot (one is still recommended before re-scanning).'
}
