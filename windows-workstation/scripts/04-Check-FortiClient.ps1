<#
.SYNOPSIS
    Detects FortiClient (Windows) and evaluates it against CVE-2025-54660
    (Fortinet PSIRT advisory FG-IR-25-844).

.DESCRIPTION
    CVE-2025-54660 - "Information disclosure through debug features":
    active debug code (CWE-489) in FortiClientWindows lets a LOCAL attacker
    run the application step-by-step under a debugger and recover the saved
    VPN user password.

    Affected / fixed versions per FG-IR-25-844
    (https://fortiguard.fortinet.com/psirt/FG-IR-25-844):

      7.4 branch : 7.4.0 - 7.4.3 vulnerable -> upgrade to 7.4.4 or above
      7.2 branch : 7.2.0 - 7.2.10 vulnerable -> upgrade to 7.2.11 or above
      7.0 branch : ALL versions vulnerable   -> migrate to a fixed release

    There is no registry/config patch for this - the fix is a version
    upgrade:
      - Free "FortiClient VPN" edition: use -AttemptWingetUpgrade, or download
        the latest installer from https://www.fortinet.com/support/product-downloads
      - EMS-managed / licensed FortiClient: push the upgrade from FortiClient
        EMS (deployment package) or install the full installer from the
        Fortinet support portal. This script cannot do that silently.

    Interim mitigations until upgraded:
      - Untick "Save Password" in the VPN profile (removes the secret this
        bug leaks) and clear any currently saved password.
      - Do not enable FortiClient debug logging.
      - Note the attacker must already have local access to the machine.

.PARAMETER ReportOnly
    Detection/report only. (This script never modifies FortiClient
    configuration; the only action it can take is the optional winget
    upgrade below.)

.PARAMETER AttemptWingetUpgrade
    Try 'winget upgrade Fortinet.FortiClientVPN' - applies to the free
    VPN-only edition, NOT to EMS-managed installs.

.EXAMPLE
    .\04-Check-FortiClient.ps1
.EXAMPLE
    .\04-Check-FortiClient.ps1 -AttemptWingetUpgrade
#>
[CmdletBinding()]
param(
    [switch]$ReportOnly,
    [switch]$AttemptWingetUpgrade
)

$ErrorActionPreference = 'Stop'

Write-Host ''
Write-Host '=== FortiClient CVE-2025-54660 (FG-IR-25-844) version check ===' -ForegroundColor Cyan

$uninstallRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$installs = @(Get-ItemProperty -Path $uninstallRoots -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like 'FortiClient*' } |
    Select-Object DisplayName, DisplayVersion)

$exePath = Join-Path $env:ProgramFiles 'Fortinet\FortiClient\FortiClient.exe'
$exeVersion = $null
if (Test-Path $exePath) {
    $exeVersion = (Get-Item $exePath).VersionInfo.ProductVersion
}

if ($installs.Count -eq 0 -and -not $exeVersion) {
    Write-Host '[OK] FortiClient is not installed on this machine - nothing to do.' -ForegroundColor Green
    Write-Host '     (If Rapid7 still reports it, the finding is from an older scan - re-scan the asset.)'
    return
}

$versionStrings = @()
foreach ($i in $installs) {
    Write-Host ("Found installed product: {0}  version {1}" -f $i.DisplayName, $i.DisplayVersion)
    if ($i.DisplayVersion) { $versionStrings += $i.DisplayVersion }
}
if ($exeVersion) {
    Write-Host ("FortiClient.exe product version: {0}" -f $exeVersion)
    $versionStrings += $exeVersion
}

$parsed = $null
foreach ($vs in $versionStrings) {
    try {
        $candidate = [version](($vs -split '\s')[0])
        if ($null -eq $parsed -or $candidate -gt $parsed) { $parsed = $candidate }
    } catch { }
}
if ($null -eq $parsed) {
    Write-Host '[WARN] Could not parse the FortiClient version - compare it manually against FG-IR-25-844.' -ForegroundColor Yellow
    return
}

$branch = ('{0}.{1}' -f $parsed.Major, $parsed.Minor)
$verdictVulnerable = $false
$advice = ''
switch ($branch) {
    '7.4' {
        if ($parsed -lt [version]'7.4.4') { $verdictVulnerable = $true; $advice = 'Upgrade to FortiClient 7.4.4 or above.' }
    }
    '7.2' {
        if ($parsed -lt [version]'7.2.11') { $verdictVulnerable = $true; $advice = 'Upgrade to FortiClient 7.2.11 or above.' }
    }
    '7.0' {
        $verdictVulnerable = $true; $advice = 'ALL 7.0 versions are vulnerable - migrate to 7.2.11+ or 7.4.4+.'
    }
    default {
        if ($parsed -lt [version]'7.0') {
            $verdictVulnerable = $true; $advice = 'End-of-life version - migrate to 7.2.11+ or 7.4.4+.'
        }
    }
}

if (-not $verdictVulnerable) {
    Write-Host ("[OK] Installed version {0} is not in the affected range of FG-IR-25-844." -f $parsed) -ForegroundColor Green
    return
}

Write-Host ("[VULNERABLE] FortiClient {0} is affected by CVE-2025-54660." -f $parsed) -ForegroundColor Red
Write-Host ("  FIX: {0}" -f $advice) -ForegroundColor Yellow
Write-Host '  - Free VPN edition: re-run this script with -AttemptWingetUpgrade, or download the latest installer:'
Write-Host '      https://www.fortinet.com/support/product-downloads'
Write-Host '  - EMS-managed install: push the upgrade from FortiClient EMS or use the full installer from the Fortinet support portal.'
Write-Host '  - Interim mitigation: untick "Save Password" in VPN profiles and do not enable debug logging.'

if ($AttemptWingetUpgrade -and -not $ReportOnly) {
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($null -eq $winget) {
        Write-Host '[WARN] winget is not available on this machine - upgrade manually.' -ForegroundColor Yellow
    } else {
        Write-Host 'Attempting: winget upgrade Fortinet.FortiClientVPN ...'
        & winget upgrade --id Fortinet.FortiClientVPN --exact --silent --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -eq 0) {
            Write-Host '[OK] winget upgrade finished - re-run this script to verify the new version.' -ForegroundColor Green
        } else {
            Write-Host ("[WARN] winget exited with code {0}. The installed product may not be the free VPN edition; EMS-managed installs must be upgraded via EMS or the full installer." -f $LASTEXITCODE) -ForegroundColor Yellow
        }
    }
}
