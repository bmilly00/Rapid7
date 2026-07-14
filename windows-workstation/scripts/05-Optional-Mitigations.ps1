<#
.SYNOPSIS
    Optional defense-in-depth hardening related to this Rapid7 finding batch.

.DESCRIPTION
    IMPORTANT: none of this replaces the Windows cumulative update
    (02-Install-WindowsUpdates.ps1) - the update is the actual fix for the
    CVE-2026-* findings. These settings reduce the attack surface those
    findings live in, and are sensible workstation hardening on their own:

      1. Disable Windows Remote Assistance solicitation
         (attack surface of CVE-2026-20824, Remote Assistance security
         feature bypass; most single-user PCs never use it).
      2. SMB hardening (attack surface of CVE-2026-20927 SMB Server DoS and
         CVE-2026-21249 NTLM spoofing):
           - Disable the SMBv1 protocol and remove the SMB1 optional feature.
           - Require SMB signing (server + client).
      3. NTLM hardening: LmCompatibilityLevel = 5
         (send NTLMv2 only, refuse LM & NTLM - relevant to NTLM spoofing).
      4. RDP hardening: require Network Level Authentication, force the TLS
         security layer, and high encryption (RDP/3389 is also the usual
         source of the TLS cipher findings on workstations).

    Possible side effects (all reversible by setting the values back):
      - SMB signing / NTLMv2-only can break VERY old NAS boxes, media players
        and printers that only speak SMB1/NTLMv1.
      - RDP NLA blocks RDP clients older than Windows XP SP3.

.PARAMETER ReportOnly
    Audit current state; change nothing.

.PARAMETER SkipRemoteAssistance
.PARAMETER SkipSmbHardening
.PARAMETER SkipNtlmHardening
.PARAMETER SkipRdpHardening
    Skip the corresponding section.

.EXAMPLE
    .\05-Optional-Mitigations.ps1 -ReportOnly
.EXAMPLE
    .\05-Optional-Mitigations.ps1 -SkipNtlmHardening
#>
[CmdletBinding()]
param(
    [switch]$ReportOnly,
    [switch]$SkipRemoteAssistance,
    [switch]$SkipSmbHardening,
    [switch]$SkipNtlmHardening,
    [switch]$SkipRdpHardening
)

$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Confirm-DwordValue {
    param([string]$Path, [string]$Name, [int]$Desired, [string]$Label)
    $current = $null
    try { $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { }
    if ($current -eq $Desired) {
        Write-Host ("[OK]    {0} ({1} = {2})" -f $Label, $Name, $Desired)
        return
    }
    $currentText = if ($null -eq $current) { 'not set' } else { "$current" }
    if ($script:ReportOnly) {
        Write-Host ("[WOULD] {0}: set {1} = {2} (currently {3})" -f $Label, $Name, $Desired, $currentText) -ForegroundColor Yellow
        return
    }
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Desired -Type DWord
    Write-Host ("[FIXED] {0}: {1} = {2} (was {3})" -f $Label, $Name, $Desired, $currentText) -ForegroundColor Green
}

Write-Host ''
Write-Host '=== Optional defense-in-depth mitigations ===' -ForegroundColor Cyan
Write-Host '(These supplement - do NOT replace - the Windows cumulative update.)'

if (-not $ReportOnly -and -not (Test-IsAdministrator)) {
    throw 'Administrator rights are required. Re-run from an elevated PowerShell, or use -ReportOnly.'
}

# 1 ---------------------------------------------------------------- Remote Assistance
if (-not $SkipRemoteAssistance) {
    Write-Host '--- Remote Assistance ---'
    Confirm-DwordValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' `
        -Name 'fAllowToGetHelp' -Desired 0 -Label 'Disable Remote Assistance solicitation'
}

# 2 ---------------------------------------------------------------- SMB
if (-not $SkipSmbHardening) {
    Write-Host '--- SMB hardening ---'
    try {
        $smbServer = Get-SmbServerConfiguration
        $smbClient = Get-SmbClientConfiguration

        if (-not $smbServer.EnableSMB1Protocol) {
            Write-Host '[OK]    SMB server: SMBv1 protocol disabled'
        } elseif ($ReportOnly) {
            Write-Host '[WOULD] SMB server: disable the SMBv1 protocol' -ForegroundColor Yellow
        } else {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
            Write-Host '[FIXED] SMB server: SMBv1 protocol disabled' -ForegroundColor Green
        }

        if ($smbServer.RequireSecuritySignature) {
            Write-Host '[OK]    SMB server: signing required'
        } elseif ($ReportOnly) {
            Write-Host '[WOULD] SMB server: require security signature (signing)' -ForegroundColor Yellow
        } else {
            Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
            Write-Host '[FIXED] SMB server: signing now required' -ForegroundColor Green
        }

        if ($smbClient.RequireSecuritySignature) {
            Write-Host '[OK]    SMB client: signing required'
        } elseif ($ReportOnly) {
            Write-Host '[WOULD] SMB client: require security signature (signing)' -ForegroundColor Yellow
        } else {
            Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
            Write-Host '[FIXED] SMB client: signing now required' -ForegroundColor Green
        }
    } catch {
        Write-Host ("[WARN] Could not query/set SMB configuration: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
    }

    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction Stop
        if ($feature.State -eq 'Enabled') {
            if ($ReportOnly) {
                Write-Host '[WOULD] Remove the SMB1Protocol optional feature' -ForegroundColor Yellow
            } else {
                Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart | Out-Null
                Write-Host '[FIXED] SMB1Protocol optional feature removed (finishes on next reboot)' -ForegroundColor Green
            }
        } else {
            Write-Host '[OK]    SMB1Protocol optional feature not enabled'
        }
    } catch {
        Write-Host '[INFO]  SMB1Protocol optional feature not present / not queryable (fine on recent Windows 11).'
    }
}

# 3 ---------------------------------------------------------------- NTLM
if (-not $SkipNtlmHardening) {
    Write-Host '--- NTLM hardening ---'
    Confirm-DwordValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'LmCompatibilityLevel' -Desired 5 -Label 'NTLMv2 only, refuse LM & NTLM'
}

# 4 ---------------------------------------------------------------- RDP
if (-not $SkipRdpHardening) {
    Write-Host '--- RDP hardening ---'
    $ts = $null
    try { $ts = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop).fDenyTSConnections } catch { }
    if ($ts -eq 1) {
        Write-Host '[INFO]  RDP inbound is disabled on this machine (fDenyTSConnections=1); applying hardening anyway in case it gets enabled later.'
    }
    $rdpKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    Confirm-DwordValue -Path $rdpKey -Name 'UserAuthentication' -Desired 1 -Label 'RDP: require Network Level Authentication'
    Confirm-DwordValue -Path $rdpKey -Name 'SecurityLayer'      -Desired 2 -Label 'RDP: force TLS security layer'
    Confirm-DwordValue -Path $rdpKey -Name 'MinEncryptionLevel' -Desired 3 -Label 'RDP: high encryption level'
}

Write-Host ''
if ($ReportOnly) {
    Write-Host '[REPORT-ONLY] No changes made.' -ForegroundColor Yellow
} else {
    Write-Host '[DONE] Optional mitigations applied. Reboot recommended (required for the SMB1 feature removal).' -ForegroundColor Green
    Write-Host '[NOTE] If an old NAS/printer stops working, the likely causes are SMB signing or NTLMv2-only - both are easy to revert (see README).' -ForegroundColor Yellow
}
