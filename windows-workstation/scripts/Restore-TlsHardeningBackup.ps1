<#
.SYNOPSIS
    Rolls back the changes made by 03-Harden-TLS.ps1 using its backup folder.

.DESCRIPTION
    03-Harden-TLS.ps1 writes .reg backups plus a manifest.json into its backup
    directory BEFORE changing anything. This script restores that state:

      1. Deletes the current SCHANNEL key and imports the backed-up copy
         (a delete-then-import is required so values the hardening ADDED are
         actually removed - a plain import only merges).
      2. Restores the previous cipher-suite order policy, or removes the
         policy key entirely if it did not exist before hardening.

    REBOOT afterwards for the restored state to take effect.

.PARAMETER BackupDirectory
    The backup folder created by 03-Harden-TLS.ps1. When run via the master
    script this is <run folder>\tls-backup, e.g.
    C:\ProgramData\Rapid7Remediation\20260714-101500\tls-backup

.PARAMETER Force
    Skip the interactive confirmation.

.EXAMPLE
    .\Restore-TlsHardeningBackup.ps1 -BackupDirectory 'C:\ProgramData\Rapid7Remediation\20260714-101500\tls-backup'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BackupDirectory,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-RegExe {
    param([string[]]$ArgumentList)
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $null = & reg.exe @ArgumentList 2>&1
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEap
    }
}

if (-not (Test-IsAdministrator)) {
    throw 'Administrator rights are required. Re-run from an elevated PowerShell.'
}

$manifestPath = Join-Path $BackupDirectory 'manifest.json'
if (-not (Test-Path $manifestPath)) {
    throw "No manifest.json found in '$BackupDirectory' - is this really a 03-Harden-TLS.ps1 backup folder?"
}
$manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json

$schannelBackup = Join-Path $BackupDirectory $manifest.SchannelBackupFile
if (-not (Test-Path $schannelBackup) -or (Get-Item $schannelBackup).Length -eq 0) {
    throw "SCHANNEL backup file missing or empty: $schannelBackup"
}

Write-Host ("About to restore SCHANNEL state of '{0}' from: {1}" -f $manifest.Computer, $schannelBackup)
Write-Host ("Backup taken (UTC): {0}" -f $manifest.CreatedUtc)
if (-not $Force) {
    $answer = Read-Host 'Type YES to continue'
    if ($answer -ne 'YES') { Write-Host 'Aborted - nothing changed.'; return }
}

$exit = Invoke-RegExe -ArgumentList @('delete', $manifest.SchannelKey, '/f')
if ($exit -ne 0) {
    throw 'Failed to delete the current SCHANNEL key - nothing was changed.'
}
$exit = Invoke-RegExe -ArgumentList @('import', $schannelBackup)
if ($exit -ne 0) {
    Write-Host '[CRITICAL] The SCHANNEL key was deleted but the import FAILED.' -ForegroundColor Red
    Write-Host ("Run this immediately from an elevated prompt:  reg import `"{0}`"" -f $schannelBackup) -ForegroundColor Red
    throw 'reg import failed'
}
Write-Host '[OK] SCHANNEL key restored from backup.' -ForegroundColor Green

if ($manifest.CipherSuitePolicyExisted) {
    $policyBackup = Join-Path $BackupDirectory $manifest.CipherSuitePolicyBackupFile
    $exit = Invoke-RegExe -ArgumentList @('import', $policyBackup)
    if ($exit -ne 0) { throw "Failed to import '$policyBackup'." }
    Write-Host '[OK] Previous cipher-suite order policy restored.' -ForegroundColor Green
} else {
    $policyPsPath = 'HKLM:\' + ($manifest.CipherSuitePolicyKey -replace '^HKLM\\', '')
    if (Test-Path $policyPsPath) {
        $exit = Invoke-RegExe -ArgumentList @('delete', $manifest.CipherSuitePolicyKey, '/f')
        if ($exit -ne 0) { throw 'Failed to remove the cipher-suite order policy key.' }
        Write-Host '[OK] Cipher-suite order policy removed (it did not exist before hardening).' -ForegroundColor Green
    } else {
        Write-Host '[OK] No cipher-suite order policy present - nothing to remove.'
    }
}

Write-Host 'Rollback complete. REBOOT the machine for the restored configuration to take effect.' -ForegroundColor Green
