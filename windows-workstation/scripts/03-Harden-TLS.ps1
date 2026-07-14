<#
.SYNOPSIS
    Hardens the Windows SCHANNEL (TLS/SSL) configuration, with registry backup.

.DESCRIPTION
    Remediates the following Rapid7 findings:
      - TLS/SSL Weak Message Authentication Code Cipher Suites
      - TLS/SSL Server Supports The Use of Static Key Ciphers
      - TLS/SSL Server Supports 3DES Cipher Suite (SWEET32)
      - TLS/SSL Server Does Not Support Any Strong Cipher Algorithms

    What it does (HKLM registry, machine-wide - affects every service that
    uses the Windows TLS stack, including Remote Desktop on TCP 3389):
      1. Backs up the current SCHANNEL key and any existing cipher-suite
         policy to .reg files (see Restore-TlsHardeningBackup.ps1).
      2. Disables SSL 2.0 / SSL 3.0 (client + server) and TLS 1.0 / TLS 1.1
         (server side; add -DisableLegacyClientTls for the client side too).
      3. Explicitly enables TLS 1.2 (and TLS 1.3 on builds that support it).
      4. Disables weak SCHANNEL ciphers: NULL, DES, RC2, RC4, Triple DES
         (3DES - the SWEET32 finding); explicitly enables AES 128/256.
      5. Disables the MD5 hash for SCHANNEL; enables SHA-256/384/512.
      6. Sets the cipher-suite order policy to forward-secret AEAD suites
         only (ECDHE + AES-GCM, plus TLS 1.3 suites). This removes static-RSA
         key exchange ("static key ciphers") and MD5/SHA-1-MAC suites from
         what the machine offers, and guarantees strong ciphers are offered.

    A REBOOT IS REQUIRED for SCHANNEL changes to take effect.

    NOTE: this fixes services that use the Windows TLS stack (RDP, IIS,
    WinRM-HTTPS, etc.). If the Rapid7 finding is against a port owned by
    software that ships its OWN TLS stack (OpenSSL-based apps, some agents),
    that application must be configured separately - check the port/service
    named in the finding's proof data in InsightVM.

.PARAMETER ReportOnly
    Audit current state; change nothing.

.PARAMETER DisableLegacyClientTls
    Also disable TLS 1.0/1.1 for *outbound* (client) connections. Leave off
    if this PC still needs to reach very old devices (printers, routers,
    IPMI/iLO boards, old NAS web pages, etc.).

.PARAMETER IncludeCbcCompatSuites
    Append ECDHE CBC SHA-256/384 suites to the allowed list for compatibility
    with older-but-not-ancient clients. These are still forward-secret with
    SHA-2 MACs, so they do not re-introduce any of the four findings.

.PARAMETER BackupDirectory
    Where to write registry backups.
    Default: %ProgramData%\Rapid7Remediation\tls-backup-<timestamp>

.EXAMPLE
    .\03-Harden-TLS.ps1 -ReportOnly
.EXAMPLE
    .\03-Harden-TLS.ps1
#>
[CmdletBinding()]
param(
    [switch]$ReportOnly,
    [switch]$DisableLegacyClientTls,
    [switch]$IncludeCbcCompatSuites,
    [string]$BackupDirectory
)

$ErrorActionPreference = 'Stop'

$SCHANNEL_KEY = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
$POLICY_KEY   = 'SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
$ENABLED_ALL  = [uint32]4294967295   # 0xFFFFFFFF - schannel convention for "enabled"

$strongSuites = @(
    'TLS_AES_256_GCM_SHA384',
    'TLS_AES_128_GCM_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
)
$cbcCompatSuites = @(
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'
)
$weakCiphers = @(
    'NULL', 'DES 56/56', 'RC2 40/128', 'RC2 56/128', 'RC2 128/128',
    'RC4 40/128', 'RC4 56/128', 'RC4 64/128', 'RC4 128/128', 'Triple DES 168'
)
$strongCiphers = @('AES 128/128', 'AES 256/256')

# Static-RSA key exchange, 3DES/RC4/DES/NULL, MD5 or SHA-1 MACs, PSK
$weakSuitePattern = '^TLS_RSA_|_3DES_|_RC4_|_DES_|_NULL_|_MD5$|_PSK_|_CBC_SHA$'

function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# .NET registry API is used because several SCHANNEL key names contain
# forward slashes (e.g. "RC4 128/128"), which the PowerShell registry
# provider cannot address reliably.
function Get-HklmValue {
    param([string]$SubKey, [string]$Name)
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKey)
    if ($null -eq $key) { return $null }
    try { return $key.GetValue($Name, $null) } finally { $key.Close() }
}

function Set-HklmDword {
    param([string]$SubKey, [string]$Name, [uint32]$Value)
    $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($SubKey)
    try {
        $intBits = [BitConverter]::ToInt32([BitConverter]::GetBytes($Value), 0)
        $key.SetValue($Name, $intBits, [Microsoft.Win32.RegistryValueKind]::DWord)
    } finally { $key.Close() }
}

function Set-HklmString {
    param([string]$SubKey, [string]$Name, [string]$Value)
    $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($SubKey)
    try { $key.SetValue($Name, $Value, [Microsoft.Win32.RegistryValueKind]::String) } finally { $key.Close() }
}

# reg.exe writes some success messages to stderr; under
# $ErrorActionPreference='Stop' + redirection that would throw in PS 5.1,
# so run it with EAP relaxed and return the exit code.
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

# ---------------------------------------------------------------- plan
$osBuild = 0
try { $osBuild = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild } catch { }

$protocolPlan = @()
foreach ($proto in @('SSL 2.0', 'SSL 3.0')) {
    foreach ($side in @('Client', 'Server')) {
        $protocolPlan += [pscustomobject]@{ Protocol = $proto; Side = $side; Enable = $false }
    }
}
foreach ($proto in @('TLS 1.0', 'TLS 1.1')) {
    $protocolPlan += [pscustomobject]@{ Protocol = $proto; Side = 'Server'; Enable = $false }
    if ($DisableLegacyClientTls) {
        $protocolPlan += [pscustomobject]@{ Protocol = $proto; Side = 'Client'; Enable = $false }
    }
}
$modernProtocols = @('TLS 1.2')
if ($osBuild -ge 20348) { $modernProtocols += 'TLS 1.3' }   # Windows 11 / Server 2022 and later
foreach ($proto in $modernProtocols) {
    foreach ($side in @('Client', 'Server')) {
        $protocolPlan += [pscustomobject]@{ Protocol = $proto; Side = $side; Enable = $true }
    }
}

$suiteList = @($strongSuites)
if ($IncludeCbcCompatSuites) { $suiteList += $cbcCompatSuites }
$functionsValue = $suiteList -join ','

Write-Host ''
Write-Host '=== TLS/SSL (SCHANNEL) hardening ===' -ForegroundColor Cyan

# ---------------------------------------------------------------- report
Write-Host '--- Current state ---'
foreach ($item in $protocolPlan) {
    $subKey  = "$SCHANNEL_KEY\Protocols\$($item.Protocol)\$($item.Side)"
    $enabled = Get-HklmValue -SubKey $subKey -Name 'Enabled'
    $curText = if ($null -eq $enabled) { 'OS default' } else { '0x{0:X}' -f [uint32]($enabled -band 0xFFFFFFFF) }
    if ($item.Enable) {
        $ok = ($null -eq $enabled) -or ($enabled -ne 0)
    } else {
        $ok = ($enabled -eq 0)
    }
    $want = if ($item.Enable) { 'enabled' } else { 'disabled' }
    if ($ok) {
        Write-Host ("[OK]   {0,-8} {1,-6} (want {2}; Enabled={3})" -f $item.Protocol, $item.Side, $want, $curText)
    } else {
        Write-Host ("[FIX]  {0,-8} {1,-6} (want {2}; Enabled={3})" -f $item.Protocol, $item.Side, $want, $curText) -ForegroundColor Yellow
    }
}
foreach ($cipher in $weakCiphers) {
    $enabled = Get-HklmValue -SubKey "$SCHANNEL_KEY\Ciphers\$cipher" -Name 'Enabled'
    if ($enabled -eq 0) {
        Write-Host ("[OK]   Cipher '{0}' explicitly disabled" -f $cipher)
    } else {
        Write-Host ("[FIX]  Cipher '{0}' not explicitly disabled" -f $cipher) -ForegroundColor Yellow
    }
}
$functionsCurrent = Get-HklmValue -SubKey $POLICY_KEY -Name 'Functions'
if ($functionsCurrent) {
    Write-Host ("Current cipher-suite order policy: {0}" -f $functionsCurrent)
} else {
    Write-Host 'No cipher-suite order policy set - the OS default suite list is in effect.'
}
try {
    $effective = @(Get-TlsCipherSuite | ForEach-Object { $_.Name })
    $weakNow   = @($effective | Where-Object { $_ -match $weakSuitePattern })
    $strongNow = @($effective | Where-Object { $_ -match '_GCM_|^TLS_AES_|^TLS_CHACHA20' })
    Write-Host ("Effective cipher suites right now: {0} total / {1} weak / {2} strong AEAD" -f $effective.Count, $weakNow.Count, $strongNow.Count)
    foreach ($w in $weakNow) { Write-Host ("  [WEAK] {0}" -f $w) -ForegroundColor Yellow }
} catch {
    Write-Host '(Get-TlsCipherSuite not available on this OS - skipped live suite listing.)'
}

if ($ReportOnly) {
    Write-Host '[REPORT-ONLY] No changes made. Re-run without -ReportOnly to apply hardening.' -ForegroundColor Yellow
    return
}

if (-not (Test-IsAdministrator)) {
    throw 'Administrator rights are required to apply TLS hardening. Re-run from an elevated PowerShell.'
}

# ---------------------------------------------------------------- backup
if (-not $BackupDirectory) {
    $BackupDirectory = Join-Path $env:ProgramData ('Rapid7Remediation\tls-backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
New-Item -Path $BackupDirectory -ItemType Directory -Force | Out-Null

$schannelBackup = Join-Path $BackupDirectory 'schannel-before.reg'
$exit = Invoke-RegExe -ArgumentList @('export', "HKLM\$SCHANNEL_KEY", $schannelBackup, '/y')
if ($exit -ne 0 -or -not (Test-Path $schannelBackup)) {
    throw "Failed to back up the SCHANNEL key to '$schannelBackup' - aborting BEFORE any change."
}

$policyExisted = Test-Path "HKLM:\$POLICY_KEY"
if ($policyExisted) {
    $policyBackup = Join-Path $BackupDirectory 'cipher-suite-policy-before.reg'
    $exit = Invoke-RegExe -ArgumentList @('export', "HKLM\$POLICY_KEY", $policyBackup, '/y')
    if ($exit -ne 0) { throw 'Failed to back up the existing cipher-suite policy - aborting BEFORE any change.' }
}

@{
    CreatedUtc                  = [DateTime]::UtcNow.ToString('o')
    Computer                    = $env:COMPUTERNAME
    SchannelKey                 = "HKLM\$SCHANNEL_KEY"
    SchannelBackupFile          = 'schannel-before.reg'
    CipherSuitePolicyKey        = "HKLM\$POLICY_KEY"
    CipherSuitePolicyExisted    = $policyExisted
    CipherSuitePolicyBackupFile = $(if ($policyExisted) { 'cipher-suite-policy-before.reg' } else { $null })
} | ConvertTo-Json | Set-Content -Path (Join-Path $BackupDirectory 'manifest.json') -Encoding ASCII
Write-Host ("[BACKUP] Registry backups written to: {0}" -f $BackupDirectory) -ForegroundColor Green

# ---------------------------------------------------------------- apply
Write-Host '--- Applying changes ---'
foreach ($item in $protocolPlan) {
    $subKey = "$SCHANNEL_KEY\Protocols\$($item.Protocol)\$($item.Side)"
    if ($item.Enable) {
        Set-HklmDword -SubKey $subKey -Name 'Enabled' -Value $ENABLED_ALL
        Set-HklmDword -SubKey $subKey -Name 'DisabledByDefault' -Value 0
    } else {
        Set-HklmDword -SubKey $subKey -Name 'Enabled' -Value 0
        Set-HklmDword -SubKey $subKey -Name 'DisabledByDefault' -Value 1
    }
    Write-Host ("[SET] Protocol {0,-8} {1,-6} -> {2}" -f $item.Protocol, $item.Side, $(if ($item.Enable) { 'ENABLED' } else { 'DISABLED' }))
}

foreach ($cipher in $weakCiphers) {
    Set-HklmDword -SubKey "$SCHANNEL_KEY\Ciphers\$cipher" -Name 'Enabled' -Value 0
    Write-Host ("[SET] Cipher '{0}' -> DISABLED" -f $cipher)
}
foreach ($cipher in $strongCiphers) {
    Set-HklmDword -SubKey "$SCHANNEL_KEY\Ciphers\$cipher" -Name 'Enabled' -Value $ENABLED_ALL
    Write-Host ("[SET] Cipher '{0}' -> ENABLED" -f $cipher)
}

Set-HklmDword -SubKey "$SCHANNEL_KEY\Hashes\MD5" -Name 'Enabled' -Value 0
Write-Host "[SET] Hash 'MD5' -> DISABLED"
foreach ($hash in @('SHA256', 'SHA384', 'SHA512')) {
    Set-HklmDword -SubKey "$SCHANNEL_KEY\Hashes\$hash" -Name 'Enabled' -Value $ENABLED_ALL
    Write-Host ("[SET] Hash '{0}' -> ENABLED" -f $hash)
}

Set-HklmDword -SubKey "$SCHANNEL_KEY\KeyExchangeAlgorithms\ECDH" -Name 'Enabled' -Value $ENABLED_ALL
Set-HklmDword -SubKey "$SCHANNEL_KEY\KeyExchangeAlgorithms\Diffie-Hellman" -Name 'Enabled' -Value $ENABLED_ALL
Set-HklmDword -SubKey "$SCHANNEL_KEY\KeyExchangeAlgorithms\Diffie-Hellman" -Name 'ServerMinKeyBitLength' -Value 2048
Set-HklmDword -SubKey "$SCHANNEL_KEY\KeyExchangeAlgorithms\Diffie-Hellman" -Name 'ClientMinKeyBitLength' -Value 2048
Write-Host '[SET] Key exchange: ECDH enabled; Diffie-Hellman minimum key length 2048'

Set-HklmString -SubKey $POLICY_KEY -Name 'Functions' -Value $functionsValue
Write-Host '[SET] Cipher-suite order policy (HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\Functions):'
foreach ($s in $suiteList) { Write-Host ("        {0}" -f $s) }

Write-Host ''
Write-Host '[DONE] SCHANNEL hardening applied. A REBOOT IS REQUIRED for it to take effect.' -ForegroundColor Green
Write-Host ("       Rollback: .\Restore-TlsHardeningBackup.ps1 -BackupDirectory `"{0}`"" -f $BackupDirectory)
Write-Host '[NOTE] Very old clients (Windows XP/Vista era, Java 6/7, anything without TLS 1.2 + ECDHE-GCM) will no longer be able to connect to TLS services on this machine.' -ForegroundColor Yellow
