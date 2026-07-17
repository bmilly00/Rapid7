<#
.SYNOPSIS
    Remediates 12 Rapid7 InsightVM findings on a Windows endpoint WITHOUT
    internet access, in a single ManageEngine Endpoint Central Custom Script
    deployment.

.DESCRIPTION
    Everything this script needs is delivered over the LAN by the Endpoint
    Central agent (script + dependency files). The endpoint never touches the
    internet.

    Findings covered and how each is fixed:

      TLS/SCHANNEL registry hardening (reboot required to take effect):
        - TLS Server Supports TLS version 1.0 .......... TLS 1.0 disabled (Client+Server)
        - TLS Server Supports TLS version 1.1 .......... TLS 1.1 disabled (Client+Server)
        - TLS/SSL Server is enabling the BEAST attack .. mitigated by disabling TLS 1.0
        - Birthday attacks / SWEET32 ................... 3DES cipher disabled + removed
        - TLS/SSL Server Supports 3DES Cipher Suite .... from the cipher-suite order
        - Weak Message Authentication Code suites ...... MD5 disabled; suite order keeps
                                                         only AEAD(GCM)/SHA-2 suites
        - Supports The Use of Static Key Ciphers ....... suite order removes TLS_RSA_*
                                                         (ECDHE/DHE forward secrecy only)
        - Does Not Support Any Strong Ciphers .......... AES-GCM suites enabled and
                                                         preferred; TLS 1.2 (and 1.3 on
                                                         supported builds) force-enabled
        (SSL 2.0/3.0 are disabled as well, and .NET Framework apps are pointed at
         the OS default TLS via SchUseStrongCrypto/SystemDefaultTlsVersions so
         they keep working once TLS 1.0/1.1 are gone.)

      Policy fixes (no payload needed):
        - CVE-2013-3900 / MS13-098 (WinVerifyTrust) .... EnableCertPaddingCheck="1" in
                                                         both the native and Wow6432Node
                                                         Wintrust\Config keys
        - CIFS Account Lockout Policy .................. local account lockout policy set
                                                         (threshold/window/duration); only
                                                         ever tightened, never loosened

      Application patches (installers must be staged as dependency files):
        - Microsoft ASP.NET: CVE-2026-45591 ............ installs the staged ASP.NET Core
                                                         Hosting Bundle / runtime for every
                                                         installed release channel that is
                                                         older than the staged build
        - 7-Zip: CVE-2026-58052 ........................ upgrades 7-Zip from a staged
                                                         7zXXXX[-x64].exe/.msi if older

    The staged installer versions ARE the compliance target for the two app
    CVEs: stage the fixed builds named in the vendor advisories and the script
    patches anything older. Nothing is ever downloaded.

    Integrity: Microsoft installers must carry a valid Microsoft Authenticode
    signature. Any payload file listed in an optional payload.sha256 file must
    match its pinned hash (mismatch = refuse to execute). Files with neither a
    pinned hash nor a valid signature (7-Zip installers are not Authenticode
    signed) run with a logged warning unless -StrictIntegrity is set.

    Before changing anything the script exports the affected registry keys and
    the current account policy to C:\ProgramData\Rapid7-Offline-Remediation\
    backup-<timestamp>\ so every change can be rolled back (reg import + reboot).

.PARAMETER AuditOnly
    Report only - no changes. Exit 0 = compliant, 2 = findings present.

.PARAMETER SkipTlsHardening
    Do not touch SCHANNEL protocols/ciphers/suite order or .NET crypto keys.

.PARAMETER SkipWinVerifyTrust
    Do not set the CVE-2013-3900 EnableCertPaddingCheck values.

.PARAMETER SkipLockoutPolicy
    Do not change the local account lockout policy.

.PARAMETER SkipAppPatches
    Do not install the staged ASP.NET Core / 7-Zip payloads.

.PARAMETER IncludeCbcFallback
    Append ECDHE AES-CBC HMAC-SHA2 suites after the GCM suites for clients that
    cannot negotiate GCM. Still forward-secret and SHA-2 (does not reintroduce
    the weak-MAC/static-key findings). Added automatically on pre-Windows-10
    builds where it is required for interoperability.

.PARAMETER NoIISReset
    Skip the automatic iisreset after a Hosting Bundle install. The patched
    runtime is then not active in IIS until IIS or the machine restarts.

.PARAMETER StrictIntegrity
    Refuse to execute any staged installer that has neither a matching entry in
    payload.sha256 nor a valid Authenticode signature.

.PARAMETER ForceReboot
    If TLS changes were applied successfully, restart the computer 5 minutes
    after the script finishes (shutdown /r). Default is to only report 3010 and
    let the Endpoint Central reboot policy handle it.

.PARAMETER PayloadPath
    Folder containing the staged installers and payload.sha256. Defaults to the
    script's own folder, which is where Endpoint Central places dependency files.

.PARAMETER LockoutThreshold
    Maximum failed logons before lockout (default 5). Existing stricter values
    are kept.

.PARAMETER LockoutWindowMinutes
    Failed-logon observation window in minutes (default 15).

.PARAMETER LockoutDurationMinutes
    Lockout duration in minutes (default 15; raised to the window if smaller).

.NOTES
    Requires: Windows PowerShell 3.0+, run elevated (Endpoint Central: System User).

    Exit codes:
        0    = compliant (nothing to do, or everything remediated with no reboot needed)
        3010 = remediated, RESTART REQUIRED (SCHANNEL changes only apply after reboot)
        2    = attention required (a finding could not be evaluated or fixed here:
               missing payload, EOL/legacy OS limitation, domain-GPO conflict, or
               -AuditOnly found non-compliant items)
        1    = fatal error (not admin, integrity refusal, installer failure)

    Endpoint Central "Custom Script" form -> "Specify the exit code(s)": 0,3010

    Logs:   C:\ProgramData\Rapid7-Offline-Remediation\remediation.log
    Backup: C:\ProgramData\Rapid7-Offline-Remediation\backup-<timestamp>\
#>

[CmdletBinding()]
param(
    [switch]$AuditOnly,
    [switch]$SkipTlsHardening,
    [switch]$SkipWinVerifyTrust,
    [switch]$SkipLockoutPolicy,
    [switch]$SkipAppPatches,
    [switch]$IncludeCbcFallback,
    [switch]$NoIISReset,
    [switch]$StrictIntegrity,
    [switch]$ForceReboot,
    [string]$PayloadPath = '',
    [ValidateRange(1, 999)]  [int]$LockoutThreshold = 5,
    [ValidateRange(1, 99999)][int]$LockoutWindowMinutes = 15,
    [ValidateRange(1, 99999)][int]$LockoutDurationMinutes = 15
)

# --- If launched from a 32-bit host on a 64-bit OS, relaunch in 64-bit PS ---
# (the Endpoint Central agent is 32-bit; a 32-bit process gets a redirected
# registry view and cannot see C:\Program Files\dotnet)
if ($env:PROCESSOR_ARCHITEW6432 -and -not $env:R7OFF_RELAUNCHED) {
    $env:R7OFF_RELAUNCHED = '1'
    $ps64    = Join-Path $env:WINDIR 'sysnative\WindowsPowerShell\v1.0\powershell.exe'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [System.Management.Automation.SwitchParameter]) {
            if ($kv.Value.IsPresent) { $argList += ('-' + $kv.Key) }
        } else {
            $argList += ('-' + $kv.Key)
            $argList += ('"{0}"' -f $kv.Value)
        }
    }
    $proc = Start-Process -FilePath $ps64 -ArgumentList $argList -Wait -PassThru -WindowStyle Hidden
    exit $proc.ExitCode
}

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = Split-Path -Parent $PSCommandPath }
if (-not $PayloadPath) { $PayloadPath = $ScriptDir }

$LogDir  = Join-Path $env:ProgramData 'Rapid7-Offline-Remediation'
$LogFile = Join-Path $LogDir 'remediation.log'
if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    # Write-Host (not Write-Output) so log lines never pollute function return
    # values; Endpoint Central still captures it as script output.
    Write-Host $line
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch { }
}

# --- 64-bit registry helpers -------------------------------------------------
# The .NET registry API is used instead of the HKLM: provider because several
# SCHANNEL cipher key names contain '/' (e.g. "RC4 128/128"), which the
# PowerShell provider would treat as a path separator, and because the
# Registry64 view is correct even if the 64-bit relaunch above was skipped.
$Registry64 = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)

function Test-RegKey {
    param([string]$SubKey)
    $k = $Registry64.OpenSubKey($SubKey)
    if ($k) { $k.Close(); return $true }
    return $false
}

function Get-RegValue {
    param([string]$SubKey, [string]$Name)
    $k = $Registry64.OpenSubKey($SubKey)
    if (-not $k) { return $null }
    try { return $k.GetValue($Name, $null) } finally { $k.Close() }
}

function Set-RegValue {
    # Returns $true when the value was actually created or changed.
    param([string]$SubKey, [string]$Name, $Value, [Microsoft.Win32.RegistryValueKind]$Kind = 'DWord')
    $k = $Registry64.CreateSubKey($SubKey)
    if (-not $k) { throw "Cannot open or create HKLM\$SubKey" }
    try {
        $existing = $k.GetValue($Name, $null)
        if (($null -ne $existing) -and ("$existing" -eq "$Value")) { return $false }
        $k.SetValue($Name, $Value, $Kind)
        Write-Log ('Registry: HKLM\{0} : {1} = {2} ({3})' -f $SubKey, $Name, $Value, $Kind)
        return $true
    } finally { $k.Close() }
}

# --- Shared state ------------------------------------------------------------
$script:Failures     = 0
$script:Attention    = 0
$script:RebootNeeded = $false
$script:OsBuild      = 0
$SchannelBase = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
$SuitePolicyKey = 'SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
$Is64Os = [Environment]::Is64BitOperatingSystem

# --- Payload integrity -------------------------------------------------------
function Get-Sha256 {
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs  = [System.IO.File]::OpenRead($Path)
    try { return (($sha.ComputeHash($fs)) | ForEach-Object { $_.ToString('x2') }) -join '' }
    finally { $fs.Close(); $sha.Dispose() }
}

$script:PayloadHashes = $null
function Get-PayloadHashes {
    if ($null -ne $script:PayloadHashes) { return $script:PayloadHashes }
    $script:PayloadHashes = @{}
    $hashFile = Join-Path $PayloadPath 'payload.sha256'
    if (Test-Path $hashFile) {
        foreach ($line in (Get-Content $hashFile)) {
            if ($line -match '^\s*([0-9A-Fa-f]{64})\s+\*?(.+?)\s*$') {
                $script:PayloadHashes[$Matches[2].ToLowerInvariant()] = $Matches[1].ToLowerInvariant()
            }
        }
        Write-Log ('payload.sha256 loaded: {0} pinned hash(es).' -f $script:PayloadHashes.Count)
    }
    return $script:PayloadHashes
}

function Test-MicrosoftSigned {
    param([string]$Path)
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path
        return (($sig.Status -eq 'Valid') -and
                ($sig.SignerCertificate.Subject -match 'O=Microsoft Corporation'))
    } catch { return $false }
}

function Test-PayloadTrusted {
    # Pinned hash beats everything; a hash mismatch is always fatal for the file.
    param([string]$Path)
    $leaf   = (Split-Path $Path -Leaf).ToLowerInvariant()
    $hashes = Get-PayloadHashes
    if ($hashes.ContainsKey($leaf)) {
        $actual = Get-Sha256 -Path $Path
        if ($actual -eq $hashes[$leaf]) {
            Write-Log ('Integrity OK (pinned SHA-256 matches): {0}' -f $leaf)
            return $true
        }
        Write-Log ('INTEGRITY FAILURE: {0} does not match its pinned SHA-256 - refusing to execute it.' -f $leaf) 'ERROR'
        return $false
    }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path
        if ($sig.Status -eq 'Valid') {
            Write-Log ('Integrity OK (valid Authenticode signature): {0}' -f $leaf)
            return $true
        }
    } catch { }
    if ($StrictIntegrity) {
        Write-Log ('{0}: no pinned hash and no valid Authenticode signature - refused (-StrictIntegrity).' -f $leaf) 'ERROR'
        return $false
    }
    Write-Log ('{0}: no pinned hash and no valid Authenticode signature. Executing anyway because it was deliberately staged - add it to payload.sha256 to close this gap.' -f $leaf) 'WARN'
    return $true
}

# --- TLS / SCHANNEL hardening ------------------------------------------------
function Get-TargetCipherSuites {
    # Windows 10/2016+ use unsuffixed suite names; older builds require _P256/_P384
    # curve suffixes on ECDHE suites and have no ECDHE_RSA+GCM at all.
    $suites = @()
    if ($script:OsBuild -ge 10240) {
        if ($script:OsBuild -ge 20348) {
            $suites += 'TLS_AES_256_GCM_SHA384', 'TLS_AES_128_GCM_SHA256'   # TLS 1.3
        }
        $suites += 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
                   'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                   'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                   'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
        if ($IncludeCbcFallback) {
            $suites += 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
                       'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
                       'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
                       'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'
        }
    }
    elseif ($script:OsBuild -ge 9200) {
        # Win8/2012/8.1/2012R2: GCM exists only for ECDHE_ECDSA and DHE_RSA, so the
        # suffixed ECDHE_RSA CBC-SHA2 suites are required for RSA certificates.
        $suites += 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384',
                   'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256',
                   'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
                   'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
                   'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384',
                   'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',
                   'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',
                   'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384',
                   'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384',
                   'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256'
    }
    else {
        # Win7/2008R2: SCHANNEL has no GCM. Best available: ECDHE + AES-CBC + SHA-2.
        # The "no strong cipher algorithms" finding cannot fully clear on this OS.
        $suites += 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384',
                   'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',
                   'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',
                   'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384',
                   'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384',
                   'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256'
    }
    return $suites
}

function Invoke-TlsHardening {
    Write-Log '--- TLS / SCHANNEL hardening ---'
    $changed = 0

    # 1. Protocols: kill SSL 2.0/3.0 + TLS 1.0/1.1, force-enable TLS 1.2 (both
    #    roles - the Client side matters so agents/apps on this box keep working).
    foreach ($proto in 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1') {
        foreach ($role in 'Client', 'Server') {
            $sub = '{0}\Protocols\{1}\{2}' -f $SchannelBase, $proto, $role
            if (Set-RegValue $sub 'Enabled' 0 'DWord')           { $changed++ }
            if (Set-RegValue $sub 'DisabledByDefault' 1 'DWord') { $changed++ }
        }
    }
    foreach ($role in 'Client', 'Server') {
        $sub = '{0}\Protocols\TLS 1.2\{1}' -f $SchannelBase, $role
        if (Set-RegValue $sub 'Enabled' 1 'DWord')           { $changed++ }
        if (Set-RegValue $sub 'DisabledByDefault' 0 'DWord') { $changed++ }
    }
    if ($script:OsBuild -ge 20348) {
        foreach ($role in 'Client', 'Server') {
            $sub = '{0}\Protocols\TLS 1.3\{1}' -f $SchannelBase, $role
            if (Set-RegValue $sub 'Enabled' 1 'DWord')           { $changed++ }
            if (Set-RegValue $sub 'DisabledByDefault' 0 'DWord') { $changed++ }
        }
    }

    # 2. Ciphers: 0 = disabled, 0xFFFFFFFF (-1) = enabled (SCHANNEL convention).
    foreach ($cipher in 'NULL', 'DES 56/56',
                        'RC2 40/128', 'RC2 56/128', 'RC2 128/128',
                        'RC4 40/128', 'RC4 56/128', 'RC4 64/128', 'RC4 128/128',
                        'Triple DES 168') {
        if (Set-RegValue ('{0}\Ciphers\{1}' -f $SchannelBase, $cipher) 'Enabled' 0 'DWord') { $changed++ }
    }
    foreach ($cipher in 'AES 128/128', 'AES 256/256') {
        if (Set-RegValue ('{0}\Ciphers\{1}' -f $SchannelBase, $cipher) 'Enabled' (-1) 'DWord') { $changed++ }
    }

    # 3. Hashes: disable MD5. SHA-1 ("SHA") is left alone - disabling it can break
    #    certificate chains; SHA-1 HMAC suites are excluded via the suite order.
    if (Set-RegValue ('{0}\Hashes\MD5' -f $SchannelBase) 'Enabled' 0 'DWord') { $changed++ }
    foreach ($hash in 'SHA256', 'SHA384', 'SHA512') {
        if (Set-RegValue ('{0}\Hashes\{1}' -f $SchannelBase, $hash) 'Enabled' (-1) 'DWord') { $changed++ }
    }

    # 4. Key exchange: forward secrecy stays available, weak DH groups do not.
    $dhKey = '{0}\KeyExchangeAlgorithms\Diffie-Hellman' -f $SchannelBase
    if (Set-RegValue $dhKey 'ServerMinKeyBitLength' 2048 'DWord') { $changed++ }
    if (Set-RegValue $dhKey 'ClientMinKeyBitLength' 2048 'DWord') { $changed++ }
    if (Set-RegValue ('{0}\KeyExchangeAlgorithms\ECDH' -f $SchannelBase) 'Enabled' (-1) 'DWord') { $changed++ }
    if (Set-RegValue ('{0}\KeyExchangeAlgorithms\PKCS' -f $SchannelBase) 'Enabled' (-1) 'DWord') { $changed++ }

    # 5. Cipher-suite order (the policy value SCHANNEL treats as authoritative).
    $target  = (Get-TargetCipherSuites) -join ','
    $current = Get-RegValue $SuitePolicyKey 'Functions'
    if ("$current" -ne $target) {
        Write-Log ('Cipher-suite order will be replaced. Old: {0}' -f $(if ($current) { $current } else { '(OS default)' }))
    }
    if (Set-RegValue $SuitePolicyKey 'Functions' $target 'String') { $changed++ }

    # 6. Legacy WinHTTP stacks (Win7/2008R2/Win8/2012) do not use TLS 1.2 unless
    #    told to; without this, killing TLS 1.0 breaks WinHTTP-based agents there.
    if ($script:OsBuild -lt 9600) {
        $winHttpKeys = @('SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp')
        if ($Is64Os) { $winHttpKeys += 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' }
        foreach ($k in $winHttpKeys) {
            if (Set-RegValue $k 'DefaultSecureProtocols' 0x800 'DWord') { $changed++ }
        }
        Write-Log 'Legacy OS: WinHTTP DefaultSecureProtocols pinned to TLS 1.2 (requires the TLS 1.2 update KB to be present).' 'WARN'
    }
    if ($script:OsBuild -lt 9200) {
        Write-Log 'This OS build has no AES-GCM in SCHANNEL - the "Does Not Support Any Strong Cipher Algorithms" finding needs an OS upgrade to fully clear.' 'WARN'
        $script:Attention++
    }

    # 7. .NET Framework apps: use OS-default TLS so they follow the new settings.
    $netKeys = @('SOFTWARE\Microsoft\.NETFramework\v4.0.30319')
    if ($Is64Os) { $netKeys += 'SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' }
    if (Test-RegKey 'SOFTWARE\Microsoft\.NETFramework\v2.0.50727') {
        $netKeys += 'SOFTWARE\Microsoft\.NETFramework\v2.0.50727'
        if ($Is64Os) { $netKeys += 'SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727' }
    }
    foreach ($k in $netKeys) {
        if (Set-RegValue $k 'SchUseStrongCrypto' 1 'DWord')       { $changed++ }
        if (Set-RegValue $k 'SystemDefaultTlsVersions' 1 'DWord') { $changed++ }
    }

    if ($changed -gt 0) {
        $script:RebootNeeded = $true
        Write-Log ('TLS hardening: {0} registry value(s) changed. A reboot is required before the new SCHANNEL settings are active.' -f $changed) 'WARN'
    } else {
        Write-Log 'TLS hardening: all values were already compliant.'
    }
}

# --- CVE-2013-3900 (WinVerifyTrust) ------------------------------------------
function Invoke-WinVerifyTrustFix {
    Write-Log '--- CVE-2013-3900 (WinVerifyTrust certificate padding check) ---'
    # REG_SZ "1" exactly as in Microsoft's advisory .reg snippet; both hives so
    # 32-bit and 64-bit processes verify strictly.
    $keys = @('SOFTWARE\Microsoft\Cryptography\Wintrust\Config')
    if ($Is64Os) { $keys += 'SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config' }
    $changed = 0
    foreach ($k in $keys) {
        if (Set-RegValue $k 'EnableCertPaddingCheck' '1' 'String') { $changed++ }
    }
    if ($changed -gt 0) {
        Write-Log ('CVE-2013-3900: EnableCertPaddingCheck set in {0} hive(s); strict Authenticode padding is enforced for new signature checks immediately.' -f $changed)
    } else {
        Write-Log 'CVE-2013-3900: EnableCertPaddingCheck already configured.'
    }
}

# --- CIFS account lockout policy ---------------------------------------------
function Get-LockoutPolicy {
    # secedit export is locale-independent, unlike parsing "net accounts" output.
    $cfg = Join-Path $env:TEMP ('r7-secpol-{0}.inf' -f $PID)
    if (Test-Path $cfg) { Remove-Item -Path $cfg -Force -ErrorAction SilentlyContinue }
    try {
        & (Join-Path $env:WINDIR 'System32\secedit.exe') /export /cfg $cfg /areas SECURITYPOLICY /quiet | Out-Null
    } catch { return $null }
    if (-not (Test-Path $cfg)) { return $null }
    $pol = @{ Threshold = 0; WindowMinutes = 0; DurationMinutes = 0 }
    foreach ($line in (Get-Content $cfg)) {
        if     ($line -match '^\s*LockoutBadCount\s*=\s*(-?\d+)')   { $pol.Threshold       = [int]$Matches[1] }
        elseif ($line -match '^\s*ResetLockoutCount\s*=\s*(-?\d+)') { $pol.WindowMinutes   = [int]$Matches[1] }
        elseif ($line -match '^\s*LockoutDuration\s*=\s*(-?\d+)')   { $pol.DurationMinutes = [int]$Matches[1] }
    }
    Remove-Item -Path $cfg -Force -ErrorAction SilentlyContinue
    return $pol
}

function Invoke-LockoutPolicy {
    Write-Log '--- CIFS account lockout policy ---'
    $desiredDur = [Math]::Max($LockoutDurationMinutes, $LockoutWindowMinutes)

    $partOfDomain = $false
    try { $partOfDomain = [bool](Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).PartOfDomain }
    catch {
        try { $partOfDomain = [bool](Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { }
    }
    if ($partOfDomain) {
        Write-Log 'Machine is domain-joined: domain GPO governs lockout for domain accounts; this sets the local SAM policy (what the Rapid7 CIFS check exercises against this host).' 'WARN'
    }

    $before = Get-LockoutPolicy
    if (-not $before) {
        Write-Log 'Could not read the current lockout policy via secedit.' 'ERROR'
        $script:Failures++
        return
    }
    Write-Log ('Current policy: threshold={0} window={1}min duration={2}min (0 threshold = lockout disabled, -1 duration = until admin unlocks)' -f `
        $before.Threshold, $before.WindowMinutes, $before.DurationMinutes)

    $needsChange = ($before.Threshold -eq 0) -or
                   ($before.Threshold -gt $LockoutThreshold) -or
                   ($before.WindowMinutes -lt $LockoutWindowMinutes) -or
                   (($before.DurationMinutes -ne -1) -and ($before.DurationMinutes -lt $desiredDur))
    if (-not $needsChange) {
        Write-Log 'Lockout policy already meets or exceeds the target - leaving it untouched.'
        return
    }

    # Tighten only: keep an existing stricter threshold, never shorten windows.
    $newThr = $LockoutThreshold
    if (($before.Threshold -gt 0) -and ($before.Threshold -lt $newThr)) { $newThr = $before.Threshold }
    $newWin = [Math]::Max($before.WindowMinutes, $LockoutWindowMinutes)
    $newDur = [Math]::Max($desiredDur, $newWin)
    if ($before.DurationMinutes -gt $newDur) { $newDur = $before.DurationMinutes }
    if ($before.DurationMinutes -eq -1) {
        Write-Log ('Existing duration is "until admin unlocks"; it will become {0} minutes because net accounts cannot preserve -1 while fixing the other values.' -f $newDur) 'WARN'
    }
    if ($newDur -gt 99999) { $newDur = 99999 }
    if ($newWin -gt $newDur) { $newWin = $newDur }

    & (Join-Path $env:WINDIR 'System32\net.exe') accounts `
        ('/lockoutthreshold:{0}' -f $newThr) `
        ('/lockoutwindow:{0}'    -f $newWin) `
        ('/lockoutduration:{0}'  -f $newDur) | ForEach-Object { if ($_) { Write-Log ('net accounts: {0}' -f $_) } }
    if ($LASTEXITCODE -ne 0) {
        Write-Log ('net accounts failed with exit code {0}.' -f $LASTEXITCODE) 'ERROR'
        $script:Failures++
        return
    }

    $after = Get-LockoutPolicy
    if ($after -and ($after.Threshold -gt 0) -and ($after.Threshold -le $LockoutThreshold)) {
        Write-Log ('Lockout policy set: threshold={0} window={1}min duration={2}min (effective immediately, no reboot needed).' -f `
            $after.Threshold, $after.WindowMinutes, $after.DurationMinutes)
    } else {
        Write-Log 'Lockout policy verification after "net accounts" did not show the expected values.' 'ERROR'
        $script:Failures++
    }
}

# --- ASP.NET Core (CVE-2026-45591) -------------------------------------------
function Get-DotnetRoots {
    $roots = @()
    if ($env:ProgramFiles)        { $roots += (Join-Path $env:ProgramFiles 'dotnet') }
    if (${env:ProgramFiles(x86)}) { $roots += (Join-Path ${env:ProgramFiles(x86)} 'dotnet') }
    foreach ($hive in 'HKLM:\SOFTWARE\dotnet\Setup\InstalledVersions',
                      'HKLM:\SOFTWARE\WOW6432Node\dotnet\Setup\InstalledVersions') {
        if (Test-Path $hive) {
            foreach ($archKey in (Get-ChildItem -Path $hive -ErrorAction SilentlyContinue)) {
                $loc = (Get-ItemProperty -Path $archKey.PSPath -ErrorAction SilentlyContinue).InstallLocation
                if ($loc) { $roots += $loc.TrimEnd('\') }
            }
        }
    }
    $roots | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
}

function Get-AspNetCoreRuntimes {
    $results = @()
    foreach ($root in (Get-DotnetRoots)) {
        $shared = Join-Path $root 'shared\Microsoft.AspNetCore.App'
        if (-not (Test-Path $shared)) { continue }
        foreach ($dir in (Get-ChildItem -Path $shared -Directory -ErrorAction SilentlyContinue)) {
            $raw  = $dir.Name
            $core = $raw.Split('-')[0]
            $ver  = $null
            try { $ver = [Version]$core } catch { }
            if ($ver) {
                $results += [pscustomobject]@{
                    Root    = $root
                    Raw     = $raw
                    Version = $ver
                    Channel = ('{0}.{1}' -f $ver.Major, $ver.Minor)
                }
            }
        }
    }
    $results
}

$script:StagedDotnetCache = $null
function Get-StagedDotnetInstallers {
    # Best staged installer per release channel; the Hosting Bundle is preferred
    # over the plain runtime at equal versions (it patches x64+x86+IIS module).
    if ($null -ne $script:StagedDotnetCache) { return $script:StagedDotnetCache }
    $map = @{}
    $files = @(Get-ChildItem -Path $PayloadPath -File -ErrorAction SilentlyContinue |
               Where-Object { ($_.Extension -eq '.exe') -and ($_.Name -match '^(dotnet-hosting|aspnetcore-runtime)-') })
    foreach ($f in $files) {
        $ver = $null
        if ($f.Name -match '(\d+\.\d+\.\d+)') { try { $ver = [Version]$Matches[1] } catch { } }
        if (-not $ver) {
            $pv = $f.VersionInfo.ProductVersion
            if ($pv -and ($pv -match '(\d+\.\d+\.\d+)')) { try { $ver = [Version]$Matches[1] } catch { } }
        }
        if (-not $ver) {
            Write-Log ('Cannot determine the version of staged installer {0} - ignoring it.' -f $f.Name) 'WARN'
            continue
        }
        $ch = '{0}.{1}' -f $ver.Major, $ver.Minor
        $isBundle = ($f.Name -like 'dotnet-hosting*')
        $keep = $true
        if ($map[$ch]) {
            if ($map[$ch].Version -gt $ver) { $keep = $false }
            elseif (($map[$ch].Version -eq $ver) -and $map[$ch].IsHostingBundle) { $keep = $false }
        }
        if ($keep) {
            $map[$ch] = [pscustomobject]@{
                Path = $f.FullName; Name = $f.Name; Version = $ver
                Channel = $ch; IsHostingBundle = $isBundle
            }
        }
    }
    $script:StagedDotnetCache = $map
    return $map
}

function Invoke-AspNetCorePatch {
    Write-Log '--- ASP.NET Core runtime (CVE-2026-45591) ---'
    $runtimes = @(Get-AspNetCoreRuntimes)
    if ($runtimes.Count -eq 0) {
        Write-Log 'No machine-wide ASP.NET Core runtimes found. If Rapid7 still flags CVE-2026-45591 here, the app is a self-contained deployment the owner must rebuild and redeploy.'
        return
    }
    foreach ($rt in $runtimes) {
        Write-Log ('Found Microsoft.AspNetCore.App {0} (root: {1})' -f $rt.Raw, $rt.Root)
    }
    $staged = Get-StagedDotnetInstallers
    $didInstall = $false
    foreach ($ch in @($runtimes | Select-Object -ExpandProperty Channel -Unique)) {
        $inst = $staged[$ch]
        if (-not $inst) {
            Write-Log ('ASP.NET Core {0}.x is installed but no {0}.x installer is staged - cannot patch offline. Stage the fixed Hosting Bundle named in the CVE-2026-45591 advisory.' -f $ch) 'WARN'
            $script:Attention++
            continue
        }
        $needs = @($runtimes | Where-Object { ($_.Channel -eq $ch) -and ($_.Version -lt $inst.Version) })
        if ($needs.Count -eq 0) {
            Write-Log ('ASP.NET Core {0}.x is already at or above the staged build {1}.' -f $ch, $inst.Version)
            continue
        }
        if (-not (Test-PayloadTrusted -Path $inst.Path)) { $script:Failures++; continue }
        if (-not (Test-MicrosoftSigned -Path $inst.Path)) {
            Write-Log ('{0} is not validly signed by Microsoft - refusing to execute it.' -f $inst.Name) 'ERROR'
            $script:Failures++
            continue
        }
        $instLog = Join-Path $LogDir ('aspnetcore-{0}.log' -f $ch)
        Write-Log ('Silently installing {0} (channel {1} -> {2}) ...' -f $inst.Name, $ch, $inst.Version)
        $p = Start-Process -FilePath $inst.Path `
                           -ArgumentList '/install', '/quiet', '/norestart', '/log', ('"{0}"' -f $instLog) `
                           -Wait -PassThru -WindowStyle Hidden
        Write-Log ('Installer exit code: {0}' -f $p.ExitCode)
        if     ($p.ExitCode -eq 0)    { $didInstall = $true }
        elseif ($p.ExitCode -eq 3010) { $didInstall = $true; $script:RebootNeeded = $true }
        elseif ($p.ExitCode -eq 1638) { Write-Log 'A same-or-newer build is already installed (1638) - treating as success.' }
        else {
            Write-Log ('Unexpected installer exit code {0} - see {1}' -f $p.ExitCode, $instLog) 'ERROR'
            $script:Failures++
        }
    }

    if ($didInstall) {
        if ((-not $NoIISReset) -and (Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue)) {
            Write-Log 'IIS detected - running iisreset so worker processes load the patched runtime ...'
            try {
                & (Join-Path $env:WINDIR 'System32\iisreset.exe') /restart 2>&1 | ForEach-Object { Write-Log ('iisreset: {0}' -f $_) }
                if ($LASTEXITCODE -ne 0) { Write-Log ('iisreset returned exit code {0}' -f $LASTEXITCODE) 'WARN' }
            } catch {
                Write-Log ('iisreset failed: {0}' -f $_.Exception.Message) 'WARN'
            }
        } elseif ($NoIISReset) {
            Write-Log 'Skipping iisreset (-NoIISReset). Running IIS apps keep the old runtime until IIS or the machine restarts.' 'WARN'
        }
        Write-Log 'Reminder: self-hosted Kestrel apps (Windows services/console apps) must be restarted to pick up the patched runtime.'

        $after = @(Get-AspNetCoreRuntimes)
        foreach ($ch in $staged.Keys) {
            $left = @($after | Where-Object { ($_.Channel -eq $ch) -and ($_.Version -lt $staged[$ch].Version) })
            foreach ($l in $left) {
                Write-Log ('STILL BELOW STAGED BUILD after install: {0} in {1} - usually an untracked xcopy/zip copy; update or remove it manually.' -f $l.Raw, $l.Root) 'WARN'
                $script:Attention++
            }
        }
    }
}

# --- 7-Zip (CVE-2026-58052) --------------------------------------------------
function Get-Installed7Zip {
    $found   = @()
    $unPaths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
    if ($Is64Os) { $unPaths += 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' }
    foreach ($unPath in $unPaths) {
        foreach ($k in (Get-ChildItem -Path $unPath -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
            if ((-not $p) -or ($p.DisplayName -notmatch '^7-Zip')) { continue }
            $ver = $null
            if ($p.DisplayVersion -and ($p.DisplayVersion -match '(\d+\.\d+)')) {
                try { $ver = [Version]$Matches[1] } catch { }
            }
            $arch = 'x86'
            if     ($p.DisplayName -match '\(arm64') { $arch = 'arm64' }
            elseif ($p.DisplayName -match '\(x64')   { $arch = 'x64' }
            elseif (($unPath -notmatch 'WOW6432Node') -and $Is64Os) { $arch = 'x64' }
            $type = 'EXE'
            if ("$($p.UninstallString)" -match '(?i)msiexec') { $type = 'MSI' }
            $found += [pscustomobject]@{
                DisplayName = $p.DisplayName; Version = $ver; Arch = $arch; Type = $type
            }
        }
    }
    if ($found.Count -eq 0) {
        # Portable/copied installs leave no uninstall entry but Rapid7 still finds 7z.exe.
        $pfArch = 'x86'
        if ($Is64Os) { $pfArch = 'x64' }
        $probes = @()
        if ($env:ProgramFiles)        { $probes += ,@((Join-Path $env:ProgramFiles '7-Zip\7z.exe'), $pfArch) }
        if (${env:ProgramFiles(x86)}) { $probes += ,@((Join-Path ${env:ProgramFiles(x86)} '7-Zip\7z.exe'), 'x86') }
        foreach ($probe in $probes) {
            if (Test-Path $probe[0]) {
                $pv  = (Get-Item $probe[0]).VersionInfo.ProductVersion
                $ver = $null
                if ($pv -and ($pv -match '(\d+\.\d+)')) { try { $ver = [Version]$Matches[1] } catch { } }
                $found += [pscustomobject]@{
                    DisplayName = ('7-Zip (file only: {0})' -f $probe[0]); Version = $ver; Arch = $probe[1]; Type = 'EXE'
                }
            }
        }
    }
    $found
}

$script:Staged7ZipCache = $null
function Get-Staged7ZipInstallers {
    if ($null -ne $script:Staged7ZipCache) { return $script:Staged7ZipCache }
    $list  = @()
    $files = @(Get-ChildItem -Path $PayloadPath -File -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -match '^7z.*\.(exe|msi)$' })
    foreach ($f in $files) {
        $arch = 'x86'
        if     ($f.Name -match '(?i)arm64') { $arch = 'arm64' }
        elseif ($f.Name -match '(?i)x64')   { $arch = 'x64' }
        $ver = $null
        # Official names encode the version as 7zMMmm (e.g. 7z2501-x64.exe = 25.01).
        if ($f.Name -match '^7z(\d{2})(\d{2})') {
            try { $ver = [Version]('{0}.{1}' -f $Matches[1], $Matches[2]) } catch { }
        }
        if ((-not $ver) -and ($f.Extension -eq '.exe')) {
            $pv = $f.VersionInfo.ProductVersion
            if ($pv -and ($pv -match '(\d+\.\d+)')) { try { $ver = [Version]$Matches[1] } catch { } }
        }
        if (-not $ver) {
            Write-Log ('Cannot determine the version of staged 7-Zip installer {0} - ignoring it.' -f $f.Name) 'WARN'
            continue
        }
        $type = 'EXE'
        if ($f.Extension -eq '.msi') { $type = 'MSI' }
        $list += [pscustomobject]@{ Path = $f.FullName; Name = $f.Name; Version = $ver; Arch = $arch; Type = $type }
    }
    $script:Staged7ZipCache = $list
    return $list
}

function Invoke-SevenZipPatch {
    Write-Log '--- 7-Zip (CVE-2026-58052) ---'
    $installed = @(Get-Installed7Zip)
    if ($installed.Count -eq 0) {
        Write-Log '7-Zip is not installed on this machine - nothing to do.'
        return
    }
    foreach ($i in $installed) {
        Write-Log ('Found: {0} (version {1}, {2}, {3} install)' -f $i.DisplayName, $i.Version, $i.Arch, $i.Type)
    }
    $staged = @(Get-Staged7ZipInstallers)
    if ($staged.Count -eq 0) {
        Write-Log '7-Zip is installed but no 7-Zip installer is staged - cannot patch offline. Stage the fixed release named in the CVE-2026-58052 advisory (7zXXXX-x64.exe).' 'WARN'
        $script:Attention++
        return
    }

    foreach ($group in ($installed | Group-Object -Property Arch)) {
        $arch    = $group.Name
        $current = $group.Group | Sort-Object -Property Version | Select-Object -Last 1
        if ($group.Count -gt 1) {
            Write-Log ('Multiple 7-Zip entries found for {0} - a stale entry from a previous EXE/MSI mix may remain in Add/Remove Programs.' -f $arch) 'WARN'
        }
        $cands = @($staged | Where-Object { $_.Arch -eq $arch })
        if ($cands.Count -eq 0) {
            Write-Log ('No staged 7-Zip installer matches architecture {0} - cannot patch this copy.' -f $arch) 'WARN'
            $script:Attention++
            continue
        }
        $sameType = @($cands | Where-Object { $_.Type -eq $current.Type })
        if ($sameType.Count -gt 0) { $cands = $sameType }
        $cand = $cands | Sort-Object -Property Version | Select-Object -Last 1

        if ($current.Version -and ($current.Version -ge $cand.Version)) {
            Write-Log ('7-Zip {0} ({1}) is already at or above the staged build {2}.' -f $current.Version, $arch, $cand.Version)
            continue
        }
        if ($current.Type -ne $cand.Type) {
            Write-Log ('Installed copy is {0} but the staged installer is {1} - the old Add/Remove entry may linger; stage the matching type if Rapid7 still flags this host afterwards.' -f $current.Type, $cand.Type) 'WARN'
        }
        if (-not (Test-PayloadTrusted -Path $cand.Path)) { $script:Failures++; continue }

        Write-Log ('Silently installing {0} ({1} {2} -> {3}) ...' -f $cand.Name, $arch, $current.Version, $cand.Version)
        if ($cand.Type -eq 'MSI') {
            $msiLog = Join-Path $LogDir ('7zip-{0}.log' -f $arch)
            $p = Start-Process -FilePath (Join-Path $env:WINDIR 'System32\msiexec.exe') `
                               -ArgumentList @('/i', ('"{0}"' -f $cand.Path), '/qn', '/norestart', '/L*v', ('"{0}"' -f $msiLog)) `
                               -Wait -PassThru -WindowStyle Hidden
        } else {
            $p = Start-Process -FilePath $cand.Path -ArgumentList '/S' -Wait -PassThru -WindowStyle Hidden
        }
        Write-Log ('Installer exit code: {0}' -f $p.ExitCode)
        if ($p.ExitCode -eq 3010) { $script:RebootNeeded = $true }
        elseif ($p.ExitCode -ne 0) {
            Write-Log ('7-Zip installer failed with exit code {0}.' -f $p.ExitCode) 'ERROR'
            $script:Failures++
            continue
        }

        $verify = @(Get-Installed7Zip | Where-Object { ($_.Arch -eq $arch) -and $_.Version -and ($_.Version -ge $cand.Version) })
        if ($verify.Count -gt 0) {
            Write-Log ('7-Zip ({0}) is now at {1}.' -f $arch, ($verify[0].Version))
        } else {
            Write-Log ('7-Zip ({0}) does not show version {1} after the install - check manually.' -f $arch, $cand.Version) 'WARN'
            $script:Attention++
        }
    }
}

# --- Compliance report -------------------------------------------------------
function Get-ComplianceReport {
    $rows = @()

    $tlsOff = @{}
    foreach ($proto in 'TLS 1.0', 'TLS 1.1') {
        $ok = $true
        foreach ($role in 'Client', 'Server') {
            $sub = '{0}\Protocols\{1}\{2}' -f $SchannelBase, $proto, $role
            $en  = Get-RegValue $sub 'Enabled'
            $dbd = Get-RegValue $sub 'DisabledByDefault'
            if (-not (($en -eq 0) -and ($dbd -eq 1))) { $ok = $false }
        }
        $tlsOff[$proto] = $ok
    }
    $tripleDesOff = ((Get-RegValue ('{0}\Ciphers\Triple DES 168' -f $SchannelBase) 'Enabled') -eq 0)
    $md5Off       = ((Get-RegValue ('{0}\Hashes\MD5' -f $SchannelBase) 'Enabled') -eq 0)

    $funcsRaw = Get-RegValue $SuitePolicyKey 'Functions'
    $suites = @()
    if ($funcsRaw) { $suites = @("$funcsRaw" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    $hasPolicy = ($suites.Count -gt 0)
    $hasRsaKx  = (@($suites | Where-Object { $_ -match '^TLS_RSA_' }).Count -gt 0)
    $has3des   = (@($suites | Where-Object { $_ -match '3DES' }).Count -gt 0)
    $hasRc4    = (@($suites | Where-Object { $_ -match 'RC4' }).Count -gt 0)
    $hasSha1   = (@($suites | Where-Object { $_ -match '_SHA(_P\d+)?$' }).Count -gt 0)
    $hasMd5    = (@($suites | Where-Object { $_ -match '_MD5' }).Count -gt 0)
    $hasGcm    = (@($suites | Where-Object { $_ -match '_GCM_' }).Count -gt 0)

    $pv = { param($ok) if ($ok) { 'PASS' } else { 'FAIL' } }

    $rows += [pscustomobject]@{ Status = (& $pv $tlsOff['TLS 1.0']); Finding = 'TLS Server Supports TLS version 1.0'
        Detail = 'TLS 1.0 disabled for Client+Server (Enabled=0, DisabledByDefault=1)' }
    $rows += [pscustomobject]@{ Status = (& $pv $tlsOff['TLS 1.1']); Finding = 'TLS Server Supports TLS version 1.1'
        Detail = 'TLS 1.1 disabled for Client+Server' }
    $rows += [pscustomobject]@{ Status = (& $pv $tlsOff['TLS 1.0']); Finding = 'TLS/SSL Server is enabling the BEAST attack'
        Detail = 'BEAST requires TLS 1.0/SSLv3 CBC; both protocols disabled' }
    $sweet32Ok = ($tripleDesOff -and $hasPolicy -and (-not $has3des))
    $rows += [pscustomobject]@{ Status = (& $pv $sweet32Ok); Finding = 'TLS/SSL Birthday attacks on 64-bit block ciphers (SWEET32)'
        Detail = '3DES cipher disabled and absent from the cipher-suite order' }
    $rows += [pscustomobject]@{ Status = (& $pv $sweet32Ok); Finding = 'TLS/SSL Server Supports 3DES Cipher Suite'
        Detail = 'same control as SWEET32' }
    $weakMacOk = ($md5Off -and $hasPolicy -and (-not $hasSha1) -and (-not $hasMd5) -and (-not $hasRc4))
    $rows += [pscustomobject]@{ Status = (& $pv $weakMacOk); Finding = 'TLS/SSL Weak Message Authentication Code Cipher Suites'
        Detail = 'MD5 disabled; suite order contains no MD5/SHA-1-MAC/RC4 suites' }
    $rows += [pscustomobject]@{ Status = (& $pv ($hasPolicy -and (-not $hasRsaKx))); Finding = 'TLS/SSL Server Supports The Use of Static Key Ciphers'
        Detail = 'suite order contains no TLS_RSA_* (RSA key-exchange) suites' }
    if ($script:OsBuild -lt 9200) {
        $rows += [pscustomobject]@{ Status = 'ATTENTION'; Finding = 'TLS/SSL Server Does Not Support Any Strong Cipher Algorithms'
            Detail = 'this OS build has no AES-GCM support in SCHANNEL - requires OS upgrade' }
    } else {
        $rows += [pscustomobject]@{ Status = (& $pv ($hasPolicy -and $hasGcm)); Finding = 'TLS/SSL Server Does Not Support Any Strong Cipher Algorithms'
            Detail = 'AES-GCM (AEAD) suites present and preferred in the suite order' }
    }

    $wvtOk = ((Get-RegValue 'SOFTWARE\Microsoft\Cryptography\Wintrust\Config' 'EnableCertPaddingCheck') -eq '1')
    if ($Is64Os) {
        $wvtOk = $wvtOk -and ((Get-RegValue 'SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config' 'EnableCertPaddingCheck') -eq '1')
    }
    $rows += [pscustomobject]@{ Status = (& $pv $wvtOk); Finding = 'CVE-2013-3900: MS13-098 WinVerifyTrust signature padding'
        Detail = 'EnableCertPaddingCheck="1" in native (and Wow6432Node) Wintrust\Config' }

    $lp = Get-LockoutPolicy
    if ($lp) {
        $lockOk = (($lp.Threshold -gt 0) -and ($lp.Threshold -le $LockoutThreshold))
        $rows += [pscustomobject]@{ Status = (& $pv $lockOk); Finding = 'CIFS Account Lockout Policy Allows Password Brute Forcing'
            Detail = ('threshold={0} window={1}min duration={2}min (target: threshold 1-{3})' -f $lp.Threshold, $lp.WindowMinutes, $lp.DurationMinutes, $LockoutThreshold) }
    } else {
        $rows += [pscustomobject]@{ Status = 'ATTENTION'; Finding = 'CIFS Account Lockout Policy Allows Password Brute Forcing'
            Detail = 'could not read the policy via secedit (needs elevation)' }
    }

    $rts = @(Get-AspNetCoreRuntimes)
    if ($rts.Count -eq 0) {
        $rows += [pscustomobject]@{ Status = 'PASS'; Finding = 'Microsoft ASP.NET: CVE-2026-45591 (ASP.NET Core DoS)'
            Detail = 'no machine-wide ASP.NET Core runtime installed (self-contained apps need an app-owner rebuild)' }
    } else {
        $stgMap = Get-StagedDotnetInstallers
        $bad = @(); $unknown = @()
        foreach ($rt in $rts) {
            $s = $stgMap[$rt.Channel]
            if (-not $s) { $unknown += $rt }
            elseif ($rt.Version -lt $s.Version) { $bad += $rt }
        }
        if ($bad.Count -gt 0) {
            $rows += [pscustomobject]@{ Status = 'FAIL'; Finding = 'Microsoft ASP.NET: CVE-2026-45591 (ASP.NET Core DoS)'
                Detail = ('below staged fixed build: {0}' -f (($bad | ForEach-Object { $_.Raw }) -join ', ')) }
        } elseif ($unknown.Count -gt 0) {
            $rows += [pscustomobject]@{ Status = 'ATTENTION'; Finding = 'Microsoft ASP.NET: CVE-2026-45591 (ASP.NET Core DoS)'
                Detail = ('no staged installer to compare against for: {0}' -f (($unknown | ForEach-Object { $_.Raw }) -join ', ')) }
        } else {
            $rows += [pscustomobject]@{ Status = 'PASS'; Finding = 'Microsoft ASP.NET: CVE-2026-45591 (ASP.NET Core DoS)'
                Detail = 'all installed runtimes at or above the staged fixed builds' }
        }
    }

    $sz = @(Get-Installed7Zip)
    if ($sz.Count -eq 0) {
        $rows += [pscustomobject]@{ Status = 'PASS'; Finding = '7-Zip: CVE-2026-58052 (Protection Mechanism Failure)'
            Detail = '7-Zip is not installed' }
    } else {
        $stg7 = @(Get-Staged7ZipInstallers)
        if ($stg7.Count -eq 0) {
            $rows += [pscustomobject]@{ Status = 'ATTENTION'; Finding = '7-Zip: CVE-2026-58052 (Protection Mechanism Failure)'
                Detail = ('installed ({0}) but no staged installer to compare against' -f (($sz | ForEach-Object { "$($_.Version)" } | Select-Object -Unique) -join ', ')) }
        } else {
            $bad7 = @()
            foreach ($i in $sz) {
                $c = @($stg7 | Where-Object { $_.Arch -eq $i.Arch }) | Sort-Object -Property Version | Select-Object -Last 1
                if ($c -and ((-not $i.Version) -or ($i.Version -lt $c.Version))) { $bad7 += $i }
            }
            if ($bad7.Count -gt 0) {
                $rows += [pscustomobject]@{ Status = 'FAIL'; Finding = '7-Zip: CVE-2026-58052 (Protection Mechanism Failure)'
                    Detail = ('below staged build: {0}' -f (($bad7 | ForEach-Object { $_.DisplayName }) -join ', ')) }
            } else {
                $rows += [pscustomobject]@{ Status = 'PASS'; Finding = '7-Zip: CVE-2026-58052 (Protection Mechanism Failure)'
                    Detail = 'installed 7-Zip at or above the staged build' }
            }
        }
    }

    return $rows
}

# --- Backup ------------------------------------------------------------------
function Backup-CurrentState {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $bdir  = Join-Path $LogDir ('backup-{0}' -f $stamp)
    New-Item -Path $bdir -ItemType Directory -Force | Out-Null
    $exports = @(
        @{ Sub = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'; File = 'schannel.reg' },
        @{ Sub = 'SOFTWARE\Policies\Microsoft\Cryptography';                    File = 'cipher-suite-policy.reg' },
        @{ Sub = 'SOFTWARE\Microsoft\Cryptography\Wintrust';                    File = 'wintrust.reg' },
        @{ Sub = 'SOFTWARE\Microsoft\.NETFramework';                            File = 'netfx.reg' }
    )
    foreach ($e in $exports) {
        if (-not (Test-RegKey $e.Sub)) { continue }
        & (Join-Path $env:WINDIR 'System32\reg.exe') export ('HKLM\{0}' -f $e.Sub) (Join-Path $bdir $e.File) /y 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Log ('reg export of HKLM\{0} failed (exit {1}).' -f $e.Sub, $LASTEXITCODE) 'WARN' }
    }
    try {
        & (Join-Path $env:WINDIR 'System32\net.exe') accounts |
            Out-File -FilePath (Join-Path $bdir 'net-accounts-before.txt') -Encoding UTF8
    } catch { }
    Write-Log ('Pre-change backup written to {0} (rollback: reg import <file>.reg, restore lockout values from net-accounts-before.txt, then reboot).' -f $bdir)
}

# --- Main --------------------------------------------------------------------
$exitCode = 0
try {
    Write-Log '======================================================================'
    Write-Log ('Rapid7 offline remediation starting on {0} (AuditOnly={1}, SkipTls={2}, SkipWVT={3}, SkipLockout={4}, SkipApps={5}, CbcFallback={6}, StrictIntegrity={7})' -f `
        $env:COMPUTERNAME, [bool]$AuditOnly, [bool]$SkipTlsHardening, [bool]$SkipWinVerifyTrust, `
        [bool]$SkipLockoutPolicy, [bool]$SkipAppPatches, [bool]$IncludeCbcFallback, [bool]$StrictIntegrity)
    Write-Log ('Payload folder: {0}' -f $PayloadPath)

    try { $script:OsBuild = [int](Get-RegValue 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'CurrentBuildNumber') } catch { }
    if (-not $script:OsBuild) { $script:OsBuild = [Environment]::OSVersion.Version.Build }
    $prodName = Get-RegValue 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'ProductName'
    Write-Log ('OS: {0} (build {1}, {2})' -f $prodName, $script:OsBuild, $(if ($Is64Os) { '64-bit' } else { '32-bit' }))

    $isAdmin = $true
    try {
        $identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        $isAdmin  = $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { }
    if ((-not $isAdmin) -and (-not $AuditOnly)) {
        Write-Log 'This script must run elevated (SYSTEM or administrator) to remediate.' 'ERROR'
        exit 1
    }

    if (-not $AuditOnly) {
        Backup-CurrentState
        if (-not $SkipTlsHardening)  { Invoke-TlsHardening }     else { Write-Log 'TLS hardening skipped (-SkipTlsHardening).' }
        if (-not $SkipWinVerifyTrust){ Invoke-WinVerifyTrustFix } else { Write-Log 'CVE-2013-3900 fix skipped (-SkipWinVerifyTrust).' }
        if (-not $SkipLockoutPolicy) { Invoke-LockoutPolicy }     else { Write-Log 'Lockout policy skipped (-SkipLockoutPolicy).' }
        if (-not $SkipAppPatches) {
            Invoke-AspNetCorePatch
            Invoke-SevenZipPatch
        } else { Write-Log 'Application patches skipped (-SkipAppPatches).' }
    } else {
        Write-Log 'AUDIT ONLY - no changes will be made.'
    }

    $report   = Get-ComplianceReport
    $failRows = @($report | Where-Object { $_.Status -eq 'FAIL' })
    $attnRows = @($report | Where-Object { $_.Status -eq 'ATTENTION' })

    Write-Log '------------------------- COMPLIANCE SUMMARY -------------------------'
    foreach ($r in $report) {
        Write-Log ('[{0}] {1}  |  {2}' -f $r.Status.PadRight(9), $r.Finding, $r.Detail)
    }
    if ((-not $AuditOnly) -and $script:RebootNeeded) {
        Write-Log 'Registry values above are in place, but SCHANNEL only reads them at boot - the TLS findings clear after the next RESTART.' 'WARN'
    }

    if ($AuditOnly) {
        if (($failRows.Count + $attnRows.Count) -gt 0) { $exitCode = 2 }
    } else {
        if     ($script:Failures -gt 0)                                { $exitCode = 1 }
        elseif (($failRows.Count -gt 0) -or ($attnRows.Count -gt 0) -or ($script:Attention -gt 0)) { $exitCode = 2 }
        elseif ($script:RebootNeeded)                                  { $exitCode = 3010 }
    }

    $resultText = 'COMPLIANT'
    if ($AuditOnly) {
        if ($exitCode -eq 2) { $resultText = 'NON-COMPLIANT - remediation required' }
    } else {
        if     ($exitCode -eq 3010) { $resultText = 'REMEDIATED - RESTART REQUIRED to activate the TLS changes' }
        elseif ($exitCode -eq 2)    { $resultText = 'ATTENTION REQUIRED - see WARN lines above (missing payload / manual follow-up)' }
        elseif ($exitCode -eq 1)    { $resultText = 'FAILED - see ERROR lines above' }
        else                        { $resultText = 'COMPLIANT - nothing to change or everything already active' }
    }
    Write-Log ('RESULT: {0} (exit code {1})' -f $resultText, $exitCode)

    if ($ForceReboot -and (-not $AuditOnly) -and $script:RebootNeeded -and ($script:Failures -eq 0)) {
        Write-Log 'ForceReboot: restarting this computer in 5 minutes ...' 'WARN'
        & (Join-Path $env:WINDIR 'System32\shutdown.exe') /r /t 300 /f /d p:2:17 `
            /c 'Security hardening (TLS/SCHANNEL) was applied and requires a restart. Save your work - restarting in 5 minutes.'
    }
}
catch {
    Write-Log ('Unhandled error: {0}' -f $_.Exception.Message) 'ERROR'
    Write-Log ($_.ScriptStackTrace) 'ERROR'
    $exitCode = 1
}

exit $exitCode
