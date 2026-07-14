<#
.SYNOPSIS
    All-in-one detection + remediation for the June 2026 Rapid7 InsightVM
    vulnerability export (Vulnerabilitiesv1.csv) on Windows endpoints.

.DESCRIPTION
    One script, one Endpoint Central Custom Script configuration, the whole
    fleet. Every module detects whether its product/setting exists on the
    machine and only acts when needed, so the same script is safe to deploy
    to every Windows asset in the export.

    EXCLUDED BY POLICY: AutoDesk AutoCAD (all 180 findings). This script never
    touches AutoCAD, Advance Steel, Civil 3D or any Autodesk component.

    What each module remediates (Rapid7 finding groups in parentheses):

      AUTO-REMEDIATED
      1  CertPadding      CVE-2013-3900 WinVerifyTrust signature padding
                          (100 assets) - registry EnableCertPaddingCheck.
      2  SmbSigning       "SMBv2 signing not required" (48 assets) - require
                          signing on the SMB server.
      3  TlsHardening     All TLS/SSL findings: BEAST, POODLE, SSLv3, TLS 1.0,
                          TLS 1.1, SWEET32/3DES, RC4, static-key ciphers, weak
                          MAC ciphers, "no strong ciphers" (up to 67 assets) -
                          SChannel protocol/cipher hardening + cipher-suite
                          order + .NET strong-crypto keys.
      4  LockoutPolicy    "CIFS Account Lockout Policy Allows Password Brute
                          Forcing" (52 assets) - local lockout 5/15/15.
      5  AutoLogon        "Windows autologin enabled" (8 assets) - disables
                          AutoAdminLogon and deletes the cleartext password.
      6  Chrome           All 1195 Google Chrome CVEs - installs the latest
                          Chrome Enterprise MSI (evergreen link, Google
                          Authenticode verified).
      7  Edge             All 449 Microsoft Edge CVEs - installs the latest
                          Edge Stable MSI (Microsoft evergreen link, verified);
                          falls back to kicking the built-in updater.
      8  AdobeAcrobat     All 397 Adobe Acrobat/Reader CVEs - runs Adobe
                          RemoteUpdateManager (RUM) to apply the newest patch.
      9  Office           All 93 Microsoft Office CVEs - triggers a
                          Click-to-Run update to the latest build.
      10 AspNetCore       ASP.NET Core CVEs incl. CVE-2025-55315 / the 2026
                          DoS-EoP set (32 assets) - upgrades in-support 8.0/
                          9.0/10.0 Hosting Bundles to the newest build;
                          reports EOL 2.x-7.x ("Obsolete Version", 13 assets).
      11 SevenZip         All 7-Zip CVEs (10 assets) - winget upgrade, or
                          downloads the newest x64 build from 7-zip.org.
      12 VisualStudio     All 9 Visual Studio CVEs - vs_installer updateall.
      13 StoreApps        Microsoft Notepad CVE-2026-20841 and other Store app
                          findings - forces a Store app update scan.
      14 Java             Oracle Java SE CPU findings (2 assets) - winget
                          upgrade when possible, otherwise reported.
      15 TeamViewer       TeamViewer CVE-2025-41421 - winget upgrade when
                          possible, otherwise reported.
      16 InsightAgent     Rapid7 Insight Agent CVEs (2 assets) - bounces the
                          agent service so it self-updates; reports version.
      17 WindowsUpdate    All 327 "Microsoft Windows" CVEs, .NET Framework
                          CVEs, SQL Server GDRs, Defender etc. - opts the box
                          into Microsoft Update and installs every applicable
                          software update via the Windows Update Agent API.
                          Runs LAST because it is the slowest.

      DETECT + REPORT ONLY (exit code 2 so the machine shows as needs-attention)
      18 MariaDb          11 MariaDB CVEs (2 assets) - unattended in-place
                          upgrade of a production DB engine is not safe from a
                          blind script; reports installed version + guidance.
      19 FortiClient      5 FortiClient CVEs (1 asset) - fixed installers are
                          only available signed-in via FortiCare/EMS.
      20 Log4j            4 Apache Log4j Core CVEs (2 assets) - the jar is
                          embedded in an application; reports every log4j jar
                          found so the app owner can upgrade it.
      21 Vnc              "VNC remote control service installed" (10 assets) -
                          may be sanctioned remote admin; reports it, or
                          uninstalls when run with -RemoveVNC.
      22 SqlServer        SQL Server RCE/EoP CVEs + "Database Open Access" -
                          GDRs arrive via the WindowsUpdate module once
                          Microsoft Update is opted in; reports instance +
                          exposure guidance.

    Findings with no endpoint-side fix ("Inconclusive host with excessive port
    connection failures") are scanner-side and ignored.

.PARAMETER AuditOnly
    Detect and report everything, change nothing. Exit 0 = fully compliant,
    2 = at least one module would make a change / needs attention.

.PARAMETER NoDownload
    Never touch the internet. Installer-based modules only use files shipped
    next to the script as Endpoint Central dependency files:
        googlechromestandaloneenterprise64.msi, MicrosoftEdgeEnterpriseX64.msi,
        dotnet-hosting-<ver>-win.exe, 7z*-x64.exe/.msi
    Modules whose installer is missing are skipped with a warning.
    (WindowsUpdate/Office/Adobe/VS use their own update channels and are not
    affected by this switch - use the Skip switches to suppress them.)

.PARAMETER SkipWindowsUpdate
    Skip module 17. Use this when Endpoint Central Patch Management already
    handles OS patching, or to keep run time short.

.PARAMETER SkipTlsHardening
    Skip module 3 (e.g. while validating that no legacy client depends on
    TLS 1.0/1.1 or RSA-key-exchange cipher suites against this server).

.PARAMETER KeepAutoLogon
    Skip module 5 (kiosk / signage machines that must keep auto-logon).

.PARAMETER RemoveVNC
    Module 21 uninstalls detected VNC servers instead of only reporting them.

.PARAMETER RestartServices
    Allow immediate service restarts where a change needs one (LanmanServer
    after the SMB-signing change). Default is to leave services alone and let
    the change activate at the next reboot.

.PARAMETER SkipModules
    Names of modules to skip, e.g. -SkipModules Chrome,Edge

.NOTES
    Exit codes (set "Specify the exit code(s)" to 0,3010 in Endpoint Central):
        0    = compliant / everything remediated, no reboot needed
        3010 = remediated, reboot required to finish (TLS/SMB/updates)
        2    = attention required - read the log (report-only findings, EOL
               software, or -AuditOnly found gaps)
        1    = at least one module failed (download/signature/install error)

    Built for ManageEngine Endpoint Central "Custom Script" (Computer scope),
    Run As: System User. PowerShell 5.1 compatible.

    Log: C:\ProgramData\Rapid7Remediation\remediation.log
#>

[CmdletBinding()]
param(
    [switch]$AuditOnly,
    [switch]$NoDownload,
    [switch]$SkipWindowsUpdate,
    [switch]$SkipTlsHardening,
    [switch]$KeepAutoLogon,
    [switch]$RemoveVNC,
    [switch]$RestartServices,
    [string[]]$SkipModules = @()
)

# --- If launched from a 32-bit host on a 64-bit OS, relaunch in 64-bit PS ----
if ($env:PROCESSOR_ARCHITEW6432 -and -not $env:R7REM_RELAUNCHED) {
    $env:R7REM_RELAUNCHED = '1'
    $ps64 = Join-Path $env:WINDIR 'sysnative\WindowsPowerShell\v1.0\powershell.exe'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    if ($AuditOnly)         { $argList += '-AuditOnly' }
    if ($NoDownload)        { $argList += '-NoDownload' }
    if ($SkipWindowsUpdate) { $argList += '-SkipWindowsUpdate' }
    if ($SkipTlsHardening)  { $argList += '-SkipTlsHardening' }
    if ($KeepAutoLogon)     { $argList += '-KeepAutoLogon' }
    if ($RemoveVNC)         { $argList += '-RemoveVNC' }
    if ($RestartServices)   { $argList += '-RestartServices' }
    if ($SkipModules.Count) { $argList += '-SkipModules'; $argList += ($SkipModules -join ',') }
    $proc = Start-Process -FilePath $ps64 -ArgumentList $argList -Wait -PassThru -WindowStyle Hidden
    exit $proc.ExitCode
}

# -File passes '-SkipModules a,b' as one literal token - split it back out.
if ($SkipModules) { $SkipModules = @($SkipModules | ForEach-Object { $_ -split ',' } | Where-Object { $_ }) }

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = Split-Path -Parent $PSCommandPath }

$LogDir  = Join-Path $env:ProgramData 'Rapid7Remediation'
$LogFile = Join-Path $LogDir 'remediation.log'
if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch { }
}

# --- Run-wide state -----------------------------------------------------------
$Script:RebootNeeded = $false
$Script:Attention    = New-Object System.Collections.ArrayList
$Script:ModuleStatus = New-Object System.Collections.ArrayList   # objects: Name, Status, Detail

function Add-Attention {
    param([string]$Message)
    [void]$Script:Attention.Add($Message)
    Write-Log $Message 'WARN'
}

function Set-ModuleStatus {
    param([string]$Name, [string]$Status, [string]$Detail = '')
    [void]$Script:ModuleStatus.Add([pscustomobject]@{ Name = $Name; Status = $Status; Detail = $Detail })
}

# --- Shared helpers ------------------------------------------------------------
function Set-RegValue {
    # Creates the key path if needed. Honors -AuditOnly.
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    if ($AuditOnly) { Write-Log ("AUDIT: would set {0}\{1} = {2} ({3})" -f $Path, $Name, $Value, $Type); return }
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    if (($Type -eq 'DWord') -and ($Value -gt [int]::MaxValue)) {
        # 0xFFFFFFFF etc: DWord writes go through Int32, so wrap to two's complement.
        $Value = [int]($Value - 4294967296)
    }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    Write-Log ("Set {0}\{1} = {2} ({3})" -f $Path, $Name, $Value, $Type)
}

function Get-InstalledApps {
    # All entries from both uninstall hives.
    $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
               'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
    foreach ($p in $paths) {
        Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, UninstallString, QuietUninstallString, WindowsInstaller, PSChildName
    }
}

function Test-SignedBy {
    param([string]$Path, [string]$SubjectMatch)
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path
        return (($sig.Status -eq 'Valid') -and ($sig.SignerCertificate.Subject -match $SubjectMatch))
    } catch { return $false }
}

function Get-RemediationFile {
    # Dependency file next to the script first, then download (unless -NoDownload).
    param([string]$LocalPattern, [string]$Url, [string]$DownloadName)
    $local = @(Get-ChildItem -Path $ScriptDir -Filter $LocalPattern -File -ErrorAction SilentlyContinue) |
             Sort-Object Name | Select-Object -Last 1
    if ($local) {
        Write-Log ("Using dependency file: {0}" -f $local.FullName)
        return $local.FullName
    }
    if ($NoDownload) {
        Write-Log ("No dependency file matching '{0}' and -NoDownload is set - skipping." -f $LocalPattern) 'WARN'
        return $null
    }
    $dest = Join-Path $env:TEMP $DownloadName
    Write-Log ("Downloading {0} ..." -f $Url)
    try {
        Invoke-WebRequest -Uri $Url -OutFile $dest -UseBasicParsing
        return $dest
    } catch {
        Write-Log ("Download failed: {0}" -f $_.Exception.Message) 'ERROR'
        return $null
    }
}

function Install-Msi {
    param([string]$MsiPath, [string]$LogName)
    $msiLog = Join-Path $LogDir $LogName
    $p = Start-Process -FilePath 'msiexec.exe' `
            -ArgumentList '/i', ('"{0}"' -f $MsiPath), '/qn', '/norestart', '/l*v', ('"{0}"' -f $msiLog) `
            -Wait -PassThru
    Write-Log ("msiexec exit code {0} (log: {1})" -f $p.ExitCode, $msiLog)
    if ($p.ExitCode -eq 3010) { $Script:RebootNeeded = $true; return $true }
    if ($p.ExitCode -eq 1638) { Write-Log 'Same or newer version already installed (1638) - OK.'; return $true }
    return ($p.ExitCode -eq 0)
}

function Get-WingetPath {
    # winget for the SYSTEM account: resolve the packaged exe directly.
    $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $pkg = @(Get-ChildItem -Path (Join-Path $env:ProgramFiles 'WindowsApps') `
             -Filter 'Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe' -Directory -ErrorAction SilentlyContinue) |
           Sort-Object Name | Select-Object -Last 1
    if ($pkg) {
        $exe = Join-Path $pkg.FullName 'winget.exe'
        if (Test-Path $exe) { return $exe }
    }
    return $null
}

function Invoke-WingetUpgrade {
    param([string]$Id)
    $winget = Get-WingetPath
    if (-not $winget) { return $null }   # null = winget unavailable
    if ($AuditOnly)   { Write-Log ("AUDIT: would run winget upgrade --id {0}" -f $Id); return $true }
    Write-Log ("winget upgrade --id {0} ..." -f $Id)
    $out = & $winget upgrade --id $Id --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1
    $code = $LASTEXITCODE
    ($out | Out-String).Trim() -split "`r?`n" | Select-Object -Last 3 | ForEach-Object { Write-Log ("  winget: {0}" -f $_) }
    Write-Log ("winget exit code for {0}: {1}" -f $Id, $code)
    # 0 = upgraded; -1978335189 (0x8A15002B) = no applicable upgrade found
    return (($code -eq 0) -or ($code -eq -1978335189))
}

function Invoke-Module {
    param([string]$Name, [scriptblock]$Body)
    if ($SkipModules -contains $Name) {
        Write-Log ("--- [{0}] skipped via -SkipModules" -f $Name)
        Set-ModuleStatus $Name 'SKIPPED' 'via -SkipModules'
        return
    }
    Write-Log ("--- [{0}] ---------------------------------------------------" -f $Name)
    try {
        & $Body
    } catch {
        Write-Log ("[{0}] FAILED: {1}" -f $Name, $_.Exception.Message) 'ERROR'
        Set-ModuleStatus $Name 'FAILED' $_.Exception.Message
    }
}

# ==============================================================================
# 1. CVE-2013-3900 - WinVerifyTrust signature padding check
# ==============================================================================
function Invoke-CertPaddingFix {
    # Microsoft's opt-in fix uses REG_SZ "1" (exact format from the advisory).
    $targets = @('HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config')
    if ([Environment]::Is64BitOperatingSystem) {
        $targets += 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config'
    }
    $missing = @($targets | Where-Object {
        (Get-ItemProperty -Path $_ -Name 'EnableCertPaddingCheck' -ErrorAction SilentlyContinue).EnableCertPaddingCheck -ne '1'
    })
    if ($missing.Count -eq 0) {
        Write-Log 'EnableCertPaddingCheck already enforced in all views.'
        Set-ModuleStatus 'CertPadding' 'OK' 'already compliant'
        return
    }
    foreach ($t in $missing) { Set-RegValue -Path $t -Name 'EnableCertPaddingCheck' -Value '1' -Type 'String' }
    Set-ModuleStatus 'CertPadding' $(if ($AuditOnly) { 'WOULD-CHANGE' } else { 'CHANGED' }) 'EnableCertPaddingCheck=1'
}

# ==============================================================================
# 2. SMBv2 signing not required
# ==============================================================================
function Invoke-SmbSigningFix {
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $cur = (Get-ItemProperty -Path $key -Name 'RequireSecuritySignature' -ErrorAction SilentlyContinue).RequireSecuritySignature
    if ($cur -eq 1) {
        Write-Log 'SMB server already requires signing.'
        Set-ModuleStatus 'SmbSigning' 'OK' 'already compliant'
        return
    }
    Set-RegValue -Path $key -Name 'RequireSecuritySignature' -Value 1 -Type 'DWord'
    Set-RegValue -Path $key -Name 'EnableSecuritySignature'  -Value 1 -Type 'DWord'
    if ($AuditOnly) { Set-ModuleStatus 'SmbSigning' 'WOULD-CHANGE' 'require SMB signing'; return }
    if ($RestartServices) {
        Write-Log 'Restarting LanmanServer so signing enforcement is active immediately ...'
        try {
            Restart-Service -Name 'LanmanServer' -Force -ErrorAction Stop
        } catch {
            Write-Log ("LanmanServer restart failed ({0}) - will apply at next reboot." -f $_.Exception.Message) 'WARN'
            $Script:RebootNeeded = $true
        }
    } else {
        $Script:RebootNeeded = $true
    }
    Write-Log 'NOTE: on domain-joined machines a GPO with a weaker setting will win - align the domain policy too.'
    Set-ModuleStatus 'SmbSigning' 'CHANGED' 'RequireSecuritySignature=1'
}

# ==============================================================================
# 3. TLS/SSL hardening (BEAST, POODLE, SSLv3, TLS1.0/1.1, 3DES, RC4, static-key,
#    weak-MAC, no-strong-ciphers)
# ==============================================================================
function Invoke-TlsHardening {
    if ($SkipTlsHardening) {
        Write-Log 'Skipped via -SkipTlsHardening.'
        Set-ModuleStatus 'TlsHardening' 'SKIPPED' 'via -SkipTlsHardening'
        return
    }
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    $protocolStates = @(
        @{ Name = 'SSL 2.0'; Enabled = 0 }, @{ Name = 'SSL 3.0'; Enabled = 0 },
        @{ Name = 'TLS 1.0'; Enabled = 0 }, @{ Name = 'TLS 1.1'; Enabled = 0 },
        @{ Name = 'TLS 1.2'; Enabled = 1 }
    )
    foreach ($p in $protocolStates) {
        foreach ($side in 'Server', 'Client') {
            $key = Join-Path (Join-Path $base $p.Name) $side
            if ($p.Enabled -eq 1) {
                Set-RegValue -Path $key -Name 'Enabled' -Value 0xffffffff -Type 'DWord'
                Set-RegValue -Path $key -Name 'DisabledByDefault' -Value 0 -Type 'DWord'
            } else {
                Set-RegValue -Path $key -Name 'Enabled' -Value 0 -Type 'DWord'
                Set-RegValue -Path $key -Name 'DisabledByDefault' -Value 1 -Type 'DWord'
            }
        }
    }
    # TLS 1.3 is left at OS default (on where supported).

    # Weak ciphers off, AES stays on. Names contain '/' so the .NET registry API
    # is required (the PS provider would treat '/' as a path separator).
    $weakCiphers = @('NULL', 'DES 56/56', 'RC2 40/128', 'RC2 56/128', 'RC2 128/128',
                     'RC4 40/128', 'RC4 56/128', 'RC4 64/128', 'RC4 128/128', 'Triple DES 168')
    $strongCiphers = @('AES 128/128', 'AES 256/256')
    $cipherBase = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers'
    if (-not $AuditOnly) {
        foreach ($c in $weakCiphers) {
            $k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey("$cipherBase\$c")
            $k.SetValue('Enabled', 0, [Microsoft.Win32.RegistryValueKind]::DWord); $k.Close()
        }
        foreach ($c in $strongCiphers) {
            $k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey("$cipherBase\$c")
            # -1 = 0xFFFFFFFF (DWord writes go through Int32)
            $k.SetValue('Enabled', -1, [Microsoft.Win32.RegistryValueKind]::DWord); $k.Close()
        }
        Write-Log ("Disabled ciphers: {0}; enabled: AES 128/256." -f ($weakCiphers -join ', '))
    } else {
        Write-Log ("AUDIT: would disable ciphers: {0}" -f ($weakCiphers -join ', '))
    }

    # MD5 out of the HMAC pool; SHA* untouched. Minimum 2048-bit DHE.
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -Name 'Enabled' -Value 0 -Type 'DWord'
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' -Name 'ServerMinKeyBitLength' -Value 2048 -Type 'DWord'

    # Cipher-suite order: ECDHE + AEAD first, no RSA key exchange (static-key
    # finding), no SHA-1 HMAC (weak-MAC finding). Suffixed entries keep
    # Win 8.1/2012 R2 functional; unknown names are ignored by each OS.
    $suites = @(
        'TLS_AES_256_GCM_SHA384', 'TLS_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',   'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',   'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384_P384', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256_P256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256'
    )
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' `
                 -Name 'Functions' -Value ($suites -join ',') -Type 'String'

    # .NET Framework apps must not fall back to TLS 1.0 once it is disabled.
    foreach ($ndp in 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319',
                     'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727') {
        if ($ndp -match 'WOW6432Node' -and -not [Environment]::Is64BitOperatingSystem) { continue }
        Set-RegValue -Path $ndp -Name 'SchUseStrongCrypto'      -Value 1 -Type 'DWord'
        Set-RegValue -Path $ndp -Name 'SystemDefaultTlsVersions' -Value 1 -Type 'DWord'
    }

    if ($AuditOnly) { Set-ModuleStatus 'TlsHardening' 'WOULD-CHANGE' 'SChannel hardening'; return }
    $Script:RebootNeeded = $true
    Write-Log 'SChannel hardening applied - takes effect after reboot.'
    Set-ModuleStatus 'TlsHardening' 'CHANGED' 'protocols/ciphers/suite order hardened'
}

# ==============================================================================
# 4. Account lockout policy
# ==============================================================================
function Invoke-LockoutPolicyFix {
    $raw = (& "$env:WINDIR\System32\net.exe" accounts) 2>&1 | Out-String
    $threshold = $null
    if ($raw -match 'Lockout threshold:\s+(\S+)') { $threshold = $Matches[1] }
    Write-Log ("Current lockout threshold: {0}" -f $threshold)
    if ($threshold -and $threshold -ne 'Never') {
        $tVal = 0; [void][int]::TryParse($threshold, [ref]$tVal)
        if (($tVal -ge 1) -and ($tVal -le 10)) {
            Write-Log 'Lockout policy already acceptable (threshold 1-10).'
            Set-ModuleStatus 'LockoutPolicy' 'OK' ("threshold={0}" -f $tVal)
            return
        }
    }
    if ($AuditOnly) { Set-ModuleStatus 'LockoutPolicy' 'WOULD-CHANGE' 'set lockout 5/15/15'; return }
    & "$env:WINDIR\System32\net.exe" accounts /lockoutthreshold:5 /lockoutwindow:15 /lockoutduration:15 | ForEach-Object { Write-Log ("  net accounts: {0}" -f $_) }
    if ($LASTEXITCODE -ne 0) { throw "net accounts returned exit code $LASTEXITCODE" }
    Write-Log 'Local lockout policy set to threshold 5 / window 15 min / duration 15 min.'
    Write-Log 'NOTE: on domain-joined machines the domain policy governs domain accounts - this fixes local-account brute forcing.'
    Set-ModuleStatus 'LockoutPolicy' 'CHANGED' 'threshold 5 / 15 / 15'
}

# ==============================================================================
# 5. Windows autologon
# ==============================================================================
function Invoke-AutoLogonFix {
    if ($KeepAutoLogon) {
        Write-Log 'Skipped via -KeepAutoLogon.'
        Set-ModuleStatus 'AutoLogon' 'SKIPPED' 'via -KeepAutoLogon'
        return
    }
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    $enabled = ($props.AutoAdminLogon -eq '1') -or ($props.AutoAdminLogon -eq 1)
    $hasPwd  = $null -ne $props.DefaultPassword
    if (-not $enabled -and -not $hasPwd) {
        Write-Log 'Auto-logon not enabled and no cleartext DefaultPassword present.'
        Set-ModuleStatus 'AutoLogon' 'OK' 'not enabled'
        return
    }
    if ($AuditOnly) { Set-ModuleStatus 'AutoLogon' 'WOULD-CHANGE' 'disable auto-logon, remove DefaultPassword'; return }
    Set-RegValue -Path $key -Name 'AutoAdminLogon' -Value '0' -Type 'String'
    foreach ($v in 'DefaultPassword', 'AutoLogonCount') {
        if ($null -ne (Get-ItemProperty -Path $key -Name $v -ErrorAction SilentlyContinue)) {
            Remove-ItemProperty -Path $key -Name $v -ErrorAction SilentlyContinue
            Write-Log ("Removed Winlogon\{0}." -f $v)
        }
    }
    Write-Log 'NOTE: if auto-logon was configured via Sysinternals Autologon/netplwiz, an LSA secret may remain; rerun that tool to clear it if Rapid7 still flags the asset.'
    Set-ModuleStatus 'AutoLogon' 'CHANGED' 'auto-logon disabled, cleartext password removed'
}

# ==============================================================================
# 6. Google Chrome
# ==============================================================================
function Invoke-ChromeUpdate {
    $exe = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
             "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe") |
           Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    if (-not $exe) {
        Write-Log 'Chrome not installed.'
        Set-ModuleStatus 'Chrome' 'N/A' 'not installed'
        return
    }
    $before = (Get-Item $exe).VersionInfo.ProductVersion
    Write-Log ("Chrome {0} found at {1}" -f $before, $exe)
    if ($AuditOnly) { Set-ModuleStatus 'Chrome' 'WOULD-CHANGE' ("update from {0} to latest" -f $before); return }
    if (-not [Environment]::Is64BitOperatingSystem) {
        Add-Attention 'Chrome present on a 32-bit OS - update manually (script ships x64 MSI logic only).'
        Set-ModuleStatus 'Chrome' 'ATTENTION' '32-bit OS'
        return
    }
    $msi = Get-RemediationFile -LocalPattern 'googlechromestandaloneenterprise64.msi' `
                               -Url 'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi' `
                               -DownloadName 'googlechromestandaloneenterprise64.msi'
    if (-not $msi) { throw 'No Chrome Enterprise MSI available (download failed or -NoDownload without dependency file).' }
    if (-not (Test-SignedBy -Path $msi -SubjectMatch 'O=Google LLC')) {
        throw "Authenticode check FAILED for $msi - refusing to execute."
    }
    if (-not (Install-Msi -MsiPath $msi -LogName 'chrome-msi.log')) { throw 'Chrome MSI install failed - see chrome-msi.log.' }
    $after = (Get-Item $exe).VersionInfo.ProductVersion
    Write-Log ("Chrome version now {0} (was {1}). Open browsers finish updating on relaunch." -f $after, $before)
    Set-ModuleStatus 'Chrome' 'CHANGED' ("{0} -> {1}" -f $before, $after)
}

# ==============================================================================
# 7. Microsoft Edge
# ==============================================================================
function Invoke-EdgeUpdate {
    $exe = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
             "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") |
           Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    if (-not $exe) {
        Write-Log 'Edge not installed.'
        Set-ModuleStatus 'Edge' 'N/A' 'not installed'
        return
    }
    $before = (Get-Item $exe).VersionInfo.ProductVersion
    Write-Log ("Edge {0} found at {1}" -f $before, $exe)
    if ($AuditOnly) { Set-ModuleStatus 'Edge' 'WOULD-CHANGE' ("update from {0} to latest" -f $before); return }

    $installed = $false
    if ([Environment]::Is64BitOperatingSystem) {
        $msi = Get-RemediationFile -LocalPattern 'MicrosoftEdgeEnterpriseX64.msi' `
                                   -Url 'https://go.microsoft.com/fwlink/?linkid=2093437' `
                                   -DownloadName 'MicrosoftEdgeEnterpriseX64.msi'
        if ($msi -and (Test-SignedBy -Path $msi -SubjectMatch 'O=Microsoft Corporation')) {
            $installed = Install-Msi -MsiPath $msi -LogName 'edge-msi.log'
        } elseif ($msi) {
            Write-Log 'Authenticode check failed on downloaded Edge MSI - falling back to built-in updater.' 'WARN'
        }
    }
    if (-not $installed) {
        # Fallback: kick the built-in Edge updater tasks.
        $tasks = @(Get-ScheduledTask -TaskName 'MicrosoftEdgeUpdate*' -ErrorAction SilentlyContinue)
        if ($tasks.Count -eq 0) { throw 'Edge MSI unavailable and no MicrosoftEdgeUpdate scheduled tasks found.' }
        $tasks | ForEach-Object { Start-ScheduledTask -InputObject $_ }
        Write-Log ("Started {0} MicrosoftEdgeUpdate task(s); waiting up to 10 minutes for a version change ..." -f $tasks.Count)
        $deadline = (Get-Date).AddMinutes(10)
        do {
            Start-Sleep -Seconds 30
            $now = (Get-Item $exe -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
        } until (($now -ne $before) -or ((Get-Date) -gt $deadline))
    }
    $after = (Get-Item $exe).VersionInfo.ProductVersion
    Write-Log ("Edge version now {0} (was {1}). Open browsers finish updating on relaunch." -f $after, $before)
    if (-not $installed -and ($after -eq $before)) {
        Add-Attention 'Edge updater was kicked but the version did not change within 10 minutes - verify Edge updates on this machine (WSUS/GPO update policies can block the updater).'
        Set-ModuleStatus 'Edge' 'ATTENTION' ("still {0} after updater run" -f $after)
        return
    }
    Set-ModuleStatus 'Edge' 'CHANGED' ("{0} -> {1}" -f $before, $after)
}

# ==============================================================================
# 8. Adobe Acrobat / Reader
# ==============================================================================
function Invoke-AdobeAcrobatUpdate {
    $adobeApps = @(Get-InstalledApps | Where-Object { $_.DisplayName -match 'Adobe (Acrobat|Reader)' })
    if ($adobeApps.Count -eq 0) {
        Write-Log 'No Adobe Acrobat/Reader installed.'
        Set-ModuleStatus 'AdobeAcrobat' 'N/A' 'not installed'
        return
    }
    foreach ($a in $adobeApps) { Write-Log ("Found: {0} {1}" -f $a.DisplayName, $a.DisplayVersion) }
    $rum = @("${env:ProgramFiles(x86)}\Common Files\Adobe\ARM\1.0\RemoteUpdateManager.exe",
             "$env:ProgramFiles\Common Files\Adobe\ARM\1.0\RemoteUpdateManager.exe") |
           Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    if (-not $rum) {
        Add-Attention 'Adobe Acrobat/Reader installed but RemoteUpdateManager.exe not found - patch via Endpoint Central Patch Mgmt or reinstall latest Acrobat.'
        Set-ModuleStatus 'AdobeAcrobat' 'ATTENTION' 'RUM missing'
        return
    }
    if ($AuditOnly) { Set-ModuleStatus 'AdobeAcrobat' 'WOULD-CHANGE' 'run RemoteUpdateManager'; return }
    Write-Log ("Running Adobe RemoteUpdateManager: {0}" -f $rum)
    $p = Start-Process -FilePath $rum -Wait -PassThru -WindowStyle Hidden
    Write-Log ("RemoteUpdateManager exit code {0} (0 = success/nothing to do)." -f $p.ExitCode)
    if ($p.ExitCode -eq 0) {
        Set-ModuleStatus 'AdobeAcrobat' 'CHANGED' 'RUM run completed'
    } else {
        Add-Attention ("Adobe RUM returned {0} - check %TEMP%\AdobeARM.log / retry; updates may require Acrobat to be closed." -f $p.ExitCode)
        Set-ModuleStatus 'AdobeAcrobat' 'ATTENTION' ("RUM exit {0}" -f $p.ExitCode)
    }
}

# ==============================================================================
# 9. Microsoft Office (Click-to-Run)
# ==============================================================================
function Invoke-OfficeC2RUpdate {
    $cfg = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
    if (-not (Test-Path $cfg)) {
        Write-Log 'No Click-to-Run Office installation.'
        Set-ModuleStatus 'Office' 'N/A' 'no C2R Office'
        return
    }
    $ver = (Get-ItemProperty -Path $cfg -ErrorAction SilentlyContinue).VersionToReport
    Write-Log ("Office C2R build {0} found." -f $ver)
    $client = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) |
              Where-Object { $_ } |
              ForEach-Object { Join-Path $_ 'Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe' } |
              Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $client) {
        Add-Attention 'Office C2R present but OfficeC2RClient.exe not found - patch Office manually.'
        Set-ModuleStatus 'Office' 'ATTENTION' 'OfficeC2RClient missing'
        return
    }
    if ($AuditOnly) { Set-ModuleStatus 'Office' 'WOULD-CHANGE' ("trigger C2R update from build {0}" -f $ver); return }
    Write-Log 'Triggering Click-to-Run update (silent, no forced app shutdown) ...'
    Start-Process -FilePath $client -ArgumentList '/update', 'user', 'updatepromptuser=false', 'displaylevel=false', 'forceappshutdown=false' -WindowStyle Hidden
    Write-Log 'Update runs in the background; if Office apps are open it completes once they close.'
    Set-ModuleStatus 'Office' 'CHANGED' 'C2R update triggered'
}

# ==============================================================================
# 10. ASP.NET Core runtimes (incl. CVE-2025-55315 + 2026 CVE set)
# ==============================================================================
function Invoke-AspNetCoreUpdate {
    $roots = @()
    if ($env:ProgramFiles)        { $roots += (Join-Path $env:ProgramFiles 'dotnet') }
    if (${env:ProgramFiles(x86)}) { $roots += (Join-Path ${env:ProgramFiles(x86)} 'dotnet') }
    $runtimes = @()
    foreach ($root in ($roots | Where-Object { Test-Path $_ })) {
        $shared = Join-Path $root 'shared\Microsoft.AspNetCore.App'
        if (-not (Test-Path $shared)) { continue }
        foreach ($dir in (Get-ChildItem -Path $shared -Directory -ErrorAction SilentlyContinue)) {
            $core = $dir.Name.Split('-')[0]
            try { $v = [Version]$core } catch { continue }
            $runtimes += [pscustomobject]@{ Raw = $dir.Name; Version = $v; Channel = ('{0}.{1}' -f $v.Major, $v.Minor); Root = $root }
        }
    }
    if ($runtimes.Count -eq 0) {
        Write-Log 'No machine-wide ASP.NET Core runtimes found.'
        Set-ModuleStatus 'AspNetCore' 'N/A' 'no runtimes'
        return
    }
    foreach ($rt in $runtimes) { Write-Log ("Found Microsoft.AspNetCore.App {0} ({1})" -f $rt.Raw, $rt.Root) }

    $supported = @('8.0', '9.0', '10.0')
    $eol = @($runtimes | Where-Object { $supported -notcontains $_.Channel })
    foreach ($e in $eol) {
        Add-Attention ("ASP.NET Core {0} is OUT OF SUPPORT (Rapid7 'Obsolete Version'). No patch exists - app owner must move the app to .NET 8/10, then uninstall the old runtime." -f $e.Raw)
    }

    $channels = @($runtimes | Where-Object { $supported -contains $_.Channel } | Select-Object -ExpandProperty Channel -Unique)
    if ($channels.Count -eq 0) {
        Set-ModuleStatus 'AspNetCore' 'ATTENTION' 'only EOL runtimes present'
        return
    }
    if ($AuditOnly) { Set-ModuleStatus 'AspNetCore' 'WOULD-CHANGE' ("update Hosting Bundle for: {0}" -f ($channels -join ', ')); return }
    $failed = 0
    foreach ($ch in $channels) {
        $exe = Get-RemediationFile -LocalPattern ("dotnet-hosting-{0}*-win.exe" -f $ch) `
                                   -Url ("https://aka.ms/dotnet/{0}/dotnet-hosting-win.exe" -f $ch) `
                                   -DownloadName ("dotnet-hosting-{0}-latest-win.exe" -f $ch)
        if (-not $exe) { $failed++; continue }
        if (-not (Test-SignedBy -Path $exe -SubjectMatch 'O=Microsoft Corporation')) {
            Write-Log ("Authenticode check FAILED for {0} - skipping." -f $exe) 'ERROR'
            $failed++; continue
        }
        $instLog = Join-Path $LogDir ("hostingbundle-{0}.log" -f $ch)
        Write-Log ("Installing latest ASP.NET Core Hosting Bundle ({0}) ..." -f $ch)
        $p = Start-Process -FilePath $exe -ArgumentList '/install', '/quiet', '/norestart', '/log', $instLog -Wait -PassThru
        Write-Log ("Hosting Bundle {0} installer exit code {1}" -f $ch, $p.ExitCode)
        if     ($p.ExitCode -eq 3010) { $Script:RebootNeeded = $true }
        elseif ($p.ExitCode -eq 1638) { Write-Log 'Same or newer bundle already installed - OK.' }
        elseif ($p.ExitCode -ne 0)    { $failed++ }
    }
    if ((Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue) -and ($channels.Count -gt 0) -and ($failed -lt $channels.Count)) {
        Write-Log 'IIS detected - running iisreset so worker processes load the patched runtime ...'
        try { & (Join-Path $env:WINDIR 'System32\iisreset.exe') /restart | ForEach-Object { Write-Log ("  iisreset: {0}" -f $_) } }
        catch { Write-Log ("iisreset failed: {0}" -f $_.Exception.Message) 'WARN' }
    }
    if ($failed -gt 0) { throw "$failed Hosting Bundle install(s) failed." }
    Set-ModuleStatus 'AspNetCore' 'CHANGED' ("Hosting Bundles updated: {0}" -f ($channels -join ', '))
}

# ==============================================================================
# 11. 7-Zip
# ==============================================================================
function Invoke-SevenZipUpdate {
    $apps = @(Get-InstalledApps | Where-Object { $_.DisplayName -like '7-Zip*' })
    if ($apps.Count -eq 0) {
        Write-Log '7-Zip not installed.'
        Set-ModuleStatus 'SevenZip' 'N/A' 'not installed'
        return
    }
    $before = ($apps | Select-Object -First 1).DisplayVersion
    Write-Log ("Found {0} (version {1})" -f ($apps | Select-Object -First 1).DisplayName, $before)
    $viaWinget = Invoke-WingetUpgrade -Id '7zip.7zip'
    if ($viaWinget) {
        Set-ModuleStatus 'SevenZip' $(if ($AuditOnly) { 'WOULD-CHANGE' } else { 'CHANGED' }) 'via winget'
        return
    }
    if ($AuditOnly) { Set-ModuleStatus 'SevenZip' 'WOULD-CHANGE' ("update from {0}" -f $before); return }
    if (-not [Environment]::Is64BitOperatingSystem) {
        Add-Attention '7-Zip on a 32-bit OS - update manually.'
        Set-ModuleStatus 'SevenZip' 'ATTENTION' '32-bit OS'
        return
    }
    # No winget: fetch the newest x64 build from 7-zip.org. Keep the same
    # installer type (MSI vs EXE) as the existing install.
    $isMsi = [bool]($apps | Where-Object { $_.WindowsInstaller -eq 1 -or $_.PSChildName -match '^\{.*\}$' })
    $ext = if ($isMsi) { 'msi' } else { 'exe' }
    $local = @(Get-ChildItem -Path $ScriptDir -Filter ("7z*-x64.{0}" -f $ext) -File -ErrorAction SilentlyContinue) | Sort-Object Name | Select-Object -Last 1
    $file = $null
    if ($local) {
        $file = $local.FullName
        Write-Log ("Using dependency file: {0}" -f $file)
    } elseif ($NoDownload) {
        Add-Attention '7-Zip outdated, but no dependency installer and -NoDownload set.'
        Set-ModuleStatus 'SevenZip' 'ATTENTION' 'no installer available'
        return
    } else {
        $page = (Invoke-WebRequest -Uri 'https://www.7-zip.org/download.html' -UseBasicParsing).Content
        $builds = [regex]::Matches($page, 'a/7z(\d{4})-x64\.' + $ext) | ForEach-Object { [int]$_.Groups[1].Value }
        if (-not $builds) { throw 'Could not parse the 7-zip.org download page for the latest x64 build.' }
        $latest = ($builds | Measure-Object -Maximum).Maximum
        $latestVer = [Version]('{0}.{1:D2}' -f [math]::Floor($latest / 100), ($latest % 100))
        $curVer = $null; try { $curVer = [Version]$before } catch { }
        if ($curVer -and ($curVer -ge $latestVer)) {
            Write-Log ("7-Zip {0} is already the newest published build." -f $before)
            Set-ModuleStatus 'SevenZip' 'OK' ("{0} is current" -f $before)
            return
        }
        $url  = ('https://www.7-zip.org/a/7z{0}-x64.{1}' -f $latest, $ext)
        $file = Join-Path $env:TEMP ('7z{0}-x64.{1}' -f $latest, $ext)
        Write-Log ("Downloading {0} ..." -f $url)
        Invoke-WebRequest -Uri $url -OutFile $file -UseBasicParsing
        Write-Log 'NOTE: 7-Zip installers are not Authenticode-signed; trust anchor is HTTPS to 7-zip.org (or ship a vetted installer as a dependency file).'
    }
    if ($isMsi) {
        if (-not (Install-Msi -MsiPath $file -LogName '7zip-msi.log')) { throw '7-Zip MSI install failed.' }
    } else {
        $p = Start-Process -FilePath $file -ArgumentList '/S' -Wait -PassThru
        if ($p.ExitCode -ne 0) { throw "7-Zip installer exit code $($p.ExitCode)." }
    }
    $after = (@(Get-InstalledApps | Where-Object { $_.DisplayName -like '7-Zip*' }) | Select-Object -First 1).DisplayVersion
    Write-Log ("7-Zip version now {0} (was {1})." -f $after, $before)
    Set-ModuleStatus 'SevenZip' 'CHANGED' ("{0} -> {1}" -f $before, $after)
}

# ==============================================================================
# 12. Visual Studio
# ==============================================================================
function Invoke-VisualStudioUpdate {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $vsinst  = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vs_installer.exe"
    if (-not (Test-Path $vswhere) -or -not (Test-Path $vsinst)) {
        Write-Log 'Visual Studio installer not present.'
        Set-ModuleStatus 'VisualStudio' 'N/A' 'not installed'
        return
    }
    $instances = @()
    try { $instances = @((& $vswhere -all -products * -format json | Out-String | ConvertFrom-Json)) } catch { }
    if ($instances.Count -eq 0) {
        Write-Log 'No Visual Studio instances found by vswhere.'
        Set-ModuleStatus 'VisualStudio' 'N/A' 'no instances'
        return
    }
    foreach ($i in $instances) { Write-Log ("Found {0} {1}" -f $i.displayName, $i.installationVersion) }
    if ($AuditOnly) { Set-ModuleStatus 'VisualStudio' 'WOULD-CHANGE' 'vs_installer updateall'; return }
    Write-Log 'Running vs_installer updateall --quiet --norestart (this can take 30+ minutes) ...'
    $p = Start-Process -FilePath $vsinst -ArgumentList 'updateall', '--quiet', '--norestart' -PassThru
    if (-not $p.WaitForExit(3600000)) {
        Write-Log 'vs_installer still running after 60 min - leaving it to finish in the background.' 'WARN'
        Add-Attention 'Visual Studio update still in progress at script end - verify version after it completes.'
        Set-ModuleStatus 'VisualStudio' 'ATTENTION' 'update still running'
        return
    }
    Write-Log ("vs_installer exit code {0}" -f $p.ExitCode)
    if ($p.ExitCode -eq 3010) { $Script:RebootNeeded = $true }
    elseif ($p.ExitCode -ne 0) { throw "vs_installer updateall failed with exit code $($p.ExitCode)." }
    Set-ModuleStatus 'VisualStudio' 'CHANGED' 'updateall completed'
}

# ==============================================================================
# 13. Store apps (Notepad CVE-2026-20841 etc.)
# ==============================================================================
function Invoke-StoreAppsUpdate {
    if ($AuditOnly) { Set-ModuleStatus 'StoreApps' 'WOULD-CHANGE' 'trigger Store update scan'; return }
    try {
        $mdm = Get-CimInstance -Namespace 'root\cimv2\mdm\dmmap' -ClassName 'MDM_EnterpriseModernAppManagement_AppManagement01' -ErrorAction Stop
        $mdm | Invoke-CimMethod -MethodName 'UpdateScanMethod' | Out-Null
        Write-Log 'Store app update scan triggered (covers Notepad, Paint and other inbox apps). Updates apply in the background.'
        Set-ModuleStatus 'StoreApps' 'CHANGED' 'update scan triggered'
    } catch {
        Write-Log ("Store update scan unavailable on this SKU ({0}) - Notepad updates arrive via the Store when available." -f $_.Exception.Message) 'WARN'
        Set-ModuleStatus 'StoreApps' 'N/A' 'MDM bridge unavailable'
    }
}

# ==============================================================================
# 14. Oracle Java
# ==============================================================================
function Invoke-JavaCheck {
    $java = @(Get-InstalledApps | Where-Object { $_.DisplayName -match '^(Java \d|Java\(TM\)|Oracle Java|Java SE Development Kit|JDK)' })
    if ($java.Count -eq 0) {
        Write-Log 'No Oracle Java installations found.'
        Set-ModuleStatus 'Java' 'N/A' 'not installed'
        return
    }
    foreach ($j in $java) { Write-Log ("Found: {0} {1}" -f $j.DisplayName, $j.DisplayVersion) }
    $jre = @($java | Where-Object { $_.DisplayName -match '^Java (8|\d+ Update)|^Java\(TM\)' })
    $done = $false
    if ($jre.Count -gt 0) {
        $r = Invoke-WingetUpgrade -Id 'Oracle.JavaRuntimeEnvironment'
        if ($r) { $done = $true }
    }
    if ($done -and -not $AuditOnly) {
        Set-ModuleStatus 'Java' 'CHANGED' 'JRE updated via winget'
    } else {
        Add-Attention ("Oracle Java present ({0}) - apply the latest quarterly CPU release manually (Oracle downloads require a licensed account), or migrate the dependent app to Eclipse Temurin." -f (($java | ForEach-Object { $_.DisplayName + ' ' + $_.DisplayVersion }) -join '; '))
        Set-ModuleStatus 'Java' 'ATTENTION' 'manual CPU update needed'
    }
}

# ==============================================================================
# 15. TeamViewer
# ==============================================================================
function Invoke-TeamViewerUpdate {
    $tv = @(Get-InstalledApps | Where-Object { $_.DisplayName -like 'TeamViewer*' })
    if ($tv.Count -eq 0) {
        Write-Log 'TeamViewer not installed.'
        Set-ModuleStatus 'TeamViewer' 'N/A' 'not installed'
        return
    }
    Write-Log ("Found: {0} {1}" -f $tv[0].DisplayName, $tv[0].DisplayVersion)
    $r = Invoke-WingetUpgrade -Id 'TeamViewer.TeamViewer'
    if ($r) {
        Set-ModuleStatus 'TeamViewer' $(if ($AuditOnly) { 'WOULD-CHANGE' } else { 'CHANGED' }) 'via winget'
    } else {
        Add-Attention ("TeamViewer {0} present and winget unavailable - update via the TeamViewer Management Console or latest full installer." -f $tv[0].DisplayVersion)
        Set-ModuleStatus 'TeamViewer' 'ATTENTION' 'manual update needed'
    }
}

# ==============================================================================
# 16. Rapid7 Insight Agent
# ==============================================================================
function Invoke-InsightAgentCheck {
    $svc = Get-Service -Name 'ir_agent' -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Log 'Rapid7 Insight Agent service not present.'
        Set-ModuleStatus 'InsightAgent' 'N/A' 'not installed'
        return
    }
    $exe = @(Get-ChildItem -Path (Join-Path $env:ProgramFiles 'Rapid7\Insight Agent') -Filter 'ir_agent.exe' -Recurse -ErrorAction SilentlyContinue) | Select-Object -First 1
    $ver = if ($exe) { $exe.VersionInfo.ProductVersion } else { 'unknown' }
    Write-Log ("Insight Agent version: {0}" -f $ver)
    if ($AuditOnly) { Set-ModuleStatus 'InsightAgent' 'OK' ("version {0} (audit)" -f $ver); return }
    Write-Log 'Restarting ir_agent so it checks in and self-updates from the Insight platform ...'
    try { Restart-Service -Name 'ir_agent' -Force -ErrorAction Stop } catch { Write-Log ("Restart failed: {0}" -f $_.Exception.Message) 'WARN' }
    Write-Log 'If the agent CVEs persist after the next scan, verify auto-update is enabled in the Insight Agent management console.'
    Set-ModuleStatus 'InsightAgent' 'CHANGED' ("service bounced (version {0})" -f $ver)
}

# ==============================================================================
# 17. Windows Update (Windows / .NET Framework / SQL GDR / Defender)
# ==============================================================================
function Invoke-WindowsUpdateModule {
    if ($SkipWindowsUpdate) {
        Write-Log 'Skipped via -SkipWindowsUpdate.'
        Set-ModuleStatus 'WindowsUpdate' 'SKIPPED' 'via -SkipWindowsUpdate'
        return
    }
    # Opt into Microsoft Update so Office MSI, SQL Server and .NET updates flow too.
    try {
        $sm = New-Object -ComObject 'Microsoft.Update.ServiceManager'
        $sm.AddService2('7971f918-a847-4430-9279-4a52d1efe18d', 7, '') | Out-Null
        Write-Log 'Microsoft Update service registration confirmed.'
    } catch {
        Write-Log ("Microsoft Update opt-in failed ({0}) - continuing with default source." -f $_.Exception.Message) 'WARN'
    }
    $session  = New-Object -ComObject 'Microsoft.Update.Session'
    $searcher = $session.CreateUpdateSearcher()
    Write-Log 'Searching for missing software updates (this can take several minutes) ...'
    $result = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
    # Feature upgrades (category 3689bdc8-...) are out of scope for a vuln fix run.
    $updates = @()
    foreach ($u in $result.Updates) {
        $isUpgrade = $false
        foreach ($cat in $u.Categories) { if ($cat.CategoryID -eq '3689bdc8-b205-4af4-8d4a-a63924c5e9d5') { $isUpgrade = $true } }
        if (-not $isUpgrade) { $updates += $u }
    }
    if ($updates.Count -eq 0) {
        Write-Log 'No applicable updates - Windows is fully patched.'
        Set-ModuleStatus 'WindowsUpdate' 'OK' 'no missing updates'
        return
    }
    foreach ($u in $updates) { Write-Log ("Missing: {0}" -f $u.Title) }
    if ($AuditOnly) { Set-ModuleStatus 'WindowsUpdate' 'WOULD-CHANGE' ("{0} update(s) missing" -f $updates.Count); return }

    $coll = New-Object -ComObject 'Microsoft.Update.UpdateColl'
    foreach ($u in $updates) {
        if (-not $u.EulaAccepted) { try { $u.AcceptEula() } catch { } }
        [void]$coll.Add($u)
    }
    Write-Log ("Downloading {0} update(s) ..." -f $coll.Count)
    $downloader = $session.CreateUpdateDownloader()
    $downloader.Updates = $coll
    $dl = $downloader.Download()
    Write-Log ("Download result code: {0} (2 = success)" -f $dl.ResultCode)

    $toInstall = New-Object -ComObject 'Microsoft.Update.UpdateColl'
    foreach ($u in $coll) { if ($u.IsDownloaded) { [void]$toInstall.Add($u) } }
    if ($toInstall.Count -eq 0) { throw 'No updates downloaded successfully.' }
    Write-Log ("Installing {0} update(s) ..." -f $toInstall.Count)
    $installer = $session.CreateUpdateInstaller()
    $installer.Updates = $toInstall
    $inst = $installer.Install()
    for ($i = 0; $i -lt $toInstall.Count; $i++) {
        Write-Log ("  {0} -> result {1} (2 = OK)" -f $toInstall.Item($i).Title, $inst.GetUpdateResult($i).ResultCode)
    }
    if ($inst.RebootRequired) { $Script:RebootNeeded = $true }
    $failedCount = 0
    for ($i = 0; $i -lt $toInstall.Count; $i++) { if ($inst.GetUpdateResult($i).ResultCode -ge 4) { $failedCount++ } }
    if ($failedCount -gt 0) {
        Add-Attention ("{0} Windows update(s) failed to install - rerun after reboot or investigate WU logs." -f $failedCount)
        Set-ModuleStatus 'WindowsUpdate' 'ATTENTION' ("{0} installed, {1} failed" -f ($toInstall.Count - $failedCount), $failedCount)
    } else {
        Set-ModuleStatus 'WindowsUpdate' 'CHANGED' ("{0} update(s) installed" -f $toInstall.Count)
    }
    Write-Log 'NOTE: the June 2026 Secure Boot bypass fixes (e.g. CVE-2026-8863) may additionally require the staged UEFI revocation steps from the MSRC advisory after this CU is installed and the machine rebooted.'
}

# ==============================================================================
# 18. MariaDB (report only)
# ==============================================================================
function Invoke-MariaDbCheck {
    $maria = @(Get-InstalledApps | Where-Object { $_.DisplayName -like 'MariaDB*' })
    $svcs  = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
               Where-Object { $_.PathName -match 'mysqld' -or $_.Name -match 'MariaDB|MySQL' })
    if (($maria.Count -eq 0) -and ($svcs.Count -eq 0)) {
        Write-Log 'MariaDB not installed.'
        Set-ModuleStatus 'MariaDb' 'N/A' 'not installed'
        return
    }
    foreach ($m in $maria) { Write-Log ("Found: {0} {1}" -f $m.DisplayName, $m.DisplayVersion) }
    foreach ($s in $svcs)  { Write-Log ("Service: {0} ({1}) -> {2}" -f $s.Name, $s.State, $s.PathName) }
    Add-Attention 'MariaDB present - 11 CVEs (incl. CVE-2026-44170, CVSS 9.8) require upgrading the server to the latest release of its series. NOT automated: back up databases, then install the newest MariaDB MSI of the same major series (in-place upgrade) in a maintenance window.'
    Set-ModuleStatus 'MariaDb' 'ATTENTION' 'manual DB engine upgrade required'
}

# ==============================================================================
# 19. Fortinet FortiClient (report only)
# ==============================================================================
function Invoke-FortiClientCheck {
    $fc = @(Get-InstalledApps | Where-Object { $_.DisplayName -like 'FortiClient*' })
    if ($fc.Count -eq 0) {
        Write-Log 'FortiClient not installed.'
        Set-ModuleStatus 'FortiClient' 'N/A' 'not installed'
        return
    }
    Write-Log ("Found: {0} {1}" -f $fc[0].DisplayName, $fc[0].DisplayVersion)
    Add-Attention ("FortiClient {0} has 5 open CVEs (incl. fortips driver flaws) - upgrade via FortiClient EMS or a fixed installer from the Fortinet support portal (login required); patched builds are not publicly downloadable." -f $fc[0].DisplayVersion)
    Set-ModuleStatus 'FortiClient' 'ATTENTION' 'manual upgrade via EMS/support portal'
}

# ==============================================================================
# 20. Apache Log4j Core (report only)
# ==============================================================================
function Invoke-Log4jScan {
    $scanRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, 'C:\inetpub') |
                 Where-Object { $_ -and (Test-Path $_) }
    $jars = @()
    foreach ($root in $scanRoots) {
        $jars += @(Get-ChildItem -Path $root -Recurse -Filter 'log4j-core-*.jar' -File -ErrorAction SilentlyContinue)
        $jars += @(Get-ChildItem -Path $root -Recurse -Filter 'log4j-1.*.jar'    -File -ErrorAction SilentlyContinue)
    }
    if ($jars.Count -eq 0) {
        Write-Log ("No log4j jars found under: {0}" -f ($scanRoots -join ', '))
        Set-ModuleStatus 'Log4j' 'OK' 'no jars found in scanned roots'
        return
    }
    foreach ($j in $jars) { Add-Attention ("Log4j jar: {0}" -f $j.FullName) }
    Add-Attention 'Log4j Core CVEs (CVE-2021-44832 + 2026 set) are fixed by upgrading the bundled log4j-core jar inside the OWNING APPLICATION to the latest 2.x release - coordinate with the app owner; do not swap jars blind.'
    Set-ModuleStatus 'Log4j' 'ATTENTION' ("{0} jar(s) reported" -f $jars.Count)
}

# ==============================================================================
# 21. VNC remote control service
# ==============================================================================
function Invoke-VncCheck {
    $vncSvcNames = 'tvnserver', 'uvnc_service', 'vncserver', 'winvnc', 'RealVNC'
    $svcs = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
              Where-Object { ($vncSvcNames -contains $_.Name) -or ($_.DisplayName -match 'VNC') })
    $apps = @(Get-InstalledApps | Where-Object { $_.DisplayName -match 'VNC' })
    if (($svcs.Count -eq 0) -and ($apps.Count -eq 0)) {
        Write-Log 'No VNC server detected.'
        Set-ModuleStatus 'Vnc' 'OK' 'not present'
        return
    }
    foreach ($s in $svcs) { Write-Log ("VNC service: {0} ({1})" -f $s.Name, $s.State) }
    foreach ($a in $apps) { Write-Log ("VNC app: {0} {1}" -f $a.DisplayName, $a.DisplayVersion) }
    if (-not $RemoveVNC) {
        Add-Attention 'VNC remote control service installed - if unsanctioned, rerun with -RemoveVNC to uninstall it (or remove manually); if sanctioned, document the exception in Rapid7.'
        Set-ModuleStatus 'Vnc' 'ATTENTION' 'present (report-only; use -RemoveVNC to uninstall)'
        return
    }
    if ($AuditOnly) { Set-ModuleStatus 'Vnc' 'WOULD-CHANGE' 'uninstall VNC'; return }
    $removed = 0
    foreach ($a in $apps) {
        $cmd = if ($a.QuietUninstallString) { $a.QuietUninstallString } else { $a.UninstallString }
        if (-not $cmd) { continue }
        if ($cmd -notmatch '(?i)msiexec' -and $cmd -notmatch '(?i)/S|/silent|/quiet|/qn') { $cmd = "$cmd /S" }
        if ($cmd -match '(?i)msiexec' -and $cmd -notmatch '(?i)/qn') { $cmd = ($cmd -replace '(?i)/I', '/X') + ' /qn /norestart' }
        Write-Log ("Uninstalling {0}: {1}" -f $a.DisplayName, $cmd)
        try {
            $p = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', $cmd -Wait -PassThru -WindowStyle Hidden
            Write-Log ("Uninstall exit code {0}" -f $p.ExitCode)
            if ($p.ExitCode -in 0, 3010, 1605) { $removed++ }
            if ($p.ExitCode -eq 3010) { $Script:RebootNeeded = $true }
        } catch { Write-Log ("Uninstall failed: {0}" -f $_.Exception.Message) 'ERROR' }
    }
    Set-ModuleStatus 'Vnc' 'CHANGED' ("{0} VNC product(s) uninstalled" -f $removed)
}

# ==============================================================================
# 22. SQL Server exposure note
# ==============================================================================
function Invoke-SqlServerCheck {
    $sql = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -match '^MSSQL(\$|SERVER)' })
    if ($sql.Count -eq 0) {
        Write-Log 'No SQL Server engine service present.'
        Set-ModuleStatus 'SqlServer' 'N/A' 'not installed'
        return
    }
    foreach ($s in $sql) { Write-Log ("SQL Server service: {0} ({1})" -f $s.Name, $s.State) }
    Add-Attention 'SQL Server present: 2026 RCE/EoP GDRs are delivered by the WindowsUpdate module once Microsoft Update is opted in (done in this run) - verify build after patching. For the "Database Open Access" finding, restrict TCP 1433 to needed subnets via firewall or bind to specific interfaces.'
    Set-ModuleStatus 'SqlServer' 'ATTENTION' 'verify GDR build + network exposure'
}

# ==============================================================================
# MAIN
# ==============================================================================
$exitCode = 0
try {
    Write-Log '======================================================================'
    Write-Log ("Rapid7 all-in-one remediation starting on {0}" -f $env:COMPUTERNAME)
    Write-Log ("Options: AuditOnly={0} NoDownload={1} SkipWindowsUpdate={2} SkipTlsHardening={3} KeepAutoLogon={4} RemoveVNC={5} RestartServices={6} SkipModules=[{7}]" -f `
        [bool]$AuditOnly, [bool]$NoDownload, [bool]$SkipWindowsUpdate, [bool]$SkipTlsHardening,
        [bool]$KeepAutoLogon, [bool]$RemoveVNC, [bool]$RestartServices, ($SkipModules -join ','))
    Write-Log 'POLICY: AutoDesk AutoCAD findings are intentionally EXCLUDED - no Autodesk software is touched by this script.'

    $isAdmin = $false
    try {
        $identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        $isAdmin  = $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { }
    if (-not $isAdmin -and -not $AuditOnly) {
        Write-Log 'This script must run elevated (SYSTEM or administrator).' 'ERROR'
        exit 1
    }

    # Quick, low-risk hardening first; slow installers last.
    Invoke-Module 'CertPadding'   { Invoke-CertPaddingFix }
    Invoke-Module 'SmbSigning'    { Invoke-SmbSigningFix }
    Invoke-Module 'TlsHardening'  { Invoke-TlsHardening }
    Invoke-Module 'LockoutPolicy' { Invoke-LockoutPolicyFix }
    Invoke-Module 'AutoLogon'     { Invoke-AutoLogonFix }
    Invoke-Module 'InsightAgent'  { Invoke-InsightAgentCheck }
    Invoke-Module 'StoreApps'     { Invoke-StoreAppsUpdate }
    Invoke-Module 'Chrome'        { Invoke-ChromeUpdate }
    Invoke-Module 'Edge'          { Invoke-EdgeUpdate }
    Invoke-Module 'AdobeAcrobat'  { Invoke-AdobeAcrobatUpdate }
    Invoke-Module 'Office'        { Invoke-OfficeC2RUpdate }
    Invoke-Module 'AspNetCore'    { Invoke-AspNetCoreUpdate }
    Invoke-Module 'SevenZip'      { Invoke-SevenZipUpdate }
    Invoke-Module 'Java'          { Invoke-JavaCheck }
    Invoke-Module 'TeamViewer'    { Invoke-TeamViewerUpdate }
    Invoke-Module 'MariaDb'       { Invoke-MariaDbCheck }
    Invoke-Module 'FortiClient'   { Invoke-FortiClientCheck }
    Invoke-Module 'Log4j'         { Invoke-Log4jScan }
    Invoke-Module 'Vnc'           { Invoke-VncCheck }
    Invoke-Module 'SqlServer'     { Invoke-SqlServerCheck }
    Invoke-Module 'VisualStudio'  { Invoke-VisualStudioUpdate }
    Invoke-Module 'WindowsUpdate' { Invoke-WindowsUpdateModule }

    # ----------------------------- SUMMARY -----------------------------------
    Write-Log '----------------------------- SUMMARY --------------------------------'
    foreach ($m in $Script:ModuleStatus) {
        Write-Log ("{0,-14} {1,-13} {2}" -f $m.Name, $m.Status, $m.Detail)
    }
    $failedModules = @($Script:ModuleStatus | Where-Object { $_.Status -eq 'FAILED' })
    $wouldChange   = @($Script:ModuleStatus | Where-Object { $_.Status -eq 'WOULD-CHANGE' })

    if ($AuditOnly) {
        if (($wouldChange.Count -gt 0) -or ($Script:Attention.Count -gt 0) -or ($failedModules.Count -gt 0)) { $exitCode = 2 }
        else { $exitCode = 0 }
    }
    elseif ($failedModules.Count -gt 0)      { $exitCode = 1 }
    elseif ($Script:Attention.Count -gt 0)   { $exitCode = 2 }
    elseif ($Script:RebootNeeded)            { $exitCode = 3010 }
    else                                     { $exitCode = 0 }

    if ($Script:Attention.Count -gt 0) {
        Write-Log ("Items needing manual follow-up: {0}" -f $Script:Attention.Count)
    }
    $resultText = switch ($exitCode) {
        0     { 'COMPLIANT / REMEDIATED' }
        3010  { 'REMEDIATED - RESTART REQUIRED' }
        2     { 'ATTENTION REQUIRED - MANUAL FOLLOW-UP ITEMS IN LOG' }
        default { 'FAILED - AT LEAST ONE MODULE ERRORED' }
    }
    Write-Log ("RESULT: {0} (exit code {1})" -f $resultText, $exitCode)
}
catch {
    Write-Log ("Unhandled error: {0}" -f $_.Exception.Message) 'ERROR'
    Write-Log ($_.ScriptStackTrace) 'ERROR'
    $exitCode = 1
}

exit $exitCode
