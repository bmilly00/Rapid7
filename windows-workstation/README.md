# Windows workstation batch — Rapid7 findings (Jan/Feb 2026 scan)

Remediation for the 21 findings reported by Rapid7 InsightVM against this PC.
One master script fixes everything it can fix automatically; each step is also
a standalone script under [`scripts/`](scripts/).

> Everything here targets **your own machine**, requires an **elevated
> PowerShell**, and makes registry **backups before changing anything**.

## Finding → fix mapping

| Rapid7 finding | Fix | Script |
|---|---|---|
| **CVE-2013-3900** — MS13-098 WinVerifyTrust signature padding (RCE) | Opt-in registry value `EnableCertPaddingCheck=1` in both the native and Wow6432Node hives, per [Microsoft's advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900) | [`scripts/01-Fix-CVE-2013-3900.ps1`](scripts/01-Fix-CVE-2013-3900.ps1) (or import [`config/Enable-CertPaddingCheck.reg`](config/Enable-CertPaddingCheck.reg)) |
| **CVE-2026-20819, -20823, -20824, -20825, -20827, -20828, -20829, -20834, -20835, -20839, -20862, -20927, -20936, -20962** (January 2026 Patch Tuesday) and **CVE-2026-21249** (February 2026) | Install the **latest Windows cumulative update** — it supersedes both months. There is no configuration workaround for these; the update *is* the fix | [`scripts/02-Install-WindowsUpdates.ps1`](scripts/02-Install-WindowsUpdates.ps1) (built-in WUA COM API, no modules needed) |
| **TLS/SSL Weak Message Authentication Code Cipher Suites**, **Static Key Ciphers**, **3DES Cipher Suite (SWEET32)**, **Does Not Support Any Strong Cipher Algorithms** | Machine-wide SCHANNEL hardening: disable SSL2/3 + server-side TLS 1.0/1.1, disable NULL/DES/RC2/RC4/3DES ciphers and MD5, and set the cipher-suite order policy to ECDHE + AES-GCM / TLS 1.3 suites only (see [`config/strong-cipher-suites.txt`](config/strong-cipher-suites.txt)) | [`scripts/03-Harden-TLS.ps1`](scripts/03-Harden-TLS.ps1) — rollback via [`scripts/Restore-TlsHardeningBackup.ps1`](scripts/Restore-TlsHardeningBackup.ps1) |
| **Fortinet FortiClient CVE-2025-54660** — info disclosure through debug features (saved VPN password recoverable by a local attacker) | **Version upgrade** per [FG-IR-25-844](https://fortiguard.fortinet.com/psirt/FG-IR-25-844): 7.4.x → **7.4.4+**, 7.2.x → **7.2.11+**, 7.0.x → migrate (no fixed 7.0 build). No config-only fix exists | [`scripts/04-Check-FortiClient.ps1`](scripts/04-Check-FortiClient.ps1) (detects the installed version, optional winget upgrade for the free VPN edition) |
| *(defense in depth, optional)* | Remote Assistance off, SMB1 off + SMB signing required, NTLMv2-only, RDP NLA/TLS — reduces the attack surface of CVE-2026-20824/-20927/-21249 while updates roll out. **Not a substitute for the cumulative update** | [`scripts/05-Optional-Mitigations.ps1`](scripts/05-Optional-Mitigations.ps1) |

## Quick start (the single-script path)

1. Copy this `windows-workstation` folder to the PC (e.g. `C:\Temp\windows-workstation`).
2. Open **PowerShell as administrator** and run:

```powershell
cd C:\Temp\windows-workstation
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Get-ChildItem -Recurse | Unblock-File

# 1) Audit first - shows every non-compliant item, changes nothing:
.\Invoke-Rapid7Remediation.ps1 -ReportOnly

# 2) Fix everything:
.\Invoke-Rapid7Remediation.ps1 -IncludeOptionalMitigations

# 3) Reboot (required for the registry/TLS changes and updates):
Restart-Computer

# 4) After reboot - verify, then re-scan the asset in InsightVM:
.\Invoke-Rapid7Remediation.ps1 -ReportOnly
```

Logs and registry backups for each apply-run land in
`C:\ProgramData\Rapid7Remediation\<timestamp>\`.

### Master script options

| Switch | Effect |
|---|---|
| `-ReportOnly` | Audit every step, change nothing (works without admin) |
| `-IncludeOptionalMitigations` | Also run the defense-in-depth script (05) |
| `-AttemptFortiClientWingetUpgrade` | Try `winget upgrade Fortinet.FortiClientVPN` if a vulnerable version is found |
| `-IncludeCbcCompatSuites` | TLS: also allow ECDHE CBC SHA-2 suites (older-client compatibility; still fixes all four TLS findings) |
| `-DisableLegacyClientTls` | TLS: also disable TLS 1.0/1.1 for *outbound* connections from this PC |
| `-AutoReboot` | Reboot automatically 60 s after the run (abort with `shutdown /a`) |
| `-SkipCertPaddingFix` / `-SkipTlsHardening` / `-SkipFortiClientCheck` / `-SkipWindowsUpdate` | Skip a step |

## Rollback

* **TLS hardening** — full registry restore from the backups taken automatically before any change:

  ```powershell
  .\scripts\Restore-TlsHardeningBackup.ps1 -BackupDirectory 'C:\ProgramData\Rapid7Remediation\<timestamp>\tls-backup'
  # then reboot
  ```

* **CVE-2013-3900** — delete the two `EnableCertPaddingCheck` values (only needed if a legacy signed installer starts showing as unsigned, which the strict check can cause by design).
* **Optional mitigations** — each is a single setting: `fAllowToGetHelp=1` (Remote Assistance), `Set-SmbServerConfiguration -RequireSecuritySignature $false`, `LmCompatibilityLevel=3`, `UserAuthentication=0` (RDP NLA).
* **Windows updates** — uninstallable via Settings → Windows Update → Update history, but don't; they are the actual fix for 15 of the findings.

## Caveats worth knowing

* **Reboot required.** SCHANNEL and WinVerifyTrust changes only take effect after a restart; Rapid7 will keep flagging until you reboot *and* re-scan.
* **TLS findings and ports.** On a workstation these findings are almost always against RDP (TCP 3389), which uses the Windows TLS stack and is fully covered here. If InsightVM shows the finding against a port owned by an app that ships its own TLS (OpenSSL-based services, some agents), that app must be reconfigured separately — check the port in the finding's proof data.
* **Old clients.** After TLS hardening, XP/Vista-era clients, Java 6/7, and anything else without TLS 1.2 + ECDHE-GCM can no longer connect **to** this PC. Use `-IncludeCbcCompatSuites` if you need slightly wider compatibility.
* **CVE-2013-3900 trade-off.** The strict padding check can make rare legacy installers (which stash data in signature padding) show as unsigned. Documented by Microsoft; easily reverted.
* **FortiClient.** If it's EMS-managed, the upgrade has to come from EMS or the full installer — the script detects and reports but can't silently upgrade those. If you don't actually use FortiClient, uninstalling it also clears the finding.
* **Domain GPOs** (if this PC ever joins a domain) override the local cipher-suite policy set here.

## Sources

* [MSRC — CVE-2013-3900 EnableCertPaddingCheck guidance](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900)
* [Fortinet PSIRT FG-IR-25-844 (CVE-2025-54660)](https://fortiguard.fortinet.com/psirt/FG-IR-25-844)
* [Rapid7 vulnerability DB — CVE-2025-54660](https://www.rapid7.com/db/vulnerabilities/fortinet-forticlient-cve-2025-54660/)
* [Microsoft — TLS cipher suites and SCHANNEL configuration](https://learn.microsoft.com/en-us/windows-server/security/tls/manage-tls)
