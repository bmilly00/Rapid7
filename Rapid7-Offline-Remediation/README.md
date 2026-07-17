# Rapid7 Offline Remediation Pack — 12 findings, one UEM deployment

Remediates the following Rapid7 InsightVM findings on a Windows PC **with no
internet access**, via a single **ManageEngine Endpoint Central (UEM) → Custom
Script** configuration. The endpoint needs zero internet: the Endpoint Central
agent delivers the script **and** the installer payloads over your LAN from the
Endpoint Central server (or a Distribution Server for remote sites).

| Rapid7 finding | CVSS | How this pack fixes it |
|---|---|---|
| Microsoft ASP.NET: CVE-2026-45591 (ASP.NET Core DoS) | 7.5 | Installs the **staged** ASP.NET Core Hosting Bundle for every installed release channel older than the staged (fixed) build |
| TLS/SSL Birthday attacks on 64-bit block ciphers (SWEET32) | 7.5 | Disables the 3DES cipher and removes it from the cipher-suite order |
| CIFS Account Lockout Policy Allows Password Brute Forcing | 6.8 | Sets the local account lockout policy (default: threshold 5, window 15 min, duration 15 min) — only ever tightens |
| TLS Server Supports TLS version 1.0 | 6.5 | Disables TLS 1.0 (Client + Server), force-enables TLS 1.2 (and TLS 1.3 on Server 2022 / Win 11+) |
| TLS Server Supports TLS version 1.1 | 6.5 | Disables TLS 1.1 (Client + Server) |
| TLS/SSL Server is enabling the BEAST attack | 5.9 | Mitigated by disabling TLS 1.0/SSLv3 (BEAST needs CBC under TLS 1.0) |
| CVE-2013-3900: MS13-098 (WinVerifyTrust) | 5.5 | Sets `EnableCertPaddingCheck="1"` in **both** the native and `Wow6432Node` `Wintrust\Config` keys |
| TLS/SSL Weak Message Authentication Code Cipher Suites | 4.0 | Disables MD5; cipher-suite order keeps only AEAD (GCM) / SHA-2 suites — no MD5/SHA-1-MAC/RC4 |
| 7-Zip: CVE-2026-58052 (Protection Mechanism Failure) | 3.3 | Upgrades 7-Zip from a **staged** `7zXXXX[-x64].exe/.msi` if the installed copy is older |
| TLS/SSL Server Supports The Use of Static Key Ciphers | 2.6 | Cipher-suite order removes all `TLS_RSA_*` (RSA key-exchange) suites — ECDHE/DHE forward secrecy only |
| TLS/SSL Server Supports 3DES Cipher Suite | 0 | Same control as SWEET32 |
| TLS/SSL Server Does Not Support Any Strong Cipher Algorithms | 0 | AES-GCM suites enabled and preferred; SSL 2.0/3.0 also disabled outright |

This folder contains **`Remediate-Rapid7Findings.ps1`** — audit + remediation +
per-finding compliance report in one script, built for Endpoint Central
**Custom Script (Computer)** deployment running as SYSTEM.

---

## How "offline" works here

1. You (an admin, on any internet-connected machine) download the two
   installers listed below and generate a hash file.
2. You upload the script + installers + hash file to the Endpoint Central
   server as a Custom Script configuration with **Dependency Files**.
3. The EC agent on the target PC pulls everything over the **LAN** from the EC
   server and runs the script locally. Nothing on the endpoint touches the
   internet, and the script itself never downloads anything.

The staged installer versions **are** the compliance target for the two
application CVEs: the script patches whatever is older than what you staged
and never executes a file that fails its integrity check.

## What files you need

| # | File | Where it goes | Required? |
|---|---|---|---|
| 1 | `Remediate-Rapid7Findings.ps1` (this folder) | Endpoint Central **Script Repository** | **Yes** |
| 2 | `dotnet-hosting-<version>-win.exe` — ASP.NET Core Hosting Bundle at the **fixed build named in the CVE-2026-45591 advisory** (or newer), one per release channel installed on the target (e.g. 8.0.x, 10.0.x). Evergreen links: `https://aka.ms/dotnet/8.0/dotnet-hosting-win.exe` (swap `8.0` for the channel) | **Dependency File(s)** | Yes, if the machine runs ASP.NET Core (Rapid7 says it does) |
| 3 | `7z<ver>-x64.exe` (or `.msi`) from <https://www.7-zip.org/> — the release that the **CVE-2026-58052 advisory** lists as fixed, or newer. Match the installed architecture; stage the same package type (EXE vs MSI) as currently installed if you know it | **Dependency File(s)** | Yes, if 7-Zip is installed (Rapid7 says it is) |
| 4 | `payload.sha256` — pinned hashes for the files above (see below) | **Dependency File(s)** | Strongly recommended (7-Zip installers carry no Authenticode signature) |
| 5 | Rapid7 **Export to CSV** of the affected assets | Used to build the target Custom Group | For targeting |

> **Note on the two 2026 CVEs:** check the vendor advisories for the exact
> first-fixed versions at the time you build the payload, and stage those (or
> anything newer). The script deliberately has no hard-coded "fixed" versions
> for them — whatever you stage is the bar it enforces and reports against.

### Generate `payload.sha256`

In the folder where you downloaded the installers (internet-connected machine):

```powershell
Get-ChildItem -File | Where-Object { $_.Extension -in '.exe', '.msi' } |
    Get-FileHash -Algorithm SHA256 |
    ForEach-Object { '{0}  {1}' -f $_.Hash, (Split-Path $_.Path -Leaf) } |
    Set-Content payload.sha256 -Encoding ascii
```

Integrity rules the script enforces on every staged installer it is about to run:
- Listed in `payload.sha256` → must match, or the file is **refused** (run fails with exit 1).
- Microsoft installers → must additionally carry a **valid Microsoft Authenticode signature**.
- Not listed and unsigned (typical for 7-Zip) → runs with a logged **warning**, or is refused if you pass `-StrictIntegrity`.

---

## Step 0 — Build the target group from Rapid7

1. In each Rapid7 vulnerability page, open **Affected Assets → Export to CSV**
   (for a single PC you can skip the export and just note the hostname).
2. In Endpoint Central: **Custom Group → Create Custom Group → Computer**
   (static), e.g. `Rapid7 - Offline hardening batch 1`, and add the machine(s).

## Step 1 — Add the script to the Script Repository

1. **Configurations → Script Repository → + Add Script**.
2. Upload `Remediate-Rapid7Findings.ps1`. Platform: **Windows**.
3. Save (and approve it if your instance requires script approval).

## Step 2 — Create the configuration

**Configurations → Add Configuration → Windows → Custom Script → Computer**

| Form field | What to enter |
|---|---|
| **Name** | `Rapid7 - Offline remediation (TLS, CVE-2013-3900, lockout, ASP.NET Core, 7-Zip)` |
| **Add Description** | `Remediates 12 Rapid7 findings: disables TLS 1.0/1.1/SSLv2/v3 + weak ciphers (SWEET32/BEAST/static-key/weak-MAC), enforces GCM suite order, sets EnableCertPaddingCheck (CVE-2013-3900), sets account lockout policy, and patches ASP.NET Core (CVE-2026-45591) + 7-Zip (CVE-2026-58052) from staged offline installers. Logs to C:\ProgramData\Rapid7-Offline-Remediation\.` |
| **Execute Script from** | **Repository** |
| **Script Name** | `Remediate-Rapid7Findings.ps1` |
| **Script Argument(s)** | *Leave blank* for standard remediation. Variants below. |
| **Dependency File(s)** | The Hosting Bundle EXE(s), the 7-Zip installer, and `payload.sha256`. EC copies them next to the script on the endpoint, which is exactly where the script looks. |
| **Specify the exit code(s)** | `0,3010` |
| **Frequency** | **Once** |
| **Enable Logging for Troubleshooting** | **Checked** |
| **Run As → Execute the script As** | **System User** (required) |

### Script argument variants

| Argument(s) | Use case |
|---|---|
| *(blank)* | Full remediation with default lockout policy (5 / 15 min / 15 min). |
| `-AuditOnly` | Pilot/report run — changes nothing, prints the per-finding PASS/FAIL table. Set success exit code to `0` only, so non-compliant machines show as failed. |
| `-IncludeCbcFallback` | Also allow ECDHE AES-CBC SHA-2 suites (still forward-secret, still SHA-2) for old clients that can't do GCM. Use if a legacy app/client breaks after the default run. |
| `-StrictIntegrity` | Refuse any staged installer with neither a pinned hash nor a valid Authenticode signature. |
| `-ForceReboot` | Restart the PC 5 minutes after a successful run instead of waiting for your EC reboot policy. |
| `-LockoutThreshold 10 -LockoutWindowMinutes 30 -LockoutDurationMinutes 30` | Custom lockout policy values. |
| `-SkipTlsHardening` / `-SkipWinVerifyTrust` / `-SkipLockoutPolicy` / `-SkipAppPatches` | Split the rollout into stages if change control requires it. |
| `-NoIISReset` | Don't bounce IIS after a Hosting Bundle install (fix inactive until reboot). |

## Step 3 — Deploy

1. **Deployment Settings**: allow retries; give the script a generous timeout
   (≥ 30 min — a Hosting Bundle install takes a few minutes).
2. **Define Target**: the Custom Group from Step 0.
3. Deploy in a **maintenance window** and pair the configuration with a
   **reboot policy** (or use `-ForceReboot`): the SCHANNEL/TLS changes only
   take effect after a restart — that's what exit code `3010` means.

## Step 4 — Monitor results

- Configuration → **Execution Status** per computer shows the script output,
  which ends with a per-finding `[PASS]/[FAIL]/[ATTENTION]` compliance table.
- On the endpoint: `C:\ProgramData\Rapid7-Offline-Remediation\remediation.log`
  plus per-installer logs, and a `backup-<timestamp>\` folder with the
  pre-change registry exports.

| Exit code | Meaning | Action |
|---|---|---|
| `0` | Compliant — nothing to do or already active | None |
| `3010` | Remediated — **restart required** to activate the TLS changes | Reboot, then re-verify |
| `2` | Attention — e.g. a runtime is installed but no matching installer was staged, an OS too old for GCM, or a value didn't verify | Read the machine's log; stage the missing payload or follow up manually |
| `1` | Failure — not admin, integrity refusal, installer error | Read the log; fix and redeploy |

## Step 5 — Verify and re-scan in Rapid7

1. After the reboot, run the configuration again with `-AuditOnly` (success
   code `0`) — every row should read `[PASS]`.
2. Trigger a scan of the asset in InsightVM. The TLS findings are probed live
   by the scan engine, so they clear as soon as the box has rebooted with the
   new SCHANNEL settings.

## Rollback

Everything the script changes is captured before the change:

- Registry: `C:\ProgramData\Rapid7-Offline-Remediation\backup-<timestamp>\*.reg`
  — restore with `reg import <file>.reg` and reboot.
- Lockout policy: previous values recorded in `net-accounts-before.txt` in the
  same folder — restore with `net accounts /lockoutthreshold:... /lockoutwindow:... /lockoutduration:...`.
- App patches are upgrades; rolling those back means reinstalling the older
  version (not recommended — that's the vulnerability).

## Caveats worth reading before you deploy

- **Reboot required.** SCHANNEL reads protocol/cipher settings at boot. Until
  the restart, Rapid7 will still see TLS 1.0/1.1/3DES.
- **Old clients can break.** After hardening, this machine only accepts
  TLS 1.2+ with ECDHE + AES(-GCM). Legacy clients (XP/2003-era software,
  Java 6/7, very old browsers/middleboxes, pre-2016 SQL Server without the
  TLS 1.2 update) can no longer connect — that is the point, but plan for it.
  `-IncludeCbcFallback` widens compatibility without reintroducing findings.
- **.NET Framework apps on the box** are pointed at OS-default TLS
  (`SchUseStrongCrypto` + `SystemDefaultTlsVersions`), which keeps most of
  them working once TLS 1.0/1.1 are gone.
- **Domain GPO wins.** If a domain GPO defines the cipher-suite order or the
  account lockout policy, it will overwrite the local values at the next
  policy refresh — put the same settings in GPO for domain-managed machines.
- **Windows 7 / Server 2008 R2** have no AES-GCM in SCHANNEL: the script
  applies the best available (ECDHE + AES-CBC + SHA-2) and reports
  `ATTENTION` — the "no strong cipher algorithms" finding needs an OS upgrade.
- **Self-contained ASP.NET Core apps** ship their own runtime; a Hosting
  Bundle install does not fix them. The app owner must rebuild with a patched
  SDK and redeploy.
- **7-Zip EXE vs MSI:** stage the same package type that's installed, or the
  superseded Add/Remove entry can linger and keep the Rapid7 finding alive
  even though the binaries are patched.

## Suggested rollout

1. `-AuditOnly` on the target (success code `0`) — confirms scoping, zero risk.
2. Full run in a maintenance window + reboot.
3. `-AuditOnly` again — expect all `[PASS]`.
4. Rapid7 re-scan; hand any exit-`2` leftovers (self-contained apps, EOL OS)
   to the relevant owners.

## References

- Microsoft CVE-2013-3900 guidance (EnableCertPaddingCheck): <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900>
- TLS/SCHANNEL registry settings: <https://learn.microsoft.com/windows-server/security/tls/tls-registry-settings>
- Cipher-suite configuration: <https://learn.microsoft.com/windows-server/security/tls/manage-tls>
- .NET Framework strong cryptography: <https://learn.microsoft.com/dotnet/framework/network-programming/tls>
- ASP.NET Core Hosting Bundle downloads: `https://aka.ms/dotnet/<channel>/dotnet-hosting-win.exe`
- 7-Zip downloads: <https://www.7-zip.org/download.html>
