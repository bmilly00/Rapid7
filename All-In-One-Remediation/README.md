# All-In-One Rapid7 Remediation — June 2026 Export (`Vulnerabilitiesv1.csv`)

One PowerShell script — **`Invoke-Rapid7Remediation.ps1`** — that remediates the
entire June 2026 Rapid7 InsightVM export (2,748 findings) on Windows endpoints,
deployed through **ManageEngine Endpoint Central (UEM) → Custom Script**, same
pattern as the earlier [CVE-2025-55315 config](../CVE-2025-55315/).

Every module first detects whether its product/setting exists, so the **same
configuration is safe to push to every Windows asset** — machines simply skip
what they don't have.

> ### 🚫 Excluded by policy — the script never touches these
> - **AutoCAD** — all 180 AutoDesk AutoCAD / Advance Steel / Civil 3D findings.
> - **VNC** — "VNC remote control service installed" (10 assets).
> - **Auto-logon** — "Windows autologin enabled" (8 assets).
> - **Account lockout policy** — "CIFS Account Lockout Policy Allows Password
>   Brute Forcing" (52 assets). `net accounts` is never read or modified.
>
> These findings will stay open in Rapid7 and are handled outside this script.
>
> ### 🔁 Never reboots
> The script performs **no machine restart of any kind** — every installer runs
> with `/norestart` and the Windows Update module only installs. Machines that
> need a restart exit with code `3010`; **reboot them manually** (or via a
> separate Endpoint Central reboot task) on your own schedule.

---

## Coverage map

### Remediated automatically

| Rapid7 finding group (count) | Module | How it's fixed |
|---|---|---|
| Google Chrome CVEs (1,195) | `Chrome` | Latest Chrome Enterprise MSI (evergreen link), Google-signature verified, silent in-place upgrade |
| Microsoft Edge CVEs (449) | `Edge` | Latest Edge Stable MSI (Microsoft evergreen link), signature verified; falls back to kicking the built-in updater |
| Adobe Acrobat/Reader CVEs (397) | `AdobeAcrobat` | Compares against Adobe's latest Continuous build, then patches via **RemoteUpdateManager** → **winget** → signed update **MSP** downloaded straight from Adobe (covers enterprise installs deployed without the updater) |
| Microsoft Windows CVEs (327), .NET Framework (5), Defender, SQL GDRs | `WindowsUpdate` | Opts into **Microsoft Update**, then searches/downloads/installs all applicable software updates via the WUA API (runs last — slowest) |
| Microsoft Office CVEs (93) | `Office` | Click-to-Run update triggered silently to latest build |
| ASP.NET Core CVEs incl. CVE-2025-55315 (10 findings / 32 assets) | `AspNetCore` | Latest 8.0 / 9.0 / 10.0 Hosting Bundle in-place upgrade (signature verified) + `iisreset` |
| 7-Zip CVEs (9) | `SevenZip` | `winget` upgrade, else newest x64 build from 7-zip.org (matches existing EXE/MSI install type) |
| Visual Studio CVEs (9) | `VisualStudio` | `vs_installer updateall --quiet` |
| Microsoft Notepad CVE-2026-20841 + Store apps | `StoreApps` | Forces a Microsoft Store app update scan (MDM bridge) |
| CVE-2013-3900 WinVerifyTrust (100 assets) | `CertPadding` | `EnableCertPaddingCheck=1` in both registry views |
| SMBv2 signing not required (48) | `SmbSigning` | `RequireSecuritySignature=1` on the SMB server |
| TLS/SSL family: BEAST, POODLE, SSLv3, TLS 1.0/1.1, 3DES/SWEET32, RC4, static-key ciphers, weak-MAC ciphers, "no strong ciphers" (up to 67) | `TlsHardening` | SChannel: SSL2/3 + TLS 1.0/1.1 off, TLS 1.2 on, weak ciphers off, MD5 off, DHE ≥ 2048, ECDHE/AEAD-only cipher-suite order, .NET strong-crypto keys |
| Rapid7 Insight Agent CVEs (2) | `InsightAgent` | Service bounce → agent self-updates from the Insight platform |
| Oracle Java SE CPU findings (≤2 assets) | `Java` | `winget` upgrade of the JRE where available |
| TeamViewer CVE-2025-41421 (1) | `TeamViewer` | `winget` upgrade where available |

### Detected + reported for manual follow-up (machine exits `2`)

| Finding group | Module | Why not automated / what to do |
|---|---|---|
| MariaDB — 11 CVEs, 2 assets (incl. CVE-2026-44170, 9.8) | `MariaDb` | Blind in-place upgrade of a production DB engine is unsafe. Back up, then install the newest MariaDB MSI of the **same series** in a maintenance window. |
| FortiClient — 5 CVEs, 1 asset | `FortiClient` | Fixed installers are only behind FortiCare/EMS login. Upgrade via EMS. |
| Apache Log4j Core — 4 CVEs, 2 assets | `Log4j` | Jar is embedded in an application; script reports every `log4j-core-*.jar` / `log4j-1.*.jar` path found. App owner upgrades the bundled jar. |
| ASP.NET Core **Obsolete Version** (13 assets) | `AspNetCore` | EOL 2.x–7.x runtimes have no patch; apps must move to .NET 8/10, then uninstall the old runtime. |
| SQL Server CVEs + Database Open Access | `SqlServer` | GDRs arrive via the `WindowsUpdate` module (Microsoft Update opt-in is done for you) — verify build after. Restrict TCP 1433 exposure via firewall. |
| Java (when `winget` is unavailable) | `Java` | Oracle CPU installers need a licensed account; or migrate the app to Eclipse Temurin. |
| "Inconclusive host with excessive port connection failures" | — | Scanner-side finding; nothing to fix on the endpoint. |

> **Secure Boot note:** the 2026 Secure Boot bypass CVEs (e.g. CVE-2026-8863,
> CVE-2026-48576) ship in the cumulative updates the `WindowsUpdate` module
> installs, but Microsoft may additionally require staged UEFI revocation steps
> per the MSRC advisory after the CU + reboot. Check the advisory once patched.

---

## Parameters

| Argument | Effect |
|---|---|
| *(blank)* | Full remediation. |
| `-AuditOnly` | Detect + report only, change **nothing**. Exit 0 = clean, 2 = gaps found. |
| `-NoDownload` | Never touch the internet; installer modules only use dependency files (see below). |
| `-SkipWindowsUpdate` | Skip OS patching (use when Endpoint Central Patch Mgmt owns it, or to keep runs short). |
| `-SkipTlsHardening` | Defer the SChannel changes (while validating legacy TLS 1.0/RSA-kx clients). |
| `-RestartServices` | Restart the LanmanServer **service** immediately after the SMB signing change (services only — the machine is never rebooted; default waits for your manual reboot). |
| `-SkipModules A,B` | Skip any modules by name, e.g. `-SkipModules Chrome,Edge,VisualStudio`. |

Module names: `CertPadding, SmbSigning, TlsHardening, InsightAgent, StoreApps,
Chrome, Edge, AdobeAcrobat, Office, AspNetCore, SevenZip, Java, TeamViewer,
MariaDb, FortiClient, Log4j, SqlServer, VisualStudio, WindowsUpdate`

### Exit codes — set **Specify the exit code(s)** to `0,3010`

| Exit code | Meaning | Action |
|---|---|---|
| `0` | Compliant / everything remediated | None |
| `3010` | Remediated — **reboot required** (TLS/SMB/OS updates). The script never reboots. | Reboot manually when convenient |
| `2` | Attention — manual follow-up items in the log | Read `C:\ProgramData\Rapid7Remediation\remediation.log` |
| `1` | At least one module failed (download/signature/install) | Read the log, fix, redeploy (retries are safe — everything is idempotent) |

---

## Endpoint Central deployment

### Step 1 — Script Repository

**Configurations → Script Repository → + Add Script** → upload
`Invoke-Rapid7Remediation.ps1` (Platform: Windows). Approve if required.

### Step 2 — Configuration

**Configurations → Add Configuration → Windows → Custom Script → Computer**

| Form field | Value |
|---|---|
| **Name** | `Rapid7 - All-In-One Vulnerability Remediation (Jun 2026)` |
| **Description** | `Remediates the June 2026 Rapid7 export: browser/Adobe/Office/7-Zip/VS/ASP.NET Core updates, TLS-SSL + SMB + CVE-2013-3900 hardening, Windows Updates. AutoCAD/VNC/autologon/lockout-policy excluded. Never reboots (3010 = manual reboot pending). Logs to C:\ProgramData\Rapid7Remediation\.` |
| **Execute Script from** | **Repository** |
| **Script Name** | `Invoke-Rapid7Remediation.ps1` |
| **Script Argument(s)** | *(blank)* for full run — variants below |
| **Dependency File(s)** | *Optional*, for `-NoDownload` / slow WAN sites: `googlechromestandaloneenterprise64.msi`, `MicrosoftEdgeEnterpriseX64.msi`, `dotnet-hosting-<8.0.x>-win.exe`, `dotnet-hosting-<9.0.x>-win.exe`, `7z<build>-x64.exe` |
| **Specify the exit code(s)** | `0,3010` |
| **Frequency** | Once (redeploy after the reboot wave for the WU second pass) |
| **Enable Logging for Troubleshooting** | Checked |
| **Run As** | **System User** (required) |

**Script timeout / Deployment Policy:** a full run with Windows Update and
Visual Studio can take 60–120 minutes. Either raise the script timeout
accordingly, or split the heavy tail out:

- Wave 1 (fast, ~5–15 min): arguments `-SkipWindowsUpdate -SkipModules VisualStudio`
- Wave 2 (patch window): arguments `-SkipModules Chrome,Edge,AdobeAcrobat,Office,SevenZip` (OS + VS only)

### Step 3 — Targets

Deploy to a Custom Group built from the Rapid7 asset export (Windows assets).
Because every module self-detects, an "all Windows workstations + servers"
group is also fine.

### Step 4 — Monitor

- Per-machine output: configuration **Execution Status** (logging enabled).
- On the endpoint: `C:\ProgramData\Rapid7Remediation\remediation.log` — ends
  with a per-module summary table (`OK / CHANGED / ATTENTION / FAILED / N.A.`)
  plus the list of manual follow-up items.
- Manually reboot the `3010` machines when convenient (the script leaves the
  restart entirely to you), then trigger a Rapid7 rescan of the group.

---

## Suggested rollout

1. **Pilot audit:** push with `-AuditOnly` (success code `0` only) to ~5
   machines — zero changes, full inventory of what the real run would do.
2. **Pilot remediation:** full run on a handful of non-critical machines.
   Watch the one genuinely risky change:
   - **TLS hardening** disables TLS 1.0/1.1, RSA-key-exchange and SHA-1/CBC-era
     suites — anything *very* old (2003/XP-era clients, ancient printers or
     appliances talking to that server, apps hard-coded to TLS 1.0) will stop
     connecting. Pilot on servers carefully; use `-SkipTlsHardening` to defer,
     then remove the switch once validated. Windows 8.1/2012 R2 gets suffixed
     ECDHE suites so RDP keeps working.
3. **Broad rollout.** No maintenance window strictly required — nothing
   reboots on its own; changes that need a restart simply stay pending.
4. **Manually reboot** the exit-`3010` machines on your schedule, rescan in
   Rapid7, then work the exit-`2` machines' logs — those carry the MariaDB /
   FortiClient / Log4j / EOL-runtime follow-ups.

### Known caveats

- Browser updates finish activating when the user relaunches Chrome/Edge
  (files are staged even while running).
- Adobe updates apply cleanly only when Acrobat/Reader is closed; if it was
  open during the MSP path the patch finishes at reboot (machine exits 3010).
  Dependency-file alternative for `-NoDownload`: ship `AcrobatDCUpd*.msp`
  (unified/64-bit Acrobat) or `AcroRdrDCUpd*.msp` (standalone Reader).
- On domain-joined machines, a domain GPO with a weaker setting overrides the
  local SMB-signing change — mirror it in the domain policy for permanence.
- Oracle Java/TeamViewer via `winget` requires the App Installer to be present
  (standard on Win10/11; usually absent on Server SKUs → reported instead).

## References

- CVE-2013-3900 (WinVerifyTrust): <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900>
- Microsoft TLS registry settings: <https://learn.microsoft.com/windows-server/security/tls/tls-registry-settings>
- Chrome Enterprise MSI: <https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi>
- Edge Stable MSI (evergreen): <https://go.microsoft.com/fwlink/?linkid=2093437>
- .NET Hosting Bundles: <https://aka.ms/dotnet/8.0/dotnet-hosting-win.exe> · <https://aka.ms/dotnet/9.0/dotnet-hosting-win.exe>
- Adobe RUM: <https://www.adobe.com/devnet-docs/acrobatetk/tools/AdminGuide/rum.html>
