# Rapid7 Remediation Scripts

Scripts and UEM (ManageEngine Endpoint Central) deployment guides for remediating
vulnerabilities reported by Rapid7 InsightVM.

| Vulnerability | Folder | Contents |
|---|---|---|
| CVE-2025-55315 — ASP.NET Core (Kestrel) Security Feature Bypass, CVSS 9.9 | [`CVE-2025-55315/`](CVE-2025-55315/) | PowerShell detect/patch script + step-by-step Endpoint Central Custom Script deployment guide |
| Workstation batch (Jan/Feb 2026 scan, 21 findings): CVE-2013-3900 (WinVerifyTrust), 15× Windows CVE-2026-\*, FortiClient CVE-2025-54660 (FG-IR-25-844), 4× TLS/SSL weak-cipher findings | [`windows-workstation/`](windows-workstation/) | Single master script `Invoke-Rapid7Remediation.ps1` + standalone per-finding scripts: Windows Update (WUA COM), WinVerifyTrust registry fix, SCHANNEL/TLS hardening with backup + rollback script, FortiClient version check, optional defense-in-depth mitigations |
