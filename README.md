# Rapid7 Remediation Scripts

Scripts and UEM (ManageEngine Endpoint Central) deployment guides for remediating
vulnerabilities reported by Rapid7 InsightVM.

| Vulnerability | Folder | Contents |
|---|---|---|
| June 2026 full export (`Vulnerabilitiesv1.csv`) — 2,748 findings across Chrome, Edge, Adobe, Windows, Office, ASP.NET Core, 7-Zip, TLS/SSL config, SMB signing, CVE-2013-3900 and more (**AutoCAD excluded by policy**) | [`All-In-One-Remediation/`](All-In-One-Remediation/) | Single all-in-one PowerShell remediation script + Endpoint Central Custom Script deployment guide |
| CVE-2025-55315 — ASP.NET Core (Kestrel) Security Feature Bypass, CVSS 9.9 | [`CVE-2025-55315/`](CVE-2025-55315/) | PowerShell detect/patch script + step-by-step Endpoint Central Custom Script deployment guide |
