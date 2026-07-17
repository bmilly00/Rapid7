# Rapid7 Remediation Scripts

Scripts and UEM (ManageEngine Endpoint Central) deployment guides for remediating
vulnerabilities reported by Rapid7 InsightVM.

| Vulnerability | Folder | Contents |
|---|---|---|
| CVE-2025-55315 — ASP.NET Core (Kestrel) Security Feature Bypass, CVSS 9.9 | [`CVE-2025-55315/`](CVE-2025-55315/) | PowerShell detect/patch script + step-by-step Endpoint Central Custom Script deployment guide |
| 12-finding offline pack — TLS 1.0/1.1, SWEET32/3DES, BEAST, weak-MAC & static-key ciphers, no strong ciphers, CVE-2013-3900 (WinVerifyTrust), CIFS account lockout, CVE-2026-45591 (ASP.NET Core), CVE-2026-58052 (7-Zip) | [`Rapid7-Offline-Remediation/`](Rapid7-Offline-Remediation/) | Single audit/remediate PowerShell script for endpoints with **no internet access** (payload staged as Endpoint Central dependency files) + deployment guide |
