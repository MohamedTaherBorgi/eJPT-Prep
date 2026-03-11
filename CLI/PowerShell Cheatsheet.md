## CMD vs PowerShell — Equivalent Cheatsheet

| PowerShell               | CMD              |
| ------------------------ | ---------------- |
| `Get-ChildItem`          | `dir`            |
| `Set-Location`           | `cd`             |
| `Get-Content`            | `type`           |
| `Select-String`          | `findstr`        |
| `Get-Process`            | `tasklist`       |
| `Get-NetTCPConnection`   | `netstat -ano`   |
| `Get-NetIPConfiguration` | `ipconfig /all`  |
| `Get-LocalUser`          | `net user`       |
| `Get-LocalGroup`         | `net localgroup` |
| `Get-ComputerInfo`       | `systeminfo`     |

## Core Concept: Verb-Noun Syntax

```powershell
Get-Content     # Read file
Set-Location    # Change directory
Get-Command     # List all available cmdlets
Get-Help <cmdlet> -Examples   # Usage examples
Get-Alias       # Show all aliases (dir = Get-ChildItem, cd = Set-Location, cat = Get-Content)
````

---
## File System

```powershell
Get-ChildItem                  # ls/dir
Get-ChildItem -Force           # Include hidden files (equivalent to dir /a)
Get-Content file.txt           # Read file (= type / cat)
New-Item -Path ".\file.txt" -ItemType "File"
New-Item -Path ".\folder" -ItemType "Directory"
Remove-Item file.txt           # del + rmdir unified
Copy-Item src.txt dst.txt
Move-Item src.txt .\folder\
```

---
## Piping, Filtering, Sorting

```powershell
Get-ChildItem | Sort-Object Length
Get-ChildItem | Where-Object -Property "Extension" -eq ".txt"
Get-ChildItem | Where-Object -Property "Name" -like "ship*"
Get-ChildItem | Select-Object Name, Length

# Search inside files (better than findstr for PS)
Select-String -Path ".\file.txt" -Pattern "password"
Select-String -Path "C:\Users\*" -Pattern "password" -Recurse
```

### Where-Object Operators

|Operator|Meaning|
|---|---|
|`-eq`|Equal|
|`-ne`|Not equal|
|`-gt`|Greater than|
|`-ge`|Greater than or equal|
|`-lt`|Less than|
|`-le`|Less than or equal|
|`-like`|Wildcard match (`*`)|

---
## System Recon

```powershell
Get-ComputerInfo          # Full system info (superset of systeminfo)
Get-LocalUser             # = net user
Get-LocalGroup            # = net localgroup
Get-Process               # Running processes + CPU/mem (= tasklist)
Get-Service               # Services: running/stopped/paused
Get-FileHash file.exe     # SHA256 by default — useful for IOC matching (BLUE)
```

---
## Network Recon

```powershell
Get-NetIPConfiguration    # Interfaces, IPs, DNS, gateway (= ipconfig /all)
Get-NetIPAddress          # All IPs including inactive interfaces
Get-NetTCPConnection      # Active TCP connections + PID (= netstat -ano)

# Red team one-liner: connections with owning process
Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess
```

---
## Interesting Pentest Cmdlets

```powershell
# ADS (Alternate Data Streams) — great for hiding/finding hidden data
Get-Item file.txt -Stream *

# Remote execution — lateral movement
Invoke-Command -ComputerName Server01 -Credential DOMAIN\user -ScriptBlock { whoami }
Invoke-Command -FilePath C:\scripts\payload.ps1 -ComputerName Server01

# Run anything remotely without a script file
Invoke-Command -ComputerName target -ScriptBlock { Get-NetTCPConnection }
```

---
## Quick Pentest Reference

```powershell
# Who am I + privileges
whoami /all

# Find files with interesting names recursively
Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -like "*password*" -or $_.Name -like "*cred*" }

# Search file contents for creds
Select-String -Path "C:\Users\*\*.txt" -Pattern "password" -Recurse

# Suspicious network connections
Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }

# Hash a suspicious binary
Get-FileHash C:\Windows\Temp\suspicious.exe -Algorithm SHA256

# List all services (hunt for anomalous ones)
Get-Service | Where-Object { $_.Status -eq "Running" }
```

---
---
