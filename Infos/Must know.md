## SMB (Server Message Block)

- **Port**: `445/TCP`
- **Service Name**: **Microsoft-DS** (Microsoft Directory Services)
- **Purpose**: Used for **file sharing, printer sharing, and inter-process communication** over a network.
### Key Facts
- Replaced ==older NetBIOS-over-TCP (ports 137–139)== in modern Windows networks.
- Exposes shares like `C$`, `ADMIN$`, and user-defined shares.
- Common attack vectors:
  - Null sessions (largely patched in modern systems)
  - Guest access misconfigurations
  - Exploits (e.g., EternalBlue on unpatched systems)
  - Credential brute-forcing / relay attacks

> 🔍 In `nmap` scans, an open port 445 typically shows as:  
> `445/tcp open  microsoft-ds`

> ✅ Always enumerate SMB during internal recon — it’s a goldmine for lateral movement.

---
---
## RDP (Remote Desktop Protocol)

- **Port**: `3389/TCP`
- **Service**: Microsoft **Remote Desktop Protocol**
- **Service Name**: **ms-wbt-server**  *(Microsoft Windows Based Terminal Server)*
- **Purpose**: Allows graphical remote access to Windows systems (desktop sharing, admin control).

### Key Facts
- Common in **Windows environments** (workstations & servers).
- Requires valid credentials (unless misconfigured).
- Often targeted for:
  - **Brute-force attacks** (weak passwords)
  - **Credential stuffing** (reused passwords)
  - **Exploits** (e.g., BlueKeep – CVE-2019-0708 on unpatched systems)
  
## <u>RDP vs SSH vs WinRM</u>

| Protocol                              | OS         | Purpose                                         | Equivalent                   |
| ------------------------------------- | ---------- | ----------------------------------------------- | ---------------------------- |
| **RDP** (Remote Desktop Protocol)     | Windows    | **Graphical remote desktop**                    | ❌ No direct Linux equivalent |
| **SSH**                               | Linux/Unix | **Encrypted command-line shell**                | Winrm on Windows             |
| **WinRM** (Windows Remote Management) | Windows    | **Command-line & scriptable remote management** | SSH on Linux/Unix            |

---
## Key Differences

- **RDP**: Full GUI session (port `3389`) — like sitting at the machine.
- **WinRM**: CLI/scripting over HTTP(S) (ports `5985`/`5986`) — used by `evil-winrm`, Ansible, PowerShell remoting.
- **SSH**: Secure shell (port `22`) — Linux default for remote access.

> ✅ **WinRM ≈ SSH for Windows**  
> ❌ **RDP ≠ SSH** — it’s a GUI tool, not a shell protocol.

---
---
# Exploit vs Payload: Core Definitions

| Term        | What It Is                                                                                              | Purpose                                                           |
| ----------- | ------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| **Exploit** | A piece of code that takes advantage of a vulnerability (e.g., buffer overflow, SQLi, file upload flaw) | Gains initial code execution on the target                        |
| **Payload** | The code you want to run after exploitation (e.g., reverse shell, webshell, meterpreter)                | Performs post-exploitation tasks (connect back, dump files, etc.) |

---
---
# Difference between **FTP** & **SMB** :

- **FTP (File Transfer Protocol):** Designed for **transferring** files. You usually download a file, edit it locally, and upload it back. It’s like a **delivery service** (FileZilla Project).
- **SMB (Server Message Block):** Designed for **sharing** resources. It allows you to open and edit a file directly on the server as if it were on your own hard drive. It’s like a **shared office folder** (Cloudflare).

**Comparison for your Notes**

|Feature|**FTP** (Port 21)|**SMB** (Port 445)|
|---|---|---|
|**Primary Use**|Sending files over the internet/web|Sharing files/printers on a local network|
|**Experience**|"Download → Edit → Upload"|"Open → Edit → Save" (Live)|
|**OS Origin**|Platform independent (Universal)|Built into **Windows** (Microsoft-DS)|
|**Pentest Focus**|Anonymous login / Cleartext creds|**Lateral Movement** / EternalBlue|

**Why Pentesters Treat Them Differently**

- **If you find FTP:** Look for **leaked files** (config files, backups, sensitive data).
- **If you find SMB:** Look for a **way into the system** (remote code execution or harvesting user hashes)

---
---
## <u>What Are Shares?</u>

### Definition
A **share** (or **network share**) is a **directory or resource on a system that has been explicitly configured to be accessible over the network** using protocols like **SMB (Windows/Linux)** or **NFS (Linux/Unix)**.

### Types of Shares

#### 1. **Administrative Shares (Windows)**

- Automatically created by Windows:
  - `C$` → Root of C: drive
  - `ADMIN$` → `%SystemRoot%` (e.g., `C:\Windows`)
  - `IPC$` → Named pipe for inter-process communication
- **Access**: Requires **local administrator credentials**
- **Hidden**: Names end with `$` → not visible in normal network browse

#### 2. **User-Defined Shares**

- Created manually by admins/users:
  - `\\SERVER\Documents`
  - `\\FILESERVER\Backups`
- **Access**: Controlled by permissions (read/write, specific users)

#### 3. **Samba Shares (Linux)**

- Configured in `/etc/samba/smb.conf`:
```ini
  [shared]
    path = /srv/data
    read only = no
    guest ok = yes
```

---
---
# Evasion vs Spoofing :

- **Evasion** : The act of bypassing security controls (Firewalls, IDS, Antivirus) to remain undetected.

- **Spoofing**: A specific technical tactic where you forge identity information (IP, MAC, Email, or Hostname) to pretend to be a trusted source. 

---
## Comparing :

| Feature          | **Evasion**                                         | **Spoofing**                                         |
| ---------------- | --------------------------------------------------- | ---------------------------------------------------- |
| **Definition**   | Bypassing a defense without triggering an alarm.    | Impersonating a user, device, or service.            |
| **Focus**        | The **Result** (Being invisible).                   | The **Identity** (Falsifying headers).               |
| **Nmap Example** | `nmap -f` (Fragmenting packets to hide signatures). | `nmap -S <IP>` (Faking your source IP address).      |
| **Analogy**      | A ninja moving through shadows to stay hidden.      | An impostor wearing a guard's uniform to get inside. |

---
## **How They Work Together** :

Pentesters use spoofing as an **evasion technique** to bypass access control lists (ACLs). For example, if a firewall only allows traffic from a specific "trusted" admin IP, you can **spoof** that IP to **evade** the firewall's block. 

**Common Evasion vs. Spoofing Techniques**

- **Evasion Techniques (Non-Spoofing)**:
    - **Fragmentation**: Breaking packets into tiny pieces so an IDS can't recognize the attack pattern.
    - **Obfuscation**: Encrypting or encoding code to hide it from Antivirus scanners.
    - **Timing**: Scanning "low and slow" to avoid triggering threshold-based alerts.
- **Spoofing Techniques**:
    - **IP Spoofing**: Modifying the source IP to hide your true location or impersonate another machine.
    - **MAC Spoofing**: Changing your hardware address to bypass network filters or hide your laptop's manufacturer.
    - **DNS Spoofing**: Redirecting traffic by providing false IP addresses for domain names.

---
---
# Nmap `-sV` vs `-sC` :

### 🔍 `-sV` (Version Detection)

- **Goal**: Identify **what service + version** is running on a port.
- **How**: Sends probes and analyzes responses to fingerprint software.
- **Output example**:
  ```
  80/tcp open  http    Apache httpd 2.4.41
  445/tcp open  microsoft-ds  Windows 10 Pro 19041
  ```

✅ Tells you: *“This is Apache 2.4.41.”*

---
### 🧠 `-sC` (Default Scripts)

- **Goal**: Run **safe, informative NSE scripts** that go **beyond version**.
- These scripts extract **contextual intelligence** that `-sV` **cannot**.

#### Examples of what `-sC` reveals (that `-sV` does NOT):
| Script | Reveals |
|-------|--------|
| `http-title` | Webpage title → e.g., “Login - WordPress” |
| `http-robots.txt` | Hidden paths like `/admin`, `/backup` |
| `smb-os-discovery` | Exact OS, NetBIOS name, workgroup |
| `ssl-cert` | Certificate issuer, expiry, CN (useful for phishing) |
| `ftp-anon` | Whether anonymous FTP login is allowed |
| `dns-recursion` | If DNS server allows abuse for amplification |

✅ Tells you: *“This Apache server hosts a WordPress login page, has `/backup` in robots.txt, and uses a self-signed cert.”*

---
### 💡 Key Insight
- `-sV` = **"What software is running?"**
- `-sC` = **"What is this service actually doing or exposing?"**

They **complement each other**.

---
### ✅ Best Practice
Always combine them:
```bash
nmap -sC -sV -p- 192.168.1.10
```
→ You get **versions + behavioral context** → better exploit selection.

> 🚫 Using only `-sV` misses critical recon clues.  
> 🚫 Using only `-sC` may miss exact versions needed for exploit matching.

---
---
# Can Hash Authentication Be Disabled ?

## Short Answer

**No — you cannot fully disable NTLM hash authentication in Windows**, but you can **mitigate or restrict** it.

---
## How Windows Uses Hashes

- Windows **always stores and uses NTLM hashes** internally for authentication.
- When you log in, the system computes the hash and compares it to the one in SAM/NTDS.dit.
- **Pass-the-Hash (PtH)** works because Windows **accepts the hash directly** over SMB/RPC — no password needed.

> 🔒 This is by design — not a bug. Microsoft calls it "credential forwarding."

---
## Mitigations (Not Full Disable)

### 1. **Disable NTLM Entirely**

- Force **Kerberos-only** auth via Group Policy:
  ```
  Computer Config → Policies → Security Settings → Local Policies → Security Options
  → Network security: Restrict NTLM: NTLM authentication in this domain → Deny all
  ```
  
- **Downside**: Breaks legacy apps, local logon, workgroup systems.

### 2. **Enable SMB Signing**

- Prevents **SMB relay** (not PtH directly), but adds integrity checks.
- Doesn’t stop PtH if attacker has hash + direct access.

### 3. **Protected Users Group (Domain Only)**

- Members **cannot use NTLM**.
- Kerberos tickets are short-lived and non-renewable.
- Only works in **Active Directory**.

### 4. **LAPS (Local Admin Password Solution)**

- Ensures **unique, random local admin passwords** per machine.
- Reduces **lateral movement via reused hashes**.

---
## Reality Check

- **Workgroup / standalone Windows**: No way to disable NTLM → **PtH always works** if you have the hash.
- **Domain environments**: Can be hardened, but misconfigurations are common.
- **CrackMapExec will succeed** if:
  - Target accepts NTLM (default)
  - You provide correct hash
  - No network filtering (e.g., firewall blocking SMB)

> ✅ **In most labs and real-world networks, PtH with CME just works.**

---
## Bottom Line

You **cannot "disable hash login"** like turning off a switch.  
But with **proper hardening**, you can **reduce its effectiveness**.  
Until then: **hash = key**.

---
---
# What Is RPC?

**RPC (Remote Procedure Call)** is a protocol that allows a program on one computer to **execute code on another machine** over a network — as if it were local.

---
## Key Facts

- **Purpose**: Enable inter-process communication across systems (client ↔ server)
- **Used by**: Windows (heavily), Linux, macOS
- **Port**: Typically dynamic (TCP/UDP <u>135</u> for endpoint mapper + high ports), but can be fixed
- **Authentication**: Uses **NTLM** or **Kerberos** → supports **Pass-the-Hash**

---
## How It Works (Windows Example)

1. Client calls a function (e.g., `NetUserEnum`)
2. RPC runtime **serializes** the request
3. Sends it over network to target’s **RPC service**
4. Target executes function and returns result

> 🔧 Under the hood: RPC is used by **SMB**, **WMI**, **DCOM**, **MS-RPRN**, etc.

---
---
# Staged vs. Stageless Payload :
### 1. Staged Payload (The "Two-Step")

A staged payload is broken into two parts. It’s like sending a "scout" first to make sure the coast is clear before the "army" arrives.

- **Stage 0 (The Stager):** A tiny piece of shellcode sent to the target. Its only job is to connect back to your machine and download the rest of the code.
    
- **Stage 1 (The Stage):** The heavy lifting code (like the full Meterpreter shell) that is pulled into memory after the connection is made.
    

> **Why use it?** > Perfect for **Buffer Overflows** where you only have a very small amount of space (e.g., 100 bytes) to inject code. The stager is small enough to fit; the full shell is not.

---
### 2. Stageless Payload (The "All-in-One")

A stageless payload is a single, self-contained file. It contains everything it needs to give you a shell in one go.

- **Fire and Forget:** It doesn't need to "call home" to download more code; it just executes its instructions immediately.
    
- **Size:** Much larger than a stager because the entire "army" is packed into the initial file.
    

> **Why use it?**
> 
> Better for **unstable networks** or high-latency environments. Since there's no "Stage 1" download, there’s less chance of the connection dropping halfway through the transfer.

---
### 🛠️ How to tell them apart in Metasploit

Metasploit uses a very specific naming convention. **This is a common eJPT/OSCP knowledge point!**

|**Type**|**Syntax Example**|**Identifier**|
|---|---|---|
|**Staged**|`windows/meterpreter/reverse_tcp`|Uses a **forward slash (`/`)** between the shell and the protocol.|
|**Stageless**|`windows/meterpreter_reverse_tcp`|Uses an **underscore (`_`)** to join them into one name.|
   
---
### ⚖️ Comparison at a Glance

|**Feature**|**Staged**|**Stageless**|
|---|---|---|
|**Size**|Very Small (Stage 0)|Large (Full binary)|
|**Stealth**|Harder to detect initially (small footprint).|Easier for AV to scan the whole file at once.|
|**Reliability**|Can fail if the "Stage 1" download is blocked.|More reliable on poor network connections.|
|**Best For...**|Exploiting small memory buffers.|USB drops, social engineering, or persistence.|

---
---
## smbclient & Samba

### Q: Is `smbclient` only for Linux Samba?
**No.** It works against **any SMB server** — including **Windows**.

### Q: Can I get a shell with `smbclient`?
**No.** It’s a **file transfer tool**, not a command shell.  
→ For remote execution, use:
- `smbmap -x 'whoami'` (if admin)
- `psexec.py` (via Impacket)

---
---
# Admin vs. High-Integrity Admin – What’s the Difference?

## 🔑 Short Answer:

- **Being in the Administrators group ≠ having admin privileges at runtime**
- **"High-integrity admin" = actual elevated privileges**
- **Regular admin session = unelevated (medium integrity)**

---
## 🧠 Windows Integrity Levels (IL)

Windows uses **Mandatory Integrity Control (MIC)** to enforce privilege boundaries:

| Integrity Level | Typical Context |
|----------------|----------------|
| **Low** | Internet Explorer Protected Mode, sandboxed apps |
| **Medium** | Standard user, **unelevated admin** |
| **High** | **Elevated admin** (after UAC approval) |
| **System** | OS services (`NT AUTHORITY\SYSTEM`) |

> ✅ **Key Insight**:  
> Even if you’re an **Administrator**, your processes start at **Medium IL** until you **explicitly elevate**.

---
## 🛡️ UAC in Action
### Scenario: You’re logged in as `admin` (member of Administrators group)

| Action | Integrity Level | Privileges |
|-------|------------------|-----------|
| Open `cmd.exe` normally | Medium | Cannot modify system files, install software, etc. |
| Right-click → “Run as administrator” | High | Full admin rights (after UAC prompt) |

> 💥 **Without elevation**:  
> - `net user test /add` → **Access denied**  
> - `whoami /groups` → shows `Mandatory Label\Medium Mandatory Level`

> ✅ **After elevation**:  
> - Same command → **Success**  
> - `whoami /groups` → shows `Mandatory Label\High Mandatory Level`

---
## 🔍 In Your Meterpreter Session

- **Initial session**: `VICTIM\admin` with **Medium IL**  
  → Can’t run admin commands (e.g., `net user`, modify `C:\Windows`)
- **After UAC bypass**: New session with **High IL**  
  → Can run **all admin commands** without UAC prompts

> ⚠️ **Important**:  
> - Both sessions show `getuid => VICTIM\admin`  
> - But **integrity level** (not username) determines what you can do  
> - Use `getprivs` or `whoami /priv` to see actual privileges

---
## 🧪 How to Check Integrity Level

In a shell:
```cmd
whoami /groups | findstr "Mandatory"
```
- `Medium Mandatory Level` → **not elevated**  
- `High Mandatory Level` → **elevated admin**

In Meterpreter:
```msf
getprivs
```
→ Elevated sessions show privileges like:
- `SeDebugPrivilege`
- `SeTakeOwnershipPrivilege`
- `SeBackupPrivilege`

---
## 🔒 Why This Matters

- **UAC is a runtime gatekeeper**, not just a group membership check
- **Malware must bypass UAC** to gain real admin power — even with admin credentials
- **Penetration testers** must escalate from **medium → high integrity** to perform privileged actions

> 🔥 **Bottom line**:  
> **Admin group = potential**  
> **High integrity = actual power**

---
---
# Why Migrate to `NT AUTHORITY\SYSTEM` After UAC Bypass?

## 🔑 Short Answer:

**Elevated admin ≠ SYSTEM**  
Even with **high-integrity admin rights**, you are still limited by the **user context**.  
`NT AUTHORITY\SYSTEM` is the **highest privilege** in Windows — above even local Administrators.

---
## 🧠 Key Differences

| Context                               | Integrity Level | Token Privileges                                            | Capabilities                                                                                      |
| ------------------------------------- | --------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| **Unelevated Admin**                  | Medium          | Limited (e.g., no `SeDebugPrivilege`)                       | Cannot access LSASS, modify system files                                                          |
| **Elevated Admin** (after UAC bypass) | High            | Full admin privileges (`SeTakeOwnership`, `SeBackup`, etc.) | Can install software, modify most files, dump SAM                                                 |
| **NT AUTHORITY\SYSTEM**               | System          | **All privileges enabled** + kernel-level access            | Full control: read **all memory**, impersonate **any user**, access **LSASS**, disable **AV/EDR** |

> ✅ **UAC bypass gets you elevated admin → migrate to SYSTEM for full OS control**

---
## 🔍 Why You Still Need SYSTEM

### 1. **Credential Access**
- Only **SYSTEM** can read **LSASS memory** → extract **plaintext passwords**, **hashes**, **Kerberos tickets**
- Tools like Mimikatz/Kiwi **require SYSTEM**

### 2. **Persistence & Defense Evasion**
- Many persistence mechanisms (e.g., **service creation**, **WMI event subscriptions**) work best as SYSTEM
- Some EDRs restrict even elevated admins — but rarely block SYSTEM

### 3. **Lateral Movement**
- To dump **domain hashes** from a Domain Controller, you need **SYSTEM** to access `NTDS.dit`
- Pass-the-Hash/Ticket attacks often require **full token control**

### 4. **Process Access**
- Some critical processes (e.g., `lsass.exe`, `winlogon.exe`) only allow **SYSTEM** to open them
- Without SYSTEM, you **cannot migrate** into them or dump their memory

---
## 🛠️ Practical Example
After UAC bypass:
```msf
meterpreter > getuid
Server username: VICTIM\admin          # ← Still a user account
meterpreter > getprivs
... SeDebugPrivilege ...              # ← Elevated, but not SYSTEM
```

After migrating to `lsass.exe`:
```msf
meterpreter > migrate 688             # lsass PID
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM   # ← Kernel-level trust
meterpreter > load kiwi
meterpreter > creds_all               # ← Now works!
```

---
## 💡 Summary
- **UAC bypass** = escape user sandbox → gain **admin power**
- **Migrate to SYSTEM** = gain **OS kernel trust** → unlock **full post-exploitation**

> 🔥 **Admin lets you *use* the system. SYSTEM lets you *own* it.**

---
---
# SAM vs. LSASS.EXE

### ✅ **Elevated Admin CAN dump the SAM database** 

- The **SAM file** (`C:\Windows\System32\config\SAM`) is protected, but an **elevated admin** (high integrity) has the privileges (`SeBackupPrivilege`, `SeTakeOwnershipPrivilege`) to:
  - Take ownership of the SAM file
  - Read it directly from disk
  - Extract **NTLM hashes** offline (e.g., with `secretsdump.py`)

> 🔑 So yes: **UAC bypass → elevated admin → can dump SAM hashes**

---
### ❌ **But Elevated Admin CANNOT read LSASS memory directly**
- **LSASS.exe** runs as **NT AUTHORITY\SYSTEM**
- Even elevated admins **cannot open LSASS process memory** by default due to:
  - **Protected Process Light (PPL)** on modern Windows
  - **Access restrictions**: Only SYSTEM (or kernel) can read LSASS memory
- Tools like **Mimikatz** require **SYSTEM** to run `sekurlsa::logonpasswords`

> 🔥 So: **Only SYSTEM can extract plaintext passwords, Kerberos tickets, or live session credentials from LSASS**

---
### 🧠 Summary Table

| Action                                           | Requires                                                   |
| ------------------------------------------------ | ---------------------------------------------------------- |
| **Dump SAM hashes from disk**                    | ✅ Elevated Admin (High IL)                                 |
| **Read LSASS memory (plaintext creds, tickets)** | ❌ Requires **NT AUTHORITY\SYSTEM**                         |
| **Use `hashdump` in Meterpreter**                | ✅ Works with **elevated admin** (uses registry/SAM backup) |
| **Use `sekurlsa::logonpasswords`**               | ❌ Requires **NT AUTHORITY\SYSTEM**                         |

> 💡 In practice:  
> - **UAC bypass** → get **SAM hashes** → crack or Pass-the-Hash  
> - **Migrate to SYSTEM** → get **plaintext passwords & tickets** → Golden Ticket, lateral movement

So your observation is correct — **elevated admin can dump SAM**, but **not LSASS**. The two are fundamentally different attack surfaces.

---
---
When you're doing web directory enumeration (using tools like `gobuster`, `ffuf`, or `dirb`) :

### The Cheat Sheet

| **Code**             | **Meaning**      | **What it means for a Pentester**                                                                                 |
| -------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------- |
| **200 OK**           | **Success**      | The door is open! You found a valid file or folder.                                                               |
| **404 Not Found**    | **Missing**      | There is nothing here. Move on to the next word in your list.                                                     |
| **401 Unauthorized** | **Locked**       | The door exists, but you need a key (password/token) to enter. **This is a great target.**                        |
| **403 Forbidden**    | **No Entry**     | The door exists, but the server is told never to let you in (often due to IP whitelisting or folder permissions). |
| **301 / 302**        | **Redirect**     | You're being sent to a different door. (e.g., `/admin` redirects to `/admin/login.php`).                          |
| **500 Error**        | **Server Crash** | You broke something. Sometimes sending a weird character in the URL causes the code to fail.                      |

---
---
