# Core Concepts

## Where Are Passwords Stored?

- **SAM (Security Accounts Manager)**: Local database storing **hashed passwords** for local accounts.
- **Active Directory (NTDS.dit)**: Stores domain account hashes on Domain Controllers.
- **In memory**: **LSASS process** caches credentials/hashes during active sessions.

> 🔒 **SAM FILE is locked** while OS runs → <u>attackers dump hashes</u> from **LSASS memory**.

---
## Hash Types 

### 1. **LM Hash**

- **Used in**: Windows XP and earlier
- **Disabled by default**: From Windows Vista+
- **Weaknesses**:
  - Converts password to **UPPERCASE**
  - Splits into **two 7-char chunks** → easy brute-force
  - **No salt** → rainbow tables work instantly
- **Format**: `AAD3B435B51404EEAAD3B435B51404EE` (empty = blank password)

### 2. **NTLM Hash**

- **Used in**: All modern Windows (Vista+)
- **Algorithm**: **MD4** of UTF-16LE password
- **Strengths over LM**:
  - Case-sensitive
  - Supports full charset (symbols, Unicode)
  - No chunking → full password hashed as one
- **Format**: `31D6CFE0D16AE931B73C59D7E0C089C0` (empty = blank password)

> ✅ **Only NTLM matters today** — LM is legacy/dead.

---
## How Authentication Works: LSA vs LSASS

| Component | Role |
|---------|------|
| **LSA (Local Security Authority)** | Policy engine: defines *how* auth should work (e.g., “use NTLM”) |
| **LSASS (Local Security Authority Subsystem Service)** | Runtime enforcer: *processes* logins, caches creds, validates hashes |

### Authentication Flow

1. User enters password  
2. **LSASS** hashes it (NTLM)  
3. Compares hash to **SAM** (local) or **Active Directory** (domain)  
4. If match → **LSASS issues access token**  
5. Token grants permissions for session

> 💀 **LSASS = goldmine** — contains **plaintext passwords**, **hashes**, **Kerberos tickets**

---
## Attacker Perspective

### To Dump Hashes, <u>You Need</u>:

- **Administrative privileges** (to access LSASS)
- Tools like:
  - `mimikatz` (`sekurlsa::logonpasswords`)
  - Meterpreter (`hashdump`, `load kiwi`)
  - `secretsdump.py` (Impacket)

### Example Output (from `hashdump`):

```
Administrator:500:aad3b435...:31d6cfe0...:::
bob:1001:aad3b435...:e52cac67...:::
```

→ Format: `Username:RID:LM_hash:NT_hash:::`

> ⚠️ **Empty LM hash** (`aad3...`) = LM disabled (normal on modern Windows)

---
## Key Takeaways

- **NTLM hash = password equivalent** → Pass-the-Hash works
- **SAM can’t be copied live** → attack **LSASS in memory**
- **Admin rights required** to dump hashes
- **LM is obsolete** — ignore it unless testing ancient systems

> 🔑 **Steal the hash → own the account. Steal the ticket → own the domain.**

add these notes: Dumping & Cracking NTLM Hashes ● We can dump Windows password hashes by leveraging various utilities like: + The inbuilt meterpreter “hashdump” command + Mimikatz ● After we have dumped the hashes, we can crack them through the use of the following utilities: + John The Ripper + Hashcat put this in resume brief note (but didnt you say its impossible to read or copy sam when os running how hashdump does that ## Gemini said You caught a very important detail! You are right: if you try to go to `C:\Windows\System32\config\SAM` and right-click "Copy," Windows will stop you with an error saying **"The file is in use by another program."** The OS kernel keeps a "file lock" on it to prevent corruption or tampering. So, how does **`hashdump`** (or other tools) get around this? They don't just "copy" the file; they use one of three "backdoor" methods. --- ### 1. The Registry Method (The `hashdump` Secret) Windows doesn't just keep the SAM on the hard drive; it loads the contents into the **Windows Registry** while the computer is running. The SAM file on your disk is just a "hibernate" version. Once Windows boots, the data lives inside the Registry hive `HKEY_LOCAL_MACHINE\SAM`. - **How it works:** If you have **SYSTEM** privileges, you can ask the Windows Registry API to give you the data. - **The Trick:** Since `hashdump` runs as a high-privilege process (often after you've used `getsystem`), it has the authority to tell the Registry: _"Export your current memory-base of the SAM to me."_ It’s not touching the "locked" file on the disk; it’s talking to the Registry service that has the file open. --- ### 2. The Volume Shadow Copy (VSS) Method This is how "offline" dumping tools work while the OS is live. - **The Logic:** Windows has a feature called "Shadow Copy" used for backups. It creates a "snapshot" of the entire hard drive at a specific moment. +1 - **The Trick:** When you create a snapshot, the "lock" doesn't exist on the copy. An attacker can create a shadow copy of the `C:` drive, and then copy the SAM file out of the _snapshot_ instead of the live folder.)


crack with :
john --format=NT hashes.txt (uses default word list)
or
john --format=NT hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

OR
hashcat -a3 (?) -m 1000 (?) hashes.txt /usr/share/wordlists/rockyou.txt

now rdp or whatever.