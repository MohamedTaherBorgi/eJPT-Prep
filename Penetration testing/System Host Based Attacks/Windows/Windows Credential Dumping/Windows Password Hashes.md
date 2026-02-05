# Core Concepts

## Where Are Passwords Stored?

- **SAM (Security Accounts Manager)**: Local database storing **hashed passwords** for local accounts.
- **Active Directory (NTDS.dit)**: Stores domain account hashes on Domain Controllers.
- **In memory**: **LSASS process** caches credentials/hashes during active sessions.

> 🔒 **SAM FILE is locked** while OS runs → attackers dump hashes from **LSASS memory**.

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

