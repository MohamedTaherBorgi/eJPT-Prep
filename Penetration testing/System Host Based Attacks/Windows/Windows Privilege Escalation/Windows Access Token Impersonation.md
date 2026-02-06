## 🔑 Are Access Tokens on All Windows Versions?

**Yes.**  

Access tokens have been a core part of Windows NT architecture since **Windows NT 3.1 (1993)** and exist in **all modern versions** (XP, 7, 10, 11, Server editions).

---
## 🧠 What Is an Access Token?

- Created by **LSASS** upon successful login
- Attached to **winlogon.exe** → inherited by **userinit.exe** → passed to all child processes
- Contains:
  - User SID
  - Group memberships
  - Privileges (e.g., `SeImpersonatePrivilege`)
  - Integrity level

> 💡 Think of it as a **session cookie with permissions** — no re-auth needed.

---
## 🔒 Token Types & Security Levels

| Token Type        | How Created                                 | Scope                                          | Risk   |
| ----------------- | ------------------------------------------- | ---------------------------------------------- | ------ |
| **Impersonation** | Non-interactive logon (e.g., SMB, RPC, IIS) | **Local system only**                          | Medium |
| **Delegation**    | Interactive logon (RDP, console, WinRM)     | **Network-wide** (can access remote resources) | High   |

> ✅ **Delegation tokens are gold** — they allow lateral movement.

---
## 🛠️ Exploitation Workflow Explained

### Initial State
- Meterpreter as `NT AUTHORITY\LOCAL_SERVICE` (low-priv service account)
- Has **`SeImpersonatePrivilege`** → can impersonate other tokens

### Why Not Migrate to `lsass.exe` Immediately?
- `migrate 3512` (lsass PID) → **"Access denied"**
- **Reason**: `LOCAL_SERVICE` lacks rights to open LSASS process
- **You must first impersonate a higher-priv token** to gain access

---
### Step 1: Load Incognito & List Tokens
```msf
load incognito
list_tokens -u
```
Output:
```
Delegation Tokens Available:
  DOMAIN\Administrator
  VICTIM\localadmin

Impersonation Tokens Available:
  (none)
```

> 💡 **Delegation tokens exist because someone logged in interactively** (e.g., RDP)

---
### Step 2: Impersonate Admin Token
```msf
impersonate_token "DOMAIN\Administrator"
getuid  # → DOMAIN\Administrator
```

> ❓ **Why `getprivs` failed after impersonation?**  
> - Impersonation gives you the **identity**, but **not full process privileges**  
> - Some commands (like `getprivs`) require a **real process context**  
> - **Solution**: Migrate to a process running as that user (e.g., `explorer.exe`)

---
### Step 3: Migrate to Stabilize Session
```msf
pgrep explorer
migrate <PID>
getprivs  # Now works
```

> ✅ **Migrating creates a real process** under the impersonated token → full privileges enabled

---
### Step 4: Escalate to SYSTEM
After impersonating admin:
- `list_tokens -u` now shows **`NT AUTHORITY\SYSTEM`** (because admin can access it)
- Impersonate SYSTEM → get full kernel privileges

---
## ⚠️ Critical Notes

### Why Can’t You Just Migrate to `lsass.exe`?
- **LSASS is protected**:
  - Runs as **SYSTEM**
  - Modern Windows uses **Protected Process Light (PPL)**
  - Only **SYSTEM or kernel** can open it directly
- **Token impersonation is the prerequisite** to gain rights to access LSASS

---
## 🧪 When No Tokens Are Available: Potato Exploits

If `list_tokens` returns nothing, but you have **`SeImpersonatePrivilege`**:
- Use **Potato-family exploits**:
  - `SigmaPotato`
  - `RoguePotato`
  - `SweetPotato`
  - `JuicyPotatoNG`

> 💡 These abuse **NTLM relay + token impersonation** to escalate to SYSTEM

---
## 🔒 Key Takeaways

- **`SeImpersonatePrivilege` = potential SYSTEM**
- **Impersonation ≠ full process** → migrate to stabilize
- **Delegation tokens > Impersonation tokens** for lateral movement

> 🔥 **Golden rule**:  
> **Token impersonation gets you the keys. Migration puts you in the driver’s seat.**


###################################################

---




