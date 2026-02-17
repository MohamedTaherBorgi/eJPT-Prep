For all confusions during this lab check :
[[Must know#Admin vs. High-Integrity Admin – What’s the Difference?]]
[[Must know#Why Migrate to `NT AUTHORITY SYSTEM` After UAC Bypass?]]
[[Must know#SAM vs. LSASS.EXE]]
# Bypassing UAC with UACMe – Clear & Technical Breakdown

## 🔐 What Is UAC?

- **User Account Control (UAC)**: Windows security feature (Vista+) that blocks silent privilege escalation.
- Even if you’re in the **local Administrators group**, actions requiring elevation trigger a **consent prompt**.
- **Default UAC level (3)** = bypassable. **Level 4 (Always Notify)** = much harder.

> ✅ **Prerequisite**: You must be a member of the **local Administrators group** to bypass UAC.

---
## 🔑 Core Concept

- **UAC ≠ Admin Rights**  
  Being in the **Administrators group ≠ SYSTEM**  
  → UAC still blocks silent privilege escalation  
- **Goal**: Bypass UAC prompt → get **true elevated privileges** (not just group membership)

---
## 🧠 Core Concept: UAC Bypass ≠ In-Place Elevation

- **You cannot elevate your current process** silently.
- UAC bypasses **spawn a NEW elevated process** — they do **not** upgrade your existing session.
- That’s why you need a **new payload** (`backdoor.exe`) — it becomes your elevated session.

---
## 🛠️ Step-by-Step Workflow Explained

### 1. Initial Exploit → Low-Priv Meterpreter
- Exploit HFS → get `meterpreter` as `VICTIM\admin`
- Payload: `windows/meterpreter/reverse_tcp` (**x86**)
- Target OS: **Windows x64**

> ❓ **Why migrate to `explorer.exe` (PID 2448)?**  
> - Initial session is **x86 on x64 OS** → limited compatibility  
> - `explorer.exe` runs as **native x64** → migrating gives you **x64 Meterpreter**  
> - Many UAC bypasses (like UACMe) **require x64** to work  
> → This is an **architecture upgrade**, **not** a privilege escalation  
> → You’re still `VICTIM\admin` (not SYSTEM)

---
### 2. Confirm Admin Group Membership
```msf
shell
C:\Windows\System32> net localgroup administrators
```
→ Confirms `admin` is in Administrators group.

> ❓ **Why `C:\Windows\System32>`?**  
> Meterpreter spawns `cmd.exe` in the **system directory** by default — not the user profile.

> ❓ **Why open `shell` inside Meterpreter?**  
> To run native Windows commands (`net user`, `whoami`, etc.) that Meterpreter doesn’t expose directly.

---
### 3. Why Generate a NEW Payload (`backdoor.exe`)?
- UACMe **cannot elevate your current Meterpreter**
- It **executes a new binary** with elevated privileges via Windows AutoElevate abuse
- So you need:
  - `Akagi64.exe` → the **bypass tool**
  - `backdoor.exe` → your **elevated payload**

> 💡 Think of it like this:  
> UACMe = **trusted launcher**  
> `backdoor.exe` = **your shell, launched elevated**

---
### 4. Execute UAC Bypass
```cmd
.\Akagi64.exe 23 C:\Temp\backdoor.exe
```
- Method `23`: Valid for your Windows version (check [UACMe docs](https://github.com/hfiref0x/UACME))
- Launches `backdoor.exe` **without UAC prompt** → connects to your **second listener**

✅ Result: **New Meterpreter session** with **high-integrity admin rights**

> ⚠️ `getuid` still shows `VICTIM\admin` — but now with **full admin privileges** (no UAC blocking)

---
### 5. Escalate to SYSTEM
- Elevated admin ≠ SYSTEM
- To get **NT AUTHORITY\SYSTEM**, migrate to a **SYSTEM-owned process**:
  ```msf
  ps          # Find lsass.exe (PID 688)
  migrate 688
  getuid      # Now: NT AUTHORITY\SYSTEM
  ```
OR
  ```msf
getsystem
  ```
> ❓ **Why didn’t `migrate explorer.exe` give SYSTEM?**  
> Because `explorer.exe` runs as the **logged-in user** (`VICTIM\admin`), **not** as SYSTEM.  
> Only processes like `lsass.exe`, `winlogon.exe`, or `services.exe` run as **SYSTEM**.

## OR easily via `exploit(windows/local/bypassuac_injection)`

and then
  ```msf
getsystem
  ```
---
## 🔑 Key Takeaways

| Action | Purpose |
|-------|--------|
| `migrate explorer.exe` | Upgrade from x86 → x64 Meterpreter (for UACMe compatibility) |
| `shell` | Run native Windows commands for enumeration |
| New payload + UACMe | Bypass UAC by spawning **new elevated process** |
| `migrate lsass.exe` | Escalate from **elevated admin → SYSTEM** |

> 🔥 **Golden Rule**:  
> **UAC bypasses spawn new processes — they don’t elevate your current one.**  
> That’s why you need the second Meterpreter session.



