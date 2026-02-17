
## 🔑 Short Answer:
> **"Access denied" = either UAC blocking (medium integrity) OR missing token privileges (even if elevated).**  
> To know which, check your **integrity level** and **privileges** — **not just your username**.

---

## 🧠 Step-by-Step: How to Diagnose "Access Denied"

### 1. **Check Your Current Context**
In Meterpreter:
```msf
getuid        # Shows user identity (e.g., VICTIM\admin)
getprivs      # Shows enabled privileges
```

In a shell:
```cmd
whoami /all
```
→ Look for:
- **Integrity Level**: `Medium` vs `High` vs `System`
- **Privileges**: e.g., `SeImpersonatePrivilege`, `SeDebugPrivilege`

---

### 2. **Interpret the Results**

| Scenario | Integrity Level | Privileges | Cause of "Access Denied" | Fix |
|--------|------------------|-----------|--------------------------|-----|
| **Unelevated Admin** | Medium | Limited (no `SeDebug`, etc.) | **UAC blocking** — you’re in Admin group but not elevated | **Bypass UAC** (e.g., UACMe) → get **High IL** |
| **Elevated Admin** | High | Full admin privileges | You have rights, but **can’t access LSASS/processes** due to **token type** or **PPL** | **Migrate to SYSTEM process** (e.g., `lsass.exe`) |
| **Service Account** (e.g., `LOCAL SERVICE`) | Medium/High | May have `SeImpersonatePrivilege` | Can’t run commands directly, but can **impersonate tokens** | Use **Incognito** → impersonate admin/SYSTEM token → then migrate |

---

### 3. **Real-World Examples**

#### ❌ Example 1: `net user test /add` → Access denied
- `getuid` = `VICTIM\admin`
- `whoami /groups` = **Medium Mandatory Level**
→ **UAC is blocking** → you need **UAC bypass**

#### ❌ Example 2: `migrate 688` (lsass) → Access denied
- `getuid` = `VICTIM\admin`
- `getprivs` = has `SeDebugPrivilege`
- But still fails
→ **LSASS is protected (PPL)** → you need to be **NT AUTHORITY\SYSTEM**, not just admin

#### ❌ Example 3: `hashdump` → Access denied
- You’re **elevated admin** (High IL)
- But `hashdump` requires **registry access** that only **SYSTEM** has
→ **Migrate to `lsass.exe` or `services.exe`**

---

## 🛠️ Decision Flowchart

```text
"Access denied" on command?
        │
        ▼
Run `getprivs` and `whoami /all`
        │
        ├── If **Integrity = Medium** → UAC is blocking → **Bypass UAC**
        │
        └── If **Integrity = High** but still denied → 
                │
                ├── Command needs **SYSTEM** (e.g., `hashdump`, `lsass` access) →                      **Migrate to SYSTEM process**
                │
                └── You have **SeImpersonatePrivilege** → **Use Incognito to                           impersonate token**, then migrate
```

---

## 💡 Pro Tips

- **UAC bypass** → gets you from **Medium → High integrity**
- **Token impersonation** → lets you **act as another user** (but session is unstable until you migrate)
- **Migrating to `lsass.exe`** → gives you **true SYSTEM** — required for credential dumping