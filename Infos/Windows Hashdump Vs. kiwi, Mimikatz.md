**It depends on which command or module you are using.** In Metasploit, `hashdump` and `kiwi` (Mimikatz) represent two different ways of getting passwords. Here is the technical breakdown of the difference:

---
### 1. `hashdump` (The Disk/Registry Method)

When you type `hashdump` in a standard Meterpreter shell, it is usually targeting the **SAM (Security Account Manager)**.

- **Where it lives:** On the disk at `C:\Windows\System32\config\SAM`.
    
- **How it works:** Because the OS locks this file while it’s running, you can't just "copy" it. Metasploit’s `hashdump` command injects a small piece of code into a process (like `services.exe`) to grab the **Registry Hives** (SAM and SYSTEM) from memory where the kernel has them open.
    
- **What you get:** You get the **NTLM hashes for LOCAL users only** (e.g., the local Administrator, Guest, or custom local accounts).
    
- **Limitation:** It contains **zero** information about Domain Users (Active Directory accounts).

---
### 2. `kiwi` / Mimikatz (The LSASS/Memory Method)

When your teacher uses `load kiwi` and then runs `lsa_dump_sam` or `creds_all`, they are attacking **LSASS (Local Security Authority Subsystem Service)**.

- **Where it lives:** In the **RAM** as a running process (`lsass.exe`).
    
- **How it works:** LSASS is the "gatekeeper" of Windows. When a user logs in (Local or Domain), LSASS handles the authentication and keeps a copy of the credentials in its own memory space so the user doesn't have to re-type their password every time they access a network share.
    
- **What you get:** * **NTLM Hashes** for both Local AND Domain users.
    
    - **Cleartext Passwords** (if WDigest is enabled or on older Windows versions).
        
    - **Kerberos Tickets** (used for Pass-the-Ticket attacks in CRTP).
    
- **Requirement:** This requires **SYSTEM** privileges because `lsass.exe` is a highly protected process.

---
### 3. Comparison for your Lab Work

|**Feature**|**hashdump (SAM)**|**kiwi (LSASS)**|
|---|---|---|
|**Location**|Disk (Registry Hive)|RAM (Active Process)|
|**Data Type**|Static (stored on the box)|Dynamic (whoever is logged in now)|
|**Target Accounts**|Local users only|Local + Domain + Service accounts|
|**Bypass Needed**|Usually just Admin|SYSTEM + AV/AMSI bypass|

---
# 1. Does `hashdump` get <u>Domain Admin</u> creds when logged in ?

**No.** Even if a Domain Admin is currently logged into the machine, `hashdump` will not see them.

- **The Reason:** `hashdump` targets the **SAM (Security Account Manager)** database. The SAM is a local file that only contains accounts created _on that specific machine_ (e.g., `.\Administrator`).
    
- **The Domain Logic:** Domain Admin accounts do not live in the local SAM. Their credentials live in the **NTDS.dit** file on the Domain Controller.
    
- **The Exception:** When a Domain Admin logs into a workstation, their credentials are "cached" locally so they can log in if the network is down. However, `hashdump` does not dump these "Cached Domain Credentials" (MSCACHE/MSCASH). You need specific scripts or **Kiwi** to extract those.

To get the Domain Admin who is currently logged in, you must attack the **LSASS process** using `kiwi`.

---
# 2. Is `hashdump` Noisy?

**Medium Noise.**

- **On Disk:** It doesn't usually write a file to disk, which helps avoid basic AV.
    
- **In Memory:** It has to "inject" code into a process (like `lsass.exe` or `services.exe`) to read the registry hives. High-end EDR (Endpoint Detection and Response) like CrowdStrike or SentinelOne will see this "Process Injection" or "Cross-Process Memory Read" and alert the blue team immediately.
    
- **Registry:** It triggers a read of the `SAM` and `SYSTEM` registry keys, which can be monitored.

---
# 3. Is `kiwi` (Mimikatz) Noisy?

**High Noise.** Mimikatz is the #1 enemy of Windows Security.

- **Signature Noise:** The `kiwi` extension's DLL has been fingerprinted for a decade. As you saw in your first screenshot, simply mentioning `"AmsiUtils"` triggered AMSI. If you try to `load kiwi` without a solid AMSI bypass, you will be caught instantly.
    
- **Behavioral Noise:** To dump credentials, Kiwi performs "LSASS Minidumping" or uses the `SeDebugPrivilege` to open a handle to `lsass.exe`. Modern Windows Defender and EDRs are specifically tuned to watch for _anyone_ touching LSASS.

---
# 4. Comparison Table: Red Team Strategy

|**Tool**|**Target**|**Gets Domain Admins?**|**Noise Level**|**Best Use Case**|
|---|---|---|---|---|
|**`hashdump`**|SAM Hive (Local)|No|Medium|Getting local admin to "Pass-the-Hash" to identical local accounts on other PCs.|
|**`kiwi`**|LSASS (Memory)|**Yes**|**High**|Stealing cleartext passwords or Kerberos tickets from active sessions.|

# <u>The "Silent" Professional Way</u> :

In your labs, if you want to be quiet, you don't use `kiwi` or `hashdump` directly. Instead, you might:

1. **Use `comsvcs.dll`:** Use a native Windows tool to dump LSASS memory to a file, then download that file and parse it with Mimikatz on _your_ machine.
    
2. **VSSAdmin:** Create a shadow copy of the drive to steal the SAM/SYSTEM files while the OS isn't looking.

### 1. The Logic: Bringing the Mountain to Muhammad

Normally, <u>Mimikatz</u> goes _to_ the <u>LSASS</u> process to find passwords. With this method, you **copy** the LSASS process's memory into a file (a "minidump"), bring that file to your own Kali machine, and run Mimikatz there.

- **On Target:** No "malicious" tools are run. Only a native Windows DLL.
    
- **On Kali:** You do the heavy lifting where the target's AV can't see you.

---
### 2. How it Works (The Execution)

You use the `rundll32.exe` utility to call a specific function inside `comsvcs.dll` called `MiniDump`.

**The Command (Run from a SYSTEM shell):**

```PowerShell
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\windows\temp\lsass.dmp full
```

**Breakdown of the syntax:**

1. **`rundll32.exe`**: A legitimate Windows tool used to run functions inside DLL files.
    
2. **`comsvcs.dll`**: The "Component Services" DLL. It contains a function intended for debugging crashed apps, but we hijack it.
    
3. **`<LSASS_PID>`**: You must replace this with the actual Process ID of `lsass.exe` (you find this by typing `ps` in Meterpreter).
    
4. **`C:\windows\temp\lsass.dmp`**: The output file where the memory will be saved.
    
5. **`full`**: Tells the DLL to dump the entire memory space of the process.

---
### 3. The "Gotcha" (Privileges)

In your second screenshot, you were logged in as `IIS APPPOOL\DefaultAppPool`.

- **Will this work?** **No.**
    
- **Why?** `lsass.exe` is owned by `SYSTEM`. To "read" the memory of a SYSTEM process, your own process must have `SeDebugPrivilege`. Only Administrators and SYSTEM have this.

Your teacher was likely looking for a token to impersonate (using **Incognito**) to get those privileges before trying this.

---
### 4. Why this is "Cool" (Evasion)

- **Bypasses Signature Scanners:** `comsvcs.dll` is signed by Microsoft. AV won't delete it.
    
- **Bypasses AMSI:** Since you aren't running a script or a known "bad" command like `"AmsiUtils"`, AMSI doesn't trigger.
    
- **Offline Analysis:** Once you have the `.dmp` file, you download it to your Kali machine and use Mimikatz:

```Bash
  # On your Kali machine
  mimikatz # sekurlsa::minidump lsass.dmp
  mimikatz # sekurlsa::logonpasswords
```

---
### 5. Is it 100% Stealthy?

Not anymore. Modern EDRs monitor `rundll32.exe` calling `comsvcs.dll`. They know that unless a developer is debugging a crash, there's no reason for that DLL to touch `lsass.exe`.
