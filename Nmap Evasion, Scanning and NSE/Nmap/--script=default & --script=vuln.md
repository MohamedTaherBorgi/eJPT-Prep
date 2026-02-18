In Nmap, scripts are powered by the **NSE (Nmap Scripting Engine)**. Choosing between these three depends on whether you want a "polite" scan or a "loud" and aggressive one.

### 1. `-sC` (The "Default" Flag)

This is exactly the same as typing `--script=default`.

- **What it does:** It runs a collection of scripts that Nmap developers consider **safe**, **fast**, and **reliable**.
    
- **Safety:** Very high. These scripts are designed not to crash services or fill up log files with garbage.
    
- **Usage:** You should use this on almost every scan. It handles basic things like grabbing SSH keys, identifying web server versions, and checking for open SMB shares.

### 2. `--script=vuln`

This is a "Category" scan. Instead of running specific scripts, it tells Nmap: "Run every script in the 'vuln' category."

- **What it does:** It checks for specific, known vulnerabilities (like EternalBlue, Heartbleed, or Shellshock).
    
- **Safety:** **Low.** These scripts are "intrusive." They work by actually trying to trigger a bug in the target system to see if it’s vulnerable.
    
- **Downside:** It can occasionally crash an old or unstable service. It is also extremely "loud"—any decent firewall or IDS (Intrusion Detection System) will see this and block your IP immediately.
    

### 3. Comparison Table

|**Feature**|**-sC / --script=default**|**--script=vuln**|
|---|---|---|
|**Intent**|General information gathering.|Finding a specific "way in" (exploit).|
|**Speed**|Fast.|Slower (checks many specific CVEs).|
|**Risk**|Low (Safe).|High (Can crash services).|
|**Stealth**|Moderate.|Zero (Very noisy).|

---

### 🛠️ When to use which?

- **Standard Enumeration:** Always start with `-sC`. It gives you the "lay of the land" without breaking anything.
    
    - _Example:_ `nmap -sC -sV <target>`
        
- **When you’re stuck:** If you see a service but don't know how to attack it, try `--script=vuln`.
    
    - _Example:_ `nmap --script=vuln -p 80,445 <target>`
        

### 💡 Pro-Tip: The "Middle Ground"

If you want to be specific, you don't have to run the whole `vuln` category. You can target a specific service. For example, if you see an SMB port (445) open, you can run only the SMB vulnerability scripts:

`nmap --script smb-vuln* -p 445 <target>`