### 1️⃣ Auditing Sudo Privileges

Before attempting privilege escalation, check what commands your current user can run with elevated privileges.

```bash
sudo -l
```

#### How to Interpret the Output

- `User <user> may run the following commands...`  
  Lists specific binaries you can execute as root.

- `(ALL : ALL) ALL`  
  You can run any command as any user.

- `NOPASSWD: sudo`  
  Allows execution of listed commands (``sudo``) without needing a password.  
  This significantly increases escalation potential.

---
### 2️⃣ Spawning a Root Shell

If `sudo -l` shows permission to run `bash`, `sh`, or `ALL`, you can spawn a root shell:

```bash
sudo bash -i
```

#### Command Breakdown

- `sudo` → Execute with root privileges  
- `bash` → Start a Bash shell  
- `-i` → Launch an interactive shell (stays open and accepts input)

---
## Key Takeaway

Always run `sudo -l` during enumeration.  
Misconfigured sudo permissions are one of the most common and reliable Linux privilege escalation vectors.
