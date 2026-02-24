# Clearing Your Tracks – Windows & Linux Post-Exploitation

## ⚠️ Critical Ethical Note

> **NEVER delete Windows Event Logs or critical system logs** unless explicitly authorized in the Rules of Engagement (RoE).  
> These logs contain forensic data the client needs for incident response and compliance.  
> **Your job**: Remove **your artifacts only** — not evidence of the compromise itself.

---
## 🪟 Windows Track Clearing

### ✅ Safe Cleanup (Your Artifacts Only)

| Artifact Type | Location | Cleanup Command |
|---------------|----------|-----------------|
| **Uploaded files** | `C:\Temp\`, `C:\Windows\Temp\` | `del C:\Temp\* /q` |
| **MSF payloads** | Varies (check module docs) | `del %TEMP%\*.exe /q` |
| **PsExec service** | Created by `psexec` module | `sc delete PSEXESVC` |
| **Scheduled tasks** | Created by you | `schtasks /delete /tn "YourTask" /f` |
| **User accounts** | Created backdoors | `net user backup_admin /delete` |
| **SSH keys** | `C:\Users\<user>\.ssh\` | `del C:\Users\<user>\.ssh\authorized_keys` |

### ❌ NEVER Delete (Client Evidence)

```cmd
wevtutil cl Security    ← DO NOT RUN
wevtutil cl System      ← DO NOT RUN
wevtutil cl Application ← DO NOT RUN
```
> 💡 **Why**: These logs show attack timeline, affected accounts, and scope — critical for client remediation.

### 🔍 Finding MSF Artifacts

```cmd
# Search for Meterpreter files
dir /s /b C:\*.exe | findstr /i "meter meterp"

# Check temp directories
dir %TEMP%
dir C:\Windows\Temp
```

### 🧹 MSF-Specific Cleanup

| Module | Artifact | Removal |
|--------|----------|---------|
| `psexec` | `PSEXESVC` service | `sc delete PSEXESVC` |
| `hta_server` | HTA file on disk | `del %TEMP%\*.hta` |
| `web_delivery` | PowerShell script block | No disk artifact (in-memory only) |
| `getgui` | Hidden user account | `net user new_user /delete` + registry cleanup |

---
## 🐧 Linux Track Clearing

### ✅ Safe Cleanup (Your Artifacts Only)

| Artifact Type | Location | Cleanup Command |
|---------------|----------|-----------------|
| **Uploaded files** | `/tmp/`, `/dev/shm/` | `rm -f /tmp/* /dev/shm/*` |
| **Reverse shells** | Processes | `pkill -f "bash -i >& /dev/tcp"` |
| **Cron jobs** | `/etc/cron.*`, `crontab -l` | `crontab -r` (current user) |
| **SSH keys** | `~/.ssh/authorized_keys` | `sed -i '/your_key/d' ~/.ssh/authorized_keys` |
| **History** | `~/.bash_history` | `history -c && history -w` |
| **Netcat listeners** | Processes | `pkill -f "nc -lvp"` |

### 🔍 Finding Hidden Artifacts

```bash
# Check for suspicious processes
ps aux | grep -E "nc|bash.*tcp|python.*pty"

# Check cron jobs
crontab -l
ls -la /etc/cron.*

# Check SSH keys
grep -r "ssh-rsa" ~/.ssh/authorized_keys 2>/dev/null

# Check recent file modifications
find /tmp -type f -mtime -1 -ls
```

### 🧹 MSF-Specific Cleanup

| Module | Artifact | Removal |
|--------|----------|---------|
| `web_delivery` | Python HTTP server | `pkill -f "python.*http.server"` |
| `shell_to_meterpreter` | No disk artifact | Kill Meterpreter session → process dies |
| `sshkey_persistence` | `~/.ssh/authorized_keys` entry | Remove your public key line |
| `cron_persistence` | Crontab entry | `crontab -r` or edit manually |

---
## 🛡️ Best Practices for Clean Engagements

### During Exploitation

1. **Always work in `/tmp` (Linux) or `C:\Temp` (Windows)**  
   → Single directory to clean later
   
2. **Use in-memory execution when possible**  
   → Meterpreter, reflective DLL injection → no disk artifacts

3. **Document every action**  
   ```text
   [10:15] Uploaded nc.exe to C:\Temp\
   [10:17] Created user 'backup_admin'
   [10:22] Added SSH key to /root/.ssh/authorized_keys
   ```

### Before Leaving

1. **Windows checklist**:
   ```cmd
   del C:\Temp\* /q
   net user backup_admin /delete
   sc query | findstr "PSEXESVC" && sc delete PSEXESVC
   reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList
   ```
   
2. **Linux checklist**:
   ```bash
   rm -rf /tmp/* /dev/shm/*
   sed -i '/your_ssh_key/d' ~/.ssh/authorized_keys
   crontab -r
   history -c && history -w
   ```

3. **Verify cleanup**:
   ```cmd
   # Windows
   dir C:\Temp
   net user
   
   # Linux
   ls -la /tmp
   crontab -l
   ```

---
## 📋 Quick Reference Cheat Sheet

| OS | Command | Purpose |
|----|---------|---------|
| **Windows** | `del C:\Temp\* /q` | Remove all temp files |
| **Windows** | `sc delete PSEXESVC` | Remove PsExec service |
| **Windows** | `net user backdoor /delete` | Remove backdoor user |
| **Linux** | `rm -rf /tmp/*` | Remove all temp files |
| **Linux** | `history -c && history -w` | Clear shell history |
| **Linux** | `crontab -r` | Remove all cron jobs |
| **Both** | `pkill -f "nc\|bash.*tcp"` | Kill reverse shells |

> 🔥 **Golden Rule**:  
> **Remove your tools, not the evidence.**  
> The client needs logs to understand the breach — your job is to prove you can breach *and* clean up *your* mess.

