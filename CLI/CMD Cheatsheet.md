## System Recon

| Command | Purpose |
|---|---|
| `whoami` | Current security principal |
| `whoami /user` | Show SID (local vs domain) |
| `hostname` | Machine name |
| `systeminfo` | OS, hardware, patch level |
| `ver` | Windows version |
| `set` | All environment variables (includes PATH) |
| `net config workstation` | Domain membership, workstation info |

### Identity Quick Reference

| `whoami` <u>Output</u> | Authority         | Database                      |
| ---------------------- | ----------------- | ----------------------------- |
| `MACHINE\user`         | Local Machine     | Local SAM                     |
| `DOMAIN\user`          | Domain Controller | Active Directory              |
| `NT AUTHORITY\SYSTEM`  | OS itself         | Internal (highest local priv) |

### SID Analysis
```cmd
whoami /user
````

- `S-1-5-21-[machine numbers]-1001` → **Local account**
- `S-1-5-21-[domain numbers]-1105` → **Domain account**

> **Red Team note:**
> `WINSRV2022-CORE\user` = local SAM account.  
> The machine's domain computer account appears as `WINSRV2022-CORE$` (with `$`).

---
## Network Recon

```cmd
ipconfig              # IP, subnet, gateway
ipconfig /all         # + DNS servers, MAC, DHCP status
netstat -abon         # All connections + PID + process name (bon = easy mnemonic 🇫🇷)
tracert <target>      # Hop-by-hop route trace
nslookup <domain>     # Forward DNS lookup
nslookup <IP>         # Reverse DNS lookup (PTR record)
nslookup example.com 1.1.1.1  # Use specific DNS server
```

### Netstat Flags

|Flag|Meaning|
|---|---|
|`-a`|All connections + listening ports|
|`-b`|Binary (process name) per connection|
|`-o`|PID per connection|
|`-n`|Numerical addresses/ports (no resolution)|

### Useful Filters

```cmd
netstat -abon | findstr -i 135      # Filter by port (case-insensitive)
set | findstr /i "path"             # Search env vars
tasklist /FI "imagename eq sshd.exe"  # Filter process list
```

> ⚠️ `findstr` won't show the process name line — it sits _below_ the matched line in `netstat -b` output.

---
## File System Navigation

```cmd
cd                    # Print current directory (where am I?)
cd ..                 # Go up one level
dir                   # List current directory
dir /a                # Include hidden + system files
dir /s                # Recursive listing
dir /s filename.txt   # Search for file recursively
tree /f               # Show all files in directory tree
tree /f /a            # ASCII mode (report-friendly)
tree C:\Users\user\Documents /f   # Scope to specific path
```

> ⚠️ Never run `tree /f` at `C:\` root — it'll run forever.

---
## File Operations

```cmd
type file.txt             # Print file contents
more file.txt             # Paginated view (Space = next page, Enter = next line)
some_command | more       # Pipe long output to paginate
copy file.txt C:\dest\    # Copy file
copy *.md C:\Markdown\    # Wildcard copy
move file.txt C:\dest\    # Move file
del file.txt              # Delete file
erase file.txt            # Same as del
mkdir folder_name         # Create directory
rmdir folder_name         # Remove directory
```

---
## Process Management

```cmd
tasklist                              # All running processes
tasklist /FI "imagename eq sshd.exe" # Filter by process name
taskkill /PID 4567                    # Kill process by PID
```

---
## System Utilities

```cmd
driverquery           # List installed drivers
driverquery | more    # Paginated driver list
chkdsk                # Check disk for errors/bad sectors
sfc /scannow          # Scan + repair system files
cls                   # Clear screen
help <command>        # Help for a command
<command> /?          # Alternative help flag (works on most commands)
```

---
## Quick Reference — Most Useful for Pentest

```cmd
# Identity & privilege check
whoami /all

# Domain membership
net config workstation

# Active connections + owning process
netstat -abon

# Find specific port or process
netstat -abon | findstr -i "445"

# Recursive file search
dir /s /a secret.txt

# Environment paths
set | findstr /i "path"

# System fingerprint
systeminfo | more
```

