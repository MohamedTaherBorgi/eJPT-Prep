## <u>whatis</u>

The `whatis` command displays a one-line description of a given command, function, or file by searching the manual page names.

### Syntax

```bash
whatis <command>

whatis nmap
# Output: nmap (1) - network exploration tool and security / port scanner
```

---
---
## <u>man</u> (Manual Pages)

Displays **built-in documentation** for commands, system calls, config files, and more.
### Basic Usage

```bash
man <command>

Examples:
man nmap        # Shows nmap manual
man grep        # Shows grep options and usage
man 5 passwd    # Shows format of /etc/passwd (section 5 = config files)
```

>Press **`/`** then type a keyword and hit **Enter** to **search forward** (e.g., `/sn`).

---
---
## Nmap `-sn` — Ping Scan (Host Discovery)

### What It Does
- Performs **host discovery only** — **no port scanning**.
- Sends **ICMP echo requests**, **TCP SYN to port 443**, **TCP ACK to port 80**, and **ICMP timestamp requests** (by default) to determine if hosts are online.
- Also known as a **"ping sweep"**.

### Command
```bash
nmap -sn 192.168.1.0/24
```

---
---
## Clear Terminal

- **Normal Linux terminal** or **msfconsole**: Press `Ctrl + L` to clear the screen instantly.

---
---
## View TCP Connections with `netstat`

## 🐧 Linux

```bash
netstat -antp
```

- `-a`: Show all connections and listening ports  
- `-n`: Display addresses numerically (no DNS resolution)  
- `-t`: TCP connections only  
- `-p`: Show PID and program name (**requires root**)

## 🪟 Windows

```cmd
netstat -ano
```

- `-a`: Show all connections and listening ports  
- `-n`: Display addresses numerically  
- `-o`: Show **Process ID (PID)**

---
---
## fping

Fast ping sweeper that scans multiple hosts in parallel.

```bash
fping -ag 192.168.1.0/24   # Ping entire subnet, show only alive hosts
```

- Faster than `ping` or shell loops  
- Uses ICMP → may miss hosts that block ping  
- Install: `sudo apt install fping`

---
---
# `ping` vs `fping`

- **`ping`**:  
  → Built-in, but **only one target at a time**.  
  → To scan multiple hosts, you need loops (slow, sequential).

- **`fping`**:  
  → **Scans multiple IPs in parallel** (fast).  
  → Supports ranges/CIDR: `fping -g 192.168.1.0/24`  
  → Shows alive/unreachable hosts cleanly.

---
---
## Host Discovery: Nmap vs. fping

**Question:** Is `nmap -sn` the same as `ping` or `fping`? Do they use the same ICMP echo technique?

**Short Answer:** **Yes**, at their core, they all use **ICMP Echo Requests** to see if a host is alive. However, **Nmap** is "smarter" because it also uses **ARP** (on local networks) and **TCP probes** (on the internet) to find hosts that might be blocking standard pings. **fping** is optimized for **speed**, sending pings to multiple IPs in parallel without waiting for individual replies.

|Tool|Technique|Best Use Case|
|---|---|---|
|**ping**|ICMP Echo|Checking a **single** host.|
|**fping**|Parallel ICMP Echo|**Speed-scanning** large ranges for uptime.|
|**nmap -sn**|ICMP + TCP + ARP|**Pentesting** to find hosts hiding behind firewalls.|

---
---
## Nmap OS Detection

- `nmap -O target` → guess OS (needs root)
- `nmap -O --osscan-guess target` → aggressive guess (shows multiple options)
- Not 100% reliable — use as hint, not fact

---
---
## **Navigation in `man` pages (less pager)**

When you search for a term like `/-sS` in the manual, use these keys to navigate the highlighted results:

| Key     | Action                                       |
| ------- | -------------------------------------------- |
| **`n`** | Move to the **next** match (forward/down)    |
| **`N`** | Move to the **previous** match (backward/up) |
| **`q`** | **Quit** and exit the manual                 |

---
---
