# Ping Sweeps (ICMP Echo Requests)

## Purpose

Discover **live hosts** in an IP range by sending **ICMP Echo Requests** (`ping`) and listening for **Echo Replies**.

---
## How It Works

- Send `ping` to multiple IPs (e.g., `192.168.1.1–254`)
- Hosts that respond are **alive/reachable**
- Non-responsive hosts may be:
  - Offline
  - Blocking ICMP (firewall)
  - Configured to ignore ping

> ⚠️ **Not reliable on all systems** — many OSes and firewalls **block or ignore ICMP** by default.  
> ❌ **No response ≠ host is down**

---
## Why Ping Sweeps Fail

| System | Behavior |
|-------|--------|
| **Windows (modern)** | Often disables ICMP replies via firewall |
| **Linux** | May drop ICMP via `iptables`/`nftables` |
| **Network devices** | Routers/firewalls frequently filter ICMP |
| **Cloud instances** | Security groups often block inbound ICMP |

---
## Practical Usage

### Recommended: Nmap

```bash
nmap -sn 192.168.1.0/24    # Uses ARP + ICMP + other probes
```

- `-sn`: Ping sweep only (no port scan)
- Faster, more reliable, handles timeouts

> 💡 For networks where ICMP is blocked, skip ping entirely:  

```bash
nmap -Pn 192.168.1.0/24   # Assume all hosts are up, scan ports directly
```

---
## OS Fingerprinting via TTL

ICMP replies include a **Time-To-Live (TTL)** value that hints at the OS:

| Initial TTL | Likely OS                             |
| ----------- | ------------------------------------- |
| **64**      | Linux, macOS, modern Unix             |
| **128**     | Windows                               |
| **255**     | Cisco routers, legacy network devices |

> 🔍 Observed TTL = Initial TTL – number of hops  

Example:
```bash
ping 192.168.1.10
# Reply: TTL=64 → likely Linux
```

---
## Key Takeaway

✅ Use ping sweeps for **initial reconnaissance**, but **never rely on them alone**.  

✅ Always follow up with **port scanning** (`nmap -Pn`) for accurate host discovery in modern environments.

---
---
# Nmap Ping Scan Notes

- `nmap -sn -iL file.txt`  
  → Performs **ping scan only** (no port scan) on IPs listed in `file.txt`.

- `nmap -sn -PS <target>`  
  → **`-PS` overrides `-sn`** — it enables **TCP SYN ping** to port 80 (or specified ports).  
  → `-PS` = **TCP SYN ping sweep** (sends SYN packet, not ICMP).

> 💡 `-PS` is a **host discovery option**, not a port scan. Common variants:  
> - `-PS22,80,443` → SYN ping on those ports  
> - `-PA` → ACK ping  
> - `-PU` → UDP ping

### TCP RST After SYN/SYN-ACK (Half-Open Scan)

In a **SYN scan** (`nmap -sS`), the attacker:

1. Sends **SYN** to target port  
2. If port is **open**: target replies with **SYN-ACK**  
3. Attacker **immediately sends RST** (not ACK) → **aborts connection**
### Why?

- Avoids full TCP handshake → **stealthier**  
- Leaves no log of completed connection on target  
- Faster (no data transfer needed)

> 🔍 This is how `nmap -sS` determines open ports **without establishing a full session**.
---
---
