# Advanced Nmap Evasion & Firewall Detection

## 1. **Detecting Firewalls**

### Normal Scan (SYN)
```bash
nmap -Pn -sS 192.168.1.10
```

- **92 closed ports** → **no firewall** (firewalls usually show `filtered`)
- **Port 445 open** → service reachable

### ACK Scan (Firewall Check)
```bash
nmap -Pn -sA 192.168.1.10
```

- **Unfiltered**: Port responds to ACK → **no stateful firewall**
- **Filtered**: No response → **firewall dropping packets**

> ✅ **`filtered` = firewall active**  
> ✅ **`closed/unfiltered` = no firewall (or permissive rules)**

---
## 2. **Why Use `--badsum`?**

### The Trick
Send a packet with an **intentionally corrupted checksum**:
```bash
nmap -Pn --badsum 192.168.1.10
```

### How It Works
| Component | Behavior |
|----------|----------|
| **Real Server** | Drops malformed packet silently (no response) |
| **Lazy Firewall/IDS** | May respond with **RST** or **ICMP unreachable** before validating checksum |

### Interpretation

- **Response received** → **Firewall/IDS is present** (real host would stay silent)
- **No response** → No middlebox *responding to bad packets* (doesn't guarantee absence)

> 💡 **Use case**: Confirm if traffic is being intercepted by security appliances

---
## 3. **Packet Fragmentation (Evade IDS)**

Break packets into tiny pieces so IDS can’t reassemble/recognize the scan:
```bash
nmap -Pn -sV -f 192.168.1.10          # Default 8-byte fragments
nmap -Pn -sV -f --mtu 8 192.168.1.10  # Explicit MTU=8 (min legal size)
```

- **`--mtu 8`**: Sets **Maximum Transmission Unit** = 8 bytes (smallest valid IP fragment)
- Bypasses **signature-based IDS** that don’t defrag packets

---
## 4. **Decoy Spoofing + Source Port Obfuscation**

Spoof scan to appear from **multiple sources**, including the **subnet gateway**, and use a **common source port** like DNS (53):
```bash
nmap -Pn -sV -p3389 -f --data-length 200 -g 53 -D 192.168.1.1,10.0.0.5 192.168.1.10
```

- `-g 53`: Sets **source port to 53 (DNS)** — common, trusted port; blends in with normal traffic
- `-D <ip1>,<ip2>`: Sends **decoy scans** from fake IPs + your real IP (mixed randomly)
- **Gateway spoofing**: Use `192.168.1.1` (first IP in subnet = router) — looks like internal traffic!
- **Requirements**: You must be **on the same network** as target for spoofing to work

> 💡 **Why `-g 53`?** Firewalls/IDS often allow outbound DNS (port 53). Using it as source makes your scan look like legitimate client traffic.

---
## 5. **Extra Evasion Flags**

| Flag | Purpose |
|------|--------|
| `-n` | **Disable DNS resolution** (skip PTR lookups → faster, less noise) |
| `--data-length 200` | Pad packets with junk data (evade length-based signatures) |
| `--ttl 64` | Set custom TTL to mimic OS (e.g., `64`=Linux, `128`=Windows) |

---
## 🧠 Pro Tips

- **Fragmentation + Decoys + `-g 53` + `-n`** = ultra-stealthy scan combo
- **Never use `-D` on external targets** — only works on **local networks**
- **Firewall?** → If ports show `filtered`, switch to `-sS -f -D -g 53` + decoys
- **Always test `--badsum`** when you suspect hidden firewalls

> 🔥 **Golden Rule**:  
> *"Make your scan look like normal DNS chatter from the gateway."*

