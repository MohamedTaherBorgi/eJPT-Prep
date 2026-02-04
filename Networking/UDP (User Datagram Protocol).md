## Overview

- **OSI Layer**: **Layer 4 (Transport Layer)**
- **Type**: Connectionless, lightweight, fast
- **Purpose**: Send data with **minimal overhead** — no guarantees on delivery or order.

---
## Core Characteristics

### ❌ Connectionless

- No handshake or session setup.
- Each **datagram is independent** — no shared state between sender/receiver.

### ❌ Unreliable

- **No ACKs**, **no retransmission**, **no ordering**.
- Packets can be **lost, duplicated, or arrive out of order** → app must handle it.

### ✅ Low Latency & Efficiency

- Smaller header (8 bytes vs TCP’s 20+ bytes).
- Ideal for **real-time** applications where speed > accuracy.

---
## Common UDP-Based Services

| Port | Service | Use Case |
|------|--------|--------|
| **53** | DNS | Domain name resolution |
| **67/68** | DHCP | IP address assignment |
| **161/162** | SNMP | Network monitoring |
| **123** | NTP | Time synchronization |
| **500** | ISAKMP/IPsec | VPN key exchange |
| **Various** | VoIP (SIP, RTP), Online Gaming, Video Streaming | Real-time media |

> ⚠️ Many firewalls **filter or block UDP** by default due to abuse (e.g., amplification attacks).

---
## TCP vs UDP Comparison

| Feature | **UDP** | **TCP** |
|--------|--------|--------|
| **Connection** | Connectionless | 3-way handshake |
| **Reliability** | ❌ No delivery guarantee | ✅ Guaranteed, ordered, retransmitted |
| **Header Size** | 8 bytes (low overhead) | 20–60 bytes |
| **Speed** | ⚡ Faster (no control logic) | Slower (due to reliability features) |
| **Use Cases** | Live video, VoIP, DNS, gaming | Web, email, file transfer, SSH |
| **State** | Stateless | Stateful (tracks connection) |

---
## UDP in Penetration Testing

### Challenges

- **Harder to scan**: No response ≠ port closed (could be filtered or ignored).
- Tools like `nmap -sU` are **slow and unreliable**.

### Opportunities

- **DNS zone transfers** (if misconfigured)
- **SNMP enumeration** (`snmpwalk`)
- **DHCP spoofing** (on local network)
- **Amplification attacks** (e.g., DNS/NTP reflection — **only in authorized labs!**)

> 🔍 Tip: Always check **UDP ports 53, 161, 67/68** — they often leak critical info.

✅ While less common than TCP exploits, **UDP services can be high-value targets** when misconfigured.

