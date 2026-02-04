## Core Functions

- **Logical addressing** (IP addresses)
- **Routing & forwarding** across networks
- **Path selection** from source to destination
- **Abstraction** of underlying physical networks

---
## Key Protocols

| Protocol | Purpose |
|--------|--------|
| **IP (IPv4/IPv6)** | Primary protocol for addressing and routing |
| **ICMP** | Error reporting & diagnostics (`ping`, `traceroute`) |
| **DHCP** | Dynamic IP address assignment |

---
## IP Versions

| Feature | **IPv4** | **IPv6** |
|--------|--------|--------|
| Address Size | 32-bit | 128-bit |
| Format | `192.168.1.10` | `2001:db8::1` |
| Address Space | ~4.3 billion | ~3.4×10³⁸ |
| Status | Widely used | Future standard |

---
## IP Addressing Types

- **Unicast**: One-to-one
- **Broadcast**: One-to-all (local subnet only)
- **Multicast**: One-to-many (specific group)

---
## IPv4 Header Key Fields

| Field              | Size    | Purpose                                           |
| ------------------ | ------- | ------------------------------------------------- |
| **Version**        | 4 bits  | `4` for IPv4                                      |
| **Header Length**  | 4 bits  | Header size in 32-bit words (min 5 = 20 bytes)    |
| **Total Length**   | 16 bits | Entire packet size (header + payload)             |
| **TTL**            | 8 bits  | Max hops before discard (decremented per router)  |
| **Protocol**       | 8 bits  | Next-layer protocol (`6`=TCP, `17`=UDP, `1`=ICMP) |
| **Source IP**      | 32 bits | Sender’s IP                                       |
| **Destination IP** | 32 bits | Receiver’s IP                                     |
| **Flags**          | 3 bits  | Fragmentation control (`DF`, `MF`)                |
| **Identification** | 16 bits | Reassembly of fragments                           |

---
## Additional Features

- **Fragmentation**: Splits large packets for MTU compatibility
- **Subnetting**: Divides networks for efficiency/security
- **ICMP Integration**: Enables network diagnostics (`ping` = ICMP echo)

---
# IPv4 Addresses

## Structure
- **32-bit address** = **4 octets** (bytes), each 8 bits
- Written in **dotted-decimal notation**:  
  `73.5.12.132`

---
## Reserved IPv4 Ranges (RFC 5735)

| Range            | Purpose                                                  |
| ---------------- | -------------------------------------------------------- |
| `0.0.0.0/8`      | "This" network (used in routing)                         |
| `127.0.0.0/8`    | **Loopback** (local host, e.g., `127.0.0.1` = localhost) |
| `10.0.0.0/8`     | Private network (Class A)                                |
| `172.16.0.0/12`  | Private network (Class B)                                |
| `192.168.0.0/16` | Private network (Class C)                                |
| `169.254.0.0/16` | Link-local (APIPA – auto-assigned when DHCP fails)       |
| `224.0.0.0/4`    | Multicast                                                |
| `240.0.0.0/4`    | Reserved for future use                                  |

> 🔒 **Private IPs** (`10.x.x.x`, `172.16–31.x.x`, `192.168.x.x`) are **not routable on the public internet** — used in LANs, labs, and corporate networks.
