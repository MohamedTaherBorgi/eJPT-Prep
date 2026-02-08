## 🔍 What Is SNMP?

**Simple Network Management Protocol (SNMP)** is an **application-layer protocol** used to:
- Monitor network devices (routers, switches, printers, servers)
- Configure settings remotely
- Receive alerts (**traps**) on events

### Core Components
| Component | Role |
|----------|------|
| **SNMP Manager** | Your Kali box — sends queries |
| **SNMP Agent** | Runs on target device — responds to queries |
| **MIB (Management Information Base)** | Hierarchical database of device info (each item = **OID**) |

### Versions & Security
| Version | Auth Method | Risk |
|--------|-------------|------|
| **SNMPv1** | Community string (plaintext "password") | High |
| **SNMPv2c** | Community string + bulk transfers | High |
| **SNMPv3** | User-based auth + encryption | Secure |

> ⚠️ **90% of SNMP vulns come from v1/v2c with weak community strings**

### Ports
- **UDP 161**: SNMP queries (manager → agent)
- **UDP 162**: SNMP traps (agent → manager)

---
## ⚠️ Critical Risks

- **Information leakage**: OS versions, user accounts, network topology
- **Configuration changes**: Some devices allow **write access** via SNMP
- **Lateral movement**: Discover internal IPs → pivot

> 🔥 **Real-world impact**:  
> SNMP leaks have led to **full network compromise** in IoT/OT environments.

