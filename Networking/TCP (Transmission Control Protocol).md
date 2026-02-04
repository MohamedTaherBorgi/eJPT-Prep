## Overview

- **OSI Layer**: **Layer 4 (Transport Layer)**
- **Type**: Connection-oriented, reliable, ordered delivery
- **Purpose**: Ensures data sent from one app arrives **accurately and in order** at another.

---
## Core Features

### ✅ Connection-Oriented

- Establishes a **virtual circuit** before data transfer.
- Uses the **3-way handshake** to initiate communication.

### ✅ Reliability

- Uses **ACKs (acknowledgments)** and **retransmission** for lost/corrupted segments.
- If no ACK → sender resends the segment.

### ✅ Ordered Delivery

- Segments may arrive out of order → TCP **reassembles them correctly** before passing to the application.

---
## 🔁 TCP 3-Way Handshake

| Step | Flag(s) | Description |
|------|--------|-------------|
| **1. Client → Server** | `SYN` | Client sends random **Initial Sequence Number (ISN)** |
| **2. Server → Client** | `SYN-ACK` | Server replies with its ISN + **ACK = Client_ISN + 1** |
| **3. Client → Server** | `ACK` | Client sends **ACK = Server_ISN + 1** → connection established |

> 🟢 After this: **Full-duplex data transfer begins**.

---
## 🚦 TCP Control Flags (in Header)

| Flag | Purpose |
|------|--------|
| **SYN** | Synchronize sequence numbers (start connection) |
| **ACK** | Acknowledgment field is valid |
| **FIN** | Sender has no more data → **graceful close** |
| **RST** | Reset connection (abrupt termination) |
| **PSH** | Push: deliver data to app immediately |
| **URG** | Urgent: process this data urgently |

> 💡 Example:  
> - **Connection setup**: `SYN` → `SYN-ACK` → `ACK`  
> - **Connection teardown**: `FIN` → `ACK` → `FIN` → `ACK`

---
## 🔢 TCP Port Ranges

| Range | Ports | Purpose | Examples |
|-------|------|--------|---------|
| **Well-Known** | `0 – 1023` | Standardized services (IANA) | `80/HTTP`, `443/HTTPS`, `22/SSH`, `21/FTP`, `25/SMTP` |
| **Registered** | `1024 – 49151` | Vendor/app-specific services | `3389/RDP`, `3306/MySQL`, `8080/HTTP-alt`, `27017/MongoDB` |
| **Dynamic/Private** | `49152 – 65535` | Ephemeral ports (client-side) | Used by OS for outgoing connections |

> ⚠️ **Max port**: `65535` (16-bit unsigned integer).

---
## Why TCP Matters in Pentesting ?

- **Service identification**: Open ports → running services.
- **Banner grabbing**: Connect to port → read service version.
- **Exploit reliability**: Most exploits use TCP (not UDP) for stable payload delivery.
- **Firewall rules**: Often allow TCP but block UDP — know the difference.