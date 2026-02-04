## 🌐 Network Protocols

- Rules that enable **different systems** (hardware/software) to **communicate** over a network.
- Each service uses specific protocols (e.g., HTTP for web, SMB for file sharing).
- Communication happens via **packets**.

---
## 📦 Packets: The Building Blocks of Network Traffic

Every packet consists of two parts:

| Part        | Purpose                                                                                                                         |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **Header**  | Protocol-specific metadata (source/dest addresses, port, flags, sequence numbers). Ensures correct delivery and interpretation. |
| **Payload** | Actual data being transmitted (e.g., email content, file chunk, webpage HTML).                                                  |

> 💡 Packets travel as **electrical/optical signals** (Ethernet, Wi-Fi) → interpreted as **binary (0s/1s)** by receiving devices.

---
## 🧱 The OSI Model (7 Layers)

A conceptual framework standardizing network communication into **7 layers**, from physical hardware to user applications.

| #     | Layer            | Function                                             | Examples                          | **Data Unit (PDU)**                    |
| ----- | ---------------- | ---------------------------------------------------- | --------------------------------- | -------------------------------------- |
| **7** | **Application**  | Direct interface for user apps                       | HTTP, FTP, SSH, DNS, SMTP, SMB    | **Data**                               |
| **6** | **Presentation** | Data translation, encryption, compression            | SSL/TLS, JPEG, MPEG               | **Data**                               |
| **5** | **Session**      | Manages connections between apps                     | NetBIOS, RPC, APIs                | **Data**                               |
| **4** | **Transport**    | End-to-end communication, flow/error control         | TCP, UDP                          | **Segment** (TCP) / **Datagram** (UDP) |
| **3** | **Network**      | Logical addressing & routing                         | IP, ICMP, IPSec                   | **Packet**                             |
| **2** | **Data Link**    | Physical addressing, frame delivery, error detection | Ethernet, MAC addresses, Switches | **Frame**                              |
| **1** | **Physical**     | Raw bit transmission over media                      | Cables, Wi-Fi, USB, Hubs          | **Bits**                               |

---
## 🔑 Key Notes

- **Not all protocols fit perfectly** into OSI — it’s a **reference model**, not a rigid standard.

- **Real-world use**:  
  - TCP/IP model (4 layers) is more common in practice.  
  - But OSI helps **troubleshoot** (e.g., “Is it a Layer 2 or Layer 3 issue?”).
  
- **Security relevance**:  
  - Attacks target specific layers:  
    - Layer 2: ARP spoofing  
    - Layer 3: IP spoofing  
    - Layer 4: SYN floods  
    - Layer 7: SQLi, XSS

---
---
## TLS vs SSL

- **SSL (Secure Sockets Layer)**:  
  - Deprecated cryptographic protocol (v2, v3).  
  - Vulnerable to POODLE, BEAST attacks.  
  - **Should not be used**.

- **TLS (Transport Layer Security)**:  
  - Successor to SSL (v1.0 → v1.3).  
  - Provides encryption, integrity, and authentication for HTTP, SMTP, etc.  
  - Used in **HTTPS (port 443)**.

> 🔒 Modern systems use **TLS**, but the term "SSL" is still used colloquially (e.g., "SSL certificate").  
> ✅ Always enforce **TLS 1.2+**; disable SSL and TLS 1.0/1.1.