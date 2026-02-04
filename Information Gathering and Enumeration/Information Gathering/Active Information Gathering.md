## <u>DNS</u>

### What is DNS?

- **Domain Name System (DNS)** resolves human-readable **domain names** to **IP addresses**.
- Acts like a **phone directory** for the internet.
- Public DNS resolvers (e.g., `1.1.1.1` – Cloudflare, `8.8.8.8` – Google) cache records for global domains.

---
---
### Common DNS Record Types
| Record    | Purpose                                                                             |
| --------- | ----------------------------------------------------------------------------------- |
| **A**     | Maps domain → **IPv4 address**                                                      |
| **AAAA**  | Maps domain → **IPv6 address**                                                      |
| **NS**    | Specifies **authoritative name servers**                                            |
| **MX**    | Points to **mail servers**                                                          |
| **CNAME** | **Alias** for another domain (e.g., `www.example.com → server-123.us-east.aws.com`) |
| **TXT**   | Holds **textual data** (e.g., SPF, DKIM, verification tokens)                       |
| **HINFO** | Host **hardware/OS info** (rarely used)                                             |
| **SOA**   | **Start of Authority** – primary DNS server & zone metadata                         |
| **SRV**   | Defines **services** (e.g., `_ldap._tcp.dc._msdcs.domain`)                          |
| **PTR**   | Reverse DNS – maps **IP → hostname**                                                |

---
---
## <u>DNS Interrogation</u>

- Actively querying DNS servers to **enumerate records** for a target domain.
- Reveals:
  - IP addresses
  - Subdomains
  - Mail servers (MX)
  - Name servers (NS)
  - Service endpoints (SRV)

> Tools: `dig`, `nslookup`, `host`, `dnsrecon`


---
---
## <u>DNS Zone Transfer</u>

# Key Note :
   --> **AXFR only works if the DNS server is misconfigured** to allow transfers from your IP.

- Legitimate process to **copy DNS zone files** between primary and secondary DNS servers.
- If **misconfigured**, attackers can request a full zone dump (<u>AXFR</u>).
- Reveals:
  - All subdomains and hostnames
  - **Internal network layout**
  - Potentially **internal IP addresses** (e.g., dev, DB, or admin hosts)

 >**zonetransfer.me** is a public domain **intentionally misconfigured** to allow zone transfers — used for testing and training.

---
---
## <u>DNS Enumeration Tools</u>: `dnsenum` vs `dig`

### `dnsenum`

- Automated tool that:
  - Finds name servers (`NS`)
  - Attempts **zone transfer (AXFR)** on each
  - Performs subdomain brute-force
  - Queries for MX, TXT, SPF, etc.
- **Convenient but noisy** — runs many queries automatically. (bruteforce)

Example:
```bash
dnsenum zonetransfer.me
```

### `dig` (More Precise & Reliable)

- Manual, granular control over DNS queries.
- Preferred for clarity and reliability during exams/labs.

Example:
```bash
dig ns zonetransfer.me (ns optionnal)
```
#### Zone Transfer with `dig`

Example:
```bash
dig axfr @ns1.zonetransfer.me zonetransfer.me
```

This command is asking:  
>“Hey `ns1.zonetransfer.me`, please send me **all DNS records you have** for the domain `zonetransfer.me`.”

>The response is a **complete dump of every record in that zone** including A, AAAA, CNAME, etc. — exactly as stored on **that one DNS server**.

---
---
## <u>Final workflow</u> :
### Working Commands

```bash
# 1. Find authoritative name servers
host -t ns zonetransfer.me (-t just to specify ns but we dont need to)
# OR
dig ns zonetransfer.me (ns optionnal)

# Example output: ns1.zonetransfer.me, ns2.zonetransfer.me

# 2. Attempt zone transfer using each NS
dig axfr @ns1.zonetransfer.me zonetransfer.me
dig axfr @ns2.zonetransfer.me zonetransfer.me

# 3. Using host
host -l zonetransfer.me ns1.zonetransfer.me (-l implies AXFR)

# 4. Using dnsrecon (automates AXFR + subdomain brute-force)
dnsrecon -d zonetransfer.me
```

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
## <u>Nmap Common Flags</u> (eJPT Focus)

### Host Discovery & Port Selection
- **`-Pn`** → Skip ping check; assume host is up (use when ICMP is blocked).
- **No port flag** → Scans **top 1000 most common TCP ports**.
- **`-p-`** → Scan **all 65535 TCP ports** (slow but thorough).
- **`-p 80,443,445`** → Scan **specific ports** only.
- **`-F`** → Scan **top 100 ports** (fast).

> 🔍 **Filtered vs Closed**:  
> - **Closed**: Port reachable, but no service running.  
> - **Filtered**: Firewall dropped probe — state unknown.

---

### Scan Types
- **`-sS`** → **SYN scan** (default for privileged users): stealthy, fast.
- **`-sU`** → **UDP scan**:  
  - UDP is **connectionless** → harder to detect open/closed state.  
  - Many services use UDP (DNS, SNMP, DHCP) → important for full recon.  
  - Much **slower and less reliable** than TCP scans.

---

### Service & OS Detection
- **`-sV`** → Probe open ports to **detect service/version** (e.g., Apache 2.4.41).
- **`-O`** → Guess **OS** based on TCP/IP fingerprinting (often inaccurate).
- **`-sC`** → Run **default NSE (Nmap Scripting Engine) scripts** (e.g., `http-title`, `smb-os-discovery`) for extra info.
- **`-A`** → Combines **`-sV`, `-sC`, `-O`** in one flag.

---

### Performance & Output
- **`-T<0-5>`** → Timing template:
  - `0` = paranoid (very slow)  
  - `1` = sneaky  
  - `2` = polite  
  - `3` = normal (default)  
  - `4` = aggressive  
  - `5` = insane (fastest, very noisy)
- **Output formats**:
  - `-oN file.txt` → Normal output (human-readable)
  - `-oX file.xml` → XML output (importable into Metasploit, Nessus, etc.)
  - `-oG file.gnmap` → Greppable format

> ✅ **eJPT Tip**: Start with `nmap -sV -sC -Pn <target>` — covers most exam needs.

