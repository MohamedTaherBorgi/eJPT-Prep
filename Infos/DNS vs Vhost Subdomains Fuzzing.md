# 🌐 Subdomain & Vhost Enumeration Note

---
## 1️⃣ Concepts: DNS vs. Vhost Fuzzing

| Feature      | DNS Fuzzing (Subdomains)                     | Vhost Fuzzing (Headers)                              |
| ------------ | -------------------------------------------- | ---------------------------------------------------- |
| **Logic**    | “Does `admin.school.com` exist in DNS?”      | “Server at this IP, do you host `admin.school.com`?” |
| **Use Case** | Finds subdomains that resolve publicly.      | Finds hidden virtual hosts on the **same IP**.       |
| **Tools**    | `gobuster dns`, `subfinder`, `amass`, `nmap` | `ffuf -H`, `gobuster vhost`                          |

---
## 2️⃣ Enumeration Methods

### 🔎 A. Nmap (Quick & Active)

Uses the `dns-brute` NSE script to check common subdomains.

```bash
nmap --script dns-brute --script-args dns-brute.domain=school.com
```

Good during initial reconnaissance.

---
### ⚡ B. FFuF (High-Speed Fuzzer)

#### Standard Subdomain Fuzzing (URL-based)

```bash
ffuf -u http://FUZZ.school.com -w /usr/share/wordlists/dirb/common.txt -c
```

Use when DNS resolution is expected.

---
#### VHost Fuzzing (Header-based)

Use when you have an IP but no DNS record.

```bash
ffuf -u http://<TARGET_IP> -H "Host: FUZZ.school.com" \
-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
-fs 1234 # filter by size if default response is fixed
```

This fuzzes the `Host` header directly.

>**-u** = base URL (use IP!)
>**-H** "Host: FUZZ.DOMAIN" = fuzz the Host header
>**-fs** = filter responses with this size (hide invalid hosts)

### What about Hydra ??

**No, Hydra does not have built-in support for subdomain enumeration or virtual host (vhost) fuzzing via the Host header.**

Hydra is primarily a **brute-force / dictionary attack tool for authentication** (logins, passwords on services like SSH, RDP, HTTP forms, SMB, FTP, etc.). It does **not** have a dedicated module or mode for:
- DNS-based subdomain brute-forcing
- Host header fuzzing / vhost enumeration
### Why people sometimes confuse it

- Hydra **can** attack HTTP services (e.g., http-get, http-post-form, http-head) → but these are for **brute-forcing login forms** or basic auth, not for fuzzing the Host header or discovering subdomains.

---
## 3️⃣ Handling False Positives (Filtering the Noise)

Servers often return `200 OK` for everything. You must filter.

Common filters:

- `-fs [size]` → Filter by **response size**
    
- `-fw [count]` → Filter by **word count**
    
- `-fc [code]` → Filter by **HTTP status code**

Example:

```bash
ffuf -u http://10.10.110.84 \
-H "Host: FUZZ.school.com" \
-w wordlist.txt \
-fs 1492
```

Pro tip: First run without filters to identify the default response size.

---
## 4️⃣ Accessing Discovered Subdomains (`/etc/hosts`)

If you discover `dev.school.com` but DNS doesn’t resolve publicly, map it locally.

### 1. Open hosts file

```bash
sudo nano /etc/hosts
```

### 2. Add mapping

```text
# IP Address   Domain and Subdomains
10.112.156.214  school.com dev.school.com admin.school.com
```

### 3. Save and exit

`Ctrl + O` → Enter → `Ctrl + X`

Now your browser will resolve the subdomain.

---
## 🛠️ Tool Comparison

|Tool|Type|Best Use|
|---|---|---|
|**Nmap**|Active|Quick brute during port scan|
|**FFuF**|Active|Fast fuzzing, header manipulation|
|**Subfinder**|Passive|API-based discovery (stealthy)|
|**Amass**|Passive/Active|Deep mapping for large targets|
