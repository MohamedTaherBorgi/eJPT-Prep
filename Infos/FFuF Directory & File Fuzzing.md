# 🔍 FFuF: Directory & File Fuzzing

### The Command

```bash
ffuf -u http://10.112.156.214/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.txt,.bak,.html -c
````

---
### 🚩 Flag Breakdown

| **Flag**  | **Description**                                                                                              |
| --------- | ------------------------------------------------------------------------------------------------------------ |
| `-u`      | **Target URL**: The `FUZZ` keyword is the injection point where words from the list are placed.              |
| `-w`      | **Wordlist**: Path to your directory discovery list (e.g., `common.txt` or `directory-list-2.3-medium.txt`). |
| `-e`      | **Extensions**: Comma-separated list. FFuF will append these to every word in the list.                      |
| `-c`      | **Color**: Enables colorized output (Green for 200, Yellow for 301, Red for 403/500).                        |
| `-fc 403` | **filter code**: We'll hide from the output all 403 HTTP status codes                                        |
| `-mc 200` | **filter code**: We want to see only 200 status code responses                                               |

---
## **✅ Top -e Extensions for ffuf (2026 Edition)**

### 1. **Daily Driver** (Recommended – Use this 90% of the time)

```sh
-e .php,.html,.js,.json,.txt,.bak,.env
```

### 2. **Best All-Rounder** (My personal favorite – Great balance)

```sh
-e .php,.html,.asp,.aspx,.js,.json,.txt,.bak,.old,.backup,.env
```

### 3. **Full Aggressive List** (When you want maximum coverage)

```sh
-e .php,.php5,.phps.phtml,.html,.htm,.asp,.aspx,.jsp,.js,.json,.xml,.txt,.bak,.old,.backup,.env,.con
```

---
### ⚙️ How the Logic Works

When you use the `-e` flag, FFuF creates a "multiplier" effect for every word in your wordlist:

1. **Base Word (Directory Check):** Checks `http://target/admin`
    
2. **Extension 1:** Checks `http://target/admin.php`
    
3. **Extension 2:** Checks `http://target/admin.txt`
    
4. **Extension 3:** Checks `http://target/admin.bak`
    
5. **Extension 4:** Checks `http://target/admin.html`

### 💡 Pro-Tips for Obsidian

- **Backups:** Always include `.bak`, `.old`, and `.save` to find source code leaks.
    
- **Filtering:** If you get too many results, add `-fs <size>` to filter out the "Page Not Found" size.
    
- **Wordlists:** For better results, use `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`.

---
---
# 📑 FFuF Extension Cheatsheet

### 1. Manual Extension List (`-e`)

**Best for:** 3–6 common extensions (quick scans).

Bash

```bash
ffuf -u http://IP/FUZZ -w filenames.txt -e .php,.txt,.bak -c
```

---
### 2. Extension Wordlist (`W1W2`)

**Best for:** Massive extension lists or custom "Deep Dives."


```bash
ffuf -u http://IP/W1W2 -w filenames.txt:W1 -w extensions.txt:W2 -c
```

- **Logic:** A "Cluster Bomb" that pairs every filename in `W1` with every extension in `W2`.
    
- **Note:** Use `W1W2` in the URL (ensure your extension file includes the leading dot).

---
### 📂 Common Kali Wordlist Paths

| **Type**              | **Path**                                                                 |
| --------------------- | ------------------------------------------------------------------------ |
| **General Filenames** | `/usr/share/wordlists/dirb/common.txt`                                   |
| **Heavy Directories** | `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`           |
| **Extensions File**   | `/usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt` |

---
---
# Fuzzing Parameters with FFUF – Practical Walkthrough

## 🔍 Objective

Discover hidden or undocumented parameters on a web endpoint that may lead to vulnerabilities like:
- SQL Injection
- XSS
- Local/Remote File Inclusion
- Command Injection

Target URL:  
`http://10.112.164.245/sqli-labs/Less-1/`

---
## 🧪 Q1: Parameter Discovery (Fuzzing Parameter Names)

When you don’t know which parameters the endpoint accepts, **fuzz parameter names**:

```bash
ffuf -u 'http://10.112.164.245/sqli-labs/Less-1/?FUZZ=1' \
     -c \
     -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -fw 39
```

### Key Flags:
- `-u`: Target URL with `FUZZ` placeholder
- `-w`: Wordlist of common parameter names
- `-fw 39`: **Filter out responses with 39 words** (noise reduction)
- `-c`: Colorized output

💡 Also try generic wordlists if custom ones fail:

```bash
ffuf -u '...?FUZZ=1' -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -fw 39
```

✅ **Success**: Finding a valid parameter like `id=1` → proceed to value fuzzing.

---
## 🔢 Q2: Value Fuzzing (Integer Brute-Force)

Now that we know the parameter is `id`, fuzz its **values** (e.g., 0–255):

### Method: Generate numbers on-the-fly + pipe to `ffuf`
```bash
seq 0 255 | ffuf -u 'http://10.112.164.245/sqli-labs/Less-1/?id=FUZZ' -c -w - -fw 33
```

### Alternative number generators:
| Command                               | Description                      |
| ------------------------------------- | -------------------------------- |
| `seq 0 255`                           | Built-in Linux number generator  |
| `for i in {0..255}; do echo $i; done` | Bash brace expansion             |
| `cook '[0-255]'`                      | Using `cook` tool (if installed) |

> ⚠️ **`-w -`** = read wordlist from **stdin** (pipe input)  
> ⚠️ **`-fw 33`** = filter out responses with 33 words (common "invalid ID" page)

✅ **Goal**: Find valid IDs that return different content (e.g., user records).

---
## 🔐 Q3: POST-Based Brute-Force (Password Fuzzing)

For login forms, fuzz **POST parameters**:

```bash
ffuf -u http://10.112.164.245/sqli-labs/Less-11/ \
     -c \
     -w /usr/share/seclists/Passwords/Leaked-Databases/hak5.txt \
     -X POST \
     -d 'uname=Dummy&passwd=FUZZ&submit=Submit' \
     -fs 1435 \
     -H 'Content-Type: application/x-www-form-urlencoded'
```

### Key Flags:
- `-X POST`: Use POST method
- `-d`: POST body with `FUZZ` in password field
- `-fs 1435`: **Filter by response size** (e.g., 1435 bytes = "invalid password" page)
- `-H`: Manually set `Content-Type` (FFUF doesn’t auto-set it for POST)

> 💡 **Why `-H`?**  
> Without `Content-Type: application/x-www-form-urlencoded`, the server may reject the request.

✅ **Success**: A response size **different from 1435** → valid password found.

---
---
# Finding vhosts and subdomains

#### Check : [[DNS vs Vhost Subdomains Fuzzing]]

---
---
# Proxifying FFUF Traffic

## 🔍 Why Proxy FFUF Traffic?

### 1. **Pivoting Through Compromised Hosts**

- When scanning internal networks via a **Meterpreter pivot** or **SSH tunnel**, you must route traffic through a local proxy (e.g., `proxychains` + `SOCKS5`)
- FFUF can send requests through this proxy to reach otherwise inaccessible targets

### 2. **Integration with Burp Suite**

- Send all FFUF traffic through **Burp Suite** (`127.0.0.1:8080`) to:
  - Inspect requests/responses in real time
  - Use **Burp extensions** (e.g., Logger++, Intruder rules)
  - Modify payloads on-the-fly
  - Capture full interaction for reporting

---
## 🛠️ Basic Proxy Usage (All Traffic)

```bash
ffuf -u http://10.112.164.245/FUZZ \
     -c \
     -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -x http://127.0.0.1:8080
```

- `-x`: Routes **all traffic** through the specified HTTP/SOCKS5 proxy
- Supports both `http://` and `socks5://` proxies
- Ideal for **full visibility** or **tunneling through pivots**

> 💡 Use when you need to **log every request** or are working behind a proxy chain

---
## 🎯 Selective Proxy Usage (Matches Only)

```bash
ffuf -u http://10.112.164.245/FUZZ \
     -c \
     -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -replay-proxy http://127.0.0.1:8080
```

- `-replay-proxy`: Sends **only matching responses** (e.g., non-404, non-filtered) to the proxy
- **Does not affect scanning traffic** — only replays successful hits

### Why Use This?

- ✅ **Reduces proxy history clutter** (only interesting results)
- ✅ **Saves bandwidth/resources** during large scans
- ✅ Perfect for **post-scan analysis** — replay valid paths in Burp for deeper testing

> 💡 Use when you want to **avoid polluting Burp history** with thousands of 404s

---
## 📋 Comparison

| Flag | Traffic Sent to Proxy | Best For |
|------|------------------------|----------|
| `-x` | **All requests/responses** | Full inspection, debugging, pivoting |
| `-replay-proxy` | **Only matches** (after filtering) | Clean Burp history, efficient analysis |
