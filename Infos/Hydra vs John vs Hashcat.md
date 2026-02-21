### Quick Overview

- **Hydra**  (bruteforce)
  Online password cracker (brute-force / dictionary attacks against live services)

- **Hashcat**  (cracking)
  Offline password cracker (super fast cracking of captured hashes)

- **John the Ripper**  (cracking)
  Offline password cracker (flexible, good on CPU, simple syntax)

### Comparison at a Glance

| Tool       | Attack Type     | Speed (with GPU) | Best For                          | Typical Use Case                     | Noise / Detection Risk |
|------------|-----------------|------------------|-----------------------------------|--------------------------------------|------------------------|
| **Hydra**  | Online          | Slow             | Brute/dict on live protocols      | RDP, SSH, SMB, HTTP forms, FTP…      | Very high (logs, lockouts, alerts) |
| **Hashcat**| Offline         | Extremely fast   | Cracking dumped hashes (NTLM, bcrypt, etc.) | Windows SAM, hashes from Responder, Mimikatz | None (offline) |
| **John**   | Offline         | Good (CPU)       | Cracking hashes, incremental mode | Same as hashcat, but easier resume   | None (offline) |

### When to Choose Which

- You have **captured hashes** (hashdump, Responder, Mimikatz, NTDS.dit, etc.) → **Hashcat** (GPU) or **John** (CPU/simple)
- You want to **brute-force / dictionary attack a live login** (SSH, RDP, SMB, web login, etc.) → **Hydra**
- You need **online spraying** (try few common passwords across many accounts without locking out) → Hydra with low attempts + delays

### Command Examples (most used in labs)

**Hydra** (online brute/dict)
```bash
# SSH – dictionary attack
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10 -t 4
								# -t : number of parallel tasks/threads
								
# RDP – try common passwords
hydra -L users.txt -P pass.txt rdp://10.10.10.10 -t 1 -w 10 -W 5
								# -w : wait time (seconds) between attempts
								# -W : wait time (seconds) after failed attempt
								
# HTTP POST form (DVWA login example)
hydra -l admin -P rockyou.txt 10.10.10.10 http-post-form "/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed"
```

**Hashcat** (offline – fastest)
```bash
# NTLM hash (Windows)
hashcat -m 1000 hashes.txt rockyou.txt -O --force

# Show cracked
hashcat -m 1000 hashes.txt --show
```

**John the Ripper** (offline – simple)
```bash
john hashes.txt --format=NT --wordlist=rockyou.txt
john --show hashes.txt
```

### Lab / THM Rule of Thumb

- Got hashes from `hashdump`, Responder, or Mimikatz? → **hashcat** (if GPU) > **john**
- Trying to crack RDP/SSH/SMB login directly? → **hydra** (careful – very noisy, use low threads `-t 1-4`, delays `-w 5 -W 10`)
- Real engagements → avoid hydra on production (lockouts + alerts); prefer password spraying with tools like CrackMapExec or manual attempts

