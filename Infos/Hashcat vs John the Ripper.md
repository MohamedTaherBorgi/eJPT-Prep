# hashcat  

**When to use**  
GPU available · Need maximum speed · Modern hashes · Labs & THM  

**Quick examples**  
```bash
# Dictionary attack – most common in labs
hashcat -m 1000 -a 0 hashes.txt rockyou.txt -O --force

# Show results after cracking
hashcat -m 1000 hashes.txt --show
```

**Core flags explained**  
`-m 1000`     NTLM (Windows NT hash)  
`-a 0`        Dictionary / straight attack  
`-a 3`        Brute-force or mask attack  
`-O`          Optimized kernel (usually faster)  
`--force`     Ignore warnings (VMs & laptops love this)  
`--show`      Display cracked passwords  

# John the Ripper  

**When to use**  
CPU only · Want simplicity · Easy resume · Incremental mode  

**Quick examples**  
```bash
# Basic dictionary attack
john hashes.txt --format=NT --wordlist=rockyou.txt

# View cracked results
john --show hashes.txt
```

**Core flags explained**  
`--format=NT`     NTLM hash type  
`--wordlist=`     Path to wordlist  
`--show`          Show cracked passwords  
`--restore`       Resume previous session  

---
## One-line decision  

GPU or speed matters → **hashcat**  
No GPU or quick & dirty → **John**  

**Most THM / CTF rooms** → start with **hashcat** + rockyou + `-O --force`
