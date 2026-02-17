In a pentest (especially on platforms like Hack The Box or TryHackMe), adding IPs and domain names to your `/etc/hosts` file is a critical step for one main reason: **Virtual Hosting.**

Here is why your browser (or tools like `curl`) needs that entry to talk to the target correctly.

---
### 1. The "Virtual Host" Problem

Modern web servers (Apache, Nginx) often host multiple websites on a **single IP address**.

- **Website A:** `dev.target.htb`
    
- **Website B:** `admin.target.htb`
    
- **Both live at:** `10.10.10.15`
    

When you type `10.10.10.15` into your browser, the server doesn't know which of those two sites you want to see, so it usually just shows a default "Welcome to Nginx" page or an error.

### 2. The HTTP "Host" Header

When you use a domain name (like `http://dev.target.htb`), your computer sends a request that includes a **Host Header**:

`Host: dev.target.htb`

The web server reads this header and says, "Ah, you want the development site!" and serves you the correct files. Without an entry in `/etc/hosts`, your computer has no idea that `dev.target.htb` belongs to that specific IP, so it tries to ask a real DNS server (like Google), which will fail because `.htb` isn't a real public domain.

### 3. Bypassing Public DNS

During a pentest, the domains you are attacking (like `internal.corp`) aren't registered on the real internet. By adding them to `/etc/hosts`, you are telling your Linux machine:

> "Don't bother asking the internet where this domain is. I'm telling you exactly where it is: it's at this IP."

---
### How to do it correctly

You can add an entry manually using `nano` or with this quick one-liner:

Bash

```
# Example: Mapping a HackTheBox IP to a domain
echo "10.10.10.15  target.htb dev.target.htb" | sudo tee -a /etc/hosts
```

### Why this helps your tools:

- **Burp Suite:** It can now intercept traffic for the domain correctly.
    
- **Nmap:** If you scan the domain name instead of the IP, Nmap can sometimes find more info (like SSL certificate names).
    
- **Fuzzing:** Tools like `ffuf` or `gobuster` need the host mapping to find hidden subdomains using "Virtual Host Discovery."


