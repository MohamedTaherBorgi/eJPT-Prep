## Website Recon vs Footprinting

### Footprinting
- **Definition**: The initial phase of reconnaissance focused on **gathering high-level information about the target organization**.
- **Scope**: Broad — includes domains, IP ranges, network blocks, employees, technologies, and public presence.
- **Goal**: Build a foundational profile of the target before deeper probing.
- **Methods**:
  - WHOIS lookups
  - DNS enumeration (MX, NS, TXT records)
  - ASN & IP range discovery (`whois`, `dig`, `nslookup`)
  - Social media and employee research
- **Type**: Primarily **passive**, though can include light active techniques (e.g., DNS queries).

### Website Reconnaissance
- **Definition**: Focused reconnaissance **specifically on web assets** (websites, web apps, APIs).
- **Scope**: Narrow — targets URLs, endpoints, technologies, directories, and client-side behavior.
- **Goal**: Identify attack surface: hidden paths, tech stack, misconfigurations, sensitive data exposure.
- **Methods**:
  - Viewing page source / robots.txt / sitemap.xml
  - Using browser dev tools (Network, Console tabs)
  - Scanning with `gobuster`, `ffuf`, or `dirb`
  - Analyzing cookies, headers, JS files
  - Checking for common vulnerabilities (e.g., backup files, admin panels)
- **Type**: Can be **passive** (manual browsing) or **active** (automated scanning).

### Key Difference
> **Footprinting = "Who is the target and what do they own?"**  
> **Website Recon = "What is this specific web app doing, and how can I interact with it?"**

---
---
## What Are We Looking For?

- IP addresses
- Directories hidden from search engines
- Names
- Email addresses
- Phone Numbers
- Physical Addresses
- Web technologies being used

---
---
## Website Behind a Proxy or Firewall

### Meaning
When a website is said to be "behind a proxy or firewall," it means that **direct access to the origin web server is restricted or mediated** by intermediary security or networking infrastructure.

### Components Involved
- **Firewall**: A network security device that filters incoming/outgoing traffic based on rules (e.g., IP, port, protocol).
- **Proxy (Reverse Proxy)**: A server that sits between clients and the origin web server, forwarding requests and responses (e.g., Nginx, Apache, Cloudflare, AWS ALB).

### Implications for Recon & Testing
- **Obscured Origin IP**: The real server IP may be hidden; you only see the proxy/firewall IP.
- **Filtered Ports/Services**: Only HTTP/HTTPS (ports 80/443) may be exposed — other services (SSH, SMB, etc.) are blocked.
- **Altered Headers**: Proxies often add or strip headers (e.g., `X-Forwarded-For`, `Via`).
- **Rate Limiting / WAF**: May trigger blocks during aggressive scanning (e.g., via Cloudflare, ModSecurity).
- **Limited Direct Interaction**: Active enumeration (e.g., port scans, service fingerprinting) may only reveal proxy behavior, not the backend.

### Common Indicators
- HTTP headers like:
  ```http
  Server: cloudflare
  X-Powered-By: PHP/7.4.3
  Via: 1.1 proxy-server
  ```
  
---
---
## <u>host</u>

A simple DNS lookup utility to **resolve domain names to IP addresses** and **query DNS records**.
### Common Uses

- Get A/AAAA records (IPs)

- Find mail servers (MX records)

- Discover name servers (NS records)
### Examples

```bash
host example.com
```
#### Multiple IPs from `host` Command → ==Proxy Indicator==

---
---
## /<u>robots.txt</u>

A standard file used by websites to **instruct web crawlers (like search engines) which paths should not be indexed or accessed**.

### Location

http://target.com/robots.txt

### Purpose
- Intended for **search engine bots**, not security enforcement.
- Often **ignored by attackers and malicious scanners** — so sensitive paths listed here may actually **leak internal directories**.

### Common Entries
```txt
User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /secret/
```

#### <u>Note :</u>
Many people think `Disallow` means "Access Denied." In reality, it just means **"Please don't index this on Google."**
### Recon Value

- May reveal:
    - Hidden admin panels (`/admin`, `/wp-admin`)
    - Backup directories (`/backup`, `/old`)
    - Development or staging paths (`/dev`, `/test`)
    - Sensitive files (`/config.php.bak`, `/database/`)

---
---
## <u>sitemap.xml</u> vs <u>sitemap_index.xml</u> (Used by search engines to index)

### `/sitemap.xml`
- Single XML file listing **all indexed URLs** on the site.
- Common on smaller websites.
- Example:
  ```xml
  <urlset>
    <url><loc>https://site.com/about</loc></url>
    <url><loc>https://site.com/contact</loc></url>
  </urlset>
  ```
  
### `/sitemap_index.xml`

- Used by larger sites (e.g., WordPress with Yoast SEO).
- **Index of multiple sitemap files** (e.g., posts, pages, media).
- Example:
```xml
<sitemapindex>
  <sitemap><loc>https://site.com/post-sitemap.xml</loc></sitemap>
  <sitemap><loc>https://site.com/page-sitemap.xml</loc></sitemap>
</sitemapindex>
```

### Recon Tip

- Both may expose **hidden, unlinked, or sensitive paths**.
- Always request both during initial web enumeration.

---
---
## <u>Wappalyzer</u> vs <u>BuiltWith</u>

- **Wappalyzer**: Browser extension that detects CMS, frameworks, JS libs, CDNs, etc. from headers/scripts. Great for quick tech stack ID.
- **BuiltWith**: Similar, but adds hosting info, SSL issuer, and historical data. Free tier limited; full reports need account.

> ✅ Use both in passive recon to guide exploit selection. Always verify findings manually.

---
---
## <u>HTTrack</u>

A **website copier** tool that downloads a website from the internet to a local directory, preserving its structure, HTML, images, and assets.

### Command Example
```bash
httrack https://target.com -O ./target_mirror
```
### Use in Recon

- **Offline analysis**: Browse full site without triggering WAF or rate limits.
- **Discover hidden content**: Find comments, backup files, or dev paths in downloaded source.
- **Extract JS/HTML**: Hunt for API endpoints, credentials, or hardcoded secrets.

### Notes

- Respects `robots.txt` by default (can be overridden).
- May miss dynamic content (e.g., SPAs loaded via AJAX).
- Useful in **passive/semi-passive** phases — avoid on large sites during live tests (noisy).
---
---
## <u>whois</u>

Queries public **domain registration databases** to retrieve ownership and technical details about a domain or IP address.

### Common Uses in Recon
- Find **registrant name, email, phone, org**
- Identify **name servers** and **DNS provider**
- Discover **creation/expiry dates** (old domains = more trust; new = possible phishing)
- Get **IP netblock/ASN info** (for IP-based whois)

### Examples
```bash
whois example.com      # Domain info
whois 192.0.2.1        # IP/netblock info
```

### Limitations

- **GDPR/Privacy Protection**: Many domains hide real owner info.
---
---
## Website Footprinting with <u>Netcraft</u>

**Netcraft** (https://sitereport.netcraft.com) is a web-based service that provides detailed passive reconnaissance on websites, including hosting, server, and historical data.

### Key Information Revealed
- **IP address** and **network location**
- **Web server** type and version (e.g., Apache 2.4.41)
- **Hosting provider** and **country**
- **SSL certificate** issuer and validity
- **Operating system** (inferred from banners/timing)
- **Site history**: Past IPs, server changes, uptime
- **Subdomains** (limited, via historical DNS)

### How to Use
1. Go to: https://sitereport.netcraft.com
2. Enter target domain (e.g., `example.com`)
3. Review the report — especially:
   - "Last seen" IP changes
   - Server header discrepancies
   - Hosting on cloud platforms (AWS, Cloudflare, etc.)

### Red Team Value
- Identify **real origin IP** if behind CDN (via historical records).
- Detect **server misconfigurations** (e.g., verbose banners).
- Correlate with other domains on same IP (**virtual host enumeration**).

> ⚠️ Netcraft no longer offers full subdomain enumeration, but remains strong for **server fingerprinting** and **infrastructure history**.

---
---
## <u>dnsrecon</u>

Performs comprehensive DNS enumeration on a target domain.
### Basic Usage

```bash
dnsrecon -d example.com
```
### Capabilities

- Queries standard records: **A, AAAA, MX, NS, TXT, SOA**
- Attempts **zone transfers** (AXFR)
- **Brute-forces subdomains** using built-in wordlist
- Detects **wildcard DNS**, **SPF records**, and **dangling CNAMEs**

**1. Wildcard DNS**

A **Wildcard DNS** record uses an asterisk (`*`) to act as a "catch-all" for any subdomain that hasn't been explicitly defined. 

- **Example**: If you set `*.example.com` to point to `192.0.2.1`, then `apple.example.com`, `banana.example.com`, and even `random123.example.com` will all resolve to that same IP address.
- **Security Risk**: Attackers can use wildcards to create convincing phishing subdomains (e.g., `login.example.com`) that technically "exist" because of the catch-all, even if the admin never created them.

**2. SPF (Sender Policy Framework) Records**

An **SPF record** is a TXT record that tells the world which mail servers are authorized to send email on behalf of your domain. 

- **Example**: `v=spf1 ip4:1.2.3.4 include:_spf.google.com -all`
    - `ip4:1.2.3.4`: Only this specific IP can send mail.
    - `include:_spf.google.com`: Google's mail servers are also allowed.
    - `-all`: **Hard Fail**; reject any email from sources not on this list.
- **Purpose**: It prevents **email spoofing** by ensuring that a scammer cannot easily send an email that appears to come from your legitimate domain.

**3. Dangling CNAMEs**

A **Dangling CNAME** occurs when a DNS record points to a resource (like a cloud bucket or a third-party service) that has been deleted or decommissioned, but the DNS record itself remains active. 

- **Example**: Your record `blog.example.com` points to `my-cool-blog.herokuapp.com`. You delete your Heroku account, but forget to delete the DNS record. Now, `blog.example.com` is "dangling" because it points to an unclaimed name on Heroku.
- **Security Risk (Subdomain Takeover)**: An attacker can sign up for a new Heroku account and claim the name `my-cool-blog.herokuapp.com`. Because your DNS record still points there, they now **effectively control** your `blog.example.com` subdomain and can host malicious content or steal cookies.

### Note :
>CDNs like **Cloudflare do not proxy email traffic** — **MX records remain public**.
  `dnsrecon` will reveal mail servers (e.g., `mail.example.com`, Google Workspace, etc.).
  If the organization self-hosts email, the MX record may expose:
  - The **real origin IP** (not behind CDN)

---
---
## <u>DNSDumpster</u> (Best)

A free web-based tool for **passive DNS reconnaissance** and **subdomain discovery**.
### URL
https://dnsdumpster.com
### What It Provides
- **Subdomains** with resolved IPs
- **DNS records**: A, AAAA, MX, TXT, NS
- **Reverse DNS** (PTR) entries
- **Domain neighbors** (other domains on same IP)
- **Visual network map** of infrastructure
- **Potential takeover indicators** (e.g., dangling CNAMEs to cloud services)

### Recon Value
- Finds **subdomains missed by brute-forcing**
- Reveals **historical or forgotten assets**
- Exposes **shared hosting** (multiple domains on one IP)
- Often bypasses CDN obfuscation by showing **origin IPs** in historical or mail-related records
---
---
## <u>wafw00f</u>

A tool to **detect and identify Web Application Firewalls (WAFs)** protecting a target website.

### Basic Usage
```bash
wafw00f https://target.com
```
### How It Works

- Sends **malicious-looking HTTP requests** (e.g., SQLi, XSS payloads)
- Analyzes responses for:
    - WAF-specific **headers** (e.g., `X-Sucuri-ID`, `CF-RAY`)
    - **Status codes** (e.g., 403, 406)
    - **Response body patterns** (e.g., Cloudflare block page)

### Output Example
```bash
[*] Checking https://target.com
[+] The site https://target.com is behind Cloudflare
```

The `-a` flag tells `wafw00f` to **check for all known WAFs**, not just the most common ones.

### Example

```bash
wafw00f -a https://target.com
```
### Default Behavior

- Without `-a`, `wafw00f` tests against a **subset of popular WAFs** (faster scan).

### With `-a`

- Tests against **all 60+ WAF fingerprints** in its database.

- More thorough, but **slower** and **more noisy**.
---
---
## <u>Sublist3r</u>

A **subdomain enumeration tool** that uses **Open Source Intelligence (OSINT)** and **search engines** to discover subdomains.

### Key Features
- Queries multiple sources:  
  `Google`, `Bing`, `Yahoo`, `VirusTotal`, `ThreatCrowd`, `DNSdumpster`, `CertSpotter`, etc.
- Fast and passive (mostly)
- Can **brute-force** subdomains if enabled (`-b` flag)

### Basic Usage
```bash
sublist3r -d target.com

#common flags :

-d target.com        # Domain to enumerate
-b                   # Enable brute-force (uses default wordlist)
-p 80,443            # Only show subdomains with these ports open (requires `-b`)
-t 50                # Threads
-o output.txt        # Save results
```

---
---
## <u>Google Dorking for Web Recon</u>

### <u>Directory Listing</u>

- Occurs when a web server **lists all files/folders** in a directory due to missing `index.html`, `index.php`, etc.
- **Risk**: Exposes sensitive files (configs, backups, credentials).
- **Dork Example**:
``` txt
site:target.com intitle:"Index of /"
```
### <u>Common Google Dorks</u>

#### `site:`
- Restricts results to a specific domain or subdomain.
``` txt
site:ine.com 
```

> ⚠️ `site:*.example.com` **does not work reliably** in modern Google. Use `site:example.com` and filter manually, or use tools like `dnsrecon`/`sublist3r` for subdomains.

#### `inurl:`
- Finds pages with specific strings in the URL.
``` txt
inurl:auth_user_file.txt 

inurl:passwd.txt 

inurl:backup
```

#### `filetype:`
- Searches for specific file extensions.
``` txt 
site:target.com filetype:pdf 

site:target.com filetype:env # May leak .env files 

site:target.com filetype:sql # Database dumps 
``` 

#### <u>Wayback Machine</u> (Archive.org)

- Use to find **historical snapshots** of a site:
- Deleted pages
- Old JS/config files
- Exposed directories
- URL: https://web.archive.org/web/*/target.com
### <u>Google Hacking Database</u> (GHDB)

- Public repository of **exploit-focused dorks**.
- Categories:
    - Footholds
    - Sensitive Directories
    - Network/VPN/Gateways
    - Error Messages

- URL: https://www.exploit-db.com/google-hacking-database

✅ Always verify findings — many dorks return outdated or false positives.

---
---
## <u>theHarvester</u>

Passive OSINT tool to gather **emails, subdomains, IPs, and hostnames** from public sources.

### Command Example
```bash
theHarvester -d target.com -b duckduckgo,rapiddns
```
### Flags

- `-d target.com` → Target domain
- `-b duckduckgo,rapiddns` → Use **DuckDuckGo** and **RapidDNS** as data sources
### Output Includes

- Associated **IP addresses**
- **Email addresses** (if found in public pages)
- **Hostnames** (sub-domains)

---
---
## <u>HaveIBeenPwned</u> (HIBP)

A public service to check if **email addresses, phone numbers, or passwords** have appeared in known data breaches.
### Website
https://haveibeenpwned.com

### -> Where HaveIBeenPwned (HIBP) Is Used in Real-World Red Teaming :

### 1. **Credential Stuffing & Password Reuse Analysis**
- After harvesting credentials (e.g., via phishing, LDAP dump, or web form), check if:
  - Passwords are **already public** → indicates low-hanging fruit.
  - Users reuse **breached passwords** across systems.
- **Action**: Prioritize accounts with known-bad passwords for lateral movement.

### 2. **Phishing Campaign Validation**
- Before sending a campaign, verify if target emails appear in breaches:
  - If yes → craft more convincing lures (“Your account was exposed in [Breach X]”).
  - Demonstrates realism during client reporting.

### 3. **Post-Exploitation Intelligence**
- During internal assessments, if you obtain a password hash or plaintext:
  - Check HIBP to see if it’s **publicly known**.
  - Helps justify risk: “This password appears in 12 breach datasets.”

### 4. **Client Awareness & Reporting**
- Show clients **real evidence** of compromised employee credentials.
- Strengthens recommendations for:
  - Enforcing MFA
  - Deploying password blocklists (e.g., Azure AD “banned password” feature)
  - Security awareness training

