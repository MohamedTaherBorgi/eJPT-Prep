## Using Nmap Scripts (NSE)

Basic syntax:

```bash
nmap --script=<script-name> -p <ports> <ip>
```

Example:

```bash
nmap --script=smb-enum-users,smb-enum-shares -p 445 10.10.10.10
```

---

## Useful Script Categories

You can also specify categories instead of individual script names.

- `safe`  
  Scripts unlikely to affect the target.

- `intrusive`  
  May affect the target. Not considered safe.

- `vuln`  
  Scan for known vulnerabilities.

- `exploit`  
  Attempt to exploit a detected vulnerability.

- `auth`  
  Attempt authentication bypass (e.g., anonymous FTP login).

- `brute`  
  Perform brute-force attacks against services.

- `discovery`  
  Gather additional information about services (e.g., SNMP queries).

Example using a category:

```bash
nmap --script=vuln -p 80 10.10.10.10
```

---
## Locating NSE Scripts in Kali

Nmap scripts are stored in:

```
/usr/share/nmap/scripts/
```

To list them:

```bash
locate *.nse
```

Example output:

```
/usr/share/nmap/scripts/acarsd-info.nse
/usr/share/nmap/scripts/address-info.nse
/usr/share/nmap/scripts/afp-brute.nse
...
```

---
## Running Multiple Scripts

You can run multiple scripts by separating them with commas:

```bash
nmap --script=smb-enum-users,smb-enum-shares -p 445 <target-ip>
```

---
## Practical Advice

- Don’t blindly run `--script=all` — it’s noisy and slow.
- Start with `safe` or `discovery`.
- Use `vuln` selectively after identifying the service.
- Always think about whether you are in a **lab** or a **production environment** before using `intrusive`, `brute`, or `exploit`.
