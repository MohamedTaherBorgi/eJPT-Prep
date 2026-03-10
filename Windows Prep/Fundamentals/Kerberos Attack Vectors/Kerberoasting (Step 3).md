### SPN Confusion — Who Owns the SPN?

SPN (Service Principal Name) is just a tag that says "this account runs a service."

It can be tied to ANY account type:

```
Machine account    MSSQL running on a server
                   → SPN tied to the machine account SQLSERVER01$
                   → machine account password = 120 random chars
                   → uncrackable → useless for kerberoasting

Domain user account   DBA manually registered MSSQL under their user account
                      → SPN tied to svc_mssql (a regular domain user)
                      → human set the password → probably weak
                      → crackable → this is what you want
```

This is exactly why Kerberoasting targets **user accounts with SPNs** not machine accounts. Machine account passwords are uncrackable. Human-set service account passwords are weak.

---
## Kerberoasting

### Root Cause

In Step 3 of Kerberos, any authenticated domain user can request a TGS
for any service that has an SPN registered — no special privileges needed.

The TGS is encrypted with the <u>Service Owner's password hash</u>.

If the service runs under a domain user account (not machine account),
that hash is derived from a human-set password — likely weak and crackable.

Attacker requests the TGS, takes the encrypted ticket offline, cracks it.

---
### SPN — Who Owns It?

SPN can be tied to two types of accounts:

| Owner | Password | Crackable? |
|---|---|---|
| Machine account (COMPUTER$) | 120 random chars, auto-rotated | No — useless |
| Domain user account (svc_mssql) | Human set | Yes — this is the target |

> SPNs tied to domain user accounts are the target.
> Admins often create service accounts as regular domain users and register
> SPNs manually — these accounts often have weak passwords and never expire.

---
### Scenario 1 — Authenticated (Have Domain User Creds)

## **Impacket GetUserSPNs — find user accounts with SPNs:**
```bash
impacket-GetUserSPNs domain.local/username:password -dc-ip DC_IP
````

This queries AD for all <u>user accounts (not machine accounts)</u> that have an SPN registered — these are your Kerberoasting targets.

**Add `-request` to automatically request the TGS and dump the hash:**

```bash
impacket-GetUserSPNs domain.local/username:password -dc-ip DC_IP -request
```

> **What does -request actually do?** 
> 
> Without `-request`→ just lists vulnerable accounts (<u>enumeration only</u>) 
> 
> With -request → goes further and actually requests a TGS for each vulnerable account from the KDC and outputs the encrypted hash ready for cracking In one command you go from "find targets" to "have crackable hashes"

## **With Rubeus:**

```powershell
Rubeus.exe kerberoast /outfile:hashes.txt /format:hashcat
```

---
### Scenario 2 — Unauthenticated

Kerberoasting requires authentication — you cannot do it without at least one valid domain user credential. You need creds first via:

```
LLMNR poisoning → capture NetNTLM hash → crack it → get domain user creds
Password spray  → guess weak passwords on valid usernames
AS-REP roasting → if any account has preauth disabled → crack → get creds
```

Then use those creds to Kerberoast.

---
### The Hash You Get

```
$krb5tgs$23$*svc_mssql$domain.local$domain.local/svc_mssql*$a3f8...long blob
```

Hash type 13100 in hashcat — TGS-REP encrypted with service account password hash.

---
### Cracking

**Hashcat:**

```bash
hashcat -m 13100 hashes.txt rockyou.txt -r best64.rule
```

**John:**

```bash
john hashes.txt --wordlist=rockyou.txt
```

Same methodology as AS-REP roasting — same rules logic applies.

---
### AS-REP Roasting vs Kerberoasting

| **Feature**         | **AS-REP Roasting** | **Kerberoasting**             |
| ------------------- | ------------------- | ----------------------------- |
| **Target step**     | Step 1 (AS-REQ)     | Step 3 (TGS-REQ)              |
| **Needs creds**     | <u>No</u>           | <u>Yes</u>                    |
| **Target accounts** | Preauth disabled    | Accounts with SPN             |
| **Hash type**       | 18200               | 13100                         |
| **Encrypted with**  | User password hash  | Service account password hash |
| **Tools**           | Rubeus, GetNPUsers  | Rubeus, GetUserSPNs           |

---
### Why -request Queries User Accounts Not Service Accounts

> **Your confusion: GetUserSPNs targets user accounts not service accounts?**

"Service account" is not a special AD object type — it is just a regular domain user account that an admin created and assigned to run a service. It has a mailbox, it has a password, it is in the Users container.

GetUserSPNs specifically queries user objects (not machine objects) that have an SPN attribute set — because those are the ones with crackable passwords. 

Machine accounts have SPNs too but GetUserSPNs filters them out automatically since their passwords are uncrackable anyway.

---
---
