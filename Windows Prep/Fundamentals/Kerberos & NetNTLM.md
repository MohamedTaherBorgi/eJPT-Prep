## Authentication in Windows Domains

Two protocols:
- **Kerberos** — default, used by all modern Windows domains
- **NetNTLM** — legacy, kept for compatibility, still widely enabled

---
## Kerberos Authentication

### Step 1 — Initial Login (AS-REQ)

This is what happens when a domain user logs in. The machine takes the username and a timestamp, encrypts the timestamp using a key derived from the user's password hash, and sends it to the KDC on the Domain Controller.

> **What is "key derived from password hash" and who creates it?**
> You type your password → machine hashes it (NTLM hash) → uses that hash as an encryption key → encrypts the timestamp with it → sends username + encrypted timestamp to KDC. The machine does this automatically in the background. You just type your password.

The KDC already has your password hash stored in AD. It decrypts the timestamp<u> and compare with its own timestamp</u> using that hash to verify your identity.

> **Is this only for domain users?**
> Yes — the KDC only knows domain accounts. 
> Local account login never touches the KDC at all (covered in NetNTLM section).

---
### Step 2 — KDC Responds with TGT + Session Key (AS-REP)

KDC sends back two things:

```
Thing 1 = Session Key → given directly to the user in readable form 

Thing 2 = TGT → encrypted with krbtgt account password hash user CANNOT open this — only KDC can contains a copy of Session Key locked inside
```

> **Is Session Key inside TGT or separate?**
> 
> Both. User receives Session Key directly so they can use it. 
> 
> TGT also contains a copy of Session Key locked inside it — but that copy is for the KDC, not the user. When the user comes back later with the TGT, the KDC decrypts it to recover the Session Key. <u>This means the KDC stores nothing between requests — completely stateless.</u>

User stores both TGT and Session Key in memory for future requests.

---
### Step 3 — User Requests Service Ticket (TGS-REQ)

When user wants to access a specific service (share, website, database), they send to KDC:

```
- Username
- Timestamp encrypted with SESSION KEY (not password hash anymore)
- The TGT itself
- SPN (Service Principal Name) — identifies which service and server they want
```

> **Why Session Key this time and not password hash?**
> 
> This is the whole point of Kerberos. After initial login you never use your password hash again. Session Key replaces your password as proof of identity for all further requests. 
> Password hash never flies across the network repeatedly.

> **Who does the encryption? Does the user have the Session Key?**
> 
> Yes — the machine stored the Session Key in memory from Step 2. 
> Windows uses it automatically in the background to encrypt the timestamp. You never see this happening.

---
### Step 4 — KDC Responds with TGS + Service Session Key (TGS-REP)

KDC sends back two things:

```
Thing 1 = Service Session Key → given directly to the user to talk to the service 

Thing 2 = TGS → encrypted with Service Owner's password hash contains a copy of Service Session Key inside
```

> **Why does TGS contain Service Session Key? Doesn't the service already have it?**
> 
> No — the service does not have a session key sitting around. Session keys are generated fresh for each new connection. Neither user nor service has it until the KDC creates it.
>
> KDC distributes it to both parties simultaneously:
> - To the user = returned directly so user can communicate with the service
> - To the service = embedded inside TGS encrypted with service's password hash
>
> When user presents TGS to the service, service decrypts it with its own password hash, reads the Service Session Key inside, and now both sides have the same key. This is how two parties who never directly exchanged keys end up with the same session key — <u>KDC is the trusted middleman</u>.

---
### Step 5 — User Connects to Service (AP-REQ)

User sends TGS to the service. Service decrypts TGS with its own password hash, extracts Service Session Key, verifies the user, grants access. No password ever touched the network.

---
### Full Kerberos Flow

```
User → KDC : username + timestamp encrypted with password hash (AS-REQ) 
KDC → User : TGT (encrypted with krbtgt hash) + Session Key (AS-REP)

User → KDC : TGT + SPN + timestamp encrypted with Session Key (TGS-REQ) 
KDC → User : TGS (encrypted with Service hash) + Service Session Key (TGS-REP)

User → Service: TGS (AP-REQ) Service : decrypts TGS, extracts Service Session Key, grants access
```

---
## NetNTLM Authentication

Challenge-response based mechanism:

```
1. Client → Server : authentication request
2. Server → Client : random challenge number
3. Client takes NTLM hash + combines with challenge → produces response
4. Client → Server : response
5. Server → DC : original challenge + client response
6. DC recalculates expected response using stored hash + challenge
7. DC compares — if match → authenticated
8. DC → Server : result
9. Server → Client : access granted or denied
```

Password and hash never travel across the network — only the challenge and derived response do.

---
### Local Account vs Domain Account in NetNTLM

> **For local accounts — who verifies? DC or local server?**

The **local server** verifies — DC is not involved at all.

| | Domain Account | Local Account |
|---|---|---|
| Who verifies | DC | Local server itself |
| Where hash is stored | DC (AD) | Local SAM on that machine |
| DC involved | Yes | No |

>When a local account is used, the server has that account's hash in its own local SAM. It generates the challenge, receives the response, recalculates using its local hash, and compares — all by itself. No DC needed.

---
---
## Kerberos Attack Vectors

### Step 1 — AS-REQ (Initial Login, User sends encrypted timestamp)

**AS-REP Roasting**

Some accounts have "Do not require Kerberos preauthentication" enabled.
This means the KDC sends back a TGT without verifying the encrypted timestamp first.
Attacker requests a TGT for that account without knowing the password.
The AS-REP response contains material encrypted with the user's password hash.
Attacker takes it offline and cracks it to recover the plaintext password.

---

### Step 2 — AS-REP (KDC returns TGT + Session Key)

**Pass the Ticket (PTT)**
If you steal a TGT from memory (via mimikatz), you can inject it into your own session.
You now authenticate to the KDC as that user without knowing their password.
TGT is the proof of identity — whoever holds it, is that user.

**Golden Ticket**
If you have the krbtgt account password hash (requires Domain Admin or DC compromise),
you can forge a TGT entirely from scratch for any user including fake Domain Admins.
Forged TGT is signed with krbtgt hash so the KDC accepts it as completely legitimate.
Persists even after password resets because it is signed by krbtgt, not the user's hash.
krbtgt hash must be reset twice to invalidate existing Golden Tickets.

---

### Step 3 — TGS-REQ (User requests service ticket, sends TGT + SPN)

**Kerberoasting**
Any domain user can request a TGS for any service that has an SPN registered.
The TGS is encrypted with the Service Owner's password hash.
Attacker requests TGS for a target service, takes the encrypted ticket offline,
and cracks it to recover the service account's plaintext password.
Works best against service accounts with weak passwords.
No special privileges needed — any domain user can do this.

---

### Step 4 — TGS-REP (KDC returns TGS encrypted with Service Owner hash)

**Silver Ticket**
If you have the Service Owner's password hash (specific service account),
you can forge a TGS entirely for that specific service without touching the KDC.
KDC is not involved at all — the service validates the ticket itself using its own hash.
More stealthy than Golden Ticket because no KDC traffic is generated.
Limited to the specific service the hash belongs to.

---

### Step 5 — AP-REQ (User presents TGS to service)

**Pass the Ticket (PTT)**
If you steal a TGS from memory for a specific service,
you can inject it and access that service as the victim user.
Useful for lateral movement to specific resources.

---

### NetNTLM Attack Vectors

---

**NTLM Relay**
Attacker sits between client and server (MITM position).
Client sends challenge response intended for the real server.
Attacker forwards it to a different target server in real time.
Target server sees a valid authentication from the victim.
Attacker gains access as the victim without ever knowing the password.
Tools: Responder + ntlmrelayx

**LLMNR/NBT-NS Poisoning**
When a machine tries to resolve a hostname that DNS cannot find,
it falls back to broadcasting LLMNR or NBT-NS on the local network.
Attacker responds to that broadcast pretending to be the requested host.
Victim sends NetNTLM authentication to the attacker.
Attacker captures the NetNTLM hash and cracks it offline.
Tools: Responder

**NetNTLM Hash Cracking**
Captured NetNTLM hashes from relay or poisoning attacks.
Hash contains the response derived from the password — crack offline with hashcat.
Does not give the hash directly usable for PtH — need to crack to plaintext first.
Unlike NTLM hashes from SAM which ARE directly usable for PtH.

---

### Summary

| Attack | Target Step | Needs | Gives You |
|---|---|---|---|
| AS-REP Roasting | Step 1 | Account with preauth disabled | Crackable hash → plaintext |
| Kerberoasting | Step 3 | Any domain user + SPN | Crackable hash → plaintext |
| Golden Ticket | Step 2 | krbtgt hash (DA level) | Forge any TGT forever |
| Silver Ticket | Step 4 | Service account hash | Forge TGS for that service |
| Pass the Ticket | Step 2/5 | TGT or TGS from memory | Authenticate as victim |
| NTLM Relay | NetNTLM | Network position | Access as victim in real time |
| LLMNR Poisoning | NetNTLM | Local network access | Captured hash → crack offline |
