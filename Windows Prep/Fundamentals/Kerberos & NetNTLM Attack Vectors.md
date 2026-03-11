## Kerberos Authentication Cycle

### Step 1 — AS-REQ (Initial Login)

_User sends encrypted timestamp to the KDC._

## **AS-REP Roasting**

- **Vulnerability:** Some accounts have "Do not require Kerberos preauthentication" enabled.
    
- **Mechanism:** The KDC sends back a TGT without verifying the encrypted timestamp first.
    
- **Exploitation:** An attacker requests a TGT for that account without knowing the password. The AS-REP response contains material encrypted with the user's password hash.
    
- **Outcome:** Attacker takes the hash offline and cracks it to recover the plaintext password.

---
### Step 2 — AS-REP (KDC Response)

_KDC returns TGT + Session Key._

## **Pass the Ticket (PTT)**

- **Mechanism:** If you steal a TGT from memory (e.g., via Mimikatz), you can inject it into your own session.
    
- **Outcome:** You authenticate to the KDC as that user without knowing their password. The TGT is the proof of identity; whoever holds it is that user.

## **Golden Ticket**

- **Prerequisite:** Requires the `krbtgt` account password hash (Domain Admin or DC compromise).
    
- **Mechanism:** You can forge a TGT entirely from scratch for any user, including fake Domain Admins.
    
- **Persistence:** The forged TGT is signed with the `krbtgt` hash, so the KDC accepts it as legitimate. It persists even after user password resets.
    
- **Remediation:** The `krbtgt` hash must be reset **twice** to invalidate existing Golden Tickets.

---
### Step 3 — TGS-REQ (Service Request)

_User requests a service ticket, sending TGT + SPN._

## **Kerberoasting**

- **Mechanism:** Any domain user can request a TGS for any service that has a Service Principal Name (SPN) registered.
    
- **Vulnerability:** The TGS is encrypted with the Service Owner's password hash.
    
- **Exploitation:** Attacker requests a TGS for a target service, exports the encrypted ticket, and cracks it offline.
    
- **Advantage:** No special privileges are needed; any domain user can perform this. It is highly effective against service accounts with weak passwords.

---
### Step 4 — TGS-REP (KDC Response)

_KDC returns TGS encrypted with the Service Owner's hash._

## **Silver Ticket**

- **Prerequisite:** Requires the Service Owner's password hash (specific service account).
    
- **Mechanism:** You forge a TGS for that specific service without interacting with the KDC.
    
- **Advantage:** More stealthy than a Golden Ticket because no KDC traffic is generated; the service validates the ticket locally using its own hash.
    
- **Limitation:** Restricted to the specific service the hash belongs to.

---
### Step 5 — AP-REQ (Service Presentation)

_User presents TGS to the target service._

## **Pass the Ticket (PTT)**

- **Mechanism:** If you steal a TGS from memory for a specific service, you can inject it and access that service as the victim user.
    
- **Use Case:** Primarily used for lateral movement to specific high-value resources.

---
## NetNTLM Attack Vectors

## **NTLM Relay**

- **Scenario:** Attacker occupies a Man-in-the-Middle (MITM) position.
    
- **Mechanism:** The client sends a challenge response intended for a legitimate server. The attacker forwards this response to a different target server in real time.
    
- **Outcome:** The target server authenticates the attacker as the victim.
    
- **Tools:** `Responder` + `ntlmrelayx`.

## **LLMNR/NBT-NS Poisoning**

- **Scenario:** A machine attempts to resolve a hostname that DNS cannot find.
    
- **Mechanism:** The machine falls back to broadcasting LLMNR or NBT-NS on the local network. The attacker responds to the broadcast, pretending to be the requested host.
    
- **Outcome:** The victim sends NetNTLM authentication to the attacker, which is captured.
    
- **Tools:** `Responder`.

## **NetNTLM Hash Cracking**

- **Mechanism:** Uses captured NetNTLM hashes from relay or poisoning attacks.
    
- **Process:** The hash contains a response derived from the password; it must be cracked offline (e.g., via `hashcat`) to retrieve the plaintext.
    
- **Note:** Unlike NTLM hashes (found in the SAM database), NetNTLM hashes are **not** directly usable for Pass-the-Hash (PtH) attacks.

---
### Summary Table

| Attack           | Skips                      | Enters Flow At               | Needs                           |
| ---------------- | -------------------------- | ---------------------------- | ------------------------------- |
| AS-REP Roasting  | __                         | Never enters — offline crack | Preauth disabled account        |
| Kerberoasting    | Nothing — uses normal flow | Normal Step 3                | Any domain user                 |
| Golden Ticket    | Steps 1 and 2              | Step 3 with forged TGT       | krbtgt hash                     |
| Silver Ticket    | Steps 1, 2, 3, 4           | Step 5 with forged TGS       | Service account hash            |
| PTT (TGT stolen) | Steps 1 and 2              | Step 3 with stolen TGT       | Shell on machine + LSASS access |
| PTT (TGS stolen) | Steps 1, 2, 3, 4           | Step 5 with stolen TGS       | Shell on machine + LSASS access |

---
---
