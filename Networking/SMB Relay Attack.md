## 🔍 What Is SMB Relay?

An **SMB relay attack** is a **man-in-the-middle (MitM)** technique where an attacker:
1. **Intercepts** SMB authentication requests
2. **Relays** the NTLM challenge-response to another target
3. **Gains access** as the original user — **without cracking the hash**

> 💡 **Key Insight**:  
> You don’t need to crack the hash — you **reuse it in real-time**.

---
## 🧠 How It Works

### Step 1: Force Authentication
- Trick a user/machine into connecting to **your rogue SMB server**
- Methods:
  - **ARP spoofing** → redirect traffic on LAN
  - **DNS poisoning** → resolve `fileserver` → your IP
  - **LLMNR/NBT-NS poisoning** → respond to `WPAD`, `CORP-SRV` queries
  - **Phishing** → `\\attacker\share` in email

### Step 2: Capture & Relay
- When victim connects to your fake SMB server:
  - You receive **NTLMv1/v2 challenge-response**
- Instead of storing it, you **immediately relay** it to a **target server** (e.g., `192.168.1.20`)
- If the target accepts it → you get **authenticated session as the victim**

---
## ⚠️ Critical Requirements

| Condition                | Why It Matters                                    |
| ------------------------ | ------------------------------------------------- |
| **SMB signing disabled** | Signing blocks relay (hash is bound to session)   |
| **Victim ≠ target**      | Can’t relay to same machine (loopback protection) |
| **Valid user context**   | Victim must have rights on target                 |

> ❌ **Fails if**:  
> - `SMBSigning = Required` (enforced by GPO)  
> - Target is DC (relaying to DC often blocked)


