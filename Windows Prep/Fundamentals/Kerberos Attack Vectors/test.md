While both techniques involve using a stolen password hash instead of a plaintext password, they operate on different protocols and result in different types of access.

---

### Comparison at a Glance

|**Feature**|**Pass-the-Hash (PtH)**|**Overpass-the-Hash (OtH)**|
|---|---|---|
|**Primary Protocol**|**NTLM** / SMB / RPC|**Kerberos**|
|**Goal**|Direct access to a service.|Obtain a Kerberos Ticket (TGT).|
|**Requirement**|Target must support NTLM.|Access to a Domain Controller (KDC).|
|**Output**|An authenticated session.|A `.kirbi` or `.ccache` Kerberos ticket.|
|**Modern Usage**|Often blocked by "Restricted Admin" mode.|Useful when NTLM is disabled/restricted.|

---

### 1. Pass-the-Hash (PtH)

In a PtH attack, you use the NTLM hash of a user to authenticate directly to a remote resource. You never touch the Kerberos infrastructure.

**How it works:**

The attacker initiates an NTLM challenge-response handshake. When the server sends a "challenge" (a random nonce), the attacker encrypts it using the stolen NTLM hash and sends it back. Because the server has the same hash in its database (or can verify it via the DC), it grants access.

**Common Tools:**

- **Mimikatz:** `sekurlsa::pth /user:Admin /domain:lab.local /ntlm:HASH`
    
- **Impacket:** `psexec.py lab.local/Admin@10.10.10.1 -hashes :HASH`
    

---

### 2. Overpass-the-Hash (OtH)

Also known as **Pass-the-Key**, this technique "bridges" the gap between NTLM and Kerberos. You use the NTLM hash (or AES keys) to perform a Kerberos **AS-REQ**.

**How it works:**

Instead of talking to the target server directly, you talk to the Domain Controller. You tell the DC, "I am User X, and here is proof (the hash)." The DC verifies the hash and issues a **Ticket Granting Ticket (TGT)**. From that point on, you are fully authenticated via Kerberos and can request service tickets (TGS) for any resource that user can access.

**Why use it?**

- **NTLM is Disabled:** If a target environment has "Network security: Restrict NTLM" enabled, a standard PtH will fail.
    
- **Stealth:** Kerberos traffic is often less scrutinized than NTLM traffic in modern SOCs.
    
- **Persistence:** Once you have the TGT, you can use it until it expires (usually 10 hours) without needing the hash again.
    

**Common Tools:**

- **Rubeus:** `Rubeus.exe asktgt /user:Admin /domain:lab.local /ntlm:HASH /ptt`
    
- **Mimikatz:** `sekurlsa::pth /user:Admin /domain:lab.local /ntlm:HASH /run:powershell.exe` (When run this way, Mimikatz injects the hash into the session so that any Kerberos request triggered by that process automatically performs OtH).
    

---

### Key Technical Distinction: The PAC

One critical difference is the **Privilege Attribute Certificate (PAC)**.

- In **PtH**, you are relying on the target server to authorize you locally or via Netlogon.
    
- In **OtH**, your TGT contains a PAC signed by the KDC. When you present a service ticket to a server, that server sees the PAC and knows exactly what groups you belong to because the Domain Controller "vouched" for you.
    

### Which one should you use?

- Use **PtH** if you just need quick, "dirty" access to a single machine (like via `psexec` or `wmiexec`).
    
- Use **OtH** if you are moving laterally across a domain that enforces Kerberos, or if you want to perform further Kerberos attacks like **Delegation** or **Silver Tickets**.
    

Would you like to see how to capture the traffic for these attacks in a lab to see the protocol differences in real-time?




