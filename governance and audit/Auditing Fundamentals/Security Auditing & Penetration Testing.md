# Security Auditing vs. Penetration Testing

## Core Differences

| Aspect | **Security Audit** | **Penetration Test** |
|-------|-------------------|----------------------|
| **Purpose** | Evaluate compliance with policies, standards (GDPR, PCI DSS), and effectiveness of controls | Simulate real-world attacks to **exploit** technical vulnerabilities |
| **Scope** | Broad: policies, procedures, physical security, configs, compliance | Narrow: specific systems/apps/networks defined in scope |
| **Methodology** | Document review, interviews, config checks, compliance mapping | Active exploitation using tools (Metasploit, Burp, Nmap) |
| **Outcome** | Gaps in policy/process; compliance status; improvement recommendations | Proof-of-concept exploits; risk-ranked vulns; technical remediation steps |
| **Frequency** | Regular (annual/biannual) or regulatory-driven | As needed (post-change, pre-launch, compliance) |

---
## How They Relate

### 🔁 Sequential Approach (Most Common)

1. **Security Audit First**  
   → Identifies weak policies, misaligned controls, compliance gaps  
2. **Penetration Test Second**  
   → Tests if technical controls actually work (e.g., "Policy says firewall blocks X — does it?")

✅ **Advantages**:  

- Covers both **procedural** and **technical** layers  
- Audit findings **guide pentest scoping**  
- Prioritizes fixes based on real risk

### 🤝 Combined Approach

- Single engagement covering **policy + exploitation**
- Used in mature programs or time-constrained assessments

✅ **Advantages**:  

- Faster, more efficient  
- Unified reporting  
- Better alignment between policy and practice

---
## Key Takeaway for Pentesters

> 🔍 **Audits tell you *what should be secure*.  
> 💥 Pentests prove *what is actually broken*.**
> ✅ Together, they close the loop: **policy → implementation → validation**.

