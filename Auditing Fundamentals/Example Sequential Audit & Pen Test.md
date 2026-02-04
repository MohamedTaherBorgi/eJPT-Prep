
## **Organization**: *SecurePayments Inc.* (PCI DSS-compliant credit card processor)

---
## 🔍 Phase 1: Security Audit (External)

### Findings:
- Inadequate encryption for cardholder data in transit  
- Weak network security & monitoring  
- Excessive user permissions (violates least privilege)  
- Outdated incident response plan  

### Remediation Actions Taken:
- Enforced TLS 1.2+ for all data in transit  
- Revised access control policies  
- Updated and tested IR procedures  

---
## 💥 Phase 2: Penetration Test (Post-Remediation)

### Objective  
Verify that **technical controls** implemented after the audit are **actually effective**.

### Scope  
- Cardholder Data Environment (CDE)  
- Web apps, network perimeter, admin interfaces  

### Execution Steps  
1. **Recon**: Reviewed network diagrams, PCI SAQ, audit report  
2. **Scanning**: `nmap`, `nikto`, `burp` on CDE  
3. **Exploitation**:  
   - Found **exposed admin panel** (no auth)  
   - Discovered **SQLi** in customer portal  

### Findings  
| Vulnerability | Risk | Root Cause |
|--------------|------|-----------|
| Unprotected admin interface | Critical | Misconfigured WAF / missing auth |
| SQL injection | High | Poor input validation in app |

### Recommendations  
- Harden admin interfaces with MFA + IP allowlisting  
- Patch app + implement WAF rules  
- Conduct secure code training  

---
## ✅ Outcome: Why Sequential Works

| Assessment | Role |
|----------|------|
| **Security Audit** | Identified **policy/process gaps** (e.g., "encryption required") |
| **Penetration Test** | Validated **technical implementation** (e.g., "TLS works, but admin panel bypasses it") |



