# From Audit to Pentest: Linux Server Security Lifecycle  

*Example: SecureTech Solutions*

---
## 🔐 Phase 1: Develop Security Policy (NIST SP 800-53 Aligned)

### Core Policy Areas & Controls

| Policy Area | NIST Control | Key Requirements |
|------------|-------------|------------------|
| **Access Control** | AC-2, AC-5 | No shared accounts; disable inactive users within 30 days |
| **Authentication** | IA-2, IA-5 | Enforce 12+ character passwords; **SSH key-only authentication**; 2FA for privileged accounts |
| **Logging** | AU-2, AU-6 | Enable centralized logging (rsyslog/journald); retain logs for at least 90 days |
| **Configuration Management** | CM-2, CM-5 | Maintain secure baseline config using Ansible/Puppet; apply security patches within 30 days |
| **System Integrity** | SI-3, SI-4 | Deploy malware protection; run regular Lynis audits; monitor for anomalies |
| **Maintenance** | MA-2, MA-3 | Perform maintenance via approved procedures and trusted tools only |

> ✅ A strong policy is specific, enforceable, and mapped to recognized standards.

---
## 🛠️ Phase 2: Security Audit with Lynis

### Steps

1. **Install and Run**:
   ```bash
   sudo apt install lynis
   sudo lynis audit system
   ```
2. **Analyze Output**:  
   - Lynis checks system settings against hardening best practices  
   - Flags misconfigurations (e.g., weak SSH ciphers, missing updates)
3. **Remediate Findings**:  
   - Fix issues (e.g., disable root SSH login, enforce password aging)  
   - Update policy if a control proves unrealistic in practice

> 🔍 Lynis acts as an **automated auditor** — it validates whether your system matches your policy.

---
## 💥 Phase 3: Penetration Test (Validate Remediation)

### Execution

1. **Recon & Scanning**:
   ```bash
   nmap -sV -p- 192.168.1.20
   ```
2. **Exploitation Attempts**:
   - Try SSH password brute-force → should fail (key-only enforced)  
   - Test for service exploits (e.g., outdated Apache modules)
3. **Validation**:
   - Confirm previously identified flaws are resolved  
   - Detect any **new vulnerabilities** introduced during fixes

### Reporting

- **Executive Summary**: High-level status of security posture  
- **Technical Findings**: Residual risks with severity (Critical/High/Medium)  
- **Recommendations**: Actionable steps (e.g., “Enable kernel ASLR”, “Restrict sudo rules”)

---
## 🔁 The Full Lifecycle Flow

1. **Define Policy** → based on NIST SP 800-53  
2. **Audit System** → using Lynis to check compliance  
3. **Remediate Gaps** → align system with policy  
4. **Penetration Test** → verify fixes hold under attack  
5. **Refine Policy** → based on test results  

> 🔑 **Audit answers**: “Are we following our rules?”  
> **Pentest answers**: “Can an attacker break in anyway?”  
> Together, they ensure **compliance + real security**.

