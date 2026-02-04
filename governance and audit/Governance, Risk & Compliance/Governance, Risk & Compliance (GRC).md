## What Is GRC?

A **unified framework** that aligns:
- **Governance**: Policies, accountability, decision-making  
- **Risk**: Identification, assessment, mitigation of threats  
- **Compliance**: Adherence to laws, regulations, and internal policies  

> 🎯 Goal: Ensure security efforts support business objectives in a regulated world.

---
## Core Components

### 1. **Governance**

- **Policy Development**: Create clear security policies (e.g., password rules, access control)  
- **Roles & Responsibilities**: Define who owns security (CISO, IT, Dev)  
- **Accountability**: Track performance via metrics, audits, and reviews  

### 2. **Risk Management**

- **Risk Identification**: Find threats (e.g., unpatched servers, phishing)  
- **Risk Assessment**: Rate risks by **likelihood × impact**  
- **Risk Mitigation**: Apply controls (patching, training, segmentation)  

### 3. **Compliance**

- **Regulatory Requirements**: Follow GDPR, HIPAA, PCI DSS, ISO 27001  
- **Internal Policies**: Enforce company-specific rules  
- **Audits & Assessments**: Prove compliance via testing and documentation  

---
## Why GRC Matters for Penetration Testers

| Benefit | Explanation |
|--------|------------|
| **Better Scoping** | Align tests with business-critical assets & compliance requirements (e.g., PCI DSS CDE) |
| **Contextual Reporting** | Frame findings as **violations of policy or regulation** (e.g., “SQLi = PCI DSS Requirement 6.5”) |
| **Strategic Impact** | Recommend fixes that satisfy **governance**, reduce **risk**, and ensure **compliance** |

> 💡 A pentest without GRC context is just a list of bugs.  
> ✅ A GRC-aware pentest drives **business-aligned security decisions**.

---
## Example: GRC in Action

- **Finding**: Weak password policy  
- **Governance Link**: Violates internal IAM policy  
- **Risk**: High likelihood of credential stuffing → account takeover  
- **Compliance**: Fails NIST 800-63B & ISO 27001 A.9.4.3  

→ Recommendation isn’t just “enforce strong passwords” — it’s **“update policy, deploy MFA, and document for audit.”**

> 🔒 **GRC turns technical flaws into business risk.**

