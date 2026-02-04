## Definitions
| Type | Purpose | Enforceability |
|------|--------|---------------|
| **Framework** | Structured approach to implement security (flexible) | ✅ Voluntary |
| **Standard** | Specific mandatory requirements | ⚠️ Often legally required |
| **Guideline** | Recommended best practices | ✅ Advisory only |

---
## 🧩 Frameworks (Flexible, Strategic)

### **NIST Cybersecurity Framework (CSF)**

- **Purpose**: Reduce cyber risk  
- **Core Functions**: **Identify, Protect, Detect, Respond, Recover**  
- **Use Case**: All industries; US govt preferred

### **COBIT**

- **Purpose**: Align IT governance with business goals  
- **Focus**: Risk management, compliance, IT process control  
- **Use Case**: Enterprises, auditors

---
## 📜 Standards (Mandatory, Compliance-Driven)

| Standard | Scope | Key Requirements | Legal? |
|---------|------|------------------|--------|
| **ISO/IEC 27001** | Global ISMS | Risk-based infosec controls, continuous improvement | ❌ Voluntary (but often contractually required) |
| **PCI DSS** | Payment cards | Secure network, protect cardholder data, access control | ✅ Required for merchants/service providers |
| **HIPAA** | US Healthcare | Privacy/Security Rules for PHI, breach notification | ✅ Mandatory for covered entities |
| **GDPR** | EU/EEA | Data subject rights, lawful processing, breach reporting | ✅ Applies to any org handling EU personal data |

---
## 📘 Guidelines (Best Practices)

### **CIS Controls**

- **What**: 18 prioritized actions (e.g., inventory, secure config, MFA)  
- **Use**: Practical, actionable hardening steps  
- **Adoption**: Widely used by govt & private sector

### **NIST SP 800-53**

- **What**: Catalog of 1000+ security/privacy controls  
- **Focus**: Federal systems (but used broadly)  
- **Legal**: ✅ Required for US federal agencies & contractors

---
## 💡 Why This Matters for Pentesters

- **Map findings to standards**:  
  - SQLi → **PCI DSS Req 6.5**  
  - Missing MFA → **CIS Control 6**, **NIST 800-53 IA-2**  
- **Prioritize based on framework**:  
  - NIST CSF "Protect" > "Recover" in preventive testing  
- **Speak the client’s language**:  
  - Report: “Fails ISO 27001 A.9.4.2 (privileged access)”  

> 🔑 **Standards tell you *what* to test. Frameworks tell you *how* to structure it. Guidelines tell you *how well* you did.**

