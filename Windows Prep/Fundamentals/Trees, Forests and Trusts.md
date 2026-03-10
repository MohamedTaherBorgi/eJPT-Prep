
## Multi-Domain Architecture

---
### Why Multiple Domains

Single domain works for small companies. As companies grow needs arise:
- Different countries with different laws and GPO requirements
- Separate IT teams managing their own resources independently
- Acquired companies with completely different infrastructure

---
### Trees

Multiple domains that **share the same namespace** joined together:

```
thm.local ← root domain ├── uk.thm.local ← subdomain └── us.thm.local ← subdomain
```

Each domain has its own DC, users, computers and policies managed independently.
UK IT team manages UK DC only — cannot touch US DC and vice versa.

---
### Forests

<u>Multiple trees</u> with **different namespaces** joined into one network:

```
thm.local ← tree 1 ├── uk.thm.local └── us.thm.local

mht.local ← tree 2 (acquired company) ├── asia.mht.local └── eu.mht.local

Both trees together = Forest
```

---
### Admin Groups

| Group | Scope |
|---|---|
| Domain Admins | Full control over their single domain only |
| Enterprise Admins | Full control over ALL domains in the entire forest |

---
### Trust Relationships

Trusts allow users from one domain to access resources in another domain.

**One-way trust:**
```

Domain AAA trusts Domain BBB → BBB users CAN access AAA resources → AAA users CANNOT access BBB resources

Note: trust direction is opposite to access direction

```

**Two-way trust:**
```

Both domains trust each other → users from either domain can access resources in the other → default when joining domains into trees or forests

```

> **Important:** 
> Trust does not automatically grant access to everything.
> Trust just makes it **possible** to authorize cross-domain access.
> What is actually accessible is still controlled by permissions and ACLs.

---
### Offensive Relevance

Trust relationships are a major lateral movement path:

```
Compromise low-value domain (uk.thm.local) :

→ enumerate trust relationships 
→ find two-way trust with high-value domain (us.thm.local) 
→ use trust to move into the other domain 
→ escalate to Enterprise Admin → own entire forest
```

Tools: BloodHound maps all trust relationships automatically.
Key attack: **Cross-domain attacks, SID history abuse, foreign group membership abuse**

---
---
