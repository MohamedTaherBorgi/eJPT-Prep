
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
thm.local ← root domain ├── uk.thm.local ← subdomain ├── us.thm.local ← subdomain
```

Each domain has its own DC, users, computers and policies managed independently.
UK IT team manages UK DC only — cannot touch US DC and vice versa.

---
### Forests

<u>Multiple trees</u> with **different namespaces** joined into one network:

```
thm.local ← tree 1 ├── uk.thm.local ├── us.thm.local

mht.local ← tree 2 (acquired company) ├── asia.mht.local ├── eu.mht.local

Both trees together = Forest
```

---
### Admin Groups

| Group | Scope |
|---|---|
| Domain Admins | Full control over their single domain only |
| Enterprise Admins | Full control over ALL domains in the entire forest |

---

## Trust Relationships & Forest Structure

### Where Trusts Exist

```
Same tree (automatic): thm.local ←——two-way trust——→ uk.thm.local created automatically when subdomain joins the tree

Different trees same forest (automatic): thm.local ←——two-way trust——→ mht.local created automatically when trees join the forest

Different forests (manual): thm.local ←——one-way or two-way——→ external.local must be manually configured by admins
```

| Relationship | Trust Type | Created |
|---|---|---|
| Parent → Child domain (same tree) | Two-way | Automatically |
| Tree → Tree (same forest) | Two-way | Automatically |
| Forest → Forest | One or two-way | Manually |
| External domain | One or two-way | Manually |

---
### Transitive Trust

Within a forest, trust does not flow directly between domains — it flows through the chain:

```
xyz.com ←——trust——→ forest root ←——trust——→ abc.com
```

>xyz.com and abc.com trust each other transitively through the <u>forest root</u>.
>
This means trust flows freely up and down the entire forest automatically.

| | Transitive | Non-Transitive |
|---|---|---|
| Trust flows through chain | Yes | No |
| Default within forest | Yes | No |
| Example | All intra-forest trusts | Some manual external trusts |

---
### Forest Boundary = True Security Boundary

Domains within the same forest <u>automatically</u> trust each other.
Two separate forests do not trust each other unless manually configured.
This is why the forest — not the domain — is the real security boundary in AD.

---
### Forest Root

The <u>first</u> domain created in the forest becomes the forest <u>root</u> automatically:

```
thm.local created first → becomes forest root
```

|                         | Forest Root     | Regular Domain |
| ----------------------- | --------------- | -------------- |
| Created first           | Yes             | No             |
| Holds Enterprise Admins | Yes — only here | No             |
| Central trust hub       | Yes             | No             |
| Can be dethroned        | No              | N/A            |

<u>Enterprise Admins group</u> **only exists in the forest root** — full admin over every domain in the entire forest.

---
### Offensive Endgame

```
Compromise any domain → escalate to Domain Admin → pivot to forest root → escalate to Enterprise Admin → own every domain in the forest
```

> Forest root is the crown jewel of the entire AD structure.
> Domain Admin = own one domain. Enterprise Admin = own everything.

---
---
