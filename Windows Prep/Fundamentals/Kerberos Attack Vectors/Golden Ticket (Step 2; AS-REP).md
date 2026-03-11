holy shit power ; ### The Real Power

You can forge the TGT to include:

```
Any username         → real or completely fake
Any group membership → put yourself in Domain Admins
Any privilege level  → full enterprise admin
Any expiry time      → valid for 10 years if you want
```

KDC reads what is inside the TGT and issues TGS accordingly — it trusts the TGT contents completely because the signature is valid.

```
### Why Golden Ticket Is Used At this point you already own everything — so why bother? ``` Persistence → even if they reset every password Golden Ticket still works until krbtgt is reset TWICE Stealth → no need to keep a live connection generate tickets on demand anytime Flexibility → impersonate any user at any time without needing their credentials
```
