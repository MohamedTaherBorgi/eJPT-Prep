## 🔍 Hash Identification

| Method | Tool |
|--------|------|
| Local (Kali) | `hash-identifier` |
| Online | [hashes.com identifier](https://hashes.com/en/tools/hash_identifier) |
| List all JtR formats | `john --list=formats` |
| Grep for specific format | `john --list=formats \| grep -iF "md5"` |

> [!tip] Standard hash types need a `raw-` prefix
> e.g. `raw-md5`, `raw-sha256`, `raw-sha1` — not universal, always verify first

---
## ⚙️ Core Syntax

```bash
john [options] [file]
```

---
## 🧩 Cracking Modes

### Auto-detect *(unreliable — last resort)*

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

### Format-Specific

```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

### Single Crack Mode (Word Mangling)

```bash
john --single --format=raw-sha256 hashes.txt
```

> [!info] What is word mangling?
> Instead of a wordlist, John **mutates a known word** (usually the username) into password candidates. Targets lazy password habits.
>
> Given username `mike`, John generates:
> `mike1` · `mike2` · `Mike1` · `MIKE1` · `mike!` · `mike$` · `m1ke` · `Mike123` ...

> [!warning] File format required for `--single`
> John needs the username to know what to mangle. Prepend it:
> ```
> ❌  1efee03cdcb96d90ad48ccc7b8666033
> ✅  mike:1efee03cdcb96d90ad48ccc7b8666033
> ```

---
## 📄 GECOS — Why It Matters for Single Crack Mode

`/etc/passwd` has **7 colon-separated fields**:

```
username : x : UID : GID : GECOS : home : shell
```

**Real example:**
```
mike:x:1001:1001:Mike Smith,Office 3,555-1234:/home/mike:/bin/bash
                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                 Field 5 = GECOS
```

GECOS stores: full name, office number, phone number.

> [!example] Why John cares
> People base passwords on their own info.
> If GECOS says **"Mike Smith"**, John also mangles:
> `Smith` · `MikeSmith` · `smith1` · `Smith!` · `msmith` ...
>
> More data fed in = **bigger, smarter candidate list**.
> This is why you use `unshadow` — it gives John the GECOS field alongside the hash.

---
## 🐧 /etc/shadow Cracking

> [!warning]
> You **cannot** feed shadow directly — John needs `/etc/passwd` too to parse it.

**Step 1 — Merge with unshadow:**
```bash
unshadow /etc/passwd /etc/shadow > unshadowed.txt
```

**Step 2 — Crack:**
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt unshadowed.txt
```

---
## 🪟 NTLM / NTHash

> [!info] What is NTHash?
> Modern Windows stores passwords as NTHash in:
> - **SAM database** → local accounts
> - **NTDS.dit** → Active Directory

```bash
john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt ntlm.txt
```

| Detail | Value |
|--------|-------|
| Format flag | `--format=nt` |
| Extraction tools | Mimikatz, secretsdump |
| Alternative to cracking | Pass-the-Hash (PTH) — skip cracking entirely |

> [!tip] Crack NTLM when you need the plaintext — e.g. password reuse across services

---
## ✅ Quick Answers

| Question | Answer |
|----------|--------|
| NTLM `--format` flag | `nt` |
| Joker's password (single crack, raw-sha256) | `Jok3r` |

---
## 🛠️ Custom Rules

**Config file locations:**

| Environment | Path |
|-------------|------|
| TryHackMe AttackBox | `/opt/john/john.conf` |
| Package manager / built from source | `/etc/john/john.conf` |

> [!tip] Stuck on syntax? Check Jumbo John's built-in rules around **line 678** of `john.conf` for working examples to reverse-engineer from.

---
### Rule Structure

```
[List.Rules:RuleName]    ← defines the rule name, used as the --rule= argument (in file)
Example: cAz"[0-9][!£$%@]"       ← modifier + character sets
```

---
### Modifiers

| Modifier | What it does                                     |
| -------- | ------------------------------------------------ |
| `Az`     | **Appends** characters to the end of the word    |
| `A0`     | **Prepends** characters to the start of the word |
| `c`      | **Capitalises** the character at that position   |

---

### Character Sets

Defined inside `[ ]`, placed inside `" "` after the modifier:

| Set       | Matches                  |
| --------- | ------------------------ |
| `[0-9]`   | Any digit 0–9            |
| `[0]`     | Only the digit 0         |
| `[A-Z]`   | Uppercase letters only   |
| `[a-z]`   | Lowercase letters only   |
| `[A-z]`   | Both upper and lowercase |
| `[a]`     | Only the letter `a`      |
| `[!£$%@]` | Any of those symbols     |

---
### Worked Example

**Target password:** `Polopassword1!`
**Word in wordlist:** `polopassword`

**What needs to happen:**
1. Capitalize first letter → `c`
2. Append a digit → `Az"[0-9]"`
3. Append a symbol → `Az"[!£$%@]"`

**<u>Rule definition</u> in `john.conf`:**
```
[List.Rules:PoloPassword]
cAz"[0-9][!£$%@]"
```

**Usage:**
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --rule=PoloPassword hash.txt
```

---
## 🤐 Cracking Password-Protected <u>ZIPs</u> / <u>RARs</u>

> [!info]
> Same pattern as `unshadow` — convert the file to a John-readable hash first, then crack.

**Step 1 — Extract hash from ZIP:**
```bash
zip2john zipfile.zip > zip_hash.txt
```

**Step 2 — Crack:**
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
```

| Part           | Purpose                                            |
| -------------- | -------------------------------------------------- |
| `zip2john`     | Converts ZIP into a crackable hash format          |
| `[options]`    | Checksum options — <u>rarely needed</u>            |
| `>`            | Redirects hash output to file                      |
| `zip_hash.txt` | Fed directly into John — no `--format` flag needed |
>unzip file.zip
>OR
>unrar x file.rar
---
## 🔑 Cracking SSH Private Key Passwords

> [!info]
> `id_rsa` keys can be password-protected. John can crack that password — same convert-then-crack pattern.

**Step 1 — Convert key to crackable hash:**
```bash
ssh2john id_rsa > id_rsa_hash.txt
```

**Step 2 — Crack:**
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash.txt
```

| Part | Purpose |
|------|---------|
| `ssh2john` | Converts `id_rsa` private key into a crackable hash |
| `>` | Redirects hash output to file |
| `id_rsa_hash.txt` | Fed directly into John — no `--format` flag needed |

---
---
