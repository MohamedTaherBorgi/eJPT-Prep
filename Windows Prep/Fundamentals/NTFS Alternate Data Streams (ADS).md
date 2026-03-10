### Every file has at least one data stream ( `$DATA` ).
## What ADS Actually Is (Root Cause / Architecture)

NTFS stores file data in **attributes**, not in a monolithic blob. Every file is really a collection of attributes in the MFT (Master File Table):

```
$STANDARD_INFORMATION   → timestamps, flags
$FILE_NAME              → filename
$DATA                   → the actual file content   ← this is a "stream"
$SECURITY_DESCRIPTOR    → ACL
```

The **unnamed `$DATA` attribute** is what you see normally. But NTFS allows **multiple named `$DATA` attributes** on the same file — those are Alternate Data Streams.

Syntax: `filename.txt:streamname`

The key thing: **the named stream data is not reflected in the file's reported size** and is invisible to most tools.

---
## Creating & Reading ADS (Basic Mechanics)

````cmd
# Write data to an ADS
echo "hidden payload" > legit.txt:hidden

# Write a full binary into an ADS
type evil.exe > legit.txt:evil.exe

# Read it back
more < legit.txt:hidden
notepad legit.txt:hidden

# Execute directly (older Windows)
start legit.txt:evil.exe

# List ADS (built-in)
dir /r legit.txt

`dir /r` output looks like:

legit.txt        14
legit.txt:evil.exe:$DATA    73802
````

---
# One `$DATA` Attribute Type, Multiple Named Instances

Technically it's **one attribute type** (`$DATA` = 0x80) but **multiple instances** of that attribute, each with a different name.

The MFT distinguishes attributes by **type + name together**:

```
Attribute Type 0x80, Name = ""           → unnamed stream (what you see normally)
Attribute Type 0x80, Name = "evil.exe"   → ADS
Attribute Type 0x80, Name = "hidden"     → another ADS
```

So the file has **one `$DATA` type, multiple streams** — each stream is a separate instance of that attribute in the MFT record.

---
## The Naming Convention Makes This Clear

```
file.txt          → file.txt::$DATA        (unnamed stream, explicit form)
file.txt:evil.exe → file.txt:evil.exe:$DATA (named stream)
```

The full syntax is actually `filename:streamname:attributetype`

- `::$DATA` — default, what everyone sees
- `:evil.exe:$DATA` — ADS

You can even do `type file.txt::$DATA` and it works identically to `type file.txt`.

---
---
