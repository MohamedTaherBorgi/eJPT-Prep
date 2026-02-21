# THM Lab Notes – Samba + Ubuntu Enumeration & Exploitation

## Key Discovery: SMB Signing Not Required

From <u>Nmap</u> smb2-security-mode output:
```
smb2-security-mode:
| 3.1.1:
|_ Message signing enabled but not required
```

**Why this is excellent for us**:
- Server allows **unsigned SMB connections** → easier attacks
- Anonymous / null sessions are more likely to work
- Tools like `enum4linux`, `rpcclient`, `smbclient -N` face fewer obstacles

---
## smbclient vs rpcclient – Quick Reference

### <u>smbclient</u>

- **Purpose**: Browse/download/upload files on SMB shares (like Windows Explorer in CLI)
- **Needs**: Port **445** (preferred) or **139**
- **Typical commands**:
  - `ls`  
  - `get staff.txt` → download file  
  - `put shell.php` → upload  
  - `recurse; mget *` → download everything
  - `exit`
- **Anonymous example**:
  ```bash
  smbclient -L //10.114.172.242 -N
  smbclient //10.114.172.242/Anonymous -N
  ```
  
> `-N` : no pass anonymous session try

- **With creds**:
  ```bash
  smbclient //10.114.172.242/Anonymous -U john%abc123
  ```

**Bottom line**: File access & share browsing tool  
Requires 445 (or 139) open  
Cannot enumerate users/groups/RIDs

### <u>rpcclient</u>

- **Purpose**: Low-level MS-RPC queries over SMB (users, groups, RIDs, shares metadata, domain info)
- **Needs**: Port **445** (modern) or **139** — **does NOT need 135** in modern Samba (RPC binds over 445)
- **Typical commands**:
  ```bash
  enumdomusers
  enumdomgroups
  queryuser 500
  srvinfo
  netshareenumall
  ```
- **Anonymous example**:
  ```bash
  rpcclient -U "" -N 10.114.172.242
  rpcclient $> netshareenumall
  ```

> `-N` : no pass anonymous session try

**Bottom line**: RPC enumeration tool  
Requires 445 (or 139) open  
Does NOT require port 135 in modern Samba/Windows

### Why rpcclient shows Windows-style paths on Ubuntu/Samba

> [!IMPORTANT]
> LIIEEEEESS 😡😡😡😡😡😡😡😡😡😡😡

Example output:
```
netname: Anonymous
        path: C:\samba\anonymous
netname: IPC$
        path: C:\tmp
        remark: IPC Service (Samba Server 4.15.13-Ubuntu)
```

**Explanation**:
- Samba **emulates Windows** behavior so Windows clients can connect seamlessly
- It **pretends** to be a Windows server → returns fake Windows paths (`C:\...`)
- Real Linux paths are hidden (e.g. `/srv/samba/anonymous` or `/tmp`)
- The remark line is honest: `Samba Server 4.15.13-Ubuntu` → confirms it's Ubuntu + Samba

**Takeaway**: Always ignore `C:\` paths from Samba — they are <u>fake</u>. Focus on share names and content.

## Important Reminders for This Lab

- **SSH usernames are case-sensitive** on Linux/Ubuntu  
  `molly` ≠ `Molly` ≠ `MOLLY`
- **Safe writable folders** (for uploads/reverse shells):  
  `/tmp` and `/dev/shm` (almost always writable by all users)
- **gobuster** ≈ **automated ffuf** (same purpose, different syntax)



