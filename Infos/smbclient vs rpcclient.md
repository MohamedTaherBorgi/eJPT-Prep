# smbclient

- **Purpose**: Main tool for **connecting to SMB shares**, browsing files, uploading/downloading — basically a command-line Windows Explorer for SMB.
- **Protocol**: Uses **SMB/CIFS** directly (prefers port 445, falls back to 139 in older setups).
- **Needs**: Port **445** open (or 139 in legacy cases).
- **Typical commands inside smbclient**:
  - `ls`, `get file.txt`, `put shell.php`, `recurse; mget *`
  - `exit`
- **Anonymous example**:
  ```bash
  smbclient -L //10.10.10.10 -N
  smbclient //10.10.10.10/Anonymous -N
  ```
- **With credentials**:
  ```bash
  smbclient //10.10.10.10/Anonymous -U john%abc123
  ```

>**Bottom line for smbclient**  
→ File access & share browsing tool  
→ **Requires 445 (or 139) open**  
→ Does **not** speak MS-RPC (cannot enumerate users/groups/RIDs)

---
# rpcclient

- **Purpose**: Low-level client for **MS-RPC** calls over SMB. Used for deep enumeration (users, groups, policies, SIDs, RIDs, domains, privileges, etc.).
- **Protocol**: Uses **MS-RPC** pipes (samr, lsarpc, srvsvc, etc.) tunneled over SMB.
- **Needs**: **Port 445** (modern) or **139** (legacy) — **does not need 135** in most cases with Samba/Windows, because modern RPC can bind directly over 445.
- **Typical commands inside rpcclient**:
  ```bash
  enumdomusers
  enumdomgroups
  queryuser 500
  srvinfo
  netshareenumall
  ```
- **Anonymous example**:
  ```bash
  rpcclient -U "" -N 10.10.10.10
  rpcclient $> enumdomusers
  ```

>**Bottom line for rpcclient**  
→ RPC enumeration & query tool (users, groups, shares metadata, domain info)  
→ **Requires 445 (or 139) open**  
→ **Does NOT require port 135** in modern Samba/Windows (RPC endpoint mapper can be reached      via 445)

### Does rpcclient work if port 135 is not open?

**Yes, in most real-world cases (including your target).**  
- Old Windows/Samba: needed 135 (RPC endpoint mapper) + dynamic high ports.  
- Modern Samba (4.x+) and Windows (SMB2/3): **RPC can bind directly over 445** — no separate 135 required for most calls.

