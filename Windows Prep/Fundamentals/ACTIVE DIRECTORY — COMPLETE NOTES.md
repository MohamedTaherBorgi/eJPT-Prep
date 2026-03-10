## OBJECTS

Everything that exists in AD is an "**object**" — users, machines, groups, OUs, GPOs, printers, contacts. 
Object just means "a thing that exists in AD." Not all objects are equal — some can authenticate and hold permissions, some cannot.

---
## SECURITY PRINCIPALS

A security principal is a specific type of object that can do two things:

1. Authenticate to the domain (prove its identity)
2. Be assigned permissions over resources

Only three things qualify:

- Users
- Machines
- Security Groups

OUs, GPOs, printers, contacts — these are objects but <u>NOT</u> security principals. They <u>cannot</u> log in or be assigned permissions.

---
## USERS

Represent either a <u>person</u> (employee) or a service (IIS, MSSQL etc). <u>Service</u> accounts are still user objects but have minimal privileges — only what their specific service needs to run.

---
## MACHINE ACCOUNTS

When a PC joins the domain, AD automatically creates a machine account for it. Named as COMPUTERNAME$ (e.g. DC01$).

Common confusion — the machine account is <u>NOT</u> the local Administrator account. They are two completely separate things:

```
Local Administrator account   = human-usable admin account that exists on that PC locally
COMPUTERNAME$                 = the computer's identity in AD, used by the OS itself to talk to the domain
```

The machine account is used by the computer itself to:

- Authenticate to the domain
- Apply Group Policy
- Communicate with other domain services
- Kerberos authentication between machines

Machine account password = 120 random characters, automatically rotated. Humans are not supposed to use it. 
>But offensively — the hash is still usable for Pass-the-Hash even though the password itself is uncrackable.

---
## SECURITY GROUPS = Groups

A container that holds users, machines, and other groups. The purpose of a security group is to grant access to resources. 
Instead of assigning permissions to 100 users individually, you assign permission to the group once — then add users to the group and they inherit the permission automatically.

<u>A user can be in many groups simultaneously.</u>

### How it works under the hood: 
The resource (folder, printer, share) has an ACL (explained below). 
The group gets added to that ACL with a specific permission. 
When john is added to the group, Windows checks the ACL at access time, sees the group has permission, checks if john is a member, and grants access. 

>Adding john to the group does NOT modify the ACL — the ACL already had the group in it. John just got the key that opens the lock.

Important built-in groups:

```
Domain Admins       = full admin over entire domain including DCs
Server Operators    = administer DCs, cannot change admin group memberships
Backup Operators    = can access ANY file ignoring all permissions
Account Operators   = can create and modify domain accounts
Domain Users        = contains all user accounts in the domain
Domain Computers    = contains all computers in the domain
Domain Controllers  = contains all DCs in the domain
```

---
## OUs (ORGANIZATIONAL UNITS)

A container that organizes users and machines inside AD. An OU does nothing on its own — its only purpose is to hold objects and receive GPOs that then apply to everything inside.

<u>A user can only be in ONE OU at a time.</u>

### Common confusion : 

Default containers like Builtin, Computers, and Users look exactly like OUs in the GUI but they are NOT OUs. They are default system containers:

```
                    Default Containers      OUs
                    
Apply GPO                   NO              YES
Delegate control            NO              YES
Create manually             NO              YES
Delete by default           NO              YES
```

>New machines that join the domain land in the Computers container by default — no GPO applies to them automatically until an admin moves them to a proper OU. 

>This is a common misconfiguration in real environments.

---
## GPOs (GROUP POLICY OBJECTS)

A GPO is a ruleset of settings that gets pushed down to everything inside an OU. 

GPO is not a container and not a group — it is <u>a configuration delivery mechanism</u>. It does nothing until linked to an OU.

### Common confusion 

GPO does NOT only push behavior rules like screensavers and USB restrictions. 

### GPO pushes TWO categories of settings:

#### Category 1
<u>Behavior and configuration settings: </u>
- Force screensaver timeout 
- Disable USB ports 
- Set password complexity requirements 
- Map network drives automatically 
- Push software installs Configure firewall rules 
- Registry settings

#### Category 2 
<u>Permission and access settings: </u>
- Add users or groups to local groups on machines (like Remote Desktop Users or Administrators) 
- User Rights Assignment : who can log on locally, who can RDP, who can debug programs, who can act as part of the OS Software restriction policies 
- Who can shut down the machine

<u>So GPO can absolutely grant RDP access</u> — by pushing a rule that adds a user or group into the local Remote Desktop Users group on every machine the GPO covers.
The actual permission still lives in the local group on the machine.
GPO is just the delivery mechanism that fills that group automatically at scale across many machines.

#### GPO application order
LSDOU (last writer wins, most specific wins): 
1. Local = GPO set on the machine itself 
2. Site = AD site the machine belongs to 
3. Domain = GPO linked at domain level 
4. OU = GPO linked to the objects OU

If there is a conflict between settings, the later one overwrites. 
<u>OU GPO wins over Domain GPO which wins over Site which wins over Local. </u>
<u>If OUs are nested, the child OU GPO wins over the parent OU GPO.</u>

<u>Exception</u> : a GPO can be marked Enforced. This means no lower level GPO can overwrite it regardless of order. 
>Used for company-wide policies that no OU admin can override.

Offensively — if you can write to a GPO linked at domain level, your settings apply to every user and machine in the domain. 
<u>BloodHound</u> maps who has GPO write permissions. 
<u>SharpGPOAbuse</u> exploits writable GPOs.

### GPO Distribution — SYSVOL

GPOs are distributed to the network via a share called **SYSVOL**, stored on the DC:

```
C:\Windows\SYSVOL\sysvol\
````

All domain users have read access to SYSVOL to sync their GPOs periodically.

**Sync timing:**
- Changes to GPOs can take up to **2 hours** to apply to all machines
- Force immediate sync on a specific machine:

```powershell
gpupdate /force
````

> **Offensively** — SYSVOL is readable by all domain users.
>  Admins sometimes store scripts, passwords, or credentials in SYSVOL GPP (Group Policy Preferences) files. 
>  Classic finding: `\\DC\SYSVOL\domain\Policies\` — search for `cpassword` in XML files → encrypted but easily decrypted via `gpp-decrypt`
---
## DELEGATION

Delegation is a permission entry placed directly on an <u>OU</u> that gives a specific user or group the ability to manage objects <u>inside that OU</u>. 

It is NOT a group membership — the user does not join anything. AD simply records an <u>ACL entry on the OU object itself.</u>

>Delegation is scoped — it only applies to the OU it is set on and flows down to objects inside it.

>Example: 
Helpdesk has ResetPassword delegation on Sales OU → helpdesk can reset passwords for everyone inside Sales OU → cannot touch IT OU or any other OU

Set via: right click OU → Delegate Control → select user or group → select specific permissions

#### Common delegatable tasks: 
Reset passwords 
Create and delete user accounts 
Manage group membership 
Unlock accounts

Offensively — delegation misconfigurations are one of the most common AD privilege escalation paths. 
If you compromise a helpdesk account that has ResetPassword delegation on an OU containing Domain Admins, you can reset a DA password and escalate instantly. 
BloodHound maps this automatically.

---
## ACLs (ACCESS CONTROL LISTS)

ACLs are the underlying permission storage that everything else writes to.
Every single object in Windows and AD has an ACL attached — <u>it is simply a list of who can do what to that object.
</u>

>Example file ACL: 
john = read, write Sarah = read only Domain Admins = full control

>Example AD object ACL: 
helpdesk = reset password john = read only Domain Admins = full control

<u>ACL is not a separate mechanism sitting alongside groups and GPOs — it is the foundation that all other mechanisms write to</u>

```
Security Group   = gets added to the ACL on a resource
                   PrinterAccess group added to printer ACL with print permission
                   john added to group = john inherits that ACL entry indirectly

GPO              = remotely writes to ACLs and local groups on machines
                   GPO adds john to Remote Desktop Users = writing to that machines local group ACL

Delegation       = writes an ACL entry directly on the OU object
                   helpdesk gets reset password ACL entry on Sales OU

Direct ACL       = manually writing to an ACL yourself without groups or GPO
                   right click folder → security → add john directly
```

Offensively — BloodHound specifically hunts misconfigured ACL entries on AD objects:

```
GenericAll          = full control over that object
GenericWrite        = modify attributes of that object
WriteDACL           = modify the ACL itself — can give yourself any permission
WriteOwner          = take ownership of the object
ForceChangePassword = reset password without knowing the current one
```

Finding any of these on a privileged object is a direct escalation path.

---
---
# ============= FULL MENTAL MODEL =============

```
OU          = WHERE objects live in AD — determines what GPO hits them
GPO         = WHAT settings and permissions are pushed to objects inside the OU
Group       = WHAT resources a user can reach — their access card
Delegation  = WHO can manage objects inside an OU
ACL         = the actual permission record on every object — everything above writes to this
```

# WHERE JOHN'S PERMISSIONS ACTUALLY COME FROM

```
Group memberships        = what resources he can reach (files, printers, RDP, shares)

GPO from his OU          = what rules and permissions are forced onto him and his machine

Built-in group rights    = if he is in Domain Admins, Backup Operators etc

Direct ACL entries       = one-off permissions set directly on a resource for him specifically

Delegation               = what AD objects he can manage
```

<u>All four apply simultaneously. No single place holds everything — AD combines them all at access time.</u>

---
---
