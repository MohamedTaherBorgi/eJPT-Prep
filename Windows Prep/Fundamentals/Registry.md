## Windows Registry

The registry is a **central hierarchical database** storing configuration data for users, applications, and hardware. Windows references it constantly during operation.

**Stores:**

- User profiles
- Installed applications and their document types
- Folder/icon property settings
- Hardware inventory
- Ports in use

**Access via:** `regedit`

---
## Structure

The registry is organized like a filesystem — **hives → keys → subkeys → values**:

```
HKEY_LOCAL_MACHINE
└── SOFTWARE
    └── Microsoft
        └── Windows
            └── CurrentVersion
                └── Run    ← value (autorun entries)
```

**Five Root Hives:**

|Hive|Abbreviation|Contains|
|---|---|---|
|`HKEY_LOCAL_MACHINE`|HKLM|System-wide settings, hardware|
|`HKEY_CURRENT_USER`|HKCU|Logged-in user settings|
|`HKEY_USERS`|HKU|All user profiles|
|`HKEY_CLASSES_ROOT`|HKCR|File associations, COM objects|
|`HKEY_CURRENT_CONFIG`|HKCC|Current hardware profile|

---
## Offensive Relevance

Registry is critical in red teaming:

```cmd
# Persistence — autorun on login
HKCU\Software\Microsoft\Windows\CurrentVersion\Run

# Stored credentials, product keys, configs
HKLM\SOFTWARE\

# UAC bypass settings
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System

# Disable defender via registry
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender
```

