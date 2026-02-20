**Kiwi (Mimikatz extension in Metasploit)** primarily retrieves credentials **from memory** (LSASS process), **not from disk**.

### Kiwi / Mimikatz in Metasploit

- Loaded via `load kiwi` in a Meterpreter session.
- Commands like:
  - `creds_all`
  - `creds_msv` / `creds_wdigest` / `creds_kerberos`
  - `sekurlsa::logonpasswords` (native Mimikatz syntax)
- These extract:
  - Clear-text passwords (if WDigest enabled or older Windows)
  - NTLM / LM hashes
  - Kerberos tickets
  - From **LSASS memory** (live process, no disk access needed).
- **Disk access** is possible with other Mimikatz modules (e.g., `lsadump::sam` for local SAM hive, `lsadump::ntds` for NTDS.dit on DCs), but Kiwi's main focus (and most used commands) is **memory-only** dumping for active/logged-in sessions.
- Advantages: In-memory → no file writes → stealthier (avoids disk forensics/AV hits on files).
- Limitations: Needs SYSTEM privileges or debug rights; modern Windows (Win10/11 + protections) often block clear-text, but hashes/tickets still work.

### Metasploit `hashdump` vs `smart_hashdump`

Both dump **local NTLM/LM hashes** (from SAM database), but differ in method and reliability:

| Module / Command              | Source          | Method                                      | Priv Required       | Safe / Reliable?                  | When to Use                              |
|-------------------------------|-----------------|---------------------------------------------|---------------------|-----------------------------------|------------------------------------------|
| `hashdump` (built-in Meterpreter command) | SAM registry (disk) | Direct registry read + SYSKEY decryption   | SYSTEM (or admin + debug) | Very safe, no injection, no crash risk | Quick & safe on most systems             |
| `post/windows/gather/hashdump` | SAM registry   | Same as above (registry export/decrypt)    | SYSTEM              | Safe, leaves no files             | Post module version of the command       |
| `post/windows/gather/smart_hashdump` | SAM (preferred) or LSASS memory | Smart logic: Tries registry first → falls back to LSASS injection if needed (handles DCs, x64 quirks, UAC) | SYSTEM (tries `getsystem`) | More reliable on tricky systems (e.g., DCs, Win2008 R2 x64) | When normal hashdump fails or on DCs    |

- **hashdump** (simple): Fast, registry-only → almost always works if you have SYSTEM.
- **smart_hashdump**: "Smarter" fallback — prefers registry (clean), but injects into LSASS if registry fails (e.g., DC where SAM is protected). More steps → slightly noisier/riskier (injection can crash LSASS on bad hooks).

In labs (like THM), start with plain `hashdump` after `getsystem`. Use `smart_hashdump` if it fails or you're on a domain controller.

Both are for **local accounts only** (<u>not domain/AD hashes from NTDS.dit</u>)
