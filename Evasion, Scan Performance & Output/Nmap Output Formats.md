## Standard Output Options

| Flag           | Format                      | Use Case                               |
| -------------- | --------------------------- | -------------------------------------- |
| `-oN file.txt` | **Normal** (human-readable) | Manual review, reports                 |
| `-oX file.xml` | **XML** (structured)        | Import into tools (Metasploit, Nessus) |

---
## Integration with Metasploit

### Option 1: Import XML
```bash
nmap -sV -oX scan.xml 192.168.1.0/24
```

Then in `msfconsole`:
```msf
db_import /path/to/scan.xml
```

### Option 2: Scan Directly in Metasploit
```msf
db_nmap -sV 192.168.1.0/24
```

→ Results auto-saved to current workspace.

---
## Useful Flags

- `-v` / `-vv`: Increase verbosity (see more details)
- `--reason`: Show **why** a port is open/closed/filtered  

Example: `445/tcp open  microsoft-ds syn-ack ttl 128`

