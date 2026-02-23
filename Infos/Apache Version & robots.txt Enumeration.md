# 1. How to Get Apache Version

Several methods exist, from polite header checks to aggressive scanning. Start with the quickest ones on the Mr. Robot machine.

## curl – Quickest & Most Polite

```bash
curl -I http://10.114.148.228
```
- `-I`: HEAD request → only fetches headers (no body)  
- Look for `Server:` line, e.g.:
  ```
  Server: Apache/2.4.7 (Ubuntu)
  ```

**curl -I vs -S**:
- `-I`: Headers only (fast, clean, recommended)  
- `-S`: Show errors (used with `-s` for silent mode + error output). Not needed here.  
- Verbose alternative:  
  ```bash
  curl -v http://10.114.148.228   # shows full headers + body
  ```

# 2. robots.txt – Hidden Files & Paths

**WTF moment**: Yes — files listed in robots.txt are **publicly downloadable** and often contain clues, creds, or flags.

**Why it works**:
- robots.txt is a plain text file at the website root:  
  `http://10.114.148.228/robots.txt`
- It lists "Disallow" paths (meant for crawlers), but **everyone** can read it.
- Paths are **relative to root** (`/`), so:
  - `Disallow: /key-1-of-3.txt` → `http://10.114.148.228/key-1-of-3.txt`

**How he knew the location**:
- He **didn't guess** — the paths are **explicitly written** in robots.txt itself.

**Steps to exploit**:
1. Download robots.txt:
   ```bash
   curl http://10.114.148.228/robots.txt > robots.txt
   cat robots.txt
   ```

   Example output (Mr. Robot):
   ```
   User-agent: *
   Disallow: /key-1-of-3.txt
   Disallow: /key-2-of-3.txt
   Disallow: /key-3-of-3.txt
   ```

2. Download listed files:
   ```bash
   wget http://10.114.148.228/key-1-of-3.txt
   wget http://10.114.148.228/key-2-of-3.txt
   ```

**Exam/Lab Tip**:
- Always check `/robots.txt` on **every** web target
- Download **every** Disallow file — they often contain:
  - Flags
  - Credentials
  - Backups
  - Hidden directories
- No need for Gobuster/FFUF first — robots.txt is **public** and gives direct paths.

**Run this now**:
```bash
curl http://10.114.148.228/robots.txt
```

