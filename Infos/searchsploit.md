### Quick Access to Exploit Files via SearchSploit

SearchSploit is pre-installed on Kali and points to `/usr/share/exploitdb/`.  
Use **EDB-ID** (Exploit-DB ID, e.g., 50911) for the commands below.

#### 1. The "Mirror" Command (Easiest & Most Common)

Copies the exploit/shellcode/paper directly into your **current working directory**.

```bash
# Mirror (copy) exploit 50911 to ./
searchsploit -m 50911
# or long version
searchsploit --mirror 50911
```

After running:

```bash
ls
# You'll typically see:
50911.py    # (or .c, .rb, .pl, etc.)
```

**Use-case**:  
Fastest way when you're about to modify/run/debug an exploit in your current project folder.

#### 2. Find the Absolute Path (for manual operations)

Shows full filesystem path without copying anything. Useful when you want to:

- `cat` / `less` / `vim` the file directly
- `cp` it somewhere specific
- Read path for documentation / analysis

```bash
searchsploit -p 50911
# or
searchsploit --path 50911
```

Typical output:

```
Exploit: Some Software 1.2.3 - Remote Buffer Overflow
     URL: https://www.exploit-db.com/exploits/50911
    Path: /usr/share/exploitdb/exploits/linux/local/50911.py
   EDB-ID: 50911
```

#### 3. Examine / Read Immediately (without copying)

Opens the exploit in your default **`$PAGER`** (usually `less`).

```bash
searchsploit -x 50911
# or
searchsploit --examine 50911
```

Behavior:

- Displays full source code in pager
- Use `/searchterm` inside less to jump to code sections
- `q` to quit

**Use-case**:

- Quick code review before deciding to copy/modify/run
- Checking payloads, required args, target versions, comments
- Reading author notes / compilation instructions

### Quick Reference Table

| Goal                              | Command                     | Result / Side-effect                          | Best for                              |
|-----------------------------------|-----------------------------|-----------------------------------------------|---------------------------------------|
| Copy to current dir               | `-m` / `--mirror`           | File appears in `./`                          | Ready-to-modify/run workflow          |
| Show full path                    | `-p` / `--path`             | Prints path (copies to clipboard on some systems) | `cat`, `vim`, targeted `cp`           |
| Read in pager immediately         | `-x` / `--examine`          | Opens in `$PAGER` (less/more)                 | Fast source review, no disk change    |

Keep the local Exploit-DB updated:

```bash
searchsploit -u
```


