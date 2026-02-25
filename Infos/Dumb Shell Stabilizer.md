Here’s a **clean, concise, perfect Markdown cheat-sheet** for the **gold-standard shell stabilization technique** (Python PTY + stty raw trick).  
Use this exact sequence every time you land a basic/dumb reverse shell during cert labs (eWPT, eWPTX, CRTP, eCPPT).

```markdown
# Gold Standard: Stabilize a Dumb Shell → Fully Interactive PTY

## Phase 1 – Spawn PTY with Python (most reliable method)
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Fallbacks if python3 missing or broken:
python  -c 'import pty; pty.spawn("/bin/bash")'
python2 -c 'import pty; pty.spawn("/bin/bash")'
```

→ You now have a bash prompt, but arrow keys / clear / tab still broken.

## Phase 2 – Background + Raw Terminal Mode
1. Press **Ctrl + Z** → background the shell  
   (you'll see: `[1]+  Stopped                 ...`)

2. Run (type blindly – you won't see chars):
```bash
stty raw -echo; fg
```
→ Press **Enter** after typing. Shell comes back to foreground in raw mode.

## Phase 3 – Fix TERM (enables vi/nano/clear/vim)
```bash
export TERM=xterm
# or more modern / colorful:
export TERM=xterm-256color
```

## Phase 4 – Match Rows & Columns (fix editor size / scrolling)
On **your attacker machine** (new tab / window):
```bash
stty size
# Example output:  38 126
```

Back in target shell:
```bash
stty rows 38 cols 126
# Replace with your actual numbers
```

## One-Liner Mnemonic / Copy-Paste Sequence
```bash
# After initial connection:
python3 -c 'import pty; pty.spawn("/bin/bash")'   # Phase 1
# Ctrl+Z
stty raw -echo; fg                                 # Phase 2
reset                                              # sometimes needed instead of export
export TERM=xterm-256color                         # Phase 3
stty rows 38 cols 126                              # Phase 4 – use your stty size
```

## Result
- ↑↓ arrow keys → history works
- Tab completion → works
- Ctrl+C → kills foreground process, **does not kill shell**
- `clear`, `reset`, `nano`, `vi`, `vim` → full screen & usable
- No more "Inappropriate ioctl for device" spam

## Quick Alternatives / Fallbacks (when python missing)
- **script** trick:
  ```bash
  script /dev/null -c bash
  ```
- **socat** full TTY (if socat on target):
  ```bash
  socat file:`tty`,raw,echo=0 exec:'bash -li',pty,stderr,setsid,sigint,sane
  ```

Use the **Python PTY method first** — it’s the fastest, most reliable for 90%+ of lab boxes.
