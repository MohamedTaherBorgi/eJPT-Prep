## UAC Screen Dimming — Secure Desktop

When UAC prompts and the screen **dims**, Windows switches to the **Secure Desktop** (`winlogon.exe` desktop).

---

## What's Actually Happening

Windows has multiple **desktop objects** (not physical desktops, but kernel objects):

```
Normal:   → runs in user's desktop session (winsta0\default)
UAC dim:  → switches to winlogon desktop (winsta0\winlogon)
```

The dim effect is literally a **screenshot of your desktop** displayed as a frozen background while the real input focus is on the secure desktop.

---

## Why It Does This

The secure desktop runs at **SYSTEM integrity level** — meaning:

- No user-mode process can interact with it
- Malware running in user space **cannot spoof or click the UAC prompt**
- Keyloggers can't capture input typed into it
- No other process can send mouse clicks or keystrokes to it

>The goal is always to **elevate without the prompt appearing at all**, since you can't click through the secure desktop from malware context.

---
---
