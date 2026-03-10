## Windows Command Line Basics

**System Info**

- `hostname` — outputs the computer name
- `whoami` — outputs the currently logged-in user
- `ipconfig` — displays network address settings

**General Tips**

- `command /?` — displays help manual for most commands
- `cls` — clears the screen (Linux equivalent: `clear`)

**netstat**

- Displays protocol statistics and current TCP/IP network connections
- Can run alone or with parameters: `-a`, `-b`, `-e`, etc.

**net**

- Primarily used to manage network resources, supports sub-commands
- Does **not** use `/?` for help — uses its own syntax:
    - `net help` — general help
    - `net help user` — help for a specific subcommand

---

## Why `net user help` Doesn't Work

`net` parses arguments **positionally** — it reads left to right:

```
net user help
```

It interprets this as: _"look up a user account named `help`"_ — so it searches for a user called "help" and fails.

```
net help user
```

Here `help` is the **subcommand**, and `user` is the **topic** — the parser hits `help` first and knows to display documentation for the `user` topic.

It's just how the `net` command's argument parser was designed — `help` must come first.

