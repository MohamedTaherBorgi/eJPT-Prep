## Alternatives to `cat`

If the `cat` command is disabled, you can use other tools to read the contents of a file.

---
### 1️⃣ Using `less` (usually works)

```bash
less <filename>

pro tip:

less fil* (completes name if has spaces to avoid using "")
```

- Allows scrolling through the file.
- Press `q` to quit.

---
### 2️⃣ Using `head` (reads the beginning of the file)

```bash
head <filename>
```

- Displays the first 10 lines by default.
- Useful if the flag or content is near the top.

---
### 3️⃣ Using `grep` (print all non-empty lines)

```bash
grep . <filename>
```

- Prints all lines that contain at least one character.
- Works well as a simple file reader workaround.

---
### 4️⃣ Using `nl` (numbered lines)

```bash
nl <filename>
```

- Displays file contents with line numbers.

---
### 5️⃣ Using `strings`

```bash
strings <filename>
```

- Extracts printable strings.
- Especially useful for binary files.

