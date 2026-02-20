# 🔍 FFuF: Directory & File Fuzzing

### The Command

```bash
ffuf -u [http://10.112.156.214/FUZZ](http://10.112.156.214/FUZZ) -w /usr/share/wordlists/dirb/common.txt -e .php,.txt,.bak,.html -c
````

---
### 🚩 Flag Breakdown

|**Flag**|**Description**|
|---|---|
|`-u`|**Target URL**: The `FUZZ` keyword is the injection point where words from the list are placed.|
|`-w`|**Wordlist**: Path to your directory discovery list (e.g., `common.txt` or `directory-list-2.3-medium.txt`).|
|`-e`|**Extensions**: Comma-separated list. FFuF will append these to every word in the list.|
|`-c`|**Color**: Enables colorized output (Green for 200, Yellow for 301, Red for 403/500).|

---
### ⚙️ How the Logic Works

When you use the `-e` flag, FFuF creates a "multiplier" effect for every word in your wordlist:

1. **Base Word (Directory Check):** Checks `http://target/admin`
    
2. **Extension 1:** Checks `http://target/admin.php`
    
3. **Extension 2:** Checks `http://target/admin.txt`
    
4. **Extension 3:** Checks `http://target/admin.bak`
    
5. **Extension 4:** Checks `http://target/admin.html`

### 💡 Pro-Tips for Obsidian

- **Backups:** Always include `.bak`, `.old`, and `.save` to find source code leaks.
    
- **Filtering:** If you get too many results, add `-fs <size>` to filter out the "Page Not Found" size.
    
- **Wordlists:** For better results, use `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`.

---
---
# 📑 FFuF Extension Cheatsheet

### 1. Manual Extension List (`-e`)

**Best for:** 3–6 common extensions (quick scans).

Bash

```bash
ffuf -u http://IP/FUZZ -w filenames.txt -e .php,.txt,.bak -c
```

---
### 2. Extension Wordlist (`W1W2`)

**Best for:** Massive extension lists or custom "Deep Dives."


```bash
ffuf -u http://IP/W1W2 -w filenames.txt:W1 -w extensions.txt:W2 -c
```

- **Logic:** A "Cluster Bomb" that pairs every filename in `W1` with every extension in `W2`.
    
- **Note:** Use `W1W2` in the URL (ensure your extension file includes the leading dot).

---
### 📂 Common Kali Wordlist Paths

| **Type**              | **Path**                                                                 |
| --------------------- | ------------------------------------------------------------------------ |
| **General Filenames** | `/usr/share/wordlists/dirb/common.txt`                                   |
| **Heavy Directories** | `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`           |
| **Extensions File**   | `/usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt` |
