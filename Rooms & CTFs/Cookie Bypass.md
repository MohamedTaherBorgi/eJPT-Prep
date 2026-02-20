# 🔓 Authentication Bypass: Client-Side Logic Flaw

### 📂 Vulnerability Analysis

The vulnerability exists in `login.js` due to insecure handling of the server's response. The code uses an "exclusive" check for failure rather than an "inclusive" check for success.

#### **Vulnerable Code Snippet:**

```javascript
const statusOrCookie = await response.text()
if (statusOrCookie === "Incorrect credentials") {
    loginStatus.textContent = "Incorrect Credentials"
    passwordBox.value=""
} else {
    // THE FLAW: If the response is ANYTHING else, it logs you in.
    Cookies.set("SessionToken", statusOrCookie)
    window.location = "/admin"
}
````

### 🕵️ Step-by-Step Explanation

1. **Input Collection**: The script grabs values from the `#username` and `#password` HTML fields.
    
2. **Request**: it sends these credentials to the `/api/login` endpoint via a POST request.
    
3. **The Flaw**: Instead of checking if the server sent a _valid_ token, the script only checks if the response is **exactly** the string `"Incorrect credentials"`.
    
4. **The Bypass**: If the server returns an empty string, a `404`, or a custom message, the script skips the error and moves to the `else` block.
    
5. **Execution**: The script then sets a cookie named `SessionToken` using whatever the server sent back and redirects the user to `/admin`.

---
### 🛠️ Exploit (Console Injection)

Since the client-side code handles the redirect and cookie setting, we can bypass the login form by manually executing these actions in the browser console (**F12 > Console**):

``` js
// 1. Manually set the cookie that the app expects
Cookies.set("SessionToken", "HackerMode");

// 2. Redirect to the protected page
window.location = "/admin";
```

> [!IMPORTANT]
> 
> This works because the `/admin` page likely only checks if the `SessionToken` cookie **exists**; it doesn't actually validate the "HackerMode" string against a database.

