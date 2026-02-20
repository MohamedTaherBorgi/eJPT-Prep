```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,9F85D92F34F42626F13A7493AB48F337

LNu5wQBBz7pKZ3cc4TWlxIUuD/opJi1DVpPa06pwiHHhe8Zjw3/v+xnmtS3O+qiN
JHnLS8oUVR6Smosw4pqLGcP3AwKvrzDWtw2ycO7mNdNszwLp3uto7ENdTIbzvJal
-----END RSA PRIVATE KEY-----
```
### 🔍 Anatomy of the Key

1. **`-----BEGIN RSA PRIVATE KEY-----`**: This is the "Header." It tells the system that the text following it is a private key using the RSA algorithm.
    
2. **`Proc-Type: 4,ENCRYPTED`**: This is the most important part for you right now. It confirms that this key **has a passphrase**. You cannot use it until it is decrypted.
    
3. **`DEK-Info: AES-128-CBC,...`**: This tells the computer that the key was encrypted using the **AES-128** algorithm. The long string of numbers after it is the "salt" used to help scramble the data.
    
4. **The Big Block of Text**: This is the actual key, but it is currently "wrapped" in encryption.

---
In the Linux world, **extensions don't really matter**, but conventions do. SSH doesn't care if the file is named `id_rsa`, `key.txt`, or `banana.jpg`—it only cares about the **content** inside the file.

However, to keep your Obsidian notes organized, here is the standard way to handle it.

---
---
### 1. The "Extension"

- **Standard Name:** `id_rsa` (No extension). This is the default name Linux looks for.
    
- **Common Alternative:** `james.key` or `james.private`.
    
- **Important:** Just ensure it is a **plain text file**.

---
### 2. How to use the key (Step-by-Step)

If you have already cracked the passphrase with `john`, follow these steps to actually log in:

#### **Step A: Set Permissions (Crucial)**

SSH will refuse to use a key if it is "too open" (meaning other users on your computer could read it). You must lock it down to just yourself.

Bash

```
chmod 600 id_rsa
```

#### **Step B: Run the SSH Command**

Use the `-i` (identity) flag to point to your key file.

Bash

```
ssh -i id_rsa james@10.112.156.214
```

#### **Step C: Enter the Passphrase**

When you run that command, the terminal will prompt you: `Enter passphrase for key 'id_rsa':` Type the password that **John the Ripper** found for you.

### `ssh2john` (The "Locked" Key)

If  the terminal says: `Enter passphrase for key 'id_rsa':`, it means the key is encrypted. Since you don't know the passphrase, you have to crack it.

### **The Workflow:**

1. **Convert:** You can't give a raw key to a cracker. `ssh2john` extracts the "scrambled" part of the key and puts it into a format that John the Ripper understands.
``` bash
ssh2john id_rsa > key_hash.txt
```

2. **Crack:** Now you use John to compare that hash against `rockyou.txt`.
``` bash
john --wordlist=/usr/share/wordlists/rockyou.txt key_hash.txt
```

