#### For Hydra bruteforce check :  [[Hydra bruteforce]]

---
---
When you type `mysql` at the end of a Hydra command, Hydra isn't looking for a "file path" or an "app" on the target server's hard drive. Instead, it is selecting a specific **internal code module** inside Hydra itself.

Here is how that "knowledge" works:

### 1. The Protocol Module

Hydra is built with dozens of "modules" (small pieces of code). When you specify `mysql`, Hydra loads the `libhydra_mysql.so` (or similar) library. This library contains the exact "language" or **handshake** that MySQL speaks.

It doesn't need to know where MySQL is installed because it communicates over the network via **Port 3306** (the default). It acts just like a regular MySQL client, trying to complete a login handshake over and over again.

### 2. The Default Port Logic

Every service has a default port assigned by IANA. Hydra has these hard-coded into its modules:

- If you say `ssh`, Hydra targets port **22**.
    
- If you say `ftp`, Hydra targets port **21**.
    
- If you say `mysql`, Hydra targets port **3306**.
    

If the target admin moved MySQL to a weird port like **8888**, Hydra wouldn't know by itself. You would have to tell it manually using the `-s` flag: `hydra -l root -P pass.txt 10.10.10.15 -s 8888 mysql`

---

### 3. How it "Talks" to the App

Hydra doesn't just send random text; it follows the **MySQL Authentication Protocol**:

1. **Greeting:** Hydra connects to the IP/Port. The server sends back a "Greeting" packet (which often includes the MySQL version).
    
2. **Login Attempt:** Hydra sends a packet containing the username and a scrambled version of the password from your wordlist.
    
3. **The Verdict:** * If the server sends back an `OK` packet, Hydra stops and shouts **"Password Found!"**
    
    - If the server sends an `Error 1045` (Access Denied), Hydra moves to the next password in your list.