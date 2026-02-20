# 🛠️ Tool Selection: Brute Force

### 🟢 Use HYDRA when:

- Target is **Linux** or standalone services.
- Attacking **SSH, FTP, HTTP-POST-Form, Telnet**.
- **Command:** `hydra -L users.txt -P rockyou.txt <IP> ssh`
>**-p** : single string
>
  **-P** password list

### 🔵 Use KERBRUTE when:

- Target is **Active Directory (Windows)**.
- Attacking **Port 88 (Kerberos)**.
- **Why?** It's faster and stealthier for AD user enumeration.
- **Command:** `./kerbrute userenum -d domain.local users.txt --dc <DC_IP>`