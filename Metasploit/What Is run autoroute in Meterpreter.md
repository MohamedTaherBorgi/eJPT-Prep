## ✅ Yes — It’s for Pivoting

`run autoroute` is a **built-in Meterpreter post module** that automatically adds a **routing entry** to Metasploit’s routing table, allowing you to **pivot through a compromised host** to reach other systems on its internal networks.

---
### When to use ONLY `autoroute` (The "Inside" Tools)

You use **just** `autoroute` when the tool you want to use is a **Metasploit module** (anything you access via the `use` command).

- **When:** You want to run a port scanner (`auxiliary/scanner/portscan/tcp`), an SMB scanner, or a login brute-forcer that is built into Metasploit.
    
- **Why:** Metasploit is "smart." Once `autoroute` is set, every module you run automatically checks that internal routing table and sends its traffic through the Meterpreter session.
    
- **Verdict:** **No Proxy needed.**

---
### When to use a Proxy + `autoroute` (The "Outside" Tools)

You use a **SOCKS Proxy** (and a tool like `proxychains`) when the tool you want to use is a **standalone Linux program** that exists outside of Metasploit.

- **When:** You want to use `nmap`, `dirb`, `smbclient`, `impacket`, or even a web browser (Firefox) to look at an internal website.
    
- **Why:** `nmap` has no idea what happens inside your Metasploit terminal. It tries to send packets out of your real network card (eth0), fails to find the private 10.x.x.x network, and gives up.
    
- **Verdict:** **Proxy REQUIRED.** You set up the proxy in Metasploit, then tell your Linux OS to "pipe" your external tools through that proxy.
---
## 🧠 How It Works

When you compromise a machine (e.g., `192.168.1.10`) that has access to another network (e.g., `10.10.10.0/24`), you can use `autoroute` to:
- Add a route from your Kali box → through the Meterpreter session → to the internal subnet
- Scan, exploit, or connect to hosts **behind the compromised host**

### Example:
```msf
meterpreter > run autoroute -s 10.10.10.0/24
[*] Adding route to 10.10.10.0/255.255.255.0...
```

Now Metasploit can reach `10.10.10.5`, `10.10.10.20`, etc., **as if they were local**.

---
## 🔍 Why Use It?

- **No manual SSH tunnels**
- **Seamless integration** with all Metasploit modules (`nmap`, `exploit`, `auxiliary`)
- **Multiple hops**: Chain routes through several compromised hosts

> 💡 Under the hood: Metasploit uses the Meterpreter session as a **SOCKS-like proxy**

---
## 🛠️ Common Workflow

1. Get Meterpreter on pivot host (`192.168.1.10`)
2. Discover internal subnets (e.g., `ipconfig`, `arp -a`)
3. Add route:
   ```msf
   run autoroute -s 10.10.10.0/24
   ```
4. Scan internal network:
   ```msf
   use auxiliary/scanner/portscan/tcp
   set RHOSTS 10.10.10.0/24
   set PORTS 22,80,445
   run
   ```
5. Exploit internal hosts directly from MSF

---
## ⚠️ Important Notes

- **Only works with Meterpreter** (not raw shells)
- Routes are **session-bound** — lost if session dies
- For **non-Metasploit tools** (e.g., `nmap`, `curl`), use **`socks4a` proxy**:
  ```msf
  use auxiliary/server/socks_proxy
  set SRVPORT 1080
  run
  ```
  Then configure `proxychains` on Kali:
  ```bash
  proxychains nmap -sT -Pn 10.10.10.5
  ```

---
## 🔒 Detection

- Creates **forwarded TCP connections** from victim → internal targets
- May trigger EDR/network alerts if scanning aggressively

> 🔥 **Golden Rule**:  
> **`autoroute` = your tunnel into the internal network.**  
> Always run it after compromising a multi-homed host.

