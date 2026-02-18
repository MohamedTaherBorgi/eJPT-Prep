### 1. TCP Connect Scan (`-sT`) — "The Polite Handshake"

This scan performs the full **TCP Three-Way Handshake**. It completes the entire connection process.

- **The Process:** 1. **You:** "Hey, want to talk?" (SYN) 2. **Server:** "Sure, I'm here!" (SYN/ACK) 3. **You:** "Great, I heard you. Talk soon!" (ACK)
    
- **The Reality:** Because the connection is fully completed, the target server **logs** the connection.
    
- **Best for:** When you don't have "Raw Socket" (root/admin) privileges on your own machine.

### 2. SYN Scan (`-sS`) — "The Ghost / Half-Open Scan"

This is the **default** scan for Nmap (if you have root/sudo access). It is "Half-open" because you hang up before the server can finish the handshake.

- **The Process:**
    
    1. **You:** "Hey, want to talk?" (SYN)
        
    2. **Server:** "Sure, I'm here!" (SYN/ACK)
        
    3. **You:** _Hangs up the phone immediately_ (RST - Reset)
        
- **The Reality:** Since the connection was never "completed," many older or basic systems **won't log it**. It’s faster and stealthier than a Connect scan.
    
- **Best for:** Professional pentesting and speed.

## <u>Disadvantages of SYN Scans</u>

There are, however, a couple of disadvantages to SYN scans, namely:

1. **Require sudo permissions in Linux**  (<u>problematic in pivoting scan</u>)
   SYN scans require the ability to create raw packets (instead of completing the full TCP handshake).  
   This capability is restricted to the root user by default, so `sudo` is required.

2. **Can crash unstable services**  
   Some unstable services may be brought down by SYN scans.  
   This can become problematic, especially if testing is being performed on a production environment provided by a client.


### 3. UDP Scan (`-sU`) — "The Shout into the Void"

UDP is "connectionless." There is no handshake. It’s like throwing a rock at a house to see if someone yells back.

- **The Process:**
    
    1. **You:** "HEY! ARE YOU THERE?" (UDP Packet)
        
    2. **Server:** _Silence._ (This usually means the port is **Open** or filtered).
        
    3. **Server:** "OUCH! NOBODY LIVES HERE!" (ICMP Port Unreachable packet).
        
- **The Reality:** This scan is **extremely slow**. Because the server doesn't have to respond if a port is open, Nmap has to wait and re-send packets to be sure it wasn't just lost in the mail.
    
- **Best for:** Finding hidden services like DNS (53), DHCP, or SNMP.

Unlike TCP, UDP connections are _stateless_. This means that, rather than initiating a connection with a back-and-forth "handshake", UDP connections rely on sending packets to a target port and essentially hoping that they make it. This makes UDP superb for connections which rely on speed over quality (e.g. video sharing), but the lack of acknowledgement makes UDP significantly more difficult (and much slower) to scan. The switch for an Nmap UDP scan is (`-sU`)  

When a packet is sent to an open UDP port, there should be no response. When this happens, Nmap refers to the port as being `open|filtered`. In other words, it suspects that the port is open, but it could be firewalled. If it gets a UDP response (which is very unusual), then the port is marked as _open_. More commonly there is no response, in which case the request is sent a second time as a double-check. If there is still no response then the port is marked _open|filtered_ and Nmap moves on.

When a packet is sent to a _closed_ UDP port, the target should respond with an <u>ICMP</u> (ping) packet containing a message that the port is unreachable. This clearly identifies closed ports, which Nmap marks as such and moves on.