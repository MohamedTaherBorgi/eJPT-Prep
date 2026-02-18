These three scans are known as **"Stealth"** or **"Inverse"** scans. They are called that because they work backward: they don't look for an **Open** port; they look for how a port reacts to being "poked" with illegal or weird data to prove it is **Closed**.

Think of these as "Social Engineering" for computers—you are trying to trick the server into reacting in a way that gives away its status.

---
### 1. TCP Null Scan (`-sN`) — "The Empty Package"

In a Null scan, you send a TCP packet with **zero flags set**.

- **The Logic:** According to the official rules (RFC 793), if a port is **closed**, it should send an `RST` (Reset) packet back. If the port is **open**, it should just ignore the weird "empty" packet and say nothing.
    
- **Response:**
    
    - **No Response:** Port is likely **Open|Filtered**.
        
    - **RST Packet:** Port is **Closed**.

### 2. TCP FIN Scan (`-sF`) — "The Unprovoked Goodbye"

You send a packet with only the `FIN` flag (used to close a connection).

- **The Logic:** You are basically saying "Goodbye!" to a conversation that never started.
    
- **The Logic:** Like the Null scan, a **closed** port will be annoyed and send an `RST`. An **open** port will ignore it.

### 3. TCP Xmas Scan (`-sX`) — "The Lit Up Tree"

This is called an "Xmas" scan because it sets the `PSH`, `URG`, and `FIN` flags all at once. In a packet sniffer (like Wireshark), it looks like it's "lit up like a Christmas tree."

- **The Logic:** This is a nonsensical combination of flags.
    
- **Response:** Just like the others, **Closed** ports send an `RST`, and **Open** ports stay silent.

---

## 📊 Why use these instead of a normal SYN scan?

### ⚠️ The "Windows" Catch

If you run an Xmas scan against a Windows machine, **every single port** will show up as `Closed`. If you run it against a Linux machine, you will see the actual open ports.

> **Hacker's Trick:** If a normal scan shows ports are open, but an Xmas scan shows everything is closed, you can bet your life the target is a **Windows** machine.

### 💡 When to use them?

Use these when you are in a "Red Team" scenario where there is a firewall or an IDS (Intrusion Detection System) that is blocking your normal `-sS` scans.