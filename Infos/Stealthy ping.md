# Stealth Host Discovery y

Goal: Check if a machine is up (alive) with minimal noise / detection risk.
### Classic ping (ICMP)

```bash
ping -c 2 10.10.10.10
```

- **Noise**: High  
- **Detection**: Very easy (IDS signatures everywhere)  
- **Avoid** in real engagements

### Stealthier: hping3 TCP ACK ping

```bash
sudo hping3 -A -c 2 10.10.10.10
```

- Sends **TCP ACK** to invalid/high port  
- Target replies **RST** if up → host alive  
- **Noise**: Low–Medium  
- **Why stealthy**: Looks like response to existing connection  
- Most firewalls allow outbound ACKs
