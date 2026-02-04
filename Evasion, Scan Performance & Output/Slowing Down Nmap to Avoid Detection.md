## Timing Templates (`-T0` to `-T5`)

| Level | Name       | Speed             | Use Case                         |
| ----- | ---------- | ----------------- | -------------------------------- |
| `-T0` | paranoid   | 🐌 Extremely slow | Evade IDS (1 probe every 5+ min) |
| `-T1` | sneaky     | 🐢 Very slow      | Bypass basic rate limits         |
| `-T2` | polite     | 🚶 Slow           | Reduce bandwidth impact          |
| `-T3` | normal     | ⏱️ Default        | Balanced speed/stealth           |
| `-T4` | aggressive | 🏃 Fast           | Reliable networks                |
| `-T5` | insane     | 🚀 Very fast      | Scan quickly (noisy)             |

> ✅ **`-T1` is often better than manual delays** — it intelligently spaces probes and retries.

---
## Manual Delays

### `--scan-delay 5s`

- Waits **5 seconds between each probe** (not per fragment).
- With `-f`: delay is **between full packet groups**, not individual fragments.
- **Why use?** Throttle scan to avoid triggering rate-based alerts.
- **Downside**: Extremely slow; `-T1` usually more efficient.

### `--host-timeout 5s`

- Abandons a host if no response within **5 seconds**.
- **Why use?** Skip unresponsive/firewalled hosts quickly.
- **⚠️ Danger**: May miss live hosts behind slow filters or high-latency networks.

---
## Best Practices

- Prefer **`-T1` or `-T2`** over manual `--scan-delay` — Nmap handles timing smarter.
- Use `--host-timeout` only on large, noisy scans where false negatives are acceptable.
- Combine with evasion:  

  ```bash
  nmap -T1 -f -g 53 -n -Pn --max-retries 1 192.168.1.0/24
  ```

> 🔒 **Goal**: Look like background noise, not a scanner.

