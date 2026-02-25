# Image Forensics & Steganography – Lab Dismantling Cheat Sheet

Goal: Extract hidden data, flags, credentials, or payloads from images (JPG, PNG, BMP, GIF, etc.)  
Three main layers to attack: **Metadata** → **Appended/Embedded Files** → **Steganography (pixel-level)**

## 1. Metadata Extraction (Quick Win – Often Contains Flags/Comments)
### Gold standard – shows EVERYTHING
```sh
exiftool image.jpg
exiftool -a -G1 -s image.jpg     # verbose, grouped, short tag names
```

### Alternative (lighter, sometimes catches different fields)
```sh
exiv2 pr image.jpg
exiv2 -pt image.jpg               # print tags
```

**Look for**:
- Comment / Description fields
- Artist / Copyright / Software
- GPSPosition / GPS coordinates
- XMP / IPTC / MakerNotes sections

## 2. Strings & Embedded / Appended Data

### Readable ASCII strings (very common for quick flags)
```sh
strings image.jpg
strings -n8 image.jpg             # min length 8 chars
```

### Search for file signatures / embedded archives
```sh
binwalk image.jpg
binwalk -e image.jpg              # extract embedded files (creates _image.jpg.extracted/)
```

## 3. <u>Steganography Extraction (Pixel / LSB / Palette Hiding)</u>
### Steghide (JPEG/PNG/BMP – passphrase protected)
```bash
# Try extract without password (often empty passphrase)
steghide extract -sf image.jpg

# If password required passphrase → brute force
stegseek image.jpg /usr/share/wordlists/rockyou.txt
stegseek --crack image.jpg /usr/share/wordlists/rockyou.txt    # faster mode
```
