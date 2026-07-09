# File Signature (Magic Number) Checker

A Python tool that detects a file's **true type** by reading its binary signature ("magic bytes") and compares it against the file's extension. This is a real digital forensics technique used to catch disguised or malicious files — for example, an executable renamed to look like a harmless `.jpg`.

## Why This Matters

File extensions can be changed freely and don't reflect what a file actually is. Forensic investigators and security analysts instead check the file's **header bytes**, which are much harder to fake. This tool automates that check.

## Features

- Reads the first bytes of any file and matches them against known file signatures
- Detects common formats: PNG, JPEG, GIF, PDF, ZIP/DOCX/XLSX, EXE, ELF, RAR, GZIP, BMP
- Flags a **mismatch** if the extension doesn't match the actual file content
- Simple command-line interface — no external dependencies required

## Tech Stack

- **Language:** Python 3 (standard library only — no pip installs needed)

## Usage

Run the script:
```bash
python file_signature_checker.py
```

Enter the path of the file you want to check:
```
Enter the full path of the file to check: C:\Users\dhine\Downloads\suspicious.jpg
```

### Example Output — Match
```
File: photo.jpg
Extension found: .jpg
Detected type: JPEG Image
Status: OK — extension matches actual file type
```

### Example Output — Mismatch (Suspicious File)
```
File: suspicious.jpg
Extension found: .jpg
Detected type: Windows Executable
Status: MISMATCH DETECTED!
  -> File claims to be '.jpg' but is actually a Windows Executable
  -> This could indicate a disguised or malicious file
```

## How It Works

1. Opens the file in binary mode and reads the first 16 bytes
2. Compares those bytes against a dictionary of known "magic number" signatures
3. Looks up the file's actual extension
4. Compares the two and reports a match, mismatch, or unknown result

## Future Improvements

- Expand the signature database to cover more file types
- Add batch scanning of an entire folder
- Export results to a CSV/PDF forensic report
- Add a hash (MD5/SHA256) calculation alongside the signature check
- Build a simple GUI or web interface

## Author

**Sanjeev**
B.Sc. Digital and Cyber Forensic Science, Rathinam Global University

## License

This project is open source and available under the [MIT License](LICENSE).
