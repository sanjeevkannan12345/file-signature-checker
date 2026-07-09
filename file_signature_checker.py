"""
File Signature (Magic Number) Checker
---------------------------------------
Detects a file's TRUE type by reading its binary signature (magic bytes)
and compares it against the file's extension. Useful in digital forensics
to catch disguised files (e.g. a .exe renamed to .jpg).

Author: Sanjeev
"""

import os

# Dictionary of known file signatures (magic numbers)
# Format: file type -> (hex signature, typical extensions)
FILE_SIGNATURES = {
    "PNG Image":        (b"\x89PNG\r\n\x1a\n", [".png"]),
    "JPEG Image":        (b"\xFF\xD8\xFF", [".jpg", ".jpeg"]),
    "GIF Image":          (b"GIF8", [".gif"]),
    "PDF Document":       (b"%PDF-", [".pdf"]),
    "ZIP Archive":        (b"PK\x03\x04", [".zip", ".docx", ".xlsx", ".pptx"]),
    "Windows Executable": (b"MZ", [".exe", ".dll"]),
    "ELF Executable":     (b"\x7fELF", [".elf", ".bin", ".out"]),
    "RAR Archive":        (b"Rar!\x1a\x07", [".rar"]),
    "GZIP Archive":       (b"\x1f\x8b", [".gz"]),
    "BMP Image":          (b"BM", [".bmp"]),
}


def detect_file_type(file_path):
    """Read the file's header bytes and match against known signatures."""
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)  # read first 16 bytes, enough for all signatures above
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        return None
    except PermissionError:
        print(f"[ERROR] Permission denied: {file_path}")
        return None

    for file_type, (signature, extensions) in FILE_SIGNATURES.items():
        if header.startswith(signature):
            return file_type, extensions

    return None, None


def check_file(file_path):
    """Compare detected file type against the file's actual extension."""
    if not os.path.isfile(file_path):
        print(f"[ERROR] Not a valid file: {file_path}")
        return

    actual_ext = os.path.splitext(file_path)[1].lower()
    detected_type, expected_exts = detect_file_type(file_path)

    print("-" * 50)
    print(f"File: {file_path}")
    print(f"Extension found: {actual_ext or '(none)'}")

    if detected_type is None:
        print("Detected type: Unknown (signature not in database)")
        print("Status: Could not verify — proceed with caution")
    else:
        print(f"Detected type: {detected_type}")
        if actual_ext in expected_exts:
            print("Status: OK — extension matches actual file type")
        else:
            print("Status: MISMATCH DETECTED!")
            print(f"  -> File claims to be '{actual_ext}' but is actually a {detected_type}")
            print("  -> This could indicate a disguised or malicious file")
    print("-" * 50)


def main():
    print("=== File Signature (Magic Number) Checker ===\n")
    file_path = input("Enter the full path of the file to check: ").strip()

    if not file_path:
        print("[ERROR] No file path entered.")
        return

    check_file(file_path)


if __name__ == "__main__":
    main()
