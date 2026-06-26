# Day 3 — yara-python, pefile, and the Scanner

---

## Part 1 — yara-python Basics

### Compiling Rules

```python
import yara

# Compile a single rule file
rules = yara.compile(filepath = "rules\process_injection.yar")

# compile  multiple files at once
rules = yara.compile(filepaths={
	"injection" : "rules\process_injection.yar", 
    "entropy" : "rules\check_packed_sample.yar",
    "Dotnet" : "rules\check_Dot_Net.yar"
})

# Scanning a rule of bunch of rules on an exe
matches = rules.match("classic_injection.exe")
print(matches) # >> If succeeded, u will get the rule name, It did work
```

---

### What You Can Read From a Match

For a YARA rule, you can read several fields from a match object: `rule`, `tags`, `meta`, `strings`, and more.

**Example rule with all fields populated:**

`process_injection.yar`

```yara
import "pe"

rule Classic_Process_Injection : injection process_memory mitre_t1055 {
    meta:
        description = "PE importing the classic Win32 process injection API triad"

    strings:
        $alloc  = "VirtualAllocEx"    ascii
        $write  = "WriteProcessMemory" ascii
        $thread = "CreateRemoteThread" ascii

    condition:
        pe.is_pe and
        filesize < 5MB and
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        pe.imports("kernel32.dll", "CreateRemoteThread")
}
```

**Python scanner:**

```python
import yara

rules   = yara.compile(filepath="process_injection.yar")
matches = rules.match("classic_injection.exe")

print(matches)
```

**Reading match fields:**

```python
for match in matches
	print(match.rule)  # rule name >> Classic_Process_Injection
	print(match.tags)  # This comes from >> injection process_memory mitre_t1055
	print(match.meta)
	print(match.strings)
	
# You can even go after the string identifiers
for match in matches:
	for string_match in match.strings:
		print(string_match.identifier)
	# In our case >> $alloc, $write, $thread
```

---

### String Instances — Offsets

There is an important feature in string matches called `instances` — it tells you exactly where in the file each string matched.

**Example:** if `VirtualAllocEx` appears 3 times at different offsets, then `#api == 3` (count), and `string_match.instances` will give you each offset individually.

**Small rule:**

```yara
rule Test {
    strings:
        $api = "VirtualAllocEx"

    condition:
        $api
}
```

**Python to read instances:**

```python
import yara

rules = yara.compile("find_crt.yar")
matches = rules.match("classic_injection.exe")

for match in matches:
    print("Rule:", match.rule)

    for string_match in match.strings:
        print("Identifier:", string_match.identifier)

        for instance in string_match.instances:
            print("Offset:", instance.offset)
            print("Value :", instance.plaintext())
```

**Rule used:**

```yara
rule Find_CreateRemoteThread {
    strings:
        $crt = "CreateRemoteThread" ascii

    condition:
        $crt
}
```

**Output:**

```
(yara-env) nader@DESKTOP-8NQ91D8:/mnt/c/users/options/Desktop/YARA Rules$ python3 compiler.py
Rule: Find_CreateRemoteThread
Identifier: $crt
Offset: 10775
Value : b'CreateRemoteThread'
Offset: 11204
Value : b'CreateRemoteThread'
Offset: 16224
Value : b'CreateRemoteThread'
Offset: 57250
Value : b'CreateRemoteThread'
Offset: 59703
Value : b'CreateRemoteThread'
```

`CreateRemoteThread` appeared 5 times across the binary — at different offsets. The import table, debug info, and string table all reference it separately.

---

### Timeout and Error Handling

A match can fail for several reasons — huge file, corrupted binary, or an internal YARA crash. Always add a timeout and wrap in a try/except so the scanner doesn't crash mid-run.

```python
try:
    matches = rules.match("samples/suspicious.exe", timeout=30)
except yara.TimeoutError:
    print("[!] Scan timed out — skipping")
except yara.Error as e:
    print("[!] YARA error:", e)
```

---

## Part 2 — pefile Basics

### Dealing with a File

```python
pe = pefile.PE("samples\classic_injection.exe")

# or the traditional way:)
with pefile.PE("samples\classic_injection.exe") as pe:
# Scousers don't get knocked out
pass

# Closing a file
pe.close()
```

---

### Extracting Imports

```python
pe = pefile.PE("samples/classic_injection.exe", fast_load=True)

# Tell pefile to parse the import table
pe.parse_data_directories(
    directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
)

# For each imported DLL, print its name and each imported function
if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode(errors="replace")
        print(f"DLL: {dll}")
        for imp in entry.imports:
            # Get by name, or fall back to ordinal number
            name = imp.name.decode(errors="replace") if imp.name else f"ord_{imp.ordinal}"
            print(f"  {name}")
```

---

### Import Hash

`The imphash is a fingerprint of the import table. Samples from the same builder or compiler usually share the same imphash even if the binary is slightly modified. Useful for clustering related samples.`

```python
imphash = pe.get_imphash()
print("Imphash:", imphash)
```

---

### Section Entropy

```python
for section in pe.sections:
    name    = section.Name.decode(errors="replace").strip("\x00")
    entropy = section.get_entropy()
    size    = section.SizeOfRawData
    print(f"Section: {name:10} | Entropy: {entropy:.4f} | Size: {size}")
```

This looked interesting, so I ran it against both `classic_injection.exe` and `classic_packed.exe` to see the difference in real numbers:

```python
import pefile

for filename in ["classic_injection.exe", "classic_packed.exe"]:

    print(f"\n{'='*60}")
    print(f"FILE: {filename}")
    print(f"{'='*60}")

    pe = pefile.PE(filename)

    for section in pe.sections:
        name    = section.Name.decode(errors="replace").strip("\x00")
        entropy = section.get_entropy()
        size    = section.SizeOfRawData
        print(f"Section: {name:10} | Entropy: {entropy:.4f} | Size: {size}")
```

**Output:**

```
(yara-env) nader@DESKTOP-8NQ91D8:/mnt/c/users/options/Desktop/YARA Rules$ python3 py_entropy.py

============================================================
FILE: classic_injection.exe
============================================================
Section: .text      | Entropy: 5.7333 | Size: 8192
Section: .data      | Entropy: 3.9700 | Size: 1024
Section: .rdata     | Entropy: 3.9131 | Size: 2560
Section: .pdata     | Entropy: 2.6702 | Size: 1024
Section: .xdata     | Entropy: 3.5488 | Size: 512
Section: .bss       | Entropy: 0.0000 | Size: 0
Section: .idata     | Entropy: 3.9986 | Size: 3072
Section: .tls       | Entropy: 0.0000 | Size: 512
Section: .reloc     | Entropy: 1.6804 | Size: 512
Section: /4         | Entropy: 0.2365 | Size: 512
Section: /19        | Entropy: 5.2712 | Size: 4608
Section: /31        | Entropy: 2.2107 | Size: 512
Section: /45        | Entropy: 1.4524 | Size: 512
Section: /57        | Entropy: 0.7070 | Size: 512
Section: /70        | Entropy: 1.6604 | Size: 512
Section: /81        | Entropy: 3.6296 | Size: 512

============================================================
FILE: classic_packed.exe
============================================================
Section: UPX0       | Entropy: 0.0000 | Size: 0
Section: UPX1       | Entropy: 7.7465 | Size: 10752
Section: UPX2       | Entropy: 3.6165 | Size: 1024
```

Unpacked binary — `.text` at 5.73, everything else low and normal. Packed binary — `UPX1` at 7.74, everything compressed into essentially two sections. The section names alone (`UPX0`, `UPX1`) already give it away before you even look at entropy.

---

## Part 3 — The Scanner

Scans a directory of samples against a directory of rules, then outputs a structured CSV report. This will be expanded as the project progresses — every rule written from Day 4 onward gets tested through this.

```python
#!/usr/bin/env python3
"""
YARA Arsenal Scanner
Author: Artful Dodger
Scans a samples directory against all rules and outputs a CSV report.

Usage:
    python yara_scanner.py <samples_dir> <rules_dir> <output.csv>

Example:
    python yara_scanner.py samples/ rules/ report.csv
"""

import yara
import pefile
import hashlib
import csv
import os
import sys
from pathlib import Path
from datetime import datetime

def sha256_of_file(filepath):
    # Compute SHA256 hash of a file.
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def get_pe_metadata(filepath):
    """
    Extract PE metadata using pefile.
    Returns a dict. Returns safe defaults if the file is not a valid PE.
    """
    try:
        pe = pefile.PE(str(filepath), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )

        # Import hash
        imphash = pe.get_imphash() if hasattr(pe, "get_imphash") else "N/A"

        # First 10 imports as a readable string
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="replace")
                for imp in entry.imports:
                    name = (imp.name.decode(errors="replace")
                            if imp.name else f"ord_{imp.ordinal}")
                    imports.append(f"{dll}!{name}")

        # Per-section entropy
        sections = []
        for s in pe.sections:
            name    = s.Name.decode(errors="replace").strip("\x00")
            entropy = s.get_entropy()
            sections.append(f"{name}:{entropy:.2f}")

        pe.close()
        return {
            "imphash"          : imphash,
            "imports_sample"   : " | ".join(imports[:10]),
            "sections_entropy" : " | ".join(sections),
        }

    except Exception:
        return {
            "imphash"          : "N/A",
            "imports_sample"   : "N/A",
            "sections_entropy" : "N/A",
        }


def load_rules(rules_dir):
    """
    Compile all .yar files in rules_dir into a single ruleset.
    Each file gets its own namespace (stem of the filename).
    """
    rule_files = list(Path(rules_dir).glob("*.yar"))

    if not rule_files:
        print(f"[!] No .yar files found in: {rules_dir}")
        sys.exit(1)

    filepaths = {f.stem: str(f) for f in rule_files}

    try:
        rules = yara.compile(filepaths=filepaths)
    except yara.SyntaxError as e:
        print(f"[!] YARA syntax error in one of your rules:\n{e}")
        sys.exit(1)

    print(f"[+] Loaded {len(rule_files)} rule file(s) from: {rules_dir}")
    return rules


# Scanning 

def scan_samples(samples_dir, rules, output_csv):
    """
    Scan every file in samples_dir against all loaded rules.
    Write results to output_csv.
    """
    samples_path = Path(samples_dir)
    sample_files = [f for f in samples_path.iterdir() if f.is_file()]

    if not sample_files:
        print(f"[!] No files found in: {samples_dir}")
        sys.exit(1)

    print(f"[+] Scanning {len(sample_files)} sample(s)...")

    rows = []

    for sample in sample_files:
        sha256  = sha256_of_file(sample)
        pe_meta = get_pe_metadata(sample)

        # Run the rules
        try:
            matches = rules.match(str(sample), timeout=30)
        except yara.TimeoutError:
            print(f"[!] Timeout — skipping: {sample.name}")
            matches = []
        except Exception as e:
            print(f"[!] Error scanning {sample.name}: {e}")
            matches = []

        if matches:
            for match in matches:
                # Extract matched string snippets (first 40 chars each)
                matched_strings = " | ".join(
                    f"{s.identifier}:{s.instances[0].plaintext()[:40]}"
                    for s in match.strings
                    if s.instances
                ) if match.strings else ""

                rows.append({
                    "Filename"         : sample.name,
                    "SHA256"           : sha256,
                    "Matched_Rule"     : match.rule,
                    "Malware_Family"   : match.meta.get("malware_family",
                     "Unknown"),
                    "Matched_Strings"  : matched_strings,
                    "PE_Imphash"       : pe_meta["imphash"],
                    "Imports_Sample"   : pe_meta["imports_sample"],
                    "Sections_Entropy" : pe_meta["sections_entropy"],
                    "Scan_Time"        : datetime.now().isoformat(),
                })
        else:
            rows.append({
                "Filename"         : sample.name,
                "SHA256"           : sha256,
                "Matched_Rule"     : "NO_MATCH",
                "Malware_Family"   : "",
                "Matched_Strings"  : "",
                "PE_Imphash"       : pe_meta["imphash"],
                "Imports_Sample"   : pe_meta["imports_sample"],
                "Sections_Entropy" : pe_meta["sections_entropy"],
                "Scan_Time"        : datetime.now().isoformat(),
            })

    # Write CSV 
    fieldnames = [
        "Filename", "SHA256", "Matched_Rule", "Malware_Family",
        "Matched_Strings", "PE_Imphash", "Imports_Sample",
        "Sections_Entropy", "Scan_Time",
    ]

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    matched = sum(1 for r in rows if r["Matched_Rule"] != "NO_MATCH")
    total   = len(sample_files)

    print(f"[+] Scan complete — {matched}/{total} sample(s) matched.")
    print(f"[+] Report saved to: {output_csv}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python yara_scanner.py <samples_dir> <rules_dir> <output.csv>")
        print("Example: python yara_scanner.py samples/ rules/ report.csv")
        sys.exit(1)

    samples_dir = sys.argv[1]
    rules_dir   = sys.argv[2]
    output_csv  = sys.argv[3]

    if not os.path.isdir(samples_dir):
        print(f"[!] samples_dir not found: {samples_dir}")
        sys.exit(1)

    if not os.path.isdir(rules_dir):
        print(f"[!] rules_dir not found: {rules_dir}")
        sys.exit(1)

    rules = load_rules(rules_dir)
    scan_samples(samples_dir, rules, output_csv)
```

---

### First Run

```bash
(yara-env) nader@DESKTOP-8NQ91D8:.../Actual YARA Project$ python3 yara_scanner.py Samples/ Rules/ report.csv
[+] Loaded 4 rule file(s) from: Rules/
[+] Scanning 2 sample(s)...
[+] Scan complete — 4/2 sample(s) matched.
[+] Report saved to: report.csv
```

`4/2` means 2 samples each matched 2 rules — so 4 total match events across 2 files. The scanner counts match events, not unique files. Working as expected.
