# AgentTesla: Static Analysis & Rule Writing

**It's about making a YARA rule for AgentTesla malware.**

**I've analyzed this malware before, you can find the full report [here](https://artfuldodger10.github.io/posts/AgentTesla-RAT-Full-Malware-Analysis-Report/).**

---

## What Is AgentTesla?

AgentTesla is a .NET-based infostealer and keylogger sold as Malware-as-a-Service since 2014. Still one of the most prevalent commodity malware families in phishing campaigns. Core capabilities:

- Credential theft from browsers, email clients, FTP clients, VPNs
- Keylogging via Windows hook APIs
- Screenshot capture
- Exfiltration via SMTP, FTP, or HTTP POST

---

## Basic Static Analysis

### 1. DIE (Detect It Easy)

DIE identified the following characteristics:

| Property          | Value                                                    |
| ----------------- | -------------------------------------------------------- |
| File Type         | PE32, GUI executable                                     |
| Language          | MSIL / C# (.NET Framework 4, CLR v4.0.30319)             |
| Linker            | Microsoft Linker                                         |
| Base Address      | 0x00400000                                               |
| Entry Point       | 0x004AC48A                                               |
| Image Size        | 0x000B4000                                               |
| Sections          | 3 (.text, .rsrc, .reloc)                                 |
| Compile Timestamp | 2024-05-30 22:21:36                                      |
| Protection (Heur) | Obfuscation, Modified Entry Point detected               |
| Packer Heuristic  | Compressed or packed data, High entropy in .text section |
| Overall Entropy   | 7.94174, Packed (99% confidence)                         |

---

### 2. PE Analysis via pefile

```python
import pefile

pe = pefile.PE(r"sample.exe", fast_load=True)
pe.parse_data_directories(
    directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
)

print("=== Basic Info ===")
print("Sections     :", pe.FILE_HEADER.NumberOfSections)
print("Imphash      :", pe.get_imphash())

print("\n=== Imports ===")
if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(" ", entry.dll.decode(errors="replace"))
else:
    print("  No imports found")

print("\n=== Sections ===")
for s in pe.sections:
    name    = s.Name.decode(errors="replace").strip("\x00")
    entropy = s.get_entropy()
    size    = s.SizeOfRawData
    print(f"  {name:12} | entropy: {entropy:.4f} | size: {size}")

pe.close()
```

**Output:**

```
(yara-env) C:\Users\Artful Dodger\Desktop\Yara Arsenal\rules> python basic_info.py
=== Basic Info ===
Sections     : 3
Imphash      : f34d5f2d4577ed6d9ceec516c1f5a744

=== Imports ===
  mscoree.dll

=== Sections ===
  .text        | entropy: 7.9789 | size: 700416
  .rsrc        | entropy: 7.0215 | size: 12288
  .reloc       | entropy: 0.0164 | size: 4096
```

3 sections, one DLL, `.text` section carries the highest entropy by far.

---

### 3. Interesting Strings

```
PY718E785ZXFG4844GPE4Z
mail.albushrametalic.com
saeed9797seead@gmail.com
dnqK.exe
QQ 復複覆
```

---

## Advanced Static Analysis (DnSpy)

### Entry Point

```
// dnqK, Version=1.2.2.0, Culture=neutral, PublicKeyToken=null
// Entry point: QQ復複覆.Program.Main
// Timestamp: 66595E60 (5/30/2024 10:21:36 PM)
```

```csharp
private static void Main() {
    Application.EnableVisualStyles();
    Application.SetCompatibleTextRenderingDefault(false);
    Application.Run(new frmMain());
}
```

No malicious behavior visible at the entry point. The actual loader logic is buried inside `frmMain`. The namespace is `QQ 復複覆`, Chinese Unicode characters, deliberate obfuscation to confuse analysts and automated tooling.

---

### Embedded Resource

Inside `frmMain.InitializeComponent()`:

```csharp
private void InitializeComponent() {
    ComponentResourceManager resources = new ComponentResourceManager(typeof(frmMain));
    this.pictureBox    = new PictureBox();
    this.openFileDialog = new OpenFileDialog();
    this.btnBrowse     = new Button();
    this.lbImageInfo   = new ListBox();
    this.cbFilterSelect = new ComboBox();
    this.gbColorFilters = new GroupBox();
    this.btnApplyFilter = new Button();
    this.btnSave       = new Button();

    byte[] data = (byte[])resources.GetObject("FF");

    for (int i = 0; i < data.Length; i++) {
        byte xorResult = Encoding.Default.GetBytes("PY718E785ZXFG4844GPE4Z")[i % 22];
        int r    = (int)(data[i] ^ xorResult);
        int g    = (int)data[(i + 1) % data.Length];
        int last = r - g + 256 & 255;
        data[i]  = (byte)last;
    }
```

```csharp
byte[] data = (byte[])resources.GetObject("FF");
```

|Field|Value|
|---|---|
|Resource name|`FF`|
|Size|69,121 bytes|
|Location|`.rsrc` section|
|Purpose|Encrypted AgentTesla Stage 2 payload|

---

### Decryption Routine

Two-step transformation applied to every byte of resource `FF`:

```csharp
byte xorResult = Encoding.Default.GetBytes("PY718E785ZXFG4844GPE4Z")[i % 22];
int r    = (int)(data[i] ^ xorResult);
int g    = (int)data[(i + 1) % data.Length];
int last = (r - g + 256) & 255;
data[i]  = (byte)last;
```

- Step 1—> XOR each byte against the 22-character key `PY718E785ZXFG4844GPE4Z`, cycling via modulo 22
- Step 2 —> arithmetic transformation using the next byte, keeping values in 0–255 range
- Key is hardcoded —> confirmed unique AgentTesla family indicator

---

### Payload Execution

```csharp
Assembly Wr_99 = Assembly.Load(data);

Type airo = Wr_99.GetTypes()[1];

typeof(Activator).InvokeMember(
    "CreateInstance",
    BindingFlags.InvokeMethod,
    null,
    null,
    new object[] { airo, this.GetInitializationParameters(frmMain.EIK) }
);
```

- `Assembly.Load(data)` —> executes decrypted payload entirely in memory, nothing written to disk
- `Activator.CreateInstance()` via reflection —> dynamically instantiates Stage 2 class
- `frmMain.EIK` passed as initialization parameter —> likely config or encryption key

---

### C2 Configuration

Extracted from Triage sandbox memory dump:

```
Protocol  : SMTP
Host      : mail.albushrametalic.com
Port      : 587 (TLS/STARTTLS)
Username  : mustafa@albushrametalic.com
Password  : GLBL1285#
To        : saeed9797seead@gmail.com
```

---

## Findings

**1. `PY718E785ZXFG4844GPE4Z`** Hardcoded XOR decryption key sitting in plain C# inside the decryption loop. Unique to this family. Critical, this alone confirms AgentTesla.

**2. `mail.albushrametalic.com`** SMTP C2 host, hardcoded in the extracted config. Original finding, not documented in any prior public report on this campaign. Critical.

**3. `saeed9797seead@gmail.com`** Attacker collection mailbox, also hardcoded in config. Strong, campaign specific.

**4. `Assembly.Load`** Fileless execution string, confirms payload never touches disk. Strong, appears across AgentTesla variants.

**5. `.text` entropy 7.97887** Near-maximum entropy, encrypted payload living inside the assembly at IL level. Strong, hard to fake without breaking the loader.

**6. PE sections = 3** Only `.text`, `.rsrc`, `.reloc`. Clean structural fingerprint of this loader. Strong.

**7. Imported DLLs = 1** Only `mscoree.dll`, everything else resolved at runtime via reflection. Strong.

**8. `dotnet.is_dotnet`** Gate condition, eliminates all non-.NET files instantly. Strong.

**9. Browser credential paths** Chrome, Edge, Firefox paths, Stage 2 infostealer behavior. Strong.

**10. `api.ipify.org`** Anti-sandbox IP check, but also used by legitimate software. Medium, supporting signal only.

**11. `QQ 復複覆` namespace** Chinese Unicode obfuscation. Medium, variant-specific, next build will change it.

**12. Resource name `FF`** Two characters. Weak, never use alone, FP risk is too high.

---

## The Rule

```yara
import "pe"
import "math"
import "dotnet"

rule AgentTesla_Malware {
    meta:
        description    = "Detects AgentTesla .NET RAT"
        author         = "Artful Dodger"
        malware_family = "AgentTesla"
        sample_sha256  = 
        "1ca6c053e788f8ea1e1eec1c712cf0ec5374ba5d8caf432717842c702e3cda0e"
        reference      = "https://artfuldodger10.github.io/posts/AgentTesla-RAT-
        Full-Malware-Analysis-Report/"
        confidence     = "High"
        techniques     = "T1140, T1620, T1071.003, T1555.003, T1056.001"

    strings:

        $xor_key   = "PY718E785ZXFG4844GPE4Z" ascii wide

        $c2_domain = "mail.albushrametalic.com" ascii

        $c2_email  = "saeed9797seead@gmail.com" ascii

        // fileless execution signal
        // Assembly.Load(data) executes decrypted Stage 2 entirely in memory
        // No second file written to disk, bypasses file-based AV
        $asm_load  = "Assembly.Load" ascii


        // Chinese Unicode characters "QQ 復複覆" 

        $ns_obf    = { 51 51 E5 BE A9 E8 A4 87 E8 A6 86 }

        $ipify     = "api.ipify.org" ascii wide

    condition:

        dotnet.is_dotnet and

        filesize < 750KB and

        pe.number_of_sections == 3 and

        pe.number_of_imported_symbols == 1 and

        ( for any section in pe.sections : (
            section.name == ".text" and
            math.entropy(section.raw_data_offset, section.raw_data_size) > 7.5
        )) and

        $xor_key and
        1 of ($asm_load, $c2_domain, $c2_email, $ns_obf, $ipify)
}
```