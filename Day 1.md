# Day 01 — YARA Syntax & Foundations

---

## The Simplest Rule

```yara
rule dummy {
    condition:
        false
}
```

If condition == `false`, match nothing. This is valid YARA Rule, the condition section is the only required part.

---

## Rule Structure

```yara
rule RuleName {
    strings:
        $var = "something"

    condition:
        $var
}
```

**Example:**

```yara
rule Malware {
    strings:
        $a = "Powershell" nocase ascii wide
        $b = "cmd.exe"

    condition:
        $b
}
```

If the string `"cmd.exe"` exists in the file → match.

---

## String Types

There are three types of strings in YARA:

1. **Hex** — `$var = { 90 90 90 }` (NOP instructions)
2. **Text** — `$a = "cmd.exe"`
3. **Regular Expression** — `$var = /cmd\.exe/`

---

## Hex String Patterns

```yara
{ E2 34 ?? C8 }       // ?? = any byte at position 3
                      // matches: E2 34 66 C8, E2 34 90 C8, etc.

{ A? }                // nibble wildcard — any byte from A0 to AF

{ F4 23 ~00 62 }      // ~00 = any byte EXCEPT 00

{ F4 23 [4-6] 62 B4 } // [4-6] = 4 to 6 bytes at that position
                      // matches: F4 23 11 22 33 44 62 B4, etc.

{ FE 39 [6] 89 }      // exactly 6 bytes — same as [6-6] or ?? ?? ?? ?? ?? ??

{ FE 39 [10-] 89 }    // at least 10 bytes, no limits

{ E2 34 (62 B4 | 90) C8 }  // alternatives — matches E2 34 90 C8
                            //                or     E2 34 62 B4 C8

                            
```

---

## Text String Modifiers

| Modifier   | What it does                                                                                                                                                   |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nocase`   | Case-insensitive — matches `Powershell`, `POWERSHELL`, `powershell`                                                                                            |
| `ascii`    | ASCII encoding (default, no need to write unless combining with `wide`)                                                                                        |
| `wide`     | UTF-16LE encoding — null byte between each character. Most Windows API strings are wide. **Always use `wide ascii` together unless you have a reason not to.** |
| `xor`      | Tries all 256 single-byte XOR keys automatically. Catches obfuscated strings.                                                                                  |
| `fullword` | Matches the string only when surrounded by non-alphanumeric characters. `"cmd"` fullword matches `cmd.exe` but not `cmdline`.                                  |
| `base64`   | Searches for base64-encoded versions of the string                                                                                                             |

---

## Regular Expressions

```yara
$a = /cmd\.exe/           // matches "cmd.exe" literally (dot escaped)
$b = /\w+/                // one or more word characters [a-zA-Z0-9_]
$c = /\s/                 // whitespace character
$d = /https?:\/\/\S+/     // URL pattern
```

---

## Condition Section

```yara
strings:
    $a = "powershell" nocase wide ascii
    $b = "cmd.exe"

condition:
    $a and $b    // both must exist
    // $a or $b  // either one is enough
```

---

## Counting & Offsets

```yara
// String count — how many times did $a appear?
#a > 5      // match only if $a appears more than 5 times
#a == 1     // match only if $a appears exactly once

// String offset — where did $a appear?
@a          // offset of the first occurrence
@a[1]       // same as above (1-indexed)
@a[2]       // offset of the second occurrence
```

> **Quick reference:**
> 
> - `$` → the string itself
> - `#` → count of occurrences
> - `@` → offset of occurrence

---

## The `of` Operator

The most important condition construct for behavioral rules. Instead of requiring every string, require N of M.

```yara
2 of ($a, $b, $c)          // any 2 of these 3
any of ($browser_path*)    // any string whose identifier starts with $browser_path
all of ($mutex*)           // all mutex strings must be present
3 of them                  // any 3 strings from the entire rule
```

---

## `for..of` — Conditions on String Occurrences

**Every occurrence of `$config_marker` must be within the first 1KB:**

```yara
for all i in (1..#config_marker) : ( @config_marker[i] < 1024 )
```

**Explaining the syntax:** 
	→ **#config_marker** may be located at offsets 100, 500, 900, so It appeared 3 times.
	so It's like `for i in [1, 2, 3]`.
    → @config_marker[i] < 1024 means offset of the `i` occurrence is within the range 1024
    → @config_marker[1] = 100, @config_marker[2] = 500, and so on..
    → all means that every iteration must be true, so the rule passes, otherwise It doesn't.


**Any occurrence of `$shellcode` must be at the entry point:**

```yara
for any of ($shellcode*) : ( $ at pe.entry_point )
```
**Same rule** → any of ($browser_path*)    // any string whose identifier starts with $browser_path

---

## Iterating Over PE Sections

**Detect a packed `.text` section:**

```yara
for any section in pe.sections : (
    section.name == ".text" and
    math.entropy(section.raw_data_offset, section.raw_data_size) > 7.0
)
```

---

## Offset Operators

```yara
$a at 0           // $a must be at byte offset 0, useful for MZ header check
$a in (0..512)    // $a anywhere within the first 512 bytes
@a[1]             // offset of the first occurrence of $a
@a[2]             // offset of the second occurrence
```

---

## File Size

```yara
filesize < 500KB    // ignore large files
filesize > 10KB     // ignore empty stubs
```

Almost every real rule should bound filesize. Cuts false positives significantly.

---

## Real Example — UPX Packer Detection

```yara
strings:
    $upx_stub = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 }

condition:
    $upx_stub at pe.entry_point
```

Matches the UPX stub only if it sits exactly at the PE entry point — not just anywhere in the file.

---

## Project Rule Template

Every rule in the arsenal follows this structure:

```yara
// 1. Gate on file type and size first
pe.is_pe and filesize < 2MB

// 2. Define strings with proper modifiers
$reg_persist = "CurrentVersion\\Run" wide ascii
$smtp_verb   = "EHLO" ascii fullword
$mutex       = "SomeFamilyMutex_" wide ascii nocase

// 3. Require N of M — never all-or-nothing
2 of ($reg_persist, $smtp_verb, $mutex)

// 4. Layer PE import conditions
pe.imports("wininet.dll", "InternetConnectA") and 2 of ($stealer*)

// 5. Add entropy for packed/obfuscated families
for any section in pe.sections : (
    math.entropy(section.raw_data_offset, section.raw_data_size) > 7.2
)
```

---

## Full Rule Example

```yara
import "pe"
import "math"

rule Credential_Stealer_Generic {
    meta:
        description = "Generic credential stealer — browser paths + crypto APIs"
        author      = "Nader"
        date        = "2025-06-13"
        confidence  = "Medium"

    strings:
        // Browser credential stores
        $chrome  = "\\Google\\Chrome\\User Data\\Default\\Login Data" wide ascii
        $firefox = "\\Mozilla\\Firefox\\profiles.ini" wide ascii
        $edge    = "\\Microsoft\\Edge\\User Data\\Default\\Login Data" wide ascii

        // Crypto/credential APIs
        $crypt1  = "CryptUnprotectData" ascii
        $crypt2  = "NCryptOpenKey" ascii

        // Network exfiltration
        $smtp      = "smtp" nocase ascii
        $http_post = "Content-Type: application/x-www-form-urlencoded" ascii

    condition:
        pe.is_pe and
        filesize < 3MB and
        (
            // 2+ browser paths + a crypto API = strong signal
            (2 of ($chrome, $firefox, $edge) and 1 of ($crypt1, $crypt2)) or
            // OR browser path + exfil method
            (1 of ($chrome, $firefox, $edge) and 1 of ($smtp, $http_post) and $crypt1)
        )
}
```

