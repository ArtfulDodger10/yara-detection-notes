AsyncRAT: Static Analysis & Rule Writing

**It's about making a YARA rule for AsyncRAT.**

**I've analyzed this malware before, you can find the full report [here](https://artfuldodger10.github.io/posts/AsyncRAT-Analysis/).**

---

## What Is AsyncRAT?

AsyncRAT is an open-source Remote Access Trojan written in C# and originally published on GitHub in 2019 under the guise of a legitimate remote administration tool. The source being public is both its strength and its weakness from a detection standpoint — anyone can grab it, recompile it, and tweak it, which means no two samples are identical. So that’s where the analysis starts.

Core capabilities:

- Remote shell and command execution
- Keylogging and screenshot capture
- File and process management
- Persistence via Run key or Scheduled Task
- Anti-VM and anti-debug techniques
- Encrypted C2 communication over TCP using AES-256

**Key difference from AgentTesla:** AgentTesla had a unique hardcoded XOR key that alone confirmed the family. AsyncRAT has no such gift — detection relies on co-occurring behavioral patterns from the config structure, mutex, crypto artifacts, and anti-analysis strings.

---

## Basic Static Analysis

### 1. DIE (Detect It Easy)

|Property|Value|
|---|---|
|File Type|PE32 — GUI executable|
|Language|MSIL / C# (.NET Framework)|
|Architecture|Intel 386 (32-bit)|
|Sections|3|
|Entry Point|0xD09E|
|Compile Timestamp|2023-10-16 21:40:53 UTC|
|Subsystem|Windows GUI|

**Version info spoofing:** The binary carries metadata impersonating WinRAR 7.5.6.1 — `CompanyName: RarLab`, `FileDescription: WinRar`, `OriginalFileName: WinRar`. A cheap trick, but it works on anyone who doesn't look twice.

---

### 2. PE Analysis via pefile(simple python script from the last time)

```
=== Basic Info ===
Sections  : 3
Imphash   : [f34d5f2d4577ed6d9ceec516c1f5a744]

=== Imports ===
  mscoree.dll

=== Sections ===
  .text        | entropy: [5.6193] | size: [45568]
  .rsrc        | entropy: [6.3038] | size: [6656]
  .reloc       | entropy: [0.0815] | size: [512]
```

Single import — `mscoree.dll` only. Same story as AgentTesla. The entire functionality lives in managed IL code, invisible to traditional import analysis.

---

### 3. Interesting Strings

```
c2.skyupdragon.io.exe
%AppData%
schtasks /create /f /sc onlogon /rl highest
CreateSubKey, OpenSubKey, SetValue, DeleteValue
Select * from AntivirusProduct
\root\SecurityCenter2
VirtualBox
SbieDll.dll
CheckRemoteDebuggerPresent
RtlSetProcessIsCritical
SslStream
AuthenticateAsClient
TcpClient
AesCryptoServiceProvider
Rfc2898DeriveBytes
HMACSHA256
GZipStream
WebClient
savePlugin / sendPlugin / Plugin.Plugin
get_UserName / get_MachineName / get_OSVersion
```

**Notable:**

`c2.skyupdragon.io.exe` — the filename the malware uses when copying itself to disk. Contains an embedded domain reference — `c2.skyupdragon.io` — suggesting secondary C2 infrastructure.

`schtasks /create /f /sc onlogon /rl highest` — scheduled task persistence, executes on every logon at highest privilege. Entire command is hardcoded and visible in strings.

`RtlSetProcessIsCritical` — marks the process as a Windows critical process. If terminated, Windows triggers a BSOD. Confirmed by `BSoD: true` in the extracted config.

`Rfc2898DeriveBytes` + `AesCryptoServiceProvider` + `HMACSHA256` together — PBKDF2 key derivation feeding AES-256-CBC encryption with HMAC integrity verification. Full crypto stack visible in strings before even opening dnSpy.

---

## Basic Dynamic Analysis

### ANY.RUN

**Full report:** https://app.any.run/tasks/2fa8f14b-f2ac-45d4-9b72-18e1f595e383

**Environment:** Windows 10 Professional (build 19044, 64-bit) **Verdict:** Malicious — AsyncRAT confirmed via YARA

|Field|Value|
|---|---|
|PID|3144|
|Path|C:\Users\admin\AppData\Local\Temp[sha256].exe|
|Parent|explorer.exe|
|Integrity Level|MEDIUM|

Flat process tree — no child processes spawned in the sandbox window.

**Behavioral indicators:**

| Severity  | Indicator                         |
| --------- | --------------------------------- |
| Malicious | ASYNCRAT detected via YARA        |
| Info      | Reads machine GUID from registry  |
| Info      | Reads computer name               |
| Info      | Checks supported system languages |

Registry: 564 read events, zero writes — persistence not triggered (AutoRun: false in config). Files: nothing dropped — consistent with install: false.

**Extracted config (ANY.RUN):**

| Field         | Value                                                            |
| ------------- | ---------------------------------------------------------------- |
| Family        | AsyncRAT                                                         |
| Version       | 0.5.8                                                            |
| Botnet        | xTeam                                                            |
| C2            | hubscore.io                                                      |
| Ports         | 8090, 7080, 443, 80                                              |
| Mutex         | rxUf9crL1mff                                                     |
| AutoRun       | false                                                            |
| Install       | false                                                            |
| InstallFolder | %AppData%                                                        |
| InstallFile   | c2.skyupdragon.io.exe                                            |
| BSoD          | true                                                             |
| AntiVM        | true                                                             |
| AES Key       | 42ef5c76d82323e50a62f28fb34230e4b2871810f45eb66dc04e0fcd765968a6 |
| Salt          | bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941 |

**Network:**

```
PID 3144 → 172.67.139.209:7080 (hubscore.io) — MALICIOUS
```

C2 is behind Cloudflare (172.67.139.209, 104.21.94.206) — IP blocking won't work here.

IDS alert: `MALWARE [ANY.RUN] Win32/Common RAT related JA3 hash observed` — .NET's `SslStream` produces a consistent TLS fingerprint across every AsyncRAT build.

---

### Triage

**Score:** 10/10

Same config extracted as ANY.RUN — consistent. Additionally flagged:

- Async RAT payload signature
- Unsigned PE
- System Language Discovery (T1614.001)
- Suspicious use of AdjustPrivilegeToken

---

## Advanced Static Analysis — DnSpy

The sample is obfuscated — class and method names are randomized alphanumeric strings. Navigation by behavior, not by name.

### Configuration Loader — Class `NmxKiSWCMEb`

**Method `VkUXWPRuNNeIB` — Config Decryptor:**

- Decodes embedded Base64 key
- Instantiates the crypto engine
- Decrypts each config field individually
- Loads embedded X.509 certificate
- Verifies RSA signature before allowing execution to continue

The malware won't proceed past this point unless every validation step passes — a tampered config gets rejected, protecting the operator's infrastructure.

**Method `TPobVYcTtGvhWE` — RSA Signature Verifier:**

```csharp
RSACryptoServiceProvider.VerifyHash() // SHA-256
```

Public key comes from the embedded certificate. If the signature doesn't match `Server_Signature` from the config — execution terminates.

**Embedded certificate:**

Self-signed, `CN=AsyncRAT Server`, dated June 18, 2026 — fresh builder output. Used as a key container for RSA verification, not for TLS.

---

### Cryptographic Engine — Class `kawzoBCaSQU`

**PBKDF2 Key Derivation:**

```csharp
Rfc2898DeriveBytes(password, salt, 50000)
```

|Parameter|Value|
|---|---|
|Password|uboPUIGxH1wbTAls9Pf7vNmiOAHEUlnt|
|Salt|bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941|
|Iterations|50,000|
|Output|42ef5c76d82323e50a62f28fb34230e4b2871810f45eb66dc04e0fcd765968a6|

50,000 iterations — enough to make offline cracking painful.

**AES Configuration:**

```
AesCryptoServiceProvider
KeySize  : 256 bits
BlockSize: 128 bits
Mode     : CBC
Padding  : PKCS7
```

**HMAC Integrity Flow:**

```
Receive encrypted blob
  → Compute HMAC-SHA256 over ciphertext
  → Compare against stored HMAC (bAUEvYzAtIBIjDAF)
  → Match: decrypt with AES-256-CBC
  → Mismatch: abort
```

Any modification to the encrypted config invalidates the HMAC and halts execution.

---

### Mutex Manager — Class `hHcUBVwURarBo`

**Method `lFlKIJmClcgz()` — Mutex Creation:**

```csharp
new Mutex(...)
```

Creates named mutex `rxUf9crL1mff`. If it already exists when the process starts:

```csharp
return false;
```

Prevents double infection, conflicting C2 connections, and resource conflicts.

**Method `xWBgFTueRllD()` — Mutex Cleanup:**

```csharp
Close()
```

Releases the mutex on shutdown so the next run starts clean.

---

### Execution Chain

```
Main()
  │
  ├─ Delay (3 seconds)
  │
  ├─ Load encrypted config       (NmxKiSWCMEb.VkUXWPRuNNeIB)
  │
  ├─ Verify RSA signature        (NmxKiSWCMEb.TPobVYcTtGvhWE)
  │
  ├─ Load embedded certificate   (X509Certificate2 → RSA public key)
  │
  ├─ Create mutex                (hHcUBVwURarBo → "rxUf9crL1mff")
  │    └─ Terminate if exists
  │
  ├─ Anti-VM checks              (VirtualBox, SbieDll.dll, CheckRemoteDebuggerPresent)
  │
  ├─ System reconnaissance       (GUID, hostname, OS, language, AV via WMI)
  │
  ├─ Installation routine        (%AppData%\c2.skyupdragon.io.exe — if install=true)
  │
  ├─ Persistence                 (schtasks /create /f /sc onlogon /rl highest)
  │
  ├─ Mark process critical       (RtlSetProcessIsCritical → BSoD on kill)
  │
  └─ C2 loop                     (TcpClient → SslStream → AES → hubscore.io:7080)
```

---

## Findings

**1. `schtasks /create /f /sc onlogon /rl highest`** Full persistence command hardcoded as a string. Executes on every logon at highest privilege. Critical — unique and highly specific.

**2. Mutex `rxUf9crL1mff`** Specific to this build — per-sample but consistent format. Strong — mutex prefix is behavioral signal even when the hash suffix changes.

**3. `RtlSetProcessIsCritical`** BSOD-on-kill capability. Confirmed active by `BSoD: true` in config. Strong — rare in legitimate software.

**4. `AesCryptoServiceProvider` + `Rfc2898DeriveBytes` + `HMACSHA256`** Full crypto stack — AES-256-CBC + PBKDF2 + HMAC integrity. Strong — appears across AsyncRAT variants.

**5. `VirtualBox` + `SbieDll.dll` + `CheckRemoteDebuggerPresent`** Anti-analysis triad. Confirmed active by `AntiVM: true` in config. Strong.

**6. `Select * from AntivirusProduct` + `\root\SecurityCenter2`** WMI AV enumeration. Strong.

**7. `TcpClient` + `SslStream` + `AuthenticateAsClient`** Encrypted TCP C2 communication stack. Strong — appears across all AsyncRAT builds.

**8. C2 domain `hubscore.io`** Extracted from sandbox config. Campaign-specific — zero FP risk. Strong.

**9. `c2.skyupdragon.io.exe`** Install filename containing secondary domain. Campaign-specific. Medium.

**10. Config field names — `Hosts`, `Ports`, `Key`, `MTX`, `Anti`** Visible in .NET metadata. Medium — present across variants but also in legitimate config-driven software.

**11. `dotnet.is_dotnet`** Gate — eliminates every non-.NET file instantly. Strong.

**12. PE sections = 3, single mscoree import** Structural fingerprint — same as AgentTesla loader architecture. Strong when combined.

---

## The Rule

```yara
import "pe"
import "math"
import "dotnet"

rule AsyncRAT_cooked {
    meta:
        description    = "Detects AsyncRAT via hardcoded persistence command, crypto stack, anti-analysis strings, and behavioral config artifacts"
        malware_family = "AsyncRAT"
        sample_sha256  = "3dbaf616dcaacfcf66909b7a3404d1536f9e0d230b3b59934f1ccc6fe3e20554"
        reference      = "https://artfuldodger10.github.io/posts/AsyncRAT-Analysis/"

    strings:
        // full persistence command hardcoded as string
        $schtasks      = "schtasks /create /f /sc onlogon /rl highest" wide ascii

        // BSOD-on-kill capability 
        $bsod          = "RtlSetProcessIsCritical" ascii

        // AES crypto stack 
        $aes           = "AesCryptoServiceProvider" wide ascii
        $pbkdf2        = "Rfc2898DeriveBytes" wide ascii
        $hmac          = "HMACSHA256" wide ascii

        // encrypted TCP C2 communication stack
        $tcpclient     = "TcpClient" wide ascii
        $sslstream     = "SslStream" wide ascii

        // anti-analysis triad
        $anti_vbox     = "VirtualBox" wide ascii nocase
        $anti_sbied    = "SbieDll.dll" wide ascii
        $anti_debug    = "CheckRemoteDebuggerPresent" ascii

        // AV enumeration via WMI
        $wmi_av        = "AntivirusProduct" wide ascii

        // config field names visible in .NET metadata
        $cfg_hosts     = "Hosts" wide ascii
        $cfg_ports     = "Ports" wide ascii
        $cfg_mtx       = "MTX" wide ascii
        $cfg_anti      = "Anti" wide ascii

        // critical
        $install_file  = "c2.skyupdragon.io.exe" wide ascii

    condition:

        dotnet.is_dotnet and
        filesize < 1MB and

        (
            // Persistence 
            $schtasks or

            // BSOD + anti-VM + AV enumeration = evasion stack
            ($bsod and 1 of ($anti_vbox, $anti_sbied) and $wmi_av) or

            // full crypto stack together
            ($aes and $pbkdf2 and $hmac) or

            // C2 communication stack + config fields
            ($tcpclient and $sslstream and 2 of ($cfg_hosts, $cfg_ports, $cfg_mtx, $cfg_anti)) or

            ($install_file and 1 of ($aes, $schtasks, $bsod))
        )
}
```

