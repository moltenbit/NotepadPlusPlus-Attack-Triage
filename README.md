# Notepad++ Supply Chain Attack Triage Script

A PowerShell-based triage script for detecting indicators of compromise (IoCs) related to the Notepad++ supply chain attack attributed to the Lotus Blossom APT group (June-November 2025).

## Background

Between June and November 2025, threat actors compromised the Notepad++ update infrastructure, allowing them to distribute malicious payloads to targeted users. The attack involved three distinct infection chains delivering various backdoors including Cobalt Strike beacons and the Chrysalis backdoor.

**Sources:**
- [Kaspersky Securelist - Notepad++ Supply Chain Attack](https://securelist.com/notepad-supply-chain-attack/118708/)
- [Rapid7 - Chrysalis Backdoor Analysis](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/)
- [Notepad++ Official Statement](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

## Important Safety Information

**This script is designed to be completely safe and non-invasive:**

- **READ-ONLY**: The script does NOT modify any files, registry entries, or system settings
- **NO NETWORK TRAFFIC**: The script does NOT generate any outbound network connections
- **NO C2 CONTACT**: The script does NOT connect to any IoC domains or IP addresses
- **PASSIVE CHECKS ONLY**: All checks are performed against local system state (files, DNS cache, netstat, registry)

## Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or later
- **Administrator privileges** (required for full functionality)

## Quick Start

1. Download the script `Invoke-NotepadPlusPlusTriage.ps1`

2. Open PowerShell **as Administrator**:
   - Press `Win + X`
   - Select "Windows PowerShell (Admin)" or "Terminal (Admin)"

3. Navigate to the script directory:
   ```powershell
   cd C:\Path\To\Script
   ```

4. If needed, allow script execution (one-time):
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
   ```

5. Run the script:
   ```powershell
   .\Invoke-NotepadPlusPlusTriage.ps1
   ```

6. Review the generated reports in the current directory:
   - `NotepadPlusPlus_Triage_YYYYMMDD_HHMMSS.json` - Machine-readable for SIEM integration
   - `NotepadPlusPlus_Triage_YYYYMMDD_HHMMSS.html` - Human-readable report

## Usage Options

```powershell
# Basic usage (reports saved to current directory)
.\Invoke-NotepadPlusPlusTriage.ps1

# Specify custom output directory
.\Invoke-NotepadPlusPlusTriage.ps1 -OutputPath "C:\Reports"

# Skip file hash calculation (faster but less thorough)
.\Invoke-NotepadPlusPlusTriage.ps1 -SkipHashCheck
```

## What the Script Checks

| Check Type | Description |
|------------|-------------|
| Suspicious Paths | Scans for known malware installation directories and files |
| File Hashes | Calculates SHA-256/SHA-1 hashes and compares against known malware |
| DNS Cache | Checks for cached lookups to malicious C2 domains |
| Network Connections | Scans active TCP connections for malicious IP addresses |
| Mutex | Checks for Chrysalis backdoor mutex |
| Registry Persistence | Scans Run keys for malicious persistence entries |
| Services | Checks for malicious BluetoothService |
| Prefetch Files | Looks for execution evidence in Windows Prefetch |
| Notepad++ Version | Identifies vulnerable installations (before v8.8.9) |

---

## Indicators of Compromise (IoCs)

### Malicious Domains

| Domain | Usage |
|--------|-------|
| `cdncheck.it.com` | Cobalt Strike C2 |
| `self-dns.it.com` | System-Info Upload |
| `safe-dns.it.com` | Metasploit Downloader / CS C2 |
| `api.skycloudcenter.com` | Chrysalis C2 |
| `api.wiresguard.com` | Chrysalis C2 |

### Malicious IP Addresses

| IP Address | Usage |
|------------|-------|
| `45.76.155.202` | Malicious Update Server |
| `45.32.144.255` | Malicious Update Server |
| `45.77.31.210` | Cobalt Strike C2 |
| `95.179.213.0` | Malicious Update Server |
| `61.4.102.97` | Chrysalis C2 |
| `59.110.7.32` | Cobalt Strike C2 |
| `124.222.137.114` | Cobalt Strike C2 |

### Suspicious File Paths

#### Chain #1 - ProShow (DLL Sideloading)

| Path | Description | False Positive Risk |
|------|-------------|---------------------|
| `%AppData%\ProShow\` | Install Directory | Medium |
| `%AppData%\ProShow\ProShow.exe` | Legitimate software (abused) | Medium |
| `%AppData%\ProShow\load` | Exploit Payload | **None** |
| `%AppData%\ProShow\defscr` | Auxiliary File | None |
| `%AppData%\ProShow\if.dnt` | Auxiliary File | None |
| `%AppData%\ProShow\proshow.crs` | Marker File | Low |
| `%AppData%\ProShow\proshow.phd` | Marker File | Low |
| `%AppData%\ProShow\proshow_e.bmp` | BMP File | Low |

#### Chain #2 - Lua/Adobe (DLL Sideloading)

| Path | Description | False Positive Risk |
|------|-------------|---------------------|
| `%AppData%\Adobe\Scripts\` | Install Directory | **High** (legitimate Adobe path) |
| `%AppData%\Adobe\Scripts\script.exe` | Lua Interpreter (abused) | Medium |
| `%AppData%\Adobe\Scripts\lua5.1.dll` | Lua Library | Medium |
| `%AppData%\Adobe\Scripts\alien.dll` | Malicious DLL | **None** |
| `%AppData%\Adobe\Scripts\alien.ini` | Compiled Lua Shellcode | **None** |

#### Chain #3 - Chrysalis Backdoor

| Path | Description | False Positive Risk |
|------|-------------|---------------------|
| `%AppData%\Bluetooth\` | Install Directory (Hidden) | Low |
| `%AppData%\Bluetooth\BluetoothService.exe` | Renamed Bitdefender tool | Low |
| `%AppData%\Bluetooth\BluetoothService` | Encrypted Shellcode (no extension) | **None** |
| `%AppData%\Bluetooth\log.dll` | Malicious Sideloading DLL | **None** |
| `%ProgramData%\USOShared\` | Staging Directory | **High** (legitimate Windows path) |
| `%ProgramData%\USOShared\svchost.exe` | Renamed Tiny-C-Compiler | **None** |
| `%ProgramData%\USOShared\conf.c` | Metasploit Shellcode | **None** |
| `%ProgramData%\USOShared\libtcc.dll` | TCC Library | Low |

### Mutex

| Mutex Name | Associated Malware |
|------------|-------------------|
| `Global\Jdhfv_1.0.1` | Chrysalis Backdoor |

### Registry Persistence

| Registry Path | Indicator |
|---------------|-----------|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Value containing `Bluetooth\BluetoothService.exe` with `-i` or `-k` flag |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | Value containing `Bluetooth\BluetoothService.exe` with `-i` or `-k` flag |

### Malicious Service

| Service Name | Path Pattern |
|--------------|--------------|
| `BluetoothService` | `*\AppData\*\Bluetooth\BluetoothService.exe` |

### Prefetch Artifacts

| Prefetch Pattern | Attack Chain |
|------------------|--------------|
| `PROSHOW.EXE-*.pf` | Chain #1 (ProShow) |
| `SCRIPT.EXE-*.pf` | Chain #2 (Lua/Adobe) |
| `BLUETOOTHSERVICE.EXE-*.pf` | Chain #3 (Chrysalis) |

### File Hashes - SHA-256 (Rapid7)

| Filename | SHA-256 |
|----------|---------|
| update.exe | `a511be5164dc1122fb5a7daa3eef9467e43d8458425b15a640235796006590c9` |
| [NSIS].nsi | `8ea8b83645fba6e23d48075a0d3fc73ad2ba515b4536710cda4f1f232718f53e` |
| BluetoothService.exe | `2da00de67720f5f13b17e9d985fe70f10f153da60c9ab1086fe58f069a156924` |
| BluetoothService (shellcode) | `77bfea78def679aa1117f569a35e8fd1542df21f7e00e27f192c907e61d63a2e` |
| log.dll | `3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad` |
| u.bat | `9276594e73cda1c69b7d265b3f08dc8fa84bf2d6599086b9acc0bb3745146600` |
| conf.c | `f4d829739f2d6ba7e3ede83dad428a0ced1a703ec582fc73a4eee3df3704629a` |
| libtcc.dll | `4a52570eeaf9d27722377865df312e295a7a23c3b6eb991944c2ecd707cc9906` |
| admin (CS Beacon) | `831e1ea13a1bd405f5bda2b9d8f2265f7b1db6c668dd2165ccc8a9c4c15ea7dd` |
| loader1 | `0a9b8df968df41920b6ff07785cbfebe8bda29e6b512c94a3b2a83d10014d2fd` |
| uffhxpSy (CS Beacon) | `4c2ea8193f4a5db63b897a2d3ce127cc5d89687f380b97a1d91e0c8db542e4f8` |
| loader2 | `e7cd605568c38bd6e0aba31045e1633205d0598c607a855e2e1bca4cca1c6eda` |
| 3yZR31VK (CS Beacon) | `078a9e5c6c787e5532a7e728720cbafee9021bfec4a30e3c2be110748d7c43c5` |
| ConsoleApplication2.exe | `b4169a831292e245ebdffedd5820584d73b129411546e7d3eccf4663d5fc5be3` |
| system (CS Beacon) | `7add554a98d3a99b319f2127688356c1283ed073a084805f14e33b4f6a6126fd` |
| s047t5g.exe | `fcc2765305bcd213b7558025b2039df2265c3e0b6401e4833123c461df2de51a` |

### File Hashes - SHA-1 (Kaspersky/Securelist)

#### Chain #1 - ProShow

| Filename | SHA-1 |
|----------|-------|
| update.exe (July) | `8e6e505438c21f3d281e1cc257abdbf7223b7f5a` |
| update.exe (August) | `90e677d7ff5844407b9c073e3b7e896e078e11cd` |
| ProShow.exe | `defb05d5a91e4920c9e22de2d81c5dc9b95a9a7c` |
| defscr | `259cd3542dea998c57f67ffdd4543ab836e3d2a3` |
| if.dnt | `46654a7ad6bc809b623c51938954de48e27a5618` |
| proshow.crs | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| proshow.phd | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| proshow_e.bmp | `9df6ecc47b192260826c247bf8d40384aa6e6fd6` |
| load (v1) | `06a6a5a39193075734a32e0235bde0e979c27228` |
| load (v2) | `9c3ba38890ed984a25abb6a094b5dbf052f22fa7` |

#### Chain #2 - Lua/Adobe

| Filename | SHA-1 |
|----------|-------|
| update.exe (Sept v1) | `573549869e84544e3ef253bdba79851dcde4963a` |
| update.exe (Sept v2) | `13179c8f19fbf3d8473c49983a199e6cb4f318f0` |
| update.exe (Sept v3) | `4c9aac447bf732acc97992290aa7a187b967ee2c` |
| update.exe (Oct) | `821c0cafb2aab0f063ef7e313f64313fc81d46cd` |
| script.exe | `bf996a709835c0c16cce1015e6d44fc95e08a38a` |
| lua5.1.dll | `2ab0758dda4e71aee6f4c8e4c0265a796518f07d` |
| alien.dll | `6444dab57d93ce987c22da66b3706d5d7fc226da` |
| alien.ini (v1) | `ca4b6fe0c69472cd3d63b212eb805b7f65710d33` |
| alien.ini (v2) | `0d0f315fd8cf408a483f8e2dd1e69422629ed9fd` |
| alien.ini (v3) | `2a476cfb85fbf012fdbe63a37642c11afa5cf020` |

#### Chain #3 - Chrysalis

| Filename | SHA-1 |
|----------|-------|
| update.exe | `d7ffd7b588880cf61b603346a3557e7cce648c93` |
| BluetoothService.exe | `21a942273c14e4b9d3faa58e4de1fd4d5014a1ed` |
| BluetoothService (shellcode) | `7e0790226ea461bcc9ecd4be3c315ace41e1c122` |
| log.dll | `f7910d943a013eede24ac89d6388c1b98f8b3717` |

---

## Understanding the Output

### Severity Levels

| Level | Meaning |
|-------|---------|
| **Critical** | Strong indicator of active compromise |
| **High** | Likely indicator of compromise |
| **Medium** | Potential indicator, possible false positive |
| **Low** | Weak indicator, high false positive chance |
| **Info** | Informational finding |

### Report Files

**JSON Report** (`NotepadPlusPlus_Triage_*.json`)
- Machine-readable format
- Suitable for SIEM ingestion
- Contains all findings with full metadata
- Includes list of all checked indicators

**HTML Report** (`NotepadPlusPlus_Triage_*.html`)
- Human-readable format
- Open in any web browser
- Color-coded severity indicators
- Summary statistics and detailed findings

## Limitations

- DNS cache entries may have expired if the compromise is old
- Network connections are point-in-time; persistent connections may not be active during scan
- Prefetch files may be cleared or overwritten
- Some legitimate software may trigger false positives for certain paths (see False Positive Risk column)

## License

This tool is provided as-is for incident response purposes. Use at your own risk.
