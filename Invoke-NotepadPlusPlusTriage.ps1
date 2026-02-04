<#
.SYNOPSIS
    Notepad++ Supply Chain Attack Triage Script

.DESCRIPTION
    This script checks for Indicators of Compromise (IoCs) related to the Notepad++
    supply chain attack (June-November 2025) attributed to the Lotus Blossom APT group.

    The script is READ-ONLY and does NOT:
    - Modify any files
    - Change registry entries
    - Create/delete services
    - Generate outbound network traffic
    - Connect to any IoC domains or IPs

    Sources:
    - https://securelist.com/notepad-supply-chain-attack/118708/
    - https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/

.PARAMETER OutputPath
    Directory where report files will be saved. Defaults to current directory.

.PARAMETER SkipHashCheck
    Skip file hash verification (faster but less thorough).

.EXAMPLE
    .\Invoke-NotepadPlusPlusTriage.ps1

.EXAMPLE
    .\Invoke-NotepadPlusPlusTriage.ps1 -OutputPath "C:\Reports"

.NOTES
    Version: 1.0
    Requires: PowerShell 5.1 or later, Administrator privileges

    IMPORTANT: This script requires Administrator privileges to check:
    - HKLM registry keys
    - Windows Services
    - Prefetch files
    - DNS Client Cache
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter()]
    [switch]$SkipHashCheck
)

#Requires -RunAsAdministrator

# ============================================================================
# CONFIGURATION - Indicators of Compromise
# ============================================================================

$Script:Config = @{

    # Malicious Domains (DO NOT CONNECT - DNS Cache check only)
    Domains = @(
        "cdncheck.it.com"
        "self-dns.it.com"
        "safe-dns.it.com"
        "api.skycloudcenter.com"
        "api.wiresguard.com"
    )

    # Malicious IPs (DO NOT CONNECT - Netstat check only)
    IPs = @(
        "45.76.155.202"
        "45.32.144.255"
        "45.77.31.210"
        "95.179.213.0"
        "61.4.102.97"
        "59.110.7.32"
        "124.222.137.114"
    )

    # Suspicious file paths to check
    SuspiciousPaths = @(
        # Chain #1 - ProShow
        @{ Path = "$env:APPDATA\ProShow"; Description = "Chain #1 Install Directory"; FalsePositiveRisk = "Medium" }
        @{ Path = "$env:APPDATA\ProShow\ProShow.exe"; Description = "Legitimate ProShow (abused for sideloading)"; FalsePositiveRisk = "Medium" }
        @{ Path = "$env:APPDATA\ProShow\load"; Description = "Chain #1 Exploit Payload"; FalsePositiveRisk = "None" }
        @{ Path = "$env:APPDATA\ProShow\defscr"; Description = "Chain #1 Auxiliary File"; FalsePositiveRisk = "None" }
        @{ Path = "$env:APPDATA\ProShow\if.dnt"; Description = "Chain #1 Auxiliary File"; FalsePositiveRisk = "None" }
        @{ Path = "$env:APPDATA\ProShow\proshow.crs"; Description = "Chain #1 Empty Marker File"; FalsePositiveRisk = "Low" }
        @{ Path = "$env:APPDATA\ProShow\proshow.phd"; Description = "Chain #1 Empty Marker File"; FalsePositiveRisk = "Low" }
        @{ Path = "$env:APPDATA\ProShow\proshow_e.bmp"; Description = "Chain #1 BMP File"; FalsePositiveRisk = "Low" }

        # Chain #2 - Lua/Adobe
        @{ Path = "$env:APPDATA\Adobe\Scripts"; Description = "Chain #2 Install Directory (legitimate Adobe path!)"; FalsePositiveRisk = "High" }
        @{ Path = "$env:APPDATA\Adobe\Scripts\script.exe"; Description = "Lua Interpreter (legitimate, abused)"; FalsePositiveRisk = "Medium" }
        @{ Path = "$env:APPDATA\Adobe\Scripts\lua5.1.dll"; Description = "Lua Library (legitimate)"; FalsePositiveRisk = "Medium" }
        @{ Path = "$env:APPDATA\Adobe\Scripts\alien.dll"; Description = "Chain #2 Malicious DLL"; FalsePositiveRisk = "None" }
        @{ Path = "$env:APPDATA\Adobe\Scripts\alien.ini"; Description = "Chain #2 Compiled Lua Shellcode"; FalsePositiveRisk = "None" }

        # Chain #3 - Chrysalis/Bluetooth
        @{ Path = "$env:APPDATA\Bluetooth"; Description = "Chain #3 Install Directory (Hidden attribute expected)"; FalsePositiveRisk = "Low" }
        @{ Path = "$env:APPDATA\Bluetooth\BluetoothService.exe"; Description = "Renamed Bitdefender Submission Wizard"; FalsePositiveRisk = "Low" }
        @{ Path = "$env:APPDATA\Bluetooth\BluetoothService"; Description = "Encrypted Shellcode (no extension!)"; FalsePositiveRisk = "None" }
        @{ Path = "$env:APPDATA\Bluetooth\log.dll"; Description = "Chain #3 Malicious Sideloading DLL"; FalsePositiveRisk = "None" }

        # Chain #3 - USOShared
        @{ Path = "$env:ProgramData\USOShared"; Description = "Chain #3 Staging Directory (legitimate Windows path!)"; FalsePositiveRisk = "High" }
        @{ Path = "$env:ProgramData\USOShared\svchost.exe"; Description = "Renamed Tiny-C-Compiler"; FalsePositiveRisk = "None" }
        @{ Path = "$env:ProgramData\USOShared\conf.c"; Description = "Metasploit Shellcode"; FalsePositiveRisk = "None" }
        @{ Path = "$env:ProgramData\USOShared\libtcc.dll"; Description = "TCC Library"; FalsePositiveRisk = "Low" }
    )

    # SHA-256 Hashes (from Rapid7)
    HashsSHA256 = @{
        "update.exe" = "a511be5164dc1122fb5a7daa3eef9467e43d8458425b15a640235796006590c9"
        "[NSIS].nsi" = "8ea8b83645fba6e23d48075a0d3fc73ad2ba515b4536710cda4f1f232718f53e"
        "BluetoothService.exe" = "2da00de67720f5f13b17e9d985fe70f10f153da60c9ab1086fe58f069a156924"
        "BluetoothService_shellcode" = "77bfea78def679aa1117f569a35e8fd1542df21f7e00e27f192c907e61d63a2e"
        "log.dll" = "3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad"
        "u.bat" = "9276594e73cda1c69b7d265b3f08dc8fa84bf2d6599086b9acc0bb3745146600"
        "conf.c" = "f4d829739f2d6ba7e3ede83dad428a0ced1a703ec582fc73a4eee3df3704629a"
        "libtcc.dll" = "4a52570eeaf9d27722377865df312e295a7a23c3b6eb991944c2ecd707cc9906"
        "admin_CSBeacon" = "831e1ea13a1bd405f5bda2b9d8f2265f7b1db6c668dd2165ccc8a9c4c15ea7dd"
        "loader1" = "0a9b8df968df41920b6ff07785cbfebe8bda29e6b512c94a3b2a83d10014d2fd"
        "uffhxpSy_CSBeacon" = "4c2ea8193f4a5db63b897a2d3ce127cc5d89687f380b97a1d91e0c8db542e4f8"
        "loader2" = "e7cd605568c38bd6e0aba31045e1633205d0598c607a855e2e1bca4cca1c6eda"
        "3yZR31VK_CSBeacon" = "078a9e5c6c787e5532a7e728720cbafee9021bfec4a30e3c2be110748d7c43c5"
        "ConsoleApplication2.exe" = "b4169a831292e245ebdffedd5820584d73b129411546e7d3eccf4663d5fc5be3"
        "system_CSBeacon" = "7add554a98d3a99b319f2127688356c1283ed073a084805f14e33b4f6a6126fd"
        "s047t5g.exe" = "fcc2765305bcd213b7558025b2039df2265c3e0b6401e4833123c461df2de51a"
    }

    # SHA-1 Hashes (from Kaspersky/Securelist)
    HashesSHA1 = @{
        # Chain #1 - ProShow
        "update_exe_july" = "8e6e505438c21f3d281e1cc257abdbf7223b7f5a"
        "update_exe_aug" = "90e677d7ff5844407b9c073e3b7e896e078e11cd"
        "ProShow.exe" = "defb05d5a91e4920c9e22de2d81c5dc9b95a9a7c"
        "defscr" = "259cd3542dea998c57f67ffdd4543ab836e3d2a3"
        "if.dnt" = "46654a7ad6bc809b623c51938954de48e27a5618"
        "proshow.crs" = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        "proshow.phd" = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        "proshow_e.bmp" = "9df6ecc47b192260826c247bf8d40384aa6e6fd6"
        "load_v1" = "06a6a5a39193075734a32e0235bde0e979c27228"
        "load_v2" = "9c3ba38890ed984a25abb6a094b5dbf052f22fa7"

        # Chain #2 - Lua/Adobe
        "update_exe_sept_v1" = "573549869e84544e3ef253bdba79851dcde4963a"
        "update_exe_sept_v2" = "13179c8f19fbf3d8473c49983a199e6cb4f318f0"
        "update_exe_sept_v3" = "4c9aac447bf732acc97992290aa7a187b967ee2c"
        "update_exe_oct" = "821c0cafb2aab0f063ef7e313f64313fc81d46cd"
        "script.exe" = "bf996a709835c0c16cce1015e6d44fc95e08a38a"
        "lua5.1.dll" = "2ab0758dda4e71aee6f4c8e4c0265a796518f07d"
        "alien.dll" = "6444dab57d93ce987c22da66b3706d5d7fc226da"
        "alien.ini_v1" = "ca4b6fe0c69472cd3d63b212eb805b7f65710d33"
        "alien.ini_v2" = "0d0f315fd8cf408a483f8e2dd1e69422629ed9fd"
        "alien.ini_v3" = "2a476cfb85fbf012fdbe63a37642c11afa5cf020"

        # Chain #3 - Chrysalis
        "update_exe_chain3" = "d7ffd7b588880cf61b603346a3557e7cce648c93"
        "BluetoothService.exe_sha1" = "21a942273c14e4b9d3faa58e4de1fd4d5014a1ed"
        "BluetoothService_shellcode_sha1" = "7e0790226ea461bcc9ecd4be3c315ace41e1c122"
        "log.dll_sha1" = "f7910d943a013eede24ac89d6388c1b98f8b3717"
    }

    # Mutex name
    MutexName = "Global\Jdhfv_1.0.1"

    # Registry persistence patterns
    RegistryPersistence = @(
        @{
            Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
            Pattern = "Bluetooth\\BluetoothService\.exe.+(-i|-k)"
            Description = "Chrysalis persistence (HKCU)"
        }
        @{
            Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
            Pattern = "Bluetooth\\BluetoothService\.exe.+(-i|-k)"
            Description = "Chrysalis persistence (HKLM)"
        }
    )

    # Service name to check
    ServiceName = "BluetoothService"
    ServicePathPattern = "*\AppData\*\Bluetooth\BluetoothService.exe"

    # Prefetch patterns
    PrefetchPatterns = @(
        @{ Pattern = "PROSHOW.EXE-*.pf"; Chain = "Chain #1 (ProShow)" }
        @{ Pattern = "SCRIPT.EXE-*.pf"; Chain = "Chain #2 (Lua/Adobe)" }
        @{ Pattern = "BLUETOOTHSERVICE.EXE-*.pf"; Chain = "Chain #3 (Chrysalis)" }
    )

    # Vulnerable Notepad++ versions (before v8.8.9)
    VulnerableVersionMax = [version]"8.8.8"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Type = "Info"
    )

    $color = switch ($Type) {
        "Info"    { "Cyan" }
        "Warning" { "Yellow" }
        "Error"   { "Red" }
        "Success" { "Green" }
    }

    $prefix = switch ($Type) {
        "Info"    { "[*]" }
        "Warning" { "[!]" }
        "Error"   { "[X]" }
        "Success" { "[+]" }
    }

    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Get-FileHashSafe {
    param(
        [string]$Path,
        [ValidateSet("SHA1", "SHA256")]
        [string]$Algorithm = "SHA256"
    )

    try {
        if (Test-Path -Path $Path -PathType Leaf) {
            $hash = Get-FileHash -Path $Path -Algorithm $Algorithm -ErrorAction Stop
            return $hash.Hash.ToLower()
        }
    }
    catch {
        return $null
    }
    return $null
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ============================================================================
# CHECK FUNCTIONS
# ============================================================================

function Test-SuspiciousPaths {
    Write-Status "Checking suspicious file paths..." -Type Info
    $findings = @()

    foreach ($item in $Script:Config.SuspiciousPaths) {
        $path = $item.Path
        $exists = Test-Path -Path $path

        if ($exists) {
            $fileInfo = Get-Item -Path $path -Force -ErrorAction SilentlyContinue
            $isHidden = $false
            $size = $null
            $lastModified = $null
            $sha256 = $null
            $sha1 = $null

            if ($fileInfo) {
                $isHidden = $fileInfo.Attributes -band [System.IO.FileAttributes]::Hidden
                if (-not $fileInfo.PSIsContainer) {
                    $size = $fileInfo.Length
                    $lastModified = $fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")

                    if (-not $SkipHashCheck) {
                        $sha256 = Get-FileHashSafe -Path $path -Algorithm SHA256
                        $sha1 = Get-FileHashSafe -Path $path -Algorithm SHA1
                    }
                }
            }

            $finding = @{
                Type = "SuspiciousPath"
                Path = $path
                Description = $item.Description
                FalsePositiveRisk = $item.FalsePositiveRisk
                Exists = $true
                IsHidden = $isHidden
                Size = $size
                LastModified = $lastModified
                SHA256 = $sha256
                SHA1 = $sha1
                HashMatch = $false
                Severity = "Medium"
            }

            # Check if hash matches known malware
            if ($sha256 -and $Script:Config.HashsSHA256.Values -contains $sha256) {
                $finding.HashMatch = $true
                $finding.Severity = "Critical"
                Write-Status "CRITICAL: Known malware hash match at $path (SHA256: $sha256)" -Type Error
            }
            elseif ($sha1 -and $Script:Config.HashesSHA1.Values -contains $sha1) {
                $finding.HashMatch = $true
                $finding.Severity = "Critical"
                Write-Status "CRITICAL: Known malware hash match at $path (SHA1: $sha1)" -Type Error
            }
            elseif ($item.FalsePositiveRisk -eq "None") {
                $finding.Severity = "High"
                Write-Status "HIGH: Malware-specific file found at $path" -Type Error
            }
            else {
                Write-Status "Found suspicious path: $path (FP Risk: $($item.FalsePositiveRisk))" -Type Warning
            }

            $findings += $finding
        }
    }

    if ($findings.Count -eq 0) {
        Write-Status "No suspicious paths found" -Type Success
    }

    return $findings
}

function Test-DNSCache {
    Write-Status "Checking DNS cache for malicious domains..." -Type Info
    $findings = @()

    try {
        $dnsCache = Get-DnsClientCache -ErrorAction Stop

        foreach ($domain in $Script:Config.Domains) {
            $matches = $dnsCache | Where-Object { $_.Entry -like "*$domain*" }

            foreach ($match in $matches) {
                Write-Status "CRITICAL: Malicious domain found in DNS cache: $($match.Entry)" -Type Error
                $findings += @{
                    Type = "DNSCache"
                    Domain = $domain
                    Entry = $match.Entry
                    Data = $match.Data
                    TTL = $match.TimeToLive
                    Severity = "Critical"
                }
            }
        }
    }
    catch {
        Write-Status "Could not query DNS cache: $($_.Exception.Message)" -Type Warning
        $findings += @{
            Type = "DNSCache"
            Error = $_.Exception.Message
            Severity = "Unknown"
        }
    }

    if ($findings.Count -eq 0 -or ($findings.Count -eq 1 -and $findings[0].Error)) {
        Write-Status "No malicious domains found in DNS cache" -Type Success
    }

    return $findings
}

function Test-NetworkConnections {
    Write-Status "Checking active network connections for malicious IPs..." -Type Info
    $findings = @()

    try {
        $connections = Get-NetTCPConnection -ErrorAction Stop

        foreach ($ip in $Script:Config.IPs) {
            $matches = $connections | Where-Object {
                $_.RemoteAddress -eq $ip -or $_.LocalAddress -eq $ip
            }

            foreach ($match in $matches) {
                Write-Status "CRITICAL: Connection to malicious IP detected: $ip" -Type Error
                $findings += @{
                    Type = "NetworkConnection"
                    MaliciousIP = $ip
                    LocalAddress = $match.LocalAddress
                    LocalPort = $match.LocalPort
                    RemoteAddress = $match.RemoteAddress
                    RemotePort = $match.RemotePort
                    State = $match.State
                    OwningProcess = $match.OwningProcess
                    Severity = "Critical"
                }
            }
        }
    }
    catch {
        Write-Status "Could not query network connections: $($_.Exception.Message)" -Type Warning
        $findings += @{
            Type = "NetworkConnection"
            Error = $_.Exception.Message
            Severity = "Unknown"
        }
    }

    if ($findings.Count -eq 0 -or ($findings.Count -eq 1 -and $findings[0].Error)) {
        Write-Status "No connections to malicious IPs found" -Type Success
    }

    return $findings
}

function Test-Mutex {
    Write-Status "Checking for Chrysalis mutex..." -Type Info
    $findings = @()

    $mutexName = $Script:Config.MutexName
    $mutexExists = $false

    try {
        $mutex = [System.Threading.Mutex]::OpenExisting($mutexName)
        $mutexExists = $true
        $mutex.Dispose()
    }
    catch [System.Threading.WaitHandleCannotBeOpenedException] {
        # Mutex does not exist - this is good
        $mutexExists = $false
    }
    catch [System.UnauthorizedAccessException] {
        # Mutex exists but we cannot access it
        $mutexExists = $true
    }
    catch {
        # Other error - mutex likely does not exist
        $mutexExists = $false
    }

    if ($mutexExists) {
        Write-Status "CRITICAL: Chrysalis mutex detected: $mutexName" -Type Error
        $findings += @{
            Type = "Mutex"
            MutexName = $mutexName
            Exists = $true
            Severity = "Critical"
        }
    }
    else {
        Write-Status "Chrysalis mutex not found" -Type Success
    }

    return $findings
}

function Test-RegistryPersistence {
    Write-Status "Checking registry for persistence mechanisms..." -Type Info
    $findings = @()

    foreach ($regItem in $Script:Config.RegistryPersistence) {
        try {
            if (Test-Path -Path $regItem.Path) {
                $values = Get-ItemProperty -Path $regItem.Path -ErrorAction SilentlyContinue

                if ($values) {
                    $properties = $values.PSObject.Properties | Where-Object {
                        $_.Name -notmatch '^PS' -and $_.Value -match $regItem.Pattern
                    }

                    foreach ($prop in $properties) {
                        Write-Status "CRITICAL: Malicious persistence found in registry: $($regItem.Path)\$($prop.Name)" -Type Error
                        $findings += @{
                            Type = "RegistryPersistence"
                            Path = $regItem.Path
                            ValueName = $prop.Name
                            ValueData = $prop.Value
                            Description = $regItem.Description
                            Severity = "Critical"
                        }
                    }
                }
            }
        }
        catch {
            Write-Status "Could not check registry path $($regItem.Path): $($_.Exception.Message)" -Type Warning
        }
    }

    if ($findings.Count -eq 0) {
        Write-Status "No malicious registry persistence found" -Type Success
    }

    return $findings
}

function Test-MaliciousService {
    Write-Status "Checking for malicious BluetoothService..." -Type Info
    $findings = @()

    try {
        $service = Get-Service -Name $Script:Config.ServiceName -ErrorAction SilentlyContinue

        if ($service) {
            # Get service path
            $serviceWmi = Get-WmiObject -Class Win32_Service -Filter "Name='$($Script:Config.ServiceName)'" -ErrorAction SilentlyContinue
            $servicePath = $serviceWmi.PathName

            if ($servicePath -like $Script:Config.ServicePathPattern) {
                Write-Status "CRITICAL: Malicious BluetoothService detected!" -Type Error
                $findings += @{
                    Type = "MaliciousService"
                    ServiceName = $Script:Config.ServiceName
                    Status = $service.Status
                    StartType = $service.StartType
                    Path = $servicePath
                    Severity = "Critical"
                }
            }
            else {
                Write-Status "BluetoothService exists but path does not match malware pattern" -Type Info
            }
        }
        else {
            Write-Status "BluetoothService not found (this is normal)" -Type Success
        }
    }
    catch {
        Write-Status "Could not check services: $($_.Exception.Message)" -Type Warning
    }

    return $findings
}

function Test-PrefetchFiles {
    Write-Status "Checking Prefetch files for execution evidence..." -Type Info
    $findings = @()

    $prefetchPath = "$env:SystemRoot\Prefetch"

    if (-not (Test-Path -Path $prefetchPath)) {
        Write-Status "Prefetch folder not accessible" -Type Warning
        return $findings
    }

    foreach ($prefetch in $Script:Config.PrefetchPatterns) {
        $matches = Get-ChildItem -Path $prefetchPath -Filter $prefetch.Pattern -ErrorAction SilentlyContinue

        foreach ($match in $matches) {
            Write-Status "HIGH: Prefetch evidence found for $($prefetch.Chain): $($match.Name)" -Type Error
            $findings += @{
                Type = "PrefetchEvidence"
                FileName = $match.Name
                FullPath = $match.FullName
                Chain = $prefetch.Chain
                LastWriteTime = $match.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                CreationTime = $match.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
                Severity = "High"
            }
        }
    }

    if ($findings.Count -eq 0) {
        Write-Status "No suspicious Prefetch files found" -Type Success
    }

    return $findings
}

function Test-NotepadVersion {
    Write-Status "Checking installed Notepad++ version..." -Type Info
    $findings = @()

    # Common installation paths
    $possiblePaths = @(
        "$env:ProgramFiles\Notepad++\notepad++.exe"
        "${env:ProgramFiles(x86)}\Notepad++\notepad++.exe"
        "$env:LOCALAPPDATA\Notepad++\notepad++.exe"
    )

    # Also check registry for installation path
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++"
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++"
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++"
    )

    foreach ($regPath in $regPaths) {
        try {
            if (Test-Path -Path $regPath) {
                $installLocation = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).InstallLocation
                if ($installLocation) {
                    $possiblePaths += Join-Path $installLocation "notepad++.exe"
                }
            }
        }
        catch { }
    }

    $possiblePaths = $possiblePaths | Select-Object -Unique

    foreach ($nppPath in $possiblePaths) {
        if (Test-Path -Path $nppPath) {
            try {
                $fileInfo = Get-Item -Path $nppPath
                $versionInfo = $fileInfo.VersionInfo
                $version = $versionInfo.ProductVersion

                # Clean up version string
                $versionClean = $version -replace '[^\d.]', ''
                $versionParts = $versionClean.Split('.')

                # Ensure we have at least 3 parts for version comparison
                while ($versionParts.Count -lt 3) {
                    $versionParts += "0"
                }

                $versionObj = [version]($versionParts[0..2] -join '.')

                $isVulnerable = $versionObj -le $Script:Config.VulnerableVersionMax

                if ($isVulnerable) {
                    Write-Status "WARNING: Vulnerable Notepad++ version installed: $version (Path: $nppPath)" -Type Warning
                    $findings += @{
                        Type = "VulnerableVersion"
                        Path = $nppPath
                        Version = $version
                        IsVulnerable = $true
                        Recommendation = "Update to version 8.8.9 or later"
                        Severity = "Medium"
                    }
                }
                else {
                    Write-Status "Notepad++ version $version is not vulnerable (Path: $nppPath)" -Type Success
                    $findings += @{
                        Type = "NotepadVersion"
                        Path = $nppPath
                        Version = $version
                        IsVulnerable = $false
                        Severity = "Info"
                    }
                }
            }
            catch {
                Write-Status "Could not determine version for: $nppPath" -Type Warning
            }
        }
    }

    if ($findings.Count -eq 0) {
        Write-Status "No Notepad++ installation found" -Type Info
    }

    return $findings
}

# ============================================================================
# REPORT GENERATION
# ============================================================================

function New-JSONReport {
    param(
        [hashtable]$Results,
        [string]$OutputPath
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "NotepadPlusPlus_Triage_$timestamp.json"
    $fullPath = Join-Path $OutputPath $filename

    $report = @{
        ReportMetadata = @{
            GeneratedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            GeneratedAtUTC = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
            Hostname = $env:COMPUTERNAME
            Username = $env:USERNAME
            ScriptVersion = "1.0"
            IncidentReference = "Notepad++ Supply Chain Attack (June-November 2025)"
        }
        Summary = @{
            TotalFindings = 0
            CriticalFindings = 0
            HighFindings = 0
            MediumFindings = 0
            LowFindings = 0
            IsCompromised = $false
        }
        Findings = $Results
        CheckedIndicators = @{
            Domains = $Script:Config.Domains
            IPs = $Script:Config.IPs
            MutexName = $Script:Config.MutexName
            SHA256Hashes = $Script:Config.HashsSHA256.Values
            SHA1Hashes = $Script:Config.HashesSHA1.Values
        }
    }

    # Calculate summary
    $allFindings = @()
    foreach ($category in $Results.Keys) {
        $allFindings += $Results[$category]
    }

    $report.Summary.TotalFindings = ($allFindings | Where-Object { $_.Severity -and $_.Severity -ne "Info" -and $_.Severity -ne "Unknown" -and -not $_.Error }).Count
    $report.Summary.CriticalFindings = ($allFindings | Where-Object { $_.Severity -eq "Critical" }).Count
    $report.Summary.HighFindings = ($allFindings | Where-Object { $_.Severity -eq "High" }).Count
    $report.Summary.MediumFindings = ($allFindings | Where-Object { $_.Severity -eq "Medium" }).Count
    $report.Summary.LowFindings = ($allFindings | Where-Object { $_.Severity -eq "Low" }).Count
    $report.Summary.IsCompromised = $report.Summary.CriticalFindings -gt 0 -or $report.Summary.HighFindings -gt 0

    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $fullPath -Encoding UTF8

    return $fullPath
}

function New-HTMLReport {
    param(
        [hashtable]$Results,
        [string]$OutputPath
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "NotepadPlusPlus_Triage_$timestamp.html"
    $fullPath = Join-Path $OutputPath $filename

    # Calculate summary
    $allFindings = @()
    foreach ($category in $Results.Keys) {
        $allFindings += $Results[$category]
    }

    $totalFindings = ($allFindings | Where-Object { $_.Severity -and $_.Severity -ne "Info" -and $_.Severity -ne "Unknown" -and -not $_.Error }).Count
    $criticalFindings = ($allFindings | Where-Object { $_.Severity -eq "Critical" }).Count
    $highFindings = ($allFindings | Where-Object { $_.Severity -eq "High" }).Count
    $mediumFindings = ($allFindings | Where-Object { $_.Severity -eq "Medium" }).Count
    $isCompromised = $criticalFindings -gt 0 -or $highFindings -gt 0

    $statusColor = if ($isCompromised) { "#dc3545" } else { "#28a745" }
    $statusText = if ($isCompromised) { "POTENTIAL COMPROMISE DETECTED" } else { "NO COMPROMISE INDICATORS FOUND" }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Notepad++ Supply Chain Attack - Triage Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        header h1 { font-size: 1.8em; margin-bottom: 10px; }
        header p { opacity: 0.9; }
        .status-banner { background: $statusColor; color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; text-align: center; font-size: 1.4em; font-weight: bold; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .summary-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); text-align: center; }
        .summary-card h3 { font-size: 2em; margin-bottom: 5px; }
        .summary-card p { color: #666; }
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .info { color: #17a2b8; }
        section { background: white; padding: 25px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        section h2 { color: #1a1a2e; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #eee; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; }
        tr:hover { background: #f8f9fa; }
        .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 0.85em; font-weight: 500; }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: #333; }
        .badge-low { background: #6c757d; color: white; }
        .badge-info { background: #17a2b8; color: white; }
        .metadata { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 10px; }
        .metadata-item { padding: 10px; background: #f8f9fa; border-radius: 5px; }
        .metadata-item strong { display: block; color: #666; font-size: 0.9em; }
        .no-findings { color: #28a745; font-style: italic; padding: 20px; text-align: center; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: 'Consolas', monospace; font-size: 0.9em; word-break: break-all; }
        footer { text-align: center; padding: 20px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Notepad++ Supply Chain Attack - Triage Report</h1>
            <p>Incident Reference: Lotus Blossom APT Campaign (June-November 2025)</p>
        </header>

        <div class="status-banner">$statusText</div>

        <div class="summary-grid">
            <div class="summary-card">
                <h3 class="critical">$criticalFindings</h3>
                <p>Critical Findings</p>
            </div>
            <div class="summary-card">
                <h3 class="high">$highFindings</h3>
                <p>High Findings</p>
            </div>
            <div class="summary-card">
                <h3 class="medium">$mediumFindings</h3>
                <p>Medium Findings</p>
            </div>
            <div class="summary-card">
                <h3>$totalFindings</h3>
                <p>Total Findings</p>
            </div>
        </div>

        <section>
            <h2>System Information</h2>
            <div class="metadata">
                <div class="metadata-item">
                    <strong>Hostname</strong>
                    $env:COMPUTERNAME
                </div>
                <div class="metadata-item">
                    <strong>Username</strong>
                    $env:USERNAME
                </div>
                <div class="metadata-item">
                    <strong>Scan Time</strong>
                    $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                </div>
                <div class="metadata-item">
                    <strong>Scan Time (UTC)</strong>
                    $((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"))
                </div>
            </div>
        </section>
"@

    # Suspicious Paths Section
    $html += @"
        <section>
            <h2>Suspicious File Paths</h2>
"@

    $pathFindings = $Results["SuspiciousPaths"] | Where-Object { $_.Exists -eq $true }
    if ($pathFindings.Count -gt 0) {
        $html += "<table><tr><th>Path</th><th>Description</th><th>Severity</th><th>Hash Match</th><th>Details</th></tr>"
        foreach ($finding in $pathFindings) {
            $severityClass = $finding.Severity.ToLower()
            $hashInfo = if ($finding.HashMatch) { "YES - Known Malware" } else { "No" }
            $details = @()
            if ($finding.SHA256) { $details += "SHA256: $($finding.SHA256)" }
            if ($finding.SHA1) { $details += "SHA1: $($finding.SHA1)" }
            if ($finding.Size) { $details += "Size: $($finding.Size) bytes" }
            if ($finding.IsHidden) { $details += "Hidden: Yes" }
            $detailsStr = $details -join "<br>"
            $html += "<tr><td><code>$($finding.Path)</code></td><td>$($finding.Description)</td><td><span class='badge badge-$severityClass'>$($finding.Severity)</span></td><td>$hashInfo</td><td>$detailsStr</td></tr>"
        }
        $html += "</table>"
    }
    else {
        $html += "<p class='no-findings'>No suspicious paths found</p>"
    }
    $html += "</section>"

    # DNS Cache Section
    $html += @"
        <section>
            <h2>DNS Cache Analysis</h2>
"@
    $dnsFindings = $Results["DNSCache"] | Where-Object { $_.Domain -and -not $_.Error }
    if ($dnsFindings.Count -gt 0) {
        $html += "<table><tr><th>Domain</th><th>Entry</th><th>Resolved Data</th><th>TTL</th><th>Severity</th></tr>"
        foreach ($finding in $dnsFindings) {
            $html += "<tr><td><code>$($finding.Domain)</code></td><td>$($finding.Entry)</td><td>$($finding.Data)</td><td>$($finding.TTL)</td><td><span class='badge badge-critical'>Critical</span></td></tr>"
        }
        $html += "</table>"
    }
    else {
        $html += "<p class='no-findings'>No malicious domains found in DNS cache</p>"
    }
    $html += "</section>"

    # Network Connections Section
    $html += @"
        <section>
            <h2>Network Connections</h2>
"@
    $netFindings = $Results["NetworkConnections"] | Where-Object { $_.MaliciousIP -and -not $_.Error }
    if ($netFindings.Count -gt 0) {
        $html += "<table><tr><th>Malicious IP</th><th>Local</th><th>Remote</th><th>State</th><th>Process ID</th><th>Severity</th></tr>"
        foreach ($finding in $netFindings) {
            $html += "<tr><td><code>$($finding.MaliciousIP)</code></td><td>$($finding.LocalAddress):$($finding.LocalPort)</td><td>$($finding.RemoteAddress):$($finding.RemotePort)</td><td>$($finding.State)</td><td>$($finding.OwningProcess)</td><td><span class='badge badge-critical'>Critical</span></td></tr>"
        }
        $html += "</table>"
    }
    else {
        $html += "<p class='no-findings'>No connections to malicious IPs detected</p>"
    }
    $html += "</section>"

    # Mutex Section
    $html += @"
        <section>
            <h2>Mutex Analysis</h2>
"@
    $mutexFindings = $Results["Mutex"] | Where-Object { $_.Exists -eq $true }
    if ($mutexFindings.Count -gt 0) {
        $html += "<table><tr><th>Mutex Name</th><th>Status</th><th>Severity</th></tr>"
        foreach ($finding in $mutexFindings) {
            $html += "<tr><td><code>$($finding.MutexName)</code></td><td>DETECTED</td><td><span class='badge badge-critical'>Critical</span></td></tr>"
        }
        $html += "</table>"
    }
    else {
        $html += "<p class='no-findings'>Chrysalis mutex not detected</p>"
    }
    $html += "</section>"

    # Registry Section
    $html += @"
        <section>
            <h2>Registry Persistence</h2>
"@
    $regFindings = $Results["RegistryPersistence"] | Where-Object { $_.ValueName }
    if ($regFindings.Count -gt 0) {
        $html += "<table><tr><th>Registry Path</th><th>Value Name</th><th>Value Data</th><th>Severity</th></tr>"
        foreach ($finding in $regFindings) {
            $html += "<tr><td><code>$($finding.Path)</code></td><td>$($finding.ValueName)</td><td><code>$($finding.ValueData)</code></td><td><span class='badge badge-critical'>Critical</span></td></tr>"
        }
        $html += "</table>"
    }
    else {
        $html += "<p class='no-findings'>No malicious registry persistence found</p>"
    }
    $html += "</section>"

    # Services Section
    $html += @"
        <section>
            <h2>Service Analysis</h2>
"@
    $svcFindings = $Results["Services"] | Where-Object { $_.ServiceName }
    if ($svcFindings.Count -gt 0) {
        $html += "<table><tr><th>Service Name</th><th>Status</th><th>Start Type</th><th>Path</th><th>Severity</th></tr>"
        foreach ($finding in $svcFindings) {
            $html += "<tr><td>$($finding.ServiceName)</td><td>$($finding.Status)</td><td>$($finding.StartType)</td><td><code>$($finding.Path)</code></td><td><span class='badge badge-critical'>Critical</span></td></tr>"
        }
        $html += "</table>"
    }
    else {
        $html += "<p class='no-findings'>No malicious BluetoothService detected</p>"
    }
    $html += "</section>"

    # Prefetch Section
    $html += @"
        <section>
            <h2>Prefetch Evidence</h2>
"@
    $prefetchFindings = $Results["Prefetch"] | Where-Object { $_.FileName }
    if ($prefetchFindings.Count -gt 0) {
        $html += "<table><tr><th>File Name</th><th>Attack Chain</th><th>Last Write Time</th><th>Creation Time</th><th>Severity</th></tr>"
        foreach ($finding in $prefetchFindings) {
            $html += "<tr><td><code>$($finding.FileName)</code></td><td>$($finding.Chain)</td><td>$($finding.LastWriteTime)</td><td>$($finding.CreationTime)</td><td><span class='badge badge-high'>High</span></td></tr>"
        }
        $html += "</table>"
    }
    else {
        $html += "<p class='no-findings'>No suspicious Prefetch files found</p>"
    }
    $html += "</section>"

    # Notepad++ Version Section
    $html += @"
        <section>
            <h2>Notepad++ Version Check</h2>
"@
    $nppFindings = $Results["NotepadVersion"]
    if ($nppFindings.Count -gt 0) {
        $html += "<table><tr><th>Installation Path</th><th>Version</th><th>Status</th><th>Recommendation</th></tr>"
        foreach ($finding in $nppFindings) {
            if ($finding.IsVulnerable) {
                $html += "<tr><td><code>$($finding.Path)</code></td><td>$($finding.Version)</td><td><span class='badge badge-medium'>Vulnerable</span></td><td>$($finding.Recommendation)</td></tr>"
            }
            else {
                $html += "<tr><td><code>$($finding.Path)</code></td><td>$($finding.Version)</td><td><span class='badge badge-info'>OK</span></td><td>No action required</td></tr>"
            }
        }
        $html += "</table>"
    }
    else {
        $html += "<p class='no-findings'>No Notepad++ installation found</p>"
    }
    $html += "</section>"

    # Checked Indicators Reference
    $html += @"
        <section>
            <h2>Checked Indicators Reference</h2>
            <h3 style="margin-top: 15px; margin-bottom: 10px;">Malicious Domains</h3>
            <p>$(($Script:Config.Domains | ForEach-Object { "<code>$_</code>" }) -join ", ")</p>

            <h3 style="margin-top: 15px; margin-bottom: 10px;">Malicious IPs</h3>
            <p>$(($Script:Config.IPs | ForEach-Object { "<code>$_</code>" }) -join ", ")</p>

            <h3 style="margin-top: 15px; margin-bottom: 10px;">Mutex</h3>
            <p><code>$($Script:Config.MutexName)</code></p>
        </section>

        <footer>
            <p>Report generated by Notepad++ Supply Chain Attack Triage Script v1.0</p>
            <p>Sources: Kaspersky Securelist, Rapid7</p>
        </footer>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $fullPath -Encoding UTF8

    return $fullPath
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Invoke-Triage {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Notepad++ Supply Chain Attack - Triage Script v1.0" -ForegroundColor Cyan
    Write-Host "  Incident: Lotus Blossom APT (June-November 2025)" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""

    # Verify admin privileges
    if (-not (Test-IsAdmin)) {
        Write-Status "This script requires Administrator privileges. Please run PowerShell as Administrator." -Type Error
        exit 1
    }

    Write-Status "Running with Administrator privileges" -Type Success
    Write-Host ""

    # Verify output path
    if (-not (Test-Path -Path $OutputPath)) {
        Write-Status "Output path does not exist: $OutputPath" -Type Error
        exit 1
    }

    Write-Status "Output path: $OutputPath" -Type Info
    Write-Status "Hash checking: $(if ($SkipHashCheck) { 'Disabled' } else { 'Enabled' })" -Type Info
    Write-Host ""

    # Run all checks
    $results = @{
        SuspiciousPaths = Test-SuspiciousPaths
        DNSCache = Test-DNSCache
        NetworkConnections = Test-NetworkConnections
        Mutex = Test-Mutex
        RegistryPersistence = Test-RegistryPersistence
        Services = Test-MaliciousService
        Prefetch = Test-PrefetchFiles
        NotepadVersion = Test-NotepadVersion
    }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Generating Reports" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""

    # Generate reports
    $jsonPath = New-JSONReport -Results $results -OutputPath $OutputPath
    Write-Status "JSON report saved: $jsonPath" -Type Success

    $htmlPath = New-HTMLReport -Results $results -OutputPath $OutputPath
    Write-Status "HTML report saved: $htmlPath" -Type Success

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Triage Complete" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""

    # Final summary
    $allFindings = @()
    foreach ($category in $results.Keys) {
        $allFindings += $results[$category]
    }

    $criticalCount = ($allFindings | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = ($allFindings | Where-Object { $_.Severity -eq "High" }).Count

    if ($criticalCount -gt 0 -or $highCount -gt 0) {
        Write-Host ""
        Write-Host "  *** POTENTIAL COMPROMISE DETECTED ***" -ForegroundColor Red
        Write-Host "  Critical Findings: $criticalCount" -ForegroundColor Red
        Write-Host "  High Findings: $highCount" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Recommended Actions:" -ForegroundColor Yellow
        Write-Host "  1. Isolate this system from the network immediately" -ForegroundColor Yellow
        Write-Host "  2. Preserve evidence (do not reboot or clean)" -ForegroundColor Yellow
        Write-Host "  3. Contact your incident response team" -ForegroundColor Yellow
        Write-Host "  4. Review the HTML report for detailed findings" -ForegroundColor Yellow
        Write-Host ""
    }
    else {
        Write-Host ""
        Write-Status "No indicators of compromise detected" -Type Success
        Write-Host ""
    }

    return $results
}

# Run the triage
$triageResults = Invoke-Triage
