# AD-Enum.ps1 - Script di Enumerazione Active Directory
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
            
            Write-SubSection $name
            Write-Finding "DNS" $dns
            Write-Finding "OS" $os
        }
    }
    
    Write-Section "Workstation"
    foreach ($computer in $computers) {
        $os = $computer.Properties.operatingsystem[0]
        if ($os -notmatch "Server") {
            $name = $computer.Properties.name[0]
            $dns = $computer.Properties.dnshostname[0]
            
            Write-SubSection $name
            Write-Finding "DNS" $dns
            Write-Finding "OS" $os
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
    
    try {
        $gpos = LDAPSearch -LDAPQuery "(objectCategory=groupPolicyContainer)"
        
        Write-Section "GPO nel Dominio"
        
        foreach ($gpo in $gpos) {
            $name = $gpo.Properties.displayname[0]
            $path = $gpo.Properties.gpcfilesyspath[0]
            
            Write-SubSection $name
            Write-Finding "Path" $path
        }
    }
    catch {
        Write-Warning "Impossibile enumerare GPO: $_"
    }
}

function Get-DomainShares {
    Write-Banner "SHARE DI RETE"
    
    $computers = LDAPSearch -LDAPQuery "(objectCategory=computer)"
    
    Write-Section "Ricerca Share (potrebbe richiedere tempo...)"
    
    foreach ($computer in $computers) {
        $hostname = $computer.Properties.dnshostname[0]
        if (-not $hostname) { continue }
        
        try {
            $shares = net view "\\$hostname" 2>&1
            if ($shares -notmatch "error|non") {
                Write-SubSection $hostname
                foreach ($line in $shares) {
                    if ($line -match "^\s*(\S+)\s+(Disk|Print)") {
                        Write-Finding "Share" $matches[1]
                    }
                }
            }
        }
        catch {
            # Host non raggiungibile, skip silenzioso
        }
    }
}

function Get-ACLAbuse {
    Write-Banner "POTENZIALI ACL ABUSE"
    
    Write-Section "Ricerca permessi pericolosi su oggetti AD"
    Write-Info "Permessi cercati: GenericAll, GenericWrite, WriteOwner, WriteDACL, Self"
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
        "$domainSID-500"      # Administrator
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
    
    # Enumera utenti
    Write-SubSection "Analisi ACL su Utenti..."
    $users = LDAPSearch -LDAPQuery "(samAccountType=805306368)"
    
    foreach ($user in $users) {
        $userDN = $user.Properties.distinguishedname[0]
        $userName = $user.Properties.samaccountname[0]
        
        try {
            $userEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$userDN")
            $acl = $userEntry.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
            
            foreach ($ace in $acl) {
                $rights = $ace.ActiveDirectoryRights.ToString()
                $sid = $ace.IdentityReference.Value
                
                # Salta SID di sistema e gruppi privilegiati
                if ($sid -in $allIgnored) { continue }
                if ($sid -match '^S-1-5-21-.*-(512|519|518|500)$') { continue }
                
                # Controlla se ha permessi pericolosi
                foreach ($dangerous in $dangerousRights) {
                    if ($rights -match $dangerous) {
                        $principalName = Convert-SIDToName -SID $sid
                        
                        # Ignora se il principal è un gruppo privilegiato
                        if ($principalName -match 'Domain Admins|Enterprise Admins|Schema Admins|SYSTEM|Administrator') { continue }
                        
                        $findings += [PSCustomObject]@{
                            TargetObject = $userName
                            TargetType = "User"
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
    }
    
    # Enumera gruppi
    Write-SubSection "Analisi ACL su Gruppi..."
    $groups = LDAPSearch -LDAPQuery "(objectCategory=group)"
    
    foreach ($group in $groups) {
        $groupDN = $group.Properties.distinguishedname[0]
        $groupName = $group.Properties.cn[0]
        
        try {
            $groupEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$groupDN")
            $acl = $groupEntry.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
            
            foreach ($ace in $acl) {
                $rights = $ace.ActiveDirectoryRights.ToString()
                $sid = $ace.IdentityReference.Value
                
                if ($sid -in $allIgnored) { continue }
                if ($sid -match '^S-1-5-21-.*-(512|519|518|500)$') { continue }
                
                foreach ($dangerous in $dangerousRights) {
                    if ($rights -match $dangerous) {
                        $principalName = Convert-SIDToName -SID $sid
                        
                        if ($principalName -match 'Domain Admins|Enterprise Admins|Schema Admins|SYSTEM|Administrator') { continue }
                        
                        $findings += [PSCustomObject]@{
                            TargetObject = $groupName
                            TargetType = "Group"
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
    }
    
    # Enumera computer
    Write-SubSection "Analisi ACL su Computer..."
    $computers = LDAPSearch -LDAPQuery "(objectCategory=computer)"
    
    foreach ($computer in $computers) {
        $compDN = $computer.Properties.distinguishedname[0]
        $compName = $computer.Properties.name[0]
        
        try {
            $compEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$compDN")
            $acl = $compEntry.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
            
            foreach ($ace in $acl) {
                $rights = $ace.ActiveDirectoryRights.ToString()
                $sid = $ace.IdentityReference.Value
                
                if ($sid -in $allIgnored) { continue }
                if ($sid -match '^S-1-5-21-.*-(512|519|518|500)$') { continue }
                
                foreach ($dangerous in $dangerousRights) {
                    if ($rights -match $dangerous) {
                        $principalName = Convert-SIDToName -SID $sid
                        
                        if ($principalName -match 'Domain Admins|Enterprise Admins|Schema Admins|SYSTEM|Administrator') { continue }
                        
                        $findings += [PSCustomObject]@{
                            TargetObject = $compName
                            TargetType = "Computer"
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
    }
    
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
            if ($sid -match '^S-1-5-21-.*-(512|519|518|500)$') { continue }
            
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
    
    # Mostra risultati
    if ($findings.Count -gt 0) {
        Write-Section "PERMESSI PERICOLOSI TROVATI!"
        
        # Raggruppa per principal
        $groupedFindings = $findings | Group-Object -Property Principal
        
        foreach ($group in $groupedFindings) {
            Write-Warning "$($group.Name) ha permessi pericolosi:"
            
            foreach ($finding in $group.Group) {
                $color = if ($finding.Dangerous -eq 'GenericAll' -or $finding.Dangerous -eq 'DCSync') { 'Red' } else { 'Yellow' }
                Write-Host "        [$($finding.TargetType)] " -ForegroundColor Cyan -NoNewline
                Write-Host "$($finding.TargetObject)" -ForegroundColor White -NoNewline
                Write-Host " -> " -NoNewline
                Write-Host "$($finding.Dangerous)" -ForegroundColor $color
            }
            Write-Host ""
        }
        
        Write-Section "POSSIBILI ATTACCHI"
        
        $genericAllFindings = $findings | Where-Object { $_.Dangerous -eq 'GenericAll' }
        $dcSyncFindings = $findings | Where-Object { $_.Dangerous -eq 'DCSync' }
        $writeFindings = $findings | Where-Object { $_.Dangerous -match 'Write|Self' }
        
        if ($genericAllFindings) {
            Write-Info "GenericAll trovato - Puoi:"
            Write-Host "        - Cambiare password dell'oggetto target" -ForegroundColor White
            Write-Host "        - Aggiungere utenti a gruppi" -ForegroundColor White
            Write-Host "        - Modificare qualsiasi attributo" -ForegroundColor White
            Write-Host ""
        }
        
        if ($dcSyncFindings) {
            Write-Warning "DCSync Rights trovato - Puoi estrarre TUTTI gli hash!"
            Write-Host "        mimikatz # lsadump::dcsync /user:Administrator" -ForegroundColor Yellow
            Write-Host ""
        }
        
        if ($writeFindings) {
            Write-Info "Write permissions trovate - Puoi:"
            Write-Host "        - WriteDacl: Modificare i permessi" -ForegroundColor White
            Write-Host "        - WriteOwner: Diventare proprietario" -ForegroundColor White
            Write-Host "        - Self: Aggiungerti a gruppi" -ForegroundColor White
            Write-Host ""
        }
        
    } else {
        Write-Info "Nessun permesso pericoloso trovato su utenti non privilegiati"
    }
    
    Write-Section "Comandi utili (se hai PowerView)"
    Write-Host "    # Trova permessi GenericAll" -ForegroundColor Yellow
    Write-Host '    Get-ObjectAcl -Identity "gruppo" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights' -ForegroundColor Gray
    Write-Host ""
    Write-Host "    # Sfrutta GenericAll su gruppo" -ForegroundColor Yellow
    Write-Host '    net group "NomeGruppo" tuouser /add /domain' -ForegroundColor Gray
    Write-Host ""
    Write-Host "    # Sfrutta GenericAll su utente (cambia password)" -ForegroundColor Yellow
    Write-Host '    net user targetuser NuovaPassword123! /domain' -ForegroundColor Gray
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
    
    return $adminAccess
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

function Get-InterestingTargets {
    Write-Banner "TARGET INTERESSANTI"
    
    Write-Section "Analisi Attack Path"
    
    # Trova admin
    $admins = @()
    $adminQuery = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Domain Admins))"
    if ($adminQuery) {
        $members = $adminQuery.Properties.member
        foreach ($m in $members) {
            if ($m -match "CN=([^,]+)") {
                $admins += $matches[1]
            }
        }
    }
    
    Write-SubSection "Domain Admins identificati"
    foreach ($admin in $admins) {
        Write-Finding "Admin" $admin -Important
    }
    
    Write-Host ""
    Write-Info "Prossimi passi suggeriti:"
    Write-Host "    1. Trova dove sono loggati i Domain Admins" -ForegroundColor White
    Write-Host "    2. Verifica se hai admin access su quei computer" -ForegroundColor White
    Write-Host "    3. Estrai credenziali con Mimikatz" -ForegroundColor White
    Write-Host "    4. Esegui lateral movement" -ForegroundColor White
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
        Get-InterestingTargets
    }
    
    # Riepilogo finale
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    Write-Banner "RIEPILOGO ENUMERAZIONE"
    Write-Host "[*] Completato in: $($duration.TotalSeconds.ToString('0.00')) secondi" -ForegroundColor Green
    Write-Host ""
    Write-Host "[!] PROSSIMI PASSI CONSIGLIATI:" -ForegroundColor Yellow
    Write-Host "    1. Controlla utenti AS-REP Roastable" -ForegroundColor White
    Write-Host "    2. Controlla service account Kerberoastable" -ForegroundColor White
    Write-Host "    3. Verifica computer con admin access" -ForegroundColor White
    Write-Host "    4. Trova dove sono loggati i Domain Admins" -ForegroundColor White
    Write-Host "    5. Cerca credenziali in SYSVOL/GPP" -ForegroundColor White
    Write-Host "    6. Testa password spray con utenti trovati" -ForegroundColor White
    Write-Host ""
}

#endregion

# Se eseguito direttamente, lancia l'enumerazione
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-ADEnum -Full
}
