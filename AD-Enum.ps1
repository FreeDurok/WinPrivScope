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
    
    return $DirectorySearcher.FindAll()
}

#endregion

#region Funzioni di Enumerazione

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
    $serviceAccounts = @()
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
        
        # Controlla service account
        if ($username -match "svc|service|sql|iis|backup|admin") {
            $serviceAccounts += $username
        }
    }
    
    Write-Finding "Totale Utenti" $userCount
    
    Write-Section "Utenti Privilegiati (IMPORTANTE!)"
    if ($adminUsers.Count -gt 0) {
        foreach ($admin in ($adminUsers | Sort-Object -Unique)) {
            Write-SubSection $admin
            # Ottieni dettagli admin
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
    
    Write-Section "Potenziali Service Account"
    if ($serviceAccounts.Count -gt 0) {
        foreach ($svc in ($serviceAccounts | Sort-Object -Unique)) {
            Write-SubSection $svc
        }
    } else {
        Write-Info "Nessun service account identificato"
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
        
        # Escludi krbtgt
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
        # Fallback usando net accounts
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
    
    Write-Section "Ricerca permessi pericolosi..."
    Write-Info "Per un'analisi completa degli ACL, usa BloodHound o PowerView"
    Write-Info "Comandi utili:"
    Write-Host ""
    Write-Host "    # PowerView - Trova permessi GenericAll" -ForegroundColor Yellow
    Write-Host '    Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|WriteProperty|WriteDacl"}' -ForegroundColor Gray
    Write-Host ""
    Write-Host "    # PowerView - Trova DCSync rights" -ForegroundColor Yellow
    Write-Host '    Get-ObjectAcl -DistinguishedName "DC=corp,DC=com" -ResolveGUIDs | Where-Object {($_.ObjectType -match "replication")}' -ForegroundColor Gray
}

#endregion

#region Main Function

function Invoke-ADEnum {
    param(
        [switch]$Quick,
        [switch]$Full
    )
    
    $startTime = Get-Date
    
    Write-Host "[*] Avvio enumerazione: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
    Write-Host "[*] Utente corrente: $env:USERDOMAIN\$env:USERNAME" -ForegroundColor Green
    Write-Host ""
    
    # Esegui enumerazione
    Get-DomainInfo
    Get-PasswordPolicy
    Get-DomainUsers
    Get-DomainGroups
    Get-SPNs
    Get-DomainComputers
    
    if ($Full) {
        Get-GPOs
        Get-DomainShares
        Get-ACLAbuse
    }
    
    # Riepilogo finale
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    Write-Host "RIEPILOGO ENUMERAZIONE"
    Write-Host "[*] Completato in: $($duration.TotalSeconds.ToString('0.00')) secondi" -ForegroundColor Green
    Write-Host ""
    Write-Host "[!] PROSSIMI PASSI CONSIGLIATI:" -ForegroundColor Yellow
    Write-Host "    1. Controlla utenti AS-REP Roastable" -ForegroundColor White
    Write-Host "    2. Controlla service account Kerberoastable" -ForegroundColor White
    Write-Host "    3. Enumera permessi con BloodHound/PowerView" -ForegroundColor White
    Write-Host "    4. Cerca credenziali in SYSVOL/GPP" -ForegroundColor White
    Write-Host "    5. Testa password spray con utenti trovati" -ForegroundColor White
    Write-Host ""
}

#endregion

# Se eseguito direttamente, lancia l'enumerazione
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-ADEnum -Full
}
