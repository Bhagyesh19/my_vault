---
type: knowledge_base
tags:
  - active_directory
  - enumertation
  - recon
---
[[pentest_template]]
Updated_latest
##  Enumeration Checklist:

1. Users and Groups (Domain/Local)
2. Sessions
3. Domain Object's Access Control List (ACLS)


---
## Manual Enumeration

#### Enumeration using powershell commands.

```powershell
net user /domain                        # Lists domain users
net user [username] /domain             # Prints domain user's info
net group /domain                       # Lists domain groups
net group [group_name] /domain          # Prints info about specified domain's group
net user [user_name] [new_password] /domain              # To change password of the specified user if have privileges to do that over that user object
Get-LocalUser                           # Lists all local users
Get-LocalGroup                          # Lists all local groups
```

####  Enumeration of Service Principal Name (SPN)

```powershell
setspn -L [service_account_name]        # Enumerate SPN for specified service account name
Get-NetUser -SPN          # Enumerate SPN using powerview cmdlet
```
 
#### Enumeration using powerview.ps1 script

> *Use -Credential option in powerview commands if you want to run the command as another user. It takes PSCredentials object as argument. Below is commands to create PSCredentials object*
```powershell
$SecPassword = ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential('CORP\robert', $SecPassword)
```
  
```powershell
Import-Module .\Powerview.ps1
Get-NetUser                       # Lists domain users. Alias for Get-DomainUser.
Get-NetGroup                      # Lists domain groups. Alias for Get-DomainGroup.
Get-NetLocalGroup                 # Lists all local group on cuttent machine.
Get-NetComputer                   # Lists all domain computers. Alias for Get-DomainComputer
Find-LocalAdminAccess             # Finds machines on the local domain where the current user has local administrator access.
Get-NetSession                    # Returns session information for the local (or a remote) machine.
Get-NetSession -ComputerName [computer_name]                   # Returns session information for the local (or a remote) machine.
Get-ObjectAcl -Identity [object_name]         # Returns the ACLs associated with a specific active directory object.
Convert-SidToName                             # Converts Security Identifier to name of the object
Find-DomainShare                  # Finds computer shares on the domain. if -CheckShareAccess passed, it will only list share to which current user has read access.
Find-InterestingDomainAcl         # Finds object ACLs in the current (or specified) domain with modification rights set to non-built in objects.
Find-DomainLocalGroupMember -GroupName "Administrators"       # Enumerates the members of specified local group (default administrators) for all the targeted machines on the current (or specified) domain.
Get-DomainComputer | Get-NetLoggedon      # Returns all logged on users for all computers in the domain.
```
 
#### Created custom script using .NET classes too enumerate AD environment as below

> *This custom script can be useful when it's not possible to use powerview or any other tools to enumerate AD environment*

```powershell
 function LDAPSearch {
    param (
    [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

	$DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

	$DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()
}
```
    - PDC = Primary Domain Controller
    - adsi = *Active Directory Services Interface* (COM interface)

- Info: 
	- Remote Server Administration Tools (RSAT) provide cmdlets like Get-ADUser to communication on domain. But they are only pre-installed on domain controller most of the time. So We can create custom scripts to enumerate AD environment from non domain controller machine using .NET Classes to communicate on domain. This also does not requires any adminstrator privileges.
	- Should always use Primary Domain Controller for LDAP quering as it contains most updated when multiple domain controllers configured in AD environment

- Need to import script to memory as below:
```powershell
Import-Module .\\ad_enum.ps1`
```

- We can use this script like below:
	- To enumerate list of domain users: `LDAPSearch -LDAPQuery "(samAccountType=805306368)"`
    - To enumerate specific group (in this case named as "Sales Department"): `LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"`


---


## Automated Enumeration

### Using Bloodhound and Sharphound.

#### Collect data using sharphound.ps1 on the target system
```powershell
Import-Module .\Sharphound.ps1

Get-Help Invoke-BloodHound -full          # Get all help options for Invoke-BloodHound command

## Invoke-BloodHound options:
#### -CollectionMethods All                           :   Performs all collection methods except for GPOLocalGroup.
#### -OutputDirectory [output_directory_path]         :   Specify path where to store resultant zip
#### -OutputPrefix [prefix_for_resultant_zip]         :   Prefix to add in name of resultant zip file
#### To see more options we can use Get-Help cmdlet or sharphound documentation
Invoke-BloodHound -CollectionMethods All -OutputDirectory [output_directory_path] -OutputPrefix [prefix_for_resultant_zip]

### Enumerates ad environment for specified CollectionMethods in loop with duration given as -LoopDuration and at interval given as -LoopInterval
Invoke-BloodHound -CollectionMethods [collection_method] -Loop -LoopDuration [HH:MM:SS] -LoopInterval [HH:MM:SS]
```

#### Analyze sharphound gathered data using bloodhound

-  Need to start neo4j server
 ```bash
sudo neo4j start          # Login to neo4j on given localhost port given in output and configure database
```

- Start bloodhound and configure it to use neo4j database(it detects database endpoint by itself mostly) and credentials. We can run custom queries too.
	- [ ] Need to add some custom bloodhound queries.

> [!info]
> We can also use bloodhound.py to collect data but it's not officially supported by Bloodhound development team.



