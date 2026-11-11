##### Basic Enum
```
net user /domain

net user xxx /domain

net group /domain

net group "xx xxx" /domain

net accounts    //passwd policy
```

##### Use of PowerView
```
Get-NetDomain

//Enum user

Get-NetUser

Get-NetUser | select cn

Get-NetUser | select cn,pwdlastset,lastlogon,whencreated ...


//Enum group
Get-NetGroup | select cn

Get-NetGroup "xx xxx" | select member

//Enum machines
Get-NetComputer

//find privi
Find-LocalAdminAccess

//Enum loon session of other host
Get-NetSession -ComputerName xxx

//also use
.\PsLoggedon.exe \\files04

//Enum services
Get-NetUser -SPN | select samaccountname,serviceprincipalname

//for A service
setspn -L xxx_service

//for priv to objectives
Get-ObjectAcl -Identity user_name

we will find some objects
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104

covert multiply ones
"xxx","xxx","xx","xxxx" | Convert-SidToName

//who has Gerneral All privi to this group
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

  GenericAll: Full permissions on object
  GenericWrite: Edit certain attributes on the object
  WriteOwner: Change ownership of the object
  WriteDACL: Edit ACE's applied to object
  AllExtendedRights: Change password, reset password, etc.
  ForceChangePassword: Password change for object
  Self (Self-Membership): Add ourselves to for example a group
```
