sysdm.cpl   #computer config
dsa.msc  #AD mgr,add delete user
net userusername passwd /add /domain     #add domain user
net group "Domain Admins" clare /add /domain   #add a user to dmmain admin group
gpupdate /force      #update the gp group policy. \n

net share sharename=c:\foldername          # share a folder
setspn HTTP/nameofhost(sql.inmy.com) inmy\sqladmin


Set-ExecutionPolicy RemoteSigned   #when script is restricted to run

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass  #When srcpit is not digital signed.

#Powerview to emulate the domain infor
  Import-Module .\PowerView.ps1
  Get-NetDOmain


  Get-NetUser | select cn

  Get-NetGroup
  Get-NetComputer

  Find-LocalAdminAccess  #important

  Get_NetSession -ComputerName $computerName
  

  
