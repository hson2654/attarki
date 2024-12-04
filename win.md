sysdm.cpl   #computer config
dsa.msc  #AD mgr,add delete user
net userusername passwd /add /domain     #add domain user
net group "Domain Admins" clare /add /domain   #add a user to dmmain admin group
gpupdate /force      #update the gp group policy. 

net share sharename=c:\foldername          # share a folder
setspn HTTP/nameofhost(sql.inmy.com) inmy\sqladmin
