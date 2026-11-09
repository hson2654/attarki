##### Basic Enum
```
net user /domain

net user xxx /domain

net group /domain

net group "xx xxx" /domain
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
```
