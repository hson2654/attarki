whoami /groups
##### Basic info of host

powershell
```
get-localuser
Get-LocalGroup

Get-LocalGroupMember adminteam

ipconfig /all

route print

netstat -ano
```

Applications
`Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`

`Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`

Process
`Get-Process`

search for password manager databases
`Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue`

search for sensitive information in configuration files of XAMPP
`Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue`

`runas /user:backupadmin cmd`

Cmdlet to obtain a list of commands executed in the past of PS
`Get-History`

`(Get-PSReadlineOption).HistorySavePath`
Clear-History does not clear the command history recorded by PSReadline. se **Get-PSReadlineOption** to obtain information from the PSReadline module

analyze the transcript file
`type C:\Users\Public\Transcripts\transcript01.txt`

in Ps with credential login another machine
`Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred`
