```
Because Kerberos is very time sensitive you should configure your client machines to use one of your domain controllers as an NTP server. 
The DigitalOcean link further down recommends using ntp instead of systemd-timesyncd due to some optimized "smoothing" algorithms that 
prevent weird clock jumps that can break some applications "timestamp in the future, session aborted, etc".
If on a system with systemd and timedatectl
```
```
Run sudo edit(nano) /etc/systemd/timesyncd.conf and uncomment NTP= and set your list of space separated servers to try
```
```
    Example /etc/systemd/timesyncd.conf
    
    [Time]
    NTP=domaincontroller.pithoslabs.com
    FallbackNTP=ntp.ubuntu.com pool.ntp.org
```
Then sudo systemctl restart systemd-timesyncd 
  //to put the new changes into effect without rebooting.

sudo systemctl restart timers.target

then, sudo ntpdate IP

