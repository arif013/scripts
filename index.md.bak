# ADCS to privesc from virtual and network service accounts to local system

We will see how it is possible to elevate our privileges to NT AUTHORITY\SYSTEM from virtual and network service accounts of a domain-joined machine (for example from a webshell on a Windows server) using ADCS

## ADCS 101
### Public Key Infrastructure
A PKI (Public Key Infrastructure) is an infrastructure used to create, manage, and revoke certificates as well as public/private keys.

Active Directory Certificate Service (ADCS) is the Microsoft implementation of PKI infrastructure in an Active Directory/Windows environment. This service was added in Windows Server 2000, is easy to install and fully integrates itself with different Microsoft services. For example, here is a non exhaustive list of the different usages of PKI infrastructure:

- TLS certificates (HTTPS / LDAPS / RDP)
- Signing binaries, PowerShell scripts or even drivers
- User authentication
- File system encryption
- Certificate templates

To simplify the creation of certificates in Active Directory, there are certificate templates.

These templates are used to specify specific parameters and rights related to the certificate that will be issued from them. For example, in a certificate template we can set the following parameters:

- Period of validity
- Who has the right to enroll
- How we can use these certificates also called Extended Key Usage (EKU)
By default, when the ADCS role is installed, different default templates are provided. One of them is the Machine template which can be requested by any machine account that is a member of the Domain Computers domain group:
![](https://sensepost.com/img/pages/blog/2022/certpotato-using-adcs-to-privesc-from-virtual-and-network-service-accounts-to-local-system/Pasted-image-20221101195224.png)

Example of a template
### Request a certificate
A certificate request is always sent to the ADCS server. It is based on a template and requires authentication.

If the request is approved by the certification authority, then the certificate is delivered and usable in line with the EKUs defined in the template.

### User authentification (PKINIT)
Kerberos supports asymmetric authentication, that is PKINIT authentication. Instead of encrypting the timestamp during pre-authentication (KRB_AS_REQ) with a password derivative (NT hash for RC4 encryption), it is possible to sign the timestamp with the private key associated with a valid certificate.

However, for PKINIT authentication to be feasible there are several conditions, one of these conditions is that the obtained certificate must have one of the following 5 EKUs:

- Client Authentification
- PKINIT Client Authentification
- Smart Card Logon
- Any Purpose
- SubCA

## Real Life Scenario from a Pentest
we have three machines:

- DC (192.168.1.1): the domain controller (Windows server 2022 fully updated) on which the certificate authority is also located
- IIS (192.168.1.2): an application server (Windows server 2022 fully updated) on which the IIS service is installed
- A Kali Linux machine (192.168.1.3)

### We got intial foothold by RCE
we have successfully uploaded a web shell on the IIS server. If we run the whoami command we can see the following result:

![](https://sensepost.com/img/pages/blog/2022/certpotato-using-adcs-to-privesc-from-virtual-and-network-service-accounts-to-local-system/Pasted-image-20221101133049.png)
- By default the service account used is iis apppool\defaultaappool a Microsoft virtual account

If we try to enumerate a remote share from our webshell:
![](https://sensepost.com/img/pages/blog/2022/certpotato-using-adcs-to-privesc-from-virtual-and-network-service-accounts-to-local-system/Pasted-image-20221101131706.png)
We will see that it is not the defaultapppool account that will try to authenticate to our server but the IIS$ machine account:
![](https://sensepost.com/img/pages/blog/2022/certpotato-using-adcs-to-privesc-from-virtual-and-network-service-accounts-to-local-system/Pasted-image-20221101132146.png)

