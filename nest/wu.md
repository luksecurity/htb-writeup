# HTB - Nest

![[OSCP/OSCP-like/HTB/Windows/22sh list/nest/img/htb-card.png]]

## Reconnaissance

### Nmap base

```
PORT    STATE SERVICE       VERSION
445/tcp open  microsoft-ds?
```

### Nmap full

```
PORT     STATE SERVICE       VERSION
445/tcp  open  microsoft-ds?
4386/tcp open  unknown
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe:
|     Reporting Service V1.2
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest, SIPOptions:
|     Reporting Service V1.2
|     Unrecognised command
|   Help:
|     Reporting Service V1.2
|     This service allows users to run queries against databases using the legacy HQK format
|     AVAILABLE COMMANDS ---
|     LIST
|     SETDIR <Directory_Name>
|     RUNQUERY <Query_ID>
|     DEBUG <Password>
|_    HELP <Command>
```

## Enumération

### Port 4386/tcp - HQK

On peut énumérer ce service à l'aide de `telnet`. La commande `help` permet d'afficher les commandes disponibles.

`telnet 10.129.200.216 4386`

![[4386-telnet-enum.png]]

Si on utilise la première commande `list`, on retrouve les dossiers du répertoire courant

![[4386-telnet-list.png]]

La commande `runquery` nous indique que la configuration de la base de données n'est pas valide.

![[4386-telnet-runq.png]]

Enfin la commande `setdir` est intéressante par elle nous permet  de sélectionner un nouveau répertoire où les requêtes peuvent être exécuter comme on peut le voir avec la commande `help setdir`. On peut essayer de se déplacer sur le répertoire des utilisateurs `C:\Users\`

![[4386-telnet-setd.png]]

Ca fonctionne, mais si j'essaye de me rendre à nouveau dans le répertoire des utilisateurs, j'obtiens un `access denied` où encore que le répertoire n'existe pas.

![[4386-telnet-denied.png]]

Il reste une dernière commande disponible `debug` qui prend en argument un mot de passe. Avec la commande `help debug`, ce mode permet l'utilisation de commandes supplémentaires pour le troubleshooting réseau ou les problème de configuration. Si on tente un mot de passe au hasard, on obtient le message `Invalid password entered`.

![[4386-telnet-debug.png]]

### Port 445/tcp - SMB

On commence à faire une énumération pour trouver le domaine à l'aide de netexec et on retrouve `HTB-NEST` que l'on ajoute dans /etc/hosts

![[445-dom.png]]

Si on tente le SMB null session ça ne donne rien, en revanche on peut lister les shares avec le SMB guest logon

`netexec smb 10.129.200.183 -u 'luks' -p '' --shares`

![[445-smb-guest.png]]

On retrouve deux partages en lecture :
- Data
- Users

On commence par le premier et on retrouve 4 dossiers :
- IT
- Production
- Reports
- Shared

On a accès uniquement au dossier `Shared` et l'on retrouve deux autres dossiers :
- Maintenance
- Templates

`smbclient --no-pass //HTB-NEST/Data`

![[445-shared.png]]

Dans le premier dossier `Maintenance`, on retrouve un fichier `Maintenance Alerts.txt` que l'on récupère

`mget "Maintenance Alerts.txt"`

![[445-shared-alert.png]]

Dans le second dossier `Templates`, on retrouve deux autres dossiers :
- HR
- Marketing

Dans le dossier `HR`, on retrouve un fichier `Welcome Email.txt` que l'on récupère

`mget "Welcome Email.txt"`

![[445-shared-welcome.png]]

L'autre dossier est vide. le fichier `Maintenance Alerts.txt` n'est pas intéressant, en revanche l'autre nous permet de trouver des creds `TempUser:welcome2019`.

![[welcome-creds.png]]

Avant de poursuivre on va aussi récupérer la liste des utilisateurs en faisant un bruteforce RID

`netexec smb HTB-NEST -u 'luks' -p '' --rid-brute`

![[445-nxc-bruterid.png]]

Si on utilise ces creds pour lister les shares de l'utilisateur avec netexec, on a maintenant accès au share `Secure$`

`netexec smb 10.129.200.183 -u 'TempUser' -p 'welcome2019' --shares`

![[445-secure$.png]]

On continue l'énumération des shares en commençant par `Users`, on a accès uniquement aux répertoires de `TempUser` et l'on retrouve un autre fichier texte `New text Document.txt` que l'on récupère

`smbclient -U 'TempUser%welcome2019' //HTB-NEST/Users`

![[445-home-tempuser.png]]

On en profite aussi pour ajouter les autres utilisateurs à notre Wordlist

![[445-share-wordlistadd.png]]

Le fichier récupéré est vide, on peut à nouveau utiliser le password spraying pour voir s'il y a du password reuse. Et effectivement c'est le cas, le mot de passe `welcome2019` fonctionne aussi pour les utilisateurs `L.Frost` et `R.Thompson` qu'on ajoute dans notre wordlists creds.txt

`netexec smb HTB-NEST -u users.lst -p pass.lst --continue-on-success`

![[445-passreuse.png]]

Avant d'explorer cette piste, on va revenir sur l'utilisateur `TempUser` pour énumérer le share `Secure$`

`smbclient -U 'TempUser%welcome2019' //HTB-NEST/Secure$`

On retrouve trois shares :
- Finance
- HR
- IT

Mais on a accès à aucun des répertoires

![[445-secure$-denied.png]]

Et on continue avec l'utilsateur `TempUser` sur le share Data

`smbclient -U 'TempUser%welcome2019' //HTB-NEST/Data`

Cette fois on a accès au répertoire `IT` :)

![[445-share-tempuser-it.png]]

Seul le dossier `Configs` contient des choses

![[445-data-temp-config.png]]

On va tout récupérer d'un coup

```
recurse
prompt off
mget *
```

![[445-grab-recurse.png]]

Sous `NotepadPlusPlus`, à la fin du fichier `config.xml`, on retrouve des paths intéressants

```
		<File filename="C:\windows\System32\drivers\etc\hosts" />
        <File filename="\\HTB-NEST\Secure$\IT\Carl\Temp.txt" />
        <File filename="C:\Users\C.Smith\Desktop\todo.txt" />
```

![[audit-np++.png]]

Dans le dossier `RU Scanner`, il y a un fichier `RU_config.xml` qui contient les credentials de `C.Smith` en base64 en lien avec le port 389/LDAP

`fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=`

![[audit-ru_scanner.png]]

Dans le fichier notepad++, on retrouve un path intéressant `\\HTB-NEST\Secure$\IT\Carl\Temp.txt`. On va essayer de se connecter à ce share à nouveau

`smbclient -U 'TempUser%welcome2019' //HTB-NEST/Secure$`

Ca fonctionne et on obtient un accès à`\\HTB-NEST\Secure$\IT\Carl\` malgré le fait qu'on ne peut pas accéder à IT à la base. On retrouve trois dossiers :
- Docs
- Reports
- VB Projects

![[445-carl-secure-access.png]]

On a accès à aucun dossier sauf `VB Projects` et on retrouve deux dossiers :
- Production
- WIP

![[445-secure-vbpro.png]]

On a accès qu'au dossier `WIP` et on retrouve un dossier `RU`

![[445-secure-ru.png]]

Dans ce dossier, on retrouve un fichier `RUScanner.sln` et un dossier du même nom

![[445-secure-ruscanner.png]]

Dans ce dossier, on retrouve plusieurs fichiers que l'on va récupérer de la même manière que tout à l'heure

![[445-secure-grab.png]]

Le fichier `Utils.vb` est particulièrement intéressant car il contient une fonction `DecryptString()`. Voici le code complet 

```vb
Imports System.Text
Imports System.Security.Cryptography
Public Class Utils

    Public Shared Function GetLogFilePath() As String
        Return IO.Path.Combine(Environment.CurrentDirectory, "Log.txt")
    End Function

    Public Shared Function DecryptString(EncryptedString As String) As String
        If String.IsNullOrEmpty(EncryptedString) Then
            Return String.Empty
        Else
            Return Decrypt(EncryptedString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)
        End If
    End Function

    Public Shared Function EncryptString(PlainString As String) As String
        If String.IsNullOrEmpty(PlainString) Then
            Return String.Empty
        Else
            Return Encrypt(PlainString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)
        End If
    End Function

    Public Shared Function Encrypt(ByVal plainText As String, _
                                   ByVal passPhrase As String, _
                                   ByVal saltValue As String, _
                                    ByVal passwordIterations As Integer, _
                                   ByVal initVector As String, _
                                   ByVal keySize As Integer) _
                           As String

        Dim initVectorBytes As Byte() = Encoding.ASCII.GetBytes(initVector)
        Dim saltValueBytes As Byte() = Encoding.ASCII.GetBytes(saltValue)
        Dim plainTextBytes As Byte() = Encoding.ASCII.GetBytes(plainText)
        Dim password As New Rfc2898DeriveBytes(passPhrase, _
                                           saltValueBytes, _
                                           passwordIterations)
        Dim keyBytes As Byte() = password.GetBytes(CInt(keySize / 8))
        Dim symmetricKey As New AesCryptoServiceProvider
        symmetricKey.Mode = CipherMode.CBC
        Dim encryptor As ICryptoTransform = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes)
        Using memoryStream As New IO.MemoryStream()
            Using cryptoStream As New CryptoStream(memoryStream, _
                                            encryptor, _
                                            CryptoStreamMode.Write)
                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length)
                cryptoStream.FlushFinalBlock()
                Dim cipherTextBytes As Byte() = memoryStream.ToArray()
                memoryStream.Close()
                cryptoStream.Close()
                Return Convert.ToBase64String(cipherTextBytes)
            End Using
        End Using
    End Function

    Public Shared Function Decrypt(ByVal cipherText As String, _
                                   ByVal passPhrase As String, _
                                   ByVal saltValue As String, _
                                    ByVal passwordIterations As Integer, _
                                   ByVal initVector As String, _
                                   ByVal keySize As Integer) _
                           As String

        Dim initVectorBytes As Byte()
        initVectorBytes = Encoding.ASCII.GetBytes(initVector)

        Dim saltValueBytes As Byte()
        saltValueBytes = Encoding.ASCII.GetBytes(saltValue)

        Dim cipherTextBytes As Byte()
        cipherTextBytes = Convert.FromBase64String(cipherText)

        Dim password As New Rfc2898DeriveBytes(passPhrase, _
                                           saltValueBytes, _
                                           passwordIterations)

        Dim keyBytes As Byte()
        keyBytes = password.GetBytes(CInt(keySize / 8))

        Dim symmetricKey As New AesCryptoServiceProvider
        symmetricKey.Mode = CipherMode.CBC

        Dim decryptor As ICryptoTransform
        decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes)

        Dim memoryStream As IO.MemoryStream
        memoryStream = New IO.MemoryStream(cipherTextBytes)

        Dim cryptoStream As CryptoStream
        cryptoStream = New CryptoStream(memoryStream, _
                                        decryptor, _
                                        CryptoStreamMode.Read)

        Dim plainTextBytes As Byte()
        ReDim plainTextBytes(cipherTextBytes.Length)

        Dim decryptedByteCount As Integer
        decryptedByteCount = cryptoStream.Read(plainTextBytes, _
                                               0, _
                                               plainTextBytes.Length)

        memoryStream.Close()
        cryptoStream.Close()

        Dim plainText As String
        plainText = Encoding.ASCII.GetString(plainTextBytes, _
                                            0, _
                                            decryptedByteCount)

        Return plainText
    End Function

End Class
```

Ne connaissant pas le VB.NET, je vais transformer le code en python avec quelques modifications pour déchiffrer le mot de passe que l'on a récupérer précédemment en le passant en argument à mon script.

```python
#!/usr/bin/env python3

import sys
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
from base64 import b64decode

class Utils:
    @staticmethod
    def decrypt_string(encrypted_string, pass_phrase, salt_value, password_iterations, init_vector, key_size):
        if not encrypted_string:
            return ""
        else:
            key_bytes = PBKDF2(pass_phrase, salt_value, key_size // 8, password_iterations)
            cipher = AES.new(key_bytes, AES.MODE_CBC, init_vector)
            decrypted_text = cipher.decrypt(b64decode(encrypted_string))
            return unpad(decrypted_text, AES.block_size).decode()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 decode.py <cipher_text>")
        sys.exit(1)

    cipher_text = sys.argv[1]
    pass_phrase = b'N3st22'
    salt_value = b'88552299'
    password_iterations = 2
    init_vector = b'464R5DFA5DL6LE28'
    key_size = 256

    decrypted_string = Utils.decrypt_string(cipher_text, pass_phrase, salt_value, password_iterations, init_vector, key_size)
    print("Decrypted string:", decrypted_string)
```

Si on teste notre script, ça fonctionne parfaitement et on récupère le mot de passe `xRxRxPANCAK3SxRxRx`

![[decode_strings.png]]

De nouveau avec netexec, on peut énumérer les shares de `C.Smith` et on obtient un accès à son share `Users`. On sait déjà qu'il y a un fichier `todo.txt` puisqu'on l'a vu dans le fichier `config.xml` de NotepadPlusPlus.

![[445-smb-csmith-share.png]]

On se connecte à son share et on peut récupérer le premier flag

![[445-csmith-userflag.png]]

## Elévation de privilèges - Administrator

Dans le share de C.Smith, on retrouve un dossier `HQK Reporting`, qui nous fait penser à notre énumérer initiale sous le port `4386`.

![[hqk-csmith-share.png]]

Je commence par récupérer tous les fichiers

![[hqk-csmith-recurse.png]]

Dans le fichier `HQK_Config_Backup.xml`, on retrouve un path `C:\Program Files\HQK\ALL QUERIES`.

![[hqk-backup.png]]

Dans le dossier `AD Integration Module`, on récupère un fichier exécutable `HqkLdap.exe`.

![[pe-binary.png]]

Enfin le fichier `Debug Mode Password` est vide

![[debug_empty_password.png]]

Toutefois, on a la possibilité d'afficher les informations détaillées sur les fichiers avec la commande `allinfo` via SMB. On a pas besoin de toutes les données, ce qui va nous intéresser ce sont les flux de données, les streams sont des fonctionnalités du système de fichier NTFS qui permettent de stocker des données supplémentaires dans un fichier par rapport au contenu principal. Ici on a deux :
- `stream: [::$DATA], 0 bytes` -> représente le flux de données principale avec 0 octet, c'est celui-ci que l'on voit quand on ouvre le fichier normalement.
- `stream: [:Password:$DATA], 15 bytes` -> représente le flux de données nommé `Password` avec 15 octets.

On peut imaginer que le stream `Password` contient un mot de passe pour accéder au mode debug de l'application HQK, ce qui pourrait nous permettre d'accéder à d'autres fonctionnalités d'énumération.

Il est possible de récupérer ce mot de passe avec la commande suivante sous la forme `<filename>:<stream_name>`.

`get "Debug Mode Password:Password"`

![[debug_stream_grab.png]]

Si maintenant on ouvre le fichier, on récupère un mot de passe `WBQ201953D8w`.

![[debug_pass.png]]

Maintenant qu'on dispose du mot de passe pour accéder à la fonctionnalité `debug` d'HQK, on peut se reconnecter avec telnet pour voir ce qu'on trouve. Ca fonctionne et on obtient `Debug mode enabled`. Et si on tape `help`, on obtient plus de commandes disponibles que lors de l'énumération initiale, notamment `service`, `session`, `showquery`.

![[4386-debug-enabled.png]]

La commande `service` nous permet d'obtenir des informations sur le serveur HQK comme la version, l'utilisateur sous lequel le programme est exécuté, le répertoire de requête initiale `C:\Program Files\HQK\ALL QUERIES` etc.

![[4386-debug-service.png]]

La commande `session` nous permet de récupérer d'autres informations comme l'ID de la session, le timestamp de démarrage etc.

![[4386-debug-session.png]]

Si maintenant on utilise `setdir` pour se rendre sous `C:\Program Files\HQK\`, on accède à d'autres répertoires notamment `LDAP` qui semble juicy

![[4386-debug-setd.png]]

Si on se rend à l'intérieur, on retrouve un fichier `Ldap.conf` et si on l'énumère avec `showquery 2`, on retrouve des informations sur l'utilisateur `Administator` et notamment un mot de passe `yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4=`.

![[4386-debug-ldap.png]]

Il ressemble beaucoup à celui qu'on a retrouvé dans le fichier de configuration d'RU Scanner.

![[ldap_pass_b64.png]]

Si je tente de déchiffrer le mot de passe avec notre script python, on obtient une erreur, un problème de padding.

![[ldap_pass_pad.png]]

Il nous reste notre binaire `HqkLdap.exe` que l'on va transférer sur notre VM Windows pour le décompiler avec `DNSpy` pour un peu ce qu'il y a sous le capot. On commence par regarde la fonction `main()`

![[dnspy-main.png]]

A partir de la ligne 24, on peut voir une lecture des paramètres LDAP à partir d'un fichier de configuration, probablement `Ldap.conf` que l'on a pu énumérer via HQK, car on retrouve des syntaxes similaires `Domain=`, `User=`, `Password=`. Ces paramètres sont stockés ensuite dans une instance de `LdapSearchSettings`, pour le paramètre `Password=`, on voit que ça fait appel à la méthode `CR.DS()` à la ligne 38 qui utilisée pour déchiffrer le mot de passe. On va donc switcher vers cette méthode

![[dnspy-ds.png]]

La méthode `DS()` de la classe `CR` est une fonction de déchiffrement de strings, `EncryptedString` est la strings chiffrée initiale, la fonction `CR.DS()` est appelé avec plusieurs paramètres :
- `Input` -> la strings chiffrée à déchiffrer
- `Key1`, `Key2`, `Key3`, ...

Après avoir récupérer les paramètres, on passe à la méthode `RD()`.

![[dns-rd.png]]

Cette méthode `RD()` est la fonction de déchiffrement utilisant l'algorithme AES en mode CBC. Elle comprend plusieurs valeurs :
- `cipherText` -> la strings chiffrée à déchiffrer
- `passPhrase` -> la passphrase 667912 utilisée pour générer la clé
- `saltValue` -> la valeur du salt utilisée (1313Rf99) pour la dérivation de la clé
- `passwordIterations` -> le nombre d'iterations (3) utilisé dans la fonction de dérivation de la clé
- `initVector` -> l'IV (1L1SA61493DRV53Z) utilisé pour le mode CBC
- `keySize` -> la taille de la clé

Cette méthode convertit ensuite l'IV et la valeur du salt en tableaux d'octets puis convertit la strings chiffrée en tableau d'octets. Ensuite elle utilise la fonction de dérivation de clé `RFC2898` pour générer la clé. Créer un provider de chiffrement AES avec la clé et l'IV. Enfin elle lit les données chiffrées depuis le flux de chiffrement, les déchiffre et les stocke dans un tableau d'octets. Enfin, elle convertit les octets déchiffrés en une strings ASCII puis la retourne.

Il est donc clair que l'on est en présence la même méthode de chiffrement pour le mot de passe LDAP d'Administrator que celui que l'on a retrouver dans RU Scanner. Si maintenant on reprend notre script python en modifiant les différentes clés.

![[decodeadm_strings.png]]

On lance le script avec le mot passe `yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4=`.

![[decodeadm_pass.png]]

Ca fonctionne et on récupère le mot de passe `XtH4nkS4Pl4y1nGX`. On sait qu'il s'agit du mot de passe de l'Administrator, utilisation de NetExec pour confirmer

![[adm_nxc.png]]

Tout est fonctionnel et on peut voir que l'on a accès au share `ADMIN$`, on peut donc utiliser psexec de la suite impacket pour obtenir un shell.

![[psexec_adm.png]]

Récupération du dernier flag

![[OSCP/OSCP-like/HTB/Windows/22sh list/nest/img/rootflag.png]]



