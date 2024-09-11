**Interface 1 (nat)      intelpro/1000mt desktop (82540em)**
**Interface 2 (host only)  VirtualBox host only ethernet adapter** 

🌞Télécharger l'application depuis votre VM

une commande wget ou curl fait le taff
c'est dispo sur ce dépôt git, c'est le fichier efrei_server


🌞 Lancer l'application efrei_server

sur la VM hein :)
lancer l'application à la main
l'application va écouter sur l'IP 127.0.0.1 par défaut, il faudra la lancer avec une variable d'environnement définie pour changer ça


Appelez-moi vite s'il ne se lance pas, c'est censé être un truc très simple qui juste fonctionne.

➜ Pour lancer une commande en définissant une variable d'environnement à la volée, on peut faire comme ça :
```bash
SUPER_VAR=toto command
par exemple, même si ça sert à rien
SUPER_VAR=toto ls /tmp
```
Prouvez que l'application écoute sur l'IP que vous avez spécifiée

profitez-en pour repérer le port TCP sur lequel écoute l'application
ça se fait en une seule commande ss
filtrez la sortie de la commande avec un | grep pour mettre en évidence la ligne intéressante dans le compte-rendu

# installation firewall 

```bash
sudo apt update
sudo apt install ufw

sudo ufw allow ssh

sudo ufw default deny incoming
sudo ufw default allow outgoing

sudo ufw enable

sudo ufw status verbose
```

# Ajouter un utilisateur au groupe sudo 

```bash
sudo usermod -aG sudo valentin 

groups valentin

sudo visudo
```

# Pour l'utilisateur à qui vous souhaitez accorder des privilèges sudo faire cette commande dans nano ou vim 
```bash
Valentin  ALL=(ALL:ALL) ALL
```
# Vérification des privilèges sudo
```bash
sudo whoami
```
# Si la configuration est correcte , il sera alors marqué 
```bash
root
```
# héberger l'application 
```bash
wget https://gitlab.com/it4lik/b3-csec-2024/-/raw/main/efrei_server?ref_type=heads&inline=false
```
# Prouvez que l'application écoute sur l'IP que vous avez spécifiée
```bash
sudo ss -tulnp
```

```bash
sudo ss -tulnp | grep efrei_server
```

🌞 Se connecter à l'application depuis votre PC

depuis votre PC ! (pas depuis une VM)
depuis votre PC, utilisez une commande nc (netcat) pour vous connecter à l'application

il faudra l'installer si vous ne l'avez pas sur votre PC :)


il faudra ouvrir un port firewall sur la VM (celui sur lequel écoute efrei_server, que vous avez repéré à l'étape précédente) pour qu'un client puisse se connecter
```bash
avec netcat, vous pourrez vous connecter en saissant :
nc <IP> <PORT>
```
# installation de netcat 
```bash
ncat.exe depuis mon pc
 ```
 ```bash
ncat.exe  192.168.56.10 8888 pour que ncat se connecte à mon debian
```
```bash
LISTEN_ADDRESS=192.168.56.10 ./efrei_server pour que efrei server écoute sur l'ip de mon debian soit 192.168.56.10 et sur le port 8888
```

🌞 Créer un service efrei_server.service

pour cela, il faut créer le fichier suivant : /etc/systemd/system/efrei_server.service

avec le contenu (simpliste) suivant :


Vous pouvez le nommer autrement (ou pas) parce que efrei_server c kan meme super niul kom nom.

```bash
[Unit]
Description=Super serveur EFREI
 
[Service]
ExecStart=/usr/local/bin/efrei_server
Environment=
EnvironmentFile=
```

➜ Pour les variables d'environnement :

choisissez SOIT Environment= SOIT EnvironmentFile= (l'un ou l'autre)


Environment= permet de préciser les variables une par une directement

EnvironmentFile= permet de préciser le chemin vers un fichier qui contient les variables d'environnement (plus clean que de foutre le bordel dans ce fichier)



➜ Une fois le fichier /etc/systemd/system/efrei_server.service créé :

exécutez la commande systemctl daemon-reload

cela ordonne à systemd de relire les fichiers de service

il va alors repérer votre nouveau efrei_server.service

c'est strictement nécessaire de taper cette commande à chaque fois que vous modifier un fichier .service

# partie 2 
```bash
sudo nano /etc/efrei_server.env
```

# ajout des variables dans le fichier d'environnement 
```bash
VAR1=value1
VAR2=value2
```
```bash
sudo nano /etc/systemd/system/efrei_server.service
```
```bash
[Unit]
Description=Super serveur EFREI

[Service]
ExecStart=/usr/local/bin/efrei_server
EnvironmentFile=/etc/efrei_server.env

[Install]
WantedBy=multi-user.target
```

# Recharger les fichiers de service systemd
```bash
sudo systemctl daemon-reload
```

# Démarrer et activer le service
```bash
sudo systemctl start efrei_server.service

sudo systemctl enable efrei_server.service

sudo systemctl status efrei_server.service
```

# voir les logs du service
```bash
journalctl -xe -u efrei_server
```

🌞 Exécuter la commande systemctl status efrei_server

le nom qu'on tape ici : efrei_server, c'est le nom du fichier
vous devriez voir que votre service est inactif

🌞 Démarrer le service

avec une commande systemctl adaptée

➜ Vous pourrez voir les logs du service avec la commande journalctl -xe -u efrei_server (si vous avez appelé le service efrei_server.service, adapatez sinon)
🌞 Vérifier que le programme tourne correctement

avec une commande systemctl adaptée, afficher le statut du service efrei_server

avec une commande ss adaptée, prouver que le programme écoute sur l'adresse IP souhaitée
depuis votre PC, connectez-vous au service, en utilisant une commande nc

# Afficher le statut du service efrei_server avec systemctl
```bash
sudo systemctl status efrei_server.service
```

# Vérifier que le programme écoute sur l'adresse IP souhaitée avec ss
```bash
sudo ss -tulnp | grep 192.168.56.10:8888
```

# Se connecter au service avec `nc` (Netcat)
```bash
ncat 192.168.56.10 8888
```

Bon pour ça, facile, on va juste faire en sorte que si le programme coupe, il soit relancé automatiquement.
🌞 Ajoutez une clause dans le fichier efrei_server.service pour le restart automatique

c'est la clause Restart=

trouvez la valeur adaptée pour qu'il redémarre tout le temps, dès qu'il est coupé

🌞 Testez que ça fonctionne

lancez le service avec une commande systemctl

affichez le processus lancé par systemd avec une commande ps

je veux que vous utilisiez une commande avec | grep quelquechose pour n'afficher que la ligne qui nous intéresse
vous devriez voir un processus efrei_server qui s'exécute


tuez le processus manuellement avec une commande kill

constatez que :

le service a bien été relancé
il y a bien un nouveau processus efrei_server qui s'exécute

Pour rappel, TOUTES les commandes pour faire ce qui est demandé avec un 🌞 doivent figurer dans le compte-rendu.

# partie 3 (1)

# Modifier le fichier de service
```bash
sudo nano /etc/systemd/system/efrei_server.service
```
```bash
[Unit]
Description=Super serveur EFREI

[Service]
ExecStart=/usr/local/bin/efrei_server
EnvironmentFile=/etc/efrei_server.env
Restart=always

[Install]
WantedBy=multi-user.target
```

# Recharger systemd pour prendre en compte les changements
```bash
sudo systemctl daemon-reload
```
# Démarrer le service
```bash
sudo systemctl start efrei_server.service
```
# Vérifier que le processus est lancé
```bash
ps aux | grep efrei_server
```

# Tuer le processus avec kill
```bash
sudo kill 5123 dans mon cas
```

# Vérifier que le service a été relancé
```bash
ps aux | grep efrei_server
```

Lorsqu'un programme s'exécute sur une machine (peu importe l'OS ou le contexte), le programme est toujours exécuté sous l'identité d'un utilisateur.
Ainsi, pendant son exécution, le programme aura les droits de cet utilisateur.

Par exemple, un programme lancé en tant que toto pourra lire un fichier /var/log/toto.log uniquement si l'utilisateur toto a les droits sur ce fichier.

🌞 Créer un utilisateur applicatif

c'est lui qui lancera efrei_server

avec une commande useradd

choisissez...

un nom approprié
un homedir approprié
un shell approprié




N'hésitez pas à venir vers moi pour discuter de ce qui est le plus "approprié" si nécessaire.

🌞 Modifier le service pour que ce nouvel utilisateur lance le programme efrei_server

je vous laisse chercher la clause appropriée à ajouter dans le fichier .service


🌞 Vérifier que le programme s'exécute bien sous l'identité de ce nouvel utilisateur

avec une commande ps

encore là, filtrez la sortie avec un | grep

n'oubliez pas de redémarrer le service pour que ça prenne effet hein !


Déjà à ce stade, le programme a des droits vraiment limités sur le système.

# partie 3 (2)

# Créer un utilisateur applicatif avec useradd
```bash
sudo useradd -r -d /home/efreiapp -s /bin/false efreiapp
```
# Modifier le fichier de service pour que cet utilisateur lance efrei_server
```bash
sudo nano /etc/systemd/system/efrei_server.service
```
```bash
[Unit]
Description=Super serveur EFREI

[Service]
ExecStart=/usr/local/bin/efrei_server
EnvironmentFile=/etc/efrei_server.env
Restart=always
User=efreiapp

[Install]
WantedBy=multi-user.target
```

# Recharger systemd et redémarrer le service
```bash
sudo systemctl daemon-reload
sudo systemctl restart efrei_server.service
```
# Vérifier que le programme s'exécute sous l'identité de l'utilisateur
```bash
ps aux | grep efrei_server
```
# Vérifier avec ps et grep
```bash
efreiapp    5249  0.0  1.2  33556 24868 ?        S    16:59   0:00 /usr/local/bin/efrei_server
```

Pour fonctionner, l'application a besoin de deux choses :

des variables d'environnement définies, ou des valeurs par défaut nulles seront utilisées
un fichier de log où elle peut écrire

par défaut elle écrit dans /tmp comme l'indique le warning au lancement de l'application
vous pouvez définir la variable LOG_DIR pour choisir l'emplacement du fichier de logs



🌞 Choisir l'emplacement du fichier de logs

créez un dossier dédié dans /var/log/ (le dossier standard pour stocker les logs)
indiquez votre nouveau dossier de log à l'application avec la variable LOG_DIR

l'application créera un fichier server.log à l'intérieur

🌞 Maîtriser les permissions du fichier de logs

avec les commandes chown et chmod

appliquez les permissions les plus restrictives possibles sur le dossier dans var/log/

# partie 3(3) 

# Créer un dossier de logs
```bash
sudo mkdir /var/log/efrei_server
```
# Changer le propriétaire du dossier
```bash
sudo chown efreiapp:efreiapp /var/log/efrei_server
```
# Appliquer des permissions restrictives
```bash
sudo chmod 700 /var/log/efrei_server
sudo chmod 777 /var/log/efrei_server
```
**Configurer la variable d'environnement LOG_DIR** dans le fichier de service :
```bash
sudo nano /etc/systemd/system/efrei_server.service
```
```bash
[Unit]
Description=Super serveur EFREI

[Service]
ExecStart=/usr/local/bin/efrei_server
EnvironmentFile=/etc/efrei_server.env
Restart=always
User=efreiapp
Environment=LOG_DIR=/var/log/efrei_server

[Install]
WantedBy=multi-user.target
```

# Vérifier que l'application écrit dans le bon dossier
```bash
ls -l /var/log/efrei_server
```
# Recharger systemd et redémarrer le service
```bash
sudo systemctl daemon-reload
sudo systemctl restart efrei_server.service
```

Il existe beaucoup de clauses qu'on peut ajouter dans un fichier .service pour que systemd s'occupe de sécuriser le service, en l'isolant du reste du système par exemple.
Ainsi, une commande est fournie systemd-analyze security qui permet de voir quelles mesures de sécurité on a activé. Un score (un peu arbitraire) est attribué au service ; cela représente son "niveau de sécurité".
Cette commande est très pratique d'un point de vue pédagogique : elle va vous montrer toutes les clauses qu'on peut ajouter dans un .service pour renforcer sa sécurité.
🌞 Modifier le .service pour augmenter son niveau de sécurité

ajoutez au moins 5 clauses dans le fichier pour augmenter le niveau de sécurité de l'application
n'utilisez que des clauses que vous comprenez, useless sinon

🌟 BONUS : Essayez d'avoir le score le plus haut avec systemd-analyze security
➜ 💡💡💡 A ce stade, vous pouvez ré-essayez l'injection que vous avez trouvé dans la partie 1. Normalement, on peut faire déjà moins de trucs avec.

# partie3 (4) 

# Pour augmenter le niveau de sécurité du fichier efrei_server.service , je dois  ajouter plusieurs clauses dans le fichier de service systemd. Ces clauses permettent d'isoler le service du reste du système, limitant ainsi son accès aux ressources et réduisant la surface d'attaque.
```bash
sudo nano /etc/systemd/system/efrei_server.service
```
### ProtectSystem=full Protège l'intégrité du système de fichiers en lecture seule 

### ProtectHome=true # Empêche l'accès aux fichiers dans /home, /root, et /run/user 

### NoNewPrivileges=true # Empêche le processus d'acquérir de nouveaux privilèges 

### PrivateTmp=true # Attribue un répertoire /tmp propre et isolé pour ce service 

### ProtectKernelModules=true # Empêche le chargement/déchargement des modules du noyau. 

### ProtectControlGroups=true # Restreint l'accès au contrôle des groups (sécurise les ressources système)

### RestrictAddressFamilies=AF_INET AF_INET6 : Restreint le service à utiliser uniquement certaines familles d’adresses réseau (par exemple, IPv4 et IPv6).

### MemoryDenyWriteExecute=true : Interdit au service de créer des zones de mémoire exécutable et modifiable, limitant ainsi certains types d'attaques.

### ProtectClock=true: Empêche le service de modifier les paramètres système de l'horloge.

### PrivateDevices=true : Cela empêche le service d’accéder aux périphériques du système, sauf les dispositifs strictement nécessaires pour son fonctionnement.

### PrivateUsers=true : Cela empêche le service d’interagir directement avec d'autres utilisateurs sur le système.

### RestrictSUIDSGID=true : Empêche le service d’exécuter des programmes qui ont l'attribut SUID (Set User ID) ou SGID (Set Group ID). Cela limite le risque d’escalade de privilèges via ces types de fichiers exécutables.

### ProtectHostname=true :  Empêche le service de modifier le nom d’hôte du système.

### ProtectProc=invisible : Masque le contenu du répertoire **`/proc`** (où résident les informations sur les processus) à ce service. Seuls les processus directement liés au service lui-même seront visibles.

# Tester le Niveau de Sécurité avec systemd-analyze security

```bash
sudo systemd-analyze security efrei_server
```

# Rechargez la configuration de systemd
```bash
sudo systemctl daemon-reload
```
# Redémarrez le service 
```bash
sudo systemctl restart efrei_server.service
```

Le firewall permet de filtrer les connexions entrantes sur la machine, mais aussi les connexions sortantes.
Une fois que notre serveur est en place, et qu'il héberge notre super service, il n'y à priori que très peu de choses qu'on veut autoriser

notre service doit accueillir les clients sur un port spécifique
notre service SSH doit rester accessible sur le port 22

Ca sous-entend que toutes autres accès réseau doit être bloqué, par exemple :

des connexions entrantes sur d'autres ports
n'importe quelle connexion sortante


Oui on bloque tout en sortie ! C'est une mesure de sécurité simple et très forte. Seul inconvénient : il faudra désactiver temporairement cette règle pour mettre à jour le serveur quand c'est nécessaire (sinon il ne peut pas utiliser le réseau, pour télécharger des paquets par exemple).

🌞 Configurer de façon robuste le firewall

bloquer toutes les connexions sortantes
bloquer toutes les connexions entrantes (y compris le ping) à part si c'est à destination du serveur SSH ou du service efrei_admin


🌞 Prouver que la configuration est effective

prouver que les connexions sortantes sont bloquées
prouver que les pings sont bloqués, mais une connexion SSH fonctionne

# Partie 4 (1)

# Configurer de façon robuste le firewall
```bash
sudo apt install ufw
```
# Activez UFW
```bash
sudo ufw enable
```
# Bloquer toutes les connexions sortantes
```bash
sudo ufw default deny outgoing
```
# Bloquer toutes les connexions entrantes sauf pour SSH (port 22) et votre service (port du service efrei_admin)
```bash
sudo ufw allow 22/tcp
sudo ufw allow 8888/tcp
```
# Bloquer les pings (ICMP Echo-Request)
```bash
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
```
# Vérifier que la règle a bien été appliquée
```bash
sudo iptables -L
```
**Cette règle va bloquer les requêtes ICMP de type "echo-request" (ping). Elle bloque donc les pings entrants.**

# Prouver que la configuration est effective

# Vérifier les connexions sortantes sont bloquées
```bash
ping google.com
```
# Vérifier que les pings entrants sont bloqués
```bash
ping 192.168.56.10 Les pings devraient être bloqués, et vous ne devriez pas recevoir de réponse.
```
# Vérifier que SSH fonctionne
```bash
ssh valentin@192.168.56.10
```
**La connexion SSH devrait fonctionner, car nous avons explicitement autorisé le port 22.**

# Vérifier que le service efrei_admin est accessible
```bash
ncat.exe 192.168.56.10 8888
```

**Si le service est correctement configuré, la connexion à ce port devrait réussir.**


Fail2ban notre vieil ami ! Fail2ban est un outil classique sur les OS GNU/Linux.
Le fonctionnement de fail2ban est simpliste :

on lui demande surveiller un fichier donné
on définit un pattern à repérer dans ce fichier
si plusieurs lignes correspondant au pattern se répètent, il effectue une action
par exemple, on ajoute une règle firewall


Quand on configure fail2ban pour surveiller un certain fichier, on dit qu'on crée une jail fail2ban.

Cas concret ici :

dès qu'un client se connecte à notre service, une ligne de log est ajouté au fichier de log
cette ligne de log contient l'IP du client qui s'est connecté
si un client se connecte + de 5 fois en moins de 10 secondes (par exemple) on peut estimer que c'est du flood (tentative de DOS ?)
il faudrait blacklister automatiquement l'IP de ce client dans le firewall
fail2ban fait exactement ça

🌞 Installer fail2ban sur la machine
🌞 Ajouter une jail fail2ban

elle doit lire le fichier de log du service, que vous avez normalement placé dans /var/log/

repérer la ligne de connexion d'un client
blacklist à l'aide du firewall l'IP de ce client

🌞 Vérifier que ça fonctionne !

faites-vous ban ! En faisant plein de connexions rapprochées avec le client
constatez que le ban est effectif
levez le ban (il y a une commande pour lever un ban qu'a réalisé fail2ban)

# Partie 4(2) 

# Installer Fail2ban
```bash
sudo apt update
sudo apt install fail2ban
```

# Configurer Fail2ban
```bash
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```
**Il faut Éditer le fichier  jail.local  et le modifier**
```bash
sudo nano /etc/fail2ban/jail.local
```

# Ajouter une jail pour votre service
```bash
[efrei-server]
enabled  = true
port     = PORT
filter   = efrei-server
logpath  = /var/log/efrei_server/server.log
maxretry = 5
findtime = 10
bantime  = 3600
```
# Créer un fichier de filtre pour Fail2ban
```bash
sudo nano /etc/fail2ban/filter.d/efrei-server.conf
```
# Ajoutez le contenu suivant dans ce fichier :
```bash
[Definition]
failregex = .*Client IP (\S+) connected.
ignoreregex =
```
# Redémarrer Fail2ban pour appliquer les modifications
```bash
sudo systemctl restart fail2ban
```
# Vérifier le Fonctionnement
```bash
sudo fail2ban-client status
```
**Efrei_server doit être listé** 

**Vérifiez les bans actifs** :
```bash
sudo fail2ban-client status efrei-server
```
**Levez un ban**
```bash
sudo fail2ban-client set efrei-server unbanip IP_ADDRESS
```
**Vérifiez les logs de Fail2ban** **pour vous assurer que tout fonctionne comme prévu**
```bash
sudo tail -f /var/log/fail2ban.log
```
**Confirmez que les règles de firewall sont correctement appliquées**
```bash
sudo iptables -L
```
**Fail2ban devrait être correctement configuré pour surveiller les logs de votre service et ajouter des règles de firewall pour bloquer les adresses IP en cas de tentative de flood.**


Lors de son fonctionnement, un programme peut être amené à exécuter des appels système (ou syscalls) en anglais.
Un programme doit exécuter un syscall dès qu'il veut interagir avec une ressource du système. Par exemple :

lire/modifier un fichier
établir une connexion réseau
écouter sur un port
changer les droits d'un fichier
obtenir la liste des processus
lancer un nouveau processus
etc.

➜ Exécuter un syscall c'est demander au kernel de faire quelque chose.
Ainsi, par exemple, quand on exécute la commande cat sur un fichier pour lire son contenu, la commande cat va exécuter (entre autres) le syscall open afin de pouvoir ouvrir et lire le fichier.

Il se passe la même chose quand genre t'utilises Discord, et t'envoies un fichier à un pote. L'application Discord va exécuter un syscall pour obtenir le contenu du fichier, et l'envoyer sur le réseau.

Si le programme est exécuté par un utilisateur qui a les droits sur ce fichier, alors le kernel autorisera ce syscall et le programme cat pourra accéder au contenu du fichier sans erreur, et l'afficher dans le terminal.

Dit autrement : n'importe quel programme qui accède au contenu d'un fichie (par exemple) exécute forcément un syscall pour obtenir le contenu de ce fichier. Peu importe l'OS, c'est un truc commun à tous.

➜ seccomp est un outil qui permet de filtrer les syscalls qu'a le droit d'exécuter un programme
On définit une liste des syscalls que le programme a le droit de faire, les autres seront bloqués.

Par exemple, un syscall sensible est fork() qui permet de créer un nouveau processus.

Dans notre cas, avec notre ptit service, c'est un des problèmes :

vous injectez du code dans l'application en tant que vilain hacker
pour exécuter des programmes comme cat ou autres
à chaque commande exécutée avec l'injection, un syscall est exécuté par le programme serveur pour demander la création d'un nouveau processus (votre injection)
on pourrait bloquer totalement ce comportement : empêcher le service de lancer un autre processus que efrei_server


🌞 Ajouter une politique seccomp au fichier .service

la politique doit être la plus restrictive possible
c'est à dire que juste le strict minimum des syscalls nécessaires doit être autorisé

# Partie 4(3) 

# Créer un fichier de politique seccomp
```bash
sudo mkdir -p /etc/efrei_server
sudo nano /etc/efrei_server/seccomp.json
```
# Définir la politique seccomp
```bash
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": [
    "SCMP_ARCH_X86_64"
  ],
  "syscalls": [
    {
      "names": [
        "read",
        "write",
        "exit",
        "close"
      ],
      "action": "SCMP_ACT_ALLOW",
      "args": []
    }
  ]
}
```
**defaultAction: Action par défaut pour les syscalls non explicitement autorisés. Ici, nous renvoyons une erreur (SCMP_ACT_ERRNO`)** 

**architectures : Architecture des syscalls à filtrer (ici x86_64).**

**syscalls : Liste des syscalls autorisés. Dans cet exemple, seuls read, write, exit, et close sont autorisés.**

# Modifier le fichier de service systemd
```bash
sudo nano /etc/systemd/system/efrei_server.service
```
# Ajouter la clause SystemCallFilter
```bash
[Unit]
Description=Super serveur EFREI

[Service]
ExecStart=/usr/local/bin/efrei_server
EnvironmentFile=/etc/efrei_server.env
Restart=always
User=efreiapp
Environment=LOG_DIR=/var/log/efrei_server
SystemCallFilter=@/etc/efrei_server/seccomp.json
```
# Recharger et redémarrer le service
```bash
sudo systemctl daemon-reload
```
# Redémarrer le service
```bash
sudo systemctl restart efrei_server
```
# Vérifier la politique seccomp
```bash
sudo strace -e trace=%file -p 5120
```
