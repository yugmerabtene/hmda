# Chapitre 2 — Attaques sur Windows et Active Directory

Version du contenu : 8.3 — alignement sur le plan maître du chapitre 1.

## 1. Objectif

Ce chapitre vous guide pas à pas à travers les attaques avancées et les techniques d'intrusion dans les environnements Active Directory. Vous découvrirez les méthodologies de déni de service, d'injection SQL, de dépassement de tampon et les attaques ciblant Active Directory. Vous apprendrez à mettre en place des contre-mesures et à comprendre le fonctionnement des attaques Pass-the-Hash et brute-force.

Ce chapitre s'effectue sur le périmètre `192.168.56.0/24` (host-only `vboxnet0`) avec Kali Linux (`192.168.56.101`) comme machine attaquante, Windows Server 2016 (`192.168.56.102`) comme cible Active Directory, Metasploitable 2 (`192.168.56.103`) comme cible Linux vulnérable et Windows XP (`192.168.56.104`) comme cible legacy.

> **Plan maître** — Ce chapitre exécute les lignes `Ch2 Lab1` à `Ch2 Lab3` du plan maître défini au **Chapitre 1, Lab 3**. Chaque étape met à jour `journal-execution.csv` et la couche Navigator. Ne recréez pas de plan local : reprenez la ligne existante et renseignez son statut.

## 2. Prérequis

**Avant de commencer :** assurez-vous d'avoir :

- Chapitre 1 complété : laboratoire configuré et connectivité de base vérifiée.
- Outils installés : `nmap`, Metasploit, `sqlmap`, `hping3`, `hydra`, `pth-winexe` (paquet `passing-the-hash`).
- Snapshot pris sur chaque VM avant de commencer les attaques.
- Dossier `preuves/` créé à la racine du laboratoire.

| Élément | Détail |
|---|---|
| Machine attaquante | Kali Linux, IP `192.168.56.101`, 2 vCPU, 2 Go de RAM, 20 Go de disque virtuel |
| Cible Active Directory | Windows Server 2016, IP `192.168.56.102` |
| Cible Linux | Metasploitable 2, IP `192.168.56.103` |
| Cible legacy | Windows XP, IP `192.168.56.104` |
| Hôte | `192.168.56.1` (interface `vboxnet0`) |
| Outils | `nmap`, Metasploit, `sqlmap`, `hping3`, `hydra`, `pth-winexe`, `tcpdump` |
| Connaissances | Réseau TCP/IP, fonctionnement HTTP/HTML, concepts Active Directory |
| Sécurité | Toutes les attaques sont effectuées dans un environnement de laboratoire isolé sans accès Internet sortant. Ne jamais attaquer de systèmes réels sans autorisation administrative. |

> **Note importante** — Ce chapitre traite des techniques d'attaque en simulation contrôlée. Toutes les démonstrations Active Directory utilisent des comptes et des configurations de test. La mitigation et la détection sont aussi importantes que l'attaque elle-même.

## 3. Plan MITRE ATT&CK du chapitre

| Lab | Techniques | Tactiques | Statut | Sources de données |
|---|---|---|---|---|
| Ch2 Lab1 | T1498 Network Denial of Service (simulation) ; T1499 Endpoint Denial of Service (simulation) ; T1499.001 OS Exhaustion Flood (théorique) ; T1499.002 Service Exhaustion Flood (théorique) ; T1499.003 Application Exhaustion Flood (théorique) ; T1499.004 Application or System Exploitation (théorique) | Impact | Couvert (simulation) pour T1498 et T1499 ; Théorique pour T1499.001, T1499.002, T1499.003 et T1499.004 | DS0029 Network Traffic ; DS0019 Service |
| Ch2 Lab2 | T1190 Exploit Public-Facing Application ; T1203 Exploitation for Client Execution (théorique) ; T1068 Exploitation for Privilege Escalation (théorique) | Initial Access ; Execution ; Privilege Escalation | T1190 couvert (simulation) ; T1203 et T1068 théoriques | DS0029 Network Traffic ; DS0015 Application Log ; DS0009 Process |
| Ch2 Lab3 | T1003 OS Credential Dumping (théorique) ; T1003.002 Security Account Manager (théorique) ; T1003.003 NTDS (théorique) ; T1550 Use Alternate Authentication Material (théorique) ; T1550.002 Pass the Hash (théorique — simulation avec hash factice) ; T1110 Brute Force (simulation) ; T1110.001 Password Guessing (simulation) ; T1110.002 Password Cracking (théorique) ; T1110.003 Password Spraying (théorique) ; T1087.002 Domain Account Discovery (théorique) ; T1018 Remote System Discovery (théorique) ; T1021.002 SMB/Windows Admin Shares (théorique) ; T1482 Domain Trust Discovery (théorique) ; T1558.003 Kerberoasting (théorique) ; T1558.004 AS-REP Roasting (théorique) | Credential Access ; Defense Evasion ; Lateral Movement ; Discovery | T1110 et T1110.001 couverts (simulation) ; T1550.002 théorique (simulation avec hash factice) ; autres théoriques | DS0026 Active Directory ; DS0028 Logon Session ; DS0002 User Account ; DS0029 Network Traffic |

> **Règle de lecture** — Le statut « Couvert (simulation) » signifie que la commande est exécutée dans le laboratoire, avec des valeurs de test. Le statut « Théorique » signifie que la technique est décrite et cartographiée, mais qu'aucune action correspondante n'est exécutée dans ce chapitre.

## Lab 1 — Test de déni de service contrôlé et analyse de disponibilité

### 1.1 Contexte et objectif

Cette première étape vous introduit aux attaques par déni de service et vous apprend à analyser l'impact sur la disponibilité des services. Vous comprendrez comment un flux SYN anormal sature les ressources réseau et comment détecter ce schéma.

> **Précision** — Ce lab réalise un **test de SYN flood contrôlé depuis une seule source**. Il ne réalise pas un DDoS (Distributed Denial of Service), qui suppose plusieurs sources distribuées. Le mapping ATT&CK reste T1498 pour le déni de service réseau et T1499 pour le déni de service sur l'endpoint.

**Objectif de Lab 1** — Effectuer un test de SYN flood contrôlé contre un service web, analyser les résultats avec `tcpdump` et Wireshark, puis documenter les contre-mesures de mitigation.

**Plan MITRE ATT&CK de Lab 1**

- **Technique** : T1498 Network Denial of Service ; T1499 Endpoint Denial of Service ; T1499.001 OS Exhaustion Flood (théorique) ; T1499.002 Service Exhaustion Flood (théorique) ; T1499.003 Application Exhaustion Flood (théorique) ; T1499.004 Application or System Exploitation (théorique).
- **Tactique** : Impact (TA0040).
- **Source de données** : DS0029 Network Traffic (paquets SYN, états de connexion) ; DS0019 Service (disponibilité du service web).
- **Règle de détection** : pic de paquets SYN sans ACK, augmentation du temps de réponse, file de connexions en `SYN_RECV`.
- **Mitigation** : SYN cookies, limitation de débit, répartiteur de charge, WAF, surveillance du trafic.
- **Statut** : Couvert (simulation) pour T1498 et T1499 ; T1499.001, T1499.002, T1499.003 et T1499.004 théoriques.

### 1.2 Étapes de Lab 1

#### Étape 1.1 — Capture du trafic de base

**Commande** : `sudo tcpdump -i any -nn -s0 -w preuves/ch2-lab1/base.pcap -c 1000`

**Contexte** : sur Kali (`192.168.56.101`), capture initiale du trafic réseau avant l'attaque.

**Résultat attendu** : fichier `preuves/ch2-lab1/base.pcap` créé avec 1000 paquets capturés pendant la période normale.

```bash
# Sur Kali : création du dossier de preuves et capture de base
mkdir -p preuves/ch2-lab1
sudo tcpdump -i any -nn -s0 -w preuves/ch2-lab1/base.pcap -c 1000 \
  2>&1 | tee preuves/ch2-lab1/tcpdump-base.log
```

**Ce que vous devez observer** :
- fichier `base.pcap` créé avec succès ;
- paquets réseau normaux capturés avant l'attaque ;
- sortie de `tcpdump` enregistrée dans `preuves/ch2-lab1/tcpdump-base.log`.

**L'enregistrement** : notez le départ de la capture dans votre carnet de laboratoire. Conservez le fichier `.pcap` et le journal `tcpdump-base.log`.

#### Étape 1.2 — Test de SYN flood contrôlé

**Commande** : `sudo hping3 -c 100 -S -p 80 192.168.56.103`

**Contexte** : sur Kali, émission de 100 paquets SYN vers le port 80 de Metasploitable 2.

**Résultat attendu** : lenteur ou interruption temporaire du service web sur la cible.

```bash
# Sur Kali : test de SYN flood contrôlé
sudo hping3 -c 100 -S -p 80 192.168.56.103 \
  2>&1 | tee preuves/ch2-lab1/hping3-synflood.log
```

**Ce que vous devez observer** :
- temps de réponse accru sur la cible ;
- éventuels messages `Connection refused` après le test ;
- 100 paquets envoyés, conformément à l'option `-c 100`.

**L'enregistrement** : notez le temps avant/après l'attaque. Conservez `hping3-synflood.log` et une capture d'écran de l'état du service web.

#### Étape 1.3 — Analyse du trafic après attaque

**Commande** : `tcpdump -r preuves/ch2-lab1/base.pcap -nn 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'`

**Contexte** : analyse des paquets SYN capturés pendant et après l'attaque.

**Résultat attendu** : identification des paquets SYN anormaux indiquant un flux de type flood.

> **Correction technique** — Le filtre `tcp.flags.syn == 1 && tcp.flags.ack == 0` est un filtre d'affichage Wireshark, pas un filtre BPF `tcpdump`. La commande ci-dessous utilise la syntaxe BPF correcte.

```bash
# Sur l'analyse des paquets SYN
tcpdump -r preuves/ch2-lab1/base.pcap -nn \
  'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0' \
  2>&1 | tee preuves/ch2-lab1/analyse-syn.txt
```

**Ce que vous devez observer** :
- liste des paquets SYN détectés durant l'attaque ;
- motif d'attaque identifiable (nombre de SYN, absence d'ACK) ;
- sortie enregistrée dans `preuves/ch2-lab1/analyse-syn.txt`.

**L'enregistrement** : notez les caractéristiques de l'attaque dans votre carnet et conservez `analyse-syn.txt`.

### 1.3 Plan d'attaque de Lab 1 à remplir en temps réel

| # | Étape | Technique ATT&CK | ID | Statut | Résultat observé | Détection observée | Mitigation applicable | Notes temps réel |
|---|---|---|---|---|---|---|---|---|
| 1 | Capture du trafic de base | — (capture de preuve, pas une technique adverse) | — | | | | | |
| 2 | Test de SYN flood contrôlé | Network Denial of Service | T1498 | | | | | |
| 3 | Analyse du trafic après attaque | Endpoint Denial of Service | T1499 | | | | | |

> Note — Cet exercice illustre `T1498` (Network Denial of Service) et `T1499` (Endpoint Denial of Service). `T1499.001`, `T1499.002`, `T1499.003` et `T1499.004` sont théoriques et ne sont pas exécutés. Le test est une simulation contrôlée depuis une seule source, pas un DDoS.

### 1.4 Ce que vous devez observer en Lab 1

**Résultat attendu** :
- test SYN flood exécuté avec succès ;
- taux de réponse augmenté ou service temporairement indisponible ;
- filtres `tcpdump` identifiant les paquets d'attaque ;
- documentation complète dans le carnet de laboratoire et les fichiers de preuve.

**Critères de réussite de Lab 1** :
- test SYN flood exécuté ;
- trafic capturé avant/après l'attaque ;
- analyse de filtre `tcpdump` effectuée ;
- mitigation initiale identifiée.

### 1.5 Après Lab 1

Progression vers Lab 2 — SQL Injection et Buffer Overflow.

### 1.6 Corrigé — Lab 1

**Résolution détaillée :**

**Étape 1.1 — Capture du trafic de base**
- **Commande** : `sudo tcpdump -i any -nn -s0 -w preuves/ch2-lab1/base.pcap -c 1000`
- **Résultat attendu** : fichier `base.pcap` créé avec 1000 paquets capturés pendant la période normale.
- **Explication** : `tcpdump` capture les paquets réseau pendant une période définie. Les 1000 paquets fournissent un échantillon de trafic normal contre lequel comparer le trafic pendant l'attaque.
- **Piège courant** : oublier l'option `-c` qui limite le nombre de paquets ; sans elle, la capture continue indéfiniment.

**Résultat attendu final** :
- fichier `preuves/ch2-lab1/base.pcap` créé avec succès ;
- journal `preuves/ch2-lab1/tcpdump-base.log` présent ;
- capture d'écran du terminal montrant la commande et le fichier créé.

**Étape 1.2 — Test de SYN flood contrôlé**
- **Commande** : `sudo hping3 -c 100 -S -p 80 192.168.56.103`
- **Résultat attendu** : lenteur ou interruption temporaire du service web sur la cible.
- **Explication** : l'envoi de 100 paquets SYN initie la procédure d'établissement de connexion TCP sans jamais la terminer, ce qui remplit la file des connexions en cours. Le volume reste volontairement faible : il s'agit d'une démonstration, pas d'une saturation réelle.
- **Piège courant** : oublier l'option `-c` qui limite le nombre de paquets ; l'émission continuerait indéfiniment.

**Résultat attendu final** :
- commande `hping3` exécutée avec 100 paquets SYN ;
- temps de réponse sur la cible observé (ralenti ou interruption) ;
- journal `preuves/ch2-lab1/hping3-synflood.log` présent.

**Étape 1.3 — Analyse du trafic après attaque**
- **Commande** : `tcpdump -r preuves/ch2-lab1/base.pcap -nn 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'`
- **Résultat attendu** : identification des paquets SYN anormaux indiquant une attaque flood.
- **Explication** : le filtre BPF isole les paquets dont le drapeau SYN est positionné et le drapeau ACK absent, caractéristiques d'un SYN flood. La syntaxe `tcp.flags...` est réservée à Wireshark.
- **Piège courant** : utiliser un filtre d'affichage Wireshark dans `tcpdump` ; la commande ne retourne alors aucun paquet ou une erreur de syntaxe.

**Résultat attendu final** :
- paquets SYN d'attaque identifiés dans la capture ;
- fichier `preuves/ch2-lab1/analyse-syn.txt` présent ;
- analyse du motif d'attaque documentée.

**Conclusion Lab 1** :
- test SYN flood contrôlé exécuté avec succès ;
- trafic capturé avant/après l'attaque ;
- analyse de filtre `tcpdump` effectuée ;
- ATT&CK cartographié : T1498, T1499.

---

## Lab 2 — SQL Injection et Buffer Overflow

### 2.1 Contexte et objectif

Cette étape explore deux vecteurs d'attaque classiques : l'injection SQL et le dépassement de tampon (buffer overflow). Vous apprendrez à identifier les points d'entrée vulnérables et à tester ces failles dans un contexte contrôlé.

**Objectif de Lab 2** — Effectuer une injection SQL contre une application web vulnérable et générer une charge utile de dépassement de tampon pour un service réseau, tout en documentant les contre-mesures.

**Plan MITRE ATT&CK de Lab 2**

- **Technique** : T1190 Exploit Public-Facing Application (Initial Access) ; T1203 Exploitation for Client Execution (Execution, théorique) ; T1068 Exploitation for Privilege Escalation (Privilege Escalation, théorique).
- **Tactique** : Initial Access (TA0001) ; Execution (TA0002) ; Privilege Escalation (TA0004).
- **Source de données** : DS0029 Network Traffic (requêtes HTTP) ; DS0015 Application Log (erreurs SQL, journaux web) ; DS0009 Process (plantage du service).
- **Règle de détection** : erreurs SQL répétées, requêtes HTTP anormales, plantages d'application, messages d'erreur de buffer.
- **Mitigation** : requêtes paramétrées, validation des entrées, mise à jour des bibliothèques, messages d'erreur génériques, WAF.
- **Statut** : T1190 couvert (simulation) ; T1203 et T1068 théoriques.

### 2.2 Étapes de Lab 2

#### Étape 2.1 — Injection SQL basique

**Commande** : `sqlmap -u "http://192.168.56.103/login.php" --data "username=admin' OR '1'='1" --batch`

**Contexte** : sur Kali, test d'injection SQL sur l'interface de connexion de Metasploitable 2.

**Résultat attendu** : identification de la base de données ou confirmation de la vulnérabilité.

```bash
# Sur Kali : injection SQL basique
mkdir -p preuves/ch2-lab2
sqlmap -u "http://192.168.56.103/login.php" \
  --data "username=admin' OR '1'='1" --batch \
  2>&1 | tee preuves/ch2-lab2/sqlmap.txt
```

**Ce que vous devez observer** :
- identification de la base de données (MySQL, PostgreSQL, etc.) ;
- extraction d'informations ou confirmation de la vulnérabilité ;
- sortie enregistrée dans `preuves/ch2-lab2/sqlmap.txt`.

**L'enregistrement** : notez les bases de données identifiées et les données extraites dans votre carnet. Conservez `sqlmap.txt`.

#### Étape 2.2 — Génération d'une charge utile de buffer overflow

**Commande** : `python3 -c "import struct; buf = b'A' * 260; buf += struct.pack('<I', 0x08048489); print(len(buf))"`

**Contexte** : sur Kali, génération d'une charge utile de débordement de tampon pour tester un service vulnérable. L'adresse `0x08048489` est un exemple : elle doit être remplacée par l'adresse réelle observée dans le débogueur.

**Résultat attendu** : charge utile de 264 octets générée et longueur affichée.

```bash
# Sur Kali : génération d'une charge utile de buffer overflow
python3 -c "import struct; buf = b'A' * 260; buf += struct.pack('<I', 0x08048489); print(len(buf))" \
  2>&1 | tee preuves/ch2-lab2/buffer-overflow.txt
```

**Ce que vous devez observer** :
- longueur de la charge utile affichée (264 octets) ;
- absence d'erreur Python ;
- journal `preuves/ch2-lab2/buffer-overflow.txt` présent.

**L'enregistrement** : notez le résultat du test dans votre carnet. Conservez `buffer-overflow.txt`. Aucun service n'est attaqué dans cette étape : la charge utile est seulement générée.

### 2.3 Plan d'attaque de Lab 2 à remplir en temps réel

| # | Étape | Technique ATT&CK | ID | Statut | Résultat observé | Détection observée | Mitigation applicable | Notes temps réel |
|---|---|---|---|---|---|---|---|---|
| 1 | Injection SQL basique | Exploit Public-Facing Application | T1190 | | | | | |
| 2 | Génération de charge utile buffer overflow | Exploitation for Client Execution | T1203 | | | | | |

> Note — Cet exercice illustre `T1190` (Exploit Public-Facing Application) et `T1203` (Exploitation for Client Execution). `T1068` (Exploitation for Privilege Escalation) est cartographié comme étape théorique suivante, non exécutée.

### 2.4 Ce que vous devez observer en Lab 2

**Résultat attendu** :
- injection SQL réussie ou tentative échouée documentée ;
- charge utile de buffer overflow générée avec résultat noté ;
- contre-mesures potentielles identifiées pour chaque vecteur.

**Critères de réussite de Lab 2** :
- outil `sqlmap` utilisé avec résultat documenté ;
- charge utile de buffer overflow générée et longueur vérifiée ;
- contre-mesures documentées pour les deux vecteurs.

### 2.5 Après Lab 2

Progression vers Lab 3 — Attaques contre Active Directory.

### 2.6 Corrigé — Lab 2

**Résolution détaillée :**

**Étape 2.1 — Injection SQL basique**
- **Commande** : `sqlmap -u "http://192.168.56.103/login.php" --data "username=admin' OR '1'='1" --batch`
- **Résultat attendu** : identification de la base de données et confirmation de la vulnérabilité.
- **Explication** : `sqlmap` est un outil d'automatisation d'injection SQL. L'option `--batch` répond oui automatiquement aux invites. L'injection `OR '1'='1'` est une tautologie qui peut provoquer une erreur SQL ou retourner toutes les lignes.
- **Piège courant** : négliger l'option `--batch` qui provoque des invites interactives ; toujours utiliser `--batch` en mode script.

**Résultat attendu final** :
- outil `sqlmap` lancé avec `--batch` ;
- base de données (MySQL, etc.) identifiée dans la sortie ;
- données extraites ou confirmation de vulnérabilité documentée ;
- fichier `preuves/ch2-lab2/sqlmap.txt` présent.

**Étape 2.2 — Génération d'une charge utile de buffer overflow**
- **Commande** : `python3 -c "import struct; buf = b'A' * 260; buf += struct.pack('<I', 0x08048489); print(len(buf))"`
- **Résultat attendu** : longueur de 264 octets affichée.
- **Explication** : le tampon de 260 octets dépasse la limite attendue, débordant vers la mémoire adjacente. L'adresse `0x08048489` est un exemple d'adresse de retour de fonction, à remplacer par l'adresse réelle de la charge utile en laboratoire.
- **Piège courant** : utiliser une adresse de retour invalide ; en laboratoire, tester d'abord avec un motif connu comme `0x41414141` (`AAAA`).

**Résultat attendu final** :
- commande `python3` exécutée sans erreur ;
- longueur `264` affichée ;
- fichier `preuves/ch2-lab2/buffer-overflow.txt` présent.

**Conclusion Lab 2** :
- outil `sqlmap` utilisé avec résultat documenté ;
- charge utile de buffer overflow générée et testée ;
- ATT&CK cartographié : T1190, T1203, T1068 (théorique).

---

## Lab 3 — Attaques contre Active Directory

### 3.1 Contexte et objectif

Cette étape cible un environnement Active Directory de laboratoire à travers des techniques Pass-the-Hash, brute-force et découverte de comptes. Vous apprendrez à décrire l'extraction de hachages, à réutiliser un hachage et à tester la robustesse des mots de passe dans un contexte contrôlé.

> **Périmètre** — La cible Active Directory est Windows Server 2016 (`192.168.56.102`). Metasploitable 2 (`192.168.56.103`) n'héberge pas Active Directory et ne doit pas être utilisée pour ces tests. Les commandes `ntdsutil` s'exécutent sur Windows Server, pas sur Kali.

**Objectif de Lab 3** — Décrire l'extraction de hachages Active Directory, simuler un Pass-the-Hash avec un hachage factice et tester la robustesse des mots de passe via LDAP, puis documenter les mitigations.

**Plan MITRE ATT&CK de Lab 3**

- **Technique** : T1003 OS Credential Dumping (Credential Access, théorique) ; T1003.002 Security Account Manager (Credential Access, théorique) ; T1003.003 NTDS (Credential Access, théorique) ; T1550 Use Alternate Authentication Material (Defense Evasion / Lateral Movement, théorique) ; T1550.002 Pass the Hash (Defense Evasion / Lateral Movement, théorique — simulation avec hash factice) ; T1110 Brute Force (Credential Access, simulation) ; T1110.001 Password Guessing (Credential Access, simulation) ; T1110.002 Password Cracking (Credential Access, théorique) ; T1110.003 Password Spraying (Credential Access, théorique) ; T1087.002 Domain Account Discovery (Discovery, théorique) ; T1018 Remote System Discovery (Discovery, théorique) ; T1021.002 SMB/Windows Admin Shares (Lateral Movement, théorique) ; T1482 Domain Trust Discovery (Discovery, théorique) ; T1558.003 Kerberoasting (Credential Access, théorique) ; T1558.004 AS-REP Roasting (Credential Access, théorique).
- **Tactique** : Credential Access (TA0006) ; Defense Evasion (TA0005) ; Lateral Movement (TA0008) ; Discovery (TA0007).
- **Source de données** : DS0026 Active Directory (événements d'annuaire) ; DS0028 Logon Session (authentifications) ; DS0002 User Account (comptes) ; DS0029 Network Traffic (LDAP, SMB).
- **Règle de détection** : authentifications NTLM inhabituelles, tentatives LDAP multiples, événements d'échec d'authentification, accès SMB administratif.
- **Mitigation** : politique de mots de passe forte, verrouillage de compte, surveillance de l'authentification, MFA, segmentation des comptes à privilèges, LAPS.
- **Statut** : T1110 et T1110.001 couverts (simulation) ; T1550.002 théorique (simulation avec hash factice) ; T1003, T1003.002, T1003.003, T1550, T1110.002, T1110.003, T1087.002, T1018, T1021.002, T1482, T1558.003 et T1558.004 théoriques.

### 3.2 Étapes de Lab 3

#### Étape 3.1 — Extraction théorique des hachages

**Commande** : `ntdsutil "ac i ntds" "ifm create" "create full C:\temp\sysvol" q q` (configuration théorique, sur Windows Server 2016)

**Contexte** : description de l'extraction de hachages depuis la base Active Directory. La commande n'est pas exécutée sur Kali.

**Résultat attendu** : fichiers contenant les hachages des comptes utilisateur, dans un dossier de laboratoire isolé.

```text
# Sur Windows Server 2016 (théorique, non exécuté dans ce lab Linux)
ntdsutil "ac i ntds" "ifm create" "create full C:\temp\sysvol" q q
```

**Ce que vous devez observer** :
- conceptuel : fichiers de hachages extraits (simulation avec fichiers de test) ;
- aucune commande `ntdsutil` n'est lancée depuis Kali.

**L'enregistrement** : notez la méthode d'extraction théorique dans votre carnet. Conservez une capture d'écran des concepts présentés.

#### Étape 3.2 — Simulation de Pass-the-Hash

**Commande** : `pth-winexe -U 'LAB/admin%<LMHASH>:<NTHASH>' //192.168.56.102 "cmd.exe"`

**Contexte** : utilisation d'un hachage factice pour une authentification distante sans connaître le mot de passe en clair.

**Résultat attendu** : accès à une invite de commande sur la cible distante, si le hachage factice et le compte de test sont valides.

```bash
# Sur Kali : simulation de Pass-the-Hash avec des valeurs de test
mkdir -p preuves/ch2-lab3
pth-winexe -U 'LAB/admin%<LMHASH>:<NTHASH>' //192.168.56.102 "cmd.exe" \
  2>&1 | tee preuves/ch2-lab3/pth-winexe.txt
```

**Ce que vous devez observer** :
- invite de commande s'affichant sur la cible distante si la simulation aboutit ;
- message d'erreur explicite si le hachage factice est refusé ;
- journal `preuves/ch2-lab3/pth-winexe.txt` présent dans tous les cas.

**L'enregistrement** : notez la commande et son résultat dans votre carnet. Conservez `pth-winexe.txt`.

#### Étape 3.3 — Brute-force sur comptes Active Directory

**Commande** : `hydra -L preuves/ch2-lab3/users.txt -P preuves/ch2-lab3/passwords.txt -s 389 -f 192.168.56.102 ldap://`

**Contexte** : test de robustesse des mots de passe via une attaque par dictionnaire sur LDAP.

**Résultat attendu** : compte de test identifié avec un mot de passe faible, ou échec documenté.

```bash
# Sur Kali : dictionnaires de test et brute-force LDAP
mkdir -p preuves/ch2-lab3
cat > preuves/ch2-lab3/users.txt <<'EOF'
admin
administrator
msfadmin
EOF
cat > preuves/ch2-lab3/passwords.txt <<'EOF'
Password123!
admin
msfadmin
EOF
hydra -L preuves/ch2-lab3/users.txt -P preuves/ch2-lab3/passwords.txt \
  -s 389 -f 192.168.56.102 ldap:// \
  2>&1 | tee preuves/ch2-lab3/hydra-ldap.txt
```

**Ce que vous devez observer** :
- compte et mot de passe identifiés dans la sortie ;
- confirmation de l'authentification réussie ;
- journal `preuves/ch2-lab3/hydra-ldap.txt` présent.

**L'enregistrement** : notez le compte de test trouvé dans votre carnet. Conservez `hydra-ldap.txt`.

### 3.3 Plan d'attaque de Lab 3 à remplir en temps réel

| # | Étape | Technique ATT&CK | ID | Statut | Résultat observé | Détection observée | Mitigation applicable | Notes temps réel |
|---|---|---|---|---|---|---|---|---|
| 1 | Extraction théorique des hachages | OS Credential Dumping: NTDS | T1003.003 | | | | | |
| 2 | Simulation Pass-the-Hash | Use Alternate Authentication Material: Pass the Hash | T1550.002 | | | | | |
| 3 | Brute-force LDAP | Brute Force: Password Guessing | T1110.001 | | | | | |

> Note — Cet exercice illustre `T1110.001` (simulation) et `T1550.002` (théorique — simulation avec hash factice). **Techniques théoriques associées (non exécutées)** : `T1003`, `T1003.002`, `T1003.003`, `T1550`, `T1110`, `T1110.002`, `T1110.003`, `T1087.002`, `T1018`, `T1021.002`, `T1482`, `T1558.003`, `T1558.004`.

### 3.4 Ce que vous devez observer en Lab 3

**Résultat attendu** :
- méthode d'extraction des hachages comprise et documentée ;
- simulation Pass-the-Hash exécutée ou refus documenté ;
- brute-force LDAP effectuée avec résultat noté ;
- techniques de mitigation documentées.

**Critères de réussite de Lab 3** :
- concepts d'extraction des hachages compris ;
- Pass-the-Hash documenté (même en simulation) ;
- brute-force LDAP exécuté avec résultat ;
- contre-mesures identifiées pour chaque technique.

### 3.5 Après Lab 3

Synthèse du chapitre 2 et transition vers le chapitre 3.

### 3.6 Corrigé — Lab 3

**Résolution détaillée :**

**Étape 3.1 — Extraction théorique des hachages**
- **Commande** : `ntdsutil "ac i ntds" "ifm create" "create full C:\temp\sysvol" q q` (théorique)
- **Résultat attendu** : fichiers contenant les hachages des comptes utilisateur (simulation en laboratoire).
- **Explication** : `ntdsutil` est l'outil officiel Microsoft pour la gestion de la base de données Active Directory. En environnement de laboratoire, on utilise des fichiers de hachages simulés ou une VM Windows Server avec un partage de dossiers.
- **Piège courant** : essayer d'exécuter `ntdsutil` sur Kali Linux ; la commande doit être exécutée sur Windows Server 2016 (`192.168.56.102`).

**Résultat attendu final** :
- concepts d'extraction des hachages présentés et documentés ;
- en laboratoire : fichiers de hachages simulés fournis ;
- capture d'écran des concepts présentés.

**Étape 3.2 — Simulation de Pass-the-Hash**
- **Commande** : `pth-winexe -U 'LAB/admin%<LMHASH>:<NTHASH>' //192.168.56.102 "cmd.exe"`
- **Résultat attendu** : accès à une invite de commande sur la cible distante si la simulation aboutit.
- **Explication** : l'attaque Pass-the-Hash réutilise un hachage de mot de passe sans connaître le mot de passe en clair. L'outil `pth-winexe` permet l'exécution distante de commandes via SMB.
- **Piège courant** : utiliser un hachage mal formaté ou un compte de test inexistant ; vérifier le format `LMHASH:NTHASH` et le nom du domaine avant de relancer.

**Résultat attendu final** :
- commande `pth-winexe` exécutée avec un hachage de test formaté ;
- invite de commande affichée ou refus explicite documenté ;
- fichier `preuves/ch2-lab3/pth-winexe.txt` présent.

**Étape 3.3 — Brute-force sur comptes Active Directory**
- **Commande** : `hydra -L preuves/ch2-lab3/users.txt -P preuves/ch2-lab3/passwords.txt -s 389 -f 192.168.56.102 ldap://`
- **Résultat attendu** : compte de test identifié avec un mot de passe faible, ou échec documenté.
- **Explication** : `hydra` effectue une attaque par dictionnaire. L'option `-L` spécifie le fichier de noms d'utilisateurs, `-P` le fichier de mots de passe, `-s` le port LDAP et `-f` s'arrête après la première réussite.
- **Piège courant** : fichiers `users.txt` ou `passwords.txt` vides ou mal formatés ; toujours vérifier leur format et leur chemin avant de lancer l'attaque.

**Résultat attendu final** :
- commande `hydra` lancée avec les fichiers de dictionnaire ;
- compte de test identifié ou échec documenté ;
- fichier `preuves/ch2-lab3/hydra-ldap.txt` présent.

**Conclusion Lab 3** :
- extraction des hachages comprise et documentée ;
- simulation Pass-the-Hash exécutée ou refus documenté ;
- brute-force LDAP exécuté avec résultat ;
- ATT&CK cartographié : T1003.003, T1550.002, T1110.001.

---

## 4. Synthèse et transition vers le chapitre 3

### 4.1 Validation finale de Lab 1 à Lab 3

Vérifiez que tous les labs ont été complétés :

- [ ] Lab 1 : test de déni de service contrôlé — trafic capturé et analysé.
- [ ] Lab 2 : SQL Injection et Buffer Overflow — tests effectués avec résultats documentés.
- [ ] Lab 3 : attaques contre Active Directory — Pass-the-Hash et brute-force documentés.

Chaque lab a été cartographié sur MITRE ATT&CK avec sa technique, sa tactique, sa source de données, sa règle de détection et sa mitigation. Tous les résultats ont été documentés dans votre rapport d'attaque avec statut, résultat observé, détection observée et notes en temps réel.

### 4.2 Transition vers le chapitre 3

Le chapitre 3 poursuit avec la génération de payloads, l'analyse des canaux de commande et contrôle (C2) et l'analyse des traces d'exfiltration. Il ne refait pas l'audit de sécurité du chapitre 5 : il produit et analyse les artefacts offensifs du laboratoire.

**Bon travail !** Vous avez maintenant complété les 3 labs fondamentaux du chapitre 2 dans un environnement de laboratoire isolé. Ces compétences constituent la base pour les techniques d'analyse et de rapport des chapitres suivants.
