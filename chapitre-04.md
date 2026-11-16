# Chapitre 4 — Forensique, réseau, rapport et restauration

Version du contenu : 8.3 — alignement sur le plan maître du chapitre 1.

## 1. Objectif

Ce chapitre vous guide pas à pas à travers l'analyse forensique, l'investigation réseau, l'analyse de l'exfiltration de données et la restauration de l'environnement de laboratoire. Vous découvrirez comment consolider les preuves, tracer les activités suspectes, produire un rapport professionnel et remettre le laboratoire dans un état sain.

> **Rôle du chapitre** — Le chapitre 4 est le chapitre **forensique, réseau, rapport et restauration**. Il reprend les preuves techniques collectées au chapitre 3, les vérifie, les consolide dans un rapport standard et restaure l'environnement. Le chapitre 3 produit et analyse les artefacts payload/C2 ; le chapitre 4 ne refait pas cette analyse depuis zéro : il la vérifie, la documente et la clôt.

Tous les labs s'effectuent sur le périmètre `192.168.56.0/24` (host-only `vboxnet0`) avec Kali Linux (`192.168.56.101`) comme machine attaquante, Metasploitable 2 (`192.168.56.103`) comme cible principale, Windows XP (`192.168.56.104`) comme cible legacy et Windows Server 2016 (`192.168.56.102`) comme cible Active Directory.

> **Plan maître** — Ce chapitre exécute les lignes `Ch4 Lab1` à `Ch4 Lab4` du plan maître défini au **Chapitre 1, Lab 3**. Chaque étape met à jour `journal-execution.csv` et la couche Navigator. Ne recréez pas de plan local : reprenez la ligne existante et renseignez son statut.

**Avant de commencer :** assurez-vous d'avoir :

- chapitre 3 complété, avec les preuves `preuves/ch3-lab1/`, `preuves/ch3-lab2/` et `preuves/ch3-lab3/` disponibles ;
- snapshots pris sur chaque VM avant de commencer les analyses forensiques ;
- disque dur suffisant pour sauvegarder les fichiers PCAP et les rapports ;
- dossier `preuves/` créé à la racine du laboratoire.

## 2. Prérequis

| Élément | Détail |
|---|---|
| Machine attaquante | Kali Linux, IP `192.168.56.101`, 2 Go de RAM, 2 CPU, disque 20 Go dynamique |
| Cible Linux | Metasploitable 2, IP `192.168.56.103`, 2 Go de RAM, 2 CPU, disque 20 Go dynamique |
| Cible Windows XP | IP `192.168.56.104` |
| Cible Active Directory | Windows Server 2016, IP `192.168.56.102` |
| Hôte | `192.168.56.1` (interface `vboxnet0`) |
| Outils | `nmap`, Wireshark, `tcpdump`, `searchsploit`, `sqlmap` |
| Connaissances | Terminal Linux, analyse forensique, bases réseau |
| Sécurité | Snapshot avant toute manipulation, rollback après |
| Identifiants | `kali` / `kali` (Kali), `msfadmin` / `msfadmin` (Metasploitable) |

## 3. Plan MITRE ATT&CK du chapitre

| Lab | Techniques | Tactiques | Statut | Sources de données |
|---|---|---|---|---|
| Ch4 Lab1 | T1119 Automated Collection (analyse défensive) ; T1083 File and Directory Discovery (analyse) ; T1059.004 Unix Shell (analyse) | Collection ; Discovery ; Execution | Couvert (analyse défensive) pour T1119 ; Couvert (analyse) pour T1083 et T1059.004 | DS0015 Application Log ; DS0022 File ; DS0017 Command |
| Ch4 Lab2 | T1040 Network Sniffing (analyse) ; T1071 / T1071.001 Application Layer Protocol / Web Protocols (analyse) ; T1571 Non-Standard Port (analyse) | Credential Access / Discovery ; Command and Control | Couvert (analyse) | DS0029 Network Traffic ; DS0009 Process ; DS0038 Domain Name |
| Ch4 Lab3 | T1041 Exfiltration Over C2 Channel (analyse) ; T1071 / T1071.001 Application Layer Protocol / Web Protocols (analyse) ; T1053.003 Scheduled Task/Job: Cron (analyse) | Exfiltration ; Command and Control ; Execution / Persistence | Couvert (analyse) | DS0029 Network Traffic ; DS0015 Application Log ; DS0022 File ; DS0003 Scheduled Job |
| Ch4 Lab4 | T1046 Network Service Discovery (vérification) ; T1490 et T1485 en référence théorique | Discovery ; — | Couvert (vérification) ; T1490/T1485 non applicables | DS0020 Snapshot ; DS0019 Service ; DS0029 Network Traffic |
| Non applicable (chapitre) | T1566 Phishing ; T1069 Permission Groups Discovery ; T1056 / T1056.001 Input Capture / Keylogging ; T1047 Windows Management Instrumentation | — | Non applicable | — |

> **Règle de lecture** — Les techniques marquées « analyse » décrivent ce que l'analyste observe et interprète dans les preuves. Elles ne sont pas exécutées comme actions offensives dans ce chapitre. La restauration de snapshot est une **remédiation**, pas une technique ATT&CK : T1490 Inhibit System Recovery décrit l'action adverse qui empêche la restauration, et T1485 Data Destruction décrit la destruction de données.

## Lab 1 — Consolidation des journaux et rapport forensique

### 1.1 Contexte et objectif

Cette première étape vous apprend à consolider les preuves forensiques collectées au chapitre 3, à vérifier les journaux système et à produire la chronologie qui servira de base au rapport standard. L'objectif est d'identifier les indicateurs de compromission (IoC), de confirmer leur présence et de documenter les événements.

**Objectif de Lab 1** — Vérifier et consolider les preuves des journaux système, identifier les IoC et produire une chronologie exploitable dans le rapport forensique.

**Plan MITRE ATT&CK de Lab 1**

- **Technique** : T1119 Automated Collection (Collection, analyse défensive) ; T1083 File and Directory Discovery (Discovery, analyse) ; T1059.004 Unix Shell (Execution, analyse des commandes observées).
- **Tactique** : Collection (TA0009) ; Discovery (TA0007) ; Execution (TA0002).
- **Source de données** : DS0015 Application Log (auth.log) ; DS0022 File (exécutables nouveaux ou modifiés) ; DS0017 Command (commandes shell observées).
- **Règle de détection** : logs d'événements, changements de fichiers, modifications de processus.
- **Mitigation** : journalisation centrale, surveillance des fichiers critiques, intégrité des fichiers (FIM), analyse régulière des journaux.
- **Statut** : Couvert (analyse défensive) pour T1119 ; Couvert (analyse) pour T1083 et T1059.004.

### 1.2 Étapes de Lab 1

#### Étape 1.1 — Vérification des preuves d'authentification

**Commande** : `grep -E "Accepted|Failed" /var/log/auth.log`

**Contexte** : sur la machine cible Linux (`192.168.56.103`), après avoir obtenu des privilèges root. Les preuves brutes ont été collectées au chapitre 3 ; cette étape vérifie qu'elles sont complètes et cohérentes.

**Résultat attendu** : extraits des événements d'authentification réussie et échouée avec horodatages.

```bash
# Sur la cible : vérification des preuves d'authentification
mkdir -p preuves/ch4-lab1
sudo grep -E "Accepted|Failed" /var/log/auth.log \
  2>&1 | tee preuves/ch4-lab1/verification-auth.txt
```

**Ce que vous devez observer** :
- lignes `Accepted` pour les connexions SSH réussies ;
- lignes `Failed` pour les échecs d'authentification ;
- horodatages et noms d'utilisateur associés ;
- cohérence avec `preuves/ch3-lab1/auth-accepted-failed.txt`.

**L'enregistrement** : notez les écarts éventuels entre les deux collectes. Conservez `preuves/ch4-lab1/verification-auth.txt`.

#### Étape 1.2 — Vérification des activités suspectes

**Commande** : `grep -i "sudo\|chmod\|chown\|curl\|wget" /var/log/auth.log`

**Contexte** : sur la cible Linux, après avoir vérifié les authentifications. L'objectif est de confirmer les commandes système suspectes et de les relier aux événements.

**Résultat attendu** : lignes contenant des commandes système suspectes avec horodatages.

```bash
# Sur la cible : vérification des activités suspectes
sudo grep -i "sudo\|chmod\|chown\|curl\|wget" /var/log/auth.log \
  2>&1 | tee preuves/ch4-lab1/verification-activites.txt
```

**Ce que vous devez observer** :
- commandes suspectes et utilisateurs associés ;
- horodatages cohérents avec la chronologie du chapitre 3 ;
- preuve `preuves/ch4-lab1/verification-activites.txt`.

**L'enregistrement** : notez les activités confirmées et les faux positifs écartés. Conservez le fichier de preuve.

#### Étape 1.3 — Vérification des exécutables nouveaux ou modifiés

**Commande** : `find / -newer /etc/passwd -type f 2>/dev/null`

**Contexte** : sur la cible Linux, après avoir analysé les journaux. L'objectif est de confirmer les exécutables nouveaux ou modifiés et de les qualifier.

**Résultat attendu** : liste des fichiers exécutables créés ou modifiés après la dernière modification de `/etc/passwd`.

```bash
# Sur la cible : vérification des exécutables récents
sudo find / -newer /etc/passwd -type f 2>/dev/null \
  | tee preuves/ch4-lab1/verification-executables.txt
```

**Ce que vous devez observer** :
- fichiers exécutables récents avec taille et chemin ;
- fichiers inconnus ou pouvant être des implants ;
- cohérence avec `preuves/ch3-lab1/executables-recents.txt`.

**L'enregistrement** : notez les fichiers confirmés et les fichiers à écarter. Conservez le fichier de preuve.

#### Étape 1.4 — Consolidation de la chronologie et du rapport

**Actions** :
1. Compiler les horodatages et événements vérifiés.
2. Classer les événements par ordre chronologique.
3. Rédiger la section « Chronologie » du rapport forensique.
4. Conserver les preuves et leurs empreintes.

```bash
# Sur Kali : consolidation des preuves du chapitre 4
{
  echo "Chronologie forensique — Ch4 Lab1"
  echo "=== Authentifications ==="
  cat preuves/ch4-lab1/verification-auth.txt
  echo "=== Activités suspectes ==="
  cat preuves/ch4-lab1/verification-activites.txt
  echo "=== Exécutables récents ==="
  cat preuves/ch4-lab1/verification-executables.txt
} > preuves/ch4-lab1/chronologie-forensique.txt 2>&1
sha256sum preuves/ch4-lab1/*.txt > preuves/ch4-lab1/empreintes.sha256 2>&1
```

**L'enregistrement** : rédigez la chronologie dans votre rapport forensique. Conservez `preuves/ch4-lab1/chronologie-forensique.txt` et `preuves/ch4-lab1/empreintes.sha256`.

### 1.3 Plan d'attaque de Lab 1 à remplir en temps réel

| # | Étape | Technique ATT&CK | ID | Statut | Résultat observé | Détection observée | Mitigation applicable | Notes temps réel |
|---|---|---|---|---|---|---|---|---|
| 1 | Vérification des authentifications | Automated Collection | T1119 | | | | | |
| 2 | Vérification des activités suspectes | Unix Shell (analyse) | T1059.004 | | | | | |
| 3 | Vérification des exécutables | File and Directory Discovery | T1083 | | | | | |
| 4 | Chronologie et rapport | Automated Collection | T1119 | | | | | |

> Note — Cet exercice illustre `T1119` (analyse défensive), `T1059.004` (analyse des commandes shell) et `T1083` (analyse des fichiers). Les preuves du chapitre 3 sont vérifiées, pas recollectées depuis zéro.

### 1.4 Ce que vous devez observer en Lab 1

**Résultat attendu** :
- extraits pertinents des journaux `auth.log` avec horodatages ;
- liste d'activités suspectes confirmées ;
- au moins 3 types d'IoC documentés ;
- chronologie des événements complète au niveau du jour et de l'heure ;
- rapport forensique commencé avec les preuves et leurs empreintes.

**Critères de réussite de Lab 1** :
- journaux d'authentification vérifiés avec extraits documentés ;
- activités suspectes identifiées et chronologisées ;
- au moins 3 types d'IoC documentés ;
- chronologie et empreintes présentes dans `preuves/ch4-lab1/`.

### 1.5 Après Lab 1

Passez à Lab 2 — Enquête sur les connexions réseau suspectes et capture complémentaire.

### 1.6 Corrigé — Lab 1

**Résolution détaillée :**

**Étape 1.1 — Vérification des preuves d'authentification**
- **Commande** : `sudo grep -E "Accepted|Failed" /var/log/auth.log`
- **Résultat attendu** : lignes d'authentification avec horodatages.
- **Explication** : `auth.log` conserve les événements SSH. La vérification confirme que la collecte du chapitre 3 est complète.
- **Piège courant** : comparer des journaux de fuseaux horaires différents ; vérifier l'heure des VM.

**Résultat attendu final** :
- extraits vérifiés ;
- fichier `preuves/ch4-lab1/verification-auth.txt` présent.

**Étape 1.2 — Vérification des activités suspectes**
- **Commande** : `sudo grep -i "sudo\|chmod\|chown\|curl\|wget" /var/log/auth.log`
- **Résultat attendu** : commandes suspectes avec utilisateurs et horodatages.
- **Explication** : `sudo`, `chmod`, `chown`, `curl` et `wget` peuvent signaler une élévation de privilèges ou un téléchargement.
- **Piège courant** : confondre une administration légitime avec une activité malveillante.

**Résultat attendu final** :
- activités vérifiées ;
- fichier `preuves/ch4-lab1/verification-activites.txt` présent.

**Étape 1.3 — Vérification des exécutables nouveaux ou modifiés**
- **Commande** : `sudo find / -newer /etc/passwd -type f 2>/dev/null`
- **Résultat attendu** : fichiers récents.
- **Explication** : `-newer` compare la date de modification à `/etc/passwd`.
- **Piège courant** : oublier `2>/dev/null` et interpréter les erreurs de permission comme des fichiers.

**Résultat attendu final** :
- fichiers vérifiés ;
- fichier `preuves/ch4-lab1/verification-executables.txt` présent.

**Étape 1.4 — Consolidation de la chronologie et du rapport**
- **Action** : concaténer les preuves et calculer les empreintes SHA-256.
- **Explication** : les empreintes prouvent l'intégrité des preuves entre la collecte et le rapport.
- **Piège courant** : modifier un fichier de preuve après avoir calculé son empreinte.

**Conclusion Lab 1** :
- preuves vérifiées et consolidées ;
- chronologie documentée ;
- empreintes conservées ;
- ATT&CK cartographié : T1119, T1083, T1059.004.

---

## Lab 2 — Enquête réseau et capture complémentaire

### 2.1 Contexte et objectif

Après avoir consolidé les journaux, cette étape vous apprend à enquêter sur les connexions réseau et à produire une capture complémentaire. Vous identifierez les canaux de communication établis par un attaquant, les données exfiltrées et les systèmes externes compromis, puis vous analyserez la capture dans Wireshark.

**Objectif de Lab 2** — Analyser l'activité réseau, capturer le trafic complémentaire, identifier les connexions établies et déterminer l'étendue de l'exfiltration ou de la communication C2.

**Plan MITRE ATT&CK de Lab 2**

- **Technique** : T1040 Network Sniffing (Credential Access / Discovery, analyse) ; T1071 / T1071.001 Application Layer Protocol / Web Protocols (Command and Control, analyse) ; T1571 Non-Standard Port (Command and Control, analyse).
- **Tactique** : Credential Access (TA0006) ; Discovery (TA0007) ; Command and Control (TA0011).
- **Source de données** : DS0029 Network Traffic (pcap, connexions) ; DS0009 Process (PID et utilisateur) ; DS0038 Domain Name (résolution DNS).
- **Règle de détection** : connexions sortantes inhabituelles, ports non standards, résolutions DNS suspectes, requêtes HTTP anormales.
- **Mitigation** : surveillance du trafic, listes de contrôle d'accès, filtrage de sortie, détection de fuite de données, analyse du trafic C2.
- **Statut** : Couvert (analyse) pour T1040, T1071 et T1571.

### 2.2 Étapes de Lab 2

#### Étape 2.1 — Liste des connexions réseau établies

**Commande** : `ss -tuln` ou `netstat -tuln`

**Contexte** : sur la machine cible Linux (`192.168.56.103`), après la consolidation des journaux. L'objectif est de lister les connexions réseau et les services en écoute.

**Résultat attendu** : liste des connexions avec leurs PID et utilisateur.

```bash
# Sur la cible : connexions réseau établies
mkdir -p preuves/ch4-lab2
sudo ss -tulnp 2>&1 | tee preuves/ch4-lab2/ss-tuln.txt
# Alternative si ss est absent
sudo netstat -tulnp 2>&1 | tee preuves/ch4-lab2/netstat-tuln.txt
```

**Ce que vous devez observer** :
- connexions établies avec numéros de port ;
- services en écoute ;
- PID et utilisateur associés ;
- preuves `ss-tuln.txt` ou `netstat-tuln.txt`.

**L'enregistrement** : notez la liste des connexions dans votre rapport. Conservez les fichiers de preuve.

#### Étape 2.2 — Identification des connexions sortantes

**Commande** : `ss -t | grep ESTAB` ou `netstat -t | grep ESTAB`

**Contexte** : sur la cible Linux, après avoir listé les connexions. L'objectif est d'identifier les connexions sortantes.

**Résultat attendu** : connexions sortantes avec adresses distantes et ports.

```bash
# Sur la cible : connexions sortantes
ss -t 2>&1 | grep ESTAB | tee preuves/ch4-lab2/connexions-sortantes.txt
netstat -t 2>&1 | grep ESTAB | tee -a preuves/ch4-lab2/connexions-sortantes.txt
```

**Ce que vous devez observer** :
- adresses distantes et ports ;
- ports non standards ou inhabituels ;
- preuve `connexions-sortantes.txt`.

**L'enregistrement** : notez les connexions sortantes dans votre rapport. Conservez le fichier de preuve.

#### Étape 2.3 — Résolution des adresses distantes

**Commande** : `nslookup <IP>` ou `host <IP>`

**Contexte** : sur la cible Linux, après avoir identifié les connexions sortantes. L'objectif est de résoudre les adresses distantes.

**Résultat attendu** : noms d'hôtes résolus pour les adresses IP distantes.

```bash
# Sur la cible : résolution d'une adresse distante
host 192.168.56.1 2>&1 | tee preuves/ch4-lab2/resolution-dns.txt
nslookup 192.168.56.1 2>&1 | tee -a preuves/ch4-lab2/resolution-dns.txt
```

**Ce que vous devez observer** :
- noms d'hôtes résolus ;
- destinations potentiellement suspectes ;
- preuve `resolution-dns.txt`.

**L'enregistrement** : notez les résolutions dans votre rapport. Conservez le fichier de preuve.

#### Étape 2.4 — Analyse des états de connexion et des ports

**Commande** : `ss -tan` ou `netstat -tan`

**Contexte** : sur la cible Linux, après la résolution des adresses. L'objectif est d'analyser les états de connexion et les ports.

**Résultat attendu** : analyse détaillée des états et des ports utilisés.

```bash
# Sur la cible : états de connexion
ss -tan 2>&1 | tee preuves/ch4-lab2/etats-connexion.txt
ss -uan 2>&1 | tee -a preuves/ch4-lab2/etats-connexion.txt
netstat -tan 2>&1 | tee -a preuves/ch4-lab2/etats-connexion.txt
```

**Ce que vous devez observer** :
- états `ESTABLISHED`, `LISTEN`, `TIME-WAIT` ;
- ports et états ;
- connexions anormales ;
- preuve `etats-connexion.txt`.

**L'enregistrement** : notez l'analyse dans votre rapport. Conservez le fichier de preuve.

#### Étape 2.5 — Recherche de connexions sur des ports non standards

**Commande** : `grep ":<port>" /proc/net/tcp`

**Contexte** : sur la cible Linux, après l'analyse des états. L'objectif est de rechercher les connexions sur des ports non standards.

**Résultat attendu** : connexions sur ports non standards détectées.

```bash
# Sur la cible : recherche du port 4444 (0x115C)
grep -i ":115C" /proc/net/tcp 2>&1 | tee preuves/ch4-lab2/ports-non-standards.txt
```

> **Repère** — Les ports de `/proc/net/tcp` sont en hexadécimal : 4444 = `115C`, 5555 = `15B3`.

**Ce que vous devez observer** :
- connexions sur ports non standards ;
- canaux C2 ou exfiltration potentiels ;
- preuve `ports-non-standards.txt`.

**L'enregistrement** : notez les ports non standards dans votre rapport. Conservez le fichier de preuve.

#### Étape 2.6 — Capture complémentaire du trafic

**Commande** : `sudo tcpdump -i any -nn -s0 -w preuves/ch4-lab2/capture.pcap -c 500`

**Contexte** : sur Kali ou sur la cible, après l'analyse des connexions. L'objectif est de produire une capture complémentaire pour Wireshark.

**Résultat attendu** : fichier `capture.pcap` contenant 500 paquets.

```bash
# Sur Kali : capture complémentaire
sudo tcpdump -i any -nn -s0 -w preuves/ch4-lab2/capture.pcap -c 500 \
  2>&1 | tee preuves/ch4-lab2/tcpdump-capture.log
sudo tcpdump -r preuves/ch4-lab2/capture.pcap -nn \
  'host 192.168.56.103 or host 192.168.56.101' \
  2>&1 | tee preuves/ch4-lab2/filtre-cibles.txt
```

**Ce que vous devez observer** :
- fichier `capture.pcap` créé ;
- paquets filtrés vers la cible et Kali ;
- preuves `tcpdump-capture.log` et `filtre-cibles.txt`.

**L'enregistrement** : conservez la capture et les journaux. Ouvrez `capture.pcap` dans Wireshark et appliquez les filtres `ip.addr == 192.168.56.103`, `tcp.flags.syn == 1 && tcp.flags.ack == 0` et `http.request`.

### 2.3 Plan d'attaque de Lab 2 à remplir en temps réel

| # | Étape | Technique ATT&CK | ID | Statut | Résultat observé | Détection observée | Mitigation applicable | Notes temps réel |
|---|---|---|---|---|---|---|---|---|
| 1 | Connexions établies | Network Sniffing (analyse) | T1040 | | | | | |
| 2 | Connexions sortantes | Application Layer Protocol | T1071 | | | | | |
| 3 | Résolution DNS | Application Layer Protocol | T1071 | | | | | |
| 4 | États de connexion | Network Sniffing (analyse) | T1040 | | | | | |
| 5 | Ports non standards | Non-Standard Port | T1571 | | | | | |
| 6 | Capture complémentaire | Network Sniffing (analyse) | T1040 | | | | | |

> Note — Cet exercice illustre `T1040` (analyse), `T1071` (analyse du protocole applicatif) et `T1571` (port non standard). Aucun scan de ports n'est exécuté dans ce lab.

### 2.4 Ce que vous devez observer en Lab 2

**Résultat attendu** :
- liste complète des connexions établies avec PID et utilisateur ;
- connexions sortantes avec adresses IP et ports distants ;
- au moins 1 port non standard détecté ;
- capture `capture.pcap` analysable dans Wireshark ;
- analyse de la potentielle exfiltration ou communication C2.

**Critères de réussite de Lab 2** :
- toutes les connexions documentées avec PID et utilisateur ;
- connexions sortantes identifiées et analysées ;
- au moins 1 port non standard détecté ;
- capture `.pcap` et filtres Wireshark documentés.

### 2.5 Après Lab 2

Passez à Lab 3 — Analyse de l'exfiltration de données et preuves.

### 2.6 Corrigé — Lab 2

**Résolution détaillée :**

**Étape 2.1 — Liste des connexions réseau établies**
- **Commande** : `sudo ss -tulnp`
- **Résultat attendu** : sockets TCP/UDP avec PID et utilisateur.
- **Explication** : `-t` TCP, `-u` UDP, `-l` écoute, `-n` ports numériques, `-p` processus.
- **Piège courant** : exécuter `ss` sans `sudo` ; les PID des autres utilisateurs ne sont pas affichés.

**Résultat attendu final** :
- connexions listées ;
- fichier `preuves/ch4-lab2/ss-tuln.txt` présent.

**Étape 2.2 — Identification des connexions sortantes**
- **Commande** : `ss -t | grep ESTAB`
- **Résultat attendu** : connexions TCP établies.
- **Explication** : `ESTAB` filtre les connexions établies ; la colonne `Peer Address` donne la destination.
- **Piège courant** : confondre une connexion locale avec une connexion sortante.

**Résultat attendu final** :
- connexions sortantes listées ;
- fichier `connexions-sortantes.txt` présent.

**Étape 2.3 — Résolution des adresses distantes**
- **Commande** : `host 192.168.56.1`
- **Résultat attendu** : nom d'hôte ou `NXDOMAIN`.
- **Explication** : la résolution inverse peut révéler un nom de machine.
- **Piège courant** : interpréter `NXDOMAIN` comme une preuve d'attaque.

**Résultat attendu final** :
- résolution documentée ;
- fichier `resolution-dns.txt` présent.

**Étape 2.4 — Analyse des états de connexion et des ports**
- **Commande** : `ss -tan`
- **Résultat attendu** : états TCP.
- **Explication** : `SYN-SENT` répété ou `TIME-WAIT` nombreux peut indiquer un balayage ou une saturation.
- **Piège courant** : ne pas corréler l'état avec le PID.

**Résultat attendu final** :
- états documentés ;
- fichier `etats-connexion.txt` présent.

**Étape 2.5 — Recherche de connexions sur des ports non standards**
- **Commande** : `grep -i ":115C" /proc/net/tcp`
- **Résultat attendu** : ligne du port 4444 ou absence.
- **Explication** : `115C` est la représentation hexadécimale de 4444.
- **Piège courant** : chercher `:4444` en décimal.

**Résultat attendu final** :
- recherche documentée ;
- fichier `ports-non-standards.txt` présent.

**Étape 2.6 — Capture complémentaire du trafic**
- **Commande** : `sudo tcpdump -i any -nn -s0 -w preuves/ch4-lab2/capture.pcap -c 500`
- **Résultat attendu** : `capture.pcap` avec 500 paquets.
- **Explication** : `-w` écrit le pcap, `-c` limite le nombre de paquets.
- **Piège courant** : oublier `-c` et laisser la capture tourner indéfiniment.

**Conclusion Lab 2** :
- connexions et ports documentés ;
- capture réseau complémentaire produite ;
- analyse Wireshark préparée ;
- ATT&CK cartographié : T1040, T1071, T1571.

---

## Lab 3 — Analyse de l'exfiltration et preuves

### 3.1 Contexte et objectif

Après avoir enquêté sur les connexions réseau, cette étape vous permet d'identifier et de documenter les preuves d'exfiltration de données sur la machine cible compromise, afin de déterminer quelles données ont été transférées, par quelle méthode et vers quelle destination.

**Objectif de Lab 3** — Identifier et documenter les techniques d'exfiltration, évaluer le volume de données compromis et tracer la destination des données exfiltrées, puis intégrer ces éléments au rapport standard.

**Plan MITRE ATT&CK de Lab 3**

- **Technique** : T1041 Exfiltration Over C2 Channel (Exfiltration, analyse) ; T1071 / T1071.001 Application Layer Protocol / Web Protocols (Command and Control, analyse) ; T1053.003 Scheduled Task/Job: Cron (Execution / Persistence / Privilege Escalation, analyse).
- **Tactique** : Exfiltration (TA0010) ; Command and Control (TA0011) ; Execution (TA0002) ; Persistence (TA0003).
- **Source de données** : DS0029 Network Traffic (volume, destination) ; DS0015 Application Log (requêtes HTTP) ; DS0022 File (fichiers volumineux) ; DS0003 Scheduled Job (cron).
- **Règle de détection** : taille des fichiers, contenu cron, modèles de journal, processus de transfert.
- **Mitigation** : surveillance des transferts, contrôle des protocoles, surveillance des cron, prévention de l'exfiltration au niveau réseau.
- **Statut** : Couvert (analyse) pour T1041, T1071.001 et T1053.003.

### 3.2 Étapes de Lab 3

#### Étape 3.1 — Recherche de grands fichiers récemment créés ou modifiés

**Commande** : `find / -size +1M -type f -mtime -1 2>/dev/null`

**Contexte** : sur la machine cible Linux (`192.168.56.103`), après l'enquête réseau. L'objectif est d'identifier les grands fichiers récents.

**Résultat attendu** : liste des grands fichiers récents avec taille et chemin.

```bash
# Sur la cible : grands fichiers récents
mkdir -p preuves/ch4-lab3
sudo find / -size +1M -type f -mtime -1 2>/dev/null \
  | tee preuves/ch4-lab3/grands-fichiers.txt
```

**Ce que vous devez observer** :
- fichiers de plus de 1 Mo modifiés récemment ;
- données structurées ou exfiltrées potentielles ;
- preuve `grands-fichiers.txt`.

**L'enregistrement** : notez les fichiers dans votre rapport d'exfiltration. Conservez le fichier de preuve.

#### Étape 3.2 — Vérification des tâches cron suspectes

**Commande** : `crontab -l` et `cat /etc/crontab`

**Contexte** : sur la cible Linux, après avoir identifié les grands fichiers. L'objectif est de vérifier les tâches cron suspectes.

**Résultat attendu** : tâches cron analysées avec leur contenu.

```bash
# Sur la cible : tâches cron
crontab -l 2>&1 | tee preuves/ch4-lab3/cron-utilisateur.txt
sudo cat /etc/crontab 2>&1 | tee preuves/ch4-lab3/cron-systeme.txt
sudo ls -la /etc/cron.* 2>&1 | tee -a preuves/ch4-lab3/cron-systeme.txt
```

**Ce que vous devez observer** :
- tâches cron configurées ;
- horodatages et commandes ;
- tâches inhabituelles ou malveillantes ;
- preuves `cron-utilisateur.txt` et `cron-systeme.txt`.

**L'enregistrement** : notez les tâches suspectes dans votre rapport. Conservez les fichiers de preuve.

#### Étape 3.3 — Analyse des processus en cours d'exécution

**Commande** : `ps aux | grep -i -E "transfer|send|upload|download|base64|encode"`

**Contexte** : sur la cible Linux, après avoir vérifié les tâches cron. L'objectif est d'identifier les processus de transfert.

**Résultat attendu** : processus liés au transfert de données.

```bash
# Sur la cible : processus de transfert
ps aux 2>&1 | grep -i -E "transfer|send|upload|download|base64|encode" \
  | tee preuves/ch4-lab3/processus-transfert.txt
```

**Ce que vous devez observer** :
- processus et arguments ;
- PID et utilisateur ;
- preuve `processus-transfert.txt`.

**L'enregistrement** : notez les processus dans votre rapport. Conservez le fichier de preuve.

#### Étape 3.4 — Analyse des journaux de transfert

**Commande** : `grep -i "POST\|PUT\|SEND" /var/log/auth.log`

**Contexte** : sur la cible Linux, après l'analyse des processus. L'objectif est de rechercher des modèles de transfert dans les journaux.

**Résultat attendu** : modèles de transfert dans les journaux.

```bash
# Sur la cible : modèles de transfert dans auth.log
sudo grep -i "POST\|PUT\|SEND" /var/log/auth.log \
  2>&1 | tee preuves/ch4-lab3/transferts-auth.txt
# Complément : journal Apache si le service web est actif
sudo grep -i "POST\|PUT" /var/log/apache2/access.log \
  2>&1 | tee preuves/ch4-lab3/transferts-apache.txt
```

**Ce que vous devez observer** :
- requêtes `POST` ou `PUT` dans le journal Apache ;
- absence de transfert dans `auth.log` (normal) ;
- preuves `transferts-auth.txt` et `transferts-apache.txt`.

**L'enregistrement** : notez les modèles de transfert dans votre rapport. Conservez les fichiers de preuve.

#### Étape 3.5 — Identification des scripts suspects

**Commande** : `find /home -name "*.sh" -exec ls -la {} \; 2>/dev/null`

**Contexte** : sur la cible Linux, après l'analyse des journaux. L'objectif est d'identifier les scripts suspects.

**Résultat attendu** : scripts suspects avec contenu et localisation.

```bash
# Sur la cible : scripts suspects
sudo find /home -name "*.sh" -exec ls -la {} \; 2>/dev/null \
  | tee preuves/ch4-lab3/scripts-suspects.txt
```

**Ce que vous devez observer** :
- scripts dans les répertoires utilisateur ;
- contenu suspect ;
- preuve `scripts-suspects.txt`.

**L'enregistrement** : notez les scripts dans votre rapport. Conservez le fichier de preuve.

#### Étape 3.6 — Détermination du volume, de la méthode et du rapport

**Actions** :
1. Estimer le volume total des données exfiltrées.
2. Identifier la méthode de transfert (HTTP, FTP, SMB, base64, etc.).
3. Tracer la destination si possible.
4. Rédiger la section « Exfiltration » du rapport.

```bash
# Sur Kali : synthèse de l'exfiltration
{
  echo "Synthèse exfiltration — Ch4 Lab3"
  echo "=== Grands fichiers ==="
  cat preuves/ch4-lab3/grands-fichiers.txt
  echo "=== Cron ==="
  cat preuves/ch4-lab3/cron-systeme.txt
  echo "=== Processus ==="
  cat preuves/ch4-lab3/processus-transfert.txt
  echo "=== Transferts HTTP ==="
  cat preuves/ch4-lab3/transferts-apache.txt
} > preuves/ch4-lab3/synthese-exfiltration.txt 2>&1
```

**L'enregistrement** : déterminez le volume et la méthode dans votre rapport. Conservez `synthese-exfiltration.txt`.

### 3.3 Plan d'attaque de Lab 3 à remplir en temps réel

| # | Étape | Technique ATT&CK | ID | Statut | Résultat observé | Détection observée | Mitigation applicable | Notes temps réel |
|---|---|---|---|---|---|---|---|---|
| 1 | Grands fichiers | Exfiltration Over C2 Channel | T1041 | | | | | |
| 2 | Tâches cron | Scheduled Task/Job: Cron | T1053.003 | | | | | |
| 3 | Processus de transfert | Exfiltration Over C2 Channel | T1041 | | | | | |
| 4 | Journaux de transfert | Application Layer Protocol: Web Protocols | T1071.001 | | | | | |
| 5 | Scripts suspects | Exfiltration Over C2 Channel | T1041 | | | | | |

> Note — Cet exercice illustre `T1041` (analyse de l'exfiltration), `T1053.003` (analyse des cron) et `T1071.001` (analyse du protocole web). Aucune exfiltration n'est exécutée dans ce lab.

### 3.4 Ce que vous devez observer en Lab 3

**Résultat attendu** :
- grands fichiers identifiés avec tailles ;
- tâches cron suspectes documentées ;
- au moins 1 processus de transfert identifié ;
- modèle d'exfiltration documenté (protocole, destination estimée) ;
- section « Exfiltration » du rapport rédigée.

**Critères de réussite de Lab 3** :
- au moins 1 fichier de plus de 1 Mo créé ou modifié récemment ;
- tâches cron suspectes documentées ;
- au moins 1 processus de transfert identifié ;
- modèle d'exfiltration documenté.

### 3.5 Après Lab 3

Passez à Lab 4 — Restauration de l'environnement de test.

### 3.6 Corrigé — Lab 3

**Résolution détaillée :**

**Étape 3.1 — Recherche de grands fichiers récemment créés ou modifiés**
- **Commande** : `sudo find / -size +1M -type f -mtime -1 2>/dev/null`
- **Résultat attendu** : fichiers de plus de 1 Mo modifiés dans les dernières 24 heures.
- **Explication** : `-size +1M` filtre la taille, `-mtime -1` la date.
- **Piège courant** : oublier `2>/dev/null` ; les erreurs de permission polluent la sortie.

**Résultat attendu final** :
- grands fichiers listés ;
- fichier `preuves/ch4-lab3/grands-fichiers.txt` présent.

**Étape 3.2 — Vérification des tâches cron suspectes**
- **Commandes** : `crontab -l`, `sudo cat /etc/crontab`
- **Résultat attendu** : tâches cron utilisateur et système.
- **Explication** : une tâche cron peut automatiser un transfert périodique.
- **Piège courant** : oublier `/etc/cron.*`.

**Résultat attendu final** :
- tâches documentées ;
- fichiers `cron-utilisateur.txt` et `cron-systeme.txt` présents.

**Étape 3.3 — Analyse des processus en cours d'exécution**
- **Commande** : `ps aux | grep -i -E "transfer|send|upload|download|base64|encode"`
- **Résultat attendu** : processus de transfert.
- **Explication** : `ps aux` liste tous les processus ; `grep -i` ignore la casse.
- **Piège courant** : le `grep` se trouve lui-même dans la sortie ; filtrer avec `grep -v grep`.

**Résultat attendu final** :
- processus documentés ;
- fichier `processus-transfert.txt` présent.

**Étape 3.4 — Analyse des journaux de transfert**
- **Commande** : `sudo grep -i "POST\|PUT" /var/log/apache2/access.log`
- **Résultat attendu** : requêtes `POST` ou `PUT`, ou absence.
- **Explication** : `auth.log` ne contient pas les requêtes HTTP ; le journal Apache est la source pertinente.
- **Piège courant** : conclure à une absence d'exfiltration sur la seule base de `auth.log`.

**Résultat attendu final** :
- journaux analysés ;
- fichiers `transferts-auth.txt` et `transferts-apache.txt` présents.

**Étape 3.5 — Identification des scripts suspects**
- **Commande** : `sudo find /home -name "*.sh" -exec ls -la {} \; 2>/dev/null`
- **Résultat attendu** : scripts shell avec permissions et dates.
- **Explication** : un script récent et exécutable est un indicateur à corréler.
- **Piège courant** : ignorer les scripts sans extension `.sh`.

**Étape 3.6 — Détermination du volume, de la méthode et du rapport**
- **Action** : additionner les tailles et qualifier le protocole.
- **Explication** : le volume et le protocole orientent la gravité et la réponse.
- **Piège courant** : confondre taille sur disque et volume transféré.

**Conclusion Lab 3** :
- grands fichiers identifiés ;
- cron et processus analysés ;
- scripts suspects documentés ;
- ATT&CK cartographié : T1041, T1053.003, T1071.001.

---

## Lab 4 — Restauration de l'environnement de test

### 4.1 Contexte et objectif

Après avoir terminé tous les exercices, cette étape vous permet de restaurer Metasploitable 2 (`192.168.56.103`) à son snapshot propre afin de préparer les prochains tests.

**Objectif de Lab 4** — Restaurer la machine cible à son état initial, démonter les modifications apportées pendant l'exercice et s'assurer que l'environnement est prêt pour un nouveau cycle de test.

> **Précision ATT&CK** — La restauration de snapshot est une **remédiation**. Elle n'est pas mappée sur T1490 Inhibit System Recovery, qui décrit l'action adverse empêchant la restauration. T1485 Data Destruction décrit la destruction de données, pas la remise en état. Les deux IDs restent cités en référence théorique pour comprendre ce que la restauration neutralise.

**Plan MITRE ATT&CK de Lab 4**

- **Technique** : T1046 Network Service Discovery (Discovery, vérification défensive après restauration) ; T1490 Inhibit System Recovery et T1485 Data Destruction citées en référence théorique.
- **Tactique** : Discovery (TA0007) pour la vérification ; — (remédiation hors kill chain).
- **Source de données** : DS0020 Snapshot (état de la VM) ; DS0019 Service (services après redémarrage) ; DS0029 Network Traffic (connectivité après restauration).
- **Règle de détection** : intégrité du snapshot, disponibilité des services, connectivité des hôtes, résultat du scan de contrôle.
- **Mitigation** : snapshots réguliers, sauvegardes, tests de restauration, journalisation des changements.
- **Statut** : Couvert (vérification) pour T1046 ; Non applicable (remédiation) pour T1490 et T1485.

### 4.2 Étapes de Lab 4

#### Étape 4.1 — Identification du snapshot actuel

**Commande** : `vboxmanage snapshot "Metasploitable 2" list`

**Contexte** : sur la machine hôte (`192.168.56.1`), après avoir terminé tous les exercices. L'objectif est d'identifier le snapshot actuel et l'état de la VM.

**Résultat attendu** : liste des snapshots disponibles pour la VM Metasploitable 2.

```bash
# Sur l'hôte : liste des snapshots
mkdir -p preuves/ch4-lab4
vboxmanage snapshot "Metasploitable 2" list \
  2>&1 | tee preuves/ch4-lab4/snapshots-list.txt
```

**Ce que vous devez observer** :
- liste des snapshots disponibles ;
- identification du snapshot « propre - avant module 3 » ;
- preuve `snapshots-list.txt`.

**L'enregistrement** : notez le snapshot actuel dans votre rapport de restauration. Conservez la liste des snapshots.

#### Étape 4.2 — Restauration du snapshot

**Commande** : `vboxmanage snapshot "Metasploitable 2" restore "propre - avant module 3"`

**Contexte** : sur la machine hôte, après avoir identifié le snapshot à restaurer. L'objectif est de restaurer la VM à son état initial.

**Résultat attendu** : Metasploitable 2 restaurée à l'état « propre - avant module 3 ».

```bash
# Sur l'hôte : restauration du snapshot
vboxmanage snapshot "Metasploitable 2" restore "propre - avant module 3" \
  2>&1 | tee preuves/ch4-lab4/snapshot-restore.txt
```

**Ce que vous devez observer** : Metasploitable 2 restaurée à l'état « propre - avant module 3 ».

**L'enregistrement** : notez la restauration dans votre rapport. Conservez `snapshot-restore.txt`.

#### Étape 4.3 — Redémarrage de la VM

**Commande** : `vboxmanage controlvm "Metasploitable 2" reboot`

**Contexte** : sur la machine hôte, après avoir restauré le snapshot. L'objectif est de redémarrer la VM pour appliquer la restauration complète.

**Résultat attendu** : Metasploitable 2 redémarre avec l'état « propre - avant module 3 ».

```bash
# Sur l'hôte : redémarrage de la VM
vboxmanage controlvm "Metasploitable 2" reboot \
  2>&1 | tee preuves/ch4-lab4/snapshot-reboot.txt
```

**Ce que vous devez observer** : la VM redémarre avec l'état restauré.

**L'enregistrement** : notez le redémarrage dans votre rapport. Conservez `snapshot-reboot.txt`.

#### Étape 4.4 — Vérification de l'accès initial

**Actions** :
1. Vérifier la connexion SSH : `ssh msfadmin@192.168.56.103`.
2. Vérifier les identifiants par défaut.
3. Vérifier que les services attendus sont en cours d'exécution.

**Contexte** : sur la machine hôte, après le redémarrage. L'objectif est de vérifier que l'accès initial fonctionne après la restauration.

**Résultat attendu** : connexion SSH réussie, identifiants par défaut fonctionnels, services en cours d'exécution.

```bash
# Sur l'hôte : vérification de l'accès après restauration
ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa \
  msfadmin@192.168.56.103 "hostname; id" \
  2>&1 | tee preuves/ch4-lab4/verification-ssh.txt
ping -c 3 192.168.56.103 2>&1 | tee preuves/ch4-lab4/verification-ping.txt
nmap -sT -p 22,80 192.168.56.103 2>&1 | tee preuves/ch4-lab4/verification-nmap.txt
```

**Ce que vous devez observer** :
- connexion SSH réussie ;
- nom d'hôte et identité affichés ;
- ports 22 et 80 accessibles ;
- preuves `verification-ssh.txt`, `verification-ping.txt` et `verification-nmap.txt`.

**L'enregistrement** : notez la vérification dans votre rapport. Conservez les fichiers de preuve.

#### Étape 4.5 — Documentation des écarts

**Actions** :
1. Comparer l'état restauré à l'état d'origine attendu.
2. Documenter tout écart entre l'état restauré et l'état d'origine.
3. Générer un rapport de restauration documentant les écarts.

```bash
# Sur l'hôte : synthèse de la restauration
{
  echo "Rapport de restauration — Ch4 Lab4"
  echo "=== Snapshots ==="
  cat preuves/ch4-lab4/snapshots-list.txt
  echo "=== Restauration ==="
  cat preuves/ch4-lab4/snapshot-restore.txt
  echo "=== Vérification SSH ==="
  cat preuves/ch4-lab4/verification-ssh.txt
  echo "=== Vérification réseau ==="
  cat preuves/ch4-lab4/verification-ping.txt
  cat preuves/ch4-lab4/verification-nmap.txt
} > preuves/ch4-lab4/rapport-restauration.txt 2>&1
```

**L'enregistrement** : documentez les écarts dans votre rapport de restauration. Conservez `rapport-restauration.txt`.

### 4.3 Plan d'attaque de Lab 4 à remplir en temps réel

| # | Étape | Technique ATT&CK | ID | Statut | Résultat observé | Détection observée | Mitigation applicable | Notes temps réel |
|---|---|---|---|---|---|---|---|---|
| 1 | Identification du snapshot | — (remédiation) | — | | | | | |
| 2 | Restauration du snapshot | — (remédiation) | — | | | | | |
| 3 | Redémarrage de la VM | — (remédiation) | — | | | | | |
| 4 | Vérification de l'accès initial | Network Service Discovery (vérification) | T1046 | | | | | |
| 5 | Documentation des écarts | — (remédiation) | — | | | | | |

> Note — La restauration est une remédiation. T1046 est utilisé pour vérifier l'exposition après restauration. T1490 (Inhibit System Recovery) et T1485 (Data Destruction) sont mentionnés en référence théorique : ils décrivent les actions adverses que la restauration neutralise, pas les étapes de ce lab.

### 4.4 Ce que vous devez observer en Lab 4

**Résultat attendu** :
- snapshot identifié et restauré ;
- VM redémarrée ;
- accès SSH et services vérifiés ;
- écarts documentés dans le rapport de restauration.

**Critères de réussite de Lab 4** :
- snapshot « propre - avant module 3 » restauré ;
- accès initial vérifié ;
- services attendus disponibles ;
- rapport de restauration rédigé avec les écarts.

### 4.5 Après Lab 4

Toute la procédure est maintenant terminée. Vous pouvez passer à la synthèse et à la transition vers le chapitre 5.

### 4.6 Corrigé — Lab 4

**Résolution détaillée :**

**Étape 4.1 — Identification du snapshot actuel**
- **Commande** : `vboxmanage snapshot "Metasploitable 2" list`
- **Résultat attendu** : liste des snapshots, dont « propre - avant module 3 ».
- **Explication** : `vboxmanage` contrôle VirtualBox en ligne de commande.
- **Piège courant** : utiliser un nom de VM différent de celui enregistré dans VirtualBox.

**Résultat attendu final** :
- snapshots listés ;
- fichier `preuves/ch4-lab4/snapshots-list.txt` présent.

**Étape 4.2 — Restauration du snapshot**
- **Commande** : `vboxmanage snapshot "Metasploitable 2" restore "propre - avant module 3"`
- **Résultat attendu** : restauration confirmée.
- **Explication** : `restore` remet le disque virtuel à l'état du snapshot.
- **Piège courant** : restaurer un snapshot alors que la VM est allumée ; l'arrêter d'abord.

**Résultat attendu final** :
- restauration confirmée ;
- fichier `snapshot-restore.txt` présent.

**Étape 4.3 — Redémarrage de la VM**
- **Commande** : `vboxmanage controlvm "Metasploitable 2" reboot`
- **Résultat attendu** : VM redémarrée.
- **Explication** : le redémarrage applique l'état restauré.
- **Piège courant** : confondre `reboot` et `reset` ; `reset` coupe brutalement la VM.

**Résultat attendu final** :
- redémarrage confirmé ;
- fichier `snapshot-reboot.txt` présent.

**Étape 4.4 — Vérification de l'accès initial**
- **Commandes** : `ssh ...`, `ping -c 3 192.168.56.103`, `nmap -sT -p 22,80 192.168.56.103`
- **Résultat attendu** : SSH fonctionnel, ping sans perte, ports ouverts.
- **Explication** : la vérification confirme que la restauration n'a pas cassé les services.
- **Piège courant** : oublier les options `HostKeyAlgorithms` et `PubkeyAcceptedAlgorithms` pour les anciennes images SSH.

**Résultat attendu final** :
- accès vérifié ;
- fichiers `verification-ssh.txt`, `verification-ping.txt` et `verification-nmap.txt` présents.

**Étape 4.5 — Documentation des écarts**
- **Action** : comparer l'état restauré à l'état attendu et consigner les écarts.
- **Explication** : un écart peut révéler un snapshot incomplet ou un service non démarré.
- **Piège courant** : ne pas dater le rapport de restauration.

**Conclusion Lab 4** :
- snapshot restauré ;
- accès et services vérifiés ;
- écarts documentés ;
- remédiation terminée ; T1046 utilisé pour la vérification ; T1490/T1485 non mappés.

---

## 4. Synthèse et transition vers le chapitre 5

### 4.1 Validation finale de Lab 1 à Lab 4

Vérifiez que tous les labs ont été complétés :

- [ ] Lab 1 : consolidation des journaux — IoC identifiés, chronologie documentée, empreintes calculées.
- [ ] Lab 2 : enquête réseau — connexions analysées, capture `.pcap` produite.
- [ ] Lab 3 : analyse de l'exfiltration — méthode et volume documentés.
- [ ] Lab 4 : restauration — snapshot restauré, accès vérifié, écarts documentés.

Chaque lab a été cartographié sur MITRE ATT&CK avec sa technique, sa tactique, sa source de données, sa règle de détection et sa mitigation. Tous les résultats ont été documentés dans votre rapport forensique avec statut, résultat observé, détection observée et notes en temps réel.

### 4.2 Transition vers le chapitre 5

Le chapitre 5 poursuit avec l'audit de sécurité et la remédiation : audit des comptes utilisateurs, analyse SSH, politiques de mots de passe, durcissement du pare-feu, matrice de risques et plan de remédiation sur 90 jours. Les concepts de MITRE ATT&CK y sont approfondis avec des labs d'audit et de planification défensive.

**Bon travail !** Vous avez maintenant complété les 4 labs forensiques et d'investigation du chapitre 4 dans un environnement de laboratoire isolé. Ces compétences constituent la base pour la production de rapports professionnels et la remédiation.
