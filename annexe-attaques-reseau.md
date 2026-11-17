# Annexe A — Attaques réseau et applicatives (héritage)

> **Note d'annexe** — Ce fichier conserve les anciens Lab 1 (test de SYN flood contrôlé) et Lab 2 (injection SQL et buffer overflow) du chapitre 2. Ce contenu est **hors du parcours principal** du chapitre 2, qui traite Metasploit et les payloads Windows XP. Les commandes, tableaux, corrigés et identifiants ATT&CK sont conservés. Les preuves restent sous `preuves/ch2-lab1/` et `preuves/ch2-lab2/`.
>
> Les cibles de ces labs sont Kali (`192.168.56.101`) et Metasploitable 2 (`192.168.56.103`). Metasploitable 2 n'est **pas** une cible du chapitre 2 : ces labs ne doivent pas être exécutés dans le parcours principal. Ils sont conservés pour référence et pour une réutilisation ultérieure.

## Objet historique

Les labs conservés couvrent un test de SYN flood contrôlé depuis une seule source (`T1498`, `T1499`), puis une injection SQL et la génération d'une charge utile de buffer overflow (`T1190`, `T1203`, `T1068`). Le test SYN flood n'est pas un DDoS distribué : il mesure l'effet d'un flux SYN anormal depuis une seule machine.

## Prérequis hérités

| Élément | Détail |
|---|---|
| Machine attaquante | Kali Linux, IP `192.168.56.101` |
| Cible Linux | Metasploitable 2, IP `192.168.56.103` |
| Outils | `nmap`, `sqlmap`, `hping3`, `tcpdump` |
| Réseau | host-only `192.168.56.0/24`, DHCP désactivé |
| Sécurité | Environnement isolé, snapshot avant test, aucune cible réelle |
| Preuves | `preuves/ch2-lab1/` et `preuves/ch2-lab2/` |

## Cartographie ATT&CK héritée

| Lab | Techniques | Tactiques | Statut | Sources de données |
|---|---|---|---|---|
| Ch2 Lab1 | T1498 Network Denial of Service (simulation) ; T1499 Endpoint Denial of Service (simulation) ; T1499.001 OS Exhaustion Flood (théorique) ; T1499.002 Service Exhaustion Flood (théorique) ; T1499.003 Application Exhaustion Flood (théorique) ; T1499.004 Application or System Exploitation (théorique) | Impact | Couvert (simulation) pour T1498 et T1499 ; Théorique pour T1499.001, T1499.002, T1499.003 et T1499.004 | DS0029 Network Traffic ; DS0019 Service |
| Ch2 Lab2 | T1190 Exploit Public-Facing Application ; T1203 Exploitation for Client Execution (théorique) ; T1068 Exploitation for Privilege Escalation (théorique) | Initial Access ; Execution ; Privilege Escalation | T1190 couvert (simulation) ; T1203 et T1068 théoriques | DS0029 Network Traffic ; DS0015 Application Log ; DS0009 Process |

---

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

> **Rappel d'annexe** — Ces deux labs sont conservés hors du parcours principal du chapitre 2. Le parcours principal reprend au fichier `chapitre-02.md`, avec les labs `Lab-01` à `Lab-05` consacrés à Metasploit et aux payloads Windows XP.
