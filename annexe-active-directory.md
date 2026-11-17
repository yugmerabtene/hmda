# Annexe B — Attaques Active Directory (héritage)

> **Note d'annexe** — Ce fichier conserve l'ancien Lab 3 du chapitre 2, consacré aux attaques Active Directory. Ce contenu est **hors du parcours principal** du chapitre 2 et sert de base à la reconstruction du chapitre 3. Les commandes, tableaux, corrigés et identifiants ATT&CK sont conservés. Les preuves restent sous `preuves/ch2-lab3/` ; lors de la reconstruction du chapitre 3, elles seront renumérotées.
>
> La cible de ce lab est Windows Server 2016 (`192.168.56.102`). Windows Server 2016 n'est **pas** une cible du chapitre 2 : ce lab ne doit pas être exécuté dans le parcours principal.

## Objet historique

Le lab conservé couvre l'extraction théorique de hachages (`T1003.003`), la simulation de Pass-the-Hash avec un hachage factice (`T1550.002`) et le brute-force LDAP (`T1110.001`). Les techniques associées non exécutées restent cartographiées dans le tableau ci-dessous.

## Prérequis hérités

| Élément | Détail |
|---|---|
| Machine attaquante | Kali Linux, IP `192.168.56.101` |
| Cible Active Directory | Windows Server 2016, IP `192.168.56.102` |
| Outils | `hydra`, `pth-winexe`, Metasploit |
| Réseau | host-only `192.168.56.0/24`, DHCP désactivé |
| Sécurité | Environnement isolé, snapshot avant test, aucune cible réelle |
| Preuves | `preuves/ch2-lab3/` |

## Cartographie ATT&CK héritée

| Lab | Techniques | Tactiques | Statut | Sources de données |
|---|---|---|---|---|
| Ch2 Lab3 | T1003 OS Credential Dumping (théorique) ; T1003.002 Security Account Manager (théorique) ; T1003.003 NTDS (théorique) ; T1550 Use Alternate Authentication Material (théorique) ; T1550.002 Pass the Hash (théorique — simulation avec hash factice) ; T1110 Brute Force (simulation) ; T1110.001 Password Guessing (simulation) ; T1110.002 Password Cracking (théorique) ; T1110.003 Password Spraying (théorique) ; T1087.002 Domain Account Discovery (théorique) ; T1018 Remote System Discovery (théorique) ; T1021.002 SMB/Windows Admin Shares (théorique) ; T1482 Domain Trust Discovery (théorique) ; T1558.003 Kerberoasting (théorique) ; T1558.004 AS-REP Roasting (théorique) | Credential Access ; Defense Evasion ; Lateral Movement ; Discovery | T1110 et T1110.001 couverts (simulation) ; T1550.002 théorique (simulation avec hash factice) ; autres théoriques | DS0026 Active Directory ; DS0028 Logon Session ; DS0002 User Account ; DS0029 Network Traffic |

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

> **Rappel d'annexe** — Ce lab est conservé hors du parcours principal du chapitre 2. La reconstruction du chapitre 3 réutilisera ce contenu, avec les cibles Windows Server 2016 et Active Directory.
