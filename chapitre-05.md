# Chapitre 5 — Audit, durcissement et remédiation

Version du contenu : 8.3 — alignement sur le plan maître du chapitre 1.

## 1. Objectif

Ce chapitre vous guide pas à pas à travers l'audit de sécurité et la remédiation d'un environnement de laboratoire. Vous apprendrez à auditer les comptes utilisateurs, à analyser la configuration SSH, à mettre en œuvre une politique de mots de passe, à auditer et durcir un pare-feu, à construire une matrice de risques et à rédiger un plan de remédiation sur 90 jours.

> **Plan maître** — Ce chapitre exécute les lignes `Ch5 Lab1` à `Ch5 Lab7` du plan maître défini au **Chapitre 1, Lab 3**. Chaque étape met à jour `journal-execution.csv` et la couche Navigator. Ne recréez pas de plan local : reprenez la ligne existante et renseignez son statut.

> **Règle de lecture ATT&CK** — Les labs de ce chapitre sont des **audits défensifs**. Les techniques citées décrivent les comportements adverses que l'audit cherche à prévenir ou à détecter. Le statut « Couvert (audit) » signifie que le lab observe ou durcit le contrôle correspondant ; il ne signifie pas que l'action adverse est exécutée.

## 2. Prérequis

**Avant de commencer :** assurez-vous d'avoir :

- chapitres 1 à 4 complétés ;
- snapshot de Metasploitable 2 (`192.168.56.103`) pris avant les modifications ;
- accès `root` ou `sudo` sur la cible Linux ;
- dossier `preuves/` créé à la racine du laboratoire.

| Élément | Détail |
|---|---|
| Machine attaquante | Kali Linux, IP `192.168.56.101`, 2 Go de RAM, 2 CPU, disque 20 Go dynamique |
| Cible Linux | Metasploitable 2, IP `192.168.56.103`, 2 Go de RAM, 2 CPU, disque 20 Go dynamique |
| Cible Active Directory | Windows Server 2016, IP `192.168.56.102` |
| Cible legacy | Windows XP, IP `192.168.56.104` |
| Hôte | `192.168.56.1` (interface `vboxnet0`) |
| Outils | `cut`, `awk`, `grep`, `getent`, `chage`, `passwd`, `ufw` ou `iptables`, `nmap`, `ssh` |
| Connaissances | Administration Linux, PAM, SSH, pare-feu, gestion des risques |
| Sécurité | Laboratoire isolé, snapshots, aucune exposition Internet |

## 3. Plan MITRE ATT&CK du chapitre

| Lab | Techniques | Tactiques | Statut | Sources de données |
|---|---|---|---|---|
| Ch5 Lab1 | T1087 Account Discovery ; T1069 Permission Groups Discovery ; T1110 / T1110.001 Brute Force / Password Guessing | Discovery ; Credential Access | Couvert (audit) pour T1087 et T1069 ; Couvert (audit défensif) pour T1110 / T1110.001 | DS0002 User Account ; DS0028 Logon Session ; DS0022 File |
| Ch5 Lab2 | T1021 Remote Services ; T1078 Valid Accounts | Lateral Movement ; Initial Access / Defense Evasion | Couvert (audit) | DS0028 Logon Session ; DS0015 Application Log ; DS0022 File |
| Ch5 Lab3 | T1110 / T1110.001 Brute Force / Password Guessing | Credential Access | Couvert (audit défensif) | DS0002 User Account ; DS0022 File |
| Ch5 Lab4 | T1046 Network Service Discovery ; T1562.004 Disable or Modify System Firewall | Discovery ; Defense Evasion | Couvert (audit) pour T1046 ; Couvert (audit / détection) pour T1562.004 | DS0018 Firewall ; DS0029 Network Traffic |
| Ch5 Lab5 | T1190 Exploit Public-Facing Application ; T1203 Exploitation for Client Execution ; T1210 Exploitation of Remote Services ; T1068 Exploitation for Privilege Escalation | Initial Access ; Execution ; Lateral Movement ; Privilege Escalation | Couvert (cartographie) | DS0022 File ; DS0026 Active Directory ; DS0029 Network Traffic |
| Ch5 Lab6 | — (planification défensive) ; IDs des Labs 1-5 en référence | — | Non applicable (planification) | DS0022 File |
| Ch5 Lab7 | — (validation) ; IDs des Labs 1-6 en référence | — | Non applicable (validation) | DS0022 File |
| Non applicable (chapitre) | T1550.002 Pass the Hash ; T1036 Masquerading ; T1499 Endpoint Denial of Service ; T1539 Steal Web Session Cookie | — | Non applicable | — |

## Lab 1 — Audit de sécurité des comptes utilisateurs

### 1.1 Contexte et objectif

**Contexte du lab** : l'étudiant effectue un audit des comptes utilisateurs sur la cible Metasploitable 2 (`192.168.56.103`) afin de documenter les comptes et leurs autorisations dans l'environnement de laboratoire.

**But du lab** : documenter l'état complet de tous les comptes utilisateurs, identifier les vulnérabilités de gestion des comptes et recommander des corrections immédiates et à long terme.

**Plan MITRE ATT&CK de Lab 1**

- **Technique** : T1087 Account Discovery (Discovery, audit) ; T1069 Permission Groups Discovery (Discovery, audit) ; T1110 / T1110.001 Brute Force / Password Guessing (Credential Access, audit défensif).
- **Tactique** : Discovery (TA0007) ; Credential Access (TA0006).
- **Source de données** : DS0002 User Account (comptes et attributs) ; DS0028 Logon Session (authentifications) ; DS0022 File (`/etc/passwd`, `/etc/shadow`, `/etc/group`).
- **Détection attendue** : listes de comptes, informations UID/GID, appartenances de groupe, détails `shadow`.
- **Mitigation associée** : audits de comptes réguliers, suppression des comptes en dormance, politiques de mots de passe fortes, principe du moindre privilège, surveillance des appartenances de groupe.
- **Statut** : Couvert (audit) pour T1087 et T1069 ; Couvert (audit défensif) pour T1110 / T1110.001.

### 1.2 Étapes à suivre

1. Listez tous les comptes utilisateurs : `cut -d: -f1 /etc/passwd`.
2. Identifiez les comptes en dormance (UID < 1000 ou inactifs) : `awk -F: '$3 < 1000 {print $1}' /etc/passwd`.
3. Extrayez les hachages de `root` et `msfadmin` dans un fichier de travail, puis évaluez leur résistance avec `john` : `sudo awk -F: '$1=="root" || $1=="msfadmin" {print $1":"$2}' /etc/shadow | sudo tee preuves/ch5-lab1/hashes.txt`.
4. Recherchez les comptes sans mot de passe ou avec mots de passe vides : `sudo awk -F: '$2=="" || $2=="!" {print $1}' /etc/shadow`.
5. Vérifiez les appartenances de groupe : `groups username` pour chaque utilisateur.
6. Identifiez les membres du groupe `sudo` : `getent group sudo`.
7. Documentez toute anomalie (comptes en dormance, autorisations excessives, groupes non autorisés).

```bash
# Sur la cible : audit des comptes, avec preuves
mkdir -p preuves/ch5-lab1
cut -d: -f1 /etc/passwd 2>&1 | tee preuves/ch5-lab1/comptes.txt
awk -F: '$3 < 1000 {print $1}' /etc/passwd 2>&1 | tee preuves/ch5-lab1/comptes-systeme.txt
sudo grep -E '^(root|msfadmin):' /etc/shadow 2>&1 | tee preuves/ch5-lab1/shadow-extrait.txt
sudo awk -F: '$1=="root" || $1=="msfadmin" {print $1":"$2}' /etc/shadow \
  2>&1 | sudo tee preuves/ch5-lab1/hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt preuves/ch5-lab1/hashes.txt \
  2>&1 | tee preuves/ch5-lab1/john.txt
sudo awk -F: '$2=="" || $2=="!" {print $1}' /etc/shadow 2>&1 | tee preuves/ch5-lab1/comptes-sans-mot-de-passe.txt
for u in $(cut -d: -f1 /etc/passwd); do groups "$u"; done 2>&1 | tee preuves/ch5-lab1/groupes.txt
getent group sudo 2>&1 | tee preuves/ch5-lab1/groupe-sudo.txt
```

### 1.3 Résultat attendu

- liste complète de tous les comptes utilisateurs ;
- comptes en dormance identifiés avec UID et raison ;
- force des mots de passe évaluée (forte, moyenne, faible) ;
- comptes sans mot de passe ou vides identifiés ;
- appartenances de groupe analysées avec anomalies notées ;
- membres du groupe `sudo` documentés ;
- liste d'anomalies avec recommandations.

### 1.4 À rapporter dans le rapport

- liste complète des comptes utilisateurs avec UID/GID ;
- comptes en dormance avec UID < 1000 ou inactifs ;
- évaluation de la force des mots de passe par compte ;
- comptes sans mot de passe ou vides identifiés ;
- appartenances de groupe analysées avec anomalies ;
- membres du groupe `sudo` documentés ;
- recommandations correctives par anomalie identifiée.

### 1.5 Critères de réussite

- tous les comptes utilisateurs listés avec UID/GID ;
- comptes en dormance identifiés et documentés ;
- évaluation de la force des mots de passe complétée ;
- au moins 1 anomalie identifiée et documentée ;
- recommandations correctives fournies pour les anomalies ;
- preuves `preuves/ch5-lab1/*.txt` présentes.

### 1.6 Corrigé — Lab 1

**Résolution détaillée :**

**Étape 1.1 — Liste complète des comptes utilisateurs**
- **Commande** : `cut -d: -f1 /etc/passwd`
- **Résultat attendu** : liste de tous les comptes utilisateurs du système : `root`, `daemon`, `bin`, `sys`, `metasploit`, `postgres`, `www-data`, `msfadmin`, `user`, etc.
- **Explication** : `/etc/passwd` contient tous les comptes système au format `login:mot_de_passe:uid:gid:commentaire:répertoire_accueil:shell`.
- **Piège courant** : oublier que certains comptes système (`daemon`, `bin`, `sys`) n'ont pas de mot de passe actif.

**Résultat attendu final** :
- liste complète des comptes affichée ;
- fichier `preuves/ch5-lab1/comptes.txt` présent ;
- identification des comptes système et des comptes utilisateurs.

**Étape 1.2 — Analyse des hachages de mots de passe**
- **Commande** : `sudo cut -d: -f1,2 /etc/shadow` (ou `sudo grep -E '^(root|msfadmin):' /etc/shadow`)
- **Résultat attendu** :
  - `root:$6$...` (hachage SHA-512) ;
  - `msfadmin:$6$...` (hachage SHA-512) ;
  - `www-data:!*...` (compte verrouillé) ;
  - `postgres:....` (hachage PostgreSQL).
- **Explication** : `/etc/shadow` contient les hachages de mots de passe, accessible uniquement avec `root`. Le format `$6$` indique SHA-512.
- **Piège courant** : essayer de lire `/etc/shadow` sans `sudo` ; la lecture est refusée.

**Résultat attendu final** :
- hachages affichés pour `root` et `msfadmin` ;
- comptes verrouillés (`!*`) identifiés ;
- fichier `preuves/ch5-lab1/shadow-extrait.txt` présent.

**Étape 1.3 — Vérification de la force des mots de passe**
- **Commande** : `john --wordlist=/usr/share/wordlists/rockyou.txt preuves/ch5-lab1/hashes.txt`
- **Résultat attendu** : John the Ripper teste les hachages avec un dictionnaire de laboratoire.
- **Explication** : `john` compare les hachages aux candidats du dictionnaire. La commande `john --test` ne casse aucun mot de passe : elle mesure seulement les performances de calcul.
- **Piège courant** : utiliser `john --test` en croyant tester les mots de passe ; cette option ne traite pas les hachages.

**Résultat attendu final** :
- résultat de John the Ripper sur les hachages ;
- force des mots de passe évaluée (forte, faible, non cassée dans le temps imparti) ;
- fichier de preuve `preuves/ch5-lab1/john.txt` présent.

**Conclusion Lab 1** :
- liste complète des comptes documentée ;
- hachages analysés avec `/etc/shadow` ;
- force des mots de passe évaluée ;
- ATT&CK cartographié : T1087, T1069, T1110 / T1110.001.

---

## Lab 2 — Analyse des vulnérabilités du service SSH

### 2.1 Contexte et objectif

**Contexte du lab** : l'étudiant analyse la configuration SSH de Metasploitable 2 (`192.168.56.103`) pour documenter ses paramètres et les écarts de sécurité observés.

**But du lab** : documenter la configuration SSH actuelle, identifier les faiblesses de sécurité et recommander des configurations durcies.

**Plan MITRE ATT&CK de Lab 2**

- **Technique** : T1021 Remote Services (Lateral Movement, audit) ; T1078 Valid Accounts (Initial Access / Defense Evasion / Persistence / Privilege Escalation, audit).
- **Tactique** : Lateral Movement (TA0008) ; Initial Access (TA0001) ; Defense Evasion (TA0005).
- **Source de données** : DS0028 Logon Session (authentifications SSH) ; DS0015 Application Log (`auth.log`) ; DS0022 File (`sshd_config`, `authorized_keys`).
- **Détection attendue** : contenu du fichier de configuration, états du service, valeurs des directives.
- **Mitigation associée** : configurations SSH durcies, directives CIS/NSA/NIST, mise à jour régulière, audits de configuration.
- **Statut** : Couvert (audit).

### 2.2 Étapes à suivre

1. Localisez le fichier de configuration SSH : `cat /etc/ssh/sshd_config`.
2. Identifiez les options de sécurité et leur valeur actuelle : `PasswordAuthentication`, `PermitRootLogin`, `PubkeyAuthentication`, `HostKeyAlgorithms`, `PubkeyAcceptedAlgorithms`.
3. Comparez la configuration actuelle aux recommandations de durcissement : standards CIS, NSA, NIST.
4. Identifiez les algorithmes obsolètes (`ssh-rsa`, clé RSA 1024 bits, etc.).
5. Vérifiez le statut du service SSH : `systemctl status ssh` ou `service ssh status`.
6. Documentez les écarts par rapport aux configurations durcies.
7. Recommandez des modifications de configuration pour sécuriser SSH.

```bash
# Sur la cible : audit SSH, avec preuves
mkdir -p preuves/ch5-lab2
cat /etc/ssh/sshd_config 2>&1 | tee preuves/ch5-lab2/sshd_config.txt
grep -E '^(PasswordAuthentication|PermitRootLogin|PubkeyAuthentication|HostKeyAlgorithms|PubkeyAcceptedAlgorithms)' \
  /etc/ssh/sshd_config 2>&1 | tee preuves/ch5-lab2/directives.txt
ssh -Q key 2>&1 | tee preuves/ch5-lab2/algorithmes-cles.txt
ssh -Q kex 2>&1 | tee preuves/ch5-lab2/algorithmes-kex.txt
systemctl status ssh 2>&1 | tee preuves/ch5-lab2/statut-ssh.txt
```

### 2.3 Résultat attendu

- contenu complet du fichier `/etc/ssh/sshd_config` analysé ;
- valeurs actuelles des directives de sécurité identifiées ;
- comparaison aux standards CIS/NSA/NIST avec écarts notés ;
- algorithmes obsolètes identifiés ;
- statut du service SSH documenté ;
- liste d'écarts avec recommandations de correction.

### 2.4 À rapporter dans le rapport

- contenu complet du fichier `/etc/ssh/sshd_config` (ou extraits clés) ;
- valeurs actuelles des directives de sécurité ;
- écart par rapport aux standards CIS/NSA/NIST documenté par directive ;
- algorithmes obsolètes identifiés avec recommandation de remplacement ;
- statut du service SSH (actif, inactif, désactivé) ;
- recommandations de modification par directive.

### 2.5 Critères de réussite

- fichier de configuration SSH récupéré avec succès ;
- au moins 5 directives de sécurité identifiées et évaluées ;
- au moins 1 écart par rapport aux standards noté ;
- au moins 1 algorithme obsolète identifié avec remplacement recommandé ;
- recommandations de configuration fournies ;
- preuves `preuves/ch5-lab2/*.txt` présentes.

### 2.6 Corrigé — Lab 2

**Résolution détaillée :**

**Étape 2.1 — Vérification de la configuration SSH**
- **Commande** : `cat /etc/ssh/sshd_config`
- **Résultat attendu** : contenu complet du fichier, incluant `Port 22`, `PermitRootLogin`, `PasswordAuthentication`, `PubkeyAuthentication`, `MaxAuthTries`.
- **Explication** : `/etc/ssh/sshd_config` définit tous les paramètres du serveur SSH.
- **Piège courant** : ne pas remarquer les valeurs par défaut qui peuvent être des failles de sécurité.

**Résultat attendu final** :
- configuration complète affichée ;
- fichier `preuves/ch5-lab2/sshd_config.txt` présent ;
- paramètres de sécurité identifiés.

**Étape 2.2 — Vérification de la politique de mot de passe**
- **Commandes** : `chage -l msfadmin` et `passwd -S msfadmin`
- **Résultat attendu** :
  - `chage -l msfadmin` : date d'expiration, dernier changement, nombre de jours avant expiration ;
  - `passwd -S msfadmin` : `msfadmin PS` (mot de passe défini) ou `L` (verrouillé).
- **Explication** : `chage` gère les expirations de mots de passe ; `passwd -S` vérifie l'état du mot de passe.
- **Piège courant** : confondre les formats de sortie entre Debian/Ubuntu et RHEL/CentOS.

**Résultat attendu final** :
- résultats de `chage` et `passwd -S` affichés ;
- politique documentée ;
- preuve `preuves/ch5-lab2/politique-mot-de-passe.txt` présente.

**Étape 2.3 — Vérification de l'authentification basée sur clé**
- **Commande** : `cat /home/msfadmin/.ssh/authorized_keys`
- **Résultat attendu** : une ou plusieurs clés publiques listées, ou fichier absent.
- **Explication** : `authorized_keys` définit les clés autorisées pour SSH.
- **Piège courant** : permissions incorrectes (700 pour `~/.ssh`, 600 pour `authorized_keys`).

**Résultat attendu final** :
- contenu de `authorized_keys` affiché ou absence documentée ;
- preuve `preuves/ch5-lab2/authorized_keys.txt` présente.

**Conclusion Lab 2** :
- configuration SSH documentée ;
- politique de mot de passe vérifiée ;
- clés SSH analysées ;
- ATT&CK cartographié : T1021, T1078.

---

## Lab 3 — Mise en œuvre des politiques de mots de passe fortes

### 3.1 Contexte et objectif

**Contexte du lab** : l'étudiant examine les politiques de mot de passe de Metasploitable 2 (`192.168.56.103`) et documente les écarts observés. Toute modification doit être faite sur un snapshot de laboratoire restaurable.

**But du lab** : mettre en place et valider des politiques de mot de passe qui empêchent les mots de passe faibles et renforcent la sécurité globale de l'authentification.

**Plan MITRE ATT&CK de Lab 3**

- **Technique** : T1110 / T1110.001 Brute Force / Password Guessing (Credential Access, audit défensif).
- **Tactique** : Credential Access (TA0006).
- **Source de données** : DS0002 User Account (comptes et politiques) ; DS0022 File (`/etc/pam.d/common-password`, `/etc/security/pwquality.conf`, `/etc/login.defs`).
- **Détection attendue** : configuration PAM, paramètres `pwquality.conf`, paramètres `login.defs`, résultat du changement de mot de passe.
- **Mitigation associée** : politiques de mots de passe fortes, rotation régulière, complexité requise, validation du rejet des mots de passe faibles.
- **Statut** : Couvert (audit défensif).

### 3.2 Étapes à suivre

1. Sauvegardez le fichier PAM actuel : `sudo cp /etc/pam.d/common-password /etc/pam.d/common-password.backup`.
2. Modifiez `/etc/pam.d/common-password` pour inclure les règles de complexité souhaitées avec `pam_pwquality`.
3. Configurez `/etc/security/pwquality.conf` avec les paramètres requis : `MINLENGTH`, `REQUIRE_DIGIT`, `REQUIRE_UPCASE`, `REQUIRE_LOWERCASE`, `REQUIRE_SPECIAL`.
4. Définissez `MAXDAYS` et `MINDAYS` dans `/etc/login.defs` pour la rotation des mots de passe.
5. Appliquez la nouvelle politique en testant le changement de mot de passe : `passwd utilisateur`.
6. Testez que les mots de passe faibles sont rejetés pendant le changement.
7. Documentez tous les changements apportés et validez la nouvelle politique.

```bash
# Sur la cible : sauvegarde et preuve
mkdir -p preuves/ch5-lab3
sudo cp /etc/pam.d/common-password /etc/pam.d/common-password.backup
ls -l /etc/pam.d/common-password /etc/pam.d/common-password.backup \
  2>&1 | tee preuves/ch5-lab3/sauvegarde-pam.txt

# Activation du module PAM (pwquality si présent, sinon cracklib)
if [ -e /lib/security/pam_pwquality.so ] || [ -e /lib/x86_64-linux-gnu/security/pam_pwquality.so ]; then
  PAM_MODULE=pam_pwquality.so
else
  PAM_MODULE=pam_cracklib.so
  echo "pam_pwquality absent : utilisation de pam_cracklib.so" \
    | tee preuves/ch5-lab3/fallback-pam.txt
fi
if ! grep -q "$PAM_MODULE" /etc/pam.d/common-password; then
  sudo sed -i "/^password.*pam_unix.so/i password requisite $PAM_MODULE retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1" \
    /etc/pam.d/common-password
fi
grep -nE 'pam_pwquality|pam_cracklib|pam_unix' /etc/pam.d/common-password \
  2>&1 | tee preuves/ch5-lab3/common-password.txt

# Configuration de pwquality (exemple de paramètres)
sudo tee /etc/security/pwquality.conf > /dev/null <<'EOF'
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
retry = 3
EOF
grep -E '^(minlen|dcredit|ucredit|lcredit|ocredit|retry)' /etc/security/pwquality.conf \
  2>&1 | tee preuves/ch5-lab3/pwquality.txt

# Rotation des mots de passe
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
grep -E '^PASS_(MAX|MIN)_DAYS' /etc/login.defs 2>&1 | tee preuves/ch5-lab3/login-defs.txt
```

> **Compatibilité PAM** — Si `pam_pwquality.so` est absent, le script utilise `pam_cracklib.so` et l'option `minlen` de la ligne PAM. Dans ce cas, `/etc/security/pwquality.conf` n'est pas lu : documentez la variante et conservez les options sur la ligne PAM.

> **Test interactif** — Le changement de mot de passe se fait avec `script -q -c "sudo passwd msfadmin" preuves/ch5-lab3/test-passwd.txt`. Le mot de passe n'est pas écrit dans le fichier de preuve : seul le résultat (succès ou rejet) est conservé.

### 3.3 Résultat attendu

- fichier PAM sauvegardé avec confirmation ;
- `/etc/pam.d/common-password` modifié avec règles de complexité ;
- `/etc/security/pwquality.conf` configuré avec paramètres requis ;
- `/etc/login.defs` mis à jour avec paramètres de rotation ;
- test de changement de mot de passe réussi avec mot de passe fort ;
- échec du changement de mot de passe avec mot de passe faible documenté ;
- documentation complète des changements.

### 3.4 À rapporter dans le rapport

- fichier PAM sauvegardé avec date et heure ;
- configuration `/etc/pam.d/common-password` modifiée avec lignes ajoutées ;
- `/etc/security/pwquality.conf` avec paramètres et valeurs ;
- `/etc/login.defs` avec paramètres `DAYS` modifiés ;
- résultat du test de mot de passe fort (succès) ;
- résultat du test de mot de passe faible (échec avec message d'erreur) ;
- documentation complète des changements et validations.

### 3.5 Critères de réussite

- PAM sauvegardé avec horodatage ;
- PAM modifié avec règles de complexité (au moins 3 paramètres `pwquality`) ;
- `pwquality.conf` configuré avec au moins 3 paramètres (longueur, chiffre, spécial) ;
- `login.defs` mis à jour avec `MIN/MAX DAYS` ;
- test mot de passe fort réussi ;
- test mot de passe faible échoué et documenté ;
- documentation complète fournie ;
- preuves `preuves/ch5-lab3/*.txt` présentes.

### 3.6 Corrigé — Lab 3

**Résolution détaillée :**

**Étape 3.1 — Sauvegarde du fichier PAM**
- **Commande** : `sudo cp /etc/pam.d/common-password /etc/pam.d/common-password.backup`
- **Résultat attendu** : fichier de sauvegarde créé.
- **Explication** : la sauvegarde permet de revenir à la configuration précédente en cas d'erreur.
- **Piège courant** : modifier PAM sans sauvegarde et bloquer les changements de mot de passe.

**Résultat attendu final** :
- sauvegarde présente ;
- fichier `preuves/ch5-lab3/sauvegarde-pam.txt` présent.

**Étape 3.2 — Modification de `/etc/pam.d/common-password`**
- **Action** : ajouter ou modifier la ligne `password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1`, avant `pam_unix.so`.
- **Résultat attendu** : module de complexité actif pour le changement de mot de passe.
- **Explication** : `pam_pwquality` applique les règles de complexité à la création et au changement de mot de passe. Si le module est absent, `pam_cracklib.so` assure la même fonction avec des options équivalentes.
- **Piège courant** : placer la ligne après `pam_unix.so` ; l'ordre des modules PAM est significatif.

**Résultat attendu final** :
- ligne `pam_pwquality` (ou `pam_cracklib`) présente ;
- preuve `preuves/ch5-lab3/common-password.txt` présente.

**Étape 3.3 — Configuration de `/etc/security/pwquality.conf`**
- **Paramètres** : `minlen = 12`, `dcredit = -1`, `ucredit = -1`, `lcredit = -1`, `ocredit = -1`, `retry = 3`.
- **Résultat attendu** : paramètres enregistrés.
- **Explication** : `dcredit`, `ucredit`, `lcredit` et `ocredit` exigent respectivement un chiffre, une majuscule, une minuscule et un caractère spécial. Ces paramètres ne s'appliquent que si `pam_pwquality.so` est utilisé.
- **Piège courant** : confondre `minlen` de `pwquality.conf` avec `PASS_MIN_LEN` de `login.defs` ; les options effectives sont celles de la ligne PAM.

**Résultat attendu final** :
- paramètres affichés ;
- fichier `preuves/ch5-lab3/pwquality.txt` présent.

**Étape 3.4 — Rotation dans `/etc/login.defs`**
- **Paramètres** : `PASS_MAX_DAYS 90`, `PASS_MIN_DAYS 1`, `PASS_WARN_AGE 7`.
- **Résultat attendu** : valeurs mises à jour.
- **Explication** : `PASS_MAX_DAYS` limite la durée de vie, `PASS_MIN_DAYS` empêche un changement immédiat.
- **Piège courant** : modifier `login.defs` sans appliquer `chage` aux comptes existants.

**Résultat attendu final** :
- valeurs affichées ;
- fichier `preuves/ch5-lab3/login-defs.txt` présent.

**Étape 3.5 — Test avec un mot de passe fort**
- **Commande** : `script -q -c "sudo passwd msfadmin" preuves/ch5-lab3/test-passwd.txt`
- **Résultat attendu** : changement accepté.
- **Explication** : `script` conserve la sortie interactive dans un fichier de preuve.
- **Piège courant** : écrire le mot de passe en clair dans le fichier de preuve ; ne conserver que le résultat.

**Résultat attendu final** :
- test réussi documenté ;
- preuve `test-passwd.txt` présente.

**Étape 3.6 — Test avec un mot de passe faible**
- **Commande** : `script -q -c "sudo passwd msfadmin" preuves/ch5-lab3/test-passwd-faible.txt`
- **Action** : retenter avec un mot de passe court ou simple.
- **Résultat attendu** : rejet avec message de `pwquality` (ou `pam_cracklib`).
- **Explication** : le rejet prouve que la politique est active.
- **Piège courant** : tester avec un mot de passe qui respecte déjà la politique.

**Résultat attendu final** :
- rejet documenté ;
- preuve `test-passwd-faible.txt` présente.

**Conclusion Lab 3** :
- PAM sauvegardé et modifié ;
- `pwquality.conf` et `login.defs` configurés ;
- tests fort et faible documentés ;
- ATT&CK cartographié : T1110 / T1110.001 (audit défensif).

---

## Lab 4 — Audit et durcissement du pare-feu de Metasploitable 2

### 4.1 Contexte et objectif

**Contexte du lab** : l'étudiant examine le filtrage réseau disponible sur Metasploitable 2 (`192.168.56.103`) et documente les règles observées. La présence d'UFW ne doit pas être présumée ; adapter l'exercice au pare-feu réellement installé sur l'image.

**But du lab** : documenter l'état actuel du pare-feu, identifier les règles assouplies et implémenter des politiques de pare-feu restrictives selon les besoins du laboratoire.

**Plan MITRE ATT&CK de Lab 4**

- **Technique** : T1046 Network Service Discovery (Discovery, audit) ; T1562.004 Disable or Modify System Firewall (Defense Evasion, audit / détection).
- **Tactique** : Discovery (TA0007) ; Defense Evasion (TA0005).
- **Source de données** : DS0018 Firewall (règles et état) ; DS0029 Network Traffic (scan de vérification).
- **Détection attendue** : listes de règles, états du pare-feu, ports exposés après durcissement.
- **Mitigation associée** : politiques restrictives, règle par défaut `deny`, surveillance des règles, audits de configuration.
- **Statut** : Couvert (audit) pour T1046 ; Couvert (audit / détection) pour T1562.004.

### 4.2 Étapes à suivre

1. Vérifiez l'état actuel du pare-feu : `ufw status` et `ufw status verbose`.
2. Listez toutes les règles actuelles : `ufw status numbered`.
3. Identifiez les règles autorisant un accès étendu (`0.0.0.0/0`, ports sensibles).
4. Désactivez ou restreignez les règles problématiques : `ufw delete <numéro>` (ou `iptables -D` si UFW est absent).
5. Implémentez des règles durcies : accès SSH seulement depuis `192.168.56.0/24`, accès HTTP/HTTPS restreint.
6. Enregistrez et vérifiez la nouvelle configuration : `ufw status verbose`.
7. Vérifiez l'exposition réelle avec un scan contrôlé : `nmap -sT -p 22,80 192.168.56.103`.
8. Documentez tous les changements et l'impact sur la posture de sécurité.

```bash
# Sur la cible : audit du pare-feu, avec preuves
mkdir -p preuves/ch5-lab4
if command -v ufw >/dev/null 2>&1; then
  sudo ufw status verbose 2>&1 | tee preuves/ch5-lab4/ufw-status.txt
  sudo ufw status numbered 2>&1 | tee preuves/ch5-lab4/ufw-regles-numerotees.txt
else
  echo "UFW absent : utilisation d'iptables" | tee preuves/ch5-lab4/outil-pare-feu.txt
  sudo iptables -L -n -v 2>&1 | tee preuves/ch5-lab4/iptables-etat.txt
fi
```

> **Adaptation** — Sur Metasploitable 2, UFW peut être absent. Dans ce cas, remplacer `ufw` par `iptables` et documenter l'outil réellement utilisé. Le corrigé fournit les deux variantes.

```bash
# Sur la cible : durcissement UFW (si disponible)
if command -v ufw >/dev/null 2>&1; then
  sudo ufw default deny incoming 2>&1 | tee -a preuves/ch5-lab4/ufw-durcissement.txt
  sudo ufw allow from 192.168.56.0/24 to any port 22 proto tcp \
    2>&1 | tee -a preuves/ch5-lab4/ufw-durcissement.txt
  sudo ufw allow from 192.168.56.0/24 to any port 80 proto tcp \
    2>&1 | tee -a preuves/ch5-lab4/ufw-durcissement.txt
  sudo ufw --force enable 2>&1 | tee -a preuves/ch5-lab4/ufw-durcissement.txt
  sudo ufw status verbose 2>&1 | tee -a preuves/ch5-lab4/ufw-durcissement.txt
else
  echo "UFW absent : appliquer la variante iptables du corrigé" \
    | tee -a preuves/ch5-lab4/ufw-durcissement.txt
fi

# Sur Kali : vérification de l'exposition
nmap -sT -p 22,80 192.168.56.103 2>&1 | tee preuves/ch5-lab4/verification-nmap.txt
```

### 4.3 Résultat attendu

- état actuel du pare-feu documenté ;
- liste complète des règles actuelles avec numéros ;
- règles identifiées comme problématiques avec raisons ;
- règles durcies implémentées avec commandes ;
- nouvelle configuration vérifiée avec `status verbose` ;
- scan de vérification exécuté ;
- documentation des changements avec impact sur la posture de sécurité.

### 4.4 À rapporter dans le rapport

- sortie `ufw status verbose` complète ;
- liste des règles actuelles avec numéros et commentaires ;
- règles identifiées comme problématiques avec raisons ;
- commandes de suppression ou de restriction de chaque règle ;
- nouvelles règles implémentées avec commandes exactes ;
- sortie `ufw status verbose` après modification ;
- résultat du scan `nmap` de vérification ;
- analyse de l'impact sur la posture de sécurité.

### 4.5 Critères de réussite

- état actuel du pare-feu documenté ;
- au moins 3 règles actuelles listées avec numéros ;
- au moins 1 règle problématique identifiée et restreinte ;
- au moins 2 règles durcies implémentées (SSH restreint, services interdits) ;
- nouvelle configuration vérifiée et documentée ;
- scan de vérification exécuté ;
- impact sur la posture de sécurité analysé ;
- preuves `preuves/ch5-lab4/*.txt` présentes.

### 4.6 Corrigé — Lab 4

**Résolution détaillée :**

**Étape 4.1 — État actuel des règles**
- **Commande** : `sudo ufw status verbose` (ou `sudo iptables -L -n -v`)
- **Résultat attendu** : règles actuelles, par défaut `ACCEPT` si aucun filtrage n'est actif.
- **Explication** : un pare-feu sans règle laisse passer tout le trafic. `iptables -L -n -v` affiche les chaînes `INPUT`, `FORWARD` et `OUTPUT`.
- **Piège courant** : présumer qu'UFW est installé ; vérifier avec `command -v ufw`.

**Résultat attendu final** :
- état initial affiché ;
- fichier `preuves/ch5-lab4/ufw-status.txt` ou `iptables-etat.txt` présent.

**Étape 4.2 — Liste numérotée des règles**
- **Commande** : `sudo ufw status numbered`
- **Résultat attendu** : règles avec un numéro.
- **Explication** : le numéro sert à supprimer une règle précise.
- **Piège courant** : supprimer une règle par son numéro après avoir modifié la liste ; revérifier avant suppression.

**Résultat attendu final** :
- règles numérotées affichées ;
- fichier `ufw-regles-numerotees.txt` présent.

**Étape 4.3 — Suppression ou restriction des règles problématiques**
- **Commande** : `sudo ufw delete <numéro>`
- **Résultat attendu** : règle supprimée ou restreinte.
- **Explication** : une règle `allow from any` sur un port sensible doit être remplacée par une restriction au réseau du laboratoire.
- **Piège courant** : supprimer la règle SSH avant d'avoir ajouté la règle restrictive ; risque de perdre l'accès.

**Résultat attendu final** :
- règle problématique traitée ;
- preuve `ufw-durcissement.txt` mise à jour.

**Étape 4.4 — Règles durcies**
- **Commandes** : `ufw default deny incoming`, `ufw allow from 192.168.56.0/24 to any port 22 proto tcp`, `ufw allow from 192.168.56.0/24 to any port 80 proto tcp`.
- **Résultat attendu** : politique par défaut `deny`, accès SSH et HTTP limités au laboratoire.
- **Explication** : la règle par défaut bloque tout, puis les exceptions autorisent uniquement le réseau `192.168.56.0/24`.
- **Piège courant** : oublier `ufw --force enable` ; les règles ne sont pas appliquées.

**Résultat attendu final** :
- règles actives ;
- preuve `ufw-durcissement.txt` présente.

**Étape 4.5 — Vérification par scan**
- **Commande** : `nmap -sT -p 22,80 192.168.56.103`
- **Résultat attendu** : ports 22 et 80 accessibles depuis Kali, conformément aux règles autorisant le réseau `192.168.56.0/24`.
- **Explication** : le scan confirme l'exposition réelle après durcissement.
- **Piège courant** : scanner depuis une adresse hors du réseau autorisé et conclure à tort que le service est fermé.

**Résultat attendu final** :
- scan exécuté ;
- fichier `verification-nmap.txt` présent.

**Variante iptables (si UFW absent)**
- **Commandes** :
```bash
sudo iptables -P INPUT DROP
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -p tcp -s 192.168.56.0/24 --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp -s 192.168.56.0/24 --dport 80 -j ACCEPT
sudo iptables -L -n -v 2>&1 | tee preuves/ch5-lab4/iptables-durcissement.txt
```
- **Résultat attendu** : politique `INPUT DROP`, boucle locale autorisée, connexions établies autorisées, SSH et HTTP limités au réseau `192.168.56.0/24`.
- **Explication** : `-P INPUT DROP` bloque tout par défaut ; les règles `ACCEPT` créent les exceptions nécessaires.
- **Piège courant** : appliquer `DROP` sans avoir autorisé SSH depuis Kali ; l'accès est perdu. Garder une session SSH ouverte pendant le test.
- **Persistance** : sur Metasploitable 2, les règles `iptables` ne survivent pas toujours au redémarrage. Documenter la méthode de persistance disponible (`iptables-save`, script de démarrage) ou signaler l'absence.

**Conclusion Lab 4** :
- état initial documenté ;
- règles durcies appliquées ;
- exposition vérifiée ;
- ATT&CK cartographié : T1046, T1562.004.

---

## Lab 5 — Audit de sécurité global et matrice de risques

### 5.1 Contexte et objectif

**Contexte du lab** : l'étudiant compile les résultats des Labs 1 à 4 dans une matrice de risques globale, évalue la criticité de chaque vulnérabilité identifiée et recommande des priorités de remédiation basées sur des critères CVSS ou équivalents.

**But du lab** : produire une matrice de risques complète documentant toutes les vulnérabilités identifiées, leurs scores de criticité et les plans de remédiation prioritaires.

**Plan MITRE ATT&CK de Lab 5**

- **Technique** : T1190 Exploit Public-Facing Application (Initial Access) ; T1203 Exploitation for Client Execution (Execution) ; T1210 Exploitation of Remote Services (Lateral Movement) ; T1068 Exploitation for Privilege Escalation (Privilege Escalation).
- **Tactique** : Initial Access (TA0001) ; Execution (TA0002) ; Lateral Movement (TA0008) ; Privilege Escalation (TA0004).
- **Source de données** : DS0022 File (findings et matrice) ; DS0026 Active Directory (contexte AD) ; DS0029 Network Traffic (services exposés).
- **Détection attendue** : matrice de risques structurée, scores de criticité, résumé exécutif.
- **Mitigation associée** : priorités de remédiation classées par criticité et par effort.
- **Statut** : Couvert (cartographie) — les techniques sont documentées dans la matrice, pas exécutées.

### 5.2 Étapes à suivre

1. Compilez tous les findings des Labs 1 à 4 dans une structure de matrice.
2. Évaluez la criticité de chaque finding de façon qualitative (critique, élevée, moyenne, faible) et reportez le score NVD avec sa version pour les CVE.
3. Associez chaque finding à une ou plusieurs techniques ATT&CK cartographiées.
4. Rédigez une recommandation de remédiation pour chaque finding, avec commande si applicable.
5. Priorisez les remédiations selon la criticité et l'effort requis.
6. Documentez le risque global et l'exposition restante après atténuation.
7. Préparez un résumé exécutif pour la direction présentant les 3 risques critiques.

```bash
# Sur Kali : création de la matrice de risques
mkdir -p preuves/ch5-lab5
cat > preuves/ch5-lab5/matrice-risques.md <<'EOF'
# Matrice de risques — Chapitre 5

| Finding | Criticité | Score NVD / évaluation | Technique ATT&CK | Remédiation | Priorité |
|---|---|---|---|---|---|
| Comptes en dormance | Majeure | Évaluation labo | T1087, T1078 | Supprimer ou verrouiller les comptes | 2 |
| Politique de mot de passe faible | Haute | Évaluation labo | T1110.001 | PAM + pwquality, minlen 12 | 1 |
| SSH root login autorisé | Haute | Évaluation labo | T1021, T1078 | PermitRootLogin no | 1 |
| Algorithmes SSH obsolètes | Majeure | Évaluation labo | T1021 | Désactiver ssh-rsa et DSA | 2 |
| Pare-feu sans règle par défaut | Haute | Évaluation labo | T1562.004 | deny incoming + restrictions | 1 |
| Ports exposés | Majeure | Évaluation labo | T1046 | Fermer les ports inutiles | 2 |
| CVE-2011-2523 (vsftpd) | Critique | 9.8 (CVSS 3.1) | T1190 | Mettre à jour vsftpd, fermer 21 | 1 |
| CVE-2007-2447 (Samba) | Moyenne | 6.0 (CVSS 2.0) | T1210 | Mettre à jour Samba | 2 |
| CVE-2010-2075 (UnrealIRCD) | Élevée | 7.5 (CVSS 2.0) | T1190 | Mettre à jour UnrealIRCD | 2 |
| Absence de journalisation centralisée | Majeure | Évaluation labo | T1119 | Centraliser les journaux | 3 |
EOF
```

> **Source des scores** — Les scores NVD proviennent des fiches CVE-2011-2523 (9.8, CVSS 3.1), CVE-2007-2447 (6.0, CVSS 2.0) et CVE-2010-2075 (7.5, CVSS 2.0), consultées le 15 novembre 2026. Les autres lignes sont des évaluations qualitatives du laboratoire, pas des scores CVSS. Les versions CVSS ne sont pas directement comparables entre elles : indiquer la version dans le rapport.

### 5.3 Résultat attendu

- matrice de risques complète avec finding, criticité, mapping ATT&CK et remédiation ;
- priorités de remédiation classées par criticité ;
- résumé exécutif des 3 risques critiques ;
- documentation de l'exposition restante ;
- recommandations stratégiques.

### 5.4 À rapporter dans le rapport

- matrice de risques complète : finding, criticité, ID ATT&CK, remédiation, priorité ;
- résumé exécutif des 3 risques critiques avec impact ;
- liste priorisée des remédiations (haute, majeure, mineure) ;
- analyse de l'exposition restante après atténuation ;
- recommandations stratégiques.

### 5.5 Critères de réussite

- matrice de risques avec au moins 10 findings documentés ;
- criticité attribuée à chaque finding ;
- mapping ATT&CK fourni pour chaque finding ;
- remédiation fournie avec commande si applicable ;
- priorités classées par criticité ;
- résumé exécutif des 3 risques critiques rédigé ;
- preuve `preuves/ch5-lab5/matrice-risques.md` présente.

### 5.6 Corrigé — Lab 5

**Résolution détaillée :**

**Étape 5.1 — Matrice des risques avec évaluation NVD**
- **Action** : pour chaque vulnérabilité identifiée dans les chapitres précédents, noter l'identifiant CVE, le score NVD avec sa version CVSS, la technique ATT&CK, la sévérité et l'action prioritaire.
- **Table de matrice** :

| CVE / finding | Score NVD | Version | Technique ATT&CK | Sévérité | Action prioritaire |
|---|---|---|---|---|---|
| CVE-2011-2523 | 9.8 | CVSS 3.1 | T1190 | Critique | Mettre à jour vsftpd, fermer le port 21 |
| CVE-2007-2447 | 6.0 | CVSS 2.0 | T1210 | Moyenne | Durcir Samba, mettre à jour |
| CVE-2010-2075 | 7.5 | CVSS 2.0 | T1190 | Élevée | Mettre à jour UnrealIRCD |
| Politique de mot de passe faible | — | — | T1110.001 | Haute (labo) | PAM + pwquality |
| SSH root login | — | — | T1021, T1078 | Haute (labo) | `PermitRootLogin no` |
| Pare-feu sans deny | — | — | T1562.004 | Haute (labo) | `ufw default deny incoming` |

> **Note** — T1203 et T1068 figurent dans le plan du chapitre comme techniques cartographiées, mais aucun finding du laboratoire ne les illustre directement : ils restent théoriques.

**Résultat attendu final** :
- matrice complète avec au moins 10 findings ;
- scores NVD reportés avec leur version CVSS ;
- priorités d'action identifiées ;
- fichier `preuves/ch5-lab5/matrice-risques.md` présent.

**Étape 5.2 — Résumé exécutif**
- **Action** : sélectionner les 3 risques critiques et rédiger un paragraphe par risque.
- **Explication** : le résumé exécutif s'adresse à une direction ; il doit tenir en une page.
- **Piège courant** : confondre criticité technique et impact métier.

**Résultat attendu final** :
- résumé exécutif rédigé ;
- exposition restante documentée.

**Conclusion Lab 5** :
- matrice de risques complète ;
- mapping ATT&CK fourni ;
- priorités classées ;
- ATT&CK cartographié : T1190, T1203, T1210, T1068.

---

## Lab 6 — Recommandations stratégiques et plan de remédiation à long terme

### 6.1 Contexte et objectif

**Contexte du lab** : l'étudiant développe un plan de remédiation stratégique sur 90 jours à partir des findings du chapitre 5, en tenant compte des contraintes de ressources, des dépendances du système et de l'impact business potentiel. Ce lab se concentre sur la planification au-delà des correctifs immédiats.

**But du lab** : créer un plan de remédiation actionnable sur 90 jours avec jalons, dépendances et indicateurs de succès mesurables.

**Plan MITRE ATT&CK de Lab 6**

- **Technique** : aucune technique adverse exécutée. Les IDs T1190, T1203, T1210 et T1068 sont cités en référence pour relier les remédiations aux risques cartographiés.
- **Tactique** : — (planification défensive).
- **Source de données** : DS0022 File (matrice de risques, plan de remédiation).
- **Détection attendue** : plan documenté, jalons définis, responsabilités assignées, indicateurs de succès.
- **Mitigation associée** : plan de remédiation stratégique et priorisé.
- **Statut** : Non applicable (planification).

### 6.2 Étapes à suivre

1. Organisez tous les findings par criticité (haute, majeure, mineure) et par domaine (SSH, comptes, mot de passe, pare-feu).
2. Identifiez les dépendances entre les remédiations (la remédiation A doit être achevée avant la remédiation B).
3. Créez un calendrier sur 90 jours avec des jalons hebdomadaires ou bihebdomadaires.
4. Assignez la responsabilité de chaque remédiation (équipe, informatique, individu).
5. Identifiez les risques résiduels et les plans de contingence.
6. Définissez les indicateurs de succès mesurables pour chaque remédiation.
7. Rédigez le plan de remédiation documenté avec les signatures requises.

```bash
# Sur Kali : création du plan de remédiation
mkdir -p preuves/ch5-lab6
cat > preuves/ch5-lab6/plan-90-jours.md <<'EOF'
# Plan de remédiation sur 90 jours

## Phase 1 — Jours 1 à 30 : interventions critiques
- [ ] Mettre à jour vsftpd et fermer le port 21.
- [ ] Désactiver PermitRootLogin et les algorithmes SSH obsolètes.
- [ ] Activer ufw avec deny incoming et restreindre SSH/HTTP au réseau 192.168.56.0/24.
- [ ] Appliquer la politique de mot de passe (PAM + pwquality).
- [ ] Documenter chaque changement avec preuve.

## Phase 2 — Jours 31 à 60 : interventions importantes
- [ ] Mettre à jour Samba (CVE-2007-2447).
- [ ] Mettre à jour UnrealIRCD (CVE-2010-2075).
- [ ] Supprimer ou verrouiller les comptes en dormance.
- [ ] Mettre en place l'authentification SSH par clé.
- [ ] Centraliser les journaux.

## Phase 3 — Jours 61 à 90 : validation et optimisation
- [ ] Effectuer un scan nmap de contrôle.
- [ ] Vérifier que les ports critiques sont fermés ou filtrés.
- [ ] Tester SSH avec la nouvelle configuration.
- [ ] Rédiger le rapport final de remédiation.
- [ ] Planifier les audits mensuels.
EOF
```

### 6.3 Résultat attendu

- plan de remédiation sur 90 jours complet avec chronologie ;
- matrice de dépendances entre les remédiations ;
- jalons hebdomadaires ou bihebdomadaires avec résultats attendus ;
- responsabilités assignées ;
- risques résiduels avec plans de contingence ;
- indicateurs de succès mesurables ;
- plan documenté prêt pour la présentation à la direction.

### 6.4 À rapporter dans le rapport

- plan de remédiation sur 90 jours avec chronologie détaillée ;
- matrice de dépendances entre les remédiations ;
- jalons avec résultats attendus ;
- responsabilités assignées ;
- risques résiduels avec plans de contingence ;
- indicateurs de succès mesurables ;
- plan documenté prêt pour la présentation.

### 6.5 Critères de réussite

- plan de remédiation sur 90 jours avec chronologie complète (13 jalons ou plus) ;
- matrice de dépendances documentée (au moins 5 dépendances) ;
- jalons avec résultats attendus spécifiés ;
- responsabilités assignées pour chaque remédiation ;
- au moins 2 risques résiduels avec plans de contingence ;
- au moins 3 indicateurs de succès mesurables ;
- preuve `preuves/ch5-lab6/plan-90-jours.md` présente.

### 6.6 Corrigé — Lab 6

**Résolution détaillée :**

**Étape 6.1 — Organisation des findings**
- **Action** : classer les findings par criticité et par domaine.
- **Explication** : la classification évite de traiter au même niveau une CVE critique et un défaut de configuration mineur.
- **Piège courant** : mélanger criticité technique et effort de remédiation.

**Étape 6.2 — Dépendances**
- **Action** : identifier les remédiations qui doivent précéder d'autres.
- **Exemple** : la restriction SSH (`PermitRootLogin no`, clés) doit être testée avant la désactivation de l'authentification par mot de passe.
- **Piège courant** : verrouiller l'accès SSH avant d'avoir validé la connexion par clé.

**Étape 6.3 — Calendrier et jalons**
- **Action** : répartir les remédiations sur 90 jours en trois phases.
- **Explication** : la phase 1 traite les risques critiques, la phase 2 les risques importants, la phase 3 valide et stabilise.
- **Piège courant** : planifier toutes les actions la première semaine sans tenir compte des dépendances.

**Étape 6.4 — Responsabilités et indicateurs**
- **Action** : assigner un responsable et un indicateur mesurable par remédiation.
- **Exemple** : « 100 % des comptes en dormance supprimés ou verrouillés au jour 60 ».
- **Piège courant** : indicateurs non mesurables (« améliorer la sécurité »).

**Étape 6.5 — Risques résiduels**
- **Action** : documenter les risques qui subsistent après remédiation et les plans de contingence.
- **Explication** : un risque résiduel accepté doit être signé par le responsable.
- **Piège courant** : considérer qu'une remédiation supprime tout le risque.

**Conclusion Lab 6** :
- plan de 90 jours rédigé ;
- dépendances et jalons documentés ;
- responsabilités et indicateurs définis ;
- ATT&CK cité en référence, sans exécution.

---

## Lab 7 — Synthèse du chapitre 5 : maîtrise et transition

### 7.1 Contexte et objectif

**Contexte du lab** : l'étudiant termine le chapitre 5 par une évaluation complète de maîtrise, prépare la transition vers les modules ultérieurs et s'assure que tous les artefacts sont correctement documentés et archivés.

**But du lab** : terminer le chapitre 5 avec une validation complète, documenter la maîtrise globale et préparer une transition transparente vers les modules ultérieurs du programme.

**Plan MITRE ATT&CK de Lab 7**

- **Technique** : aucune technique adverse exécutée. Les IDs des Labs 1 à 6 sont cités en référence pour la validation croisée.
- **Tactique** : — (validation).
- **Source de données** : DS0022 File (artefacts, rapports, checklists).
- **Détection attendue** : validation complète, checklist de maîtrise, artefacts archivés.
- **Mitigation associée** : archivage des connaissances, transition documentaire.
- **Statut** : Non applicable (validation).

### 7.2 Étapes à suivre

1. Effectuez une validation finale de tous les artefacts du chapitre 5 (rapports, matrices, plans de remédiation).
2. Rédigez un document de maîtrise résumant les concepts clés maîtrisés du chapitre 5.
3. Vérifiez que tous les plans de remédiation sont documentés avec les jalons complétés.
4. Préparez une liste de contrôle de transition vers le module suivant ou les modules de niveau supérieur.
5. Stockez tous les artefacts dans l'emplacement documentaire désigné avec métadonnées.
6. Transmettez la documentation à l'instructeur ou au prochain agent de test.
7. Réfléchissez à la maîtrise globale des concepts du chapitre 5 en lien avec les chapitres précédents.

```bash
# Sur Kali : checklist de transition
mkdir -p preuves/ch5-lab7
cat > preuves/ch5-lab7/checklist-transition.md <<'EOF'
# Checklist de transition — Chapitre 5

- [ ] Lab 1 : audit des comptes terminé, preuves présentes.
- [ ] Lab 2 : audit SSH terminé, preuves présentes.
- [ ] Lab 3 : politique de mots de passe appliquée, tests documentés.
- [ ] Lab 4 : pare-feu audité et durci, scan de vérification présent.
- [ ] Lab 5 : matrice de risques complète (10 findings ou plus).
- [ ] Lab 6 : plan de 90 jours complet avec jalons et indicateurs.
- [ ] Lab 7 : document de maîtrise rédigé.
- [ ] Artefacts archivés avec métadonnées.
EOF
```

### 7.3 Résultat attendu

- validation finale de tous les artefacts ;
- document de maîtrise résumant les concepts clés ;
- plans de remédiation documentés avec statut ;
- liste de contrôle de transition complétée ;
- artefacts stockés avec métadonnées ;
- transmission de la documentation ;
- réflexion de maîtrise globale.

### 7.4 À rapporter dans le rapport

- validation finale de tous les artefacts (cocher chaque item) ;
- document de maîtrise résumant les findings clés (1 à 2 pages) ;
- confirmation que tous les plans de remédiation sont documentés avec statut ;
- checklist de transition complétée à 100 % ;
- emplacement d'archivage avec métadonnées ;
- réflexion de maîtrise globale (1 à 2 pages) ;
- recommandations pour les modules ultérieurs (3 à 5 points).

### 7.5 Critères de réussite

- tous les artefacts validés et documentés ;
- document de maîtrise créé ;
- plans de remédiation documentés avec statut ;
- checklist de transition à 100 % ;
- emplacement d'archivage documenté ;
- réflexion de maîtrise rédigée ;
- au moins 3 recommandations pour les modules ultérieurs ;
- preuve `preuves/ch5-lab7/checklist-transition.md` présente.

### 7.6 Corrigé — Lab 7

**Résolution détaillée :**

**Étape 7.1 — Validation des artefacts**
- **Action** : vérifier la présence et la complétude des preuves des Labs 1 à 6.
- **Explication** : un artefact sans preuve n'est pas validé.
- **Piège courant** : valider un lab sur la seule base du rapport, sans fichier de preuve.

**Étape 7.2 — Document de maîtrise**
- **Action** : rédiger 1 à 2 pages sur les concepts maîtrisés.
- **Explication** : le document relie les labs aux compétences attendues.
- **Piège courant** : recopier le sommaire sans analyser les acquis.

**Étape 7.3 — Checklist de transition**
- **Action** : cocher chaque item et dater la validation.
- **Explication** : la checklist sert de preuve de fin de chapitre.
- **Piège courant** : cocher un item sans preuve associée.

**Étape 7.4 — Archivage**
- **Action** : stocker les artefacts avec métadonnées (date, auteur, version).
- **Explication** : l'archivage permet de rejouer ou d'auditer le travail.
- **Piège courant** : archiver les preuves sans empreinte d'intégrité.

**Conclusion Lab 7** :
- artefacts validés ;
- document de maîtrise rédigé ;
- checklist de transition complétée ;
- chapitre 5 clôturé.

---

## 4. Synthèse et clôture

### 4.1 Validation finale de Lab 1 à Lab 7

Vérifiez que tous les labs ont été complétés :

- [ ] Lab 1 : audit des comptes — inventaire et anomalies documentés.
- [ ] Lab 2 : audit SSH — configuration et écarts documentés.
- [ ] Lab 3 : politique de mots de passe — PAM, pwquality et tests documentés.
- [ ] Lab 4 : pare-feu — état initial, durcissement et scan documentés.
- [ ] Lab 5 : matrice de risques — 10 findings ou plus, mapping ATT&CK.
- [ ] Lab 6 : plan de 90 jours — jalons, dépendances et indicateurs.
- [ ] Lab 7 : synthèse — checklist et document de maîtrise.

### 4.2 Clôture

Le chapitre 5 termine le parcours par une démarche défensive complète : audit, priorisation, remédiation et validation. Les techniques ATT&CK citées dans ce chapitre servent de grille de lecture pour relier chaque contrôle aux risques adverses correspondants. Aucune action offensive réelle n'est exécutée dans ce chapitre.

### Annexe — Structure générale du chapitre

Ce chapitre contient **7 labs** :

| Lab | Titre | Focus principal |
|---|---|---|
| **Lab 1** | Audit de sécurité des comptes utilisateurs | Audit des comptes |
| **Lab 2** | Analyse des vulnérabilités du service SSH | Analyse du service SSH |
| **Lab 3** | Mise en œuvre des politiques de mots de passe fortes | Politique de mots de passe |
| **Lab 4** | Audit et durcissement du pare-feu de Metasploitable 2 | Audit et durcissement du pare-feu |
| **Lab 5** | Audit de sécurité global et matrice de risques | Matrice de risques |
| **Lab 6** | Recommandations stratégiques et plan de remédiation à long terme | Plan de 90 jours |
| **Lab 7** | Synthèse du chapitre 5 : maîtrise et transition | Synthèse et transition |

**Format commun à tous les labs** :
- contexte du lab ;
- but du lab ;
- plan MITRE ATT&CK ;
- étapes à suivre ;
- résultat attendu ;
- éléments à rapporter ;
- critères de réussite ;
- corrigé immédiatement après l'énoncé.

**Références communes** :
- toutes les IP en `192.168.56.x` (réseau host-only `vboxnet0`) ;
- identifiants : `msfadmin` / `msfadmin` sur Metasploitable 2 (`192.168.56.103`) ;
- format cohérent avec les chapitres 1 à 4.
