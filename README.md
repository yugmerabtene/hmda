# Hacking-v2 - Cours MITRE ATT&CK

## Structure du cours

| Chapitre | Titre | Contenu |
|---------|-------|---------|
| [Chapitre 1](chapitre-01.md) | Introduction au cours, mise en place du laboratoire et exploitation complète | Architecture du lab, découverte MITRE ATT&CK, recherche de CVE, Navigator, planification d'attaque, exploitation réelle |
| [Chapitre 2](chapitre-02.md) | Attaques sur Windows et Active Directory | DDoS, injection SQL, dépassement de tampon, identifiants, Pass-the-Hash |
| [Chapitre 3](chapitre-03.md) | Payloads, C2 et analyse | msfvenom, payloads Windows XP, livraison et exécution, C2, analyse forensique |
| [Chapitre 4](chapitre-04.md) | Forensique, réseau, rapport et restauration | Analyse des journaux forensiques, investigation réseau, exfiltration de données, restauration du lab |
| [Chapitre 5](chapitre-05.md) | Audit, durcissement et remédiation | Audit des comptes utilisateurs, analyse SSH, politiques de mots de passe, durcissement du pare-feu, plan de remédiation à 90 jours |

## Environnement

- Réseau du laboratoire : `192.168.56.0/24` (host-only vboxnet0)
- Attaquant : Kali Linux `192.168.56.101`
- Cibles : Metasploitable 2 `192.168.56.103` (obligatoire) ; Windows Server 2016 `192.168.56.102` (facultatif) ; Windows XP `192.168.56.104` (obligatoire pour les tests de payloads du chapitre 3)
- Identifiants : `kali`/`kali`, `msfadmin`/`msfadmin`

## Fichiers

- `chapitre-01.md` à `chapitre-05.md` - Contenu complet du cours ; le chapitre 1 comprend huit labs (Labs 01–08), les chapitres 2 à 5 proposent leurs propres labs progressifs
- `.env` - Variables d'environnement du laboratoire (identifiants SSH, configuration réseau)
- `.gitignore` - Exclut les fichiers sensibles

## Configuration

- `opencode.json` - Configuration du projet OpenCode
- `AGENTS.md` - Guide des agents et règles de rédaction du cours
- `.opencode/agent/` - `orchestrator`, `hacker`, `student`, `sysadmin`
- `.opencode/skills/` - `common`, `hacker`, `student`, `sysadmin`
- `.env` - Identifiants du laboratoire et adresses IP statiques
- `tracking.db` / `tracking.json` - État de progression du cours
- `scripts/orchestrator_cli.py` - CLI de progression (`python3 scripts/orchestrator_cli.py`)
- `syllabus.md`, `CHANGELOG.md`, `CONTEXT.md` - Programme, historique, contexte du projet
- `scripts/rag/`, `books/`, `sources/plain/` - Index RAG local et sources

## Démarrage

1. Cloner le dépôt
2. Installer VirtualBox avec Kali et Metasploitable 2 (les VM Windows sont facultatives)
3. Configurer le réseau host-only `vboxnet0` avec l'IP `192.168.56.1`, DHCP désactivé, sans NAT ni adaptateur ponté pendant les labs
4. Démarrer SSH : `sudo service ssh start` (Kali)
5. Suivre chaque chapitre dans l'ordre

## Avertissement de sécurité

> Ce cours est destiné à des fins éducatives uniquement. Toutes les attaques et manipulations sont effectuées dans un environnement de laboratoire isolé sans accès Internet sortant. Ne jamais appliquer ces techniques sur des systèmes réels sans autorisation administrative systémique.
