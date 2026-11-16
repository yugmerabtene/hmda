# Changelog

Toutes les modifications notables du cours sont documentées ici. Les chapitres
`chapitre-0N.md` restent des documents de cours : ils ne contiennent ni bloc
`Changelog`, ni note de version, ni historique de modifications.

## [Unreleased]

### Added
- Gabarit de cours des chapitres 1 à 5 dans le skill `common` (section 16) :
  squelette, champs obligatoires, spécificités par chapitre, preuves, ordre
  d'exécution et checklist de validation.
- Bloc obligatoire `**But** — ...`, `**Machine** — ...`, `**Prérequis** — ...` au
  début de chaque étape de lab, avant l'encart de localisation.
- Règle de centralisation de l'historique dans `CHANGELOG.md` et dans GitHub
  (commits, tags, releases).
- Configuration portable dans le dossier du cours : `opencode.json`, `.env`
  corrigé (Kali `.101`, Metasploitable `.103`, Windows Server `.102`,
  Windows XP `.104`), `AGENTS.md`, agents, skills, `syllabus.md`,
  `CHANGELOG.md`, `CONTEXT.md`, `tracking.db`, `tracking.json`,
  `scripts/orchestrator_cli.py` et RAG (`scripts/rag/`, `books/`, index).

### Changed
- Chapitre 1 : suppression du bloc de version et de changelog en tête de chapitre.
- Règles de rédaction alignées dans `AGENTS.md`, les agents et les skills.
- Suppression des avertissements de simulation et des critères « aucun exploit
  exécuté » ; règle unique : tous les exploits et payloads sont développés,
  exécutés et testés en réel sur les VMs du lab, sans limitation.
- Chapitre 1, Lab-06 : suppression de l'étape de contrôle négatif des exploits et
  renumérotation des étapes ; critères alignés sur l'exploitation réelle.
- Chapitre 3 : ajout de l'exécution réelle des payloads sur Windows XP (handler,
  livraison, session, preuve, rollback) et suppression des mentions « payload non
  exécuté ».
- Agents : règle de sécurité de l'orchestrateur alignée sur l'exploitation réelle
  en lab isolé ; règle de qualité du hacker interdisant les formulations de
  simulation ou de payload non exécuté.
- Chapitre 1 : statut `T1068` passé à « Exécuté — Ch3 Lab2 » et élévation locale
  renvoyée au chapitre 3.
- Chapitre 3 : notes des labs d'analyse reformulées pour analyser les traces de
  l'exécution réelle, sans relancer d'action offensive.

## [1.2] - 2026-11-16

### Changed
- Refonte de forme des Labs 01–06 : suppression des sections « Corrigé » séparées,
  explications fusionnées dans les étapes, sans suppression de commande ni de preuve.
- Qualification de `CVE-2021-4158` documentée à cette date comme hors périmètre
  d’exécution (QEMU hôte). Cette qualification est révisée dans les travaux en cours.

### Added
- Lab-07 : exploitation contrôlée de `CVE-2011-2523`, `CVE-2007-2447`,
  `CVE-2010-2075` et `CVE-2004-2687`.
- Lab-08 : SQLi, XSS réfléchi/stocké, injection de commande, LFI et exfiltration DVWA.
- Scripts Metasploit, `sqlmap` et Selenium/Chromium complets ; preuve XSS navigateur
  avec exfiltration de cookie.
- Tableau de qualification des 12 CVE ; archivage et rollback ; avenant ATT&CK A.7.

## [1.1] - 2026-11-14

### Added
- Preuves `stdout` + `stderr` + code retour.
- Lab-05 (énumération approfondie) et Lab-06 (validation CVE et matrice de risques).

### Changed
- Prérequis root et fallback `nmap -sT` ; option `-n` sur Kali.
- Lab-03 autoporteur avec modèles et scripts ; validation CVE hors ligne.
- Correction de l’exemple EDB-ID ; ajout de `-sV` en phase 1.
- Arborescence de preuves unique ; règle de fusion des statuts ; baseline par VM.
- Commandes `script` et `tcpdump` ; modèles de fiches dry-run ; inventaire sans
  auto-inclusion ; exemples réels et suppression des séquences ANSI.

## [1.0] - 2026-11-07

### Added
- Version initiale du chapitre 1.
