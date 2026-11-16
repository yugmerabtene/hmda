# Hacking-v2 - Cours MITRE ATT&CK

## Course Structure

| Chapter | Title | Focus |
|---------|-------|-------|
| [Chapitre 1](chapitre-01.md) | Introduction au cours, mise en place du laboratoire et exploitation complète | Architecture lab, MITRE ATT&CK discovery, CVE research, Navigator, attack planning, exploitation réelle |
| [Chapitre 2](chapitre-02.md) | Attaques sur Windows et Active Directory | DDoS, SQLi, Buffer Overflow, credentials, Pass-the-Hash |
| [Chapitre 3](chapitre-03.md) | Payloads, C2 et analyse | msfvenom, payloads Windows XP, livraison et exécution, C2, analyse forensique |
| [Chapitre 4](chapitre-04.md) | Forensique, réseau, rapport et restauration | Forensic log analysis, network investigation, data exfiltration, lab restoration |
| [Chapitre 5](chapitre-05.md) | Audit, durcissement et remédiation | User account audit, SSH analysis, password policies, firewall hardening, 90-day remediation plan |

## Environment

- Target Lab: `192.168.56.0/24` (host-only vboxnet0)
- Attacker: Kali Linux `192.168.56.101`
- Targets: Metasploitable 2 `192.168.56.103` (required); Windows Server 2016 `192.168.56.102` (optional); Windows XP `192.168.56.104` (required for chapter 3 payload tests)
- Credentials: `kali`/`kali`, `msfadmin`/`msfadmin`

## Files

- `chapitre-01.md` through `chapitre-05.md` - Complete course content; chapter 1 includes eight labs (Labs 01–08), chapters 2–5 provide their own progressive labs
- `.env` - Lab environment variables (SSH credentials, network config)
- `.gitignore` - Excludes sensitive files

## Configuration

- `opencode.json` - OpenCode project configuration
- `AGENTS.md` - agent guide and course writing rules
- `.opencode/agent/` - `orchestrator`, `hacker`, `student`, `sysadmin`
- `.opencode/skills/` - `common`, `hacker`, `student`, `sysadmin`
- `.env` - lab credentials and static IP addresses
- `tracking.db` / `tracking.json` - course progress state
- `scripts/orchestrator_cli.py` - progress CLI (`python3 scripts/orchestrator_cli.py`)
- `syllabus.md`, `CHANGELOG.md`, `CONTEXT.md` - program, history, project context
- `scripts/rag/`, `books/`, `sources/plain/` - local RAG index and sources

## Getting Started

1. Clone the repository
2. Set up VirtualBox with Kali and Metasploitable 2 (Windows VMs are optional)
3. Configure host-only network `vboxnet0` with IP `192.168.56.1`, DHCP disabled, no NAT or bridged adapter during labs
4. Start SSH in: `sudo service ssh start` (Kali)
5. Follow each chapter sequentially

## Security Notice

> Ce cours est destiné à des fins éducatives uniquement. Toutes les attaques et manipulations sont effectuées dans un environnement de laboratoire isolé sans accès Internet sortant. Ne jamais appliquer ces techniques sur des systèmes réels sans autorisation administrative systémique.

## Contact

Send mail to: yug.merabtene@gmail.com • Repository managed by yugmerabtene (https://github.com/yugmerabtene)