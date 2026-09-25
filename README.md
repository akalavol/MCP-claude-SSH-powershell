# MCP RemoteDev — SSH + PowerShell

Serveur MCP (stdio, Python) qui permet à Claude Desktop / Claude Code de travailler sur des
projets présents sur des machines distantes, **sans shell libre** : Claude n'a qu'un jeu
d'outils fermés (lire, patcher, git, tests, build, docker, logs), limités à des dossiers
en liste blanche.

```
Claude ──stdio──> RemoteDev (PC local) ──ssh──> Linux  (sh)
                                        ──ssh──> Windows (PowerShell 7 over SSH)  ← recommandé
                                        ──winrm─> Windows (Invoke-Command)
```

> **Lire la section [Modèle de sécurité et limites](#modèle-de-sécurité-et-limites) avant
> de brancher une machine.** Ce MCP réduit la surface d'attaque ; il n'est pas une frontière
> de sécurité. La frontière, c'est l'utilisateur système `claude-dev` et ses droits.

## Installation

```powershell
git clone <ce dépôt> C:\Projet\mcp-remotedev
cd C:\Projet\mcp-remotedev
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy config\hosts.example.yaml config\hosts.yaml   # puis l'adapter
```

Prérequis sur le PC qui exécute le MCP : Python ≥ 3.10, client OpenSSH (`ssh`), et `pwsh`
uniquement si un hôte utilise le backend `winrm`. Paramiko n'est pas utilisé : on passe par
le client OpenSSH, qui gère `~/.ssh/config`, `known_hosts` et `ssh-agent`.

### Claude Code

```powershell
claude mcp add remotedev -- C:\Projet\mcp-remotedev\.venv\Scripts\python.exe C:\Projet\mcp-remotedev\server.py
```

### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "remotedev": {
      "command": "C:\\Projet\\mcp-remotedev\\.venv\\Scripts\\python.exe",
      "args": ["C:\\Projet\\mcp-remotedev\\server.py"],
      "env": { "REMOTEDEV_MODE": "dev" }
    }
  }
}
```

`REMOTEDEV_MODE` (`safe` | `dev`) surcharge `policies.yaml`. `REMOTEDEV_CONFIG_DIR` permet
d'utiliser un autre dossier de configuration.

## Préparer une machine Linux

```bash
sudo adduser --disabled-password claude-dev      # pas de sudo, pas de mot de passe
sudo -u claude-dev mkdir -p /home/claude-dev/projects /home/claude-dev/.ssh
# coller la clé publique (claude_dev.pub) :
sudo -u claude-dev tee -a /home/claude-dev/.ssh/authorized_keys
sudo chmod 700 /home/claude-dev/.ssh && sudo chmod 600 /home/claude-dev/.ssh/authorized_keys
```

Côté PC :

```powershell
ssh-keygen -t ed25519 -f "$env:USERPROFILE\.ssh\claude_dev"
ssh -i "$env:USERPROFILE\.ssh\claude_dev" claude-dev@192.168.1.20   # une fois : accepter la clé d'hôte
```

Le MCP utilise `BatchMode=yes` : aucune invite n'est possible. Il faut donc une clé **sans
passphrase** ou chargée dans `ssh-agent`, et une clé d'hôte déjà présente dans
`known_hosts`. Le MCP n'active jamais `StrictHostKeyChecking=no`.

Options utiles :
- `journalctl` pour `service_logs` : `sudo usermod -aG systemd-journal claude-dev`.
- Services redémarrables sans sudo : unités `systemctl --user` de claude-dev
  (`restart_mode: user`, et `loginctl enable-linger claude-dev`). Si vous tenez à un service
  système : `restart_mode: sudo` et une règle sudoers **nominative**, par exemple
  `claude-dev ALL=(root) NOPASSWD: /usr/bin/systemctl restart hermes-dev`.
- Node installé via nvm : il n'est pas dans le `PATH` d'une session SSH non interactive.
  Utiliser `path_prepend` dans `hosts.yaml`.
- Git « dubious ownership » : si le dépôt appartient à un autre utilisateur, git refuse de
  s'y exécuter. Le MCP n'ajoute jamais `safe.directory` pour vous.

## Préparer une machine Windows (PowerShell 7 over SSH, recommandé)

```powershell
# En administrateur, sur la cible :
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service sshd -StartupType Automatic; Start-Service sshd
winget install Microsoft.PowerShell                        # pwsh doit être dans le PATH système
New-LocalUser claude-dev -NoPassword                       # utilisateur STANDARD, jamais admin
icacls C:\Projet\Tervya /grant "claude-dev:(OI)(CI)M"      # droits uniquement sur les projets
# clé publique -> C:\Users\claude-dev\.ssh\authorized_keys (profil créé à la 1re connexion)
```

Le MCP lance `pwsh -EncodedCommand <bootstrap>`, puis envoie le script et les données par
stdin. Le sous-système SSH PowerShell n'est donc pas nécessaire, et le shell par défaut
(cmd ou powershell) ne voit que du base64. Pas de problème de quoting, pas de limite de
8191 caractères.

**Si `claude-dev` est administrateur**, OpenSSH lui donne un jeton élevé (pas d'UAC) et les
clés sont lues dans `C:\ProgramData\ssh\administrators_authorized_keys`. Tout le modèle
s'effondre. Ne le faites pas.

### Backend WinRM (déconseillé)

`backend: winrm` exécute `Invoke-Command -ComputerName` depuis le `pwsh` local, avec
l'identité Windows courante. Hors domaine Active Directory, il faut HTTPS ou TrustedHosts,
ainsi que des identifiants non interactifs, que ce backend ne gère pas. L'endpoint par
défaut exécute Windows PowerShell 5.1 : les scripts générés restent compatibles 5.1. Un
endpoint JEA en mode `NoLanguage` n'est pas compatible, car le MCP envoie des scripts.
**Seule la logique de ce backend est testée ; la couche réseau WinRM, elle, ne l'est pas.**

## Configuration

- `config/hosts.yaml` : machines, `allowed_paths`, projets, permissions (`read`, `dev`),
  docker, services redémarrables, sources de logs. Voir `config/hosts.example.yaml`.
- `config/policies.yaml` : mode global, motifs de secrets, chemins système interdits,
  limites de taille, timeouts, chemin du journal d'audit.

Au démarrage, le serveur refuse une configuration dangereuse : `allowed_path` à la racine
(`/`, `C:\`), `allowed_path` situé dans un chemin protégé, projet hors des
`allowed_paths`, journal d'audit non inscriptible.

Permission effective = mode global ∩ permissions de l'hôte. En mode `safe`, les outils DEV
ne sont **pas exposés** à Claude : ils ne sont pas juste refusés.

## Outils

| Niveau | Outils |
|---|---|
| READ | `host_list`, `host_info`, `system_info`, `disk_usage`, `get_processes`, `get_services`, `list_files`, `read_file`, `file_info`, `search_files`, `git_status`, `git_diff`, `git_log`, `git_branch`, `docker_ps`, `docker_images`, `docker_logs`, `docker_compose_status`, `service_status`, `service_logs`, `read_logs` |
| DEV | `write_file`, `patch_file`, `git_pull` (ff-only), `git_checkout`, `run_tests`, `run_build`, `docker_compose_up`, `docker_compose_down`, `docker_restart`, `restart_dev_service` |
| ADMIN | aucun, volontairement |

Non exposés volontairement : commande arbitraire, `git push/commit/reset/clean/rebase`,
`docker run/exec`, `sudo`, `reboot`, installation de paquets système.

- `patch_file` fait un remplacement exact `old_string` → `new_string`, qui doit être unique
  (ou `replace_all`). C'est bien plus fiable qu'un diff unifié généré par un LLM. Les fins
  de ligne CRLF et l'encodage (BOM, UTF-16) sont préservés.
- `run_tests` / `run_build` détectent automatiquement pytest (avec le venv du projet s'il
  existe), npm/pnpm/yarn, cargo, go, dotnet, make et docker compose. On peut aussi fixer
  `projects.<nom>.test` / `.build` dans `hosts.yaml`. `target` permet de relancer un seul
  test.
- Toutes les écritures sont atomiques (fichier temporaire + renommage).
- `.git/` est protégé en écriture : un hook git, c'est de l'exécution de code.

## Modèle de sécurité et limites

Ce que le MCP fait réellement :

1. **Aucune interpolation de texte du modèle dans du code.** Chemins, requêtes et noms sont
   quotés comme données (`sh` / PowerShell). Le contenu des fichiers passe par stdin.
2. **Double contrôle des chemins** : un contrôle lexical local (`..`, `~`, UNC, flux ADS,
   noms courts 8.3, points finaux NTFS), puis une **garde exécutée sur la cible** sur le
   chemin *résolu* (`realpath` ; refus des symlinks et jonctions sous Windows), dans le même
   script que l'opération. Sans cette seconde garde, un simple
   `ln -s /etc/shadow projet/x.txt` contourne tout filtre lexical, comme celui proposé
   dans la spec d'origine.
3. **Secrets** : les fichiers `.env`, les clés, etc. sont refusés en lecture et en écriture
   (`ACCESS DENIED — SECRET FILE`), même via un lien symbolique. Ils sont exclus de
   `search_files` et de `git_diff`. Les sorties passent par un masquage des formats de jetons
   connus (clés privées, `ghp_…`, `AKIA…`, `sk-…`).
4. **Audit** JSONL (`logs/audit.log`) : horodatage, hôte, outil, paramètres, résultat,
   durée. Le contenu écrit n'y figure jamais (seulement sa taille et son empreinte SHA-256).
5. **Timeouts** partout ; sous Linux, un `timeout` côté cible tue aussi le processus
   distant.
6. `docker_compose_up` inspecte `docker compose config` et refuse `privileged`,
   `network_mode/pid/ipc: host`, `cap_add`, `devices`, le socket docker, et les bind mounts
   hors des `allowed_paths`.

Ce qu'il **ne peut pas** faire, et que vous devez savoir :

- **DEV = exécution de code arbitraire.** `write_file` + `run_tests` permet à Claude
  d'exécuter n'importe quel code en tant que `claude-dev` : il suffit d'écrire un test qui
  lance ce qu'il veut. Même chose pour `npm install` (scripts `postinstall`) et
  `run_build`. Le filtre de secrets, la liste noire de commandes et les chemins interdits
  ne s'appliquent **qu'aux outils** : un test écrit par Claude peut lire `.env` et
  l'afficher. Les seules vraies barrières sont les droits Unix/NTFS de `claude-dev`.
- **Groupe `docker` = root.** Si `claude-dev` est dans le groupe docker, un test peut
  lancer `docker run -v /:/host`. La vérification de `docker_compose_up` n'y change rien.
  N'activez docker que sur des machines où cette équivalence est acceptable, ou utilisez
  Docker rootless.
- La liste noire de commandes (`command_filter.py`) ne filtre que les commandes test/build
  écrites dans votre configuration. C'est un filet contre les fautes de frappe, pas une
  protection.
- Les « confirmations » pour actions à risque reposent sur le client MCP : les outils
  portent des annotations (`readOnlyHint`, `destructiveHint`), et Claude Desktop / Claude
  Code demandent l'approbation par outil. Un paramètre `confirm=true` que le modèle
  remplirait lui-même serait du théâtre.
- Hardlinks : `realpath` ne les détecte pas. Sous Linux, laissez
  `fs.protected_hardlinks=1` (le défaut).
- Il reste une fenêtre TOCTOU entre la garde et l'opération dans un même script. Elle
  n'est exploitable que par un processus qui tourne déjà en tant que `claude-dev`, et
  celui-ci a déjà tous les droits de `claude-dev`.
- Windows over SSH : il n'y a pas de `timeout` côté cible. Si la connexion est coupée, un
  processus de test peut survivre.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

La suite exécute réellement les scripts générés, avec le backend `local` : `sh`,
PowerShell (si `pwsh` est installé) et WinRM (avec `Invoke-Command` simulé). Elle
vérifie aussi un serveur MCP complet via stdio. Pour valider le transport SSH contre un
`sshd` joignable dont le dossier cible est sur la même machine :

```bash
REMOTEDEV_SSH_TEST="claude-dev@127.0.0.1:2222:/chemin/cle:/home/claude-dev/projects" pytest
```

Testé avec `mcp` 1.30 et 2.2, Python 3.11, PowerShell 7.4. Non testé : cibles Windows
réelles, WinRM réseau, Windows PowerShell 5.1.

## Structure

```
server.py                      point d'entrée stdio
remotedev/app.py               construction du serveur, filtrage par mode
remotedev/runtime.py           exécution, préambules de scripts, audit, décorateur @tool
remotedev/config.py            modèles pydantic de hosts.yaml / policies.yaml
remotedev/backends/            ssh_backend.py, powershell_backend.py (WinRM), local_backend.py
remotedev/security/            path_filter.py, command_filter.py, validator.py
remotedev/tools/               files, git, tests, docker, services, system
config/                        hosts.example.yaml, policies.yaml
tests/                         tests unitaires, d'outils (sh/pwsh/winrm) et MCP stdio
```
