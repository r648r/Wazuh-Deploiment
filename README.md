# Déploiement de détection sur endpoint Windows — Wazuh + Sysmon + Sigma + YARA

🇫🇷 **Français** · [🇬🇧 English](README.en.md)

Déploiement PowerShell en une passe qui transforme un endpoint Windows en
**hôte prêt à détecter** : installe l'agent **Wazuh**, **Sysmon**, planifie des
chasses **Chainsaw + Sigma** sur les EVTX, câble **YARA** et les Sysinternals
(`autoruns`, `sigcheck`, `logonsessions`) en commandes d'active-response Wazuh,
et embarque des scripts **Atomic Red Team** pour valider les détections.

## Stack de détection déployée

| Composant | Rôle |
|---|---|
| Agent Wazuh | Télémétrie EDR/SIEM → manager Wazuh |
| Sysmon | Journalisation riche des process / réseau / registre |
| Sigma + Chainsaw | Chasse EVTX planifiée contre le ruleset Sigma |
| YARA | Scan malware à la demande (active response) |
| Sysinternals | Collecteurs `autoruns`, `sigcheck`, `logonsessions` |
| Atomic Red Team | Validation des détections (tests ART, simu ransomware) |

## Démo

```console
PS C:\> .\Deploy-WazuhAgent.ps1 -WAZUH_AGENT_GROUP Workstations `
                                -WAZUH_AGENT_NAME WIN-CLIENT01 `
                                -WAZUH_REGISTRATION_SERVER 198.51.100.50
[+] Wazuh agent installed and registered (group: Workstations)
[+] Installing Sysmon ............................. OK
[+] Updating local_internal_options.conf (remote commands enabled)
[+] Downloading & extracting chainsaw.exe ......... OK
[+] Config Sigcheck / Chainsaw / Logonsessions / Autoruns ... OK
[+] Cloning Sigma ruleset -> C:\Program Files\socfortress\sigma
    Receiving objects: 100% (115121/115121), 38.87 MiB | 16.3 MiB/s, done.
[+] Finished — endpoint is detection-ready
```

Exemple de scan YARA en active-response :

```console
PS C:\> .\yara.ps1
MalwareType           FilePath
-----------           --------
Mimikatz_Memory       C:\Users\Public\Downloads\mk.exe
Generic_Ransomware    C:\Users\Public\Downloads\invoice.scr
```

> Les valeurs ci-dessus sont **synthétiques** — aucun hôte, IP ou détection réels.

---

## Paramètres

Le script de déploiement prend trois paramètres obligatoires :

- `WAZUH_AGENT_GROUP` — le groupe Wazuh auquel l'agent est assigné.
- `WAZUH_AGENT_NAME` — le nom de l'agent affiché sur le dashboard.
- `WAZUH_REGISTRATION_SERVER` — l'adresse IP du manager Wazuh.

## Fonctions principales

### CustomLog
Gère l'affichage des logs en distinguant les erreurs des messages d'information.
- `message` (string) — le message à afficher.
- `isAnError` (bool) — si le message est une erreur (optionnel, défaut `false`).
```powershell
CustomLog -message "Installation succeeded."
CustomLog -message "Installation failed." -isAnError $true
```

### InstallWazuh
Installe l'agent Wazuh : vérifie si le service existe déjà, le télécharge et
l'installe sinon, et le démarre s'il n'est pas en cours d'exécution.

### InstallScripts
Exécute les scripts qui installent les composants supplémentaires (ex. Sysmon),
chacun avec les privilèges admin via `StartPowershellAsAdmin`, en capturant les erreurs.

### UpdateLocalInternalOption
Met à jour `local_internal_options.conf` pour activer les commandes distantes
(`wazuh_command.remote_commands=1`).

### InitializeAndDownloadChainsaw
Réinitialise le répertoire cible, puis télécharge et extrait Chainsaw
(combine `InitChainsawSetup` + `DownloadChainsaw`).

### PullOrCloneSigma
Clone le dépôt de règles Sigma, ou fait un pull s'il existe déjà.

### MoveFiles
Copie les fichiers de configuration requis vers leurs destinations et vérifie chaque copie.

### StartWazuh
Démarre le service `WazuhSvc`.

### StartPowershellAsAdmin
Exécute des commandes PowerShell avec les privilèges administrateur.
- `Arguments` (string) — les arguments passés à la commande PowerShell.

### UninstallWazuhSysinternal
Supprime les outils Sysinternals (`C:\Program Files\sysinternals`) et désinstalle
l'agent Wazuh.

## Constantes

- `$CHAINSAW_SOURCE_FOLDER` — répertoire source de Chainsaw.
- `$ADMIN_DOCUMENT` — répertoire Documents de l'administrateur.
- `$SOCFORTRESS_DESTINATION_FOLDER` — répertoire de destination SOCFortress.
- `$SIGMA_RULES_GIT_URL` — URL du dépôt Git des règles Sigma.
- `$TEMP_PATH` — répertoire temporaire.
- `$IS_ADMIN` — si le script s'exécute avec les privilèges admin.
- `$SCRIPT_TO_EXEC` — table de hachage des scripts à exécuter.
- `$WAZUH_INSTALLER_PATH` — chemin de l'installateur de l'agent Wazuh.
- `$WAZUH_INSTALL_COMMAND` — commande d'installation de l'agent Wazuh.

## Main

La fonction `Main` orchestre le déploiement. Elle vérifie les privilèges admin
(se relance en élevé si besoin), puis exécute, dans l'ordre :

1. `InstallWazuh`
2. `InstallScripts`
3. `UpdateLocalInternalOption`
4. `InitializeAndDownloadChainsaw`
5. `MoveFiles`
6. `PullOrCloneSigma`
