# Wazuh Agent Installation

Documentation du script PowerShell utilisé pour installer et configurer l'agent Wazuh, ainsi que d'autres outils de sécurité comme Chainsaw et Sigma. Le script est structuré pour exécuter plusieurs tâches, de l'installation de Wazuh à la configuration et au déplacement des fichiers nécessaires.

## Paramètres d'entrée

Le script accepte trois paramètres obligatoires :

- `WAZUH_AGENT_GROUP` : Le groupe auquel l'agent Wazuh doit être assigné.
- `WAZUH_AGENT_NAME` : Le nom de l'agent Wazuh sur le dashboard.
- `WAZUH_REGISTRATION_SERVER` : @IP du Wazuh Manager

Ces paramètres doivent être fournis lors de l'exécution du script pour garantir le bon fonctionnement de toutes les fonctions.

## Fonctions principales

### CustomLog

Cette fonction permet de gérer l'affichage des messages de log, en distinguant les messages d'erreur des messages d'information.

#### Paramètres :
- `message` (string) : Le message à afficher.
- `isAnError` (bool) : Indique si le message est une erreur (optionnel, par défaut à `false`).

#### Exemple d'utilisation :
```powershell
CustomLog -message "Installation réussie."
CustomLog -message "Erreur lors de l'installation." -isAnError $true
```

### MoveFiles

Cette fonction déplace les fichiers de configuration nécessaires à l'installation de Wazuh et d'autres outils associés.

#### Fonctionnement :
- Utilise un hash table pour définir les chemins source et destination des fichiers.
- Copie les fichiers de la source vers la destination.
- Vérifie si la copie a été réussie et affiche un message approprié.

### InstallScripts

Cette fonction exécute les scripts nécessaires à l'installation de composants supplémentaires comme Sysmon.

#### Fonctionnement :
- Parcourt une table de hachage définissant les scripts à exécuter.
- Tente d'exécuter chaque script en utilisant une fonction de démarrage en tant qu'administrateur (`StartPowershellAsAdmin`).
- Capture et affiche les erreurs éventuelles.

### StartWazuh

Cette fonction démarre le service Wazuh.

#### Fonctionnement :
- Utilise `Start-Service` pour démarrer le service `WazuhSvc`.
- Affiche un message de confirmation.

### InstallWazuh

Cette fonction gère le processus d'installation de l'agent Wazuh.

#### Fonctionnement :
- Vérifie si le service Wazuh est déjà installé.
- Si non, télécharge et installe l'agent Wazuh.
- Si le service n'est pas en cours d'exécution après l'installation, il le démarre.

### StartPowershellAsAdmin

Cette fonction permet d'exécuter des commandes PowerShell avec des privilèges administratifs.

#### Paramètres :
- `Arguments` (string) : Les arguments à passer à la commande PowerShell.

### UpdateLocalInternalOption

Cette fonction met à jour le fichier de configuration `local_internal_options.conf` pour activer les commandes distantes.

#### Fonctionnement :
- Lit le fichier de configuration.
- Modifie ou ajoute la ligne `wazuh_command.remote_commands=1` selon le cas.

### PullOrCloneSigma

Cette fonction clone ou met à jour le dépôt Git de Sigma.

#### Fonctionnement :
- Vérifie si le répertoire du dépôt existe.
- Si non, clone le dépôt.
- Si oui, effectue un pull pour mettre à jour le dépôt.

### InitChainsawSetup

Cette fonction initialise la configuration de Chainsaw en supprimant les anciens répertoires et en créant de nouveaux.

#### Fonctionnement :
- Supprime les répertoires existants si nécessaire.
- Crée le répertoire de destination.

### DownloadChainsaw

Cette fonction télécharge et extrait Chainsaw.

#### Fonctionnement :
- Vérifie si Chainsaw est déjà téléchargé.
- Si non, télécharge et extrait Chainsaw.

### InitializeAndDownloadChainsaw

Cette fonction combine l'initialisation et le téléchargement de Chainsaw.

#### Fonctionnement :
- Supprime les répertoires existants.
- Crée le répertoire de destination.
- Télécharge et extrait Chainsaw.

### UninstallWazuhSysinternal

Cette fonction supprime les outils Sysinternals et désinstalle l'agent Wazuh.

#### Fonctionnement :
- Supprime le répertoire `C:\Program Files\sysinternals`.

## Constantes

Le script définit plusieurs constantes utilisées dans les fonctions :

- `$CHAINSAW_SOURCE_FOLDER` : Chemin du répertoire source de Chainsaw.
- `$ADMIN_DOCUMENT` : Chemin du répertoire des documents de l'administrateur.
- `$SOCFORTRESS_DESTINATION_FOLDER` : Chemin du répertoire de destination pour SOCFortress.
- `$SIGMA_RULES_GIT_URL` : URL du dépôt Git de Sigma.
- `$TEMP_PATH` : Chemin du répertoire temporaire.
- `$IS_ADMIN` : Indique si le script est exécuté avec des privilèges administratifs.
- `$SCRIPT_TO_EXEC` : Table de hachage des scripts à exécuter.
- `$WAZUH_INSTALLER_PATH` : Chemin de l'installateur de l'agent Wazuh.
- `$WAZUH_INSTALL_COMMAND` : Commande pour installer l'agent Wazuh.

## Fonction Main

La fonction principale `Main` orchestre l'exécution des différentes étapes du script.

#### Fonctionnement :
- Vérifie si le script est exécuté avec des privilèges administratifs.
- Si non, relance le script en mode administrateur.
- Exécute les fonctions dans l'ordre suivant :
  1. `InstallWazuh`
  2. `InstallScripts`
  3. `UpdateLocalInternalOption`
  4. `InitializeAndDownloadChainsaw`
  5. `MoveFiles`
  6. `PullOrCloneSigma`

#### Exemple d'appel :
```powershell
PS C:\Windows\system32> cd C:\Users\Admin\Documents\                                                                    PS C:\Users\Admin\Documents> ls                                                                                                                                                                                                                                                                                                                                             Répertoire : C:\Users\Admin\Documents                                                                                                                                                                                                       
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        16/05/2024     15:55                Exe
d-----        16/05/2024     15:55                HiSuite
d-----        16/05/2024     15:55                Icone
d-----        16/05/2024     15:55                PushToUsers
d-----        17/05/2024     10:32                TaskBar
d-----        04/06/2024     15:39                WazuhAgent
d-----        04/06/2024     16:15                WindowsPowerShell
d-----        16/05/2024     15:55                Winget
-a----        05/06/2024     11:17          10608 Wazaaaaah.ps1


PS C:\Users\Admin\Documents> .\Wazaaaaah.ps1 -WAZUH_AGENT_GROUP Alpes -WAZUH_AGENT_NAME Raphzer -WAZUH_REGISTRATION_SERVER 10.100.19.21
[+] Wazuh agent already installed.
[+] Installing Sysmon
[+] Updating local_internal_options.conf                                                                                [+] Downloading chainsaw.exe                                                                                            [+] Extracting chainsaw.exe                                                                                             [+] Config Sigcheck OK                                                                                                  [+] Config Chainsaw OK                                                                                                  [+] Config Chainsaw.ps1 OK                                                                                              [+] Config Logonsession OK
[+] Config Autoruns OK
Cloning into 'C:\Program Files\socfortress\sigma'...
remote: Enumerating objects: 115121, done.
remote: Counting objects: 100% (698/698), done.
remote: Compressing objects: 100% (460/460), done.
remote: Total 115121 (delta 344), reused 523 (delta 232), pack-reused 114423
Receiving objects: 100% (115121/115121), 38.87 MiB | 16.33 MiB/s, done.
Resolving deltas: 100% (87278/87278), done.
Updating files: 100% (3673/3673), done.
[+]  Clonning repo to C:\Program Files\socfortress\sigma
[+] Finish !
```

# TODO
- [ ] Lire les commentaire dans wazaaah.ps1 pour factorisé `YaraSetup` et `OssecSetup`
- [ ] Rendre le script bash comaptible avec la version 4.8 de Wazuh 
  - [ ] Changer le lien de téléchargement
  - [ ] Changer la comamnde d'installation de l'agent
  - [ ] Tester Sigma
  - [ ] Tester yara
  - [ ] Tester toute les fonctions du Sam aussi
- [ ] Faire en sorte de faire de la haute disponibilité sur Wazuh voir doc :
- [ ] 
- [ ] 
- [ ] 
- [ ] 
