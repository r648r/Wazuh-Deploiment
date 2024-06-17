# Windows Endpoint Detection Deployment — Wazuh + Sysmon + Sigma + YARA

[🇫🇷 Français](README.md) · 🇬🇧 **English**

One-shot PowerShell deployment that turns a Windows endpoint into a
**detection-ready host**: installs the **Wazuh** agent, **Sysmon**, schedules
**Chainsaw + Sigma** EVTX hunts, wires **YARA** and Sysinternals (`autoruns`,
`sigcheck`, `logonsessions`) as Wazuh active-response commands, and ships
**Atomic Red Team** scripts to validate the detections.

## Detection stack deployed

| Component | Role |
|---|---|
| Wazuh agent | EDR/SIEM telemetry → Wazuh manager |
| Sysmon | Rich process / network / registry event logging |
| Sigma + Chainsaw | Scheduled EVTX hunting against the Sigma ruleset |
| YARA | On-demand malware scanning (active response) |
| Sysinternals | `autoruns`, `sigcheck`, `logonsessions` collectors |
| Atomic Red Team | Detection validation (ART tests, ransomware sim) |

## Demo

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

Example YARA active-response scan:

```console
PS C:\> .\yara.ps1
MalwareType           FilePath
-----------           --------
Mimikatz_Memory       C:\Users\Public\Downloads\mk.exe
Generic_Ransomware    C:\Users\Public\Downloads\invoice.scr
```

> Values above are **synthetic** — no real host, IP or finding is shown.

---

## Parameters

The deployment script takes three required parameters:

- `WAZUH_AGENT_GROUP` — the Wazuh group the agent is assigned to.
- `WAZUH_AGENT_NAME` — the agent name shown on the dashboard.
- `WAZUH_REGISTRATION_SERVER` — IP address of the Wazuh manager.

## Main functions

### CustomLog
Handles log output, distinguishing error messages from informational ones.
- `message` (string) — the message to print.
- `isAnError` (bool) — whether the message is an error (optional, default `false`).
```powershell
CustomLog -message "Installation succeeded."
CustomLog -message "Installation failed." -isAnError $true
```

### InstallWazuh
Installs the Wazuh agent: checks whether the service already exists, downloads and
installs it if not, and starts it if it isn't running.

### InstallScripts
Runs the scripts that install extra components (e.g. Sysmon), executing each with
admin privileges via `StartPowershellAsAdmin` and capturing any errors.

### UpdateLocalInternalOption
Updates `local_internal_options.conf` to enable remote commands
(`wazuh_command.remote_commands=1`).

### InitializeAndDownloadChainsaw
Resets the target directory, then downloads and extracts Chainsaw
(combines `InitChainsawSetup` + `DownloadChainsaw`).

### PullOrCloneSigma
Clones the Sigma rules repository, or pulls the latest if it already exists.

### MoveFiles
Copies the required configuration files to their destinations and verifies each copy.

### StartWazuh
Starts the `WazuhSvc` service.

### StartPowershellAsAdmin
Runs PowerShell commands with administrative privileges.
- `Arguments` (string) — arguments passed to the PowerShell command.

### UninstallWazuhSysinternal
Removes the Sysinternals tools (`C:\Program Files\sysinternals`) and uninstalls
the Wazuh agent.

## Constants

- `$CHAINSAW_SOURCE_FOLDER` — Chainsaw source directory.
- `$ADMIN_DOCUMENT` — administrator Documents directory.
- `$SOCFORTRESS_DESTINATION_FOLDER` — SOCFortress destination directory.
- `$SIGMA_RULES_GIT_URL` — Sigma rules Git repository URL.
- `$TEMP_PATH` — temporary directory.
- `$IS_ADMIN` — whether the script runs with admin privileges.
- `$SCRIPT_TO_EXEC` — hash table of scripts to execute.
- `$WAZUH_INSTALLER_PATH` — Wazuh agent installer path.
- `$WAZUH_INSTALL_COMMAND` — Wazuh agent install command.

## Main

The `Main` function orchestrates the deployment. It checks for admin privileges
(relaunching elevated if needed), then runs, in order:

1. `InstallWazuh`
2. `InstallScripts`
3. `UpdateLocalInternalOption`
4. `InitializeAndDownloadChainsaw`
5. `MoveFiles`
6. `PullOrCloneSigma`
