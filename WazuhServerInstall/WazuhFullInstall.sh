#!/bin/bash

# Colors
declare B_RED='\033[1;31m'
declare COLOR_OFF='\033[0m'
declare GREEN='\033[0;32m'
declare BLUE='\033[0;34m'
declare PURPLE='\033[0;35m'

# Paths
declare GIT_WAZUH_FOLDER="/temp/wazuh/"
declare RULESET_FOLDER="/var/ossec/etc/rules/"
declare LOCAL_INTERNAL_OPTIONS_CONFIGURATION_PATH="/var/ossec/etc/local_internal_options.conf"
declare WAZUH_SHARED_GROUP_FOLDER="/var/ossec/etc/shared/"


# Internal Field Separator, it determines how Bash recognizes word boundaries 
IFS=''

# Wazuh Utils 
declare TEMP_RULES_FOLDERS=("Windows Sysinternals Sigcheck" "Windows Chainsaw" "Windows_Sysmon" "Windows Logon Sessions" "Windows Autoruns")
declare GROUPS_RULES=("dev" "Staging" "Testing")


# Config files and wazuh rules
declare AGENT_CONFIGURATION=$(cat <<'EOF'
<agent_config>
    <!-- Windows Sysinternals Sigcheck -->
    <wodle name="command">
        <disabled>no</disabled>
        <tag>sigcheck</tag>
        <command>Powershell.exe -executionpolicy bypass -File "C:\Program Files\Sysinternals\sigcheck.ps1"</command>
        <interval>1d</interval>
        <ignore_output>yes</ignore_output>
        <run_on_start>yes</run_on_start>
        <timeout>0</timeout>
    </wodle>

    <!-- Windows Chainsaw -->
    <wodle name="command">
        <disabled>no</disabled>
        <tag>windows_chainsaw</tag>
        <command>Powershell.exe -executionpolicy bypass -File "C:\Users\Admin\Documents\chainsaw.ps1"</command>
        <interval>5m</interval>
        <ignore_output>yes</ignore_output>
        <run_on_start>yes</run_on_start>
        <timeout>0</timeout>
    </wodle>

    <!-- Windows Sysmon -->
    <localfile>
        <location>Microsoft-Windows-Sysmon/Operational</location>
        <log_format>eventchannel</log_format>
    </localfile>

    <!-- Windows Logon Sessions -->
    <wodle name="command">
        <disabled>no</disabled>
        <tag>logonsessions</tag>
        <command>Powershell.exe -executionpolicy bypass -File "C:\Program Files\Sysinternals\logonsessions.ps1"</command>
        <interval>1h</interval>
        <ignore_output>yes</ignore_output>
        <run_on_start>yes</run_on_start>
        <timeout>0</timeout>
    </wodle>

    <!-- Windows Autoruns -->
    <wodle name="command">
        <disabled>no</disabled>
        <tag>autoruns</tag>
        <command>Powershell.exe -executionpolicy bypass -File "C:\Program Files\Sysinternals\autoruns.ps1"</command>
        <interval>1d</interval>
        <ignore_output>yes</ignore_output>
        <run_on_start>yes</run_on_start>
        <timeout>0</timeout>
    </wodle>
</agent_config>
EOF
)

declare SYSCHECK_YARA_RULES_CONTENT=$(cat <<'EOF'
<group name="syscheck,">
    <rule id="100303" level="7">
    <if_sid>550</if_sid>
    <field name="file">C:\\\\Users</field>
    <description>File modified in "$(file)" directory.</description>
    </rule>
    <rule id="100304" level="7">
    <if_sid>554</if_sid>
    <field name="file">C:\\\\Users</field>
    <description>File added to "$(file)"  directory.</description>
    </rule>
</group>
<group name="yara,">
    <rule id="108000" level="0">
    <decoded_as>yara_decoder</decoded_as>
    <description>Yara grouping rule</description>
    </rule>
    <rule id="108001" level="12">
    <if_sid>108000</if_sid>
    <match>wazuh-yara: INFO - Scan result: </match>
    <description>File "$(yara_scanned_file)" is a positive match. Yara rule: $(yara_rule)</description>
    </rule>
</group>
EOF
)

declare YARA_DECODER_CONTENT=$(cat <<'EOF'
<decoder name="yara_decoder">
    <prematch>wazuh-yara:</prematch>
</decoder>

<decoder name="yara_decoder1">
    <parent>yara_decoder</parent>
    <regex>wazuh-yara: (\S+) - Scan result: (\S+) (\S+)</regex>
    <order>log_type, yara_rule, yara_scanned_file</order>
</decoder>
EOF
)

declare YARA_OSSEC_CONF_CONTENT=$(cat <<'EOF'
<ossec_config>
    <command>
        <name>yara_windows</name>
        <executable>yara.bat</executable>
        <timeout_allowed>no</timeout_allowed>
    </command>

    <active-response>
        <command>yara_windows</command>
        <location>local</location>
        <rules_id>100303,100304</rules_id>
    </active-response>
</ossec_config>
EOF
)

# Function (camelcase)
customOutput() {
    local texte="$1"
    echo ""
    echo -e "${BLUE}$texte${COLOR_OFF}"
}

installDependencies() {
    customOutput "Update and Upgrade the System Packages"
     apt update &&  apt upgrade -y
    apt-get -qq install nala -y
    customOutput "Installing dependencies"
    nala install -y curl apt-transport-https unzip wget libcap2-bin software-properties-common lsb-release gnupg git
}

installWazuhManager() {
    customOutput "Installing Wazuh Manager"
    curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
     bash ./wazuh-install.sh -a -i -o | tee /root/install_manager.log
}

changeAndStorePassword() {
    curl -so wazuh-passwords-tool.sh https://packages.wazuh.com/4.4/wazuh-passwords-tool.sh
     bash wazuh-passwords-tool.sh -a -gf /root/passwd.txt
}

configureSocforteressWazuhRules() {
    customOutput "Downloading Rules configuration"
    
    git clone "https://github.com/socfortress/Wazuh-Rules.git" "$GIT_WAZUH_FOLDER" >/dev/null
    customOutput "Push Rules configuration"
    for temp_folder in "${TEMP_RULES_FOLDERS[@]}"; do
        echo ""
        echo -e "${PURPLE}[Src]${COLOR_OFF} $GIT_WAZUH_FOLDER$temp_folder"
        echo -e "${GREEN}[Dst]${COLOR_OFF} $RULESET_FOLDER$filename"
        echo "================================================="
        find "$GIT_WAZUH_FOLDER$temp_folder" -name "*.xml" -print0 | while read -rd $'\0' rule_file_path; do
            filename=$(basename "$rule_file_path")
            if [ -f "$RULESET_FOLDER$filename" ]; then
                echo "[UPDATE] $filename"
                rm -f "$RULESET_FOLDER$filename"
            else
                echo "[COPYING] $filename"
            fi
            cp -f "$rule_file_path" "$RULESET_FOLDER"
        done
        echo "================================================="
    done
}

allowCommandExecution() {
    customOutput "Remove command execution from manager to agent"
    if grep -q "wazuh_command.remote_commands" "$LOCAL_INTERNAL_OPTIONS_CONFIGURATION_PATH"; then
        if grep -q "wazuh_command.remote_commands=0" "$LOCAL_INTERNAL_OPTIONS_CONFIGURATION_PATH"; then
            sed -i '/wazuh_command.remote_commands=0/d' "$LOCAL_INTERNAL_OPTIONS_CONFIGURATION_PATH"
            echo "wazuh_command.remote_commands=1" >>"$LOCAL_INTERNAL_OPTIONS_CONFIGURATION_PATH"
        fi
    else
        echo "wazuh_command.remote_commands=1" >>"$LOCAL_INTERNAL_OPTIONS_CONFIGURATION_PATH"
    fi
}

createAgentGroup() {
    if  /var/ossec/bin/agent_groups -l | grep -q "$1"; then
        echo "Group $1 found"
    else
        echo "Group $1 not found"
        echo "Creating group $1"
         /var/ossec/bin/agent_groups -a -g "$1" -q
    fi
}

updateAgentConfiguration() {
    local configFile="$WAZUH_SHARED_GROUP_FOLDER$1/agent.conf"
    local marker="Windows Sysmon"

    if grep -q "$marker" "$configFile"; then
        echo "Marker already present in the configuration file. No changes made."
    else
        for line in "${AGENT_CONFIGURATION[@]}"; do
            echo "$line" | tee -a "$configFile" >/dev/null
        done
        echo "Updating Agent configuration"
    fi
}

configureGroups() {
    
    for group in "${GROUPS_RULES[@]}"; do
        customOutput "Setup $group Group"
        createAgentGroup "$group"
        updateAgentConfiguration "$group"
        echo "==============================="
    done
}

cleanInstallationFiles() {
    customOutput "Cleaning install script and useless git repo"
     rm -f ./wazuh-install-files.tar
     rm -f ./wazuh-install.sh
     rm -f ./wazuh-passwords-tool.sh
     rm -rf "$GIT_WAZUH_FOLDER"
}

addContentIfNotExist() {
    local filePath="$1"
    local content="$2"
    local identifier="$3"

    if ! grep -q "$identifier" "$filePath"; then
        echo "$content" >>"$filePath"
        customOutput "Content added to $filePath."
    else
        customOutput "Content already present in $filePath. No changes made."
    fi
}

configYara() {
    addContentIfNotExist "/var/ossec/etc/rules/local_rules.xml" "$SYSCHECK_YARA_RULES_CONTENT" '<group name="syscheck,">'
    addContentIfNotExist "/var/ossec/etc/decoders/local_decoder.xml" "$YARA_DECODER_CONTENT" '<decoder name="yara_decoder">'
    addContentIfNotExist "/var/ossec/etc/ossec.conf" "$YARA_OSSEC_CONF_CONTENT" '<command>yara_windows</command>'
}

## MAIN
MAIN() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "{$B_RED}Please run as root${COLOR_OFF}"
        exit
    fi

    customOutput "Update and install dependencies log in /root/update_install_dependencies.log"
    installDependencies
    installWazuhManager 
    configureSocforteressWazuhRules
    configYara
    allowCommandExecution
    configureGroups
    
    updateAgentConfiguration
    changeAndStorePassword
     systemctl restart wazuh-manager
    cleanInstallationFiles
}

MAIN

#                                          ┌───────────────────┐    ┌───────────────────────────────┐
#                                          │  Génération d'une │    │  Déclanchement: Régle 108001  │
#          ┌─────────────────┐             │Alerte de niveau 12◄────┤"File ... is a positive match."│
#          │Téléchargement du│             └───────────────────┘    │      "Yara rule: ..."         │
#          │     Malware     │                                      └──────────────▲────────────────┘
#          └────────┬────────┘         ┌───────────────────────────┐               │
#                   │                  │ Normalisation des log par │ ┌─────────────┴──────────────┐
#  ┌────────────────▼────────────────┐ │ le décocdeur:yara_decoder1├─► Déclanchement: Régle 108000│
#  │      Fichier Ajouté dans        │ │    (local_decoder.xml)    │ │   Groupement de règle YARA │
#  │ (C:\Users\<USER_NAME>\Downloads)│ └───────────▲───────────────┘ └────────────────────────────┘
#  └────────────────┬────────────────┘             │
#                   │                  ┌───────────┴────────────┐    ┌──────────────────────┐
#     ┌─────────────▼────────────┐     │ Détection des logs par │    │    Enregistrement    │
#     │  Détection par FIM d'un  │     │le décodeur:yara_decoder◄────┤     du Scan YARA     │
#     │  Fichier ajouté/modifié  │     │   (local_decoder.xml)  │    │(active-responses.log)│
#     └────────────┬─────────────┘     └────────────────────────┘    └──────────▲───────────┘
#                  │                                                            │
#  ┌───────────────▼───────────────────────────────────────────┐   ┌────────────┴─────────────┐
#  │  Déclanchement: Régle 550    ou  Déclanchement: Régle 554 │   │   Scan YARA du Fichier   │
#  │"Integrity checksum changed"     "File added to the system"│   │avec yara.bat─► yara64.exe│
#  │                   (0015-ossec_rules.xml)                  │   │       (ossec.conf)       │
#  └─────────────┬───────────────────────────────────┬─────────┘   └───────────▲──────────────┘
#                │                                   │                         │
#  ┌─────────────▼───────────────────────────────────▼──────────┐ ┌────────────┴───────────────┐
#  │Déclanchement: Régle 100303  ou  Déclanchement: Régle 108000│ │    Déclenchement de la     │
#  │       File modified in               File added to         ├─►Réponse Active: yara_windows│
#  │          C:\Users\<USER_NAME>\Downloads directory.         │ │      (ossec.conf)          │
#  │                    (local_rules.xml)                       │ └────────────────────────────┘
#  └────────────────────────────────────────────────────────────┘
#
