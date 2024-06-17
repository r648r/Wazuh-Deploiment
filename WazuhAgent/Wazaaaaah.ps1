param (
    [Parameter(Mandatory = $true)]
    [string] $WAZUH_AGENT_GROUP,

    [Parameter(Mandatory = $true)]
    [string] $WAZUH_AGENT_NAME,

    [Parameter(Mandatory = $true)]
    [string] $WAZUH_REGISTRATION_SERVER
)

#############
# CONSTANTE #
#############

## Chainsaw | Sigma ##
[string] $SOCFORTRESS_DESTINATION_FOLDER = "C:\Program Files\socfortress"
[string] $ADMIN_DOCUMENT = "C:\Users\Admin\Documents"
[string] $CHAINSAW_SOURCE_FOLDER = "$SOCFORTRESS_DESTINATION_FOLDER\chainsaw"
[string] $SIGMA_RULES_GIT_URL = "https://github.com/SigmaHQ/sigma.git"
[string] $CHAINSAW_FILE = "$ADMIN_DOCUMENT\chainsaw.zip"
[string] $CHAINSAW_FILE_URL = "https://github.com/WithSecureLabs/chainsaw/releases/download/v2.9.0/chainsaw_x86_64-pc-windows-msvc.zip"

## Genreral ##
[string] $CONFIG_FILE_PATH = "C:\Program Files (x86)\ossec-agent\ossec.conf"
[string] $TEMP_PATH = [System.IO.Path]::GetTempPath()
[bool] $IS_ADMIN = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
[hashtable] $SCRIPT_TO_EXEC = @{
    "Sysmon" = "$ADMIN_DOCUMENT\WazuhAgent\sysmon_install.ps1"
}

[hashtable] $CONFIG_FILES = @{
    "Sigcheck"     = @{
        "Source"      = "$ADMIN_DOCUMENT\WazuhAgent\sigcheck.ps1";
        "Destination" = "C:\Program Files\Sysinternals\"
    };
    "Logonsession" = @{
        "Source"      = "$ADMIN_DOCUMENT\WazuhAgent\logonsessions.ps1";
        "Destination" = "C:\Program Files\Sysinternals\"
    };
    "Autoruns"     = @{
        "Source"      = "$ADMIN_DOCUMENT\WazuhAgent\autoruns.ps1";
        "Destination" = "C:\Program Files\Sysinternals\"
    };
    "Chainsaw" = @{
        "Source"      = "$ADMIN_DOCUMENT\chainsaw";
        "Destination" = "C:\Program Files\socfortress"
    };
    "Chainsaw.ps1" = @{
        "Source"      = "$ADMIN_DOCUMENT\WazuhAgent\chainsaw.ps1";
        "Destination" = "C:\Program Files (x86)\ossec-agent\active-response\bin\chainsaw.ps1"
    };
    "yara.bat" = @{
        "Source"      = "$ADMIN_DOCUMENT\WazuhAgent\yara.bat";
        "Destination" = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara.bat"
    };
}

## Wazuh Install ##
# Typer cette variable 
$PATH_LOCAL_CONFIGURATION= "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"
[string] $WAZUH_INSTALLER_PATH = Join-Path -Path $TEMP_PATH -ChildPath "wazuh-agent.msi"
[string] $WAZUH_INSTALL_COMMAND = "& msiexec.exe /i `"$WAZUH_INSTALLER_PATH`" /qn WAZUH_MANAGER='$WAZUH_REGISTRATION_SERVER' WAZUH_AGENT_GROUP='$WAZUH_AGENT_GROUP' WAZUH_AGENT_NAME='$WAZUH_AGENT_NAME'"

############
# FONCTION #
############
function CustomLog {
    param(
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [string]
        $message,
        [bool] $isAnError = $false
    )

    if ($isAnError) {
        Write-Error "[-] "$message
    }
    else {
        Write-Host "[+] " -NoNewline -ForegroundColor Green
        Write-Host $message
    }
}

function MoveFiles {
    foreach ($file in $CONFIG_FILES.Keys) {
        Copy-Item -Path $CONFIG_FILES[$file]["Source"] `
            -Destination $CONFIG_FILES[$file]["Destination"] `
            -Recurse `
            -Force
    
        if ( Test-Path -Path $CONFIG_FILES[$file]["Destination"] ) {
            CustomLog -message "Config $file OK"
        }
        else {
            CustomLog -message "$file The destination config file is empty" -isAnError $true
            break
        }
    }
}

function InstallScripts {
    foreach ($Name in $SCRIPT_TO_EXEC.Keys) {
        try {
            CustomLog -message "Installing $Name "
            StartPowershellAsAdmin -Arguments "-File `"$($SCRIPT_TO_EXEC[$Name])`"" 
        }
        catch {
            CustomLog -message "An error occurred during $Name installation: $($_.Exception.Message)" -isAnError $true
        }
    }
}

function StartWazuh {
    Start-Service WazuhSvc
    CustomLog -message "Wazuh service started."
}

function InstallWazuh {
    try {
        $service = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            Write-Warning "Wazuh service not found."

            CustomLog -message "Downloading Wazuh agent installer..."
            $WAZUH_INSTALLER_URL = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.3-1.msi"
            Invoke-WebRequest -Uri $WAZUH_INSTALLER_URL -OutFile $WAZUH_INSTALLER_PATH

            CustomLog -message "Installing Wazuh agent with configuration..."
            StartPowershellAsAdmin -Arguments " -Command $WAZUH_INSTALL_COMMAND"
        } 
        else {
            CustomLog -message "Wazuh agent already installed."
        }
        if ($service.Status -ne 'Running') {
            StartWazuh
        } 
    }
    catch {
        CustomLog -message "An error occurred during installation: $($_.Exception.Message)" -isAnError $true
        Exit 1
    }
}

function StartPowershellAsAdmin {
    param (
        # Argument
        [Parameter(Mandatory = $true)]
        [string]
        $Arguments
    )
    Start-Process -FilePath PowerShell.exe -Wait -Verb Runas -ArgumentList $Arguments
}

function UpdateLocalInternalOption {
    CustomLog -message "Updating local_internal_options.conf"
    $local_internal_options_configuration = Get-Content $PATH_LOCAL_CONFIGURATION
    if (($local_internal_options_configuration -imatch "wazuh_command.remote_commands=")) {
        if (($local_internal_options_configuration -imatch "wazuh_command.remote_commands=0")) {
            $local_internal_options_configuration = $local_internal_options_configuration -replace "wazuh_command.remote_commands=0", "wazuh_command.remote_commands=1"
        } 
    
    }
    elseif (!($local_internal_options_configuration -contains "wazuh_command.remote_commands=1")) {
        $local_internal_options_configuration = $local_internal_options_configuration + "wazuh_command.remote_commands=1"
    }
    
    $local_internal_options_configuration | Out-File -FilePath "C:\Program Files (x86)\ossec-agent\local_internal_options.conf" -Force
}

function PullOrCloneSigma {
    [string] $chainsaw_repository_path = "$SOCFORTRESS_DESTINATION_FOLDER\sigma"
    try {
        if (!(Test-Path $chainsaw_repository_path)) {

            git clone $SIGMA_RULES_GIT_URL $chainsaw_repository_path | Out-Null
            CustomLog -message " Clonning repo to $chainsaw_repository_path"
        }
        else {
            Write-Host "[+] " -NoNewline -ForegroundColor Green
            git -C $chainsaw_repository_path pull
        }
    }
    catch {
        Write-Error "[-] Git probleme [$($_.Exception.Message)]"
        break;
    }
}

function InitChainsawSetup {
    # Factoriser ce code (Peut etre meme le suppr)
    if (Test-Path -Path "$CHAINSAW_SOURCE_FOLDER") {
        CustomLog -message "Removing existing directory: $CHAINSAW_SOURCE_FOLDER"
        Remove-Item -Path "$CHAINSAW_SOURCE_FOLDER" -Recurse -Force -ErrorAction Stop
    }
    elseif (Test-Path -Path $SOCFORTRESS_DESTINATION_FOLDER) {
        CustomLog -message "Removing existing directory: $SOCFORTRESS_DESTINATION_FOLDER"
        Remove-Item -Path $SOCFORTRESS_DESTINATION_FOLDER -Recurse -Force -ErrorAction Stop
    }
    elseif (Test-Path -Path $SOCFORTRESS_DESTINATION_FOLDER) {
        CustomLog -message "Removing existing directory: $SOCFORTRESS_DESTINATION_FOLDER"
        Remove-Item -Path $SOCFORTRESS_DESTINATION_FOLDER -Recurse -Force -ErrorAction Stop
    }
    New-Item -ItemType Directory -Force -Path "$SOCFORTRESS_DESTINATION_FOLDER" | Out-Null
}

function DownloadChainsaw {
    if (-not (Test-Path $CHAINSAW_FILE)) {
        CustomLog -message "Downloading chainsaw.exe"
        Invoke-WebRequest -Uri $CHAINSAW_FILE_URL -OutFile $CHAINSAW_FILE
    } else {
        CustomLog -message "Chainsaw.exe already downloaded"
    }

    if (-not (Test-Path "$ADMIN_DOCUMENT/chainsaw")) {
        CustomLog -message "Extracting chainsaw.exe"
        Expand-Archive -Path $CHAINSAW_FILE -DestinationPath $ADMIN_DOCUMENT
    } else {
        CustomLog -message "Chainsaw.exe already extracted"
    }
}

function RemoveDirectoryIfExists {
    param (
        [string] $path
    )
    if (Test-Path -Path $path) {
        CustomLog -message "Removing existing directory: $path"
        Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
    }
}

function InitializeAndDownloadChainsaw {
    # Initialize setup
    RemoveDirectoryIfExists -path $CHAINSAW_SOURCE_FOLDER
    RemoveDirectoryIfExists -path $SOCFORTRESS_DESTINATION_FOLDER
    RemoveDirectoryIfExists -path "$ADMIN_DOCUMENT\chainsaw"
    RemoveDirectoryIfExists -path "$ADMIN_DOCUMENT\chainsaw.zip"

    # Create the destination directory
    New-Item -ItemType Directory -Force -Path $SOCFORTRESS_DESTINATION_FOLDER | Out-Null

    # Download and extract Chainsaw
    if (-not (Test-Path $CHAINSAW_FILE)) {
        CustomLog -message "Downloading chainsaw.exe"
        Invoke-WebRequest -Uri $CHAINSAW_FILE_URL -OutFile $CHAINSAW_FILE
    } else {
        CustomLog -message "Chainsaw.exe already downloaded"
    }

    if (-not (Test-Path "$ADMIN_DOCUMENT/chainsaw")) {
        CustomLog -message "Extracting chainsaw.exe"
        Expand-Archive -Path $CHAINSAW_FILE -DestinationPath $ADMIN_DOCUMENT
    } else {
        CustomLog -message "Chainsaw.exe already extracted"
    }
}

function YaraSetup {
    # Factoriser ce code dans la fonction MoveFile
    $headers = @{
        'Accept' = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        'Accept-Language' = 'en-US,en;q=0.5'
        'Referer' = 'https://valhalla.nextron-systems.com/'
        'Content-Type' = 'application/x-www-form-urlencoded'
        'DNT' = '1'
        'Upgrade-Insecure-Requests' = '1'
    }

    $body = @{
        'demo' = 'demo'
        'apikey' = '1111111111111111111111111111111111111111111111111111111111111111'
        'format' = 'text'
    }

    $tempDir = [System.IO.Path]::GetTempPath() + [System.IO.Path]::GetRandomFileName()
    New-Item -Path $tempDir -ItemType Directory -Force | Out-Null

    try {
        Invoke-WebRequest -Uri 'https://github.com/VirusTotal/yara/releases/download/v4.2.3/yara-4.2.3-2029-win64.zip' -OutFile "$tempDir\v4.2.3-2029-win64.zip"
        Invoke-WebRequest -Uri 'https://valhalla.nextron-systems.com/api/v1/get' -Method Post -Headers $headers -Body $body -OutFile "$tempDir\yara_rules.yar"

        Expand-Archive -Path "$tempDir\v4.2.3-2029-win64.zip" -DestinationPath $tempDir -Force
        $yaraExePath = Join-Path -Path $tempDir -ChildPath "yara64.exe"
        if (-Not (Test-Path -Path $yaraExePath)) {
            throw "Le fichier 'yara64.exe' est introuvable dans l'archive extraite."
        }

        New-Item -Path 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\' -ItemType Directory -Force | Out-Null
        New-Item -Path 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\' -ItemType Directory -Force | Out-Null

        Copy-Item -Path $yaraExePath -Destination 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\' -Force
        CustomLog -message "YARA binary download succesfully"
        
        Copy-Item -Path "$tempDir\yara_rules.yar" -Destination 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\' -Force
        CustomLog -message "YARA rules download succesfully"
    }
    catch {
        Write-Error "Une erreur est survenue : $_"
    }
    finally {
        Remove-Item -Path $tempDir -Recurse -Force
    }
}

function YaraOssecSetup {
    param (
        [Parameter(Mandatory = $true)]
        [string] $Username
    )
    $configContent = Get-Content -Path $CONFIG_FILE_PATH
    $directoryConfig = "<directories realtime=""yes"">C:\Users\$Username\Downloads</directories>"
    $configContentString = $configContent -join "`n"
    if (-not ($configContentString.Contains($directoryConfig))) {
        $newConfigContentString = $configContentString -replace "(</syscheck>)", "    $directoryConfig`n`$1"
        $newConfigContent = $newConfigContentString -split "`n"
        Set-Content -Path $CONFIG_FILE_PATH -Value $newConfigContent
        CustomLog -message "ossec.conf MAJ"
    } else {
        CustomLog -message "ossec.conf already setup"
    }
    Restart-Service -Name wazuh
}

function WingetInstallDependencies4Wazuh {
    winget source update
    winget install git.git --accept-package-agreements --accept-source-agreements
}


############
#   MAIN   #
############
function Main {
    param (
        [CmdletBinding()]
        [Parameter(Mandatory = $true)]
        [string] $Group,

        [Parameter(Mandatory = $true)]
        [string] $Name,

        [Parameter(Mandatory = $true)]
        [string] $Manager
    )

    begin {
        if (!($IS_ADMIN)) {
            # Faire en sorte que ca marche, suppr la boucle
            $name, $args = $($MyInvocation.Line).Split(" ")
            $unbound_arguments = ""
            for ($i = 0; $i -lt $args.length; $i += 2) {
                $unbound_arguments += "$($args[$i]) $($args[$i+1]) "
            }
            $relaunch_as_admin_args = "-noexit -File `"$($MyInvocation.MyCommand.Path)`" $($unbound_arguments)"
            $MyInvocation.UnboundArguments
            StartPowershellAsAdmin -Arguments $relaunch_as_admin_args
            Exit
        }
    }
    
    process {
        InstallWazuh
        InstallScripts
        UpdateLocalInternalOption
        InitializeAndDownloadChainsaw
        MoveFiles
        PullOrCloneSigma
        YaraOssecSetup -Username $Name
    }

    end {
        CustomLog "Finish !"
    }
}

Main -Group $WAZUH_AGENT_GROUP -Name $WAZUH_AGENT_NAME -Manager $WAZUH_REGISTRATION_SERVER
