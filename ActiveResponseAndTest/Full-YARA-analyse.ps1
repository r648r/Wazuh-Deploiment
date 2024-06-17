param (
    [string]$DOWNLOADS_PATH = "C:\Users\Admin\",
    [string]$YARA_EXE_PATH = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\yara64.exe",
    [string]$YARA_RULES_PATH = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\yara_rules.yar"
)

function runYaraScan {
    param (
        [string]$exePath,
        [string]$rulesPath,
        [string]$scanPath
    )

    # Exécuter la commande et capturer la sortie et les erreurs dans des variables
    $output = & $exePath $rulesPath -r $scanPath 2>&1

    # Filtrer les résultats pour exclure les messages d'erreur
    $filteredOutput = $output | Where-Object { $_ -notmatch 'error scanning .* could not open file' }

    # Créer un tableau d'objets personnalisés pour les résultats filtrés
    $results = $filteredOutput | ForEach-Object {
        # Diviser chaque ligne en deux parties : type de malware et chemin de fichier
        if ($_ -match "^(.*?)\s+(C:.*)$") {
            [PSCustomObject]@{
                MalwareType = $matches[1]
                FilePath = $matches[2]
            }
        }
    }

    return $results
}

function displayResults {
    param (
        [array]$results
    )

    # Afficher les résultats dans un tableau
    $results | Format-Table -AutoSize
}

# Exécuter l'analyse et afficher les résultats
$results = runYaraScan -exePath $YARA_EXE_PATH -rulesPath $YARA_RULES_PATH -scanPath $DOWNLOADS_PATH
displayResults -results $results
