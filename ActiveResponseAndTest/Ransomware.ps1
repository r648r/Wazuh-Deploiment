$rootDir = "C:\Users\Admin\Downloads\Ransomware-Samples"
$password = "infected"
$malwareDir = "C:\Users\Admin\Downloads\malware"
$repo = "https://github.com/kh4sh3i/Ransomware-Samples.git"
git clone $repo $rootDir

# Load the required assembly for ZIP file handling
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Function to extract ZIP files
function ExtractZipFile {
    param (
        [string]$zipFilePath,
        [string]$destinationPath,
        [string]$password
    )
    
    # Create destination directory if it does not exist
    if (-not (Test-Path $destinationPath)) {
        New-Item -ItemType Directory -Path $destinationPath
    }
    
    # Create a new shell application COM object
    $shell = New-Object -ComObject Shell.Application
    
    # Open the ZIP file
    $zipFile = $shell.NameSpace($zipFilePath)
    
    if ($null -eq $zipFile) {
        Write-Output "Failed to open ZIP file: $zipFilePath"
        return
    }

    # Extract the ZIP file
    foreach ($item in $zipFile.Items()) {
        $shell.NameSpace($destinationPath).CopyHere($item, 16)
    }
    
    Write-Output "Extracted: $zipFilePath to $destinationPath"
}

# Create the malware directory if it doesn't exist
if (-not (Test-Path $malwareDir)) {
    New-Item -ItemType Directory -Path $malwareDir
}

# Loop through each sub-directory in the root directory
Get-ChildItem -Path $rootDir -Directory | ForEach-Object {
    $subDir = $_.FullName
    # Get all ZIP files in the sub-directory
    Get-ChildItem -Path $subDir -Filter *.zip | ForEach-Object {
        $zipFile = $_.FullName
        $destination = [System.IO.Path]::Combine($subDir, "Extracted")
        # Extract the ZIP file
        ExtractZipFile -zipFilePath $zipFile -destinationPath $destination -password $password
    }
    
    # Move all files to the malware directory
    Get-ChildItem -Path $subDir -Recurse -File | ForEach-Object {
        if ($_.Extension -ne ".zip") {
            $file = $_.FullName
            $destFile = [System.IO.Path]::Combine($malwareDir, $_.Name)
            Move-Item -Path $file -Destination $destFile
            Write-Output "Moved: $file to $destFile"
        }
    }    
}
