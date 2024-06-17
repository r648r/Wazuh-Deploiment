$sysinternals_repo = 'download.sysinternals.com'
$sysinternals_downloadlink = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
$sysinternals_folder = 'C:\Program Files\sysinternals'
$sysinternals_zip = 'SysinternalsSuite.zip'
$sysmonconfigDefault_downloadlink = 'https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml'
$sysmonconfigRecommended_downloadlink = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml'
$sysmonconfigdefault_file = 'sysmonconfig-export.xml'
$sysmonconfigrecommended_file = 'sysmonSwiftSecurity.xml'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (Test-Path -Path $sysinternals_folder) {
  write-host ('Sysinternals folder already exists')
}
else {
  $OutPath = $env:TMP
  $output = $sysinternals_zip
  New-Item -Path "C:\Program Files" -Name "sysinternals" -ItemType "directory"
  $X = 0
  do {
    Write-Output "Waiting for network"
    Start-Sleep -s 5
    $X += 1
  } until(($connectreult = Test-NetConnection $sysinternals_repo -Port 443 | Where-Object { $_.TcpTestSucceeded }) -or $X -eq 3)

  if ($connectreult.TcpTestSucceeded -eq $true) {
    Try {
      write-host ('Downloading and copying Sysinternals Tools to C:\Program Files\sysinternals...')
      Invoke-WebRequest -Uri $sysinternals_downloadlink -OutFile $OutPath\$output
      Expand-Archive -path $OutPath\$output -destinationpath $sysinternals_folder
      Start-Sleep -s 10
      Invoke-WebRequest -Uri $sysmonconfigDefault_downloadlink -OutFile $OutPath\$sysmonconfigdefault_file
      Invoke-WebRequest -Uri $sysmonconfigRecommended_downloadlink -OutFile $OutPath\$sysmonconfigrecommended_file
      $serviceName = 'Sysmon64'
      If (Get-Service $serviceName -ErrorAction SilentlyContinue) {
        write-host ('Sysmon Is Already Installed')
      }
      else {
        # Add Sysinternals to PATH
        $EnvVarPath = [System.Environment]::GetEnvironmentVariable("Path")
        [System.Environment]::SetEnvironmentVariable("PATH", $EnvVarPath + ";C:\Program Files\Sysinternals\")
    
        Invoke-Command { reg.exe ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f }
        Invoke-Command { reg.exe ADD HKU\.DEFAULT\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f }
        Start-Process -FilePath $sysinternals_folder\Sysmon64.exe -Argumentlist @("-accepteula -i", "$OutPath\$sysmonconfigdefault_file")
        Start-Process -FilePath $sysinternals_folder\Sysmon64.exe -Argumentlist @("-c", "$OutPath\$sysmonconfigrecommended_file")
      }
    }
    Catch {
      $ErrorMessage = $_.Exception.Message
      $FailedItem = $_.Exception.ItemName
      Write-Error -Message "$ErrorMessage $FailedItem"
      exit 1
    }
    Finally {
      Remove-Item -Path $OutPath\$output
    }

  }
  else {
    Write-Output "Unable to connect to Sysinternals Repo"
  }
}