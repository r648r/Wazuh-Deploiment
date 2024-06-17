$downloads_path = "C:\Users\Admin\Downloads"
$log_file_path = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
$files = Get-ChildItem -Path $downloads_path -File | Select-Object -ExpandProperty FullName
$yara_exe_path = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\yara64.exe"
$yara_rules_path = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\yara_rules.yar"

foreach ($file in $files) {
    $yara_output = & $yara_exe_path $yara_rules_path $file
    if ($null -ne $yara_output -and $yara_output.Trim() -ne "") {
        Add-Content -Path $log_file_path -Value $file
        foreach ($line in $yara_output) {
            Add-Content -Path $log_file_path -Value "wazuh-yara: INFO - Scan result: $line"
        }
    }
}
