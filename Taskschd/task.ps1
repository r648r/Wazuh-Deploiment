# Tester ce code !!
function Get-TaskExecutionInfo {
    param (
        [string]$taskName
    )

    $task = Get-ScheduledTask -TaskName $taskName
    $nextRunTime = $task.NextRunTime
    $lastRunTime = $task.LastRunTime

    Write-Output "Prochaine execution : $nextRunTime"
    Write-Output "Derniere execution : $lastRunTime"
}

$xmlPath =  "C:\Users\Admin\Documents\Taskschd\Chainsaw.xml"
$taskName = "Chansaw-1H"
Register-ScheduledTask -Xml (Get-Content $xmlPath | Out-String) -TaskName $taskName
Get-TaskExecutionInfo -taskName $taskName