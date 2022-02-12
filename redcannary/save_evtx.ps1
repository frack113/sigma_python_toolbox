write-host "  _________________________  " -ForegroundColor red
write-host "((                         ))" -ForegroundColor red
write-host " )) Frack113 tests script (( " -ForegroundColor red
write-host "((                         ))" -ForegroundColor red
write-host "  -------------------------  " -ForegroundColor red
write-host " for the best of my knowledge "

write-host "Import module"
Import-Module .\Export-WinEvents

$list_channel = ('Application','Security','System','Microsoft-Windows-Sysmon/Operational','Windows PowerShell','Microsoft-Windows-PowerShell/Operational')
$list_channel | Export-WinEvents -TimeBucket 'Last 5 Minutes' -OutputPath "test_dataset.json" -Verbose
