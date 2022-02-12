write-host "  _________________________  " -ForegroundColor red
write-host "((                         ))" -ForegroundColor red
write-host " )) Frack113 clean script (( " -ForegroundColor red
write-host "((                         ))" -ForegroundColor red
write-host "  -------------------------  " -ForegroundColor red
Import-Module .\Export-WinEvents
$list_channel = ('Application','Security','System','Microsoft-Windows-Sysmon/Operational','Windows PowerShell','Microsoft-Windows-PowerShell/Operational')
$list_channel | Clear-WinEvents -Verbose
