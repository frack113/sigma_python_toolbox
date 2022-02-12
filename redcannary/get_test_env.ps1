write-host "  _________________________  " -ForegroundColor red
write-host "((                         ))" -ForegroundColor red
write-host " )) Frack113 tests script (( " -ForegroundColor red
write-host "((                         ))" -ForegroundColor red
write-host "  -------------------------  " -ForegroundColor red
write-host " for the best of my knowledge "

write-host "Import module"
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psm1

Invoke-AtomicTest all -GetPrereqs -TimeoutSeconds 480
