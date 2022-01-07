write-host "  _________________________  " -ForegroundColor red
write-host "((                         ))" -ForegroundColor red
write-host " )) Frack113 tests script (( " -ForegroundColor red
write-host "((                         ))" -ForegroundColor red
write-host "  -------------------------  " -ForegroundColor red
write-host " for the best of my knowledge "

write-host "Import module"
Import-Module .\Export-WinEvents
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psm1

write-host " Open csv"
$csv = Import-Csv -Path .\Full_tests.csv -Delimiter ';'

$list_channel = ('Application','Security','System','Microsoft-Windows-Sysmon/Operational','Windows PowerShell','Microsoft-Windows-PowerShell/Operational')

foreach ($info in $csv)
{
	$technique = $info.technique
	$nmr = $info.nmr_test
	$valid = $info.sigma
	$name =  $info.name
	if ($info.os -like '*windows*'){
		if ($valid -eq 'False') {
			write-host "Test $name - $technique test : $nmr" 
			write-host "Make environnement" 
			Invoke-AtomicTest $technique -TestNumbers $nmr -GetPrereqs
			$list_channel | Clear-WinEvents -Verbose
			Start-Sleep -s 5

			write-host "Start Aurora" 
			Start-Process C:\aurora-beta\aurora-agent-64.exe -WorkingDirectory C:\aurora-beta\ -ArgumentList "-c agent-config-standard.yml","--minimum-level low","--json","-l c:\Tests\$($technique)_test_$($nmr)_aurora.json"
			Start-Sleep -s 15
		
			write-host "Start test" 
			Invoke-AtomicTest $technique -TestNumbers $nmr

			Start-Sleep -s 5
			$list_channel | Export-WinEvents -TimeBucket 'Last 5 Minutes' -OutputPath "$($technique)_test_$($nmr)_dataset.json" -Verbose

			write-host "Stop Aurora" 
			Stop-Process -name aurora-agent-64
		
			write-host "Cleanup" 
			Invoke-AtomicTest $technique -TestNumbers $nmr -Cleanup
			Start-Sleep -s 5
		} Else {
			write-host "$name / $technique test: $nmr allready done" -ForegroundColor green
		}
	} Else {
		write-host "$name / $technique test: $nmr  Not windows" -ForegroundColor yellow
	}
	
}