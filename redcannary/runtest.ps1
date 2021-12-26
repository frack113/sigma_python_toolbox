write-host "Import module"
Import-Module .\Export-WinEvents
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psm1

write-host " Open csv"
$csv = Import-Csv -Path .\Full_tests.csv -Delimiter ';'

$list_channel = ('Application','Security','System','Microsoft-Windows-Sysmon/Operational','Windows PowerShell','Microsoft-Windows-PowerShell/Operational')

foreach ($info in $csv)
{
	$technique=$info.technique
	$nmr=$info.nmr_test

	write-host "Test $technique test : $nmr" 

	Invoke-AtomicTest $technique -GetPrereqs
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
}