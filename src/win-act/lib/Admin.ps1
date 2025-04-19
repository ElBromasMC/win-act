
$route = Join-Path -Path (Get-Location) -ChildPath ".\lib\Activation.ps1"
Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList "-noexit -executionpolicy bypass -file `"$route`""

