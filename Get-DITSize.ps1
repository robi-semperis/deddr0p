# Display DIT size 

$ditPath = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters")."DSA Database file"

Get-Item $ditPath | Select-Object FullName, @{Name="SizeGB"; Expression={[math]::Round($_.Length / 1GB, 3)}}

