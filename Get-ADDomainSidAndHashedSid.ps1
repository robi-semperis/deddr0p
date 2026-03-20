Write-Host "FQDN: $((Get-ADDomain).DNSroot)"

$rootDomainSid = ""
$hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
$hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($rootDomainSid)) 
$hashString = [System.BitConverter]::ToString($hash)
Write-Host "Encrypted Sid: " $hashString.Replace('-', '')
Write-Host ""


$rootDomainSid = (Get-ADDomain -Server (Get-ADForest).RootDomain).DomainSID.value
$rootDomainSid
$hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
$hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($rootDomainSid))
$hashString = [System.BitConverter]::ToString($hash)
$hashString.Replace('-', '')
