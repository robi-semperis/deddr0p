<#
.SYNOPSIS
    Sets a configurable synthetic thumbnailPhoto value on lab user accounts.

.DESCRIPTION
    Searches for user objects beneath the configured UsersOU using Active Directory
    Name Resolution (ANR). Matching users must have a name beginning with the
    configured UsernamePrefix in the ANR search.

    If a matching user does not already have a thumbnailPhoto value, the script
    adds a synthetic byte payload sized according to PhotoSizeKB. Use
    -ForceUpdate to replace an existing value or add one when it is missing.

    This version uses native LDAP/ADSI through System.DirectoryServices. It does
    not use the ActiveDirectory PowerShell module and does not require Active
    Directory Web Services (ADWS).

    Edit the $DefaultSettings section before running the script. The script does
    not prompt for configuration values. The UsersOU, UsernamePrefix, and
    PhotoSizeKB settings can also be overridden for a single run using optional
    command-line parameters; the hard-coded defaults are not changed.

.NOTES
    Script Name : Invoke-SetUserPhoto.ps1
    Version     : v1.3.2
    PowerShell  : Windows PowerShell 5.1
    Platform    : Windows Server 2019 or later
    Requirement : LDAP/ADSI; no ADWS or ActiveDirectory PowerShell module required

    The generated value is a synthetic binary payload intended for lab storage
    testing. The default size is 64 KB. It is not guaranteed to be a displayable
    JPEG image.

    thumbnailPhoto size limitations:
    - The default maximum for thumbnailPhoto is 102,400 bytes, equivalent to 100 KiB.
    - Because PowerShell uses 1KB = 1,024 bytes, the maximum PhotoSizeKB setting
      for that default schema limit is PhotoSizeKB = 100.
    - PhotoSizeKB = 128 produces 131,072 bytes, exceeding the default schema limit
      and causing a constraint violation.
    - The schema rangeUpper value is checked at runtime because custom schemas may
      impose a lower limit.

    The ANR filter may match more than sAMAccountName. Review the result count and
    use a distinctive UsernamePrefix. Per-user processing details are always
    displayed; -Verbose is not required.

    Use only in an isolated lab environment. The script modifies Active Directory
    user objects and should not be run against production directories.

.PARAMETER ForceUpdate
    Replaces the existing thumbnailPhoto value for every matching user, or adds
    the value when thumbnailPhoto is not present.

.PARAMETER ClearThumbnailPhoto
    Removes the thumbnailPhoto value from every matching user by clearing the
    attribute so it is not set. This cannot be combined with -ForceUpdate.

.PARAMETER UsersOU
    Optional command-line override for the UsersOU default setting.

.PARAMETER UsernamePrefix
    Optional command-line override for the UsernamePrefix default setting.

.PARAMETER PhotoSizeKB
    Optional command-line override for the PhotoSizeKB default setting.

.PARAMETER Help
    Displays the complete comment-based help, including parameters and examples.

.EXAMPLE
    .\Invoke-SetUserPhoto.ps1

    Adds a synthetic 64-KB thumbnailPhoto value only to matching users that do
    not already have one.

.EXAMPLE
    .\Invoke-SetUserPhoto.ps1 -ForceUpdate

    Replaces or adds thumbnailPhoto for every matching user, regardless of whether
    the attribute currently has a value.

.EXAMPLE
    .\Invoke-SetUserPhoto.ps1 -ClearThumbnailPhoto

    Clears thumbnailPhoto for matching users that currently have a photo value.

.EXAMPLE
    .\Invoke-SetUserPhoto.ps1 -ClearThumbnailPhoto -WhatIf

    Shows which matching users would have thumbnailPhoto cleared without modifying
    Active Directory.

.EXAMPLE
    .\Invoke-SetUserPhoto.ps1 -UsersOU 'OU=TEST,DC=D01,DC=lab' -UsernamePrefix 'Good Act0r 00016' -PhotoSizeKB 64

    Runs once with command-line overrides. The hard-coded defaults remain unchanged.

.EXAMPLE
    .\Invoke-SetUserPhoto.ps1 -WhatIf

    Shows what would be changed without modifying Active Directory.

.EXAMPLE
    .\Invoke-SetUserPhoto.ps1 -Help

    Displays the full script help.

.EXAMPLE
    .\Invoke-SetUserPhoto.ps1 -WhatIf

    Representative dry-run output:

    What if: Performing the operation "add a synthetic 64-KB thumbnailPhoto value" on target "CN=good0001,OU=TEST,DC=adfr,DC=lab".
    What if: Performing the operation "add a synthetic 64-KB thumbnailPhoto value" on target "CN=good0002,OU=TEST,DC=adfr,DC=lab".

    thumbnailPhoto schema maximum : 102400 bytes (100 KiB)
    Requested PhotoSizeKB         : 64 KB (65536 bytes)

    Invoke-SetUserPhoto.ps1 v1.3.2 completed.
    Target OU       : OU=TEST,DC=adfr,DC=lab
    ANR prefix      : good
    Photo size      : 64 KB
    Users found     : 2
    Users processed : 2
    Users changed   : 0
    Users skipped   : 0
    Errors          : 0
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [switch]$ForceUpdate,

    [Parameter(Mandatory = $false)]
    [switch]$ClearThumbnailPhoto,

    [Parameter(Mandatory = $false)]
    [string]$UsersOU,

    [Parameter(Mandatory = $false)]
    [string]$UsernamePrefix,

    [Parameter(Mandatory = $false)]
    [int]$PhotoSizeKB,

    [Parameter(Mandatory = $false)]
    [switch]$Help
)

# ============================================================================
# Default settings - edit these values before running the script.
# ============================================================================
$DefaultSettings = [ordered]@{
    UsersOU        = 'REPLACE_WITH_OU_DN_FOR_USERS'
    UsernamePrefix  = 'REPLACE_WITH_USERNAME_PREFIX_TO_SEARCH'
    PhotoSizeKB    = 64
}

$ScriptName     = 'Invoke-SetUserPhoto.ps1'
$ScriptVersion  = 'v1.3.2'
$PhotoSizeBytes = $null

function Show-ScriptHelp {
    $helpPath = $PSCommandPath

    if ([string]::IsNullOrWhiteSpace($helpPath)) {
        $helpPath = $MyInvocation.ScriptName
    }

    Get-Help -Name $helpPath -Full | Out-Host
}

function Escape-LdapFilterValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    # Escape LDAP filter metacharacters except '*', which is retained as a wildcard.
    $escaped = $Value.Replace('\', '\5c')
    $escaped = $escaped.Replace('(', '\28')
    $escaped = $escaped.Replace(')', '\29')
    $escaped = $escaped.Replace([string][char]0, '\00')

    return $escaped
}

function New-SyntheticPhotoBytes {
    param(
        [Parameter(Mandatory = $true)]
        [int]$SizeBytes
    )

    $bytes = New-Object byte[] $SizeBytes
    $randomNumberGenerator = [System.Security.Cryptography.RandomNumberGenerator]::Create()

    try {
        $randomNumberGenerator.GetBytes($bytes)
    }
    finally {
        $randomNumberGenerator.Dispose()
    }

    # Prevent PowerShell from enumerating the byte array into an Object[] result.
    Write-Output -NoEnumerate -InputObject $bytes
}

function Get-ThumbnailPhotoSchemaLimitBytes {
    # Reads the thumbnailPhoto attributeSchema rangeUpper value through LDAP.
    # Returns 0 when no rangeUpper value is defined.
    $rootDse = $null
    $schemaRoot = $null
    $schemaSearcher = $null
    $schemaResult = $null

    try {
        $rootDse = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList 'LDAP://RootDSE'
        $null = $rootDse.NativeObject
        $schemaNamingContext = [string]$rootDse.Properties['schemaNamingContext'][0]

        if ([string]::IsNullOrWhiteSpace($schemaNamingContext)) {
            return 0
        }

        # schemaNamingContext already contains CN=Schema,CN=Configuration,...
        $schemaRoot = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList ("LDAP://$schemaNamingContext")
        $null = $schemaRoot.NativeObject

        $schemaSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $schemaRoot
        $schemaSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $schemaSearcher.Filter = '(&(objectClass=attributeSchema)(lDAPDisplayName=thumbnailPhoto))'
        $null = $schemaSearcher.PropertiesToLoad.Add('rangeUpper')
        $schemaResult = $schemaSearcher.FindOne()

        if ($null -eq $schemaResult -or
            $schemaResult.Properties['rangeupper'].Count -eq 0) {
            return 0
        }

        return [int64]$schemaResult.Properties['rangeupper'][0]
    }
    finally {
        if ($schemaResult) { $schemaResult = $null }
        if ($schemaSearcher) { try { $schemaSearcher.Dispose() } catch {} }
        if ($schemaRoot) { try { $schemaRoot.Dispose() } catch {} }
        if ($rootDse) { try { $rootDse.Dispose() } catch {} }
    }
}

function Get-LdapPhotoSize {
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.SearchResult]$SearchResult
    )

    # Check the returned property names rather than assuming that requesting the
    # attribute means it exists on the object.
    $photoPropertyName = @(
        $SearchResult.Properties.PropertyNames |
            Where-Object { $_ -ieq 'thumbnailPhoto' }
    ) | Select-Object -First 1

    if ([string]::IsNullOrWhiteSpace($photoPropertyName)) {
        return 0
    }

    $photoValues = $SearchResult.Properties[$photoPropertyName]

    if ($null -eq $photoValues -or $photoValues.Count -eq 0) {
        return 0
    }

    $photoValue = $photoValues[0]

    if ($photoValue -is [byte[]]) {
        return $photoValue.Length
    }

    if ($photoValue -is [System.Array]) {
        return $photoValue.Length
    }

    # A non-null returned value still indicates that the attribute exists.
    return 1
}

if ($Help) {
    Show-ScriptHelp
    exit 0
}

if ($PSBoundParameters.ContainsKey('UsersOU')) {
    $DefaultSettings.UsersOU = $UsersOU
}

if ($PSBoundParameters.ContainsKey('UsernamePrefix')) {
    $DefaultSettings.UsernamePrefix = $UsernamePrefix
}

if ($PSBoundParameters.ContainsKey('PhotoSizeKB')) {
    $DefaultSettings.PhotoSizeKB = $PhotoSizeKB
}

if ($ForceUpdate -and $ClearThumbnailPhoto) {
    Write-Error '-ForceUpdate and -ClearThumbnailPhoto cannot be used together.'
    exit 2
}

try {
    $photoSizeKB = [int]$DefaultSettings.PhotoSizeKB
}
catch {
    Write-Error 'PhotoSizeKB must be a positive whole number. Set it in the Default settings section.'
    exit 2
}

if ($photoSizeKB -lt 1) {
    Write-Error 'PhotoSizeKB must be at least 1. Set it in the Default settings section.'
    exit 2
}

$PhotoSizeBytes = $photoSizeKB * 1KB

if ([string]::IsNullOrWhiteSpace($DefaultSettings.UsersOU) -or
    [string]::IsNullOrWhiteSpace($DefaultSettings.UsernamePrefix)) {
    Write-Error @"
Default configuration is incomplete.
Edit the Default settings section in $ScriptName and assign:
  UsersOU        = the target OU distinguished name
  UsernamePrefix = the ANR prefix to search for
  PhotoSizeKB    = the synthetic payload size in KB
The script does not prompt for these values.
"@
    exit 2
}

if ($DefaultSettings.UsersOU -like 'REPLACE_WITH_*' -or
    $DefaultSettings.UsernamePrefix -like 'REPLACE_WITH_*') {
    Write-Error @"
Default configuration has not been set.
Edit the Default settings section in $ScriptName and assign:
  UsersOU        = the target OU distinguished name
  UsernamePrefix = the ANR prefix to search for
  PhotoSizeKB    = the synthetic payload size in KB
The script does not prompt for these values.
"@
    exit 2
}

if ($ClearThumbnailPhoto) {
    Write-Host 'Operation mode                 : ClearThumbnailPhoto' -ForegroundColor Cyan
    Write-Host 'PhotoSizeKB/schema validation  : skipped because no photo value will be written' -ForegroundColor Cyan
}
else {
    try {
        $thumbnailPhotoSchemaMaxBytes = Get-ThumbnailPhotoSchemaLimitBytes
    }
    catch {
        Write-Error "Unable to read the thumbnailPhoto schema rangeUpper value through LDAP. $($_.Exception.Message)"
        exit 1
    }

    if ($thumbnailPhotoSchemaMaxBytes -le 0) {
        Write-Error 'The thumbnailPhoto schema rangeUpper value could not be determined. No users were modified.'
        exit 1
    }

    $thumbnailPhotoSchemaMaxKB = [math]::Floor($thumbnailPhotoSchemaMaxBytes / 1KB)

    Write-Host "thumbnailPhoto schema maximum : $thumbnailPhotoSchemaMaxBytes bytes ($thumbnailPhotoSchemaMaxKB KiB)" -ForegroundColor Cyan
    Write-Host "Requested PhotoSizeKB         : $photoSizeKB KB ($PhotoSizeBytes bytes)" -ForegroundColor Cyan

    if ($PhotoSizeBytes -gt $thumbnailPhotoSchemaMaxBytes) {
        Write-Error @"
PhotoSizeKB validation failed before any users were modified.
Requested size              : $photoSizeKB KB ($PhotoSizeBytes bytes)
Maximum allowed by AD schema : $thumbnailPhotoSchemaMaxBytes bytes ($thumbnailPhotoSchemaMaxKB KiB)
Set PhotoSizeKB to $thumbnailPhotoSchemaMaxKB or lower and run the script again.
"@
        exit 2
    }
}

$searchRoot = $null
$searcher = $null
$searchResults = $null
$targetOUEntry = $null

try {
    # RootDSE is accessed through LDAP and does not require ADWS.
    $rootDse = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList 'LDAP://RootDSE'
    $null = $rootDse.NativeObject
    $defaultNamingContext = [string]$rootDse.Properties['defaultNamingContext'][0]
    $rootDse.Dispose()

    $targetOUEntry = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList ("LDAP://$($DefaultSettings.UsersOU)")
    $null = $targetOUEntry.NativeObject

    $escapedPrefix = Escape-LdapFilterValue -Value $DefaultSettings.UsernamePrefix
    $ldapFilter = "(&(objectCategory=person)(objectClass=user)(anr=$escapedPrefix*))"

    $searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $targetOUEntry
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $searcher.PageSize = 1000
    $searcher.Filter = $ldapFilter
    $null = $searcher.PropertiesToLoad.Add('distinguishedName')
    $null = $searcher.PropertiesToLoad.Add('sAMAccountName')
    $null = $searcher.PropertiesToLoad.Add('thumbnailPhoto')

    $searchResults = $searcher.FindAll()
}
catch {
    Write-Error "Unable to query the target OU through LDAP/ADSI. $($_.Exception.Message)"
    if ($searchResults) { $searchResults.Dispose() }
    if ($searcher) { $searcher.Dispose() }
    if ($targetOUEntry) { $targetOUEntry.Dispose() }
    exit 1
}

$processedCount = 0
$changedCount = 0
$skippedCount = 0
$errorCount = 0
$matchedCount = $searchResults.Count

if ($matchedCount -eq 0) {
    Write-Warning "No matching users found beneath '$($DefaultSettings.UsersOU)' using ANR prefix '$($DefaultSettings.UsernamePrefix)'."
    $searchResults.Dispose()
    $searcher.Dispose()
    $targetOUEntry.Dispose()
    exit 0
}

foreach ($result in $searchResults) {
    $processedCount++
    $distinguishedName = [string]$result.Properties['distinguishedname'][0]
    $samAccountName = [string]$result.Properties['samaccountname'][0]
    $thumbnailPhotoSize = Get-LdapPhotoSize -SearchResult $result
    $hasThumbnailPhoto = ($thumbnailPhotoSize -gt 0)

    if ($ClearThumbnailPhoto) {
        if (-not $hasThumbnailPhoto) {
            $skippedCount++
            Write-Host "Skipped $($samAccountName): thumbnailPhoto is not set." -ForegroundColor Yellow
            continue
        }

        $action = 'clear'
        $operationDescription = 'clear the thumbnailPhoto value'
    }
    else {
        if ($hasThumbnailPhoto -and -not $ForceUpdate) {
            $skippedCount++
            Write-Host "Skipped $($samAccountName): thumbnailPhoto already exists ($thumbnailPhotoSize bytes)." -ForegroundColor Yellow
            continue
        }

        $action = if ($hasThumbnailPhoto) { 'replace' } else { 'add' }
        $operationDescription = "${action} a synthetic $photoSizeKB-KB thumbnailPhoto value"
    }

    if (-not $PSCmdlet.ShouldProcess(
            $distinguishedName,
            $operationDescription)) {
        continue
    }

    $userEntry = $null

    try {
        $userEntry = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList ("LDAP://$distinguishedName")
        $null = $userEntry.NativeObject

        $thumbnailPhotoProperty = $userEntry.Properties['thumbnailPhoto']

        if ($ClearThumbnailPhoto) {
            # Clear() removes the attribute value so thumbnailPhoto is not set.
            $thumbnailPhotoProperty.Clear()
            $userEntry.CommitChanges()
            $changedCount++
            Write-Host "Cleared thumbnailPhoto for $samAccountName." -ForegroundColor Green
        }
        else {
            [byte[]]$syntheticPhoto = New-SyntheticPhotoBytes -SizeBytes $PhotoSizeBytes

            # Use Add() with an explicit byte array for reliable ADSI octet-string writes.
            # Clear() makes this work for both new and existing thumbnailPhoto values.
            $thumbnailPhotoProperty.Clear()
            $null = $thumbnailPhotoProperty.Add($syntheticPhoto)
            $userEntry.CommitChanges()

            $changedCount++
            Write-Host "Updated $samAccountName." -ForegroundColor Green
        }
    }
    catch {
        $errorCount++
        Write-Warning "Failed to update $($samAccountName): $($_.Exception.Message)"
    }
    finally {
        if ($userEntry) {
            $userEntry.Dispose()
        }
    }
}

$searchResults.Dispose()
$searcher.Dispose()
$targetOUEntry.Dispose()

Write-Host ''
Write-Host "$ScriptName $ScriptVersion completed." -ForegroundColor Green
Write-Host "Target OU       : $($DefaultSettings.UsersOU)"
Write-Host "ANR prefix      : $($DefaultSettings.UsernamePrefix)"
if ($ClearThumbnailPhoto) {
    Write-Host "Operation       : Clear thumbnailPhoto"
}
else {
    Write-Host "Photo size      : $photoSizeKB KB"
}
Write-Host "Users found     : $matchedCount"
Write-Host "Users processed : $processedCount"
Write-Host "Users changed   : $changedCount"
Write-Host "Users skipped   : $skippedCount"
Write-Host "Errors          : $errorCount"
Write-Host "Per-user processing details are displayed by default."
