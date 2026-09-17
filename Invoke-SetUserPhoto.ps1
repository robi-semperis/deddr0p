<#
.SYNOPSIS
    Sets a configurable synthetic thumbnailPhoto value on lab user accounts.

.DESCRIPTION
    Searches for user objects beneath the configured UsersOU using an LDAP OR
    filter across common name-related attributes. Matching users must have a
    name-related attribute matching the configured UsernamePrefix. Include LDAP wildcard characters
    explicitly in UsernamePrefix, such as '*' for all users or 'Good*' for a
    prefix search.

    If a matching user does not already have a thumbnailPhoto value, the script
    adds a synthetic byte payload sized according to PhotoSizeKB. Use
    -ForceUpdate to replace an existing value or add one when it is missing.

    This version uses native LDAP through System.DirectoryServices.Protocols. It
    does not use the ActiveDirectory PowerShell module and does not require Active
    Directory Web Services (ADWS). Updates use bounded parallel LDAP workers.

    Edit the $DefaultSettings section before running the script. The script does
    not prompt for configuration values. The UsersOU, UsernamePrefix, and
    PhotoSizeKB settings can also be overridden for a single run using optional
    command-line parameters; the hard-coded defaults are not changed.

.NOTES
    Script Name : Invoke-SetUserPhoto.ps1
    Version     : v1.4.5
    PowerShell  : Windows PowerShell 5.1
    Platform    : Windows Server 2019 or later
    Requirement : LDAP/Protocols; no ADWS or ActiveDirectory PowerShell module required

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

    The name-attribute filter may match more than sAMAccountName. Review the result
    count and use a distinctive UsernamePrefix. Per-user processing details are displayed as
    worker results complete; -Verbose is not required. The default worker count is
    four and can be changed with -MaxParallelism.

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
    Optional command-line override for the UsernamePrefix default setting. Include
    LDAP wildcard characters explicitly, such as '*' or 'Good*'.

.PARAMETER PhotoSizeKB
    Optional command-line override for the PhotoSizeKB default setting.

.PARAMETER MaxParallelism
    Maximum number of concurrent LDAP worker connections. The default is 4.

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
    .\Invoke-SetUserPhoto.ps1 -UsersOU 'OU=TEST,DC=adfr,DC=lab' -UsernamePrefix 'good*' -PhotoSizeKB 64

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

    Invoke-SetUserPhoto.ps1 v1.4.5 completed.
    Target OU       : OU=TEST,DC=adfr,DC=lab
    Username filter : good*
    Photo size      : 64 KB
    Users found     : 2
    Users processed : 2
    Users changed   : 0
    Users skipped   : 0
    Errors          : 0

.EXAMPLE
    .\Invoke-SetUserPhoto.ps1 -UsersOU 'OU=TEST,DC=adfr,DC=lab' -UsernamePrefix 'GdAct0r-00000*' -PhotoSizeKB 100

    Selects the top-level OU "TEST".
    Uses the user prefix 'GdAct0r-00000*' for search filtering.
    Sets the synthetic thumbnailPhoto to 100 KB, the maximum size.
    Add -ForceUpdate if these users already have a value set for thumbnailPhoto.
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
    [ValidateRange(1, 32)]
    [int]$MaxParallelism = 4,

    [Parameter(Mandatory = $false)]
    [switch]$Help
)

# ============================================================================
# Default settings - edit these values before running the script.
# ============================================================================
$DefaultSettings = [ordered]@{
    UsersOU        = 'REPLACE_WITH_OU_DN_FOR_USERS'
    # Include LDAP wildcard characters explicitly, such as '*' or 'Good*'.
    UsernamePrefix  = 'REPLACE_WITH_USERNAME_PREFIX_TO_SEARCH'
    PhotoSizeKB    = 64
}

$ScriptName     = 'Invoke-SetUserPhoto.ps1'
$ScriptVersion  = 'v1.4.5'
$PhotoSizeBytes = $null

try {
    Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
}
catch {
    Write-Error "Unable to load System.DirectoryServices.Protocols. $($_.Exception.Message)"
    exit 1
}


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

function New-LdapConnection {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server
    )

    $identifier = New-Object -TypeName System.DirectoryServices.Protocols.LdapDirectoryIdentifier -ArgumentList @(
        $Server,
        389,
        $false,
        $false
    )
    $connection = New-Object -TypeName System.DirectoryServices.Protocols.LdapConnection -ArgumentList $identifier
    $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
    $connection.SessionOptions.ProtocolVersion = 3
    $connection.Bind()

    return $connection
}

function Get-LdapRootDseValues {
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.Protocols.LdapConnection]$Connection
    )

    $request = [System.DirectoryServices.Protocols.SearchRequest]::new(
        '',
        '(objectClass=*)',
        [System.DirectoryServices.Protocols.SearchScope]::Base,
        [string[]]@('defaultNamingContext', 'schemaNamingContext')
    )
    $response = $Connection.SendRequest($request)

    if ($response.Entries.Count -eq 0) {
        throw 'LDAP RootDSE did not return an entry.'
    }

    $entry = $response.Entries[0]
    return [pscustomobject]@{
        DefaultNamingContext = [string]$entry.Attributes['defaultNamingContext'][0]
        SchemaNamingContext  = [string]$entry.Attributes['schemaNamingContext'][0]
    }
}

function Get-ThumbnailPhotoSchemaLimitBytes {
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.Protocols.LdapConnection]$Connection,

        [Parameter(Mandatory = $true)]
        [string]$SchemaNamingContext
    )

    $request = [System.DirectoryServices.Protocols.SearchRequest]::new(
        $SchemaNamingContext,
        '(&(objectClass=attributeSchema)(lDAPDisplayName=thumbnailPhoto))',
        [System.DirectoryServices.Protocols.SearchScope]::Subtree,
        [string[]]@('rangeUpper')
    )
    $response = $Connection.SendRequest($request)

    if ($response.Entries.Count -eq 0) {
        return 0
    }

    $rangeUpper = $response.Entries[0].Attributes['rangeUpper']
    if ($null -eq $rangeUpper -or $rangeUpper.Count -eq 0) {
        return 0
    }

    return [int64]$rangeUpper[0]
}

function Find-LdapUserEntries {
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.Protocols.LdapConnection]$Connection,

        [Parameter(Mandatory = $true)]
        [string]$SearchBase,

        [Parameter(Mandatory = $true)]
        [string]$Filter
    )

    $cookie = [byte[]]@()

    do {
        $request = [System.DirectoryServices.Protocols.SearchRequest]::new(
            $SearchBase,
            $Filter,
            [System.DirectoryServices.Protocols.SearchScope]::Subtree,
            [string[]]@('distinguishedName', 'sAMAccountName')
        )
        $pageControl = [System.DirectoryServices.Protocols.PageResultRequestControl]::new(1000)

        if ($cookie.Length -gt 0) {
            $pageControl.Cookie = $cookie
        }

        $null = $request.Controls.Add($pageControl)
        $response = $Connection.SendRequest($request)

        foreach ($entry in $response.Entries) {
            Write-Output -NoEnumerate -InputObject $entry
        }

        $pageResponse = @(
            $response.Controls |
                Where-Object { $_ -is [System.DirectoryServices.Protocols.PageResultResponseControl] }
        ) | Select-Object -First 1

        if ($null -eq $pageResponse) {
            $cookie = [byte[]]@()
        }
        else {
            $cookie = $pageResponse.Cookie
        }
    }
    while ($cookie.Length -gt 0)
}

function Invoke-LdapModifyPool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LdapServer,

        [Parameter(Mandatory = $true)]
        [object[]]$WorkItems,

        [Parameter(Mandatory = $true)]
        [int]$MaxWorkers,

        [Parameter(Mandatory = $false)]
        [switch]$ClearMode,

        [Parameter(Mandatory = $false)]
        [byte[]]$PhotoBytes
    )

    # Each runspace owns one LDAP connection and processes a chunk of users.
    # This bounds concurrency while avoiding a new bind for every user.
    $workerScript = {
        param(
            [string]$Server,
            [object[]]$Items,
            [bool]$Clear,
            [byte[]]$Bytes
        )

        $connection = $null
        $action = if ($Clear) { 'clear' } else { 'update' }

        try {
            $identifier = New-Object -TypeName System.DirectoryServices.Protocols.LdapDirectoryIdentifier -ArgumentList @(
                $Server,
                389,
                $false,
                $false
            )
            $connection = New-Object -TypeName System.DirectoryServices.Protocols.LdapConnection -ArgumentList $identifier
            $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
            $connection.SessionOptions.ProtocolVersion = 3
            $connection.Bind()
        }
        catch {
            foreach ($item in $Items) {
                [pscustomobject]@{
                    Success          = $false
                    DistinguishedName = $item.DistinguishedName
                    SamAccountName   = $item.SamAccountName
                    Action           = $action
                    Error            = "Unable to bind LDAP worker: $($_.Exception.Message)"
                }
            }
            return
        }

        try {
            foreach ($item in $Items) {
                try {
                    $modification = New-Object -TypeName System.DirectoryServices.Protocols.DirectoryAttributeModification
                    $modification.Name = 'thumbnailPhoto'

                    if ($Clear) {
                        $modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete
                    }
                    else {
                        $modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                        # Force the Add(object) overload so PowerShell does not try to
                        # convert the byte array into a single byte value.
                        $null = $modification.Add([object]([byte[]]$Bytes))
                    }

                    # Populate the request's modification collection directly. This
                    # avoids PowerShell overload conversion of the byte array into a
                    # DirectoryAttributeModification object.
                    $modifyRequest = [System.DirectoryServices.Protocols.ModifyRequest]::new()
                    $modifyRequest.DistinguishedName = $item.DistinguishedName
                    $null = $modifyRequest.Modifications.Add($modification)
                    $response = $connection.SendRequest($modifyRequest)
                    $noSuchAttributeIsAcceptable = $Clear -and
                        ($response.ResultCode -eq [System.DirectoryServices.Protocols.ResultCode]::NoSuchAttribute)
                    $success = ($response.ResultCode -eq [System.DirectoryServices.Protocols.ResultCode]::Success) -or
                        $noSuchAttributeIsAcceptable

                    if (-not $success) {
                        throw "LDAP $($response.ResultCode): $($response.ErrorMessage)"
                    }

                    [pscustomobject]@{
                        Success          = $true
                        DistinguishedName = $item.DistinguishedName
                        SamAccountName   = $item.SamAccountName
                        Action           = $action
                        Error            = $null
                    }
                }
                catch {
                    [pscustomobject]@{
                        Success          = $false
                        DistinguishedName = $item.DistinguishedName
                        SamAccountName   = $item.SamAccountName
                        Action           = $action
                        Error            = $_.Exception.Message
                    }
                }
            }
        }
        finally {
            if ($connection) {
                $connection.Dispose()
            }
        }
    }

    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxWorkers)
    $runspacePool.Open()
    $usersPerWorkerBatch = 50
    $nextIndex = 0

    try {
        # Submit at most MaxWorkers runspaces at a time. Each worker keeps one
        # LDAP connection open while it processes its bounded chunk of users.
        while ($nextIndex -lt $WorkItems.Count) {
            $pending = @()

            for ($workerIndex = 0;
                 $workerIndex -lt $MaxWorkers -and $nextIndex -lt $WorkItems.Count;
                 $workerIndex++) {
                $endIndex = [math]::Min(
                    $nextIndex + $usersPerWorkerBatch - 1,
                    $WorkItems.Count - 1
                )
                $chunk = @($WorkItems[$nextIndex..$endIndex])
                $nextIndex = $endIndex + 1

                $powershell = [powershell]::Create()
                $powershell.RunspacePool = $runspacePool
                $null = $powershell.AddScript($workerScript.ToString())
                $null = $powershell.AddArgument($LdapServer)
                $null = $powershell.AddArgument($chunk)
                $null = $powershell.AddArgument([bool]$ClearMode)
                $null = $powershell.AddArgument($PhotoBytes)

                $asyncResult = $powershell.BeginInvoke()
                $pending += [pscustomobject]@{
                    PowerShell  = $powershell
                    AsyncResult = $asyncResult
                    Items       = $chunk
                }
            }

            foreach ($pendingItem in $pending) {
                try {
                    $workerResults = $pendingItem.PowerShell.EndInvoke($pendingItem.AsyncResult)
                    foreach ($workerResult in $workerResults) {
                        Write-Output -NoEnumerate -InputObject $workerResult
                    }
                }
                catch {
                    foreach ($item in $pendingItem.Items) {
                        [pscustomobject]@{
                            Success          = $false
                            DistinguishedName = $item.DistinguishedName
                            SamAccountName   = $item.SamAccountName
                            Action            = if ($ClearMode) { 'clear' } else { 'update' }
                            Error             = $_.Exception.Message
                        }
                    }
                }
                finally {
                    $pendingItem.PowerShell.Dispose()
                }
            }
        }
    }
    finally {
        $runspacePool.Close()
        $runspacePool.Dispose()
    }
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
  UsernamePrefix = the name filter to search for
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
  UsernamePrefix = the name filter to search for
  PhotoSizeKB    = the synthetic payload size in KB
The script does not prompt for these values.
"@
    exit 2
}

if ($ClearThumbnailPhoto) {
    Write-Host 'Operation mode                 : ClearThumbnailPhoto' -ForegroundColor Cyan
    Write-Host 'PhotoSizeKB/schema validation  : skipped because no photo value will be written' -ForegroundColor Cyan
}

$ldapConnection = $null
$searchEntries = $null
$ldapServer = $env:LOGONSERVER -replace '^\\\\', ''

if ([string]::IsNullOrWhiteSpace($ldapServer)) {
    $ldapServer = $env:USERDNSDOMAIN
}

if ([string]::IsNullOrWhiteSpace($ldapServer)) {
    Write-Error 'Unable to determine a domain controller. Set LOGONSERVER or USERDNSDOMAIN and run the script again.'
    exit 1
}

try {
    $ldapConnection = New-LdapConnection -Server $ldapServer
    $rootDseValues = Get-LdapRootDseValues -Connection $ldapConnection

    if (-not $ClearThumbnailPhoto) {
        $thumbnailPhotoSchemaMaxBytes = Get-ThumbnailPhotoSchemaLimitBytes `
            -Connection $ldapConnection `
            -SchemaNamingContext $rootDseValues.SchemaNamingContext

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

    $escapedPrefix = Escape-LdapFilterValue -Value $DefaultSettings.UsernamePrefix
    $nameAttributeFilter = "(|(displayName=$escapedPrefix)(sAMAccountName=$escapedPrefix)(name=$escapedPrefix)(userPrincipalName=$escapedPrefix)(cn=$escapedPrefix)(givenName=$escapedPrefix)(sn=$escapedPrefix))"
    $baseLdapFilter = "(&(objectCategory=person)(objectClass=user)$nameAttributeFilter)"
    $presenceClause = if ($ClearThumbnailPhoto) {
        '(thumbnailPhoto=*)'
    }
    elseif (-not $ForceUpdate) {
        '(!(thumbnailPhoto=*))'
    }
    else {
        ''
    }

    $ldapFilter = "(&(objectCategory=person)(objectClass=user)$nameAttributeFilter$presenceClause)"
    $searchEntries = @(Find-LdapUserEntries `
        -Connection $ldapConnection `
        -SearchBase $DefaultSettings.UsersOU `
        -Filter $ldapFilter)

    # If the optimized filter returns no actionable users, run the base
    # name-attribute query once more so the operator can distinguish no matches from users
    # excluded because thumbnailPhoto already exists or is absent.
    $baseSearchMatchCount = $null
    if ($searchEntries.Count -eq 0) {
        $baseSearchEntries = @(Find-LdapUserEntries `
            -Connection $ldapConnection `
            -SearchBase $DefaultSettings.UsersOU `
            -Filter $baseLdapFilter)
        $baseSearchMatchCount = $baseSearchEntries.Count
    }
}
catch {
    Write-Error "Unable to query Active Directory through LDAP. $($_.Exception.Message)"
    if ($ldapConnection) {
        $ldapConnection.Dispose()
    }
    exit 1
}
finally {
    if ($ldapConnection) {
        $ldapConnection.Dispose()
    }
}

$processedCount = $searchEntries.Count
$changedCount = 0
$skippedCount = 0
$errorCount = 0
$workItems = @()

if ($processedCount -eq 0) {
    Write-Warning "No actionable matching users found beneath '$($DefaultSettings.UsersOU)' using UsernamePrefix '$($DefaultSettings.UsernamePrefix)'."
    Write-Host ''
    Write-Host 'LDAP query details:' -ForegroundColor Yellow
    Write-Host "  LDAP server : $ldapServer"
    Write-Host "  Search base : $($DefaultSettings.UsersOU)"
    Write-Host "  Query used  : $ldapFilter"
    Write-Host ''
    Write-Host "  Base name query: $baseLdapFilter"
    Write-Host "  Base matches  : $baseSearchMatchCount"

    if (-not $ForceUpdate -and -not $ClearThumbnailPhoto -and $baseSearchMatchCount -gt 0) {
        Write-Host ''
        Write-Host 'Matching users were found, but they were excluded because thumbnailPhoto already has a value.' -ForegroundColor Yellow
        Write-Host ''
        Write-Host 'Use -ForceUpdate to replace the existing thumbnailPhoto values.' -ForegroundColor Yellow
    }
    elseif ($ClearThumbnailPhoto -and $baseSearchMatchCount -gt 0) {
        Write-Host ''
        Write-Host 'Matching users were found, but none currently have a thumbnailPhoto value to clear.' -ForegroundColor Yellow
    }
    elseif ($baseSearchMatchCount -eq 0) {
        Write-Host ''
        Write-Host 'The base name-attribute query also found no users. Verify the UsersOU and UsernamePrefix values.' -ForegroundColor Yellow
    }

    Write-Host ''
    exit 0
}

$operationDescription = if ($ClearThumbnailPhoto) {
    'clear the thumbnailPhoto value'
}
else {
    'write the synthetic thumbnailPhoto value'
}

foreach ($entry in $searchEntries) {
    $distinguishedName = [string]$entry.Attributes['distinguishedName'][0]
    $samAccountName = [string]$entry.Attributes['sAMAccountName'][0]

    if ($PSCmdlet.ShouldProcess($distinguishedName, $operationDescription)) {
        $workItems += [pscustomobject]@{
            DistinguishedName = $distinguishedName
            SamAccountName   = $samAccountName
        }
    }
}

$syntheticPhoto = $null
if (-not $ClearThumbnailPhoto -and $workItems.Count -gt 0) {
    [byte[]]$syntheticPhoto = New-SyntheticPhotoBytes -SizeBytes $PhotoSizeBytes
}

if ($workItems.Count -gt 0) {
    Write-Host "LDAP server     : $ldapServer" -ForegroundColor Cyan
    Write-Host "Parallel workers: $MaxParallelism" -ForegroundColor Cyan

    $modifyResults = @(Invoke-LdapModifyPool `
        -LdapServer $ldapServer `
        -WorkItems $workItems `
        -MaxWorkers $MaxParallelism `
        -ClearMode:$ClearThumbnailPhoto `
        -PhotoBytes $syntheticPhoto)

    foreach ($modifyResult in $modifyResults) {
        if ($modifyResult.Success) {
            $changedCount++
            if ($ClearThumbnailPhoto) {
                Write-Host "Cleared thumbnailPhoto for $($modifyResult.SamAccountName)." -ForegroundColor Green
            }
            else {
                Write-Host "Updated $($modifyResult.SamAccountName)." -ForegroundColor Green
            }
        }
        else {
            $errorCount++
            $failedVerb = if ($ClearThumbnailPhoto) { 'clear' } else { 'update' }
            Write-Warning "Failed to $failedVerb $($modifyResult.SamAccountName): $($modifyResult.Error)"
        }
    }
}

Write-Host ''
Write-Host "$ScriptName $ScriptVersion completed." -ForegroundColor Green
Write-Host "Target OU       : $($DefaultSettings.UsersOU)"
Write-Host "Username filter : $($DefaultSettings.UsernamePrefix)"
if ($ClearThumbnailPhoto) {
    Write-Host 'Operation       : Clear thumbnailPhoto'
}
else {
    Write-Host "Photo size      : $photoSizeKB KB"
}
Write-Host "LDAP workers    : $MaxParallelism"
Write-Host "Users found     : $processedCount"
Write-Host "Users queued    : $($workItems.Count)"
Write-Host "Users processed : $processedCount"
Write-Host "Users changed   : $changedCount"
Write-Host "Users skipped   : $skippedCount"
Write-Host "Errors          : $errorCount"
Write-Host 'Search filters exclude users that already satisfy the requested mode.'
