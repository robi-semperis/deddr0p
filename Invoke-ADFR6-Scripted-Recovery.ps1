#requires -Version 5.0
<#
 =================================================================================================
 Script          : Invoke-ADFR6-Scripted-Recovery.ps1
 Version         : v1.1.0
 Date            : 2026-09-03
 Original Author : Rob Ingenthron, Semperis  (2026)
 -------------------------------------------------------------------------------------------------
#>
<#
.SYNOPSIS
    Invoke-ADFR6-Scripted-Recovery.ps1

    ADFR 6.0 scripted forest recovery with switchable targets and backup-set scoping.

.DESCRIPTION
    The DEFAULTS section is the main place to adapt this script for another lab.
    Edit the forest, domains, DC mappings, existing target IPs, and blank-target
    IPs there. Command-line values override the applicable DEFAULTS values.

    TargetMode:
      Existing - use the ExistingTargetVm/ExistingTargetIp values.
      Blank    - use the BlankTargetVm/BlankTargetIp values.

    Important: Start-ADFRForestRecovery is the automated forest-recovery/
    restore-anywhere workflow. ADFR normally requires compatible, clean,
    non-domain-controller target machines for that workflow. TargetMode=Existing
    therefore only works when the existing target machines satisfy ADFR's target
    validation; a running domain controller may be rejected by ADFR.

    Backup-set scope:
      AllMapped                 - place every enabled mapping in the recovery plan.
      BackupSetIntersection     - place only enabled mappings found in the selected
                                  backup-set inventory in the recovery plan.
      -UseBackupSetScope         - convenience switch equivalent to
                                  -ScopeMode BackupSetIntersection; it overrides the
                                  DEFAULTS ScopeMode value.

    BackupSetIntersection supports an MVC/partial backup such as one DC per domain:
    only the mapped DCs found in the selected backup set are placed in the recovery
    plan. Mappings not present in that backup set are omitted and reported as
    ignored, allowing ADFR to prune omitted DCs from the recovered topology.

    The script previews the plan unless -StartRecovery is specified. It writes a
    JSON scope report and a CSV DC report; the report is updated with the recovery
    ID after Start-ADFRForestRecovery returns.

    Run from an elevated Windows PowerShell 5.x session with the matching ADFR
    6.0 PowerShell module installed. Do not use PowerShell ISE.

.CHANGE_HISTORY


.PARAMETERS
    Command-line parameters and options:
      -AdfrServer <string>
      -TargetMode <Existing|Blank>
      -ScopeMode <AllMapped|BackupSetIntersection>
      -UseBackupSetScope
      -RuleSessionTag <guid>
      -ReportPath <string>
      -StartRecovery
      -Help

.PARAMETER AdfrServer
    ADFR Management Server to connect to. If omitted, the DEFAULTS value is used
    (default: localhost).

.PARAMETER TargetMode
    Selects the target fields in DEFAULTS.DcMappings. Existing uses
    ExistingTargetVm/ExistingTargetIp. Blank uses BlankTargetVm/BlankTargetIp.
    Valid options are Existing and Blank. If omitted, DEFAULTS.TargetMode is used.

.PARAMETER ScopeMode
    Selects which enabled DC mappings are included. AllMapped includes every
    enabled DcMappings row. BackupSetIntersection reads the selected backup-set
    inventory and includes only enabled mappings present in that backup set;
    missing mappings are ignored and appear in the reports.

.PARAMETER UseBackupSetScope
    Convenience switch equivalent to -ScopeMode BackupSetIntersection. If both
    switches are supplied, -UseBackupSetScope takes precedence.

.PARAMETER RuleSessionTag
    Selects a specific ADFR backup session by GUID. If omitted, the newest valid
    backup returned by Get-ADFRBackupJob is selected.

.PARAMETER ReportPath
    Path for the JSON operator report. A CSV report with the same base name is
    also written. If omitted, timestamped reports are written to the current
    directory.

.PARAMETER StartRecovery
    Starts Start-ADFRForestRecovery after displaying the plan. Without this
    switch, the script only previews the plan and writes reports.

.PARAMETER Help
    Displays this comment-based help, including the script name, description,
    parameters, and examples, then exits without connecting to ADFR.

    Common PowerShell parameters such as -WhatIf, -Confirm, -Verbose, and
    -ErrorAction are also available because the script uses CmdletBinding.

.EXAMPLE
    .\adfr6-scripted-recovery.ps1

    Previews the recovery plan using all DEFAULTS values. No recovery is started.

.EXAMPLE
    .\adfr6-scripted-recovery.ps1 -StartRecovery

    Uses only the DEFAULTS values and -StartRecovery. It previews the plan and
    then starts the recovery.

.EXAMPLE
    .\adfr6-scripted-recovery.ps1 -TargetMode Blank -ScopeMode BackupSetIntersection -StartRecovery

    Targets the configured blank VMs and recovers only the enabled DC mappings
    found in the selected backup set. This is the typical MVC/partial-backup
    command-line form.

.EXAMPLE
    .\adfr6-scripted-recovery.ps1 -UseBackupSetScope

    Previews the plan with BackupSetIntersection. This is equivalent to
    -ScopeMode BackupSetIntersection and does not start recovery.

.EXAMPLE
    .\adfr6-scripted-recovery.ps1 -ScopeMode AllMapped -TargetMode Blank

    Previews a plan containing every enabled DcMappings row, regardless of
    whether each DC is present in the selected backup-set inventory. AllMapped
    is the original behavior and can fail if the selected backup does not include
    every mapped DC.

.EXAMPLE
    .\adfr6-scripted-recovery.ps1 -AdfrServer adfr-mgmt.d01.lab -TargetMode Blank -ScopeMode BackupSetIntersection -RuleSessionTag 332c8ba2-b18a-491d-9c73-3e08b7f8c571 -ReportPath C:\ADFR\Reports\mvc.json -StartRecovery

    Connects to the specified ADFR server, selects a specific backup session,
    targets blank VMs, uses MVC/partial-backup scoping, writes the reports to the
    specified path, and starts recovery.

.EXAMPLE
     .\adfr6-scripted-recovery.ps1 -UseBackupSetScope -TargetMode Blank -StartRecovery

    Typical commandline for demo in ransomeware lab in Skillable.
    Use the MVC backup with just two DCs and recover those 2 DCs only out of the six existing.
    Target new blank VMs.

.EXAMPLE
    .\adfr6-scripted-recovery.ps1 -Help

    Displays the script help and exits without connecting to ADFR.
#>

<#
 =================================================================================================
.VERSION HISTORY 
 Date        Version     Author                        Description
 ----------  ----------  --------------------------    ---------------------------------------------------------------
 2026-09-03   v1.1.0    Rob Ingenthron, Semperis       Initial coding with Glean.

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$AdfrServer,
    [ValidateSet('Existing', 'Blank')]
    [string]$TargetMode,
    [ValidateSet('AllMapped', 'BackupSetIntersection')]
    [string]$ScopeMode,
    [switch]$UseBackupSetScope,
    [Guid]$RuleSessionTag = [Guid]::Empty,
    [string]$ReportPath,
    [switch]$StartRecovery,
    [switch]$Help
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# -Help follows the standard PowerShell comment-based-help pattern. It exits
# before importing the ADFR module, prompting for credentials, or making changes.
if ($Help) {
    Get-Help -Name $MyInvocation.MyCommand.Path -Full
    return
}

# =============================================================================
# DEFAULTS - edit this section when adapting the script to another lab.
# =============================================================================
$Defaults = [ordered]@{
    AdfrServer = 'localhost'
    ForestName = 'adfr.lab'
    RootDomain = 'adfr.lab'
    RecoveryPlan = 'adfr-lab-MVC-Forest-Recovery'

    # Existing is retained for this lab. For clean recovery targets, use Blank.
    TargetMode = 'Existing'

    # AllMapped preserves the original behavior. Use -UseBackupSetScope, or
    # change this value to BackupSetIntersection, for MVC/partial backup sets.
    ScopeMode = 'AllMapped'

    # Every enabled source DC is a candidate. Backup-set scoping can remove
    # candidates that are not present in the selected backup set.
    DcMappings = @(
        [pscustomobject]@{
            Include          = $true
            Domain           = 'adfr.lab'
            SourceDcName     = 'ADFR-DC1'
            SourceDcFqdn     = 'ADFR-DC1.adfr.lab'
            ExistingTargetVm = ''
            ExistingTargetIp = ''
            BlankTargetVm    = 'blank-vm1'
            BlankTargetIp    = '10.160.10.1'
            RestoreOperation = 1
        }
        [pscustomobject]@{
            Include          = $true
            Domain           = 'adfr.lab'
            SourceDcName     = 'ADFR-DC2'
            SourceDcFqdn     = 'ADFR-DC2.adfr.lab'
            ExistingTargetVm = ''
            ExistingTargetIp = ''
            BlankTargetVm    = 'blank-vm3'
            BlankTargetIp    = '10.160.10.2'
            RestoreOperation = 1
        }
        [pscustomobject]@{
            Include          = $true
            Domain           = 'child.adfr.lab'
            SourceDcName     = 'ADFR-CHILD-DC1'
            SourceDcFqdn     = 'ADFR-CHILD-DC1.child.adfr.lab'
            ExistingTargetVm = ''
            ExistingTargetIp = ''
            BlankTargetVm    = 'blank-vm2'
            BlankTargetIp    = '10.160.20.1'
            RestoreOperation = 1
        }
        [pscustomobject]@{
            Include          = $true
            Domain           = 'child.adfr.lab'
            SourceDcName     = 'ADFR-CHILD-DC2'
            SourceDcFqdn     = 'ADFR-CHILD-DC2.child.adfr.lab'
            ExistingTargetVm = ''
            ExistingTargetIp = ''
            BlankTargetVm    = 'blank-vm4'
            BlankTargetIp    = '10.160.20.2'
            RestoreOperation = 1
        }
    )
}

# Command-line values override DEFAULTS values.
if ([string]::IsNullOrWhiteSpace($AdfrServer)) {
    $AdfrServer = $Defaults.AdfrServer
}
if ([string]::IsNullOrWhiteSpace($TargetMode)) {
    $TargetMode = $Defaults.TargetMode
}
if ([string]::IsNullOrWhiteSpace($ScopeMode)) {
    $ScopeMode = $Defaults.ScopeMode
}
if ($UseBackupSetScope) {
    $ScopeMode = 'BackupSetIntersection'
}

$selectedMappings = @($Defaults.DcMappings | Where-Object { $_.Include })
if ($selectedMappings.Count -eq 0) {
    throw 'No DC mappings are enabled in the DEFAULTS section.'
}

# =============================================================================
# Utility functions used for backup-set matching and reporting.
# =============================================================================
function Get-NormalizedDcKeys {
    param(
        [Parameter(Mandatory = $false)][string]$SourceDcName,
        [Parameter(Mandatory = $false)][string]$SourceDcFqdn
    )

    $keys = New-Object System.Collections.Generic.List[string]
    foreach ($value in @($SourceDcName, $SourceDcFqdn)) {
        if ([string]::IsNullOrWhiteSpace($value)) {
            continue
        }

        $normalized = $value.Trim().TrimEnd('.').ToLowerInvariant()
        if (-not $keys.Contains($normalized)) {
            [void]$keys.Add($normalized)
        }

        if ($normalized.Contains('.')) {
            $shortName = $normalized.Split('.')[0]
            if (-not $keys.Contains($shortName)) {
                [void]$keys.Add($shortName)
            }
        }
    }

    return @($keys)
}

function Get-InventoryDcNames {
    param(
        [Parameter(Mandatory = $true)][object[]]$InventoryRows
    )

    $names = New-Object System.Collections.Generic.List[string]
    $propertyNames = @('DCName', 'DcFqdn', 'DnsHostName', 'HostName')

    foreach ($row in $InventoryRows) {
        # DCName is the inventory identity used by ADFR. Prefer it so a row
        # exposing both an FQDN and a short host name is counted only once.
        $dcNameProperty = $row.PSObject.Properties['DCName']
        if ($null -ne $dcNameProperty -and -not [string]::IsNullOrWhiteSpace([string]$dcNameProperty.Value)) {
            $cleanValue = ([string]$dcNameProperty.Value).Trim().TrimEnd('.')
            if (-not $names.Contains($cleanValue)) {
                [void]$names.Add($cleanValue)
            }
            continue
        }

        foreach ($propertyName in @('DcFqdn', 'DnsHostName', 'HostName')) {
            $property = $row.PSObject.Properties[$propertyName]
            if ($null -eq $property) {
                continue
            }

            $value = [string]$property.Value
            if ([string]::IsNullOrWhiteSpace($value)) {
                continue
            }

            $cleanValue = $value.Trim().TrimEnd('.')
            if (-not $names.Contains($cleanValue)) {
                [void]$names.Add($cleanValue)
            }
            break
        }
    }

    return @($names)
}

function Test-MappingInBackupSet {
    param(
        [Parameter(Mandatory = $true)][object]$Mapping,
        [Parameter(Mandatory = $true)][hashtable]$InventoryKeySet
    )

    foreach ($key in (Get-NormalizedDcKeys -SourceDcName $Mapping.SourceDcName -SourceDcFqdn $Mapping.SourceDcFqdn)) {
        if ($InventoryKeySet.ContainsKey($key)) {
            return $true
        }
    }

    return $false
}

function Write-RecoveryReports {
    param(
        [Parameter(Mandatory = $true)][string]$JsonPath,
        [Parameter(Mandatory = $true)][string]$CsvPath,
        [Parameter(Mandatory = $true)][object]$Report,
        [Parameter(Mandatory = $true)][object[]]$ReportRows
    )

    $report | ConvertTo-Json -Depth 10 | Set-Content -Path $JsonPath -Encoding UTF8
    $ReportRows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
}

# =============================================================================
# 1. Load the ADFR module, authenticate, and select the forest.
#    The credential parameter is -Credential (singular).
# =============================================================================
Import-Module Semperis.PoSh.ADFR -MinimumVersion 6.0 -Force

$loadedModule = Get-Module Semperis.PoSh.ADFR
if ($null -eq $loadedModule -or $loadedModule.Version.Major -lt 6) {
    throw 'ADFR 6.0 PowerShell module was not loaded. Verify the module installation and version.'
}

Write-Host ('Loaded ADFR PowerShell module: {0} ({1})' -f $loadedModule.Name, $loadedModule.Version) -ForegroundColor Cyan

$adfrCredential = Get-Credential -Message 'Enter the Windows credentials for an ADFR Recovery Administrator'
$conn = Connect-ADFRServer `
    -Server $AdfrServer `
    -Credential $adfrCredential `
    -ErrorAction Stop

Select-ADFRForest -Name $Defaults.ForestName -ErrorAction Stop

# =============================================================================
# 2. Select the backup session before building the recovery plan.
# =============================================================================
$backupJobs = @(Get-ADFRBackupJob -Connection $conn)
$validBackups = @(
    $backupJobs |
        Where-Object { $_.ValidationStatus -eq 'Valid' } |
        Sort-Object EndDateTime -Descending
)

$selectedBackup = $null
if ($RuleSessionTag -ne [Guid]::Empty) {
    $selectedBackup = @(
        $backupJobs |
            Where-Object { ([string]$_.RuleSessionTag) -eq ([string]$RuleSessionTag) } |
            Select-Object -First 1
    ) | Select-Object -First 1

    if ($null -ne $selectedBackup -and $selectedBackup.ValidationStatus -ne 'Valid') {
        throw ('The supplied RuleSessionTag is not Valid. ValidationStatus={0}.' -f $selectedBackup.ValidationStatus)
    }
}
else {
    if ($validBackups.Count -eq 0) {
        throw 'No valid ADFR backup was found. Supply a valid -RuleSessionTag.'
    }

    $selectedBackup = $validBackups[0]
    $RuleSessionTag = [Guid]$selectedBackup.RuleSessionTag
}

if ($RuleSessionTag -eq [Guid]::Empty) {
    throw 'The selected backup did not provide a usable RuleSessionTag.'
}

Write-Host ('Using RuleSessionTag: {0}' -f $RuleSessionTag) -ForegroundColor Cyan

# =============================================================================
# 3. Intersect DcMappings with the selected backup-set inventory when requested.
# =============================================================================
$backupSetDcNames = @()
$ignoredMappings = @()
$backupInventoryRows = @()

if ($ScopeMode -eq 'BackupSetIntersection') {
    Write-Host 'Refreshing and reading the selected backup-set inventory...' -ForegroundColor Cyan

    Invoke-ADFRBackupInventory -Connection $conn -Wait $true | Out-Null
    $backupInventoryRows = @(
        Get-ADFRBackupInventory -Connection $conn |
            Where-Object { ([string]$_.RuleSessionTag) -eq ([string]$RuleSessionTag) }
    )

    if ($backupInventoryRows.Count -eq 0) {
        throw ('No backup inventory rows were found for RuleSessionTag {0}. Verify the selected backup and inventory availability.' -f $RuleSessionTag)
    }

    $backupSetDcNames = @(Get-InventoryDcNames -InventoryRows $backupInventoryRows | Sort-Object -Unique)
    if ($backupSetDcNames.Count -eq 0) {
        throw 'The selected backup inventory contained no recognizable DC names.'
    }

    $inventoryKeySet = @{}
    foreach ($backupDcName in $backupSetDcNames) {
        foreach ($key in (Get-NormalizedDcKeys -SourceDcName $backupDcName -SourceDcFqdn $backupDcName)) {
            $inventoryKeySet[$key] = $true
        }
    }

    $mappingsInBackupSet = @()
    foreach ($mapping in $selectedMappings) {
        if (Test-MappingInBackupSet -Mapping $mapping -InventoryKeySet $inventoryKeySet) {
            $mappingsInBackupSet += $mapping
        }
        else {
            $ignoredMappings += [pscustomobject]@{
                Domain       = $mapping.Domain
                SourceDcFqdn = $mapping.SourceDcFqdn
                Reason       = 'Not present in selected backup-set inventory'
            }
        }
    }

    $selectedMappings = @($mappingsInBackupSet)
    if ($selectedMappings.Count -eq 0) {
        throw 'None of the enabled DcMappings were found in the selected backup set.'
    }
}

# Resolve the active target VM/IP only after backup-set filtering. This prevents
# an omitted mapping with an intentionally blank target from stopping recovery.
$activeMappings = @(
    foreach ($mapping in $selectedMappings) {
        if ($TargetMode -eq 'Existing') {
            $targetVm = $mapping.ExistingTargetVm
            $targetIp = $mapping.ExistingTargetIp
        }
        else {
            $targetVm = $mapping.BlankTargetVm
            $targetIp = $mapping.BlankTargetIp
        }

        if ([string]::IsNullOrWhiteSpace($targetIp)) {
            throw ('No target IP is configured for {0} in TargetMode={1}.' -f $mapping.SourceDcFqdn, $TargetMode)
        }

        [pscustomobject]@{
            Domain           = $mapping.Domain
            SourceDcName     = $mapping.SourceDcName
            SourceDcFqdn     = $mapping.SourceDcFqdn
            TargetVm         = $targetVm
            TargetIp         = $targetIp
            RestoreOperation = [int]$mapping.RestoreOperation
        }
    }
)

# ADFR requires an initial restored DC in the forest-root domain. A child domain
# with no matching backup entries is omitted from the plan and can be pruned.
$rootMappings = @($activeMappings | Where-Object { $_.Domain -ieq $Defaults.RootDomain })
if ($rootMappings.Count -eq 0) {
    throw ('No mapped DC from the forest root domain ({0}) was found in the selected backup/scope.' -f $Defaults.RootDomain)
}

# =============================================================================
# 4. Load recovery-plan types and build the filtered recovery plan.
# =============================================================================
$dcEntryTypeName = 'Semperis.ADFR.Objects.Restore.ForestRecoveryPlan.RecoveryPlanDcEntry'
$domainEntryTypeName = 'Semperis.ADFR.Objects.Restore.ForestRecoveryPlan.RecoveryPlanDomainEntry'
$planTypeName = 'Semperis.ADFR.Objects.Restore.ForestRecoveryPlan.RecoveryPlan'

function Find-LoadedClrType {
    param([Parameter(Mandatory = $true)][string]$TypeName)

    return @(
        [AppDomain]::CurrentDomain.GetAssemblies() |
            ForEach-Object { $_.GetType($TypeName, $false) } |
            Where-Object { $null -ne $_ }
    ) | Select-Object -First 1
}

$dcEntryType = Find-LoadedClrType -TypeName $dcEntryTypeName
$domainEntryType = Find-LoadedClrType -TypeName $domainEntryTypeName
$planType = Find-LoadedClrType -TypeName $planTypeName

if ($null -eq $dcEntryType -or $null -eq $domainEntryType -or $null -eq $planType) {
    throw @"
The ADFR recovery-plan CLR types are not loaded.

Confirm all of the following:
  1. This is the ADFR Management Server or an approved host with the ADFR 6.0 module installed.
  2. The loaded module is version 6.x and matches the ADFR Management Server.
  3. Import-Module, Connect-ADFRServer, and Select-ADFRForest completed successfully.
  4. The recovery-plan classes are present in the installed ADFR 6.0 assemblies.
"@
}

function New-RecoveryPlanDcEntry {
    param(
        [Parameter(Mandatory = $true)][string]$SourceDcFqdn,
        [Parameter(Mandatory = $true)][string]$TargetIp,
        [Parameter(Mandatory = $true)][int]$RestoreOperation
    )

    $entry = New-Object -TypeName $dcEntryTypeName
    $entry.DcFqdn = $SourceDcFqdn
    $entry.RestoreOperation = $RestoreOperation
    $entry.TargetIP = $TargetIp
    return $entry
}

$planEntries = @{}
foreach ($mapping in $activeMappings) {
    $planEntries[$mapping.SourceDcFqdn] = New-RecoveryPlanDcEntry `
        -SourceDcFqdn $mapping.SourceDcFqdn `
        -TargetIp $mapping.TargetIp `
        -RestoreOperation $mapping.RestoreOperation
}

$dcListTypeName = 'System.Collections.Generic.List[{0}]' -f $dcEntryTypeName
$domainListTypeName = 'System.Collections.Generic.List[{0}]' -f $domainEntryTypeName
$domainEntries = @{}

foreach ($domainGroup in ($activeMappings | Group-Object -Property Domain)) {
    $domainEntry = New-Object -TypeName $domainEntryTypeName
    $domainEntry.DomainFqdn = $domainGroup.Name
    $domainEntry.RecoveryDcEntries = New-Object -TypeName $dcListTypeName

    foreach ($mapping in $domainGroup.Group) {
        [void]$domainEntry.RecoveryDcEntries.Add($planEntries[$mapping.SourceDcFqdn])
    }

    $domainEntries[$domainGroup.Name] = $domainEntry
}

$recoveryPlan = New-Object -TypeName $planTypeName
$recoveryPlan.Id = [Guid]::NewGuid()
$recoveryPlan.Name = $Defaults.RecoveryPlan
$recoveryPlan.Description = ('Restore {0}; scope={1}; targetMode={2}' -f $Defaults.ForestName, $ScopeMode, $TargetMode)
$recoveryPlan.ValidationStatus = 1
$recoveryPlan.LastModifiedUtc = [DateTime]::UtcNow
$recoveryPlan.RecoveryDomainEntries = New-Object -TypeName $domainListTypeName

foreach ($domain in ($domainEntries.Keys | Sort-Object)) {
    [void]$recoveryPlan.RecoveryDomainEntries.Add($domainEntries[$domain])
}

# =============================================================================
# 5. Write the operator report and preview the filtered plan.
# =============================================================================
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path (Get-Location) ('ADFR-Recovery-Scope-{0}.json' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$ReportPath = [IO.Path]::GetFullPath($ReportPath)
$CsvReportPath = [IO.Path]::ChangeExtension($ReportPath, '.csv')

$reportRows = @(
    foreach ($mapping in $activeMappings) {
        [pscustomobject]@{
            RuleSessionTag   = [string]$RuleSessionTag
            ScopeMode        = $ScopeMode
            TargetMode       = $TargetMode
            Domain           = $mapping.Domain
            SourceDcFqdn     = $mapping.SourceDcFqdn
            TargetVm         = $mapping.TargetVm
            TargetIp         = $mapping.TargetIp
            RestoreOperation = $mapping.RestoreOperation
            Selected         = $true
            SelectionReason  = if ($ScopeMode -eq 'BackupSetIntersection') { 'Mapped DC present in selected backup set' } else { 'Enabled DcMapping' }
        }
    }
    foreach ($mapping in $ignoredMappings) {
        [pscustomobject]@{
            RuleSessionTag   = [string]$RuleSessionTag
            ScopeMode        = $ScopeMode
            TargetMode       = $TargetMode
            Domain           = $mapping.Domain
            SourceDcFqdn     = $mapping.SourceDcFqdn
            TargetVm         = ''
            TargetIp         = ''
            RestoreOperation = ''
            Selected         = $false
            SelectionReason  = $mapping.Reason
        }
    }
)

$report = [ordered]@{
    GeneratedUtc                    = [DateTime]::UtcNow.ToString('o')
    ForestName                      = $Defaults.ForestName
    RootDomain                      = $Defaults.RootDomain
    RuleSessionTag                  = [string]$RuleSessionTag
    BackupValidationStatus          = if ($null -ne $selectedBackup) { [string]$selectedBackup.ValidationStatus } else { 'Explicit tag not returned by Get-ADFRBackupJob' }
    ScopeMode                       = $ScopeMode
    TargetMode                      = $TargetMode
    BackupSetDcCount                = $backupSetDcNames.Count
    BackupSetDcs                    = @($backupSetDcNames)
    EnabledDcMappingsCount          = $selectedMappings.Count + $ignoredMappings.Count
    SelectedForRecoveryCount        = $activeMappings.Count
    SelectedForRecovery             = @($activeMappings | Select-Object Domain, SourceDcFqdn, TargetVm, TargetIp, RestoreOperation)
    IgnoredMappingCount             = $ignoredMappings.Count
    IgnoredMappings                 = @($ignoredMappings)
    RecoveryPlanDomains              = @($activeMappings | Select-Object -ExpandProperty Domain -Unique | Sort-Object)
    RecoveryId                      = $null
    RecoveryStatus                  = if ($StartRecovery) { 'PendingStart' } else { 'PreviewOnly' }
    JsonReportPath                  = $ReportPath
    CsvReportPath                   = $CsvReportPath
}

Write-RecoveryReports -JsonPath $ReportPath -CsvPath $CsvReportPath -Report $report -ReportRows $reportRows

Write-Host ''
Write-Host ('Recovery plan preview - TargetMode: {0}; ScopeMode: {1}' -f $TargetMode, $ScopeMode) -ForegroundColor Green
$reportRows | Format-Table Domain, SourceDcFqdn, TargetVm, TargetIp, Selected, SelectionReason -AutoSize
Write-Host ('Backup-set DCs found: {0}; mapped DCs selected for recovery: {1}; mappings ignored: {2}' -f $backupSetDcNames.Count, $activeMappings.Count, $ignoredMappings.Count) -ForegroundColor Yellow
Write-Host ('JSON report: {0}' -f $ReportPath) -ForegroundColor DarkGray
Write-Host ('CSV report:  {0}' -f $CsvReportPath) -ForegroundColor DarkGray
$recoveryPlan | ConvertTo-Json -Depth 10

if (-not $StartRecovery) {
    Write-Warning 'Preview only. Re-run with -StartRecovery to invoke Start-ADFRForestRecovery.'
    return
}

# =============================================================================
# 6. Start recovery and update the report with the returned recovery ID.
# =============================================================================
Write-Warning ('TargetMode={0}. Confirm the target VMs are appropriate before continuing.' -f $TargetMode)

if ($PSCmdlet.ShouldProcess($Defaults.ForestName, 'Start ADFR forest recovery')) {
    $recoveryId = Start-ADFRForestRecovery `
        -RecoveryPlan $recoveryPlan `
        -RuleSessionTag $RuleSessionTag `
        -Confirm

    $report.RecoveryId = [string]$recoveryId
    $report.RecoveryStatus = 'Started'
    $report.GeneratedUtc = [DateTime]::UtcNow.ToString('o')

    $jobStatus = @(
        Get-ADFRRecoveryJobStatus |
            Where-Object { ([string]$_.RecoveryId) -eq ([string]$recoveryId) }
    )
    if ($jobStatus.Count -gt 0) {
        $report.RecoveryStatusDetail = @($jobStatus | Select-Object *)
    }

    Write-RecoveryReports -JsonPath $ReportPath -CsvPath $CsvReportPath -Report $report -ReportRows $reportRows

    Write-Host ('Recovery started. Recovery ID: {0}' -f $recoveryId) -ForegroundColor Green
    Write-Host ('Updated report: {0}' -f $ReportPath) -ForegroundColor Green
    $jobStatus
}
