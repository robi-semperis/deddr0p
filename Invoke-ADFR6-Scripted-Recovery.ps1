#requires -Version 5.0
<#
.SYNOPSIS
    Invoke-ADFR6-Scripted-Recovery.ps1

    ADFR 6.0 scripted forest recovery with CSV-driven lab configuration,
    switchable targets, and backup-set scoping.

    To display the complete help from PowerShell, use:
      Get-Help .\Invoke-ADFR6-Scripted-Recovery.ps1 -Full
    The script switch -Help displays the same full help and then exits.

.DESCRIPTION
    Lab-specific forest, domain, recovery-plan, and DC mapping values are loaded
    from a comma-delimited CSV file with a header row. This avoids editing the
    PowerShell script when moving the recovery workflow to a new lab environment.

    By default, the script loads Invoke-ADFR6-Scripted-Recovery.csv from the same
    directory as this script. Use -DcMappingsCsv to select another CSV file.
    Every data row must contain these columns, in this logical schema:

      AdfrServer, ForestName, RootDomain, RecoveryPlan, Domain, SourceDcName,
      SourceDcFqdn, Include, RestoreOperation, Staged, ExistingTargetVm,
      ExistingTargetIp, BlankTargetVm, BlankTargetIp

    The first four values are environment-level settings and must be repeated
    consistently on every data row. Include and Staged accept true/false, 1/0,
    yes/no, or on/off. RestoreOperation must be RestoreFromBackup, Delete, or
    Repromote. The remaining mapping fields are retained as strings and are used
    by the selected TargetMode. The CSV must contain at least one data row.

    RestoreOperation controls the action assigned to each included DC:
      RestoreFromBackup - recover the DC from the selected backup.
      Delete            - omit the DC from the initial ADFR recovery plan so
                          ADFR can apply its delete-by-omission behavior. Delete
                          is never passed to an ADFR recovery-plan entry.
      Repromote         - include a repromote action after backup-restored DCs
                          are recovered.

    Include=true, Staged=false rows are eligible for the initial recovery plan.
    Include=true, Staged=true rows are held as Continue Staged Recovery candidates.
    Include=false rows are ignored. Only RestoreFromBackup and Repromote are sent
    to ADFR. Delete rows are reported as prune-by-omission candidates; to recover
    one later through staged recovery, change its CSV operation to a valid ADFR
    operation and set Staged=true before running the staged-recovery workflow.

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
    only the mapped DCs found in that selected backup set are placed in the recovery
    plan. Mappings not present in that backup set are omitted and reported as
    ignored, allowing ADFR to prune omitted DCs from the recovered topology.

    The script previews the plan unless -StartRecovery is specified. It writes a
    JSON scope report and a CSV DC report; the report is updated with the recovery
    ID after Start-ADFRForestRecovery returns. Each run also writes a transcript
    log in the current directory named <script>-<yyyyMMdd_HHmmss>.log. Transcript
    logs matching that name are retained for 60 days by default.

    Run from an elevated Windows PowerShell 5.x session with the matching ADFR
    6.0 PowerShell module installed. Do not use PowerShell ISE.

.NOTES
    Script          : Invoke-ADFR6-Scripted-Recovery.ps1
    Version         : v2.3.4
    Date            : 2026-09-10
    Original Author : Rob Ingenthron, Semperis (2026)

.CHANGE_HISTORY
 =================================================================================================
.VERSION HISTORY
 Date        Version     Author                        Description
 ----------  ----------  --------------------------    ---------------------------------------------------------------
 2026-09-10  v2.3.4      Rob Ingenthron, Semperis       Adds full-process transcript logging, 60-day log retention cleanup, and an explicit script completion timestamp.
 2026-09-10  v2.3.3      Rob Ingenthron, Semperis       Restores direct ADFR status polling for immediate step output and suppresses further status queries during stale-final-step grace handling.
 2026-09-10  v2.3.2      Rob Ingenthron, Semperis       Bounds ADFR status queries, prevents stale-step completion from waiting on another query, and displays ADFR UTC timestamps alongside local time.
 2026-09-10  v2.3.1      Rob Ingenthron, Semperis       Adds timestamped operational logging, progress heartbeats, and stale final-step completion handling.
 2026-09-08  v2.3.0      Rob Ingenthron, Semperis       Makes -Help print the complete in-script documentation block directly instead of relying on Get-Help rendering.
 2026-09-08  v2.2.9      Rob Ingenthron, Semperis       Places .SYNOPSIS first so the -Help switch resolves the full comment-based help.
 2026-09-08  v2.2.8      Rob Ingenthron, Semperis       Makes the comment-based help discoverable by Get-Help and documents full-help usage.
 2026-09-08  v2.2.7      Rob Ingenthron, Semperis       Refreshes the ADFR connection every 15 minutes and retries broker-status queries after connection failures.
 2026-09-04  v2.2.6      Rob Ingenthron, Semperis       Prints the initial nested step snapshot and tolerates status responses without an exact RecoveryId match.
 2026-09-04  v2.2.5      Rob Ingenthron, Semperis       Added optional -ShowProgress polling with per-step status-change output and machine-readable completion status.
 2026-09-04  v2.2.4      Rob Ingenthron, Semperis       Treats CSV Delete as plan omission/prune-by-omission; only valid ADFR operations reach the recovery plan.
 2026-09-04  v2.2.3      Rob Ingenthron, Semperis       Added PowerShell 5.x-safe CSV loading and relative/absolute path resolution.
 2026-09-04  v2.2.2      Rob Ingenthron, Semperis       Removed duplicate RestoreOperation keys that caused PowerShell parser errors.
 2026-09-04  v2.2.1      Rob Ingenthron, Semperis       Standardized and enforced the required CSV header order.
 2026-09-04  v2.2.0      Rob Ingenthron, Semperis       Added named RestoreOperation values for restore, delete,
                                                       and repromote recovery-plan actions.
 2026-09-04  v2.1.0      Rob Ingenthron, Semperis       Added the Staged CSV flag; initial recovery excludes staged
                                                       rows and reports them for Continue Staged Recovery.
 2026-09-04  v2.0.0      Rob Ingenthron, Semperis       Replaced embedded environment defaults and DcMappings with
                                                       comma-delimited CSV input; added CSV schema validation,
                                                       type conversion, and -DcMappingsCsv.
 2026-09-03  v1.1.0      Rob Ingenthron, Semperis       Initial coding with Glean.

.PARAMETERS
    Command-line parameters and options:
      -AdfrServer <string>
      -DcMappingsCsv <string>
      -TargetMode <Existing|Blank>
      -ScopeMode <AllMapped|BackupSetIntersection>
      -UseBackupSetScope
      -RuleSessionTag <guid>
      -ReportPath <string>
      -StartRecovery
      -ShowProgress
      -Help

.PARAMETER AdfrServer
    Optional command-line override for the AdfrServer value loaded from the CSV.
    If omitted, the CSV value is used.

.PARAMETER DcMappingsCsv
    Path to the comma-delimited CSV containing the four environment fields and
    the ten DC mapping fields. The required CSV header order is:
    Domain, SourceDcName, SourceDcFqdn, Include, RestoreOperation, Staged,
    ExistingTargetVm, ExistingTargetIp, BlankTargetVm, BlankTargetIp.
    RestoreOperation accepts RestoreFromBackup, Delete, or Repromote.
    Relative paths are resolved from the current PowerShell directory; absolute
    paths are used as provided. If omitted, the script loads
    Invoke-ADFR6-Scripted-Recovery.csv from the script directory. Include=true/
    Staged=false rows are sent in the initial
    recovery plan. Include=true/Staged=true rows are reported for the
    post-recovery Continue Staged Recovery operation.

.PARAMETER TargetMode
    Selects the target fields loaded from the CSV. Existing uses
    ExistingTargetVm/ExistingTargetIp. Blank uses BlankTargetVm/BlankTargetIp.
    Valid options are Existing and Blank. If omitted, the script default is Blank.

.PARAMETER ScopeMode
    Selects which enabled initial-recovery DC mappings are included. AllMapped
    includes every enabled CSV mapping where Staged=false. BackupSetIntersection
    reads the selected backup-set inventory and includes only those initial rows
    present in that backup set; missing initial mappings are ignored and appear in
    the reports. Include=true/Staged=true rows remain staged-recovery candidates.

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

.PARAMETER ShowProgress
    Requires -StartRecovery. After starting the recovery, polls
    Get-ADFRRecoveryJobStatus every 30 seconds. It prints a step when its Status
    changes and exits after the final "Repromotion of Domain Controllers" step
    has an Ended value or a terminal status. During monitoring, the ADFR server
    connection is refreshed every 15 minutes and refreshed immediately after a
    broker-status query failure. Operational messages include local timestamps,
    and a five-minute heartbeat is printed while status remains unchanged. ADFR
    step timestamps are displayed as local time with the raw ADFR value alongside
    them. If all preceding steps are terminal but ADFR leaves the final step
    InProgress, the script waits 10 minutes and completes without issuing another
    status query during that grace period, with a stale-final-step warning. The
    final progress object is also emitted to the PowerShell success output stream
    for use by another script.

.PARAMETER Help
    Displays this comment-based help, including the script name, description,
    parameters, and examples, then exits without connecting to ADFR. This is
    equivalent to: Get-Help .\Invoke-ADFR6-Scripted-Recovery.ps1 -Full

    Common PowerShell parameters such as -WhatIf, -Confirm, -Verbose, and
    -ErrorAction are also available because the script uses CmdletBinding.

.EXAMPLE
    .\Invoke-ADFR6-Scripted-Recovery.ps1

    Loads Invoke-ADFR6-Scripted-Recovery.csv from the script directory and
    previews the recovery plan using the CSV and other default values.

.EXAMPLE
    .\Invoke-ADFR6-Scripted-Recovery.ps1 -StartRecovery

    Uses only -StartRecovery in addition to the default CSV path, previews the
    plan, and then starts the recovery.

.EXAMPLE
    .\Invoke-ADFR6-Scripted-Recovery.ps1 -DcMappingsCsv C:\ADFR\Labs\lab02.csv

    Loads a different lab environment from the specified comma-delimited CSV and
    previews the recovery plan.

.EXAMPLE
    .\Invoke-ADFR6-Scripted-Recovery.ps1 -DcMappingsCsv C:\ADFR\Labs\lab02.csv -TargetMode Blank -ScopeMode BackupSetIntersection -StartRecovery

    Loads the lab configuration from lab02.csv, targets the configured blank VMs,
    recovers only enabled mappings found in the selected backup set, and starts
    recovery.

.EXAMPLE
    .\Invoke-ADFR6-Scripted-Recovery.ps1 -AdfrServer adfr-mgmt.d01.lab -DcMappingsCsv C:\ADFR\Labs\lab02.csv -RuleSessionTag 332c8ba2-b18a-491d-9c73-3e08b7f8c571 -ReportPath C:\ADFR\Reports\mvc.json -WhatIf

    Overrides only the CSV ADFR server value, selects a specific backup session,
    writes reports to the specified path, and previews without starting recovery.

.EXAMPLE
    .\Invoke-ADFR6-Scripted-Recovery.ps1 -UseBackupSetScope -TargetMode Blank -StartRecovery -ShowProgress

    Typical MVC/partial-backup command line. It uses the default CSV beside the
    script, targets blank VMs, selects the backup-set intersection, starts
    recovery, and polls ADFR for step status changes every 30 seconds.

.EXAMPLE
    .\Invoke-ADFR6-Scripted-Recovery.ps1 -UseBackupSetScope -TargetMode Blank -DcMappingsCsv .\Invoke-ADFR6-Scripted-Recovery.csv -StartRecovery -ShowProgress

    Commandline for Semperis Skillable ransomware recovery lab. MVC/partial-backup command line. 
    It uses the included sample CSV preconfigured for the Semperis Skillable ransomware lab.
    Targets blank VMs, selecting the backup-set intersection based on the selected backup set (for an an MVC recovery).
    Starts recovery and polls ADFR for step status changes every 30 seconds. 
    Also refreshes the ADFR connection every 15 minutes to prevent a timeout.

.EXAMPLE
    .\Invoke-ADFR6-Scripted-Recovery.ps1 -Help

    Displays the script help and exits without connecting to ADFR.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$AdfrServer,
    [string]$DcMappingsCsv,
    [ValidateSet('Existing', 'Blank')]
    [string]$TargetMode,
    [ValidateSet('AllMapped', 'BackupSetIntersection')]
    [string]$ScopeMode,
    [switch]$UseBackupSetScope,
    [Guid]$RuleSessionTag = [Guid]::Empty,
    [string]$ReportPath,
    [switch]$StartRecovery,
    [switch]$ShowProgress,
    [switch]$Help
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# -Help exits before loading the CSV, importing the ADFR module, or prompting
# for credentials. It prints the complete documentation block directly so the
# result is not reduced to PowerShell's syntax-only view for this script.
if ($Help) {
    $scriptText = Get-Content -LiteralPath $MyInvocation.MyCommand.Path -Raw
    $helpStart = $scriptText.IndexOf('<#')
    $helpEnd = $scriptText.IndexOf('#>', $helpStart + 2)

    if ($helpStart -lt 0 -or $helpEnd -lt 0) {
        throw 'The script documentation block could not be found.'
    }

    $helpText = $scriptText.Substring($helpStart + 2, $helpEnd - $helpStart - 2).Trim()
    $helpText = $helpText -replace '(?m)^\.(SYNOPSIS|DESCRIPTION|NOTES|CHANGE_HISTORY|PARAMETERS|PARAMETER|EXAMPLE)\s*$', "`r`n`$1`r`n"
    Write-Output $helpText.Trim()
    return
}

# Transcript configuration. The log is created in the directory from which the
# script is run, not beside the script or beside the CSV configuration.
$LogRetentionDays = 60
$scriptBaseName = [IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$transcriptFileName = '{0}-{1}.log' -f $scriptBaseName, (Get-Date -Format 'yyyyMMdd_HHmmss')
$transcriptPath = Join-Path -Path (Get-Location).Path -ChildPath $transcriptFileName
$transcriptStarted = $false

try {
    Start-Transcript -Path $transcriptPath -Force | Out-Null
    $transcriptStarted = $true
    Write-Host ('Transcript log: {0}' -f $transcriptPath)

if ($ShowProgress -and -not $StartRecovery) {
    throw '-ShowProgress requires -StartRecovery because there is no recovery job to monitor during preview-only execution.'
}

# =============================================================================
# CSV CONFIGURATION - the environment and DC mappings are external input.
# =============================================================================
$RequiredCsvColumns = @(
    'AdfrServer',
    'ForestName',
    'RootDomain',
    'RecoveryPlan',
    'Domain',
    'SourceDcName',
    'SourceDcFqdn',
    'Include',
    'RestoreOperation',
    'Staged',
    'ExistingTargetVm',
    'ExistingTargetIp',
    'BlankTargetVm',
    'BlankTargetIp'
)

$AllowedRestoreOperations = @('RestoreFromBackup', 'Delete', 'Repromote')

function ConvertTo-CsvBoolean {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$FieldName
    )

    switch ($Value.Trim().ToLowerInvariant()) {
        'true'  { return $true }
        '1'     { return $true }
        'yes'   { return $true }
        'y'     { return $true }
        'on'    { return $true }
        'false' { return $false }
        '0'     { return $false }
        'no'    { return $false }
        'n'     { return $false }
        'off'   { return $false }
        default {
            throw ("CSV field '{0}' must be true/false, 1/0, yes/no, or on/off. Value '{1}' is invalid." -f $FieldName, $Value)
        }
    }
}

function Resolve-DcMappingsCsvPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    if ([IO.Path]::IsPathRooted($Path)) {
        $candidatePath = $Path
    }
    else {
        $candidatePath = Join-Path -Path (Get-Location).Path -ChildPath $Path
    }

    if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
        throw ("The DC mappings CSV was not found: {0}" -f $candidatePath)
    }

    return (Get-Item -LiteralPath $candidatePath -ErrorAction Stop).FullName
}

function Import-DcMappingsConfiguration {
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw ("The DC mappings CSV was not found: {0}" -f $Path)
    }

    try {
        $rows = @(Import-Csv -LiteralPath $Path -Delimiter ',' -ErrorAction Stop)
    }
    catch {
        throw ("Unable to read the comma-delimited DC mappings CSV '{0}': {1}" -f $Path, $_.Exception.Message)
    }

    if ($rows.Count -eq 0) {
        throw ("The DC mappings CSV '{0}' contains no data rows. It must include a header row and at least one mapping row." -f $Path)
    }

    $actualColumns = @($rows[0].PSObject.Properties.Name)
    $missingColumns = @($RequiredCsvColumns | Where-Object { $_ -notin $actualColumns })
    $unexpectedColumns = @($actualColumns | Where-Object { $_ -notin $RequiredCsvColumns })
    $actualHeader = [string]::Join(',', [string[]]$actualColumns)
    $expectedHeader = [string]::Join(',', [string[]]$RequiredCsvColumns)
    $incorrectColumnOrder = $actualHeader -cne $expectedHeader

    if ($missingColumns.Count -gt 0 -or $unexpectedColumns.Count -gt 0 -or $incorrectColumnOrder) {
        $missingText = if ($missingColumns.Count -gt 0) { $missingColumns -join ', ' } else { '(none)' }
        $unexpectedText = if ($unexpectedColumns.Count -gt 0) { $unexpectedColumns -join ', ' } else { '(none)' }
        throw ("The DC mappings CSV header is invalid. Missing columns: {0}. Unexpected columns: {1}. Expected order: {2}" -f $missingText, $unexpectedText, ($RequiredCsvColumns -join ', '))
    }

    $environmentFields = @('AdfrServer', 'ForestName', 'RootDomain', 'RecoveryPlan')
    $environmentValues = [ordered]@{}
    $firstRow = $rows[0]

    foreach ($field in $environmentFields) {
        $value = ([string]$firstRow.$field).Trim()
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw ("CSV field '{0}' is blank on data row 2." -f $field)
        }

        $rowNumber = 2
        foreach ($row in $rows) {
            $rowValue = ([string]$row.$field).Trim()
            if ([string]::IsNullOrWhiteSpace($rowValue)) {
                throw ("CSV field '{0}' is blank on data row {1}." -f $field, $rowNumber)
            }
            if ($rowValue -ine $value) {
                throw ("CSV field '{0}' must be the same on every row. Row 2 has '{1}', but row {2} has '{3}'." -f $field, $value, $rowNumber, $rowValue)
            }
            $rowNumber++
        }

        $environmentValues[$field] = $value
    }

    $mappings = @()
    $rowNumber = 2
    foreach ($row in $rows) {
        $include = ConvertTo-CsvBoolean -Value ([string]$row.Include) -FieldName ("Include on row {0}" -f $rowNumber)
        $stagedRecovery = ConvertTo-CsvBoolean -Value ([string]$row.Staged) -FieldName ("Staged on row {0}" -f $rowNumber)

        $restoreOperationText = ([string]$row.RestoreOperation).Trim()
        $restoreOperationMatches = @($AllowedRestoreOperations | Where-Object { $_ -ieq $restoreOperationText })
        if ($restoreOperationMatches.Count -ne 1) {
            throw ("CSV field 'RestoreOperation' on data row {0} must be one of: {1}. Value '{2}' is invalid." -f $rowNumber, ($AllowedRestoreOperations -join ', '), $restoreOperationText)
        }
        $restoreOperation = [string]$restoreOperationMatches[0]

        $domain = ([string]$row.Domain).Trim()
        $sourceDcName = ([string]$row.SourceDcName).Trim()
        $sourceDcFqdn = ([string]$row.SourceDcFqdn).Trim()
        if ([string]::IsNullOrWhiteSpace($domain) -or
            [string]::IsNullOrWhiteSpace($sourceDcName) -or
            [string]::IsNullOrWhiteSpace($sourceDcFqdn)) {
            throw ("CSV row {0} must provide Domain, SourceDcName, and SourceDcFqdn." -f $rowNumber)
        }

        $mappings += [pscustomobject]@{
            Include          = $include
            RestoreOperation = $restoreOperation
            Staged           = $stagedRecovery
            Domain           = $domain
            SourceDcName     = $sourceDcName
            SourceDcFqdn     = $sourceDcFqdn
            ExistingTargetVm = ([string]$row.ExistingTargetVm).Trim()
            ExistingTargetIp = ([string]$row.ExistingTargetIp).Trim()
            BlankTargetVm    = ([string]$row.BlankTargetVm).Trim()
            BlankTargetIp    = ([string]$row.BlankTargetIp).Trim()
        }

        $rowNumber++
    }

    return [pscustomobject]@{
        AdfrServer   = $environmentValues.AdfrServer
        ForestName   = $environmentValues.ForestName
        RootDomain   = $environmentValues.RootDomain
        RecoveryPlan = $environmentValues.RecoveryPlan
        DcMappings   = @($mappings)
        SourcePath   = $Path
    }
}

if ([string]::IsNullOrWhiteSpace($DcMappingsCsv)) {
    $DcMappingsCsv = Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-ADFR6-Scripted-Recovery.csv'
}

$DcMappingsCsv = Resolve-DcMappingsCsvPath -Path $DcMappingsCsv
$csvConfiguration = Import-DcMappingsConfiguration -Path $DcMappingsCsv

# DEFAULTS retains the internal object shape used by the recovery workflow, but
# all environment and DC mapping values now come from the external CSV.
$Defaults = [ordered]@{
    AdfrServer   = $csvConfiguration.AdfrServer
    ForestName   = $csvConfiguration.ForestName
    RootDomain   = $csvConfiguration.RootDomain
    RecoveryPlan = $csvConfiguration.RecoveryPlan
    TargetMode   = 'Blank'
    ScopeMode    = 'AllMapped'
    DcMappings   = $csvConfiguration.DcMappings
}

# Command-line values override CSV/default values.
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

$includedMappings = @($Defaults.DcMappings | Where-Object { $_.Include })
$initialCandidateMappings = @($includedMappings | Where-Object { -not $_.Staged })
$stagedMappings = @($includedMappings | Where-Object { $_.Staged })

if ($initialCandidateMappings.Count -eq 0) {
    throw ("No initial-recovery DC mappings with Include=true and Staged=false were found in the CSV: {0}" -f $DcMappingsCsv)
}

# Only Include=true/Staged=false rows are eligible for the initial backup restore.
# Include=true/Staged=true rows are retained for the later staged-recovery handoff.
$selectedMappings = @($initialCandidateMappings)

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

function Get-RecoveryStepPropertyValue {
    param(
        [Parameter(Mandatory = $true)][object]$Step,
        [Parameter(Mandatory = $true)][string]$PropertyName
    )

    $property = $Step.PSObject.Properties[$PropertyName]
    if ($null -eq $property -or $null -eq $property.Value) {
        return ''
    }

    return [string]$property.Value
}

function Write-AdfrTimestampedHost {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][System.ConsoleColor]$ForegroundColor = [System.ConsoleColor]::Gray
    )

    $cleanMessage = $Message.TrimEnd([char[]]@('.', ' '))
    Write-Host ('{0} : {1}' -f $cleanMessage, (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')) -ForegroundColor $ForegroundColor
}

function Write-AdfrTimestampedWarning {
    param(
        [Parameter(Mandatory = $true)][string]$Message
    )

    $cleanMessage = $Message.TrimEnd([char[]]@('.', ' '))
    Write-Warning ('{0} : {1}' -f $cleanMessage, (Get-Date).ToString('MM/dd/yyyy HH:mm:ss'))
}

function Format-AdfrTimestampForDisplay {
    param(
        [Parameter(Mandatory = $false)][AllowEmptyString()][string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Value
    }

    $parsed = [DateTimeOffset]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    if ([DateTimeOffset]::TryParse($Value, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed.ToLocalTime().ToString('MM/dd/yyyy HH:mm:ss')
    }

    return $Value
}

function Refresh-ADFRRecoveryConnection {
    param(
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $true)][PSCredential]$Credential,
        [Parameter(Mandatory = $true)][string]$ForestName,
        [Parameter(Mandatory = $true)][ref]$Connection
    )

    # Reuse the same server and credential inputs as the initial connection.
    # Re-select the forest because a reconnect may reset the selected context.
    $Connection.Value = Connect-ADFRServer `
        -Server $Server `
        -Credential $Credential `
        -ErrorAction Stop

    Select-ADFRForest -Name $ForestName -ErrorAction Stop | Out-Null
}

function Watch-ADFRRecoveryProgress {
    param(
        [Parameter(Mandatory = $true)][string]$RecoveryId,
        [Parameter(Mandatory = $true)][string]$AdfrServer,
        [Parameter(Mandatory = $true)][string]$ForestName,
        [Parameter(Mandatory = $true)][PSCredential]$Credential,
        [Parameter(Mandatory = $true)][ref]$Connection,
        [Parameter(Mandatory = $false)][int]$PollSeconds = 30,
        [Parameter(Mandatory = $false)][int]$ReconnectMinutes = 15,
        [Parameter(Mandatory = $false)][int]$FinalStepGraceMinutes = 10
    )

    $finalStepName = 'Repromotion of Domain Controllers'
    $lastStatusByStep = @{}
    $warnedNoStatusRows = $false
    $nextConnectionRefreshUtc = [DateTime]::UtcNow.AddMinutes($ReconnectMinutes)
    $nextProgressHeartbeatUtc = [DateTime]::UtcNow.AddMinutes(5)
    $finalStepInProgressSinceUtc = $null
    $lastFinalStepSnapshot = $null
    $statusQueryNumber = 0

    Write-AdfrTimestampedHost -Message ('Monitoring ADFR recovery progress every {0} seconds...' -f $PollSeconds) -ForegroundColor Cyan

    while ($true) {
        # Once all preceding steps are terminal and the final step is stale, do
        # not issue another ADFR status query. This preserves the initial/direct
        # cmdlet output path and prevents the post-warning query from blocking.
        if ($null -ne $finalStepInProgressSinceUtc -and
            $null -ne $lastFinalStepSnapshot) {
            $staleDeadlineUtc = $finalStepInProgressSinceUtc.AddMinutes($FinalStepGraceMinutes)
            if ([DateTime]::UtcNow -ge $staleDeadlineUtc) {
                Write-AdfrTimestampedWarning -Message ('ADFR still reports the final step as InProgress after {0} minutes, while all preceding steps are terminal. Treating the recovery as complete; verify the ADFR console.' -f $FinalStepGraceMinutes)
                $scriptEndedAt = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')
                $lastFinalStepSnapshot.Ended = $scriptEndedAt
                $lastFinalStepSnapshot.ScriptEnded = $scriptEndedAt
                Write-Host ('Ended: {0}' -f $scriptEndedAt)
                Write-AdfrTimestampedHost -Message 'Restore process complete (final ADFR step status remained stale)' -ForegroundColor Green
                Write-Host ''
                return $lastFinalStepSnapshot
            }

            $remainingSeconds = [int][Math]::Ceiling(($staleDeadlineUtc - [DateTime]::UtcNow).TotalSeconds)
            Start-Sleep -Seconds ([Math]::Max(1, [Math]::Min($PollSeconds, $remainingSeconds)))
            continue
        }

        if ([DateTime]::UtcNow -ge $nextConnectionRefreshUtc) {
            Write-AdfrTimestampedHost -Message 'Refreshing the ADFR server connection before the next status query' -ForegroundColor Cyan
            try {
                Refresh-ADFRRecoveryConnection `
                    -Server $AdfrServer `
                    -Credential $Credential `
                    -ForestName $ForestName `
                    -Connection $Connection
                $nextConnectionRefreshUtc = [DateTime]::UtcNow.AddMinutes($ReconnectMinutes)
                Write-AdfrTimestampedHost -Message 'ADFR server connection refreshed' -ForegroundColor Green
            }
            catch {
                Write-AdfrTimestampedWarning -Message ('Scheduled ADFR connection refresh failed: {0}. A retry will be attempted in 60 seconds.' -f $_.Exception.Message)
                $nextConnectionRefreshUtc = [DateTime]::UtcNow.AddSeconds(60)
            }
        }

        try {
            Write-AdfrTimestampedHost -Message 'Querying ADFR recovery status via Get-ADFRRecoveryJobStatus' -ForegroundColor DarkGray
            $allJobRows = @(Get-ADFRRecoveryJobStatus -ErrorAction Stop)
        }
        catch {
            $statusError = $_.Exception.Message
            Write-AdfrTimestampedWarning -Message ('Get-ADFRRecoveryJobStatus failed: {0}. Refreshing the ADFR connection and retrying once.' -f $statusError)
            try {
                Refresh-ADFRRecoveryConnection `
                    -Server $AdfrServer `
                    -Credential $Credential `
                    -ForestName $ForestName `
                    -Connection $Connection
                $nextConnectionRefreshUtc = [DateTime]::UtcNow.AddMinutes($ReconnectMinutes)
                $allJobRows = @(Get-ADFRRecoveryJobStatus -ErrorAction Stop)
                Write-AdfrTimestampedHost -Message 'ADFR status query succeeded after connection refresh' -ForegroundColor Green
            }
            catch {
                Write-AdfrTimestampedWarning -Message ('ADFR status query still failed after connection refresh: {0}. The monitor will retry in {1} seconds.' -f $_.Exception.Message, $PollSeconds)
                Start-Sleep -Seconds $PollSeconds
                continue
            }
        }
        $jobRows = @(
            $allJobRows |
                Where-Object { ([string]$_.RecoveryId).Trim() -eq ([string]$RecoveryId).Trim() }
        )

        # Some ADFR module builds return the current recovery status without
        # preserving the exact RecoveryId string returned by the start cmdlet.
        # If only one status object is returned, it is unambiguous and usable.
        if ($jobRows.Count -eq 0 -and $allJobRows.Count -eq 1) {
            $jobRows = @($allJobRows)
        }
        elseif ($jobRows.Count -eq 0 -and -not $warnedNoStatusRows) {
            Write-AdfrTimestampedWarning -Message ('Get-ADFRRecoveryJobStatus returned no status object matching RecoveryId {0}.' -f $RecoveryId)
            $warnedNoStatusRows = $true
        }
        elseif ($jobRows.Count -gt 0) {
            $warnedNoStatusRows = $false
        }

        # Get-ADFRRecoveryJobStatus returns one recovery object whose Steps
        # property contains the per-step status objects shown by the ADFR CLI.
        # Fall back to a top-level StepName for module versions that emit rows
        # directly.
        $statusQueryNumber++
        $statusRows = @(
            foreach ($job in $jobRows) {
                $stepsProperty = $job.PSObject.Properties['Steps']
                if ($null -ne $stepsProperty -and $null -ne $stepsProperty.Value) {
                    @($stepsProperty.Value)
                }
                elseif ($null -ne $job.PSObject.Properties['StepName']) {
                    $job
                }
            }
        )

        if ($statusQueryNumber -eq 1 -or [DateTime]::UtcNow -ge $nextProgressHeartbeatUtc) {
            Write-AdfrTimestampedHost -Message ('ADFR status query succeeded; progress monitor is still running. Status rows: {0}' -f $statusRows.Count) -ForegroundColor DarkGray
            $nextProgressHeartbeatUtc = [DateTime]::UtcNow.AddMinutes(5)
        }

        foreach ($step in $statusRows) {
            $stepName = Get-RecoveryStepPropertyValue -Step $step -PropertyName 'StepName'
            if ([string]::IsNullOrWhiteSpace($stepName)) {
                continue
            }

            $status = Get-RecoveryStepPropertyValue -Step $step -PropertyName 'Status'
            if (-not $lastStatusByStep.ContainsKey($stepName) -or $lastStatusByStep[$stepName] -ine $status) {
                # The first observation is printed so the operator can see the
                # current position immediately. Later observations print only
                # when the step's Status changes.
                $stepStartedRaw = Get-RecoveryStepPropertyValue -Step $step -PropertyName 'Started'
                $stepStartedLocal = Format-AdfrTimestampForDisplay -Value $stepStartedRaw
                Write-Host ('StepName: {0}' -f $stepName)
                Write-Host ('Status: {0}' -f $status)
                if ($stepStartedRaw -ne $stepStartedLocal -and -not [string]::IsNullOrWhiteSpace($stepStartedRaw)) {
                    Write-Host ('Started: {0} (ADFR raw: {1})' -f $stepStartedLocal, $stepStartedRaw)
                }
                else {
                    Write-Host ('Started: {0}' -f $stepStartedLocal)
                }
                Write-Host ''
                $lastStatusByStep[$stepName] = $status
            }
        }

        $finalStep = @(
            $statusRows |
                Where-Object {
                    (Get-RecoveryStepPropertyValue -Step $_ -PropertyName 'StepName') -ieq $finalStepName
                } |
                Select-Object -Last 1
        ) | Select-Object -First 1

        if ($null -ne $finalStep) {
            $finalStatus = Get-RecoveryStepPropertyValue -Step $finalStep -PropertyName 'Status'
            $finalStarted = Get-RecoveryStepPropertyValue -Step $finalStep -PropertyName 'Started'
            $finalEnded = Get-RecoveryStepPropertyValue -Step $finalStep -PropertyName 'Ended'
            $finalStartedLocal = Format-AdfrTimestampForDisplay -Value $finalStarted
            $finalEndedLocal = Format-AdfrTimestampForDisplay -Value $finalEnded
            $terminalStatus = $finalStatus -match '^(Completed|Complete|Succeeded|Success|Failed|Failure|Error|Canceled|Cancelled|Aborted|Skipped)$'
            $priorSteps = @($statusRows | Where-Object {
                (Get-RecoveryStepPropertyValue -Step $_ -PropertyName 'StepName') -ine $finalStepName
            })
            $priorStepsAreTerminal = ($priorSteps.Count -gt 0) -and (@($priorSteps | Where-Object {
                $priorStatus = Get-RecoveryStepPropertyValue -Step $_ -PropertyName 'Status'
                $priorStatus -notmatch '^(Completed|Complete|Succeeded|Success|Failed|Failure|Error|Canceled|Cancelled|Aborted|Skipped)$'
            }).Count -eq 0)

            if (-not [string]::IsNullOrWhiteSpace($finalEnded) -or $terminalStatus) {
                if (-not [string]::IsNullOrWhiteSpace($finalEnded)) {
                    if ($finalEnded -ne $finalEndedLocal) {
                        Write-Host ('ADFR Ended: {0} (ADFR raw: {1})' -f $finalEndedLocal, $finalEnded)
                    }
                    else {
                        Write-Host ('ADFR Ended: {0}' -f $finalEndedLocal)
                    }
                }
                $scriptEndedAt = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')
                Write-Host ('Ended: {0}' -f $scriptEndedAt)
                Write-Host ('Status: {0}' -f $finalStatus)
                Write-AdfrTimestampedHost -Message 'Restore process complete' -ForegroundColor Green
                Write-Host ''

                return [pscustomobject]@{
                    OutputType  = 'ADFR.ScriptedRecovery.ProgressStatus'
                    PSTypeName  = 'ADFR.ScriptedRecovery.ProgressStatus'
                    RecoveryId  = [string]$RecoveryId
                    StepName    = $finalStepName
                    Status      = $finalStatus
                    Started     = $finalStarted
                    Ended       = $scriptEndedAt
                    AdfrEnded   = $finalEnded
                    ScriptEnded = $scriptEndedAt
                    Complete    = $true
                }
            }

            if ($finalStatus -match '^InProgress$' -and $priorStepsAreTerminal) {
                $lastFinalStepSnapshot = [pscustomobject]@{
                    OutputType  = 'ADFR.ScriptedRecovery.ProgressStatus'
                    PSTypeName  = 'ADFR.ScriptedRecovery.ProgressStatus'
                    RecoveryId  = [string]$RecoveryId
                    StepName    = $finalStepName
                    Status      = 'CompletedWithStaleFinalStep'
                    Started     = $finalStarted
                    Ended       = $null
                    AdfrEnded   = $finalEnded
                    ScriptEnded = $null
                    Complete    = $true
                }

                if ($null -eq $finalStepInProgressSinceUtc) {
                    $finalStepInProgressSinceUtc = [DateTime]::UtcNow
                    Write-AdfrTimestampedWarning -Message ('ADFR still reports the final step as InProgress while all preceding steps are terminal. Waiting up to {0} minutes for the final status to update.' -f $FinalStepGraceMinutes)
                    Write-AdfrTimestampedHost -Message 'No further ADFR status queries will be issued during the stale-final-step grace period' -ForegroundColor DarkGray
                }
                elseif ([DateTime]::UtcNow -ge $finalStepInProgressSinceUtc.AddMinutes($FinalStepGraceMinutes)) {
                    Write-AdfrTimestampedWarning -Message ('ADFR still reports the final step as InProgress after {0} minutes, while all preceding steps are terminal. Treating the recovery as complete; verify the ADFR console.' -f $FinalStepGraceMinutes)
                    $scriptEndedAt = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')
                    $lastFinalStepSnapshot.Ended = $scriptEndedAt
                    $lastFinalStepSnapshot.ScriptEnded = $scriptEndedAt
                    Write-Host ('Ended: {0}' -f $scriptEndedAt)
                    Write-AdfrTimestampedHost -Message 'Restore process complete (final ADFR step status remained stale)' -ForegroundColor Green
                    Write-Host ''

                    return $lastFinalStepSnapshot
                }
            }
            else {
                $finalStepInProgressSinceUtc = $null
                $lastFinalStepSnapshot = $null
            }
        }

        Start-Sleep -Seconds $PollSeconds
    }
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

Write-AdfrTimestampedHost -Message ('Loaded ADFR PowerShell module: {0} ({1})' -f $loadedModule.Name, $loadedModule.Version) -ForegroundColor Cyan

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

Write-AdfrTimestampedHost -Message ('Using RuleSessionTag: {0}' -f $RuleSessionTag) -ForegroundColor Cyan

# =============================================================================
# 3. Intersect DcMappings with the selected backup-set inventory when requested.
# =============================================================================
$backupSetDcNames = @()
$ignoredMappings = @()
$pruneByOmissionMappings = @($includedMappings | Where-Object { $_.RestoreOperation -eq 'Delete' })
$backupInventoryRows = @()

if ($ScopeMode -eq 'BackupSetIntersection') {
    Write-AdfrTimestampedHost -Message 'Refreshing and reading the selected backup-set inventory' -ForegroundColor Cyan

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
    foreach ($mapping in $initialCandidateMappings) {
        # Delete is an explicit CSV omission decision, so retain it for
        # prune-by-omission reporting even when it is absent from the backup set.
        # Repromote also does not require a backup inventory row. RestoreFromBackup
        # is the only action pruned by BackupSetIntersection.
        if ($mapping.RestoreOperation -in @('Delete', 'Repromote')) {
            $mappingsInBackupSet += $mapping
        }
        elseif (Test-MappingInBackupSet -Mapping $mapping -InventoryKeySet $inventoryKeySet) {
            $mappingsInBackupSet += $mapping
        }
        else {
            $ignoredMappings += [pscustomobject]@{
                Include          = $mapping.Include
                RestoreOperation = $mapping.RestoreOperation
                Staged           = $mapping.Staged
                Domain           = $mapping.Domain
                SourceDcName     = $mapping.SourceDcName
                SourceDcFqdn     = $mapping.SourceDcFqdn
                Reason           = 'RestoreFromBackup row not present in selected backup-set inventory'
            }
        }
    }

    $selectedMappings = @($mappingsInBackupSet)
    if ($selectedMappings.Count -eq 0) {
        throw 'None of the eligible Include=true/Staged=false mappings were retained for the selected recovery plan.'
    }
}

# Delete is a CSV-only omission/prune decision. It must not become an
# ADFR recovery-plan entry, and therefore must not require a target IP.
$adfrCandidateMappings = @($selectedMappings | Where-Object { $_.RestoreOperation -ne 'Delete' })

# Resolve the active target VM/IP only after backup-set filtering. This prevents
# an omitted mapping with an intentionally blank target from stopping recovery.
$activeMappings = @(
    foreach ($mapping in $adfrCandidateMappings) {
        if ($TargetMode -eq 'Existing') {
            $targetVm = $mapping.ExistingTargetVm
            $targetIp = $mapping.ExistingTargetIp
        }
        else {
            $targetVm = $mapping.BlankTargetVm
            $targetIp = $mapping.BlankTargetIp
        }

        if ([string]::IsNullOrWhiteSpace($targetIp)) {
            throw ('No target IP is configured for {0} in TargetMode={1} and RestoreOperation={2}.' -f $mapping.SourceDcFqdn, $TargetMode, $mapping.RestoreOperation)
        }

        [pscustomobject]@{
            Include          = $mapping.Include
            RestoreOperation = $mapping.RestoreOperation
            Staged           = $mapping.Staged
            Domain           = $mapping.Domain
            SourceDcName     = $mapping.SourceDcName
            SourceDcFqdn     = $mapping.SourceDcFqdn
            TargetVm         = $targetVm
            TargetIp         = $targetIp
        }
    }
)

# Staged rows are not added to the automated forest-recovery plan. They are
# retained with their selected target values for the operator's later Continue
# Staged Recovery operation in the ADFR Recovery Portal.
$stagedRecoveryMappings = @(
    foreach ($mapping in ($stagedMappings | Where-Object { $_.RestoreOperation -ne 'Delete' })) {
        if ($TargetMode -eq 'Existing') {
            $targetVm = $mapping.ExistingTargetVm
            $targetIp = $mapping.ExistingTargetIp
        }
        else {
            $targetVm = $mapping.BlankTargetVm
            $targetIp = $mapping.BlankTargetIp
        }

        [pscustomobject]@{
            Include          = $mapping.Include
            RestoreOperation = $mapping.RestoreOperation
            Staged           = $mapping.Staged
            Domain           = $mapping.Domain
            SourceDcName     = $mapping.SourceDcName
            SourceDcFqdn     = $mapping.SourceDcFqdn
            TargetVm         = $targetVm
            TargetIp         = $targetIp
        }
    }
)

# ADFR requires an initial restored DC in the forest-root domain. A child domain
# with no matching backup entries is omitted from the initial forest-recovery plan.
$rootMappings = @($activeMappings | Where-Object { $_.Domain -ieq $Defaults.RootDomain })
if ($rootMappings.Count -eq 0) {
    throw ('No mapped DC from the forest root domain ({0}) was found in the selected initial-recovery scope.' -f $Defaults.RootDomain)
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

function ConvertTo-AdfrRestoreOperationValue {
    param(
        [Parameter(Mandatory = $true)][object]$Entry,
        [Parameter(Mandatory = $true)][ValidateSet('RestoreFromBackup', 'Repromote')][string]$Operation
    )

    $operationProperty = $Entry.GetType().GetProperty('RestoreOperation')
    if ($null -eq $operationProperty) {
        throw 'The ADFR recovery-plan entry does not expose a RestoreOperation property.'
    }

    $operationType = $operationProperty.PropertyType
    $nullableType = [Nullable]::GetUnderlyingType($operationType)
    if ($null -ne $nullableType) {
        $operationType = $nullableType
    }

    if ($operationType.IsEnum) {
        $enumNames = @([Enum]::GetNames($operationType))
        $enumMatch = @($enumNames | Where-Object { $_ -ieq $Operation })
        if ($enumMatch.Count -ne 1) {
            throw ("The ADFR RestoreOperation enum does not contain '{0}'. Available values: {1}" -f $Operation, ($enumNames -join ', '))
        }
        return [Enum]::Parse($operationType, [string]$enumMatch[0], $true)
    }

    if ($operationType -eq [string]) {
        return $Operation
    }

    # Older ADFR plan classes expose this property as an integer rather than an
    # enum. Preserve the legacy numeric values for the two valid ADFR operations.
    $legacyValues = @{
        RestoreFromBackup = 1
        Repromote         = 3
    }
    try {
        return [Convert]::ChangeType($legacyValues[$Operation], $operationType)
    }
    catch {
        throw ("The ADFR RestoreOperation property type '{0}' cannot accept named operation '{1}'." -f $operationType.FullName, $Operation)
    }
}

function New-RecoveryPlanDcEntry {
    param(
        [Parameter(Mandatory = $true)][string]$SourceDcFqdn,
        [Parameter(Mandatory = $false)][string]$TargetIp,
        [Parameter(Mandatory = $true)][ValidateSet('RestoreFromBackup', 'Repromote')][string]$RestoreOperation
    )

    $entry = New-Object -TypeName $dcEntryTypeName
    $entry.DcFqdn = $SourceDcFqdn
    $entry.RestoreOperation = ConvertTo-AdfrRestoreOperationValue -Entry $entry -Operation $RestoreOperation
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
            RuleSessionTag       = [string]$RuleSessionTag
            ScopeMode            = $ScopeMode
            TargetMode           = $TargetMode
            Include              = $mapping.Include
            RestoreOperation     = $mapping.RestoreOperation
            Staged               = $mapping.Staged
            RecoveryPhase        = 'InitialForestRecovery'
            Domain               = $mapping.Domain
            SourceDcName         = $mapping.SourceDcName
            SourceDcFqdn         = $mapping.SourceDcFqdn
            TargetVm             = $mapping.TargetVm
            TargetIp             = $mapping.TargetIp
            Selected             = $true
            StagedRecoverySelected = $false
            SelectionReason      = if ($ScopeMode -eq 'BackupSetIntersection') { 'Mapped DC present in selected backup set' } else { 'Include=true; Staged=false' }
        }
    }
    foreach ($mapping in $stagedRecoveryMappings) {
        [pscustomobject]@{
            RuleSessionTag       = [string]$RuleSessionTag
            ScopeMode            = $ScopeMode
            TargetMode           = $TargetMode
            Include              = $mapping.Include
            RestoreOperation     = $mapping.RestoreOperation
            Staged               = $mapping.Staged
            RecoveryPhase        = 'StagedRecovery'
            Domain               = $mapping.Domain
            SourceDcName         = $mapping.SourceDcName
            SourceDcFqdn         = $mapping.SourceDcFqdn
            TargetVm             = $mapping.TargetVm
            TargetIp             = $mapping.TargetIp
            Selected             = $false
            StagedRecoverySelected = $true
            SelectionReason      = 'Include=true; Staged=true; pending Continue Staged Recovery'
        }
    }
    foreach ($mapping in $pruneByOmissionMappings) {
        [pscustomobject]@{
            RuleSessionTag       = [string]$RuleSessionTag
            ScopeMode            = $ScopeMode
            TargetMode           = $TargetMode
            Include              = $mapping.Include
            RestoreOperation     = $mapping.RestoreOperation
            Staged               = $mapping.Staged
            RecoveryPhase        = 'PruneByOmission'
            Domain               = $mapping.Domain
            SourceDcName         = $mapping.SourceDcName
            SourceDcFqdn         = $mapping.SourceDcFqdn
            TargetVm             = ''
            TargetIp             = ''
            Selected             = $false
            StagedRecoverySelected = $false
            SelectionReason      = 'RestoreOperation=Delete; omitted from the ADFR recovery plan so ADFR can delete/prune the DC by omission'
        }
    }
    foreach ($mapping in $ignoredMappings) {
        [pscustomobject]@{
            RuleSessionTag       = [string]$RuleSessionTag
            ScopeMode            = $ScopeMode
            TargetMode           = $TargetMode
            Include              = $mapping.Include
            RestoreOperation     = $mapping.RestoreOperation
            Staged               = $mapping.Staged
            RecoveryPhase        = 'IgnoredFromInitialRecovery'
            Domain               = $mapping.Domain
            SourceDcName         = $mapping.SourceDcName
            SourceDcFqdn         = $mapping.SourceDcFqdn
            TargetVm             = ''
            TargetIp             = ''
            Selected             = $false
            StagedRecoverySelected = $false
            SelectionReason      = $mapping.Reason
        }
    }
)

$report = [ordered]@{
    GeneratedUtc                    = [DateTime]::UtcNow.ToString('o')
    ConfigurationCsvPath            = $DcMappingsCsv
    ForestName                      = $Defaults.ForestName
    RootDomain                      = $Defaults.RootDomain
    RuleSessionTag                  = [string]$RuleSessionTag
    BackupValidationStatus          = if ($null -ne $selectedBackup) { [string]$selectedBackup.ValidationStatus } else { 'Explicit tag not returned by Get-ADFRBackupJob' }
    ScopeMode                       = $ScopeMode
    TargetMode                      = $TargetMode
    BackupSetDcCount                = $backupSetDcNames.Count
    BackupSetDcs                    = @($backupSetDcNames)
    IncludedDcMappingsCount         = $includedMappings.Count
    InitialRecoveryCandidateCount   = $initialCandidateMappings.Count
    SelectedForRecoveryCount        = $activeMappings.Count
    SelectedForRecovery             = @($activeMappings | Select-Object Domain, SourceDcName, SourceDcFqdn, RestoreOperation, TargetVm, TargetIp)
    StagedRecoveryCandidateCount    = $stagedRecoveryMappings.Count
    StagedRecoveryCandidates         = @($stagedRecoveryMappings | Select-Object Domain, SourceDcName, SourceDcFqdn, RestoreOperation, TargetVm, TargetIp)
    PruneByOmissionCandidateCount  = $pruneByOmissionMappings.Count
    PruneByOmissionCandidates       = @($pruneByOmissionMappings | Select-Object Domain, SourceDcName, SourceDcFqdn, RestoreOperation, Staged)
    IgnoredMappingCount             = $ignoredMappings.Count
    IgnoredMappings                 = @($ignoredMappings)
    RecoveryPlanDomains              = @($activeMappings | Select-Object -ExpandProperty Domain -Unique | Sort-Object)
    RecoveryId                      = $null
    RecoveryStatus                  = if ($StartRecovery) { 'PendingStart' } else { 'PreviewOnly' }
    StagedRecoveryStatus            = if ($stagedRecoveryMappings.Count -gt 0) { 'PendingOperatorContinueStagedRecovery' } else { 'NoneConfigured' }
    JsonReportPath                  = $ReportPath
    CsvReportPath                   = $CsvReportPath
}

Write-RecoveryReports -JsonPath $ReportPath -CsvPath $CsvReportPath -Report $report -ReportRows $reportRows

Write-Host ''
Write-AdfrTimestampedHost -Message ('Recovery plan preview - TargetMode: {0}; ScopeMode: {1}' -f $TargetMode, $ScopeMode) -ForegroundColor Green
$reportRows | Format-Table Include, RestoreOperation, Staged, RecoveryPhase, Domain, SourceDcFqdn, TargetVm, TargetIp, Selected, StagedRecoverySelected, SelectionReason -AutoSize
Write-AdfrTimestampedHost -Message ('Backup-set DCs found: {0}; initial DCs selected for recovery: {1}; prune-by-omission candidates: {2}; staged-recovery candidates: {3}; mappings ignored: {4}' -f $backupSetDcNames.Count, $activeMappings.Count, $pruneByOmissionMappings.Count, $stagedRecoveryMappings.Count, $ignoredMappings.Count) -ForegroundColor Yellow
if ($pruneByOmissionMappings.Count -gt 0) {
    Write-AdfrTimestampedWarning -Message 'Rows with RestoreOperation=Delete are omitted from the ADFR recovery plan and are intended to be pruned/deleted by omission.'
}
if ($stagedRecoveryMappings.Count -gt 0) {
    Write-AdfrTimestampedWarning -Message 'Staged-recovery candidates are not part of the initial backup recovery plan.'
    Write-AdfrTimestampedHost -Message 'After the initial forest recovery completes, use Recovery Portal > Continue Staged Recovery and select these DCs:' -ForegroundColor Yellow
    $stagedRecoveryMappings | Format-Table Domain, SourceDcFqdn, RestoreOperation, TargetVm, TargetIp -AutoSize
}
Write-AdfrTimestampedHost -Message ('JSON report: {0}' -f $ReportPath) -ForegroundColor DarkGray
Write-AdfrTimestampedHost -Message ('CSV report:  {0}' -f $CsvReportPath) -ForegroundColor DarkGray
$recoveryPlan | ConvertTo-Json -Depth 10

if (-not $StartRecovery) {
    Write-AdfrTimestampedWarning -Message 'Preview only. Re-run with -StartRecovery to invoke Start-ADFRForestRecovery for the initial recovery.'
    return
}

# =============================================================================
# 6. Start recovery and update the report with the returned recovery ID.
# =============================================================================
Write-AdfrTimestampedWarning -Message ('TargetMode={0}. Confirm the target VMs are appropriate before continuing.' -f $TargetMode)

if ($PSCmdlet.ShouldProcess($Defaults.ForestName, 'Start ADFR forest recovery')) {
    $recoveryId = Start-ADFRForestRecovery `
        -RecoveryPlan $recoveryPlan `
        -RuleSessionTag $RuleSessionTag `
        -Confirm

    $report.RecoveryId = [string]$recoveryId
    $report.RecoveryStatus = if ($stagedRecoveryMappings.Count -gt 0) { 'InitialRecoveryStarted_StagedRecoveryPending' } else { 'Started' }
    $report.GeneratedUtc = [DateTime]::UtcNow.ToString('o')

    try {
        $jobStatus = @(
            Get-ADFRRecoveryJobStatus -ErrorAction Stop |
                Where-Object { ([string]$_.RecoveryId).Trim() -eq ([string]$recoveryId).Trim() }
        )
    }
    catch {
        Write-AdfrTimestampedWarning -Message ('Initial recovery status query failed: {0}. -ShowProgress will retry after refreshing the ADFR connection.' -f $_.Exception.Message)
        $jobStatus = @()
    }
    if ($jobStatus.Count -gt 0) {
        $report.RecoveryStatusDetail = @($jobStatus | Select-Object *)
    }

    Write-RecoveryReports -JsonPath $ReportPath -CsvPath $CsvReportPath -Report $report -ReportRows $reportRows

    Write-AdfrTimestampedHost -Message ('Initial forest recovery started. Recovery ID: {0}' -f $recoveryId) -ForegroundColor Green
    if ($stagedRecoveryMappings.Count -gt 0) {
        Write-AdfrTimestampedWarning -Message 'When the initial forest recovery is complete, use Recovery Portal > Continue Staged Recovery for the rows marked Staged=true in the CSV.'
    }
    Write-AdfrTimestampedHost -Message ('Updated report: {0}' -f $ReportPath) -ForegroundColor Green

    if ($ShowProgress) {
        $progressStatus = Watch-ADFRRecoveryProgress `
            -RecoveryId ([string]$recoveryId) `
            -AdfrServer $AdfrServer `
            -ForestName $Defaults.ForestName `
            -Credential $adfrCredential `
            -Connection ([ref]$conn) `
            -PollSeconds 30 `
            -ReconnectMinutes 15
        $report.RecoveryStatus = [string]$progressStatus.Status
        $report.RecoveryProgressComplete = $true
        $report.RecoveryProgressStatus = $progressStatus
        # Do not issue another synchronous ADFR status query here. The monitor
        # already completed with its final status snapshot, and a post-completion
        # broker refresh was the original source of the apparent hang.
        $report.RecoveryStatusDetail = @($progressStatus)
        $report.GeneratedUtc = [DateTime]::UtcNow.ToString('o')
        Write-RecoveryReports -JsonPath $ReportPath -CsvPath $CsvReportPath -Report $report -ReportRows $reportRows
        Write-AdfrTimestampedHost -Message ('Updated report: {0}' -f $ReportPath) -ForegroundColor Green
        Write-Output $progressStatus
        return
    }

    $jobStatus
}
}
finally {
    if ($transcriptStarted) {
        try {
            $logCutoff = (Get-Date).AddDays(-$LogRetentionDays)
            $logFileRegex = '^' + [regex]::Escape($scriptBaseName) + '-\d{8}_\d{6}\.log$'
            $oldTranscriptLogs = @(
                Get-ChildItem -LiteralPath (Get-Location).Path -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match $logFileRegex -and $_.LastWriteTime -lt $logCutoff }
            )
            foreach ($oldTranscriptLog in $oldTranscriptLogs) {
                Remove-Item -LiteralPath $oldTranscriptLog.FullName -Force -ErrorAction SilentlyContinue
                Write-Host ('Removed transcript log older than {0} days: {1}' -f $LogRetentionDays, $oldTranscriptLog.FullName)
            }
        }
        catch {
            Write-Warning ('Transcript log maintenance failed: {0}' -f $_.Exception.Message)
        }

        try {
            Stop-Transcript | Out-Null
        }
        catch {
            # The transcript may already have been stopped by the host.
        }
    }
}
