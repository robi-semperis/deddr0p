<#
   Set-Semperis-AuditGPO.ps1


   Rob Ingenthron, Semperis

#>

<#
.SYNOPSIS
  Create/update a GPO named "Semperis Auditing Policy settings" for the required DSP auditing settings, 
  enforce advanced audit subcategories, configure ONLY the requested Advanced Audit Policy subcategories,
  link the GPO to the Domain Controllers OU at top precedence, mirror the Force-subcategory switch into 
  Security Options (GptTmpl.inf), and (optionally) export HTML + CSV reports.

.DESCRIPTION
  - Supports -WhatIf / -Confirm (SupportsShouldProcess=$true) and -DryRun (rich preview).
  - Enforces "Audit: Force audit policy subcategory settings (Windows Vista or later)..." by:
      * Writing SCENoApplyLegacyAuditPolicy = 1 to the GPO registry policy (authoritative).    # Maps to the policy per MS docs
      * MIRRORING the same via Security Options CSE (GptTmpl.inf line: ...SCENoApplyLegacyAuditPolicy=4,1) for visual auditing in GPMC.
  - Writes MS-GPAC-compliant audit.csv (Advanced Audit Policy subcategories; Success only).
  - Links GPO to OU=Domain Controllers,<domainDN> at Order=1; optional Enforced.
  - Report folder logic:
      * Default: <script directory>\GPOReports
      * Fallback: C:\GPOReports (if creation fails)

.PARAMETER EnforceLink
  Optional. If provided, sets the GPO link as Enforced (Yes).

.PARAMETER DCsToValidate
  Optional. List of DC hostnames for remote auditpol/registry validation (read-only).

.PARAMETER ReportFolder
  Optional. Override for report folder path. If omitted, uses smart logic above.

.PARAMETER AddTimestamp
  Optional. Appends -yyyyMMdd-HHmmss to report filenames.

.PARAMETER DryRun
  Optional. Emits exact changes without writing to SYSVOL or editing links. (Reports skipped in DryRun.)

.EXAMPLE
  .\Set-Semperis-AuditGPO.ps1 -DryRun -Verbose

.EXAMPLE
  .\Set-Semperis-AuditGPO.ps1 -EnforceLink -AddTimestamp -Confirm
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$EnforceLink,
    [string[]]$DCsToValidate,
    [string]$ReportFolder,
    [switch]$AddTimestamp,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$script:DryRun = $DryRun

# -------------------------------- Helpers ------------------------------------

function Ensure-Module([string]$Name){
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        throw "Required module '$Name' is not available. Please install RSAT/GPMC for GroupPolicy."
    }
    Import-Module $Name -ErrorAction Stop | Out-Null
}

function Get-DomainInfo {
    try {
        $root = [ADSI]"LDAP://RootDSE"
        $defaultNC = $root.defaultNamingContext
    } catch {
        throw "This machine must be joined to a domain to create/update a domain GPO."
    }
    $domainFqdn = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
    $dcOU = "OU=Domain Controllers,$defaultNC"
    @{ Fqdn=$domainFqdn; DefaultNamingContext=$defaultNC; DCOU=$dcOU }
}

function Invoke-Action {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][scriptblock]$Do,
        [scriptblock]$Preview
    )
    if ($script:DryRun) {
        Write-Host ("DRY-RUN: {0} -> {1}" -f $Action, $Target) -ForegroundColor Yellow
        if ($Preview) { & $Preview }
        return
    }
    if ($PSCmdlet.ShouldProcess($Target, $Action)) {
        & $Do
    }
}

function Set-GpoAuditSubcategoryOverride([string]$GpoName){
    # Authoritative registry-policy setting for the "Force audit policy subcategory settings..." switch. [1](https://sid-500.com/2017/08/25/configuring-group-policies-by-using-windows-powershell/)
    $act = "Set SCENoApplyLegacyAuditPolicy=1 in GPO registry (Computer)"
    $tgt = "HKLM\System\CurrentControlSet\Control\Lsa (GPO: $GpoName)"
    Invoke-Action -Action $act -Target $tgt -Do {
        Set-GPRegistryValue -Name $GpoName `
            -Key 'HKLM\System\CurrentControlSet\Control\Lsa' `
            -ValueName 'SCENoApplyLegacyAuditPolicy' -Type DWord -Value 1
    } -Preview {
        Write-Host "  Would set: [HKLM\System\CurrentControlSet\Control\Lsa] SCENoApplyLegacyAuditPolicy (DWORD) = 1"
    }
}

function Write-GptTmplInfSecurityOption([guid]$GpoGuid,[string]$DomainFqdn){
    # Mandatory UI-parity: reflect the same setting in Security Options (GptTmpl.inf)
    # Line format (4,1 => REG_DWORD 1) ensures GPMC shows policy Enabled under Security Options. [2](https://github.com/H0wl3r/Advanced-Security-Audit-Configuration)
    $seceditDir = "\\$DomainFqdn\SYSVOL\$DomainFqdn\Policies\{$GpoGuid}\Machine\Microsoft\Windows NT\SecEdit"
    $infPath    = Join-Path $seceditDir 'GptTmpl.inf'
    $act = "Write Security Options INF (GptTmpl.inf) for SCENoApplyLegacyAuditPolicy"
    $tgt = $infPath

    $doBlock = {
        if (-not (Test-Path $seceditDir)) { New-Item -ItemType Directory -Path $seceditDir -Force | Out-Null }
        $content = @()
        if (Test-Path $infPath) {
            $content = Get-Content -Path $infPath -Encoding Unicode
        } else {
            $content = @(
                '[Unicode]',
                'Unicode=yes',
                '[Version]',
                'signature="$CHICAGO$"',
                'Revision=1',
                '[Registry Values]'
            )
        }

        if (-not ($content -match '^\[Registry Values\]$')) {
            $content += '[Registry Values]'
        }

        # Remove stale entries, then add the correct one.
        $content = $content | Where-Object { $_ -notmatch '^MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\SCENoApplyLegacyAuditPolicy\s*=' }
        $content += 'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1'  # REG_DWORD 1

        <#
        What does "4,1" mean?

        More explicitly:

        4 = store this value as REG_DWORD
        1 = set the DWORD to 1 (Enabled)

        Thus the GptTmpl.inf line:
        MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1

        is fully equivalent to:
        [Registry Entry]
        Type:  REG_DWORD
        Data:  1
        #>

        $content | Set-Content -Path $infPath -Encoding Unicode
        Write-Host "Wrote $infPath (Security Options reflection)"
    }

    $previewBlock = {
        Write-Host "  Would ensure folder: $seceditDir"
        Write-Host "  Would upsert: $infPath"
        Write-Host "  Would include under [Registry Values]:"
        Write-Host "    MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1"
    }

    Invoke-Action -Action $act -Target $tgt -Do $doBlock -Preview $previewBlock
}

function Get-GpoSysvolAuditPath([guid]$GpoGuid, [string]$DomainFqdn){
    $base = "\\$DomainFqdn\SYSVOL\$DomainFqdn\Policies\{$GpoGuid}\Machine\Microsoft\Windows NT\Audit"
    if (-not $script:DryRun -and -not (Test-Path $base)) {
        New-Item -ItemType Directory -Path $base -Force | Out-Null
    }
    Join-Path $base 'audit.csv'
}

function New-AuditCsvLine {
    param(
        [Parameter(Mandatory)][string]$SubcategoryName,
        [Parameter(Mandatory)][string]$SubcategoryGuid,
        [Parameter(Mandatory)][ValidateSet('Success','Failure','Success and Failure','No Auditing')][string]$SettingText,
        [Parameter(Mandatory)][ValidateSet(0,1,2,3)][int]$SettingNumeric
    )
    ",System,$SubcategoryName,{$SubcategoryGuid},$SettingText,,$SettingNumeric"
}

function Get-PlannedAuditCsvLines {
    # MS-GPAC format; Setting Value: 1=Success, 2=Failure, 3=Success+Failure. [3](https://www.tenable.com/audits/items/MSCT_Windows_Server_20H2_DC_v1.0.0.audit:cdc7f81fb88d93de8e3f314e6776c711)
    $Success = 1
    $lines = @()
    $lines += 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
    # ACCOUNT MANAGEMENT
    $lines += New-AuditCsvLine 'Audit Application Group Management'    '0cce9239-69ae-11d9-bed3-505054503030' 'Success' $Success
    $lines += New-AuditCsvLine 'Audit Computer Account Management'     '0cce9236-69ae-11d9-bed3-505054503030' 'Success' $Success
    $lines += New-AuditCsvLine 'Audit Distribution Group Management'   '0cce9238-69ae-11d9-bed3-505054503030' 'Success' $Success
    $lines += New-AuditCsvLine 'Audit Other Account Management Events' '0cce923a-69ae-11d9-bed3-505054503030' 'Success' $Success
    $lines += New-AuditCsvLine 'Audit Security Group Management'       '0cce9237-69ae-11d9-bed3-505054503030' 'Success' $Success
    $lines += New-AuditCsvLine 'Audit User Account Management'         '0cce9235-69ae-11d9-bed3-505054503030' 'Success' $Success
    # DS ACCESS
    $lines += New-AuditCsvLine 'Audit Directory Service Changes'       '0cce923c-69ae-11d9-bed3-505054503030' 'Success' $Success
    # POLICY CHANGE
    $lines += New-AuditCsvLine 'Audit Authentication Policy Change'    '0cce9230-69ae-11d9-bed3-505054503030' 'Success' $Success
    # ACCOUNT LOGON
    $lines += New-AuditCsvLine 'Audit Credential Validation'           '0cce923f-69ae-11d9-bed3-505054503030' 'Success' $Success
    $lines += New-AuditCsvLine 'Audit Kerberos Authentication Service' '0cce9242-69ae-11d9-bed3-505054503030' 'Success' $Success
    # LOGON/LOGOFF
    $lines += New-AuditCsvLine 'Audit Logon'                           '0cce9215-69ae-11d9-bed3-505054503030' 'Success' $Success
    return ,$lines
}

function Show-AuditCsvDiff {
    param([string]$ExistingPath,[string[]]$PlannedLines)
    Write-Host "  Target file: $ExistingPath"
    if (-not (Test-Path $ExistingPath)) {
        Write-Host "  No existing audit.csv found. Entire file would be created."
        return
    }
    $existing = Get-Content -Path $ExistingPath -Encoding UTF8
    $old = if ($existing.Count -gt 0) { $existing[1..($existing.Count-1)] } else { @() }
    $new = if ($PlannedLines.Count -gt 0) { $PlannedLines[1..($PlannedLines.Count-1)] } else { @() }
    $added   = Compare-Object -ReferenceObject $old -DifferenceObject $new -PassThru | Where-Object SideIndicator -eq '=>'
    $removed = Compare-Object -ReferenceObject $old -DifferenceObject $new -PassThru | Where-Object SideIndicator -eq '<='
    Write-Host "  Diff summary:"
    Write-Host ("    +{0} lines to add" -f ($added  | Measure-Object | Select-Object -ExpandProperty Count))
    Write-Host ("    -{0} lines to remove" -f ($removed| Measure-Object | Select-Object -ExpandProperty Count))
    if ($added)   { Write-Host "  Added lines (planned):";   $added   | ForEach-Object { Write-Host "    $_" } }
    if ($removed) { Write-Host "  Removed lines (current):"; $removed | ForEach-Object { Write-Host "    $_" } }
}

function Write-AuditCsv {
    param([string]$Path,[string[]]$PlannedLines)
    $act = "Write audit.csv"
    $tgt = $Path
    Invoke-Action -Action $act -Target $tgt -Do {
        if (Test-Path $Path) { Copy-Item $Path "$Path.bak-$(Get-Date -Format 'yyyyMMdd-HHmmss')" -ErrorAction SilentlyContinue }
        $PlannedLines | Set-Content -Path $Path -Encoding UTF8
        Write-Host "Wrote $Path"
    } -Preview {
        Show-AuditCsvDiff -ExistingPath $Path -PlannedLines $PlannedLines
        Write-Host "  Would write the following content:"
        $PlannedLines | ForEach-Object { Write-Host "    $_" }
    }
}

function Link-GpoToDomainControllersTop([string]$GpoName, [string]$TargetOU, [bool]$Enforced){
    $enf = if ($Enforced) { [Microsoft.GroupPolicy.EnforceLink]::Yes } else { [Microsoft.GroupPolicy.EnforceLink]::No }
    $action = "Link GPO at top precedence (Order=1), Enforced=$($enf.ToString())"
    $target = "$TargetOU"

    $doBlock = {
        $inherit  = Get-GPInheritance -Target $TargetOU
        $existing = $inherit.GpoLinks | Where-Object { $_.DisplayName -eq $GpoName }
        if ($existing) {
            Set-GPLink -Name $GpoName -Target $TargetOU -LinkEnabled Yes -Enforced $enf -Order 1 | Out-Null
        } else {
            New-GPLink -Name $GpoName -Target $TargetOU -LinkEnabled Yes -Enforced $enf -Order 1 | Out-Null
        }
    }
    $previewBlock = {
        $inherit  = Get-GPInheritance -Target $TargetOU
        $existing = $inherit.GpoLinks | Where-Object { $_.DisplayName -eq $GpoName }
        if ($existing) {
            Write-Host "  Would Set-GPLink -Name '$GpoName' -Target '$TargetOU' -LinkEnabled Yes -Enforced $enf -Order 1"
        } else {
            Write-Host "  Would New-GPLink -Name '$GpoName' -Target '$TargetOU' -LinkEnabled Yes -Enforced $enf -Order 1"
        }
        Write-Host "  Current link order:"
        $inherit.GpoLinks | Sort-Object Order | Format-Table Order,DisplayName,Enabled,Enforced -AutoSize | Out-String | Write-Host
        Write-Host "  After change: '$GpoName' will be at Order=1 (highest precedence)."
    }

    Invoke-Action -Action $action -Target $target -Do $doBlock -Preview $previewBlock
}

function Show-LinkOrder([string]$TargetOU){
    $links = (Get-GPInheritance -Target $TargetOU).GpoLinks
    Write-Host "`nCurrent link order for $TargetOU (1 = highest precedence):"
    $links | Sort-Object Order | Format-Table Order,DisplayName,Enabled,Enforced
}

function Resolve-ReportFolder([string]$OverridePath){
    if ($OverridePath) {
        if ($script:DryRun) {
            Write-Host "[REPORTS] Dry-run: would use/ensure folder '$OverridePath'"
            return $OverridePath
        }
        try {
            if (-not (Test-Path $OverridePath)) { New-Item -ItemType Directory -Path $OverridePath -Force | Out-Null }
            return $OverridePath
        } catch {
            Write-Warning "Could not create report folder at override path '$OverridePath' : $($_.Exception.Message)"
        }
    }

    $scriptBase = $PSScriptRoot
    if (-not $scriptBase) {
        $scriptBase = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
        if (-not $scriptBase) { $scriptBase = (Get-Location).Path }
    }

    $preferred = Join-Path $scriptBase 'GPOReports'
    if ($script:DryRun) {
        Write-Host "[REPORTS] Dry-run: would create or use '$preferred'; if not permitted, would fall back to 'C:\GPOReports'."
        return $preferred
    }

    try {
        if (-not (Test-Path $preferred)) { New-Item -ItemType Directory -Path $preferred -Force | Out-Null }
        return $preferred
    } catch {
        Write-Warning "Could not create report folder at '$preferred' : $($_.Exception.Message)"
        $fallback = 'C:\GPOReports'
        try {
            if (-not (Test-Path $fallback)) { New-Item -ItemType Directory -Path $fallback -Force | Out-Null }
            Write-Host "[REPORTS] Falling back to '$fallback'"
            return $fallback
        } catch {
            throw "Failed to create report folder at both '$preferred' and 'C:\GPOReports' : $($_.Exception.Message)"
        }
    }
}

function Export-GPOReports([Microsoft.GroupPolicy.Gpo]$Gpo, [string]$ReportFolder, [switch]$Timestamp, [string]$AuditCsvPath){
    if ($script:DryRun) {
        Write-Host "`n[REPORTS] Dry-run mode: skipping HTML/CSV file creation (HTML would reflect *current* GPO, not planned changes)."
        return
    }
    $ts = $(if($Timestamp){'-' + (Get-Date -Format 'yyyyMMdd-HHmmss')}else{''})
    # HTML via Get-GPOReport (native HTML/XML only). [4](https://artifact-expressions.readthedocs.io/en/stable/artifacts/windows/windows.auditeventsubcategories.html)
    $html = Join-Path $ReportFolder ($Gpo.DisplayName.Replace(' ','_') + "$ts.html")
    Get-GPOReport -Guid $Gpo.Id.Guid -ReportType Html -Path $html | Out-Null

    # CSV from audit.csv + security option row
    $csv = Join-Path $ReportFolder ($Gpo.DisplayName.Replace(' ','_') + "$ts-ChangeRecords.csv")
    $rows = @(
        [pscustomobject]@{
            Area           = 'SecurityOption'
            Item           = 'SCENoApplyLegacyAuditPolicy'
            Guid           = ''
            SettingText    = 'Enabled'
            SettingNumeric = 1
            Source         = 'Registry (HKLM\System\CurrentControlSet\Control\Lsa)'
        }
    )
    if (Test-Path $AuditCsvPath){
        $content = Get-Content -Path $AuditCsvPath -Encoding UTF8
        for($i=1; $i -lt $content.Count; $i++){
            $parts = $content[$i].Split(',')
            if ($parts.Count -ge 7){
                $rows += [pscustomobject]@{
                    Area           = 'AdvancedAuditSubcategory'
                    Item           = $parts[2].Trim()
                    Guid           = $parts[3].Trim(' ','{','}')
                    SettingText    = $parts[4].Trim()
                    SettingNumeric = $parts[6].Trim()
                    Source         = 'audit.csv'
                }
            }
        }
    }
    $rows | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    Write-Host "`n[REPORTS]"
    Write-Host "  HTML : $html"
    Write-Host "  CSV  : $csv"
}

function Verify-GpoHasForceSwitch([Microsoft.GroupPolicy.Gpo]$Gpo, [string]$ReportFolder){
    if ($script:DryRun) { return }
    $html = Join-Path $ReportFolder ($Gpo.DisplayName.Replace(' ','_') + '-verify.html')
    Get-GPOReport -Guid $Gpo.Id.Guid -ReportType Html -Path $html | Out-Null  # [4](https://artifact-expressions.readthedocs.io/en/stable/artifacts/windows/windows.auditeventsubcategories.html)
    $txt = Get-Content -Path $html -Raw
    $ok  = $txt -match 'SCENoApplyLegacyAuditPolicy' -and $txt -match 'Control\\Lsa' -and $txt -match '>1<'
    if ($ok) {
        Write-Host "[VERIFY] GPO contains SCENoApplyLegacyAuditPolicy = 1 in its registry policy stream."
    } else {
        Write-Warning "[VERIFY] Could not confirm SCENoApplyLegacyAuditPolicy=1 in the GPO report. The registry policy entry may be missing."
    }
}

function Test-LocalEffectiveSettings {
    Write-Host "`n[LOCAL VALIDATION] To verify effective Advanced Audit Policy on this host, run:"
    Write-Host "  auditpol.exe /get /category:*"
    Write-Host "To query the override switch locally:"
    Write-Host "  reg query HKLM\System\CurrentControlSet\Control\Lsa /v SCENoApplyLegacyAuditPolicy"
    Write-Host "Expected: SCENoApplyLegacyAuditPolicy REG_DWORD 0x1"
}

function Test-RemoteDCs([string[]]$DCs){
    if (-not $DCs -or $DCs.Count -eq 0) { return }
    Write-Host "`n[REMOTE VALIDATION] Checking DCs: $($DCs -join ', ')"
    $checks = @(
        @{ Name='Application Group Management'   ; Guid='{0cce9239-69ae-11d9-bed3-505054503030}' ; Expect='Success' },
        @{ Name='Computer Account Management'    ; Guid='{0cce9236-69ae-11d9-bed3-505054503030}' ; Expect='Success' },
        @{ Name='Distribution Group Management'  ; Guid='{0cce9238-69ae-11d9-bed3-505054503030}' ; Expect='Success' },
        @{ Name='Other Account Mgmt Events'      ; Guid='{0cce923a-69ae-11d9-bed3-505054503030}' ; Expect='Success' },
        @{ Name='Security Group Management'      ; Guid='{0cce9237-69ae-11d9-bed3-505054503030}' ; Expect='Success' },
        @{ Name='User Account Management'        ; Guid='{0cce9235-69ae-11d9-bed3-505054503030}' ; Expect='Success' },
        @{ Name='Directory Service Changes'      ; Guid='{0cce923c-69ae-11d9-bed3-505054503030}' ; Expect='Success' },
        @{ Name='Authentication Policy Change'   ; Guid='{0cce9230-69ae-11d9-bed3-505054503030}' ; Expect='Success' },
        @{ Name='Credential Validation'          ; Guid='{0cce923f-69ae-11d9-bed3-505054503030}' ; Expect='Success' },
        @{ Name='Kerberos Authentication Service'; Guid='{0cce9242-69ae-11d9-bed3-505054503030}' ; Expect='Success' },
        @{ Name='Logon'                          ; Guid='{0cce9215-69ae-11d9-bed3-505054503030}' ; Expect='Success' }
    )
    foreach ($dc in $DCs) {
        Write-Host "`n--- $dc ---"
        try {
            Invoke-Command -ComputerName $dc -ScriptBlock {
                reg query 'HKLM\System\CurrentControlSet\Control\Lsa' /v SCENoApplyLegacyAuditPolicy 2>$null
            } -ErrorAction Stop | Write-Host
            foreach ($c in $checks) {
                $out = Invoke-Command -ComputerName $dc -ScriptBlock { param($g) auditpol /get /subcategory:$g } -ArgumentList $c.Guid -ErrorAction Stop
                $line = $out | Where-Object { $_ -match '.*(Success|Failure).*' } | Select-Object -First 1
                $ok = ($line -match 'Success\s*:\s*Enabled')
                "{0,-34} ({1}) : {2}" -f $c.Name, $c.Guid, ($(if($ok){'OK'}else{'MISMATCH'}))
            }
        } catch {
            Write-Warning "Validation failed on $dc : $($_.Exception.Message)"
        }
    }
}

# -------------------------------- Main ---------------------------------------

Ensure-Module -Name GroupPolicy
$info    = Get-DomainInfo
$gpoName = 'Semperis Auditing Policy settings'

# Create or get the GPO
$gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
if (-not $gpo) {
    Invoke-Action -Action "Create GPO" -Target $gpoName -Do {
        $script:gpo = New-GPO -Name $gpoName -Comment "Advanced Audit Policy (subset) for Domain Controllers; created $(Get-Date -Format o)"
        $script:gpo
    } -Preview {
        Write-Host "  Would New-GPO -Name '$gpoName' -Comment 'Advanced Audit Policy (subset) for Domain Controllers; created <timestamp>'"
    }
    if (-not $script:DryRun) { $gpo = Get-GPO -Name $gpoName }
    if ($script:DryRun -and -not $gpo) { $gpoGuid = [guid]::NewGuid() }
} else {
    Write-Host "Updating existing GPO: $($gpo.DisplayName)  (ID: $($gpo.Id))"
}

# Enforce subcategory override inside the GPO (registry policy)
Set-GpoAuditSubcategoryOverride -GpoName $gpoName

# ALWAYS mirror the setting into Security Options (GptTmpl.inf) for visual auditing in GPMC
if (-not $gpoGuid) { $gpoGuid = if ($gpo) { $gpo.Id.Guid } else { [guid]::NewGuid() } }
Write-GptTmplInfSecurityOption -GpoGuid $gpoGuid -DomainFqdn $info.Fqdn

# Prepare audit.csv content and path
$auditCsvPath = Get-GpoSysvolAuditPath -GpoGuid $gpoGuid -DomainFqdn $info.Fqdn
$plannedLines = Get-PlannedAuditCsvLines
Write-AuditCsv -Path $auditCsvPath -PlannedLines $plannedLines

# Link to Domain Controllers OU with top precedence (Order = 1)
Link-GpoToDomainControllersTop -GpoName $gpoName -TargetOU $info.DCOU -Enforced:$EnforceLink.IsPresent

# Show current link order
Show-LinkOrder -TargetOU $info.DCOU

Write-Host "`nDeployment step(s) complete."
if (-not $script:DryRun) { Write-Host "Next: on Domain Controllers, run 'gpupdate /force' (or await background refresh)." }
else { Write-Host "Dry-run only: no changes were applied." }

# ---------------------- Validation (read-only) & Reports ----------------------

Test-LocalEffectiveSettings
if ($DCsToValidate) { Test-RemoteDCs -DCs $DCsToValidate }

# Reports + verification (skipped in DryRun)
$resolvedReportFolder = Resolve-ReportFolder -OverridePath $ReportFolder
if ($gpo) {
    Export-GPOReports -Gpo $gpo -ReportFolder $resolvedReportFolder -Timestamp:$AddTimestamp.IsPresent -AuditCsvPath $auditCsvPath
    Verify-GpoHasForceSwitch -Gpo $gpo -ReportFolder $resolvedReportFolder
} else {
    if (-not $script:DryRun) { Write-Warning "GPO object not available for reporting; reports were not generated." }
    else { Write-Host "[REPORTS] Dry-run: reports not generated." }
}
