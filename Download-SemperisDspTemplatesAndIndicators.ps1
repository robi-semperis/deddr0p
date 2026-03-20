#######################################################################
#
# Download-SemperisDspTemplatesAndIndicators.ps1
#
#
# Rob Ingenthron, Semperis  2026-01
# Inspired by James Ravenell, Semperis
#
#######################################################################

<#
.SYNOPSIS
Downloads Semperis DSP artifacts (multiple ZIPs), optionally extracts only the
Compliance Report Templates ZIP, and then (optionally) imports the ZIP templates into the
Semperis DSP Management Server. Supports idempotent downloads via ETag/Last-Modified.

.DESCRIPTION
This script:
- Downloads a catalog of Semperis DSP-related ZIP packages to a local folder.
- Uses HTTP with progress and automatic BITS fallback (Windows-only).
- Adds retry with exponential backoff for resilience.
- Improves HTTP reliability with timeouts, redirects, and proxy honoring.
- Logs verbosely to a rotating log file next to the script.
- (Security) Validates ZIP paths (zip-slip guard) before extraction.
- (Idempotency) Performs a HEAD pre-check; if ETag/Last-Modified matches previously
  stored metadata (.meta.json next to each file), it skips downloading.
- (Import) Ensures **Semperis.PoSh.DSP** module is loaded (from PSModulePath or a
  user-specified -DspModulePath), connects to DSP via `Connect-DspServer localhost`,
  verifies ConnectionState=Opened, and imports ONLY the ZIP files downloaded in this run
  (including inner files from the Compliance package) using Import-DspReportTemplate
  with full paths. You can skip imports using -SkipZipImports or respond to the
  popup prompt with timeout (defaults to proceeding if no response).
- Supports -WhatIf / -Verbose (CmdletBinding).
- Supports -NoProgress for non-interactive runs (applies to HTTP path).
- Supports -LockWaitSec to control how long we wait for exclusive locks.
- Supports -SkipIfLocked to skip a file (gracefully) if it remains locked after waiting.
- Supports -SkipZipImports to bypass the DSP import step entirely.
- Prints a FINAL SUMMARY with counts for downloaded, up-to-date/skipped, skipped-locked, download failures,
  extracted inner files, import success, import failures, and imports skipped.
- Mirrors DSP module’s raw output lines to the log as INFO.

.PARAMETER DestinationRoot
Destination folder for downloaded files. Defaults to:
C:\Software\Semperis\DSP\Templates

.PARAMETER RetryCount
Number of retry attempts (in addition to the initial attempt). Defaults to 2.

.PARAMETER RetryDelaySec
Initial delay (seconds) before the first retry. This value doubles each retry
(up to 60 seconds). Defaults to 3.

.PARAMETER NoProgress
Suppress progress bars for HTTP downloads. Useful for CI/non-interactive runs.
(BITS fallback runs synchronously without custom progress.)

.PARAMETER LockWaitSec
Maximum seconds to wait for exclusive access to files before overwrite/move.
Defaults to 20 unless overridden.

.PARAMETER SkipIfLocked
If specified (or enabled in DEFAULTS), a file that remains locked after
LockWaitSec will be skipped (gracefully) and will not be retried or imported.

.PARAMETER DspModulePath
OPTIONAL. A path pointing to the **Semperis.PoSh.DSP** module. It can be:
- The module **folder** (the script will locate a matching `.psd1`/`.psm1`), or
- The module **file** (`.psd1` or `.psm1`) itself.

.PARAMETER SkipZipImports
OPTIONAL. If supplied, the script will skip importing the downloaded/extracted ZIP
templates into DSP. Downloads and extractions still occur and are logged.

.PARAMETER ImportPromptTimeoutSec
OPTIONAL. Overrides the default popup timeout (in seconds) for this run. The value is
validated and clamped to 1–30 seconds. If not specified, the script uses the in-script DEFAULTS value.

.EXAMPLE
PS> .\Download-SemperisDspTemplatesAndIndicators.ps1 -Verbose

.EXAMPLE
PS> .\Download-SemperisDspTemplatesAndIndicators.ps1 -DestinationRoot 'D:\DSP\Templates' -NoProgress -LockWaitSec 45 -SkipIfLocked `
>> -DspModulePath 'C:\Packages\Semperis.PoSh.DSP'

.EXAMPLE
PS> .\Download-SemperisDspTemplatesAndIndicators.ps1 -SkipZipImports

.EXAMPLE
PS> .\Download-SemperisDspTemplatesAndIndicators.ps1 -ImportPromptTimeoutSec 12

.OUTPUTS
None. Writes informational output to the host and to a rotating log file.

.NOTES
Author: <Your Name/Team>
Version: 1.4.0
PowerShell: Windows PowerShell 5.x (incl. ISE v5) and PowerShell 7+ (Windows)
BITS: Windows-only; script falls back to HTTP automatically when BITS is unavailable.

CHANGELOG:
- 1.4.0 — IRP prompt made configurable via DEFAULTS ($DEFAULT_IrpPromptTitle / $DEFAULT_IrpPromptBody).
- 1.3.9 — Added popup (timeout = proceed) to optionally skip IRPTemplates.zip download/import; counts toward Imports skipped.
- 1.3.8 — Compliance extractor filters by DEFAULTS extensions list (e.g., @('.zip')).
- 1.3.7 — Compliance extractor only extracted inner .zip files; manual selective extraction.
- 1.3.6 — FINAL SUMMARY includes "Imports skipped" count.
- 1.3.5 — Range validation (clamp 1–30s) for -ImportPromptTimeoutSec; log each skipped import with reason (flag/popup).
- 1.3.4 — Added -ImportPromptTimeoutSec parameter (per-run override).
- 1.3.3 — Configurable DEFAULTS for popup title/body text.
- 1.3.2 — Popup prompt with timeout before import; detailed logging of skipped imports.
- 1.3.1 — Mirrored DSP raw lines into log.
- 1.3.0 — Idempotency, zip-slip guard, DestinationRoot param, import pipeline, lock handling, per-file replace retry, -DspModulePath, -SkipZipImports, inner-zip enumeration, FINAL SUMMARY.
#>

# =====================================================================================
# PARAMETERS
# =====================================================================================
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [int]$RetryCount,
    [int]$RetryDelaySec,
    [string]$DestinationRoot = 'C:\Software\Semperis\DSP\Templates',
    [switch]$NoProgress,
    [int]$LockWaitSec,
    [switch]$SkipIfLocked,
    [string]$DspModulePath,
    [switch]$SkipZipImports,
    [int]$ImportPromptTimeoutSec  # per-run override (validated & clamped to 1–30)
)

# =====================================================================================
# DEFAULTS / VERSION / GLOBALS
# =====================================================================================
$script:Version = '1.4.0'
$DEFAULT_RetryCount              = 2
$DEFAULT_RetryDelaySec           = 3
$DEFAULT_LockWaitSec             = 20
$DEFAULT_SkipIfLocked            = $false
$DEFAULT_ImportPromptTimeoutSec  = 6

# Configurable pop-up title & body text (body uses {0} for timeout seconds) for IMPORT step
$DEFAULT_ImportPromptTitle = 'Semperis DSP Template/Indicator Imports'
$DEFAULT_ImportPromptBody  = "Do you want to SKIP importing the downloaded ZIP templates into Semperis DSP for this run?`n`nClick 'Yes' to skip importing.`nClick 'No' (or wait {0} seconds) to proceed with importing."

# NEW: Configurable pop-up title & body text for IRP package decision
$DEFAULT_IrpPromptTitle = 'IRP Indicators package download'
$DEFAULT_IrpPromptBody  = "If you don't have the IRP license, do you want to skip the IRP package download? (Click 'Yes' to skip)"

# Allowed extensions for selective extraction from the Compliance package
$DEFAULT_ComplianceExtractExtensions = @('.zip')  # case-insensitive; add more like '.json', '.csv' if ever needed

if (-not $RetryCount)    { $RetryCount    = $DEFAULT_RetryCount }
if (-not $RetryDelaySec) { $RetryDelaySec = $DEFAULT_RetryDelaySec }
if (-not $PSBoundParameters.ContainsKey('LockWaitSec'))   { $LockWaitSec   = $DEFAULT_LockWaitSec }
if (-not $PSBoundParameters.ContainsKey('SkipIfLocked'))  { $SkipIfLocked  = $DEFAULT_SkipIfLocked }

# Expose variables users can tweak persistently in-script
# If parameter provided, validate & clamp; else fall back to DEFAULT.
if ($PSBoundParameters.ContainsKey('ImportPromptTimeoutSec')) {
    $requested = $ImportPromptTimeoutSec
    if ($requested -lt 1 -or $requested -gt 30) {
        $clamped = [Math]::Min([Math]::Max($requested, 1), 30)
        Write-Warning "ImportPromptTimeoutSec ($requested) is out of range. Clamping to $clamped seconds (allowed: 1–30)."
        Write-Log -Level WARN -Message "ImportPromptTimeoutSec out of range: requested=$requested; clamped=$clamped (1–30)"
        $ImportPromptTimeoutSec = $clamped
    }
} else {
    $ImportPromptTimeoutSec = $DEFAULT_ImportPromptTimeoutSec
}

# Defaults used for the IMPORT prompt
$ImportPromptTitle = $DEFAULT_ImportPromptTitle
$ImportPromptBody  = $DEFAULT_ImportPromptBody

# Defaults used for the IRP package prompt
$IrpPromptTitle = $DEFAULT_IrpPromptTitle
$IrpPromptBody  = $DEFAULT_IrpPromptBody

# Expose the extensions allow-list for Compliance extraction
$ComplianceExtractExtensions = $DEFAULT_ComplianceExtractExtensions

# Unique candidate set for imports (case-insensitive)
$script:CandidateZips = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

# Final summary stats
$script:Stats = [pscustomobject]@{
    Downloaded        = 0
    SkippedIdempotent = 0
    SkippedLocked     = 0
    DownloadFailed    = 0
    ExtractedInner    = 0
    ImportSuccess     = 0
    ImportFailed      = 0
    ImportSkipped     = 0
}

# =====================================================================================
# LOGGING
# =====================================================================================
function Get-ScriptBasePath {
    try { if ($MyInvocation.MyCommand.Path) { Split-Path $MyInvocation.MyCommand.Path -Parent } else { (Get-Location).Path } }
    catch { (Get-Location).Path }
}
function Initialize-Log {
    $log = Join-Path (Get-ScriptBasePath) 'Download-SemperisDspTemplatesAndIndicators.log'
    try {
        if (Test-Path $log) {
            $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
            Move-Item -Path $log -Destination "$log.$ts.bak" -Force -ErrorAction SilentlyContinue
        }
        New-Item -ItemType File -Path $log -Force | Out-Null
        $script:LogFile = $log
        Write-Log -Level INFO -Message "Log initialized at : $log"
        return $log
    } catch {
        Write-Warning "Unable to create log : $($_.Exception.Message)"
        $script:LogFile = $null
        return $null
    }
}
function Write-Log {
    param(
        [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO',
        [Parameter(Mandatory)][string]$Message
    )
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    $line  = "[$stamp] [$Level] $Message"
    if ($script:LogFile) { try { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 } catch {} }
    switch ($Level) {
        'INFO'  { Write-Verbose $Message }
        'DEBUG' { Write-Verbose $Message }
        'WARN'  { Write-Warning $Message }
        'ERROR' { Write-Error $Message -ErrorAction Continue }
    }
}

# =====================================================================================
# UTILITIES
# =====================================================================================
function Set-Tls12IfNeeded {
    try {
        [System.Net.ServicePointManager]::Expect100Continue = $false
        [System.Net.ServicePointManager]::DefaultConnectionLimit = 8
        $cur = [System.Net.ServicePointManager]::SecurityProtocol
        if (($cur -band [System.Net.SecurityProtocolType]::Tls12) -eq 0) {
            [System.Net.ServicePointManager]::SecurityProtocol = $cur -bor [System.Net.SecurityProtocolType]::Tls12
        }
        Write-Log -Level INFO -Message "TLS 1.2 enabled"
    } catch { Write-Log -Level WARN -Message "Failed enabling TLS : $($_.Exception.Message)" }
}

function Wait-FileUnlock {
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$TimeoutSec = 20
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        try {
            $dir = Split-Path -Path $Path -Parent
            if (-not (Test-Path $dir)) { return $true }
            $fs = [IO.File]::Open($Path, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            $fs.Close()
            return $true
        } catch {
            if ($sw.Elapsed.TotalSeconds -gt $TimeoutSec) { return $false }
            Start-Sleep -Milliseconds 300
        }
    }
}

function Replace-FileWithRetry {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [int]$TimeoutSec = 20,
        [switch]$SkipIfLocked
    )
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        try {
            $destDir = Split-Path -Path $Destination -Parent
            if (-not (Test-Path $destDir)) {
                New-Item -ItemType Directory -Path $destDir -Force -ErrorAction Stop | Out-Null
            }
            if (Test-Path $Destination) {
                if (-not (Wait-FileUnlock -Path $Destination -TimeoutSec 1)) {
                    throw [System.IO.IOException]::new("Destination locked: $Destination")
                }
                Remove-Item $Destination -Force -ErrorAction Stop
            }
            Move-Item -Path $Source -Destination $Destination -Force -ErrorAction Stop
            return [pscustomobject]@{ Success=$true; Skipped=$false; Error=$null }
        } catch {
            if ($sw.Elapsed.TotalSeconds -ge $TimeoutSec) {
                if ($SkipIfLocked) {
                    return [pscustomobject]@{ Success=$false; Skipped=$true; Error="Skipped (locked): $Destination" }
                } else {
                    return [pscustomobject]@{ Success=$false; Skipped=$false; Error=$_.Exception.Message }
                }
            }
            Start-Sleep -Milliseconds 300
        }
    }
}

function New-SafeDirectory {
    param([string]$Path)
    if (Test-Path $Path) { Write-Log -Level DEBUG -Message "Directory exists : $Path"; return $true }
    $canProcess = $PSCmdlet -and $PSCmdlet.ShouldProcess($Path, "Create directory")
    if ($canProcess) {
        try { New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null
              Write-Log -Level INFO -Message "Created directory : $Path"; return $true }
        catch { Write-Log -Level WARN -Message "Directory creation failed : $($_.Exception.Message)"; return $false }
    }
    Write-Log -Level INFO -Message "(WhatIf) Would create directory : $Path"
    return $true
}
function Get-FriendlySize {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes/1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N2} MB' -f ($Bytes/1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N2} KB' -f ($Bytes/1KB)) }
    "$Bytes B"
}

function Add-CandidateZip {
    param([Parameter(Mandatory)][string]$Path)
    try {
        $rp = Resolve-Path -LiteralPath $Path -ErrorAction Stop
        [void]$script:CandidateZips.Add($rp.Path)
    } catch { }
}

# =====================================================================================
# ZIP-SLIP GUARD
# =====================================================================================
function Test-ZipSafe {
    param(
        [Parameter(Mandatory)][string]$ZipFile,
        [Parameter(Mandatory)][string]$DestinationFolder
    )
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipFile)
        foreach ($entry in $zip.Entries) {
            $targetPath = Join-Path $DestinationFolder $entry.FullName
            $fullTarget = [IO.Path]::GetFullPath($targetPath)
            $fullRoot   = [IO.Path]::GetFullPath($DestinationFolder + [IO.Path]::DirectorySeparatorChar)
            if (-not $fullTarget.StartsWith($fullRoot, [StringComparison]::OrdinalIgnoreCase)) {
                $zip.Dispose(); return $false
            }
        }
        $zip.Dispose(); return $true
    } catch {
        Write-Log -Level ERROR -Message "Zip safety check failed: $($_.Exception.Message)"
        return $false
    }
}

# =====================================================================================
# IDENTITY / METADATA (for idempotency)
# =====================================================================================
function Get-LocalMetaPath { param([string]$OutFile) return "$OutFile.meta.json" }
function Load-DownloadMeta {
    param([string]$MetaPath)
    if (Test-Path $MetaPath) {
        try { return Get-Content -Raw -Path $MetaPath | ConvertFrom-Json } catch { }
    }
    return $null
}
function Save-DownloadMeta {
    param(
        [string]$MetaPath,
        [string]$Uri,
        [string]$ETag,
        [string]$LastModifiedRFC1123
    )
    $obj = [pscustomobject]@{
        Uri          = $Uri
        ETag         = $ETag
        LastModified = $LastModifiedRFC1123
        Updated      = (Get-Date).ToString('o')
    }
    $json = $obj | ConvertTo-Json
    Set-Content -Path $MetaPath -Value $json -Encoding UTF8
}
function Get-RemoteHeaders {
    param([Parameter(Mandatory)][string]$Uri)
    try {
        $req = [System.Net.HttpWebRequest]::Create($Uri)
        $req.Method                      = 'HEAD'
        $req.UserAgent                   = 'PSDownloader/1.1'
        $req.AllowAutoRedirect           = $true
        $req.MaximumAutomaticRedirections= 10
        $req.Timeout                     = 1000 * 60 * 2
        $req.ReadWriteTimeout            = 1000 * 60 * 2
        $req.KeepAlive                   = $false
        $req.Proxy = [System.Net.WebRequest]::DefaultWebProxy
        if ($req.Proxy) { $req.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials }

        $resp = $req.GetResponse()
        $etag = $resp.Headers['ETag']
        $lm   = $resp.Headers['Last-Modified']
        $resp.Close()
        return [pscustomobject]@{ ETag = $etag; LastModified = $lm }
    } catch {
        Write-Log -Level WARN -Message "HEAD failed for $Uri : $($_.Exception.Message)"
        return $null
    }
}
function Test-ResourceUpToDate {
    param(
        [string]$OutFile,
        [pscustomobject]$RemoteHeaders,
        [pscustomobject]$LocalMeta
    )
    if (-not (Test-Path $OutFile)) { return $false }
    if (-not $RemoteHeaders -or (-not $RemoteHeaders.ETag -and -not $RemoteHeaders.LastModified)) { return $false }
    if ($LocalMeta) {
        if ($RemoteHeaders.ETag -and $LocalMeta.ETag -and ($RemoteHeaders.ETag -eq $LocalMeta.ETag)) { return $true }
        if ($RemoteHeaders.LastModified -and $LocalMeta.LastModified -and ($RemoteHeaders.LastModified -eq $LocalMeta.LastModified)) { return $true }
    }
    return $false
}

# =====================================================================================
# HTTP DOWNLOAD
# =====================================================================================
function Invoke-HttpDownload {
    param(
        [string]$Uri,
        [string]$OutFile,
        [switch]$NoProgress,
        [int]$LockWaitSec,
        [switch]$SkipIfLocked
    )

    $tmp = "$OutFile.partial"
    $ProgressIdHttp = Get-Random
    Write-Host "→ Starting HTTP download ..." -ForegroundColor Cyan
    Write-Host " Source : $Uri"
    Write-Host " Target : $OutFile"
    Write-Log -Level INFO -Message "HTTP : $Uri -> $OutFile"

    $canProcess = $PSCmdlet -and $PSCmdlet.ShouldProcess($OutFile, "HTTP download")
    if (-not $canProcess) {
        return [pscustomobject]@{ Success=$true; Method='HTTP(WhatIf)'; Error=$null; ETag=$null; LastModified=$null; Skipped=$false }
    }

    $resp = $null; $stream = $null; $fs = $null
    try {
        if (Test-Path $tmp) {
            if (-not (Wait-FileUnlock -Path $tmp -TimeoutSec $LockWaitSec)) {
                $msg = "Temp file locked: $tmp"
                if ($SkipIfLocked) { return [pscustomobject]@{ Success=$false; Method='HTTP'; Error=$msg; ETag=$null; LastModified=$null; Skipped=$true } }
                throw $msg
            }
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        }

        $req = [System.Net.HttpWebRequest]::Create($Uri)
        $req.UserAgent                   = 'PSDownloader/1.1'
        $req.AllowAutoRedirect           = $true
        $req.MaximumAutomaticRedirections= 10
        $req.Timeout                     = 1000 * 60 * 5
        $req.ReadWriteTimeout            = 1000 * 60 * 5
        $req.KeepAlive                   = $false
        $req.Proxy = [System.Net.WebRequest]::DefaultWebProxy
        if ($req.Proxy) { $req.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials }

        $resp   = $req.GetResponse()
        $etag   = $resp.Headers['ETag']
        $lm     = $resp.Headers['Last-Modified']
        $stream = $resp.GetResponseStream()
        $total  = $resp.ContentLength
        $fs     = New-Object IO.FileStream($tmp, 'Create', 'Write', 'None')
        $buf    = New-Object byte[] (64KB)
        $readTotal = 0

        while (($read = $stream.Read($buf,0,$buf.Length)) -gt 0) {
            $fs.Write($buf,0,$read)
            $readTotal += $read
            if (-not $NoProgress) {
                if ($total -gt 0) {
                    $pct = $readTotal * 100 / $total
                    Write-Progress -Id $ProgressIdHttp -Activity "HTTP Download" `
                        -Status ("{0} of {1}" -f (Get-FriendlySize $readTotal),(Get-FriendlySize $total)) `
                        -PercentComplete $pct
                } else {
                    Write-Progress -Id $ProgressIdHttp -Activity "HTTP Download" `
                        -Status ("{0} downloaded" -f (Get-FriendlySize $readTotal)) `
                        -PercentComplete -1
                }
            }
        }
        if (-not $NoProgress) { Write-Progress -Id $ProgressIdHttp -Activity "HTTP Download" -Completed }

        $fs.Close(); $fs = $null
        $rep = Replace-FileWithRetry -Source $tmp -Destination $OutFile -TimeoutSec $LockWaitSec -SkipIfLocked:$SkipIfLocked
        if ($rep.Skipped) {
            Write-Log -Level WARN -Message "Skipped (locked) : $OutFile"
            return [pscustomobject]@{ Success=$false; Method='HTTP'; Error='Skipped (locked)'; ETag=$etag; LastModified=$lm; Skipped=$true }
        }
        if (-not $rep.Success) {
            throw "Failed to replace target: $OutFile — $($rep.Error)"
        }

        Write-Host "✔ HTTP download succeeded : $OutFile" -ForegroundColor Green
        Write-Log -Level INFO -Message "HTTP success"
        return [pscustomobject]@{ Success=$true; Method='HTTP'; Error=$null; ETag=$etag; LastModified=$lm; Skipped=$false }
    }
    catch {
        Write-Log -Level WARN -Message "HTTP failed : $($_.Exception.Message)"
        if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
        return [pscustomobject]@{ Success=$false; Method='HTTP'; Error=$_.Exception.Message; ETag=$null; LastModified=$null; Skipped=$false }
    }
    finally {
        try { if ($fs) { $fs.Dispose() } } catch {}
        try { if ($stream) { $stream.Dispose() } } catch {}
        try { if ($resp) { $resp.Close() } } catch {}
    }
}

# =====================================================================================
# BITS DOWNLOAD (fallback)
# =====================================================================================
function Invoke-BitsDownload {
    param(
        [string]$Uri,
        [string]$OutFile,
        [int]$LockWaitSec,
        [switch]$SkipIfLocked
    )
    Write-Host "→ Using BITS fallback ..." -ForegroundColor Cyan
    Write-Host " Source : $Uri"
    Write-Host " Target : $OutFile"
    Write-Log -Level INFO -Message "BITS : $Uri -> $OutFile"

    $canProcess = $PSCmdlet -and $PSCmdlet.ShouldProcess($OutFile, "BITS download")
    if (-not $canProcess) {
        return [pscustomobject]@{ Success=$true; Method='BITS(WhatIf)'; Error=$null; Skipped=$false }
    }

    try {
        if (Test-Path $OutFile) {
            if (-not (Wait-FileUnlock -Path $OutFile -TimeoutSec $LockWaitSec)) {
                if ($SkipIfLocked) {
                    Write-Log -Level WARN -Message "Skipped (locked) before BITS: $OutFile"
                    return [pscustomobject]@{ Success=$false; Method='BITS'; Error='Skipped (locked)'; Skipped=$true }
                }
                throw "Target file is locked and cannot be replaced: $OutFile"
            }
            Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
        }

        Start-BitsTransfer -Source $Uri -Destination $OutFile -ErrorAction Stop

        Write-Host "✔ BITS download succeeded : $OutFile" -ForegroundColor Green
        Write-Log -Level INFO -Message "BITS success"
        return [pscustomobject]@{ Success=$true; Method='BITS'; Error=$null; Skipped=$false }
    }
    catch {
        Write-Log -Level WARN -Message "BITS exception : $($_.Exception.Message)"
        return [pscustomobject]@{ Success=$false; Method='BITS'; Error=$_.Exception.Message; Skipped=$false }
    }
}

# =====================================================================================
# RETRY WRAPPER
# =====================================================================================
function Invoke-DownloadWithRetry {
    param(
        [string]$Uri,
        [string]$OutFile,
        [int]$RetryCount,
        [int]$RetryDelaySec,
        [switch]$NoProgress,
        [int]$LockWaitSec,
        [switch]$SkipIfLocked
    )
    $attempt = 0
    $delay = $RetryDelaySec
    while ($true) {
        $attempt++
        Write-Host "Attempt $attempt ..." -ForegroundColor Cyan
        Write-Log -Level INFO -Message "Attempt $attempt : $Uri -> $OutFile"

        $res = Invoke-HttpDownload -Uri $Uri -OutFile $OutFile -NoProgress:$NoProgress -LockWaitSec $LockWaitSec -SkipIfLocked:$SkipIfLocked
        if ($res.Skipped) { return $res }
        if ($res.Success) { return $res }

        $bitsCmd = Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue
        if ($bitsCmd) {
            $res = Invoke-BitsDownload -Uri $Uri -OutFile $OutFile -LockWaitSec $LockWaitSec -SkipIfLocked:$SkipIfLocked
            if ($res.Skipped) { return $res }
            if ($res.Success) { return $res }
        } else {
            Write-Log -Level WARN -Message "BITS not available; skipping BITS fallback."
        }

        if ($attempt -gt $RetryCount + 1) {
            Write-Log -Level ERROR -Message "Exhausted retries. Last error : $($res.Error)"
            return $res
        }
        Write-Host "Retrying in $delay seconds ..." -ForegroundColor Yellow
        Write-Log -Level INFO -Message "Waiting $delay seconds before retry"
        Start-Sleep -Seconds $delay
        $delay = [Math]::Min($delay * 2, 60)
    }
}

# =====================================================================================
# EXTRACTION (ONLY SELECTED EXTENSIONS FROM THE COMPLIANCE ZIP)
# =====================================================================================
function Extract-ComplianceZip {
    param(
        [string]$ZipFile,
        [string]$DestinationFolder
    )
    $extList = @()
    if ($ComplianceExtractExtensions -is [System.Collections.IEnumerable]) { $extList = @($ComplianceExtractExtensions) }
    if (-not $extList -or $extList.Count -eq 0) { $extList = @('.zip') }

    Write-Host ("Extracting from Compliance package (allowed: {0}) ..." -f ($extList -join ', ')) -ForegroundColor Yellow
    Write-Log -Level INFO -Message ("Selective extraction: allowed extensions => {0}" -f ($extList -join ', '))

    if (-not (Test-Path $ZipFile)) {
        Write-Host "Cannot extract. ZIP not found : $ZipFile" -ForegroundColor Red
        Write-Log -Level ERROR -Message "Extract failed — ZIP missing : $ZipFile"
        return @()
    }
    $canProcess = $PSCmdlet -and $PSCmdlet.ShouldProcess($ZipFile, "Selective extract (allowed extensions)")
    if (-not $canProcess) {
        Write-Log -Level INFO -Message "(WhatIf) Would extract only allowed extensions from : $ZipFile"
        return @()
    }

    # Zip-slip safety check against the full archive
    if (-not (Test-ZipSafe -ZipFile $ZipFile -DestinationFolder $DestinationFolder)) {
        Write-Host "Unsafe ZIP contents detected. Aborting extraction." -ForegroundColor Red
        Write-Log -Level ERROR -Message "Zip traversal detected in $ZipFile"
        return @()
    }

    # Build a case-insensitive HashSet for extension membership tests
    $hashExt = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($e in $extList) { if ($e) { [void]$hashExt.Add($e) } }

    $extracted = @()
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipFile)

        foreach ($entry in $zip.Entries) {
            if (-not $entry.FullName) { continue }
            # Skip directory entries
            if ($entry.FullName.EndsWith('/') -or $entry.FullName.EndsWith('\')) { continue }

            $entryExt = [IO.Path]::GetExtension($entry.FullName)
            if (-not $hashExt.Contains($entryExt)) { continue }

            # Target path resolution
            $targetPath = Join-Path $DestinationFolder $entry.FullName
            $fullTarget = [IO.Path]::GetFullPath($targetPath)
            $fullRoot   = [IO.Path]::GetFullPath($DestinationFolder + [IO.Path]::DirectorySeparatorChar)

            # Redundant safety: ensure path remains under root
            if (-not $fullTarget.StartsWith($fullRoot, [StringComparison]::OrdinalIgnoreCase)) {
                Write-Log -Level WARN -Message "Blocked path (zip-slip): $($entry.FullName)"
                continue
            }

            # Ensure parent directory exists
            $parent = Split-Path -Path $fullTarget -Parent
            if (-not (Test-Path $parent)) {
                New-Item -ItemType Directory -Path $parent -Force -ErrorAction SilentlyContinue | Out-Null
            }

            # Extract this entry
            try {
                $outStream = [System.IO.File]::Open($fullTarget, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                $inStream  = $entry.Open()
                $inStream.CopyTo($outStream)
                $outStream.Close()
                $inStream.Close()

                $resolved = Resolve-Path -LiteralPath $fullTarget -ErrorAction SilentlyContinue
                if ($resolved) {
                    $extracted += $resolved.Path
                    Write-Log -Level INFO -Message "Extracted file: $($resolved.Path)"
                } else {
                    $extracted += $fullTarget
                    Write-Log -Level INFO -Message "Extracted file: $fullTarget"
                }
            } catch {
                Write-Log -Level WARN -Message "Failed extracting '$($entry.FullName)' : $($_.Exception.Message)"
            }
        }

        $zip.Dispose()

        # Delete the source compliance ZIP after extraction
        try {
            Remove-Item $ZipFile -Force
            Write-Host "Deleted original Compliance ZIP file after extraction." -ForegroundColor Green
            Write-Log -Level INFO -Message "Deleted source compliance ZIP"
        } catch {
            Write-Log -Level WARN -Message "Could not delete source ZIP '$ZipFile' : $($_.Exception.Message)"
        }

        if ($extracted.Count -gt 0) {
            Write-Host ("✔ Extracted {0} file(s) into : {1}" -f $extracted.Count, $DestinationFolder) -ForegroundColor Green
        } else {
            Write-Host "No files matching the allowed extensions were found to extract." -ForegroundColor Yellow
        }

        return $extracted
    }
    catch {
        Write-Host "Extraction failed : $($_.Exception.Message)" -ForegroundColor Red
        Write-Log -Level ERROR -Message "Selective extraction failure : $($_.Exception.Message)"
        return @()
    }
}

# =====================================================================================
# DSP MODULE LOADING (Semperis.PoSh.DSP)
# =====================================================================================
function Ensure-DspModuleAvailable {
    param([string]$ModulePath)
    $moduleName = 'Semperis.PoSh.DSP'
    if (Get-Module -Name $moduleName) { Write-Log -Level INFO -Message "DSP module already loaded: $moduleName"; return $true }

    if ($ModulePath) {
        try {
            if (Test-Path -LiteralPath $ModulePath) {
                $item = Get-Item -LiteralPath $ModulePath -ErrorAction Stop
                if ($item.PSIsContainer) {
                    $psd1 = Get-ChildItem -Path $item.FullName -Filter "$moduleName*.psd1" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                    $psm1 = $null
                    if (-not $psd1) { $psm1 = Get-ChildItem -Path $item.FullName -Filter "$moduleName*.psm1" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 }
                    if     ($psd1) { Import-Module -LiteralPath $psd1.FullName -ErrorAction Stop; Write-Log -Level INFO -Message "Imported DSP module from: $($psd1.FullName)"; return $true }
                    elseif ($psm1) { Import-Module -LiteralPath $psm1.FullName -ErrorAction Stop; Write-Log -Level INFO -Message "Imported DSP module from: $($psm1.FullName)"; return $true }
                    else { Write-Log -Level WARN -Message "No module manifest/module file found under: $($item.FullName)" }
                } else {
                    Import-Module -LiteralPath $item.FullName -ErrorAction Stop
                    Write-Log -Level INFO -Message "Imported DSP module from: $($item.FullName)"
                    return $true
                }
            } else {
                Write-Log -Level WARN -Message "DspModulePath not found: $ModulePath"
            }
        } catch {
            Write-Log -Level ERROR -Message "Failed to import DSP module from path '$ModulePath' : $($_.Exception.Message)"
            return $false
        }
    }

    $available = Get-Module -Name $moduleName -ListAvailable
    if ($available) {
        try { Import-Module -Name $moduleName -ErrorAction Stop; Write-Log -Level INFO -Message "Imported DSP module by name: $moduleName"; return $true }
        catch { Write-Log -Level ERROR -Message "DSP module found but failed to load: $($_.Exception.Message)"; return $false }
    }

    Write-Log -Level WARN -Message "Module '$moduleName' not found. Please install or specify -DspModulePath."
    return $false
}

# =====================================================================================
# POPUP PROMPT WITH TIMEOUT (reusable)
# =====================================================================================
function Show-YesNoPromptWithTimeout {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [string]$Title = 'Confirm Action',
        [int]$TimeoutSec = 6
    )
    try {
        $ws = New-Object -ComObject WScript.Shell
        # Buttons: Yes/No (0x4), Icon: Question (0x20)
        $buttons = 0x4 + 0x20
        $res = $ws.Popup($Message, [int]$TimeoutSec, $Title, $buttons)
        switch ($res) {
            6   { return [pscustomobject]@{ Responded=$true; Choice='Yes'; TimedOut=$false } } # Yes
            7   { return [pscustomobject]@{ Responded=$true; Choice='No' ; TimedOut=$false } } # No
           -1   { return [pscustomobject]@{ Responded=$false; Choice=$null; TimedOut=$true  } } # Timeout
            default { return [pscustomobject]@{ Responded=$false; Choice=$null; TimedOut=$true } }
        }
    } catch {
        # Fallback: treat as timeout so we proceed
        return [pscustomobject]@{ Responded=$false; Choice=$null; TimedOut=$true }
    }
}

# =====================================================================================
# IMPORT INTO SEMPERIS DSP (keeps raw lines; mirrors to log; returns one object)
# =====================================================================================
function Import-DspTemplates {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [string]$DspServer = 'localhost',
        [string[]]$CandidateFiles,
        [string]$DspModulePath
    )

    Write-Host "Starting import into Semperis DSP Management Server..." -ForegroundColor Cyan
    Write-Log  -Level INFO -Message "Import step started. Server=$DspServer; SourceRoot=$SourceRoot"

    $resultObj = [pscustomobject]@{ Success = $false; Imported = 0; Failed = 0 }

    if (-not (Ensure-DspModuleAvailable -ModulePath $DspModulePath)) {
        Write-Warning "Module 'Semperis.PoSh.DSP' not available. Skipping import."
        return $resultObj
    }

    $requiredCmds = 'Connect-DspServer','Import-DspReportTemplate'
    foreach ($cmd in $requiredCmds) {
        if (-not (Get-Command -Name $cmd -ErrorAction SilentlyContinue)) {
            Write-Warning "Required DSP cmdlet not found after module load: $cmd"
            Write-Log -Level ERROR -Message "Missing DSP cmdlet: $cmd"
            return $resultObj
        }
    }

    try { $conn = Connect-DspServer $DspServer -ErrorAction Stop }
    catch {
        Write-Warning "Failed to connect to DSP server '$DspServer': $($_.Exception.Message)"
        Write-Log -Level ERROR -Message "Connect-DspServer failed: $($_.Exception.Message)"
        return $resultObj
    }
    if (-not $conn -or -not $conn.ConnectionState -or $conn.ConnectionState -ne 'Opened') {
        Write-Warning "DSP connection not opened. ConnectionState: '$($conn.ConnectionState)'"
        Write-Log -Level ERROR -Message "DSP connection failed or not opened."
        return $resultObj
    }
    Write-Host "✔ Connected to DSP server '$DspServer' (ConnectionState=Opened)" -ForegroundColor Green
    Write-Log -Level INFO -Message "Connected to DSP server. ConnectionState=Opened"

    # Resolve candidates if not provided
    $zipFiles = @()
    if ($CandidateFiles -and $CandidateFiles.Count -gt 0) {
        $zipFiles = $CandidateFiles | Where-Object { $_ -and (Test-Path $_) }
    } else {
        try {
            $zipFiles = Get-ChildItem -Path $SourceRoot -Filter *.zip -Recurse -File -ErrorAction SilentlyContinue |
                        ForEach-Object FullName
        } catch { $zipFiles = @() }
    }

    if (-not $zipFiles -or $zipFiles.Count -eq 0) {
        Write-Host "No ZIP files found to import under '$SourceRoot'." -ForegroundColor Yellow
        Write-Log -Level INFO -Message "Import step: no ZIP candidates found."
        $resultObj.Success = $true
        return $resultObj
    }

    $imported = 0
    $failed   = 0
    foreach ($zip in $zipFiles) {
        $canProcess = $PSCmdlet -and $PSCmdlet.ShouldProcess($zip, "Import-DspReportTemplate")
        if (-not $canProcess) {
            Write-Log -Level INFO -Message "(WhatIf) Would import: $zip"
            continue
        }
        try {
            # Capture raw output, echo and log
            $raw = Import-DspReportTemplate -FilePath $zip -ErrorAction Stop
            if ($raw) {
                $raw | ForEach-Object {
                    Write-Host $_
                    Write-Log -Level INFO -Message $_
                }
            }

            Write-Host "✔ Imported: $zip" -ForegroundColor Green
            Write-Log -Level INFO -Message "Imported: $zip"
            $imported++
        } catch {
            Write-Warning "Import failed for '$zip': $($_.Exception.Message)"
            Write-Log -Level ERROR -Message "Import failed for '$zip': $($_.Exception.Message)"
            $failed++
        }
    }

    Write-Host "Import complete. Success=$imported; Failed=$failed" -ForegroundColor Cyan
    Write-Log -Level INFO -Message "Import summary: Success=$imported; Failed=$failed"

    $resultObj.Imported = $imported
    $resultObj.Failed   = $failed
    $resultObj.Success  = ($failed -eq 0)
    return $resultObj
}

# =====================================================================================
# MAIN
# =====================================================================================
function Start-DownloadProcess {
    $logFile = Initialize-Log
    Write-Log -Level INFO -Message "===== Run started : $(Get-Date) ====="
    Write-Log -Level INFO -Message "Version: $script:Version"
    Write-Log -Level INFO -Message "PowerShell: $($PSVersionTable.PSVersion.ToString()) (Edition: $($PSVersionTable.PSEdition))"
    $changelog = Join-Path (Get-ScriptBasePath) 'CHANGELOG.md'
    if (Test-Path $changelog) { Write-Log -Level INFO -Message "CHANGELOG: $changelog" }

    Set-Tls12IfNeeded

    $root = $DestinationRoot
    New-SafeDirectory -Path $root | Out-Null

    # ---- DOWNLOAD CATALOG ----
    $downloads = @(
        @{ Name="DSP Templates"                  ; Url="https://semperis.com/downloads/Templates/DSPTemplates.zip"                      ; File="DSPTemplates.zip" }
        @{ Name="AAD Indicators"                 ; Url="https://semperis.com/downloads/Templates/DSP_AADIndicators.zip"                ; File="DSP_AADIndicators.zip" }
        @{ Name="IRP / IOA Templates"            ; Url="https://semperis.com/downloads/Templates/IRPTemplates.zip"                     ; File="IRPTemplates.zip" }
        @{ Name="DSP Compliance Report Templates"; Url="https://semperis.com/downloads/Templates/DSP-ComplianceReportingTemplates.zip"  ; File="DSP-ComplianceReportingTemplates.zip" ; Extract=$true }
    )

    foreach ($item in $downloads) {
        Write-Host ""
        Write-Host "=== Downloading $($item.Name) ===" -ForegroundColor Cyan

        # IRP prompt BEFORE idempotency checks/downloads (timeout => proceed)
        if ($item.File -eq 'IRPTemplates.zip') {
            $irpRes = Show-YesNoPromptWithTimeout -Message $IrpPromptBody -Title $IrpPromptTitle -TimeoutSec $ImportPromptTimeoutSec
            if ($irpRes -and $irpRes.Choice -eq 'Yes') {
                Write-Host "Skipping IRP package download and import by user choice." -ForegroundColor Yellow
                Write-Log  -Level INFO -Message "IRP package skipped by popup: user chose Yes."
                # Count as an import skipped (one package)
                $script:Stats.ImportSkipped += 1
                continue
            } else {
                if ($irpRes.TimedOut) {
                    Write-Log -Level INFO -Message "IRP package prompt timed out after $ImportPromptTimeoutSec sec; proceeding with download/import."
                } else {
                    Write-Log -Level INFO -Message "IRP package prompt: user chose No; proceeding with download/import."
                }
            }
        }

        $destination = Join-Path $root $item.File
        $metaPath    = Get-LocalMetaPath -OutFile $destination
        $localMeta   = Load-DownloadMeta -MetaPath $metaPath
        $remoteHdrs  = Get-RemoteHeaders -Uri $item.Url

        if (Test-ResourceUpToDate -OutFile $destination -RemoteHeaders $remoteHdrs -LocalMeta $localMeta) {
            Write-Host "Up-to-date : $destination (skipping download)" -ForegroundColor Green
            Write-Log -Level INFO -Message "Skipped (Not Modified) : $($item.Url)"
            $script:Stats.SkippedIdempotent++

            if ($item.ContainsKey("Extract") -and $item.Extract -eq $true) {
                # Compliance: include any allowed inner files already on disk for import
                try {
                    $existingInner = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
                                     Where-Object { $_.Extension -in $ComplianceExtractExtensions }
                    foreach ($f in $existingInner) { Add-CandidateZip -Path $f.FullName }
                } catch { }
            } else {
                Add-CandidateZip -Path $destination
            }
        } else {
            $result = Invoke-DownloadWithRetry `
                -Uri $item.Url `
                -OutFile $destination `
                -RetryCount $RetryCount `
                -RetryDelaySec $RetryDelaySec `
                -NoProgress:$NoProgress `
                -LockWaitSec $LockWaitSec `
                -SkipIfLocked:$SkipIfLocked

            if ($result.Skipped) {
                Write-Host "SKIPPED (locked) : $destination" -ForegroundColor Yellow
                Write-Log -Level WARN -Message "Skipped (locked) : $destination"
                $script:Stats.SkippedLocked++
            }
            elseif ($result.Success) {
                Write-Host "Success : $destination" -ForegroundColor Green
                Write-Log -Level INFO -Message "Downloaded $($item.Name) to $destination"
                $script:Stats.Downloaded++

                $etag = if ($result.ETag) { $result.ETag } else { if ($remoteHdrs) { $remoteHdrs.ETag } else { $null } }
                $lm   = if ($result.LastModified) { $result.LastModified } else { if ($remoteHdrs) { $remoteHdrs.LastModified } else { $null } }
                try { Save-DownloadMeta -MetaPath $metaPath -Uri $item.Url -ETag $etag -LastModifiedRFC1123 $lm } catch {}

                if ($item.ContainsKey("Extract") -and $item.Extract -eq $true) {
                    $innerFiles = Extract-ComplianceZip -ZipFile $destination -DestinationFolder $root
                    if ($innerFiles -and $innerFiles.Count -gt 0) {
                        $script:Stats.ExtractedInner += $innerFiles.Count
                        foreach ($p in $innerFiles) { Add-CandidateZip -Path $p }
                    }
                } else {
                    Add-CandidateZip -Path $destination
                }
            } else {
                Write-Host "FAILED : $($item.Name)" -ForegroundColor Red
                Write-Log -Level ERROR -Message "FAILED : $($item.Name) — $($result.Error)"
                $script:Stats.DownloadFailed++
            }
        }
    }

    # ---- OPTIONAL IMPORT INTO DSP ----
    Write-Host ""
    if ($SkipZipImports) {
        Write-Host "Skipping DSP imports because -SkipZipImports was specified." -ForegroundColor Yellow
        Write-Log  -Level INFO -Message "DSP import skipped by -SkipZipImports."

        # Log each skipped candidate + summary (reason=flag)
        $candidateArray = @()
        if ($script:CandidateZips -is [System.Collections.IEnumerable]) { $candidateArray = @($script:CandidateZips) }
        foreach ($c in $candidateArray) { Write-Log -Level INFO -Message "Skipped import [reason=flag]: $c" }
        Write-Log -Level INFO -Message "Skipped import summary [reason=flag]: Count=$($candidateArray.Count)"
        $script:Stats.ImportSkipped += $candidateArray.Count
    } else {
        # Popup prompt with timeout — default proceed if no response
        $promptMsg = ($ImportPromptBody -f $ImportPromptTimeoutSec)
        $promptRes = Show-YesNoPromptWithTimeout -Message $promptMsg -Title $ImportPromptTitle -TimeoutSec $ImportPromptTimeoutSec
        if ($promptRes -and $promptRes.Choice -eq 'Yes') {
            Write-Host "Skipping DSP imports by user choice." -ForegroundColor Yellow
            Write-Log  -Level INFO -Message "DSP import skipped by popup: user chose Yes."

            # Log each skipped candidate + summary (reason=popup)
            $candidateArray = @()
            if ($script:CandidateZips -is [System.Collections.IEnumerable]) { $candidateArray = @($script:CandidateZips) }
            foreach ($c in $candidateArray) { Write-Log -Level INFO -Message "Skipped import [reason=popup]: $c" }
            Write-Log -Level INFO -Message "Skipped import summary [reason=popup]: Count=$($candidateArray.Count)"
            $script:Stats.ImportSkipped += $candidateArray.Count
        } else {
            if ($promptRes.TimedOut) {
                Write-Log -Level INFO -Message "DSP import prompt timed out after $ImportPromptTimeoutSec sec; proceeding with import."
            } else {
                Write-Log -Level INFO -Message "DSP import prompt: user chose No; proceeding with import."
            }

            Write-Host "=== Importing ZIP templates into DSP ===" -ForegroundColor Cyan

            # Build array safely
            $candidateArray = @()
            if ($script:CandidateZips -is [System.Collections.IEnumerable]) { $candidateArray = @($script:CandidateZips) }

            # Capture the single result object directly (no pipeline)
            $importResult = Import-DspTemplates -SourceRoot $root -DspServer 'localhost' -CandidateFiles $candidateArray -DspModulePath $DspModulePath

            # Defensive: only tally if expected properties exist
            if ($importResult -is [pscustomobject] -and
                $importResult.PSObject.Properties.Match('Imported').Count -gt 0 -and
                $importResult.PSObject.Properties.Match('Failed').Count -gt 0) {

                $script:Stats.ImportSuccess += [int]$importResult.Imported
                $script:Stats.ImportFailed  += [int]$importResult.Failed
            }
            else {
                Write-Log -Level WARN -Message "Import result not in expected object form; skipping summary tally."
            }
        }
    }

    # ---- FINAL SUMMARY ----
    Write-Host ""
    Write-Host "================== FINAL SUMMARY ==================" -ForegroundColor Cyan
    Write-Host ("Downloaded ZIPs       : {0}" -f $script:Stats.Downloaded)
    Write-Host ("Up-to-date / Skipped  : {0}" -f $script:Stats.SkippedIdempotent)
    Write-Host ("Skipped (locked)      : {0}" -f $script:Stats.SkippedLocked)
    Write-Host ("Download failures     : {0}" -f $script:Stats.DownloadFailed)
    Write-Host ("Extracted inner files : {0}" -f $script:Stats.ExtractedInner)
    Write-Host ("Imported successfully : {0}" -f $script:Stats.ImportSuccess)
    Write-Host ("Import failures       : {0}" -f $script:Stats.ImportFailed)
    Write-Host ("Imports skipped       : {0}" -f $script:Stats.ImportSkipped)
    Write-Host "===================================================" -ForegroundColor Cyan

    Write-Log -Level INFO -Message ("SUMMARY: Downloaded={0}, UpToDate={1}, SkippedLocked={2}, DownloadFailed={3}, ExtractedInner={4}, ImportSuccess={5}, ImportFailed={6}, ImportSkipped={7}" -f `
        $script:Stats.Downloaded, $script:Stats.SkippedIdempotent, $script:Stats.SkippedLocked, $script:Stats.DownloadFailed, $script:Stats.ExtractedInner, $script:Stats.ImportSuccess, $script:Stats.ImportFailed, $script:Stats.ImportSkipped)

    Write-Host ""
    Write-Host "Log file : $logFile"
    Write-Log -Level INFO -Message "===== Run complete ====="
}

# =====================================================================================
# EXECUTE
# =====================================================================================
try {
    Start-DownloadProcess
}
catch {
    Write-Warning "Fatal error : $($_.Exception.Message)"
    Write-Log -Level ERROR -Message "Fatal script error : $($_.Exception.Message)"
    throw
}
