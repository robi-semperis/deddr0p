# Set-CustomUserEnvironmentCustomizations.ps1

<#
.SYNOPSIS
Applies File Explorer view settings to ALL existing user profiles (if elevated), or to the CURRENT
user only (when not elevated). The script will **restart Explorer only if** any of the File
Explorer options were changed (Show extensions, Show hidden items, Restore previous windows), or
when `-RestartIfBordersChanged` is used and the borders value changed. It also ensures C:\bin and
C:\bin\utils exist and are present in the current user’s PATH (idempotent), and sets visible window
borders via UserPreferencesMask.

.DESCRIPTION
This script configures three Windows File Explorer "View" preferences per user under:
HKU\<SID or temp mount>\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced

It sets:
  - HideFileExt     (DWORD) = 0   -> Show file extensions (uncheck "Hide extensions for known file types")
  - Hidden          (DWORD) = 1   -> Show hidden files, folders, and drives
  - PersistBrowsers (DWORD) = 1   -> Restore previous folder windows at logon

For the CURRENT user, it also:
  - Ensures folders exist: C:\bin and C:\bin\utils (with robust error handling, honoring -WhatIf)
  - Adds them to the user PATH if missing (HKCU\Environment\Path) without duplicates (honors -WhatIf)
  - Sets visible window borders by writing HKCU\Control Panel\Desktop\UserPreferencesMask (REG_BINARY)
  - Broadcasts "Environment" change so new processes pick it up immediately (honors -WhatIf)

After writing CURRENT USER settings, the script:
  - **Broadcasts a shell refresh and restarts Explorer only if**:
      * any of the three Explorer options changed, **or**
      * `-RestartIfBordersChanged` was passed **and** the borders value changed.
    If all were already compliant (and no borders-triggered restart is requested), it **skips** both.

When run elevated, it also applies the same Explorer settings for all other non-special user profiles
by loading their user hives when necessary. Other users pick up the new values when they next start
Explorer or sign in. (PATH & borders modifications are applied only to the CURRENT user.)

.PARAMETER SkipBackup
Skip exporting a .reg backup of:
  - Explorer\Advanced for each processed user, and
  - the current user’s Desktop\UserPreferencesMask value.

.PARAMETER IncludeSpecialProfiles
Also process profiles marked as "Special" (e.g., Default, Public). Usually not necessary.

.PARAMETER NoBroadcastRefresh
Suppress the in-place Explorer refresh broadcast for the CURRENT user (broadcast is only considered
when a restart is needed per the conditions above).

.PARAMETER RestartIfBordersChanged
When specified, File Explorer will also be restarted if the borders setting (UserPreferencesMask)
was changed, even if the three Explorer options were already compliant.

.PARAMETER Help
Prints an integrated help page (overview, parameters, examples) and exits without making changes.

.INPUTS
None.

.OUTPUTS
Human-readable status to the console. Uses Write-Verbose for detailed progress when -Verbose is passed.

.EXAMPLE
# Typical run for your own profile (idempotent). Explorer restart occurs only if Explorer options changed,
# or borders changed AND -RestartIfBordersChanged is supplied:
.\Set-CustomUserEnvironmentCustomizations.ps1

.EXAMPLE
# All profiles (Explorer options), skip backups, include Special profiles, verbose tracing:
.\Set-CustomUserEnvironmentCustomizations.ps1 -SkipBackup -IncludeSpecialProfiles -Verbose

.EXAMPLE
# Also restart if the borders value changed (in addition to Explorer options):
.\Set-CustomUserEnvironmentCustomizations.ps1 -RestartIfBordersChanged

.EXAMPLE
# SAFE TEST (no changes applied): Simulate actions and see what would happen.
# -WhatIf honors the registry writes, directory creation, PATH update, broadcasts, and restart.
.\Set-CustomUserEnvironmentCustomizations.ps1 -WhatIf -Verbose

.EXAMPLE
# Apply values but suppress the broadcast step (restart stays conditional):
.\Set-CustomUserEnvironmentCustomizations.ps1 -NoBroadcastRefresh

.NOTES
- PowerShell 5.1 compatible.
- Idempotent: re-running keeps the desired values and does not duplicate PATH entries.
- Errors for one value, user, or path creation are logged and the script continues with others.
- Run elevated to load/unload other users' hives (Explorer settings). PATH & borders changes are for CURRENT user only.

.LINK
Get-Help .\Set-CustomUserEnvironmentCustomizations.ps1 -Full
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
  [switch]$SkipBackup,
  [switch]$IncludeSpecialProfiles,
  [switch]$NoBroadcastRefresh,
  [switch]$RestartIfBordersChanged,
  [switch]$Help
)

# ==============================
# Constants & Desired Values
# ==============================
$AdvSubPath = 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$RegExe     = Join-Path $env:SystemRoot 'System32\reg.exe'

# Desired Explorer view settings (HKCU/HKU per user)
$Desired = [ordered]@{
  HideFileExt     = 0  # 0 = show extensions; 1 = hide extensions
  Hidden          = 1  # 1 = show hidden;    2 = do not show hidden
  PersistBrowsers = 1  # 1 = restore previous folder windows at logon
}

# Desired PATH folders for CURRENT user
$DesiredUserPathEntries = @('C:\bin','C:\bin\utils')

# Desired borders mask (REG_BINARY) for HKCU\Control Panel\Desktop\UserPreferencesMask
# Matches: reg add ... /d 9032078010000000  -> bytes: 90 32 07 80 10 00 00 00
$DesiredUserPreferencesMaskBytes = 0x90,0x32,0x07,0x80,0x10,0x00,0x00,0x00

# ==============================
# Built-in Help (on-demand)
# ==============================
function Show-Help {
  $help = @"
Set-CustomUserEnvironmentCustomizations.ps1
==========================================

PURPOSE
  Applies three File Explorer view preferences for the current user (always), and for
  all existing user profiles when the script is run elevated. The script **restarts Explorer only
  when any of the Explorer options changed**, or when `-RestartIfBordersChanged` is provided and
  the borders value changed. Otherwise, it skips restart.

  Additionally, for the CURRENT user:
  - Creates C:\bin and C:\bin\utils if needed (with robust error handling; honors -WhatIf).
  - Adds both to the user PATH if not already present (idempotent; honors -WhatIf).
  - Sets visible borders (HKCU\Control Panel\Desktop\UserPreferencesMask).
  - Broadcasts "Environment" so new processes pick up the updated PATH (honors -WhatIf).

DEFAULT BEHAVIOR
  - If Explorer options changed, or borders changed with -RestartIfBordersChanged:
      * Broadcast shell refresh (unless -NoBroadcastRefresh) and restart Explorer.
  - Otherwise: skip broadcast and restart.

SAFE TESTING
  - Use **-WhatIf -Verbose** to simulate all actions (registry writes, directory creation,
    PATH update, broadcast, restart) without making changes.

PARAMETERS
  -SkipBackup             Skip .reg backups (Explorer\Advanced for each processed user; current UserPreferencesMask).
  -IncludeSpecialProfiles Include "Special" profiles (Default, Public).
  -NoBroadcastRefresh     Suppress the in-place Explorer refresh broadcast (only considered when restart is needed).
  -RestartIfBordersChanged Also restart Explorer if borders value changed (in addition to Explorer options).
  -Help                   Show this help and exit without making changes.

EXAMPLES
  1) .\Set-CustomUserEnvironmentCustomizations.ps1
  2) .\Set-CustomUserEnvironmentCustomizations.ps1 -SkipBackup -IncludeSpecialProfiles -Verbose
  3) .\Set-CustomUserEnvironmentCustomizations.ps1 -RestartIfBordersChanged
  4) .\Set-CustomUserEnvironmentCustomizations.ps1 -WhatIf -Verbose
  5) .\Set-CustomUserEnvironmentCustomizations.ps1 -NoBroadcastRefresh
"@
  Write-Host $help -ForegroundColor Cyan
}
if ($Help) { Show-Help; return }

# ==============================
# Helper Functions
# ==============================
function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-RegPath {
  param([Parameter(Mandatory)][string]$RootHivePath)
  $full = Join-Path $RootHivePath $AdvSubPath
  if (-not (Test-Path -LiteralPath $full)) {
    Write-Verbose "Creating registry path: $full"
    if ($PSCmdlet.ShouldProcess($full, 'Create registry key')) {
      try {
        New-Item -Path $full -Force -ErrorAction Stop | Out-Null
      } catch {
        Write-Warning ("Failed to create registry path: {0}. {1}" -f $full, $_.Exception.Message)
        throw
      }
    }
  }
  return $full
}

function Set-ExplorerAdvancedValues {
  <#
    .SYNOPSIS
      Writes desired Explorer\Advanced values under the specified hive if needed.
    .OUTPUTS
      [pscustomobject] @{ Changed=[bool]; ChangedItems=[string[]] }
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$RootHivePath,
    [Parameter(Mandatory)][hashtable]$Pairs
  )
  $adv = Ensure-RegPath -RootHivePath $RootHivePath
  $changed = $false
  $changedItems = New-Object System.Collections.Generic.List[string]

  foreach ($kv in $Pairs.GetEnumerator()) {
    $name    = $kv.Key
    $desired = [int]$kv.Value

    $current = $null
    try { $current = (Get-ItemProperty -Path $adv -Name $name -ErrorAction Stop).$name } catch {}

    if ($current -ne $desired) {
      Write-Verbose "Setting $adv\$name : $current -> $desired"
      if ($PSCmdlet.ShouldProcess("$adv\$name", "Set DWORD to $desired")) {
        $attemptOk = $false
        try {
          New-ItemProperty -Path $adv -Name $name -Value $desired -PropertyType DWord -Force -ErrorAction Stop | Out-Null
          $attemptOk = $true
        } catch {
          Write-Verbose ("New-ItemProperty failed for {0}\{1}: {2}" -f $adv, $name, $_.Exception.Message)
        }
        $after = $null
        try { $after = (Get-ItemProperty -Path $adv -Name $name -ErrorAction Stop).$name } catch {}
        if (-not $attemptOk -or $after -ne $desired) {
          try {
            Set-ItemProperty -Path $adv -Name $name -Value $desired -Type DWord -ErrorAction Stop
            $after = (Get-ItemProperty -Path $adv -Name $name -ErrorAction Stop).$name
            $attemptOk = $true
          } catch {
            Write-Verbose ("Set-ItemProperty failed for {0}\{1}: {2}" -f $adv, $name, $_.Exception.Message)
          }
        }
        if (-not $attemptOk -or $after -ne $desired) {
          try {
            Remove-ItemProperty -Path $adv -Name $name -ErrorAction SilentlyContinue
            New-ItemProperty -Path $adv -Name $name -Value $desired -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            $after = (Get-ItemProperty -Path $adv -Name $name -ErrorAction Stop).$name
          } catch {
            Write-Warning ("Failed to write {0}\{1} = {2}. {3}" -f $adv, $name, $desired, $_.Exception.Message)
            continue
          }
        }
        if ($after -eq $desired) {
          $changed = $true
          $changedItems.Add($name) | Out-Null
          Write-Verbose ("Verified {0}\{1} = {2}" -f $adv, $name, $desired)
        } else {
          Write-Warning ("Unable to set {0}\{1} to {2}. Current={3}." -f $adv, $name, $desired, ($after -as [string]))
        }
      }
    } else {
      Write-Verbose "$adv\$name already $desired (no change)"
    }
  }

  [pscustomobject]@{
    Changed      = $changed
    ChangedItems = $changedItems.ToArray()
  }
}

function Export-AdvancedBackup {
  param(
    [Parameter(Mandatory)][string]$HiveNative,
    [Parameter(Mandatory)][string]$Label
  )
  if ($SkipBackup) { return }
  $outDir = Join-Path $env:TEMP 'ExplorerRegBackups'
  if (-not (Test-Path -LiteralPath $outDir)) {
    try { New-Item -ItemType Directory -Path $outDir -ErrorAction Stop | Out-Null } catch {
      Write-Warning ("Failed to create backup directory '{0}': {1}" -f $outDir, $_.Exception.Message)
      return
    }
  }
  $stamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
  $file   = Join-Path $outDir ("Explorer_Advanced_Backup_{0}_{1}.reg" -f $Label, $stamp)
  Write-Verbose "Exporting backup: $HiveNative -> $file"
  if ($PSCmdlet.ShouldProcess($HiveNative, "Export registry backup")) {
    try {
      $p = Start-Process -FilePath $RegExe -ArgumentList @('export', $HiveNative, $file, '/y') `
           -PassThru -NoNewWindow -Wait -ErrorAction Stop
      if ($p.ExitCode -eq 0) {
        Write-Host "Backup saved: $file" -ForegroundColor Green
      } else {
        Write-Warning "Backup export returned ExitCode $($p.ExitCode) for $HiveNative."
      }
    } catch {
      Write-Warning ("Backup export failed for {0}: {1}" -f $HiveNative, $_.Exception.Message)
    }
  }
}

function Get-UserProfiles {
  try {
    $profiles = Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object {
      $_.LocalPath -and (Test-Path $_.LocalPath)
    }
  } catch {
    Write-Warning ("Failed to enumerate user profiles: {0}" -f $_.Exception.Message)
    $profiles = @()
  }
  if (-not $IncludeSpecialProfiles) {
    $profiles = $profiles | Where-Object { -not $_.Special }
  }
  return $profiles
}

function Is-ProfileLoaded { param([string]$Sid) return Test-Path -LiteralPath ("HKU:\{0}" -f $Sid) }

function Load-UserHive {
  param([Parameter(Mandatory)][string]$NtUserDatPath, [Parameter(Mandatory)][string]$MountName)
  $nativeMount = "HKU\$MountName"
  Write-Verbose "Loading hive: $NtUserDatPath -> $nativeMount"
  $args = @('load', $nativeMount, $NtUserDatPath)
  try {
    $p = Start-Process -FilePath $RegExe -ArgumentList $args -PassThru -NoNewWindow -Wait -ErrorAction Stop
    if ($p.ExitCode -ne 0) { throw "reg.exe load returned ExitCode $($p.ExitCode)" }
  } catch { throw "Failed to load hive from '$NtUserDatPath' ($_)"}
  return "HKU:\$MountName"
}

function Unload-UserHive {
  param([Parameter(Mandatory)][string]$MountName)
  $nativeMount = "HKU\$MountName"
  Write-Verbose "Unloading hive: $nativeMount"
  $args = @('unload', $nativeMount)
  try {
    $p = Start-Process -FilePath $RegExe -ArgumentList $args -PassThru -NoNewWindow -Wait -ErrorAction Stop
    if ($p.ExitCode -ne 0) { Write-Warning "Failed to unload hive $nativeMount (ExitCode $($p.ExitCode))." }
  } catch { Write-Warning ("Failed to unload hive {0}: {1}" -f $nativeMount, $_.Exception.Message) }
}

# ==============================
# Native interop (Shell + User32)
# ==============================
if (-not ("User32Native" -as [type])) {
  Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class User32Native {
    public static readonly IntPtr HWND_BROADCAST = (IntPtr)0xffff;
    public const uint WM_SETTINGCHANGE = 0x001A;
    public const uint SMTO_ABORTIFHUNG = 0x0002;

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
        uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
}

public static class Shell32Native {
    public const int  SHCNE_ASSOCCHANGED = 0x08000000;
    public const uint SHCNF_IDLIST       = 0x0;

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    public static extern void SHChangeNotify(int wEventId, uint uFlags, IntPtr dwItem1, IntPtr dwItem2);
}
"@
}

# ==============================
# Broadcast helpers (honor -WhatIf)
# ==============================
function Invoke-ExplorerSettingsRefresh {
  [CmdletBinding()]
  param([string]$SettingsKey = 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced', [int]$TimeoutMs = 1000)
  if ($NoBroadcastRefresh) { return }
  if (-not $PSCmdlet.ShouldProcess("Explorer shell", "Broadcast settings refresh")) { return }

  Write-Verbose "Shell refresh: SHChangeNotify(SHCNE_ASSOCCHANGED)"
  try {
    [Shell32Native]::SHChangeNotify([Shell32Native]::SHCNE_ASSOCCHANGED, [Shell32Native]::SHCNF_IDLIST, [IntPtr]::Zero, [IntPtr]::Zero)
  } catch { Write-Warning ("SHChangeNotify failed: {0}" -f $_.Exception.Message) }

  Write-Verbose "Broadcast WM_SETTINGCHANGE to HWND_BROADCAST (lParam='$SettingsKey')"
  try {
    [UIntPtr]$result = [UIntPtr]::Zero
    [void][User32Native]::SendMessageTimeout(
      [User32Native]::HWND_BROADCAST,
      [User32Native]::WM_SETTINGCHANGE,
      [UIntPtr]::Zero,
      $SettingsKey,
      [User32Native]::SMTO_ABORTIFHUNG,
      [uint32]$TimeoutMs,
      [ref]$result
    )
  } catch { Write-Warning ("WM_SETTINGCHANGE broadcast failed: {0}" -f $_.Exception.Message) }
}

function Invoke-EnvironmentRefresh {
  [CmdletBinding()]
  param([int]$TimeoutMs = 1000)
  if (-not $PSCmdlet.ShouldProcess("System environment", "Broadcast environment change")) { return }

  Write-Verbose "Broadcast WM_SETTINGCHANGE (Environment)"
  try {
    [UIntPtr]$result = [UIntPtr]::Zero
    [void][User32Native]::SendMessageTimeout(
      [User32Native]::HWND_BROADCAST,
      [User32Native]::WM_SETTINGCHANGE,
      [UIntPtr]::Zero,
      'Environment',
      [User32Native]::SMTO_ABORTIFHUNG,
      [uint32]$TimeoutMs,
      [ref]$result
    )
  } catch { Write-Warning ("Environment broadcast failed: {0}" -f $_.Exception.Message) }
}

# ==============================
# PATH helpers (CURRENT user) — robust + honors -WhatIf
# ==============================
function Resolve-NormalizedPath {
  param([Parameter(Mandatory)][string]$Path)
  try { $full = [System.IO.Path]::GetFullPath($Path) } catch { $full = $Path }
  if ($full.Length -gt 3) { $full = $full.TrimEnd('\') }
  return $full
}

function Ensure-DirectoryExists {
  <#
    .SYNOPSIS
      Ensures a directory exists with detailed error handling.
    .OUTPUTS
      [pscustomobject] @{ Success=[bool]; Path=[string]; ErrorMessage=[string] }
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  $norm = Resolve-NormalizedPath -Path $Path
  if (Test-Path -LiteralPath $norm -PathType Container) {
    Write-Verbose "Directory already exists: $norm"
    return [pscustomobject]@{ Success=$true; Path=$norm; ErrorMessage=$null }
  }

  try { $root = [System.IO.Path]::GetPathRoot($norm) } catch { $root = $null }
  if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root)) {
    $msg = "Drive or root path not available for '$norm'."
    Write-Warning $msg
    return [pscustomobject]@{ Success=$false; Path=$norm; ErrorMessage=$msg }
  }

  Write-Verbose "Creating directory: $norm"
  if (-not $PSCmdlet.ShouldProcess($norm, "Create directory")) {
    return [pscustomobject]@{ Success=$true; Path=$norm; ErrorMessage=$null }  # simulate success for -WhatIf
  }

  try {
    New-Item -ItemType Directory -Path $norm -Force -ErrorAction Stop | Out-Null
    Write-Host "Created directory: $norm" -ForegroundColor Green
    return [pscustomobject]@{ Success=$true; Path=$norm; ErrorMessage=$null }
  } catch [System.UnauthorizedAccessException] {
    $msg = "Access denied creating '$norm'. Try running PowerShell as Administrator."
    Write-Warning $msg; return [pscustomobject]@{ Success=$false; Path=$norm; ErrorMessage=$msg }
  } catch [System.IO.IOException] {
    $msg = "I/O error creating '$norm': $($_.Exception.Message)"
    Write-Warning $msg; return [pscustomobject]@{ Success=$false; Path=$norm; ErrorMessage=$msg }
  } catch {
    $msg = "Unexpected error creating '$norm': $($_.Exception.Message)"
    Write-Warning $msg; return [pscustomobject]@{ Success=$false; Path=$norm; ErrorMessage=$msg }
  }
}

function Ensure-UserPathIncludes {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string[]]$AddPaths)

  $currentPath = [Environment]::GetEnvironmentVariable('Path','User'); if ($null -eq $currentPath) { $currentPath = '' }
  $sep   = ';'
  $parts = $currentPath -split ';' | ForEach-Object { $_.Trim().Trim('"') } | Where-Object { $_ -ne '' }

  $normalized = New-Object System.Collections.Generic.List[string]
  foreach ($p in $parts) { $normalized.Add( (Resolve-NormalizedPath -Path $p).ToLowerInvariant() ) }

  $added   = @()
  $missing = @()

  foreach ($p in $AddPaths) {
    $norm = Resolve-NormalizedPath -Path $p
    if (-not (Test-Path -LiteralPath $norm -PathType Container)) {
      Write-Warning ("Skipping PATH add for '{0}' because it does not exist." -f $norm)
      $missing += $norm; continue
    }
    $key = $norm.ToLowerInvariant()
    if (-not $normalized.Contains($key)) {
      Write-Verbose "Adding to PATH: $norm"
      $parts += $norm; $normalized.Add($key); $added += $norm
    } else { Write-Verbose "PATH already contains: $norm" }
  }

  if ($added.Count -gt 0) {
    $newPath = ($parts -join $sep)
    if ($PSCmdlet.ShouldProcess("HKCU: Environment Path", "Update user PATH")) {
      try {
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Write-Host ("Updated user PATH (added: {0})" -f ($added -join ', ')) -ForegroundColor Green
      } catch { Write-Warning ("Failed to update user PATH: {0}" -f $_.Exception.Message) }
    }
  } else { Write-Verbose "User PATH not changed (entries already present or skipped)." }

  if ($missing.Count -gt 0) {
    Write-Warning ("The following directories were not added to PATH because they do not exist: {0}" -f ($missing -join ', '))
  }
}

function Ensure-BinPaths {
  [CmdletBinding()]
  param([string[]]$Paths = $DesiredUserPathEntries)

  $successPaths = New-Object System.Collections.Generic.List[string]
  $failed       = New-Object System.Collections.Generic.List[string]

  foreach ($p in $Paths) {
    $result = Ensure-DirectoryExists -Path $p
    if ($result.Success) { $successPaths.Add($result.Path) | Out-Null }
    else { $failed.Add(("{0} → {1}" -f $result.Path, $result.ErrorMessage)) | Out-Null }
  }

  if ($successPaths.Count -gt 0) {
    Ensure-UserPathIncludes -AddPaths $successPaths.ToArray()
    Invoke-EnvironmentRefresh -TimeoutMs 1000
  }

  if ($failed.Count -gt 0) {
    Write-Warning "Some requested directories could not be created:"
    $failed | ForEach-Object { Write-Warning " - $_" }
  }
}

# ==============================
# Visible borders (CURRENT user) — UserPreferencesMask
# ==============================
function Export-DesktopUPMBackup {
  param([string]$Label = 'HKCU-Desktop-UPM')
  if ($SkipBackup) { return }
  $outDir = Join-Path $env:TEMP 'ExplorerRegBackups'
  if (-not (Test-Path -LiteralPath $outDir)) { try { New-Item -ItemType Directory -Path $outDir -ErrorAction Stop | Out-Null } catch { return } }
  $stamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
  $file   = Join-Path $outDir ("Desktop_UserPreferencesMask_Backup_{0}_{1}.reg" -f $Label, $stamp)
  if ($PSCmdlet.ShouldProcess('HKCU\Control Panel\Desktop', 'Export Desktop key backup')) {
    try {
      Start-Process -FilePath $RegExe -ArgumentList @('export','HKCU\Control Panel\Desktop',$file,'/y') -PassThru -NoNewWindow -Wait | Out-Null
      Write-Host "Backup (UserPreferencesMask) saved: $file" -ForegroundColor Green
    } catch { Write-Warning "Failed to export HKCU\Control Panel\Desktop backup: $($_.Exception.Message)" }
  }
}

function Set-VisibleWindowBorders {
  <#
    .SYNOPSIS
      Sets HKCU\Control Panel\Desktop\UserPreferencesMask to a REG_BINARY that enables visible window borders.
      Equivalent to: reg add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9032078010000000 /f
    .OUTPUTS
      [pscustomobject] @{ Changed=[bool] }
  #>
  [CmdletBinding()]
  param([byte[]]$Bytes = $DesiredUserPreferencesMaskBytes)

  $desktopKey = 'HKCU:\Control Panel\Desktop'
  try {
    if (-not (Test-Path -LiteralPath $desktopKey)) {
      Write-Verbose "Creating $desktopKey"
      if ($PSCmdlet.ShouldProcess($desktopKey, 'Create registry key')) {
        New-Item -Path $desktopKey -Force | Out-Null
      } else { return [pscustomobject]@{ Changed = $false } }
    }
  } catch {
    Write-Warning ("Unable to ensure '{0}': {1}" -f $desktopKey, $_.Exception.Message)
    return [pscustomobject]@{ Changed = $false }
  }

  # Check existing
  $equal = $false
  try {
    $readBack = (Get-ItemProperty -Path $desktopKey -Name 'UserPreferencesMask' -ErrorAction Stop).'UserPreferencesMask'
    if ($readBack -and ($readBack.Length -eq $Bytes.Length)) {
      $equal = $true
      for ($i=0;$i -lt $Bytes.Length;$i++){ if ($readBack[$i] -ne $Bytes[$i]){ $equal = $false; break } }
    }
  } catch { $equal = $false }

  if ($equal) {
    Write-Verbose "UserPreferencesMask already matches desired value."
    return [pscustomobject]@{ Changed = $false }
  }

  Export-DesktopUPMBackup

  if ($PSCmdlet.ShouldProcess("$desktopKey\UserPreferencesMask","Set REG_BINARY (visible borders)")) {
    try {
      New-ItemProperty -Path $desktopKey -Name 'UserPreferencesMask' -Value $Bytes -PropertyType Binary -Force -ErrorAction Stop | Out-Null
    } catch {
      Write-Verbose "New-ItemProperty (Binary) failed: $($_.Exception.Message)"
      try { Set-ItemProperty -Path $desktopKey -Name 'UserPreferencesMask' -Value $Bytes -ErrorAction Stop }
      catch { Write-Warning ("Failed to set UserPreferencesMask: {0}" -f $_.Exception.Message); return [pscustomobject]@{ Changed = $false } }
    }
  } else { return [pscustomobject]@{ Changed = $false } }

  # Verify
  try {
    $readBack2 = (Get-ItemProperty -Path $desktopKey -Name 'UserPreferencesMask' -ErrorAction Stop).'UserPreferencesMask'
    $ok = ($readBack2 -and ($readBack2.Length -eq $Bytes.Length))
    if ($ok) {
      for ($i=0;$i -lt $Bytes.Length;$i++){ if ($readBack2[$i] -ne $Bytes[$i]){ $ok = $false; break } }
    }
    if ($ok) {
      Write-Host "UserPreferencesMask set successfully (visible borders enabled)." -ForegroundColor Green
      return [pscustomobject]@{ Changed = $true }
    } else {
      Write-Warning "UserPreferencesMask verification mismatch; a sign-out may be required on some builds."
      return [pscustomobject]@{ Changed = $true }
    }
  } catch {
    Write-Warning ("Could not verify UserPreferencesMask: {0}" -f $_.Exception.Message)
    return [pscustomobject]@{ Changed = $true }
  }
}

# ==============================
# Explorer Restart (current session; CONDITIONAL)
# ==============================
function Restart-ExplorerCurrentSession {
  [CmdletBinding()]
  param()
  if (-not $PSCmdlet.ShouldProcess("Explorer (current session)", "Restart Explorer")) { return }
  try {
    $procs = Get-Process -Name explorer -ErrorAction SilentlyContinue
    if ($procs) { Write-Verbose "Stopping explorer.exe ..."; $procs | Stop-Process -Force; Start-Sleep -Milliseconds 600 }
    Write-Verbose "Starting explorer.exe ..."; Start-Process explorer.exe | Out-Null
  } catch { Write-Warning ("Explorer restart failed: {0}" -f $_.Exception.Message) }
}

# ==============================
# Elevation Check & Warning
# ==============================
$IsElevated = Test-Admin
if (-not $IsElevated) {
  Write-Host ""
  Write-Host "WARNING:" -ForegroundColor Yellow
  Write-Host "This script must be run elevated (as Administrator) to load/unload other users' hives." -ForegroundColor Red
  Write-Host "Continuing with CURRENT USER changes only (HKCU). Re-run as Administrator to apply to all profiles." -ForegroundColor Yellow
  Write-Host ""
}

# ==============================
# CURRENT USER (always)
# ==============================
Write-Verbose "Applying view settings to CURRENT user (HKCU)..."
Write-Host "Applying settings to CURRENT user (HKCU)..." -ForegroundColor Cyan

$explorerResult = $null
try { $explorerResult = Set-ExplorerAdvancedValues -RootHivePath 'HKCU:' -Pairs $Desired }
catch { Write-Warning ("Failed to apply settings to HKCU: {0}" -f $_.Exception.Message); $explorerResult = [pscustomobject]@{ Changed=$false; ChangedItems=@() } }

if (-not $SkipBackup) { Export-AdvancedBackup -HiveNative ("HKCU\{0}" -f $AdvSubPath) -Label 'HKCU' }

# Ensure C:\bin and C:\bin\utils exist and are present on PATH for CURRENT user
Write-Host "Ensuring C:\bin and C:\bin\utils exist and are on PATH for the current user..." -ForegroundColor Cyan
if ($PSBoundParameters.ContainsKey('Verbose') -and $VerbosePreference -eq 'Continue') { Ensure-BinPaths -Paths $DesiredUserPathEntries -Verbose }
else { Ensure-BinPaths -Paths $DesiredUserPathEntries }

# Set visible borders (returns whether a change occurred)
Write-Host "Enabling visible window borders (UserPreferencesMask) for the current user..." -ForegroundColor Cyan
$borderResult = Set-VisibleWindowBorders -Verbose:$VerbosePreference

# Determine if we need to broadcast and restart
$shouldRestart = $false
if ($explorerResult.Changed) { $shouldRestart = $true }
elseif ($RestartIfBordersChanged -and $borderResult.Changed) { $shouldRestart = $true }

if ($shouldRestart) {
  if (-not $NoBroadcastRefresh) { Invoke-ExplorerSettingsRefresh -Verbose }
  else { Write-Verbose "Broadcast refresh suppressed via -NoBroadcastRefresh." }

  Write-Host "Conditions met for Explorer restart. Restarting Explorer ..." -ForegroundColor Yellow
  Restart-ExplorerCurrentSession
} else {
  Write-Host "Explorer options already in desired state and no borders-triggered restart requested; skipping restart." -ForegroundColor Green
}

# ==============================
# ALL PROFILES (when elevated) - Explorer settings only
# ==============================
if ($IsElevated) {
  Write-Verbose "Enumerating user profiles..."
  $profiles = Get-UserProfiles
  if (-not $profiles -or $profiles.Count -eq 0) {
    Write-Host "No user profiles found to process." -ForegroundColor Yellow
  } else {
    $summary = New-Object System.Collections.Generic.List[psobject]

    foreach ($p in $profiles) {
      $sid      = $p.SID
      $userPath = $p.LocalPath
      $label    = ($sid -replace '[^a-zA-Z0-9\-]', '_')

      Write-Host "Processing profile: SID=$sid  Path=$userPath  (Loaded=$($p.Loaded))" -ForegroundColor Cyan
      try {
        if (Is-ProfileLoaded -Sid $sid) {
          try { Set-ExplorerAdvancedValues -RootHivePath ("HKU:\$sid") -Pairs $Desired } catch {
            Write-Warning ("Failed to set values for HKU:\{0}: {1}" -f $sid, $_.Exception.Message)
          }
          if (-not $SkipBackup) { Export-AdvancedBackup -HiveNative ("HKU\{0}\{1}" -f $sid, $AdvSubPath) -Label $label }
        } else {
          $ntuser = Join-Path $userPath 'NTUSER.DAT'
          if (-not (Test-Path -LiteralPath $ntuser)) {
            Write-Warning ("View settings: NTUSER.DAT not found for SID={0} at {1}. Skipping." -f $sid, $userPath)
            $summary.Add([pscustomobject]@{ SID=$sid; Path=$userPath; Mode='Skipped'; Result='No NTUSER.DAT' })
            continue
          }
          $mount = "_EXPLTMP_{0}" -f ($sid -replace '[^a-zA-Z0-9\-]', '_')
          try {
            $root = Load-UserHive -NtUserDatPath $ntuser -MountName $mount
            try { Set-ExplorerAdvancedValues -RootHivePath $root -Pairs $Desired } catch {
              Write-Warning ("Failed to set values for mounted hive {0}: {1}" -f $mount, $_.Exception.Message)
            }
            if (-not $SkipBackup) { Export-AdvancedBackup -HiveNative ("HKU\{0}\{1}" -f $mount, $AdvSubPath) -Label $label }
          } catch { Write-Warning ("Hive load failed for SID={0}: {1}" -f $sid, $_.Exception.Message) }
          finally { Unload-UserHive -MountName $mount }
        }
        # Note: PATH & borders changes apply only to CURRENT user in this script.
        $summary.Add([pscustomobject]@{ SID=$sid; Path=$userPath; Mode='Processed'; Result='OK' })
      } catch {
        Write-Warning ("Failed to update profile SID={0} ({1}). {2}" -f $sid, $userPath, $_.Exception.Message)
        $summary.Add([pscustomobject]@{ SID=$sid; Path=$userPath; Mode='Processed'; Result='ERROR' })
      }
    }

    Write-Host "`nSummary (all profiles):" -ForegroundColor Cyan
    $summary | Sort-Object SID | Format-Table -AutoSize
  }
}

Write-Host "`nDone." -ForegroundColor Green
