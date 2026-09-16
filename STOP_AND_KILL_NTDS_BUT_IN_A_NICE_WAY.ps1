<#
Stop_and_KILL_NTDS.ps1

 Stop the Active Directory Domain Services (NTDS) service
 and then KILL it by renaming the DIT file.

 I use this to emulate ransomware for ADFR demos.

 MUST RUN AS ADMINISTRATOR


Rob Ingenthron, Semperis
#>


# Specify the file path
# (In my labs, the DIT is always on C:, but could be in a different location
# so better to add derived location at some point.)
$ditFilePath = "C:\Windows\NTDS\ntds.dit"

# Ensure script is run as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host ""
    Write-Error "You must run this script as Administrator."
    Write-Host ""
    Write-Host "The NTDS service is special and more protected and not directly manageable"
    Write-Host "without running in an 'Administrative' context."
    Write-Host ""
    Write-Host "Run this script in a PowerShell prompt or ISE 'as Administrator'."
    Write-Host ""
    return 1
}
else {
    Write-Host ""
    Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red -BackgroundColor Yellow
    Write-Host ""
    Write-Host "  WARNING!! Emulating ransomware:"
    Write-Host "  This Active Directory domain cotnroller will be incapacitated!!!"
    Write-Host ""
    Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red -BackgroundColor Yellow
    Write-Host ""
}


# Check if NTDS service exists
$service = Get-Service -Name "NTDS" -ErrorAction SilentlyContinue
if (-not $service) {
    Write-Error "NTDS service not found on this system."
    return 1
}

# Check if service is running
if ($service.Status -ne 'Running') {
    Write-Host "NTDS service is not running. No action taken."
    return 0
}

# Confirm with the user to STOP service!!
Write-Host ""
Write-Host "--------------------------------------------------------------" -ForegroundColor yellow -BackgroundColor DarkRed
$confirmation = Read-Host "WARNING: Stopping NTDS will halt Active Directory. Type 'YES' to proceed"
if ($confirmation -eq 'YES') {
    try {
        Stop-Service -Name "NTDS" -Force -ErrorAction Stop
        Write-Host "NTDS service stopped successfully."
    }
    catch {
        Write-Error "Failed to stop NTDS service: $_"
        write-host ""
        return 1
    }
} else {
    Write-Host "Operation cancelled."
    return 0
}

# Confirm with the user to RENAME/DELETE NTDS.DIT!!
Write-Host ""
Write-Host "--------------------------------------------------------------" -ForegroundColor yellow -BackgroundColor DarkRed
$confirmation = Read-Host "!!WARNING: Deleting/Renaming NTDS.DIT will kill this AD domain controller!!`r`n Type 'YES' to proceed"
if ($confirmation -eq 'YES') {
    try {
        if (Test-Path -Path "$($ditFilePath).PWNED") {
            Remove-Item -Path "$($ditFilePath).PWNED" -Force  -ErrorAction Stop
        }
    }
    catch {
        # Nothing to do here
    }

    try {
        if (Test-Path -Path $ditFilePath) {
            #Remove-Item -Path $ditFilePath -Force  -ErrorAction Stop
            Rename-Item -Path $ditFilePath -NewName "$($ditFilePath).PWNED" -Force -ErrorAction Stop
            #Write-Host "File renoved successfully: $ditFilePath"
            Write-Host "File renamed successfully: $($ditFilePath) to $($ditFilePath).PWNED" -ForegroundColor Yellow -BackgroundColor Red
        }
        else {
            Write-Host ""
            Write-Host "File not found: $ditFilePath"
            Write-Host ""
            Write-Host "Was file already renamed or deleted??"
            Write-Host "Perhaps this is not a domain controller."
            Write-Host ""
            return 2
        }

        Write-Host ""
        Write-Host "Active Directory domain controller is incapacitated!!" -ForegroundColor Green -BackgroundColor DarkGray
        Write-Host ""
    }
    catch {
        write-Host ""
        #Write-Error "Failed to delete file '$($ditFilePath)': $_"
        Write-Error "Failed to rename file '$($ditFilePath)': $_"
        write-host ""
        return 1
    }
} else {
    Write-Host ""
    Write-Host "Operation cancelled."
}


Write-Host ""
Write-Host ""
Write-Host "Trying to restart the NTDS (Active Directory Domain Services) service..."
Start-Service -Name "NTDS" -ErrorAction SilentlyContinue
Write-Host ""
(Get-Service -Name "NTDS" -ErrorAction SilentlyContinue)
Write-Host ""
Write-Host ""
(Get-ChildItem -Path $(Split-Path -Path $ditFilePath -Parent)).FullName

