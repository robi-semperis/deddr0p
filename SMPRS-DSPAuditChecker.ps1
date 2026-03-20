<#
    Semperis Community DSP Audit checker

    Developed by Evgenij Smirnov (evgenijs@semperis.com) in the Spring of 2024.

    Based on the outstanding work of Derek Weigel (derekw@semperis.com) in 2022.

    Improvements from Derek's script:
    
    - Added Audit Policy subcategories required for IRP
    - Audit Policy evaluation is language-independent
    - Audit Policy evaluation does not use auditpol.exe so no process creation activity
    - Effective Audit Policy evaluation on DCs is done by either PSRemoting or Remote WMI, 
      the preferred protocol is selectable
    - Included auditing of the right 'Write SACL' (SystemAccess)
    - No dependency on ActiveDirectory module or ADWS
    - Group Policy evaluation (what policies potentially acting on DCs have audit policies or subcategory policy set)
    - If the user running the script is from a different forest than the machine the script is being executed on, 
      it is possible to specify the machine's forest for scanning.

    Omissions from Derek's script:

    - Selecting a subset of DCs is not implemented yet

    If running on DC, the script must run elevated in order to retrieve the effective audit policy. It is therefore NOT recommended to run it on a DC.
    If running in a multidomain forest, Enterprise Admin credentials will provide the most complete result.
    
    Build date: 2024-03-29

    Change log:
    
    2024-03-29 First limited release

#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('SACL','AuditPolicy','GroupPolicy')]
    [string[]]$Inspect = @('SACL','AuditPolicy','GroupPolicy'),
    [Parameter(Mandatory=$false)]
    [switch]$SkipDNS,
    [Parameter(Mandatory=$false)]
    [switch]$SetSACL,
    [Parameter(Mandatory=$false)]
    [switch]$IncludeIRP,
    [Parameter(Mandatory=$false)]
    [switch]$MachineForest,
    [Parameter(Mandatory=$false)]
    [switch]$ExportToFile,
    [Parameter(Mandatory=$false)]
    [switch]$LogToConsole,
    # Log Level: 0=DEBUG, 1=VERBOSE, 2=INFO, 3=WARNING, 4=ERROR, 5=CRITICAL
    [Parameter(Mandatory=$false)]
    [ValidateRange(0,5)]
    [int]$LogLevel = 2,
    [Parameter(Mandatory=$false)]
    [ValidateSet('PSRemoting','WMI')]
    [string]$PreferProtocol = 'PSRemoting',
    [Parameter(Mandatory=$false)]
    [ValidateRange(1,120)]
    [int]$WaitForWMI = 5
)
#region function definitions

function Get-DomainControllersOU {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )
    try {
        $rootDSE = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$Domain/rootDSE")
        $rootDSE.RefreshCache()
        $domainNC = $rootDSE.defaultNamingContext[0]
        $domainEntry = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$Domain/$domainNC")
        $domainEntry.RefreshCache()
        foreach ($wko in $domainEntry.wellKnownObjects) {
            $type = $wko.GetType()
            $dn = $type.InvokeMember("DNString", [System.Reflection.BindingFlags]::GetProperty, $null, $wko, $null)
            $guidarr = $type.InvokeMember("BinaryValue", [System.Reflection.BindingFlags]::GetProperty, $null, $wko, $null)
            $guid = ([System.Guid]::new($guidarr)).Guid
            if ($guid -eq 'ffb261a3-d2ff-d111-aa4b-00c04fd7d83a') { return $dn }
        }
    } catch {}
}

function Get-DSAudit {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ObjectDN,
        [Parameter(Mandatory=$false)]
        [string]$Server
    )
    try {
        $o = Get-DSObject -ObjectDN $ObjectDN -Server $Server
        $s = New-Object System.DirectoryServices.DirectorySearcher($o)
        $null = $s.PropertiesToLoad.Add("ntSecurityDescriptor")
        $s.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Sacl
        $z = $s.FindOne()
        $rules = [System.Security.AccessControl.RawSecurityDescriptor]::new([byte[]]($z.Properties["ntSecurityDescriptor"][0]),0).SystemAcl.Where({$_.SecurityIdentifier.Value -eq 'S-1-1-0'})
    } catch {
        $rules = $null
    }
    $mask = @{
        1 = 'CREATE_CHILD'
        2 = 'DELETE_CHILD'
        4 = 'LIST'
        8 = 'EXTENDED_WRITE'
        16 = 'READ_PROPERTY'
        32 = 'WRITE_PROPERTY'
        64 = 'DELETE_TREE'
        128 = 'LIST_OBJECT'
        256 = 'CONTROL_ACCESS'
        65536 = 'DELETE'
        131072 = 'READ_ACL'
        262144 = 'WRITE_DACL'
        524288 = 'WRITE_OWNER'
        16777216 = 'WRITE_SACL'
    }
    $res = @()
    foreach ($rule in $rules) {
        if ($rule.ObjectAceFlags) { continue }
        if (($rule.AuditFlags.value__ -band 1) -eq 0) { continue }
        if (($rule.InheritanceFlags.value__ -band 1) -eq 0) { continue }
        foreach ($bit in $mask.Keys) {
            if (($rule.AccessMask -band $bit) -gt 0) {
                if ($res -notcontains $mask[$bit]) { $res += $mask[$bit] }
            }
        }
    }
    return $res
}

function Get-DSChildren {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ParentDN,
        [Parameter(Mandatory=$false)]
        [string]$LDAPFilter = "(objectClass=*)",
        [Parameter(Mandatory=$false)]
        [switch]$SearchSubtree,
        [Parameter(Mandatory=$false)]
        [string[]]$Properties,
        [Parameter(Mandatory=$false)]
        [switch]$SearchResults,
        [Parameter(Mandatory=$false)]
        [string]$Server
    )
    $parentParms = @{
        'ObjectDN' = $ParentDN
    }
    if ($PSBoundParameters.ContainsKey("Server")) {
        $parentParms.Add('Server', $Server)
    }
    $parent = Get-DSObject @parentParms
    if ($parent -ne $false) {
        $res = @()
        $ds = New-Object System.DirectoryServices.DirectorySearcher
        $ds.SearchRoot = $parent
        $ds.Filter = $LDAPFilter
        if ($SearchSubtree) {
            $ds.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        } else {
            $ds.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
        }
        $ds.PageSize = 1000
        if ($SearchResults) {
            foreach ($prop in $Properties) {
                $null = $ds.PropertiesToLoad.Add($prop)
            }
        }
        $ds.FindAll().ForEach({
            if ($SearchResults) {
                $item = $_
            } else {
                $item = $_.GetDirectoryEntry()
            }
            $res += $item
        })
        return $res
    } else {
        return $false
    }
}

function Get-DSObject {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$ObjectDN = "RootDSE",
        [Parameter(Mandatory=$false)]
        [string]$Server
    )
    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $pathPrefix = "LDAP://$($Server)/"
    } else {
        $pathPrefix = "LDAP://"
    }
    try {
        $dsE = New-Object System.DirectoryServices.DirectoryEntry("$($pathPrefix)$ObjectDN") -EA Stop
        $dsE.RefreshCache()
        return $dsE
    } catch {
        Write-ScriptLog ('Errror getting {0} from server [{1}]: {2}' -f $ObjectDN, $Server, $_.Exception.Message) -Level 4
        return $false
    }
}

function Get-Forest {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [switch]$Machine
    )
    if ($Machine) {
        $wmiCS = Get-WmiObject Win32_ComputerSystem
        if (-not $wmiCS.PartOfDomain) {
            Write-ScriptLog 'Computer is not part of a domain, aborting!' -Level 5
            return $null
        }
        $tgtDomain = $wmics.Domain
        Write-ScriptLog ('Computer is part of domain: {0}' -f $tgtDomain) -Level 2
    } else {
        $tgtDomain = ($env:USERDNSDOMAIN).ToLower()
        Write-ScriptLog ('User is part of domain: {0}' -f $tgtDomain) -Level 2
    }
    $tgtRootDSE = Get-DSObject -Server $tgtDomain
    if ($tgtRootDSE -eq $false) { return $null }
    $rootPart = Get-DSChildren -ParentDN ('CN=Partitions,{0}' -f $tgtRootDSE.configurationNamingContext[0]) -LDAPFilter ('(ncName={0})' -f $tgtRootDSE.rootDomainNamingContext[0]) -Server $tgtDomain
    if ($rootPart -ne $false) {
        $rootFQDN = $rootPart[0].Properties['dnsRoot'][0]
    } else {
        $rootFQDN = $null
    }
    if ($null -ne $rootFQDN) {
        $newRootDSE = Get-DSObject -Server $rootFQDN
        $dc = $newRootDSE.dnsHostName[0]
    } else {
        $dc = $tgtRootDSE.dnsHostName[0]
    }
    $out = [PSCustomObject]@{
        'RootNC' = $tgtRootDSE.rootDomainNamingContext[0]
        'SchemaNC' = $tgtRootDSE.schemaNamingContext[0]
        'ConfigNC' = $tgtRootDSE.configurationNamingContext[0]
        'RootFQDN' = $rootFQDN
        'DCFound' = $dc
    }
    return $out
}

function Write-ScriptLog {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$false)]
        [ValidateRange(0,5)]
        [int]$Level = 0
    )
    if ($Level -gt $script:MaxLoggedLevel) { $script:MaxLoggedLevel = $Level }
    if ($Level -lt $script:LogLevel) { return }
    if ($null -eq $script:LogPath) {
        $script:LogPath = Join-Path -Path $env:TEMP -ChildPath ('{0}-DSPAuditChecker.log' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
        Write-Host ('Logging at level {1} to: {0}' -f $script:LogPath, $script:LogLevel) -ForegroundColor Gray
    }
    switch($Level) {
        0 { $clr = 'DarkGray'; $lvl = 'DEBUG' }
        1 { $clr = 'Gray'; $lvl = 'VERBOSE' }
        2 { $clr = 'Green'; $lvl = 'INFO' }
        3 { $clr = 'Yellow'; $lvl = 'WARNING' }
        4 { $clr = 'Red'; $lvl = 'ERROR' }
        5 { $clr = 'Magenta'; $lvl = 'CRITICAL' }
    }
    $outMsg = ('{0} {1,-8} {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $lvl, $Message)
    if ($script:LogToConsole) {
        Write-Host $outMsg -ForegroundColor $clr
    }
    $outMsg | Out-File -FilePath $script:LogPath -Encoding utf8 -Append -Force
}

#endregion
<#
    MAIN DSP AUDIT CHECKER SCRIPT
#>
#region init log
$script:LogPath = $null
$startDate = Get-Date
Write-ScriptLog ('DSP Audit Checker starting on {0} as {1}\{2}' -f $env:COMPUTERNAME, $env:USERDOMAIN, $env:USERNAME) -Level 2
#endregion
#region constants and globals
$script:MaxLoggedLevel = 0
$auditExpected = @{
	'0cce9230-69ae-11d9-bed3-505054503030' = ([PSCustomObject]@{'Name' = 'Authentication Policy Change'; 'Category' = 'Policy Change'; 'Success' = $true; 'Failure' = $false});
	'0cce9235-69ae-11d9-bed3-505054503030' = ([PSCustomObject]@{'Name' = 'User Account Management'; 'Category' = 'Account Management'; 'Success' = $true; 'Failure' = $false});
	'0cce9236-69ae-11d9-bed3-505054503030' = ([PSCustomObject]@{'Name' = 'Computer Account Management'; 'Category' = 'Account Management'; 'Success' = $true; 'Failure' = $false});
	'0cce9237-69ae-11d9-bed3-505054503030' = ([PSCustomObject]@{'Name' = 'Security Group Management'; 'Category' = 'Account Management'; 'Success' = $true; 'Failure' = $false});
	'0cce9238-69ae-11d9-bed3-505054503030' = ([PSCustomObject]@{'Name' = 'Distribution Group Management'; 'Category' = 'Account Management'; 'Success' = $true; 'Failure' = $false});
	'0cce9239-69ae-11d9-bed3-505054503030' = ([PSCustomObject]@{'Name' = 'Application Group Management'; 'Category' = 'Account Management'; 'Success' = $true; 'Failure' = $false});
	'0cce923a-69ae-11d9-bed3-505054503030' = ([PSCustomObject]@{'Name' = 'Other Account Management Events'; 'Category' = 'Account Management'; 'Success' = $true; 'Failure' = $false});
	'0cce923c-69ae-11d9-bed3-505054503030' = ([PSCustomObject]@{'Name' = 'Directory Service Changes'; 'Category' = 'DS Access'; 'Success' = $true; 'Failure' = $false});
}
if ($IncludeIRP) {
    $auditExpected += @{
	    '0cce9215-69ae-11d9-bed3-505054503030' = ([PSCustomObject]@{'Name' = 'Logon'; 'Category' = 'Logon/Logoff'; 'Success' = $true; 'Failure' = $true});
	    '0cce923f-69ae-11d9-bed3-505054503030' = ([PSCustomObject]@{'Name' = 'Credential Validation'; 'Category' = 'Account Logon'; 'Success' = $true; 'Failure' = $true});
	    '0cce9240-69ae-11d9-bed3-505054503030' = ([PSCustomObject]@{'Name' = 'Kerberos Service Ticket Operations'; 'Category' = 'Account Logon'; 'Success' = $true; 'Failure' = $true});
	    '0cce9242-69ae-11d9-bed3-505054503030' = ([PSCustomObject]@{'Name' = 'Kerberos Authentication Service'; 'Category' = 'Account Logon'; 'Success' = $true; 'Failure' = $true});
    }
}
if ($Inspect -contains 'AuditPolicy') {
    $dcTest = @'
& {
    $def = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Audit
{
    public class Pol
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, PreserveSig = true, SetLastError = true)]
        public static extern bool AuditEnumerateSubCategories(Guid AuditCategoryGuid, bool RetrieveAllSubCategories, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] out Guid[] auditSubCategories, out uint numSubCategories);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, PreserveSig = true, SetLastError = true)]
        public static extern bool AuditQuerySystemPolicy([MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1), In] Guid[] pSubCategoryGuids, uint dwPolicyCount, out IntPtr ppAuditPolicy);

        public static AUDIT_POLICY_INFORMATION QueryPolicy(Guid sc)
        {
            IntPtr ppAuditPolicy;
            if (AuditQuerySystemPolicy(new Guid[] {sc}, 1, out ppAuditPolicy)) {
                return ToStructure<AUDIT_POLICY_INFORMATION>(ppAuditPolicy);
            }
            return new AUDIT_POLICY_INFORMATION();
        }

        public static T ToStructure<T>(IntPtr ptr, long allocatedBytes = -1)
        {
            Type type = typeof(T).IsEnum ? Enum.GetUnderlyingType(typeof(T)) : typeof(T);
            if (allocatedBytes < 0L || allocatedBytes >= (long) Marshal.SizeOf(type))
            {
                return (T) Marshal.PtrToStructure(ptr, type);
            }
            throw new InsufficientMemoryException();
        }

        public struct AUDIT_POLICY_INFORMATION
        {
            public Guid sc;
            public uint ai;
            public Guid ca;
        }
    }
}
"@
    Add-Type -TypeDefinition $def -Language CSharp
    $regLegacyAudit = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -EA SilentlyContinue
    $res = @{
        'LegacyDisabled' = ($regLegacyAudit.SCENoApplyLegacyAuditPolicy -eq 1)
    }
    $sc = @()
    $ns = 0
    $ca = [Guid]::Empty
    if ([Audit.Pol]::AuditEnumerateSubCategories($ca, $true, [ref]$sc, [ref]$ns)) {
        foreach ($c in $sc) {
            $pol = -1
            $pol = [Audit.Pol]::QueryPolicy($c)
            $res.Add($c.Guid,$pol.ai)
        }
    }

    $output = [PSCustomObject]$res | ConvertTo-Json -Compress
    if ($null -eq $PSSenderInfo) {
        New-ItemProperty -Path 'HKLM:\SOFTWARE' -Name 'Semperis.AuditPolicy' -PropertyType String -Value $output -Force -EA Stop
    } else {
        $output
    }
}
'@
    $dcTestScriptBlock = [scriptblock]::Create($dcTest)
    $ecmd = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($dcTest))
    $dcTestCommand = ('cmd.exe /c "powershell.exe -EncodedCommand {0}"' -f $ecmd)
    if ($dcTestCommand.Length -le 8190) { $lvl = 1 } else { $lvl = 3 }
    Write-ScriptLog ('Remote WMI command length: {0}' -f $dcTestCommand.Length) -Level $lvl

}
$mustHaveAudit = @('CREATE_CHILD','DELETE_CHILD','EXTENDED_WRITE','WRITE_PROPERTY','DELETE_TREE','CONTROL_ACCESS','DELETE','WRITE_DACL','WRITE_OWNER','WRITE_SACL')
$iniPat = 'MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\SCENoApplyLegacyAuditPolicy\=(?<valuea>\d)\,(?<valueb>\d)'
if ($SetSACL) {
    if ($Inspect -notcontains 'SACL') {
        Write-ScriptLog 'SACL excluded but SetSACL specified, adding SACL check' -Level 1
    }
    Write-ScriptLog 'Adding C# code for SetSACL' -Level 0
    $def = @'
using System;
using System.Security.Principal;
using System.DirectoryServices;
using System.Security.AccessControl;

namespace ADSec {

    public class SACL {

        public static string AddEveryoneAuditAll(string path) {
            string msg = "";
            try 
            {
                DirectoryEntry de = new DirectoryEntry();
                de.Path = path;
                de.Options.SecurityMasks = SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl | SecurityMasks.Sacl;
                de.RefreshCache();
                ActiveDirectorySecurity sdc = de.ObjectSecurity;
                ActiveDirectoryRights rights = ActiveDirectoryRights.AccessSystemSecurity | ActiveDirectoryRights.Self | ActiveDirectoryRights.CreateChild | ActiveDirectoryRights.Delete | ActiveDirectoryRights.DeleteChild | ActiveDirectoryRights.DeleteTree | ActiveDirectoryRights.ExtendedRight | ActiveDirectoryRights.WriteDacl | ActiveDirectoryRights.WriteOwner | ActiveDirectoryRights.WriteProperty;
                ActiveDirectoryAuditRule rule = new ActiveDirectoryAuditRule(new NTAccount("Everyone"), rights, AuditFlags.Success,ActiveDirectorySecurityInheritance.All);
                sdc.AddAuditRule(rule);
                de.CommitChanges();
            } 
            catch (Exception e) 
            {
                msg = e.Message;
            }
            return msg;
        }
    
    }

}
'@
    try {
        Add-Type -TypeDefinition $def -Language CSharp -ReferencedAssemblies "System.DirectoryServices.dll" -EA Stop
    } catch {
        Write-ScriptLog ('Error adding C# code for SetSACL: {0}' -f $_.Exception.Message) -Level 4
    }
}
$forestData = @{
    'InspectionRequestedFor' = $Inspect
    'SACLModificationRequested' = ($true -eq $SetSACL)
    'MaxLoggedLevel' = 0
    'Execution' = [PSCustomObject]@{
        'Machine' = [Environment]::MachineName
        'User' = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME)
        'Start' = Get-Date $startDate -Format 'yyyy-MM-dd HH:mm:ss'
    }
    'Forest' = $null
    'Partitions' = @()
    'DomainControllers' = @()
    'GroupPolicies' = @()
}
#endregion
#region init
Write-ScriptLog ('Expected audit subcategories: {0}' -f $auditExpected.Count) -Level 1
$wmiCS = Get-WmiObject Win32_ComputerSystem
if (-not $wmiCS.PartOfDomain) {
    Write-ScriptLog 'Computer is not part of a domain, aborting!' -Level 5
    exit
}
if (($wmiCS.DomainRole -gt 3) -and ($Inspect -contains 'AuditPolicy')) {
    Write-ScriptLog 'Computer is DC and AuditPolicy has been requested, checking if elevated token present' -Level 1
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-ScriptLog 'Running in an elevated shell, OK to continue' -Level 2
    } else {
        Write-ScriptLog 'Running in a non-elevated shell, AuditPolicy discovery will break' -Level 5
        Write-Host 'Audit policy inspection has been requested, and the script is running locally on a domain controller, but without elevation. This will break the Audit Policy detection on this machine. Please run the script elevated, or run it from a member machine!' -ForegroundColor Red
        exit
    }
}
if ($MachineForest) {
    $inspectForest = Get-Forest -Machine
} else {
    $inspectForest = Get-Forest
}
if ($null -eq $inspectForest) {
    Write-ScriptLog 'There was a critical error identifying the forest, aborting!' -Level 5
    exit
}
Write-ScriptLog ('Inspecting forest: {0}' -f $inspectForest.RootNC) -Level 2
$forestData['Forest'] = $inspectForest
#endregion
#region list objects to investigate
$inspectPartitions = @()
$inspectDomainControllers = @()
$inspectGroupPolicies = @()
$domainsforGPO = @()
$sitesforGPO = @()
if (($Inspect -contains 'SACL') -or ($Inspect -contains 'GroupPolicy')) {
    Write-ScriptLog 'SACL or GroupPolicy selected: listing partitions' -Level 2
    $partContainer = Get-DSChildren -ParentDN $inspectForest.ConfigNC -LDAPFilter '(objectClass=crossRefContainer)' -Server $inspectForest.DCFound
    if ($partContainer) {
        $partContainerDN = $partContainer[0].Properties['distinguishedName'][0]
        Write-ScriptLog ('Partitions container: {0}' -f $partContainerDN)
        $partitions = Get-DSChildren -ParentDN $partContainerDN -LDAPFilter '(objectClass=crossRef)' -Server $inspectForest.DCFound
        Write-ScriptLog ('Partitions found: {0}' -f $partitions.Count) -Level 1
        foreach ($part in $partitions) {
            $ncName = $part.Properties['ncName'][0]
            $sysFlags = $part.Properties['systemFlags'][0]
            if (($sysFlags -band 2) -gt 0) {
                Write-ScriptLog ('Domain partition: {0}' -f $ncName) -Level 1
                if ($Inspect -contains 'SACL') {
                    $inspectPartitions += [PSCustomObject]@{'NC' = $ncName; 'DC' = $part.Properties['dnsRoot'][0]}
                }
                if ($Inspect -contains 'GroupPolicy') {
                    $domainsforGPO += [PSCustomObject]@{'NC' = $ncName; 'DC' = $part.Properties['dnsRoot'][0]}
                }
            } elseif ($Inspect -contains 'SACL') {
                if (($sysFlags -band 4) -gt 0) {
                    Write-ScriptLog ('Application partition: {0}' -f $ncName) -Level 1
                    if ($SkipDNS) {
                        Write-ScriptLog 'Skipped because -SkipDNS was specified'    
                    } else {
                        $inspectPartitions += [PSCustomObject]@{'NC' = $ncName; 'DC' = ($part.Properties['dnsRoot'][0].Substring($part.Properties['dnsRoot'][0].IndexOf('.') + 1))}
                    }
                } else {
                    Write-ScriptLog ('System partition: {0}' -f $ncName) -Level 1
                    $inspectPartitions += [PSCustomObject]@{'NC' = $ncName; 'DC' = $inspectForest.DCFound}
                }
            }
        }
    }
    Write-ScriptLog ('Partitions to inspect: {0}' -f $inspectPartitions.Count) -Level 2
}
if ($Inspect -contains 'AuditPolicy') {
    Write-ScriptLog 'AuditPolicy selected: listing domain controllers' -Level 2
    $sitesContainer = Get-DSChildren -ParentDN $inspectForest.ConfigNC -LDAPFilter '(objectClass=sitesContainer)' -Server $inspectForest.DCFound
    if ($sitesContainer) {
        $sitesContainerDN = $sitesContainer[0].Properties['distinguishedName'][0]
        Write-ScriptLog ('Sites container: {0}' -f $sitesContainerDN)
        $sites = @(Get-DSChildren -ParentDN $sitesContainerDN -LDAPFilter '(objectClass=site)' -Server $inspectForest.DCFound)
        Write-ScriptLog ('Sites found: {0}' -f $sites.Count) -Level 1
        foreach ($site in $sites) {
            Write-ScriptLog ('Inspecting site: {0}' -f $site.Properties['name'][0]) -Level 1
            if (($Inspect -contains 'GroupPolicy') -and ($site.Properties['gpLink'].Count -gt 0)) {
                Write-ScriptLog ('Site {1} has {0} GPOs linked to it and GPO inspection has been requested, earmarking' -f $site.Properties['gpLink'].Count, $site.Properties['name'][0]) -Level 1
                $sitesforGPO += [PSCustomObject]@{'Site' = $site.Properties['name'][0]; 'GPLink' = $site.Properties['gpLink']}
            }
            $serversContainer = Get-DSChildren -ParentDN $site.Properties['distinguishedName'][0] -LDAPFilter '(objectClass=serversContainer)' -Server $inspectForest.DCFound
            if ($serversContainer) {
                $serversContainerDN = $serversContainer[0].Properties['distinguishedName'][0]
                Write-ScriptLog ('Servers container for site: {0}' -f $serversContainerDN)
                $servers = @(Get-DSChildren -ParentDN $serversContainerDN -LDAPFilter '(objectClass=server)' -Server $inspectForest.DCFound)
                Write-ScriptLog ('Servers in site: {0}' -f $servers.Count)
                foreach ($server in $servers) {
                    $inspectDomainControllers += $server.Properties['dnsHostName'][0]
                }
            } else {
                Write-ScriptLog ('Servers container could not be determined for site {0}!' -f $site.Properties['name'][0]) -Level 3
            }
        }
    } else {
        Write-ScriptLog 'Sites container could not be determined!' -Level 3
    }
    Write-ScriptLog ('Domain Controllers to inspect: {0}' -f $inspectDomainControllers.Count) -Level 2
}
if ($Inspect -contains 'GroupPolicy') {
    Write-ScriptLog 'GroupPolicy selected: listing group policies' -Level 2
    $iGP = @()
    $pattern = [regex]"(\[LDAP\:\/\/.+?\;\d\])"
    foreach ($site in $sitesforGPO) {
        $linkedGP = $pattern.Matches($site.GPLink).Where({$_.Success}).Value
        Write-ScriptLog ('{0} GPO linked to site {1}' -f $linkedGP.Count, $site.Site) -Level 1
        $iGP += $linkedGP
    }
    foreach ($domain in $domainsforGPO) {
        $domObj = Get-DSObject -ObjectDN $domain.NC -Server $domain.DC
        $linkedGP = $pattern.Matches($domObj.Properties['gpLink'][0]).Where({$_.Success}).Value
        Write-ScriptLog ('{0} GPO linked to domain {1}' -f $linkedGP.Count, $domain.NC) -Level 1
        $iGP += $linkedGP
        $dcOU = Get-DomainControllersOU -Domain $domain.DC
        Write-ScriptLog ('DC OU in domain {0}: {1}' -f $domain.NC, $dcOU)
        $dcOUObj = Get-DSObject -ObjectDN $dcOU
        $linkedGP = $pattern.Matches($dcOUObj.Properties['gpLink'][0]).Where({$_.Success}).Value
        Write-ScriptLog ('{0} GPO linked to DC OU {1}' -f $linkedGP.Count, $dcOU) -Level 1
        $iGP += $linkedGP
    }
    $iGP = ($iGP | Sort-Object -Unique)
    Write-ScriptLog ('{0} unique GP links found' -f $iGP.Count) -Level 1
    foreach ($gp in $iGP) {
        if ($gp -match '^\[LDAP\:\/\/(?<gpdn>.+)\;(?<gpla>\d+)\]$') {
            if ($Matches['gpla'] -in @("0","2")) {
                if ($inspectGroupPolicies -notcontains $Matches['gpdn']) {
                    $inspectGroupPolicies += $Matches['gpdn']
                }
            }
        }
    }
    Write-ScriptLog ('Group Policies to inspect: {0}' -f $inspectGroupPolicies.Count) -Level 2
}
#endregion
#region process
Write-Host ('Will inspect: {0} partitions, {1} domain controllers, {2} group policies' -f $inspectPartitions.Count, $inspectDomainControllers.Count, $inspectGroupPolicies.Count) -ForegroundColor Cyan
Write-Host ' '
foreach ($part in $inspectPartitions) {
    Write-Host ('{0} via {1}:' -f $part.NC, $part.DC) -ForegroundColor Green
    Write-ScriptLog ('Inspecting ACL on partition {0}' -f $part.NC) -Level 2
    $partAudit = Get-DSAudit -ObjectDN $part.NC -Server $part.DC
    $partObject = [PSCustomObject]@{
        'DN' = $part.NC
        'Server' = $part.DC
        'AuditEveryone' = $partAudit
        'AuditMissing' = @()
        'SetRequested' = ($SetSACL -eq $true)
        'SetSuccessful' = $null
        'SetMessage' = $null
    }
    Write-ScriptLog ('Audit returned: {0}' -f ($partAudit -join ',')) -Level 1
    $missingAudit = @()
    foreach ($au in $mustHaveAudit) {
        if ($partAudit -notcontains $au) {
            $missingAudit += $au
        }
    }
    if ($missingAudit.Count -gt 0) {
        $partObject.AuditMissing = $missingAudit
        Write-Host (' - Missing audit entries for Everyone on {0}:' -f $part.NC) -ForegroundColor Yellow
        Write-Host ('   {0}' -f ($missingAudit -join ',')) -ForegroundColor DarkYellow
        Write-ScriptLog ('{0} missing audit entries: {1}' -f $missingAudit.Count, ($missingAudit -join ',')) -Level 1
        if ($SetSACL) {
            Write-ScriptLog 'SetACL specified, will add the missing audit entries now' -Level 2
            try {
                $setResult = [ADSec.SACL]::AddEveryoneAuditAll("LDAP://$($part.DC)/$($part.NC)")
            } catch {
                $setResult = $_.Exception.Message
            }
            if ([string]::IsNullOrWhiteSpace($setResult)) {
                $partObject.SetSuccessful = $true
                Write-Host ' - Required audit entries added successfully' -ForegroundColor Green
            } else {
                $partObject.SetSuccessful = $false
                $partObject.SetMessage = $setResult
                Write-Host (' - Could not add required audit entries: {0}' -f $setResult) -ForegroundColor Red
            }
        }
    } else {
        Write-ScriptLog ('All required audit entries are present') -Level 1
        Write-Host ('All required audit entries present for Everyone on {0}' -f $part.NC) -ForegroundColor Green
    }
    Write-Host ' '
    $forestData['Partitions'] += $partObject
}
foreach ($dc in $inspectDomainControllers) {
    Write-Host ('Inspecting DC {0}' -f $dc) -ForegroundColor Green
    Write-ScriptLog ('Inspecting Audit Policy on DC {0}' -f $dc) -Level 2
    $dcObject = [PSCustomObject]@{
        'Name' = $dc
        'Protocol' = $null
        'Success' = $null
        'ErrorMessage' = $null
        'AuditPolicyRaw' = $null
        'AuditLegacyDisabled' = $null
        'AuditMissing' = @()
    }
    $remoteName = $null
    if ($PreferProtocol -eq 'PSRemoting') {
        Write-ScriptLog 'Trying PSRemoting (preferred)' -Level 0
        try {
            $remoteName = Invoke-Command -ComputerName $dc -ScriptBlock { $env:COMPUTERNAME } -EA Stop
            $dcObject.Protocol = 'PSRemoting'
        } catch {
            Write-ScriptLog ('PSRemoting (preferred) failed: {0}' -f $_.Exception.Message) -Level 1
        }
        if ($null -eq $remoteName) {
            Write-ScriptLog 'PSRemoting (preferred) failed, trying WMI...' -Level 1
            try {
                $remCS = Get-WmiObject -ComputerName $dc -Class Win32_ComputerSystem -EA Stop
                $remoteName = $remCS.Name
                $dcObject.Protocol = 'WMI'
            } catch {
                Write-ScriptLog ('WMI (fallback) failed: {0}' -f $_.Exception.Message) -Level 1
            }
        }
    } else {
        Write-ScriptLog 'Trying WMI (preferred)' -Level 0
        try {
            $remCS = Get-WmiObject -ComputerName $dc -Class Win32_ComputerSystem -EA Stop
            $remoteName = $remCS.Name
            $dcObject.Protocol = 'WMI'
        } catch {
            Write-ScriptLog ('WMI (preferred) failed: {0}' -f $_.Exception.Message) -Level 1
        }
        if ($null -eq $remoteName) {
            Write-ScriptLog 'WMI (preferred) failed, trying PSRemoting...' -Level 1
            try {
                $remoteName = Invoke-Command -ComputerName $dc -ScriptBlock { $env:COMPUTERNAME } -EA Stop    
                $dcObject.Protocol = 'PSRemoting'
            } catch {
                Write-ScriptLog ('PSRemoting (fallback) failed: {0}' -f $_.Exception.Message) -Level 1
            }
        }
    }
    if(-not [string]::IsNullOrWhiteSpace($remoteName)) {
        if ($dc -notlike "$($remoteName).*") { 
            Write-ScriptLog ('Targeted DC {0} returned different name [{1}], will proceed with caution' -f $dc, $remoteName) -Level 3
        }
    }
    $auPol = $null
    if ($dcObject.Protocol -eq 'PSRemoting') {
        Write-ScriptLog ('Retrieving the Audit Policy using PSRemoting from {0}' -f $dc) -Level 1
        try {
            $auPolResult = Invoke-Command -ComputerName $dc -ScriptBlock $dcTestScriptBlock -EA Stop
            if ($null -eq $auPolResult) {
                Write-ScriptLog 'PSRemoting call was successful but returned an empty result' -Level 3
                $dcObject.Success = $false
                $dcObject.ErrorMessage = 'An empty result was returned'
            } else {
                Write-ScriptLog 'PSRemoting call was successful' -Level 1
                $auPol = $auPolResult.ToString()
                $dcObject.Success = $true
                $dcObject.AuditPolicyRaw = $auPol
            }
        } catch {
            Write-ScriptLog ('PSRemoting call threw an error: {0}' -f $_.Exception.Message) -Level 3
            $dcObject.Success= $false
            $dcObject.ErrorMessage = $_.Exception.Message
        }
    } else {
        Write-ScriptLog ('Retrieving the Audit Policy using WMI from {0}' -f $dc) -Level 1
        $args = @(
            $dcTestCommand
        )
        try {
            $wmiRes = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $args -ComputerName $dc -EA Stop
        } catch {
            Write-ScriptLog ('WMI call threw an error: {0}' -f $_.Exception.Message) -Level 3
            $wmiRes = $null
            $dcObject.Success= $false
            $dcObject.ErrorMessage = $_.Exception.Message
        }
        if ($wmiRes.ReturnValue -eq 0) {
            Write-ScriptLog 'WMIcall was successful, waiting for the result to appear in the registry...' -Level 1
            $msPath = ('\\{0}\ROOT\DEFAULT:StdRegProv' -f $dc)
            $mScope = New-Object System.Management.ManagementScope($msPath)
            $mScope.Connect()
            $regObject = New-Object System.Management.ManagementClass($mScope, $msPath, $null)
            $nPasses = 0
            do {
                $nPasses++
                Write-ScriptLog 'Waiting for 500 ms...' -Level 0
                Start-Sleep -Milliseconds 500
                $res = $regObject.GetStringValue(2147483650, 'SOFTWARE', 'Semperis.AuditPolicy')
             } until (($res.ReturnValue -eq 0) -or ($nPasses -gt ($WaitforWMI * 2)))
             if ($res.ReturnValue -eq 0) {
                Write-ScriptLog 'Retrieved AuditPolicy from WMI registry' -Level 0
                $auPol = $res.sValue
                $dcObject.Success = $true                
                $dcObject.AuditPolicyRaw = $res.sValue
             }
             try {
                Write-ScriptLog 'Deleting the registry value' -Level 0
                $res = $regObject.DeleteValue(2147483650, 'SOFTWARE', 'Semperis.AuditPolicy')
            } catch {
                Write-ScriptLog ('Error deleting the registry value: {0}' -f $_.Exception.Message) -Level 1
            }
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($auPol)) {
        Write-ScriptLog ('Raw audit policy: {0}' -f $auPol) -Level 1
        try {
            $auObject = $auPol | ConvertFrom-Json -EA Stop
            if ($auObject.LegacyDisabled -ne $true) {
                $dcObject.AuditLegacyDisabled = $false
                Write-Host ' - Audit legacy categories is NOT disabled' -ForegroundColor Yellow
            } else {
                $dcObject.AuditLegacyDisabled = $true
                Write-Host ' - Audit legacy categories is disabled' -ForegroundColor Green
            }
            Write-ScriptLog ('Audit legacy categories disabled: {0}' -f $dcObject.AuditLegacyDisabled) -Level 2
            $missingP = 0
            foreach ($polid in $auditExpected.Keys) {
                Write-ScriptLog ('Checking for Audit Policy {0} [{1}; Success={2}; Failure={3}]' -f $polid, ($auditExpected[$polid]).Name, ($auditExpected[$polid]).Success, ($auditExpected[$polid]).Failure) -Level 0
                $auS = (($auObject."$($polid)" -band 1) -gt 0)
                $auF = (($auObject."$($polid)" -band 2) -gt 0)
                Write-ScriptLog ('Value from DC: {0}; Success={1}; Failure={2}' -f $auObject."$($polid)", $auS, $auF) -Level 0
                if ((-not $auS) -and ($auditExpected[$polid]).Success) {
                    $missingP++
                    $missingEntry = ('{0} : Success' -f $polid)
                    $missingEntryV = ('{0} : Success' -f ($auditExpected[$polid]).Name)
                    $dcObject.AuditMissing += $missingEntry
                    Write-ScriptLog ('Missing: {0}' -f $missingEntry) -Level 1
                    Write-Host (' - missing {1}' -f $dc, $missingEntryV -f $dc) -ForegroundColor Yellow
                }
                if ((-not $auF) -and ($auditExpected[$polid]).Failure) {
                    $missingP++
                    $missingEntry = ('{0} : Failure' -f $polid)
                    $missingEntryV = ('{0} : Failure' -f ($auditExpected[$polid]).Name)
                    $dcObject.AuditMissing += $missingEntry
                    Write-ScriptLog ('Missing: {0}' -f $missingEntry) -Level 1
                    Write-Host (' - missing {1}' -f $dc, $missingEntryV -f $dc) -ForegroundColor Yellow
                }
            }
            if ($missingP -eq 0) {
                Write-Host (' - All audit policies set as expected' -f $dc) -ForegroundColor Green
            }
        } catch {
            Write-ScriptLog ('Converting AuditPolicy from JSON failed: {0}' -f $_.Exception.Message) -Level 3
        }
    } else {
        Write-ScriptLog ('Audit policy for {0} could not be retrieved' -f $dc) -Level 2
        Write-Host (' - Could not retrieve audit policy!') -ForegroundColor Red
    }
    Write-Host ' '
    $forestData['DomainControllers'] += $dcObject
}
Write-Host ' '
foreach ($gpo in $inspectGroupPolicies) {
    Write-ScriptLog ('Inspecting Audit Policy settings in GPO {0}' -f $gpo) -Level 2
    $regValue = $null
    $relAudit = @()
    $domNC = $gpo.Substring($gpo.IndexOf(',DC=') + 1)
    $domDC = $domainsForGPO.Where({$_.NC -eq $domNC})[0].DC
    Write-ScriptLog ('Getting information on GPO {0} from server {1}' -f $gpo, $domDC) -Level 1
    $gpObject = Get-DSObject -ObjectDN $gpo -Server $domDC
    $gpoName = $gpObject.Properties['displayName'][0]
    Write-Host ('Audit Policy settings in GPO [{0}] from {1}' -f $gpoName, $domNC) -ForegroundColor Green
    if ($gpObject.Properties['gPCMachineExtensionNames'][0] -match '\{827D319E\-6EAC\-11D2\-A4EA\-00C04F79F83A\}') {
        Write-ScriptLog ('GPO {0} contains the Security SCE' -f $gpoName) -Level 1
        $gpoGUID = $gpObject.Properties['name'][0]
        $gpoFolder = $gpObject.Properties['gPCFileSysPath'][0]
        if (Test-Path -Path $gpoFolder -PathType Container) {
            Write-ScriptLog ('GPO folder {0} is accessible' -f $gpoFolder) -Level 0
            $infFile = Join-Path -Path $gpoFolder -ChildPath 'MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
            $csvFile = Join-Path -Path $gpoFolder -ChildPath 'MACHINE\Microsoft\Windows NT\Audit\audit.csv'
            if (Test-Path -Path $infFile -PathType Leaf) {
                Write-ScriptLog ('SecEdit file {0} is accessible' -f $infFile) -Level 0
                try {
                    $lines = (Get-Content -Path $infFile -EA Stop) -match $iniPat
                } catch {
                    $lines = @()
                    Write-ScriptLog ('Error importing INF file: {0}' -f $_.Exception.Message) -Level 3
                }
                if ($lines.Count -gt 0) {
                    Write-ScriptLog ('Legacy categories line found!' -f $iniFile) -Level 0
                    if ($lines[0] -match $iniPat) {
                        $regValue = $Matches['valueb'] -as [int]
                        Write-ScriptLog ('Registry value for Legacy: {0}' -f $regValue) -Level 0
                    }
                }
            } else {
                Write-ScriptLog ('SecEdit file {0} is NOT accessible' -f $infFile) -Level 0
            }
            if (Test-Path -Path $csvFile -PathType Leaf) {
                Write-ScriptLog ('Audit file {0} is accessible' -f $csvFile) -Level 0
                try {
                    $auData = Import-CSV -Path $csvFile -EA Stop
                    Write-ScriptLog ('Imported {0} audit policy settings' -f $auData.Count) -Level 1
                } catch {
                    $auData = @()
                    Write-ScriptLog ('Error importing CSV file: {0}' -f $_.Exception.Message) -Level 3
                }
                $relAudit = $auData.Where({($_."Subcategory GUID").Trim('\{\}') -in $auditExpected.Keys})
                Write-ScriptLog ('Detected {0} relevant audit settings' -f $relAudit.Count) -Level 2
            } else {
                Write-ScriptLog ('Audit file {0} is NOT accessible' -f $csvFile) -Level 0
            }
        } else {
            Write-ScriptLog ('GPO folder {0} is NOT accessible' -f $gpoFolder) -Level 3
        }
    } else {
        Write-ScriptLog ('GPO {0} does not contain the Security SCE' -f $gpoName) -Level 1
        continue
    }
    if (($null -ne $regValue) -or ($relAudit.Count -gt 0)) {
        #Write-Host ('{0} ({1}) is potentially linked to DCs and contains audit settings' -f $gpoName, $domNC) -ForegroundColor Green
        Write-ScriptLog ('{0} from {1} is potentially linked to DCs and contains audit settings' -f $gpoName, $domNC) -Level 2
        $gpoOut = [PSCustomObject]@{
            'Name' = $gpoName
            'Domain' = $domNC
            'GUID' = $gpoGUID
            'AuditLegacyDisabled' = $null
            'AuditPolicySettings' = @()
        }
        if ($null -ne $regValue) {
            $gpoOut.AuditLegacyDisabled = ($regValue -eq 1)
            if ($regValue -eq 1) {
                Write-Host ' - SCENoApplyLegacyAuditPolicy is set to 1' -ForegroundColor Green
            } else {
                Write-Host ' - SCENoApplyLegacyAuditPolicy is set to 0' -ForegroundColor Yellow
            }
        }
        if ($relAudit.Count -gt 0) {
            $gpoOut.AuditPolicySettings = $relAudit | Select-Object -Property @{'l'='Subcategory';'e'={($_."Subcategory GUID").Trim('\{\}')}},@{'l'='Setting';'e'={$_."Setting Value"}}
            Write-Host (' - {0} relevant audit policies are set, not necessarily to the expected values' -f $relAudit.Count) -ForegroundColor Green
        }
        Write-Host ' '
        $forestData['GroupPolicies'] += $gpoOut
    }
}
#endregion
#region output
$forestData['MaxLoggedLevel'] = $script:MaxLoggedLevel

if ($ExportToFile) {
    $exportFile = Join-Path -Path ([environment]::GetFolderPath('MyDocuments')) -ChildPath ('{0}-DSPAuditSettings.json' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
    Write-ScriptLog ('Exporting script results to {0}' -f $exportFile) -Level 2
    [PSCustomObject]$forestData | ConvertTo-Json -Depth 5 | Set-Content $exportFile -Encoding UTF8 -Force
}

#endregion
#region bailout
if ($script:MaxLoggedLevel -gt 2) {
    Write-Warning 'Warnings or errors were generated and at least the most critical ones were logged. Please review the log file!'
}
Write-ScriptLog 'Sayonara!' -Level 2
#region

# SIG # Begin signature block
# MIImpwYJKoZIhvcNAQcCoIImmDCCJpQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU4IQpKxYeGdhpumLig39JvS1T
# 8g+ggh+5MIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
# AQwFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVy
# MRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEh
# MB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTIxMDUyNTAwMDAw
# MFoXDTI4MTIzMTIzNTk1OVowVjELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3Rp
# Z28gTGltaXRlZDEtMCsGA1UEAxMkU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5n
# IFJvb3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjeeUEiIE
# JHQu/xYjApKKtq42haxH1CORKz7cfeIxoFFvrISR41KKteKW3tCHYySJiv/vEpM7
# fbu2ir29BX8nm2tl06UMabG8STma8W1uquSggyfamg0rUOlLW7O4ZDakfko9qXGr
# YbNzszwLDO/bM1flvjQ345cbXf0fEj2CA3bm+z9m0pQxafptszSswXp43JJQ8mTH
# qi0Eq8Nq6uAvp6fcbtfo/9ohq0C/ue4NnsbZnpnvxt4fqQx2sycgoda6/YDnAdLv
# 64IplXCN/7sVz/7RDzaiLk8ykHRGa0c1E3cFM09jLrgt4b9lpwRrGNhx+swI8m2J
# mRCxrds+LOSqGLDGBwF1Z95t6WNjHjZ/aYm+qkU+blpfj6Fby50whjDoA7NAxg0P
# OM1nqFOI+rgwZfpvx+cdsYN0aT6sxGg7seZnM5q2COCABUhA7vaCZEao9XOwBpXy
# bGWfv1VbHJxXGsd4RnxwqpQbghesh+m2yQ6BHEDWFhcp/FycGCvqRfXvvdVnTyhe
# Be6QTHrnxvTQ/PrNPjJGEyA2igTqt6oHRpwNkzoJZplYXCmjuQymMDg80EY2NXyc
# uu7D1fkKdvp+BRtAypI16dV60bV/AK6pkKrFfwGcELEW/MxuGNxvYv6mUKe4e7id
# FT/+IAx1yCJaE5UZkADpGtXChvHjjuxf9OUCAwEAAaOCARIwggEOMB8GA1UdIwQY
# MBaAFKARCiM+lvEH7OKvKe+CpX/QMKS0MB0GA1UdDgQWBBQy65Ka/zWWSC8oQEJw
# IDaRXBeF5jAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUE
# DDAKBggrBgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmlj
# YXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBDAUAA4IBAQASv6Hvi3Sa
# mES4aUa1qyQKDKSKZ7g6gb9Fin1SB6iNH04hhTmja14tIIa/ELiueTtTzbT72ES+
# BtlcY2fUQBaHRIZyKtYyFfUSg8L54V0RQGf2QidyxSPiAjgaTCDi2wH3zUZPJqJ8
# ZsBRNraJAlTH/Fj7bADu/pimLpWhDFMpH2/YGaZPnvesCepdgsaLr4CnvYFIUoQx
# 2jLsFeSmTD1sOXPUC4U5IOCFGmjhp0g4qdE2JXfBjRkWxYhMZn0vY86Y6GnfrDyo
# XZ3JHFuu2PMvdM+4fvbXg50RlmKarkUT2n/cR/vfw1Kf5gZV6Z2M8jpiUbzsJA8p
# 1FiAhORFe1rYMIIGGjCCBAKgAwIBAgIQYh1tDFIBnjuQeRUgiSEcCjANBgkqhkiG
# 9w0BAQwFADBWMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MS0wKwYDVQQDEyRTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYw
# HhcNMjEwMzIyMDAwMDAwWhcNMzYwMzIxMjM1OTU5WjBUMQswCQYDVQQGEwJHQjEY
# MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSswKQYDVQQDEyJTZWN0aWdvIFB1Ymxp
# YyBDb2RlIFNpZ25pbmcgQ0EgUjM2MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIB
# igKCAYEAmyudU/o1P45gBkNqwM/1f/bIU1MYyM7TbH78WAeVF3llMwsRHgBGRmxD
# eEDIArCS2VCoVk4Y/8j6stIkmYV5Gej4NgNjVQ4BYoDjGMwdjioXan1hlaGFt4Wk
# 9vT0k2oWJMJjL9G//N523hAm4jF4UjrW2pvv9+hdPX8tbbAfI3v0VdJiJPFy/7Xw
# iunD7mBxNtecM6ytIdUlh08T2z7mJEXZD9OWcJkZk5wDuf2q52PN43jc4T9OkoXZ
# 0arWZVeffvMr/iiIROSCzKoDmWABDRzV/UiQ5vqsaeFaqQdzFf4ed8peNWh1OaZX
# nYvZQgWx/SXiJDRSAolRzZEZquE6cbcH747FHncs/Kzcn0Ccv2jrOW+LPmnOyB+t
# AfiWu01TPhCr9VrkxsHC5qFNxaThTG5j4/Kc+ODD2dX/fmBECELcvzUHf9shoFvr
# n35XGf2RPaNTO2uSZ6n9otv7jElspkfK9qEATHZcodp+R4q2OIypxR//YEb3fkDn
# 3UayWW9bAgMBAAGjggFkMIIBYDAfBgNVHSMEGDAWgBQy65Ka/zWWSC8oQEJwIDaR
# XBeF5jAdBgNVHQ4EFgQUDyrLIIcouOxvSK4rVKYpqhekzQwwDgYDVR0PAQH/BAQD
# AgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwGwYD
# VR0gBBQwEjAGBgRVHSAAMAgGBmeBDAEEATBLBgNVHR8ERDBCMECgPqA8hjpodHRw
# Oi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ1Jvb3RS
# NDYuY3JsMHsGCCsGAQUFBwEBBG8wbTBGBggrBgEFBQcwAoY6aHR0cDovL2NydC5z
# ZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdSb290UjQ2LnA3YzAj
# BggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJKoZIhvcNAQEM
# BQADggIBAAb/guF3YzZue6EVIJsT/wT+mHVEYcNWlXHRkT+FoetAQLHI1uBy/YXK
# ZDk8+Y1LoNqHrp22AKMGxQtgCivnDHFyAQ9GXTmlk7MjcgQbDCx6mn7yIawsppWk
# vfPkKaAQsiqaT9DnMWBHVNIabGqgQSGTrQWo43MOfsPynhbz2Hyxf5XWKZpRvr3d
# MapandPfYgoZ8iDL2OR3sYztgJrbG6VZ9DoTXFm1g0Rf97Aaen1l4c+w3DC+IkwF
# kvjFV3jS49ZSc4lShKK6BrPTJYs4NG1DGzmpToTnwoqZ8fAmi2XlZnuchC4NPSZa
# PATHvNIzt+z1PHo35D/f7j2pO1S8BCysQDHCbM5Mnomnq5aYcKCsdbh0czchOm8b
# kinLrYrKpii+Tk7pwL7TjRKLXkomm5D1Umds++pip8wH2cQpf93at3VDcOK4N7Ew
# oIJB0kak6pSzEu4I64U6gZs7tS/dGNSljf2OSSnRr7KWzq03zl8l75jy+hOds9TW
# SenLbjBQUGR96cFr6lEUfAIEHVC1L68Y1GGxx4/eRI82ut83axHMViw1+sVpbPxg
# 51Tbnio1lB93079WPFnYaOvfGAA0e0zcfF/M9gXr+korwQTh2Prqooq2bYNMvUoU
# KD85gnJ+t0smrWrb8dee2CvYZXD5laGtaAxOfy/VKNmwuWuAh9kcMIIGOzCCBKOg
# AwIBAgIQHdAGLCATbV3zXCkwcR/6uDANBgkqhkiG9w0BAQwFADBUMQswCQYDVQQG
# EwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSswKQYDVQQDEyJTZWN0aWdv
# IFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2MB4XDTIzMDQxMTAwMDAwMFoXDTI2
# MDcxMDIzNTk1OVowUjELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJlcmxpbjEYMBYG
# A1UECgwPRXZnZW5paiBTbWlybm92MRgwFgYDVQQDDA9FdmdlbmlqIFNtaXJub3Yw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDWU++8HQhIm3mNseP1FGyx
# SibWo0LTbiuxipenEUIPY2TXUjDuGeoaDLSG9btqm8q4gbF2aNvYRyr+x2n6w4qO
# SPck+U3VQbjoaC9g8D5Bj0Ef1qdRBtdPxrW2enqVAHZTVo6UuFFspahqQJwFS6Nu
# 0iwTNwn4/S26RpQH40H7v3TzYkBOSH7/eahw5TceGVj+ua3tQCNAXQunUZGAZ0Su
# a8PY6HIKTurz9YCyq+/fqQ8URdFPBFE52SLrImLAhIBJ0q++nTvOo1cfsIHNg4gj
# lsqWG7iCC1jPP05W/vanzY/WT6Z5rSm4kU+0FWdO0sN+ArYCBvx25WrNI3HoqRDV
# lxi+lXmu9il0I1n25eriI6gi/b1fzN5M78gcCPjIkHhvL2FCV4gYGrbGt9jaZVY/
# Dcu+6zTYzNIQCx1oClheAh+PF1lz15Dn7jb7PwKXlGaTQDkAcDlJL10HrFo86yNO
# szaDaZK9cAlKFa0ZfWiX0jhsn03nzYMl84pFgztqIyi59CoTclIJti7hp4r9cLBn
# xvEIY+38Avh4rUhPOmgJb9jQjt/D+2TS9VbTZXmwJq8jsyhCQmUkt+NnLrVNUq8i
# meJ6Yb79sfzOOsgTRCCcNM3jCyE8X81qS+aB11TwbHCDQ7Z4InJGzbi0NvSrJXv4
# 7CEd9PXu+C13NWP5tho17wIDAQABo4IBiTCCAYUwHwYDVR0jBBgwFoAUDyrLIIco
# uOxvSK4rVKYpqhekzQwwHQYDVR0OBBYEFFlOpEfGcbuN/LvFXLoY6WLG6qZMMA4G
# A1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MEoGA1UdIARDMEEwNQYMKwYBBAGyMQECAQMCMCUwIwYIKwYBBQUHAgEWF2h0dHBz
# Oi8vc2VjdGlnby5jb20vQ1BTMAgGBmeBDAEEATBJBgNVHR8EQjBAMD6gPKA6hjho
# dHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ0NB
# UjM2LmNybDB5BggrBgEFBQcBAQRtMGswRAYIKwYBBQUHMAKGOGh0dHA6Ly9jcnQu
# c2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FSMzYuY3J0MCMG
# CCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwF
# AAOCAYEACIils2uUHfaHVcfC8fzE0Kwk/cyQ7AjsjcteTH0iOIE+ydu1F4mG1BxS
# 5klnIQd0vf7R8w/74oMDPOzN17Nt+pgjuXScYAkjgkMicwMLy4ke8YAzthq8NZIF
# dlXqNOBorC9CBEN/f7B/nMKW8O98gvYHvLj434ALsJOxJBL/SolO2P8/gmLQevCL
# Pc0LDFlTrH3jMHbManDNXRsdMjpOi9vCfaVGnTsNxshaKTCzbbMGqNxwBnMdPkbv
# BCZrY4e3BTUPJ/8LuR31/3xs746KhUc7W8PIpO6VLofQ/vWtzfpuGCzLIQtWX1JD
# RX7Et140msmZExAPCPXqTeLPVo4vmt7OjmDsR7JHTh3GqX5tBZqoJicd8Qq/NuXi
# R29/Xa4og8vMfFzqPblSX0lvWuPoXWb1yW+k/GKtdD6BYerMLYuqXN+U2bAJNPqk
# IK7IfyX2Jmm7aBNIq+wyaCaQuMZ01yJcVVhoWIel+YRS4iJZlrsPzyexeimhKdRT
# sI72fLNuMIIG7DCCBNSgAwIBAgIQMA9vrN1mmHR8qUY2p3gtuTANBgkqhkiG9w0B
# AQwFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNV
# BAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsx
# LjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkw
# HhcNMTkwNTAyMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjB9MQswCQYDVQQGEwJHQjEb
# MBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRgw
# FgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxJTAjBgNVBAMTHFNlY3RpZ28gUlNBIFRp
# bWUgU3RhbXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDI
# GwGv2Sx+iJl9AZg/IJC9nIAhVJO5z6A+U++zWsB21hoEpc5Hg7XrxMxJNMvzRWW5
# +adkFiYJ+9UyUnkuyWPCE5u2hj8BBZJmbyGr1XEQeYf0RirNxFrJ29ddSU1yVg/c
# yeNTmDoqHvzOWEnTv/M5u7mkI0Ks0BXDf56iXNc48RaycNOjxN+zxXKsLgp3/A2U
# Urf8H5VzJD0BKLwPDU+zkQGObp0ndVXRFzs0IXuXAZSvf4DP0REKV4TJf1bgvUac
# gr6Unb+0ILBgfrhN9Q0/29DqhYyKVnHRLZRMyIw80xSinL0m/9NTIMdgaZtYClT0
# Bef9Maz5yIUXx7gpGaQpL0bj3duRX58/Nj4OMGcrRrc1r5a+2kxgzKi7nw0U1BjE
# MJh0giHPYla1IXMSHv2qyghYh3ekFesZVf/QOVQtJu5FGjpvzdeE8NfwKMVPZIMC
# 1Pvi3vG8Aij0bdonigbSlofe6GsO8Ft96XZpkyAcSpcsdxkrk5WYnJee647BeFbG
# RCXfBhKaBi2fA179g6JTZ8qx+o2hZMmIklnLqEbAyfKm/31X2xJ2+opBJNQb/HKl
# FKLUrUMcpEmLQTkUAx4p+hulIq6lw02C0I3aa7fb9xhAV3PwcaP7Sn1FNsH3jYL6
# uckNU4B9+rY5WDLvbxhQiddPnTO9GrWdod6VQXqngwIDAQABo4IBWjCCAVYwHwYD
# VR0jBBgwFoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYEFBqh+GEZIA/D
# QXdFKI7RNV8GEgRVMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEA
# MBMGA1UdJQQMMAoGCCsGAQUFBwMIMBEGA1UdIAQKMAgwBgYEVR0gADBQBgNVHR8E
# STBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0UlNB
# Q2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwdgYIKwYBBQUHAQEEajBoMD8GCCsG
# AQUFBzAChjNodHRwOi8vY3J0LnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0UlNBQWRk
# VHJ1c3RDQS5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0cnVzdC5j
# b20wDQYJKoZIhvcNAQEMBQADggIBAG1UgaUzXRbhtVOBkXXfA3oyCy0lhBGysNsq
# fSoF9bw7J/RaoLlJWZApbGHLtVDb4n35nwDvQMOt0+LkVvlYQc/xQuUQff+wdB+P
# xlwJ+TNe6qAcJlhc87QRD9XVw+K81Vh4v0h24URnbY+wQxAPjeT5OGK/EwHFhaNM
# xcyyUzCVpNb0llYIuM1cfwGWvnJSajtCN3wWeDmTk5SbsdyybUFtZ83Jb5A9f0Vy
# wRsj1sJVhGbks8VmBvbz1kteraMrQoohkv6ob1olcGKBc2NeoLvY3NdK0z2vgwY4
# Eh0khy3k/ALWPncEvAQ2ted3y5wujSMYuaPCRx3wXdahc1cFaJqnyTdlHb7qvNhC
# g0MFpYumCf/RoZSmTqo9CfUFbLfSZFrYKiLCS53xOV5M3kg9mzSWmglfjv33sVKR
# zj+J9hyhtal1H3G/W0NdZT1QgW6r8NDT/LKzH7aZlib0PHmLXGTMze4nmuWgwAxy
# h8FuTVrTHurwROYybxzrF06Uw3hlIDsPQaof6aFBnf6xuKBlKjTg3qj5PObBMLvA
# oGMs/FwWAKjQxH/qEZ0eBsambTJdtDgJK0kHqv3sMNrxpy/Pt/360KOE2See+wFm
# d7lWEOEgbsausfm2usg1XTN2jvF8IAwqd661ogKGuinutFoAsYyr4/kKyVRd1Llq
# dJ69SK6YMIIG9TCCBN2gAwIBAgIQOUwl4XygbSeoZeI72R0i1DANBgkqhkiG9w0B
# AQwFADB9MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVy
# MRAwDgYDVQQHEwdTYWxmb3JkMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxJTAj
# BgNVBAMTHFNlY3RpZ28gUlNBIFRpbWUgU3RhbXBpbmcgQ0EwHhcNMjMwNTAzMDAw
# MDAwWhcNMzQwODAyMjM1OTU5WjBqMQswCQYDVQQGEwJHQjETMBEGA1UECBMKTWFu
# Y2hlc3RlcjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSwwKgYDVQQDDCNTZWN0
# aWdvIFJTQSBUaW1lIFN0YW1waW5nIFNpZ25lciAjNDCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAKSTKFJLzyeHdqQpHJk4wOcO1NEc7GjLAWTkis13sHFl
# gryf/Iu7u5WY+yURjlqICWYRFFiyuiJb5vYy8V0twHqiDuDgVmTtoeWBIHIgZEFs
# x8MI+vN9Xe8hmsJ+1yzDuhGYHvzTIAhCs1+/f4hYMqsws9iMepZKGRNcrPznq+kc
# Fi6wsDiVSs+FUKtnAyWhuzjpD2+pWpqRKBM1uR/zPeEkyGuxmegN77tN5T2MVAOR
# 0Pwtz1UzOHoJHAfRIuBjhqe+/dKDcxIUm5pMCUa9NLzhS1B7cuBb/Rm7HzxqGXtu
# uy1EKr48TMysigSTxleGoHM2K4GX+hubfoiH2FJ5if5udzfXu1Cf+hglTxPyXnyp
# sSBaKaujQod34PRMAkjdWKVTpqOg7RmWZRUpxe0zMCXmloOBmvZgZpBYB4DNQnWs
# +7SR0MXdAUBqtqgQ7vaNereeda/TpUsYoQyfV7BeJUeRdM11EtGcb+ReDZvsdSbu
# /tP1ki9ShejaRFEqoswAyodmQ6MbAO+itZadYq0nC/IbSsnDlEI3iCCEqIeuw7oj
# cnv4VO/4ayewhfWnQ4XYKzl021p3AtGk+vXNnD3MH65R0Hts2B0tEUJTcXTC5TWq
# LVIS2SXP8NPQkUMS1zJ9mGzjd0HI/x8kVO9urcY+VXvxXIc6ZPFgSwVP77kv7AkT
# AgMBAAGjggGCMIIBfjAfBgNVHSMEGDAWgBQaofhhGSAPw0F3RSiO0TVfBhIEVTAd
# BgNVHQ4EFgQUAw8xyJEqk71j89FdTaQ0D9KVARgwDgYDVR0PAQH/BAQDAgbAMAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwSgYDVR0gBEMwQTA1
# BgwrBgEEAbIxAQIBAwgwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdvLmNv
# bS9DUFMwCAYGZ4EMAQQCMEQGA1UdHwQ9MDswOaA3oDWGM2h0dHA6Ly9jcmwuc2Vj
# dGlnby5jb20vU2VjdGlnb1JTQVRpbWVTdGFtcGluZ0NBLmNybDB0BggrBgEFBQcB
# AQRoMGYwPwYIKwYBBQUHMAKGM2h0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGln
# b1JTQVRpbWVTdGFtcGluZ0NBLmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Au
# c2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIBAEybZVj64HnP7xXDMm3eM5Hr
# d1ji673LSjx13n6UbcMixwSV32VpYRMM9gye9YkgXsGHxwMkysel8Cbf+PgxZQ3g
# 621RV6aMhFIIRhwqwt7y2opF87739i7Efu347Wi/elZI6WHlmjl3vL66kWSIdf9d
# hRY0J9Ipy//tLdr/vpMM7G2iDczD8W69IZEaIwBSrZfUYngqhHmo1z2sIY9wwyR5
# OpfxDaOjW1PYqwC6WPs1gE9fKHFsGV7Cg3KQruDG2PKZ++q0kmV8B3w1RB2tWBhr
# YvvebMQKqWzTIUZw3C+NdUwjwkHQepY7w0vdzZImdHZcN6CaJJ5OX07Tjw/lE09Z
# RGVLQ2TPSPhnZ7lNv8wNsTow0KE9SK16ZeTs3+AB8LMqSjmswaT5qX010DJAoLEZ
# Khghssh9BXEaSyc2quCYHIN158d+S4RDzUP7kJd2KhKsQMFwW5kKQPqAbZRhe8hu
# uchnZyRcUI0BIN4H9wHU+C4RzZ2D5fjKJRxEPSflsIZHKgsbhHZ9e2hPjbf3E7Tt
# oC3ucw/ZELqdmSx813UfjxDElOZ+JOWVSoiMJ9aFZh35rmR2kehI/shVCu0pwx/e
# OKbAFPsyPfipg2I2yMO+AIccq/pKQhyJA9z1XHxw2V14Tu6fXiDmCWp8KwijSPUV
# /ARP380hHHrl9Y4a1LlAMYIGWDCCBlQCAQEwaDBUMQswCQYDVQQGEwJHQjEYMBYG
# A1UEChMPU2VjdGlnbyBMaW1pdGVkMSswKQYDVQQDEyJTZWN0aWdvIFB1YmxpYyBD
# b2RlIFNpZ25pbmcgQ0EgUjM2AhAd0AYsIBNtXfNcKTBxH/q4MAkGBSsOAwIaBQCg
# eDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEE
# AYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJ
# BDEWBBS/tddxWvn1re/zgvxKyQWxtAuoJjANBgkqhkiG9w0BAQEFAASCAgAs+GP+
# DpCTkbtnau4tO3cgTWHKd741Zrj17wXKwPecS5TXEc96U+75khFz0MuR2Sbo3Ocp
# bbuWYWejc32F+2v4dHmSx5puyxYWaX8p+vfL/E2kjcirY+za9oUaydsxCMNFaoQ/
# dzYmI4JVWcSX21hxcPH4IiwdizPLm9aj+nfuymTt+NTwf6X6DwrKuA3/wLMJNscC
# q9b2z/GRJTTqcIABWP6/Rr/3PsQkk7bU/QUXoR5BkXOitJ5GbRAkvhockeidT/Ch
# qq+vKLEXBUT57Nd/fmfxjHp8WdFSk+tawpELgVylOSVceOLaZzq9glHPyQIDy8HP
# sEYXi+N/5ZWp3PIROlpo1mF+V5A518oap6AK14O6Z1Tu6tlyd7AQhBi2I9GEZrs2
# b1qJGXVHxP9NpBwC3ZX1itVl9jLXaLqVpo6uTrtb6OQLHcw549xGyRhxzIfb+XKs
# dVyAaS4aOKwgJ4uD2LlePCWcJqWwx00VhiPPr1xDD/Bq1PiUr9+N9wsLewY6eZPu
# Ncvyn2TMZINdfUDlVm1crsLWSx9YZSTx+qOAj/gcKIJnkc0YwWgRYlk22Vq9Zm14
# O+vQY3NxMMqpjmHCLb+kcfkbcTgxC8zbqpKNlFhv2a4NbanYmQiwG7tc7jiTlRSJ
# k5dwmzUK2Mz/VE/5GWgdrrDizVQyN/TnWEYNvKGCA0swggNHBgkqhkiG9w0BCQYx
# ggM4MIIDNAIBATCBkTB9MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBN
# YW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRgwFgYDVQQKEw9TZWN0aWdvIExp
# bWl0ZWQxJTAjBgNVBAMTHFNlY3RpZ28gUlNBIFRpbWUgU3RhbXBpbmcgQ0ECEDlM
# JeF8oG0nqGXiO9kdItQwDQYJYIZIAWUDBAICBQCgeTAYBgkqhkiG9w0BCQMxCwYJ
# KoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNDAzMjkxNDM1MjNaMD8GCSqGSIb3
# DQEJBDEyBDAp5fGeP0rvyYwCCuFxngcLfZKHityko9+ATQJ3NOHoxgR6vaiWz6vy
# lZn+d5NetRIwDQYJKoZIhvcNAQEBBQAEggIAhbKCP34FCwXheK/kUykc6KNXRzUt
# S0EzMAE3UWq5C+xUSnpvwiNTy2Lmec/UQW7Il4jI4iKMpGmFLqDbdfyJtWy3fnjg
# QzABXWFPYCAwtRBZj+VceTftKwU18r5byiGrqB7GWdgrRIscEnI3mWGMHzHH57tM
# xq1eM5oOZ45WcHcKEaaxNZHLmXCZxZLXjs0I/v06ntkART0awSKc7k2iSLkA12lk
# LIKWJ+HEU+7QCEaLrREnxrpVb9LKuNoEtdmYW09y6L08l2S1fnJ6KjaUs/0TcFg0
# flFs0ZVf/LiBq4ct+CYg5gcKmaKbztT54ge9fDTZqaKgQZSh0a4T/MDuXAJy+CTM
# hk0yOKI+AXTOaLHSLklCE9K+ysOMILaquWSQvPF9Wcx7WdxEZZv7pRE2lAXBzHml
# IX88xcdN7ZNuZM1h1i7/IZzJXwLZ0eRdZr7HXQ3qgfv7kYxIh+z9nu/MlZjde70s
# lGUDMu+wsrFPpQAcLWbhawZdMD8/qYjibL2irYhY7AiQbgFSNazUKpjaH9/cigcH
# wmNofk7Qep0k29E/3rVghk2ryW0D0hdn96jaG7uRVSrbZBTcnHVLGofDStFE4Yhy
# q1p2+Y7E64TAn5U+CGZiUl6a0IuXkeELZE9zFAySm8gvQCY1An33FLVCIkFZLlv9
# cYSLh2ANyMUetRs=
# SIG # End signature block
