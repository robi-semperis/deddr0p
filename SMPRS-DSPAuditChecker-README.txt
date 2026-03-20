SMPRS-DSPAuditChecker.ps1 by Evgenij Smirnov

https://portal.pnp.semperis.com/utils/dsp-audit/


This new script enhances the process by the following functionality:

    check (selectable) for IRP-related audit policies
    check for and set the "WriteSACL" SACL entry
    list GPOs linked to domains, DC OUs and sites that contain audit policy settings
    the DC audit policy checking is not based on auditpol.exe to be a. language-independent and b. not have PowerShell spawn a new process which could upset EDR in some cases
    beside PowerShell remoting (WinRM), remote WMI can be used to access remote DCs
    does not require elevation if run on a member rather than on a DC
    does not use Active Directory PowerShell module and ADWS, direct LDAP access to AD

SYNTAX:

./SMPRS-DSPAuditChecker.ps1
    [-Inspect ([string[]])]
    [-SkipDNS [switch]]
    [-SetSACL [switch]]
    [-IncludeIRP [switch]]
    [-MachineForest [switch]]
    [-ExportToFile [switch]]
    [-LogLevel [int 0-5 default 2]]
    [-LogToConsole [switch]]
    [-PreferProtocol [string]]
    [-WaitForWMI [int 1-120 default 5]]

All parameters are optional. Running the script without parameters will result in the following behavior:

    All partitions in the forest will be examined for SACL, including DNS partitions.
    No changes will be made to any SACLs.
    All domain controllers in the forest will be examined for aufit policy.
    For communicating with domain controllers, PowerShell remoting will be tried first, falling back to WMI if that fails.
    All Group Policy objects in the forest will be examined for audit settings if they are linked to Sites, Domains or DC OUs and contain the Security CSE.
    Log file will be written at level 2 (INFO) and above, no console log will be output.
    No JSON file will be generated.

EXAMPLE for my labs:

./SMPRS-DSPAuditChecker.ps1 -SetSACL -IncludeIRP -LogToConsole 