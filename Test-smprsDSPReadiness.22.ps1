<#
Version History:
	22	- 23-Jan-23
		- Updated recommendations for setting GPO registry backup timeout
		- Checking for the status of Optional Featuress
		- Added detection and reporting of Dynamic Objects
		- Added check for GPO names containing ascii character < 32
		- Added logging of screen output to a logfile
		- Added -OutputFolder to enable path to be changed from default
			$env:USERPROFILE\Documents\Semperis\Test-smprsDSPReadiness
		- Script Output folder path is returned by the script
	21	- Dev
		- Updated reporting of failed HTML reports and Custom GPOs
	20	- 21-Jul-22
		- Miscellaneous minor changes
	19	- 06-Jul-22
		- Added check that the GPO object is in the Systems\Policies container before calling the Report
		- Added check for the minimum and recommended minimum number of CPUs to run DSP on current server
		- Added check for time to backup GPOs exceeding the default GPO Backup Timeout
		- Separated the reporting of custom and failed GPOs
	18 - 19-May-22
		- Added check for failed GPO HTML report generation
		- Fixed issue reporting Unknown Semperis SCP Objects
		- Fixed issue with DC's in a domain being offline
		- Fixed issue with failure to connect to any DCs in a domain
		- Added -ExcludedPartitions parameter to allow testing to exlude domains that are not part of DSP install
		- Added check for required PowerShell modules present on the system running the script.
	17 - 07-May-22
		- Add test for invalid defaultSecurityDescriptor on schema-class objects
		- Added check for Domain Mode
		- Changed LDAP search using Get-ADObject to ADObject search
		- Added LDAP search using DirectorySearcher
		- Added detection for Custom Citrix GPOs using custom Name extensions
			Note: Detection will be changed to any GPO a non-Microsoft Extension GUID in the next release
		- Added check for existing Semperis Service Control Point (SCP) objects
		- Added check for computer and servicePrincipalName of localhost
	16	- 03-Jan-22
		- Count active and defunct schema objects seperately
		- Added SchemaSearch selector, DSP or LDAP
	15	- 28-Dec-2021
		- Renamed to Test-smprsDSPReadiness
		- Added version output to header block
		- Removed GC and GCS from DsConnection validation
		- Remove parameter listAll
		- Added parameter SaveSchema
		- Schema output to $env:UserProfile\Documents\Semperis\Test-smprsDSPReadiness
	14	- 23-Dec-2021
		- Added output of Base OS version to header block
		- Fixed schema query to correctly use DsConnection type
	13	- 19-May-2021
		- Added test for pwdLastSet
	12	- 21-May-2020
		- Added test for invalidLinkId		
	11	-
		- Test for duplicate OID entries in the schema

#>

	Param(
		[Parameter(
			Mandatory = $false,
			Position = 0
		)]
		[string]$DsServer,
		
		[Parameter(
			Mandatory = $false
		)]
		[ValidateSet('LDAP','LDAPS')]
		[string]$DSConnection = "LDAP",
		
		[Parameter(
			Mandatory = $false
		)]
		[ValidateSet('DSP','LDAP','ADObject')]
		[string]$SchemaSearch = 'DSP',

		[switch]
		$SaveSchema = $false,
		
		[switch]
		$ExcludeGPOReports = $false,
		
		[string[]]$ExcludedDomains,
		
		[switch]$DisplayDynamicObjects = $false,
		
		[string]$OutputFolder = "$env:UserProfile\Documents\Semperis",
		
		[Alias ('LL')]
		[int]$LogLevel = 1
		
	)

Function ConvertTo-FormattedDateString ($date) {if($date){return ([datetime]$date).ToString('yyy-MM-dd HH:mm:ss')}}

	$IsDevBuild = $false
	[string]$scriptVersion = '22'
	If ($IsDevBuild) {$scriptVersion += ' (Dev)'}
	
	$validDirectory = $true
	$invalidLinkId = $false
	$invalidSchema = $false
	$PageSize = 120
	$DSPCanBeInstalled = $true

	$ADVersionNames = @{
		14 = 'Windows 2000'
		24 = 'Windows 2003 SP3'
		30 = 'Windows 2003'	
		31 = 'Windows 2003 R2'
		44 = 'Windows 2008'	
		47 = 'Windows 2008 R2'
		69 = 'Windows 2012 R2'
		72 = 'Windows 2016 TP'	
		81 = 'Windows 2016 TP 2' 	
		82 = 'Windows 2016 TP 3'	
		85 = 'Windows 2016 TP 4'	
		87 = 'Windows 2016'
		88 = 'Windows 2019'	
	}

	$DsPorts = @{
		'LDAP' = 389
		'LDAPS' = 636
		'GC' = 3268
		'GCS' = 3269
	}

function Write-smprsLog {
	param (
		[int]$LogType = 1,
#		[int]$LogLevel = 2,
		[string]$Message
	)
	
	if ($LogType -le $LogLevel) {
		Write-Host $Message
	}
	
	if ($LogFile) {
		$Message >> $LogFile
	}

}

Function ExecuteDirectorySearch {
	param (
		$DirectorySearcher,
		$SearchRoot,
		$SearchScope,
		$Filter,
		$Attributes,
		$SecurityMask,
		$Message

	)

	if ($Message) {Write-smprsLog 1 $Message}

	try {
		if ($SearchRoot) {
			$DirectorySearcher.SearchRoot.Path = $SearchRoot
		}
		$DirectorySearcher.SearchScope = $SearchScope
		$DirectorySearcher.Filter = $Filter
		$Null = $DirectorySearcher.PropertiesToLoad.clear()
		$Null = $DirectorySearcher.PropertiesToLoad.AddRange($Attributes)
		if ($SecurityMask) {
			$DirectorySearcher.SecurityMasks = $SecurityMask
		}
	}
	catch {
		Write-smprsLog 0 "Error: Configuring DirectorySearcher:"
		Write-smprsLog 0 "  SearchRoot: $SearchRoot"
		Write-smprsLog 0 "  Filter:     $Filter"
		Write-smprsLog 0 "  Attributes: $Attributes"
		Write-smprsLog 0 "  Scope:      $SearchScope"
		Write-smprsLog 0 "Error: $(([ComponentModel.Win32Exception] $DirectorySearcher).Message)"

		Return $Null

	}

	# Process the query
	try {
		$results = $DirectorySearcher.FindAll().properties

	}
	catch {
		Write-smprsLog 0 "Error: at DirectorySearcher.FindAll:"
		Write-smprsLog 0 "  SearchRoot: $SearchRoot"
		Write-smprsLog 0 "  Filter:     $Filter"
		Write-smprsLog 0 "  Attributes: $Attributes"
		Write-smprsLog 0 "  Scope:      $SearchScope"
		Write-smprsLog 0 ("`n{0}`n{1}" -f ($_.ErrorDetails.Message,$_.ScriptStackTrace))

		$results = $Null

	}

	Return $results

}

Function isCustomGPO {
	param (
		[string]$ExtensionNames
	)
	
	# XenApp / Citrix custom GPO identifier
	[string]$customGPO = '{0D0C7034-2EBD-4A87-A9B9-9015E3F2E6E0}{015F9736-7663-4CA9-B32D-7DDDA0F0E2FB}'
	
	if ($ExtensionNames) {
		return (($ExtensionNames.Substring($ExtensionNames.count).Replace('[','').Split(']')) -contains $customGPO)
	}
	else {
		return $false
	}
}

	$gpsmEstimatedGPOBackupTimeSeconds = 10
	$gpsmBackupTimeDefault = 3600		# 1 hour in seconds
	$BackupGPOs = !$ExcludeGPOReports
	[string[]]$unsupportedFeatures = @()
	[int]$forestDynamicObjectCount  = 0

	Write-smprsLog 0 ("Test-smprsDSPReadiness v{0}" -f $scriptVersion)
	
	# Check for minimum requirements to running
	$validateRequirements = $true
	If ($PSVersionTable.PSVersion.Major -lt 5) {$validateRequirements = $false; Write-smprsLog 1 "Requires PowerShell 5.1 or later"}
	$modules = Get-Module -ListAvailable
#	If (!($modules | where {$_.Name -like 'ActiveDirectory'})) {$validateRequirements = $false; Write-smprsLog 1 "Requires PowerShell module ActiveDirectory"}
	If (!($modules | where {$_.Name -like 'GroupPolicy'}) -and $BackupGPOs) {
#		$validateRequirements = $false
		Write-smprsLog 1 "`nRequires PowerShell module GroupPolicy to detect problem GPOs`nDisabling GPO testing" -ForegroundColor Yellow
		$ExcludeGPOReports = $true
	}
	if(!$validateRequirements) {
		Write-smprsLog 1 "One or more prerequisites missing unable to continue`n" -ForegroundColor Red
		return
	}

	if (!$DsServer){
		$DSPath = ("{0}://RootDSE" -f $DSConnection)
	}
	else {
		$DSPath = ("{0}://{1}/RootDSE" -f $DSConnection,$DsServer)
	}

	# All the properties returned are of type System.DirectoryServices.PropertyValueCollection so have to explicitly get the first entry
	try {
		$directory = ([ADSI]$DSPath)
	}
	catch {
		Write-smprsLog 0 $_
		return
	}
	
	if ($directory.rootDomainNamingContext.count -eq 0) {
		Write-smprsLog 1 ("`nError: No Root DomainNaming Context returned`n  DsServer: {0}`n  DSPath: {1}`n  User: {2}`n`nPass a Forest, Domain or DC FQDN as a parameter`n" -f $DsServer,$DSPath,("$env:userdomain\$env:username"))
		return
	
	}

	$ForestADSPath = $directory.rootDomainNamingContext[0]
	$ForestDnsName = $ForestADSPath -replace 'DC=','' -replace ',','.'
	$ConnectedDsServer = $directory.dnshostname[0]
	$LdapPath = ("{0}://{1}" -f $DSConnection,$ConnectedDsServer)

	$ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest',$ForestDnsName)
	$ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)

	# Create Searcher Object
	$DomainSearcher = New-Object DirectoryServices.DirectorySearcher
	$DomainSearcher.PageSize = $PageSize
	$DomainSearcher.CacheResults = $False
	$DomainSearcher.ExtendedDN = 0

	# Get schema Object
	$context = new-object System.DirectoryServices.ActiveDirectory.DirectoryContext @(([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::DirectoryServer), (("{0}:{1}" -f $ConnectedDsServer,$DsPorts[$DSConnection])))
	$schema = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySchema]::GetSchema($context)
	$schemaObject =  new-object System.DirectoryServices.DirectoryEntry(("{0}://{1}/{2}" -f $DSConnection, $ConnectedDsServer, $schema.Name))
	$schemaVersion = $schemaObject.objectVersion
	$schemaVersionName = $ADVersionNames[$schemaVersion]

	# Define the output filenames
	if (!$OutputFolder.EndsWith('\')) {$OutputFolder += '\'}
	$ScriptOutputFolder = ("{0}Test-smprsDSPReadiness" -f $OutputFolder)
	if (!(Test-Path -Path $ScriptOutputFolder -ErrorAction SilentlyContinue)) {
		$f = New-Item -Path $ScriptOutputFolder -ItemType 'Directory' -force
	}
	
	$LogFile = "{0}\Test-smprsDSPReadiness-{1}.log" -f $ScriptOutputFolder,$ForestDnsName

	# Initialise a fresh copy of the logfile, don't display to the screen
	if (Test-Path -Path $Logfile -ErrorAction SilentlyContinue) {Remove-Item -Path $LogFile}
	
	Write-smprsLog 99 ("Test-smprsDSPReadiness v{0}" -f $scriptVersion)
	
	$SaveSchemaFile = "{0}\Schema_{1}_{2}_{3}.csv" -f $ScriptOutputFolder,$ForestDnsName,$ConnectedDsServer,$SchemaSearch
	$SaveLinkIdFile = "{0}\InvalidLinkId{1}_{2}.csv" -f $ScriptOutputFolder,$ForestDnsName,$ConnectedDsServer
	if (Test-Path -Path $SaveLinkIdFile -ErrorAction SilentlyContinue) {
		Remove-Item -Path $SaveLinkIdFile
	}
	$SaveDuplicateOidFile = "{0}\DuplicateOid{1}_{2}.csv" -f $ScriptOutputFolder,$ForestDnsName,$ConnectedDsServer
	if (Test-Path -Path $SaveDuplicateOidFile -ErrorAction SilentlyContinue) {
		Remove-Item -Path $SaveDuplicateOidFile
	}

	Write-smprsLog 1 "`nParameters:"
	Write-smprsLog 1 "  DsServer:         $DsServer"
	Write-smprsLog 1 "  DSConnection:     $DSConnection"
	Write-smprsLog 1 "  SchemaSearch:     $SchemaSearch"
	if ($SaveSchema) {
		Write-smprsLog 1 ("  SaveSchema:")
		Write-smprsLog 1 ("    Path:       $SaveSchemaFile")

		"objectClass;lDAPDisplayName;oid;isDefunct;syntax;whenCreated;whenChanged" > $SaveSchemaFile
		
	}
	Write-smprsLog 1  "  OutputPath:       $ScriptOutputFolder"

	Write-smprsLog 1  "`nForest:"
	Write-smprsLog 1  "  FQDN:             $ForestDnsName"
	Write-smprsLog 1  "  ForestADSPath:    $ForestADSPath"
	Write-smprsLog 1 ("  FunctionalLevel:  {0}" -f $ForestObject.ForestModeLevel)
	Write-smprsLog 1  "  ConnectedServer:  $ConnectedDsServer"
	Write-smprsLog 1 ("  Schema:")
	Write-smprsLog 1 ("    SchemaADSPath:  {0} " -f $directory.schemaNamingContext[0])
	Write-smprsLog 1 ("    Version:        $schemaVersion ($schemaVersionName)")
	
	# Create Searcher Object
	$DomainSearcher = New-Object DirectoryServices.DirectorySearcher
	$DomainSearcher.PageSize = $PageSize
	$DomainSearcher.CacheResults = $False
	# $DomainSearcher.SearchRoot = ""
	$DomainSearcher.ExtendedDN = 0
	
	Write-smprsLog 1 "`n  Checking Optional Features..."
	
	# All Attribute Objects
	$Arguments = @{
		DirectorySearcher = $DomainSearcher
		SearchRoot = ("{0}/{1}" -f $LdapPath,($directory.configurationNamingContext.ToString()))
		SearchScope = "subTree"
		Filter = '(&(objectClass=msDS-OptionalFeature))'
		Attributes = @('objectClass','cn','msDS-OptionalFeatureFlags','msDS-EnabledFeatureBL')
	}

	try {
		$results = ExecuteDirectorySearch @Arguments
		
		foreach ($result in $results) {
			$featureState = 'Disabled'
			$featureName = $result.cn
			if ($result.'msds-enabledfeaturebl'.Count -gt 0) {
				$featureState = 'Enabled'
				switch ($featureName) {
					'Privileged Access Management Feature' {$unsupportedFeatures += $featureName}
				}
			}

			Write-smprsLog 1 ("    {0}: {1}" -f $featureName[0],$featureState)

		}
		
	}
	catch {
		Write-smprsLog 0 "  Error getting $schemaClass class using $SchemaSearch search"
		Write-smprsLog 0 $_.ErrorDetails
		Write-smprsLog 0 $_.ScriptStackTrace
		Write-smprsLog 0 ''
		$results = $null
		
	}

	Write-smprsLog 1 "`n  Checking Schema for known issues..."
	$oids = @{}

	$CountClasses = @{
		Active = 0
		Defunct = 0
	}

	$CountAttributes = @{
		Active = 0
		Defunct = 0
	}

	foreach ($schemaClass in 'Class','Attribute') {
		Write-smprsLog 1 "    $schemaClass objects"
		try{
			switch ($schemaClass) {
				'Class' {
					switch ($SchemaSearch) {
						'DSP' {
							$results = $schema.FindAllClasses() + $schema.FindAllDefunctClasses()

						}
						
						'ADObject' {
							$results = Get-ADObject -LDAPFilter '(&(objectClass=classSchema))' -Searchbase $schema.name -SearchScope Subtree -Server $ConnectedDsServer -Properties 'objectClass','lDAPDisplayName','governsID','isDefunct','defaultSecurityDescriptor','whenCreated','whenChanged'

						}

						'LDAP' {
							# All Class Objects
							$Arguments = @{
								DirectorySearcher = $DomainSearcher
								SearchRoot = ("{0}/{1}" -f $LdapPath,($directory.schemaNamingContext.ToString()))
								SearchScope = "subTree"
								Filter = '(&(objectClass=classSchema))'
								Attributes = @('objectClass','lDAPDisplayName','governsID','isDefunct','defaultSecurityDescriptor','whenCreated','whenChanged')
							}

							$results = ExecuteDirectorySearch @Arguments

						}
						
					}

				}

				'Attribute' {
					switch ($SchemaSearch) {
						'DSP' {
							$results = $schema.FindAllProperties()  + $schema.FindAllDefunctProperties()

						}
						
						'ADObject' {
							$results = Get-ADObject -LDAPFilter '(&(objectClass=attributeSchema))' -Searchbase $schema.name -SearchScope Subtree -Server $ConnectedDsServer -Properties 'objectClass','lDAPDisplayName','attributeID','attributeSyntax','linkID','isDefunct','whenCreated','whenChanged'

						}

						'LDAP' {
							# All Attribute Objects
							$Arguments = @{
								DirectorySearcher = $DomainSearcher
								SearchRoot = ("{0}/{1}" -f $LdapPath,($directory.schemaNamingContext.ToString()))
								SearchScope = "subTree"
								Filter = '(&(objectClass=attributeSchema))'
								Attributes = @('objectClass','lDAPDisplayName','attributeID','attributeSyntax','linkID','isDefunct','whenCreated','whenChanged')
							}

							$results = ExecuteDirectorySearch @Arguments

						}
						
						
					}

				}

			}
		}
		catch {
			Write-smprsLog 0 "  Error getting $schemaClass class using $SchemaSearch search"
			Write-smprsLog 0 $_.ErrorDetails
			Write-smprsLog 0 $_.ScriptStackTrace
			Write-smprsLog 0 ''
			$results = $null

		}

		if ($results) {
			foreach ($object in $results) {
				switch ($SchemaSearch) {
					'DSP' {
						$oid = $object.Oid
						$lDAPDisplayName = $object.Name
						$syntax = $object.Syntax

					}

					'ADObject' {
						if ($object.objectClass -contains 'attributeSchema') {
							$oid = $object.attributeID
						}
						else {
							$oid = $object.governsID
						}
						$lDAPDisplayName = $object.lDAPDisplayName
						$syntax = $object.attributeSyntax

					}

					'LDAP' {
						# the properties of $object must be referenced as lowercase to work !!
						if ($object.objectclass -contains 'attributeSchema') {
							$oid = $object.attributeid
						}
						else {
							$oid = $object.governsid
						}
						$lDAPDisplayName = $object.ldapdisplayname
						$syntax = $object.attributesyntax

					}
					
				}

				# Explicitly define so always written as True or False to output file
				$isDefunct = $false
				if ($object.isdefunct) {$isDefunct = $true}

				switch ($schemaClass) {
					'Class' {
						if ($isDefunct) {
							$CountClasses.Defunct += 1
						}
						else {
							$CountClasses.Active += 1
						}

						#check for invalid defaultSecurityDescriptor - duplicate ACEs in the string
						if ($object.defaultsecuritydescriptor) {
							try {
								$ntsd = ConvertFrom-SddlString -Sddl ($object.defaultsecuritydescriptor) -Type ActiveDirectoryRights | Out-Null
							}
							catch {
								$invalidSchema = $true
								$DSPCanBeInstalled = $false
								Write-smprsLog 0 ("Invalid defaultSecurityDescriptor:`n`tlDAPDisplayName: {0}`n`tdefaultSecurityDescriptor: {1}" -f $lDAPDisplayName, ($object.defaultsecuritydescriptor))
								
							}
							
						}

					}
					'Attribute' {
						if ($isDefunct) {
							$CountAttributes.Defunct += 1
						}
						else {
							$CountAttributes.Active += 1
						}

						# Can't use -le 1 because null is interpreted as 0 and results in a false true
						if (($object.linkid -eq 0) -or ($object.linkid -eq 1)) {
							$validDirectory = $false
							$invalidLinkId = $true
							$el = "Invalid LinkID: value={0} on {1}" -f $object.linkid, $object.Name
							Write-smprsLog 1 "    $el"
							$el >> $SaveLinkIdFile
						}

					}

				}

				$ee = "{0};{1};{2};{3};{4};{5};{6}" -f $schemaClass,$lDAPDisplayName, $oid, $isDefunct, $syntax ,(ConvertTo-FormattedDateString($object.whenCreated)),( ConvertTo-FormattedDateString($object.whenChanged))

				if ($SaveSchema) {
					$ee >> $SaveSchemaFile
				}

				if ($oid) {
					if (!$oids.containsKey($oid)) {
						$oids.Add($oid,$ee)
					}
					else {
						$DSPCanBeInstalled = $false
						$invalidSchema = $true
						$eed =  "{0}" -f $oids.Get_Item($oid)
						Write-smprsLog 1 "    duplicate OID: $oid"
						Write-smprsLog 1 "      $ee"
						Write-smprsLog 1 "      $eed"
						
						$eed >> $SaveDuplicateOidFile
						$ee >> $SaveDuplicateOidFile

					}
				}
				else {
					Write-smprsLog 1 "`nWarning: Null OID"
					Write-smprsLog 1 "$ee`n"
				}

			}

		}

	}

	Write-smprsLog 1 "`n    Counts:"
	Write-smprsLog 1 ("      Classes:`n        Active: {0}`n        Defunct: {1}`n        Total: {2}" -f $CountClasses.Active,$CountClasses.Defunct,($CountClasses.Active + $CountClasses.Defunct))
	Write-smprsLog 1 ("      Attributes:`n        Active: {0}`n        Defunct: {1}`n        Total: {2}" -f $CountAttributes.Active,$CountAttributes.Defunct,($CountAttributes.Active + $CountAttributes.Defunct))

	Write-smprsLog 1 "`nChecking Domain partitions for known issues"
	[int]$countForestCustomGPOs = 0
	[int]$countDomains = 0
	[int]$gpsmMaxBackupTime = 0
	
	ForEach($Domain in $ForestObject.Domains) {
		if ($ExcludedDomains -contains $Domain) {continue}
		
		$countDomains++
		if ($countDomains -gt 1) {Write-smprsLog 1 ""}
		
		$DomainFqdn = $Domain.name
		$DomainDn = "DC=" + $DomainFqdn.Replace('.',',DC=')
		Write-smprsLog 1 ("  {0}" -f $DomainFqdn)
		
		if (!$Domain.DomainControllers) {
			Write-smprsLog 0 "    Unable to connect to DC in domain: $DomainFqdn"
			continue
		}

		# Find a DC that we can connect to
		for ($i = 0 ; $i -lt $Domain.DomainControllers.count ; $i++) {
			$DomainDC = $Domain.DomainControllers[$i]
			$DomainDcName = $DomainDC.name
			$DSPrefix = "${DSConnection}://$DomainDcname/"

			$DSRootDSEPath = ("{0}RootDSE" -f $DSPrefix)

			try {
				$directory = ([ADSI]$DSRootDSEPath)
				
				Write-smprsLog 1 ("    Connected to: {0}" -f $DomainDcName)
				
				$DomainDcDn = $DomainDC.GetDirectoryEntry().ServerReference
				
				# We found a DC so use it
				break
			}
			catch {
				Write-smprsLog 0 ("Failed to connect to: {0}" -f $DomainDcName)
				$DSPrefix = ''
			}

		}
		
		if (!$DSPrefix) {
			Write-smprsLog 0 "    Unable to connect to DC in domain: $DomainFqdn"
			continue

		}
			
		if ($debug) {
			Write-smprsLog 1 "    Search Parameters"
			Write-smprsLog 1 "      DomainDN: $DomainDN"
			Write-smprsLog 1 "      DomainDcName: DomainDcName"
			Write-smprsLog 1 "      DomainDcDn: DomainDcDn"
			Write-smprsLog 1 "      DSPrefix: $DSPrefix"
		}

		# Create Searcher Object
		try {
			$DomainObject = New-Object DirectoryServices.DirectoryEntry($DSPrefix+$DomainDn)
			$DomainSearcher = New-Object DirectoryServices.DirectorySearcher($DomainObject)
			$DomainSearcher.PageSize = $PageSize
			$DomainSearcher.CacheResults = $False
			# $DomainSearcher.SearchRoot = ""
			$DomainSearcher.ExtendedDN = 0
			
		}
		catch {
			Write-smprsLog 0 "    Unable to connect to DC in domain: $DomainFqdn"
			continue
		}
	
		# Domain Type
		Write-smprsLog 1 "    Domain Details:"
		$Arguments = @{
			DirectorySearcher = $DomainSearcher
			SearchScope = "base"
			Filter = "(objectClass=domainDNS)"
			Attributes = @("name","nTMixedDomain")
		}

		try {
			$results = ExecuteDirectorySearch @Arguments

			# Using ($results.nTMixedDomain)[0] results in an error .ntmixeddomain works !!
			if (($results.ntmixeddomain)[0] -eq 0) {
				$DomainType = "Native"
			}
			else {
				$DomainType = "Mixed"
				$DSPCanBeInstalled = $false

			}

			Write-smprsLog 1 "      DomainType: $DomainType"

		}
		catch {
			Write-smprsLog 0 "Error: $(([ComponentModel.Win32Exception] $result).Message)"

		}
		
		Write-smprsLog 1 ("      Domain Mode: {0}" -f $Domain.DomainMode)
		Write-smprsLog 1 ("      DC Count: {0}" -f $Domain.DomainControllers.count)
		Write-smprsLog 1 ("      FSMO Role Holders:")
		Write-smprsLog 1 ("        PDC: {0}" -f $Domain.PdcRoleOwner)
		Write-smprsLog 1 ("        RID: {0}" -f $Domain.RidRoleOwner)
		Write-smprsLog 1 ("        Infrastructure Master: {0}" -f $Domain.InfrastructureRoleOwner)
		
		# Write-smprsLog 1 "    Checking Domain Language"
		# Look for well known sid of domain admins
		# cn=Users by SID
		$Arguments = @{
			DirectorySearcher = $DomainSearcher
			SearchScope = "subTree"
			Filter = "(&(objectClass=group)(objectSID=\01\02\00\00\00\00\00\05\20\00\00\00\21\02\00\00))"
			Attributes = @("name","cn")
		}

		try {
			$results = ExecuteDirectorySearch @Arguments

			switch ($results.cn) {
				'Users' {
					$DirectoryLanguage = "en"
					$DirectoryLanguageText = "English"
				}
				'Usuarios' {
					$DirectoryLanguage = "es"
					$DirectoryLanguageText = "Spanish"
				}
				'Benutzer' {
					$DirectoryLanguage = "de"
					$DirectoryLanguageText = "German"
				}
				'Utilisateurs' {
					$DirectoryLanguage = "fr"
					$DirectoryLanguageText = "French"
				}
				'Gebruikers' {
					$DirectoryLanguage = "nl"
					$DirectoryLanguageText = "Dutch"
				}
				'Convidados' {
					$DirectoryLanguage = "po"
					$DirectoryLanguageText = "Portuguese"
				}
				default {
					$DirectoryLanguage = "??"
					$DirectoryLanguageText = $results.cn.ToString()
				}

			}

			Write-smprsLog 1 ("      Language: {0} ({1})" -f $DirectoryLanguage,$DirectoryLanguageText)

			if ($DirectoryLanguage -ne 'en') {
				try {
					# cn=Users by English name
					$Arguments = @{
						DirectorySearcher = $DomainSearcher
						SearchScope = "subTree"
						Filter = "(&(objectClass=group)(groupType=-214748643)(cn=Users))"	# 0x80000005 - Builtin_Local_Group | Resource_Group | Security_Enabled
						Attributes = @("name","cn")
					}

					$results = ExecuteDirectorySearch @Arguments

					if ($results) {
						Write-smprsLog 1 " Multiple Language objects found"

					}

				}
				catch {
					Write-smprsLog 0 "Error: $(([ComponentModel.Win32Exception] $result).Message)"

				}

			}

		}
		catch {

			Write-smprsLog 0 "Error: $(([ComponentModel.Win32Exception] $result).Message)"

		}

		Write-smprsLog 1 "    Checking Pre-Windows 2000 Compatible Access group contains Authenticated Users"
		$pre2000AuthenticatedUsers = $false
		
		<# search for SID 1-5-32-554 and check for presence of CN=S-1-5-11 in member #>
		$Arguments = @{
			DirectorySearcher = $DomainSearcher
			SearchScope = "subTree"
			Filter = "(&(objectClass=group)(objectSID=\01\02\00\00\00\00\00\05\20\00\00\00\2A\02\00\00))"
			Attributes = @("name","member")
		}

		try {
			$results = ExecuteDirectorySearch @Arguments

			foreach ($result In $results) {
				foreach ($memberEntry in $result.member) {
					$memberDN = $memberEntry.Split(';')[2]
					if ($memberDN.ToUpper().StartsWith('CN=S-1-5-11,')) {$pre2000AuthenticatedUsers = $true}
				}
			}
			
			if (!$pre2000AuthenticatedUsers) {
				Write-smprsLog 1 "      Authenticated Users not found"
				$DSPCanBeInstalled = $false
				
			}
			
		}
		catch {
			
		}
		
		# Password Last Set = -1
		Write-smprsLog 1 "    Checking for objects with pwdLastSet=-1"
		
		$SavePwdLastSet = "{0}\PwdLastSet_{1}_{2}.csv" -f $ScriptOutputFolder,$DomainFqdn,$ConnectedDsServer
		if (Test-Path -Path $SavePwdLastSet -ErrorAction SilentlyContinue) {
			Remove-Item -Path $SavePwdLastSet
		}

		$Arguments = @{
			DirectorySearcher = $DomainSearcher
			SearchScope = "subTree"
			Filter = "(&(objectCategory=person)(objectClass=user)(pwdLastSet=-1))"
			Attributes = @("objectClass","objectCategory","name","displayName","sAMAccountName","userPrincipalName")
		}

		try {
			$results = ExecuteDirectorySearch @Arguments -Message 'Find pwdLastSet = -1'

			ForEach ($result In $results) {
				$invalidPwdLastSet = $true
				$DSPCanBeInstalled = $false
				
				$out = "{0} ; {1}" -f $result.Item('name'), $result.item('sAMAccountName')
				Write-smprsLog 1 ("      " + $out)
				
				$out >> $SavePwdLastSet
			}

		}
		catch {
			Write-smprsLog 0 "Error: $(([ComponentModel.Win32Exception] $result).Message)"

		}

		Write-smprsLog 1 "    Checking for Semperis SCP Objects"
		$Arguments = @{
			DirectorySearcher = $DomainSearcher
			SearchScope = "subTree"
			Filter = "(&(objectClass=serviceConnectionPoint)(cn=Semperis*))"
			Attributes = @("name","cn","distinguishedName","keywords","serviceDNSName","whenChanged","whenCreated")
		}

		try {
			$results = ExecuteDirectorySearch @Arguments
			
			foreach ($result in $results) {
				switch ($result.Item('name')) {
					'Semperis.Adsn.Management' {Write-smprsLog 1 ("      Audit: {0}" -f ($result.Item('distinguishedName').Split(';',2)[1]))}
					'Semperis.Adsn.Collector'  {Write-smprsLog 1 ("      Audt Collector: {0}" -f ($result.Item('distinguishedName').Split(';',2)[1]))}
					'Semperis.Dsp.Management'  {Write-smprsLog 1 ("      DSP: {0}" -f ($result.Item('distinguishedName').Split(';',2)[1]))}
					default {Write-smprsLog 1 ("      Unknown Semperis SCP object: {0}" -f ($result.Item('distinguishedName').Split(';',2)[1]))}
				}
			}

		}
		catch {
			Write-smprsLog 0 "Error: $(([ComponentModel.Win32Exception] $result).Message)"
			
		}

		Write-smprsLog 1 "    Checking for localhost objects"
		$Arguments = @{
			DirectorySearcher = $DomainSearcher
			SearchScope = "subTree"
			Filter = "(|(&(objectClass=computer)(cn=localhost))(&(objectClass=computer)(sAMAccountName=localhost))(&(objectClass=computer)(servicePrincipalName=host/localhost*)))"
			Attributes = @("name","cn","distinguishedName","whenChanged","whenCreated")
		}
		
		[int]$countDomainLocalHostObjects = 0

		try {
			$results = ExecuteDirectorySearch @Arguments
			
			foreach ($result in $results) {
				$countDomainLocalHostObjects++
				$DSPCanBeInstalled = $false
				
				if (($result.Item('name')) -eq 'localhost') {
					Write-smprsLog 1 ("      Computer: {0}" -f ($result.Item('distinguishedName').Split(';')[2]))
				}
				elseif (($result.Item('sAMAccountName')) -eq 'localhost') {
					Write-smprsLog 1 ("      sAMAccountName: {0}" -f ($result.Item('distinguishedName').Split(';')[2]))
				}
				else {
					Write-smprsLog 1 ("      SPN: {0}" -f ($result.Item('distinguishedName').Split(';')[2]))				
				}
			}

		}
		catch {
			Write-smprsLog 0 "Error: $(([ComponentModel.Win32Exception] $result).Message)"
			
		}

		$countForestHostObjects += $countDomainLocalHostObjects

		Write-smprsLog 1 "    Checking GPOs"
		# gpCMachineExtensionNames or gPCUserExtensionNames containing Citrix GUIDs

		$Arguments = @{
			DirectorySearcher = $DomainSearcher
			SearchScope = "subTree"
			Filter = "(|(&(objectClass=groupPolicyContainer)(gPCMachineExtensionNames=*))(&(objectClass=groupPolicyContainer)(gPCuserExtensionNames=*)))"
			Attributes = @("name","cn","displayName","gPCMachineExtensionNames","gPCUserExtensionNames","distinguishedName")
		}

		[int]$countDomainGPOs = 0
		[int]$countDomainCustomGPOs = 0
		[int]$countDomainShadowGPOs = 0
		[int]$countDomainFailedHTMLReports = 0
		[int]$countInvalidGPONames = 0
		[string]$gpoBackupPath = $env:userProfile + "\Documents\GpoReport.html"

		try {
			$results = ExecuteDirectorySearch @Arguments
			foreach ($result in $results) {
				$countDomainGPOs ++
				
				# check that displayName contains valid characters
				[char[]]$invalidChars = @()
				foreach ($c in [char[]]($result.Item('displayName')[0])) {
					if ([byte]$c[0] -lt 32) {
						$invalidChars += $c[0]
					}
					
				}

				if ($invalidChars.Count -gt 0) {
					Write-smprsLog 1 ("        displayName Contains invalid Characters:`n          Name: {0}`n          dn: {1}" -f $result.Item('displayName')[0],$result.Item('distinguishedName')[0])
					foreach ($c in $invalidChars) {
						Write-smprsLog 1 ("            {0}" -f ([byte]$c[0]))
					}
					
					$countInvalidGPONames ++
					
					$DSPCanBeInstalled = $false
					
				}
				
				if ((isCustomGPO $result.Item('gPCMachineExtensionNames')) -or (isCustomGPO $result.Item('gPCUserExtensionNames'))) {
					if (($countDomainFailedHTMLReports + $countDomainCustomGPOs + $countDomainShadowGPOs)  -eq 0) {Write-smprsLog 1 "      Problem GPOs:"}
					Write-smprsLog 1 ("        Custom GPO:`n          Name: {0}`n          dn: {1}" -f $result.Item('displayName')[0],$result.Item('distinguishedName')[0])
					$countDomainCustomGPOs ++
				}
				
				if (!$ExcludeGPOReports) {
					# Check that the GPO is in the standard MS location before generating the report
					if ($result.distinguishedname -like "*CN=Policies,CN=System,DC=*") {
						try {
							Get-GPOReport -Guid ($result.Item('cn')[0]) -ReportType Html -Path $gpoBackupPath -Domain $Domain
							
						}
						catch {
							if (($countDomainFailedHTMLReports + $countDomainCustomGPOs + $countDomainShadowGPOs)  -eq 0) {Write-smprsLog 1 "      Problem GPOs:"}
							Write-smprsLog 1 ("        GPO Report Failed:`n          Name: {0}`n          dn: {1}" -f $result.Item('displayName')[0],$result.Item('distinguishedName')[0])
							$countDomainFailedHTMLReports ++
						}
						# cleanup the report
						if (Test-Path -Path $gpoBackupPath -ErrorAction SilentlyContinue) {
							Remove-Item -Path $gpoBackupPath
						}					
					}
					else {
						if (($countDomainFailedHTMLReports + $countDomainCustomGPOs + $countDomainShadowGPOs)  -eq 0) {Write-smprsLog 1 "      Problem GPOs:"}
						Write-smprsLog 1 ("        Shadow GPO: {0}" -f $result.Item('distinguishedName')[0])
						$countDomainShadowGPOs ++
					}					
				}
			}
		}
		catch {
			Write-smprsLog 0 "Error: $(([ComponentModel.Win32Exception] $result).Message)"
			
		}
		
		Write-smprsLog 1 "      GPO Count: $countDomainGPOs"
		$gpsmBackupTime = ($countDomainGPOs * $gpsmEstimatedGPOBackupTimeSeconds)
		if ($gpsmBackupTime -gt $gpsmMaxBackupTime) {
			$gpsmMaxBackupTime = $gpsmBackupTime				
		}
		
		if ($countDomainCustomGPOs -gt 0) {
			Write-smprsLog 1 "      Custom GPO Count: $countDomainCustomGPOs"
		}
		
		$countForestCustomGPOs += $countDomainCustomGPOs
		$countForestShadowGPOs += $countDomainShadowGPOs
		$countForestFailedHTMLReports += $countDomainFailedHTMLReports
		$countForestInvalidGPONames += $countInvalidGPONames
		Write-smprsLog 1 "    Checking for Dynamic Objects"
		[int]$domainDynamicObjectCount = 0
		$Arguments = @{
			DirectorySearcher = $DomainSearcher
			SearchScope = "subTree"
			Filter = "(&(objectClass=dynamicObject))"
			Attributes = @("name","cn","distinguishedName","entryTTL","whenChanged","whenCreated")
		}

		try {
			$results = ExecuteDirectorySearch @Arguments
			
			foreach ($result in $results) {
				$domainDynamicObjectCount += 1
				if ($DisplayDynamicObjects) {Write-smprsLog 1 ("      {0}" -f ($result.Item('distinguishedName').Split(';')[2]))}
#				if (!($unsupportedFeatures -Contains 'Dynamic Opbjects')) {$unsupportedFeatures += 'Dynamic Objects'}
			}

		}
		catch {
			Write-smprsLog 0 "Error: $(([ComponentModel.Win32Exception] $result).Message)"
			
		}
		
		if ($domainDynamicObjectCount -gt 0) {
			Write-smprsLog 1 ("      Found: {0}" -f $domainDynamicObjectCount)
		}
		
		$forestDynamicObjectCount += $domainDynamicObjectCount

	}
	
	# Check if the current server is usable as a DSP Management Server
	Write-smprsLog 1 "`nChecking current server"
	$InstallOnThisServer = $true
	$ci = Get-ComputerInfo
	Write-smprsLog 1 ("  CPU Count: {0}" -f $ci.CsNumberOfLogicalProcessors)
	
	if ($ci.CsNumberOfLogicalProcessors -lt 4) {
		Write-smprsLog 1 "    CPU Count below minimum recommended number (4)"
		
		if ($ci.CsNumberOfLogicalProcessors -lt 2) {
			Write-smprsLog 1 "    CPU Count below minimum supported number (2)"
			$InstallOnThisServer = $false
		}
		
	}

	if ($countForestShadowGPOs -gt 0) {
		Write-smprsLog 1 "`nWARNING: Shaddow GPOs have been detected in the forest"
		Write-smprsLog 1 "  Shaddow GPOs are GPO objects that are located outside the 'cn=Policies,cn=System' container"
		Write-smprsLog 1 "  of the domain.  These GPO objects are ignored by Microsoft GPO processing and cannot be backed"
		Write-smprsLog 1 "  up by the DSP GPO backup process.  Changes to the AD component of the object are tracked by"
		Write-smprsLog 1 "  regular DSP changed item processes"
	}
	
	if ($DSPCanBeInstalled) {
		Write-smprsLog 1 "`nSemperis DSP can be installed in the directory"

		if ($invalidLinkId) {
			Write-smprsLog 1 "  LinkID must be updated to not-set (recommended) or build 2.7.7355 or greater installed"
		}
		
		if ($countForestFailedHTMLReports -gt 0) {
			Write-smprsLog 1 ("  GPOs that fail to generate HTML Reports detected: {0}" -f $countForestFailedHTMLReports)
			Write-smprsLog 1 "  DSP build 3.5 Sp5 or 3.6 Sp1 and later is required to support GPOs that fail to generate HTML Reports"
		}
		
		if ($countForestCustomGPOs -gt 0) {
			Write-smprsLog 1 ("  Custom GPOs detected: {0}" -f $countForestCustomGPOs)
			Write-smprsLog 1 "  DSP build 3.5 Sp5 or 3.6 Sp1 and later may be required to support custom GPOs"
		}

		if (!$InstallOnThisServer) {
			Write-smprsLog 1 "  DSP is not supported on this server"
		}
		
		if ($gpsmMaxBackupTime -gt $gpsmBackupTimeDefault) {
			# double the estimated time to make sure we have plenty of time
			$gpsmRecomendedMaxBackupTime = $gpsmMaxBackupTime * 2
			$gpsmRecomendedMaxBackupTimeMin = $gpsmRecomendedMaxBackupTime / 60
			Write-smprsLog 1 ("  GPO  Backup Timeout must be increased to {0} minutes" -f $gpsmRecomendedMaxBackupTimeMin)
			Write-smprsLog 1 ("    Recomend setting the Semperis registry entry on the DSP Management Server:")
			Write-smprsLog 1 ("    HKLM:\SOFTWARE\Semperis\Gpsm\Timeouts\GpsmBackupDownloadMaxTimeSeconds:Reg_Dword = {0}" -f $gpsmRecomendedMaxBackupTime)
		}
		
		if ($unsupportedFeatures.Count -gt 0) {
			Write-smprsLog 1 "  DSP does not support the following Optional Features:"
			foreach ($feature in $unsupportedFeatures) {
				Write-smprsLog 1 "    $feature"
				switch ($feature) {
					'Privileged Access Management Feature' {
						Write-smprsLog 1 "      DSP will restore expired group members when restoring a deleted group"
					}
				}
			}
		}
		
	}
	else {
		Write-smprsLog 1 "`nSemperis DSP can not currently used for this forest or requires a mimimum version of DSP"

		if ($invalidSchema) {
			Write-smprsLog 1 "  Invalid Directory schema must be fixed"
		}

		if ($invalidPwdLastSet) {
			Write-smprsLog 1 "  pwdLastSet values of -1 must be set to valid date or not-set"
		}

		if ($countForestHostObjects -gt 0) {
			Write-smprsLog 1 "  computerObject = localhost or computer object with SPN=localhost must be removed"
		}

		if ($invalidLinkId) {
			Write-smprsLog 1 "  LinkID must be updated to not-set (recommended) or build 2.7.7355 or greater installed"
		}
		
		if (($countForestCustomGPOs -gt 0) -or ($countForestFailedHTMLReports -gt 0)) {
			Write-smprsLog 1 "  DSP build 3.5 Sp5 or 3.6 Sp1 and later is required to support problem GPOs"
		}

		if ($countForestInvalidGPONames -gt 0) {
			Write-smprsLog 1 "  GPOs with invalid names detected, GPO Backups will fail"
		}
		
		if (!$pre2000AuthenticatedUsers) {
			Write-smprsLog 1 ("  One or momre Domains do not include 'NT Authority\Authentcated Users' in the 'Pre-Windows 2000 Compatible Access' group")
			Write-smprsLog 1 ("    By default membership of the Pre-Windows 2000 Compatible Access group is required to access the")
			Write-smprsLog 1 ("    cn=MicrosoftDNS,cn=System,<partition-adpath> container in each partition hosting DNS objects. The")
			Write-smprsLog 1 ("    account used to install DSP requires read access to these containers")
		}

	}

	Write-smprsLog 1 ""
	
	return $ScriptOutputFolder
