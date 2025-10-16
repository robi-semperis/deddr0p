################################################################################
################################################################################
##
## Invoke-CreateDspChangeDataForDemos.ps1
##
##
## Run this script on a LAB DC to generate interesting DSP data, but will also
## work on the DSP server.
##
## There are more run-related comments after the change notes section below.
##
## To summarize, this script does the following activities to populate AD 
## with change data:
##
##   * Creates many object types consistently to populate AD.
##
##   * Makes consistent changes for demo'ing of DSP.
##
##   * "Fixes"/re-creates objects that it previously created.
##
##   * Makes changes in the Configuration partition: subnets, sites, etc.
##
##   * Makes changes in the primary DNS zone (DomainDnsZone) for the root domain.
##
##   * Adds and changes DNS records.
##
##   * Makes changes in a reverse zone (PTR records).
##
##   * Creates GPO and makes changes.
##
##   * Makes changes to the Default Domain Policy.
##
##   * Makes group changes.
##
##   * Makes changes to user attributes.
##
##   * Using the Credential Management, creates changes as a different user
##     to a few attributes on a user object.
##
##   * Performs an automated undo operation using the DSP PoSh cmdlets.
##
##   * Locks out a user account. (Too many bad password attempts.)
##
##   * Makes changes to ACL's.
##
##   * Created and modifies (and deletes) FGPP's. (msDS-PasswordSettings)
##
##   * userAccountControl modifications on multiple user accounts.
##
##   * Adds a new AD site, subnet, and replication link.
##
##   * Creates a special OU with extremely restricted OU access, and then
##     populates the OU with some computer objects to represent tier 0 assets.
##   
##   * Script creates a top-level OU structure populated with objects,
##     and later in the script the OU is deleted. This allows you to easily
##     demo the recovery of an entire OU structure. The script re-populates
##     the OU every time it is run, so this is always available.
##
################################################################################
################################################################################


<#  
.SYNOPSIS  
    Active Directory activity-generation script.

.DESCRIPTION
    Automatically gemerate AD activities such as users, groups, DNS, GPOs, FGPP, and changes to objects and ACLs.

.EXAMPLE
    Invoke-CreateDspChangeDataForDemos.ps1

    Runs with default parameters" no commandline options.

.NOTES  
    Author     : Rob Ingenthron
    Version    : 3.7.4.0-20251001
#>


<#
.CREATE_SHORTCUT
   
   You may want to create a short to run this script more quickly from the desktop.

   Due to UAC, you may not be abe to set the shortcut to run the PowerShell script As Administrator.

   Follow these steps to call the script and run As Administrator from a shortcut.

   NOTE: Shortcuts have a 215 character limit in the "Target:" field. So to get around
         that limitation, you can create a symbolic link to the script with a shorter
         name to call from the shortcut.

   Creating symbolic link to script: 
       Change directory to the folder where the script is located.
       Use MKLINK to create a symbolic link (assuming script is located in "c:\demo suites"):
           MKLINK "c:\demo suites\stuff.ps1" "c:\demo suites\Invoke-CreateDspChangeDataForDemos.ps1"
       Create a shortcut on the desktop and copy this command line:
           C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nologo -noprofile -Command "& {Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -nologo -noexit -ExecutionPolicy Bypass -file ""c:\demo suites\stuff.ps1""')}"

   Now just double-click the icon to run the script As Administrator.

#>






################################################################################
##------------------------------------------------------------------------------
##
## CHANGE HISTORY
##
##
## 2022-02-24  Rob Ingenthron  Release      (robi@semperis.com)
##
## 2022-03-25  Rob Ingenthron  Added a bunch more activities, including DNS reverse
##                             zone creation, more OU creation, deleting an OU,
##                             and added more attribute settings to Axl Rose.
##                             Fixed some bugs.
##
## 2022-03-28  Rob Ingenthron  Added DSP PoSH cmdlets to connect to DSP and
##                             UNDO an attribute change to Axl.
##                             IMPORTANT: Need to somehow discover the DSP server
##                             to remove the hard-coding. Can search for the
##                             SCP (service connection point).
##
## 2022-03-29  Rob Ingenthron  Added a bunch of code to search for the DSP SCP
##                             to get the DSP server name programmatically. 
##                             Added some more error-handling.
##                             Cleaned up some code. 
##                             NEED TO ADD: error-handling for when the DSP
##                                          server connection fails.
##
## 2022-03-31  Rob Ingenthron  Added code to check for good DSP connection:
##                             Loop counter to limit the time waiting for a DSP
##                             to complete.
##                             Added hard-coded section for the name of the
##                             unprivileged DSP admin to use for demos.
##                             Added hard-coded section to create and populate
##                             data into my preferred demo user account. This 
##                             is to simulate on-boarding or scripted user mods.
##
## 2022-04-12  Rob Ingenthron  Converted user and group creation (for lab change stuff)
##                             to use hash tables with PSObject for better
##                             management and to make it easier to customize.
##
##                             Added hash table blocks for the Tier 2 admin user,
##                             two generic admins, the primary demo user, and
##                              a secondary demo user.
##                             Made code to populate special groups more generic
##                             leveraging the user hash tables.
##                             Fixed up code for groups and users with If-Thens to 
##                             either create or update if already existing.
##
## 2022-04-16  Rob Ingenthron  Bug fixes.
##                             Fixed problem with DSP server discovery in single domain
##                             forest.
##                             Fixed some issues with object creation.
##                             Added two additional demo user accts.
##                             Added additional undo sections.
##                             Proved bug exists when using the undo cmdlet where
##                             the undo operation (via PoSh) does NOT show in the
##                             DSP console in the undo section for either DSP 3.5 
##                             or DSP 3.6!!
##
## 2022-04-18  Rob Ingenthron  Added another FGPP PSO 'SpecialAccounts_PSO' to 
##                             leave in place (for other reporting and usage).
##                             Added group 'Service Accounts' to which the PSO
##                             can be assigned.
##                             Experimenting with hash tables to see how I can
##                             make this code more efficient to manage as well 
##                             as easier to update.
##                             Added a 'monitoring' account into Tier 1 OU. This
##                             is getting closer to the more generic coding that
##                             should be done for user account creation/updating.
##
## 2022-05-04  Rob Ingenthron  Added code to use the Windows Credential Store to
##                             run some of the attribute-changing commands to 
##                             show a different "Changed By" name.
##                             Added a generic Operations Tier 1 account for making
##                             some attribute changes.
##
## 2022-05-05  Rob Ingenthron  Hopefully fixed an issue with my automation account:
##                             I must have had a bad attribute or something. I just
##                             removed most of the initial creation attributes,
##                             leaving it for the update steps to add them.
##                             PROBLEM: Still an issue with the DNS record for 
##                             deadhost.
##                             PROBLEM: for some reason, after a couple of runs,
##                             the Peter Griffin 'title' undo starts failing.
##                             Must be something wrong with my timing between
##                             changes. I set (reset) the attribute value in
##                             the beginning, and that should also be triggering
##                             the undo rule, so maybe that, in combination with
##                             changing it to "CEO" later, is causing a conflict.
##                             In the logs, it looks like a SQL issue or SQL
##                             communication problem. But it is a consistent
##                             issue which I just replicated in a CloudShare 
##                             environment. 
##
## 2022-05-05  Rob Ingenthron  Fixed account lockout section to not output junk,
##                             and moved the account lockout action to just after
##                             the Default Domain Policy change to '11' logon
##                             attempts.
##
## 2022-05-05  Rob Ingenthron  Added "work-around" for DSP bug where a change
##                             with no corresponding replication event leads 
##                             an auto-undo failure. See the section 
##                       "TRIGGER UNDO RULE: CHANGE 'Title' ATTRIBUTE FOR '$($DemoUser3.Name)'"
##                             for details.
##
## 2022-05-06  Rob Ingenthron  Updated some of the demouser attribute changing code.
##                             Added DemoUser4 (Paul McCartney).
##                             NOTE: Should update demouser attribute updates to
##                             determine IF a change needs to be made.
##      
## 2022-09-07  Rob Ingenthron  Added section "WMI Filters - Add WMI Filters for GPOs"
##                             function: Set-DCAllowSystemOnlyChange
##                             function: Create-WMIFilters
##
##                             The WMI filters are really nice for showing the
##                             effect of the grouping function in "Changes".
##
## 2022-09-09  Rob Ingenthron  Added some lines to effect userAccountControl.
##                             Can demo the advanced filtering example to show
##                             all changes to userAccountControl (password settings).
##
## 2022-09-13  Rob Ingenthron  Fixed GPLink actions. (Needed to try remove first.)
##                             Fixed some minor code errors.
##                             Send certain GPO link output to null. (PoSh doesn't
##                             include a native cmdlet for checking for links.)
##
## 2022-09-27  Rob Ingenthron  Added more demo user accounts for Lab Users.
##                             Fixed some minor bugs.
##                             Added more helpful information at start of script.
##
## 2022-10-03  Rob Ingenthron  Mike Carlson provded some feedback for issues running
##                             in a new environment.
##                             Fixed some error display issues: don't need to show
##                             for a "get" where there may not be data, like a new
##                             GPO for changing a registry key.
##                             Fixed some minor bugs.
##                             Added forced module loading for ActiveDirectory and
##                             GroupPolicy.
##                             In the WMI Filters section, 
##                             added "-ErrorAction SilentlyContinue" to stop output
##                             to user.
##                             Added section to try to load the RSAT DNS mgmt feature.
##                             Cleaned up some output display stuff.
##                             Attempt to load one of the DSP PoSh MSI installers,
##                             assuming it is in the same folder where this script is
##                             run from.
##                             Added a cool function that allows a user to pause
##                             longer for reading or doing something else (like
##                             download and copy the DSP PoSh module).
##
## 2022-10-06  Rob Ingenthron  Added a section to create a forward DNS zone plus
##                             four forward and PTR records. This can help with 
##                             demos/POCs to show deletion and recovery of the zone.
##                             Made changes to the WMI filter section to make
##                             a change to the description of the first 3 WMI
##                             filters to trigger some change history. Good for
##                             demonstrating how the grouping function makes the
##                             display of change data cleaner/streamlined.
##
## 2022-10-06  Rob Ingenthron  Corrected a couple of demo user names. 
##                             Also changed "RobAdmin-Tier2" to "Admin-Tier2", 
##                             which is the unprivileged user account I use for
##                             DSP demos.
##                             Added a check at the end for the ISE vs console:
##                             if running within a normal PoSh console window,
##                             there will be a 5 minute (300 seconds) delay (which 
##                             not needed in the ISE since the buffer output
##                             window is always available).
##
## 2022-10-06  Rob Ingenthron  Fixed a bug with the creation of the "automation"
##                             account. (Due to incluging non-defined attributes.)
##                             Fixed a few message output lines.
##                             Reduced a bunch of sleep intervals to run slightly
##                             faster. Still takes over 20 minutes with set delays.
##
## 2022-10-06  Rob Ingenthron  Found yet another bug with the automation acct
##                             creation due to the password policy, so I moved
##                             the Default Domain Policy GPO ahead of the user
##                             creation section so that the min password length
##                             is 8 characters to accomodate my usual 9-character
##                             password. 
##                             I will have to add more error-handling for when an
##                             account cannot be created due to the password.
##
## 2022-10-06  Rob Ingenthron  Forgot to add "-ComputerName $DomainDC1" to all 
##                             of the DNS commands, so they all failed when not
##                             running on a DC.
##                             Also modified the way I do the forced replication
##                             steps, seeing if DC2 has a value. (In CloudShare
##                             there is only one DC, so no sense in doing the 
##                             replication command twice.)
##                             Some additional error-fixing tweaks.
##
## 2022-10-07  Rob Ingenthron  Moved all of the hard-code mods to nearer the 
##                             top of the script and all in one section to make
##                             it easier to find and manage.
##                             Also made a couple of other minor tweaks.
##
## 2022-10-10  Rob Ingenthron  Added a script info section at start of script. 
##
## 2022-10-13  Rob Ingenthron  Added prompt for generic user account creation
##                             with timeout; user can specify a different 
##                             value to create more or less generic user accounts.
##                             PowerShell has no cmdlet to take input with a 
##                             timeout, so I used a pop-up to ask if the user
##                             wants a different value than the hard-coded 
##                             default. No response = default value.
##                             (Someday, I will probably have to write an .INI
##                             to store the value as a default.)
##
## 2022-10-16  Rob Ingenthron  Another bug: since adding code to populate the
##                             "DeleteMe OU" OU with some objects, this caused 
##                             an error with Remove-ADOrganizationalUnit due
##                             to the leaf objects. Even though the autocompletion
##                             in ISE didn't show it, there is a "-Recursive" 
##                             option for Remove-ADOrganizationalUnit which takes
##                             care of the leaf objects (the user accounts).
##                             (I thought I was going to have to change permissions
##                             and mess with inheritance.)
##
## 2022-10-16  Rob Ingenthron  PowerShell is so stupidly inconsistent! There is
##                             NO way to hide the error output from the DNS
##                             cmdlet Get-DnsServerZone, such as when the zone
##                             is not found, even when using a filter or error-
##                             handling commands. Sending error output to
##                             Out-Null also causes the variable assignment to
##                             null!!! SO, just have to leave the error message
##                             for the case when the zone doesn't already exist.
##
## 2022-10-16  Rob Ingenthron  Added a little more output before the auto-undo
##                             section to reiterate that an undo rule is required
##                             for that part of the demo to work.
##                             Added additional output to show the undo commands
##                             in the undo section.
##                             FOUND A BUG!! Earlier in the year, using this
##                             script, I can repeatedly show that scripted DSP
##                             undo actions are not being displayed in the  
##                             "undo actions" in DSP.
##
## 2022-10-16  Rob Ingenthron  Added some additional output messages for cmdlets.
##
## 2022-10-16  Rob Ingenthron  Minor update: enhanced the header text output for
##                             each code section. (Just added blank lines before 
##                             and after.)
##                             Added a start/title section at the start.
##
## 2022-10-16  Rob Ingenthron  Decided to move the WMI filter section down so 
##                             the prompted items (prompts for the user) will
##                             come up sooner and be doen with earlier on.
##
## 2022-10-17  Rob Ingenthron  Added Start-Transcript for logging. Also
##                             added log management to save only 5 days of logs.
##                             Added additional notes for what undo rules to 
##                             so that they trigger the auto-undo function.
##
## 2022-10-18  Rob Ingenthron  J4 set up a new lab in Abathur, and he used the
##                             PoSh module int he install folder, and we found
##                             that the Connect-DSPServer cmdlet has different
##                             options!! I've seen this before, but did not 
##                             connect the dots. There are two different PoSh
##                             installer modules: one that is included with the
##                             DSP installer wizard, and one that can be downloaded
##                             from within the DSP console. So, I had to add a
##                             line in my error-handling to just try both!
##                             $DSPconnection = Connect-DSPServer -ComputerName $DSPServerName
##                             $DSPconnection = Connect-DSPServer -Server $DSPServerName
##                             (It seems like -Server may be the older option.)
##                             Had to use a try statement to figure out the error.
##                             Could not use the Catch to determine the error
##                             because the DSP PoSh cmdlet doesn't return a unique
##                             error code for each error.
## 
## 2022-10-25  Rob Ingenthron  Mike asked me about using PoSh to change ACLs,
##                             and then I discovered a logic error in my code
##                             for the ACL change on "Bad OU": I needed to first
##                             remove the specific ACE to then add a different
##                             ACE, because I was leaving a "Deny".
##                             Now I have the code add, then remove, then add.
##
## 2022-10-26  Rob Ingenthron  Fixed an issue with the PTR records in the 
##                             "specialsite" zone. The PoSh cmdlet to add a 
##                             DNS A record including the -CreatePtr record kept
##                             failing and there was nothing online to help, so
##                             I added the use of the Add-DnsResourceRecordPtr
##                             cmdlet to all the sections where DNS A records are
##                             being created/updated.
##                             With DNS cmdlets, PoSh continually generates
##                             error messages that cannot be ignored, even
##                             when using basically the same commandline, such
##                             as with the PTR record creation. I don't want to
##                             add even more coding lines for try-catch for
##                             each cmdlet line.
##
## 2022-11-02  Rob Ingenthron  Updated password entry for demo/lab user accts.
##                             Now the script will prompt the user user to 
##                             either use a default password for all new acct
##                             creations (for any of the demo accounts, not the
##                             bulk generic user accts), or the user will be
##                             prompted for a password for each new demo/lab 
##                             user account creation (which is 7 or 8 accounts).
##                             Later I will add a prompt for the common password:
##                             In the ISE, there is a "Cancel" button on Read-Host
##                             dialogs which completely exits the script, and
##                             didn't want to spend time figuring out a good
##                             work-around that would function the same in both
##                             the ISE and the PoSh command console.
##
## 2022-11-02  Rob Ingenthron  Fixed a small coding error with the forced 
##                             replication command message. Should now work
##                             in any domain whether 1 DC or 100+ DCs.
##
## 2022-11-02  Rob Ingenthron  I added code to automate the crednetial store 
##                             management for the alternative admin account
##                             when the user opts to use the default password.
##                             This eliminates an additional prompt since we
##                             already have the needed password.
##
## 2022-11-07  Rob Ingenthron  Added a few more lines for the changes by an
##                             alternate admin account. (Just to show a different
##                             'who" account name in the changes.)
##
## 2022-11-09  Rob Ingenthron  Had to add some more delay between changes done
##                             with the alternative admin.
##
## 2022-11-10  Rob Ingenthron  Added DemoUser3 as the manager of some of the 
##                             DemoUser accounts. Only adding the manager when
##                             updating, not on newly created.
##                             Just adding to show in some of the reports.
##
## 2022-11-29  Rob Ingenthron  Added creation of a new GPO named 
##                             "CIS Windows Server Policy GPO". (The name can be 
##                             easily customized.)
##                             The description and several policy settings are
##                             modified. This is nice for showing off the GPO
##                             changes.
##                             I have allowed additional time between changes to
##                             allow for replication delay and propagation to DSP.
##                             Note that for some reason, these registry settings
##                             are failing to show in the proper place in the 
##                             GPO and instead show up as additional registry
##                             settings.
##                       ----- To speed up the script a little, I will later 
##                       ----- break up the CIS GPO section to do settings 
##                       ----- earlier in the script, and then the reset/changes
##                             near the end. (That will eliminate the extra delays.)
##                             Fixed a couple of minor display issues.
##
## 2022-11-30  Rob Ingenthron  Added code to create two OU's under 'Lab Users'.
##                             Referenced with vars $UsersOUName01 and $UsersOUName02.
##                             Purpose is to create user objects in 01 and move to 02.
##                             Later in code, move users in 02 back to 01.
##                             This will help bump up the graph to show more move 
##                             operations in DSP.
##
## 2022-12-20  Rob Ingenthron  Added two more demo users and two ADM users. Purpose
##                             is to start adding more nested users and groups to 
##                             better demo Forest Druid. The ADM accounts will be
##                             in Tier 2 but will have additional permissions via
##                             nested groups.
##
## 2023-01-17  Rob Ingenthron  Changed 3 users' department to 'xxxxxx' to emulate
##                             script or HR system issue. Demo undo capability.
##
## 2023-01-18  Rob Ingenthron  Added a guidance/suggestions display at the end
##                             of the script to suggest a few things to look for 
##                             in changes.
##
## 2023-02-03  Rob Ingenthron  Added -PasswordNeverExpire option to OpsAdmin1 acct.
##                             (Default name is adm.JohnWick)
##
## 2023-03-08  Rob Ingenthron  Added a section to add subnets to AD Sites and Services,
##                             including a /24 for the subnet that we are in.
##                             (Note that this works fine for our labs, but with
##                             and existing prod AD, this could fail due to my
##                             selection of IP subnets.)
##
## 2023-09-12  Rob Ingenthron  Added some additional objects under the OU
##                             "DeleteMe OU" to demo the ability to recovery an
##                             entire deleted OU tree structure with a couple
##                             of clicks. (Added sub-OUs, objects, accounts.)
##
## 2023-09-18  Rob Ingenthron  A few bug fixes in newly added code.
##
## 2023-10-13  Rob Ingenthron  Added code to create and delete a couple of AD
##                             subnets to show additional changes in DSP's
##                             Configuration partition view, and also to demo
##                             an undo of a deleted subnet.
##                             Also changed the descriptions of the subnets a
##                             a couple of times.
##
## 2024-01-25  Rob Ingenthron  Added two new groups, which get populated with
##                             lab user accounts:
##                             Pizza Party Group
##                             Party Planners Group
##
##                             In populating the membership to these groups, the
##                             script (purposely) creates a circular group
##                             nesting. 
##
## 2024-01-31  Rob Ingenthron  Changed the CIS Benchmark GPO settings a little 
##                             so that the changes show up more consistently in
##                             in the DSP GPO changes module.
##
##                             Seperated the changes into two groups a little 
##                             farther apart in the code to allow a little more
##                             time to settle and replicate to the DSP mgmt server
##                             which also enabled removing about 85 seconds of
##                             delays for timing I previously added. So overall,
##                             the script runs a little faster and the CIS GPO
##                             updates show up with about 2 minutes of seperation.
##
##                             I also made sure to have one secure change and
##                             one insecure change so I could speak to whatever
##                             story best fits the sales call for the demo.
##
## 2024-01-31  Rob Ingenthron  Added a little more internal documentation for
##                             the "forceguest" setting in the CIS Benchmark GPO.
##
## 2024-02-05  Rob Ingenthron  Moved the CIS modify section (the 2nd part) later
##                             in the script to buffer more time in between changes 
##                             to better capture the GPO changes AND the GPO
##                             snapshot (backup), clearly showing a time diff.
##
## 2024_02-05  Rob Ingenthron  Added another setting in the CIS GPO for more
##                             change data. Added "LmCompatibilityLevel". 
##                             Changed from a more secure setting to a less
##                             secure setting.
##
## 2024-02-16  Rob Ingenthron  Moved the CIS Windows Server benchmark GPO
##                             updates/changes later in the script to provide
##                             more of a time gap between changes to better
##                             differentiate in the DSP GPO module for demos.
##
## 2024-03-15  Rob Ingenthron  Moved the section to check for needed permissions
##                             before doing any real scripted stuff so that the
##                             user doesn't have to wait to see if permissions
##                             are missing.
##                             Also added a check to see if the script is running
##                             As Administrator (due to UAC). We need the context
##                             to be Administrator for the PowerShell window to 
##                             many different commands.
##
## 2024-03-18  Rob Ingenthron  Added a few minor tweaks and left in code for 
##                             checking if the current user is running with
##                             elevated permissions (As Administrator) in the
##                             PoSh window. 
##
##                             I need to figure out a clever way to force an exit
##                             when this script is started with a shortcut that causes
##                             a NEW PoSh window to open As Administrator. For now, 
##                             the window will not close as the exit command is not 
##                             processed.
##
##                             Added comments in this script on how to create a 
##                             symbolic link and the shortcut.
##
## 2024-03-18  Rob Ingenthron  Decided to debug a fix a very minor but annoying
##                             bug where a file named "1" was generated. It was
##                             due to the commandline I had used to try to hide
##                             error output from the "net use" commandline I was
##                             using to cause an account lockout.
##
##                             Modified the line with this proper $null redirection:
##                             net use \\$DomainDNSRoot\netlogon /user:"$DomainDNSRoot\$($DemoUser2.SamAccountName)" nopass > $null 2>&1
##
##                             $null takes the good output and 2> redirects the 
##                             error output also to $null (which is stream "1").
##
## 2024-03-19  Rob Ingenthron  Added "-PasswordNeverExpires $True" to several
##                             accounts that need to stay active for demos. 
##
## 2024-05-13  Rob Ingenthron  Had a code logic error. When the DSP PoSh module
##                             was not already installed, after finding the module,
##                             the script did not try to load it after installing,
##                             so I added code to try to import the module after
##                             the install.
##
## 2024-05-30  Rob Ingenthron  Corrected a typo on the commandline to load DNS module.
##
## 2024-06-05  Rob Ingenthron  Added some internal documentation updates.
##                             Fixed bug: somehow and some point, the "-Filter" 
##                             option lost the dash in the log file cleanup 
##                             at the start of the script, preventing log cleanup.
##                             Fixed bug: somehow, quotes got removed from the 
##                             'SpecialLabUsers_PSO' creation commandline.
##                             Fixed bug: had a hard-coded site name, assumed 
##                             from development work in Abathur lab, where the
##                             named site doesn't exist by default in any new 
##                             environment. Used the $MyADSite variable.
##                             (To-do: script adding a new AD site!!!)
##
## 2024-07-12  Rob Ingenthron  Increased loop from 30 to 50 to lockout user acct
##                             so more likely to always hit the "Brute Force"
##                             IRP indicator.
##                             Bug watch: need to fix error with the Hyper-V
##                             WMI filter. Getting an error, but not sure why.
##
## 2024-08-13  Rob Ingenthron  Added code to create special OU with some 
##                             computer objects representing more secure
##                             (tier0/tier1) resources.
##                             Intent is to modify the ACL to be more restricted
##                             so that only admins may access the OU and content.
##                             Script removes ALL ACEs, changes the owner to the
##                             logged on user, and then adds only the logged on
##                             user for full access to the OU.
##                       
##                             Added some checking around the DNS PTR record
##                             creation to first check for existence of the PTR
##                             before calling the PTR creation command.
##
## 2024-08-14  Rob Ingenthron  Fixed a problem in the WMI filter modification 
##                             section where there was a problem when more than
##                             one WMI filter existed with the same mxWMI-Name
##                             value. (You can have more than one WMI filter
##                             with the same mxWMI-Name, which is the human-
##                             readable name. Now the code will loop through
##                             names that are the same and just use the last
##                             one found. (Note that this could yield a different
##                             on each run, however, the point of this section
##                             is just to generate some WMI changes to look
##                             in the DSP Changes section.)
##
## 2024-08-15  Rob Ingenthron  Fixed missing quotes issues somehow introduced
##                             in the FGPP creation section. 
##                             Added variables for naming of FGPP, and then 
##                             added code to create an leave a FGPP. (The first 
##                             is deleted later in the code, so now one is
##                             deleted and the second remains.) FGPP's will be
##                             re-created if deleted in demos.
##
## 2024-08-16  Rob Ingenthron  Added code to create a new AD site, add a new
##                             AD subnet, and then create an AD site link. 
##                             If any of these already exist, they should get
##                             updated, so Location and Descripting can be
##                             modified and those values should be reset each
##                             time the script runs.
##
## 2024-11-13  Rob Ingenthron  Added account "Admin-Tier0" because some people 
##                             could not get past the idea of using an alt admin
##                             account for logons to DSP with full privileges.
##                             (Account not privileged in AD, but full rights in DSP.)
##                             So now I log onto DSP with this "Admin-Tier0" account.
##
## 2024-11-20  Rob Ingenthron  Added "-PasswordNeverExpires $True" to three accounts:
##                               Admin-Tier0
##                               Admin-Tier2
##                               adm.JohnWick
##
## 2024-12-10  Rob Ingenthron  Minor bug fixes.
##
## 2025-10-01  Rob Ingenthron  Added code to password spray a few accounts to 
##                             trigger the password spray attack indicator (IRP).
##
##------------------------------------------------------------------------------
################################################################################









################################################################################
#-------------------------------------------------------------------------------
# NOTES ABOUT OPERATION
#
# * Hash tables, near the beginning of the script, allow you to modify attributes
#   for a bunch of "demo user" accounts and groups. These are pre-populated but
#   the values can be changed as preferred.
#
# * The first time the demo and special accounts are created, the user password
#   is prompted for. Assuming some may want a different password for different
#   user accounts, each new account prompts for a password. This is only done
#   during account creation. (If one of these accounts is deleted, the script
#   will re-create the user object and prompt for the password.)
#
# * All prompts have automatic timeouts, so the script can be run unsupervised.
#   (The only exception is the very first run of the script on the server.)
#
# * On the very first run of the script, which should be done As Administrator,
#   a Credential Manager module is loaded. This is only done one time. Enter "Y" 
#   to complete both of the load operations from the Microsoft reference.
#   The Credential Manager is used to store a password for later use, automatically.
#   After successful installation, this is never prompted for again.
#
# * This script must be run with Domain Admin rights for almost everything to work.
#   Enterprise Admin membership is needed for a new changes, but the majority of the
#   script will still work with EA rights. There is a check at the start of the 
#   to validate the user rights.
# 
# * Every time the script is run, it checks for the DSP PoSh module. 
#   If the module appears to be missing, the script prompts the user
#   to obtain the module installer and add it to the scripts folder from
#   where this script is running. 
#   NOTE: The DSP PoSh module is not required for this script, but if installed,
#         then the script will use the DSP cmdlets to perform a few automated 
#         recoveries of attribute changes.
#
# * There are delays built in to the operations, as well as forced replication many 
#   times throughout this script to make sure changes are replicated before 
#   dependent changes are made, as well as to avoid any issues with doing too
#   many actions to the same attribute in too short of a period (so we can clearly
#   see replicated changes). As such, this script takes at least 15 minutes to complete.
#   This extra processing time also presents the data in DSP Changes more orderly.
#
# * There is a section which does changes as a different admin user 
#   "ops admin - Tier 1 admin account" to show alternative "who" values in the 
#   "Changes" section. The first time this script is run, it will prompt for 
#   the user account name and password which will be added to the Windows 
#   Credential Store. The script will prompt for the account name to use.
#
# * This script does some undo operations using the DSP PoSh cmdlets. This 
#   requires the installation of the DSP PoSh installer from the DSP console.
#   You will have to download the installer and run the installer.
#
# * There is a section intended to test auto-undo. This presumes the existence
#   of notification rules with the "undo" option checked/enabled for a user where 
#   the 'Title' attribute is protected. (The 'Title' attribute is changed to "CEO"
#   and the rule will cause the title to be reverted to the previous setting.)
#   This script cannot create the rules programatically. 
#   This script looks at the user "DemoUser3" for this section.
#   This script will still function regardless of the auto-undo rules' existence.
#   This script should be run once to create the user(s), then create the rule.
#
# * There is a section intended to test auto-undo. This presumes the existence
#   of notification rules with the "undo" option checked/enabled for a group where 
#   the membership is completely cleared. (So the auto-undo should re-populate the
#   group membership.) 
#   This script cannot create the rules programatically. 
#   This script looks at the group "SpecialLabAdmins" for this section.
#   This script will still function regardless of the auto-undo rules' existence.
#   This script should be run once to create the group(s), then create the rule.
# 
#-------------------------------------------------------------------------------
################################################################################









<#
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
((Test-Admin) -eq $false)


if ((Test-Admin) -eq $false)  {
    if ($elevated) {
        # tried to elevate, did not work, aborting
        Write-Host "Failed to elevate!!!"
    } else {
        Write-Host "Starting process!!!"
        ###Start-Process pwsh -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
    Write-Host "Exiting!!!"
    ###exit
}
#>









################################################################################
# LOOP x TIMES
# Loop script to create more activity!
#
# Run $LoopTimes in-a-row
$LoopTimes = 1
for ($i = 1; $i -le $LoopTimes; $i++) {
   Write-Host "`n`n`n"
   Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Yellow
   Write-Host "LOOPING!!!   Loop # $i of $LoopTimes" -ForegroundColor Yellow
   Write-Host "LOOPING!!!   Loop # $i of $LoopTimes" -ForegroundColor Yellow
   Write-Host "LOOPING!!!   Loop # $i of $LoopTimes" -ForegroundColor Yellow
   Write-Host "LOOPING!!!   Loop # $i of $LoopTimes" -ForegroundColor Yellow
   Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Yellow
   Write-Host "`n`n`n"
   #
   # Looping ends near bottom, after the transcript file has been closed
   #
   #############################################################################







################################################################################
#------------------------------------------------------------------------------
#
# For the sake of end-users running this, we will create a log/transcript file
# in the event there are any errors during the script run.
#
Write-Host "`n`n`n"
# Current path from which this script was executed...
Write-Host "$(Get-Item .)" -ForegroundColor Magenta   # gives current folder, but not necessarily he folder from where this script is run
$ScriptPath = $MyInvocation.MyCommand.Path    # Path will only exist when the script is *run* in the ISE.
If ($ScriptPath -eq $Null) {$scriptdir = (Get-Item .).FullName} Else {$scriptdir = Split-Path $scriptpath}
#$scriptdir = Split-Path $scriptpath                  # THIS VAR IS USED LATER!!!!
Write-Host ""
Write-Host ":: Script path: $scriptdir  " -ForegroundColor Magenta
Write-Host ""

Start-Transcript -OutputDirectory $scriptdir\Logs\ -NoClobber -IncludeInvocationHeader -Force -ErrorAction Stop -Verbose

# Delete old log files after X number of days...
# (to be added: more error handling when logs cannot be deleted, and write to log)
$DaysToRetain = 5
Write-Host "`n"
Write-Host "--Searching for old log files to delete (older than $($DaysToRetain) days)..." -ForegroundColor Yellow
Get-ChildItem -Path $scriptdir\Logs\ -Filter "PowerShell_transcript.*" -force -ErrorAction SilentlyContinue | `
               where {($_.LastWriteTime -lt (Get-Date).AddDays(-$DaysToRetain)) -and ($_.PSIsContainer -eq $False)} | `
               Remove-Item -Verbose -Force -ErrorAction SilentlyContinue

#Stop-Transcript -Verbose

Write-Host "`n"

#
#-------------------------------------------------------------------------------
################################################################################



Write-Host ""
Write-Host "PowerShell script name: " $MyInvocation.MyCommand.Name

################################################################################
##
## C H E C K   F O R   R I G H T S   A N D   P E R M I S S I O N S
##
## -----------------------------------------------------------------------------
## Before doing anything or displaying anything, we should make sure user has
## the basic rights and permissions to run this script.
## 
## We need ths script running as Administrator (until we include a clever way to elevate)
## We need Domain Admins membership
## We need Enterprise Admins membership
##
## The script can run without any of those, but most functionality will fail.
##
## If Enterprise Admin membership is missing, then changes to forest config and 
## the default domain policiy will fail.
##
################################################################################
################################################################################
#------------------------------------------------------------------------------
#
# Check if user has required and optional permissions
#   * PowerShell command window running as Administrator
#   * Domain Admins
#   * Enterprise Admins   (for a few changes, like the Default Domain Policy)
#

Write-Host ""
Write-Host ""

# check whether the current context is running as Administrator, otherwise
# many functions will not work.
Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
Write-Host "::"
If (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host ":: PowerShell command window conext is running as Administrator." -ForegroundColor Yellow -BackgroundColor DarkGreen
    Write-Host "::"
    Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
}
Else
{
    Write-Host ":: PowerShell command window is NOT running as Administrator!" -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host "::"
    Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
    Write-Host "::"
    Write-Host ":: NOTE THAT MOST FUNCTIIONALITY IN THIS SCRIPT WILL FAIL!!" -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host "::"
    Write-Host ":: Please QUIT this script and run this script As Administrator!!"
    Write-Host "::"
    Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
    Start-Sleep 20
}


# check whether the currently login user is a Domain Admin
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
Write-Host "::"
If ($WindowsPrincipal.IsInRole("Domain Admins"))
{
    Write-Host ":: $($currentUser.Name) is a Domain Admin." -ForegroundColor Yellow -BackgroundColor DarkGreen
    Write-Host "::"
    Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
}
Else
{
    Write-Host ":: $($currentUser.Name) NOT a Domain Admin." -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host "::"
    Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
    Write-Host "::"
    Write-Host ":: NOTE THAT MOST FUNCTIIONALITY IN THIS SCRIPT WILL FAIL!!" -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host "::"
    Write-Host ":: Please QUIT this script and add your admin account to the ""Domain Admins"" group!!"
    Write-Host "::"
    Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
    Start-Sleep 20
}

# check whether the currently login user is an Enterprise Admin
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
Write-Host "::"
If ($WindowsPrincipal.IsInRole("Enterprise Admins"))
{
    Write-Host ":: $($currentUser.Name) is an Enterprise Admin." -ForegroundColor Yellow -BackgroundColor DarkGreen
    Write-Host "::"
    Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
}
else
{
    Write-Host ":: $($currentUser.Name) NOT an Enterprise Admin." -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host "::"
    Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
    Write-Host "::"
    Write-Host ":: NOTE THAT SOME FUNCTIONALITY IN THIS SCRIPT WILL FAIL!!" -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host "::"
    Write-Host ":: Membership in ""Enterprise Admins"" is needed to modify some policies and certain"
    Write-Host ":: types of AD configuration changes."
    Write-Host "::"
    Write-Host ":: Most functionality will work so feel free to continue and later add your admin"
    Write-Host ":: account to the ""Enterprise Admins"" group before running this script again."
    Write-Host "::"
    Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
    Start-Sleep 10
}

Write-Host ""
Write-Host ""
#
#------------------------------------------------------------------------------
################################################################################
################################################################################









################################################################################
#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                      " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::    Invoke-CreateDspChangeDataForDemos                                " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::                                                                      " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::      Generates changes to Active Directory data:                     " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - AD Sites and Services                                       " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - AD User objects                                             " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - AD User account lockout                                     " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - FGPP's (fine-grained password polices)                      " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - GPOs                                                        " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - Group objects                                               " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - DNS records and zones                                       " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - Default Domain Policy                                       " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - OUs and deletion protection                                 " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - Creates a highly restricted OU                              " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - WMI filters                                                 " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - ACLs                                                        " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - Adds an AD site, subnet, and site link                      " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - GPO linking                                                 " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - Brute Force password attack (and account lockout)           " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::                                                                      " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::    May be re-run as often as desired.                                " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::                                                                      " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::    Script will reset changed items for consistent demo usage.        " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::                                                                      " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "`n`n"
Start-Sleep 5
#-------------------------------------------------------------------------------
################################################################################






################################################################################
#------------------------------------------------------------------------------
# Get our AD forest and domain info...
#
$DomainInfo = Get-ADDomain
$DomainNETBIOS = $DomainInfo.NetBIOSName
$DomainDNSRoot = $DomainInfo.DNSRoot
$DomainDN = $DomainInfo.DistinguishedName
$DomainPDCe = $DomainInfo.PDCEmulator
$DomainDCList = ($DomainInfo).ReplicaDirectoryServers
$SubordinateReferences = ($DomainInfo).SubordinateReferences

$DomainDC1 = $DomainDCList[0]

If ($DomainDCList[1]) {$DomainDC2 = $DomainDCList[1]} Else {$DomainDC2 = $DomainDC1}

Write-Host ""
Write-Host ""
Write-Host ""
Write-Host "----------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "--          Domain NetBIOS: $DomainNETBIOS" -ForegroundColor Cyan
Write-Host "--         Domain DNS Root: $DomainDNSRoot" -ForegroundColor Cyan
Write-Host "--               Domain DN: $DomainDN" -ForegroundColor Cyan
Write-Host "--             Domain PDCe: $DomainPDCe" -ForegroundColor Cyan
Write-Host "--              Domain DC1: $DomainDC1" -ForegroundColor Cyan
Write-Host "--              Domain DC2: $DomainDC2" -ForegroundColor Cyan
Write-Host "----------------------------------------------------------------" -ForegroundColor Cyan
Write-Host ""
Write-Host ""
Write-Host ""
Start-Sleep 3
#------------------------------------------------------------------------------
################################################################################






################################################################################
################################################################################
#-------------------------------------------------------------------------------
#
# CUSTOMIZATIONS SECTION: SET VALUES FOR YOUR SPECIFIC LAB OR POC
#
# I did not want to prompt for these because this script can be re-run 
# frequently, but each person may want to configure their lab/POC to 
# have some preferred user names and group names for their demo/POC work.
#
# This section has some settings to more readily customer this script to
# your preferences, such as number of generic users generated, user names, 
# locations, phone numbers, etc.
#




#--------------------------------------------------------------------------------
#
# Number of generic user accounts to create in "OU=TEST"
#
# Note that the user will be prompted later to see if they want to select a
# different value. 
#
$GenericUsersCount = 250
#




#--------------------------------------------------------------------------------
# Tier 0 Admin - main demo logon account
#
# User account for DSP console logons to show the use of an NON-privileged
# Tier 0 account that is able to manage DSP and undo changes in AD.
#
   $hashtable = @{
        Name                = 'Admin-Tier0'          # CN
        SamAccountName      = 'Admin-Tier0'
        GivenName           = 'Admin'
        Surname             = 'Tier0'
        DisplayName         = 'Admin-Tier0'
        Initials            = 'AT0'
        Description         = 'Tier1 Non-Privileged Admin'
        Mail                = 'Admin-Tier0@fabrikam.com'
        Title               = 'Sr Solution Architect'
        Department          = 'Pre-Sales'
        Division            = 'Product Sales'
        Company             = 'Semperis'
        TelephoneNumber     = '408-555-9090'       # OfficePhone using Set-ADUser cmdlet
        TelephoneNumberAlt  = '(415) 555-9191'     # number to change to (to catch in DSP)
        FAX                 = '(415) 555-8880'     # facsimileTelephoneNumber attribute
        City                = 'Silicon Valley'
        EmployeeID          = '000001101'
        Path                = "OU=Tier 0,OU=Lab Admins,$DomainDN"  # Must match tier 0 OU path created below               
        #Orphan              = ($user.Login -eq "")
    }
    $AdminUser0 = New-Object PSObject -Property $hashtable
#
#





#--------------------------------------------------------------------------------
# Tier 2 Admin - main demo logon account
#
# User account for DSP console logons to show the use of an NON-privileged
# Tier 2 account that is able to manage DSP and undo changes in AD.
#
   $hashtable = @{
        Name                = 'Admin-Tier2'          # CN
        SamAccountName      = 'Admin-Tier2'
        GivenName           = 'Admin'
        Surname             = 'Tier2'
        DisplayName         = 'Admin-Tier2'
        Initials            = 'AT2'
        Description         = 'Tier2 Non-Privileged Admin'
        Mail                = 'Admin-Tier2@fabrikam.com'
        Title               = 'Sr Solution Architect'
        Department          = 'Pre-Sales'
        Division            = 'Product Sales'
        Company             = 'Semperis'
        TelephoneNumber     = '408-555-9090'       # OfficePhone using Set-ADUser cmdlet
        TelephoneNumberAlt  = '(415) 555-9191'     # number to change to (to catch in DSP)
        FAX                 = '(415) 555-8880'     # facsimileTelephoneNumber attribute
        City                = 'Silicon Valley'
        EmployeeID          = '000001138'
        Path                = "OU=Tier 2,OU=Lab Admins,$DomainDN"  # Must match tier 2 OU path created below               
        #Orphan              = ($user.Login -eq "")
    }
    $AdminUser2 = New-Object PSObject -Property $hashtable
#
#


#------------------------------------------------------------------------------
#
# ops admin - Tier 1 admin account
#
   $hashtable = @{
        Name                = 'adm.JohnWick'       # CN
        SamAccountName      = 'adm.johnwick'
        GivenName           = 'John'
        Surname             = 'Wick'
        DisplayName         = 'John Wick (admin)'
        Initials            = 'ajw'
        Description         = 'Admin for Lab Operations'
        Mail                = 'adm.johnwick@fabrikam.com'
        Title               = 'Operations Lead'
        Department          = 'Demo'
        Division            = 'IT'
        Company             = 'Semperis'
        TelephoneNumber     = '408-555-1919'       # OfficePhone using Set-ADUser cmdlet
        TelephoneNumberAlt  = '(619) 555-1230'     # number to change to (to catch in DSP)
        FAX                 = '(619) 555-0987'     # facsimileTelephoneNumber attribute
        City                = 'New York'
        EmployeeID          = '00010011'
        Path                = "OU=Tier 1,OU=Lab Admins,$DomainDN"  # Must match tier 2 OU path created below               
        #Orphan              = ($user.Login -eq "")
    }
    $OpsAdmin1 = New-Object PSObject -Property $hashtable
#
#

#------------------------------------------------------------------------------
#
# generic admin - Tier 2 admin account
#
   $hashtable = @{
        Name                = 'App Admin II'       # CN
        SamAccountName      = 'AppAdminII'
        GivenName           = 'App'
        Surname             = 'Admin II'
        DisplayName         = 'App Admin II'
        Initials            = 'AA2'
        Description         = 'Admin for Lab Applications'
        Mail                = 'AppAdminII@fabrikam.com'
        Title               = 'Application Lead'
        Department          = 'Demo Development'
        Division            = 'Software'
        Company             = 'Semperis'
        TelephoneNumber     = '408-555-2424'       # OfficePhone using Set-ADUser cmdlet
        TelephoneNumberAlt  = '(619) 555-9999'     # number to change to (to catch in DSP)
        FAX                 = '(619) 555-9990'     # facsimileTelephoneNumber attribute
        City                = 'San Diego'
        EmployeeID          = '00088123'
        Path                = "OU=Tier 2,OU=Lab Admins,$DomainDN"  # Must match tier 2 OU path created below               
        #Orphan              = ($user.Login -eq "")
    }
    $GenericAdmin1 = New-Object PSObject -Property $hashtable
#
#

#------------------------------------------------------------------------------
#
# generic admin - Tier 2 admin account
#
   $hashtable = @{
        Name                = 'App Admin III'       # CN
        SamAccountName      = 'AppAdminIII'
        GivenName           = 'App'
        Surname             = 'Admin III'
        DisplayName         = 'App Admin III'
        Initials            = 'AA3'
        Description         = 'Admin for Lab Applications'
        Mail                = 'AppAdminIII@fabrikam.com'
        Title               = 'Application Manager'
        Department          = 'Demo Development'
        Division            = 'Software'
        Company             = 'Semperis'
        TelephoneNumber     = '408-555-3434'       # OfficePhone using Set-ADUser cmdlet
        TelephoneNumberAlt  = '(619) 555-9119'     # number to change to (to catch in DSP)
        FAX                 = '(619) 555-9110'     # facsimileTelephoneNumber attribute
        City                = 'San Diego'
        EmployeeID          = '00088120'
        Path                = "OU=Tier 2,OU=Lab Admins,$DomainDN"  # Must match tier 2 OU path created below               
        #Orphan              = ($user.Login -eq "")
    }
    $GenericAdmin2 = New-Object PSObject -Property $hashtable
#
#


#------------------------------------------------------------------------------
# DemoUser1
#
# Hard-coded user values for the preferred demo user account you want to change 
# attributes on in DSP demos to demonstrate change auditing for multiple changes.
#
# These variables will be referenced in later sections where changes are made so
# you don't have to make edits throughout this code if you want a different user
# name or other attributes.
#
   $hashtable = @{
        Name                = 'Axl Rose'          # CN
        SamAccountName      = 'arose'
        GivenName           = 'William'
        Surname             = 'Rose'
        DisplayName         = 'Axl Rose'
        Initials            = 'AFR'
        Description         = 'Coder'
        Mail                = 'AppAdminII@fabrikam.com'
        Title               = 'Application Mgr'
        Department          = 'Sales'
        Division            = 'Rock Analysis'
        Company             = 'Roses and Guns'
        TelephoneNumber     = '408-555-1212'       # OfficePhone using Set-ADUser cmdlet
        TelephoneNumberAlt  = '(000) 867-5309'     # number to change to (to catch in DSP)
        FAX                 = '(408) 555-1212'     # facsimileTelephoneNumber attribute
        FAXalt              = '+501 11-0001'     # facsimileTelephoneNumber attribute
        City                = 'City of Angels'
        EmployeeID          = '000123456'
        Path                = "OU=Lab Users,$DomainDN"                  
        #Orphan              = ($user.Login -eq "")
    }
    $DemoUser1 = New-Object PSObject -Property $hashtable


#------------------------------------------------------------------------------
# DemoUser2
#
# Hard-coded user values for the preferred demo user account you want to change 
# attributes on in DSP demos to demonstrate change auditing for multiple changes.
#
# These variables will be referenced in later sections where changes are made so
# you don't have to make edits throughout this code if you want a different user
# name or other attributes.
#
   $hashtable = @{
        Name                = 'Luke Skywalker'      # CN
        SamAccountName      = 'lskywalker'
        GivenName           = 'Luke'
        Surname             = 'Skywalker'
        DisplayName         = 'Luke Skywalker'
        Initials            = 'LS'
        Description         = 'apprentice'
        Mail                = 'lskywaklker@fabrikam.com'
        Title               = 'Nerfherder'
        Department          = 'Religion'
        Division            = 'Spoon Bending'
        Company             = 'Jedi Knights, Inc'
        TelephoneNumber     = '408-555-5151'       # OfficePhone using Set-ADUser cmdlet
        TelephoneNumberAlt  = '(111) 555-JEDI'     # number to change to (to catch in DSP)
        FAX                 = '(408) 555-5555'     # facsimileTelephoneNumber attribute
        FAXalt              = '+41 111-9999'       # facsimileTelephoneNumber attribute
        City                = 'Tatooine'
        EmployeeID          = '00314159'
        Path                = "OU=Lab Users,$DomainDN"                  
        #Orphan              = ($user.Login -eq "")
    }
    $DemoUser2 = New-Object PSObject -Property $hashtable



#------------------------------------------------------------------------------
# DemoUser3
#
# Hard-coded user values for the preferred demo user account you want to change 
# attributes on in DSP demos to demonstrate change auditing for multiple changes.
#
# These variables will be referenced in later sections where changes are made so
# you don't have to make edits throughout this code if you want a different user
# name or other attributes.
#
   $hashtable = @{
        Name                = 'Peter Griffin'      # CN
        SamAccountName      = 'peter.griffin'
        GivenName           = 'Peter'
        Surname             = 'Griffin'
        DisplayName         = 'Peter Griffin'
        Initials            = 'JPG'
        Description         = 'cartoon character'
        Mail                = 'peter.griffin@fabrikam.com'
        Title               = 'Sales'
        Department          = 'Parody'
        Division            = 'Blue Collar'
        Company             = 'Happy-Go-Lucky Toy Factory'
        TelephoneNumber     = '408-777-3333'       # OfficePhone using Set-ADUser cmdlet
        TelephoneNumberAlt  = '(216) 555-JEDI'     # number to change to (to catch in DSP)
        FAX                 = '(216) 555-1000'     # facsimileTelephoneNumber attribute
        FAXalt              = '+1 216 111-888'       # facsimileTelephoneNumber attribute
        City                = 'Quahog'
        EmployeeID          = '00987654321'
        Path                = "OU=Lab Users,$DomainDN"                  
        #Orphan              = ($user.Login -eq "")
    }
    $DemoUser3 = New-Object PSObject -Property $hashtable



#------------------------------------------------------------------------------
# DemoUser4
#
# Hard-coded user values for the preferred demo user account you want to change 
# attributes on in DSP demos to demonstrate change auditing for multiple changes.
#
# These variables will be referenced in later sections where changes are made so
# you don't have to make edits throughout this code if you want a different user
# name or other attributes.
#
   $hashtable = @{
        Name                = 'Paul McCartney'      # CN
        SamAccountName      = 'pmccartney'
        GivenName           = 'Paul'
        Surname             = 'McCartney'
        DisplayName         = 'Paul McCartney'
        Initials            = 'JPM'
        Description         = 'Bandmember'
        Mail                = 'pmccartney@fabrikam.com'
        Title               = 'Lead Beatle'
        Department          = 'Music'
        Division            = 'Legends'
        Company             = 'The Beat Brothers'
        TelephoneNumber     = '011 44 20 1234 5678'     # OfficePhone using Set-ADUser cmdlet
        TelephoneNumberAlt  = '011 44 151 1BEA TLES'     # number to change to (to catch in DSP)
        FAX                 = '011 44 20 5555 1111'     # facsimileTelephoneNumber attribute
        FAXalt              = '011 44 151 2222 9999'     # facsimileTelephoneNumber attribute
        City                = 'Liverpool'
        EmployeeID          = '000001212'
        Path                = "OU=Lab Users,$DomainDN"                  
        #Orphan              = ($user.Login -eq "")
    }
    $DemoUser4 = New-Object PSObject -Property $hashtable



#------------------------------------------------------------------------------
# DemoUser5
#
# Hard-coded user values for the preferred demo user account you want to change 
# attributes on in DSP demos to demonstrate change auditing for multiple changes.
#
# These variables will be referenced in later sections where changes are made so
# you don't have to make edits throughout this code if you want a different user
# name or other attributes.
#
   $hashtable = @{
        Name                = 'Yan Li'      # CN
        SamAccountName      = 'yanli'
        GivenName           = 'Yan'
        Surname             = 'Li'
        DisplayName         = 'Yan Li'
        Initials            = 'YL'
        Description         = 'manager of shop line'
        Mail                = 'yanli@fabrikam.com'
        Title               = 'Manager'
        Department          = 'Wiget Manufacturing'
        Division            = 'Manufacturing'
        Company             = 'Contractors Inc'
        TelephoneNumber     = '212 555-5600'     # OfficePhone using Set-ADUser cmdlet
        TelephoneNumberAlt  = '212 555-5601'     # number to change to (to catch in DSP)
        FAX                 = '212 555-5699'     # facsimileTelephoneNumber attribute
        FAXalt              = '212 555-5698'     # facsimileTelephoneNumber attribute
        City                = 'Jersey'
        EmployeeID          = '000062312'
        Path                = "OU=Lab Users,$DomainDN"                  
        #Orphan              = ($user.Login -eq "")
    }
    $DemoUser5 = New-Object PSObject -Property $hashtable



#------------------------------------------------------------------------------
# DemoUser6
#
# Hard-coded user values for the preferred demo user account you want to change 
# attributes on in DSP demos to demonstrate change auditing for multiple changes.
#
# These variables will be referenced in later sections where changes are made so
# you don't have to make edits throughout this code if you want a different user
# name or other attributes.
#
   $hashtable = @{
        Name                = 'Aria Cruz'      # CN
        SamAccountName      = 'acruz'
        GivenName           = 'Aria'
        Surname             = 'Cruz'
        DisplayName         = 'Aria Cruz'
        Initials            = 'AC'
        Description         = 'development programmer'
        Mail                = 'acruz@fabrikam.com'
        Title               = 'Lead Programmer'
        Department          = 'Product Development'
        Division            = 'Software Management'
        Company             = 'Semperis Labs'
        TelephoneNumber     = '213 667-5555'     # OfficePhone using Set-ADUser cmdlet
        TelephoneNumberAlt  = '213 667-5556'     # number to change to (to catch in DSP)
        FAX                 = '213 12-FAXIT'     # facsimileTelephoneNumber attribute
        FAXalt              = '213 669-4201'     # facsimileTelephoneNumber attribute
        City                = 'Rancho Cucamonga'
        EmployeeID          = '000701212'
        Path                = "OU=Lab Users,$DomainDN"                  
        #Orphan              = ($user.Login -eq "")
    }
    $DemoUser6 = New-Object PSObject -Property $hashtable



#------------------------------------------------------------------------------
# DemoUser7
#
# Hard-coded user values for the preferred demo user account you want to change 
# attributes on in DSP demos to demonstrate change auditing for multiple changes.
#
# These variables will be referenced in later sections where changes are made so
# you don't have to make edits throughout this code if you want a different user
# name or other attributes.
#
   $hashtable = @{
        Name                = 'Carlos M. Hern ndez'      # CN
        SamAccountName      = 'cmhernandez'
        GivenName           = 'Carlos'
        Surname             = 'Hern ndez'
        DisplayName         = 'Carlos Hern ndez'
        Initials            = 'CMH'
        Description         = 'Financial VP'
        Mail                = 'cmh@fabrikam.com'
        Title               = 'CFO'
        Department          = 'Finance'
        Division            = 'Finance'
        Company             = 'Semperis Labs'
        TelephoneNumber     = '+55 0021 123 5678'     # OfficePhone using Set-ADUser cmdlet
        TelephoneNumberAlt  = '+55 0021 123-3434'     # number to change to (to catch in DSP)
        FAX                 = '+55 0021 123-5678'     # facsimileTelephoneNumber attribute
        FAXalt              = '+55 0021 123-5679'     # facsimileTelephoneNumber attribute
        City                = 'Rio de Janeiro'
        EmployeeID          = '000001200'
        Path                = "OU=Lab Users,$DomainDN"                  
        #Orphan              = ($user.Login -eq "")
    }
    $DemoUser7 = New-Object PSObject -Property $hashtable




#------------------------------------------------------------------------------
# DemoUser8
#
# Hard-coded user values for the preferred demo user account you want to change 
# attributes on in DSP demos to demonstrate change auditing for multiple changes.
#
# These variables will be referenced in later sections where changes are made so
# you don't have to make edits throughout this code if you want a different user
# name or other attributes.
#
   $hashtable = @{
        Name                = 'Dawn Raji'      # CN
        SamAccountName      = 'draji'
        GivenName           = 'Dawn'
        Surname             = 'Raji'
        DisplayName         = 'Dawn Raji'
        Initials            = 'DR'
        Description         = 'System Engineering Manager'
        Mail                = 'dawn45@adventure-works.com'
        Title               = 'Site CIO'
        Department          = 'Engineering'
        Division            = 'Engineering'
        Company             = 'Northwind'
        TelephoneNumber     = '1 (11) 500 555-0126'     # OfficePhone using Set-ADUser cmdlet
        TelephoneNumberAlt  = '1 (11) 500 555-0128'     # number to change to (to catch in DSP)
        FAX                 = '1 (11) 500 555-0288'     # facsimileTelephoneNumber attribute
        FAXalt              = '1 (11) 500 555-0399'     # facsimileTelephoneNumber attribute
        City                = 'East Brisbane'
        State               = 'WA'
        EmployeeID          = '088002181'
        Path                = "OU=Lab Users,$DomainDN"                  
        #Orphan              = ($user.Login -eq "")
    }
    $DemoUser8 = New-Object PSObject -Property $hashtable




#------------------------------------------------------------------------------
# DemoUser9
#
# Hard-coded user values for the preferred demo user account you want to change 
# attributes on in DSP demos to demonstrate change auditing for multiple changes.
#
# These variables will be referenced in later sections where changes are made so
# you don't have to make edits throughout this code if you want a different user
# name or other attributes.
#
   $hashtable = @{
        Name                = 'Gary Jimenez'      # CN
        SamAccountName      = 'gjimenez'
        GivenName           = 'Gary'
        Surname             = 'Jimenez'
        DisplayName         = 'Gary Jimenez'
        Initials            = 'GJ'
        Description         = 'System Engineering Site Manager'
        Mail                = 'gjimenez@adventure-works.com'
        Title               = 'Site Manager'
        Department          = 'Engineering'
        Division            = 'Engineering'
        Company             = 'Northwind'
        TelephoneNumber     = '1 (500) 555-1221'     # OfficePhone using Set-ADUser cmdlet
        TelephoneNumberAlt  = '1 (500) 555-1234'     # number to change to (to catch in DSP)
        FAX                 = '1 (500) 555-9911'     # facsimileTelephoneNumber attribute
        FAXalt              = '1 (500) 555-9922'     # facsimileTelephoneNumber attribute
        City                = 'Hobart'
        State               = 'WA'
        EmployeeID          = '088002181'
        Path                = "OU=Lab Users,$DomainDN"                  
        #Orphan              = ($user.Login -eq "")
    }
    $DemoUser9 = New-Object PSObject -Property $hashtable





#------------------------------------------------------------------------------
# DemoUser10
#
# Hard-coded user values for the preferred demo user account you want to change 
# attributes on in DSP demos to demonstrate change auditing for multiple changes.
#
# These variables will be referenced in later sections where changes are made so
# you don't have to make edits throughout this code if you want a different user
# name or other attributes.
#
   $hashtable = @{
        Name                = 'Vladimir Levin'      # CN
        SamAccountName      = 'vlevin'
        GivenName           = 'Vladimir'
        Surname             = 'Jimenez'
        DisplayName         = 'Vladimir Levin'
        Initials            = 'VL'
        Description         = 'Suspicious User'
        Mail                = 'vlevin@adventure-works.com'
        Title               = 'Sr Site Manager'
        Department          = 'Engineering'
        Division            = 'Engineering'
        Company             = 'Northwind'
        TelephoneNumber     = '1 (500) 555-8321'     # OfficePhone using Set-ADUser cmdlet
        TelephoneNumberAlt  = '1 (500) 555-8324'     # number to change to (to catch in DSP)
        FAX                 = '1 (500) 555-6611'     # facsimileTelephoneNumber attribute
        FAXalt              = '1 (500) 555-6622'     # facsimileTelephoneNumber attribute
        City                = 'St Petersburg'
        State               = 'VS'
        EmployeeID          = '055002881'
        Path                = "OU=Lab Users,$DomainDN"                  
        #Orphan              = ($user.Login -eq "")
    }
    $DemoUser10 = New-Object PSObject -Property $hashtable





#------------------------------------------------------------------------------
# AdmUser1
#
# Hard-coded user values for the preferred demo user account you want to change 
# attributes on in DSP demos to demonstrate change auditing for multiple changes.
#
# These variables will be referenced in later sections where changes are made so
# you don't have to make edits throughout this code if you want a different user
# name or other attributes.
#
   $hashtable = @{
        Name                = 'adm.draji'      # CN
        SamAccountName      = 'adm.draji'
        GivenName           = 'Dawn'
        Surname             = 'Raji'
        DisplayName         = 'Dawn Raji (ADM)'
        Initials            = 'DR'
        Description         = 'System Engineering Manager'
        Mail                = 'dawn45@adventure-works.com'
        Title               = 'Site CIO'
        Department          = 'Engineering'
        Division            = 'Engineering'
        Company             = 'Northwind'
        TelephoneNumber     = '1 (11) 500 555-0126'     # OfficePhone using Set-ADUser cmdlet
        TelephoneNumberAlt  = '1 (11) 500 555-0128'     # number to change to (to catch in DSP)
        FAX                 = '1 (11) 500 555-0288'     # facsimileTelephoneNumber attribute
        FAXalt              = '1 (11) 500 555-0399'     # facsimileTelephoneNumber attribute
        City                = 'East Brisbane'
        State               = 'WA'
        EmployeeID          = '088002181'
        Path                = "OU=Tier 2,OU=Lab Admins,$DomainDN"                  
        #Orphan              = ($user.Login -eq "")
    }
    $AdmUser1 = New-Object PSObject -Property $hashtable





#------------------------------------------------------------------------------
# AdmUser2
#
# Hard-coded user values for the preferred demo user account you want to change 
# attributes on in DSP demos to demonstrate change auditing for multiple changes.
#
# These variables will be referenced in later sections where changes are made so
# you don't have to make edits throughout this code if you want a different user
# name or other attributes.
#
   $hashtable = @{
        Name                = 'adm.gjimenez'      # CN
        SamAccountName      = 'adm.gjimenez'
        GivenName           = 'Gary'
        Surname             = 'Jimenez'
        DisplayName         = 'Gary Jimenez (ADM)'
        Initials            = 'GJ'
        Description         = 'System Engineering Site Manager'
        Mail                = 'gjimenez@adventure-works.com'
        Title               = 'Site Manager'
        Department          = 'Engineering'
        Division            = 'Engineering'
        Company             = 'Northwind'
        TelephoneNumber     = '1 (500) 555-1221'     # OfficePhone using Set-ADUser cmdlet
        TelephoneNumberAlt  = '1 (500) 555-1234'     # number to change to (to catch in DSP)
        FAX                 = '1 (500) 555-9911'     # facsimileTelephoneNumber attribute
        FAXalt              = '1 (500) 555-9922'     # facsimileTelephoneNumber attribute
        City                = 'Hobart'
        State               = 'WA'
        EmployeeID          = '088002181'
        Path                = "OU=Tier 2,OU=Lab Admins,$DomainDN"                  
        #Orphan              = ($user.Login -eq "")
    }
    $AdmUser2 = New-Object PSObject -Property $hashtable





#------------------------------------------------------------------------------
# AdmUser3
#
# Hard-coded user values for the preferred demo user account you want to change 
# attributes on in DSP demos to demonstrate change auditing for multiple changes.
#
# These variables will be referenced in later sections where changes are made so
# you don't have to make edits throughout this code if you want a different user
# name or other attributes.
#
   $hashtable = @{
        Name                = 'adm.GlobalAdmin (old)'      # CN
        SamAccountName      = 'adm.GlobalAdmin'
        GivenName           = 'Warren'
        Surname             = 'Buffet'
        DisplayName         = 'adm.GlobalAdmin (old)'
        Initials            = 'GA'
        Description         = 'Global Systems Admin (old acct)'
        Mail                = 'adm.globaladmin@adventure-works.com'
        Title               = 'Global Systems Admin'
        Department          = 'Operations'
        Division            = 'Operations'
        Company             = 'Northwind'
        TelephoneNumber     = '1 (500) 555-4554'     # OfficePhone using Set-ADUser cmdlet
        TelephoneNumberAlt  = '1 (500) 555-4555'     # number to change to (to catch in DSP)
        FAX                 = '1 (500) 555-9954'     # facsimileTelephoneNumber attribute
        FAXalt              = '1 (500) 555-9955'     # facsimileTelephoneNumber attribute
        City                = 'Hobart'
        State               = 'WA'
        EmployeeID          = '088002011'
        Path                = "OU=Tier 0,OU=Lab Admins,$DomainDN"                  
        #Orphan              = ($user.Login -eq "")
    }
    $AdmUser3 = New-Object PSObject -Property $hashtable




#------------------------------------------------------------------------------
# AutomationAcct1
#
# Hard-coded user values for the demo user account you would use in a notification
# rule to show how you can ignore changes made by an automation (e.g. Service-Now)
# account (work-flow). 
#
# These variables will be referenced in later sections where changes are made so
# you don't have to make edits throughout this code if you want a different user
# name or other attributes.
#
# Regular Expression - Unicode - Unicode Categories
#$String -replace '[^\p{L}\p{Nd}]', ''

$CompressedName = ($DomainInfo.NetBIOSName) -replace '[^\p{L}\p{Nd}]', '' # use the lab forest name
$namesuffix = 'automation'

   $hashtable_create_AutomationAcct1 = @{
        Name                = "$($CompressedName)$namesuffix"      # CN
        SamAccountName      = "$($CompressedName)$namesuffix"
        DisplayName         = "$($CompressedName)$namesuffix"
        Path                = "OU=Tier 0,OU=Lab Admins,$DomainDN"                  
        #Orphan              = ($user.Login -eq "")
    }
    $AutomationAcct1 = New-Object PSObject -Property $hashtable_create_AutomationAcct1
    
    $hashtable_update_AutomationAcct1 = @{
        #Name                = "$($CompressedName)$namesuffix"      # CN cannot be changed with an update
        DisplayName         = "$($CompressedName)$namesuffix"
        Description         = "special $namesuffix account"
        Mail                = "$($CompressedName)$namesuffix@fabrikam.com"
        Department          = 'Orchestration'
        Company             = 'Semperis Lab'                
        #Orphan              = ($user.Login -eq "")
    }

$CompressedName = $null
$namesuffix = $null



#------------------------------------------------------------------------------
# MonitoringAcct1
#
# Hard-coded user values for a tier 1 demo user account (ostensibly for monitoring).
#
# This is just another account that could be used in demos. I wanted something
# the "Tier 1" OU.
#
# These variables will be referenced in later sections where changes are made so
# you don't have to make edits throughout this code if you want a different user
# name or other attributes.
#
# Regular Expression - Unicode - Unicode Categories
#$String -replace '[^\p{L}\p{Nd}]', ''

$CompressedName = ($DomainInfo.NetBIOSName) -replace '[^\p{L}\p{Nd}]', '' # use the lab forest name
$namesuffix = 'monitoring'

   $hashtable_create_MonitoringAcct1 = @{
        Name                = "$($CompressedName)$namesuffix"      # CN
        SamAccountName      = "$($CompressedName)$namesuffix"
        DisplayName         = "$($CompressedName)$namesuffix"
        Path                = "OU=Tier 1,OU=Lab Admins,$DomainDN"                  
        #Orphan              = ($user.Login -eq "")
    }
    $MonitoringAcct1 = New-Object PSObject -Property $hashtable_create_MonitoringAcct1
    
    $hashtable_update_MonitoringAcct1 = @{
        #Name                = "$($CompressedName)automation"      # CN cannot be changed with an update
        DisplayName         = "$($CompressedName)$namesuffix"
        Description         = "special $namesuffix account"
        Mail                = "$($CompressedName)$namesuffix@fabrikam.com"
        Department          = 'Orchestration'
        Company             = 'Semperis Lab'                
        #Orphan              = ($user.Login -eq "")
    }

$CompressedName = $null
$namesuffix = $null




#------------------------------------------------------------------------------
#
# This group will be used to test and demo the UNDO capabilities as well as 
# show off the change auditing for group changes.
#
#
   $hashtable = @{
        Name             = 'Special Lab Users'
        SamAccountName   = 'SpecialLabUsers'
        DisplayName      = 'Special Lab Users'
        Description      = "Members of this lab group are special"
        GroupCategory    = 'Security'
        GroupScope       = 'Global'
        Path             = "OU=Lab Users,$DomainDN"
        #Orphan           = ($user.Login -eq "")
    }
    $SpecialLabUsers = New-Object PSObject -Property $hashtable
    $SpecialLabGroup = 'Special Lab Users'
#


#------------------------------------------------------------------------------
#
# This group is used to demonstrate the AUTO UNDO capabilities of DSP.
#
# You must create a notification rule AFTER this group is created!
#
# This requires that a notification rule be setup for the undo demo to work.
#
# The first time this script is run, it will create the group and populate it
# with the "app admin" users, but they will get removed at the end of the script.
# 
#
   $hashtable = @{
        Name             = 'Special Lab Admins'
        SamAccountName   = 'SpecialLabAdmins'
        DisplayName      = 'Special Lab Admins'
        Description      = "Members of this lab group are admins"
        GroupCategory    = 'Security'
        GroupScope       = 'Global'
        Path             = "OU=Lab Admins,$DomainDN"
        #Orphan           = ($user.Login -eq "")
    }
    $SpecialLabAdmins = New-Object PSObject -Property $hashtable
    $SpecialAdminGroup = 'Special Lab Admins'
#



#------------------------------------------------------------------------------
#
# This group adds to the AD data to provide more groups to play around with.
#
# The first time this script is run, it will create the group and populate it
# with the demo user accounts. If users are removed, they will get re-added the
# next time this script is run.
# 
#
   $hashtable = @{
        Name             = 'Pizza Party Group'
        SamAccountName   = 'PizzaPartyGroup'
        DisplayName      = 'Pizza Party Group'
        Description      = "Members of this lab group get info about pizza parties"
        GroupCategory    = 'Distribution'
        GroupScope       = 'Global'
        Path             = "OU=Lab Users,$DomainDN"
        #Orphan           = ($user.Login -eq "")
    }
    $PizzaParty = New-Object PSObject -Property $hashtable
    $PizzaPartyGroup = 'Pizza Party Group'
#



#------------------------------------------------------------------------------
#
# This group adds to the AD data to provide more groups to play around with.
#
# This will be used to create a circular group nesting.
#
# The first time this script is run, it will create the group and populate it
# with the demo user accounts. If users are removed, they will get re-added the
# next time this script is run.
# 
#
   $hashtable = @{
        Name             = 'Party Planners Group'
        SamAccountName   = 'PartyPlannersGroup'
        DisplayName      = 'Party Planners Group'
        Description      = "Members of this lab group do party planning"
        GroupCategory    = 'Distribution'
        GroupScope       = 'Global'
        Path             = "OU=Lab Users,$DomainDN"
        #Orphan           = ($user.Login -eq "")
    }
    $PartyPlannersGroup = New-Object PSObject -Property $hashtable
    $PartyPlannersGroupName = 'Party Planners Group'
#




#------------------------------------------------------------------------------
#
# Can use this group for nesting to better show off Forest Druid.
#
#
   $hashtable = @{
        Name             = 'Helpdesk Ops'
        SamAccountName   = 'HelpdeskOps'
        DisplayName      = 'Helpdesk Ops'
        Description      = "Members of this lab group are Helpdesk operators"
        GroupCategory    = 'Security'
        GroupScope       = 'Global'
        Path             = "OU=Lab Users,$DomainDN"
        #Orphan           = ($user.Login -eq "")
    }
    $HelpdeskOps = New-Object PSObject -Property $hashtable
    $HelpdeskOpsGroup = 'Helpdesk Ops'
#



#------------------------------------------------------------------------------
#
# This group is used with a FGPP.
#
# I just wanted to have an assigned FGPP to apply to a group.
#
#
   $hashtable = @{
        Name             = 'Special Accounts'
        SamAccountName   = 'Special Accounts'
        DisplayName      = 'Special Accounts'
        Description      = "Members of this lab group are special accts and service accts"
        GroupCategory    = 'Security'
        GroupScope       = 'Universal'
        Path             = "OU=Lab Admins,$DomainDN"
        #Orphan           = ($user.Login -eq "")
    }
    $SpecialAccountsObj = New-Object PSObject -Property $hashtable
    $SpecialAccountsGroup = 'Special Accounts'
#



#------------------------------------------------------------------------------
# Special OU
#
# This OU is to demo a more restrictive ACL with a couple of computer objects added.
#
#
   $hashtable = @{
        Name             = 'zSpecial OU'
        SamAccountName   = 'zSpecial OU'
        DisplayName      = 'zSpecial OU'
        Description      = "Restricted OU for special objects"
        #GroupCategory    = 'Security'
        #GroupScope       = 'Universal'
        Path             = "$DomainDN"
        #Orphan           = ($user.Login -eq "")
    }
    $SpecialOuObj = New-Object PSObject -Property $hashtable
    $SpecialOU = 'zSpecial OU'
#



#------------------------------------------------------------------------------
#
# This computer object is to demo having objects in a more restricted OU.
#
#
   $hashtable = @{
        Name             = 'PIMPAM'
        SamAccountName   = 'PIMPAM'
        DisplayName      = 'PIMPAM'
        Description      = "Privileged access server"
        #GroupCategory    = 'Security'
        #GroupScope       = 'Universal'
        Path             = "$SpecialOU,$DomainDN"
        #Orphan           = ($user.Login -eq "")
    }
    $SpecialComputerObj1 = New-Object PSObject -Property $hashtable
    $SpecialComputer1 = 'PIMPAM'
#



#------------------------------------------------------------------------------
#
# This computer object is to demo having objects in a more restricted OU.
#
#
   $hashtable = @{
        Name             = 'VAULT'
        SamAccountName   = 'VAULT'
        DisplayName      = 'VAULT'
        Description      = "Vault server to store passwords and crednetials"
        #GroupCategory    = 'Security'
        #GroupScope       = 'Universal'
        Path             = "$SpecialOU,$DomainDN"
        #Orphan           = ($user.Login -eq "")
    }
    $SpecialComputerObj2 = New-Object PSObject -Property $hashtable
    $SpecialComputer2 = 'VAULT'
#



#------------------------------------------------------------------------------
#
# This computer object is to demo having objects in a more restricted OU.
#
#
   $hashtable = @{
        Name             = 'BASTION-HOST01'
        SamAccountName   = 'BASTION-HOST01'
        DisplayName      = 'BASTION-HOST01'
        Description      = "Bastion host for restricted privileged access"
        #GroupCategory    = 'Security'
        #GroupScope       = 'Universal'
        Path             = "$SpecialOU,$DomainDN"
        #Orphan           = ($user.Login -eq "")
    }
    $SpecialComputerObj3 = New-Object PSObject -Property $hashtable
    $SpecialComputer3 = 'BASTION-HOST01'
#





#------------------------------------------------------------------------------
#
# This computer object is to demo having objects in a more restricted OU.
#
#
   $hashtable = @{
        Name             = 'BASTION-HOST01'
        SamAccountName   = 'BASTION-HOST01'
        DisplayName      = 'BASTION-HOST01'
        Description      = "Bastion host for restricted privileged access"
        #GroupCategory    = 'Security'
        #GroupScope       = 'Universal'
        Path             = "$SpecialOU,$DomainDN"
        #Orphan           = ($user.Login -eq "")
    }
    $SpecialComputerObj3 = New-Object PSObject -Property $hashtable
    $SpecialComputer3 = 'BASTION-HOST01'
#





#------------------------------------------------------------------------------
#
# This is a site object to create/add a new site to AD
#
#
   $hashtable = @{
        Name             = 'SemperisLabs'
        SamAccountName   = 'SemperisLabs'
        DisplayName      = 'SemperisLabs'
        Description      = "AD site for Semperis Labs"
        Location         = "USA-TX-Labs"
        SubnetName       = "10.3.22.0/24"
        SubnetDescription = "AD subnet for Semperis Labs"
        SubnetLocation   = "USA-TX-Labs"
        #Orphan           = ($user.Login -eq "")
    }
    $ADSiteObj001 = New-Object PSObject -Property $hashtable
    $ADSite001 = 'SemperisLabs'
#



#
# End of Customizations Section
# 
#-------------------------------------------------------------------------------
################################################################################
################################################################################








################################################################################
#-------------------------------------------------------------------------------
#
# Test-PsOneKeyPress()
#
# Really cool function that waits for a keypress to continue. Used in this code
# wait for the user where they might want more time to read certain output or
# do something outside the script then continue (e.g., copy the DSP PoSh module).
#
function Test-PSOneKeyPress
{
  <#
      .SYNOPSIS
      Tests whether keys are currently pressed

      .DESCRIPTION
      Returns $true when ALL of the submitted keys are currently pressed.
      Uses API calls and does not rely on the console. It works in all PowerShell Hosts
      including ISE and VSCode/EditorServices        

      .EXAMPLE
      Test-PsOneKeyPress -Key A,B -SpecialKey Control,ShiftLeft -Wait
      returns once the keys A, B, Control and left Shift were simultaneously pressed

      .EXAMPLE
      Test-PsOneKeyPress -SpecialKey Control -Wait -Timeout 00:00:05 -ShowProgress
      returns once the keys A, B, Control and left Shift were simultaneously pressed

      .EXAMPLE
      Test-PSOneKeyPress -Key Escape -Timeout '00:00:20' -Wait -ShowProgress
      wait for user to press ESC, and timeout after 20 seconds

      .EXAMPLE
      Test-PSOneKeyPress -Key H -SpecialKey Alt,Shift -Wait -ShowProgress
      wait for Alt+Shift+H

      .LINK
      https://powershell.one/tricks/input-devices/detect-key-press
  #>
    
  [CmdletBinding(DefaultParameterSetName='test')]
  param
  (
    # regular key, can be a comma-separated list
    [Parameter(ParameterSetName='wait')]
    [Parameter(ParameterSetName='test')]
    [ConsoleKey[]]
    $Key = $null,

    # special key, can be a comma-separated list
    [Parameter(ParameterSetName='wait')]
    [Parameter(ParameterSetName='test')]
    [ValidateSet('Alt','CapsLock','Control','ControlLeft','ControlRight','LeftMouseButton','MiddleMouseButton', 'RightMouseButton','NumLock','Shift','ShiftLeft','ShiftRight','MouseWheel')]
    [string[]]
    $SpecialKey = $null,
    
    # waits for the key combination to be pressed
    [Parameter(Mandatory,ParameterSetName='wait')]
    [switch]
    $Wait,
    
    # timeout (timespan) for the key combination to be pressed
    [Parameter(ParameterSetName='wait')]
    [Timespan]
    $Timeout=[Timespan]::Zero,
    
    # show progress
    [Parameter(ParameterSetName='wait')]
    [Switch]
    $ShowProgress
  )
    
  # at least one key is mandatory:
  if (($Key.Count + $SpecialKey.Count) -lt 1)
  {
    throw "No key specified."
  }
  # use a hashtable to translate string values to integers
  # this could have also been done using a enumeration
  # however if a parameter is using a enumeration as type,
  # the enumeration must be defined before the function
  # can be called. 
  # My goal was to create a hassle-free stand-alone function,
  # so enumerations were no option
  $converter = @{
    Shift = 16
    ShiftLeft = 160
    ShiftRight = 161
    Control = 17
    Alt = 18
    CapsLock = 20
    ControlLeft = 162
    ControlRight = 163
    LeftMouseButton = 1
    RightMouseButton = 2
    MiddleMouseButton = 4
    MouseWheel = 145
    NumLock = 144
  }

  # create an array with ALL keys from BOTH groups
    
  # start with an integer list of regular keys 
  if ($Key.Count -gt 0)
  {
    $list = [System.Collections.Generic.List[int]]$Key.value__
  }
  else
  {
    $list = [System.Collections.Generic.List[int]]::new()
  }
  # add codes for all special characters
  foreach($_ in $SpecialKey)
  {
    $list.Add($converter[$_])
  }
  # $list now is a list of all key codes for all keys to test
    
  # access the windows api
  $Signature = @'
    [DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)] 
    public static extern short GetAsyncKeyState(int virtualKeyCode); 
'@

  # Add-Type compiles the source code and adds the type [PsOneApi.Keyboard]:
  Add-Type -MemberDefinition $Signature -Name Keyboard -Namespace PsOneApi
    
  # was -Wait specified?
  $isNoWait = $PSCmdlet.ParameterSetName -ne 'wait'
  
  # do we need to watch a timeout?
  $hasTimeout = ($Timeout -ne [Timespan]::Zero) -and ($isNoWait -eq $false)
  if ($hasTimeout)
  {
    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
  }  
  
  # use a try..finally to clean up
  try
  {
    # use a counter
    $c = 0
    
    # if -Wait was specified, the loop repeats until
    # either the keys were pressed or the timeout is exceeded
    # else, the loop runs only once
    do
    {
      # increment counter
      $c++
      
      # test each key in $list. If any key returns $false, the total result is $false:
      foreach ($_ in $list)
      {
          $pressed = [bool]([PsOneApi.Keyboard]::GetAsyncKeyState($_) -eq -32767)
          # if there is a key NOT pressed, we can skip the rest and bail out 
          # because ALL keys need to be pressed
          if (!$pressed) { break }
      }
    
      # is the timeout exceeded?
      if ($hasTimeout)
      {
        if ($stopWatch.Elapsed -gt $Timeout)
        {
          throw "Waiting for keypress timed out."
        }
      }
      
      # show progress indicator? if so, only every second
      if ($ShowProgress -and ($c % 2 -eq 0))
      {
        Write-Host '.' -NoNewline
      }
      # if the keys were not pressed and the function waits for the keys,
      # sleep a little:
      if (!$isNoWait -and !$pressed)
      {
        Start-Sleep -Milliseconds 500
      }
    } until ($pressed -or $isNoWait)
  
    # if this is just checking the key states, return the result:
    if ($isNoWait)
    {
      return $pressed
    }
  }
  finally
  {
    if ($hasTimeout)
    {
      $stopWatch.Stop()    
    }
    if ($ShowProgress)
    {
      Write-Host
    }
    $KeyPressStatus = $pressed
  }

  return $KeyPressStatus
}


#Test-PSOneKeyPress -Key H -SpecialKey Alt,Shift -Wait -ShowProgress  # press Alt-Shift-H to exit!!
#Test-PSOneKeyPress -Key H -Timeout '00:00:08' -Wait -ShowProgress -ErrorAction SilentlyContinue # press H to exit!!

#
#-------------------------------------------------------------------------------
################################################################################







################################################################################
#-------------------------------------------------------------------------------
#
Write-Host ""
Write-Host ""
Write-Host "#####################################################################################" -ForegroundColor White -BackgroundColor Black
Write-Host "#------------------------------------------------------------------------------------" -ForegroundColor White -BackgroundColor Black
Write-Host "# PREREQUISITES AND DEPENDENCIES                                                     " -ForegroundColor White -BackgroundColor Black
Write-Host "#                                                                                    " -ForegroundColor White -BackgroundColor Black
Write-Host "# This script may be run as-is!!                                                     " -ForegroundColor White -BackgroundColor Black
Write-Host "#                                                                                    " -ForegroundColor White -BackgroundColor Black
Write-Host "# NOTE: You will get prompts for credential management and an option to enter a      " -ForegroundColor White -BackgroundColor Black
Write-Host "#       user count for generic user account creation.                                " -ForegroundColor White -BackgroundColor Black
Write-Host "#                                                                                    " -ForegroundColor White -BackgroundColor Black
Write-Host "# There are some optional prerequisites for -full- functionality within this script. " -ForegroundColor White -BackgroundColor Black
Write-Host "#                                                                                    " -ForegroundColor White -BackgroundColor Black
Write-Host "# This script will run to completion, but some of the scripted steps/functionality   " -ForegroundColor White -BackgroundColor Black
Write-Host "# may fail with regard to the following prerequisites:                               " -ForegroundColor White -BackgroundColor Black
Write-Host "#                                                                                    " -ForegroundColor White -BackgroundColor Black
Write-Host "# * Needs Internet access to get to the external Credential Manager functions.       " -ForegroundColor White -BackgroundColor Black
Write-Host "#     - Credential Manager is used to securely store a credential for use            " -ForegroundColor White -BackgroundColor Black
Write-Host "#       in the steps where an alternative credential is used to make changes.        " -ForegroundColor White -BackgroundColor Black
Write-Host "#     - Credential Manager tools are on github.                                      " -ForegroundColor White -BackgroundColor Black
Write-Host "#     - Note that this script will still function without the Credential             " -ForegroundColor White -BackgroundColor Black
Write-Host "#       Manager functions, but the changes by an alternative admin will fail.        " -ForegroundColor White -BackgroundColor Black
Write-Host "#                                                                                    " -ForegroundColor White -BackgroundColor Black
Write-Host "# * Need the DSP PoSh module installed locally. Must download from the DSP console.  " -ForegroundColor White -BackgroundColor Black
Write-Host "#   This is required for the scripted undo action(s) near the end of the script.     " -ForegroundColor White -BackgroundColor Black
Write-Host "#                                                                                    " -ForegroundColor White -BackgroundColor Black
Write-Host "# * Need Enterprise Admin in order to modify the Default Domain Policy GPO, to       " -ForegroundColor White -BackgroundColor Black
Write-Host "#   create OU's, and potentially some other changes to certain policies or ACL's.    " -ForegroundColor White -BackgroundColor Black
Write-Host "#                                                                                    " -ForegroundColor White -BackgroundColor Black
Write-Host "# * You will need to configure the SMTP settings to get email alerts.                " -ForegroundColor White -BackgroundColor Black
Write-Host "#                                                                                    " -ForegroundColor White -BackgroundColor Black
Write-Host "# * Newly created (non-existing) user accounts will prompt for a password value.     " -ForegroundColor White -BackgroundColor Black
Write-Host "#   (Only prompts for passwords one time upon initial account creation.)             " -ForegroundColor White -BackgroundColor Black
Write-Host "#                                                                                    " -ForegroundColor White -BackgroundColor Black
Write-Host "# * There must be a Notification Rule pre-created to demo the auto-undo function.    " -ForegroundColor White -BackgroundColor Black
Write-Host "#   (See the ""Notes About Operation"" section below for more details.)                " -ForegroundColor White -BackgroundColor Black
Write-Host "#                                                                                    " -ForegroundColor White -BackgroundColor Black
Write-Host "#   Create these Notification Rules with UNDO enabled:                               " -ForegroundColor White -BackgroundColor Black
Write-Host "#    RULE #1: undo change to 'title' attribute changes for user 'DemoUser3'          " -ForegroundColor White -BackgroundColor Black
Write-Host "#             (DemoUser3 is $($DemoUser3.SamAccountName))                                           " -ForegroundColor White -BackgroundColor Black
Write-Host "#                                                                                    " -ForegroundColor White -BackgroundColor Black
Write-Host "#    RULE #2: undo group membership changes for group 'SpecialLabAdmins'             " -ForegroundColor White -BackgroundColor Black
Write-Host "#             (SpecialLabsAdmins'$($SpecialLabAdmins.Name)')                                 " -ForegroundColor White -BackgroundColor Black
Write-Host "#                                                                                    " -ForegroundColor White -BackgroundColor Black
Write-Host "#   (Break out now or pause the script if more time is needed to read this text)     " -ForegroundColor White -BackgroundColor Black
Write-Host "#------------------------------------------------------------------------------------" -ForegroundColor White -BackgroundColor Black
Write-Host "#####################################################################################" -ForegroundColor White -BackgroundColor Black
Write-Host ""
Write-Host ""

# ---------------------------------------------------------------------
# Pause (Read-Host) on key press
# 
# This is an interesting way to offer an interactive use the chance to 
# pause the script. If the specific key press is not seen within the
# specified time, then the script will continue one. If the specified
# key IS detected, then the script pauses until the user continues it.
#
# This is a method to allow the user to read the output (above) if 
# more time is needed.
#
 
Write-Host "::                                                                         " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::  Press 'S' or 's' (multiple times) within 15 seconds to pause longer!!  " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::                                                                         " -ForegroundColor White -BackgroundColor DarkGray

$KeyPressed = Test-PSOneKeyPress -Key S -Timeout '00:00:15' -Wait -ShowProgress -ErrorAction SilentlyContinue
Write-Host "PRESSED: $KeyPressed"
If ($KeyPressed)
{
    Write-Host ""
    Read-Host "     *** press <Enter> key when ready to continue the script ***   "
    Write-Host ""
}

# ---------------------------------------------------------------------
#
#------------------------------------------------------------------------------
################################################################################






################################################################################
#------------------------------------------------------------------------------
#
Write-Host ""
Write-Host ""
Write-Host ""
Write-Host "::                                                      " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: LOAD MODULES                                         " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                      " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::"  -ForegroundColor Yellow
Write-Host ":: Making sure AD PoSh modules are loaded and DNS tools (RSAT) are installed" -ForegroundColor Yellow
Write-Host "Import-Module ActiveDirectory" -ForegroundColor Cyan
Import-Module ActiveDirectory
Write-Host ""
Write-Host "Import-Module GroupPolicy" -ForegroundColor Cyan
Import-Module GroupPolicy
Write-Host ""
Write-Host "Add-WindowsCapability -Online -Name "Rsat.Dns.Tools" -Verbose" -ForegroundColor Cyan
Add-WindowsCapability -Online -Name "Rsat.Dns.Tools" -Verbose
Write-Host ""
Write-Host "Import-Module DnsServer" -ForegroundColor Cyan
Import-Module DnsServer
Start-Sleep 5
Write-Host ""
Write-Host ""
#
#------------------------------------------------------------------------------
################################################################################






################################################################################
#------------------------------------------------------------------------------
#
Write-Host ""
Write-Host ":: Running 'Import-Module Semperis.PoSh.DSP' to load DSP cmdlets..." -ForegroundColor Yellow
Write-Host ""

Write-Host ""
# Current path from which this script was executed...
(Get-Item .).FullName   # gives current folder, but not necessarily he folder from where this script is run
$ScriptPath = $MyInvocation.MyCommand.Path
$scriptdir = Split-Path $scriptpath                  # THIS VAR IS USED LATER!!!!
Write-Host ""
Write-Host ":: Script path: $scriptdir  " -ForegroundColor Magenta
Write-Host ""
Start-Sleep 3


#Remove-Module Semperis.PoSh.DSP -Verbose

Write-Host ""
Write-Host ""
Write-Host "Import-Module Semperis.PoSh.DSP -Verbose -ErrorAction SilentlyContinue" -ForegroundColor Magenta
Import-Module Semperis.PoSh.DSP -Verbose -ErrorAction SilentlyContinue
$ModuleStatus = Get-Module Semperis.PoSh.DSP
If ($ModuleStatus)
{
    Write-Host ""
    Write-Host ":: DSP PoSh module already installed." -ForegroundColor Yellow
    Write-Host ":: The DSP PoSh module 'Semperis.PoSh.DSP' has been loaded!!" -ForegroundColor Yellow
    Write-Host ""
    $DspPoShStatus = $true
}
Else
{ 
    Write-Host ""
    Write-Host ":: -----------------------------------------------------------------------------" -ForegroundColor Yellow -BackgroundColor Red
    Write-Host "::         The DSP PoSh module 'Semperis.PoSh.DSP' is NOT installed!!           " -ForegroundColor Yellow -BackgroundColor Red
    Write-Host "::                                                                              " -ForegroundColor Yellow -BackgroundColor Red
    Write-Host "::         Attempting to install the DSP PoSh module...                         " -ForegroundColor Yellow -BackgroundColor Red
    Write-Host ":: -----------------------------------------------------------------------------" -ForegroundColor Yellow -BackgroundColor Red
    Write-Host ""
    $DspPoShStatus = $false

    Write-Host "" 
    Write-Host "::                                                                              " -ForegroundColor White -BackgroundColor DarkCyan
    Write-Host "::    This script will look for the DSP PowerShell module MSI installer         " -ForegroundColor White -BackgroundColor DarkCyan
    Write-Host "::    in the same directory from where this script was run.                     " -ForegroundColor White -BackgroundColor DarkCyan
    Write-Host "::                                                                              " -ForegroundColor White -BackgroundColor DarkCyan
    Write-Host "::    Do you need more time to download and/or copy-and-paste the MSI file      " -ForegroundColor White -BackgroundColor DarkCyan
    Write-Host "::    into the [$ScriptDir] directory?                                   " -ForegroundColor White -BackgroundColor DarkCyan
    Write-Host "::                                                                              " -ForegroundColor White -BackgroundColor DarkCyan


    # ---------------------------------------------------------------------
    # Pause (Read-Host) on key press
    # 
    # This is an interesting way to offer an interactive use the chance to 
    # pause the script. If the specific key press is not seen within the
    # specified time, then the script will continue one. If the specified
    # key IS detected, then the script pauses until the user continues it.
    #
    # This is a method to allow the user to read the output (above) if 
    # more time is needed.
    #
     
    Write-Host "::                                                                          " -ForegroundColor White -BackgroundColor DarkGray
    Write-Host "::  Press 'S' or 's' (multiple times) within 15 seconds to pause longer!!   " -ForegroundColor White -BackgroundColor DarkGray
    Write-Host "::                                                                          " -ForegroundColor White -BackgroundColor DarkGray
    
    $KeyPressed = Test-PSOneKeyPress -Key S -Timeout '00:00:15' -Wait -ShowProgress -ErrorAction SilentlyContinue
    Write-Host "PRESSED: $KeyPressed"
    If ($KeyPressed)
    {
        Write-Host ""
        Read-Host "     *** press <Enter> key when ready to continue the script ***   "
        Write-Host ""
    }



    Write-Host ""
    $filename = 'Semperis.PowerShell.Installer.msi' # filename from complete installer package (downloaded)
    $searchinfolder = '\\pdc\Shared\Accounting*'
    $searchinfolder = '\\f187-d01-dc02\C$\*'
    $searchinfolder = "$scriptdir"
    $dspPoshFile1 = Get-ChildItem -Path $searchinfolder -Filter $filename -Recurse -ErrorAction SilentlyContinue # | %{$_.FullName}
    $dspPoshFile1.FullName
    $dspPoshFile1.VersionInfo
    #$dspPoshFile1.LastWriteTime

    Write-Host ""
    $filename = 'Semperis.PoSh.DSP.Installer.msi'   # filename on DSP PoSh module from DSP console download
    $searchinfolder = '\\pdc\Shared\Accounting*'
    $searchinfolder = '\\f187-d01-dc02\C$\*'
    $searchinfolder = "$scriptdir"
    $dspPoshFile2 = Get-ChildItem -Path $searchinfolder -Filter $filename -Recurse -ErrorAction SilentlyContinue # | %{$_.FullName}
    $dspPoshFile2.FullName
    $dspPoshFile2.VersionInfo
    #$dspPoshFile2.LastWriteTime

    Write-Host ""
    
    # note that DSP PoSh files do not include a version number that can
    # be rendered with PoSh calls, so we have to use the date and hope that
    # the latest dated file is the latest version of the DSP module installer.

    If ($dspPoshFile1.Exists -or $dspPoshFile2.Exists)
    {
        If ($dspPoshFile1.LastWriteTime -gt $dspPoshFile2.LastWriteTime)
        {
            Write-Host ""
            Write-Host ":: Installing DSP PoSh module ($($dspPoshFile1.FullName))..." -ForegroundColor Yellow -BackgroundColor DarkCyan
            $MSIArguments = @(
                "/i"
                ('"{0}"' -f $dspPoshFile1.FullName)
            "/norestart"
            )
            Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow 
            Write-Host ""
            Write-Host ""
        }
        Else
        {
            Write-Host ""
            Write-Host "                                                                " -ForegroundColor Yellow -BackgroundColor DarkCyan
            Write-Host ":: Installing DSP PoSh module ($($dspPoshFile2.FullName))..." -ForegroundColor Yellow -BackgroundColor DarkCyan
            Write-Host "                                                                " -ForegroundColor Yellow -BackgroundColor DarkCyan
            Write-Host ""
            $MSIArguments = @(
                "/i"
                ('"{0}"' -f $dspPoshFile2.FullName)
                "/norestart"
            )
            Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow 
            Write-Host ""
            Write-Host ""
        }

        # Try to load the DSP PoSh module now...

        Write-Host ""
        Write-Host ""
        Write-Host "Import-Module Semperis.PoSh.DSP -Verbose -ErrorAction SilentlyContinue" -ForegroundColor Magenta
        Import-Module Semperis.PoSh.DSP -Verbose -ErrorAction SilentlyContinue
        $ModuleStatus = Get-Module Semperis.PoSh.DSP
        If ($ModuleStatus)
        {
            Write-Host ""
            Write-Host ":: DSP PoSh module already installed." -ForegroundColor Yellow
            Write-Host ":: The DSP PoSh module 'Semperis.PoSh.DSP' has been loaded!!" -ForegroundColor Yellow
            Write-Host ""
            $DspPoShStatus = $true
        }
        Else
        { 
            Write-Host ""
            Write-Host ":: -----------------------------------------------------------------------------" -ForegroundColor Yellow -BackgroundColor Red
            Write-Host "::         The DSP PoSh module 'Semperis.PoSh.DSP' is NOT installed!!           " -ForegroundColor Yellow -BackgroundColor Red
            Write-Host ":: -----------------------------------------------------------------------------" -ForegroundColor Yellow -BackgroundColor Red
            Write-Host "::                                                                              " -ForegroundColor Yellow -BackgroundColor Red
            Write-Host ":: The tasks using DSP automation will not work in this script, but other       " -ForegroundColor Yellow -BackgroundColor Red
            Write-Host ":: activities will be unaffected.                                               " -ForegroundColor Yellow -BackgroundColor Red
            Write-Host "::                                                                              " -ForegroundColor Yellow -BackgroundColor Red
            Write-Host ":: To remediate this, you will have to diagnose why the DSP PoSh module is      " -ForegroundColor Yellow -BackgroundColor Red
            Write-Host ":: not being loaded.                                                            " -ForegroundColor Yellow -BackgroundColor Red
            Write-Host "::                                                                              " -ForegroundColor Yellow -BackgroundColor Red
            Write-Host ":: The script will now continue without the DSP PoSh module loaded...           " -ForegroundColor Yellow -BackgroundColor Red
            Write-Host "::                                                                              " -ForegroundColor Yellow -BackgroundColor Red
            Write-Host ":: -----------------------------------------------------------------------------" -ForegroundColor Yellow -BackgroundColor Red
        }

    }
}


#$DataStamp = get-date -Format yyyyMMddTHHmmss
#$logFile = '{0}-{1}.log' -f $file.fullname,$DataStamp
#$MSIArguments = @(
#    "/i"
#    ('"{0}"' -f $file.fullname)
#    "/qn"
#    "/norestart"
#    "/L*v"
#    $logFile
#)
#Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow 

Write-Host ""
Write-Host ""
#
#------------------------------------------------------------------------------
################################################################################






################################################################################
#------------------------------------------------------------------------------
Write-Host ""
Write-Host ""
Write-Host "------------------------------------------------------------------" -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: START :: Creating change data for DSP demos...                 " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "------------------------------------------------------------------" -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
#-------------------------------------------------------------------------------
################################################################################







################################################################################
##------------------------------------------------------------------------------
## Create "OU=TEST" and populate with N generic user accounts
##
## The variables are duplicative of variables I've already created, but I copied
## this working code and didn't want to re-map the variables, so I will leave
## this cleanup work to a later date.
##
## Hard-coded configuration value is in the CONFIGURATION section.
##
# Prompt user in case they want to create/update a different number of generic
# user accounts in the "OU=TEST" OU.
#
# Only doing this here to kep the flow a little better, since the user just had
# another prompt or two. 
#
# It's actually kind of difficult to figure out where best to prompt to follow
# the flow of the script. I preferred to not do this in the configuration
# section because the user would not yet be prompted with script info.
#
# This section could be further down the script in the user setup section... 
# There will be one more prompt earlier on for the alternate credential input.
#
Write-Host ""
Write-Host ""
Write-Host "::                                                                 " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: CHANGE DEFAULT GENERIC USER COUNT FOR THIS RUN?                 " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                 " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                 " -ForegroundColor Yellow -BackgroundColor DarkCyan
Write-Host ":: This script will create generic user accounts in 'OU=TEST' if   " -ForegroundColor Yellow -BackgroundColor DarkCyan
Write-Host ":: they do not already exist.                                      " -ForegroundColor Yellow -BackgroundColor DarkCyan
Write-Host "::                                                                 " -ForegroundColor Yellow -BackgroundColor DarkCyan
Write-Host ":: The default number of accounts to create is $GenericUsersCount                 " -ForegroundColor Yellow -BackgroundColor DarkCyan
Write-Host "::                                                                 " -ForegroundColor Yellow -BackgroundColor DarkCyan
Write-Host ":: (If this script was previously run, the script will not create  " -ForegroundColor Yellow -BackgroundColor DarkCyan
Write-Host ":: additional duplicate accounts. If a lesser number is chosen,    " -ForegroundColor Yellow -BackgroundColor DarkCyan
Write-Host ":: existing generic accoutns will not be removed.)                 " -ForegroundColor Yellow -BackgroundColor DarkCyan
Write-Host "::                                                                 " -ForegroundColor Yellow -BackgroundColor DarkCyan
#
$Shell = New-Object -ComObject "WScript.Shell"
#intButton = objShell.Popup(strText,[nSecondsToWait],[strTitle],[nType]) 
$Button = $Shell.Popup("Default generic user creation count is 250. `nDo you want to enter a different value for the user count?", 8, "Default Generic User Count Value", 4+32)
#$Button  # 6=Yes   7=No   -1=no response
Write-Host ""
If ($Button -eq 6)
    {
    Do
        {
        [int]$GenericUsersCount = Read-Host -Prompt "-- Enter number of generic user accounts to create (1 to 10000):"
        }
        Until (($GenericUsersCount -le 10000) -and ($GenericUsersCount -gt 0))
    }
Else
    {
    #$GenericUsersCount = 250
    }

Write-Host ""
Write-Host ":: Script will create [$GenericUsersCount] generic user accounts if they do not already exist." -ForegroundColor Cyan
Write-Host ""
Write-Host ""


$adDomain = Get-ADDomain -Current LocalComputer
$adDomainDN = $adDomain.DistinguishedName
$adDomainFQDN = $adDomain.DNSRoot
$adDomainNetBIOS = $adDomain.NetBIOSName
$adDomainDeletedObjectsContainerDN = $adDomain.DeletedObjectsContainer
$adDomainDomainControllersContainerDN = $adDomain.DomainControllersContainer
$adDomainSID = $adDomain.DomainSID.Value
$adDomainRwdcPdcFsmoFQDN = $adDomain.PDCEmulator
$adDomainRwdcFQDN = (Get-ADDomainController -DomainName $adDomainFQDN -Discover).HostName[0]
$OUforTestUsers = "OU=TEST,$adDomainDN"
If ((Get-ADObject -SearchBase $adDomainDN -LDAPFilter "(distinguishedName=$OUforTestUsers)") -eq $null) {
	New-ADOrganizationalUnit -Name $($OUforTestUsers.Split(",")[0].Replace("OU=","")) -Path $adDomainDN
}

$adForest = Get-ADForest -Current LocalComputer
$adForestRootDomainFQDN = $adForest.RootDomain
$adForestRootDomain = Get-ADDomain $adForestRootDomainFQDN
$adForestRootDomainNetBIOS = $adForestRootDomain.NetBIOSName
$adForestRootDomainSID = $adForestRootDomain.DomainSID.Value
$adForestRwdcSchFsmoFQDN = $adForest.SchemaMaster
$adForestRwdcDnmFsmoFQDN = $adForest.DomainNamingMaster
$adForestPartitionsContainerDN = $adForest.PartitionsContainer
$adForestConfigNCDN = $adForestPartitionsContainerDN.Replace("CN=Partitions,","")
$adForestSchemaNCDN = "CN=Schema," + $adForestConfigNCDN
#################################################################################



# Create Generic Accounts: Good Actors
# $OU = "OU=TEST,$adDomainDN"
#
Invoke-Command -ArgumentList $adDomain,$adDomainDN,$adDomainFQDN,$adDomainNetBIOS,$adDomainRwdcFQDN,$OUforTestUsers -ScriptBlock {
	Param (
		$adDomain,
		$adDomainDN,
		$adDomainFQDN,
		$adDomainNetBIOS,
		$adDomainRwdcFQDN,
		$OUforTestUsers
	)
  
  
    $N = $GenericUsersCount # number of user accounts to create (assuming max 999,999 for prefix padding)

    $PREFIX  = @('000000', '00000', '0000', '000', '00', '0')  # This is for padding names

    Write-Host ""
    Write-Host ""
    Write-Host "::" -ForegroundColor Yellow
    Write-Host "::" -ForegroundColor Yellow
    Write-Host ":: Bulk create $([int]$N) generic user accounts in '$($OUforTestUsers)'..." -ForegroundColor Yellow
    Write-Host "::" -ForegroundColor Yellow
    Write-Host "::" -ForegroundColor Yellow
    Write-Host ":: (Quit now or script will continue in 6 seconds)" -ForegroundColor Yellow
    Write-Host "::" -ForegroundColor Yellow
    Write-Host "::" -ForegroundColor Yellow
    Write-Host ""
    Start-Sleep 6

    # N-1 because we start at 0

	0..($N-1) | ForEach-Object{
		$randomNr = (Get-Date -Format "yyyyMMddHHmmss").ToString() + (Get-Random -Minimum 10 -Maximum 99)
		$password = $(-join (33..126 | ForEach-Object {[char]$_} | Get-Random -Count 32))

        $INDEX = "$($PREFIX[($($_).ToString().Length)])$($_)"

        If ($GenericUser = Get-ADUser -LDAPFilter "((objectClass=user)(objectCategory=person) (| (sAMAccountName=$("GdAct0r-" + $INDEX)) (CN=$("Good Act0r " + $adDomainFQDN + " " + $INDEX)) ) )")
        {
            Write-Host "User $($GenericUser) [$("GdAct0r-" + $INDEX)] already exists." -ForegroundColor DarkGray
        }
        Else
        {
    		Write-Host "Creating User Account: ""Good Act0r $($INDEX)"" [$("GdAct0r-" + $INDEX)] ..." -ForegroundColor Magenta
		    New-ADUser -Path $OUforTestUsers -Enabled $true -Name $("Good Act0r" + " " + $INDEX) -GivenName "Good" -Surname $("Act0r " + " " + $INDEX) -DisplayName $("Good Act0r " + " " + $INDEX) -SamAccountName $("GdAct0r-" + $INDEX) -UserPrincipalName "Good.Act0r.$INDEX@$adDomainFQDN" -Description $("Good Act0r "+ " " + $($_) + "(" + $adDomainFQDN + ")" ) -AccountPassword $(ConvertTo-SecureString $password -AsPlainText -Force) -Server $adDomainRwdcFQDN
#            This code is to add configuation changes that affect indicators of compromise...
#    		  If ($($_).ToString().EndsWith("1") -eq $true) 
#             {
#			      Set-ADUser -Identity $("GdAct0r" + $($INDEX)) -Description $("Good Act0r " + " " + $($INDEX) + " Password = " + $password) -Add @{"msDS-AllowedToDelegateTo" = @("MSSQLSvc/$randomNr:1433", "MSSQLSvc/$randomNr.$adDomainFQDN:1433") } -ServicePrincipalNames @{Add = "HTTP/$randomNr.111.$adDomainFQDN", "HTTP/$randomNr.222.$adDomainFQDN" } -Server $adDomainRwdcFQDN
#		      }
###		      Set-ADAccountControl -Identity $("GdAct0r" + $($INDEX)) -PasswordNeverExpires $false -Server $adDomainRwdcFQDN
        }
		Write-Host "- - -"
	}
    
    Write-Host "::" -ForegroundColor Yellow
    Write-Host ":: Done!!" -ForegroundColor Yellow
    Write-Host ""
}
##
##------------------------------------------------------------------------------
################################################################################







################################################################################
##------------------------------------------------------------------------------
## CREDENTIAL MANAGER STUFF FOR WINDOWS CREDENTIAL USAGE
##
# We need these functions to manage and utilize some Windows creds for making
# some of the attribute changes so we get a different "Changed By" user name.
#
# We need to make sure this module is loaded via the Internet.
#
# https://childebrandt42.wordpress.com/2020/07/07/using-windows-credential-manager-with-powershell/
#
# https://www.powershellgallery.com/packages/CredentialManager/2.0
# Get-StoredCredential
# Get-StrongPassword
# Get-StrongPassword -Length 20 -NumberOfSpecialCharacters 4
# New-StoredCredential
# Remove-StoredCredential

Write-Host ""
Write-Host ""
Write-Host ""
Write-Host "::                                                              " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: CREDENTIAL MANAGER                                           " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                              " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                              " -ForegroundColor Yellow -BackgroundColor DarkCyan
Write-Host ":: Package to utilize and mangage the Windows Credential Store. " -ForegroundColor Yellow -BackgroundColor DarkCyan
Write-Host "::                                                              " -ForegroundColor Yellow -BackgroundColor DarkCyan
Write-Host ":: Loading 'CredentialManager' package from the Internet...     " -ForegroundColor Yellow -BackgroundColor DarkCyan
Write-Host "::                                                              " -ForegroundColor Yellow -BackgroundColor DarkCyan

Install-Module -Name CredentialManager -Verbose

# The credentials will have to be installed AFTER the user creation section.

Write-Host "`n`n"

##------------------------------------------------------------------------------
################################################################################







#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                  " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- LETS SET SOME AD SITE CONFIGURATION STUFF FOR LATER ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                  " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

Write-Host ":: Site link info for 'DEFAULTIPSITELINK'..." -ForegroundColor Yellow
Get-ADReplicationSiteLink -Identity DEFAULTIPSITELINK

Write-Host ""
Write-Host ":: Let's change the site cost to 10..." -ForegroundColor Yellow
Set-ADReplicationSiteLink -Identity DEFAULTIPSITELINK -Cost 10 -Verbose

Write-Host ""
Write-Host ":: Let's also change the ReplicationFrequencyInMinutes to 15..." -ForegroundColor Yellow
Set-ADReplicationSiteLink -Identity DEFAULTIPSITELINK -ReplicationFrequencyInMinutes 15 -Verbose

Write-Host ""
Write-Host ""





#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                  " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- LETS CREATE/UPDATE SOME AD SUBNETS ----                     " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                  " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""


#
# Let's add/update our own IP range: we can add a /24 for our subnet...
# (We do this first so we don't accidentally add a conflict in the next section)
#
# We also should associate our subnet with the local AD site.
#
#
$MyADSite = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name

ForEach ($ipaddress in ((Get-NetIPAddress -AddressFamily IPv4).IPAddress))
{
    #Write-Host "$ipaddress"
    If ($ipaddress.Contains('192.168.'))
    {
        $ADsubnet = $ipaddress.Substring(0,($ipaddress.LastIndexOf('.'))) + '.0/24'
        
        Write-Host ""
        Write-Host "::   Add or update my subnet '$ADsubnet'..." -ForegroundColor Yellow
        If ($subnetObj = Get-ADReplicationSubnet -Filter "Name -like ""$ADsubnet""")
        {
            Write-Host ""
            Write-Host "::      Updating my IP subnet '$ADsubnet' to AD Sites and Services..." -ForegroundColor Yellow -BackgroundColor DarkMagenta
            If ($MyADSite)
            {
                Write-Host "::          (Associating with AD site '$MyADSite')                              " -ForegroundColor Yellow -BackgroundColor DarkMagenta
                Set-ADReplicationSubnet -Identity "$ADsubnet" -Site $MyADSite -Description "Primary Lab Subnet for Demos" -Location "SemperisLabs-USA-AZ" -Verbose
            }
            Else
            {
                Set-ADReplicationSubnet -Identity "$ADsubnet" -Description "Primary Lab Subnet for Demos" -Location "SemperisLabs-USA-AZ" -Verbose
            }
        }
        Else
        {
            Write-Host ""
            Write-Host "::      Adding my IP subnet '$ADsubnet' to AD Sites and Services..." -ForegroundColor Yellow -BackgroundColor DarkGreen
            If ($MyADSite)
            {
                Write-Host "::          (Associating with AD site '$MyADSite')                            " -ForegroundColor Yellow -BackgroundColor DarkGreen
                New-ADReplicationSubnet -Name "$ADsubnet" -Site $MyADSite -Description "Primary Lab Subnet for Demos" -Location "SemperisLabs-USA-AZ" -Verbose
            }
            Else
            {
                New-ADReplicationSubnet -Name "$ADsubnet" -Description "Primary Lab Subnet for Demos" -Location "SemperisLabs-USA-AZ" -Verbose
            }

        }
    }
}

Write-Host ""
Write-Host ""

#
# Construct a dictionary table for subnets where the value is a multi-value array.
#
# table = key,value    (where 'value' is an array of items with subnet properties)
#
$ADsubnets = @{}
$ADsubnets.Add("10.0.0.0/8",@('Lab-USA-All','Primary Lab Infrastructure Network'))
$ADsubnets.Add("172.16.32.0/20",@('Lab-USA-CA','Special demo lab subnet'))
$ADsubnets.Add("10.222.0.0/16",@('Lab-USA-East','Special Devices Infrastructure Network'))
$ADsubnets.Add("10.111.0.0/16",@('Lab-EMEA-ES','test subnet 0002'))
$ADsubnets.Add("10.112.0.0/16",@('Lab-EMEA-ES','test subnet 0002'))
$ADsubnets.Add("111.2.5.0/24",@('USA-TX-Labs','Lab subnet in TX'))
$ADsubnets.Add("111.2.6.0/24",@('USA-TX-Dallas-Labs','Lab subnet in Dallas,TX'))
$ADsubnets.Add("192.168.0.0/16",@('Lab-USA-TX','Primary Demo Lab Infrastructure Network'))
$ADsubnets.Add("192.168.57.0/24",@('Lab-USA-AZ','Special DMZ network'))

Write-Host ""
$ADsubnets
#$ADsubnets["172.16.32.0/20"].GetValue(0)
#$ADsubnets["172.16.32.0/20"].GetValue(1)
Write-Host ""
Write-Host ""


ForEach($ADsubnet in $ADsubnets.Keys)
{
    Write-Host "::   SUBNET $ADsubnet" -ForegroundColor Yellow    # show subnet which is used as the dictionary key
    $ADsubnets[$ADsubnet][1]          # show array value 0, which is the Location value
    $ADsubnets[$ADsubnet][0]          # show array value 1, which is the Description


    If ($subnetObj = Get-ADReplicationSubnet -Filter "Name -like ""$ADsubnet""")
    {
        Write-Host "::       Subnet '$ADsubnet' already exists!    Updating..." -ForegroundColor Yellow -BackgroundColor DarkMagenta
        Set-ADReplicationSubnet -Identity $ADsubnet -Description $ADsubnets[$ADsubnet][0] -Location $ADsubnets[$ADsubnet][1] -Verbose
    }
    Else
    {
        Write-Host "::       Subnet '$ADsubnet' does NOT exist!    Creating subnet..." -ForegroundColor Yellow -BackgroundColor DarkGreen
        New-ADReplicationSubnet -Name "$ADsubnet" -Description $ADsubnets[$ADsubnet][0] -Location $ADsubnets[$ADsubnet][1] -Verbose
    }
   
    Write-Host ""
}

Write-Host ""
Write-Host ""
Write-Host ""









#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                               " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- REPLICATION SUBNET STUFF: ADD ACTIVE DORECTORY SUBNETS ----              " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::         (TO BE DELETED LATER IN SCRIPT)                                       " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                               " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
#
$objADSubnet1 = '111.111.4.0/24'
$objADSubnet2 = '111.111.5.0/24'
#
# Have to use Try-Catch due to unblockable error messages when subnet does not exist.
#
Try
{
    Get-ADReplicationSubnet -Identity $objADSubnet1 -ErrorAction Ignore
}
Catch
{
    New-ADReplicationSubnet -Name $objADSubnet1 -Description 'test subnet added via script' -Location 'USA-TX-Labs' -Site $MyADSite -Verbose
}
Try
{
    Get-ADReplicationSubnet -Identity $objADSubnet2 -ErrorAction SilentlyContinue
}
Catch
{
    New-ADReplicationSubnet -Name $objADSubnet2 -Description 'test subnet added via script' -Location 'USA-TX-Labs' -Site $MyADSite -ErrorAction Ignore -Verbose
}








#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                     " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- OU STUFF: CREATE LAB OU OBJECTS (CREATE IF MISSING!!!) ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                     " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
If (!(Get-ADOrganizationalUnit -LDAPFilter '(OU=DeleteMe OU)'))
{
    Write-Host "::    -- Creating OU 'DeleteMe OU'..." -ForegroundColor Cyan
    New-ADOrganizationalUnit -Path $DomainDN -Name 'DeleteMe OU' -DisplayName 'DeleteMe OU' -Description 'OU that gets DELETED by someone' -ErrorAction SilentlyContinue -Verbose
}
If (!(Get-ADOrganizationalUnit -LDAPFilter '(OU=Bad OU)'))
{
    Write-Host "::    -- Creating OU 'Bad OU'..." -ForegroundColor Cyan
    New-ADOrganizationalUnit -Path $DomainDN -Name 'Bad OU' -DisplayName 'Bad OU' -Description 'OU that gets modified by someone' -ErrorAction SilentlyContinue -Verbose
}
If (!(Get-ADOrganizationalUnit -LDAPFilter '(OU=Lab Users)'))
{
    Write-Host "::    -- Creating OU 'Lab Users'..." -ForegroundColor Cyan
    New-ADOrganizationalUnit -Path $DomainDN -Name 'Lab Users' -DisplayName 'Lab Users' -Description 'OU for all lab users!!' -ErrorAction SilentlyContinue -Verbose
}

$UsersOUName01 = 'Dept101'   # '101' is a prime number
If (!(Get-ADOrganizationalUnit -LDAPFilter "(OU=$UsersOUName01)"))
{
    Write-Host "::    -- Creating OU '$UsersOUName01'..." -ForegroundColor Cyan
    New-ADOrganizationalUnit -Path "OU=Lab Users,$DomainDN" -Name $UsersOUName01 -DisplayName $UsersOUName01 -Description "OU for users in $UsersOUName01" -ErrorAction SilentlyContinue -Verbose
}
$UsersOUName02 = 'Dept999'   # '999' is a special number... 999 -> 9+9+9=27 -> 2+7=9
If (!(Get-ADOrganizationalUnit -LDAPFilter "(OU=$UsersOUName02)"))
{
    Write-Host "::    -- Creating OU '$UsersOUName02'..." -ForegroundColor Cyan
    New-ADOrganizationalUnit -Path "OU=Lab Users,$DomainDN" -Name $UsersOUName02 -DisplayName $UsersOUName02 -Description "OU for users in $UsersOUName02" -ErrorAction SilentlyContinue -Verbose
}

If (!(Get-ADOrganizationalUnit -LDAPFilter '(OU=Lab Admins)'))
{
    Write-Host "::    -- Creating OU 'Lab Admins'..." -ForegroundColor Cyan
    New-ADOrganizationalUnit -Path $DomainDN -Name 'Lab Admins' -DisplayName 'Lab Admins' -Description 'OU for all lab admins!!' -ErrorAction SilentlyContinue -Verbose
}

If (!(Get-ADOrganizationalUnit -LDAPFilter '(OU=Tier 0)'))
{
    Write-Host "::    -- Creating OU 'Tier 0'..." -ForegroundColor Cyan
    New-ADOrganizationalUnit -Path "OU=Lab Admins,$DomainDN" -Name 'Tier 0' -DisplayName 'Tier 0' -Description 'OU for all TIER 0 lab admins!!' -ErrorAction SilentlyContinue -Verbose
}
If (!(Get-ADOrganizationalUnit -LDAPFilter '(OU=Tier 1)'))
{
    Write-Host "::    -- Creating OU 'Tier 1'..." -ForegroundColor Cyan
    New-ADOrganizationalUnit -Path "OU=Lab Admins,$DomainDN" -Name 'Tier 1' -DisplayName 'Tier 1' -Description 'OU for all TIER 1 lab admins!!' -ErrorAction SilentlyContinue -Verbose
}
If (!(Get-ADOrganizationalUnit -LDAPFilter '(OU=Tier 2)'))
{
    Write-Host "::    -- Creating OU 'Tier 2'..." -ForegroundColor Cyan
    New-ADOrganizationalUnit -Path "OU=Lab Admins,$DomainDN" -Name 'Tier 2' -DisplayName 'Tier 2' -Description 'OU for all TIER 2 lab admins!!' -ErrorAction SilentlyContinue -Verbose
}





#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                   " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- DEFAULT DOMAIN POLICY SETTINGS ----          " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                   " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
Write-Host ":: --------------------------------------------------------------------" -ForegroundColor DarkCyan -BackgroundColor Yellow
Write-Host ":: IMPORTANT!!! CURRENT ACCOUNT MUST BE MEMBER OF ENTERPRISE ADMINS!!!!" -ForegroundColor DarkCyan -BackgroundColor Yellow
Write-Host ":: --------------------------------------------------------------------" -ForegroundColor DarkCyan -BackgroundColor Yellow
Write-Host ""
Write-Host ""
Write-Host ":: Setting Default Domain Policy values for passwords before creating/updating users" -ForegroundColor Yellow
Write-Host ""
Write-Host ""
Write-Host ":: Get the 'Default Domain Policy' GPO info..." -ForegroundColor Yellow
Get-ADDefaultDomainPasswordPolicy
Start-Sleep 3
#
# From Registry....
# [System Access]
# MinimumPasswordAge = 0
# MaximumPasswordAge = 42
# MinimumPasswordLength = 0
# PasswordComplexity = 1
# PasswordHistorySize = 0
# LockoutBadCount = 777        <<<--- what is this registry setting mapped to the GPO????
# ResetLockoutCount = 1
# LockoutDuration = 1
#
Write-Host ":: Set LockoutThreshold value to '11' in 'Default Domain Policy'..." -ForegroundColor Yellow
###Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 15 -Identity fbef721f-354e-4a73-981c-332be1fe67ae
Set-ADDefaultDomainPasswordPolicy -Identity $DomainDNSRoot -LockoutThreshold 11 -Verbose
Set-ADDefaultDomainPasswordPolicy -Identity $DomainDNSRoot -LockoutDuration 0.00:03:00.0 -LockoutObservationWindow 0.00:03:00.0 -Verbose  # D.H:M:S.F
Set-ADDefaultDomainPasswordPolicy -Identity $DomainDNSRoot -MinPasswordAge 0 -MinPasswordLength 8 -Verbose

Write-Host ""
Write-Host ":: Get the modified 'Default Domain Policy' GPO info..." -ForegroundColor Yellow
Get-ADDefaultDomainPasswordPolicy
Start-Sleep 3
Write-Host ""
Write-Host ""

Write-Host ":: Force replication after 5 second pause..." -ForegroundColor Yellow
Start-Sleep 5
If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan} 
If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}
Start-Sleep 5

Write-Host ""
Write-Host ""
Write-Host ":: Get the 'Default Domain Policy' GPO info..." -ForegroundColor Yellow
Get-ADDefaultDomainPasswordPolicy
Start-Sleep 10

# NOTE: For some reason, making further changes to LockoutThreshold in the GPO will 
# not be captured if done right here. So, I moved a copy of the following steps to 
# the end of the script to give more time for the changes to "settle".

#Write-Host ":: Set LockoutThreshold value to '888' in 'Default Domain Policy'..." -ForegroundColor Yellow
#Set-ADDefaultDomainPasswordPolicy -Identity $DomainDNSRoot -LockoutThreshold 888
#
#Write-Host ":: Get the 'Default Domain Policy' GPO info..." -ForegroundColor Yellow
#Get-ADDefaultDomainPasswordPolicy







#--------------------------------------------------------------------------------
# 
# DEFAULT DEMO USER PASSWORD
#
# Several demo user accounts are created by this script. When the user accounts
# are created, the command prompts for a password. 
#
# We can prompt for a password one time to use the same password for each user
# account creation, or the user can elect to be prompted for each password.
# 
# If the user doesn't respond, the default is to use 'Password1' as the default 
# password to apply to any new demo accounts created.
#
# This allows the creation process to be more automated in not prompting 6 or 7
# times for passwords.
#
# (The section that creates bulk generic users doesn't use this default password,
# but instead uses a randomized password.)
#

Write-Host "`n`n"
Write-Host "`n`n"
Write-Host "::                                                " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: Password to use for new demo user accounts     " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ":: This script creates a few demo user accounts." -ForegroundColor Yellow
Write-Host ":: For ease of initial setup, script will use the same password for each new demo user account." -ForegroundColor Yellow
Write-Host ""

$DemoUserPassword = $Null
$Shell = New-Object -ComObject "WScript.Shell"
#intButton = objShell.Popup(strText,[nSecondsToWait],[strTitle],[nType]) 
$Button = $Shell.Popup("Script can use the same password for any new demo user accounts created.`nYou can say 'No' here and you will be prompted for any new demo user accounts created.`n`nDo you want to use 'Password1' for all newly create demo accounts?`n`n`n(Timeout default is YES)", 8, "Default Generic User Count Value", 4+32)
#$Button  # 6=Yes   7=No   -1=no response
Write-Host ""
If ($Button -eq 6 -or $Button -eq -1)
    {
    # YES or No Response
    $DemoUserPassword = ConvertTo-SecureString 'Password1' -AsPlainText -Force
    Write-Host ""
    Write-Host "                                                                        " -ForegroundColor Yellow -BackgroundColor White
    Write-Host " -- Script will use same password for each new demo account created!    " -ForegroundColor Black -BackgroundColor White
    Write-Host "                                                                        " -ForegroundColor Yellow -BackgroundColor White
    Start-Sleep 2
    }
Else
    {
    # NO 
    #Prompt user for each new demo account created. (Not inlcuding the generic user accounts.)
    $DemoUserPassword = $Null
    Write-Host ""
    Write-Host "                                                                            " -ForegroundColor Red -BackgroundColor White
    Write-Host "  -- NO means each new demo account created will prompt for a password.     " -ForegroundColor Red -BackgroundColor White
    Write-Host "                                                                            " -ForegroundColor Red -BackgroundColor White
    Write-Host ""
    Write-Host "  -- No big deal... You will be prompted for a password for each new demo user account." -ForegroundColor Yellow
    Write-Host "`n`n"
    Start-Sleep 4
    }

#
#--------------------------------------------------------------------------------







#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                                      " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- USER STUFF: CREATE LAB USERS FOR CHANGE ACTIVITY (CREATE IF MISSING!!!) ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                                      " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

# My demo Tier 0 account for DSP console logon
$UserObj = $null
If (!($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($AdminUser0.Name)))" -Properties * -ErrorAction SilentlyContinue))
{
    Write-Host "::    -- Creating user '$($AdminUser0.Name)' for DSP console logons in demos..." -ForegroundColor Cyan
    If ($DemoUserPassword)
    {
    # $DemoUserPassword has a value
    New-ADUser -Name "$($AdminUser0.Name)" -SamAccountName $($AdminUser0.SamAccountName) -GivenName "$($AdminUser0.GivenName)" -Surname "$($AdminUser0.Surname)" -DisplayName "$($AdminUser0.DisplayName)" -Department "$($AdminUser0.Department)" -Description "$($AdminUser0.Description)" -Accountpassword $DemoUserPassword -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -PasswordNeverExpires $True -OtherAttributes @{'title'="$($AdminUser0.Title)";'mail'="$($AdminUser0.Mail)"} -Path "OU=Tier 0,OU=Lab Admins,$DomainDN" -Verbose
    }
    Else
    {
    # prompt for password
    New-ADUser -Name "$($AdminUser0.Name)" -SamAccountName $($AdminUser0.SamAccountName) -GivenName "$($AdminUser0.GivenName)" -Surname "$($AdminUser0.Surname)" -DisplayName "$($AdminUser0.DisplayName)" -Department "$($AdminUser0.Department)" -Description "$($AdminUser0.Description)" -Accountpassword (Read-Host -AsSecureString "AccountPassword") -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -PasswordNeverExpires $True -OtherAttributes @{'title'="$($AdminUser0.Title)";'mail'="$($AdminUser0.Mail)"} -Path "OU=Tier 0,OU=Lab Admins,$DomainDN" -Verbose
    }
    Write-Host ""
}
Else
{
    Write-Host "::    -- Updating user '$($AdminUser0.Name)' for DSP console logons in demos..." -ForegroundColor Cyan
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -City "$($AdminUser0.City)" -Company "$($AdminUser0.Company)" -Department "$($AdminUser0.Department)" -Description "$($AdminUser0.Description)" -Division "$($AdminUser0.Division)" -EmailAddress "$($AdminUser0.Mail)" -EmployeeID "$($AdminUser0.EmployeeID)" -GivenName "$($AdminUser0.GivenName)" -Initials "$($AdminUser0.Initials)" -Fax "$($AdminUser0.FAX)" -OfficePhone "$($AdminUser0.TelephoneNumber)" -Surname "$($AdminUser0.Surname)" -Title "$($AdminUser0.Title)" -Verbose
    Write-Host ""
    # Trigger userAccountControl attribute changes...
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $True -Verbose
    Start-Sleep 2
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $False -PasswordNeverExpires $True -Verbose
    Write-Host ""
}



# My demo Tier 2 account for DSP console logon
$UserObj = $null
If (!($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($AdminUser2.Name)))" -Properties * -ErrorAction SilentlyContinue))
{
    Write-Host "::    -- Creating user '$($AdminUser2.Name)' for DSP console logons in demos..." -ForegroundColor Cyan
    If ($DemoUserPassword)
    {
    # $DemoUserPassword has a value
    New-ADUser -Name "$($AdminUser2.Name)" -SamAccountName $($AdminUser2.SamAccountName) -GivenName "$($AdminUser2.GivenName)" -Surname "$($AdminUser2.Surname)" -DisplayName "$($AdminUser2.DisplayName)" -Department "$($AdminUser2.Department)" -Description "$($AdminUser2.Description)" -Accountpassword $DemoUserPassword -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -PasswordNeverExpires $True -OtherAttributes @{'title'="$($AdminUser2.Title)";'mail'="$($AdminUser2.Mail)"} -Path "OU=Tier 2,OU=Lab Admins,$DomainDN" -Verbose
    }
    Else
    {
    # prompt for password
    New-ADUser -Name "$($AdminUser2.Name)" -SamAccountName $($AdminUser2.SamAccountName) -GivenName "$($AdminUser2.GivenName)" -Surname "$($AdminUser2.Surname)" -DisplayName "$($AdminUser2.DisplayName)" -Department "$($AdminUser2.Department)" -Description "$($AdminUser2.Description)" -Accountpassword (Read-Host -AsSecureString "AccountPassword") -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -PasswordNeverExpires $True -OtherAttributes @{'title'="$($AdminUser2.Title)";'mail'="$($AdminUser2.Mail)"} -Path "OU=Tier 2,OU=Lab Admins,$DomainDN" -Verbose
    }
    Write-Host ""
}
Else
{
    Write-Host "::    -- Updating user '$($AdminUser2.Name)' for DSP console logons in demos..." -ForegroundColor Cyan
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -City "$($AdminUser2.City)" -Company "$($AdminUser2.Company)" -Department "$($AdminUser2.Department)" -Description "$($AdminUser2.Description)" -Division "$($AdminUser2.Division)" -EmailAddress "$($AdminUser2.Mail)" -EmployeeID "$($AdminUser2.EmployeeID)" -GivenName "$($AdminUser2.GivenName)" -Initials "$($AdminUser2.Initials)" -Fax "$($AdminUser2.FAX)" -OfficePhone "$($AdminUser2.TelephoneNumber)" -Surname "$($AdminUser2.Surname)" -Title "$($AdminUser2.Title)" -Verbose
    Write-Host ""
    # Trigger userAccountControl attribute changes...
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $True -Verbose
    Start-Sleep 2
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $False -PasswordNeverExpires $True -Verbose
    Write-Host ""
}



# ---------
# preferred demo user account, DemoUser1
$UserObj = $null
If (!($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($DemoUser1.SamAccountName)))" -Properties * -ErrorAction SilentlyContinue))
{
    Write-Host "::    -- Creating user '$($DemoUser1.Name)' for DSP demos (showing user attribute changes)..." -ForegroundColor Cyan
    If ($DemoUserPassword)
    {
    # $DemoUserPassword has a value
    New-ADUser -Name "$($DemoUser1.Name)" -SamAccountName $($DemoUser1.SamAccountName) -DisplayName "$($DemoUser1.DisplayName)" -GivenName "$($DemoUser1.GivenName)" -Surname "$($DemoUser1.Surname)" -Department "$($DemoUser1.Department)" -Description "$($DemoUser1.Description)" -Accountpassword $DemoUserPassword -Enabled $true -PasswordNeverExpires $True -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($DemoUser1.Title)";'mail'="$($DemoUser1.Mail)"} -Path "$($DemoUser1.Path)" -Verbose
    }
    Else
    {
    # prompt for password
    New-ADUser -Name "$($DemoUser1.Name)" -SamAccountName $($DemoUser1.SamAccountName) -DisplayName "$($DemoUser1.DisplayName)" -GivenName "$($DemoUser1.GivenName)" -Surname "$($DemoUser1.Surname)" -Department "$($DemoUser1.Department)" -Description "$($DemoUser1.Description)" -Accountpassword (Read-Host -AsSecureString "AccountPassword") -PasswordNeverExpires $True -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($DemoUser1.Title)";'mail'="$($DemoUser1.Mail)"} -Path "$($DemoUser1.Path)" -Verbose
    }

    # More attributes will be set for this user later in this script.
    Write-Host ""
}
Else
{
    Write-Host "::    -- Updating user '$($DemoUser1.Name)' for account manipulation in demos..." -ForegroundColor Cyan
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -City "$($DemoUser1.City)" -Company "$($DemoUser1.Company)" -Department "$($DemoUser1.Department)" -Description "$($DemoUser1.Description)" -Division "$($DemoUser1.Division)" -EmailAddress "$($DemoUser1.Mail)" -EmployeeID "$($DemoUser1.EmployeeID)" -GivenName "$($DemoUser1.GivenName)" -Initials "$($DemoUser1.Initials)" -Fax "$($DemoUser1.FAX)" -OfficePhone "$($DemoUser1.TelephoneNumber)" -Surname "$($DemoUser1.Surname)" -Title "$($DemoUser1.Title)" -Verbose
    Write-Host ""
    # Trigger userAccountControl attribute changes...
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNeverExpires $True -PasswordNotRequired $True -Verbose
    Start-Sleep 2
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $False -Verbose
    Write-Host ""
}



# ---------
# Secondary demo user account, DemoUser2
$UserObj = $null
If (!($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($DemoUser2.SamAccountName)))" -Properties * -ErrorAction SilentlyContinue))
{
    Write-Host "::    -- Creating user '$($DemoUser2.Name)' for DSP demos (showing user attribute changes)..." -ForegroundColor Cyan
    If ($DemoUserPassword)
    {
    # $DemoUserPassword has a value
    New-ADUser -Name "$($DemoUser2.Name)" -SamAccountName $($DemoUser2.SamAccountName) -DisplayName "$($DemoUser2.DisplayName)" -GivenName "$($DemoUser2.GivenName)" -Surname "$($DemoUser2.Surname)" -Department "$($DemoUser2.Department)" -Description "$($DemoUser2.Description)" -Accountpassword $DemoUserPassword -PasswordNeverExpires $True -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($DemoUser2.Title)";'mail'="$($DemoUser2.Mail)"} -Path "$($DemoUser2.Path)" -Verbose
    }
    Else
    {
    # prompt for password
    New-ADUser -Name "$($DemoUser2.Name)" -SamAccountName $($DemoUser2.SamAccountName) -DisplayName "$($DemoUser2.DisplayName)" -GivenName "$($DemoUser2.GivenName)" -Surname "$($DemoUser2.Surname)" -Department "$($DemoUser2.Department)" -Description "$($DemoUser2.Description)" -Accountpassword (Read-Host -AsSecureString "AccountPassword") -PasswordNeverExpires $True -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($DemoUser2.Title)";'mail'="$($DemoUser2.Mail)"} -Path "$($DemoUser2.Path)" -Verbose
    }

    # More attributes will be set for this user later in this script.
    Write-Host ""
}
Else
{
    Write-Host "::    -- Updating user '$($DemoUser2.Name)' for account manipulation in demos..." -ForegroundColor Cyan
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -City "$($DemoUser2.City)" -Company "$($DemoUser2.Company)" -Department "$($DemoUser2.Department)" -Description "$($DemoUser2.Description)" -Division "$($DemoUser2.Division)" -EmailAddress "$($DemoUser2.Mail)" -EmployeeID "$($DemoUser2.EmployeeID)" -GivenName "$($DemoUser2.GivenName)" -Initials "$($DemoUser2.Initials)" -Fax "$($DemoUser2.FAX)" -OfficePhone "$($DemoUser2.TelephoneNumber)" -Surname "$($DemoUser2.Surname)" -Title "$($DemoUser2.Title)" -Verbose
    Write-Host ""
    # Trigger userAccountControl attribute changes...
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNeverExpires $True -PasswordNotRequired $True -Verbose
    Start-Sleep 2
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $False -Verbose
    Write-Host ""
}



# ---------
# Tertiary demo user account, DemoUser3
$UserObj = $null
If (!($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($DemoUser3.SamAccountName)))" -Properties * -ErrorAction SilentlyContinue))
{
    Write-Host "::    -- Creating user '$($DemoUser3.Name)' for DSP demos (showing user attribute changes)..." -ForegroundColor Cyan
    If ($DemoUserPassword)
    {
    # $DemoUserPassword has a value
    New-ADUser -Name "$($DemoUser3.Name)" -SamAccountName $($DemoUser3.SamAccountName) -DisplayName "$($DemoUser3.DisplayName)" -GivenName "$($DemoUser3.GivenName)" -Surname "$($DemoUser3.Surname)" -Department "$($DemoUser3.Department)" -Description "$($DemoUser3.Description)" -Accountpassword $DemoUserPassword -PasswordNeverExpires $True -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($DemoUser3.Title)";'mail'="$($DemoUser3.Mail)"} -Path "$($DemoUser3.Path)" -Verbose
    }
    Else
    {
    # prompt for password
    New-ADUser -Name "$($DemoUser3.Name)" -SamAccountName $($DemoUser3.SamAccountName) -DisplayName "$($DemoUser3.DisplayName)" -GivenName "$($DemoUser3.GivenName)" -Surname "$($DemoUser3.Surname)" -Department "$($DemoUser3.Department)" -Description "$($DemoUser3.Description)" -Accountpassword (Read-Host -AsSecureString "AccountPassword") -PasswordNeverExpires $True -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($DemoUser3.Title)";'mail'="$($DemoUser3.Mail)"} -Path "$($DemoUser3.Path)" -Verbose
    }

    # More attributes will be set for this user later in this script.
    Write-Host ""
}
Else
{
    # NOTE: We have a later section that changes the 'Title' attribute in order to 
    # trigger an auto-undo rule for this user, so HERE we need to set the 'Title' 
    # attribute seperately, ONLY if it is different than the desired value at this
    # point, due to an auto-undo bug that sis surfaced when an attribute is changed
    # to the same value, which is effectively no change, so has no replication event
    # to undo. See the section where 'Title' is changed to "CEO" later in this script.

    Write-Host "::    -- Updating user '$($DemoUser3.Name)' for account manipulation in demos..." -ForegroundColor Cyan
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -PasswordNeverExpires $True -City "$($DemoUser3.City)" -Company "$($DemoUser3.Company)" -Department "$($DemoUser3.Department)" -Description "$($DemoUser3.Description)" -Division "$($DemoUser3.Division)" -EmailAddress "$($DemoUser3.Mail)" -EmployeeID "$($DemoUser3.EmployeeID)" -GivenName "$($DemoUser3.GivenName)" -Initials "$($DemoUser3.Initials)" -Fax "$($DemoUser3.FAX)" -OfficePhone "$($DemoUser3.TelephoneNumber)" -Surname "$($DemoUser3.Surname)" -Verbose
    If ($(Get-ADUser -Identity "$($UserObj.DistinguishedName)" -Properties Title).Title -ine "$($UserObj.Title)")
    {
        Write-Host "::     -- Updating 'Title' attribute to '$($DemoUser3.Title)'..." -ForegroundColor Yellow
        Set-ADUser -Identity "$($UserObj.DistinguishedName)" -PasswordNeverExpires $True -Title "$($DemoUser3.Title)" -Verbose
    }
    Write-Host ""
    # Trigger userAccountControl attribute changes...
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNeverExpires $True -PasswordNotRequired $True -Verbose
    Start-Sleep 2
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $False -Verbose
    Write-Host ""
}

#
# Set user manager
#
$UserManagerDN = $null
If (($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($DemoUser3.SamAccountName)))" -Properties * -ErrorAction SilentlyContinue))
{
    Write-Host ""
    Write-Host ":: Using DemoUser5 ('$($DemoUser3.DisplayName)') as the manager for some of the following user accounts."
    $UserManagerDN = $UserObj.DistinguishedName
    Write-Host ""
}





# ---------
# Fourth (quaternary???) demo user account, DemoUser4
$UserObj = $null
If (!($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($DemoUser4.SamAccountName)))" -Properties * -ErrorAction SilentlyContinue))
{
    Write-Host "::    -- Creating user '$($DemoUser4.Name)' for DSP demos (showing user attribute changes)..." -ForegroundColor Cyan
    If ($DemoUserPassword)
    {
    # $DemoUserPassword has a value
    New-ADUser -Name "$($DemoUser4.Name)" -SamAccountName $($DemoUser4.SamAccountName) -DisplayName "$($DemoUser4.DisplayName)" -GivenName "$($DemoUser4.GivenName)" -Surname "$($DemoUser4.Surname)" -Department "$($DemoUser4.Department)" -Description "$($DemoUser4.Description)" -Accountpassword $DemoUserPassword -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($DemoUser4.Title)";'mail'="$($DemoUser4.Mail)"} -Path "$($DemoUser4.Path)" -Verbose
    }
    Else
    {
    # prompt for password
    New-ADUser -Name "$($DemoUser4.Name)" -SamAccountName $($DemoUser4.SamAccountName) -DisplayName "$($DemoUser4.DisplayName)" -GivenName "$($DemoUser4.GivenName)" -Surname "$($DemoUser4.Surname)" -Department "$($DemoUser4.Department)" -Description "$($DemoUser4.Description)" -Accountpassword (Read-Host -AsSecureString "AccountPassword") -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($DemoUser4.Title)";'mail'="$($DemoUser4.Mail)"} -Path "$($DemoUser4.Path)" -Verbose
    }

    # More attributes will be set for this user later in this script.
    Write-Host ""
}
Else
{
    Write-Host "::    -- Updating user '$($DemoUser4.Name)' for account manipulation in demos..." -ForegroundColor Cyan
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -City "$($DemoUser4.City)" -Company "$($DemoUser4.Company)" -Department "$($DemoUser4.Department)" -Description "$($DemoUser4.Description)" -Division "$($DemoUser4.Division)" -EmailAddress "$($DemoUser4.Mail)" -EmployeeID "$($DemoUser4.EmployeeID)" -GivenName "$($DemoUser4.GivenName)" -Initials "$($DemoUser4.Initials)" -Fax "$($DemoUser4.FAX)" -OfficePhone "$($DemoUser4.TelephoneNumber)" -Surname "$($DemoUser4.Surname)" -Title "$($DemoUser4.Title)" -Verbose
    Write-Host ""
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Manager $UserManagerDN -Verbose

    # Trigger userAccountControl attribute changes...
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $True -Verbose
    Start-Sleep 2
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $False -Verbose
    Write-Host ""
}




 
# ---------
# operations admin used for making some changes to show different "changed by" values  $OpsAdmin1
$UserObj = $null
If (!($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($OpsAdmin1.SamAccountName)))" -Properties * -ErrorAction SilentlyContinue))
{
    Write-Host "::    -- Creating user '$($OpsAdmin1.Name)'..." -ForegroundColor Cyan
    If ($DemoUserPassword)
    {
    # $DemoUserPassword has a value
    New-ADUser -Name "$($OpsAdmin1.Name)" -SamAccountName "$($OpsAdmin1.SamAccountName)" -GivenName "$($OpsAdmin1.GivenName)" -Surname "$($OpsAdmin1.Surname)" -Department "$($OpsAdmin1.Department)" -Description "$($OpsAdmin1.Description)" -Accountpassword $DemoUserPassword -PasswordNeverExpires $True -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -PasswordNeverExpires $True -OtherAttributes @{'title'="$($OpsAdmin1.Title)";'mail'="$($OpsAdmin1.Mail)"} -Path "$($OpsAdmin1.Path)" -Verbose
    }
    Else
    {
    # prompt for password
    New-ADUser -Name "$($OpsAdmin1.Name)" -SamAccountName "$($OpsAdmin1.SamAccountName)" -GivenName "$($OpsAdmin1.GivenName)" -Surname "$($OpsAdmin1.Surname)" -Department "$($OpsAdmin1.Department)" -Description "$($OpsAdmin1.Description)" -Accountpassword (Read-Host -AsSecureString "AccountPassword") -PasswordNeverExpires $True -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -PasswordNeverExpires $True -OtherAttributes @{'title'="$($OpsAdmin1.Title)";'mail'="$($OpsAdmin1.Mail)"} -Path "$($OpsAdmin1.Path)" -Verbose
    }

    Write-Host ""
}
Else
{
    Write-Host "::    -- Updating user '$($OpsAdmin1.Name)' for DSP console logons in demos..." -ForegroundColor Cyan
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -PasswordNeverExpires $True -City "$($OpsAdmin1.City)" -Company "$($OpsAdmin1.Company)" -Department "$($OpsAdmin1.Department)" -Description "$($OpsAdmin1.Description)" -Division "$($OpsAdmin1.Division)" -EmailAddress "$($OpsAdmin1.Mail)" -EmployeeID "$($OpsAdmin1.EmployeeID)" -GivenName "$($OpsAdmin1.GivenName)" -Initials "$($OpsAdmin1.Initials)" -Fax "$($OpsAdmin1.FAX)" -OfficePhone "$($OpsAdmin1.TelephoneNumber)" -Surname "$($OpsAdmin1.Surname)" -Title "$($OpsAdmin1.Title)" -Verbose
    Write-Host ""
    # Trigger userAccountControl attribute changes...
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNeverExpires $True -PasswordNotRequired $True -Verbose
    Start-Sleep 2
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $False -PasswordNeverExpires $True -Verbose
    Write-Host ""
}




# ---------
# generic admin account to use for group memberships and changes
$UserObj = $null
If (!($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($GenericAdmin1.SamAccountName)))" -Properties * -ErrorAction SilentlyContinue))
{
    Write-Host "::    -- Creating user '$($GenericAdmin1.Name)'..." -ForegroundColor Cyan
    If ($DemoUserPassword)
    {
    # $DemoUserPassword has a value
    New-ADUser -Name "$($GenericAdmin1.Name)" -SamAccountName "$($GenericAdmin1.SamAccountName)" -GivenName "$($GenericAdmin1.GivenName)" -Surname "$($GenericAdmin1.Surname)" -Department "$($GenericAdmin1.Department)" -Description "$($GenericAdmin1.Description)" -Accountpassword $DemoUserPassword -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($GenericAdmin1.Title)";'mail'="$($GenericAdmin1.Mail)"} -Path "$($GenericAdmin1.Path)" -Verbose
    }
    Else
    {
    # prompt for password
    New-ADUser -Name "$($GenericAdmin1.Name)" -SamAccountName "$($GenericAdmin1.SamAccountName)" -GivenName "$($GenericAdmin1.GivenName)" -Surname "$($GenericAdmin1.Surname)" -Department "$($GenericAdmin1.Department)" -Description "$($GenericAdmin1.Description)" -Accountpassword (Read-Host -AsSecureString "AccountPassword") -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($GenericAdmin1.Title)";'mail'="$($GenericAdmin1.Mail)"} -Path "$($GenericAdmin1.Path)" -Verbose
    }

    Write-Host ""
}
Else
{
    Write-Host "::    -- Updating user '$($GenericAdmin1.Name)' for DSP console logons in demos..." -ForegroundColor Cyan
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -City "$($GenericAdmin1.City)" -Company "$($GenericAdmin1.Company)" -Department "$($GenericAdmin1.Department)" -Description "$($GenericAdmin1.Description)" -Division "$($GenericAdmin1.Division)" -EmailAddress "$($GenericAdmin1.Mail)" -EmployeeID "$($GenericAdmin1.EmployeeID)" -GivenName "$($GenericAdmin1.GivenName)" -Initials "$($GenericAdmin1.Initials)" -Fax "$($GenericAdmin1.FAX)" -OfficePhone "$($GenericAdmin1.TelephoneNumber)" -Surname "$($GenericAdmin1.Surname)" -Title "$($GenericAdmin1.Title)" -Verbose
    Write-Host ""
    # Trigger userAccountControl attribute changes...
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $True -Verbose
    Start-Sleep 2
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $False -Verbose
    Write-Host ""
}



# ---------
# another generic admin account to use for group memberships and changes (and Mimikatz demos)
$UserObj = $null
If (!($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($GenericAdmin2.SamAccountName)))" -ErrorAction SilentlyContinue))
{
    Write-Host "::    -- Creating user '$($GenericAdmin2.Name)'..." -ForegroundColor Cyan
    If ($DemoUserPassword)
    {
    # $DemoUserPassword has a value
    New-ADUser -Name "$($GenericAdmin2.Name)" -SamAccountName "$($GenericAdmin2.SamAccountName)" -GivenName "$($GenericAdmin2.GivenName)" -Surname "$($GenericAdmin2.Surname)" -Department "$($GenericAdmin2.Department)" -Description "$($GenericAdmin2.Description)" -Accountpassword $DemoUserPassword -PasswordNeverExpires $True -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($GenericAdmin2.Title)";'mail'="$($GenericAdmin2.Mail)"} -Path "$($GenericAdmin2.Path)" -Verbose
    }
    Else
    {
    # prompt for password
    New-ADUser -Name "$($GenericAdmin2.Name)" -SamAccountName "$($GenericAdmin2.SamAccountName)" -GivenName "$($GenericAdmin2.GivenName)" -Surname "$($GenericAdmin2.Surname)" -Department "$($GenericAdmin2.Department)" -Description "$($GenericAdmin2.Description)" -Accountpassword (Read-Host -AsSecureString "AccountPassword") -PasswordNeverExpires $True -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($GenericAdmin2.Title)";'mail'="$($GenericAdmin2.Mail)"} -Path "$($GenericAdmin2.Path)" -Verbose
    }

    Write-Host ""
}
Else
{
    Write-Host "::    -- Updating user '$($GenericAdmin2.Name)' for DSP console logons in demos..." -ForegroundColor Cyan
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -City "$($GenericAdmin2.City)" -Company "$($GenericAdmin2.Company)" -Department "$($GenericAdmin2.Department)" -Description "$($GenericAdmin2.Description)" -Division "$($GenericAdmin2.Division)" -EmailAddress "$($GenericAdmin2.Mail)" -EmployeeID "$($GenericAdmin2.EmployeeID)" -GivenName "$($GenericAdmin2.GivenName)" -Initials "$($GenericAdmin2.Initials)" -Fax "$($GenericAdmin2.FAX)" -OfficePhone "$($GenericAdmin2.TelephoneNumber)" -Surname "$($GenericAdmin2.Surname)" -Title "$($GenericAdmin2.Title)" -Verbose
    Write-Host ""
    # Trigger userAccountControl attribute changes...
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNeverExpires $True -PasswordNotRequired $True -Verbose
    Start-Sleep 2
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $False -Verbose
    Write-Host ""
}



# ---------
# $AutomationAcct1
# automation account (for demos to show exclusion possibility for notification rules)
$UserObj = $null
If (!($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($AutomationAcct1.SamAccountName)))" -ErrorAction SilentlyContinue))
{
    Write-Host "::    -- Creating user '$($AutomationAcct1.Name)' for DSP demos showing off rule exceptions..." -ForegroundColor Cyan
    If ($DemoUserPassword)
    {
    # $DemoUserPassword has a value
    New-ADUser -Name "$($AutomationAcct1.Name)" -SamAccountName "$($AutomationAcct1.SamAccountName)" -Accountpassword $DemoUserPassword -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -Path "$($AutomationAcct1.Path)" -Verbose
    }
    Else
    {
    # prompt for password
    New-ADUser -Name "$($AutomationAcct1.Name)" -SamAccountName "$($AutomationAcct1.SamAccountName)" -Accountpassword (Read-Host -AsSecureString "AccountPassword") -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -Path "$($AutomationAcct1.Path)" -Verbose
    }

    Write-Host ""
    Start-Sleep 5
    Write-Host "::    -- Adding additional attribute data to user '$($AutomationAcct1.Name)'..." -ForegroundColor Cyan
    Set-ADUser -Identity "$($AutomationAcct1.Name)" -Replace $hashtable_update_AutomationAcct1 -Verbose
    Write-Host ""
}
Else
{
    Write-Host "::    -- Updating user '$($UserObj.Name)' for DSP demos showing off rule exceptions..." -ForegroundColor Cyan
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Replace $hashtable_update_AutomationAcct1 -Verbose
    Write-Host ""
    # Trigger userAccountControl attribute changes...
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $True -Verbose
    Start-Sleep 2
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $False -Verbose
    Write-Host ""
}



# ---------
# generic tier 1 monitoring account...
$UserObj = $null
If (!($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($MonitoringAcct1.SamAccountName)))" -ErrorAction SilentlyContinue))
{
    Write-Host "::    -- Creating user '$($MonitoringAcct1.Name)' as Tier 1 user in DSP demos..." -ForegroundColor Cyan
#    New-ADUser -Name "$($MonitoringAcct1.Name)" -SamAccountName "$($MonitoringAcct1.SamAccountName)" -GivenName "$($MonitoringAcct1.GivenName)" -Surname "$($MonitoringAcct1.Surname)" -Department "$($MonitoringAcct1.Department)" -Description "$($MonitoringAcct1.Description)" -Accountpassword (Read-Host -AsSecureString "AccountPassword") -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($MonitoringAcct1.Title)";'mail'="$($MonitoringAcct1.Mail)"} -Path "$($MonitoringAcct1.Path)" -Verbose
    If ($DemoUserPassword)
    {
    # $DemoUserPassword has a value
    New-ADUser @hashtable_create_MonitoringAcct1 -Accountpassword $DemoUserPassword -Verbose    # when "splatting", use the "@" instead of the "$" for the hashtable
    }
    Else
    {
    # prompt for password
    New-ADUser @hashtable_create_MonitoringAcct1 -Accountpassword (Read-Host -AsSecureString "AccountPassword") -Verbose    # when "splatting", use the "@" instead of the "$" for the hashtable
    }

    Write-Host ""
    Start-Sleep 5
    Write-Host "::    -- Adding additional attribute data to user '$($MonitoringAcct1.Name)'..." -ForegroundColor Cyan
    $UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($MonitoringAcct1.SamAccountName)))" -ErrorAction SilentlyContinue
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Replace $hashtable_update_MonitoringAcct1 -Verbose
    Write-Host ""
}
Else
{
    Write-Host "::    -- Updating user '$($UserObj.Name)' as Tier 1 user in DSP demos..." -ForegroundColor Cyan
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Replace $hashtable_update_MonitoringAcct1 -Verbose
    Write-Host ""
    # Trigger userAccountControl attribute changes...
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $True -Enabled $False -Verbose
    Start-Sleep 2
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $False -Enabled $True -Verbose
    Write-Host ""
}




# ---------
# DemoUser5
#
$UserObj = $null
If (!($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($DemoUser5.SamAccountName)))" -Properties * -ErrorAction SilentlyContinue))
{
    Write-Host "::    -- Creating user '$($DemoUser5.Name)' for DSP demos (showing user attribute changes)..." -ForegroundColor Cyan
    If ($DemoUserPassword)
    {
    # $DemoUserPassword has a value
    New-ADUser -Name "$($DemoUser5.Name)" -SamAccountName $($DemoUser5.SamAccountName) -DisplayName "$($DemoUser5.DisplayName)" -GivenName "$($DemoUser5.GivenName)" -Surname "$($DemoUser5.Surname)" -Department "$($DemoUser5.Department)" -Description "$($DemoUser5.Description)" -Accountpassword $DemoUserPassword -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($DemoUser5.Title)";'mail'="$($DemoUser5.Mail)"} -Path "$($DemoUser5.Path)" -Verbose
    }
    Else
    {
    # prompt for password
    New-ADUser -Name "$($DemoUser5.Name)" -SamAccountName $($DemoUser5.SamAccountName) -DisplayName "$($DemoUser5.DisplayName)" -GivenName "$($DemoUser5.GivenName)" -Surname "$($DemoUser5.Surname)" -Department "$($DemoUser5.Department)" -Description "$($DemoUser5.Description)" -Accountpassword (Read-Host -AsSecureString "AccountPassword") -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($DemoUser5.Title)";'mail'="$($DemoUser5.Mail)"} -Path "$($DemoUser5.Path)" -Verbose
    }

    # More attributes will be set for this user later in this script.
    Write-Host ""
}
Else
{
    Write-Host "::    -- Updating user '$($DemoUser5.Name)' for account manipulation in demos..." -ForegroundColor Cyan
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -City "$($DemoUser5.City)" -Company "$($DemoUser5.Company)" -Department "$($DemoUser5.Department)" -Description "$($DemoUser5.Description)" -Division "$($DemoUser5.Division)" -EmailAddress "$($DemoUser5.Mail)" -EmployeeID "$($DemoUser5.EmployeeID)" -GivenName "$($DemoUser5.GivenName)" -Initials "$($DemoUser5.Initials)" -Fax "$($DemoUser5.FAX)" -OfficePhone "$($DemoUser5.TelephoneNumber)" -Surname "$($DemoUser5.Surname)" -Title "$($DemoUser5.Title)" -Verbose
    Write-Host ""
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Manager $UserManagerDN -Verbose

    # Trigger userAccountControl attribute changes...
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $True -Verbose
    Start-Sleep 2
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $False -Verbose
    Write-Host ""
}





# ---------
# DemoUser6
#
$UserObj = $null
If (!($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($DemoUser6.SamAccountName)))" -Properties * -ErrorAction SilentlyContinue))
{
    Write-Host "::    -- Creating user '$($DemoUser6.Name)' for DSP demos (showing user attribute changes)..." -ForegroundColor Cyan
    If ($DemoUserPassword)
    {
    # $DemoUserPassword has a value
    New-ADUser -Name "$($DemoUser6.Name)" -SamAccountName $($DemoUser6.SamAccountName) -DisplayName "$($DemoUser6.DisplayName)" -GivenName "$($DemoUser6.GivenName)" -Surname "$($DemoUser6.Surname)" -Department "$($DemoUser6.Department)" -Description "$($DemoUser6.Description)" -Accountpassword $DemoUserPassword -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($DemoUser6.Title)";'mail'="$($DemoUser6.Mail)"} -Path "$($DemoUser6.Path)" -Verbose
    }
    Else
    {
    # prompt for password
    New-ADUser -Name "$($DemoUser6.Name)" -SamAccountName $($DemoUser6.SamAccountName) -DisplayName "$($DemoUser6.DisplayName)" -GivenName "$($DemoUser6.GivenName)" -Surname "$($DemoUser6.Surname)" -Department "$($DemoUser6.Department)" -Description "$($DemoUser6.Description)" -Accountpassword (Read-Host -AsSecureString "AccountPassword") -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($DemoUser6.Title)";'mail'="$($DemoUser6.Mail)"} -Path "$($DemoUser6.Path)" -Verbose
    }

    # More attributes will be set for this user later in this script.
    Write-Host ""
}
Else
{
    Write-Host "::    -- Updating user '$($DemoUser6.Name)' for account manipulation in demos..." -ForegroundColor Cyan
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -City "$($DemoUser6.City)" -Company "$($DemoUser6.Company)" -Department "$($DemoUser6.Department)" -Description "$($DemoUser6.Description)" -Division "$($DemoUser6.Division)" -EmailAddress "$($DemoUser6.Mail)" -EmployeeID "$($DemoUser6.EmployeeID)" -GivenName "$($DemoUser6.GivenName)" -Initials "$($DemoUser6.Initials)" -Fax "$($DemoUser6.FAX)" -OfficePhone "$($DemoUser6.TelephoneNumber)" -Surname "$($DemoUser6.Surname)" -Title "$($DemoUser6.Title)" -Verbose
    Write-Host ""
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Manager $UserManagerDN -Verbose

    # Trigger userAccountControl attribute changes...
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $True -Verbose
    Start-Sleep 2
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $False -Verbose
    Write-Host ""
}




# ---------
# DemoUser7
#
$UserObj = $null
If (!($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($DemoUser7.SamAccountName)))" -Properties * -ErrorAction SilentlyContinue))
{
    Write-Host "::    -- Creating user '$($DemoUser7.Name)' for DSP demos (showing user attribute changes)..." -ForegroundColor Cyan
    If ($DemoUserPassword)
    {
    # $DemoUserPassword has a value
    New-ADUser -Name "$($DemoUser7.Name)" -SamAccountName $($DemoUser7.SamAccountName) -DisplayName "$($DemoUser7.DisplayName)" -GivenName "$($DemoUser7.GivenName)" -Surname "$($DemoUser7.Surname)" -Department "$($DemoUser7.Department)" -Description "$($DemoUser7.Description)" -Accountpassword $DemoUserPassword -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($DemoUser7.Title)";'mail'="$($DemoUser7.Mail)"} -Path "$($DemoUser7.Path)" -Verbose
    }
    Else
    {
    # prompt for password
    New-ADUser -Name "$($DemoUser7.Name)" -SamAccountName $($DemoUser7.SamAccountName) -DisplayName "$($DemoUser7.DisplayName)" -GivenName "$($DemoUser7.GivenName)" -Surname "$($DemoUser7.Surname)" -Department "$($DemoUser7.Department)" -Description "$($DemoUser7.Description)" -Accountpassword (Read-Host -AsSecureString "AccountPassword") -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($DemoUser7.Title)";'mail'="$($DemoUser7.Mail)"} -Path "$($DemoUser7.Path)" -Verbose
    }

    # More attributes will be set for this user later in this script.
    Write-Host ""
}
Else
{
    Write-Host "::    -- Updating user '$($DemoUser7.Name)' for account manipulation in demos..." -ForegroundColor Cyan
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -City "$($DemoUser7.City)" -Company "$($DemoUser7.Company)" -Department "$($DemoUser7.Department)" -Description "$($DemoUser7.Description)" -Division "$($DemoUser7.Division)" -EmailAddress "$($DemoUser7.Mail)" -EmployeeID "$($DemoUser7.EmployeeID)" -GivenName "$($DemoUser7.GivenName)" -Initials "$($DemoUser7.Initials)" -Fax "$($DemoUser7.FAX)" -OfficePhone "$($DemoUser7.TelephoneNumber)" -Surname "$($DemoUser7.Surname)" -Title "$($DemoUser7.Title)" -Verbose
    Write-Host ""
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Manager $UserManagerDN -Verbose

    # Trigger userAccountControl attribute changes...
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $True -Verbose
    Start-Sleep 2
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $False -Verbose
    Write-Host ""
}




# ---------
# DemoUser8
#
$UserObj = $null
If (!($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($DemoUser8.SamAccountName)))" -Properties * -ErrorAction SilentlyContinue))
{
    Write-Host "::    -- Creating user '$($DemoUser8.Name)' for DSP demos (showing user attribute changes)..." -ForegroundColor Cyan
    If ($DemoUserPassword)
    {
    # $DemoUserPassword has a value
    New-ADUser -Name "$($DemoUser8.Name)" -SamAccountName $($DemoUser8.SamAccountName) -DisplayName "$($DemoUser8.DisplayName)" -GivenName "$($DemoUser8.GivenName)" -Surname "$($DemoUser8.Surname)" -Department "$($DemoUser8.Department)" -Description "$($DemoUser8.Description)" -Accountpassword $DemoUserPassword -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($DemoUser8.Title)";'mail'="$($DemoUser8.Mail)"} -Path "$($DemoUser8.Path)" -Verbose
    }
    Else
    {
    # prompt for password
    New-ADUser -Name "$($DemoUser8.Name)" -SamAccountName $($DemoUser8.SamAccountName) -DisplayName "$($DemoUser8.DisplayName)" -GivenName "$($DemoUser8.GivenName)" -Surname "$($DemoUser8.Surname)" -Department "$($DemoUser8.Department)" -Description "$($DemoUser8.Description)" -Accountpassword (Read-Host -AsSecureString "AccountPassword") -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($DemoUser8.Title)";'mail'="$($DemoUser8.Mail)"} -Path "$($DemoUser8.Path)" -Verbose
    }

    # More attributes will be set for this user later in this script.
    Write-Host ""
}
Else
{
    Write-Host "::    -- Updating user '$($DemoUser8.Name)' for account manipulation in demos..." -ForegroundColor Cyan
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -City "$($DemoUser8.City)" -Company "$($DemoUser8.Company)" -Department "$($DemoUser8.Department)" -Description "$($DemoUser8.Description)" -Division "$($DemoUser8.Division)" -EmailAddress "$($DemoUser8.Mail)" -EmployeeID "$($DemoUser8.EmployeeID)" -GivenName "$($DemoUser8.GivenName)" -Initials "$($DemoUser8.Initials)" -Fax "$($DemoUser8.FAX)" -OfficePhone "$($DemoUser8.TelephoneNumber)" -Surname "$($DemoUser8.Surname)" -Title "$($DemoUser8.Title)" -Verbose
    Write-Host ""
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Manager $UserManagerDN -Verbose

    # Trigger userAccountControl attribute changes...
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $True -Verbose
    Start-Sleep 2
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $False -Verbose
    Write-Host ""
}




# ---------
# DemoUser9
#
$UserObj = $null
If (!($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($DemoUser9.SamAccountName)))" -Properties * -ErrorAction SilentlyContinue))
{
    Write-Host "::    -- Creating user '$($DemoUser9.Name)' for DSP demos (showing user attribute changes)..." -ForegroundColor Cyan
    If ($DemoUserPassword)
    {
    # $DemoUserPassword has a value
    New-ADUser -Name "$($DemoUser9.Name)" -SamAccountName $($DemoUser9.SamAccountName) -DisplayName "$($DemoUser9.DisplayName)" -GivenName "$($DemoUser9.GivenName)" -Surname "$($DemoUser9.Surname)" -Department "$($DemoUser9.Department)" -Description "$($DemoUser9.Description)" -Accountpassword $DemoUserPassword -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($DemoUser9.Title)";'mail'="$($DemoUser9.Mail)"} -Path "$($DemoUser9.Path)" -Verbose
    }
    Else
    {
    # prompt for password
    New-ADUser -Name "$($DemoUser9.Name)" -SamAccountName $($DemoUser9.SamAccountName) -DisplayName "$($DemoUser9.DisplayName)" -GivenName "$($DemoUser9.GivenName)" -Surname "$($DemoUser9.Surname)" -Department "$($DemoUser9.Department)" -Description "$($DemoUser9.Description)" -Accountpassword (Read-Host -AsSecureString "AccountPassword") -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($DemoUser9.Title)";'mail'="$($DemoUser9.Mail)"} -Path "$($DemoUser9.Path)" -Verbose
    }

    # More attributes will be set for this user later in this script.
    Write-Host ""
}
Else
{
    Write-Host "::    -- Updating user '$($DemoUser9.Name)' for account manipulation in demos..." -ForegroundColor Cyan
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -City "$($DemoUser9.City)" -Company "$($DemoUser9.Company)" -Department "$($DemoUser9.Department)" -Description "$($DemoUser9.Description)" -Division "$($DemoUser9.Division)" -EmailAddress "$($DemoUser9.Mail)" -EmployeeID "$($DemoUser9.EmployeeID)" -GivenName "$($DemoUser9.GivenName)" -Initials "$($DemoUser9.Initials)" -Fax "$($DemoUser9.FAX)" -OfficePhone "$($DemoUser9.TelephoneNumber)" -Surname "$($DemoUser9.Surname)" -Title "$($DemoUser9.Title)" -Verbose
    Write-Host ""
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Manager $UserManagerDN -Verbose

    # Trigger userAccountControl attribute changes...
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $True -Verbose
    Start-Sleep 2
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $False -Verbose
    Write-Host ""
}




# ---------
# DemoUser10
#
$UserObj = $null
If (!($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($DemoUser10.SamAccountName)))" -Properties * -ErrorAction SilentlyContinue))
{
    Write-Host "::    -- Creating user '$($DemoUser10.Name)' for DSP demos (showing user attribute changes)..." -ForegroundColor Cyan
    If ($DemoUserPassword)
    {
    # $DemoUserPassword has a value
    New-ADUser -Name "$($DemoUser10.Name)" -SamAccountName $($DemoUser10.SamAccountName) -DisplayName "$($DemoUser10.DisplayName)" -GivenName "$($DemoUser10.GivenName)" -Surname "$($DemoUser10.Surname)" -Department "$($DemoUser10.Department)" -Description "$($DemoUser10.Description)" -Accountpassword $DemoUserPassword -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($DemoUser10.Title)";'mail'="$($DemoUser10.Mail)"} -Path "$($DemoUser10.Path)" -Verbose
    }
    Else
    {
    # prompt for password
    New-ADUser -Name "$($DemoUser10.Name)" -SamAccountName $($DemoUser10.SamAccountName) -DisplayName "$($DemoUser10.DisplayName)" -GivenName "$($DemoUser10.GivenName)" -Surname "$($DemoUser10.Surname)" -Department "$($DemoUser10.Department)" -Description "$($DemoUser10.Description)" -Accountpassword (Read-Host -AsSecureString "AccountPassword") -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($DemoUser10.Title)";'mail'="$($DemoUser10.Mail)"} -Path "$($DemoUser10.Path)" -Verbose
    }

    # More attributes will be set for this user later in this script.
    Write-Host ""
}
Else
{
    Write-Host "::    -- Updating user '$($DemoUser10.Name)' for account manipulation in demos..." -ForegroundColor Cyan
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -City "$($DemoUser10.City)" -Company "$($DemoUser10.Company)" -Department "$($DemoUser10.Department)" -Description "$($DemoUser10.Description)" -Division "$($DemoUser10.Division)" -EmailAddress "$($DemoUser10.Mail)" -EmployeeID "$($DemoUser10.EmployeeID)" -GivenName "$($DemoUser10.GivenName)" -Initials "$($DemoUser10.Initials)" -Fax "$($DemoUser10.FAX)" -OfficePhone "$($DemoUser10.TelephoneNumber)" -Surname "$($DemoUser10.Surname)" -Title "$($DemoUser10.Title)" -Verbose
    Write-Host ""
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Manager $UserManagerDN -Verbose

    # Trigger userAccountControl attribute changes...
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $True -Verbose
    Start-Sleep 2
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNotRequired $False -Verbose
    Write-Host ""
}




# ---------
# AdmUser1
#
$UserObj = $null
If (!($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($AdmUser1.SamAccountName)))" -Properties * -ErrorAction SilentlyContinue))
{
    Write-Host "::    -- Creating user '$($AdmUser1.Name)' for DSP demos (showing user attribute changes)..." -ForegroundColor Cyan
    If ($DemoUserPassword)
    {
    # $DemoUserPassword has a value
    New-ADUser -Name "$($AdmUser1.Name)" -SamAccountName $($AdmUser1.SamAccountName) -DisplayName "$($AdmUser1.DisplayName)" -GivenName "$($AdmUser1.GivenName)" -Surname "$($AdmUser1.Surname)" -Department "$($AdmUser1.Department)" -Description "$($AdmUser1.Description)" -Accountpassword $DemoUserPassword -PasswordNeverExpires $True -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($AdmUser1.Title)";'mail'="$($AdmUser1.Mail)"} -Path "$($AdmUser1.Path)" -Verbose
    }
    Else
    {
    # prompt for password
    New-ADUser -Name "$($AdmUser1.Name)" -SamAccountName $($AdmUser1.SamAccountName) -DisplayName "$($AdmUser1.DisplayName)" -GivenName "$($AdmUser1.GivenName)" -Surname "$($AdmUser1.Surname)" -Department "$($AdmUser1.Department)" -Description "$($AdmUser1.Description)" -Accountpassword (Read-Host -AsSecureString "AccountPassword") -PasswordNeverExpires $True -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($AdmUser1.Title)";'mail'="$($AdmUser1.Mail)"} -Path "$($AdmUser1.Path)" -Verbose
    }

    # More attributes will be set for this user later in this script.
    Write-Host ""
}
Else
{
    Write-Host "::    -- Updating user '$($AdmUser1.Name)' for account manipulation in demos..." -ForegroundColor Cyan
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -City "$($AdmUser1.City)" -Company "$($AdmUser1.Company)" -Department "$($AdmUser1.Department)" -Description "$($AdmUser1.Description)" -Division "$($AdmUser1.Division)" -EmailAddress "$($AdmUser1.Mail)" -EmployeeID "$($AdmUser1.EmployeeID)" -GivenName "$($AdmUser1.GivenName)" -Initials "$($AdmUser1.Initials)" -Fax "$($AdmUser1.FAX)" -OfficePhone "$($AdmUser1.TelephoneNumber)" -Surname "$($AdmUser1.Surname)" -Title "$($AdmUser1.Title)" -Verbose
    Write-Host ""
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Manager $UserManagerDN -Verbose

    # Trigger userAccountControl attribute changes...
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNeverExpires $True -PasswordNotRequired $True -Verbose
    Start-Sleep 2
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNeverExpires $True -PasswordNotRequired $False -Verbose
    Write-Host ""
}




# ---------
# AdmUser2
#
$UserObj = $null
If (!($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($AdmUser2.SamAccountName)))" -Properties * -ErrorAction SilentlyContinue))
{
    Write-Host "::    -- Creating user '$($AdmUser2.Name)' for DSP demos (showing user attribute changes)..." -ForegroundColor Cyan
    If ($DemoUserPassword)
    {
    # $DemoUserPassword has a value
    New-ADUser -Name "$($AdmUser2.Name)" -SamAccountName $($AdmUser2.SamAccountName) -DisplayName "$($AdmUser2.DisplayName)" -GivenName "$($AdmUser2.GivenName)" -Surname "$($AdmUser2.Surname)" -Department "$($AdmUser2.Department)" -Description "$($AdmUser2.Description)" -Accountpassword $DemoUserPassword -PasswordNeverExpires $True -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($AdmUser2.Title)";'mail'="$($AdmUser2.Mail)"} -Path "$($AdmUser2.Path)" -Verbose
    }
    Else
    {
    # prompt for password
    New-ADUser -Name "$($AdmUser2.Name)" -SamAccountName $($AdmUser2.SamAccountName) -DisplayName "$($AdmUser2.DisplayName)" -GivenName "$($AdmUser2.GivenName)" -Surname "$($AdmUser2.Surname)" -Department "$($AdmUser2.Department)" -Description "$($AdmUser2.Description)" -Accountpassword (Read-Host -AsSecureString "AccountPassword") -PasswordNeverExpires $True -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($AdmUser2.Title)";'mail'="$($AdmUser2.Mail)"} -Path "$($AdmUser2.Path)" -Verbose
    }

    # More attributes will be set for this user later in this script.
    Write-Host ""
}
Else
{
    Write-Host "::    -- Updating user '$($AdmUser2.Name)' for account manipulation in demos..." -ForegroundColor Cyan
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -City "$($AdmUser2.City)" -Company "$($AdmUser2.Company)" -Department "$($AdmUser2.Department)" -Description "$($AdmUser2.Description)" -Division "$($AdmUser2.Division)" -EmailAddress "$($AdmUser2.Mail)" -EmployeeID "$($AdmUser2.EmployeeID)" -GivenName "$($AdmUser2.GivenName)" -Initials "$($AdmUser2.Initials)" -Fax "$($AdmUser2.FAX)" -OfficePhone "$($AdmUser2.TelephoneNumber)" -Surname "$($AdmUser2.Surname)" -Title "$($AdmUser2.Title)" -Verbose
    Write-Host ""
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Manager $UserManagerDN -Verbose

    # Trigger userAccountControl attribute changes...
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNeverExpires $True -PasswordNotRequired $True -Verbose
    Start-Sleep 2
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNeverExpires $True -PasswordNotRequired $False -Verbose
    Write-Host ""
}






# ---------
# AdmUser3
#
$UserObj = $null
If (!($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($AdmUser3.SamAccountName)))" -Properties * -ErrorAction SilentlyContinue))
{
    Write-Host "::    -- Creating user '$($AdmUser3.Name)' for DSP demos (showing user attribute changes)..." -ForegroundColor Cyan
    If ($DemoUserPassword)
    {
    # $DemoUserPassword has a value
    New-ADUser -Name "$($AdmUser3.Name)" -SamAccountName $($AdmUser3.SamAccountName) -DisplayName "$($AdmUser3.DisplayName)" -GivenName "$($AdmUser3.GivenName)" -Surname "$($AdmUser3.Surname)" -Department "$($AdmUser3.Department)" -Description "$($AdmUser3.Description)" -Accountpassword $DemoUserPassword -PasswordNeverExpires $True -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($AdmUser3.Title)";'mail'="$($AdmUser3.Mail)"} -Path "$($AdmUser3.Path)" -Verbose
    }
    Else
    {
    # prompt for password
    New-ADUser -Name "$($AdmUser3.Name)" -SamAccountName $($AdmUser3.SamAccountName) -DisplayName "$($AdmUser3.DisplayName)" -GivenName "$($AdmUser3.GivenName)" -Surname "$($AdmUser3.Surname)" -Department "$($AdmUser3.Department)" -Description "$($AdmUser3.Description)" -Accountpassword (Read-Host -AsSecureString "AccountPassword") -PasswordNeverExpires $True -Enabled $true -CannotChangePassword $True -ChangePasswordAtLogon $False -OtherAttributes @{'title'="$($AdmUser3.Title)";'mail'="$($AdmUser3.Mail)"} -Path "$($AdmUser3.Path)" -Verbose
    }

    # More attributes will be set for this user later in this script.
    Write-Host ""
}
Else
{
    Write-Host "::    -- Updating user '$($AdmUser3.Name)' for account manipulation in demos..." -ForegroundColor Cyan
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -City "$($AdmUser3.City)" -Company "$($AdmUser3.Company)" -Department "$($AdmUser3.Department)" -Description "$($AdmUser3.Description)" -Division "$($AdmUser3.Division)" -EmailAddress "$($AdmUser3.Mail)" -EmployeeID "$($AdmUser3.EmployeeID)" -GivenName "$($AdmUser3.GivenName)" -Initials "$($AdmUser3.Initials)" -Fax "$($AdmUser3.FAX)" -OfficePhone "$($AdmUser3.TelephoneNumber)" -Surname "$($AdmUser3.Surname)" -Title "$($AdmUser3.Title)" -Verbose
    Write-Host ""
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Manager $UserManagerDN -Verbose

    # Trigger userAccountControl attribute changes...
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNeverExpires $True -PasswordNotRequired $True -Verbose
    Start-Sleep 2
    Set-ADAccountControl -Identity "$($UserObj.DistinguishedName)" -PasswordNeverExpires $True -PasswordNotRequired $False -Verbose
    Write-Host ""
}







Write-Host ""
Write-Host ""

Write-Host ":: Force replication after 10 second pause..." -ForegroundColor Yellow
Start-Sleep 10
If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}







#################################################################################
#
# ALTERNATE ADMIN CREDENTIAL MANAGEMENT
#
# In order to show a different account making changes in our demos, here we use
# the Credential Manager to manipulate the Microsoft Credential Store to store
# and recall the credentials for an admin user to make a change or two. The in the
# DSP Changes section, you can see changes from a different user account.
#
# I wanted to show a different admin making two or three changes to the same 
# attribute where we could undo to a selected previous state, as well as showing
# additional admin activities.
#
#
# We will populate the Credential Store with a password for the Ops Admin acct.
#
# https://childebrandt42.wordpress.com/2020/07/07/using-windows-credential-manager-with-powershell/
#
$OpsAdmin1Creds = $null

Write-Host ""
Write-Host ""
Write-Host "::                                                            " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: Attempting to retrieve the credential for '$($OpsAdmin1.SamAccountName)'..." -ForegroundColor Yellow
Write-Host "::                                                            " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""

#Get-StoredCredential -Target "$($OpsAdmin1.SamAccountName)"
$OpsAdmin1Creds = Get-StoredCredential -Target "$($OpsAdmin1.SamAccountName)" -Verbose # target is the 'label' to reference

If ($OpsAdmin1Creds)
{
    Write-Host ""
    Write-Host ""
    Write-Host ":: Found and retrieved credential for '$($OpsAdmin1.SamAccountName)'!!!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host ""
}
Else
{
    Write-Host ""
    Write-Host ""
    Write-Host ":: Could NOT retrieve credential for '$($OpsAdmin1.SamAccountName)'" -ForegroundColor Yellow -BackgroundColor Red
    Write-Host ""
    Write-Host ":: Updating the alternative admin credential in the Micrsoft Credential Store..." -ForegroundColor Yellow
    Write-Host ""

    If ($DemoUserPassword)
    {
        # We have a default user password: assume the same user passwork for this credential
        Write-Host "::    Using script 'default password' for this admin account;" -ForegroundColor Yellow
        Write-Host "::    Adding credential for '$($OpsAdmin1.SamAccountName)' to the Windows Credential Store." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "      Entering credentials for '$($OpsAdmin1.SamAccountName)' with the default password..." -ForegroundColor Cyan -BackgroundColor DarkGreen
        $admincred = new-object -typename System.Management.Automation.PSCredential -argumentlist $($OpsAdmin1.SamAccountName), $DemoUserPassword
        New-StoredCredential -Comment "$($OpsAdmin1.Description)" -Credentials $admincred -Target "$($OpsAdmin1.SamAccountName)" -Verbose
        $OpsAdmin1Creds = Get-StoredCredential -Target "$($OpsAdmin1.SamAccountName)" -Verbose # target is the 'label' to reference
        Write-Host ""
        Write-Host ""
        $OpsAdmin1Creds
    }
    Else
    {
        # User elected to not use the 'default' user account password
        Write-Host "::    Manually adding credential for '$($OpsAdmin1.SamAccountName)' to the Windows Credential Store..." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "                                                                                                " -ForegroundColor Cyan -BackgroundColor DarkGreen
        Write-Host "::    Please enter the username '$($OpsAdmin1.SamAccountName)' and the account password when prompted...    " -ForegroundColor Cyan -BackgroundColor DarkGreen
        Write-Host "                                                                                                " -ForegroundColor Cyan -BackgroundColor DarkGreen
        Write-Host ""
        Write-Host ""
        New-StoredCredential -Comment "$($OpsAdmin1.Description)" -Credentials $(Get-Credential) -Target "$($OpsAdmin1.SamAccountName)" -Verbose
        $OpsAdmin1Creds = Get-StoredCredential -Target "$($OpsAdmin1.SamAccountName)" -Verbose # target is the 'label' to reference
        Write-Host ""
        Write-Host ""
        $OpsAdmin1Creds
        Write-Host ""
        Write-Host ""
    }
}

Write-Host ""

<#
# https://childebrandt42.wordpress.com/2020/07/07/using-windows-credential-manager-with-powershell/

Remove-StoredCredential -Target 'DemoUser1Creds'
Remove-StoredCredential -Target "$($OpsAdmin1.SamAccountName)"

New-PSDrive -Name P -PSProvider FileSystem -Root \\server\share -Credential domain\user

New-PSDrive -Name V -PSProvider FileSystem -Root \\f122-d01-dc01\netlogon -Credential $DemoUser1Creds
Remove-PSDrive -Name V

$net = new-object -ComObject WScript.Network
$net.MapNetworkDrive("u:", "\\server\share", $false, "domain\user", "password")

New-PSDrive -Name P -PSProvider FileSystem -Root \\Server01\Public -Credential user\domain -Persist

set-aduser -Credential $DemoUser1Creds -Identity AppAdminIII -Company 'CircleM' -Verbose

#>

#
#################################################################################









################################################################################
#-------------------------------------------------------------------------------
# WMI Filters - Add WMI Filters for GPOs
#
# WMI Filters nicely demo the "Grouped" filtering option in DSP, where ungrouping
# shows a lot of details.
#
# This function will re-create any WMI filters that you delete.
#
# NOTE: WMI filters are referenced in GPOs by the WMI filter GUID. This is very
# important if you use one of these WMI filters in a GPO and then delete the 
# WMI filter, where a new WMI filter will be created with the same display name
# but it will have a different GUID, so the WMI filter in your GPO (that you 
# deleted) will simply be gone, and this NEW WMI filter will not automatically 
# replace the deleted one (because of the GUID reference).
#
# This function is credited below. I usually do not use functions in a script of 
# this type because debugging is a lot more difficult with PowerSWhell ISE.
#
# This section has two functions: 
#   Set-DCAllowSystemOnlyChange 
#   Create-WMIFilters
#
#
Write-Host ""
Write-Host ""
Write-Host ""
Write-Host "::                                                            " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: Creating/Updating demo WMI filters                         " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                            " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                            " -ForegroundColor White -BackgroundColor DarkCyan
Write-Host ":: WMI Filters are nice for showing the differences with the  " -ForegroundColor White -BackgroundColor DarkCyan
Write-Host ":: 'grouping' function in the 'Changes' section.              " -ForegroundColor White -BackgroundColor DarkCyan
Write-Host ":: (This will re-create any previously deleted.)              " -ForegroundColor White -BackgroundColor DarkCyan
Write-Host ":: You could also use in a GPO and show that an undo will     " -ForegroundColor White -BackgroundColor DarkCyan
Write-Host ":: also restore the GPO filtering.                            " -ForegroundColor White -BackgroundColor DarkCyan
Write-Host "::                                                            " -ForegroundColor White -BackgroundColor DarkCyan
Write-Host ":: This script will also modify the first three filters to    " -ForegroundColor White -BackgroundColor DarkCyan
Write-Host ":: make sure we get *something* in the Changes section.       " -ForegroundColor White -BackgroundColor DarkCyan
Write-Host "::                                                            " -ForegroundColor White -BackgroundColor DarkCyan
Write-Host ""
Start-Sleep 2


Function Set-DCAllowSystemOnlyChange
{
	param ([switch]$Set)
	if ($Set)
	{
		Write-Host "Checking if registry key is set to allow changes to AD System Only Attributes is set."
		$ntds_vals = (Get-Item HKLM:\System\CurrentControlSet\Services\NTDS\Parameters -ErrorAction Ignore).GetValueNames()
		if ( $ntds_vals -eq "Allow System Only Change")
		{
			$kval = Get-ItemProperty HKLM:\System\CurrentControlSet\Services\NTDS\Parameters -name "Allow System Only Change" -ErrorAction Ignore -Verbose
			if ($kval -eq "1")
			{
		    	Write-Host "'Allow System Only Change' key is already set"    
			}
			else
			{
		    	Write-Host "'Allow System Only Change' key is not set"
				Write-Host "Creating key and setting value to 1"
				Set-ItemProperty HKLM:\System\CurrentControlSet\Services\NTDS\Parameters -name "Allow System Only Change" -Value 0 -ErrorAction Ignore -Verbose
			}
		}
		else
		{ 
            Write-Host "Creating key and property for 'Allow System Only Change' and setting value to 1"
			New-ItemProperty HKLM:\System\CurrentControlSet\Services\NTDS\Parameters -name "Allow System Only Change" -Value 1 -PropertyType "DWord" -ErrorAction Ignore -Verbose
		}
	}
	else
	{
		$ntds_vals = (Get-Item HKLM:\System\CurrentControlSet\Services\NTDS\Parameters -ErrorAction Ignore).GetValueNames()
		if ( $ntds_vals -eq "Allow System Only Change")
		{
			Write-Host "Disabling 'Allow System Only Change' Attributes on server"
			Set-ItemProperty HKLM:\System\CurrentControlSet\Services\NTDS\Parameters -name "Allow System Only Change" -Value 0 -ErrorAction Ignore -Verbose
		}
	}
}
Function Create-WMIFilters
{
	# Based on function from http://gallery.technet.microsoft.com/scriptcenter/f1491111-9f5d-4c83-b436-537eca9e8d94
    # Name,Query,Description
    $WMIFilters = @(
                    ('Hyper-V Virtual Machines', 
                        'SELECT * FROM Win32_ComputerSystem WHERE Model = "Virtual Machine"', 
                        'Microsoft Hyper-V 2.0 AND 3.0'),
                    ('VMware Virtual Machines', 
                        'SELECT * FROM Win32_ComputerSystem WHERE Model LIKE "VMware%"', 
                        'VMware Fusion, Workstation AND ESXi'),
                    ('Parallels Virtual Machines', 
                        'SELECT * FROM Win32_ComputerSystem WHERE Model LIKE "Parallels%"', 
                        'OSX Parallels Virtual Machine'),
                    ('VirtualBox Virtual Machines', 
                        'SELECT * FROM Win32_ComputerSystem WHERE Model LIKE "VirtualBox%"', 
                        'Oracle VirtualBox Virtual Machine'),
                    ('Xen Virtual Machines', 
                        'SELECT * FROM Win32_ComputerSystem WHERE Model LIKE "HVM dom%"', 
                        'Citrix Xen Server Virtual Machine'),
                    ('Virtual Machines',
                        'SELECT * FROM Win32_ComputerSystem WHERE (Model LIKE "Parallels%" OR Model LIKE "HVM dom% OR Model LIKE "VirtualBox%" OR Model LIKE "Parallels%" OR Model LIKE "VMware%" OR Model = "Virtual Machine")',
                        'Virtual Machine from Hyper-V, VMware, Xen, Parallels OR VirtualBox'),
                    ('Java is Installed', 
                        'SELECT * FROM win32_Directory WHERE (name="c:\\Program Files\\Java" OR name="c:\\Program Files (x86)\\Java")', 
                        'Oracle Java'),
                    ('Java JRE 7 is Installed', 
                        'SELECT * FROM win32_Directory WHERE (name="c:\\Program Files\\Java\\jre7" OR name="c:\\Program Files (x86)\\Java\\jre7")', 
                        'Oracle Java JRE 7'),
                    ('Java JRE 6 is Installed', 
                        'SELECT * FROM win32_Directory WHERE (name="c:\\Program Files\\Java\\jre6" OR name="c:\\Program Files (x86)\\Java\\jre6")', 
                        'Oracle Java JRE 6'),
                    ('Workstation 32-bit', 
                        'Select * from WIN32_OperatingSystem WHERE ProductType=1 Select * from Win32_Processor WHERE AddressWidth = "32"', 
                        ''),
                    ('Workstation 64-bit', 
                        'Select * from WIN32_OperatingSystem WHERE ProductType=1 Select * from Win32_Processor WHERE AddressWidth = "64"', 
                        ''),
                    ('Workstations', 
                        'SELECT * FROM Win32_OperatingSystem WHERE ProductType = "1"', 
                        ''),
                    ('Domain Controllers', 
                        'SELECT * FROM Win32_OperatingSystem WHERE ProductType = "2"', 
                        ''),
                    ('Servers', 
                        'SELECT * FROM Win32_OperatingSystem WHERE ProductType = "3"', 
                        ''),
                    ('Windows XP', 
                        'SELECT * FROM Win32_OperatingSystem WHERE (Version LIKE "5.1%" OR Version LIKE "5.2%") AND ProductType = "1"', 
                        ''),
                    ('Windows Vista', 
                        'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.0%" AND ProductType = "1"', 
                        ''),
                    ('Windows 7', 
                        'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.1%" AND ProductType = "1"', 
                        ''),
                    ('Windows 8', 
                        'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.2%" AND ProductType = "1"', 
                        ''),
                    ('Windows Server 2003', 
                        'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "5.2%" AND ProductType = "3"', 
                        ''),
                    ('Windows Server 2008', 
                        'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.0%" AND ProductType = "3"', 
                        ''),
                    ('Windows Server 2008 R2', 
                        'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.1%" AND ProductType = "3"', 
                        ''),
                    ('Windows Server 2012', 
                        'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.2%" AND ProductType = "3"', 
                        ''),
                    ('Windows Vista AND Windows Server 2008', 
                        'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.0%" AND ProductType<>"2"', 
                        ''),
                    ('Windows Server 2003 AND Windows Server 2008', 
                        'SELECT * FROM Win32_OperatingSystem WHERE (Version LIKE "5.2%" OR Version LIKE "6.0%") AND ProductType="3"', 
                        ''),
                    ('Windows XP AND 2003', 
                        'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "5.%" AND ProductType<>"2"', 
                        ''),
                    ('Windows 8 AND 2012', 
                        'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.2%" AND ProductType<>"2"', 
                        ''),
                    ('Internet Explorer 10', 
                        'SELECT * FROM CIM_Datafile WHERE (Name="c:\\Program Files (x86)\\Internet Explorer\\iexplore.exe" OR Name="c:\\Program Files\\Internet Explorer\\iexplore.exe") AND version LIKE "10.%"'),
                    ('Internet Explorer 9', 
                        'SELECT * FROM CIM_Datafile WHERE (Name="c:\\Program Files (x86)\\Internet Explorer\\iexplore.exe" OR Name="c:\\Program Files\\Internet Explorer\\iexplore.exe") AND version LIKE "9.%"'),
                    ('Internet Explorer 8', 
                        'SELECT * FROM CIM_Datafile WHERE (Name="c:\\Program Files (x86)\\Internet Explorer\\iexplore.exe" OR Name="c:\\Program Files\\Internet Explorer\\iexplore.exe") AND version LIKE "8.%"'),
                    ('Internet Explorer 7', 
                        'SELECT * FROM CIM_Datafile WHERE (Name="c:\\Program Files (x86)\\Internet Explorer\\iexplore.exe" OR Name="c:\\Program Files\\Internet Explorer\\iexplore.exe") AND version LIKE "7.%"')
                )

    $defaultNamingContext = (get-adrootdse).defaultnamingcontext 
    $configurationNamingContext = (get-adrootdse).configurationNamingContext 
    $msWMIAuthor = "Administrator@" + [System.DirectoryServices.ActiveDirectory.Domain]::getcurrentdomain().name
    
	Write-Verbose "Starting creation of WMI Filters:"
    for ($i = 0; $i -lt $WMIFilters.Count; $i++) 
    {
        $WMIGUID = [string]"{"+([System.Guid]::NewGuid())+"}"   
        $WMIDN = "CN="+$WMIGUID+",CN=SOM,CN=WMIPolicy,CN=System,"+$defaultNamingContext
        $WMICN = $WMIGUID
        $WMIdistinguishedname = $WMIDN
        $WMIID = $WMIGUID
#
#
"`n`n============================="
$msWMIName
$WMIGUID
#
#

        $now = (Get-Date).ToUniversalTime()
        $msWMICreationDate = ($now.Year).ToString("0000") + ($now.Month).ToString("00") + ($now.Day).ToString("00") + ($now.Hour).ToString("00") + ($now.Minute).ToString("00") + ($now.Second).ToString("00") + "." + ($now.Millisecond * 1000).ToString("000000") + "-000"

        $msWMIName = $WMIFilters[$i][0]

        $msWMIParm1 = $WMIFilters[$i][2] + " "
        $msWMIParm2 = "1;3;10;" + $WMIFilters[$i][1].Length.ToString() + ";WQL;root\CIMv2;" + $WMIFilters[$i][1] + ";"

        $Attr = @{"msWMI-Name" = $msWMIName;"msWMI-Parm1" = $msWMIParm1;"msWMI-Parm2" = $msWMIParm2;"msWMI-Author" = $msWMIAuthor;"msWMI-ID"=$WMIID;"instanceType" = 4;"showInAdvancedViewOnly" = "TRUE";"distinguishedname" = $WMIdistinguishedname;"msWMI-ChangeDate" = $msWMICreationDate; "msWMI-CreationDate" = $msWMICreationDate}
        $WMIPath = ("CN=SOM,CN=WMIPolicy,CN=System,"+$defaultNamingContext)
    	
		Write-Verbose "Adding WMI Filter for: $msWMIName"

"- - - -"
### Get-WmiObject -List -Namespace $namespace | Where-Object { $_.methods }
### Get-ADObject -LDAPFilter "(&(objectClass=msWMI-Som))"
###$objWMIFilter = Get-ADObject -LDAPFilter "(&(objectClass=msWMI-Som)(msWMI-Name=Internet Explorer 8))" -Properties msWMI-Name
'- - - - '
$msWMIName
$WMICN
$WMIPath
"======="
        If ($objWMIFilter = Get-ADObject -LDAPFilter "(&(objectClass=msWMI-Som)(msWMI-Name=$msWMIName))" -Properties msWMI-Name)
            {
            Write-Host ""
            Write-Host "NOTIFICATION!!  ---WMI Filter already exists!!   ($msWMIName)" -ForegroundColor Gray
            Write-Host "WMI Filter name (msWMI-Name): $($objWMIFilter.'msWMI-Name')`n" -ForegroundColor Gray

            # Trigger change history for first 3 WMI filters...
            If ($i -lt 3)
                {
                #
                # Ther could be duplicate named WMI filters based on msWMI-Name where the WMI filter
                # has a different and unique "Name" attribute (e.g., {f3de6068-a0be-404b-8a22-bbcc83a031fe})
                # and a different and unique "ObjectGUID". In other words, AD allows duplicate "msWMI-Name"
                # values. SO, we need to loop through the objects to just change the last one we find for
                # DSP changes view. (We could delete the duplicates, but then we'd have to also make sure 
                # WMI filter is not linked to any GPOs.)
                #
                # So loop though any dups and just use the last one in the list...
                #
                $objWMIFilterItem = $Null
                ForEach ($objWMIFilterItem in $objWMIFilter) {Write-Host "    -- Found WMI filter '$($WMIFilters[$i][0])' with 'msWMI-Name': `n`t`t$($objWMIFilterItem)" -ForegroundColor Magenta }
                $objWMIFilter = $objWMIFilterItem

                Write-Host ":: Modifying WMI filter description to trigger changes..." -ForegroundColor Yellow
                Write-Host "   ---"
                Write-Host "            WMI filter CN: CN=$($objWMIFilter.Name)" -ForegroundColor Cyan
                Write-Host "          WMI filter name: $($WMIFilters[$i][0])" -ForegroundColor Cyan
                Write-Host "   WMI Filter description: $($WMIFilters[$i][2])" -ForegroundColor Cyan
                Write-Host "   ---"
                Set-ADObject -Identity $objWMIFilter.distinguishedName -DisplayName $msWMIName -Description "-changed description-" -Verbose
                Start-Sleep 5
                Set-ADObject -Identity $objWMIFilter.distinguishedName -DisplayName $msWMIName -Description "$($WMIFilters[$i][2])" -Verbose
                Write-Host "---"
                }
            Write-Host
            }
        Else
            {
            Write-Host ""
            Write-Host "INFO!!     ---Creating new GPO WMI filter ($msWMIName)..." -ForegroundColor White -BackgroundColor DarkCyan
            New-ADObject -name $WMICN -type "msWMI-Som" -Path $WMIPath -OtherAttributes $Attr | Out-Null
            }

    }
	Write-Verbose "Finished adding WMI Filters"
}


Set-DCAllowSystemOnlyChange -Set
Create-WMIFilters
Set-DCAllowSystemOnlyChange 

##
##------------------------------------------------------------------------------
################################################################################






#------------------------------------------------------------------------------
#
# create OU structure: Add objects to "Delete Me" OU for demo of 
# recovering an entire deleted OU tree.
#
Write-Host "`n`n"
Write-Host "::                                                                           " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- OU STUFF: ADD SUB-OU'S AND OTHER OBJECTS TO 'DELETE ME' OU ----      " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                           " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
If ((Get-ADOrganizationalUnit -LDAPFilter '(OU=DeleteMe OU)'))
{
    Write-Host "::    -- Populating OU 'DeleteMe OU' with some user objects..." -ForegroundColor Yellow
    #Set-ADOrganizationalUnit -Identity "OU=DeleteMe OU,$DomainDN" -ProtectedFromAccidentalDeletion $False
    #Remove-ADOrganizationalUnit -Identity "OU=DeleteMe OU,$DomainDN" -ErrorAction SilentlyContinue -Confirm:$False


    # --- Create or re-create some user objects in this OU...

    # Create Accounts: Generic user accounts for OU
    $OU = "OU=DeleteMe OU,$adDomainDN"
    #
    Invoke-Command -ArgumentList $adDomain,$adDomainDN,$adDomainFQDN,$adDomainNetBIOS,$adDomainRwdcFQDN,$OU -ScriptBlock {
	    Param (
	    	$adDomain,
		    $adDomainDN,
		    $adDomainFQDN,
		    $adDomainNetBIOS,
		    $adDomainRwdcFQDN,
		    $OU
	    )
  
  
    $N = 10    # number of user accounts to create (assuming max 999,999 for prefix padding)

    $PREFIX  = @('000000', '00000', '0000', '000', '00', '0')  # This is for padding names

    Write-Host ""

    # N-1 because we start at 0

	0..($N-1) | ForEach-Object{
		$randomNr = (Get-Date -Format "yyyyMMddHHmmss").ToString() + (Get-Random -Minimum 10 -Maximum 99)
		$password = $(-join (33..126 | ForEach-Object {[char]$_} | Get-Random -Count 32))

        $INDEX = "$($PREFIX[($($_).ToString().Length)])$($_)"

        If ($GenericUser = Get-ADUser -LDAPFilter "((objectClass=user)(objectCategory=person) (| (sAMAccountName=$("GenericAct0r-" + $INDEX)) (CN=$("Generic Act0r " + $adDomainFQDN + " " + $INDEX)) ) )")
        {
            Write-Host "User $($GenericUser) [$("GenericAct0r-" + $INDEX)] already exists." -ForegroundColor DarkGray
        }
        Else
        {
    		Write-Host "Creating User Account: ""Generic Act0r $($INDEX)"" [$("GenericAct0r-" + $INDEX)] ..." -ForegroundColor Magenta
		    New-ADUser -Path $OU -Enabled $true -Name $("Generic Act0r" + " " + $INDEX) -GivenName "Generic" -Surname $("Act0r " + " " + $INDEX) -DisplayName $("Generic Act0r " + " " + $INDEX) -SamAccountName $("GenericAct0r-" + $INDEX) -UserPrincipalName "Generic.Act0r.$INDEX@$adDomainFQDN" -Description $("Generic Act0r "+ " " + $($_) + "  (" + $adDomainFQDN + ")" ) -AccountPassword $(ConvertTo-SecureString $password -AsPlainText -Force) -Server $adDomainRwdcFQDN
#            This code is to add configuation changes that affect indicators of compromise...
#    		  If ($($_).ToString().EndsWith("1") -eq $true) 
#             {
#			      Set-ADUser -Identity $("GdAct0r" + $($INDEX)) -Description $("Good Act0r " + " " + $($INDEX) + " Password = " + $password) -Add @{"msDS-AllowedToDelegateTo" = @("MSSQLSvc/$randomNr:1433", "MSSQLSvc/$randomNr.$adDomainFQDN:1433") } -ServicePrincipalNames @{Add = "HTTP/$randomNr.111.$adDomainFQDN", "HTTP/$randomNr.222.$adDomainFQDN" } -Server $adDomainRwdcFQDN
#		      }
###		      Set-ADAccountControl -Identity $("GdAct0r" + $($INDEX)) -PasswordNeverExpires $false -Server $adDomainRwdcFQDN
        }
		Write-Host "- - -"
	}
    
    Write-Host "::" -ForegroundColor Yellow
    Write-Host ":: Done!!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host ""
} # end scriptblock




    # --- Create a sub-OU object...

    $thisOUName = 'Corp Special OU'
    Write-Host "::" -ForegroundColor Yellow
    Write-Host "::" -ForegroundColor Yellow
    Write-Host "::    -- Populating OU Tree...    ($thisOUName)" -ForegroundColor Yellow
    Write-Host "::" -ForegroundColor Yellow

    If ((Get-ADOrganizationalUnit -LDAPFilter '(OU=DeleteMe OU)'))
    {
        If (!(Get-ADOrganizationalUnit -LDAPFilter "(OU=$thisOUName,OU=DELETE ME,$DomainDN)"))
        {
            Write-Host "::    -- OU=DeleteMe OU --> Creating sub-OU '$thisOUName'..." -ForegroundColor Cyan
            New-ADOrganizationalUnit -Path "OU=DELETEME OU,$DomainDN" -Name $thisOUName -DisplayName $thisOUName -Description 'sub-OU that gets DELETED by script' -ErrorAction SilentlyContinue -Verbose
        }
    }

    # Lets create a group here...
    $thisGroupName = "Special Access - Datacenter"
    If (!(Get-ADGroup -LDAPFilter "(CN=$thisGroupName)"))
    {
        Write-Host "::        -- 'OU=$thisOUName'  -->>  Creating group '$thisGroupName'..." -ForegroundColor Cyan
        New-ADGroup -Path "OU=$thisOUName,OU=DELETEME OU,$DomainDN" -Name "$thisGroupName" -Description "Resource Administrators for special Lab" -DisplayName "$thisGroupName" -SamAccountName $thisGroupName -GroupScope Global -GroupCategory Security -Verbose
    }



    # --- Create a sub-OU object plus some other objects...

    $thisOUName = 'Servers'
    Write-Host "::" -ForegroundColor Yellow
    Write-Host "::" -ForegroundColor Yellow
    Write-Host "::    -- Populating OU Tree...    ($thisOUName)" -ForegroundColor Yellow
    Write-Host "::" -ForegroundColor Yellow

    If ((Get-ADOrganizationalUnit -LDAPFilter '(OU=DeleteMe OU)'))
    {
        If (!(Get-ADOrganizationalUnit -LDAPFilter "(OU=$thisOUName,OU=DELETE ME,$DomainDN)"))
        {
            Write-Host "::    -- OU=DeleteMe OU --> Creating computer object in sub-OU '$thisOUName'..." -ForegroundColor Cyan
            New-ADOrganizationalUnit -Path "OU=DELETEME OU,$DomainDN" -Name $thisOUName -DisplayName $thisOUName -Description 'sub-OU that gets DELETED by script' -ErrorAction SilentlyContinue -Verbose
        }
    }

    # Lets create a computer object here...
    $thisComputerName = 'srv-iis-us01'
    If (!(Get-ADComputer -LDAPFilter "(CN=$thisComputerName)"))
    {
        Write-Host "::        -- 'OU=$thisOUName'  -->>  Creating computer object '$thisComputerName'..." -ForegroundColor Cyan
        New-ADComputer -Path "OU=$thisOUName,OU=DELETEME OU,$DomainDN" -Name "$thisComputerName" -AccountPassword $(ConvertTo-SecureString "$0meRand0JunkH3r3!!" -AsPlainText -Force) -Description "Special application server for lab ($thisComputerName)" -DisplayName "$thisComputerName" -SAMAccountName "$thisComputerName" -verbose
    }

    # Lets create a group here...
    $thisGroupName = "Server Admins - US"
    If (!(Get-ADGroup -LDAPFilter "(CN=$thisGroupName)"))
    {
        Write-Host "::        -- 'OU=$thisOUName'  -->>  Creating group object '$thisGroupName'..." -ForegroundColor Cyan
        New-ADGroup -Path "OU=$thisOUName,OU=DELETEME OU,$DomainDN" -Name "$thisGroupName" -Description "Resource Administrators for special Lab" -DisplayName "$thisGroupName" -SamAccountName $thisGroupName -GroupScope Global -GroupCategory Security -Verbose
    }
    # Lets create a group here...
    $thisGroupName = "Server Admins - APAC"
    If (!(Get-ADGroup -LDAPFilter "(CN=$thisGroupName)"))
    {
        Write-Host "::        -- 'OU=$thisOUName'  -->>  Creating group object '$thisGroupName'..." -ForegroundColor Cyan
        New-ADGroup -Path "OU=$thisOUName,OU=DELETEME OU,$DomainDN" -Name "$thisGroupName" -Description "Resource Administrators for special Lab" -DisplayName "$thisGroupName" -SamAccountName $thisGroupName -GroupScope Global -GroupCategory Security -Verbose
    }



    # --- Create a sub-OU object plus some other objects...

    $thisOUName = 'Resources'
    Write-Host "::" -ForegroundColor Yellow
    Write-Host "::" -ForegroundColor Yellow
    Write-Host "::    -- Populating OU Tree...    ($thisOUName)" -ForegroundColor Yellow
    Write-Host "::" -ForegroundColor Yellow

    If ((Get-ADOrganizationalUnit -LDAPFilter '(OU=DeleteMe OU)'))
    {
        If (!(Get-ADOrganizationalUnit -LDAPFilter "(OU=$thisOUName,OU=DELETE ME,$DomainDN)"))
        {
            Write-Host "::    -- OU=DeleteMe OU --> Creating computer object in sub-OU '$thisOUName'..." -ForegroundColor Cyan
            New-ADOrganizationalUnit -Path "OU=DELETEME OU,$DomainDN" -Name $thisOUName -DisplayName $thisOUName -Description 'sub-OU that gets DELETED by script' -ErrorAction SilentlyContinue -Verbose
        }
    }

    # Lets create a computer object here...
    $thisComputerName = 'ops-app-us05'
    If (!(Get-ADComputer -LDAPFilter "(CN=$thisComputerName)"))
    {
        Write-Host "::        -- 'OU=$thisOUName'  -->>  Creating computer object '$thisComputerName'..." -ForegroundColor Cyan
        New-ADComputer -Path "OU=$thisOUName,OU=DELETEME OU,$DomainDN" -Name "$thisComputerName" -AccountPassword $(ConvertTo-SecureString "$0meRand0JunkH3r3!!" -AsPlainText -Force) -Description "Special application server for lab" -DisplayName "$thisComputerName" -SAMAccountName "$thisComputerName" -verbose
    }

    # Lets create a group here...
    $thisGroupName = "Resource Admins"
    If (!(Get-ADGroup -LDAPFilter "(CN=$thisGroupName)"))
    {
        Write-Host "::        -- 'OU=$thisOUName'  -->>  Creating group object '$thisGroupName'..." -ForegroundColor Cyan
        New-ADGroup -Path "OU=$thisOUName,OU=DELETEME OU,$DomainDN" -Name "$thisGroupName" -Description "Resource Administrators for special Lab" -DisplayName "$thisGroupName" -SamAccountName $thisGroupName -GroupScope Global -GroupCategory Security -Verbose
    }

}

Write-Host "::" -ForegroundColor Yellow
Write-Host "::" -ForegroundColor Yellow
Write-Host "::    -- Done populating OU Tree!!!" -ForegroundColor Yellow
Write-Host "::" -ForegroundColor Yellow
Write-Host "::" -ForegroundColor Yellow
Write-Host ""

Start-Sleep 5





#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                        " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- OU ACTIONS PART 1: POPULATE USERS INTO OU ($UsersOUName01) ----          " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                        " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

# This is setting the initial phase, where 01 is going to be our starting point
# for later moving these user accounts to 02. The idea is to generate activity 
# that will reflect on the activity graph on the DSP Overview page.

Write-Host ":: Move any users in OU '$UsersOUName02' to OU '$UsersOUName01'..." -ForegroundColor Yellow

$UsersOUName01dn = (Get-ADOrganizationalUnit -LDAPFilter "(OU=$UsersOUName01)").DistinguishedName
$UsersOUName02dn = (Get-ADOrganizationalUnit -LDAPFilter "(OU=$UsersOUName02)").DistinguishedName

$adUserGroup = Get-ADUser -Filter {Enabled -eq "True"} -SearchBase ($UsersOUName02dn)

# Move any user object from 02 to 01...

ForEach($user in $adUserGroup)
    {
    Write-Host ":: -- Moving Active Directory user: '$($user.Name)'" -ForegroundColor Yellow
    Write-Host "      -- Target OU: '$UsersOUName01dn'" -ForegroundColor Magenta
    Move-ADObject -Identity $user -targetpath $UsersOUName01dn -Verbose
    Write-Host ""
    }


# Create any missing/needed user objects in 01...

If ((Get-ADOrganizationalUnit -LDAPFilter "(OU=$UsersOUName01)"))
{
    Write-Host "::    -- Populating OU '$UsersOUName01' with some user objects..." -ForegroundColor Yellow
    #Set-ADOrganizationalUnit -Identity "OU=$UsersOUName01,$DomainDN" -ProtectedFromAccidentalDeletion $False
    #Remove-ADOrganizationalUnit -Identity "OU=$UsersOUName01,$DomainDN" -ErrorAction SilentlyContinue -Confirm:$False

    # Create Accounts: Generic user accounts for OU
    $OU = $UsersOUName01dn
    #
    Invoke-Command -ArgumentList $adDomain,$adDomainDN,$adDomainFQDN,$adDomainNetBIOS,$adDomainRwdcFQDN,$OU -ScriptBlock {
	    Param (
	    	$adDomain,
		    $adDomainDN,
		    $adDomainFQDN,
		    $adDomainNetBIOS,
		    $adDomainRwdcFQDN,
		    $OU
	    )
  
  
    $N = 15    # number of user accounts to create (assuming max 999,999 for prefix padding)

    $PREFIX  = @('000', '00', '0')  # This is for padding names

    Write-Host ""

    # N-1 because we start at 0

	0..($N-1) | ForEach-Object{
		$randomNr = (Get-Date -Format "yyyyMMddHHmmss").ToString() + (Get-Random -Minimum 10 -Maximum 99)
		$password = $(-join (33..126 | ForEach-Object {[char]$_} | Get-Random -Count 32))

        $INDEX = "$($PREFIX[($($_).ToString().Length)])$($_)"

        If ($GenericUser = Get-ADUser -LDAPFilter "((objectClass=user)(objectCategory=person) (| (sAMAccountName=$("LabUs3r-" + $INDEX)) (CN=$("Lab Us3r " + $adDomainFQDN + " " + $INDEX)) ) )")
        {
            Write-Host "User $($GenericUser) [$("LabUs3r-" + $INDEX)] already exists." -ForegroundColor DarkGray
        }
        Else
        {
    		Write-Host "Creating User Account: ""Lab Us3r $($INDEX)"" [$("LabUs3r-" + $INDEX)] ..." -ForegroundColor Magenta
            $OU
            $INDEX
		    New-ADUser -Path $OU -Enabled $true -Name $("Lab Us3r" + " " + $INDEX) -GivenName "Lab" -Surname $("Us3r " + " " + $INDEX) -DisplayName $("Lab Us3r " + " " + $INDEX) -SamAccountName $("LabUs3r-" + $INDEX) -UserPrincipalName "Lab.Us3r.$INDEX@$adDomainFQDN" -Description $("Lab Us3r "+ " " + $($_) + "  (" + $adDomainFQDN + ")" ) -AccountPassword $(ConvertTo-SecureString $password -AsPlainText -Force) -Server $adDomainRwdcFQDN -Verbose
#            This code is to add configuation changes that affect indicators of compromise...
#    		  If ($($_).ToString().EndsWith("1") -eq $true) 
#             {
#			      Set-ADUser -Identity $("GdAct0r" + $($INDEX)) -Description $("Good Act0r " + " " + $($INDEX) + " Password = " + $password) -Add @{"msDS-AllowedToDelegateTo" = @("MSSQLSvc/$randomNr:1433", "MSSQLSvc/$randomNr.$adDomainFQDN:1433") } -ServicePrincipalNames @{Add = "HTTP/$randomNr.111.$adDomainFQDN", "HTTP/$randomNr.222.$adDomainFQDN" } -Server $adDomainRwdcFQDN
#		      }
###		      Set-ADAccountControl -Identity $("GdAct0r" + $($INDEX)) -PasswordNeverExpires $false -Server $adDomainRwdcFQDN
        }
		Write-Host "- - -"
	}
    
    Write-Host "::" -ForegroundColor Yellow
    Write-Host ":: Done!!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host ""
} # end scriptblock

}







################################################################################
#-------------------------------------------------------------------------------
# Create special OU structure with more restrictive ACL and populate with objects.
#
Write-Host "`n`n"
Write-Host "::                                                                       " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- OU STUFF: Create special OU structure with more restrictive ACL  " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                and populate with objects                              " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                       " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- [$($SpecialOuObj.Name)] ----                                                " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                       " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

#------------------------------------------------------------------------------
#
# This OU is to demo a more restrictive ACL with special computer objects added.
# 
# All security ACEs will be removed and the logged account will be added for full access.
#
#
$SpecialOuObj

Write-Host ""
Write-Host "::" -ForegroundColor Yellow
Write-Host "::" -ForegroundColor Yellow
Write-Host "::    -- Creating/Populating OU Tree...    (OU=$($SpecialOuObj.Name))" -ForegroundColor Yellow
Write-Host "::" -ForegroundColor Yellow

If (Get-ADOrganizationalUnit -Filter "OU -Like '$($SpecialOuObj.Name)'" -SearchBase $DomainDN)
{
    Write-Host "::" -ForegroundColor Yellow
    Write-Host "::        -- OU ($($SpecialOuObj.Name)) already exists!" -ForegroundColor Yellow
    Write-host "::" -ForegroundColor Yellow
}
Else
{
    Write-Host "::    -- OU=$($SpecialOuObj.Name) --> Creating sub-OU '$($SpecialOuObj.Name)'..." -ForegroundColor Cyan
    New-ADOrganizationalUnit -Name $SpecialOuObj.Name -City 'Mandalay Bay' -DisplayName $SpecialOuObj.DisplayName -Description $SpecialOuObj.Description -ErrorAction SilentlyContinue -Verbose
    Write-host "::" -ForegroundColor Cyan
}

Write-host "::" -ForegroundColor Yellow
Write-host "::" -ForegroundColor Yellow



# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Change owner on the OU and set more restrictive ACL on the OU...
#
#
If ($OUobj = Get-ADOrganizationalUnit -Filter "OU -Like '$($SpecialOuObj.Name)'" -SearchBase $DomainDN)
{
    Write-Host ""

    # --- Set OWNER of OU to the logged on domain account
    $CurrentUser.Name
    $sid = New-Object System.Security.Principal.NTAccount("$($CurrentUser.Name)")
    $OUpath = ("AD:" + (Get-ADOrganizationalUnit -Filter "OU -Like '$($SpecialOuObj.Name)'" -SearchBase $DomainDN).DistinguishedName)
    $OUacl = get-acl -Path $OUpath
    $OUacl.SetOwner($sid)
    Set-Acl -path $OUpath -AclObject $OUacl -Verbose

    Write-Host ""
    Write-Host ""

    # --- Set logged on account with full object access
    $OUace = (Get-Acl "$($OUpath)")
       #  method to exclude the ACL from inheriting rules: $acl.SetAccessRuleProtection($true,$false)
       #  The second argument (preserveInheritance) also removes existing inherited 
       #  rules when set to false, leaving just the system default ACE's.
       #  Removes inherited ACEs and protects against inheriting future parent ACEs
    $OUace.SetAccessRuleProtection($True, $False)
       $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
       $accessType = [System.Security.AccessControl.AccessControlType]::Allow
       # - - - - - 
       #  All 	1 	
       # Indicates inheritance that includes the object to which the ACE is applied, the object's immediate children, and the descendents of the object's children.
       # Children 	4 	
       # Indicates inheritance that includes the object's immediate children only, not the object itself or the descendents of its children.
       # Descendents 	2 	
       # Indicates inheritance that includes the object's immediate children and the descendants of the object's children, but not the object itself.
       # None 	0 	
       # Indicates no inheritance. The ACE information is only used on the object on which the ACE is set. ACE information is not inherited by any descendents of the object.
       # SelfAndChildren 	3 	
       # Indicates inheritance that includes the object itself and its immediate children. It does not include the descendents of its children.
       $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
       # - - - - - 
    $accessrule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $sid, $adRights, $accessType , $inheritanceType
    $OUace.AddAccessRule($accessrule)
    Set-Acl -Path $OUpath -AclObject $OUace -Verbose

    # --- Remove all security ACEs and make sure the logged on account is added for FULL access
    $OUacl.SetAccessRuleProtection($True, $False)
    $OUacl.Access | %{$OUacl.RemoveAccessRule($_)}   # remove all security
    $OUacl.SetOwner([System.Security.Principal.NTAccount] $env:USERNAME)   # set the current user as owner
       $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
       $accessType = [System.Security.AccessControl.AccessControlType]::Allow
       $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    $accessrule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $sid, $adRights, $accessType , $inheritanceType   # set my admin account as also having access
    $OUacl.AddAccessRule($accessrule)
    Set-Acl -Path $OUpath -AclObject $OUacl -Verbose


<#
    # --- Remove access for EVERYONE
    $OUacl.access
    $acesToRemove = $OUacl.Access | ?{ $_.IsInherited -eq $true -and $_.IdentityReference -eq 'EVERYONE' }
    ###$OUacl.RemoveAccessRuleAll($acesToRemove)  # cannot remove multiple ACE's at one time, though not well documented :-(
    foreach ($ace in $acesToRemove) {$OUacl.RemoveAccessRuleAll($ace)}
    Set-Acl -Path $OUpath -AclObject $OUacl -Verbose

    $OUace = (Get-Acl "$($OUpath)").Access 
    foreach ($acl in $OUace) {
        #$acl.SetAccessRuleProtection($True, $True)
        $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
        $accessType = [System.Security.AccessControl.AccessControlType]::Allow
        $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
        $accessrule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $sid, $adRights, $accessType , $inheritanceType
        $acl.AddAccessRule($accessrule) 
        Set-Acl -Path $OUpath -AclObject $ace -Verbose
    }
#>


}

Write-host "::" -ForegroundColor Yellow
Write-host "::" -ForegroundColor Yellow


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# When the OU exists, create some special objects in this container...
#
#
If (Get-ADOrganizationalUnit -Filter "OU -Like '$($SpecialOuObj.Name)'" -SearchBase $DomainDN)
{
    #------------------------------------------------------------------------------
    #
    # This computer object is for having objects in a more restricted OU.
    #
    Write-Host ""
    Write-Host ""
    $SpecialComputerObj1

    Write-Host ""
    Write-Host "::     -- Checking for computer object existence: [$($SpecialComputerObj1.Name)]" -ForegroundColor Yellow

    If (!(Get-ADComputer -LDAPFilter "(CN=$($SpecialComputerObj1.Name))"))
    {
        Write-Host "::        -- 'OU=$($SpecialOuObj.Name)'  -->>  Creating computer object '$($SpecialComputerObj1.Name)'..." -ForegroundColor Cyan
        New-ADComputer -Path "OU=$($SpecialOuObj.Name),$DomainDN" -Name "$($SpecialComputerObj1.Name)" -Description "$($SpecialComputerObj1.Description) ($($SpecialComputerObj1.Name))" -DisplayName "$($SpecialComputerObj1.Name)" -SAMAccountName "$($SpecialComputerObj1.Name)" -verbose -AccountPassword $(ConvertTo-SecureString "!$0meRand0JunkH3r3!!4" -AsPlainText -Force)
    }
    Else
    {
        Write-Host "::             -- Computer object '$($SpecialComputerObj1.Name)' already exists!" -ForegroundColor Yellow
    }


    #------------------------------------------------------------------------------
    #
    # This computer object is for having objects in a more restricted OU.
    #
    Write-Host ""
    Write-Host ""
    $SpecialComputerObj2

    Write-Host ""
    Write-Host "::     -- Checking for computer object existence: [$($SpecialComputerObj2.Name)]" -ForegroundColor Yellow

    If (!(Get-ADComputer -LDAPFilter "(CN=$($SpecialComputerObj2.Name))"))
    {
        Write-Host "::        -- 'OU=$($SpecialOuObj.Name)'  -->>  Creating computer object '$($SpecialComputerObj2.Name)'..." -ForegroundColor Cyan
        New-ADComputer -Path "OU=$($SpecialOuObj.Name),$DomainDN" -Name "$($SpecialComputerObj2.Name)" -Description "$($SpecialComputerObj2.Description) ($($SpecialComputerObj2.Name))" -DisplayName "$($SpecialComputerObj2.Name)" -SAMAccountName "$($SpecialComputerObj2.Name)" -verbose -AccountPassword $(ConvertTo-SecureString "!$0meRand0JunkH3r3!!5" -AsPlainText -Force)
    }
    Else
    {
        Write-Host "::             -- Computer object '$($SpecialComputerObj2.Name)' already exists!" -ForegroundColor Yellow
    }


    #------------------------------------------------------------------------------
    #
    # This computer object is for having objects in a more restricted OU.
    #
    Write-Host ""
    Write-Host ""
    $SpecialComputerObj3

    Write-Host ""
    Write-Host "::     -- Checking for computer object existence: [$($SpecialComputerObj3.Name)]" -ForegroundColor Yellow

    If (!(Get-ADComputer -LDAPFilter "(CN=$($SpecialComputerObj3.Name))"))
    {
        Write-Host "::        -- 'OU=$($SpecialOuObj.Name)'  -->>  Creating computer object '$($SpecialComputerObj3.Name)'..." -ForegroundColor Cyan
        New-ADComputer -Path "OU=$($SpecialOuObj.Name),$DomainDN" -Name "$($SpecialComputerObj3.Name)" -Description "$($SpecialComputerObj3.Description) ($($SpecialComputerObj3.Name))" -DisplayName "$($SpecialComputerObj3.Name)" -SAMAccountName "$($SpecialComputerObj3.Name)" -verbose -AccountPassword $(ConvertTo-SecureString "!$0meRand0JunkH3r3!!6" -AsPlainText -Force)
    }
    Else
    {
        Write-Host "::             -- Computer object '$($SpecialComputerObj3.Name)' already exists!" -ForegroundColor Yellow
    }

}

#
#-------------------------------------------------------------------------------
################################################################################






################################################################################
#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                                 " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- AD SITE STUFF: CREATE/ADD/UPDATE AD SITE [$ADSite001] ----                 " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                                 " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
Write-Host ":: - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" -ForegroundColor Gray
Write-Host "::" -ForegroundColor Gray
Write-Host ":: Performing some more AD Sites and Services settings and changes..." -ForegroundColor Gray
Write-Host "::" -ForegroundColor Gray
Write-Host ":: Adding/updating an AD site [$($ADSiteObj001.Name)]." -ForegroundColor Gray
Write-Host ":: Adding/updating an AD subnet [$($ADSiteObj001.SubnetName)] and assigning to this site." -ForegroundColor Gray
Write-Host ":: Adding/updating an AD site link [$($ADSite_DefaultSite.Name) -- $($ADSiteObj001.Name)]." -ForegroundColor Gray
Write-Host "::" -ForegroundColor Gray
Write-Host ":: - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -" -ForegroundColor Gray
Write-Host ""

# Get current sites...
Write-Host "::"
Write-Host ":: ---  Listing of all AD sites:"
$ADSitesList = Get-ADReplicationSite -Filter * | Select Name
$ADSitesList

$ADSite_DefaultSite = Get-ADReplicationSite -Filter "Name -Like 'Default-First-*'" | Select Name
#$($ADSite_DefaultSite.Name)

Write-Host "::"
Write-Host ":: --- Checking for existence of AD site [$($ADSiteObj001.Name)]..."
$AdRepSite = $Null
If (!($AdRepSite = Get-AdReplicationSite -Filter "Name -Like '$($ADSiteObj001.Name)'"))
{
    Write-Host "::     --- Creating new AD replication site..." -ForegroundColor Cyan
    New-ADReplicationSite -Name "$($ADSiteObj001.Name)" -Description "$($ADSiteObj001.Description)" -OtherAttributes @{'Location'="$($ADSiteObj001.Location)"} -Verbose
    Start-Sleep 3

    Write-Host "::         --- Set/replace AD replication site [$($ADSiteObj001.Name)] Location to [$($ADSiteObj001.Location)]..." -ForegroundColor Cyan
    Set-ADReplicationSite -Identity "$($ADSiteObj001.Name)" -Replace @{'Location'="$($ADSiteObj001.Location)"} -Verbose
}
Else
{
    Write-Host "::     --- AD replication site [$($ADSiteObj001.Name)] already exists!" -ForegroundColor Magenta
    $AdRepSite

    Write-Host "::         --- Set/replace AD replication site [$($ADSiteObj001.Name)] Location to [$($ADSiteObj001.Location)]..." -ForegroundColor Cyan
    Set-ADReplicationSite -Identity "$($ADSiteObj001.Name)" -Replace @{'Location'="$($ADSiteObj001.Location)"} -Verbose
}

# Get current sites...
Write-Host ""
Write-Host ""
Write-Host ":: Listing of all AD sites:"
Get-AdReplicationSite -Filter * | Select Name

Write-Host ""
Write-Host ""
Write-Host ":: --- Checking for existence of AD replication subnet [$($ADSiteObj001.SubnetName)]..."
$AdRepSubnet = $Null
If (!($AdRepSubnet = Get-ADReplicationSubnet -Filter "Name -Like '$($ADSiteObj001.SubnetName)'"))
{
    Write-Host "::     --- Creating new AD replication subnet..." -ForegroundColor Cyan
    New-ADReplicationSubnet -Name "$($ADSiteObj001.SubnetName)" -Site "$($ADSiteObj001.Name)" -Verbose
    Start-Sleep 3

    Write-Host "::         --- Set/replace subnet [$($ADSiteObj001.SubnetName)] site to [$($ADSiteObj001.Name)]..." -ForegroundColor Cyan
    Set-ADReplicationSubnet -Identity "$($ADSiteObj001.SubnetName)" -Site "$($ADSiteObj001.Name)" -Verbose # could site to reassign subnet

    Write-Host "::         --- Set/replace Description on subnet..." -ForegroundColor Cyan
    Set-ADReplicationSubnet -Identity "$($ADSiteObj001.SubnetName)" -Description "$($ADSiteObj001.SubnetDescription)" -Verbose
    Write-Host "::         --- Set/replace Location on subnet..." -ForegroundColor Cyan
    Set-ADReplicationSubnet -Identity "$($ADSiteObj001.SubnetName)" -Location "$($ADSiteObj001.SubnetLocation)" -Verbose
    Write-Host "::         --- Replacing Description on subnet..." -ForegroundColor Cyan
    Set-ADReplicationSubnet -Identity "$($ADSiteObj001.SubnetName)" -Replace @{'Description'="$($ADSiteObj001.SubnetDescription)"} -Verbose
}
Else 
{
    Write-Host "::     --- AD replication subnet [$($ADSiteObj001.SubnetName)] already exists!" -ForegroundColor Magenta
    $AdRepSubnet

    Write-Host "::         --- Set/replace subnet [$($ADSiteObj001.SubnetName)] site to [$($ADSiteObj001.Name)]..." -ForegroundColor Cyan
    Set-ADReplicationSubnet -Identity "$($ADSiteObj001.SubnetName)" -Site "$($ADSiteObj001.Name)" -Verbose # could site to reassign subnet

    Write-Host "::         --- Set/replace Description on subnet..." -ForegroundColor Cyan
    Set-ADReplicationSubnet -Identity "$($ADSiteObj001.SubnetName)" -Description "$($ADSiteObj001.SubnetDescription)" -Verbose
    Write-Host "::         --- Set/replace Location on subnet..." -ForegroundColor Cyan
    Set-ADReplicationSubnet -Identity "$($ADSiteObj001.SubnetName)" -Location "$($ADSiteObj001.SubnetLocation)" -Verbose
    Write-Host "::         --- Replacing Description on subnet..." -ForegroundColor Cyan
    Set-ADReplicationSubnet -Identity "$($ADSiteObj001.SubnetName)" -Replace @{'Description'="$($ADSiteObj001.SubnetDescription)"} -Verbose
}

Write-Host ""
Write-Host ""
Write-Host " --- List all AD subnets with a location that starts with 'USA'..."
Get-ADReplicationSubnet -Filter {Location -like "USA*"} -Verbose

Write-Host ""
Write-Host ""
Write-Host " --- List all AD subnets with a location that contains 'labs'..."
Get-ADReplicationSubnet -Filter {Location -like "*labs*"} -Verbose

Write-Host ""
Write-Host ""
Write-Host ":: --- Add/Update AD Replication Line [$($ADSite_DefaultSite.Name) -- $($ADSiteObj001.Name)]..."
$AdRepSiteLink = $Null
If (!($AdRepSiteLink = Get-ADReplicationSiteLink -Filter "Name -Like '$($ADSite_DefaultSite.Name) -- $($ADSiteObj001.Name)'"))
{
    Write-Host "::     --- Creating new AD replication site link..." -ForegroundColor Cyan
    New-ADReplicationSiteLink -Name "$($ADSite_DefaultSite.Name) -- $($ADSiteObj001.Name)" -SitesIncluded $ADSite_DefaultSite.Name,$($ADSiteObj001.Name) -Verbose
    Start-Sleep 3

    Write-Host "::         --- Set/replace Description and Site Cost on site link..." -ForegroundColor Cyan
    Set-ADReplicationSiteLink -Identity "$($ADSite_DefaultSite.Name) -- $($ADSiteObj001.Name)" -Cost 22 -Description "Site link for [$($ADSiteObj001.Name)]" -Verbose
    Write-Host "::         --- Set/replace ReplicationFrequencyInMinutes on site link..." -ForegroundColor Cyan
    Set-ADReplicationSiteLink -Identity "$($ADSite_DefaultSite.Name) -- $($ADSiteObj001.Name)" -ReplicationFrequencyInMinutes 18 -Verbose
}
Else
{
    Write-Host "::     --- AD replication site link [$($ADSite_DefaultSite.Name) -- $($ADSiteObj001.Name)] already exists!" -ForegroundColor Magenta
    $AdRepSiteLink

    Write-Host "::         --- Set/replace Description and Site Cost on site link..." -ForegroundColor Cyan
    Set-ADReplicationSiteLink -Identity "$($ADSite_DefaultSite.Name) -- $($ADSiteObj001.Name)" -Cost 22 -Description "Site link for [$($ADSiteObj001.Name)]" -Verbose
    Write-Host "::         --- Set/replace ReplicationFrequencyInMinutes on site link..." -ForegroundColor Cyan
    Set-ADReplicationSiteLink -Identity "$($ADSite_DefaultSite.Name) -- $($ADSiteObj001.Name)" -ReplicationFrequencyInMinutes 18 -Verbose
}

Write-Host ""
Write-Host ""

####
If (0 -eq 1)
{
    # just using this section for debugging and testing
    Remove-ADReplicationSiteLink -Identity "$($ADSite_DefaultSite.Name) -- $($ADSiteObj001.Name)" -Confirm:$False -Verbose
    Remove-ADReplicationSubnet -Identity "$($ADSiteObj001.SubnetName)" -Confirm:$False -Verbose
    Remove-ADReplicationSite -Identity "$($ADSiteObj001.Name)" -Confirm:$False -Verbose
}
####


#------------------------------------------------------------------------------
################################################################################






################################################################################
#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                                 " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- GROUP OBJECT STUFF: SET UP GROUP FOR LAB USERS ($($SpecialLabUsers.Name)) ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                                 " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

# This is our Lab Users group where we have multiple group members...

$GroupObj = $null

If (!($GroupObj = Get-ADGroup -LDAPFilter "(&(objectClass=group)(cn=$($SpecialLabUsers.Name)))"))
{
    Write-Host ""
    Write-Host "::    -- Creating group '$($SpecialLabUsers.Name)'..." -ForegroundColor Cyan
    New-ADGroup -Name "$($SpecialLabUsers.Name)" -SamAccountName $($SpecialLabUsers.SamAccountName) -GroupCategory $($SpecialLabUsers.GroupCategory) -GroupScope $($SpecialLabUsers.GroupScope) -DisplayName "$($SpecialLabUsers.DisplayName)" -Path "$($SpecialLabUsers.Path)" -Description "$($SpecialLabUsers.Description)" -Verbose

    Start-Sleep 15

    # Populate with users using the beginning text from the $GenericAdmin1 and $GenericAdmin2 names...

    $GroupObj = $null
    $GroupObj = Get-ADGroup -LDAPfilter "(&(objectCategory=group)(cn=$($SpecialLabUsers.Name)))" -ErrorAction SilentlyContinue -Verbose
    $MembersToAdd = $null
    $MembersToAdd = Get-ADUser -LDAPfilter "(&(objectCategory=person)(cn=$($($GenericAdmin1.Name).Substring(0,5))*))" -ErrorAction SilentlyContinue -Verbose
    Write-Host "::    -- Adding members '$($($GenericAdmin1.Name).Substring(0,5))*' to group '$($SpecialLabAdmins.Name)'..." -ForegroundColor Cyan
    Add-ADGroupMember -Identity $GroupObj.DistinguishedName -Members $MembersToAdd -ErrorAction SilentlyContinue -Verbose
    $MembersToAdd = $null
    $MembersToAdd = Get-ADUser -LDAPfilter "(&(objectCategory=person)(cn=$($($GenericAdmin2.Name).Substring(0,5))*))" -ErrorAction SilentlyContinue -Verbose
    Write-Host "::    -- Adding members '$($($GenericAdmin2.Name).Substring(0,5))*' to group '$($SpecialLabAdmins.Name)'..." -ForegroundColor Cyan
    Add-ADGroupMember -Identity $GroupObj.DistinguishedName -Members $MembersToAdd -ErrorAction SilentlyContinue -Verbose
    $MembersToAdd = $null
    $MembersToAdd = Get-ADUser -LDAPfilter "(&(objectCategory=person)(cn=$($($AdminUser0.Name).Substring(0,5))*))" -ErrorAction SilentlyContinue -Verbose
    Write-Host "::    -- Adding members '$($($GenericAdmin2.Name).Substring(0,5))*' to group '$($SpecialLabAdmins.Name)'..." -ForegroundColor Cyan
    Add-ADGroupMember -Identity $GroupObj.DistinguishedName -Members $MembersToAdd -ErrorAction SilentlyContinue -Verbose
    $MembersToAdd = $null
    $MembersToAdd = Get-ADUser -LDAPfilter "(&(objectCategory=person)(cn=$($($DemoUser1.Name).Substring(0,5))*))" -ErrorAction SilentlyContinue -Verbose
    Write-Host "::    -- Adding members '$($($GenericAdmin2.Name).Substring(0,5))*' to group '$($SpecialLabAdmins.Name)'..." -ForegroundColor Cyan
    Add-ADGroupMember -Identity $GroupObj.DistinguishedName -Members $MembersToAdd -ErrorAction SilentlyContinue -Verbose
    $MembersToAdd = $null
    $GroupObj = $null

    Write-Host ":: Force replication after 10 second pause..." -ForegroundColor Yellow
    Start-Sleep 10
    If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
    If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}
}
Else
{
    Write-Host ""
    Write-Host "::    -- Updating group '$($SpecialLabUsers.Name)'..." -ForegroundColor Cyan
    $GroupObj
    Set-ADGroup -Identity "$($GroupObj.DistinguishedName)" -GroupCategory $($SpecialLabUsers.GroupCategory) -GroupScope $($SpecialLabUsers.GroupScope) -Description "$($SpecialLabUsers.Description)" -Verbose

    # Populate with users using the beginning text from the $GenericAdmin1 and $GenericAdmin2 names...

    $MembersToAdd = $null
    $MembersToAdd = Get-ADUser -LDAPfilter "(&(objectCategory=person)(cn=$($($GenericAdmin1.Name).Substring(0,5))*))" -ErrorAction SilentlyContinue -Verbose
    Write-Host "::    -- Adding members '$($($GenericAdmin1.Name).Substring(0,5))*' to group '$($SpecialLabAdmins.Name)'..." -ForegroundColor Cyan
    Add-ADGroupMember -Identity $GroupObj.DistinguishedName -Members $MembersToAdd -ErrorAction SilentlyContinue -Verbose
    $MembersToAdd = $null
    $MembersToAdd = Get-ADUser -LDAPfilter "(&(objectCategory=person)(cn=$($($GenericAdmin2.Name).Substring(0,5))*))" -ErrorAction SilentlyContinue -Verbose
    Write-Host "::    -- Adding members '$($($GenericAdmin2.Name).Substring(0,5))*' to group '$($SpecialLabAdmins.Name)'..." -ForegroundColor Cyan
    Add-ADGroupMember -Identity $GroupObj.DistinguishedName -Members $MembersToAdd -ErrorAction SilentlyContinue -Verbose
    $MembersToAdd = $null

    Write-Host ":: Force replication after 10 second pause..." -ForegroundColor Yellow
    Start-Sleep 10
    If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
    If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}
}




#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                                   " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- GROUP OBJECT STUFF: SET UP GROUP FOR LAB ADMINS ($($SpecialLabAdmins.Name)) ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                                   " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

# This is our Lab Admins group where we have multiple group members...

#
# This is our special admins group to use to demo the AUTO UNDO feature with a notification rule:
#       Set up the notification rule after this group is created.
#
# $DomainNETBIOS\$($SpecialLabAdmins.SamAccountName)
#
$GroupObj = $null
If (!($GroupObj = Get-ADGroup -LDAPFilter "(&(objectClass=group)(cn=$($SpecialLabAdmins.Name)))"))
{
    Write-Host ""
    Write-Host "::    -- Creating group '$($SpecialLabAdmins.Name)'..." -ForegroundColor Cyan
    New-ADGroup -Name "$($SpecialLabAdmins.Name)" -SamAccountName $($SpecialLabAdmins.SamAccountName) -GroupCategory $($SpecialLabAdmins.GroupCategory) -GroupScope $($SpecialLabAdmins.GroupScope) -DisplayName "$($SpecialLabAdmins.DisplayName)" -Path "$($SpecialLabAdmins.Path)" -Description "$($SpecialLabAdmins.Description)" -Verbose
    Start-Sleep 15

    # Populate with users...

    $GroupObj = $null
    $GroupObj = Get-ADGroup -LDAPfilter "(&(objectCategory=group)(cn=$($SpecialLabAdmins.Name)))" -ErrorAction SilentlyContinue -Verbose
    $MembersToAdd = $null
    $MembersToAdd = Get-ADUser -LDAPfilter "(&(objectCategory=person)(cn=App Admin*))" -ErrorAction SilentlyContinue -Verbose
    Write-Host "::    -- Adding members to group '$($SpecialLabAdmins.Name)'..." -ForegroundColor Cyan
    Add-ADGroupMember -Identity $GroupObj.DistinguishedName -Members $MembersToAdd -ErrorAction SilentlyContinue -Verbose
    $GroupObj = $null
    $MembersToAdd = $null
}
Else
{
    # Because we later remove all group membership and DSP may not have an auto-undo rule set, 
    # we need to make sure that this group is properly populated.

    Write-Host ""
    Write-Host "::    -- Updating group '$($SpecialLabAdmins.Name)'..." -ForegroundColor Cyan
    $GroupObj
    Set-ADGroup -Identity "$($GroupObj.DistinguishedName)" -GroupCategory $($SpecialLabUsers.GroupCategory) -GroupScope $($SpecialLabUsers.GroupScope) -Description "$($SpecialLabUsers.Description)" -Verbose

    # Populate with users...

    $MembersToAdd = $null
    $MembersToAdd = Get-ADUser -LDAPfilter "(&(objectCategory=person)(cn=App Admin*))" -ErrorAction SilentlyContinue
    Write-Host "::    -- Adding members to group '$($GroupObj.Name)'..." -ForegroundColor Cyan
    Add-ADGroupMember -Identity "$($GroupObj.DistinguishedName)" -Members $MembersToAdd.DistinguishedName -ErrorAction SilentlyContinue -Verbose
    $MembersToAdd = $null

    Write-Host ":: Force replication after 10 second pause..." -ForegroundColor Yellow
    Start-Sleep 10
    If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
    If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}
}





#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                               " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- GROUP OBJECT STUFF: SET UP GROUP FOR HELPDESK OPS ($($HelpdeskOps.Name)) ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                               " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

#
# $DomainNETBIOS\$($HelpdeskOps.SamAccountName)
#
$GroupObj = $null
If (!($GroupObj = Get-ADGroup -LDAPFilter "(&(objectClass=group)(cn=$($HelpdeskOps.Name)))"))
{
    Write-Host ""
    Write-Host "::    -- Creating group '$($HelpdeskOps.Name)'..." -ForegroundColor Cyan
    New-ADGroup -Name "$($HelpdeskOps.Name)" -SamAccountName $($HelpdeskOps.SamAccountName) -GroupCategory $($HelpdeskOps.GroupCategory) -GroupScope $($HelpdeskOps.GroupScope) -DisplayName "$($HelpdeskOps.DisplayName)" -Path "$($HelpdeskOps.Path)" -Description "$($HelpdeskOps.Description)" -Verbose
    Start-Sleep 15

    # Populate with users...

    $GroupObj = $null
    $GroupObj = Get-ADGroup -LDAPfilter "(&(objectCategory=group)(cn=$($HelpdeskOps.Name)))" -ErrorAction SilentlyContinue -Verbose
    $MembersToAdd = $null
    $MembersToAdd = Get-ADUser -LDAPfilter "(&(objectCategory=person)(cn=App Admin*))" -ErrorAction SilentlyContinue -Verbose
    Write-Host "::    -- Adding members to group '$($HelpdeskOps.Name)'..." -ForegroundColor Cyan
    Add-ADGroupMember -Identity $GroupObj.DistinguishedName -Members $MembersToAdd -ErrorAction SilentlyContinue -Verbose
    $GroupObj = $null
    $MembersToAdd = $null
}
Else
{
    # Because we later remove all group membership and DSP may not have an auto-undo rule set, 
    # we need to make sure that this group is properly populated.

    Write-Host ""
    Write-Host "::    -- Updating group '$($HelpdeskOps.Name)'..." -ForegroundColor Cyan
    $GroupObj
    Set-ADGroup -Identity "$($GroupObj.DistinguishedName)" -GroupCategory $($HelpdeskOps.GroupCategory) -GroupScope $($HelpdeskOps.GroupScope) -Description "$($HelpdeskOps.Description)" -Verbose

    # Populate with users...

    $MembersToAdd = $null
    $MembersToAdd = Get-ADUser -LDAPfilter "(&(objectCategory=person)(cn=App Admin*))" -ErrorAction SilentlyContinue
    Write-Host "::    -- Adding members to group '$($GroupObj.Name)'..." -ForegroundColor Cyan
    Add-ADGroupMember -Identity "$($GroupObj.DistinguishedName)" -Members $MembersToAdd.DistinguishedName -ErrorAction SilentlyContinue -Verbose
    $MembersToAdd = $null

    Write-Host ":: Force replication after 10 second pause..." -ForegroundColor Yellow
    Start-Sleep 10
    If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
    If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}
}







#--------------------------------------------------------------------------------
# Group for pizza parties to show nested groups, and potentially circular nesting
#
#    $PizzaParty = New-Object PSObject -Property $hashtable
#    $PizzaPartyGroup = 'Pizza Party Group'
#

$GroupObj = $null
If (!($GroupObj = Get-ADGroup -LDAPFilter "(&(objectClass=group)(cn=$($PizzaParty.Name)))"))
{
    Write-Host ""
    Write-Host "::    -- Creating group '$($PizzaParty.Name)'..." -ForegroundColor Cyan
    New-ADGroup -Name "$($PizzaParty.Name)" -SamAccountName $($PizzaParty.SamAccountName) -GroupCategory $($PizzaParty.GroupCategory) -GroupScope $($PizzaParty.GroupScope) -DisplayName "$($PizzaParty.DisplayName)" -Path "$($PizzaParty.Path)" -Description "$($PizzaParty.Description)" -Verbose
    Start-Sleep 15

    # Populate with users...

    $GroupObj = $null
    $GroupObj = Get-ADGroup -LDAPfilter "(&(objectCategory=group)(cn=$($PizzaParty.Name)))" -ErrorAction SilentlyContinue -Verbose

    # Populate with group object (self!!!)...
    $MembersToAdd = $null
    $MembersToAdd = Get-ADGroup -LDAPfilter "(&(objectCategory=group)(cn=Pizza*))" -ErrorAction SilentlyContinue -Verbose
    Write-Host "::    -- Adding members to group '$($GroupObj.Name)'...   $($MembersToAdd.Name)" -ForegroundColor Cyan
    Add-ADGroupMember -Identity $GroupObj.DistinguishedName -Members $MembersToAdd -ErrorAction SilentlyContinue -Verbose
    Write-Host "::"

    # Populate with group object (for circular nesting)...
    $MembersToAdd = $null
    $MembersToAdd = Get-ADGroup -LDAPfilter "(&(objectCategory=group)(cn=Party Planners*))" -ErrorAction SilentlyContinue -Verbose
    Write-Host "::    -- Adding members to group '$($GroupObj.Name)'...   $($MembersToAdd.Name)" -ForegroundColor Cyan
    Add-ADGroupMember -Identity $GroupObj.DistinguishedName -Members $MembersToAdd -ErrorAction SilentlyContinue -Verbose
    Write-Host "::"

    # Populate with user objects...
    #$MembersToAdd = $null
    #$MembersToAdd = Get-ADUser -LDAPfilter "(&(objectCategory=person)(cn=App Admin*))" -ErrorAction SilentlyContinue -Verbose
    #Write-Host "::    -- Adding members to group '$($GroupObj.Name)'...   $($MembersToAdd.Name)" -ForegroundColor Cyan
    #Add-ADGroupMember -Identity $GroupObj.DistinguishedName -Members $MembersToAdd -ErrorAction SilentlyContinue -Verbose

    # Populate with user objects...
    $MembersToAdd = $null
    $MembersToAdd = Get-ADUser -LDAPfilter "(objectCategory=person)" -SearchBase "OU=Lab Users,$adDomainDN" -ErrorAction SilentlyContinue -Verbose
    Write-Host "::    -- Adding members to group '$($GroupObj.Name)'...   $($MembersToAdd.Name)" -ForegroundColor Cyan
    Add-ADGroupMember -Identity "$($GroupObj.DistinguishedName)" -Members $MembersToAdd.DistinguishedName -ErrorAction SilentlyContinue -Verbose

    $GroupObj = $null
    $MembersToAdd = $null
}
Else
{
    Write-Host ""
    Write-Host "::    -- Updating group '$($GroupObj.Name)'..." -ForegroundColor Cyan
    $GroupObj
    Set-ADGroup -Identity "$($GroupObj.DistinguishedName)" -GroupCategory $($PizzaParty.GroupCategory) -GroupScope $($PizzaParty.GroupScope) -DisplayName "$($PizzaParty.DisplayName)" -Description "$($PizzaParty.Description)" -Verbose

    # Populate with group object (self!!!)...
    $MembersToAdd = $null
    $MembersToAdd = Get-ADGroup -LDAPfilter "(&(objectCategory=group)(cn=Pizza*))" -ErrorAction SilentlyContinue -Verbose
    Write-Host "::    -- Adding members to group '$($GroupObj.Name)'...   $($MembersToAdd.Name)" -ForegroundColor Cyan
    Add-ADGroupMember -Identity $GroupObj.DistinguishedName -Members $MembersToAdd -ErrorAction SilentlyContinue -Verbose
    Write-Host "::"

    # Populate with group object (for circular nesting)...
    $MembersToAdd = $null
    $MembersToAdd = Get-ADGroup -LDAPfilter "(&(objectCategory=group)(cn=Party Planners*))" -ErrorAction SilentlyContinue -Verbose
    Write-Host "::    -- Adding members to group '$($GroupObj.Name)'...   $($MembersToAdd.Name)" -ForegroundColor Cyan
    Add-ADGroupMember -Identity $GroupObj.DistinguishedName -Members $MembersToAdd -ErrorAction SilentlyContinue -Verbose
    Write-Host "::"

    # Populate with user objects...
    #$MembersToAdd = $null
    #$MembersToAdd = Get-ADUser -LDAPfilter "(&(objectCategory=person)(cn=App Admin*))" -ErrorAction SilentlyContinue
    #Write-Host "::    -- Adding members to group '$($GroupObj.Name)'...   $($MembersToAdd.Name)" -ForegroundColor Cyan
    #Add-ADGroupMember -Identity "$($GroupObj.DistinguishedName)" -Members $MembersToAdd.DistinguishedName -ErrorAction SilentlyContinue -Verbose

    # Populate with user objects...
    $MembersToAdd = $null
    $MembersToAdd = Get-ADUser -LDAPfilter "(objectCategory=person)" -SearchBase "OU=Lab Users,$adDomainDN" -ErrorAction SilentlyContinue -Verbose
    Write-Host "::    -- Adding members to group '$($GroupObj.Name)'...   $($MembersToAdd.Name)" -ForegroundColor Cyan
    Add-ADGroupMember -Identity "$($GroupObj.DistinguishedName)" -Members $MembersToAdd.DistinguishedName -ErrorAction SilentlyContinue -Verbose

    $GroupObj = $null
    $MembersToAdd = $null

    #Write-Host ":: Force replication after 10 second pause..." -ForegroundColor Yellow
    #Start-Sleep 10
    #If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
    #If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}
}

#
#------------------------------------------------------------------------------





#--------------------------------------------------------------------------------
# Group for party planners to show nested groups, and potentially circular nesting.
#  
# Making this group a member of Pizza Party, and make Pizza Party a member of this group.
#
#
#    $PartyPlannersGroup = New-Object PSObject -Property $hashtable
#    $PartyPlannersGroupName = 'Party Planners Group'
#

$GroupObj = $null
If (!($GroupObj = Get-ADGroup -LDAPFilter "(&(objectClass=group)(cn=$($PartyPlannersGroup.Name)))"))
{
    Write-Host ""
    Write-Host "::    -- Creating group '$($PartyPlannersGroup.Name)'..." -ForegroundColor Cyan
    New-ADGroup -Name "$($PartyPlannersGroup.Name)" -SamAccountName $($PartyPlannersGroup.SamAccountName) -GroupCategory $($PartyPlannersGroup.GroupCategory) -GroupScope $($PartyPlannersGroup.GroupScope) -DisplayName "$($PartyPlannersGroup.DisplayName)" -Path "$($PartyPlannersGroup.Path)" -Description "$($PartyPlannersGroup.Description)" -Verbose
    Start-Sleep 15

    # Populate with users...

    $GroupObj = $null
    $GroupObj = Get-ADGroup -LDAPfilter "(&(objectCategory=group)(cn=$($PartyPlannersGroup.Name)))" -ErrorAction SilentlyContinue -Verbose

    # Populate with group object...
    $MembersToAdd = $null
    $MembersToAdd = Get-ADGroup -LDAPfilter "(&(objectCategory=group)(cn=Pizza*))" -ErrorAction SilentlyContinue -Verbose
    Write-Host "::    -- Adding members to group '$($GroupObj.Name)'...   $($MembersToAdd.Name)" -ForegroundColor Cyan
    Add-ADGroupMember -Identity $GroupObj.DistinguishedName -Members $MembersToAdd -ErrorAction SilentlyContinue -Verbose
    Write-Host "::"

    # Populate with user objects...
    #$MembersToAdd = $null
    #$MembersToAdd = Get-ADUser -LDAPfilter "(&(objectCategory=person)(cn=App Admin*))" -ErrorAction SilentlyContinue -Verbose
    #Write-Host "::    -- Adding members to group '$($GroupObj.Name)'...   $($MembersToAdd.Name)" -ForegroundColor Cyan
    #Add-ADGroupMember -Identity $GroupObj.DistinguishedName -Members $MembersToAdd -ErrorAction SilentlyContinue -Verbose

    # Populate with user objects...
    $MembersToAdd = $null
    $MembersToAdd = Get-ADUser -LDAPfilter "(objectCategory=person)" -SearchBase "OU=Lab Users,$adDomainDN" -SearchScope OneLevel -ErrorAction SilentlyContinue -Verbose
    Write-Host "::    -- Adding members to group '$($GroupObj.Name)'...   $($MembersToAdd.Name)" -ForegroundColor Cyan
    Add-ADGroupMember -Identity "$($GroupObj.DistinguishedName)" -Members $MembersToAdd.DistinguishedName -ErrorAction SilentlyContinue -Verbose

    $GroupObj = $null
    $MembersToAdd = $null
}
Else
{
    Write-Host ""
    Write-Host "::    -- Updating group '$($GroupObj.Name)'..." -ForegroundColor Cyan
    $GroupObj
    Set-ADGroup -Identity "$($GroupObj.DistinguishedName)" -GroupCategory $($PartyPlannersGroup.GroupCategory) -GroupScope $($PartyPlannersGroup.GroupScope) -DisplayName "$($PartyPlannersGroup.DisplayName)" -Description "$($PartyPlannersGroup.Description)" -Verbose

    # Populate with group object...
    $MembersToAdd = $null
    $MembersToAdd = Get-ADGroup -LDAPfilter "(&(objectCategory=group)(cn=Pizza*))" -ErrorAction SilentlyContinue -Verbose
    Write-Host "::    -- Adding members to group '$($GroupObj.Name)'...   $($MembersToAdd.Name)" -ForegroundColor Cyan
    Add-ADGroupMember -Identity $GroupObj.DistinguishedName -Members $MembersToAdd -ErrorAction SilentlyContinue -Verbose
    Write-Host "::"

    # Populate with user objects...
    #$MembersToAdd = $null
    #$MembersToAdd = Get-ADUser -LDAPfilter "(&(objectCategory=person)(cn=App Admin*))" -ErrorAction SilentlyContinue
    #Write-Host "::    -- Adding members to group '$($GroupObj.Name)'...   $($MembersToAdd.Name)" -ForegroundColor Cyan
    #Add-ADGroupMember -Identity "$($GroupObj.DistinguishedName)" -Members $MembersToAdd.DistinguishedName -ErrorAction SilentlyContinue -Verbose

    # Populate with user objects...
    $MembersToAdd = $null
    $MembersToAdd = Get-ADUser -LDAPfilter "(objectCategory=person)" -SearchBase "OU=Lab Users,$adDomainDN" -SearchScope OneLevel -ErrorAction SilentlyContinue -Verbose
    Write-Host "::    -- Adding members to group '$($GroupObj.Name)'...   $($MembersToAdd.Name)" -ForegroundColor Cyan
    Add-ADGroupMember -Identity "$($GroupObj.DistinguishedName)" -Members $MembersToAdd.DistinguishedName -ErrorAction SilentlyContinue -Verbose

    $GroupObj = $null
    $MembersToAdd = $null

    #Write-Host ":: Force replication after 10 second pause..." -ForegroundColor Yellow
    #Start-Sleep 10
    #If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
    #If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}
}

#
#------------------------------------------------------------------------------







#------------------------------------------------------------------------------
# Special group to apply a FGPP to...

#    $SpecialAccountsObj = New-Object PSObject -Property $hashtable
#    $SpecialAccountsGroup = 'Special Accounts'

$GroupObj = $null
If (!($GroupObj = Get-ADGroup -LDAPFilter "(&(objectClass=group)(cn=$($SpecialAccountsObj.Name)))"))
{
    Write-Host ""
    Write-Host "::    -- Creating group '$($SpecialAccountsObj.Name)'..." -ForegroundColor Cyan
    New-ADGroup -Name "$($SpecialAccountsObj.Name)" -SamAccountName $($SpecialAccountsObj.SamAccountName) -GroupCategory $($SpecialAccountsObj.GroupCategory) -GroupScope $($SpecialAccountsObj.GroupScope) -DisplayName "$($SpecialAccountsObj.DisplayName)" -Path "$($SpecialAccountsObj.Path)" -Description "$($SpecialAccountsObj.Description)" -Verbose
    Start-Sleep 15

    # Populate with users...

    $GroupObj = $null
    $GroupObj = Get-ADGroup -LDAPfilter "(&(objectCategory=group)(cn=$($SpecialAccountsObj.Name)))" -ErrorAction SilentlyContinue -Verbose

    # Populate with user objects...
    $MembersToAdd = $null
    $MembersToAdd = Get-ADUser -LDAPfilter "(&(objectCategory=person)(cn=App Admin*))" -ErrorAction SilentlyContinue -Verbose
    Write-Host "::    -- Adding members to group '$($GroupObj.Name)'..." -ForegroundColor Cyan
    Add-ADGroupMember -Identity $GroupObj.DistinguishedName -Members $MembersToAdd -ErrorAction SilentlyContinue -Verbose
    $GroupObj = $null
    $MembersToAdd = $null
}
Else
{
    Write-Host ""
    Write-Host "::    -- Updating group '$($GroupObj.Name)'..." -ForegroundColor Cyan
    $GroupObj
    Set-ADGroup -Identity "$($GroupObj.DistinguishedName)" -GroupCategory $($SpecialAccountsObj.GroupCategory) -GroupScope $($SpecialAccountsObj.GroupScope) -DisplayName "$($SpecialAccountsObj.DisplayName)" -Description "$($SpecialAccountsObj.Description)" -Verbose

    # Populate with user objects...
    $MembersToAdd = $null
    $MembersToAdd = Get-ADUser -LDAPfilter "(&(objectCategory=person)(cn=App Admin*))" -ErrorAction SilentlyContinue
    Write-Host "::    -- Adding members to group '$($GroupObj.Name)'..." -ForegroundColor Cyan
    Add-ADGroupMember -Identity "$($GroupObj.DistinguishedName)" -Members $MembersToAdd.DistinguishedName -ErrorAction SilentlyContinue -Verbose
    $MembersToAdd = $null

    Write-Host ":: Force replication after 10 second pause..." -ForegroundColor Yellow
    Start-Sleep 10
    If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
    If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}
}





#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                                               " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- USER OBJECT STUFF - MAKE SURE OPS ADMIN IS ADDED TO 'ACCOUNT OPERATORS': ($($OpsAdmin1.Name)) ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                                               " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

# Ops Admin acct needs to have rights to change user attributes

$GroupObj = $null
If (!($GroupObj = Get-ADGroup -LDAPFilter "(&(objectClass=group)(cn=Account Operators))"))
{
    Write-Host ""
    Write-Host "::                                                             " -ForegroundColor Cyan -BackgroundColor Red
    Write-Host "::    -- ERROR!!!  'Account Operators' DOES NOT EXIST!!!!!!!   " -ForegroundColor Cyan -BackgroundColor Red
    Write-Host "::                                                             " -ForegroundColor Cyan -BackgroundColor Red
    Start-Sleep 15

    $GroupObj = $null
}
Else
{
    Write-Host ""
    Write-Host "::    -- Updating group 'Account Operator' membership: adding '$($OpsAdmin1.SamAccountName)'..." -ForegroundColor Cyan
    $GroupObj
    Write-Host ""

    # Populate with user objects...
    $MembersToAdd = $null
    $MembersToAdd = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($OpsAdmin1.SamAccountName)))" -Verbose -ErrorAction SilentlyContinue
    Write-Host "::    -- Adding members to group '$($GroupObj.Name)'..." -ForegroundColor Cyan
    Add-ADGroupMember -Identity "$($GroupObj.DistinguishedName)" -Members $MembersToAdd.DistinguishedName -ErrorAction SilentlyContinue -Verbose
    $MembersToAdd = $null

    Write-Host ":: Force replication after 10 second pause..." -ForegroundColor Yellow
    Start-Sleep 10
    If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
    If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}
}





#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- USER OBJECT STUFF - SET AND CHANGE USER ATTRIBUTES: DemoUser2 ($($DemoUser2.Name)) ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

#$DemoUserObj = Get-ADUser -LDAPFilter "(&(objectCategory=person)(sAMAccountName=$($DemoUser2.SamAccountName)))" -Verbose -ErrorAction SilentlyContinue

$UserObj = $null
If ($UserObj = Get-ADUser -LDAPFilter "(&(objectCategory=person)(sAMAccountName=$($DemoUser2.SamAccountName)))" -Verbose -ErrorAction SilentlyContinue)
{
    Write-Host ":: Get 'telephoneNumber' for user object '$($UserObj.Name)'..." -ForegroundColor Yellow
    $DemoUser2Phone = (Get-ADUser -Identity "$($UserObj.DistinguishedName)" -Properties telephoneNumber).telephoneNumber
    $DemoUser2Phone
    If ($DemoUser2Phone -ine $DemoUser2.TelephoneNumber)
    {
        Write-Host ":: Set 'telephoneNumber' for user object '$($UserObj.Name)' to '$($DemoUser2.TelephoneNumber)'..." -ForegroundColor Yellow
        Set-ADUser -Identity "$($UserObj.DistinguishedName)" -OfficePhone "$($DemoUser2.TelephoneNumber)"
        Write-Host ""
    }

    Write-Host ""
    Write-Host ":: Force replication after 15 second pause..." -ForegroundColor Yellow
    Start-Sleep 15
    If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
    If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}

    ## NOTE!! Should NOT be doing this in this manner!!!!!!
    ##        We should be first checking for values to determine IF they need to be changed!!!

    Write-Host ""
    Write-Host ":: Setting more attributes on user '$($UserObj.Name)' to simulate HR changes..." -ForegroundColor Yellow
    Write-Host ":: (pausing 5 seconds before setting more attributes)"
    Start-Sleep 5
    Write-Host ""
    Write-Host ":: Set 'telephoneNumber' for user object '$($UserObj.Name)' to '$($DemoUser2.TelephoneNumberAlt)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -OfficePhone "$($DemoUser2.TelephoneNumberAlt)" -Verbose
    Write-Host ":: Set 'city' for user object '$($UserObj.Name)' to 'Tribeca'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -City "Tribeca" -Verbose
    Write-Host ":: Set 'division' for user object '$($UserObj.Name)' to '$($DemoUser2.Division)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -division "$($DemoUser2.Division)" -Verbose
    Write-Host ":: Set 'employeeID' for user object '$($UserObj.Name)' to '$($DemoUser2.EmployeeID)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -employeeID "$($DemoUser2.EmployeeID)" -Verbose
    Write-Host ":: Set 'initials' for user object '$($UserObj.Name)' to '$($DemoUser2.Initials)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -initials "$($DemoUser2.Initials)" -Verbose
    Write-Host ":: Set 'company' for user object '$($UserObj.Name)' to '$($DemoUser2.Company)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -company "$($DemoUser2.Company)" -Verbose
    Write-Host ":: Set 'FAX' for user object '$($UserObj.Name)' to '$($DemoUser2.FAX)'..." -ForegroundColor Yellow # facsimileTelephoneNumber
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Fax "$($DemoUser2.FAX)" -Verbose
}





#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                                            " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- USER OBJECT STUFF - SET AND CHANGE USER ATTRIBUTES: DemoUser3 ($($DemoUser3.Name)) ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                                            " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

#$DemoUserObj = Get-ADUser -LDAPFilter "(&(objectCategory=person)(sAMAccountName=$($DemoUser3.SamAccountName)))" -Verbose -ErrorAction SilentlyContinue

If ($UserObj = Get-ADUser -LDAPFilter "(&(objectCategory=person)(sAMAccountName=$($DemoUser3.SamAccountName)))" -Verbose -ErrorAction SilentlyContinue)
{
    Write-Host ":: Get 'telephoneNumber' for user object '$($UserObj.Name)'..." -ForegroundColor Yellow
    $DemoUser3Phone = (Get-ADUser -Identity "$($UserObj.DistinguishedName)" -Properties telephoneNumber).telephoneNumber
    $DemoUser3Phone
    If ($DemoUser3Phone -ine $DemoUser3.TelephoneNumber)
    {
        Write-Host ":: Set 'telephoneNumber' for user object '$($UserObj.Name)' to '$($DemoUser3.TelephoneNumber)'..." -ForegroundColor Yellow
        Set-ADUser -Identity "$($UserObj.DistinguishedName)" -OfficePhone "$($DemoUser3.TelephoneNumber)"
        Write-Host ""
    }

    Write-Host ""
    Write-Host ":: Force replication after 5 second pause..." -ForegroundColor Yellow
    Start-Sleep 5
    If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
    If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}

    ## NOTE!! Should NOT be doing this in this manner!!!!!!
    ##        We should be first checking for values to determine IF they need to be changed!!!

    Write-Host ""
    Write-Host ":: Setting more attributes on user '$($UserObj.Name)' to simulate HR changes..." -ForegroundColor Yellow
    Write-Host ":: (pausing 15 seconds before setting more attributes)"
    Start-Sleep 15
    Write-Host ""
    Write-Host ":: Set 'telephoneNumber' for user object '$($UserObj.Name)' to '$($DemoUser3.TelephoneNumberAlt)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -OfficePhone "$($DemoUser3.TelephoneNumberAlt)" -Verbose
    Write-Host ":: Set 'city' for user object '$($UserObj.Name)' to 'Tribeca'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -City "Tribeca" -Verbose
    Write-Host ":: Set 'division' for user object '$($UserObj.Name)' to '$($DemoUser3.Division)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -division "$($DemoUser3.Division)" -Verbose
    Write-Host ":: Set 'employeeID' for user object '$($UserObj.Name)' to '$($DemoUser3.EmployeeID)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -employeeID "$($DemoUser3.EmployeeID)" -Verbose
    Write-Host ":: Set 'initials' for user object '$($UserObj.Name)' to '$($DemoUser3.Initials)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -initials "$($DemoUser3.Initials)" -Verbose
    Write-Host ":: Set 'company' for user object '$($UserObj.Name)' to '$($DemoUser3.Company)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -company "$($DemoUser3.Company)" -Verbose
    Write-Host ":: Set 'FAX' for user object '$($UserObj.Name)' to '$($DemoUser3.FAX)'..." -ForegroundColor Yellow # facsimileTelephoneNumber
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Fax "$($DemoUser3.FAX)" -Verbose
}





#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- USER OBJECT STUFF - SET AND CHANGE USER ATTRIBUTES: DemoUser4 ($($DemoUser4.Name)) ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

#$DemoUserObj = Get-ADUser -LDAPFilter "(&(objectCategory=person)(sAMAccountName=$($DemoUser4.SamAccountName)))" -Verbose -ErrorAction SilentlyContinue

If ($UserObj = Get-ADUser -LDAPFilter "(&(objectCategory=person)(sAMAccountName=$($DemoUser4.SamAccountName)))" -Verbose -ErrorAction SilentlyContinue)
{
    Write-Host ":: Get 'telephoneNumber' for user object '$($UserObj.Name)'..." -ForegroundColor Yellow
    $DemoUser4Phone = (Get-ADUser -Identity "$($UserObj.DistinguishedName)" -Properties telephoneNumber).telephoneNumber
    $DemoUser4Phone
    If ($DemoUser4Phone -ine $DemoUser4.TelephoneNumber)
    {
        Write-Host ":: Set 'telephoneNumber' for user object '$($UserObj.Name)' to '$($DemoUser4.TelephoneNumber)'..." -ForegroundColor Yellow
        Set-ADUser -Identity "$($UserObj.DistinguishedName)" -OfficePhone "$($DemoUser4.TelephoneNumber)"
        Write-Host ""
    }

    Write-Host ""
    Write-Host ":: Force replication after 10 second pause..." -ForegroundColor Yellow
    Start-Sleep 10
    If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
    If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}

    ## NOTE!! Should NOT be doing this in this manner!!!!!!
    ##        We should be first checking for values to determine IF they need to be changed!!!

    Write-Host ""
    Write-Host ":: Setting more attributes on user '$($UserObj.Name)' to simulate HR changes..." -ForegroundColor Yellow
    Write-Host ":: (pausing 15 seconds before setting more attributes)"
    Start-Sleep 15
    Write-Host ""
    Write-Host ":: Set 'telephoneNumber' for user object '$($UserObj.Name)' to '$($DemoUser4.TelephoneNumberAlt)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -OfficePhone "$($DemoUser4.TelephoneNumberAlt)" -Verbose
    Write-Host ":: Set 'city' for user object '$($UserObj.Name)' to 'Tribeca'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -City "Tribeca" -Verbose
    Write-Host ":: Set 'division' for user object '$($UserObj.Name)' to '$($DemoUser4.Division)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -division "$($DemoUser4.Division)" -Verbose
    Write-Host ":: Set 'employeeID' for user object '$($UserObj.Name)' to '$($DemoUser4.EmployeeID)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -employeeID "$($DemoUser4.EmployeeID)" -Verbose
    Write-Host ":: Set 'initials' for user object '$($UserObj.Name)' to '$($DemoUser4.Initials)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -initials "$($DemoUser4.Initials)" -Verbose
    Write-Host ":: Set 'company' for user object '$($UserObj.Name)' to '$($DemoUser4.Company)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -company "$($DemoUser4.Company)" -Verbose
    Write-Host ":: Set 'FAX' for user object '$($UserObj.Name)' to '$($DemoUser4.FAX)'..." -ForegroundColor Yellow # facsimileTelephoneNumber
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Fax "$($DemoUser4.FAX)" -Verbose
}








#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                                        " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- REPLICATION SUBNET STUFF: CHANGE ACTIVE DORECTORY SUBNET DESCRIPTIONS ----        " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::         (ADDED EARLIER IN SCRIPT)                                                      " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                                        " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
#
# These variables were set earlier in this script...
#$objADSubnet1 = '111.111.4.0/24'
#$objADSubnet2 = '111.111.5.0/24'
#
# Have to use Try-Catch due to unblockable error messages when subnet does not exist.
#
Try
{
    If (Get-ADReplicationSubnet -Identity $objADSubnet1 -ErrorAction Ignore)
    {
        Set-ADReplicationSubnet -Identity $objADSubnet1 -Description "Changed the subnet desctiption attribute!!" -ErrorAction SilentlyContinue -Verbose
    }
}
Catch
{
    Write-Host "::     Subnet '$objADSubnet1' does not exist!"
    Write-Host ""
    Write-Host ""
}
Try
{
    If (Get-ADReplicationSubnet -Identity $objADSubnet2 -ErrorAction SilentlyContinue)
    {
        Set-ADReplicationSubnet -Identity $objADSubnet2 -Description "Changed the subnet desctiption attribute!!" -ErrorAction SilentlyContinue -Verbose
    }

}
Catch
{
    Write-Host "::     Subnet '$objADSubnet2' does not exist!"
    Write-Host ""
    Write-Host ""
}









#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- ACL CHANGE STUFF - PART 1: 'OU=BAD OU' ----            " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
Write-Host ":: Change ACL on 'Bad OU' -denying- 'Everyone' to have 'deleteChild' permission..." -ForegroundColor Yellow
# example: OU=Bad OU,DC=f097-d01,DC=lab

$OU = $null
$objACL = $null
$OU = Get-ADOrganizationalUnit -LDAPFilter '(&(objectClass=OrganizationalUnit)(OU=Bad OU))'

#$User = [Security.Principal.NTAccount]'Everyone'
$GroupSID = [System.Security.Principal.SecurityIdentifier]'S-1-1-0' #Everyone Group

$objACL = Get-ACL "AD:\$OU"
$objACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($GroupSID,"DeleteChild,DeleteTree","Deny", 'None', [guid]'00000000-0000-0000-0000-000000000000')
#$objACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($GroupSID,"DeleteChild,DeleteTree","Allow", 'None', [guid]'00000000-0000-0000-0000-000000000000')
$objACL.AddAccessRule($objACE)
Set-acl -AclObject $objACL "AD:\$OU" -Verbose
$objACL = $null
$OU = $null
Start-Sleep 10





#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                       " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- GROUP STUFF: MODIFY GROUP MEMBERSHIP ($($SpecialLabUsers.Name)) ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                       " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
Write-Host ":: Remove group member 'App Admin III' from group '$($SpecialLabUsers.Name)'..." -ForegroundColor Yellow
$MemberToRemove = $null
$GroupName = $null
$MemberToRemove = get-aduser -LDAPfilter "(&(objectCategory=person)(cn=App Admin III))"
$GroupObj = Get-ADGroup -LDAPfilter "(&(objectCategory=group)(cn=$($SpecialLabUsers.Name)))"
Remove-ADGroupMember -Identity $GroupObj.DistinguishedName -Members $MemberToRemove.DistinguishedName -Confirm:$False -Verbose
$MemberToRemove = $null
$GroupObj = $null









#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- ACCOUNT LOCKOUT AND BRUTE FORCE ATTACK                 " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- Account to lockout: '$($DemoUser2.Name)'               " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ":: Purposely using incorrect password to lock out account for '$($DemoUser2.Name)'..." -ForegroundColor Yellow
Write-Host ""
1..50 | % { 
    write "   -- logon attempt $_"
    #net use \\$DomainDNSRoot\netlogon /user:"$DomainDNSRoot\$($DemoUser2.SamAccountName)" nopass

    #$ErrorActionPreference="continue"
    # The " > $null 2>&1" is to send good and error output to null because we do not care and we
    # are TRYING to generate errors to cause an account lockout.
    #
    Invoke-Command -ScriptBlock {
        net use \\$DomainDNSRoot\netlogon /user:"$DomainDNSRoot\$($DemoUser2.SamAccountName)" nopass  > $null 2>&1
    } -ErrorAction SilentlyContinue

  }
Write-Host ""
Write-Host ":: After 20 attempts with incorrect password the account should be locked out." -ForegroundColor Yellow
Write-Host ""

#get-aduser -identity $($DemoUser2.SamAccountName) -properties * | select accountexpirationdate, accountexpires, accountlockouttime, badlogoncount, padpwdcount, lastbadpasswordattempt, lastlogondate, lockedout, passwordexpired, passwordlastset, pwdlastset | format-list
get-aduser -identity $($DemoUser2.SamAccountName) -properties * | select displayName, samaccountname, lockedOut, accountlockouttime, badlogoncount, padpwdcount, lastbadpasswordattempt, lastlogondate, passwordlastset, pwdlastset | format-list

Write-Host ""
Write-Host ""
Write-Host ""







#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                              " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- PASSWORD SPRAY ATTACK ----                              " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                              " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: Chose 5 users from OU=TEST and attempt to log onto a share   " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: with 10 different passwords to trigger the attack indicator. " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                              " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::"
Write-Host "::"
Write-Host ":: Try the multiple passwords against some user accounts..." -ForegroundColor Yellow
Write-Host "::"
Write-Host "::  Attempting against users in $($OUforTestUsers)" -ForegroundColor Yellow
Write-Host "::"
Write-Host "::"

# Run X number of passwords against Y number of users...


# Target domain or service
$PWSdomain = "$DomainDNSRoot"

# Chose 5 user accounts from OU=TEST
$TestOuUsers = Get-ADUser -Filter * -SearchBase $OUforTestUsers | Select-object -First 5 SamAccountName

# Loop $i number of iterations
for ($i = 1; $i -le 10; $i++) {
    $PWSpassword = "SomeP@sswordGu3ss!$($i)"
    Write-Host " password spray loop # $i     (password = '$PWSpassword')" -ForegroundColor Cyan -BackgroundColor DarkYellow

    foreach ($user in $TestOuUsers) {
        Write-Output "password spray $($user.SamAccountName) with bad password $PWSpassword"

        try {
            $securePassword = ConvertTo-SecureString $PWSpassword -AsPlainText -Force
            $cred = New-Object System.Management.Automation.PSCredential ("$($user.SamAccountName)", $securePassword)

            # Attempt to access a known resource (e.g., a UNC path or service) using
            # session-only PSdrive.
            # (Not sure why, by using the user format "\\d01.local\username" does not seem to create events)
            New-PSDrive -Name "TempShare" -PSProvider FileSystem -Root $UNCPath -Credential $cred -ErrorAction Ignore -Verbose
        
        } catch {
            Write-Error "Error testing $($user.SamAccountName)"
        }

        Remove-PSDrive -Name "TempShare" -ErrorAction Ignore  # remove just in case it worked
    }

}
Write-Host "`n`n`n"







#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- GPO STUFF: 'Questionable GPO' ----                     " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

#Create GPO if it doesn't exist...
Write-Host ":: Create GPO 'Questionable GPO' if it does not exist..." -ForegroundColor Yellow
New-GPO -Name 'Questionable GPO' -Comment 'This is a GPO with some questionable settings for testing  2022-02-15' -ErrorAction SilentlyContinue

Start-Sleep 10
$GPO = $null
$GPO = Get-GPO -Name 'Questionable GPO'
Write-Host ""
Write-Host ""

Write-Host ":: Force replication after 15 second pause..." -ForegroundColor Yellow
Start-Sleep 15
If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}

Write-Host ""
Write-Host ":: Attempting to UN-link GPO 'Questionable GPO' from 'Bad OU' to show a gpLink change..." -ForegroundColor Yellow
Write-Host ""

$objOU4GPO = Get-ADOrganizationalUnit -LDAPFilter "((objectClass=organizationalUnit)(OU=Bad OU))" -Verbose
$objOU4GPO

$objSpecialGPO = Get-GPO -Name "Questionable GPO" -Verbose
$objSpecialGPO

Write-Host ":: (Just force remove without checking existence and ignore errors.)" -ForegroundColor Yellow
Write-Host "Remove-GPLink -Name $objSpecialGPO.DisplayName -Target ""$($objOU4GPO.DistinguishedName)"" -Verbose -ErrorAction Ignore"
Remove-GPLink -Name $objSpecialGPO.DisplayName -Target "$($objOU4GPO.DistinguishedName)" -Verbose -ErrorAction SilentlyContinue #| Out-Null

Write-Host ""
Write-Host ":: Waiting 20 seconds for the GPO unlinking to replicate..." -ForegroundColor Yellow
Write-Host ""
Start-Sleep 20
Write-Host ""
Write-Host ":: Later in this script, this GPO will get linked to the 'Bad OU' OU." -ForegroundColor Yellow
Write-Host ""
Write-Host ""
Write-Host ""
Write-Host ":: Get the 'BlockDomainPicturePassword' value..." -ForegroundColor Yellow
Get-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName BlockDomainPicturePassword -Verbose -ErrorAction SilentlyContinue
Write-Host ":: Set the 'BlockDomainPicturePassword' value to '1' in '$($GPO.DisplayName)'..." -ForegroundColor Yellow
Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName BlockDomainPicturePassword -Type DWord -Value 1 -Verbose

Write-Host ":: Force replication after 20 second pause..." -ForegroundColor Yellow
Start-Sleep 20
If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}

Write-Host ":: Set the 'BlockDomainPicturePassword' value to '0' in '$($GPO.DisplayName)'..." -ForegroundColor Yellow
Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName BlockDomainPicturePassword -Type DWord -Value 0



Write-Host "`n`n"
Write-Host "::                                                                        " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- MORE GPO STUFF: Questionable GPO ----                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                        " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
Write-Host ":: Get the 'CreateEncryptedOnlyTickets' value..." -ForegroundColor Yellow
Get-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\policies\Microsoft\Windows NT\Terminal Services" -ValueName CreateEncryptedOnlyTickets -Verbose -ErrorAction SilentlyContinue
Write-Host ":: Set the 'CreateEncryptedOnlyTickets' value to '1' in 'Questionable GPO'..." -ForegroundColor Yellow
Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\policies\Microsoft\Windows NT\Terminal Services" -ValueName CreateEncryptedOnlyTickets -Type DWord -Value 1 -Verbose

Write-Host ":: Force replication after 20 second pause..." -ForegroundColor Yellow
Start-Sleep 20
If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}

Start-Sleep 20  # waiting a little extra for replication to complete...
Write-Host ":: Set the 'CreateEncryptedOnlyTickets' value to '0' in '$($GPO.DisplayName)'..." -ForegroundColor Yellow
Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\policies\Microsoft\Windows NT\Terminal Services" -ValueName CreateEncryptedOnlyTickets -Type DWord -Value 0 -Verbose







#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- GPO STUFF: 'Lab SMB Client Policy GPO' ----            " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

#Create GPO if it doesn't exist...
If (!(Get-GPO -Name 'Lab SMB Client Policy GPO' -ErrorAction SilentlyContinue))
{
    Write-Host ":: Create GPO 'Lab Account Policy GPO' if it does not exist..." -ForegroundColor Yellow
    New-GPO -Name 'Lab SMB Client Policy GPO' -Comment 'This is a GPO with some account policy settings for testing  2022-03-26' -ErrorAction SilentlyContinue -Verbose
    Write-Host ""
    Start-Sleep 10
}

$GPO = $null
$GPO = Get-GPO -Name 'Lab SMB Client Policy GPO'
$GPO
Write-Host ""
Write-Host ""

    # "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" AllowInsecureGuestAuth = 0 | 1
    #
    # In the console tree, select Computer Configuration > Administrative Templates > Network > Lanman Workstation.
    #
    # This policy setting determines if the SMB client will allow insecure guest logons to an SMB server.  
    #
    # If you enable this policy setting or if you do not configure this policy setting, the SMB client will 
    # allow insecure guest logons.  
    #
    # If you disable this policy setting, the SMB client will reject insecure 
    # guest logons.  
    #
    # Insecure guest logons are used by file servers to allow unauthenticated access to shared folders. 
    # While uncommon in an enterprise environment, insecure guest logons are frequently used by consumer 
    # Network Attached Storage (NAS) appliances acting as file servers. Windows file servers require 
    # authentication and do not use insecure guest logons by default. Since insecure guest logons 
    # are unauthenticated, important security features such as SMB Signing and SMB Encryption are disabled. 
    # As a result, clients that allow insecure guest logons are vulnerable to a variety of man-in-the-middle 
    # attacks that can result in data loss, data corruption, and exposure to malware. Additionally, any data
    # written to a file server using an insecure guest logon is potentially accessible to anyone on the network. 
    # Microsoft recommends disabling insecure guest logons and configuring file servers to require authenticated 
    # access.

    Write-Host ""
    Write-Host ":: Get current setting for 'AllowInsecureGuestAuth' in GPO '$($GPO.DisplayName)..." -ForegroundColor Yellow
    Write-Host ""
    Get-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName AllowInsecureGuestAuth
    Write-Host ""
    Write-Host ":: Set 'AllowInsecureGuestAuth' to value '1' to allow !INSECURE! SMB client connections..." -ForegroundColor Yellow
    #Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName AllowInsecureGuestAuth -Value 0 -Type DWord # enabled is SECURE!!
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName AllowInsecureGuestAuth -Value 1 -Type DWord -Verbose # disabled is INSECURE!!
    Write-Host ""
    Write-Host ""

    Write-Host ":: Force replication after 20 second pause..." -ForegroundColor Yellow
    Start-Sleep 20
    If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
    If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}
    
    Write-Host ""
    Write-Host ""
    Invoke-GPUpdate -Force -Verbose
    Write-Host ""
    Write-Host ""

    Start-Sleep 10
    Write-Host ""
    Write-Host ":: Get current setting for 'AllowInsecureGuestAuth' in GPO '$($GPO.DisplayName)..." -ForegroundColor Yellow
    Write-Host ""
    Get-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName AllowInsecureGuestAuth -Verbose -ErrorAction SilentlyContinue
    Write-Host ""
    Write-Host ":: Set 'AllowInsecureGuestAuth' to insecure value '0' to PREVENT insecure SMB client connections..." -ForegroundColor Yellow
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName AllowInsecureGuestAuth -Value 0 -Type DWord -Verbose # enabled is SECURE!!
    #Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName AllowInsecureGuestAuth -Value 1 -Type DWord # disabled is INSECURE!!
    Write-Host ""
    Write-Host "" 

Write-Host ":: Force replication after 25 second pause..." -ForegroundColor Yellow
Start-Sleep 25
If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}

Write-Host ""
Write-Host ""
Invoke-GPUpdate -Force -Verbose
Write-Host ""
Write-Host ""






#------------------------------------------------------------------------------
#
# CIS Windows Server Policy GPO - Update Policy (part 1 - initial/reset settings)
#
# In a later section, code will update some settings, 1) to show a more restrictive 
# setting and 2) to set a less restrictive setting. In a demo, I can speak to how 
# outages can be incured due to GPO changes and we can see the differences.
#
# We make changes a few minutes later to give the GPO time to settle and replicate
# wihtout adding additional timing delays here.
#
#

$GPOName = 'CIS Benchmark Windows Server Policy GPO'


Write-Host "`n`n"
Write-Host "::                                                                         " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- GPO STUFF: '$GPOName' ----          " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                         " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""


$DateTag = Get-Date -Format "yyyy-dd-MM_HHmm"

#Create GPO if it doesn't exist...
If (!($GPO = Get-GPO -Name "$GPOName" -ErrorAction SilentlyContinue))
{
    Write-Host ":: Create '$GPOName' if it does not exist..." -ForegroundColor Yellow
    New-GPO -Name "$GPOName" -Comment "This is a GPO with some CIS Benchmark recommendations for testing GPO changes $DateTag" -ErrorAction SilentlyContinue -Verbose
    Write-Host ""
    Write-Host "`n"
    Write-Host ":: Force replication after 15 seconds to propagate new GPO..." -ForegroundColor Yellow
    Start-Sleep 15
    If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
    If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}

    $GPO = Get-GPO -Name "$GPOName" -ErrorAction SilentlyContinue
}

#$GPO = $null
#$GPO = Get-GPO -Name "$GPOName"
$GPO
$GPO.Description = "This is a GPO with some CIS Benchmark recommendations for testing GPO changes $DateTag"
Write-Host ""
Write-Host ""

# NOTE: These ALL end up as "Extra Registry Settings"!!! I cannot figure out how to set the policy
#       settings using the defined registry settings/keys. 

    # "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" AllowInsecureGuestAuth = 0 | 1
    #
    # This policy setting determines if the SMB client will allow insecure guest logons to an SMB server.  
    #
    # If you enable this policy setting or if you do not configure this policy setting, the SMB client will 
    # allow insecure guest logons.  
    #
    # If you disable this policy setting, the SMB client will reject insecure 
    # guest logons.  
    #
    # Insecure guest logons are used by file servers to allow unauthenticated access to shared folders. 
    # While uncommon in an enterprise environment, insecure guest logons are frequently used by consumer 
    # Network Attached Storage (NAS) appliances acting as file servers. Windows file servers require 
    # authentication and do not use insecure guest logons by default. Since insecure guest logons 
    # are unauthenticated, important security features such as SMB Signing and SMB Encryption are disabled. 
    # As a result, clients that allow insecure guest logons are vulnerable to a variety of man-in-the-middle 
    # attacks that can result in data loss, data corruption, and exposure to malware. Additionally, any data
    # written to a file server using an insecure guest logon is potentially accessible to anyone on the network. 
    # Microsoft recommends disabling insecure guest logons and configuring file servers to require authenticated access.

    Write-Host ""
    Write-Host ":: Get current setting for 'AllowInsecureGuestAuth' in GPO '$($GPO.DisplayName)..." -ForegroundColor Yellow
    Write-Host ""
    Get-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName AllowInsecureGuestAuth
    Write-Host ""
    Write-Host ":: Set 'AllowInsecureGuestAuth' to value '1' to allow !INSECURE! SMB client connections..." -ForegroundColor Yellow
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName AllowInsecureGuestAuth -Value 0 -Type DWord # enabled is SECURE!!
    #Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName AllowInsecureGuestAuth -Value 1 -Type DWord -Verbose # disabled is INSECURE!!
    Write-Host ""
    Write-Host ""

    # Set a Windows Update value or two...
    Write-Host ""
    Write-Host ":: Set some WindowsUpdate settings..." -ForegroundColor Yellow

    Get-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "DetectionFrequencyEnabled" -ErrorAction Silent -Verbose
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "DetectionFrequencyEnabled" -Value 0 -Type DWord -Verbose

    Get-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "De-tectionFrequency" -ErrorAction Silent -Verbose
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "De-tectionFrequency" -Value 82 -Type DWord -Verbose

    # Set/Change some security settings...
    #
    # Windows includes two network-sharing security models - Classic and Guest only. With the classic model, local accounts must be password protected; 
    # otherwise, anyone can use guest user accounts to access shared system resources.
    #
    # If the value for  Network access: Sharing and security model for local accounts  is not set to 
    #  Classic - local users authenticate as themselves , then this is a finding (less secure).
    #
    # Configure the policy value for:
    # Computer Configuration -> 
    #   Windows Settings -> 
    #      Security Settings -> 
    #         Local Policies -> 
    #            Security Options -> 
    #               "Network access: Sharing and security model for local accounts" to "Classic - local users authenticate as themselves". 
    #                 (reg value should be 0 for this more secure setting)
    #
    # reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" -v forceguest   # the value should ALWAYS be "0" for a DC!!!
    Write-Host ""
    Write-Host ":: Set some Windows security policy settings..." -ForegroundColor Yellow
    Get-GPRegistryValue -Name $GPO.DisplayName -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" -ValueName "forceguest" -ErrorAction Silent -Verbose
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" -ValueName "forceguest" -Value 0 -Type DWord -Verbose # less secure setting

#   DESCRIPTION: NTLM sessions that are allowed to fall back to Null (unauthenticated) sessions may gain 
#                unauthorized access.
#   Computer Configuration\Policies\Windows Settings\Security Settings\LocalPolicies\Security Options\Network security: Allow LocalSystem NULL session fallback
#   The recommended state for this setting is: Disabled
#   HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0:allownullsessionfallback
#   IMPACT: Any applications that require NULL sessions for LocalSystem will not work as designed. 
    Get-GPRegistryValue -Name $GPO.DisplayName -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" -ValueName "allownullsessionfallback" -ErrorAction Silent -Verbose
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" -ValueName "allownullsessionfallback" -Value 0 -Type DWord -Verbose

#   The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM
#   DESCRIPTION: The Kerberos v5 authentication protocol is the default for authentication of users who are 
#                logging on to domain accounts. NTLM, which is less secure, is retained in later Windows 
#                versions for compatibility with clients and servers that are running earlier versions of 
#                Windows or applications that still use it. It is also used to authenticate logons to 
#                stand-alone computers that are running later versions.
#   Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> 
#   Recommended to set "Network Security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM".
# POLICY LOCATION: Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options
# REGISTRY LOCATION: HKLM\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel
# 
# Setting 	 	                                                Registry security level
# "Send LM & NTLM responses" 	                                0
# "Send LM & NTLM   use NTLMv2 session security if negotiated"  1
# "Send NTLM response only"                                     2
# "Send NTLMv2 response only"                                   3
# "Send NTLMv2 response only. Refuse LM"                        4
# "Send NTLMv2 response only. Refuse LM & NTLM"                 5
#
#   Registry Path: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa:LmCompatibilityLevel  REG_DWORD   value: 5
    Get-GPRegistryValue -Name $GPO.DisplayName -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" -ValueName "LmCompatibilityLevel" -ErrorAction Silent -Verbose
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" -ValueName "LmCompatibilityLevel" -Value 5 -Type DWord -Verbose

#   Prevent the storage of the LAN Manager hash of passwords
#   DESCRIPTION: The LAN Manager hash uses a weak encryption algorithm and there are several tools available 
#                that use this hash to retrieve account passwords. This setting controls whether a LAN Manager
#                hash of the password is stored in the SAM the next time the password is changed.
#   Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: Do not store LAN Manager hash value on next password change" to "Enabled". 
#   Registry Path: HKLM\SYSTEM\CurrentControlSet\Control\Lsa:NoLMHash    REG_DWORD   Value: 0x00000001 (1)
    Get-GPRegistryValue -Name $GPO.DisplayName -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" -ValueName "NoLMHash" -ErrorAction Silent -Verbose
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" -ValueName "NoLMHash" -Value 1 -Type DWord -Verbose


    Write-Host "`n"
    Write-Host ":: Force replication to propagate GPO changes..." -ForegroundColor Yellow
    If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
    If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}



    Write-Host "`n"
    Write-Host ":: 10 second pause to allow for replication..." -ForegroundColor Yellow
    Start-Sleep 10
    
    Write-Host ""
    Write-Host ""
    Write-Host "Invoke-GPUpdate -Force -Verbose" -ForegroundColor Cyan
    Invoke-GPUpdate -Force -Verbose
    Write-Host ""
    Write-Host ""

    Write-Host "`n"
    Write-Host ":: 5 second pause to allow for refresh..." -ForegroundColor Yellow
    Start-Sleep 5

#    Write-Host ""
#    Write-Host ":: Get current setting for 'AllowInsecureGuestAuth' in GPO '$($GPO.DisplayName)..." -ForegroundColor Yellow
#    Write-Host ""
#    Get-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName AllowInsecureGuestAuth -Verbose -ErrorAction SilentlyContinue
#    Write-Host ""
#    Write-Host ":: Set 'AllowInsecureGuestAuth' to insecure value '1' to PREVENT insecure SMB client connections..." -ForegroundColor Yellow
#    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName AllowInsecureGuestAuth -Value 1 -Type DWord -Verbose # enabled is SECURE!!
    #Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName AllowInsecureGuestAuth -Value 1 -Type DWord # disabled is INSECURE!!
#    Write-Host ""
#    Write-Host "" 

#    # Set all CIS Benchmark values to their proper secure settings!!!
#    Write-Host ""
#    Write-Host ":: Make sure all of the CIS Benchmark settings are set/reset to secure values..."
#    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName AllowInsecureGuestAuth -Value 1 -Type DWord -Verbose # disabled is INSECURE!!
#    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "DetectionFrequencyEnabled" -Value 1 -Type DWord -Verbose
#    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "De-tectionFrequency" -Value 22 -Type DWord -Verbose
#    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" -ValueName "forceguest" -Value 0 -Type DWord -Verbose
#    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" -ValueName "allownullsessionfallback" -Value 0 -Type DWord -Verbose
#    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" -ValueName "LmCompatibilityLevel" -Value 5 -Type DWord -Verbose
#    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" -ValueName "NoLMHash" -Value 1 -Type DWord -Verbose

Write-Host "`n"
Write-Host ":: Force replication after 5 second pause..." -ForegroundColor Yellow
Start-Sleep 5
If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}

Write-Host ""
Write-Host ""
Write-Host "Invoke-GPUpdate -Force -Verbose" -ForegroundColor Cyan
Invoke-GPUpdate -Force -Verbose
Write-Host ""
Write-Host ""
#
#------------------------------------------------------------------------------







# create a group for the FGPP stuff instead of using 'Special Lab Users'

#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                        " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- FINE-GRAINED PASSWORD POLICY STUFF: 'SpecialLabUsers_PSO' ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                        " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
Write-Host ":: Set a Fine-Grained Password Policy on the group 'Special Lab Users'..." -ForegroundColor Yellow
Write-Host "::      -- Create the fine-grained password policy 'SpecialLabUsers_PSO'..." -ForegroundColor Yellow
New-ADFineGrainedPasswordPolicy -Name  SpecialLabUsers_PSO  -Precedence 2 -Description 'Account Lockout policy for Special Lab Users members'  -DisplayName  'SpecialLabUsers_PSO'  -LockoutDuration "8:00" -LockoutObservationWindow "8:00" -LockoutThreshold 20 -Verbose
Write-Host "::      -- Assign the new file-grained password policy to the 'Special Lab Users' group..." -ForegroundColor Yellow
Add-ADFineGrainedPasswordPolicySubject -Identity "SpecialLabUsers_PSO" -Subjects "SpecialLabUsers" 

Write-Host ":: Force replication after 20 second pause..." -ForegroundColor Yellow
Start-Sleep 20
If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}
# create a group for the FGPP stuff instead of using 'Special Lab Users'








#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                                  " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- REPLICATION SUBNET STUFF: DELETE ACTIVE DORECTORY SUBNETS ----              " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::         (ADDED EARLIER IN SCRIPT)                                                " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                                  " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
#
# These variables were set earlier in this script...
#$objADSubnet1 = '111.111.4.0/24'
#$objADSubnet2 = '111.111.5.0/24'
#
# Have to use Try-Catch due to unblockable error messages when subnet does not exist.
#
Try
{
    If (Get-ADReplicationSubnet -Identity $objADSubnet1 -ErrorAction Ignore)
    {
        Set-ADReplicationSubnet -Identity $objADSubnet1 -Description "Changed the subnet description attribute again!!" -ErrorAction SilentlyContinue -Verbose
        Start-Sleep 5
        Remove-ADReplicationSubnet -Identity $objADSubnet1 -Confirm:$False -ErrorAction SilentlyContinue -Verbose
    }
}
Catch
{
    Write-Host "::     Subnet '$objADSubnet1' does not exist or was already removed!"
    Write-Host ""
    Write-Host ""
}
Try
{
    If (Get-ADReplicationSubnet -Identity $objADSubnet2 -ErrorAction SilentlyContinue)
    {
        Set-ADReplicationSubnet -Identity $objADSubnet2 -Description "Changed the subnet description attribute again!!" -ErrorAction SilentlyContinue -Verbose
        Start-Sleep 5
        #Remove-ADReplicationSubnet -Identity $objADSubnet2 -Confirm:$False -ErrorAction SilentlyContinue -Verbose
    }

}
Catch
{
    Write-Host "::     Subnet '$objADSubnet2' does not exist or was already removed!"
    Write-Host ""
    Write-Host ""
}







#------------------------------------------------------------------------------
$FGPPName = 'SpecialAccounts_PSO'
Write-Host "`n`n"
Write-Host "::                                                                        " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- FINE-GRAINED PASSWORD POLICY STUFF: '$FGPPName' ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                        " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
$FGPPobj = $null
If (!($FGPPobj = Get-ADFineGrainedPasswordPolicy -LDAPFilter "(&(objectClass=msDS-PasswordSettings)(Name=$FGPPName))" -ErrorAction SilentlyContinue))
{
    Write-Host ":: Set a Fine-Grained Password Policy on the group '$FGPPName'..." -ForegroundColor Yellow
    Write-Host "::      -- Create the fine-grained password policy '$FGPPName'..." -ForegroundColor Yellow
    New-ADFineGrainedPasswordPolicy -Name "$FGPPName"  -Precedence 2 -Description "Account Lockout policy for special accounts" -DisplayName "$FGPPName" -LockoutDuration "8:00" -LockoutObservationWindow "8:00" -LockoutThreshold 25 -Verbose
    Start-Sleep 15
    #$FGPPobj = Get-ADFineGrainedPasswordPolicy -LDAPFilter "(&(objectClass=msDS-PasswordSettings)(Name=$FGPPName))" -ErrorAction SilentlyContinue
    $FGPPobj
    ##Write-Host "::      -- Assign the new file-grained password policy to the 'Special Lab Users' group..." -ForegroundColor Yellow
    ##Add-ADFineGrainedPasswordPolicySubject -Identity "$FGPPName" -Subjects "SpecialLabUsers"
    
    # Change an attribute of this FGPP to show a change to the PSO... 
    Write-Host ":: Making changes to the FGPP to show in the DSP Changes view..." -ForegroundColor Yellow
    Set-ADFineGrainedPasswordPolicy -Identity $FGPPobj -ComplexityEnabled $False -Verbose
    Write-Host ":: (delaying 15 seconds)" -ForegroundColor Yellow
    Start-Sleep 15
    Set-ADFineGrainedPasswordPolicy -Identity $FGPPobj -ComplexityEnabled $True -Description 'FGPP with modified FGPP Values' -Verbose 
    Write-Host ""
}
Else
{
    Write-Host ":: Found Fine-Grained Password Policy named '$FGPPName' for special and service accounts." -ForegroundColor Yellow
    Write-Host ""
    $FGPPobj

    # Change an attribute of this FGPP to show a change to the PSO... 
    Write-Host ":: Making changes to the FGPP to show in the DSP Changes view..." -ForegroundColor Yellow
    Set-ADFineGrainedPasswordPolicy -Identity $FGPPobj -ComplexityEnabled $False -Verbose
    Write-Host ":: (delaying 15 seconds)" -ForegroundColor Yellow
    Start-Sleep 15
    Set-ADFineGrainedPasswordPolicy -Identity $FGPPobj -ComplexityEnabled $True -Description 'FGPP with modified FGPP Values' -Verbose 
    Start-Sleep 15
    Set-ADFineGrainedPasswordPolicy -Identity $FGPPobj -ComplexityEnabled $True -Description 'Account Lockout policy for special accounts' -Verbose 
    Write-Host ""


    #Remove-ADFineGrainedPasswordPolicy -Identity $FGPPName -Confirm:$False -Verbose

}
Write-Host ""



#------------------------------------------------------------------------------
$FGPPName = 'SpecialAccounts_PSO2'
Write-Host "`n`n"
Write-Host "::                                                                        " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- FINE-GRAINED PASSWORD POLICY STUFF: '$FGPPName' ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                        " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
$FGPPobj = $null
If (!($FGPPobj = Get-ADFineGrainedPasswordPolicy -LDAPFilter "(&(objectClass=msDS-PasswordSettings)(Name=$FGPPName))" -ErrorAction SilentlyContinue))
{
    Write-Host ":: Set a Fine-Grained Password Policy on the group '$FGPPName'..." -ForegroundColor Yellow
    Write-Host "::      -- Create the fine-grained password policy '$FGPPName'..." -ForegroundColor Yellow
    New-ADFineGrainedPasswordPolicy -Name "$FGPPName"  -Precedence 2 -Description "Account Lockout policy for special accounts" -DisplayName "$FGPPName" -LockoutDuration "5:00" -LockoutObservationWindow "5:00" -LockoutThreshold 22 -Verbose
    Start-Sleep 15
    #$FGPPobj = Get-ADFineGrainedPasswordPolicy -LDAPFilter "(&(objectClass=msDS-PasswordSettings)(Name=$FGPPName))" -ErrorAction SilentlyContinue
    $FGPPobj
    ##Write-Host "::      -- Assign the new file-grained password policy to the 'Special Lab Users' group..." -ForegroundColor Yellow
    ##Add-ADFineGrainedPasswordPolicySubject -Identity "$FGPPName" -Subjects "SpecialLabUsers"
    
    # Change an attribute of this FGPP to show a change to the PSO... 
    Write-Host ":: Making changes to the FGPP to show in the DSP Changes view..." -ForegroundColor Yellow
    Set-ADFineGrainedPasswordPolicy -Identity $FGPPobj -ComplexityEnabled $False -Verbose
    Write-Host ":: (delaying 15 seconds)" -ForegroundColor Yellow
    Start-Sleep 15
    Set-ADFineGrainedPasswordPolicy -Identity $FGPPobj -ComplexityEnabled $True -Description 'Account Lockout policy for special accounts - modified FGPP Value' -Verbose
    Write-Host ""
}
Else
{
    Write-Host ":: Found Fine-Grained Password Policy named '$FGPPName' for special and service accounts." -ForegroundColor Yellow
    Write-Host ""
    $FGPPobj

    # Change an attribute of this FGPP to show a change to the PSO... 
    Write-Host ":: Making changes to the FGPP to show in the DSP Changes view..." -ForegroundColor Yellow
    Set-ADFineGrainedPasswordPolicy -Identity $FGPPobj -ComplexityEnabled $False -Verbose
    Write-Host ":: (delaying 15 seconds)" -ForegroundColor Yellow
    Start-Sleep 15
    Set-ADFineGrainedPasswordPolicy -Identity $FGPPobj -ComplexityEnabled $True -Description 'FGPP with modified FGPP Value' -Verbose 
    Start-Sleep 15
    Set-ADFineGrainedPasswordPolicy -Identity $FGPPobj -ComplexityEnabled $True -Description 'Account Lockout policy for special accounts' -Verbose 
    Write-Host ""


    #Remove-ADFineGrainedPasswordPolicy -Identity $FGPPName -Confirm:$False -Verbose

}
Write-Host ""




Write-Host ":: Force replication after 20 second pause..." -ForegroundColor Yellow
Start-Sleep 20
If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}



# After using a new group for the PSO, delete this FGPP...

Write-Host ":: Remove the Fine-Grained Password Policy assignment on the 'Special Lab Users' group..." -ForegroundColor Yellow
Write-Host ":: (waiting 25 more seconds)" -ForegroundColor Yellow
Start-Sleep 25
# NOTE: this could be a problem due to the "5 minute rule"!!!
Remove-ADFineGrainedPasswordPolicySubject -Identity "SpecialLabUsers_PSO" -Subjects "SpecialLabUsers" -Confirm:$False

Remove-ADFineGrainedPasswordPolicy -Identity "SpecialLabUsers_PSO" -Verbose -Confirm:$False

Write-Host ":: Force replication after 20 second pause..." -ForegroundColor Yellow
Start-Sleep 20
If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}








#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- GROUP STUFF: 'Special Lab Users' ----                  " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
Write-Host ":: Delete group 'Special Lab Users' if it exists..." -ForegroundColor Yellow
$GroupName = $null
$GroupName = Get-ADGroup -LDAPFilter '(&(objectClass=group)(cn=Special Lab Users))'
Remove-ADObject -Identity $GroupName.DistinguishedName -Confirm:$False -ErrorAction SilentlyContinue
$GroupName = $null

Write-Host ":: Force replication after 10 second pause..." -ForegroundColor Yellow
Start-Sleep 10
If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}

Write-Host ":: Create a new AD group 'Special Lab Users' in OU 'Lab Users'..." -ForegroundColor Yellow
New-ADGroup -Name "Special Lab Users" -SamAccountName SpecialLabUsers -GroupCategory Security -GroupScope Global -DisplayName "Special Lab Users" -Path "OU=Lab Users,$DomainDN" -Description "Members of this lab group are special"

Write-Host ":: Force replication after 10 second pause..." -ForegroundColor Yellow
Start-Sleep 10
If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}

Write-Host ":: Set 'Special Lab Users' to category 'Distribution'..." -ForegroundColor Yellow
Set-ADGroup -Identity SpecialLabUsers -GroupCategory Distribution
Start-Sleep 10
Write-Host ":: Set 'Special Lab Users' to scope 'Universal'..." -ForegroundColor Yellow
Set-ADGroup -Identity SpecialLabUsers -GroupScope Universal
Start-Sleep 10
Write-Host ":: Move 'Special Lab Users' to 'Lab Admins' OU..." -ForegroundColor Yellow
Move-ADObject -Identity "CN=Special Lab Users,OU=Lab Users,$DomainDN" -TargetPath "OU=Lab Admins,$DomainDN"
Start-Sleep 10

Write-Host ":: Force replication after 10 second pause..." -ForegroundColor Yellow
Start-Sleep 10
If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}

# Do NOT delete here!!! I will prevent changes from appearing!!!!
#Write-Host ":: Delete group 'Special Group'..." -ForegroundColor Yellow
#Remove-ADObject -Identity 'CN=Special Group,OU=Lab Admins,DC=f097-d01,DC=lab' -Confirm:$False
#Start-Sleep 8

$MemberToAdd = $null
$GroupName = $null
$MemberToAdd = get-aduser -LDAPfilter '(&(objectCategory=person)(cn=App Admin III))'
$GroupName = get-adgroup -LDAPfilter '(&(objectCategory=group)(cn=Special Lab Users))'
Add-ADGroupMember -Identity $GroupName.DistinguishedName -Members $MemberToAdd.DistinguishedName
$MemberToAdd = $null





#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                                                 " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- USER OBJECT STUFF - SET USER ATTRIBUTES WITH ALTERNATE CREDS: DemoUser1 ($($DemoUser1.Name)) ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ----                DemoUser1 ($($DemoUser1.Name))                                                        " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                                                 " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

# This section definitely requires purposeful delays in order to make multiple
# changes to the same attribute on an object. (I thought 16 seconds between 
# changes would be good, but it is not always reliable, probably due to lab
# performance. When I did not have enough of a delay, either a change would
# missing, or an undo would fail with a weird invalid indices error, which
# actually could have been something else and just coincidental.)
# 
# Due to the need for delays, and not wanting this section to be like 3 or 4 minutes
# long, I am just spreading out the changes in the script.
#
# Interesting note: In DSP v3.6, DSP will find the two changes to 'telephoneNumber' done here by
# two different users, and DSP v3.6 will show the latest change, but ALSO show that TWO users
# made a change to the same attribute in about the same time.


#$DemoUserObj = Get-ADUser -LDAPFilter "(&(objectCategory=person)(sAMAccountName=$($DemoUser1.SamAccountName)))" -Verbose -ErrorAction SilentlyContinue

If ($UserObj = Get-ADUser -LDAPFilter "(&(objectCategory=person)(sAMAccountName=$($DemoUser1.SamAccountName)))" -Verbose -ErrorAction SilentlyContinue)
{
    Write-Host ":: Get 'telephoneNumber' for user object '$($UserObj.Name)'..." -ForegroundColor Yellow
    (Get-ADUser -Identity "$($UserObj.DistinguishedName)" -Properties telephoneNumber).telephoneNumber
    
    # Using our ALTERNATIVE admin creds to make a change....   
    # (Make sure account is NOT locked out and set password to never expire or force reset it!!)
    Write-Host ":: Have '$($OpsAdmin1Creds.UserName)' set 'telephoneNumber' for user object '$($UserObj.Name)' to '$($DemoUser1.TelephoneNumber)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -OfficePhone "$($DemoUser1.TelephoneNumber)" -Credential $OpsAdmin1Creds -Verbose
    Write-Host ""
	Write-Host ":: Have '$($OpsAdmin1Creds.UserName)' set 'info' attribute for user object '$($UserObj.Name)' to 'first change of info attribute text'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Replace @{info='first change of info attribute text'} -Credential $OpsAdmin1Creds -Verbose
    Start-Sleep 8
	
    # NOTE: when making multiple changes to the same attribute on the same
	#       AD object, around 15 seconds seems to be the magic delay amount
	#       to pick up each change, otherwise, AD will stack the changes and
	#       only the most recent is replicated.
	
    Write-Host ""
    Write-Host ":: Force replication after 8 second pause..." -ForegroundColor Yellow
    Start-Sleep 8
    If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
    If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}

    Write-Host ""
    Write-Host ":: Setting more attributes on user '$($UserObj.Name)' to simulate HR changes..." -ForegroundColor Yellow
    Write-Host ":: (pausing 8 seconds before setting more attributes)"
    Start-Sleep 8
    Write-Host ""
    Write-Host ":: Set 'telephoneNumber' for user object '$($UserObj.Name)' to '$($DemoUser1.TelephoneNumberAlt)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -OfficePhone "$($DemoUser1.TelephoneNumberAlt)" -Credential $OpsAdmin1Creds -Verbose
    Write-Host ":: Set 'city' for user object '$($UserObj.Name)' to 'Tribeca'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -City "Tribeca" -Credential $OpsAdmin1Creds -Verbose
    Write-Host ":: Set 'division' for user object '$($UserObj.Name)' to '$($DemoUser1.Division)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -division "$($DemoUser1.Division)" -Credential $OpsAdmin1Creds -Verbose
    Write-Host ":: Set 'employeeID' for user object '$($UserObj.Name)' to '$($DemoUser1.EmployeeID)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -employeeID "$($DemoUser1.EmployeeID)" -Credential $OpsAdmin1Creds -Verbose
	#
	# Do the rest of these changes as the logged on admin in case the alternative
	# credentials were not successfully called up. At least we will have some more
	# user changes shown.
	#
    Write-Host ":: Set 'initials' for user object '$($UserObj.Name)' to '$($DemoUser1.Initials)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -initials "$($DemoUser1.Initials)" -Verbose
    Write-Host ":: Set 'company' for user object '$($UserObj.Name)' to '$($DemoUser1.Company)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -company "$($DemoUser1.Company)" -Verbose
    Write-Host ":: Set 'FAX' for user object '$($UserObj.Name)' to '$($DemoUser1.FAX)'..." -ForegroundColor Yellow # facsimileTelephoneNumber
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Fax "$($DemoUser1.FAX)" -Verbose
    #
	# Now do a few more changes to the info attribute with alt creds...
	#
	Write-Host ":: Have '$($OpsAdmin1Creds.UserName)' set 'info' attribute for user object '$($UserObj.Name)' to 'second change of info attribute text'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Replace @{info='second change of info attribute text'} -Credential $OpsAdmin1Creds -Verbose
    Write-Host ""
	Write-Host ":: Force replication after 15 second pause..." -ForegroundColor Yellow
    Start-Sleep 15
    If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
    If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}
    Start-Sleep 15
    Write-Host ""
	Write-Host ":: Have '$($OpsAdmin1Creds.UserName)' clear the 'info' attribute for user object '$($UserObj.Name)'..." -ForegroundColor Yellow
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Clear info -Credential $OpsAdmin1Creds -Verbose

	Write-Host ""
    Write-Host ":: Force replication after 16 second pause..." -ForegroundColor Yellow
    Start-Sleep 16
    If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
    If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}
	Start-Sleep 5
}





#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- DNS STUFF ----                                         " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

Write-Host ""
Write-Host ":: Create/Update DNS reverse zones and PTR records..." -ForegroundColor Yellow

# Have to create reverse zones for the PTR records to make sure they exist before creating forward records!!!

Write-Host "`n`n"
Write-Host ":: Making sure the reverse (PTR) zones exist..."
Write-Host ""

If (!((Get-DnsServerZone -ComputerName $DomainDC1 -Name '10.in-addr.arpa' -ErrorAction SilentlyContinue).IsReverseLookupZone))  
{
    Write-Host ":: Create DNS reverse zone for '10.x.x.x' zone '$DomainDNSRoot'..." -ForegroundColor Yellow
    Add-DnsServerPrimaryZone -ComputerName $DomainDC1 -DynamicUpdate NonsecureAndSecure -NetworkId  10.0.0.0/8  -ReplicationScope Forest -WarningAction Ignore -ErrorAction Ignore -Verbose
}

If (!((Get-DnsServerZone -ComputerName $DomainDC1 -Name '172.in-addr.arpa' -ErrorAction SilentlyContinue).IsReverseLookupZone))
{
    Write-Host ":: Create DNS reverse zone for '172.x.x.x' zone '$DomainDNSRoot'..." -ForegroundColor Yellow
    Add-DnsServerPrimaryZone -ComputerName $DomainDC1 -DynamicUpdate NonsecureAndSecure -NetworkId  172.0.0.0/8  -ReplicationScope Forest -WarningAction Ignore -ErrorAction Ignore -Verbose
}

If (!((Get-DnsServerZone -ComputerName $DomainDC1 -Name '168.192.in-addr.arpa' -ErrorAction SilentlyContinue).IsReverseLookupZone))
{
    Write-Host ":: Create DNS reverse zone for '192.168.x.x' zone '$DomainDNSRoot'..." -ForegroundColor Yellow
    Add-DnsServerPrimaryZone -ComputerName $DomainDC1 -DynamicUpdate NonsecureAndSecure -NetworkId  192.168.0.0/16  -ReplicationScope Forest -WarningAction Ignore -ErrorAction Ignore -Verbose
}

Write-Host ":: Force replication after 10 second pause..." -ForegroundColor Yellow
Start-Sleep 10
If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}




# Create a forward zone to add records to and then delete later (can recover/undo in the demo)
$playzone = 'specialsite.lab'

 $result = $null
 $result = Get-DnsServerZone -ComputerName $DomainDC1 -Name "$playzone" -WarningAction Ignore -ErrorAction Ignore #| out-null # stupid PoSh will not ignore error
 If (!($result)) 
 {
    Write-Host ""
    Write-Host ":: Creating missing DNS forward zone '$playzone'..." -ForegroundColor Yellow
    Add-DnsServerPrimaryZone -ComputerName $DomainDC1 -DynamicUpdate NonsecureAndSecure "$playzone" -ReplicationScope Forest -Verbose
    Set-DnsServerPrimaryZone -ComputerName $DomainDC1 -Name "$playzone" -Notify Notify -Verbose
    
    Start-Sleep 10
    If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
    If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}

    Set-DnsServerPrimaryZone -ComputerName $DomainDC1 -Name "$playzone" -Notify NoNotify -Verbose

    Write-Host ""
    Write-Host ":: Make sure there are records in the zone '$playzone'..." -ForegroundColor Yellow
    Write-Host ""
    
    If (!(Get-DnsServerResourceRecord -ComputerName $DomainDC1 -Name "mylabhost01" -ZoneName "$playzone" -WarningAction Ignore -ErrorAction Ignore))
    {
        Add-DnsServerResourceRecordA -ComputerName $DomainDC1 -Name "mylabhost01" -ZoneName "$playzone" -IPv4Address "172.111.10.11" -TimeToLive 01:00:00 -CreatePtr -AgeRecord -AllowUpdateAny -Verbose
    }
    # Even though the above line should create a PTR, it generates an error due to the PTR possibly already existing or because PowerShell is stupid
    If (!(Get-DnsServerResourceRecord -ComputerName $DomainDC2 -Name "11.10.111" -ZoneName "172.in-addr.arpa" -RRType Ptr -WarningAction Ignore -ErrorAction Ignore))
    {
        Add-DnsServerResourceRecordPtr -ComputerName $DomainDC2 -Name "11.10.111" -ZoneName "172.in-addr.arpa" -PtrDomainName "mylabhost01.specialsite.lab" -TimeToLive 01:00:00 -AllowUpdateAny -AgeRecord -Verbose
    }
    

    If (!(Get-DnsServerResourceRecord -ComputerName $DomainDC1 -Name "mylabhost02" -ZoneName "$playzone" -WarningAction Ignore -ErrorAction Ignore))
    {
        Add-DnsServerResourceRecordA -ComputerName $DomainDC1 -Name "mylabhost02" -ZoneName "$playzone" -IPv4Address "172.111.10.12" -TimeToLive 01:00:00 -CreatePtr -AgeRecord -AllowUpdateAny -Verbose
    }
    # Even though the above line should create a PTR, it generates an error due to the PTR possibly already existing or because PowerShell is stupid
    If (!(Get-DnsServerResourceRecord -ComputerName $DomainDC2 -Name "12.10.111" -ZoneName "172.in-addr.arpa" -RRType Ptr -WarningAction Ignore -ErrorAction Ignore))
    {
        Add-DnsServerResourceRecordPtr -ComputerName $DomainDC2 -Name "12.10.111" -ZoneName "172.in-addr.arpa" -PtrDomainName "mylabhost02.specialsite.lab" -TimeToLive 01:00:00 -AllowUpdateAny -AgeRecord -Verbose
    }


    If (!(Get-DnsServerResourceRecord -ComputerName $DomainDC1 -Name "mylabhost03" -ZoneName "$playzone" -WarningAction Ignore -ErrorAction Ignore))
    {
        Add-DnsServerResourceRecordA -ComputerName $DomainDC1 -Name "mylabhost03" -ZoneName "$playzone" -IPv4Address "172.111.10.13" -TimeToLive 01:00:00 -CreatePtr -AgeRecord -AllowUpdateAny -Verbose
    }
    # Even though the above line should create a PTR, it generates an error due to the PTR possibly already existing or because PowerShell is stupid
    If (!(Get-DnsServerResourceRecord -ComputerName $DomainDC2 -Name "13.10.111" -ZoneName "172.in-addr.arpa" -RRType Ptr -WarningAction Ignore -ErrorAction Ignore))
    {
        Add-DnsServerResourceRecordPtr -ComputerName $DomainDC2 -Name "13.10.111" -ZoneName "172.in-addr.arpa" -PtrDomainName "mylabhost03.specialsite.lab" -TimeToLive 01:00:00 -AllowUpdateAny -AgeRecord -Verbose
    }


    If (!(Get-DnsServerResourceRecord -ComputerName $DomainDC1 -Name "mylabhost04" -ZoneName "$playzone" -WarningAction Ignore -ErrorAction Ignore))
    {
        Add-DnsServerResourceRecordA -ComputerName $DomainDC1 -Name "mylabhost04" -ZoneName "$playzone" -IPv4Address "172.111.10.14" -TimeToLive 01:00:00 -CreatePtr -AgeRecord -AllowUpdateAny -Verbose
    }
    # Even though the above line should create a PTR, it generates an error due to the PTR possibly already existing or because PowerShell is stupid
    If (!(Get-DnsServerResourceRecord -ComputerName $DomainDC2 -Name "14.10.111" -ZoneName "172.in-addr.arpa" -RRType Ptr -WarningAction Ignore -ErrorAction Ignore))
    {
        Add-DnsServerResourceRecordPtr -ComputerName $DomainDC2 -Name "14.10.111" -ZoneName "172.in-addr.arpa" -PtrDomainName "mylabhost04.specialsite.lab" -TimeToLive 01:00:00 -AllowUpdateAny -AgeRecord -Verbose
    }

}
Else
{
    Write-Host ""
    Write-Host ":: Updating DNS forward zone '$playzone'..." -ForegroundColor Yellow
    Set-DnsServerPrimaryZone -ComputerName $DomainDC1 -DynamicUpdate NonsecureAndSecure -Name "$playzone" -Verbose
    Set-DnsServerPrimaryZone -ComputerName $DomainDC1 -Name "$playzone" -Notify Notify -Verbose
    
    Start-Sleep 5
    If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
    If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}

    Set-DnsServerPrimaryZone -ComputerName $DomainDC1 -Name "$playzone" -Notify NoNotify -Verbose
    
    Write-Host ""
    Write-Host ":: Make sure there are records in the zone..." -ForegroundColor Yellow
    Write-Host ""

    If (!(Get-DnsServerResourceRecord -ComputerName $DomainDC1 -Name "mylabhost01" -ZoneName "$playzone" -WarningAction Ignore -ErrorAction Ignore))
    {
        Add-DnsServerResourceRecordA -ComputerName $DomainDC1 -Name "mylabhost01" -ZoneName "$playzone" -IPv4Address "172.111.10.11" -TimeToLive 01:00:00 -CreatePtr -AgeRecord -AllowUpdateAny -WarningAction Ignore -ErrorAction Ignore -Verbose
    }
    # Even though the above line should create a PTR, it generates an error due to the PTR possibly already existing or because PowerShell is stupid
    If (!(Get-DnsServerResourceRecord -ComputerName $DomainDC2 -Name "11.10.111" -ZoneName "172.in-addr.arpa" -RRType Ptr -WarningAction Ignore -ErrorAction Ignore))
    {
        Add-DnsServerResourceRecordPtr -ComputerName $DomainDC2 -Name "11.10.111" -ZoneName "172.in-addr.arpa" -PtrDomainName "mylabhost01.specialsite.lab" -TimeToLive 01:00:00 -AllowUpdateAny -AgeRecord -Verbose
    }


    If (!(Get-DnsServerResourceRecord -ComputerName $DomainDC1 -Name "mylabhost02" -ZoneName "$playzone" -WarningAction Ignore -ErrorAction Ignore))
    {
        Add-DnsServerResourceRecordA -ComputerName $DomainDC1 -Name "mylabhost02" -ZoneName "$playzone" -IPv4Address "172.111.10.12" -TimeToLive 01:00:00 -CreatePtr -AgeRecord -AllowUpdateAny -WarningAction Ignore -ErrorAction Ignore -Verbose
    }
    # Even though the above line should create a PTR, it generates an error due to the PTR possibly already existing or because PowerShell is stupid
    If (!(Get-DnsServerResourceRecord -ComputerName $DomainDC2 -Name "12.10.111" -ZoneName "172.in-addr.arpa" -RRType Ptr -WarningAction Ignore -ErrorAction Ignore))
    {
        Add-DnsServerResourceRecordPtr -ComputerName $DomainDC2 -Name "12.10.111" -ZoneName "172.in-addr.arpa" -PtrDomainName "mylabhost02.specialsite.lab" -TimeToLive 01:00:00 -AllowUpdateAny -AgeRecord -Verbose
    }

    If (!(Get-DnsServerResourceRecord -ComputerName $DomainDC1 -Name "mylabhost03" -ZoneName "$playzone" -WarningAction Ignore -ErrorAction Ignore))
    {
        Add-DnsServerResourceRecordA -ComputerName $DomainDC1 -Name "mylabhost03" -ZoneName "$playzone" -IPv4Address "172.111.10.13" -TimeToLive 01:00:00 -CreatePtr -AgeRecord -AllowUpdateAny -WarningAction Ignore -ErrorAction Ignore -Verbose
    }
    # Even though the above line should create a PTR, it generates an error due to the PTR possibly already existing or because PowerShell is stupid
    If (!(Get-DnsServerResourceRecord -ComputerName $DomainDC2 -Name "13.10.111" -ZoneName "172.in-addr.arpa" -RRType Ptr -WarningAction Ignore -ErrorAction Ignore))
    {
        Add-DnsServerResourceRecordPtr -ComputerName $DomainDC2 -Name "13.10.111" -ZoneName "172.in-addr.arpa" -PtrDomainName "mylabhost03.specialsite.lab" -TimeToLive 01:00:00 -AllowUpdateAny -AgeRecord -Verbose
    }

    If (!(Get-DnsServerResourceRecord -ComputerName $DomainDC1 -Name "mylabhost04" -ZoneName "$playzone" -WarningAction Ignore -ErrorAction Ignore))
    {
        Add-DnsServerResourceRecordA -ComputerName $DomainDC1 -Name "mylabhost04" -ZoneName "$playzone" -IPv4Address "172.111.10.14" -TimeToLive 01:00:00 -CreatePtr -AgeRecord -AllowUpdateAny -WarningAction Ignore -ErrorAction Ignore -Verbose
    }
    # Even though the above line should create a PTR, it generates an error due to the PTR possibly already existing or because PowerShell is stupid
    If (!(Get-DnsServerResourceRecord -ComputerName $DomainDC2 -Name "14.10.111" -ZoneName "172.in-addr.arpa" -RRType Ptr -WarningAction Ignore -ErrorAction Ignore))
    {
        Add-DnsServerResourceRecordPtr -ComputerName $DomainDC2 -Name "14.10.111" -ZoneName "172.in-addr.arpa" -PtrDomainName "mylabhost04.specialsite.lab" -TimeToLive 01:00:00 -AllowUpdateAny -AgeRecord -Verbose
    }

}


Write-Host ""
Write-Host ""

Write-Host ":: Get DNS A record for 'testhost099' in zone '$DomainDNSRoot'..." -ForegroundColor Yellow
Get-DnsServerResourceRecord -ComputerName $DomainDC1 -Name "testhost099" -ZoneName "$DomainDNSRoot"
Write-Host ""
Write-Host ":: Delete the A record 'testhost099' if it already exists..." -ForegroundColor Yellow
Remove-DnsServerResourceRecord -ComputerName $DomainDC1 -ZoneName "$DomainDNSRoot" -RRType "A" -Name "testhost099" -RecordData "172.18.99.99" -Confirm:$False -Force

Write-Host ""
Write-Host ":: Force replication after 10 second pause..." -ForegroundColor Yellow
Start-Sleep 10
If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}

Write-Host ""
Write-Host ":: Create and modify a DNS A record in the '$DomainDNSRoot' zone..." -ForegroundColor Yellow
Write-Host ""

Write-Host ":: Add a DNS A record 'testhost099'..." -ForegroundColor Yellow
Add-DnsServerResourceRecordA -ComputerName $DomainDC1 -Name "testhost099" -ZoneName "$DomainDNSRoot" -IPv4Address "172.18.99.99" -TimeToLive 01:00:00 -CreatePtr -AgeRecord -AllowUpdateAny -WarningAction Ignore -ErrorAction Ignore -Verbose
# Even though the above line should create a PTR, it generates an error due to the PTR possibly already existing or because PowerShell is stupid
If (!(Get-DnsServerResourceRecord -ComputerName $DomainDC1 -Name "99.99.18" -ZoneName "172.in-addr.arpa"))
{
    Write-Host ":: Add a DNS PTR record '99.99.18.172.in-addr.arpa' for 'testhost099'..." -ForegroundColor Yellow
    Add-DnsServerResourceRecordPtr -ComputerName $DomainDC1 -Name "99.99.18" -ZoneName "172.in-addr.arpa" -PtrDomainName "testhost099.$DomainDNSRoot" -TimeToLive 01:00:00 -AllowUpdateAny -AgeRecord -WarningAction Ignore -ErrorAction Ignore -Verbose
}

Write-Host ""
Write-Host ":: Add a DNS A record 'deadhost01'..." -ForegroundColor Yellow
Add-DnsServerResourceRecordA -ComputerName $DomainDC1 -Name "deadhost01" -ZoneName "$DomainDNSRoot" -IPv4Address "172.18.11.11" -TimeToLive 01:00:00 -CreatePtr -AgeRecord -AllowUpdateAny -WarningAction Ignore -ErrorAction Ignore -Verbose
# Even though the above line should create a PTR, it generates an error due to the PTR possibly already existing or because PowerShell is stupid
If (!(Get-DnsServerResourceRecord -ComputerName $DomainDC1 -Name "11.11.18" -ZoneName "172.in-addr.arpa"))
{
    Write-Host ":: Add a DNS PTR record '11.11.18.172.in-addr.arpa' for 'deadhost01'..." -ForegroundColor Yellow
    Add-DnsServerResourceRecordPtr -ComputerName $DomainDC1 -Name "11.11.18" -ZoneName "172.in-addr.arpa" -PtrDomainName "deadhost01.$DomainDNSRoot" -TimeToLive 01:00:00 -AllowUpdateAny -AgeRecord -WarningAction Ignore -ErrorAction Ignore -Verbose
}

Write-Host ""
Write-Host ":: Add a DNS A record 'deadhost02'..." -ForegroundColor Yellow
Add-DnsServerResourceRecordA -ComputerName $DomainDC1 -Name "deadhost02" -ZoneName "$DomainDNSRoot" -IPv4Address "172.18.11.12" -TimeToLive 01:00:00 -CreatePtr -AllowUpdateAny -WarningAction Ignore -ErrorAction Ignore -Verbose
# Even though the above line should create a PTR, it generates an error due to the PTR possibly already existing or because PowerShell is stupid
If (!(Get-DnsServerResourceRecord -ComputerName $DomainDC1 -Name "12.11.18" -ZoneName "172.in-addr.arpa"))
{
    Write-Host ":: Add a DNS PTR record '12.11.18.172.in-addr.arpa' for 'deadhost02'..." -ForegroundColor Yellow
    Add-DnsServerResourceRecordPtr -ComputerName $DomainDC1 -Name "12.11.18" -ZoneName "172.in-addr.arpa" -PtrDomainName "deadhost02.$DomainDNSRoot" -TimeToLive 01:00:00 -AllowUpdateAny -AgeRecord -WarningAction Ignore -ErrorAction Ignore -Verbose
}

Write-Host ""
Start-Sleep 6

Get-DnsServerResourceRecord -ComputerName $DomainDC1 -Name "testhost099" -ZoneName "$DomainDNSRoot" -Verbose
Write-Host ""
Start-Sleep 6

Write-Host ":: Change DNS TTL on 'testhost099' A record..." -ForegroundColor Yellow
$OldObj = Get-DnsServerResourceRecord -ComputerName $DomainDC1 -Name "testhost099" -ZoneName "$DomainDNSRoot" -RRType "A"
$NewObj = $OldObj.Clone()
$NewObj.TimeToLive = [System.TimeSpan]::FromHours(2)
Set-DnsServerResourceRecord -ComputerName $DomainDC1 -NewInputObject $NewObj -OldInputObject $OldObj -ZoneName "$DomainDNSRoot" -PassThru
Write-Host ""
#Write-Host ":: Remove the A record for 'deadhost01'..." -ForegroundColor Yellow
#Remove-DnsServerResourceRecord -ComputerName $DomainDC1 -ZoneName "$DomainDNSRoot" -RRType "A" -Name "deadhost01" -RecordData "172.18.11.11" -Confirm:$False -Force
#Start-Sleep 10


Write-Host ":: Force replication after 5 second pause..." -ForegroundColor Yellow
Start-Sleep 5
If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}





#------------------------------------------------------------------------------
# Finish making change to the in the Default Domain GPO
Write-Host "`n`n"
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- MORE DEFAULT DOMAIN GPO STUFF ----                     " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
Write-Host ":: Get the 'Default Domain Policy' GPO info..." -ForegroundColor Yellow
Get-ADDefaultDomainPasswordPolicy -Verbose

# NOTE: For some reason, making multiple changes to LockoutThreshold in this GPO will 
# not be captured if multiple changes are made to the same value/key. So, I moved a 
# copy of the steps here to give more time for the previous changes to "settle".

Write-Host ":: Set LockoutThreshold value to '888' in 'Default Domain Policy'..." -ForegroundColor Yellow
Set-ADDefaultDomainPasswordPolicy -Identity $DomainDNSRoot -LockoutThreshold 888 -Verbose

Start-Sleep 10
Write-Host ":: Get the modified 'Default Domain Policy' GPO info..." -ForegroundColor Yellow
Get-ADDefaultDomainPasswordPolicy -Verbose
Write-Host ""
Write-Host ""







#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                        " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- OU ACTIONS PART 2: POPULATE USERS INTO OU ($UsersOUName02) ----          " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                        " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

# This is setting the secondary phase of this action, where 01 is going our starting point
# where we will move ALL user accounts to 02. The idea is to generate activity 
# that will reflect on the activity graph on the DSP Overview page.

Write-Host ":: Move ALL users in OU '$UsersOUName01' to OU '$UsersOUName02'..." -ForegroundColor Yellow

$UsersOUName01dn = (Get-ADOrganizationalUnit -LDAPFilter "(OU=$UsersOUName01)").DistinguishedName
$UsersOUName02dn = (Get-ADOrganizationalUnit -LDAPFilter "(OU=$UsersOUName02)").DistinguishedName

$adUserGroup = Get-ADUser -Filter {Enabled -eq "True"} -SearchBase ($UsersOUName01dn)

# Move any user object in 01 to 02...

If ($adUserGroup.Count -gt 0)
    {
    ForEach($user in $adUserGroup)
        {
        Write-Host ":: -- Moving Active Directory user: '$($user.Name)'" -ForegroundColor Yellow
        Write-Host "      -- Target OU: '$UsersOUName02dn'" -ForegroundColor Magenta
        Move-ADObject -Identity $user -targetpath $UsersOUName02dn -Verbose
        Write-Host ""
        }

    Write-Host "`n"
    Write-Host "::                                                              "  -ForegroundColor Yellow -BackgroundColor DarkGray
    Write-Host ":: User objects moved from OU=$UsersOUName01 to OU=$UsersOUName02!!!          " -ForegroundColor Yellow -BackgroundColor DarkGray
    Write-Host "::                                                              "  -ForegroundColor Yellow -BackgroundColor DarkGray
    Write-Host "::                                                              "  -ForegroundColor Yellow -BackgroundColor DarkGray
    Write-Host ":: Be sure to check the Activity graph on the Overview page!!   "  -ForegroundColor Yellow -BackgroundColor DarkGray
    Write-Host "::                                                              "  -ForegroundColor Yellow -BackgroundColor DarkGray
    Write-Host "`n"
    }
Else
    {
    Write-Host "`n`n"
    Write-Host "::                                                            " -ForegroundColor Red -BackgroundColor Yellow
    Write-Host "::   NO USER OBJECTS TO MOVE FROM OU '$UsersOUName01'!!!             " -ForegroundColor Red -BackgroundColor Yellow
    Write-Host "::                                                            " -ForegroundColor Red -BackgroundColor Yellow
    Write-Host "::   NO ADDITIONAL MOVE STATISTICS WILL BE GENERATED!!        " -ForegroundColor Red -BackgroundColor Yellow
    Write-Host "::                                                            " -ForegroundColor Red -BackgroundColor Yellow
    Write-Host "`n`n"
    }






#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                   " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- USER OBJECT STUFF - CHANGE FAX: DemoUser1 ($($DemoUser1.Name)) ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                   " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

#$DemoUserObj = Get-ADUser -LDAPFilter "(&(objectCategory=person)(sAMAccountName=$($DemoUser1.SamAccountName)))" -Verbose -ErrorAction SilentlyContinue

If ($UserObj = Get-ADUser -LDAPFilter "(&(objectCategory=person)(sAMAccountName=$($DemoUser1.SamAccountName)))" -Verbose -ErrorAction SilentlyContinue)
{
    Write-Host ":: Get 'facsimileTelephoneNumber' for user object '$($UserObj.Name)'..." -ForegroundColor Yellow
    (Get-ADUser -Identity "$($UserObj.DistinguishedName)" -Properties facsimileTelephoneNumber).facsimileTelephoneNumber
    Write-Host ":: Change 'FAX' for user object '$($UserObj.Name)' to '$($DemoUser1.FAXalt)'..." -ForegroundColor Yellow # facsimileTelephoneNumber
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Fax "$($DemoUser1.FAXalt)" -Verbose

    Write-Host ""
    Write-Host ":: 3 second pause..." -ForegroundColor Yellow
    Start-Sleep 3

}





#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                         " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- USER OBJECT STUFF - CHANGE FAX: DemoUser2 ($($DemoUser2.Name)) ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                         " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

#$DemoUserObj = Get-ADUser -LDAPFilter "(&(objectCategory=person)(sAMAccountName=$($DemoUser2.SamAccountName)))" -Verbose -ErrorAction SilentlyContinue

If ($UserObj = Get-ADUser -LDAPFilter "(&(objectCategory=person)(sAMAccountName=$($DemoUser2.SamAccountName)))" -Verbose -ErrorAction SilentlyContinue)
{
    Write-Host ":: Get 'facsimileTelephoneNumber' for user object '$($UserObj.Name)'..." -ForegroundColor Yellow
    (Get-ADUser -Identity "$($UserObj.DistinguishedName)" -Properties facsimileTelephoneNumber).facsimileTelephoneNumber
    Write-Host ":: Change 'FAX' for user object '$($UserObj.Name)' to '$($DemoUser2.FAXalt)'..." -ForegroundColor Yellow # facsimileTelephoneNumber
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Fax "$($DemoUser2.FAXalt)" -Verbose

    Write-Host ""
    Write-Host ":: 3 second pause..." -ForegroundColor Yellow
    Start-Sleep 3

}





#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                        " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- USER OBJECT STUFF - CHANGE FAX: DemoUser3 ($($DemoUser3.Name)) ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                        " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

#$DemoUserObj = Get-ADUser -LDAPFilter "(&(objectCategory=person)(sAMAccountName=$($DemoUser3.SamAccountName)))" -Verbose -ErrorAction SilentlyContinue

If ($UserObj = Get-ADUser -LDAPFilter "(&(objectCategory=person)(sAMAccountName=$($DemoUser3.SamAccountName)))" -Verbose -ErrorAction SilentlyContinue)
{
    Write-Host ":: Get 'facsimileTelephoneNumber' for user object '$($UserObj.Name)'..." -ForegroundColor Yellow
    (Get-ADUser -Identity "$($UserObj.DistinguishedName)" -Properties facsimileTelephoneNumber).facsimileTelephoneNumber
    Write-Host ":: Change 'FAX' for user object '$($UserObj.Name)' to '$($DemoUser3.FAXalt)'..." -ForegroundColor Yellow # facsimileTelephoneNumber
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Fax "$($DemoUser3.FAXalt)" -Verbose

    Write-Host ""
    Write-Host ":: 3 second pause..." -ForegroundColor Yellow
    Start-Sleep 3

}


Write-Host ""
Write-Host ":: Force replication after 1 second pause..." -ForegroundColor Yellow
Start-Sleep 1
If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}








#------------------------------------------------------------------------------
# Changing 3 user accounts for undo examples: wrong department number
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- USER OBJECT STUFF - CHANGE DEPT: DemoUser1 ($($DemoUser1.Name)) ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

#$DemoUserObj = Get-ADUser -LDAPFilter "(&(objectCategory=person)(sAMAccountName=$($DemoUser1.SamAccountName)))" -Verbose -ErrorAction SilentlyContinue

If ($UserObj = Get-ADUser -LDAPFilter "(&(objectCategory=person)(sAMAccountName=$($DemoUser1.SamAccountName)))" -Verbose -ErrorAction SilentlyContinue)
{
    Write-Host ":: Get 'department' for user object '$($UserObj.Name)'..." -ForegroundColor Yellow
    (Get-ADUser -Identity "$($UserObj.DistinguishedName)" -Properties department).department
    Write-Host ":: Change 'department' for user object '$($UserObj.Name)' to 'xxxxxx'..." -ForegroundColor Yellow # department
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Department "xxxxxx" -Verbose
    
    Write-Host ""
    Write-Host ":: 3 second pause..." -ForegroundColor Yellow
    Start-Sleep 3

}


#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                          " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- USER OBJECT STUFF - CHANGE DEPT: DemoUser2 ($($DemoUser2.Name)) ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                          " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

#$DemoUserObj = Get-ADUser -LDAPFilter "(&(objectCategory=person)(sAMAccountName=$($DemoUser2.SamAccountName)))" -Verbose -ErrorAction SilentlyContinue

If ($UserObj = Get-ADUser -LDAPFilter "(&(objectCategory=person)(sAMAccountName=$($DemoUser2.SamAccountName)))" -Verbose -ErrorAction SilentlyContinue)
{
    Write-Host ":: Get 'department' for user object '$($UserObj.Name)'..." -ForegroundColor Yellow
    (Get-ADUser -Identity "$($UserObj.DistinguishedName)" -Properties department).department
    Write-Host ":: Change 'department' for user object '$($UserObj.Name)' to 'xxxxxx'..." -ForegroundColor Yellow # department
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Department "xxxxxx" -Verbose

    Write-Host ""
    Write-Host ":: 3 second pause..." -ForegroundColor Yellow
    Start-Sleep 3

}


#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                         " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- USER OBJECT STUFF - CHANGE DEPT: DemoUser3 ($($DemoUser3.Name)) ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                         " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

#$DemoUserObj = Get-ADUser -LDAPFilter "(&(objectCategory=person)(sAMAccountName=$($DemoUser3.SamAccountName)))" -Verbose -ErrorAction SilentlyContinue

If ($UserObj = Get-ADUser -LDAPFilter "(&(objectCategory=person)(sAMAccountName=$($DemoUser3.SamAccountName)))" -Verbose -ErrorAction SilentlyContinue)
{
    Write-Host ":: Get 'department' for user object '$($UserObj.Name)'..." -ForegroundColor Yellow
    (Get-ADUser -Identity "$($UserObj.DistinguishedName)" -Properties department).department
    Write-Host ":: Change 'department' for user object '$($UserObj.Name)' to 'xxxxxx'..." -ForegroundColor Yellow # department
    Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Department "xxxxxx" -Verbose

    Write-Host ""
    Write-Host ":: 3 second pause..." -ForegroundColor Yellow
    Start-Sleep 3

}


Write-Host ""
Write-Host ":: Force replication after 1 second pause..." -ForegroundColor Yellow
Start-Sleep 1
If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}







#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- MORE DNS CHANGES ----                                  " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
Write-Host ":: Remove the A record for 'deadhost01'..." -ForegroundColor Yellow
Remove-DnsServerResourceRecord -ComputerName $DomainDC1 -ZoneName "$DomainDNSRoot" -RRType "A" -Name "deadhost01" -RecordData "172.18.11.11" -Confirm:$False -Force -Verbose
Start-Sleep 3





#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- MORE ACL STUFF ----                                    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
Write-Host ":: Change ACL on 'Bad OU' -allowing- 'Everyone' to have 'deleteChild' permission..." -ForegroundColor Yellow
# OU=Bad OU,DC=f097-d01,DC=lab

$OU = $null
$objACL = $null
$OU = Get-ADOrganizationalUnit -LDAPFilter '(&(objectClass=OrganizationalUnit)(OU=Bad OU))'

#$User = [Security.Principal.NTAccount]'Everyone'
$GroupSID = [System.Security.Principal.SecurityIdentifier]'S-1-1-0' #Everyone Group

$objACL = Get-ACL "AD:\$($OU)"

# Need to make sure we get a change, so set to add the Deny permission, which may already be set...
$objACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($GroupSID,"DeleteChild,DeleteTree","Deny", 'None', [guid]'00000000-0000-0000-0000-000000000000')
$objACL.AddAccessRule($objACE)
Set-acl -AclObject $objACL "AD:\$OU" -Verbose
Start-Sleep 5

# Now remove the Deny ACE we just granted...
$objACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($GroupSID,"DeleteChild,DeleteTree","Deny", 'None', [guid]'00000000-0000-0000-0000-000000000000')
$objACL.RemoveAccessRule($objACE)
Set-acl -AclObject $objACL "AD:\$OU" -Verbose
Start-Sleep 5

# Now set to Allow DeleteChild and DeleteTree...
$objACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($GroupSID,"DeleteChild,DeleteTree","Allow", 'None', [guid]'00000000-0000-0000-0000-000000000000')
#$objACL.AddAccessRule($objACE)(Get-Acl -Path $OU.DistinguishedName).Access
$objACL.AddAccessRule($objACE)
Set-acl -AclObject $objACL "AD:\$OU" -Verbose
Start-Sleep 5

Write-Host ""
Write-Host ":: Force replication after 1 second pause..." -ForegroundColor Yellow
Start-Sleep 1
If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}

Write-Host ""
Write-Host ""
Write-Host ":: Change ACL on 'Bad OU' -removing- 'deleteChild, DeleteTree' permissions for 'Everyone'..." -ForegroundColor Yellow

# Now remove the Allow DeleteTree right...
$objACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($GroupSID,"DeleteTree","Allow", 'None', [guid]'00000000-0000-0000-0000-000000000000')
#$objACL.AddAccessRule($objACE)(Get-Acl -Path $OU.DistinguishedName).Access
$objACL.RemoveAccessRule($objACE)
Set-acl -AclObject $objACL "AD:\$OU" -Verbose
Start-Sleep 5

# Now remove the Allow DeleteChild ACE...
$objACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($GroupSID,"DeleteChild","Allow", 'None', [guid]'00000000-0000-0000-0000-000000000000')
#$objACL.AddAccessRule($objACE)(Get-Acl -Path $OU.DistinguishedName).Access
$objACL.RemoveAccessRule($objACE)
Set-acl -AclObject $objACL "AD:\$OU" -Verbose
Start-Sleep 2

$objACL = $null
$OU = $null





#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- MORE OU STUFF: DELETING 'DELETE ME' OU ----            " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
If ((Get-ADOrganizationalUnit -LDAPFilter '(OU=DeleteMe OU)'))
{
    Write-Host "::    -- Deleting OU 'DeleteMe OU'..." -ForegroundColor Cyan
    Set-ADOrganizationalUnit -Identity "OU=DeleteMe OU,$DomainDN" -ProtectedFromAccidentalDeletion $False -Verbose
    Start-Sleep 5
	Remove-ADOrganizationalUnit -Identity "OU=DeleteMe OU,$DomainDN" -Recursive -ErrorAction SilentlyContinue -Confirm:$False -Verbose
}

Start-Sleep 3





#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- MORE OU STUFF: LINKING GPO TO 'Bad OU' ----            " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
Write-Host ":: These changes will generate a 'gpLink' event in the change auditing..." -ForegroundColor Yellow
Write-Host ""
Write-Host "::   Removing a GPLink if it exists...   (just force removing without checking and drop output)" -ForegroundColor Yellow
Write-Host "Remove-GPLink -Name $objSpecialGPO.DisplayName -Target ""$($objOU4GPO.DistinguishedName)"" -Domain ""$DomainDNSRoot"" -Verbose -ErrorAction Ignore" -ForegroundColor Cyan
Remove-GPLink -Name $objSpecialGPO.DisplayName -Target "$($objOU4GPO.DistinguishedName)" -Domain "$DomainDNSRoot" -Verbose -ErrorAction SilentlyContinue # | Out-Null
Start-Sleep 7
Write-Host ""
Write-Host "::   Adding GPLink..." -ForegroundColor Yellow
New-GPLink -Name $objSpecialGPO.DisplayName -Target "$($objOU4GPO.DistinguishedName)" -LinkEnabled Yes -Domain "$DomainDNSRoot" -Verbose
Write-Host ""
Write-Host ""

Start-Sleep 5







## NOTE: Increased the gap of these GPO changes for the CIS Benchmark settings in order to 
## differentiate the changes within the GPO module in DSP. 


#------------------------------------------------------------------------------
#
# CIS Windows Server Policy GPO - Update Policy (part 2 - change setting!!)
#
#
# Trying to keep this at least 5 minutes later so it is clearly found in the change stream.
#
# Updating some settings, 1) to show a more restrictive setting and 2) to set a less
# restrictive setting. In a demo, I can speak to how outages can be incured due to
# GPO changes and we can see the differences.
#
# We made the initial settings in an earlier section of this code.
#
#

$GPOName = 'CIS Benchmark Windows Server Policy GPO'


Write-Host "`n`n"
Write-Host "::                                                                         " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- GPO STUFF: '$GPOName' ----          " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                         " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""


$DateTag = Get-Date -Format "yyyy-dd-MM_HHmm"

# GPO was created a little earlier in this script...

# Should add error-handling in case the GPO didn't get created!!

$GPO = $null
$GPO = Get-GPO -Name "$GPOName" -ErrorAction SilentlyContinue


#If (!($GPO = Get-GPO -Name "$GPOName" -ErrorAction SilentlyContinue))
#{
#    Write-Host ":: Create '$GPOName' if it does not exist..." -ForegroundColor Yellow
#    New-GPO -Name "$GPOName" -Comment "This is a GPO with some CIS Benchmark recommendations for testing GPO changes $DateTag" -ErrorAction SilentlyContinue -Verbose
#    Write-Host ""
#    Write-Host "`n"
#    Write-Host ":: Force replication after 15 seconds to propagate new GPO..." -ForegroundColor Yellow
#    Start-Sleep 15
#    If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
#    If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}
#
#    $GPO = Get-GPO -Name "$GPOName" -ErrorAction SilentlyContinue
#}

#$GPO = Get-GPO -Name "$GPOName"
$GPO
$GPO.Description = "This is a GPO with some CIS Benchmark recommendations for testing GPO changes $DateTag"
Write-Host ""
Write-Host ""

# NOTE: These ALL end up as "Extra Registry Settings"!!! I cannot figure out how to set the policy
#       settings using the defined registry settings/keys. 

    # "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" AllowInsecureGuestAuth = 0 | 1
    #
    # This policy setting determines if the SMB client will allow insecure guest logons to an SMB server.  
    #
    # If you enable this policy setting or if you do not configure this policy setting, the SMB client will 
    # allow insecure guest logons.  
    #
    # If you disable this policy setting, the SMB client will reject insecure 
    # guest logons.  
    #
    # Insecure guest logons are used by file servers to allow unauthenticated access to shared folders. 
    # While uncommon in an enterprise environment, insecure guest logons are frequently used by consumer 
    # Network Attached Storage (NAS) appliances acting as file servers. Windows file servers require 
    # authentication and do not use insecure guest logons by default. Since insecure guest logons 
    # are unauthenticated, important security features such as SMB Signing and SMB Encryption are disabled. 
    # As a result, clients that allow insecure guest logons are vulnerable to a variety of man-in-the-middle 
    # attacks that can result in data loss, data corruption, and exposure to malware. Additionally, any data
    # written to a file server using an insecure guest logon is potentially accessible to anyone on the network. 
    # Microsoft recommends disabling insecure guest logons and configuring file servers to require authenticated access.


#NOTE: Earlier, we set settings for this GPO. Now we are going to change and weaken some settings....


    Write-Host ""
    Write-Host ":: Get current setting for 'AllowInsecureGuestAuth' in GPO '$($GPO.DisplayName)..." -ForegroundColor Yellow
    Write-Host ""
    Get-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName AllowInsecureGuestAuth -Verbose -ErrorAction SilentlyContinue
    Write-Host ""
    Write-Host ":: Set 'AllowInsecureGuestAuth' to insecure value '0' to ALLOW insecure SMB client connections..." -ForegroundColor Yellow
    #Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName AllowInsecureGuestAuth -Value 0 -Type DWord -Verbose # enabled is SECURE!!
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName AllowInsecureGuestAuth -Value 1 -Type DWord # disabled is INSECURE!!
    Write-Host ""
    Write-Host "" 

    # Change some of the CIS Benchmark values
    Write-Host ""
    Write-Host ":: Make sure all of the CIS Benchmark settings are set/reset to secure values..."
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" -ValueName AllowInsecureGuestAuth -Value 1 -Type DWord -Verbose # disabled is INSECURE!!
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "DetectionFrequencyEnabled" -Value 1 -Type DWord -Verbose
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "De-tectionFrequency" -Value 22 -Type DWord -Verbose
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" -ValueName "forceguest" -Value 1 -Type DWord -Verbose # Force Guest; less secure connections
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" -ValueName "allownullsessionfallback" -Value 0 -Type DWord -Verbose
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" -ValueName "NoLMHash" -Value 1 -Type DWord -Verbose


# Network security: LAN Manager authentication level
# DESCRIPTION: This policy setting determines which challenge or response authentication protocol is used for network logons. 
# POLICY LOCATION: Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options
# REGISTRY LOCATION: HKLM\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel
# 
# Setting 	 	                                                Registry security level
# "Send LM & NTLM responses" 	                                0
# "Send LM & NTLM   use NTLMv2 session security if negotiated"  1
# "Send NTLM response only"                                     2
# "Send NTLMv2 response only"                                   3
# "Send NTLMv2 response only. Refuse LM"                        4
# "Send NTLMv2 response only. Refuse LM & NTLM"                 5
#
    Get-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\System\CurrentControlSet\Control\Lsa\" -ValueName "LmCompatibilityLevel" -ErrorAction Silent -Verbose
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\System\CurrentControlSet\Control\Lsa\" -ValueName "LmCompatibilityLevel" -Value 3 -Type DWord -Verbose


Write-Host "`n"
Write-Host ":: Force replication..." -ForegroundColor Yellow
If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}

Write-Host ""
Write-Host ""
Write-Host "Invoke-GPUpdate -Force -Verbose" -ForegroundColor Cyan
Start-Sleep 5
Invoke-GPUpdate -Force -Verbose
Write-Host ""
Write-Host ""
#
#------------------------------------------------------------------------------










<#
https://docs.microsoft.com/en-us/windows/win32/ad/control-access-rights

For extended rights, which are special operations not covered by the standard set of access rights. For example, the user class can be granted a "Send As" right that can be used by Exchange, Outlook, or any other mail application, to determine whether a particular user can have another user send mail on their behalf. Extended rights are created on controlAccessRight objects by setting the validAccesses attribute to equal the ADS_RIGHT_DS_CONTROL_ACCESS (256) access right.

For defining property sets, to enable controlling access to a subset of an object's attributes, rather than just to the individual attributes. Using the standard access rights, a single ACE can grant or deny access to all of an object's attributes or to a single attribute. Control access rights provide a way for a single ACE to control access to a set of attributes. For example, the user class supports the Personal-Information property set that includes attributes such as street address and telephone number. Property set rights are created on controlAccessRight objects by setting the validAccesses attribute to contain both the ACTR_DS_READ_PROP (16) and the ACTRL_DS_WRITE_PROP (32) access rights.


AccessSystemSecurity 	16777216	The right to get or set the SACL in the object security descriptor.
CreateChild 	        1	        The right to create children of the object.
Delete 	                65536    	The right to delete the object.
DeleteChild           	2       	The right to delete children of the object.
DeleteTree           	64      	The right to delete all children of this object, regardless of the permissions of the children.
ExtendedRight        	256     	A customized control access right. For a list of possible extended rights, see the Extended Rights article. For more information about extended rights, see the Control Access Rights article.
GenericAll          	983551  	The right to create or delete children, delete a subtree, read and write properties, examine children and the object itself, add and remove the object from the directory, and read or write with an extended right.
GenericExecute      	131076   	The right to read permissions on, and list the contents of, a container object.
GenericRead         	131220   	The right to read permissions on this object, read all the properties on this object, list this object name when the parent container is listed, and list the contents of this object if it is a container.
GenericWrite        	131112   	The right to read permissions on this object, write all the properties on this object, and perform all validated writes to this object.
ListChildren        	4       	The right to list children of this object. For more information about this right, see the Controlling Object Visibility article.
ListObject          	128      	The right to list a particular object. For more information about this right, see the see the Controlling Object Visibility article.
ReadControl         	131072   	The right to read data from the security descriptor of the object, not including the data in the SACL.
ReadProperty        	16       	The right to read properties of the object.
Self                	8       	The right to perform an operation that is controlled by a validated write access right.
Synchronize         	1048576   	The right to use the object for synchronization. This right enables a thread to wait until that object is in the signaled state.
WriteDacl           	262144   	The right to modify the DACL in the object security descriptor.
WriteOwner          	524288   	The right to assume ownership of the object. The user must be an object trustee. The user cannot transfer the ownership to other users.
WriteProperty       	32       	The right to write properties of the object.


#>


<#

You can use the script below to get and assign Full Control permission to a computer object on an OU:

$acl = get-acl "ad:OU=xxx,DC=com"

$acl.access        #to get access right of the OU

$computer = get-adcomputer "COMPUTERNAME"

$sid = [System.Security.Principal.SecurityIdentifier] $computer.SID

# Create a new access control entry to allow access to the OU

$identity = [System.Security.Principal.IdentityReference] $SID

$adRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"

$type = [System.Security.AccessControl.AccessControlType] "Allow"

$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"

$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType

# Add the ACE to the ACL, then set the ACL to save the changes

$acl.AddAccessRule($ace)

Set-acl -aclobject $acl "ad:OU=xxx,DC=com"

#>






# THIS ACL SETTING DOES NOT SEEM TO WORK PROPERLY!!!  THE ACL IS NOT CHANGED AS EXPECTED!!!
# THE "ALLOW" SEEMS TO ENABLE A "DENY" CHECKBOX!!!  THEN, MANUALLY UNCHECKING THE "DENY" 
# MAKES THE "ALLOW" CHECKED!!  WE NEED A "CLEAR" FUNCTION.


#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- ACL CHANGE STUFF - PART 2: 'OU=BAD OU' ----            " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
Write-Host ":: Change ACL on 'Bad OU' -allowing- 'Everyone' to have 'deleteChild' permission..." -ForegroundColor Yellow
Write-Host "::   (this is probably a BAD thing!!!)" -ForegroundColor Yellow

# example: OU=Bad OU,DC=f097-d01,DC=lab

$OU = $null
$objACL = $null
$OU = Get-ADOrganizationalUnit -LDAPFilter '(&(objectClass=OrganizationalUnit)(OU=Bad OU))'

#$User = [Security.Principal.NTAccount]'Everyone'
$GroupSID = [System.Security.Principal.SecurityIdentifier]'S-1-1-0' #Everyone Group

$objACL = Get-ACL "AD:\$OU"
#$objACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($GroupSID,"DeleteChild,DeleteTree","Deny", 'None', [guid]'00000000-0000-0000-0000-000000000000')
$objACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($GroupSID,"DeleteChild,DeleteTree","Allow", 'None', [guid]'00000000-0000-0000-0000-000000000000')
$objACL.AddAccessRule($objACE)
Set-acl -AclObject $objACL "AD:\$OU" -Verbose

$objACL = $null
$OU = $null
Start-Sleep 5





#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                       " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- LETS CHANGE SOME AD SITE CONFIGURATION STUFF SET EARLIER ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                       " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

Write-Host ":: Site link info for 'DEFAULTIPSITELINK'..." -ForegroundColor Yellow
Get-ADReplicationSiteLink -Identity DEFAULTIPSITELINK

Write-Host ""
Write-Host ":: Let's change the site cost to 555..." -ForegroundColor Yellow
Set-ADReplicationSiteLink -Identity DEFAULTIPSITELINK -Cost 555 -Verbose

Write-Host ""
Write-Host ":: Let's also change the ReplicationFrequencyInMinutes to 16..." -ForegroundColor Yellow
Set-ADReplicationSiteLink -Identity DEFAULTIPSITELINK -ReplicationFrequencyInMinutes 16 -Verbose

Write-Host ""




#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                                            " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- FIND DSP SERVER: UNDO EARLIER CHANGE TO Axl VIA CMDLET: facsimileTelephoneNumber ---- " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                                            " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""

# Use the Import-Module and Connect-DSPServer cmdlets to import the Semperis.PoSh.DSP
# module and connect to the DSP Management Server.

# Use the Get-DSPChangedItem and Get-DSPDeletedItem cmdlets to retrieve the objects you
# would normally see on the Changes page or Changes > Deleted page, respectively.

# NEED TO SEARCH DNS FOR DSP SERVER OR GET THE SERVER NAME AT THE START!!!!!!
#
# dsquery * -filter "(&(objectClass=serviceConnectionPoint))"
# adfind -b "dc=f122-d02,dc=f122-d01,dc=lab" -f "objectClass=serviceConnectionPoint" -s subtree
#
# $SubordinateReferences has the list of partitions (which includes any child domains)
#

Write-Host ""
Write-Host ":: Run 'Import-Module Semperis.PoSh.DSP' to load DSP cmdlets..." -ForegroundColor Yellow
Write-Host ""


#Remove-Module Semperis.PoSh.DSP -Verbose
Import-Module Semperis.PoSh.DSP -Verbose
$ModuleStatus = Get-Module Semperis.PoSh.DSP
If ($ModuleStatus)
{
    Write-Host ""
    Write-Host ":: The DSP PoSh module 'Semperis.PoSh.DSP' has been loaded!!" -ForegroundColor Yellow
    Write-Host ""
    $DspPoShStatus = $true
}
Else
{ 
    Write-Host ":: ------------------------------------------------------------" -ForegroundColor Yellow -BackgroundColor Red
    Write-Host ":: The DSP PoSh module 'Semperis.PoSh.DSP' is NOT installed!!  " -ForegroundColor Yellow -BackgroundColor Red
    Write-Host ":: Skipping DSP cmdlet demo section...                         " -ForegroundColor Yellow -BackgroundColor Red
    Write-Host ":: ------------------------------------------------------------" -ForegroundColor Yellow -BackgroundColor Red
    $DspPoShStatus = $false
}


# If the DSP PoSh module is installed, then use some DSP PoSh cmdlets!!!

If ($DspPoShStatus)
{

# Need to locate the DSP server in the AD forest...
Write-Host ""
Write-Host ":: Searching for the DSP server..." -ForegroundColor Yellow
Write-Host ""

$DSPServerName = $null

$SCPList = Get-ADObject -LDAPFilter "objectClass=serviceConnectionPoint" -SearchBase $DomainDN


If ($SCPList)
{
    # Searching root domain for DSP server

    ForEach($SCPitem in $SCPList)
    {
        If ($SCPitem.Name.Contains('Semperis.Dsp.Management'))
        {
            #$DomainInfo
            $DSPDN = $SCPitem.DistinguishedName.Split(',')
            $DSPServerName = $DSPDN[1].Substring(3) + '.' + $DomainInfo.DNSRoot
            Write-Host ":: ------------------------------------------------------------" -ForegroundColor Green
            Write-Host ":: WE FOUND THE DSP SERVER: $DSPServerName" -ForegroundColor Green
            Write-Host ":: ------------------------------------------------------------" -ForegroundColor Green
        }
    }
}



If (!($DSPServerName))
{
    # If not found in root domain, enumerate through the child domains to find the DSP server.
    ForEach($PartitionName in $SubordinateReferences)
    {
        Write-Host "$PartitionName"
        If ($PartitionName.Contains('DC=DomainDnsZones') -or $PartitionName.Contains('DC=ForestDnsZones') -or $PartitionName.Contains('CN=Configuration'))
        {
            #Write-Host "   NO GOOD!"
        }
        Else
        {
            $SubDomShortName = $null
            $SubDomShortName = $PartitionName.Substring(3,$PartitionName.IndexOf(',')-3)  # short name for domain
            $ChildDomainInfo = Get-ADDomain -Identity $SubDomShortName -Verbose

            If ( (($ChildDomainInfo).ReplicaDirectoryServers)[1] )
            {
                $ChildDC = (($ChildDomainInfo).ReplicaDirectoryServers)[1]
            }
            Else
            {
                $ChildDC = (($ChildDomainInfo).ReplicaDirectoryServers)[0]
            }

            $SCPList = Get-ADObject -LDAPFilter "objectClass=serviceConnectionPoint" -SearchBase $ChildDomainInfo.DistinguishedName -Server $ChildDC
        
            If ($SCPList)
            {
                ForEach($SCPitem in $SCPList)
                {
                    If ($SCPitem.Name.Contains('Semperis.Dsp.Management'))
                    {
                        $DSPDN = $SCPitem.DistinguishedName.Split(',')
                        $DSPServerName = $DSPDN[1].Substring(3) + '.' + $ChildDomainInfo.DNSRoot
                        Write-Host ":: ------------------------------------------------------------" -ForegroundColor Green
                        Write-Host ":: WE FOUND THE DSP SERVER: $DSPServerName" -ForegroundColor Green
                        Write-Host ":: ------------------------------------------------------------" -ForegroundColor Green
                    }
                }
            }
        }
    }

}



##
## IMPORTANT NOTE!!!
##
## Apparently there are two different DSP PoSh installers, and one of the installers
## has a Connect-DSPServer cmdlet with different commandline options!!!!
##
## One installer has "Connect-DSPServer -ComputerName <dsp server name>" while
## the other has "Connect-DSPServer -Server <DSP server name>". 
##
## I am unsure as to the best way to check for this, so I am just using error-
## handling to try both options.
##
##
## Steps:
## 1) Try the connect command without the server option to generate an error.
## 2) Check if the error is a missing argument error or a parameter not found.
## 3) Set flag for the correct server connection parameter to use.
## 4) If error is unknown/unhandled, then just make the flag blank which will error the commandline.
##
Write-Host "`n`n"
$DSPServerConnectOption = '-Server'
Try
    {
    Connect-DSPServer -Server

    $Error[0].Exception.GetType().FullName
    $Error[0].FullyQualifiedErrorId
    #$Error[0].Exception.GetType() | Select  Property *
    #Connect-DSPServer -ComputerName

    }
Catch [System.Management.Automation.ParameterBindingException]
    {
    # We have to search the FullyQualifiedErrorId because the ParameterBindingException is not unique
    If (($Error[0].FullyQualifiedErrorId).ToString().Contains("MissingArgument"))
        {
        Write-Host "`n"
        Write-Host " *** We have the '-Server' commandline option" -ForegroundColor Magenta
        $DSPServerConnectOption = '-Server'
        }
    ElseIf (($Error[0].FullyQualifiedErrorId).ToString().Contains("NamedParameterNotFound"))
        {
        # "Connect-DSPServer : A parameter cannot be found that matches parameter name 'Server'."
        Write-Host "`n"
        Write-Host " *** We have the '-ComputerName' commandline option" -ForegroundColor Magenta
        $DSPServerConnectOption = '-ComputerName'
        }
    Else
        {
        Write-Host "`n"
        Write-Host " **UNKNOWN ERROR** Error unknown: cannot determine error when connecting!" -ForegroundColor Magenta -BackgroundColor White
        Write-Host ""
        $Error[0].FullyQualifiedErrorId
        $Error[0].Exception.GetType().FullName
        Write-Host "`n"
        $DSPServerConnectOption = $Null  # This will cause the Connect-DSPServer command to fail!!
        }
    }
Finally
    {
    If ($DSPServerConnectOption)
        {
        Write-Host " *** This DSP PoSh module version requires the server option '$DSPServerConnectOption' to connect" -ForegroundColor Magenta
        }
    Else
        {
        Write-Host " ***WARNING!! Could not find or determine DSP PoSh version for commandline to use!!" -ForegroundColor Magenta -BackgroundColor White
        }
    }
Write-Host "`n`n"




# If we found the DSP server, then do some DSP stuff!!!
If ($DSPServerName)
{
    # Undo this earlier change (which should be enough time as of now to allow for replication and for the DSP
    # agent to pick up the change and forward it into DSP/SQL): 
    #   Set-ADUser -Identity "CN=Axl Rose,OU=Lab Users,$DomainDN" -Fax '(408) 555-1212'


    Write-Host ""
    Write-Host ":: Connect to the DSP server (assuming only one)..." -ForegroundColor Yellow
    $LoopCount = 0
    $DSPconnection = $null
    # Need to check for different DSP PoSh module loaded...
    If ($DSPServerConnectOption -eq '-computername')
    {
        Write-Host "Connect-DSPServer -ComputerName $DSPServerName -Verbose" -ForegroundColor Cyan
        $DSPconnection = Connect-DSPServer -ComputerName $DSPServerName -Verbose
    }
    Else
    {
        Write-Host "Connect-DSPServer -ComputerName $DSPServerName -Verbose" -ForegroundColor Cyan
        $DSPconnection = Connect-DSPServer -Server $DSPServerName -Verbose
    }
    
    Write-Host ""

    While ( (!($DSPconnection.ConnectionState)) -and ($LoopCount -lt 10) )
    {
        Write-Host "WAIT"
        Start-Sleep 2
        $LoopCount++    # We need to count loops in case connection not acheived

        # Need to check for different DSP PoSh module loaded...
        If ($DSPServerConnectOption -eq '-computername')
        {
            Write-Host "Connect-DSPServer -ComputerName $DSPServerName -Verbose" -ForegroundColor Cyan
            $DSPconnection = Connect-DSPServer -ComputerName $DSPServerName -Verbose
        }
        Else
        {
            Write-Host "Connect-DSPServer -ComputerName $DSPServerName -Verbose" -ForegroundColor Cyan
            $DSPconnection = Connect-DSPServer -Server $DSPServerName -Verbose
        }

    }
    
    If (!($DSPconnection.ConnectionState))
    {
        Write-Host ""
        Write-Host ""
        Write-Host ":: --------------------------------------------" -ForegroundColor Yellow -BackgroundColor Red
        Write-Host ":: ERROR!!!! CONNECTION TO DSP SERVER FAILED!!!" -ForegroundColor Yellow -BackgroundColor Red
        Write-Host ":: --------------------------------------------" -ForegroundColor Yellow -BackgroundColor Red
        Write-Host ""
        Write-Host ""
        Write-Host ":: We did not get connected... Skipping the DSP PoSh cmdlet stuff..." -ForegroundColor Yellow
        Write-Host ""
        Write-Host ""
    }
    Else
    {
        Write-Host ""
        Write-Host ":: Connected to DSP!!" -ForegroundColor Yellow
        Write-Host "     --         Connection: $($DSPconnection.Connection)" -ForegroundColor Cyan -BackgroundColor DarkGray
        Write-Host "     -- Connection Address: $($DSPconnection.ConnectionAddress)" -ForegroundColor Cyan -BackgroundColor DarkGray
        Write-Host "     --   Connection State: $($DSPconnection.ConnectionState)" -ForegroundColor Cyan -BackgroundColor DarkGray
        Write-Host ""
        Start-Sleep 1
 

        #
        # Assuming change to facsimileTelephoneNumber was made to '$($DemoUser1.Name)' in the root domain...
        #
        Write-Host ":: Get the user object DN for '$($DemoUser1.Name)'..."
        $ObjectDN = (Get-ADUser -LDAPFilter "(&(objectCategory=person)(cn=$($DemoUser1.Name)))").DistinguishedName
        Write-Host ":: $ObjectDN"
        Write-Host ":: Use user DN to find the previous change to FAX (facsimileTelephoneNumber) attribute..." -ForegroundColor Yellow
        $ChangeItem = Get-DSPChangedItem -Domain $DomainDNSRoot -ObjectDN "$ObjectDN" -Attribute facsimileTelephoneNumber -SearchTerm "$($DemoUser1.FAXalt)" -Verbose
        Write-Host ":: Here is our change to 'facsimileTelephoneNumber' for '$ObjectDN'..."
        $ChangeItem
        Write-Host ":: UNDO the attribute change of 'facsimileTelephoneNumber' on '$ObjectDN'..." -ForegroundColor Yellow
        Write-Host "Undo-DSPChangedItem -InputObject $ChangeItem -ForceReplication -Confirm:$False -Verbose" -ForegroundColor Cyan
        $UndoStatus = (Undo-DSPChangedItem -InputObject $ChangeItem -ForceReplication -Confirm:$False -Verbose)
        If ($UndoStatus)
        {
            Write-Host ":: Undo was successful!!!" -ForegroundColor Yellow
        }
        Else
        {
            Write-Host ":: Undo FAILED (or was not found)!!!!" -ForegroundColor Yellow -BackgroundColor Red
        }
          

        
        #
        # Assuming change to facsimileTelephoneNumber was made to '$($DemoUser2.Name)' in the root domain...
        #
        Write-Host ""
        Write-Host ""
        Write-Host ":: Get the user object DN for '$($DemoUser2.Name)'..."
        $ObjectDN = (Get-ADUser -LDAPFilter "(&(objectCategory=person)(cn=$($DemoUser2.Name)))").DistinguishedName
        Write-Host ":: $ObjectDN"
        Write-Host ":: Use user DN to find the previous change to FAX (facsimileTelephoneNumber) attribute..." -ForegroundColor Yellow
        $ChangeItem = Get-DSPChangedItem -Domain $DomainDNSRoot -ObjectDN "$ObjectDN" -Attribute facsimileTelephoneNumber -SearchTerm "$($DemoUser2.FAXalt)" -Verbose
        Write-Host ":: Here is our change to 'facsimileTelephoneNumber' for '$ObjectDN'..."
        $ChangeItem
        Write-Host ":: UNDO the attribute change of 'facsimileTelephoneNumber' on '$ObjectDN'..." -ForegroundColor Yellow
        Write-Host "Undo-DSPChangedItem -InputObject $ChangeItem -ForceReplication -Confirm:$False -Verbose" -ForegroundColor Cyan
        $UndoStatus = (Undo-DSPChangedItem -InputObject $ChangeItem -ForceReplication -Confirm:$False -Verbose)
        If ($UndoStatus)
        {
            Write-Host ":: Undo was successful!!!" -ForegroundColor Yellow
        }
        Else
        {
            Write-Host ":: Undo FAILED (or was not found)!!!!" -ForegroundColor Yellow -BackgroundColor Red
        }
 

 
        #
        # Assuming change to facsimileTelephoneNumber was made to '$($DemoUser3.Name)' in the root domain...
        #
        Write-Host ""
        Write-Host ""
        Write-Host ":: Get the user object DN for '$($DemoUser3.Name)'..."
        $ObjectDN = (Get-ADUser -LDAPFilter "(&(objectCategory=person)(cn=$($DemoUser3.Name)))").DistinguishedName
        Write-Host ":: $ObjectDN"
        Write-Host ":: Use user DN to find the previous change to FAX (facsimileTelephoneNumber) attribute..." -ForegroundColor Yellow
        $ChangeItem = Get-DSPChangedItem -Domain $DomainDNSRoot -ObjectDN "$ObjectDN" -Attribute facsimileTelephoneNumber -SearchTerm "$($DemoUser3.FAXalt)" -Verbose
        Write-Host ":: Here is our change to 'facsimileTelephoneNumber' for '$ObjectDN'..."
        $ChangeItem
        Write-Host ":: UNDO the attribute change of 'facsimileTelephoneNumber' on '$ObjectDN'..." -ForegroundColor Yellow
        Write-Host "Undo-DSPChangedItem -InputObject $ChangeItem -ForceReplication -Confirm:$False -Verbose" -ForegroundColor Cyan
        $UndoStatus = (Undo-DSPChangedItem -InputObject $ChangeItem -ForceReplication -Confirm:$False -Verbose)
        If ($UndoStatus)
        {
            Write-Host ":: Undo was successful!!!" -ForegroundColor Yellow
        }
        Else
        {
            Write-Host ":: Undo FAILED (or was not found)!!!!" -ForegroundColor Yellow -BackgroundColor Red
        }
 
 
        Write-Host ""
        Write-Host ""
    } # end \ Check for good DSP connection
}

} # end \ $DspPoShStatus check is $True
Else
{
    Write-Host ""
    Write-Host ":: Skipping the DSP PoSh cmdlets section because 'Semperis.PoSh.DSP' was not installed." -ForegroundColor Yellow
    Write-Host ""
}




#------------------------------------------------------------------------------
#
Write-Host ""
Write-Host ""
Write-Host ""
Write-Host "                                                                                "
Write-Host "#------------------------------------------------------------------------------#"
Write-Host "#                                                                              #"
Write-Host "# Let's trigger some actions that trigger UNDO rules.                          #"
Write-Host "#                                                                              #"
Write-Host "# You need to create the notification rules to undo these changes.             #"
Write-Host "#                                                                              #"
Write-Host "# For visibility, we will first undo an attribute change before the change     #"
Write-Host "# to remove all group members. The attribute undo will act as a sort of        #"
Write-Host "# visual seperator in the Undo Action page.                                    #"
Write-Host "#                                                                              #"
Write-Host "#------------------------------------------------------------------------------#"
Write-Host "                                                                                "
Write-Host ""
Write-Host ""





#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                              " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- TRIGGER UNDO RULE: CHANGE 'Title' ATTRIBUTE FOR '$($DemoUser3.Name)' ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                              " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
#
# Until the rule-making scripting is added her to create the notification rule 
# and enable the UNDO option, this section will not work the very first time this 
# script is run because the data has not yet been established. 
#
# When the lab is first set up and this script has been run, go to DSP and create
# the UNDO rules.
#
#
Write-Host ""
Write-Host ""
Write-Host ":: Doing this last because we want to allow replication time for previous changes." -ForegroundColor Yellow
Write-Host ""
Write-Host ""
Write-Host "::                                                                             " -ForegroundColor Yellow -BackgroundColor DarkMagenta
Write-Host "::  There MUST be an existing auto-undo rule enabled for this action to demo!! " -ForegroundColor Yellow -BackgroundColor DarkMagenta
Write-Host "::                                                                             " -ForegroundColor Yellow -BackgroundColor DarkMagenta
Write-Host ""
Write-Host ""
Start-Sleep 5
#
#
# <<<insert DSP PoSh code here to programmatically create and enable the auto-undo rule>>>
#
#
Write-Host ""
Write-Host ":: Changing protected 'Title' attribute for '$DomainNETBIOS\$($DemoUser3.Name)'..." -ForegroundColor Yellow
Write-Host "::     ($($DemoUser3.sAMAccountName))" -ForegroundColor Yellow
Write-Host ":: (!!! This will trigger the auto-undo rule if it exists !!!)" -ForegroundColor Yellow
$UserObj = $null
If (!($UserObj = Get-ADUser -LDAPfilter "(&(objectCategory=person)(samaccountname=$($DemoUser3.sAMAccountName)))" -Properties * -ErrorAction SilentlyContinue))
{
    Write-Host ""
    Write-Host "::    -- ERROR!! User account '$($DemoUser3.sAMAccountName)' not found!!!" -ForegroundColor Yellow -BackgroundColor Red
    Write-Host ""
}
Else
{
    # There is a bug in the handling of certain types of changes in DSP. The problem is when a change
    # is made to an attribute where the attribute is "set" to the same data value, which is effectively 
    # no change. In that case a "change" is made but there is nothing to replicate. The bug is 
    # surfaced when a subsequent change is made to the SAME attribute on the same object, and then an
    # UNDO action is triggered with an UNDO rule. In other words, when the same data is written to a
    # specific attribute and then a short time later the same attribute is written with different data
    # all while an auto-undo rule is in effect, the undo action will fail because there is no 
    # corresponding replication event. DSP basically just hangs for that operation, where it appears
    # with the blue "working" icon in the auto undo section, and then hours or days later, it changes
    # to red to indicate failure. In the DSP logs, it looks like SQL issues or timeouts.
    #
    # To work around this bug for the purposes of this script, I am checking for the existing
    # value of the attribute, and only change it if it is not what we want. Here in the section
    # where we want to trigger an auto undo rule, we change it to "CEO" if it is not currently "CEO".

    If ($(Get-ADUser -Identity "$($UserObj.DistinguishedName)" -Properties Title).Title -ne "CEO")
    {
        Write-Host "::    -- Updating 'Title' attribute for '$($DemoUser3.Name)'..." -ForegroundColor Cyan
        Set-ADUser -Identity "$($UserObj.DistinguishedName)" -Title "CEO" -Verbose
        Write-Host ""
    }
}
Write-Host ""
Write-Host ":: Waiting 20 extra seconds because the AUTO UNDO takes longer to trigger..." -ForegroundColor Yellow
Write-Host ""
Start-Sleep 20





#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                            " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- TRIGGER UNDO RULE: REMOVE ALL USERS FROM '$($SpecialLabAdmins.Name)' ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                                            " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
#
# Until the rule-making scripting is added her to create the notification rule 
# and enable the UNDO option, this section will not work the very first time this 
# script is run because the data has not yet been established. 
#
# When the lab is first set up and this script has been run, go to DSP and create
# the UNDO rules.
#
#
Write-Host ""
Write-Host ""
Write-Host ":: Doing this last because we want to allow replication time for previous changes." -ForegroundColor Yellow
Write-Host ""
Write-Host "::                                                             " -ForegroundColor Yellow -BackgroundColor DarkMagenta
Write-Host "::  There MUST be an auto-undo rule enabled for this action!!  " -ForegroundColor Yellow -BackgroundColor DarkMagenta
Write-Host "::                                                             " -ForegroundColor Yellow -BackgroundColor DarkMagenta
Write-Host ""
#
# Populate $SpecialAdminGroup group befor doing UNDO test.
# 
# IMPORTANT!!! 
#     This requires a notification rule with the UNDO option set for when membership changes!!!
#
#
#
#
# <<<insert DSP PoSh code here to programmatically create and enable the auto-undo rule>>>
#
#
#
#
#
Write-Host ""
Write-Host ":: Removing all group members from group '$DomainNETBIOS\$($SpecialLabAdmins.SamAccountName)'..." -ForegroundColor Yellow
Write-Host "::     ($($SpecialLabAdmins.Name))" -ForegroundColor Yellow
Write-Host ":: (!!! This will trigger the auto-undo rule if it exists !!!)" -ForegroundColor Yellow
$GroupObj = $null
$GroupObj = Get-ADGroup -LDAPfilter "(&(objectCategory=group)(cn=$($SpecialLabAdmins.Name)))"
Get-ADGroupMember -Identity $GroupObj.DistinguishedName | ForEach-Object {Remove-ADGroupMember -Identity $GroupObj.DistinguishedName $_ -Confirm:$false -Verbose} 
$GroupObj = $null
Write-Host ""
Write-Host ":: Waiting 20 extra seconds because the AUTO UNDO takes longer to trigger..." -ForegroundColor Yellow
Write-Host ""
Start-Sleep 20





#------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ":: ---- FINAL FORCED REPLICATION ----                          " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host "::                                                             " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""
Write-Host ":: Run a final 'repadmin /syncall' after 20 second pause..." -ForegroundColor Yellow
Start-Sleep 20
If (($(C:\Windows\System32\repadmin.exe /syncall /force $DomainDC1) -Join '-').ToString().ToLower().Contains('syncall finished')) {Write-Host "Replication command completed!!!" -ForegroundColor Cyan}
If ($DomainDC2) {C:\Windows\System32\repadmin.exe /syncall /force $DomainDC2 | Out-Null}

Write-Host ""
Write-Host ""
Write-Host ":: ---- DONE!! ----    " -ForegroundColor DarkRed -BackgroundColor Yellow
Write-Host ""
Write-Host ""






################################################################################
#-------------------------------------------------------------------------------
Write-Host "`n`n"
Write-Host "::                                                                      " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::    Invoke-CreateDspChangeDataForDemos COMPLETED!!                    " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::                                                                      " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::      Some things to search for in Changes:                           " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - AD Sites and Services                                       " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - AD User objects                                             " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - AD User account lockout                                     " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - Changes to users' 'department' attribute                    " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - FGPP (fine-grained password policy)                         " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - GPO modifications                                           " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - Group objects                                               " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - DNS records and zones                                       " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - Default Domain Policy                                       " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - OUs and deletion protection                                 " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - Deleted OU with child objects                               " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - WMI filters (msWMI-Som class)                               " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - ACL (ntSecurityDescriptor) changes                          " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - GPO linking                                                 " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::        - Changes to Configuration Partition (Sites and Services)     " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::                                                                      " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::                                                                      " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::    Script may be re-run as often as desired.                         " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::    Script will reset most changed items for consistent demo usage.   " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "::                                                                      " -ForegroundColor White -BackgroundColor DarkGray
Write-Host "`n`n"
#-------------------------------------------------------------------------------
################################################################################








#------------------------------------------------------------------------------
# End the logging
#
Stop-Transcript -Verbose



}  # THIS IS THE CRAZY LOOP FOR ALL THIS STUFF!!



#------------------------------------------------------------------------------
if ($host.name -eq 'ConsoleHost') # or -notmatch 'ISE'
    {
    Write-Host "`n`n"
    Write-Host ":: (sleeping for 300 seconds, or you can break out/exit this script)" -ForegroundColor Yellow
    Start-Sleep 300
    Exit
    }
else
    {
    Write-Host "`n`n"
    Write-Host ":: (sleeping for 5 seconds at script exit)" -ForegroundColor Yellow
    Start-Sleep 5
    Exit
    }




    