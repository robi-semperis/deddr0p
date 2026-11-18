<#
.SYNOPSIS
    Invoke-ADContentGenerator-v1_8_22.ps1    v1.8.22

    Script that provisions objects and content into an Active Directory lab
    environment, also generating synthetic AD change activity for AD change
    monitoring tools.

    NOTE: Does not change AD functionality or AD system/configuration
    settings.

    This script uses the Windows Credential Store for secure password(s)
    storage for demo accounts created by this script.

.DESCRIPTION
    Use -RemoveAllGeneratedContent as an exclusive cleanup operation. It
    requires elevated Administrator, Domain Admins and Enterprise Admins
    token membership before any removal confirmation. The fixed 15-second
    confirmation defaults to CANCEL, including Enter, Escape and UI failure.
    Removal does not retrieve passwords or run provisioning.

    Every normal provisioning run overwrites a JSON ownership inventory in
    the CURRENT DIRECTORY, named from the actual script filename with .ps1
    replaced by .JSON. Capture THIS invocation's MyInvocation.MyCommand.Path
    once at script entry. If it is a symbolic link, follow its target chain
    to the actual PS1 file; resolve relative targets beside each link.
    Use the final target basename for JSON naming and script metadata.
    If resolution fails, retain the original runtime basename instead.
    Never enumerate the directory or borrow another script/editor filename.
    Run the complete saved file (F5 in ISE); selected-text/Invoke-Expression
    execution without its own saved-script identity stops without guessing.
    Project EVERY baseline object definition into BaselineCatalog, including
    targets absent from the directory. A compact generic-user range covers
    every configured index, independent of today's selected count; discovery
    also includes existing managed six-digit SAMs above the configured cap.
    Catalogs contain identity selectors only, never credentials/password data.
    Read-only scans resolve GUIDs/exact DNS data into Objects without dropping
    absent catalog entries. SyntheticCatalog supplements WMI name aliases and
    old/new DNS A/PTR variants on a best-effort basis. Built-in and reference-
    only objects remain excluded. Scan errors are unresolved, never absence.
    Failure to open/overwrite the inventory stops before provisioning writes.
    Creations are saved immediately, including partially initialized objects.

    Cleanup re-resolves all current baseline selectors BEFORE confirmation,
    unioning existing identities with saved GUIDs, even if Objects was empty.
    The approved target list is frozen; post-cleanup discovery never deletes
    newly discovered/replacement identities. The source JSON stays unchanged.
    No script/schema version checks are used. Existing JSON is read best
    effort; domain and script identity remain mandatory. Unsupported or
    malformed saved entries are skipped and reported, not guessed.
    A separate timestamped RemovalResults JSON reports failures, residuals,
    discovery gaps and complete post-scan catalogs. Unknown historical WMI
    renames can remain when neither a GUID nor configured alias is available.
    No blanket guarantee of complete cleanup or replicated convergence. It
    removes users, computers, groups, GPO links and GPOs, FGPPs regardless of
    subject attachments, WMI filters, AD subnets/sites, DNS records/zones,
    then OUs. A recorded OU, DNS zone or AD site is removed with ALL its
    descendants, even unrecorded/pre-existing content. Accidental-deletion
    protection inside approved AD targets is cleared as needed; DC accounts
    and NTDS Settings objects block automatic AD tree removal. Built-in or
    existing-only reference objects also block the entire container deletion
    if encountered inside it. No rollback.
    Inventory and transcript files, stored credentials and GPO backups are
    retained. Existing-object edits outside removed containers are not undone.

    Collects a dedicated Tier0Admin password (currently Admin-Tier0) in a
    separate per-domain Windows Credential Store entry, in addition to the
    shared DEMO password. Both use the same masked dialog and seven-second
    no-input timeout, configurable once in DEFAULTS. The first typed or
    pasted character disables the timeout until OK, Cancel or window close,
    even if the entry is later cleared. Generic-user count input follows
    the same rule, including invalid input while it is being corrected.
    Cancel/timeout reuses only the matching stored credential; missing entry
    plus no input displays an error and stops before any provisioning.
    Tier0Admin uses its dedicated secret at creation and permitted refresh;
    normal password-preservation settings remain in effect on reruns.

    Tier0Admin (currently Admin-Tier0) and OpsAdmin (currently adm.johnwick)
    have PasswordNeverExpires=True in their editable baseline definitions.
    Set this at creation and reconcile existing
    accounts even when their passwords are preserved. Read back the flag on
    the selected DC. Other accounts remain unmanaged for this setting unless
    explicitly configured. If a preserved account requires a password change
    at logon, stop preflight rather than silently clearing that requirement.

    Use -Help for the script name, synopsis, description, parameters and
    examples without operational notes or revision history. Help exits before
    defaults, transcripts, prompts, module loading, discovery or AD operations.

    Checks prerequisites, retrieves or prompts for a demo-account password,
    and ensures the specified lab organizational units exist with their
    desired descriptions.

    A missing demo-password key is a normal first run: prompt the operator
    and save the entered password for this Windows user and computer.
    Uses only the new, version-independent credential namespace; never
    reads or migrates keys from earlier script names. Credential API
    errors are captured inside managed wrappers before PowerShell can
    overwrite the thread error state. Genuine store errors stop the run.

    Checks required modules and installs missing Windows management tools
    before password/count prompts or provisioning. Imports ActiveDirectory,
    GroupPolicy and DnsServer globally and verifies their required cmdlets.
    Missing or incomplete modules receive one Windows installation/repair
    attempt and one import retry. Uses Windows Server features or Windows
    client RSAT capabilities, not similarly named Gallery packages.

    ActiveDirectory and CimCmdlets bootstrap before domain discovery.
    Installing AD tools at this point requires local elevation; domain
    administrator rights are checked after discovery. Full checks follow
    rights validation and include CimCmdlets, DnsClient and repadmin.exe.
    Inbox CIM/DNS-client components have no standalone RSAT installer;
    import failures stop with Windows component-repair guidance.

    Failed installation, failed verification or an installer-reported
    required restart stops before prompts/provisioning. Windows servicing
    may require access to configured feature sources/Windows Update; WSUS
    policy or an unsupported OS can block installation. The script never
    automatically reboots, promotes a DC or installs a DNS server role.
    Later DNS operation/permission/PTR failures remain best-effort warnings.

    Specific object ACL definitions live in Get-LabSpecificObjectAclDefinitions
    and Get-LabSpecificObjectAclADChangeDefinitions. After demo-user baseline
    provisioning, preserve Bad OU's existing DACL and add DemoUser9 Read/Write
    on that object only; add AdmUser1 Read/Write on the object and all child
    objects. Read/Write means GenericRead plus GenericWrite, not Full Control.

    Synthetic ACL changes remove DemoUser9's explicit allow/deny ACEs from
    Bad OU, and remove AdmUser1's explicit allow-read rights at every scope
    on that OU. Preserve write rights, including ReadControl shared with
    GenericWrite. Do not add deny ACEs or change inherited ACEs/other trustees.
    Inherited/group rights can still provide read access. Descendants with
    protected DACLs do not inherit the OU grant; child-local ACEs are untouched.

    ACL helpers edit only nTSecurityDescriptor's DACL on the selected DC,
    pin object GUIDs and trustee SIDs, preserve existing inheritance, owner
    and SACL, and verify the complete resulting DACL. For GPOs the helper
    edits only the AD groupPolicyContainer, not SYSVOL or GPO delegation
    consistency. Avoid concurrent edits of the same DACL. Failures stop;
    earlier writes may remain committed and no rollback is attempted.
    Each baseline/synthetic ACL batch ends with one forced domain replication
    checkpoint and the configured PauseTimeSeconds settling delay; this is
    not proof of inherited-ACE propagation, convergence or DSP capture.

    Baseline DNS definitions live in Get-LabDnsZoneDefinitions and
    Get-LabDnsRecordDefinitions in the editable-data section. Before other
    baseline writes, create/reconcile specialsite.lab, 172.in-addr.arpa,
    168.192.in-addr.arpa, 10.in-addr.arpa and 6.6.6.in-addr.arpa, in that
    order. Managed zones
    are AD-integrated Primary with Forest replication and NonsecureAndSecure
    dynamic updates. Only specialsite.lab is explicitly reconciled unsigned;
    any existing DNSSEC parent DS records/trust anchors are not changed.
    Existing file-backed primaries can be converted without deleting zones;
    secondary/stub zones are warned and skipped rather than replaced.

    Ensure four static mylabhost A records in specialsite.lab, and five
    static deadhost/junkie/fakehost records in the current computer's AD
    domain DNS zone (including a child domain). Do not create or alter the
    main AD zone's configuration. All DNS reads/writes target the already
    selected writable DC; no arbitrary DNS-server/DC failover occurs.
    The selected DC must host DNS and the relevant writable zones. DNS
    access uses the current Windows credentials, without new prompts.

    Reconcile associated PTRs independently after each verified A record,
    with the same outcome as Create associated pointer (PTR) record, while
    keeping A creation independent of PTR failures. Prefer the longest
    hosted reverse-zone suffix. The 6.6.6.0/24 reverse zone is explicitly
    managed. Missing reverse zones for 11.x produce warnings; do not create unspecified zones or rewrite CNAMEs.
    Reruns repair missing PTRs even when the A record already matches.
    Preserve unrelated records and PTR targets. An ambiguous multivalue A
    owner with no matching desired address is warned and skipped. A single
    managed A record is updated in place when static; an aging managed A
    record is replaced with a static record, retaining TTL. A replacement
    failure can leave that managed A missing; no rollback is attempted.
    Read back zones, addresses and static timestamps before success output.

    Baseline specialsite.lab A records explicitly use TTLMinutes=3600
    (60 hours). deadhost02 resets to TTLMinutes=60 for a repeatable demo.
    Existing managed TTLs are reconciled even when the address matches.
    fakehost02 associated PTR resets to PtrTTLSeconds=3600 (one hour).
    The junkie222 baseline removes AppAdminIII's explicit DNS-node ACEs;
    inherited rights, unknown/orphaned SIDs and parent ACLs are not changed.
    A missing demo user is a first-run no-op. ACL failures warn separately.

    Synthetic DNS activity deletes only the mylabhost03 A record, leaving
    its PTR intact; changes mylabhost04 TTL to 1 minute; changes junkie222
    from 11.22.33.222 to 11.22.33.111; changes deadhost02 TTL to 7200 minutes;
    and adds App Admin III (AppAdminIII) Read/Write on junkie222's dnsNode.
    In 6.6.6.in-addr.arpa, delete only the fakehost01 PTR at owner 111;
    set the fakehost02 PTR at owner 222 to TTLSeconds=31. Retain their
    forward A records and unrelated PTR targets. The next baseline recreates
    the deleted PTR and restores the remaining PTR TTL to 3600 seconds.
    Read/Write is GenericRead plus GenericWrite, not Full Control. A node
    ACL covers all record values at that name. Unrelated trustees, owner,
    audit rules and inherited ACEs are preserved. Existing deny ACEs and
    effective user access are not evaluated. Only the selected DC is used.

    Address changes establish the new associated PTR before removing only
    this host's matching old PTR target. Missing 11.x reverse zones warn
    without reverting the A change or creating unspecified reverse zones.
    DNS action/ACL failures warn and continue with the remaining actions;
    prior writes may remain and no rollback is attempted. One DNS-aware
    synthetic replication checkpoint follows the full DNS action batch.
    This checkpoint uses one repadmin /syncall /A /d /e /P invocation,
    then one PauseTimeSeconds wait. /A covers every naming context hosted
    by the selected DC, including Schema and Configuration; it is not a
    DNS-only filter. Native output can still show multiple partitions and
    partners within that single invocation. Baseline DNS remains unchanged.
    The fixed terminal Helpdesk Ops membership changes remain last.

    DNS has one shared baseline replication checkpoint after the complete
    batch, not per zone or host. It pushes hosted AD DNS application
    partitions plus the domain partition for legacy-integrated zones, then
    waits PauseTimeSeconds once. DNS checkpoint failures warn and continue;
    they do not prove convergence. A completely skipped DNS preflight has
    no replication wait. Other baseline checkpoint failures remain fatal.

    Rsat.Dns.Tools is a Windows capability, not an importable module.
    Missing DnsServer triggers installation of the fixed full client name
    Rsat.Dns.Tools~~~~0.0.1.0 or Server feature RSAT-DNS-Server. AD cmdlets use
    RSAT-AD-PowerShell, replication uses RSAT-ADDS-Tools, and GPOs use GPMC;
    client equivalents are the AD DS/LDS and Group Policy RSAT capabilities.
    Blank capability inventory never supplies a name to installation.
    Verify package state after installation and verify module/cmdlet loading.
    For already working DNS cmdlets, inconclusive package inventory alone
    does not trigger installation or block the run.

    ClearStoredCreds retains its early return, skips full tool checks and
    never installs tools during bootstrap. Missing bootstrap dependencies
    stop with guidance instead of elevating a credential-clear operation.

    Before baseline AD writes, displays total and available space for each
    local drive-letter fixed disk using read-only CIM inventory. Warns in
    Yellow on Red when free space is at or below DiskSpaceWarningThresholdGB
    in DEFAULTS (1 GB by default; GB uses 1,073,741,824 bytes). Low space,
    missing inventory and inventory failures warn without stopping the run.
    The local check remains independent of the DSP server check below.
    ClearStoredCreds skips both checks. No cleanup or disk changes occur.

    For both local and DSP disk reports, only the Available field uses
    Yellow foreground on Red background when free space is strictly
    below DiskSpaceHighlightThresholdGB (2 GB by default). Comparison
    uses unrounded bytes; exactly 2 GB keeps normal Info styling.
    Existing warning-message thresholds remain independent.

    After all local and attempted DSP disk output, pause once for
    DiskSpaceReviewPauseSeconds (10 seconds) if any checked disk has
    less than DiskSpacePauseThresholdGB (2 GB) free. Compare unrounded
    bytes; exactly 2 GB, unknown values and skipped disks do not trigger
    a pause. Multiple low disks still cause one pause, before baseline
    writes and outside AD-processing timing. Then continue automatically.

    Remote DSP disk checks are automatic and best-effort by default. Use
    CheckDspDiskSpace = $False in DEFAULTS to disable them entirely. When
    disabled, skips both DSP SCP discovery and remote disk queries,
    reports the check as skipped and still checks local fixed disks.
    Invalid non-Boolean values warn and skip the optional remote check.

    When enabled, discovers DSP management-server hostnames from SCPs in
    the selected domain's forest. Searches domain naming contexts, not the
    Configuration partition, for Semperis.Adsn.Management SCPs with both
    Role=Management and Role=Collector keywords. Reads serviceDNSName,
    deduplicates valid hostnames and checks each discovered server. There
    is no manual hostname list or guessed hostname. Stale registrations
    may still appear; discovery does not prove a server is active or owns
    the current GPSM store. Unreadable forest domains are reported UNKNOWN.

    Discovery uses the selected writable DC to identify the forest and query
    its own domain. Other domains are queried by their DNS names. A local
    background job bounds the discovery wait (DspDiscoveryTimeoutSeconds in
    DEFAULTS; 30 seconds by default). A failed or timed-out discovery warns
    and returns no targets; incomplete job output is not treated as a full
    discovery. Job startup/cleanup adds overhead to the configured wait.

    Each DSP server is queried for all drive-letter fixed disks using the
    logged-on Windows identity, never the stored demo password. Brief TCP
    probes check standard WSMan HTTP (5985), HTTPS (5986), then DCOM/RPC
    (135) endpoints. An open port is not proof of authentication or usable
    inventory: only a successful CIM query counts. WSMan uses Kerberos;
    DCOM uses current-identity Windows authentication. No credential prompts,
    CredSSP/delegation, certificate bypasses or remote-access changes occur.

    DspDiskCheckTimeoutSeconds in DEFAULTS bounds all attempts per server
    together (10 seconds by default), inside a local background job. Each
    probe waits at most 700 ms, with shorter CIM operation timeouts. Job
    startup/cleanup adds overhead. A failed query may fall back to the next
    reachable standard endpoint while budget remains. On timeout or failure,
    skip the server, report free space UNKNOWN and continue AD activity.
    No partial timed-out inventory is reported. Low disk space still warns.
    Reports do not assess mount-point-only volumes, quota limits or which
    drive holds the configured GPSM backup store.

    Adds zSpecial OU directly beneath the domain root, with DisplayName
    "zSpecial OU" and Description "Restricted OU for special objects".
    SamAccountName is definition metadata, not an OU attribute. This OU will
    later be set with a very restrictive ACL. No custom ACL changes for this
    OU are implemented in this revision.

    OU lookup/create failures are logged and processing continues. An empty
    search can mean a hidden existing OU, not necessarily a missing OU;
    creation failure is not treated as proof that an object was created or
    successfully reconciled.

    Dependent computer definitions in unavailable OUs/containers are
    skipped; accessible computers and subsequent provisioning sections can
    continue. Skipped computers have no verified reference in
    LabComputerObjects. Identity conflicts, OU update failures and other
    write failures still stop processing; no ACL bypass or permission
    changes are attempted.

    Creates/reconciles the configured groups and their non-membership
    properties using editable, keyed hash-table definitions.

    Keeps operator-editable OU, group, nesting and demo-user definitions
    together immediately after DEFAULTS. Applies additive group nesting from
    the child-to-parent hash table, including intentional self-membership
    for labs.

    Creates/reconciles demo users from early editable hash tables; restores
    their configured profile attributes, CN, OU and enabled state. New demo
    users receive the DEMO password only when explicitly allowlisted;
    Tier0Admin receives its dedicated stored password. All others receive
    random passwords appropriate to their account type. Existing random
    passwords are preserved. DoNotUpdateDemoUsersPasswords and
    RefreshAllPasswords affect collected-password accounts only.

    Reconciles ordered direct membership lists for users, groups and
    computers after demo users exist. Defaults to additive updates; optional
    exact mode preserves required nesting and suppresses removals on
    resolution failures.

    Creates/reconciles six keyed computer objects from
    Get-LabComputerDefinitions after OU provisioning and before AD Changes.
    PIMPAM, VAULT and BASTION-HOST01 belong in zSpecial OU; APPSERVER01,
    BadOne and TOOLS01 in CN=Computers. Restores changed CN, SAM, display
    name, description and parent container. Computer SAM names are
    normalized to exactly one trailing dollar sign.

    New computer accounts are created enabled; every defined computer
    account is reconciled to Enabled=True on later runs and verified before
    publication. Existing machine passwords, SPNs and DNS names are not
    managed. No machine joins or ACL changes occur.

    Verified objects are stored in $script:LabComputerObjects by stable key;
    definitions remain in $script:LabComputerDefinitions. Later AD Changes
    can use ObjectGUID as identity and refresh cached properties after
    mutations.

    Creates/reconciles enabled special accounts using the NetBIOS domain
    name as a prefix. Preserves configured suffixes while limiting SAM names
    to 20 characters.

    New special accounts receive random passwords of at least 30 characters,
    honoring higher AD requirements. Existing passwords and change-at-logon
    state remain untouched. Legacy special-account reset flags and
    RefreshAllPasswords do not reset these random-password accounts.
    Optional descriptions and relative OU paths are defined near demo users.

    Creates/reconciles numbered generic users in OU=TEST using six-digit
    indices. Prompts for a one-time count after the demo-password prompt;
    uses GenericUserCount (25) after eight seconds without input or on
    cancellation. Typing/pasting permanently disables that dialog's timeout,
    even if the input is invalid or later cleared. Accepts ASCII digits within
    1..GenericUserMaximumCount (10000). Skips generic users if TEST is
    unavailable, then continues to memberships.

    New generic users are enabled and receive independent random
    passwords of at least 20 characters, growing for higher effective AD
    requirements, with exactly two permitted special characters. Existing generic-user passwords/enabled states and
    users beyond the count are preserved. Generated passwords are never
    displayed, logged or stored.

    Processes numbered generic users one at a time, capped by the explicit
    GenericUserMaximumCount default. Uses exact identity lookups, then
    creates or updates and immediately verifies each account before
    continuing. No generic-user prefix preloading or batch verification is
    performed by provisioning. Separate read-only inventory scans DO discover
    all configured six-digit SAMs, including accounts above today's count;
    these become cleanup targets without changing their passwords/properties.

    DoNotUpdateGenericUsers defaults to true: existing generic accounts are
    left untouched, without profile reconciliation or baseline verification.
    Set it to false to reconcile changed attributes on existing accounts.
    Missing generic accounts are created and verified in either mode.

    Creates/reconciles SemperisLabs and Semperis-Devs from the grouped
    Get-LabSiteDefinitions before subnet and IP site-link provisioning.
    SemperisLabs retains DisplayName SemperisLabs, Description "AD site for
    Semperis Labs" and Location USA-TX-Labs. Creates missing sites
    and restores changed managed fields; verifies exact identity and values
    on the selected DC. SamAccountName is retained as definition metadata,
    not written to AD.

    Associated subnet fields are projected from that same site definition:
    10.3.22.0/24, Description "AD subnet for Semperis Labs", Location
    USA-TX-Labs, assigned to SemperisLabs. This is baseline provisioning
    regardless of MakeADChanges. Semperis-Devs has DisplayName "Semperis
    Devs", Description "restricted site for devs" and associated subnet
    10.4.22.0/25, Description "AD subnet for devs". Its site/subnet locations
    are omitted and remain unmanaged. Actual site names and site-link
    endpoint references use DNS-safe labels; DisplayName may contain spaces.

    Creates/reconciles AD Sites and Services subnets from
    Get-LabSubnetDefinitions after the user definitions. Name is mandatory;
    Site, Location and Description are optional. Explicit blanks clear
    values; omitted fields stay unmanaged. Named sites must exist; missing
    sites warn and skip the affected subnet.

    Creates unlinked subnets when Site is blank; only changed fields are
    written. Unlisted subnets are not deleted. The adjacent baseline IP
    site-link stage creates/reconciles SemperisLabs-SemperisDevs, with exact
    membership SemperisLabs and Semperis-Devs, cost 7 and replication every
    15 minutes. Only changed cost, interval and site membership are written;
    schedule, options and other unconfigured fields remain untouched.
    Default-First-Site-Name and DEFAULTIPSITELINK are not managed. All writes
    are pinned to the selected DC and immediately read back. Sites, subnets
    and site links retain the existing no-forced-replication/no-delay policy.

    Creates/reconciles two FGPPs using editable definitions and the selected
    writable DC. Lab Service Accounts FGPP sets minimum length 8, maximum
    age 180 days and history 0; applies exactly to the Global Security group
    Tier1 Operators in OU=Tier 1,OU=Lab Admins, NOT to an OU or OU-derived
    members.

    Provisioning leaves the service FGPP assigned and caches its verified
    identity, managed fields and subjects for the later synthetic AD Changes
    phase. That phase removes and verifies the group assignment on the
    selected DC. Identity, managed fields and absence of assigned subjects
    are checked again without forced replication or a settling delay.
    The FGPP object is retained. Neither FGPP phase has a dedicated checkpoint.

    MakeADChanges=False leaves baseline FGPP assignments active and skips
    their synthetic removal. With True, each completed run repeats the
    assign/remove cycle. Other DCs and DSP may not observe intermediate
    assignments; local read-back does not prove convergence or DSP capture.
    Earlier committed writes are not rolled back on a later failure.

    Lab Test FGPP sets minimum length 32, minimum age 1 day, maximum age 30
    days and history 15; explicitly has no subjects, including on reruns.

    Null optional fields copy domain defaults on creation and remain
    unmanaged on rerun. Group memberships and passwords are not changed by
    FGPP setup. Assignments are verified; resultant per-user policy is not
    guaranteed.

    Creates/reconciles thirty WMI filters from the ordered, editable
    Get-LabWmiFilterDefinitions before the baseline GPO batch. Managed values
    are msWMI-Name, msWMI-Author, msWMI-Parm1 (description) and msWMI-Parm2
    (GPMC-encoded WQL). Author is Administrator@ plus the current domain name,
    validated against the selected provisioning domain. Empty descriptions
    clear msWMI-Parm1; missing Internet Explorer descriptions default to blank.

    Filters reside in CN=SOM,CN=WMIPolicy,CN=System,<domain DN>. Preserve
    existing CN/msWMI-ID, object GUID and creation metadata; change metadata
    updates only with actual managed-field changes. Unchanged reruns perform
    no filter writes. Ambiguous names, identity conflicts, missing/denied
    infrastructure and failed read-backs stop safely, without claiming rollback.
    No filter is deleted, renamed or associated/disassociated with a GPO.
    Updating a filter already used by a GPO CAN change that GPO's applicability.

    The sample combined VM query's missing quote is corrected and its duplicate
    Parallels predicate removed. Workstation 32/64-bit filters store separate
    OS and processor queries, evaluated together (AND), not concatenated SQL.
    Namespace defaults to root\CIMv2 in each editable definition. This script
    validates structure and encoding but does not execute queries on clients
    or prove effective Group Policy/WMI applicability or performance.

    Definitions remain in $script:LabWmiFilterDefinitions. Only a fully
    verified batch is published in $script:LabWmiFilterObjects by stable key;
    e.g. ['HyperVVirtualMachines'].ObjectGUID, .FilterId, .Name and
    .DistinguishedName. Refresh by GUID and verify identity before future
    synthetic changes. Hyper-V appends " TEST" to its baseline description,
    leaving its visible name and WQL query unchanged; VMware changes its query
    to Model LIKE "ESX%". Baselines remain unchanged and restore the original
    descriptions and queries on reruns. Previously renamed TEST filters are
    not adopted or deleted by this configuration; remove them manually.
    Synthetic WMI changes also delete Parallels Virtual Machines by verified
    baseline GUID; the next baseline run recreates it before synthetic
    deletion. Retained filters preserve GUID/CN/ID. GPO associations are
    not edited; deleting a filter can leave existing GPO references dangling.
    No dedicated forced replication or settling delay follows the baseline
    filter batch. Its selected-DC verification and completion timestamp are
    retained; GPO processing begins immediately afterward.

    Creates or reconciles three lab GPOs from Get-LabGpoDefinitions.
    Special Change Auditing Activity Settings GPO is an example for the
    supplied DSP 5.3 auditing requirements. Its GPMC Comment states its
    purpose; Computer Configuration is enabled and User Configuration is
    disabled. It is created without links; existing links permit settings
    updates because its ApplyWhenLinked flag defaults True.

    Enables the subcategory-override Security Option through GptTmpl.inf
    (SCENoApplyLegacyAuditPolicy DWORD 1). Eleven advanced audit subcategories
    use native UTF-8 machine audit.csv records, each Success only. English
    editor paths, GUIDs and storage references are in editable definitions.
    No per-subcategory registry values are invented. Unlisted audit rows
    are retained. Audit CSE registration and AD/GPT computer versions are
    maintained after backup, with content/metadata read-back checks.

    This does not manage GPO links, alter object SACLs, run auditpol or
    force policy refresh. Enabled links may apply changed settings through
    normal policy processing. CSV/metadata checks are not effective-client policy
    verification; review the advanced settings in GPMC during lab validation.

    Each GPO has an editable Boolean ApplyWhenLinked. True permits settings
    reconciliation when links are reported; False warns and skips that GPO
    when any link is reported. CIS benchmark defaults False; Questionable
    and Special Change Auditing Activity Settings GPOs default True.
    Skipped GPOs are not counted as verified. Links are never created, removed or
    changed. Manual link changes do not trigger the script automatically;
    run it again to reconcile configured settings against the current links.

    The original CIS Benchmark Windows Server Policy GPO is preserved.
    Questionable GPO adds NTLM level 3, a 42-day user-ticket lifetime (1008
    hours), a 10-minute service ticket, reversible encryption and an account
    lockout threshold of 10 failed logon attempts. LDAP
    server signing is explicitly None (DWORD 1), not left undefined;
    separate Server 2025 signing enforcement remains unmanaged.

    Its Administrative Templates policies disable Turn off picture password
    sign-in and Allow only Windows Vista or later connections through
    explicit registry-policy DWORD zero values, with read-back verification.

    AccountPolicy records use native Kerberos Policy/System Access sections;
    they are never written as registry policy or applied to this host. Reads
    both account-policy numeric and boolean native report fields.

    Routes Storage RegistryPolicy entries through GroupPolicy registry
    cmdlets and Storage SecurityOptions entries through the native
    GptTmpl.inf security template, preserving unrelated INF content.

    Backs up the GPO before writes. Reads before SET; native verification
    also checks CSE/tool registration, AD/SYSVOL versions and native GPO
    report data.

    Migrates only managed native settings out of earlier Registry.pol
    entries, after the native values and report verify. Uses the same
    selected writable DC throughout. Guards linked updates per GPO and
    detects concurrent edits to GPO content/metadata. Linked changes can
    affect lab target systems.

    Native file/AD writes are not transactional; do not edit this GPO during
    a run. Failures stop without automatic rollback; the backup path is
    logged.

    Requested values are a lab baseline, not CIS compliance: guest SMB is
    enabled and Windows Update DetectionFrequency is 82 with
    DetectionFrequencyEnabled 0. Supplied explanatory comments are preserved
    alongside the settings. No GPO links, unrelated-setting resets or
    delayed setting changes occur.

    Retained baseline object-type checkpoints force AD replication followed
    by a PauseTimeSeconds pause (default 5 seconds), including unchanged runs
    and recoverable skips. They follow DNS, OUs, all GPOs, computers,
    groups plus nesting, demo users, special accounts, generic users and
    direct group memberships. Baseline WMI filters, sites, subnets and FGPPs
    have no dedicated forced replication or delay. All changes and selected-DC
    verification remain enabled. Reserved categories and read-only summaries
    have no checkpoint.

    Baseline WMI filters follow the OU checkpoint. All baseline GPOs follow
    WMI verification and its completion timestamp without an intervening
    replication checkpoint or delay, before computer provisioning. GPO result
    caching and the shared configurable GPO checkpoint remain with the GPO
    batch. Remaining baseline processing provides more time before synthetic
    GPO changes; policy values, link safeguards and synthetic behavior are
    unchanged.

    repadmin /syncall /d /e /P pushes from the selected writable DC across
    sites. Ordinary retained object checkpoints use the domain partition;
    DNS also pushes hosted application partitions. Except for best-effort
    DNS, retained checkpoints stop on replication failure before sleeping or
    starting the next section. Earlier writes remain committed.

    At PauseTimeSeconds=5, eight non-DNS baseline checkpoints total 40 seconds
    of waits. A completed DNS checkpoint adds one 5-second wait (45 seconds
    total), plus repadmin execution time. A skipped or failed DNS checkpoint
    adds no full wait. MakeADChanges=False does not disable retained baseline
    checkpoints. A successful sync and fixed pause do not force SYSVOL/DFSR,
    verify convergence or guarantee DSP capture of intermediate changes.

    Discovers the executing computer's AD site into $MyADSite before AD
    writes. Assigns test subnets 111.111.4.0/24 and 111.111.5.0/24 to that
    site. If site discovery fails, warns and continues with both test
    subnets unlinked. Existing site links on these two subnets are cleared
    in that fallback.

    Selects a responsive writable DC in the local computer's domain,
    preferring the local DC when applicable, and uses it for subsequent AD
    operations. The PDC emulator does not need to be online. DC selection
    occurs at startup; a later failure during provisioning stops the run
    rather than retrying writes against another DC before replication has
    converged.

    During domain discovery, reports inter-site change notification as
    True or False per IP site link by reading options bit 0x1 on the selected
    DC. This is not a domain-wide setting or a replication health test.
    Unreadable configuration reports Unknown, not False; no readable links
    report Not applicable. No notification settings are modified.

    After provisioning and its summary, MakeADChanges (DEFAULTS) controls a
    separate synthetic AD Changes phase for audit-tool demonstrations. True
    enables that phase; False skips it and proceeds to completion.

    The five usrus* laptop/workstation accounts under OU=Computers,OU=Corp
    are created enabled like all defined computers. Synthetic computer
    changes delete usrusazlap12 and set usrusnjlap20 Description to
    "someone changed this computer description!!!". Missing targets log an
    error and skip only that action. Verified updates/deletions enter the
    synthetic computer summary. The next baseline run recreates the deleted
    account and restores the description before enabled synthetic changes.

    Synthetic demo-user changes set FAX (facsimileTelephoneNumber) to the
    literal text "(xxx) xxx-xxxx" for DemoUser5 (Yan Li) and DemoUser6
    (Aria Cruz). Verified GUIDs pin both targets. Baseline fax values remain
    unchanged and are restored before synthetic overrides on subsequent runs.
    Only changed, verified users are counted as synthetic demo-user updates.

    Synthetic GPO changes target the verified CIS Benchmark Windows Server
    Policy GPO first: native DWORD forceguest=1, LmCompatibilityLevel=4 and
    NoLMHash=0, plus Security Event Log MaxSize=20480 KB (20 MB), the
    minimum allowed by the EventLog.admx Security policy. Its baseline is
    1048576 KB (1024 MB/1 GB). These are explicit values, not relative
    toggles. The three native baseline values remain 0, 5 and 1; normal
    provisioning restores all four before the enabled synthetic phase
    reapplies its overrides. This unlinked lab GPO demonstrates DSP capture;
    no event log is resized on the executing computer and no link is created.

    Questionable GPO follows with account lockout threshold 100 failed
    logon attempts, LmCompatibilityLevel=5 and ClearTextPassword=0 (Disabled).
    Its provisioning baseline remains threshold=10, NTLM level=3 and
    reversible encryption=1. LockoutBadCount uses native System Access,
    not a registry value or password-history count. Existing lockout
    duration/reset-window settings remain unmanaged. Threshold 100 locks
    the account on the 100th qualifying failed attempt, not the 101st.
    No accounts are unlocked and no passwords are reset or converted.
    Questionable GPO retains its ApplyWhenLinked=True default.

    Get-LabGpoADChangeDefinitions holds the editable overrides. Reuses the
    native security and registry-policy writers, pre-write backup and
    read-back/report checks.
    Only a GPO verified during this run is eligible; missing or skipped
    targets warn and skip, while replaced identities and real errors stop.
    ApplyWhenLinked is inherited independently from each GPO's baseline
    (CIS False; Questionable True by default).
    No linked-policy bypass, new GPO, link edit, password reset, local
    registry change is introduced. A standard replication checkpoint follows
    the complete synthetic GPO batch. These deliberately weaker lab
    settings may affect targets of enabled links;
    NoLMHash=0 does not itself create LM hashes or change any password.

    The synthetic subnet sequence validates subnet 111.111.5.0/24, changes
    its Description to "Changed the subnet description attribute again!!",
    then verifies the new value and the same object's existence. When
    DeleteAfterDescriptionChange is True, immediately revalidates identity
    and description, deletes without confirmation and verifies absence on
    the selected DC. No forced replication, pre-deletion wait or end-of-batch
    checkpoint is performed. The intermediate description may not reach
    other DCs or DSP before deletion. Description-only changes also have no
    dedicated replication or delay. All deletion safeguards remain active.

    The next synthetic sequence changes subnet 111.111.4.0/24 Description
    to "This description changed by script!!" and verifies the same object's
    identity and description on the selected DC. This subnet is not deleted.

    The terminal synthetic stage removes ALL direct user members from
    Helpdesk Ops, not only users listed in baseline membership definitions.
    It includes disabled users and inetOrgPerson users; nested groups and
    computers are retained. It does not recursively change nested groups or
    users' primary-group membership. Unresolvable/foreign principals stop
    preflight rather than being silently treated as non-user members.
    The verified baseline group GUID pins the target; no same-name fallback
    or replacement group is adopted. Each user link is removed separately,
    and zero direct users is verified before adding Vladimir Levin. His
    baseline key is DemoUser10 (vlevin); preflight his GUID before removals
    and refresh it before adding. Missing/replaced users stop, with no
    name-based fallback or automatic account creation. Vladimir is added
    even if he was among the users just removed. Verify he is the only
    direct user before and after the final Domain replication checkpoint.
    This addition is the script's last directory mutation. Concurrent
    changes can fail verification; prior writes are not rolled back.

    Invoke-LabADChanges is the fixed ordering wrapper: first run all ordinary
    categories in Invoke-LabADChangeCategories, then the terminal cleanup.
    Add ALL future synthetic functionality inside the categories runner,
    never after the final stage or elsewhere after Invoke-LabADChanges.
    An earlier fatal failure still aborts normally; cleanup is NOT a finally
    action and does not run during failure unwinding. MakeADChanges=False
    skips it. Normal baseline membership reconciliation precedes it and can
    re-add configured users on the next run. An empty group skips removals
    but still receives the final user addition.
    This remove-then-add batch contains the last mutations on a successful
    run. Replication, reads, logging and timing may follow, but no other AD
    writes. DSP ingestion/display ordering and unrelated changes are outside
    this script's control; newest DSP placement cannot be guaranteed.

    Synthetic change subsections use the same INFO section headings as
    provisioning. Each implemented object class starts with its own heading
    before its change actions: GPOs, FGPPs, then AD Sites and Services
    (subnets and IP site links), then final Helpdesk Ops cleanup. Add headings for future
    demo user, group, computer or OU change activity when implemented. Reserved categories emit no
    headings or implied changes. AD Sites and Services changes currently
    affect subnets and set SemperisLabs-SemperisDevs to cost 444 and
    replication interval 105 minutes. Baseline remains cost 7 / 15 minutes.
    Synthetic site-link changes manage only cost and replInterval; link
    membership, schedule, options and description are not written.

    Retained synthetic checkpoints follow DNS, GPOs, successful OU subtree
    deletion and the final Helpdesk Ops membership batch. Each has one
    PauseTimeSeconds pause after its replication command(s). FGPPs and AD
    Sites and Services, including subnets and future site/site-link changes,
    have no dedicated forced replication or settling delay in either phase.
    Reserved categories have no checkpoints or extra waits.

    Use the retained standard for future demo-user, group, computer and OU
    synthetic batches, outside object loops and skip/unchanged guards.
    MakeADChanges=False skips synthetic actions and their checkpoints.
    At the default 5 seconds, four successful synthetic checkpoints add
    20 seconds of waits plus repadmin time; skipped OU deletion omits its
    checkpoint. Neither waits nor command success guarantee convergence.

    Normal AD replication remains enabled. Other retained checkpoints can
    incidentally replicate FGPP or Sites and Services changes; in particular,
    synthetic DNS /A still includes Configuration and the domain partition.
    No dedicated delivery or DSP-capture window is promised for intermediate
    FGPP assignments or subnet descriptions before removal/deletion.

    Ordinary categories retain their existing missing-target skip rules;
    the terminal group requires a verified target and stops on failure.
    Lookup/write failures stop processing.
    Existing baseline provisioning, password handling and replication
    behavior are unchanged by this switch. Normal provisioning restores
    managed subnet descriptions and recreates a deleted configured subnet
    on the next run. Selected-DC verification is not an all-DC convergence
    check or a guarantee that DSP has captured each intermediate change.

.DISCLAIMER
2026 Semperis, All rights reserved.
This sample script is not supported under any Semperis standard support program or service.
The sample script is provided AS-IS without warranty of any kind.
Semperis disclaims all implied warranties including, without limitation, any implied
warranties of merchantability or of fitness for a particular purpose. The entire risk
arising out of the use or performance of the sample script remains with you. In no
event shall Semperis, its authors, or anyone else involved in the creation, production,
or delivery of the scripts be liable for any damages whatsoever (including, without
limitation, damages for loss of business profits, business interruption, loss of
business information, or other pecuniary loss) arising out of the use of or inability
to use the sample script, even if Semperis has been advised of the possibility of such damages.

.NOTES
    Version: v1.8.22

    Before group-nesting listings, the final summary shows current FGPP
    direct user/group assignment DNs on the selected DC, including policies
    without subjects. It queries all visible policies, not baseline plans,
    so synthetic assignment removals are reflected. This read-only display
    has a blank line before and after, warns on read failures, and does not
    calculate resultant per-user policy or verify replication convergence.

    ACL identity checks use DirectoryEntry.psbase.Guid for the .NET GUID,
    bypassing the ADSI Guid attribute's different byte-order representation.
    Specific-object DN checks also use the underlying .NET properties.
    Keep identity checks before reads/commits and during DACL verification.

    Internal Dev Content and all Sharepoint/content groups target
    OU=Groups,OU=Corp beneath the discovered domain. Existing matching groups
    follow normal baseline reconciliation. Sharepoint - Restricted,
    Sharepoint - Corp Wiki, Sharepoint - Special Content and
    Sharepoint - Partners are Global security groups with exact configured
    descriptions. AD groups have no account-style Enabled property.

    Baseline nesting adds Sharepoint Admins, Internal Dev Content,
    Sharepoint - Restricted and Sharepoint - Corp Wiki to Sharepoint Users.
    Sharepoint - Special Content is a member of Sharepoint Admins;
    Sharepoint - Partners is a member of Sharepoint - Special Content.
    These direct links are additive and restored on baseline reruns.

    Root Corp layout also places Contractors and service accounts below
    Users, and Servers below Computers. These are baseline definitions;
    existing OUs at the former direct-child paths are not moved or deleted.

    Department layout below Corp (Finance, HR, IT, Marketing, Sales and
    Security) uses Users with Admins, service accounts and Contractors, and
    Computers with Servers. The service accounts OU keeps its space-based
    name; no rename to service-accounts is requested. Missing IT containers
    are included. All definitions remain parent-first and unprotected.
    Existing HR/Finance user and computer paths follow the nested containers.
    These are baseline desired-state definitions, not synthetic moves.
    Existing OUs at previous paths are not moved or deleted automatically;
    cleanup remains manual. Existing matching account reconciliation and
    all synthetic activity, password rules and credential behavior remain.

    Baseline Finance group InternalFinance (stable key) is named
    Finance-internal for Name, SamAccountName and DisplayName and targets
    OU=Groups,OU=Finance,OU=Corp. A new unprotected Admins OU is defined below
    OU=Users,OU=HR,OU=Corp, and adm.hr targets that child OU. HR computers
    appsvr-hr-001/002/003 target OU=Servers,OU=Computers,OU=HR,OU=Corp. HR service users
    svc-hr-db02, svc-hr-proxy01 and svc-hr-salesforce01 target
    OU=service accounts,OU=Users,OU=HR,OU=Corp. All paths append the discovered domain.
    No old-tree cleanup or old-group migration is added. Existing baseline
    identity reconciliation still applies to matching users/computers.
    Existing synthetic deletion settings/actions remain unchanged. Password
    preservation and the Admin-Tier0 ordinary-demo exception are unchanged.

    The shared DEMO credential applies only to DemoUser1-13 and AdmUser1
    (adm.draji). Tier0Admin (currently Admin-Tier0) uses its own credential,
    selected by stable definition key. It retains the ordinary-demo policy
    exception and reset/preservation rules. Collected-password exceptions
    follow effective AD requirements, not script admin minimums.
    All other baseline users receive random passwords ONLY at creation.
    Other admins (adm., Admin-, AppAdminII/III) require at least 20 characters;
    svc/service and special non-human accounts require at least 30. Other
    regular users follow AD requirements. Random generation defaults to 30
    and grows for higher AD minimums; longer candidates are accepted.

    Editable password rules are in Get-LabManagedUserPasswordSettings.
    Existing random-account passwords and change-at-logon state are always
    preserved, including RefreshAllPasswords and legacy reset flags.
    The DEMO key remains Semperis.Invoke-ADContentGenerator.<domain DNS>.
    The dedicated key is Semperis.Invoke-ADContentGenerator.Tier0Admin.<domain DNS>.
    Neither key includes the script version or a user SID. No shared DEMO
    credential is copied or used as fallback for Tier0Admin. Passwords are
    not logged; marshaled secret buffers are cleared. Each returned
    SecureString is disposed on success or failure. OU location does not
    select the source. ClearStoredCreds clears both current-domain entries.
    Entering a replacement updates its stored entry, but an existing account
    is reset only with RefreshAllPasswords or disabled preservation.

    Shared candidates are checked before writes in their provisioning phase.
    New accounts are created DISABLED, their actual resultant policy is read,
    and their password is initialized before enabling. Effective requirements
    are read from the selected DC; lookup failures stop rather than bypass.
    A later failure can still leave a partial account and earlier writes.
    Existing disabled accounts with pwdLastSet=0 and a preserved password stop
    with explicit repair guidance; this state alone does not prove absence
    of a password. No automatic existing-account repair is attempted.

    These are SCRIPT rules only: no FGPP definitions, assignments or domain
    policies are changed for these rules. Existing unrelated FGPP baseline
    and synthetic activity is retained. Length/standard complexity checks do
    not predict password-history or custom DC-filter acceptance. Current
    policy is not a prediction of future group memberships/assignments.

    RefreshAllPasswords runs the normal workflow and resets allowlisted
    DEMO accounts and Tier0Admin to their respective stored domain passwords.
    Generic users and all other random-password account types, including
    admins, service users and special accounts, remain excluded. Existing
    passwords are not inspected for length or reset merely to meet minima.
    Shared reset candidates and new random passwords must satisfy current
    AD/FGPP requirements. No domain-wide or out-of-scope reset is performed.

    The Finance computer baseline now targets srv-finance-app01 beneath
    OU=Servers,OU=Computers,OU=Finance,OU=Corp. Its stable definition key is retained;
    no migration, rename or deletion of svc-finance-svr-001 is requested.
    The Finance service account targets OU=service accounts,OU=Users,OU=Finance,OU=Corp
    while retaining its SAM and UPN. Existing matching users are reconciled
    to the new path without resetting existing service-account passwords.
    svc- demo accounts in any OU receive a managed random password only at
    creation; reruns preserve their passwords and change-at-logon state,
    regardless of the shared demo-password reset flag.

    Corp is created beneath the discovered domain root. Guest Users is
    beneath OU=Users,OU=Corp, with Partners and Contractors beneath it.
    An existing top-level Guest Users OU is moved with its complete subtree
    to this path before reconciling child OUs and users. Move/read-back uses
    the original GUID on the selected DC. Existing child identities and
    memberships are retained. Fresh domains create only the new structure;
    reruns leave an already relocated tree in place. If both old and new
    trees exist, stop for manual resolution rather than merge or delete.

    Every OU in these hierarchies explicitly has
    accidental-deletion protection disabled, including matching existing OUs.
    The obsolete OU tree and all its child OU definitions are retired from
    baseline provisioning. Account/group targets use Corp where applicable.
    No unrelated OU migration or automatic object deletion is added.
    Synthetic actions retain their current identity-based targets; recursive
    OU deletion remains paused rather than redirecting deletion into Corp.

    Partner DEMO users TJ Martineau (tmartineau) and Brian Britt (bbritt)
    target OU=Partners,OU=Guest Users,OU=Users,OU=Corp beneath the discovered
    domain. Existing users found by SAM/GUID are reconciled to this new OU;
    downstream operations use their refreshed objects or SAM names. Both
    are enabled and directly added to Sharepoint - Partners by baseline
    membership reconciliation. Supplied attributes, including external mail,
    null State and leading-zero employee IDs, are preserved as configured.
    TelephoneNumberAlt/FAXalt remain demo-change metadata, not AD attributes.
    These users follow existing non-allowlisted creation-only random-password
    rules; existing passwords and change-at-logon state are preserved.

    ISOLATED LAB ONLY: John Wick (jwick) is a direct IT Contractors member.
    The baseline creates/reconciles IT Contractors, Extended Helpdesk,
    Server Operations and Legacy Recovery Admins as Global security groups
    in OU=Groups,OU=IT,OU=Corp beneath the discovered domain. Required
    nesting follows that order, ending in the domain's existing BUILTIN
    Administrators group by its CN=Administrators,CN=Builtin domain DN.
    This intentionally grants jwick Tier 0 access; never run this in
    production. John Wick membership uses his exact Corp Contractors DN,
    resolved afresh on every run so account deletion/recreation is safe.
    No prior user SID/GUID is stored. The built-in group is not created,
    moved or renamed. Its DN assumes the configured Administrators CN;
    update it if that built-in group has been renamed or localized.
    Existing unrelated memberships remain under the additive defaults.

    DisplayGroupNestingSummary in DEFAULTS selects optional group-only ASCII
    trees in the final processing summary. Defaults: Sharepoint Users,
    Sharepoint - Special Content, Pizza Party Group, Helpdesk-L3,
    Tier1 Operators, Special Admin Group, Helpdesk-ALL, Domain Admins and
    Administrators. Administrators resolves only in the domain Builtin
    container. Set to $null, an empty string, @(), or blank entries to omit the
    entire block and its additional blank lines.
    Trees read current direct memberships from the selected DC after all AD
    processing, including synthetic changes, rather than desired definitions.
    Names/SAM names must resolve uniquely in the discovered domain. The
    selected group is cyan. Member Of (parent groups) follows memberOf links
    upward to ancestors; Members (child groups) follows member links downward
    to descendants. These are separate labeled branches, not one ambiguous
    containment tree. Other groups are white; warnings are yellow. User
    members are not displayed. Repeated groups appear on each path; circular
    references stop with a marker, with the selected group still cyan.
    Failed relationship reads warn and other branches/directions continue.
    An empty branch says no visible group links; it is not proof of absence.
    ACL-trimmed attributes/objects can limit visibility without an AD error;
    this report is not proof of complete access or of absence of hidden links.
    Safety limits are 64 nested levels and 2000 nodes per direction/root;
    truncated branches are explicitly marked. Reporting performs no writes,
    replication, retries or DC failover and never changes processing counts.
    Its read time occurs after the processing stopwatch has stopped.

    The final processing summary reports verified created, updated and deleted
    objects separately for baseline and synthetic activity. Repeated changes
    to one identified object count once per action and phase. An object may
    appear in both updated and deleted totals when both actions occurred.
    Password resets count as user updates; already-matching objects do not.

    Group nesting and membership links use added/removed counts; removing FGPP
    assignments updates the policy rather than deleting it. Recursive OU
    deletion counts its pre-enumerated contents after root deletion verifies.
    User categories come from the accounts resolved during this run; unknown
    accounts are reported as other users. Failed/unverified partial writes
    are excluded from counts and must be reviewed in earlier warnings/errors.
    Summary collection performs no additional directory reads or writes and
    does not change replication timing or the terminal AD-write boundary.

    GPO file-sharing and lock violations (Windows errors 32/33), including
    wrapped .NET file-write errors for GPT.INI, produce warnings and skip the
    affected GPO. Remaining GPOs and script sections continue. Skipped GPOs
    are unverified, excluded from successful counts and synthetic changes.
    Earlier writes may have committed; review AD/SYSVOL consistency and the
    logged backup before rerunning. No automatic write retry, rollback,
    link changes or DC failover is attempted. Other GPO errors remain fatal.

    Baseline data includes Sharepoint/content security groups and the
    Helpdesk-ALL hierarchy. New groups use Global scope, following the lab's
    existing security-group convention. Sharepoint-Community is a direct
    member of Sharepoint Users; Helpdesk-L1, Helpdesk-L2 and Helpdesk-L3 are
    direct members of Helpdesk-ALL. Explicit direct user links put adm.sjenkins
    in both L1 and L3, and marie.courtney in L2. Membership mode is unchanged.

    Demo/admin password assignment follows the explicit shared-account
    allowlist and account-type rules described above; all other users receive
    creation-only random passwords. Existing random passwords are preserved.
    Serge Vaudenay uses GivenName Serge and Surname Vaudenay.
    No other memberships are inferred from descriptions.

    Managed random passwords contain at least 28 letters/digits (uppercase,
    lowercase and a digit guaranteed) plus one ! and one @, shuffled
    cryptographically. Length grows for higher effective AD requirements.
    They are never logged, saved to the credential store or exported to a
    vault. Domain/FGPP policies and custom password filters still apply.
    Existing invalid passwords are not repaired in the creation-only scope.
    Accounts deleted by synthetic activity and later recreated are NEW
    accounts and receive a new password at creation.

    Synthetic OU deletion is currently PAUSED: OUforSyntheticDeletion in
    DEFAULTS is null. The function and call site remain available for later
    reuse with an explicitly chosen OU. Other synthetic activity is unchanged.
    When enabled with a nonblank target and MakeADChanges true, the relative
    path is resolved in the discovered domain; the OU and all its contents are
    recursively deleted immediately after synthetic FGPP processing and
    its completion timestamp, before synthetic subnet changes.
    Deletion uses one Remove-ADOrganizationalUnit -Recursive call against
    the configured root OU; descendants are removed by that OU tree action.
    Subtree enumeration is read-only, with no per-child delete calls. This
    does not guarantee a single AD audit event or a single DSP activity.
    Null or blank opts out with an advisory. Protection is never disabled by
    this operation; protected or unreadable subtree protection fails closed.
    No OU is deleted by this step while paused. The obsolete deletion-target
    example has been removed. If deletion is re-enabled later, a
    baseline rerun can recreate defined objects with new identities; that
    is not AD recovery or preservation of deleted-object SIDs and GUIDs.

    A monotonic Stopwatch starts inside Invoke-Main immediately before the
    first OU provisioning call, after prerequisites, password/count prompts
    and operator-site discovery. No AD object creations, updates or resets
    precede this boundary. The timer includes provisioning, verification,
    replication, pauses, enabled synthetic changes and SecureString cleanup;
    it stops when Invoke-Main returns or throws. Prerequisites, prompt time,
    transcript startup/shutdown and final status-output overhead are excluded.

    When synthetic AD changes are enabled, a flush-left elapsed-time line
    follows the baseline summary's final section-completion timestamp and
    precedes the synthetic phase banner. It uses the same text, millisecond
    format, White foreground and DarkMagenta background as the final total.
    This is a cumulative snapshot; the stopwatch is not stopped or reset.
    The final total still includes baseline and synthetic processing.
    When MakeADChanges=False, only the existing final total is displayed.

    The final flush-left INFO line reports total elapsed processing time as
    HH:MM:SS.mmm (total hours can exceed 24), also on processing errors or
    early returns after timing starts. If provisioning never starts (such as
    credential clearing or a prerequisite/prompt failure), no elapsed line is
    printed. Timing is informational, not a claim that processing succeeded.

    Baseline and synthetic sections end with a local completion timestamp:
      [STATUS] section completed at: yyyy-MM-dd HH:mm:ss
    The marker uses Magenta foreground, two spaces and no explicit background.
    Batch markers follow verification and any retained replication/wait.
    Group creation, nesting and individual GPO processing also have their
    own markers. The
    provisioning summary is stamped before synthetic changes begin. Handled
    skips/warnings still complete a section; fatal errors do not stamp it.
    Prerequisites and reserved synthetic categories are not stamped. No new
    queries, mutations, replication commands or pauses are introduced.

    Edit desired lab data in OPERATOR-EDITABLE DATA DEFINITIONS, after
    DEFAULTS.

    PauseTimeSeconds in DEFAULTS controls retained baseline and synthetic
    replication-pause settings and defaults to 5 seconds. FGPPs and AD Sites
    and Services (sites, subnets and site links) do not use this setting.
    Baseline WMI filters also have no dedicated replication or pause.
    Password/count no-input timeouts and disk-review delays are separate.
    Data-entry timeouts stop permanently once typing or pasting begins.

    Native replication sync/callback output uses Gray foreground with no
    explicit background color. Each nonblank line has an [INFO] prefix and
    four-space indentation; native message whitespace is preserved.
    Retained pause messages use Gray foreground on DarkGreen background.

    Baseline replication standard: finish non-exempt implemented sections
    with Invoke-LabBaselineReplicationSync outside object loops. GPOs use
    Invoke-LabGpoReplicationSync. Direct memberships have a final baseline
    checkpoint because their writes follow the groups/nesting checkpoint.
    Baseline WMI filters are exempt and proceed directly to GPO processing.
    FGPPs and Sites and Services remain exempt in both phases; do not add
    checkpoints or delays when extending their site/subnet/site-link actions.

    Shared engine Invoke-LabReplicationCheckpoint serves retained baseline
    and synthetic wrappers. Synthetic DNS uses one /A invocation across all
    hosted naming contexts; baseline DNS retains per-partition commands.
    End non-exempt synthetic categories with Invoke-LabSyntheticReplicationSync
    after actions, verification and summary. Reserved categories have no waits.

    When saving a new revision, prepend a dated entry to .VERSION_HISTORY.
    Keep .VERSION_HISTORY after .DESCRIPTION and .NOTES, and before
    .PARAMETERS and .EXAMPLES. Newest-first applies to history entries only.
    Keep history descriptions within 60-character columns and align wrapped
    lines under Description. Preserve historical versions and credential
    keys.

    Console output uses flush-left headers and two-space section details.
    Action INFO messages use six spaces (-IndentLevel 3); action results,
    warnings and failures retain four spaces (-IndentLevel 2).

    Linked-GPO skips caused by ApplyWhenLinked=False use Yellow foreground
    on DarkRed background, both at the skip and in the provisioning summary.
    Other warnings retain Yellow foreground with no explicit background.

    Membership checks use two spaces, member details four, actions six and
    their SUCCESS results eight (-IndentLevel 4).

    Function summaries and final completion are flush-left (-IndentLevel 0).
    New sections use Write-SectionHeader, then Write-Status (default level
    1). Shared helpers apply to generic-user, GPO, DNS, FGPP, site/service,
    and subnet steps.

    Subnets are forest-wide configuration-partition objects. The operator
    needs appropriate delegated rights there; local elevation or
    domain-level permissions alone do not guarantee access. All subnet reads
    and writes use the selected writable DC. Blank Site definitions remove
    existing site links.

    GPO initialization requires the GroupPolicy module (GPMC/RSAT), SYSVOL
    access and GPO create/edit rights. The module is checked before AD
    writes. Current GPO values, not local machine registry values, are read
    before SET. Omitted GPO values remain unmanaged; only listed policy
    entries are ensured.

    Native Security Options require edit rights to GptTmpl.inf, GPT.INI and
    the GPO's AD version/extension attributes. A GPO backup is saved beneath
    the editable BackupRoot before any setting writes. Only listed native
    DWORD values and supported AccountPolicy integers are merged; unrelated
    sections and settings remain unmanaged.

    Native security-template settings verify against INF data, CSE
    registration, matching AD/GPT versions and Get-GPOReport
    SecurityOptions/Account entries before success.

    AdvancedAudit settings use a separate strict UTF-8 machine audit.csv
    reader/writer and the Audit CSE/tool pair. Managed rows are reconciled
    by subcategory GUID; unmanaged CSV rows are retained. Success verifies
    CSV content, CSE registration and matching AD/GPT computer versions,
    not client-effective policy or a parsed advanced-audit GPO report.

    Optional Comment is stored as the GPO description shown in GPMC.
    Optional GpoStatus=UserSettingsDisabled manages GPC flags=1: Computer
    enabled, User disabled. Existing definitions without these fields do
    not have their comment or configuration status changed.

    MaxTicketAge uses hours; 1008 hours is 42 days, not a renewal lifetime.
    Only migrated duplicates for those listed values are removed from
    Registry.pol.

    ApplyWhenLinked is an editable Boolean in each GPO definition. CIS
    benchmark uses False; Questionable and Special Change Auditing Activity
    Settings GPOs use True. False warns and skips that GPO when any link is
    reported, even a disabled link; later GPOs and script sections continue.
    Initial skips occur before backups or settings/metadata writes. If a
    new link is detected after reconciliation starts, further writes stop
    for that GPO and the warning notes possible partial changes. No skipped
    GPO is reported as fully verified. Actual read/write/verification errors
    remain fatal. True permits settings updates with links; it does not
    create links or force effective policy on clients. New GPOs are created
    without links; existing targets/options/order are not edited. Checks
    are not an atomic lock against concurrent link administration.

    Enabled existing links may deliver changed settings during normal policy
    processing. No gpupdate is forced and effective client policy is not
    verified. Refresh an already-open editor after the run.

    A native-write failure can leave partial changes; no automatic rollback
    or failover is attempted. A GPO failure stops before the end-of-GPO
    replication step.

    Retained checkpoints require repadmin.exe and appropriate replication
    rights. Baseline checkpoints use the domain and hosted DNS application
    partitions; synthetic DNS /A also includes Schema and Configuration.
    Missing repadmin.exe triggers AD DS management-tools installation.
    Refreshes process-only PATH lookup for the Windows system directory
    when necessary, then verifies availability before provisioning writes.
    Non-DNS replication or wait failures stop
    the run; DNS checkpoint failures warn and continue. No DC
    failover or rollback is attempted. These checkpoints are settling time,
    not proof of AD/SYSVOL convergence or DSP capture of intermediate states.

    Run using Windows PowerShell 5.1 from an interactive, domain-connected
    Windows session. Password prompting uses a masked Windows Forms dialog,
    which works in PowerShell ISE. The credential is stored for the current
    Windows user on this computer.

    ---------------------
    Example of poor nested group structure taken from an example by 'The Admins You Didn't Count' by Breach Craft:

    John Wick - jwick
    Expected access: contractor support resources
    v
     IT Contractors
     v
     Extended Helpdesk
     v
     Server Operations
     v
     Legacy Recovery Admins
     v
     BUILTIN\Administrators

    In this illustrative story:
    * IT Contractors was added to Extended Helpdesk for a support engagement.
    * Helpdesk was already nested in Server Operations for maintenance.
    * Server Operations belonged to Legacy Recovery Admins from an old migration.
    * Legacy Recovery Admins had been placed in the domain's Administrators group for temporary recovery work--and never removed.

    Each change had a local justification. Nobody reviewed the complete chain.
    ---------------------

.VERSION_HISTORY
 Date        Version     Author                        Description
 ----------  ----------  --------------------------    ------------------------------------------------------------
 2026-11-17  v1.8.22     Rob Ingenthron, Semperis      Align baseline and synthetic summary counters using the
                                                       longest bracketed category label across both phases, with
                                                       five spaces before created/added. Preserve counts, row
                                                       order, colors and directory behavior.
 2026-11-17  v1.8.21     Rob Ingenthron, Semperis      Add the current filename and version immediately below
                                                       .SYNOPSIS, using matching paragraph indentation and a blank
                                                       separator before the synopsis text. Preserve script
                                                       behavior.
 2026-11-17  v1.8.20     Rob Ingenthron, Semperis      Add synthetic IP site-link changes: cost 444 and replication
                                                       interval 105 minutes. Preserve baseline cost 7 / 15 minutes
                                                       and unmanaged link fields. Verify changes on the selected DC
                                                       before terminal group changes; retain the no-sync/no-delay
                                                       policy.
 2026-11-17  v1.8.19     Rob Ingenthron, Semperis      Fix site creation by using Semperis-Devs as the AD name;
                                                       retain Semperis Devs as DisplayName. Update the IP link
                                                       endpoint and reject spaces/invalid characters in site names
                                                       and endpoint references before their provisioning writes.
                                                       Preserve subnet settings, link name, cost and interval.
 2026-11-16  v1.8.18     Rob Ingenthron, Semperis      Add Semperis Devs and subnet 10.4.22.0/25, plus the IP site
                                                       link SemperisLabs-SemperisDevs at cost 7 / 15 minutes. Group
                                                       topology activity; reconcile and verify managed fields on
                                                       the selected DC. Track links in inventory and summaries.
                                                       Preserve default topology and the existing no-sync/no-delay
                                                       policy.
 2026-11-16  v1.8.17     Rob Ingenthron, Semperis      Revise startup bullets to add/updates and sets/resets.
                                                       Append the requested idempotence and system/configuration
                                                       statements. Preserve display colors, spacing and behavior.
 2026-11-16  v1.8.16     Rob Ingenthron, Semperis      Add the operator informational block between STARTUP and
                                                       domain discovery in Gray with no background color and a
                                                       blank line before and after. Preserve other output and
                                                       behavior.
 2026-11-16  v1.8.15     Rob Ingenthron, Semperis      Change only the startup section label from INFO to STARTUP.
                                                       Preserve startup colors and all other output labels.
 2026-11-16  v1.8.14     Rob Ingenthron, Semperis      Change the default INFO section-header foreground from Green
                                                       to DarkGreen while retaining its Gray background. Keep
                                                       explicit startup DarkBlue and provisioning-summary White
                                                       overrides, ordinary status output and native replication
                                                       output unchanged.
 2026-11-16  v1.8.13     Rob Ingenthron, Semperis      Add a read-only FGPP application display before nested-group
                                                       listings in the final summary, with a blank line before and
                                                       after. Query current direct user/group assignments from the
                                                       selected DC; include unassigned policies and warn on query
                                                       failures. Preserve policy settings, assignments, group trees
                                                       and existing summary counts.
 2026-11-16  v1.8.12     Rob Ingenthron, Semperis      Set only the Starting Invoke-ADContentGenerator header
                                                       foreground to DarkBlue. Retain its existing Gray background
                                                       and leave every other section header and output color
                                                       unchanged.
 2026-11-16  v1.8.11     Rob Ingenthron, Semperis      Fix false ACL identity mismatches by reading DirectoryEntry
                                                       GUIDs through psbase.Guid instead of the ADSI-adapted Guid
                                                       attribute. Apply to all three specific-object checks and
                                                       both DNS ACL checks. Read specific-object DNs through
                                                       psbase.Properties. Retain GUID/DC pinning, DACL
                                                       verification, ACL scopes and prompt timeout safeguards.
 2026-11-16  v1.8.10     Rob Ingenthron, Semperis      Disable data-entry prompt timeouts permanently after the
                                                       first typed or pasted character, even if input is invalid or
                                                       later cleared. Guard password/count timer events and count
                                                       acceptance with shared per-dialog state. Retain no-input
                                                       defaults, Cancel behavior and the fixed removal-confirmation
                                                       deadline.
 2026-11-16  v1.8.9      Rob Ingenthron, Semperis      Set OpsAdmin (adm.johnwick) PasswordNeverExpires to true in
                                                       its editable baseline definition. Reuse existing creation,
                                                       reconciliation, conflict checks and read-back verification.
                                                       Preserve existing managed passwords, Tier0Admin settings and
                                                       all password-reset safeguards.
 2026-11-16  v1.8.8      Rob Ingenthron, Semperis      Set Tier0Admin PasswordNeverExpires to true in the editable
                                                       baseline definition. Apply at creation and reconcile
                                                       existing accounts independently of password-reset flags;
                                                       verify read-back. Keep other accounts unmanaged unless
                                                       explicitly configured. Reject a preserved change-at-logon
                                                       conflict before demo-user writes; retain dedicated
                                                       credentials and password safeguards.
 2026-11-16  v1.8.7      Rob Ingenthron, Semperis      Add dedicated nTSecurityDescriptor DACL helpers and editable
                                                       baseline/synthetic ACL definitions. Grant DemoUser9 object-
                                                       only Read/Write on Bad OU; grant AdmUser1 Read/Write on the
                                                       OU and descendants. Remove DemoUser9 explicit ACEs and
                                                       AdmUser1 explicit read grants during synthetic changes;
                                                       retain write and shared ReadControl. Preserve
                                                       unrelated/inherited ACEs. Verify full DACL read-back and use
                                                       one replication checkpoint after each ACL batch. Pin
                                                       selected-DC GUID/SID identities.
 2026-11-16  v1.8.6      Rob Ingenthron, Semperis      Remove script/schema version gates from cleanup. Use
                                                       existing JSON best effort; retain domain, filename and
                                                       GUID/DNS identity safeguards. Skip/report unsupported or
                                                       malformed saved entries; keep the source unchanged. Rebuild
                                                       current catalogs without requiring saved catalogs or a
                                                       RunId. Report specific ownership mismatches and mark skipped
                                                       entries for review. Preserve REMOVE ALL and default-cancel
                                                       behavior.
 2026-11-16  v1.8.5      Rob Ingenthron, Semperis      Change the destructive cleanup confirmation button to REMOVE
                                                       ALL and align its prompt/help wording. Preserve the
                                                       15-second deadline and default-cancel behavior.
 2026-11-16  v1.8.4      Rob Ingenthron, Semperis      Resolve the invoked script symbolic-link chain before JSON
                                                       naming. Resolve relative targets beside each link; use the
                                                       final PS1 filename for inventory naming and metadata. Fall
                                                       back to the original runtime identity if resolution fails,
                                                       including broken links, cycles or unavailable metadata. Keep
                                                       the JSON in the current working directory.
 2026-11-16  v1.8.3      Rob Ingenthron, Semperis      Capture the invoked script's own MyInvocation.MyCommand.Path
                                                       at entry. Require a saved PS1 invocation; reject selected-
                                                       text execution instead of reusing stale filename state.
                                                       Strip the runtime extension and append .JSON once; use that
                                                       exact name for provisioning and cleanup in the current
                                                       directory. Never enumerate files or fall back to a
                                                       caller/editor filename.
 2026-11-16  v1.8.2      Rob Ingenthron, Semperis      Project every baseline object definition into schema 3, even
                                                       when absent; encode the full generic-user series
                                                       independently of the selected creation count. Resolve
                                                       configured identities again before removal, retaining saved
                                                       GUID targets. Supplement synthetic DNS variants and WMI
                                                       aliases on a best-effort basis. Preserve the source
                                                       inventory; rescan after cleanup and write a separate results
                                                       JSON with residuals and unresolved failures.
 2026-11-16  v1.8.1      Rob Ingenthron, Semperis      Capture actual saved PS1 identity once at script entry; use
                                                       it for JSON naming, metadata and removal validation.
                                                       Inventory all configured lab-generated content, including
                                                       existing older-run objects and generic users above the
                                                       selected count. Exclude built-in, critical and existing-only
                                                       references. Deduplicate GUID/DNS identities, report
                                                       incomplete read-only discovery and refresh after partial
                                                       failures. Expand destructive cleanup warnings; require
                                                       schema 2 configured-content inventory.
 2026-11-16  v1.8.0      Rob Ingenthron, Semperis      Add exclusive RemoveAllGeneratedContent mode with strict
                                                       Administrator, Domain Admins and Enterprise Admins checks
                                                       before a fixed 15-second, default-cancel confirmation.
                                                       Overwrite a current-directory JSON inventory each
                                                       provisioning run; persist only newly created GUIDs and exact
                                                       DNS identities, including partial creations. Remove users,
                                                       computers, groups, GPO links/policies, FGPPs, WMI filters,
                                                       sites/subnets, DNS and OUs. Approved containers include all
                                                       descendants. Never adopt older or merely updated objects;
                                                       retain inventory during cleanup for retries.
 2026-11-16  v1.7.64     Rob Ingenthron, Semperis      Relocate Guest Users and its Partners/Contractors subtree
                                                       beneath Corp/Users. Move an existing root tree by GUID, stop
                                                       on duplicate old/new trees, and verify the new parent.
                                                       Update partner DEMO user paths and notes. Preserve object
                                                       identities, memberships, passwords and later identity-based
                                                       references.
 2026-11-16  v1.7.63     Rob Ingenthron, Semperis      Pause five seconds immediately after warning that the
                                                       operator lacks Enterprise Admins membership. Preserve
                                                       warning formatting, membership checks and continue behavior;
                                                       no added delay for confirmed members or lookup failures.
 2026-11-16  v1.7.62     Rob Ingenthron, Semperis      Install missing AD, GPO, DNS and replication management
                                                       tools using Server features or client RSAT capabilities.
                                                       Retry global imports and verify required commands. Handle
                                                       elevation, servicing failure, restart requirements and
                                                       repadmin lookup before provisioning. Preserve non-installing
                                                       credential-clear mode and existing AD definitions.
 2026-11-16  v1.7.61     Rob Ingenthron, Semperis      Capitalize DEMO in the password prompt name. Add a blank
                                                       line before Cancel or timeout guidance in both password
                                                       dialogs. Preserve automatic sizing and all credential,
                                                       timeout and provisioning behavior.
 2026-11-16  v1.7.60     Rob Ingenthron, Semperis      Add a dedicated Tier0Admin Credential Store password using
                                                       the same dialog and timeout as DEMO users. Stop before
                                                       provisioning when neither entered nor stored. Route
                                                       Tier0Admin creation/refresh to its own secret, preserve
                                                       reset rules, and clear both entries in clear mode.
 2026-11-16  v1.7.59     Rob Ingenthron, Semperis      Append the supplied John Wick poor-nesting example at the
                                                       end of NOTES with a preceding blank line. Use ASCII-safe
                                                       punctuation and downward markers. Keep -Help filtering and
                                                       all operational behavior unchanged.
 2026-11-15  v1.7.58     Rob Ingenthron, Semperis      Add an exclusive -Help option that prints the script name,
                                                       synopsis, description, parameters and examples. Omit notes
                                                       and revision history. Return before defaults, transcripts,
                                                       prerequisites, prompts or AD operations.
 2026-11-15  v1.7.57     Rob Ingenthron, Semperis      Resolve John Wick direct membership by his exact Corp DN on
                                                       every run. Use a DN for built-in Administrators and add it
                                                       to the final nesting display. Preserve other group
                                                       references, additive nesting and account password rules.
 2026-11-15  v1.7.56     Rob Ingenthron, Semperis      Add four IT security groups and the John Wick contractor-to-
                                                       Tier-0 nesting chain. Resolve built-in Administrators by SID
                                                       as existing-only. Add jwick to IT Contractors and document
                                                       the intentional isolated-lab privilege exposure.
 2026-11-15  v1.7.55     Rob Ingenthron, Semperis      Add John Wick (jwick) as DemoUser16 with supplied baseline
                                                       attributes in Corp/IT/Users/Contractors. Preserve existing
                                                       password rules and group membership definitions.
 2026-11-15  v1.7.54     Rob Ingenthron, Semperis      Add partner DEMO users TJ Martineau and Brian Britt with
                                                       supplied baseline attributes in Guest Users/Partners. Add
                                                       both users directly to Sharepoint - Partners. Preserve
                                                       existing creation-only random-password rules, metadata
                                                       handling and earlier definitions.
 2026-11-15  v1.7.53     Rob Ingenthron, Semperis      Insert Sharepoint - Special Content immediately after
                                                       Sharepoint Users in the default group nesting display list.
                                                       Preserve remaining order and reporting behavior.
 2026-11-15  v1.7.52     Rob Ingenthron, Semperis      Display both Member Of parent paths and Members child paths
                                                       for each selected group. Highlight the selected group cyan,
                                                       including cycle markers. Keep separate labeled directions,
                                                       read-only traversal, warnings and disabled-output behavior.
 2026-11-15  v1.7.51     Rob Ingenthron, Semperis      Add Domain Admins to the default group nesting display list.
                                                       Preserve existing selected groups and reporting behavior.
 2026-11-15  v1.7.50     Rob Ingenthron, Semperis      Add Helpdesk-ALL to the default group nesting display list.
                                                       Preserve existing selected groups and reporting behavior.
 2026-11-15  v1.7.49     Rob Ingenthron, Semperis      Add Special Admin Group to the default group nesting display
                                                       list. Preserve existing selected groups and reporting
                                                       behavior.
 2026-11-15  v1.7.48     Rob Ingenthron, Semperis      Add Tier1 Operators to the default group nesting display
                                                       list. Preserve existing selected groups and reporting
                                                       behavior.
 2026-11-15  v1.7.47     Rob Ingenthron, Semperis      Add Helpdesk-L3 to the default group nesting display list.
                                                       Preserve existing selected groups and reporting behavior.
 2026-11-15  v1.7.46     Rob Ingenthron, Semperis      Add optional DEFAULTS-selected live group nesting ASCII
                                                       trees inside the final processing summary. Default to
                                                       Sharepoint Users and Pizza Party Group. Suppress all added
                                                       output when empty; flag cycles and unreadable or truncated
                                                       branches without changing AD or processing counts.
 2026-11-15  v1.7.45     Rob Ingenthron, Semperis      Indent all four lines of the OU creation error by four
                                                       additional spaces. Preserve continuation alignment, message
                                                       text and skip-and-continue behavior.
 2026-11-15  v1.7.44     Rob Ingenthron, Semperis      Format OU creation errors on four aligned lines. Put the
                                                       exception after the colon and explanatory sentences on
                                                       separate lines aligned with Could. Preserve error severity,
                                                       ACL handling and skip-and-continue behavior.
 2026-11-14  v1.7.43     Rob Ingenthron, Semperis      Handle Windows sharing and lock violations as warning-only
                                                       GPO skips, including wrapped GPT.INI write errors. Continue
                                                       remaining GPOs and sections; exclude unverified GPOs from
                                                       counts and synthetic changes. Preserve partial-write and
                                                       backup warnings; keep other failures fatal.
 2026-11-14  v1.7.42     Rob Ingenthron, Semperis      Add four Global Sharepoint security groups in Corp Groups
                                                       with exact configured descriptions. Add six baseline child-
                                                       to-parent memberships, preserving existing links and normal
                                                       baseline reconciliation. No synthetic AD changes.
 2026-11-14  v1.7.41     Rob Ingenthron, Semperis      Add AD-integrated 6.6.6.0/24 reverse zone to baseline.
                                                       Delete only the fakehost01 PTR and set fakehost02 PTR TTL to
                                                       31 seconds during synthetic DNS changes. Recreate missing
                                                       baseline PTRs and restore fakehost02 PTR TTL to 3600
                                                       seconds. Verify exact targets and counts; preserve forward
                                                       and unrelated reverse records.
 2026-11-14  v1.7.40     Rob Ingenthron, Semperis      Fix DNS node ACL SecurityMasks access through PSBase.Options
                                                       to bypass the PowerShell ADSI property adapter. Keep DACL-
                                                       only reads and writes, GUID checks, verification, warning
                                                       handling and PTR behavior unchanged. Applies to baseline
                                                       cleanup and synthetic ACL grants.
 2026-11-13  v1.7.39     Rob Ingenthron, Semperis      Change Hyper-V WMI description to include TEST during
                                                       synthetic activity instead of renaming the filter. Validate
                                                       and verify msWMI-Parm1 updates. Preserve the baseline name,
                                                       IDs and queries; restore description on baseline reruns.
                                                       Leave previously renamed filters for manual deletion.
 2026-11-13  v1.7.38     Rob Ingenthron, Semperis      Resolve baseline WMI filters by visible name first. Use the
                                                       synthetic renamed alias only when the baseline name is
                                                       absent. Update existing filters in place, preserving IDs and
                                                       creation dates. Keep exact-name ambiguity and race
                                                       safeguards; never merge or delete duplicates automatically.
 2026-11-13  v1.7.37     Rob Ingenthron, Semperis      Add five enabled Corp computer baseline accounts. Delete
                                                       usrusazlap12 and change usrusnjlap20 description during
                                                       synthetic computer changes. Log missing targets as errors
                                                       and continue. Verify GUID-pinned actions on the selected DC
                                                       and report computer updates/deletions in the summary.
 2026-11-13  v1.7.36     Rob Ingenthron, Semperis      Set synthetic fax values for DemoUser5 (Yan Li) and
                                                       DemoUser6 (Aria Cruz) to literal (xxx) xxx-xxxx. Target
                                                       verified user GUIDs, verify reads on the selected DC and
                                                       count changed demo users in the summary. Preserve baseline
                                                       fax values, passwords and all existing synthetic changes.
 2026-11-13  v1.7.35     Rob Ingenthron, Semperis      Track verified synthetic WMI updates and deletions in the
                                                       phase summary by GUID. Record verified final group link
                                                       removals and addition before later failures or replication.
                                                       Preserve per-action deduplication and all directory actions.
                                                       FGPP assignment removal remains an update, not policy
                                                       deletion.
 2026-11-13  v1.7.34     Rob Ingenthron, Semperis      Delete Parallels Virtual Machines during synthetic WMI
                                                       changes using its verified baseline GUID and filter ID.
                                                       Verify absence on the selected DC and remove its cached
                                                       reference. Keep baseline creation, Hyper-V rename and VMware
                                                       ESX query changes unchanged.
 2026-11-13  v1.7.33     Rob Ingenthron, Semperis      Add synthetic WMI changes: append TEST to the Hyper-V filter
                                                       name and change the VMware query to ESX%. Preserve filter
                                                       GUIDs, IDs and GPO links. Restore renamed filters in
                                                       baseline reruns without duplicate creation; verify changes
                                                       on the selected DC.
 2026-11-13  v1.7.32     Rob Ingenthron, Semperis      Retire Corp OU Structure and all 10 descendant OU
                                                       definitions from baseline provisioning. Remove obsolete OU-
                                                       based password-scope logic and references. Retain Corp
                                                       account/group targets and synthetic actions; leave recursive
                                                       OU deletion paused. Do not delete existing AD objects or
                                                       change password-source rules.
 2026-11-13  v1.7.31     Rob Ingenthron, Semperis      Restrict shared credentials to DemoUser1-13, AdmUser1 and
                                                       Admin-Tier0. Generate creation-only random passwords for
                                                       other users and special service accounts. Enforce admin 20+
                                                       and service 30+ minima and higher AD requirements. Preserve
                                                       existing random passwords even on refresh; retain enabled
                                                       baselines, OU/group changes and FGPPs.
 2026-11-13  v1.7.30     Rob Ingenthron, Semperis      Target Internal Dev Content, Sharepoint Admins, Sharepoint
                                                       Users and Sharepoint-Community in Corp Groups. Preserve
                                                       stable keys, group identities, scope, category and
                                                       membership definitions. Keep account rules, OU layouts and
                                                       paused synthetic deletion unchanged.
 2026-11-13  v1.7.29     Rob Ingenthron, Semperis      Nest root Corp Contractors and service accounts beneath
                                                       Users, and Servers beneath Computers. Preserve names,
                                                       unprotected status, department layouts, passwords and paused
                                                       synthetic OU deletion. Do not move or delete existing OUs.
 2026-11-12  v1.7.28     Rob Ingenthron, Semperis      Pause synthetic OU deletion by setting
                                                       OUforSyntheticDeletion to null. Preserve deletion function,
                                                       call site and former HR Operations path in comments for
                                                       later reuse. Keep all baseline definitions and other
                                                       synthetic activity unchanged.
 2026-11-12  v1.7.27     Rob Ingenthron, Semperis      Restructure baseline Finance, HR, IT, Marketing, Sales and
                                                       Security: place service accounts, Admins and Contractors
                                                       beneath Users, and Servers beneath Computers. Add missing IT
                                                       containers and update HR/Finance account paths. Preserve OU
                                                       names, protection, passwords and synthetic activity; no old-
                                                       OU cleanup or migration added.
 2026-11-12  v1.7.26     Rob Ingenthron, Semperis      Rename Internal Finance to Finance-internal in Corp Finance
                                                       Groups. Add HR Users Admins OU and target adm.hr there.
                                                       Target three HR computers in Corp HR Servers and three HR
                                                       service users in Corp HR service accounts. Keep stable keys,
                                                       password rules and synthetic actions unchanged; add no old-
                                                       tree cleanup.
 2026-11-12  v1.7.25     Rob Ingenthron, Semperis      Treat Admin-Tier0 as an ordinary shared-password demo user
                                                       for DSP sign-in. Exempt only this named account from the
                                                       script admin minimum; honor effective AD policy and normal
                                                       preservation/reset flags. Defer additional credential-store
                                                       options.
 2026-11-12  v1.7.24     Rob Ingenthron, Semperis      Use minimum password lengths: non-human accounts 30+, admins
                                                       20+, ordinary users follow AD. Keep admin/shared passwords
                                                       stored; preserve existing svc- passwords. Read effective
                                                       policy on the selected DC. Initialize only newly created
                                                       users before enabling. Validate shared passwords before
                                                       phase writes. Improve incomplete-account diagnostics. Leave
                                                       all FGPP definitions and assignments unchanged.
 2026-11-12  v1.7.23     Rob Ingenthron, Semperis      Add RefreshAllPasswords for the full provisioning run.
                                                       Refresh shared-password demo and special accounts from the
                                                       Windows Credential Store, overriding their preservation
                                                       flags. Exclude all random-password types. Match new-user
                                                       password rules; document scope and usage. Keep generic,
                                                       managed svc-, replication and synthetic behavior unchanged.
 2026-11-12  v1.7.22     Rob Ingenthron, Semperis      Preserve existing svc- demo-account passwords and password-
                                                       change requirements in every OU, regardless of the shared
                                                       reset flag. Generate managed passwords only at creation.
                                                       Keep Corp OU Structure creation-only behavior and unrelated
                                                       baseline, summary and synthetic operations unchanged.
 2026-11-12  v1.7.21     Rob Ingenthron, Semperis      Add twelve unprotected OUs: five service-account containers
                                                       and Finance with Users, Groups, Computers, Contractors,
                                                       service accounts and Servers. Define srv-finance-app01 in
                                                       the new Finance Servers OU without migrating the old
                                                       computer. Retarget the Finance service account; preserve its
                                                       SAM, UPN and existing password rules.
 2026-11-12  v1.7.20     Rob Ingenthron, Semperis      Add five Servers OUs under Corp and its Marketing, Sales, HR
                                                       and Security departments. Add IT under Corp with Users,
                                                       Groups, Computers and Contractors children. Disable
                                                       accidental-deletion protection on all ten definitions,
                                                       including matching existing OUs. Preserve other behavior.
 2026-11-12  v1.7.19     Rob Ingenthron, Semperis      Add 38 parent-first baseline OUs under domain-root Corp and
                                                       Guest Users. Disable accidental-deletion protection for
                                                       every new definition, including existing matching OUs.
                                                       Preserve prior definitions, summary counters and synthetic
                                                       behavior.
 2026-11-12  v1.7.18     Rob Ingenthron, Semperis      Add white, aligned baseline and synthetic processing summary
                                                       after script completion and before total elapsed time. Count
                                                       verified object actions and membership links; include
                                                       recursive OU deletion contents. Preserve AD write ordering,
                                                       replication and password behavior.
 2026-11-12  v1.7.17     Rob Ingenthron, Semperis      Correct baseline FGPP summary: assignments are not removed
                                                       until the later synthetic AD Changes phase, when enabled.
                                                       Logging only; preserve provisioning and replication
                                                       behavior.
 2026-11-12  v1.7.16     Rob Ingenthron, Semperis      Synchronize active version, help examples, startup banner
                                                       and transcript filenames to v1.7.16. Preserve historical
                                                       version entries, account data and operational behavior.
 2026-11-12  v1.7.15     Rob Ingenthron, Semperis      Correct Serge Vaudenay given name and surname.
                                                       Preserve all other attributes and baseline behavior.
 2026-11-12  v1.7.14     Rob Ingenthron, Semperis      Add six demo/admin users and nine Global Security groups.
                                                       Nest Sharepoint-Community in Sharepoint Users and Helpdesk
                                                       levels in Helpdesk-ALL. Assign adm.sjenkins to L1 and L3,
                                                       and marie.courtney to L2. Preserve supplied attributes,
                                                       shared-demo password handling and existing checkpoints.
 2026-11-12  v1.7.13     Rob Ingenthron, Semperis      Replace SYNOPSIS with the requested lab provisioning,
                                                       synthetic change activity, AD functionality note and Windows
                                                       Credential Store wording. Documentation and version metadata
                                                       only; preserve all operational behavior.
 2026-11-12  v1.7.12     Rob Ingenthron, Semperis      Remove the baseline WMI-filter forced replication checkpoint
                                                       and settling delay. Preserve filter creation, updates,
                                                       verification, completion timestamp and following GPO
                                                       processing. Leave other checkpoints and both elapsed-time
                                                       displays unchanged.
 2026-11-12  v1.7.11     Rob Ingenthron, Semperis      Display cumulative elapsed processing time after the
                                                       baseline summary timestamp and before the synthetic AD
                                                       changes banner. Match the final text, milliseconds and
                                                       White-on-DarkMagenta colors; leave the stopwatch running and
                                                       preserve the final total.
 2026-11-12  v1.7.10     Rob Ingenthron, Semperis      Remove dedicated forced replication and settling delays for
                                                       FGPPs, AD sites and subnets in baseline and synthetic
                                                       phases, including per-action waits. Retain selected-DC
                                                       verification, deletion safeguards, other checkpoints and
                                                       completion timestamps.
 2026-11-12  v1.7.9      Rob Ingenthron, Semperis      Reduce the shared post-replication pause from 9 to 5 seconds
                                                       for baseline and synthetic checkpoints, FGPP validation and
                                                       subnet settling. Update current help and timing totals;
                                                       preserve unrelated delays and account-password behavior.
 2026-11-12  v1.7.8      Rob Ingenthron, Semperis      Set Corp OU Structure user passwords only at creation;
                                                       require new accounts enabled with a 30-character random
                                                       password. Preserve existing passwords and change-at-logon
                                                       state regardless of the shared-demo reset flag, including
                                                       svc accounts in this tree. Retain svc behavior elsewhere.
 2026-11-12  v1.7.7      Rob Ingenthron, Semperis      Set fresh cryptographic 30-character passwords for baseline
                                                       users under Corp OU Structure or with svc-prefixed SAMs. Use
                                                       28 alphanumerics and two shuffled distinct symbols. Reset
                                                       existing scoped passwords before enabling accounts,
                                                       independent of the shared-demo preservation flag. Never log
                                                       generated passwords; preserve other account behavior.
 2026-11-11  v1.7.6      Rob Ingenthron, Semperis      Use one Remove-ADOrganizationalUnit -Recursive call against
                                                       the configured root OU. Subtree enumeration is read-only; no
                                                       per-child delete calls are issued. Preserve post-FGPP
                                                       placement, advisory, protection checks and verification.
                                                       Separate descendant audit events may still be generated.
 2026-11-11  v1.7.5      Rob Ingenthron, Semperis      Run configured recursive OU deletion immediately after
                                                       synthetic FGPP processing, replication and completion
                                                       output, before subnet changes. Keep the blank-setting
                                                       advisory in the same synthetic stage. Preserve deletion
                                                       safeguards, defaults and final membership ordering.
 2026-11-11  v1.7.4      Rob Ingenthron, Semperis      Add OUforSyntheticDeletion and guarded recursive OU deletion
                                                       after the OU modification extension point. Blank settings
                                                       show a white advisory. Validate subtree scope, protection
                                                       and identity; verify deletion and replicate before later
                                                       synthetic categories.
 2026-11-11  v1.7.3      Rob Ingenthron, Semperis      Add four computers and five enabled users in the HR and
                                                       Finance baseline OUs. Use svc-finance-common01 for the
                                                       Finance service logon while retaining the requested object
                                                       name. Reuse existing demo password and reconciliation logic;
                                                       no groups or memberships added.
 2026-11-11  v1.7.2      Rob Ingenthron, Semperis      Define Finance directly beneath Operational and its servers,
                                                       service accounts and Finance Admins beneath Finance.
                                                       Preserve descriptions and disabled deletion protection. No
                                                       migration or deletion actions are added.
 2026-11-11  v1.7.1      Rob Ingenthron, Semperis      Extend HR Operations with servers, service accounts, HR
                                                       Admins and Finance. Add servers, service accounts and
                                                       Finance Admins beneath Finance. Disable deletion protection
                                                       on all seven added OUs; keep unspecified descriptions blank.
 2026-11-11  v1.7.0      Rob Ingenthron, Semperis      Add Corp OU Structure, Operational, HR Operations and
                                                       Applications baseline OUs with exact descriptions. Manage
                                                       optional accidental-deletion protection on creation and
                                                       reruns; leave protection on older definitions unchanged.
 2026-11-11  v1.6.11     Rob Ingenthron, Semperis      Expand native security policy verification details into
                                                       aligned continuation lines, two spaces right of Verified.
                                                       Preserve punctuation, values, colors and verification logic.
 2026-11-11  v1.6.10     Rob Ingenthron, Semperis      Indent final post-replication membership verification four
                                                       spaces and align its trailing caveats on a new line.
                                                       Preserve verification, colors and terminal write ordering.
 2026-11-11  v1.6.9      Rob Ingenthron, Semperis      Place link-configuration disclaimers on aligned continuation
                                                       lines in GPO results and success/skip summaries. Preserve
                                                       message wording, colors and operational behavior.
 2026-11-11  v1.6.8      Rob Ingenthron, Semperis      Wrap audit.csv verification disclaimer onto a continuation
                                                       line aligned with Verified, without a repeated SUCCESS
                                                       prefix. Preserve colors and operational behavior.
 2026-11-11  v1.6.7      Rob Ingenthron, Semperis      Wrap DNS zone results and GPO writer guidance onto aligned
                                                       continuation lines without repeated status prefixes.
                                                       Preserve colors and operational behavior.
 2026-11-11  v1.6.6      Rob Ingenthron, Semperis      Use one repadmin /syncall /A invocation for synthetic DNS,
                                                       then one existing settling pause. Keep baseline partition
                                                       syncs and section timestamps unchanged.
 2026-11-09  v1.6.5      Rob Ingenthron, Semperis      Add Magenta section completion timestamps in baseline and
                                                       synthetic phases, including post-replication markers.
                                                       Preserve existing actions, waits and terminal mutation
                                                       order.
 2026-11-09  v1.6.4      Rob Ingenthron, Semperis      Add repeatable synthetic DNS A deletion, TTL/address changes
                                                       and demo-user node Read/Write ACLs. Reset baseline TTLs and
                                                       ACLs; update PTRs best-effort; add one DNS checkpoint.
 2026-11-09  v1.6.3      Rob Ingenthron, Semperis      Indent the DNS baseline summary by two spaces using
                                                       IndentLevel 1. Preserve warning colors and message text.
 2026-11-09  v1.6.2      Rob Ingenthron, Semperis      Use standard yellow foreground without a background for
                                                       associated-PTR warnings. Preserve critical highlighting and
                                                       four-space warning indentation.
 2026-11-09  v1.6.1      Rob Ingenthron, Semperis      Add the supplied Semperis disclaimer after .DESCRIPTION,
                                                       with its exact wording and a trailing blank line.
 2026-11-09  v1.6.0      Rob Ingenthron, Semperis      Add editable baseline DNS zones, static A records and
                                                       independent best-effort PTR reconciliation. Verify
                                                       forest-wide zones and current-domain host records;
                                                       add a DNS-aware replication checkpoint and summary.
 2026-11-09  v1.5.9      Rob Ingenthron, Semperis      Warn and continue without Enterprise Admins membership.
                                                       Keep the white notice unchanged; explicitly report
                                                       missing Domain Admins as a graceful preflight stop.
 2026-11-09  v1.5.8      Rob Ingenthron, Semperis      Refine startup spacing and group elevation under
                                                       operator rights. Report Enterprise Admins as success;
                                                       add a white notice and aligned least-privilege advice.
 2026-11-09  v1.5.7      Rob Ingenthron, Semperis      Show elapsed processing time white on DarkMagenta.
                                                       Frame the synthetic AD changes heading with matching
                                                       asterisk separators; keep operational logic unchanged.
 2026-11-09  v1.5.6      Rob Ingenthron, Semperis      Pause once for 10 seconds after all disk-space output
                                                       when any checked local or DSP disk has less than 2 GB
                                                       free. Keep the pause outside AD-processing timing.
 2026-11-09  v1.5.5      Rob Ingenthron, Semperis      Reflow site-link notification details and DSP connection
                                                       text into aligned, unprefixed continuation lines. Keep
                                                       notification checks and remote disk behavior unchanged.
 2026-11-08  v1.5.4      Rob Ingenthron, Semperis      Highlight Available text yellow on red below 2 GB for
                                                       local and DSP disks. Put the SCP registration caveat on
                                                       its own line aligned with DSP; retain connection logic.
 2026-11-08  v1.5.3      Rob Ingenthron, Semperis      Enable short best-effort DSP disk checks using current
                                                       Windows credentials. Probe WSMan and DCOM endpoints;
                                                       query fixed disks over a usable connection or skip.
                                                       Bound all attempts per host; never change remote access.
 2026-11-08  v1.5.2      Rob Ingenthron, Semperis      Make DSP disk checks opt-in, disabled by default. Skip
                                                       SCP discovery and remote inventory when disabled; retain
                                                       local disk checks. Do not alter remote-access settings.
 2026-11-08  v1.5.1      Rob Ingenthron, Semperis      Capture credential API errors inside managed wrappers so
                                                       missing keys prompt for and save a new demo password.
                                                       Keep the new namespace; do not migrate or read old keys.
                                                       Preserve genuine-error stops and secure secret cleanup.
 2026-11-08  v1.5.0      Rob Ingenthron, Semperis      Rename script to Invoke-ADContentGenerator and update
                                                       active version, help, startup and transcript references.
                                                       Replace banner exactly; preserve white foreground and
                                                       one blank line. Rename the stable credential namespace.
 2026-11-08  v1.4.6      Rob Ingenthron, Semperis      Add alignment-preserving ASCII startup banner in white
                                                       with no explicit background. Print one blank line before
                                                       the Starting section header; preserve existing behavior.
 2026-11-08  v1.4.5      Rob Ingenthron, Semperis      Discover DSP management hosts from forest AD SCPs using
                                                       verified names and role keywords. Remove manual host list.
                                                       Bound discovery wait; warn on missing, unreadable or stale
                                                       registrations. Preserve nonblocking disk checks.
 2026-11-08  v1.4.4      Rob Ingenthron, Semperis      Add editable DSP server names and current-identity remote
                                                       disk inventory with per-server timeout. Warn and continue on
                                                       denied access, offline hosts or unknown space. Preserve
                                                       local checks; never prompt for extra credentials.
 2026-11-08  v1.4.3      Rob Ingenthron, Semperis      Display local fixed-drive total and free space before
                                                       baseline writes. Warn yellow on red at 1 GB free or less;
                                                       inventory failures warn without stopping. Exclude other
                                                       computers and credential-only runs.
 2026-11-08  v1.4.2      Rob Ingenthron, Semperis      Check/import AD, GroupPolicy and DNS modules before prompts,
                                                       after rights validation. Check client DNS RSAT capability or
                                                       server feature without installation. Warn yellow on red;
                                                       gracefully stop for mandatory AD and preserve required GPO
                                                       preflight.
 2026-11-08  v1.4.1      Rob Ingenthron, Semperis      After terminal direct-user removal, add verified Vladimir
                                                       Levin as the only direct user. Preflight his baseline GUID
                                                       before removals; verify final membership before and after
                                                       replication. Preserve non-user members and last-write
                                                       ordering.
 2026-11-08  v1.4.0      Rob Ingenthron, Semperis      Run Helpdesk Ops direct-user removal as the terminal
                                                       synthetic stage after every extensible category. Verify by
                                                       baseline GUID; preserve non-user members and add offline
                                                       regression coverage. DSP order is not guaranteed.
 2026-11-08  v1.3.32     Rob Ingenthron, Semperis      Document verified WMI filter Name and ObjectGUID references
                                                       beside editable definitions. Explain stable keys, map
                                                       availability and GUID refresh; preserve runtime behavior.
 2026-11-08  v1.3.31     Rob Ingenthron, Semperis      Add thirty keyed WMI filter baselines before GPOs, with
                                                       preflight, drift repair, query encoding, author reset and
                                                       GUID references. Preserve IDs and links; verify on the
                                                       selected DC. Correct malformed sample WQL. Add one domain
                                                       replication checkpoint.
 2026-11-08  v1.3.30     Rob Ingenthron, Semperis      Start processing timing after prompts and site discovery,
                                                       immediately before OU provisioning. Guard timer cleanup and
                                                       suppress elapsed output when processing never starts.
 2026-11-08  v1.3.29     Rob Ingenthron, Semperis      Report total elapsed processing time with a Stopwatch around
                                                       Invoke-Main. Exclude transcript startup/shutdown and retain
                                                       final timing on success, early returns and errors.
 2026-11-08  v1.3.28     Rob Ingenthron, Semperis      Set CIS GPO Security Event Log baseline to 1024 MB and
                                                       synthetic size to the supported minimum 20 MB. Preserve
                                                       unlinked safeguards, writers, backups and replication waits.
 2026-11-08  v1.3.27     Rob Ingenthron, Semperis      Use PauseTimeSeconds for FGPP post-removal and subnet pre-
                                                       deletion waits. Remove per-policy timing and retain
                                                       replication ordering, identity checks and batch checkpoints.
 2026-11-08  v1.3.26     Rob Ingenthron, Semperis      Add PauseTimeSeconds=9 in DEFAULTS and use it for every
                                                       standard post-replication batch wait. Display the configured
                                                       duration in pause/completion messages. Preserve
                                                       action-specific waits and replication behavior.
 2026-11-08  v1.3.25     Rob Ingenthron, Semperis      Standardize synthetic object-type batch checkpoints with
                                                       forced replication and nine-second waits. Share the baseline
                                                       engine, select the correct partition and preserve existing
                                                       action-specific waits, safeguards and policy values.
 2026-11-08  v1.3.24     Rob Ingenthron, Semperis      Move all baseline GPO processing after the OU checkpoint.
                                                       Keep result caching and the nine-second GPO checkpoint with
                                                       the earlier batch. Preserve policy values and synthetic
                                                       changes.
 2026-11-08  v1.3.23     Rob Ingenthron, Semperis      Add one forced AD replication checkpoint and nine-second
                                                       pause after each baseline object-type batch. Use
                                                       Configuration for sites/subnets; preserve synthetic changes,
                                                       policy values and output styling.
 2026-11-07  v1.3.22     Rob Ingenthron, Semperis      Set Questionable GPO baseline lockout threshold to 10.
                                                       Add synthetic threshold=100, NTLM level=5 and reversible
                                                       encryption=0 using native policy and report verification.
 2026-11-07  v1.3.21     Rob Ingenthron, Semperis      Add synthetic CIS GPO security changes: forceguest=1,
                                                       LmCompatibilityLevel=4 and NoLMHash=0. Preserve baseline,
                                                       linked-update safeguards, backups and GUID verification.
 2026-11-07  v1.3.20     Rob Ingenthron, Semperis      Highlight linked-GPO policy-skip warnings in Yellow on
                                                       DarkRed, including skipped summaries. Preserve other colors,
                                                       indentation and graceful continuation behavior.
 2026-11-07  v1.3.19     Rob Ingenthron, Semperis      Permit linked updates for Questionable GPO. Warn and skip
                                                       link-policy refusals; retain fatal handling for real errors
                                                       and report skipped or partial results truthfully.
 2026-11-07  v1.3.18     Rob Ingenthron, Semperis      Rename linked-update flag to ApplyWhenLinked. CIS and
                                                       Questionable default False; DSP auditing defaults True.
                                                       Preserve guards, backups, verification and existing links.
 2026-11-07  v1.3.17     Rob Ingenthron, Semperis      Add INFO headings before each implemented synthetic change
                                                       category; retain silent placeholders for future categories.
 2026-11-07  v1.3.16     Rob Ingenthron, Semperis      Rename synthetic AD Changes heading to change activity.
 2026-11-07  v1.3.15     Rob Ingenthron, Semperis      Add unlinked Computer-only DSP example auditing GPO with
                                                       comment, native audit CSV subcategories, override Security
                                                       Option, backups and metadata verification.
 2026-11-07  v1.3.14     Rob Ingenthron, Semperis      Remove and verify the temporary FGPP assignment first, then
                                                       force replication and wait ten seconds for settling.
                                                       Preserve policy objects and verify post-wait state.
 2026-11-07  v1.3.13     Rob Ingenthron, Semperis      Move temporary FGPP assignment replication, wait and removal
                                                       into synthetic AD Changes. Keep baseline assignments when
                                                       disabled; preserve FGPP objects and verify cached
                                                       identities.
 2026-11-07  v1.3.12     Rob Ingenthron, Semperis      Render all native replication sync/callback messages in Gray
                                                       with no explicit background, INFO prefixes and four-space
                                                       indentation. Preserve replication and pause behavior.
 2026-11-07  v1.3.11     Rob Ingenthron, Semperis      Force Configuration-partition replication after verified
                                                       subnet description changes and before the two-second
                                                       deletion pause. Stop before pause/delete on failure.
 2026-11-07  v1.3.10     Rob Ingenthron, Semperis      Pause two seconds before synthetic subnet deletion and
                                                       revalidate afterward. Report read-only per-IP-site-link
                                                       change notification flags during domain discovery.
 2026-11-07  v1.3.9      Rob Ingenthron, Semperis      Label synthetic change subsections by object type. Change
                                                       and verify 111.111.4.0/24 Description without deletion;
                                                       preserve the existing 111.111.5.0/24 sequence.
 2026-11-07  v1.3.8      Rob Ingenthron, Semperis      Reformat DESCRIPTION and NOTES into related, readable
                                                       paragraphs. Preserve help wording and script behavior.
 2026-11-07  v1.3.7      Rob Ingenthron, Semperis      Clarify Windows Update and SMBv1 client dependency warnings.
                                                       Preserve all policy values and execution behavior.
 2026-11-07  v1.3.6      Rob Ingenthron, Semperis      Log OU lookup/create failures and continue without ACL
                                                       changes. Skip computers targeting unavailable OUs or
                                                       containers; continue accessible computer provisioning.
                                                       Report skipped definitions without claiming verification.
 2026-11-07  v1.3.5      Rob Ingenthron, Semperis      Create every defined computer enabled and restore enabled
                                                       state on later runs. Verify enabled state before publishing
                                                       object references. Document the keyed GUID example beside
                                                       the editable computer definitions.
 2026-11-07  v1.3.4      Rob Ingenthron, Semperis      Add six keyed computer definitions and verified baseline
                                                       provisioning before AD Changes. Reconcile names, paths and
                                                       attributes; normalize computer SAM suffixes. Stage new
                                                       accounts disabled and preserve existing account state.
 2026-11-07  v1.3.3      Rob Ingenthron, Semperis      Add domain-root zSpecial OU with managed description and
                                                       display name. Retain SAM name as metadata and document the
                                                       future restrictive ACL without applying it.
 2026-11-07  v1.3.2      Rob Ingenthron, Semperis      Provision and verify SemperisLabs site before its linked
                                                       10.3.22.0/24 subnet. Restore changed display name,
                                                       description, location and subnet linkage. Keep SAM name as
                                                       metadata; preserve existing synthetic AD changes.
 2026-11-06  v1.3.1      Rob Ingenthron, Semperis      Add gated subnet AD changes: validate 111.111.5.0/24, set
                                                       and verify its description, then delete without confirmation
                                                       and verify absence. Recheck identity before deletion;
                                                       preserve 111.111.4.0/24 and baseline provisioning.
 2026-11-06  v1.3.0      Rob Ingenthron, Semperis      Start 1.3.x with MakeADChanges default True and a gated
                                                       post-provisioning AD Changes scaffold for synthetic audit
                                                       activity. False skips that phase; no mutations are defined
                                                       yet. Preserve provisioning and GPO summary formatting.
 2026-11-06  v1.2.2      Rob Ingenthron, Semperis      Split GPO success summaries after the GPO name colon. Put
                                                       all details on a continuation line two spaces beyond the
                                                       message text. Preserve summary values and temporary FGPP
                                                       replication, wait and removal behavior.
 2026-11-06  v1.2.1      Rob Ingenthron, Semperis      Temporarily assign service FGPP to Tier1 Operators, force
                                                       selected-DC replication, wait 10 seconds, then remove and
                                                       verify the assignment. Keep test FGPP unassigned; preserve
                                                       policies and existing GPO replication.
 2026-11-06  v1.2.0      Rob Ingenthron, Semperis      Start 1.2.x with editable FGPP definitions and verified
                                                       create/update logic. Assign service policy to Tier1
                                                       Operators; keep the 32-character test policy unassigned.
                                                       Reuse selected DC; preserve optional existing settings.
 2026-11-06  v1.1.26     Rob Ingenthron, Semperis      Add per-account SpecialAcctPasswordReset: automation False,
                                                       monitoring True. Preserve the global password-preservation
                                                       override and new-account initialization; validate Boolean
                                                       flags and align read-back with the reset decision.
 2026-11-06  v1.1.25     Rob Ingenthron, Semperis      Set replication pause message to Gray foreground with
                                                       DarkGreen background. Preserve exact text, two-space indent,
                                                       eight-second sleep and blank-output handling.
 2026-11-06  v1.1.24     Rob Ingenthron, Semperis      Skip empty and whitespace-only repadmin output before
                                                       formatting. Preserve selected-DC replication, native exit-
                                                       code checks and the magenta eight-second pause; add blank-
                                                       output regression scenarios.
 2026-11-06  v1.1.23     Rob Ingenthron, Semperis      After all GPOs succeed, force domain AD replication from the
                                                       selected DC using repadmin /syncall. Print a two-space
                                                       magenta pause message and sleep 8 seconds; check the exit
                                                       code without claiming SYSVOL convergence.
 2026-11-06  v1.1.22     Rob Ingenthron, Semperis      Add per-GPO UpdateEvenIfLinked: Questionable defaults to
                                                       True, CIS benchmark to False. Guard linked updates before
                                                       writes and during native/registry verification; preserve
                                                       link configuration.
 2026-11-06  v1.1.21     Rob Ingenthron, Semperis      Reconcile linked or unlinked lab GPOs without changing
                                                       links. Replace link-only aborts with impact warnings and
                                                       report final link counts; retain backup and content
                                                       verification.
 2026-11-06  v1.1.20     Rob Ingenthron, Semperis      Explicitly set LDAP server signing to None in Questionable
                                                       GPO using native DWORD one. Preserve unlinked-only checks
                                                       and leave Server 2025 enforcement policy unmanaged.
 2026-11-06  v1.1.19     Rob Ingenthron, Semperis      Add two Disabled Administrative Templates policies to
                                                       Questionable GPO. Preserve native security settings and use
                                                       existing registry-policy read-back verification.
 2026-11-06  v1.1.18     Rob Ingenthron, Semperis      Add unlinked Questionable GPO with native NTLM, Kerberos and
                                                       reversible-password policies. Verify native account report
                                                       values and preserve the original GPO baseline.
 2026-11-06  v1.1.17     Rob Ingenthron, Semperis      Add short Bowser, MRxSmb20 and NSI explanations beside the
                                                       editable dependency array. Preserve all values and behavior.
 2026-11-06  v1.1.16     Rob Ingenthron, Semperis      Split initial GPO definition notes into readable paragraphs
                                                       and add blank spacing after notes/references. Formatting
                                                       only; preserve all settings and provisioning behavior.
 2026-11-06  v1.1.15     Rob Ingenthron, Semperis      Document all GPO value choices, ranges and dependency
                                                       examples beside editable values. Clarify unconfigured state
                                                       and security caveats; preserve settings and execution.
 2026-11-06  v1.1.14     Rob Ingenthron, Semperis      Add SMBv1 client/server disablement and client dependency
                                                       policy. Support verified registry MultiString values; retain
                                                       native NTLMv2-only policy and add offline tests.
 2026-11-06  v1.1.13     Rob Ingenthron, Semperis      Handle GroupPolicy keyPath not-found errors after legacy
                                                       Registry.pol removal. Preserve strict failure handling and
                                                       add offline mocked registry-read regression tests.
 2026-11-06  v1.1.12     Rob Ingenthron, Semperis      Allow blank INI lines in native Security Options helpers.
                                                       Preserve trailing newlines and add offline regression tests.
 2026-11-06  v1.1.11     Rob Ingenthron, Semperis      Split native Security Options from registry policy. Added
                                                       GPO backup, INF merge, CSE/version updates, native report
                                                       verification and managed legacy-entry migration.
 2026-11-06  v1.1.10     Rob Ingenthron, Semperis      Added editable GPO editor paths and display names with
                                                       unknown fallbacks; renamed value type/data output labels.
                                                       Preserved Gray detail color and registry-only behavior.
 2026-11-06  v1.1.9      Rob Ingenthron, Semperis      Changed GPO checking continuation lines to Gray foreground;
                                                       preserved key-line color, indentation and registry behavior.
 2026-11-06  v1.1.8      Rob Ingenthron, Semperis      Added one space to all GPO checking continuation lines; left
                                                       registry-key lines and provisioning behavior unchanged.
 2026-11-06  v1.1.7      Rob Ingenthron, Semperis      Split GPO checking output into key, value name, desired type
                                                       and desired data lines; preserved registry behavior.
 2026-11-06  v1.1.6      Rob Ingenthron, Semperis      Fixed strict-mode GPO reads of child-key records without
                                                       HasValue; validate value metadata before reading payloads.
 2026-11-06  v1.1.5      Rob Ingenthron, Semperis      Fixed missing GPO value reads by enumerating key values;
                                                       clarified separate Key, ValueName, type and data in output.
 2026-11-06  v1.1.4      Rob Ingenthron, Semperis      Added editable unlinked GPO initialization and seven DWORD
                                                       settings; GET before SET, old/new output, read-back checks
                                                       and supplied comments.
 2026-11-06  v1.1.3      Rob Ingenthron, Semperis      Clarified the AD-site lookup warning with continuation and
                                                       unlinked-subnet details; retained four-space warning
                                                       indentation.
 2026-11-06  v1.1.2      Rob Ingenthron, Semperis      Changed operator-site discovery failure to warn and continue
                                                       creating/updating both test subnets unlinked; removed skip
                                                       counts.
 2026-11-06  v1.1.1      Rob Ingenthron, Semperis      Added two test subnets linked to the operator computer AD
                                                       site in $MyADSite; failed discovery skips both safely.
 2026-11-06  v1.1.0      Rob Ingenthron, Semperis      Started 1.1.x with editable AD subnet definitions and
                                                       create/update verification; optional blanks clear, omissions
                                                       preserve, missing named sites warn and skip.
 2026-11-06  v1.0.42     Rob Ingenthron, Semperis      Split NOTES into topic-based paragraphs for readability;
                                                       preserved wording and all script behavior.
 2026-11-06  v1.0.41     Rob Ingenthron, Semperis      Added DoNotUpdateSpecialDomainAcctPasswords, default false;
                                                       optionally preserve existing special-account passwords.
 2026-11-06  v1.0.40     Rob Ingenthron, Semperis      Added DoNotUpdateDemoUsersPasswords defaulting to true;
                                                       preserve existing demo passwords unless reset mode is
                                                       enabled.
 2026-11-06  v1.0.39     Rob Ingenthron, Semperis      Indented generic-user verification SUCCESS messages eight
                                                       spaces, beneath their six-space action INFO messages.
 2026-11-06  v1.0.38     Rob Ingenthron, Semperis      Split DESCRIPTION into topic-based paragraphs for
                                                       readability; preserved all wording and script behavior.
 2026-11-06  v1.0.37     Rob Ingenthron, Semperis      Added DoNotUpdateGenericUsers defaulting to true; create
                                                       missing users only, or set false to reconcile existing
                                                       users.
 2026-11-06  v1.0.36     Rob Ingenthron, Semperis      Replaced generic-user batching with a bounded per-account
                                                       lookup, create/update and immediate verification loop.
 2026-11-06  v1.0.35     Rob Ingenthron, Semperis      Limited TEST OU verification to selected account GUIDs in
                                                       bounded LDAP filters; no unrelated or above-count user
                                                       reads.
 2026-11-06  v1.0.34     Rob Ingenthron, Semperis      Grouped generic-user checking and verified output per user
                                                       after the paged read-back; retained lookup diagnostics.
 2026-11-06  v1.0.33     Rob Ingenthron, Semperis      Added indented lookup phase messages, elapsed search times
                                                       and returned-object counts for generic-user diagnostics.
 2026-11-06  v1.0.32     Rob Ingenthron, Semperis      Removed the generic-user profile-restoration INFO line;
                                                       retained profile updates, checking output and verification.
 2026-11-06  v1.0.31     Rob Ingenthron, Semperis      Replaced per-user generic-account read-backs with paged
                                                       batch verification by object GUID; retained profile checks,
                                                       creation/update behavior and named-account failures.
 2026-11-06  v1.0.30     Rob Ingenthron, Semperis      Added timed generic-user count input, six-digit TEST OU
                                                       accounts and cryptographic 20-character passwords; skip
                                                       unavailable TEST and preserve existing passwords/users.
 2026-11-06  v1.0.29     Rob Ingenthron, Semperis      Added editable NetBIOS-prefixed special accounts with
                                                       suffix-preserving SAM limits, OU/profile reconciliation and
                                                       credential-store password resets.
 2026-11-06  v1.0.28     Rob Ingenthron, Semperis      Added AdmUser4 (adm.robi) with supplied baseline attributes
                                                       in the Tier 0 OU; retained existing group memberships.
 2026-11-06  v1.0.27     Rob Ingenthron, Semperis      Aligned function summaries and script completion flush-left;
                                                       styled provisioning summary white on gray.
 2026-11-06  v1.0.26     Rob Ingenthron, Semperis      Indented demo password-reset SUCCESS output four more
                                                       spaces, beneath its preceding action INFO message.
 2026-11-06  v1.0.25     Rob Ingenthron, Semperis      Indented group member details beneath checks and membership
                                                       action SUCCESS results beneath action INFO messages.
 2026-11-06  v1.0.24     Rob Ingenthron, Semperis      Renamed membership settings and definitions getters to
                                                       GroupUserMembership names; updated all references.
 2026-11-05  v1.0.23     Rob Ingenthron, Semperis      Added ordered direct group memberships with additive/exact
                                                       modes, protected required nesting and named lookup errors.
 2026-11-05  v1.0.22     Rob Ingenthron, Semperis      Added Tier1 Operators in Tier 1, required nesting in Special
                                                       Admin Group, and existing-only group references.
 2026-11-03  v1.0.21     Rob Ingenthron, Semperis      Indented action INFO messages two additional spaces;
                                                       preserved detail, result and error indentation.
 2026-11-03  v1.0.20     Rob Ingenthron, Semperis      Added 18 editable demo-user baselines with profile
                                                       reconciliation, enabled accounts and per-run password reset.
 2026-11-03  v1.0.19     Rob Ingenthron, Semperis      Added Special Admin Group in Tier 0 and nested it in Domain
                                                       Admins, resolved by domain SID and RID 512.
 2026-11-02  v1.0.18     Rob Ingenthron, Semperis      Nested Helpdesk Ops in Remote Desktop Users via SID; set its
                                                       SAM account name to HelodeskOps.
 2026-11-02  v1.0.17     Rob Ingenthron, Semperis      Moved .VERSION_HISTORY after .DESCRIPTION and .NOTES, before
                                                       .PARAMETERS and .EXAMPLES.
 2026-11-02  v1.0.16     Rob Ingenthron, Semperis      Updated 'Bad OU' description to 'An OU that may have some
                                                       issues'.
 2026-11-01  v1.0.15     Rob Ingenthron, Semperis      Centralized editable lab definitions after DEFAULTS; kept
                                                       provisioning separate from desired data.
 2026-11-01  v1.0.14     Rob Ingenthron, Semperis      Added explicit group-definition instructions for missing
                                                       nesting groups.
 2026-11-01  v1.0.13     Rob Ingenthron, Semperis      Added editable group nesting with intentional self-
                                                       membership and direct-link verification.
 2026-11-01  v1.0.12     Rob Ingenthron, Semperis      Added newest-first revision history with fixed-width columns
                                                       and wrapped descriptions.
 2026-11-01  v1.0.11     Rob Ingenthron, Semperis      Added group creation function for group validation and
                                                       updates.

.PARAMETERS
.PARAMETER Help
    Displays the current script filename, synopsis, description, parameters
    and examples, then returns without running the provisioning workflow.
    Omits operational notes and version history. Requires no AD modules,
    domain connection, credential prompts or elevated rights. Cannot combine
    with ClearStoredCreds, RefreshAllPasswords or RemoveAllGeneratedContent.

.PARAMETER ClearStoredCreds
    Clears this script's shared DEMO and dedicated Tier0Admin passwords from
    the current Windows user's Credential Store for the discovered domain,
    then exits without password prompts or provisioning.
    This option does not require Administrator or Domain Admins membership, but
    it does require the ActiveDirectory module and domain connectivity so the
    script can identify its credential entry.

.PARAMETER RemoveAllGeneratedContent
    Runs cleanup ONLY; cannot combine with Help, ClearStoredCreds or
    RefreshAllPasswords. Requires elevated Administrator, Domain Admins and
    Enterprise Admins in the current logon token. Missing rights stop before
    confirmation. Confirm REMOVE ALL within 15 seconds; default/timeout is cancel.

    Reads the current-directory <actual-script-basename>.JSON inventory.
    Capture THIS invocation's MyInvocation.MyCommand.Path at script entry.
    Prefer the final symbolic-link target basename when resolution succeeds;
    otherwise use the original runtime basename. Never search the directory.
    Provisioning and removal use the same resolved-or-runtime identity.
    Script/schema versions and saved catalog labels do not gate cleanup.
    Requires matching script basename and domain identity, plus an Objects
    array. Never overwrites it during removal, permitting repeated cleanup
    and retries after partial failures. Unknown/malformed saved entries are
    skipped with warnings while other usable entries continue; skips are
    included in the results report and prevent a clean success status.
    Keep this file trusted and protected from unauthorized changes: it is the
    cleanup authority, not a cryptographically signed ownership attestation.
    Missing, locked, malformed or mismatched inventory stops safely.

    EVERY baseline definition is a cleanup selector, including targets absent
    when the inventory was written. Re-resolve all current baseline settings
    before confirmation and union them with saved GUID/exact-DNS identities.
    Generic users cover the full configured range plus existing higher-numbered
    managed SAMs, independent of the selected creation count. Catalog entries
    remain even when absent. Synthetic DNS variants and configured WMI aliases
    are best effort; unknown historical WMI renames can remain.

    Built-in/critical objects, default GPOs, main AD DNS zones and entries in
    Get-LabExistingGroupDefinitions remain excluded. Memberships/nesting, GPO
    settings and FGPP subjects are relationships, not new deletion targets.
    A normal run overwrites the inventory using CURRENT baseline definitions;
    historical definitions no longer configured are not reconstructed. Retain
    trusted inventories/aliases if needed. Existing JSON is used best effort
    based on its actual fields and identities, regardless of version labels.
    Saved catalogs and correlation RunId are optional; current baseline
    catalogs are rebuilt in memory. Do not regenerate content merely to
    refresh an inventory version. Missing ownership identity still stops
    cleanup safely; version independence does not authorize name-only deletion.

    Approved containers include ALL descendants, including unrecorded content.
    DNS A/PTR cleanup outside approved zones uses exact owner/type/data and
    directory GUIDs; records have no independent immutable per-record GUID.
    Ambiguous/unresolved identities are skipped with warnings, not name-only
    deletion. Computers and WMI filters are included. A post-removal rescan
    checks remaining baseline/synthetic selectors and saved GUIDs. Separate
    <basename>.RemovalResults.<timestamp>.<unique>.JSON reports residuals and
    unresolved failures; source inventory stays unchanged for retries.
    Verification is on the selected DC, not replicated forest convergence.
    Requires installed AD/CIM tools and, when needed, GroupPolicy/DnsServer;
    removal never installs prerequisites or forces replication.

.PARAMETER RefreshAllPasswords
    Runs the full workflow and refreshes only allowlisted shared-password
    demo users from the DEMO entry and Tier0Admin from its dedicated entry
    in the current domain's Windows Credential Store. Overrides preservation
    only for these collected-password accounts. All random
    account types (regular, admin, service, special and generic) are excluded.
    Effective AD requirements still apply. This is not a domain-wide reset.
    Cannot combine with ClearStoredCreds, which clears the credential and exits.

.EXAMPLES
.EXAMPLE
    .\Invoke-ADContentGenerator-v1_8_22.ps1 -RemoveAllGeneratedContent
    From the SAME current directory used for provisioning, load
    Invoke-ADContentGenerator-v1_8_22.JSON and run only cleanup after strict
    rights checks and explicit confirmation within 15 seconds. Timeout or
    default selection cancels. Generated OUs, sites and DNS zones include all
    descendants. Keep the inventory for retries and review the transcript.

.EXAMPLE
    .\Invoke-ADContentGenerator-v1_8_22.ps1 -Help
    Display selected help sections without starting the lab workflow.

.EXAMPLE
    .\Invoke-ADContentGenerator-v1_8_22.ps1
    Run lab provisioning from an elevated Windows PowerShell session.

.EXAMPLE
    .\Invoke-ADContentGenerator-v1_8_22.ps1 -ClearStoredCreds
    Clear this Windows user's DEMO and Tier0Admin entries for the domain.

.EXAMPLE
    .\Invoke-ADContentGenerator-v1_8_22.ps1 -RefreshAllPasswords
    Run the entire script and refresh the stored-password user accounts.
    This option only refreshes accounts whose original password was NOT
    randomly generated, for example the explicitly allowlisted shared-password
    demo users. Special accounts now have random passwords and are excluded. Generic users, managed svc- users, and other
    random-password accounts are excluded. Uses the same password-setting
    criteria as a NEW user of each type and the Windows Credential Store
    password; normal preservation flags are overridden for eligible users.
#>
#Requires -Version 5.1

[CmdletBinding(DefaultParameterSetName = 'Provision')]
param(
    [Parameter(ParameterSetName = 'Help', HelpMessage = 'Display selected help sections without running the workflow.')]
    [switch]$Help,
    [Parameter(ParameterSetName = 'ClearStoredCreds', HelpMessage = 'Clear the stored credential for this script and current domain, then exit.')]
    [switch]$ClearStoredCreds,
    [Parameter(ParameterSetName = 'Provision', HelpMessage = 'Run the full script and refresh shared-password users; exclude all randomly generated password types.')]
    [switch]$RefreshAllPasswords,
    [Parameter(Mandatory = $true, ParameterSetName = 'RemoveGenerated', HelpMessage = 'Remove only recorded generated content, after strict rights checks and timed confirmation; do not provision.')]
    [switch]$RemoveAllGeneratedContent
)

# Capture THIS invocation's own saved PS1 path at script entry.
# MyInvocation.MyCommand is the command being executed, not the caller.
# Never use MyInvocation.ScriptName, an editor's active tab, directory
# enumeration, a caller's path, or a previously retained automatic variable.
# Reset retained state before validating so an unsupported selected-text run
# cannot silently reuse a filename from an earlier invocation in this session.
$script:LabExecutingScriptPath = $null
$script:LabExecutingScriptFile = $null
$script:LabExecutingInventoryFile = $null
if ($null -eq $MyInvocation.MyCommand -or
    $MyInvocation.MyCommand -isnot [System.Management.Automation.ExternalScriptInfo]) {
    Write-Error 'Cannot identify this saved script. Run the complete saved .ps1 file (F5 in PowerShell ISE or invoke its full path). Do not run selected text or use Invoke-Expression. No filename will be guessed.'
    return
}
$script:LabExecutingScriptPath = [string]$MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($script:LabExecutingScriptPath) -or
    -not [IO.Path]::IsPathRooted($script:LabExecutingScriptPath) -or
    [IO.Path]::GetExtension($script:LabExecutingScriptPath) -ine '.ps1') {
    Write-Error 'This invocation did not provide its own full saved .ps1 path. No filename will be guessed; no provisioning or cleanup was started.'
    return
}
# Prefer the final file behind a symbolic launch link. Inspect ONLY this
# invocation's path; never search neighboring files or execute the target.
# Resolve relative targets against EACH link's directory, not the CWD.
# Commit the resolved identity only after the entire chain succeeds. Missing
# metadata, access failures, broken links, cycles or excessive depth retain
# the original runtime identity for both inventory naming and metadata.
$labRuntimeScriptPath = $script:LabExecutingScriptPath
try {
    $labCandidatePath = $labRuntimeScriptPath
    $labVisitedLinkPaths = @{}
    $labLinkResolutionComplete = $false
    for ($labLinkDepth = 0; $labLinkDepth -lt 32; $labLinkDepth++) {
        $labCandidatePath = [IO.Path]::GetFullPath($labCandidatePath)
        if ($labVisitedLinkPaths.ContainsKey($labCandidatePath)) {
            throw 'A cycle was found in the script symbolic-link chain.'
        }
        $labVisitedLinkPaths[$labCandidatePath] = $true
        $labScriptItem = Get-Item -LiteralPath $labCandidatePath -Force -ErrorAction Stop
        if ($labScriptItem.PSProvider.Name -ne 'FileSystem' -or $labScriptItem.PSIsContainer) {
            throw 'The script symbolic-link target is not a filesystem file.'
        }
        $labLinkTypeProperty = $labScriptItem.PSObject.Properties['LinkType']
        if ($null -eq $labLinkTypeProperty) {
            throw 'The filesystem provider did not supply link-type metadata.'
        }
        if ([string]$labLinkTypeProperty.Value -ine 'SymbolicLink') {
            # Unknown reparse-point types cannot establish a final identity.
            if (($labScriptItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'The script uses an unsupported reparse-point type.'
            }
            if ([IO.Path]::GetExtension($labCandidatePath) -ine '.ps1') {
                throw 'The resolved script target is not a PS1 file.'
            }
            $labLinkResolutionComplete = $true
            break
        }
        $labTargetProperty = $labScriptItem.PSObject.Properties['Target']
        if ($null -eq $labTargetProperty) { throw 'Symbolic-link target metadata is unavailable.' }
        $labLinkTargets = @($labTargetProperty.Value)
        if ($labLinkTargets.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$labLinkTargets[0])) {
            throw 'Symbolic-link target metadata is empty or ambiguous.'
        }
        $labTargetPath = [string]$labLinkTargets[0]
        if (-not [IO.Path]::IsPathRooted($labTargetPath)) {
            $labTargetPath = [IO.Path]::Combine([IO.Path]::GetDirectoryName($labCandidatePath),$labTargetPath)
        }
        $labCandidatePath = $labTargetPath
    }
    if (-not $labLinkResolutionComplete) { throw 'The script symbolic-link chain exceeded the resolution limit.' }
    $script:LabExecutingScriptPath = $labCandidatePath
}
catch {
    # Best effort only: never replace a valid runtime name with a guess or
    # an intermediate link when final-target resolution cannot be completed.
    $script:LabExecutingScriptPath = $labRuntimeScriptPath
}
$script:LabExecutingScriptFile = [IO.Path]::GetFileName($script:LabExecutingScriptPath)
$script:LabExecutingInventoryFile = [IO.Path]::GetFileNameWithoutExtension($script:LabExecutingScriptPath) + '.JSON'

if ($PSCmdlet.ParameterSetName -eq 'RemoveGenerated' -and -not $RemoveAllGeneratedContent) {
    Write-Error 'RemoveAllGeneratedContent was explicitly disabled. No operation was run.'
    return
}

# Help is intentionally handled before DEFAULTS or any operational setup.
# Read the leading help comment directly: the custom PARAMETERS/EXAMPLES
# wrappers and VERSION_HISTORY are not standard Get-Help section keywords.
# Keeping one source of help text also keeps filenames/examples synchronized.
if ($Help) {
    try {
        $helpSource = [System.IO.File]::ReadAllText($script:LabExecutingScriptPath)
        $helpHeader = [regex]::Match($helpSource, '\A\s*<#(?<Header>.*?)#>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
        if (-not $helpHeader.Success) {
            throw 'The leading script help comment was not found.'
        }
        Write-Output ('SCRIPT: {0}' -f $script:LabExecutingScriptFile)
        Write-Output ''
        $helpSections = [regex]::Matches($helpHeader.Groups['Header'].Value,
            '(?ms)^\.(?<Name>[A-Z_]+)\b[^\r\n]*\r?\n.*?(?=^\.[A-Z_]+\b|\z)')
        foreach ($helpSection in $helpSections) {
            if ($helpSection.Groups['Name'].Value -cin @('SYNOPSIS', 'DESCRIPTION', 'PARAMETERS', 'PARAMETER', 'EXAMPLES', 'EXAMPLE')) {
                Write-Output $helpSection.Value.TrimEnd()
                Write-Output ''
            }
        }
    }
    catch {
        Write-Error ('Unable to display script help: {0}' -f $_.Exception.Message)
    }
    # Return, not exit: preserve the calling console or PowerShell ISE session.
    return
}

# ======================================================================
# DEFAULTS
# ======================================================================
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Shared no-input timeout for DEMO and dedicated Tier0Admin password dialogs.
# First typed/pasted character disables the timeout, even after clearing.
$PasswordPromptTimeoutSeconds = 7

# Local and DSP fixed-drive warning threshold, in binary GB (1 GB = 1 GiB).
# Warning messages do not abort or clean up; the review pause is separate.
$DiskSpaceWarningThresholdGB = 1

# Highlight only the Available field when free space is strictly below this.
# Separate from the existing warning-message threshold above.
$DiskSpaceHighlightThresholdGB = 2

# Pause once after all disk output when any checked disk is below this limit.
# Compare unrounded bytes; exactly 2 GB does not trigger the pause.
$DiskSpacePauseThresholdGB = 2
$DiskSpaceReviewPauseSeconds = 10

# Automatic, best-effort remote DSP disk check using current Windows credentials.
# $False skips both DSP SCP discovery and remote disk inventory entirely.
$CheckDspDiskSpace = $True

# Shared wait budget for all connection attempts per DSP host, not per protocol.
# Job startup/cleanup adds overhead; no remote configuration or credential prompts.
$DspDiskCheckTimeoutSeconds = 10

# Maximum wait for forest-wide DSP SCP discovery; cleanup adds overhead.
$DspDiscoveryTimeoutSeconds = 30

# Standard pause for retained baseline and synthetic replication checkpoints.
# FGPPs and AD Sites and Services (sites/subnets/site links) have no such wait.
$PauseTimeSeconds = 5

# Run the separate post-provisioning synthetic AD Changes phase.
# $False skips that phase only; existing content create/update behavior stays enabled.
# Synthetic mutations are listed in the editable AD change definitions.
$MakeADChanges = $True

# Optional read-only, group-only trees in the final processing summary.
# Disable with $null, '', @(), or blank entries. A single string also works.
# Use exact group names or SAM names in the discovered domain.
# Administrators is pinned to CN=Administrators,CN=Builtin in this domain.
$DisplayGroupNestingSummary = @(
    'Sharepoint Users'
    'Sharepoint - Special Content'
    'Pizza Party Group'
    'Helpdesk-L3'
    'Tier1 Operators'
    'Special Admin Group'
    'Helpdesk-ALL'
    'Domain Admins'
    'Administrators'
)

# PAUSED while baseline OU structure is being revised. Null skips this
# deletion only; keep the function and normal call site for later reuse.
# To resume later, explicitly set an approved relative OU path here.
$OUforSyntheticDeletion = $null

# Collected-password resets apply to allowlisted DEMO users and Tier0Admin.
# Tier0Admin uses its own credential, never the shared DEMO value.
# Other users/admins/service accounts receive random passwords at creation;
# their existing passwords/change-at-logon state are always preserved.
$DoNotUpdateDemoUsersPasswords = $true  # Refresh overrides only shared users.

# Legacy compatibility setting: special accounts now use creation-only random
# passwords, so this setting and per-account reset flags cannot reset them.
$DoNotUpdateSpecialDomainAcctPasswords = $false

# Generic-user defaults; count input is one-time and never changes these.
$GenericUserCount = 25
$GenericUserMaximumCount = 10000  # May be raised, but never above 999999.
# No-input wait only; typing/pasting disables this dialog's timeout.
$GenericUserPromptTimeoutSeconds = 8
$DoNotUpdateGenericUsers = $true  # Create missing accounts only; $false enables updates.

# Two spaces per level: 0 = root, 1 = detail, 2 = action result/error, 3 = action INFO.
$script:OutputIndentLevel = 0

# ======================================================================
# OPERATOR-EDITABLE DATA DEFINITIONS
# ======================================================================
# Edit the returned lists/tables in this section to change desired lab data.
# Provisioning functions below validate and apply these definitions; they
# must not contain a second, independently maintained copy of this data.
# These getters only return data; they do not read or write Active Directory.
# Domain-dependent user/group paths and existing-only group SIDs are built from
# the validated domain context after discovery, not during initial loading.
#
# Current definitions: OUs, group properties, existing-only group references,
# group-to-group nesting, demo/special/generic users, group memberships,
# computers, sites/subnets, DNS zones/records, WMI filters, GPOs, FGPPs,
# specific object ACLs and synthetic overrides.
# Add future object definitions here, not inside create/update functions.
# An empty/omitted definition is NOT an instruction to delete lab objects
# or clear existing group memberships.

# --- Organizational units (keep parent OUs before their children) --------
function Get-LabOrganizationalUnitDefinitions {
    [CmdletBinding()]
    param()

    # Keep this list parent-first. ParentPath is a relative OU path beneath
    # the domain DN; an empty ParentPath means the domain root.
    # Optional PreviousParentPath opts an OU into an explicit old-location
    # move before creation; an empty previous parent means the domain root.
    return @(
        [pscustomobject]@{ Name = 'Bad OU';    ParentPath = '';              Description = 'An OU that may have some issues' }
        [pscustomobject]@{ Name = 'TEST';      ParentPath = '';              Description = '' }
        [pscustomobject]@{ Name = 'Lab Admins'; ParentPath = '';             Description = '' }
        [pscustomobject]@{ Name = 'Tier 0';    ParentPath = 'OU=Lab Admins'; Description = '' }
        [pscustomobject]@{ Name = 'Tier 1';    ParentPath = 'OU=Lab Admins'; Description = '' }
        [pscustomobject]@{ Name = 'Tier 2';    ParentPath = 'OU=Lab Admins'; Description = '' }
        [pscustomobject]@{ Name = 'Lab Users'; ParentPath = '';              Description = '' }
        [pscustomobject]@{ Name = 'Dept101';   ParentPath = 'OU=Lab Users';  Description = '' }
        [pscustomobject]@{ Name = 'Dept999';   ParentPath = 'OU=Lab Users';  Description = '' }
        [pscustomobject]@{ Name = 'svc';       ParentPath = 'OU=Lab Users';  Description = '' }
        # Corp and Guest Users: all listed OUs are intentionally unprotected.
        [pscustomobject]@{
            Name                            = 'Corp'
            ParentPath                      = ''
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Users'
            ParentPath                      = 'OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Groups'
            ParentPath                      = 'OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Computers'
            ParentPath                      = 'OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Contractors'
            ParentPath                      = 'OU=Users,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Guest Users'
            ParentPath                      = 'OU=Users,OU=Corp'
            PreviousParentPath              = ''
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Partners'
            ParentPath                      = 'OU=Guest Users,OU=Users,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Contractors'
            ParentPath                      = 'OU=Guest Users,OU=Users,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Marketing'
            ParentPath                      = 'OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Users'
            ParentPath                      = 'OU=Marketing,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Admins'
            ParentPath                      = 'OU=Users,OU=Marketing,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Groups'
            ParentPath                      = 'OU=Marketing,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Computers'
            ParentPath                      = 'OU=Marketing,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Contractors'
            ParentPath                      = 'OU=Users,OU=Marketing,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Sales'
            ParentPath                      = 'OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Users'
            ParentPath                      = 'OU=Sales,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Admins'
            ParentPath                      = 'OU=Users,OU=Sales,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Groups'
            ParentPath                      = 'OU=Sales,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Computers'
            ParentPath                      = 'OU=Sales,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Contractors'
            ParentPath                      = 'OU=Users,OU=Sales,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'HR'
            ParentPath                      = 'OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Users'
            ParentPath                      = 'OU=HR,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Admins'
            ParentPath                      = 'OU=Users,OU=HR,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Groups'
            ParentPath                      = 'OU=HR,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Computers'
            ParentPath                      = 'OU=HR,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Contractors'
            ParentPath                      = 'OU=Users,OU=HR,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Security'
            ParentPath                      = 'OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Users'
            ParentPath                      = 'OU=Security,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Admins'
            ParentPath                      = 'OU=Users,OU=Security,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Groups'
            ParentPath                      = 'OU=Security,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Computers'
            ParentPath                      = 'OU=Security,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Contractors'
            ParentPath                      = 'OU=Users,OU=Security,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Risk'
            ParentPath                      = 'OU=Security,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Users'
            ParentPath                      = 'OU=Risk,OU=Security,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Groups'
            ParentPath                      = 'OU=Risk,OU=Security,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Computers'
            ParentPath                      = 'OU=Risk,OU=Security,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Contractors'
            ParentPath                      = 'OU=Risk,OU=Security,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Compliance'
            ParentPath                      = 'OU=Security,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Users'
            ParentPath                      = 'OU=Compliance,OU=Security,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Groups'
            ParentPath                      = 'OU=Compliance,OU=Security,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Computers'
            ParentPath                      = 'OU=Compliance,OU=Security,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Contractors'
            ParentPath                      = 'OU=Compliance,OU=Security,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }

        # Additional Servers containers and the Corp IT hierarchy.
        [pscustomobject]@{
            Name                            = 'Servers'
            ParentPath                      = 'OU=Computers,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Servers'
            ParentPath                      = 'OU=Computers,OU=Marketing,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Servers'
            ParentPath                      = 'OU=Computers,OU=Sales,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Servers'
            ParentPath                      = 'OU=Computers,OU=HR,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Servers'
            ParentPath                      = 'OU=Computers,OU=Security,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'IT'
            ParentPath                      = 'OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Users'
            ParentPath                      = 'OU=IT,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Admins'
            ParentPath                      = 'OU=Users,OU=IT,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'service accounts'
            ParentPath                      = 'OU=Users,OU=IT,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Groups'
            ParentPath                      = 'OU=IT,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Computers'
            ParentPath                      = 'OU=IT,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Servers'
            ParentPath                      = 'OU=Computers,OU=IT,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Contractors'
            ParentPath                      = 'OU=Users,OU=IT,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }

        # Service-account containers and the new Corp Finance hierarchy.
        [pscustomobject]@{
            Name                            = 'service accounts'
            ParentPath                      = 'OU=Users,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'service accounts'
            ParentPath                      = 'OU=Users,OU=Marketing,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'service accounts'
            ParentPath                      = 'OU=Users,OU=Sales,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'service accounts'
            ParentPath                      = 'OU=Users,OU=HR,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'service accounts'
            ParentPath                      = 'OU=Users,OU=Security,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Finance'
            ParentPath                      = 'OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Users'
            ParentPath                      = 'OU=Finance,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Admins'
            ParentPath                      = 'OU=Users,OU=Finance,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Groups'
            ParentPath                      = 'OU=Finance,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Computers'
            ParentPath                      = 'OU=Finance,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Contractors'
            ParentPath                      = 'OU=Users,OU=Finance,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'service accounts'
            ParentPath                      = 'OU=Users,OU=Finance,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }
        [pscustomobject]@{
            Name                            = 'Servers'
            ParentPath                      = 'OU=Computers,OU=Finance,OU=Corp'
            Description                     = ''
            ProtectedFromAccidentalDeletion = $false
        }

        # This OU will later be set with a very restrictive ACL.
        # ParentPath = '' resolves Path to "$DomainDN" (the domain root).
        # SamAccountName is reference metadata only; OUs are not SAM accounts.
        [pscustomobject]@{
            Name           = 'zSpecial OU'
            SamAccountName = 'zSpecial OU'
            DisplayName    = 'zSpecial OU'
            Description    = 'Restricted OU for special objects'
            ParentPath     = ''
            #GroupCategory = 'Security'
            #GroupScope    = 'Universal'
            #Orphan        = ($user.Login -eq "")
        }
    )
}

# --- Groups (properties only; nesting is defined separately below) -------
function Get-LabGroupDefinitions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainDN
    )

    # Add more keyed hash tables here. Keep keys stable when changing names.
    # Later reference examples:
    # $script:LabGroupDefinitions['SpecialLabUsers'].SamAccountName
    # $script:LabGroupObjects['SpecialLabUsers'].ObjectGUID
    return [ordered]@{
        # ISOLATED LAB ONLY: intentional contractor-to-Tier-0 access path.
        ITContractors = @{
            Name           = 'IT Contractors'
            SamAccountName = 'IT Contractors'
            DisplayName    = 'IT Contractors'
            Description    = 'Contractor support resources - isolated lab example'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Groups,OU=IT,OU=Corp,$DomainDN"
        }
        ExtendedHelpdesk = @{
            Name           = 'Extended Helpdesk'
            SamAccountName = 'Extended Helpdesk'
            DisplayName    = 'Extended Helpdesk'
            Description    = 'Extended helpdesk support - isolated lab example'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Groups,OU=IT,OU=Corp,$DomainDN"
        }
        ServerOperations = @{
            Name           = 'Server Operations'
            SamAccountName = 'Server Operations'
            DisplayName    = 'Server Operations'
            Description    = 'Server maintenance operations - isolated lab example'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Groups,OU=IT,OU=Corp,$DomainDN"
        }
        LegacyRecoveryAdmins = @{
            Name           = 'Legacy Recovery Admins'
            SamAccountName = 'Legacy Recovery Admins'
            DisplayName    = 'Legacy Recovery Admins'
            Description    = 'Legacy recovery access - intentional Tier 0 lab exposure'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Groups,OU=IT,OU=Corp,$DomainDN"
        }
        SpecialLabUsers = @{
            Name           = 'Special Lab Users'
            SamAccountName = 'SpecialLabUsers'
            DisplayName    = 'Special Lab Users'
            Description    = 'Members of this lab group are special'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Lab Users,$DomainDN"
        }
        SpecialLabAdmins = @{
            Name           = 'Special Lab Admins'
            SamAccountName = 'SpecialLabAdmins'
            DisplayName    = 'Special Lab Admins'
            Description    = 'Members of this lab group are admins'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Lab Admins,$DomainDN"
        }
        PizzaPartyGroup = @{
            Name           = 'Pizza Party Group'
            SamAccountName = 'PizzaPartyGroup'
            DisplayName    = 'Pizza Party Group'
            Description    = 'Members of this lab group get info about pizza parties'
            GroupCategory  = 'Distribution'
            GroupScope     = 'Global'
            Path           = "OU=Lab Users,$DomainDN"
        }
        PartyPlannersGroup = @{
            Name           = 'Party Planners Group'
            SamAccountName = 'PartyPlannersGroup'
            DisplayName    = 'Party Planners Group'
            Description    = 'Members of this lab group do party planning'
            GroupCategory  = 'Distribution'
            GroupScope     = 'Global'
            Path           = "OU=Lab Users,$DomainDN"
        }
        HelpdeskOps = @{
            Name           = 'Helpdesk Ops'
            SamAccountName = 'HelpdeskOps'
            DisplayName    = 'Helpdesk Ops'
            Description    = 'Members of this lab group are Helpdesk operators'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Lab Users,$DomainDN"
        }
        SpecialAdminGroup = @{
            Name           = 'Special Admin Group'
            SamAccountName = 'Special Admin Group'
            DisplayName    = 'Special Admin Group'
            Description    = 'special group for special admins'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Tier 0,OU=Lab Admins,$DomainDN"
        }
        Tier1Operators = @{
            Name           = 'Tier1 Operators'
            SamAccountName = 'Tier1 Operators'
            DisplayName    = 'Tier1 Operators'
            Description    = 'Members of this group are special admins for Tier1 infrastructure'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Tier 1,OU=Lab Admins,$DomainDN"
        }
        SpecialAccounts = @{
            Name           = 'Special Accounts'
            SamAccountName = 'Special Accounts'
            DisplayName    = 'Special Accounts'
            Description    = 'Members of this lab group are special accts and service accts'
            GroupCategory  = 'Security'
            GroupScope     = 'Universal'
            Path           = "OU=Lab Admins,$DomainDN"
        }
        # Sharepoint/content and tiered Helpdesk lab security groups.
        SharepointAdmins = @{
            Name           = 'Sharepoint Admins'
            SamAccountName = 'Sharepoint Admins'
            DisplayName    = 'Sharepoint Admins'
            Description    = 'Sharepoint Site Administrators'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Groups,OU=Corp,$DomainDN"
        }
        SharepointUsers = @{
            Name           = 'Sharepoint Users'
            SamAccountName = 'Sharepoint Users'
            DisplayName    = 'Sharepoint Users'
            Description    = 'Sharepoint Site Users'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Groups,OU=Corp,$DomainDN"
        }
        InternalDevContent = @{
            Name           = 'Internal Dev Content'
            SamAccountName = 'Internal Dev Content'
            DisplayName    = 'Internal Dev Content'
            Description    = 'Special access to internal developer content'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Groups,OU=Corp,$DomainDN"
        }
        SharepointRestricted = @{
            Name           = 'Sharepoint - Restricted'
            SamAccountName = 'Sharepoint - Restricted'
            DisplayName    = 'Sharepoint - Restricted'
            Description    = 'Restrticted content on Sharepoint'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Groups,OU=Corp,$DomainDN"
        }
        SharepointCorpWiki = @{
            Name           = 'Sharepoint - Corp Wiki'
            SamAccountName = 'Sharepoint - Corp Wiki'
            DisplayName    = 'Sharepoint - Corp Wiki'
            Description    = 'Internal corporate wiki site access'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Groups,OU=Corp,$DomainDN"
        }
        SharepointSpecialContent = @{
            Name           = 'Sharepoint - Special Content'
            SamAccountName = 'Sharepoint - Special Content'
            DisplayName    = 'Sharepoint - Special Content'
            Description    = 'Sharepoint access for certain special content areas'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Groups,OU=Corp,$DomainDN"
        }
        SharepointPartners = @{
            Name           = 'Sharepoint - Partners'
            SamAccountName = 'Sharepoint - Partners'
            DisplayName    = 'Sharepoint - Partners'
            Description    = 'Sharepoint access for external partners to partner/channel info'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Groups,OU=Corp,$DomainDN"
        }
        InternalFinance = @{
            Name           = 'Finance-internal'
            SamAccountName = 'Finance-internal'
            DisplayName    = 'Finance-internal'
            Description    = 'Restricted Finance internal content'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Groups,OU=Finance,OU=Corp,$DomainDN"
        }
        SharepointCommunity = @{
            Name           = 'Sharepoint-Community'
            SamAccountName = 'Sharepoint-Community'
            DisplayName    = 'Sharepoint-Community'
            Description    = 'Sharepoint Community Users'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Groups,OU=Corp,$DomainDN"
        }
        HelpdeskALL = @{
            Name           = 'Helpdesk-ALL'
            SamAccountName = 'Helpdesk-ALL'
            DisplayName    = 'Helpdesk-ALL'
            Description    = 'All Helpdesk members company-wide'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Tier 2,OU=Lab Admins,$DomainDN"
        }
        HelpdeskL1 = @{
            Name           = 'Helpdesk-L1'
            SamAccountName = 'Helpdesk-L1'
            DisplayName    = 'Helpdesk-L1'
            Description    = 'Level 1 (lowest) Helpdesk members - basic end-user support'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Tier 2,OU=Lab Admins,$DomainDN"
        }
        HelpdeskL2 = @{
            Name           = 'Helpdesk-L2'
            SamAccountName = 'Helpdesk-L2'
            DisplayName    = 'Helpdesk-L2'
            Description    = 'Level 2 Helpdesk members - identity and access support'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Tier 1,OU=Lab Admins,$DomainDN"
        }
        HelpdeskL3 = @{
            Name           = 'Helpdesk-L3'
            SamAccountName = 'Helpdesk-L3'
            DisplayName    = 'Helpdesk-L3'
            Description    = 'Level 3 Helpdesk members - password reset support'
            GroupCategory  = 'Security'
            GroupScope     = 'Global'
            Path           = "OU=Tier 0,OU=Lab Admins,$DomainDN"
        }
    }
}

# --- Existing-only group references (no creation/property updates) -------
function Get-LabExistingGroupDefinitions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainSID,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainDN
    )

    # Reference built-in or otherwise externally managed AD groups here.
    # Resolve these groups for nesting/membership; Ensure-RequiredGroups does
    # not create them, move/rename them, or reconcile their properties.
    # Explicit identities avoid accidentally selecting a same-named group.
    # S-1-5-32-555 is the domain's BUILTIN Remote Desktop Users group, not
    # the separate local group on each member workstation/server. Nesting
    # here does not configure RDP access on those member computers.
    return [ordered]@{
        # Domain BUILTIN\Administrators, not member-server local admins.
        # Existing-only DN reference: never create, move or rename it.
        BuiltinAdministrators = @{
            Name     = 'Administrators'
            Identity = "CN=Administrators,CN=Builtin,$DomainDN"
        }
        RemoteDesktopUsers = @{
            Name     = 'Remote Desktop Users'
            Identity = 'S-1-5-32-555'
        }
        # Resolve Domain Admins by domain SID/RID even if renamed/localized.
        DomainAdmins = @{
            Name     = 'Domain Admins'
            Identity = '{0}-512' -f $DomainSID
        }
        # DnsAdmins has no well-known SID; resolve its SAM account name.
        # It exists only where DNS installation has created it. References
        # are existing-only: this table never creates missing groups.
        DnsAdmins = @{
            Name     = 'DnsAdmins'
            Identity = 'DnsAdmins'
        }
        DomainControllers = @{
            Name     = 'Domain Controllers'
            Identity = '{0}-516' -f $DomainSID
        }
        # Enterprise Admins exists only in the forest-root domain. Resolve
        # by SAM name, not the child domain SID plus RID 519. The current
        # resolver uses the selected domain's DC; child-domain runs cannot
        # use this entry to manage forest-root memberships. If referenced
        # but unavailable, normal missing-parent warnings/skips apply.
        # If renamed, replace Identity with its actual SAM, SID, GUID or DN.
        EnterpriseAdmins = @{
            Name     = 'Enterprise Admins'
            Identity = 'Enterprise Admins'
        }
        AccountOperators = @{
            Name     = 'Account Operators'
            Identity = 'S-1-5-32-548'
        }
        EventLogReaders = @{
            Name     = 'Event Log Readers'
            Identity = 'S-1-5-32-573'
        }
        PrintOperators = @{
            Name     = 'Print Operators'
            Identity = 'S-1-5-32-550'
        }
        BackupOperators = @{
            Name     = 'Backup Operators'
            Identity = 'S-1-5-32-551'
        }
    }
}

# --- Group-to-group nesting (child -> one or more parents) ---------------
function Get-LabGroupNestingDefinitions {
    [CmdletBinding()]
    param()

    # OPERATOR-EDITABLE NESTING TABLE
    # Child group = list of parent groups the child must become a member of.
    # Use configured group Names, SAM names, or stable LabGroupDefinitions keys.
    # Existing-only parents may use the Name, key, or Identity from
    # Get-LabExistingGroupDefinitions (for example, Remote Desktop Users).
    # Add more child entries or more parents to an existing entry as needed.
    # Example using keys: PizzaPartyGroup = @('PartyPlannersGroup')
    #
    # Intentional self-membership/circular nesting is allowed for this lab.
    # The self-reference below is literal, not a reverse Party Planners link.
    # To make a two-group cycle, add a separate reverse child -> parent entry.
    #
    # Nesting provisioning is ADDITIVE: it never removes users or memberships.
    # An empty parent list, missing child entry, or omitted existing parent is
    # not an instruction to remove a link. General membership reconciliation
    # uses separately defined desired lists and preserves required nesting.
    return [ordered]@{
        # ISOLATED LAB ONLY: every link is child -> parent and additive.
        # jwick joins IT Contractors through the direct-member table below.
        # This complete chain grants domain BUILTIN Administrator access.
        'IT Contractors' = @(
            'Extended Helpdesk'
        )
        'Extended Helpdesk' = @(
            'Server Operations'
        )
        'Server Operations' = @(
            'Legacy Recovery Admins'
        )
        'Legacy Recovery Admins' = @(
            'BuiltinAdministrators'
        )
        'Pizza Party Group' = @(
            'Party Planners Group'
            'Pizza Party Group'
        )
        'Helpdesk Ops' = @(
            'Remote Desktop Users'
        )
        # Lab use: this grants members Domain Admin privileges.
        'Special Admin Group' = @(
            'Domain Admins'
        )
        # Lab use: Special Admin Group is itself nested in Domain Admins.
        # Other parent memberships are preserved; add future required parents
        # to this array. Missing configured links are restored on every run.
        'Tier1 Operators' = @(
            'Special Admin Group'
        )
        # Child group -> parent group; all links remain additive.
        'Sharepoint Admins' = @(
            'Sharepoint Users'
        )
        'Internal Dev Content' = @(
            'Sharepoint Users'
        )
        'Sharepoint - Restricted' = @(
            'Sharepoint Users'
        )
        'Sharepoint - Corp Wiki' = @(
            'Sharepoint Users'
        )
        'Sharepoint - Special Content' = @(
            'Sharepoint Admins'
        )
        'Sharepoint - Partners' = @(
            'Sharepoint - Special Content'
        )
        'Sharepoint-Community' = @(
            'Sharepoint Users'
        )
        'Helpdesk-L1' = @(
            'Helpdesk-ALL'
        )
        'Helpdesk-L2' = @(
            'Helpdesk-ALL'
        )
        'Helpdesk-L3' = @(
            'Helpdesk-ALL'
        )
    }
}

# --- Managed passwords for scoped baseline users ------------------------
function Get-LabManagedUserPasswordSettings {
    [CmdletBinding()]
    param()

    # Shared-password allowlist identifies SAM names, not OU location.
    # DemoUser1-13 map to the ordinary names below; AdmUser1 is adm.draji.
    # Every other defined user receives random passwords ONLY at creation.
    # All existing random-password accounts are excluded from refresh/reset.
    # PasswordLength is a preference (30), not an exact-length restriction.
    # Type minima are 20 for admins, 30 for service/non-human accounts;
    # ordinary users follow AD. Random length grows for higher AD minimums.
    # Explicit shared exceptions follow AD requirements, not the admin minimum.
    # Special automation/monitoring accounts are random non-human accounts.
    # All operator-editable password rules and alphabets are together here.
    return [ordered]@{
        ServiceAccountPrefix  = 'svc-'  # Retained for compatibility.
        ServiceAccountPrefixes = @('svc','service')
        PasswordLength        = 30
        NonHumanMinimumLength = 30
        AdminMinimumLength    = 20
        AdminAccountPrefixes  = @('adm.','Admin-')
        AdminAccountNames     = @('AppAdminII','AppAdminIII')
        OrdinaryDemoAccountNames = @('Admin-Tier0','adm.draji')
        SharedPasswordAccountNames = @(
            'arose','lskywalker','peter.griffin','pmccartney','yanli',
            'acruz','cmhernandez','draji','gjimenez','vlevin',
            'sarah.jenkins','marie.courtney','serge.vaudenay',
            'adm.draji','Admin-Tier0'
        )
        SymbolCount           = 2
        UppercaseCharacters   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        LowercaseCharacters   = 'abcdefghijklmnopqrstuvwxyz'
        DigitCharacters       = '0123456789'
        SymbolCharacters      = '!@'
    }
}

# --- Demo users (baseline attributes, not generic users) -----------------
function Get-LabDemoUserDefinitions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainDN,
        [Parameter(Mandatory = $true)]
        [string]$DomainDNSRoot
    )

    # Keep keys stable for later demo-change functions. All records below are
    # DEMO users, including the named admin examples; not generic-user data.
    # Example: $script:LabDemoUserDefinitions['DemoUser1'].TelephoneNumberAlt
    # TelephoneNumberAlt/FAXalt are demo-change metadata, not AD attributes.
    # Mail is retained exactly as supplied; UPN uses the discovered domain.
    # Explicit null/empty baseline attributes are cleared on reruns. Omitted
    # optional attributes are unmanaged. No other attributes are reset.
    # All configured accounts retain their Enabled=True baseline.
    # Password source is selected by account rules, never by OU location.
    # Only allowlisted DemoUser1-13, AdmUser1 and Admin-Tier0 use shared
    # credentials. All other users get creation-only random passwords;
    # admins require 20+, service/non-human 30+, ordinary users follow AD.
    # Random generation defaults to 30 and grows for higher AD minimums.
    # Tier0Admin uses its dedicated credential, selected by stable key.
    # Other shared-password users use the DEMO credential; existing passwords
    # and change requirements remain unless DoNotUpdateDemoUsersPasswords is
    # false. Any permitted password reset completes before re-enabling.
    # Tier0Admin and OpsAdmin explicitly manage PasswordNeverExpires.
    # Omitted PasswordNeverExpires leaves that setting unmanaged for others.
    # Existing account expiration, lockout and other policies are not changed.
    # Identity recovery uses SAM or CN+OU, like groups; stable keys are not
    # persisted to AD. Changing both identifying values may require repair.
    # Supplied unusual spellings, duplicate mail and employee IDs are retained.
    return [ordered]@{
        Tier0Admin = @{
            Name                = 'Admin-Tier0'
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
            TelephoneNumber     = '408-555-9090'
            TelephoneNumberAlt  = '(415) 555-9191'
            FAX                 = '(415) 555-8880'
            FAXalt              = $null
            City                = 'Silicon Valley'
            State               = $null
            EmployeeID          = '000001101'
            UserPrincipalName   = "Admin-Tier0@$DomainDNSRoot"
            Path                = "OU=Tier 0,OU=Lab Admins,$DomainDN"
            Enabled             = $true
            PasswordNeverExpires = $true
        }
        Tier2Admin = @{
            Name                = 'Admin-Tier2'
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
            TelephoneNumber     = '408-555-9090'
            TelephoneNumberAlt  = '(415) 555-9191'
            FAX                 = '(415) 555-8880'
            FAXalt              = $null
            City                = 'Silicon Valley'
            State               = $null
            EmployeeID          = '000001138'
            UserPrincipalName   = "Admin-Tier2@$DomainDNSRoot"
            Path                = "OU=Tier 2,OU=Lab Admins,$DomainDN"
            Enabled             = $true
        }
        OpsAdmin = @{
            Name                = 'adm.JohnWick'
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
            TelephoneNumber     = '408-555-1919'
            TelephoneNumberAlt  = '(619) 555-1230'
            FAX                 = '(619) 555-0987'
            FAXalt              = $null
            City                = 'New York'
            State               = $null
            EmployeeID          = '00010011'
            UserPrincipalName   = "adm.johnwick@$DomainDNSRoot"
            Path                = "OU=Tier 1,OU=Lab Admins,$DomainDN"
            Enabled             = $true
            PasswordNeverExpires = $true
        }
        AppAdminII = @{
            Name                = 'App Admin II'
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
            TelephoneNumber     = '408-555-2424'
            TelephoneNumberAlt  = '(619) 555-9999'
            FAX                 = '(619) 555-9990'
            FAXalt              = $null
            City                = 'San Diego'
            State               = $null
            EmployeeID          = '00088123'
            UserPrincipalName   = "AppAdminII@$DomainDNSRoot"
            Path                = "OU=Tier 2,OU=Lab Admins,$DomainDN"
            Enabled             = $true
        }
        AppAdminIII = @{
            Name                = 'App Admin III'
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
            TelephoneNumber     = '408-555-3434'
            TelephoneNumberAlt  = '(619) 555-9119'
            FAX                 = '(619) 555-9110'
            FAXalt              = $null
            City                = 'San Diego'
            State               = $null
            EmployeeID          = '00088120'
            UserPrincipalName   = "AppAdminIII@$DomainDNSRoot"
            Path                = "OU=Tier 2,OU=Lab Admins,$DomainDN"
            Enabled             = $true
        }
        DemoUser1 = @{
            Name                = 'Axl Rose'
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
            TelephoneNumber     = '408-555-1212'
            TelephoneNumberAlt  = '(000) 867-5309'
            FAX                 = '(408) 555-1212'
            FAXalt              = '+501 11-0001'
            City                = 'City of Angels'
            State               = $null
            EmployeeID          = '000123456'
            UserPrincipalName   = "arose@$DomainDNSRoot"
            Path                = "OU=Lab Users,$DomainDN"
            Enabled             = $true
        }
        DemoUser2 = @{
            Name                = 'Luke Skywalker'
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
            TelephoneNumber     = '408-555-5151'
            TelephoneNumberAlt  = '(111) 555-JEDI'
            FAX                 = '(408) 555-5555'
            FAXalt              = '+41 111-9999'
            City                = 'Tatooine'
            State               = $null
            EmployeeID          = '00314159'
            UserPrincipalName   = "lskywalker@$DomainDNSRoot"
            Path                = "OU=Lab Users,$DomainDN"
            Enabled             = $true
        }
        DemoUser3 = @{
            Name                = 'Peter Griffin'
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
            TelephoneNumber     = '408-777-3333'
            TelephoneNumberAlt  = '(216) 555-JEDI'
            FAX                 = '(216) 555-1000'
            FAXalt              = '+1 216 111-888'
            City                = 'Quahog'
            State               = $null
            EmployeeID          = '00987654321'
            UserPrincipalName   = "peter.griffin@$DomainDNSRoot"
            Path                = "OU=Lab Users,$DomainDN"
            Enabled             = $true
        }
        DemoUser4 = @{
            Name                = 'Paul McCartney'
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
            TelephoneNumber     = '011 44 20 1234 5678'
            TelephoneNumberAlt  = '011 44 151 1BEA TLES'
            FAX                 = '011 44 20 5555 1111'
            FAXalt              = '011 44 151 2222 9999'
            City                = 'Liverpool'
            State               = $null
            EmployeeID          = '000001212'
            UserPrincipalName   = "pmccartney@$DomainDNSRoot"
            Path                = "OU=Lab Users,$DomainDN"
            Enabled             = $true
        }
        DemoUser5 = @{
            Name                = 'Yan Li'
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
            TelephoneNumber     = '212 555-5600'
            TelephoneNumberAlt  = '212 555-5601'
            FAX                 = '212 555-5699'
            FAXalt              = '212 555-5698'
            City                = 'Jersey'
            State               = $null
            EmployeeID          = '000062312'
            UserPrincipalName   = "yanli@$DomainDNSRoot"
            Path                = "OU=Lab Users,$DomainDN"
            Enabled             = $true
        }
        DemoUser6 = @{
            Name                = 'Aria Cruz'
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
            TelephoneNumber     = '213 667-5555'
            TelephoneNumberAlt  = '213 667-5556'
            FAX                 = '213 12-FAXIT'
            FAXalt              = '213 669-4201'
            City                = 'Rancho Cucamonga'
            State               = $null
            EmployeeID          = '000701212'
            UserPrincipalName   = "acruz@$DomainDNSRoot"
            Path                = "OU=Lab Users,$DomainDN"
            Enabled             = $true
        }
        DemoUser7 = @{
            Name                = 'Carlos M. Hern ndez'
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
            TelephoneNumber     = '+55 0021 123 5678'
            TelephoneNumberAlt  = '+55 0021 123-3434'
            FAX                 = '+55 0021 123-5678'
            FAXalt              = '+55 0021 123-5679'
            City                = 'Rio de Janeiro'
            State               = $null
            EmployeeID          = '000001200'
            UserPrincipalName   = "cmhernandez@$DomainDNSRoot"
            Path                = "OU=Lab Users,$DomainDN"
            Enabled             = $true
        }
        DemoUser8 = @{
            Name                = 'Dawn Raji'
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
            TelephoneNumber     = '1 (11) 500 555-0126'
            TelephoneNumberAlt  = '1 (11) 500 555-0128'
            FAX                 = '1 (11) 500 555-0288'
            FAXalt              = '1 (11) 500 555-0399'
            City                = 'East Brisbane'
            State               = 'WA'
            EmployeeID          = '088002181'
            UserPrincipalName   = "draji@$DomainDNSRoot"
            Path                = "OU=Lab Users,$DomainDN"
            Enabled             = $true
        }
        DemoUser9 = @{
            Name                = 'Gary Jimenez'
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
            TelephoneNumber     = '1 (500) 555-1221'
            TelephoneNumberAlt  = '1 (500) 555-1234'
            FAX                 = '1 (500) 555-9911'
            FAXalt              = '1 (500) 555-9922'
            City                = 'Hobart'
            State               = 'WA'
            EmployeeID          = '088002181'
            UserPrincipalName   = "gjimenez@$DomainDNSRoot"
            Path                = "OU=Lab Users,$DomainDN"
            Enabled             = $true
        }
        DemoUser10 = @{
            Name                = 'Vladimir Levin'
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
            TelephoneNumber     = '1 (500) 555-8321'
            TelephoneNumberAlt  = '1 (500) 555-8324'
            FAX                 = '1 (500) 555-6611'
            FAXalt              = '1 (500) 555-6622'
            City                = 'St Petersburg'
            State               = 'VS'
            EmployeeID          = '055002881'
            UserPrincipalName   = "vlevin@$DomainDNSRoot"
            Path                = "OU=Lab Users,$DomainDN"
            Enabled             = $true
        }
        DemoUser11 = @{
            Name                = 'Sarah Jenkins'
            SamAccountName      = 'sarah.jenkins'
            GivenName           = 'Sarah'
            Surname             = 'Jenkins'
            DisplayName         = 'Sarah Jenkins'
            Initials            = 'SJ'
            Description         = 'Helpdesk member - L3'
            Mail                = 'sarah.jenkins@adventure-works.com'
            Title               = 'Sr Helpdesk Manager'
            Department          = 'Support'
            Division            = 'Support Org'
            Company             = 'Northwind'
            TelephoneNumber     = '1 (500) 555-8621'
            TelephoneNumberAlt  = '1 (500) 555-8624'
            FAX                 = '1 (500) 555-6611'
            FAXalt              = '1 (500) 555-6622'
            City                = 'Long Beach'
            State               = 'CA'
            EmployeeID          = '055006881'
            UserPrincipalName   = "sarah.jenkins@$DomainDNSRoot"
            Path                = "OU=Lab Users,$DomainDN"
            Enabled             = $true
        }
        DemoUser12 = @{
            Name                = 'Marie Courtney'
            SamAccountName      = 'marie.courtney'
            GivenName           = 'Marie'
            Surname             = 'Courtney'
            DisplayName         = 'Marie Courtney'
            Initials            = 'MC'
            Description         = 'Helpdesk member - L2'
            Mail                = 'marie.courtney@adventure-works.com'
            Title               = 'Sr Helpdesk Team Lead'
            Department          = 'Support'
            Division            = 'Support Org'
            Company             = 'Northwind'
            TelephoneNumber     = '1 (500) 555-8721'
            TelephoneNumberAlt  = '1 (500) 555-8724'
            FAX                 = '1 (500) 555-6611'
            FAXalt              = '1 (500) 555-6622'
            City                = 'Orange'
            State               = 'CA'
            EmployeeID          = '055007881'
            UserPrincipalName   = "marie.courtney@$DomainDNSRoot"
            Path                = "OU=Lab Users,$DomainDN"
            Enabled             = $true
        }
        DemoUser13 = @{
            Name                = 'Serge Vaudenay'
            SamAccountName      = 'serge.vaudenay'
            GivenName           = 'Serge'
            Surname             = 'Vaudenay'
            DisplayName         = 'Serge Vaudenay'
            Initials            = 'SV'
            Description         = 'Helpdesk member - L3'
            Mail                = 'serge.vaudenay@adventure-works.com'
            Title               = 'Sr Helpdesk Admin'
            Department          = 'Support'
            Division            = 'Support Org'
            Company             = 'Northwind'
            TelephoneNumber     = '1 (500) 555-8821'
            TelephoneNumberAlt  = '1 (500) 555-8824'
            FAX                 = '1 (500) 555-6611'
            FAXalt              = '1 (500) 555-6622'
            City                = 'Orange'
            State               = 'CA'
            EmployeeID          = '055008881'
            UserPrincipalName   = "serge.vaudenay@$DomainDNSRoot"
            Path                = "OU=Lab Users,$DomainDN"
            Enabled             = $true
        }
        DemoUser14 = @{
            Name                = 'TJ Martineau'
            SamAccountName      = 'tmartineau'
            GivenName           = 'TJ'
            Surname             = 'Martineau'
            DisplayName         = 'TJ Martineau [partner]'
            Initials            = 'TJM'
            Description         = 'Partner SE'
            Mail                = 'tj.martineau@acmesecurity.com'
            Title               = 'Sr Solutions Engineer'
            Department          = 'Sales'
            Division            = 'Partner-Channel'
            Company             = 'Acme Security'
            TelephoneNumber     = '408-555-9067'
            TelephoneNumberAlt  = '(000) 867-9068'
            FAX                 = '(408) 555-7531'
            FAXalt              = '+1 408 555-9731'
            City                = 'Birmingham'
            State               = $null
            EmployeeID          = '000164656'
            UserPrincipalName   = "tmartineau@$DomainDNSRoot"
            Path                = "OU=Partners,OU=Guest Users,OU=Users,OU=Corp,$DomainDN"
            Enabled             = $true
        }
        DemoUser15 = @{
            Name                = 'Brian Britt'
            SamAccountName      = 'bbritt'
            GivenName           = 'Brian'
            Surname             = 'Britt'
            DisplayName         = 'Brian Britt [partner]'
            Initials            = 'BB'
            Description         = 'Partner SE'
            Mail                = 'bbritt@holisticops.com'
            Title               = 'Sr Solutions Engineer'
            Department          = 'Sales'
            Division            = 'Partner-Channel'
            Company             = 'Holistic Ops, Inc'
            TelephoneNumber     = '415-555-1061'
            TelephoneNumberAlt  = '(415) 867-9069'
            FAX                 = '(415) 555-7531'
            FAXalt              = '+1 415 555-9731'
            City                = 'Daly City'
            State               = $null
            EmployeeID          = '000164657'
            UserPrincipalName   = "bbritt@$DomainDNSRoot"
            Path                = "OU=Partners,OU=Guest Users,OU=Users,OU=Corp,$DomainDN"
            Enabled             = $true
        }
        DemoUser16 = @{
            Name                = 'John Wick'
            SamAccountName      = 'jwick'
            GivenName           = 'John'
            Surname             = 'Wick'
            DisplayName         = 'John Wick [consultant]'
            Initials            = 'JW'
            Description         = 'Independent Consultant'
            Mail                = 'jwick@example.com'
            Title               = 'Security Consultant'
            Department          = 'Operations'
            Division            = 'Special Projects'
            Company             = 'Continental Services'
            TelephoneNumber     = '212-555-0147'
            TelephoneNumberAlt  = '(212) 555-0182'
            FAX                 = '(212) 555-0193'
            FAXalt              = '+1 212 555-0164'
            City                = 'New York'
            State               = 'NY'
            EmployeeID          = '000000001'
            UserPrincipalName   = "jwick@$DomainDNSRoot"
            Path                = "OU=Contractors,OU=Users,OU=IT,OU=Corp,$DomainDN"
            Enabled             = $true
        }
        AdmUser1 = @{
            Name                = 'adm.draji'
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
            TelephoneNumber     = '1 (11) 500 555-0126'
            TelephoneNumberAlt  = '1 (11) 500 555-0128'
            FAX                 = '1 (11) 500 555-0288'
            FAXalt              = '1 (11) 500 555-0399'
            City                = 'East Brisbane'
            State               = 'WA'
            EmployeeID          = '088002181'
            UserPrincipalName   = "adm.draji@$DomainDNSRoot"
            Path                = "OU=Tier 2,OU=Lab Admins,$DomainDN"
            Enabled             = $true
        }
        AdmUser2 = @{
            Name                = 'adm.gjimenez'
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
            TelephoneNumber     = '1 (500) 555-1221'
            TelephoneNumberAlt  = '1 (500) 555-1234'
            FAX                 = '1 (500) 555-9911'
            FAXalt              = '1 (500) 555-9922'
            City                = 'Hobart'
            State               = 'WA'
            EmployeeID          = '088002181'
            UserPrincipalName   = "adm.gjimenez@$DomainDNSRoot"
            Path                = "OU=Tier 2,OU=Lab Admins,$DomainDN"
            Enabled             = $true
        }
        AdmUser3 = @{
            Name                = 'adm.GlobalAdmin (old)'
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
            TelephoneNumber     = '1 (500) 555-4554'
            TelephoneNumberAlt  = '1 (500) 555-4555'
            FAX                 = '1 (500) 555-9954'
            FAXalt              = '1 (500) 555-9955'
            City                = 'Hobart'
            State               = 'WA'
            EmployeeID          = '088002011'
            UserPrincipalName   = "adm.GlobalAdmin@$DomainDNSRoot"
            Path                = "OU=Tier 0,OU=Lab Admins,$DomainDN"
            Enabled             = $true
        }
        AdmUser4 = @{
            Name                = 'adm.robi'
            SamAccountName      = 'adm.robi'
            GivenName           = 'Rob'
            Surname             = 'Ivanov'
            DisplayName         = 'Rob Ivanov (adm)'
            Initials            = 'RI'
            Description         = 'alternate admin acct'
            Mail                = 'adm.robi@adventure-works.com'
            Title               = 'Global Systems Admin II'
            Department          = 'Operations'
            Division            = 'Operations'
            Company             = 'Northwind'
            TelephoneNumber     = '1 (500) 555-4664'
            TelephoneNumberAlt  = '1 (500) 555-4665'
            FAX                 = '1 (500) 555-6654'
            FAXalt              = '1 (500) 555-6655'
            City                = 'Hobart'
            State               = 'WA'
            EmployeeID          = '088006011'
            UserPrincipalName   = "adm.robi@$DomainDNSRoot"
            Path                = "OU=Tier 0,OU=Lab Admins,$DomainDN"
            Enabled             = $true
        }
        AdmUser5 = @{
            Name                = 'adm.JJocobo'
            SamAccountName      = 'adm.JJocobo'
            GivenName           = 'adm.JJocobo'
            Surname             = ''
            DisplayName         = 'adm.JJocobo (Jason Jocobo)'
            Description         = 'Alternate admin account for Jason Jocobo'
            UserPrincipalName   = "adm.JJocobo@$DomainDNSRoot"
            Path                = "OU=Tier 1,OU=Lab Admins,$DomainDN"
            Enabled             = $true
        }
        AdmUser6 = @{
            Name                = 'adm.svaudenay'
            SamAccountName      = 'adm.svaudenay'
            GivenName           = 'Serge'
            Surname             = 'Vaudenay (ADM)'
            DisplayName         = 'Serge Vaudenay (ADM)'
            Initials            = ''
            Description         = 'Helpdesk member - L1'
            Mail                = 'serge.vaudenay@adventure-works.com'
            Title               = ''
            Department          = 'Support'
            Division            = 'Support Org'
            Company             = 'Northwind'
            TelephoneNumber     = '1 (500) 555-8821'
            TelephoneNumberAlt  = '1 (500) 555-8824'
            FAX                 = ''
            FAXalt              = ''
            City                = 'Orange'
            State               = 'CA'
            EmployeeID          = ''
            UserPrincipalName   = "adm.svaudenay@$DomainDNSRoot"
            Path                = "OU=Tier 2,OU=Lab Admins,$DomainDN"
            Enabled             = $true
        }
        AdmUser7 = @{
            Name                = 'adm.sjenkins'
            SamAccountName      = 'adm.sjenkins'
            GivenName           = 'Sarah'
            Surname             = 'Jenkins (ADM)'
            DisplayName         = 'Sarah Jenkins (ADM)'
            Initials            = ''
            Description         = 'Helpdesk member - L3'
            Mail                = 'sarah.jenkins@adventure-works.com'
            Title               = ''
            Department          = 'Support'
            Division            = 'Support Org'
            Company             = 'Northwind'
            TelephoneNumber     = '1 (500) 555-8821'
            TelephoneNumberAlt  = '1 (500) 555-8824'
            FAX                 = ''
            FAXalt              = ''
            City                = 'Orange'
            State               = 'CA'
            EmployeeID          = ''
            UserPrincipalName   = "adm.sjenkins@$DomainDNSRoot"
            Path                = "OU=Tier 1,OU=Lab Admins,$DomainDN"
            Enabled             = $true
        }
        'svc-hr-salesforce01' = @{
            Name                = 'svc-hr-salesforce01'
            SamAccountName      = 'svc-hr-salesforce01'
            DisplayName         = 'svc-hr-salesforce01'
            Description         = 'SalesForce service account'
            UserPrincipalName   = "svc-hr-salesforce01@$DomainDNSRoot"
            Path                = "OU=service accounts,OU=Users,OU=HR,OU=Corp,$DomainDN"
            Enabled             = $true
        }
        'svc-hr-db02' = @{
            Name                = 'svc-hr-db02'
            SamAccountName      = 'svc-hr-db02'
            DisplayName         = 'svc-hr-db02'
            Description         = 'HR database service account'
            UserPrincipalName   = "svc-hr-db02@$DomainDNSRoot"
            Path                = "OU=service accounts,OU=Users,OU=HR,OU=Corp,$DomainDN"
            Enabled             = $true
        }
        'svc-hr-proxy01' = @{
            Name                = 'svc-hr-proxy01'
            SamAccountName      = 'svc-hr-proxy01'
            DisplayName         = 'svc-hr-proxy01'
            Description         = 'HR proxy server service acct'
            UserPrincipalName   = "svc-hr-proxy01@$DomainDNSRoot"
            Path                = "OU=service accounts,OU=Users,OU=HR,OU=Corp,$DomainDN"
            Enabled             = $true
        }
        'svc-finance-common-01' = @{
            Name                = 'svc-finance-common-01'
            SamAccountName      = 'svc-finance-common01'
            DisplayName         = 'svc-finance-common-01'
            Description         = 'shared Finances service acct'
            UserPrincipalName   = "svc-finance-common01@$DomainDNSRoot"
            Path                = "OU=service accounts,OU=Users,OU=Finance,OU=Corp,$DomainDN"
            Enabled             = $true
        }
        'adm.hr' = @{
            Name                = 'adm.hr'
            SamAccountName      = 'adm.hr'
            DisplayName         = 'adm.hr'
            Description         = 'HR common administrator account managed via password vault'
            UserPrincipalName   = "adm.hr@$DomainDNSRoot"
            Path                = "OU=Admins,OU=Users,OU=HR,OU=Corp,$DomainDN"
            Enabled             = $true
        }
    }
}

# --- Special domain accounts --------------------------------------------
function Get-LabSpecialDomainAccountDefinitions {
    [CmdletBinding()]
    param()

    # Special accounts use random passwords, at least 30 characters, ONLY
    # at creation. Existing passwords and change-at-logon state are preserved.
    # SpecialAcctPasswordReset is retained as a legacy definition field only;
    # it does not reset random passwords, even with RefreshAllPasswords.
    # NetBIOSName is prepended at runtime; only that prefix is truncated.
    # RelativePath excludes the domain DN; it is appended at runtime.
    # Omit Description to leave an existing description unmanaged.
    # Description = '' clears it. Missing OUs are not created here.
    @(
        [pscustomobject]@{ Suffix = 'automation'; Description = 'This is an account for automated tasks'; RelativePath = 'OU=Tier 0,OU=Lab Admins'; SpecialAcctPasswordReset = $False }
        [pscustomobject]@{ Suffix = 'monitoring'; Description = 'This account is for the monitoring application'; RelativePath = 'OU=Tier 1,OU=Lab Admins'; SpecialAcctPasswordReset = $True }
    )
}

# --- Group memberships (users, groups and computers) ---------------------
function Get-LabGroupUserMembershipSettings {
    [CmdletBinding()]
    param()

    # $false = ADDITIVE: add missing members; never remove any members.
    # $true  = EXACT: reconcile direct members to the lists below PLUS the
    # required child groups from Get-LabGroupNestingDefinitions.
    # An explicitly empty @() in exact mode removes all direct members except
    # protected required nesting. An omitted group is never managed here.
    # WARNING: exact mode can remove administrative access. Review lists first.
    return @{
        ExactMembership = $false
    }
}

function Get-LabGroupUserMembershipDefinitions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainDN
    )

    # Parent group -> ordered list of desired direct members.
    # Use exact DN, DisplayName, Name or SamAccountName for groups/members.
    # A DN resolves the current object at that path, never a stored SID.
    # Members may be AD users, groups or computers. A computer SAM usually
    # ends in '$'. Stable group-definition keys are also accepted.
    # Matching is case-insensitive, not fuzzy. Ambiguous matches are errors.
    # Duplicate aliases for one member are deduplicated by ObjectGUID.
    # Existing-only groups use their registered identities where applicable.
    # Objects are resolved in the selected domain on the selected writable DC;
    # Enterprise Admins therefore requires a forest-root-domain run.
    # This function does NOT create missing accounts or groups. In particular,
    # service accounts and other supplied names must already exist or be added
    # to the appropriate creation definitions before membership can be applied.
    # Missing/ambiguous members are reported; resolved members can still be
    # added, but all removals for that group are suppressed on that run.
    # Missing/ambiguous required-nesting references suppress ALL removals.
    # Primary-group membership is not changed; only direct 'member' links are
    # managed. AD scope/category/permission constraints remain enforced.
    # Example of an explicitly empty list: 'Special Accounts' = @()
    return [ordered]@{
        # Intentional isolated-lab Tier 0 exposure through required nesting.
        'IT Contractors' = @(
            "CN=John Wick,OU=Contractors,OU=Users,OU=IT,OU=Corp,$DomainDN"
        )
        'Sharepoint - Partners' = @(
            'tmartineau'
            'bbritt'
        )
        'Enterprise Admins' = @(
            'adm.draji'
        )
        'Helpdesk Ops' = @(
            'App Admin II'
            'App Admin III'
        )
        'Party Planners Group' = @(
            'Aria Cruz'
            'Axl Rose'
            'Carlos M. Hern ndez'
            'Dawn Raji'
            'Gary Jimenez'
            'Luke Skywalker'
            'Paul McCartney'
            'Peter Griffin'
            'Vladimir Levin'
            'Yan Li'
        )
        'Pizza Party Group' = @(
            'Aria Cruz'
            'Axl Rose'
            'Carlos M. Hern ndez'
            'Dawn Raji'
            'Gary Jimenez'
            'Luke Skywalker'
            'Paul McCartney'
            'Peter Griffin'
            'Vladimir Levin'
            'Yan Li'
            'svc-dsp-agents'
            'svc-dsp-sql'
        )
        'Special Lab Users' = @(
            'App Admin III'
        )
        'Tier1 Operators' = @(
            'adm.JohnWick'
        )
        'Special Admin Group' = @(
            'adm.draji'
        )
        'Domain Admins' = @(
            'adm.draji'
            'Administrator'
            'adm.robi'
            'APM FD Integration (dsp-fd-apm)'
            'BadOne'
            'd01admin'
        )
        'DnsAdmins' = @(
            'adm.gjimenez'
        )
        # Explicit direct user links; nesting above supplies Helpdesk-ALL.
        'Helpdesk-L1' = @(
            'adm.sjenkins'
        )
        'Helpdesk-L3' = @(
            'adm.sjenkins'
        )
        'Helpdesk-L2' = @(
            'marie.courtney'
        )
    }
}

# --- Generic users ------------------------------------------------------
function Get-LabGenericUserSettings {
    [CmdletBinding()]
    param()

    # Names use an invariant six-digit index (000001 through 999999).
    # The count defaults are in DEFAULTS. The target OU must already exist.
    # Only newly created users receive random passwords; existing passwords
    # and enabled states are not changed. Accounts above the count remain.
    # DEFAULTS controls create-only versus update mode via DoNotUpdateGenericUsers.
    return [ordered]@{
        RelativePath                  = 'OU=TEST'
        SamAccountNamePrefix          = 'GdAct0r-'
        NamePrefix                    = 'Good Act0r '
        DisplayNamePrefix             = 'Good Act0r '
        GivenName                     = 'Good'
        SurnamePrefix                 = 'Act0r '
        UserPrincipalNamePrefix       = 'Good.Act0r.'
        DescriptionPrefix             = 'Generic user account #'
        PasswordUppercaseCharacters   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        PasswordLowercaseCharacters   = 'abcdefghijklmnopqrstuvwxyz'
        PasswordDigitCharacters       = '0123456789'
        PasswordSpecialCharacters     = '!@#$%^&*-+'
    }
}

# --- Computer objects (properties; not machine joins or passwords) --------
function Get-LabComputerDefinitions {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$DomainDN)

    # Keep stable keys even when changing editable names/SAMs or paths.
    # SAM definitions may omit '$'; provisioning adds exactly one suffix.
    # Every defined computer is created enabled and re-enabled on later runs.
    # Examples for later AD Changes (use GUIDs, refresh properties after writes):
    # $script:LabComputerDefinitions['PIMPAM'].Path
    # Later reference a verified computer by its stable key and ObjectGUID:
    # $script:LabComputerObjects['PIMPAM'].ObjectGUID
    # A missing definition never requests deletion of an existing computer.
    return [ordered]@{
        'PIMPAM' = @{
            Name           = 'PIMPAM'
            SamAccountName = 'PIMPAM'
            DisplayName    = 'PIMPAM'
            Description    = 'Privileged access server'
            Path           = "OU=zSpecial OU,$DomainDN"
        }
        'VAULT' = @{
            Name           = 'VAULT'
            SamAccountName = 'VAULT'
            DisplayName    = 'VAULT'
            Description    = 'Vault server to store passwords and crednetials'
            Path           = "OU=zSpecial OU,$DomainDN"
        }
        'BASTION-HOST01' = @{
            Name           = 'BASTION-HOST01'
            SamAccountName = 'BASTION-HOST01'
            DisplayName    = 'BASTION-HOST01'
            Description    = 'Bastion host for restricted privileged access'
            Path           = "OU=zSpecial OU,$DomainDN"
        }
        'APPSERVER01' = @{
            Name           = 'APPSERVER01'
            SamAccountName = 'APPSERVER01'
            DisplayName    = 'APPSERVER01'
            Description    = 'Application server for special services'
            Path           = "CN=Computers,$DomainDN"
        }
        'BadOne' = @{
            Name           = 'BadOne'
            SamAccountName = 'BadOne'
            DisplayName    = 'BadOne'
            Description    = 'Questionable Application server for special services'
            Path           = "CN=Computers,$DomainDN"
        }
        'TOOLS01' = @{
            Name           = 'TOOLS01'
            SamAccountName = 'TOOLS01'
            DisplayName    = 'TOOLS01'
            Description    = 'Server for admin tools and functions'
            Path           = "CN=Computers,$DomainDN"
        }
        'appsvr-hr-001' = @{
            Name           = 'appsvr-hr-001'
            SamAccountName = 'appsvr-hr-001'
            DisplayName    = 'appsvr-hr-001'
            Description    = 'HR SalesForce Web services'
            Path           = "OU=Servers,OU=Computers,OU=HR,OU=Corp,$DomainDN"
        }
        'appsvr-hr-002' = @{
            Name           = 'appsvr-hr-002'
            SamAccountName = 'appsvr-hr-002'
            DisplayName    = 'appsvr-hr-002'
            Description    = 'HR database server'
            Path           = "OU=Servers,OU=Computers,OU=HR,OU=Corp,$DomainDN"
        }
        'appsvr-hr-003' = @{
            Name           = 'appsvr-hr-003'
            SamAccountName = 'appsvr-hr-003'
            DisplayName    = 'appsvr-hr-003'
            Description    = 'proxy server'
            Path           = "OU=Servers,OU=Computers,OU=HR,OU=Corp,$DomainDN"
        }
        # Stable key only; never use it to find or migrate the old computer.
        'svc-finance-svr-001' = @{
            Name           = 'srv-finance-app01'
            SamAccountName = 'srv-finance-app01'
            DisplayName    = 'srv-finance-app01'
            Description    = 'Finance server'
            Path           = "OU=Servers,OU=Computers,OU=Finance,OU=Corp,$DomainDN"
        }
        'usrusazlap11' = @{
            Name           = 'usrusazlap11'
            SamAccountName = 'usrusazlap11'
            DisplayName    = 'usrusazlap11'
            Description    = 'standard user laptop build'
            Path           = "OU=Computers,OU=Corp,$DomainDN"
        }
        'usrusazlap12' = @{
            Name           = 'usrusazlap12'
            SamAccountName = 'usrusazlap12'
            DisplayName    = 'usrusazlap12'
            Description    = 'standard user laptop build'
            Path           = "OU=Computers,OU=Corp,$DomainDN"
        }
        'usrusnjlap20' = @{
            Name           = 'usrusnjlap20'
            SamAccountName = 'usrusnjlap20'
            DisplayName    = 'usrusnjlap20'
            Description    = 'standard user laptop build'
            Path           = "OU=Computers,OU=Corp,$DomainDN"
        }
        'usrusnjlap22' = @{
            Name           = 'usrusnjlap22'
            SamAccountName = 'usrusnjlap22'
            DisplayName    = 'usrusnjlap22'
            Description    = 'standard user laptop build'
            Path           = "OU=Computers,OU=Corp,$DomainDN"
        }
        'usrusnjwks23' = @{
            Name           = 'usrusnjwks23'
            SamAccountName = 'usrusnjwks23'
            DisplayName    = 'usrusnjwks23'
            Description    = 'standard user workstation build'
            Path           = "OU=Computers,OU=Corp,$DomainDN"
        }
    }
}

# --- Active Directory sites, subnets, and site links ---------------------
function Get-LabSiteDefinitions {
    [CmdletBinding()]
    param()

    # Site definitions also own their associated subnet settings. The subnet
    # getter projects those fields; do not repeat that data in another list.
    # SamAccountName is reference metadata, NOT an AD site attribute to write.
    # No user-dependent Orphan expression or site-change action is activated.
    @(
        @{
            Name              = 'SemperisLabs'
            SamAccountName    = 'SemperisLabs'
            DisplayName       = 'SemperisLabs'
            Description       = 'AD site for Semperis Labs'
            Location          = 'USA-TX-Labs'
            SubnetName        = '10.3.22.0/24'
            SubnetDescription = 'AD subnet for Semperis Labs'
            SubnetLocation    = 'USA-TX-Labs'
        }
        @{
            Name              = 'Semperis-Devs'
            SamAccountName    = 'Semperis-Devs'
            DisplayName       = 'Semperis Devs'
            Description       = 'restricted site for devs'
            SubnetName        = '10.4.22.0/25'
            SubnetDescription = 'AD subnet for devs'
            # Location and SubnetLocation are omitted: leave them unmanaged.
        }
    )
}

function Get-LabSubnetDefinitions {
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$MyADSite = '',
        [AllowEmptyCollection()][object[]]$SiteDefinitions = @()
    )

    # Name is the required IPv4/IPv6 network prefix, not a display label.
    # Site, Location and Description are optional. Repeated locations are valid.
    # An explicit blank or $null clears an existing value; omit a key to leave
    # that property unmanaged. In particular, Site = '' removes a site link.
    # Nonblank Site accepts an existing site name or DN. Missing sites cause
    # that entire subnet to be warned and skipped; sites are not created here.
    # Nothing is deleted when a definition is removed. Overlap is allowed.
    return @(
        @{
            Name        = '10.0.0.0/8'
            Site        = ''
            Location    = 'Lab-USA-All'
            Description = 'Primary Lab Infrastructure Network'
        }
        @{
            Name        = '172.16.32.0/20'
            Site        = ''
            Location    = 'Lab-USA-CA'
            Description = 'Special demo lab subnet'
        }
        @{
            Name        = '10.222.0.0/16'
            Site        = ''
            Location    = 'Lab-USA-East'
            Description = 'Special Devices Infrastructure Network'
        }
        @{
            Name        = '10.111.0.0/16'
            Site        = ''
            Location    = 'Lab-EMEA-ES'
            Description = 'test subnet 0002'
        }
        @{
            Name        = '10.112.0.0/16'
            Site        = ''
            Location    = 'Lab-EMEA-ES'
            Description = 'test subnet 0002'
        }
        @{
            Name        = '111.2.5.0/24'
            Site        = ''
            Location    = 'USA-TX-Labs'
            Description = 'Lab subnet in TX'
        }
        @{
            Name        = '111.2.6.0/24'
            Site        = ''
            Location    = 'USA-TX-Dallas-Labs'
            Description = 'Lab subnet in Dallas,TX'
        }
        @{
            Name        = '192.168.0.0/16'
            Site        = ''
            Location    = 'Lab-USA-TX'
            Description = 'Primary Demo Lab Infrastructure Network'
        }
        @{
            Name        = '192.168.57.0/24'
            Site        = ''
            Location    = 'Lab-USA-AZ'
            Description = 'Special DMZ network'
        }
        # Discovery is performed by Invoke-Main, not by this data getter.
        # Both definitions remain present when discovery fails; a blank Site
        # creates an unlinked subnet or clears an existing site link.
        @{
            Name        = '111.111.4.0/24'
            Site        = $MyADSite
            Location    = 'USA-TX-Labs'
            Description = 'test subnet added via script'
        }
        @{
            Name        = '111.111.5.0/24'
            Site        = $MyADSite
            Location    = 'USA-TX-Labs'
            Description = 'test subnet added via script'
        }
        # Project associated subnets from the authoritative site definitions.
        foreach ($siteDefinition in $SiteDefinitions) {
            $subnetDefinition = @{
                Name        = $siteDefinition.SubnetName
                Site        = $siteDefinition.Name
                Description = $siteDefinition.SubnetDescription
            }
            if ($siteDefinition.Contains('SubnetLocation')) {
                $subnetDefinition['Location'] = $siteDefinition.SubnetLocation
            }
            $subnetDefinition
        }
    )
}

function Get-LabSiteLinkDefinitions {
    [CmdletBinding()]
    param()

    # Baseline IP site links. SitesIncluded is the exact managed membership.
    # Unlisted links (including DEFAULTIPSITELINK) are never modified.
    # Schedule, options, description and other attributes remain unmanaged.
    @(
        @{
            Name                          = 'SemperisLabs-SemperisDevs'
            SitesIncluded                 = @('SemperisLabs', 'Semperis-Devs')
            Cost                          = 7
            ReplicationFrequencyInMinutes = 15
        }
    )
}

# --- DNS zones and records (baseline; all A records are static) ----------
function Get-LabDnsZoneDefinitions {
    [CmdletBinding()]
    param()

    # Order matters: the forward zone first, then all reverse zones, before A/PTRs.
    # Forest means all DNS servers in the forest (ForestDnsZones partition).
    # EnsureUnsigned applies only to the expressly managed forward zone.
    return @(
        @{ Name='specialsite.lab'; NetworkId='';               ReplicationScope='Forest'; DynamicUpdate='NonsecureAndSecure'; EnsureUnsigned=$true }
        @{ Name='172.in-addr.arpa'; NetworkId='172.0.0.0/8';    ReplicationScope='Forest'; DynamicUpdate='NonsecureAndSecure'; EnsureUnsigned=$false }
        @{ Name='168.192.in-addr.arpa'; NetworkId='192.168.0.0/16'; ReplicationScope='Forest'; DynamicUpdate='NonsecureAndSecure'; EnsureUnsigned=$false }
        @{ Name='10.in-addr.arpa';  NetworkId='10.0.0.0/8';     ReplicationScope='Forest'; DynamicUpdate='NonsecureAndSecure'; EnsureUnsigned=$false }
        @{ Name='6.6.6.in-addr.arpa'; NetworkId='6.6.6.0/24';      ReplicationScope='Forest'; DynamicUpdate='NonsecureAndSecure'; EnsureUnsigned=$false }
    )
}

function Get-LabDnsRecordDefinitions {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$DomainDNSRoot)

    # DomainDNSRoot is the current computer's AD domain, including a child domain.
    # Missing PTR zones (notably 11.x) warn; no unspecified zones are created.
    # Existing main-domain zone settings are never changed by these records.
    # TTLMinutes is MINUTES, not seconds: 3600 minutes = 60 hours.
    # Reset deadhost02 to its normal 60-minute baseline before each demo.
    # PtrTTLSeconds manages only the associated PTR TTL, independently of A.
    # Reset fakehost02 PTR to one hour before the 31-second synthetic change.
    # AclResetSamAccountName removes this user's explicit node ACEs; inherited
    # rights and orphaned/unknown SIDs cannot safely be removed here.
    return @(
        @{ ZoneName='specialsite.lab'; Name='mylabhost01'; IPv4Address='172.111.10.11'; Static=$true; CreatePtr=$true; TTLMinutes=3600 }
        @{ ZoneName='specialsite.lab'; Name='mylabhost02'; IPv4Address='172.111.10.12'; Static=$true; CreatePtr=$true; TTLMinutes=3600 }
        @{ ZoneName='specialsite.lab'; Name='mylabhost03'; IPv4Address='172.111.10.13'; Static=$true; CreatePtr=$true; TTLMinutes=3600 }
        @{ ZoneName='specialsite.lab'; Name='mylabhost04'; IPv4Address='172.111.10.14'; Static=$true; CreatePtr=$true; TTLMinutes=3600 }
        @{ ZoneName=$DomainDNSRoot; Name='deadhost01'; IPv4Address='172.18.11.11'; Static=$true; CreatePtr=$true }
        @{ ZoneName=$DomainDNSRoot; Name='deadhost02'; IPv4Address='172.18.11.12'; Static=$true; CreatePtr=$true; TTLMinutes=60 }
        @{ ZoneName=$DomainDNSRoot; Name='junkie222';  IPv4Address='11.22.33.222'; Static=$true; CreatePtr=$true; AclResetSamAccountName='AppAdminIII' }
        @{ ZoneName=$DomainDNSRoot; Name='fakehost01'; IPv4Address='6.6.6.111'; Static=$true; CreatePtr=$true }
        @{ ZoneName=$DomainDNSRoot; Name='fakehost02'; IPv4Address='6.6.6.222'; Static=$true; CreatePtr=$true; PtrTTLSeconds=3600 }
    )
}

function Get-LabDnsADChangeDefinitions {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$DomainDNSRoot)

    # Ordered, purposeful synthetic activity. TTLMinutes uses MINUTES;
    # TTLSeconds uses SECONDS for the expressly configured reverse PTR.
    # DeleteA retains its associated PTR; DeletePtr retains its forward A.
    # Read/Write means GenericRead | GenericWrite on this dnsNode only.
    return @(
        @{ Action='DeleteA'; ZoneName='specialsite.lab'; Name='mylabhost03'; IPv4Address='172.111.10.13' }
        @{ Action='SetTTL'; ZoneName='specialsite.lab'; Name='mylabhost04'; IPv4Address='172.111.10.14'; TTLMinutes=1 }
        @{ Action='SetAddress'; ZoneName=$DomainDNSRoot; Name='junkie222'; OldIPv4Address='11.22.33.222'; IPv4Address='11.22.33.111'; Static=$true }
        @{ Action='SetTTL'; ZoneName=$DomainDNSRoot; Name='deadhost02'; IPv4Address='172.18.11.12'; TTLMinutes=7200 }
        @{ Action='GrantAcl'; ZoneName=$DomainDNSRoot; Name='junkie222'; IPv4Address='11.22.33.111'; SamAccountName='AppAdminIII' }
        @{ Action='DeletePtr'; ZoneName='6.6.6.in-addr.arpa'; Name='111'; PtrDomainName=('fakehost01.' + $DomainDNSRoot) }
        @{ Action='SetPtrTTL'; ZoneName='6.6.6.in-addr.arpa'; Name='222'; PtrDomainName=('fakehost02.' + $DomainDNSRoot); TTLSeconds=31 }
    )
}

# --- WMI filters (baseline, no automatic GPO association) ----------------
function Get-LabWmiFilterDefinitions {
    [CmdletBinding()]
    param()

    # Keys are stable references; Name is the visible GPMC filter name, NOT
    # the object's CN. AD stores each filter under a separate GUID-shaped CN.
    #
    # Later synthetic AD changes can reference the verified baseline objects
    # by the same stable key used in the definitions below. For example:
    # $script:LabWmiFilterObjects['HyperVVirtualMachines'].Name
    # $script:LabWmiFilterObjects['HyperVVirtualMachines'].ObjectGUID
    #
    # Name is the verified visible filter name. ObjectGUID identifies the AD
    # object and remains stable if that filter is renamed; prefer it for
    # targeted lookups and changes rather than constructing a DN from Name.
    # This object map is populated after successful baseline provisioning.
    # Check that the key exists before referencing it in later operations.
    # Refresh the object by GUID before future, explicitly requested changes;
    # cached names and other properties may be stale after a change.
    #
    # The separate definitions map contains desired baseline values:
    # $script:LabWmiFilterDefinitions['HyperVVirtualMachines'].Name
    # FilterId is the GPO-facing filter ID, distinct from the AD ObjectGUID:
    # $script:LabWmiFilterObjects['HyperVVirtualMachines'].FilterId
    # All queries in a filter are ANDed; put one SELECT in each array entry.
    # Preserve legacy targets as requested; no newer OS filters are invented.
    # Blank descriptions are managed blanks (clear msWMI-Parm1 on rerun).
    # The source VM query had a missing quote and a duplicate Parallels term;
    # those are corrected. Workstation queries are split into two ANDed entries.
    $definitions = [ordered]@{
        HyperVVirtualMachines = @{
            Name        = 'Hyper-V Virtual Machines'
            Description = 'Microsoft Hyper-V 2.0 AND 3.0'
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM Win32_ComputerSystem WHERE Model = "Virtual Machine"'
            )
        }
        VMwareVirtualMachines = @{
            Name        = 'VMware Virtual Machines'
            Description = 'VMware Fusion, Workstation AND ESXi'
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM Win32_ComputerSystem WHERE Model LIKE "VMware%"'
            )
        }
        ParallelsVirtualMachines = @{
            Name        = 'Parallels Virtual Machines'
            Description = 'OSX Parallels Virtual Machine'
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM Win32_ComputerSystem WHERE Model LIKE "Parallels%"'
            )
        }
        VirtualBoxVirtualMachines = @{
            Name        = 'VirtualBox Virtual Machines'
            Description = 'Oracle VirtualBox Virtual Machine'
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM Win32_ComputerSystem WHERE Model LIKE "VirtualBox%"'
            )
        }
        XenVirtualMachines = @{
            Name        = 'Xen Virtual Machines'
            Description = 'Citrix Xen Server Virtual Machine'
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM Win32_ComputerSystem WHERE Model LIKE "HVM dom%"'
            )
        }
        VirtualMachines = @{
            Name        = 'Virtual Machines'
            Description = 'Virtual Machine from Hyper-V, VMware, Xen, Parallels OR VirtualBox'
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM Win32_ComputerSystem WHERE (Model LIKE "Parallels%" OR Model LIKE "HVM dom%" OR Model LIKE "VirtualBox%" OR Model LIKE "VMware%" OR Model = "Virtual Machine")'
            )
        }
        JavaInstalled = @{
            Name        = 'Java is Installed'
            Description = 'Oracle Java'
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM win32_Directory WHERE (name="c:\\Program Files\\Java" OR name="c:\\Program Files (x86)\\Java")'
            )
        }
        JavaJre7Installed = @{
            Name        = 'Java JRE 7 is Installed'
            Description = 'Oracle Java JRE 7'
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM win32_Directory WHERE (name="c:\\Program Files\\Java\\jre7" OR name="c:\\Program Files (x86)\\Java\\jre7")'
            )
        }
        JavaJre6Installed = @{
            Name        = 'Java JRE 6 is Installed'
            Description = 'Oracle Java JRE 6'
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM win32_Directory WHERE (name="c:\\Program Files\\Java\\jre6" OR name="c:\\Program Files (x86)\\Java\\jre6")'
            )
        }
        Workstation32Bit = @{
            Name        = 'Workstation 32-bit'
            Description = ''
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'Select * from WIN32_OperatingSystem WHERE ProductType=1'
                'Select * from Win32_Processor WHERE AddressWidth = "32"'
            )
        }
        Workstation64Bit = @{
            Name        = 'Workstation 64-bit'
            Description = ''
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'Select * from WIN32_OperatingSystem WHERE ProductType=1'
                'Select * from Win32_Processor WHERE AddressWidth = "64"'
            )
        }
        Workstations = @{
            Name        = 'Workstations'
            Description = ''
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM Win32_OperatingSystem WHERE ProductType = "1"'
            )
        }
        DomainControllers = @{
            Name        = 'Domain Controllers'
            Description = ''
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM Win32_OperatingSystem WHERE ProductType = "2"'
            )
        }
        Servers = @{
            Name        = 'Servers'
            Description = ''
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM Win32_OperatingSystem WHERE ProductType = "3"'
            )
        }
        WindowsXP = @{
            Name        = 'Windows XP'
            Description = ''
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM Win32_OperatingSystem WHERE (Version LIKE "5.1%" OR Version LIKE "5.2%") AND ProductType = "1"'
            )
        }
        WindowsVista = @{
            Name        = 'Windows Vista'
            Description = ''
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.0%" AND ProductType = "1"'
            )
        }
        Windows7 = @{
            Name        = 'Windows 7'
            Description = ''
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.1%" AND ProductType = "1"'
            )
        }
        Windows8 = @{
            Name        = 'Windows 8'
            Description = ''
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.2%" AND ProductType = "1"'
            )
        }
        WindowsServer2003 = @{
            Name        = 'Windows Server 2003'
            Description = ''
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "5.2%" AND ProductType = "3"'
            )
        }
        WindowsServer2008 = @{
            Name        = 'Windows Server 2008'
            Description = ''
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.0%" AND ProductType = "3"'
            )
        }
        WindowsServer2008R2 = @{
            Name        = 'Windows Server 2008 R2'
            Description = ''
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.1%" AND ProductType = "3"'
            )
        }
        WindowsServer2012 = @{
            Name        = 'Windows Server 2012'
            Description = ''
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.2%" AND ProductType = "3"'
            )
        }
        WindowsVistaAndServer2008 = @{
            Name        = 'Windows Vista AND Windows Server 2008'
            Description = ''
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.0%" AND ProductType<>"2"'
            )
        }
        WindowsServer2003And2008 = @{
            Name        = 'Windows Server 2003 AND Windows Server 2008'
            Description = ''
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM Win32_OperatingSystem WHERE (Version LIKE "5.2%" OR Version LIKE "6.0%") AND ProductType="3"'
            )
        }
        WindowsXPAnd2003 = @{
            Name        = 'Windows XP AND 2003'
            Description = ''
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "5.%" AND ProductType<>"2"'
            )
        }
        Windows8And2012 = @{
            Name        = 'Windows 8 AND 2012'
            Description = ''
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.2%" AND ProductType<>"2"'
            )
        }
        InternetExplorer10 = @{
            Name        = 'Internet Explorer 10'
            Description = ''
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM CIM_Datafile WHERE (Name="c:\\Program Files (x86)\\Internet Explorer\\iexplore.exe" OR Name="c:\\Program Files\\Internet Explorer\\iexplore.exe") AND version LIKE "10.%"'
            )
        }
        InternetExplorer9 = @{
            Name        = 'Internet Explorer 9'
            Description = ''
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM CIM_Datafile WHERE (Name="c:\\Program Files (x86)\\Internet Explorer\\iexplore.exe" OR Name="c:\\Program Files\\Internet Explorer\\iexplore.exe") AND version LIKE "9.%"'
            )
        }
        InternetExplorer8 = @{
            Name        = 'Internet Explorer 8'
            Description = ''
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM CIM_Datafile WHERE (Name="c:\\Program Files (x86)\\Internet Explorer\\iexplore.exe" OR Name="c:\\Program Files\\Internet Explorer\\iexplore.exe") AND version LIKE "8.%"'
            )
        }
        InternetExplorer7 = @{
            Name        = 'Internet Explorer 7'
            Description = ''
            Namespace   = 'root\CIMv2'
            Queries     = @(
                'SELECT * FROM CIM_Datafile WHERE (Name="c:\\Program Files (x86)\\Internet Explorer\\iexplore.exe" OR Name="c:\\Program Files\\Internet Explorer\\iexplore.exe") AND version LIKE "7.%"'
            )
        }
    }
    return ,$definitions
}

# --- Group Policy Objects, settings, and links ---------------------------
function Get-LabGpoDefinition {
    [CmdletBinding()]
    param()

    # This is a deliberately mixed-security lab baseline, NOT CIS compliance.
    # Requested values are preserved, including insecure guest SMB access.
    # DetectionFrequency = 82 is retained even though it is outside the usual
    # Windows Update detection-frequency range; the enable flag is 0.
    #
    # Storage selects RegistryPolicy (Registry.pol) or SecurityOptions
    # (native GptTmpl.inf). All desired data stays in this editable section.
    # Only explicitly listed SecurityOptions values are migrated out of old
    # Registry.pol entries, and only AFTER native verification succeeds.
    # No link targets, replication wait or delayed changes are defined here.
    #
    # Key is the registry key ONLY; ValueName is a separate named value under
    # that key. Type is its registry type, and Value is its desired data.
    #
    # VALUE DATA REFERENCE: each record below lists its supported choices.
    # Numeric codes are decimal. A value of 0 is a real setting, NOT an
    # instruction to leave the policy unconfigured. There is no numeric
    # Not Configured / Not Defined sentinel accepted by these definitions.
    #
    # Removing/commenting a record only stops management of that record;
    # it does NOT remove an existing Registry.pol or native INF setting.
    # Use a separate explicit GPO edit to clear an already-configured value.
    #
    # Options document registry meanings, not guaranteed OS support. Review
    # the target Windows version, installed features and security impact.
    #
    # Optional GpoSettingsPath and GpoDisplayName are English editor reference
    # labels only, not proof of installed templates or a native policy state.
    # Leave either blank or omit it to display <Unknown> independently.
    #
    # Paths include Computer Configuration\Policies for the domain GPO editor.
    # Windows Update subfolders depend on ADMX version; older templates may
    # list Automatic Updates detection frequency directly under Windows Update.
    # Both DetectionFrequency values below belong to that same policy setting.
    #
    # Native settings are independently verified in the GPO security report.
    # Do not concurrently edit GPO settings while the script runs. Existing
    # links are preserved. ApplyWhenLinked defaults False for this GPO.
    #
    # BackupRoot contains timestamped GPO backups for manual recovery; no
    # automatic rollback or recursive cleanup of those backups is performed.

    # Mapping references:
    # https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-lanmanworkstation
    # https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update
    # https://learn.microsoft.com/en-us/windows/deployment/update/waas-wu-settings
    # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj852268(v=ws.11)

    # True permits settings updates when linked; False requires no links.
    # This never creates, removes, enables, disables or reorders GPO links.
    $ApplyWhenLinked = $False

    return @{
        Name = 'CIS Benchmark Windows Server Policy GPO'
        ApplyWhenLinked = $ApplyWhenLinked
        BackupRoot = (Join-Path $env:ProgramData 'Semperis\LabGpoBackups')
        Warnings = @(
            'This is a lab baseline, not CIS-compliant: insecure guest SMB access is enabled; Windows Update DetectionFrequency=82 is ignored (DetectionFrequencyEnabled=0).'
            'SMBv1 client/server disablement requires a target restart after policy application. LanmanWorkstation (Workstation service) DependOnService replaces its full dependency list to exclude the SMBv1 client driver; review target-specific dependencies before linking. No features, services or restarts are changed locally.'
        )
        Settings = @(
            # Security Event Log maximum size: units are KB, NOT bytes.
            # Administrative Templates / Event Log Service / Security uses
            # EventLog.admx Channel_LogMaxSize_2, not the legacy Event Log UI.
            # Supported Security-policy range: 20480..2147483647 KB.
            # 1048576 KB = 1024 MB = 1 GB; synthetic changes use 20480 KB.
            # This unlinked demo GPO is not intended for policy application.
            # Writes only the GPO Registry.pol value; never resizes a local log.
            # Reference: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-eventlogservice#specifymaximumfilesizesecuritylog
            @{
                Key       = 'HKLM\Software\Policies\Microsoft\Windows\EventLog\Security'
                ValueName = 'MaxSize'
                Storage   = 'RegistryPolicy'
                GpoSettingsPath = 'Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Security'
                GpoDisplayName  = 'Specify the maximum log file size (KB)'
                Type      = 'DWord'
                # Enabled with an explicit size; 0 is not a supported size.
                # Baseline: 1048576 KB. Minimum synthetic value: 20480 KB.
                Value     = 1048576
            }

            # "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" AllowInsecureGuestAuth = 0 | 1
            #
            # This policy setting determines if the SMB client will allow insecure guest logons to an SMB server.
            #
            # Enabling this policy permits insecure guest logons, subject to other SMB requirements.
            # If not configured, behavior depends on Windows version/edition and other policies;
            # do not assume all modern systems permit guest access by default.
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
            @{
                Key       = 'HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation'
                ValueName = 'AllowInsecureGuestAuth'
                Storage   = 'RegistryPolicy'
                GpoSettingsPath = 'Computer Configuration\Policies\Administrative Templates\Network\Lanman Workstation'
                GpoDisplayName  = 'Enable insecure guest logons'
                Type      = 'DWord'
                # Value data options (DWord):
                #   0 = Disabled: reject insecure SMB guest logons (more secure).
                #   1 = Enabled: permit insecure SMB guest logons (current lab value).
                # Guest access may still fail if SMB signing/encryption is required.
                # Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/guest-access-in-smb2-is-disabled-by-default
                Value     = 1
            }

            # Disable SMBv1 on both the server and client; leave SMBv2/v3 alone.
            # Registry.pol settings, NOT native Security Options or Preferences.
            # Without the optional SecGuide ADMX, GPMC may list these under
            # Extra Registry Settings instead of named Administrative Templates.
            # Reference: https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
            # IMPORTANT: DependOnService replaces the complete dependency list
            # on targets when applied. Review custom/OS-specific dependencies
            # before manually linking this lab GPO. The list below follows the
            # Microsoft SMBv1-disable guidance; MRxSMB10 is deliberately absent.
            # No optional feature is removed and no local service is changed.
            # Target systems require a restart after policy application.
            @{
                Key       = 'HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters'
                ValueName = 'SMB1'
                Storage   = 'RegistryPolicy'
                GpoSettingsPath = 'Computer Configuration\Policies\Administrative Templates\MS Security Guide (SecGuide ADMX required; otherwise Extra Registry Settings)'
                GpoDisplayName  = 'Configure SMB v1 server: Disabled'
                Type      = 'DWord'
                # Value data options (DWord):
                #   0 = Disable the SMBv1 server protocol (current; recommended).
                #   1 = Enable the SMBv1 server protocol if its feature is installed.
                # This does not control SMBv2/v3 or install/remove Windows features.
                # Restart targets after application; absence is not an enable code.
                Value     = 0
            }
            @{
                Key       = 'HKLM\System\CurrentControlSet\Services\LanmanWorkstation'
                ValueName = 'DependOnService'
                Storage   = 'RegistryPolicy'
                GpoSettingsPath = 'Computer Configuration\Policies\Administrative Templates\Extra Registry Settings (direct Registry.pol entry)'
                GpoDisplayName  = 'SMBv1 client dependencies: exclude MRxSMB10'
                Type      = 'MultiString'
                # Value data options (MultiString; no fixed enumeration):
                # Use an array of actual service/driver key names, NOT display names.
                # Each entry must be valid for the target OS; preserve custom needs.
                # SMBv1-disabled example (current Microsoft guidance):
                #   @('Bowser', 'MRxSmb20', 'NSI')
                # Legacy SMBv1-capable example (reference only; less secure):
                #   @('Bowser', 'MRxSmb10', 'MRxSmb20', 'NSI')
                # MRxSmb10 is the SMBv1 client redirector driver.
                # Do NOT add MRxSmb10 while its Start value is 4: that leaves an
                # unsatisfied dependency and can prevent Workstation from starting.
                # Re-enabling SMBv1 also needs its installed feature and client/server
                # controls reviewed; changing this array alone does not enable it.
                # There is no universal list of all custom dependency names. Check
                # each target's existing DependOnService before applying this GPO.
                # This writer REPLACES the list, not merges it, and rejects @(),
                # null/blank elements and a scalar comma-separated string.
                # Even one dependency must use an array, for example @('NSI'); that
                # is syntax guidance, NOT a recommended Workstation configuration.
                # Bowser = Browser Support Driver (the name is intentional).
                # MRxSmb20 = SMB 2.x/3.x client redirector driver.
                # NSI = Network Store Interface service.
                Value     = @('Bowser', 'MRxSmb20', 'NSI')
            }
            @{
                Key       = 'HKLM\System\CurrentControlSet\Services\mrxsmb10'
                ValueName = 'Start'
                Storage   = 'RegistryPolicy'
                GpoSettingsPath = 'Computer Configuration\Policies\Administrative Templates\MS Security Guide (SecGuide ADMX required; otherwise Extra Registry Settings)'
                GpoDisplayName  = 'Configure SMB v1 client driver: Disable driver (recommended)'
                Type      = 'DWord'
                # Value data options (DWord; Windows service/driver Start codes):
                #   0 = Boot: load via the boot loader (drivers only).
                #   1 = System: load during I/O subsystem initialization (drivers).
                #   2 = Automatic: start via Service Control Manager at startup.
                #   3 = Demand/manual: start when requested, not disabled.
                #   4 = Disabled: do not load (current SMBv1 hardening value).
                # Codes 0/1 are generic driver codes, NOT recommended MRxSMB10
                # alternatives. Use only modes supported by this driver/target OS.
                # Choosing 2/3 allows startup; it does not install the SMBv1 feature
                # or restore Workstation dependencies. Review all SMBv1 records
                # together. Target restart is required after policy application.
                # Reference: https://learn.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree
                Value     = 4
            }

            # Windows Update: configure the supplied initial values exactly.
            @{
                Key       = 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
                ValueName = 'DetectionFrequencyEnabled'
                Storage   = 'RegistryPolicy'
                GpoSettingsPath = 'Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update\Manage updates offered from Windows Server Update Service'
                GpoDisplayName  = 'Automatic Updates detection frequency'
                Type      = 'DWord'
                # Value data options (DWord):
                #   0 = Disabled: ignore custom DetectionFrequency; use the normal
                #       22-hour detection interval (current lab value).
                #   1 = Enabled: use DetectionFrequency below; select 1-22 hours.
                # These two records represent ONE Windows Update policy. WSUS
                # location must be configured; disabling Configure Automatic
                # Updates makes this policy ineffective. No prerequisites are set
                # by these two records alone.
                # Reference: https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/4-configure-group-policy-settings-for-automatic-updates
                Value     = 0
            }
            @{
                Key       = 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
                ValueName = 'DetectionFrequency'
                Storage   = 'RegistryPolicy'
                GpoSettingsPath = 'Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update\Manage updates offered from Windows Server Update Service'
                GpoDisplayName  = 'Automatic Updates detection frequency'
                Type      = 'DWord'
                # Value data options (DWord; hours): every integer from 1 to 22.
                #   1 = shortest supported interval; 22 = normal/default interval.
                #   0 and values above 22 are NOT supported policy selections.
                # Windows randomizes the actual wait to 80-100% of this interval.
                # Requires DetectionFrequencyEnabled = 1 and WSUS prerequisites.
                # Current 82 is deliberately preserved lab data, NOT a valid
                # supported interval; do not enable the custom flag with 82.
                # The script checks DWORD shape/read-back, not Windows Update's
                # semantic range. Edit this to 1-22 before enabling the policy.
                # Reference: https://learn.microsoft.com/de-de/security-updates/windowsupdateservices/18127499
                Value     = 82
            }

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
            @{
                Key       = 'HKLM\System\CurrentControlSet\Control\Lsa'
                ValueName = 'forceguest'
                Storage   = 'SecurityOptions'
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options'
                GpoDisplayName  = 'Network access: Sharing and security model for local accounts'
                Type      = 'DWord'
                # Value data options (DWord):
                #   0 = Classic - local users authenticate as themselves (current).
                #   1 = Guest only - local users authenticate as Guest.
                # This concerns network access using LOCAL accounts, not the
                # authentication method for domain accounts. Keep Classic for DCs.
                # Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/3c837e92-016e-4148-86e5-b4f0381a757f
                Value     = 0
            }

            #   DESCRIPTION: NTLM sessions that are allowed to fall back to Null (unauthenticated) sessions may gain
            #                unauthorized access.
            #   Computer Configuration\Policies\Windows Settings\Security Settings\LocalPolicies\Security Options\Network security: Allow LocalSystem NULL session fallback
            #   The recommended state for this setting is: Disabled
            #   HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0:allownullsessionfallback
            #   IMPACT: Any applications that require NULL sessions for LocalSystem will not work as designed.
            @{
                Key       = 'HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0'
                ValueName = 'allownullsessionfallback'
                Storage   = 'SecurityOptions'
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options'
                GpoDisplayName  = 'Network security: Allow LocalSystem NULL session fallback'
                Type      = 'DWord'
                # Value data options (DWord):
                #   0 = Disabled: disallow LocalSystem NULL-session fallback
                #       compatibility behavior (current; more secure).
                #   1 = Enabled: allow compatibility behavior using an unprotected,
                #       well-known session key; this does NOT make NULL sessions safe.
                # Older applications can be affected when disabled. This is not
                # a blanket switch controlling all anonymous network access.
                # Reference: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj852238(v=ws.11)
                Value     = 0
            }

            #   The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM
            #   DESCRIPTION: The Kerberos v5 authentication protocol is the default for authentication of users who are
            #                logging on to domain accounts. NTLM, which is less secure, is retained in later Windows
            #                versions for compatibility with clients and servers that are running earlier versions of
            #                Windows or applications that still use it. It is also used to authenticate logons to
            #                stand-alone computers that are running later versions.
            #   Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options ->
            #   Recommended to set "Network Security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM".
            # POLICY LOCATION: Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options
            # REGISTRY LOCATION: HKLM\System\CurrentControlSet\Control\Lsa:LmCompatibilityLevel
            #
            #   Registry Path: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa:LmCompatibilityLevel  REG_DWORD   value: 5
            @{
                Key       = 'HKLM\System\CurrentControlSet\Control\Lsa'
                ValueName = 'LmCompatibilityLevel'
                Storage   = 'SecurityOptions'
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options'
                GpoDisplayName  = 'Network security: LAN Manager authentication level'
                Type      = 'DWord'
                # Value data options (DWord; complete level list):
                #   0 = Send LM & NTLM responses.
                #   1 = Send LM & NTLM; use NTLMv2 session security if negotiated.
                #   2 = Send NTLM response only (NTLMv1, NOT NTLMv2-only).
                #   3 = Send NTLMv2 response only; DCs still accept LM/NTLMv1.
                #   4 = Send NTLMv2 response only; DCs refuse LM, accept NTLMv1/v2.
                #   5 = Send NTLMv2 response only; DCs refuse LM & NTLMv1 (current).
                # Levels 0-3 allow DCs to accept LM, NTLMv1 and NTLMv2 responses.
                # NTLMv2 session security (level 1) is NOT NTLMv2 authentication.
                # Kerberos remains the domain default where negotiable; this is
                # not a Kerberos-only policy and does not disable NTLMv2.
                # Lower levels weaken this baseline and may be unsupported on
                # newer Windows releases; consult the target OS before changing.
                # Reference: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level
                Value     = 5
            }

            #   Prevent the storage of the LAN Manager hash of passwords
            #   DESCRIPTION: The LAN Manager hash uses a weak encryption algorithm and there are several tools available
            #                that use this hash to retrieve account passwords. This setting controls whether a LAN Manager
            #                hash of the password is stored in the SAM the next time the password is changed.
            #   Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: Do not store LAN Manager hash value on next password change" to "Enabled".
            #   Registry Path: HKLM\SYSTEM\CurrentControlSet\Control\Lsa:NoLMHash    REG_DWORD   Value: 0x00000001 (1)
            @{
                Key       = 'HKLM\System\CurrentControlSet\Control\Lsa'
                ValueName = 'NoLMHash'
                Storage   = 'SecurityOptions'
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options'
                GpoDisplayName  = 'Network security: Do not store LAN Manager hash value on next password change'
                Type      = 'DWord'
                # Value data options (DWord):
                #   0 = Disabled: do not prohibit LM-hash storage via this policy
                #       (less secure; OS/password conditions still govern storage).
                #   1 = Enabled: do not store an LM hash at the NEXT password
                #       change (current; recommended).
                # Enabling this is not an immediate purge of all existing hashes;
                # accounts need subsequent password changes for the new behavior.
                # Older clients/applications requiring LM may stop authenticating.
                # Reference: https://learn.microsoft.com/en-us/azure/governance/policy/samples/guest-configuration-baseline-windows
                Value     = 1
            }
        )
    }
}

function Get-LabQuestionableGpoDefinition {
    [CmdletBinding()]
    param()

    # Deliberately questionable LAB policy; never deploy to production.
    # ApplyWhenLinked defaults True; existing links are not edited.
    # Same backup, read-before-write and native verification as the first GPO.
    # Edit the Value beside each policy; omitted records remain unmanaged.
    # SecurityOptions uses [Registry Values] in GptTmpl.inf, NOT Registry.pol.
    # RegistryPolicy uses GroupPolicy cmdlets to read/write Registry.pol
    # for Administrative Templates, separately from native Security Options.
    # AccountPolicy uses raw integers in its named native INF Section, NOT
    # registry keys, registry type prefixes or local secedit/net accounts.
    # Removing a record does not clear an already-defined policy.
    # True permits settings updates when linked; False requires no links.
    # This never creates, removes, enables, disables or reorders GPO links.
    $ApplyWhenLinked = $True

    return @{
        Name = 'Questionable GPO'
        ApplyWhenLinked = $ApplyWhenLinked
        BackupRoot = (Join-Path $env:ProgramData 'Semperis\LabGpoBackups')
        Warnings = @(
            'Questionable GPO is deliberately insecure lab content: NTLM level 3 still permits older inbound authentication, user tickets last 42 days, and reversible password encryption is enabled. Use only in isolated labs; linked changes may affect target systems.'
            'Baseline account lockout threshold is 10 failed logon attempts. Existing lockout duration and counter-reset window are not changed; linked settings may affect target accounts.'
            'LDAP server signing is explicitly None (not required), a DC-only setting. The separate Server 2025 enforcement policy can still require signing and is intentionally left unmanaged. If linked to DCs, changes can affect effective policy during normal processing.'
            'This script edits GPO settings without forcing policy refresh. Existing enabled links can apply these settings through normal policy processing. It does not reset passwords or directly change tickets or local settings on this host.'
        )
        Settings = @(
            @{
                Key       = 'HKLM\System\CurrentControlSet\Control\Lsa'
                ValueName = 'LmCompatibilityLevel'
                Storage   = 'SecurityOptions'
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options'
                GpoDisplayName  = 'Network security: LAN Manager authentication level'
                Type      = 'DWord'
                # 3 = Send NTLMv2 response only (requested). Unlike level 5,
                # this does NOT require DCs to refuse inbound LM and NTLMv1.
                # 0 = LM/NTLM; 1 = LM/NTLM with negotiated NTLMv2 session
                # security; 2 = NTLM only; 4 = NTLMv2/refuse LM;
                # 5 = NTLMv2/refuse LM and NTLMv1. Session security is not
                # the same as NTLMv2 authentication. Kerberos stays separate.
                Value     = 3
            }
            @{
                Section   = 'Kerberos Policy'
                ValueName = 'MaxTicketAge'
                Storage   = 'AccountPolicy'
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Kerberos Policy'
                GpoDisplayName  = 'Maximum lifetime for user ticket'
                Type      = 'Integer'
                # HOURS, not days: 42 days * 24 = 1008 hours (requested).
                # Range 0..99999 hours; 0 means no expiration, NOT undefined.
                # Default is 10 hours. Long lifetimes extend stolen-ticket
                # exposure. MaxRenewAge is a different policy, left unmanaged.
                Value     = 1008
            }
            @{
                Section   = 'Kerberos Policy'
                ValueName = 'MaxServiceAge'
                Storage   = 'AccountPolicy'
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Kerberos Policy'
                GpoDisplayName  = 'Maximum lifetime for service ticket'
                Type      = 'Integer'
                # MINUTES: 10 = ten minutes (requested; minimum permitted).
                # Native decimal field supports up to 99999; keep this at or
                # below the user-ticket lifetime after converting units.
                # Default is 600 minutes. Short lifetimes increase renewals.
                Value     = 10
            }
            @{
                Section   = 'System Access'
                ValueName = 'LockoutBadCount'
                Storage   = 'AccountPolicy'
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policy'
                GpoDisplayName  = 'Account lockout threshold'
                Type      = 'Integer'
                # Count of failed logon attempts, not a time or password-history
                # setting. 0 disables lockout; valid range is 0..999 attempts.
                # Baseline 10 locks on the tenth qualifying failed attempt.
                # Duration/reset-window settings are retained, not invented.
                # Synthetic activity later sets this to 100 when enabled.
                Value     = 10
            }
            @{
                Section   = 'System Access'
                ValueName = 'ClearTextPassword'
                Storage   = 'AccountPolicy'
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy'
                GpoDisplayName  = 'Store passwords using reversible encryption'
                Type      = 'Integer'
                # 1 = Enabled (requested; insecure); 0 = Disabled (recommended).
                # Reversible storage is effectively plaintext-equivalent.
                # If applied, storage changes require subsequent password
                # sets/changes; existing passwords are not converted here.
                Value     = 1
            }
            @{
                Key       = 'HKLM\Software\Policies\Microsoft\Windows\System'
                ValueName = 'BlockDomainPicturePassword'
                Storage   = 'RegistryPolicy'
                GpoSettingsPath = 'Computer Configuration\Policies\Administrative Templates\System\Logon'
                GpoDisplayName  = 'Turn off picture password sign-in'
                Type      = 'DWord'
                # 0 = Disabled (requested): do not block picture-password
                # sign-in with this policy. The policy name is a negative.
                # 1 = Enabled: block domain-user picture-password sign-in.
                # Zero is an explicit Disabled state, NOT Not Configured.
                # Availability still depends on OS support/other policies;
                # this does not create a picture password for any user.
                # Reference: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-credentialproviders#blockpicturepassword
                Value     = 0
            }
            @{
                Key       = 'HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services'
                ValueName = 'CreateEncryptedOnlyTickets'
                Storage   = 'RegistryPolicy'
                GpoSettingsPath = 'Computer Configuration\Policies\Administrative Templates\System\Remote Assistance'
                GpoDisplayName  = 'Allow only Windows Vista or later connections'
                Type      = 'DWord'
                # 0 = Disabled (requested): do not require Vista-or-later
                # Remote Assistance invitation encryption; permits older
                # connection compatibility when Remote Assistance is enabled.
                # 1 = Enabled: require improved invitation encryption.
                # Zero is an explicit Disabled state, NOT Not Configured.
                # This does NOT enable Remote Assistance, open its firewall,
                # change Remote Desktop/NLA, or affect unsolicited offers.
                # Reference: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-remoteassistance#ra_encryptedticketonly
                Value     = 0
            }
            @{
                Key       = 'HKLM\System\CurrentControlSet\Services\NTDS\Parameters'
                ValueName = 'LDAPServerIntegrity'
                Storage   = 'SecurityOptions'
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options'
                GpoDisplayName  = 'Domain controller: LDAP server signing requirements'
                Type      = 'DWord'
                # 1 = None (requested: signing is NOT required / disabled).
                # 2 = Require signing (recommended secure setting).
                # This policy uses None, not a Disabled radio button; use
                # DWORD 1, NOT 0 or removal, for an explicitly defined None.
                # Native INF entry is LDAPServerIntegrity=4,1 under its full
                # MACHINE registry path. Do not write this to Registry.pol.
                # DC-only: this does not force clients to use unsigned LDAP,
                # disable TLS, or change LDAP channel-binding requirements.
                # Server 2025+ has a separate signing enforcement policy that
                # can override None. That policy remains unmanaged here.
                # Reference: https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/ldap-channel-binding-and-ldap-signing-requirements---server-2025-updates/921536
                Value     = 1
            }
        )
    }
}

function Get-LabDspAuditingGpoDefinition {
    [CmdletBinding()]
    param()

    # Example requested from DSP 5.3 Installation Guide; created unlinked.
    # Computer-only: GpoStatus disables User Configuration (GPC flags=1).
    # Comment is the actual GPMC Comment, not just a script source comment.
    # ApplyWhenLinked defaults True so settings can be updated after linking.
    # Existing links are preserved; enabled links can affect lab targets.
    # SecurityOptions uses GptTmpl.inf and documents the real registry value.
    # AdvancedAudit uses native Machine\Microsoft\Windows NT\Audit\audit.csv;
    # these subcategories have GUIDs/bitmasks, NOT individual registry entries.
    # AuditFlags: 0=No Auditing, 1=Success, 2=Failure, 3=Success and Failure.
    # Requested entries are explicitly Success ONLY (Failure bit is not set).
    # Unlisted subcategories, audit options and per-user CSV rows are unmanaged.
    # No SACL changes, links, gpupdate or local auditpol configuration occur.
    # Directory Service Changes events also depend on suitable object SACLs.
    # Protocol references:
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/6494a0f2-8a16-40e2-b87d-328be7d732e0
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/ac9c8234-d2e8-455d-be76-f84244dd1e58
    # True permits settings updates when linked; False requires no links.
    # This never creates, removes, enables, disables or reorders GPO links.
    $ApplyWhenLinked = $True

    return @{
        Name = 'Special Change Auditing Activity Settings GPO'
        Comment = 'This is an example GPO for the auditing settings needed for Semperis DSP.'
        GpoStatus = 'UserSettingsDisabled'
        ApplyWhenLinked = $ApplyWhenLinked
        BackupRoot = (Join-Path $env:ProgramData 'Semperis\LabGpoBackups')
        Warnings = @(
            'ApplyWhenLinked defaults True for this example; the linked-update safeguard reports its current value. Enabled links may deliver these auditing settings to lab targets. User Configuration is disabled. No links or object SACLs are edited, and effective client policy is not verified here.'
            'Advanced audit records explicitly configure Success only, not Success and Failure. The override Security Option is enabled. Review the DSP guide and target environment before any separate deployment.'
        )
        Settings = @(
            @{
                Key       = 'HKLM\System\CurrentControlSet\Control\Lsa'
                ValueName = 'SCENoApplyLegacyAuditPolicy'
                Storage   = 'SecurityOptions'
                ReportValueType = 'BooleanOrNumber' # GPMC may serialize Enabled as true.
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options'
                GpoDisplayName  = 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings'
                Type      = 'DWord'
                # Native [Registry Values]: MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1
                # REG_DWORD 1 = Enabled; 0 = Disabled. Not Registry.pol.
                Value     = 1
            }
            @{
                ValueName = '{0CCE9239-69AE-11D9-BED3-505054503030}'
                Storage   = 'AdvancedAudit'
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Management'
                GpoDisplayName  = 'Audit Application Group Management'
                Type      = 'AuditFlags'
                # Native audit.csv, System target; no registry key/value.
                Value     = 1 # Success only; 2=Failure, 3=Success and Failure.
            }
            @{
                ValueName = '{0CCE9236-69AE-11D9-BED3-505054503030}'
                Storage   = 'AdvancedAudit'
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Management'
                GpoDisplayName  = 'Audit Computer Account Management'
                Type      = 'AuditFlags'
                # Native audit.csv, System target; no registry key/value.
                Value     = 1 # Success only; 2=Failure, 3=Success and Failure.
            }
            @{
                ValueName = '{0CCE9238-69AE-11D9-BED3-505054503030}'
                Storage   = 'AdvancedAudit'
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Management'
                GpoDisplayName  = 'Audit Distribution Group Management'
                Type      = 'AuditFlags'
                # Native audit.csv, System target; no registry key/value.
                Value     = 1 # Success only; 2=Failure, 3=Success and Failure.
            }
            @{
                ValueName = '{0CCE923A-69AE-11D9-BED3-505054503030}'
                Storage   = 'AdvancedAudit'
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Management'
                GpoDisplayName  = 'Audit Other Account Management Events'
                Type      = 'AuditFlags'
                # Native audit.csv, System target; no registry key/value.
                Value     = 1 # Success only; 2=Failure, 3=Success and Failure.
            }
            @{
                ValueName = '{0CCE9237-69AE-11D9-BED3-505054503030}'
                Storage   = 'AdvancedAudit'
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Management'
                GpoDisplayName  = 'Audit Security Group Management'
                Type      = 'AuditFlags'
                # Native audit.csv, System target; no registry key/value.
                Value     = 1 # Success only; 2=Failure, 3=Success and Failure.
            }
            @{
                ValueName = '{0CCE9235-69AE-11D9-BED3-505054503030}'
                Storage   = 'AdvancedAudit'
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Management'
                GpoDisplayName  = 'Audit User Account Management'
                Type      = 'AuditFlags'
                # Native audit.csv, System target; no registry key/value.
                Value     = 1 # Success only; 2=Failure, 3=Success and Failure.
            }
            @{
                ValueName = '{0CCE923C-69AE-11D9-BED3-505054503030}'
                Storage   = 'AdvancedAudit'
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\DS Access'
                GpoDisplayName  = 'Audit Directory Service Changes'
                Type      = 'AuditFlags'
                # Native audit.csv, System target; no registry key/value.
                Value     = 1 # Success only; 2=Failure, 3=Success and Failure.
            }
            @{
                ValueName = '{0CCE9230-69AE-11D9-BED3-505054503030}'
                Storage   = 'AdvancedAudit'
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Policy Change'
                GpoDisplayName  = 'Audit Authentication Policy Change'
                Type      = 'AuditFlags'
                # Native audit.csv, System target; no registry key/value.
                Value     = 1 # Success only; 2=Failure, 3=Success and Failure.
            }
            @{
                ValueName = '{0CCE923F-69AE-11D9-BED3-505054503030}'
                Storage   = 'AdvancedAudit'
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Logon'
                GpoDisplayName  = 'Audit Credential Validation'
                Type      = 'AuditFlags'
                # Native audit.csv, System target; no registry key/value.
                Value     = 1 # Success only; 2=Failure, 3=Success and Failure.
            }
            @{
                ValueName = '{0CCE9242-69AE-11D9-BED3-505054503030}'
                Storage   = 'AdvancedAudit'
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Logon'
                GpoDisplayName  = 'Audit Kerberos Authentication Service'
                Type      = 'AuditFlags'
                # Native audit.csv, System target; no registry key/value.
                Value     = 1 # Success only; 2=Failure, 3=Success and Failure.
            }
            @{
                ValueName = '{0CCE9215-69AE-11D9-BED3-505054503030}'
                Storage   = 'AdvancedAudit'
                GpoSettingsPath = 'Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Logon/Logoff'
                GpoDisplayName  = 'Audit Logon'
                Type      = 'AuditFlags'
                # Native audit.csv, System target; no registry key/value.
                Value     = 1 # Success only; 2=Failure, 3=Success and Failure.
            }
        )
    }
}

function Get-LabGpoDefinitions {
    [CmdletBinding()]
    param()

    # Ordered GPO list; none of these definitions contains link targets.
    Get-LabGpoDefinition
    Get-LabQuestionableGpoDefinition
    Get-LabDspAuditingGpoDefinition
}

# GPO linking is not implemented. Synthetic settings are defined separately below.

# --- Fine-grained password policies (FGPPs) -------------------------------
function Get-LabFineGrainedPasswordPolicyDefinitions {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$DomainDN)

    # FGPPs cannot link to OUs. Subjects below are GLOBAL SECURITY GROUP DNs.
    # Assignment applies to all eligible group members, not an OU filter.
    # Lower Precedence wins among competing group policies; a direct user
    # assignment can override it. Resultant user policy is not verified here.
    # PasswordNeverExpires and other account settings can affect expiration.
    # Ages use DAYS; lockout intervals use MINUTES. History 0 is explicit.
    # $null optional fields: copy domain defaults when NEW; preserve on rerun.
    # SubjectGroupDNs is EXACT, not additive. Extra subjects on these two
    # named lab policies are removed AFTER desired groups are added/verified.
    # RemoveSubjectsAfterReplication is retained as a legacy setting name:
    # true requests temporary subjects removed ONLY in the synthetic phase.
    # Provisioning leaves desired subjects assigned. The synthetic phase
    # removes/verifies them FIRST, then replicates and waits for settling.
    # All replication waits use PauseTimeSeconds in DEFAULTS; no per-policy delay.
    # MakeADChanges=False skips that phase and leaves assignments active.
    # A replication/wait failure does not roll back a committed removal.
    # An empty @() explicitly keeps the test policy completely unassigned.
    # This does not alter group membership, reset passwords or change GPOs.
    @(
        @{
            Name = 'Lab Service Accounts FGPP'
            Description = 'Lab service-account policy temporarily assigned to Tier1 Operators'
            Precedence = 20
            MinPasswordLength = 8
            MinPasswordAgeDays = $null
            MaxPasswordAgeDays = 180
            PasswordHistoryCount = 0
            ComplexityEnabled = $null
            ReversibleEncryptionEnabled = $null
            LockoutThreshold = $null
            LockoutDurationMinutes = $null
            LockoutObservationWindowMinutes = $null
            SubjectGroupDNs = @("CN=Tier1 Operators,OU=Tier 1,OU=Lab Admins,$DomainDN")
            RemoveSubjectsAfterReplication = $true
        }
        @{
            Name = 'Lab Test FGPP'
            Description = 'Unassigned lab test password policy'
            Precedence = 30
            MinPasswordLength = 32
            MinPasswordAgeDays = 1
            MaxPasswordAgeDays = 30
            PasswordHistoryCount = 15
            ComplexityEnabled = $null
            ReversibleEncryptionEnabled = $null
            LockoutThreshold = $null
            LockoutDurationMinutes = $null
            LockoutObservationWindowMinutes = $null
            SubjectGroupDNs = @()
            RemoveSubjectsAfterReplication = $false
        }
    )
}

# --- Specific AD object ACLs --------------------------------------------
function Get-LabSpecificObjectAclDefinitions {
    [CmdletBinding()]
    param()

    # RelativeDN is beneath the current domain DN. Scope None = this object
    # only; All = this object and all descendant objects (not descendants
    # with protected DACLs). Preserve existing ACEs and add only missing bits.
    # TrusteeUserKey references this run's verified demo-user GUID/SID.
    # Supported AD classes: user, group, organizationalUnit,
    # groupPolicyContainer (AD GPO container ONLY, not SYSVOL permissions).
    @(
        @{ Key='BadOuDemo9'; RelativeDN='OU=Bad OU'; ObjectClass='organizationalUnit'; TrusteeUserKey='DemoUser9'; Scope='None' }
        @{ Key='BadOuAdmin1'; RelativeDN='OU=Bad OU'; ObjectClass='organizationalUnit'; TrusteeUserKey='AdmUser1'; Scope='All' }
    )
}

function Get-LabSpecificObjectAclADChangeDefinitions {
    [CmdletBinding()]
    param()

    # Reference verified baseline keys, never independently resolve names.
    # RemoveExplicitTrustee removes that SID's explicit allow/deny ACEs.
    # RemoveExplicitRead removes explicit allow-read bits at EVERY scope;
    # retain write (including shared ReadControl), other rights and denies.
    # Neither action removes inherited/group rights or child-local ACEs.
    @(
        @{ BaselineKey='BadOuDemo9'; Action='RemoveExplicitTrustee' }
        @{ BaselineKey='BadOuAdmin1'; Action='RemoveExplicitRead' }
    )
}

# --- Synthetic AD change activity ---------------------------------------
function Get-LabComputerADChangeDefinitions {
    [CmdletBinding()]
    param()

    # Stable keys from Get-LabComputerDefinitions; never search by name.
    [ordered]@{
        usrusazlap12 = @{ Action = 'Delete' }
        usrusnjlap20 = @{
            Action = 'SetDescription'
            Description = 'someone changed this computer description!!!'
        }
    }
}

function Get-LabDemoUserADChangeDefinitions {
    [CmdletBinding()]
    param()

    # Keys reference Get-LabDemoUserDefinitions, not SAM/display-name lookups.
    # FAX maps to the AD LDAP attribute facsimileTelephoneNumber; FAXalt is
    # separate demo metadata and is not written to AD.
    [ordered]@{
        DemoUser5 = @{ FAX = '(xxx) xxx-xxxx' }
        DemoUser6 = @{ FAX = '(xxx) xxx-xxxx' }
    }
}

function Get-LabWmiFilterADChangeDefinitions {
    [CmdletBinding()]
    param()

    # Stable keys reference the verified baseline map, never a DN by name.
    [ordered]@{
        HyperVVirtualMachines = @{
            Description = 'Microsoft Hyper-V 2.0 AND 3.0 TEST'
        }
        VMwareVirtualMachines = @{
            Queries = @('SELECT * FROM Win32_ComputerSystem WHERE Model LIKE "ESX%"')
        }
        ParallelsVirtualMachines = @{
            Delete = $true
        }
    }
}

function Get-LabGpoADChangeDefinitions {
    [CmdletBinding()]
    param()

    # Explicit synthetic DWORD values; do not change the baseline records.
    # forceguest=1: Guest only; retain Classic (0) for production DCs.
    # NTLM level 4: send NTLMv2; refuse LM, but still accept NTLMv1/v2.
    # NoLMHash=0: disable the prohibition on LM-hash storage at a later
    # password change, subject to OS/password conditions. No passwords reset.
    # MaxSize is RegistryPolicy in KB: 20480 (20 MB) is the Security-policy
    # minimum, reduced from the 1048576 KB (1024 MB) baseline for DSP capture.
    # Do not use 0 or the 1024 KB minimum of other event-log policies.
    $overrides = [ordered]@{
        forceguest           = 1
        LmCompatibilityLevel = 4
        NoLMHash             = 0
        MaxSize              = 20480
    }

    # Reuse baseline identity, link policy, backup root and editor metadata.
    # These getters return new local data only; there are no AD/GPO reads.
    $baseline = Get-LabGpoDefinition
    $settings = @(
        foreach ($name in $overrides.Keys) {
            $matches = @($baseline.Settings | Where-Object { $_.ValueName -ieq $name })
            $expectedStorage = if ($name -ceq 'MaxSize') { 'RegistryPolicy' } else { 'SecurityOptions' }
            if ($matches.Count -ne 1 -or $matches[0].Storage -ine $expectedStorage -or
                $matches[0].Type -ine 'DWord') { throw ('Synthetic GPO setting [{0}] requires one {1} DWORD baseline record.' -f $name, $expectedStorage) }
            if ($name -ceq 'MaxSize' -and $matches[0].Key -ine 'HKLM\Software\Policies\Microsoft\Windows\EventLog\Security') {
                throw 'Synthetic MaxSize must target only the Security Event Log policy key.'
            }
            $setting = $matches[0].Clone()
            $setting.Value = $overrides[$name]
            if ($name -iin @('forceguest','NoLMHash')) {
                $setting.ReportValueType = 'BooleanOrNumber'
            }
            $setting
        }
    )
    @{
        Name = $baseline.Name
        ApplyWhenLinked = $baseline.ApplyWhenLinked
        BackupRoot = $baseline.BackupRoot
        Warnings = @('Synthetic lab changes deliberately weaken three Security Options and reduce Security Event Log capacity to 20 MB for DSP demonstrations. Keep this demo GPO unlinked. No passwords, links or local registry values are changed.')
        Settings = $settings
    }

    # Questionable GPO overrides run after the CIS overrides. The higher
    # lockout threshold is less restrictive; NTLM level 5 and disabled
    # reversible encryption strengthen their respective baseline settings.
    $questionableOverrides = [ordered]@{
        LockoutBadCount       = 100
        LmCompatibilityLevel  = 5
        ClearTextPassword     = 0
    }
    $questionableBaseline = Get-LabQuestionableGpoDefinition
    $questionableSettings = @(
        foreach ($name in $questionableOverrides.Keys) {
            $matches = @($questionableBaseline.Settings | Where-Object { $_.ValueName -ieq $name })
            $storage = 'AccountPolicy'
            $type = 'Integer'
            if ($name -ieq 'LmCompatibilityLevel') { $storage = 'SecurityOptions'; $type = 'DWord' }
            if ($matches.Count -ne 1 -or $matches[0].Storage -ine $storage -or
                $matches[0].Type -ine $type) { throw ('Synthetic Questionable GPO setting [{0}] requires one matching native baseline record.' -f $name) }
            $setting = $matches[0].Clone()
            $setting.Value = $questionableOverrides[$name]
            $setting
        }
    )
    @{
        Name = $questionableBaseline.Name
        ApplyWhenLinked = $questionableBaseline.ApplyWhenLinked
        BackupRoot = $questionableBaseline.BackupRoot
        Warnings = @('Synthetic Questionable GPO changes raise the lockout threshold to 100, require NTLM level 5 and disable reversible password encryption. Existing enabled links may apply these settings; passwords, lockout duration/reset window and links are not changed.')
        Settings = $questionableSettings
    }
}

function Get-LabSubnetADChangeDefinitions {
    [CmdletBinding()]
    param()

    # Ordered synthetic actions, NOT baseline subnet provisioning settings.
    # Each target must exist before its description is set or it is deleted.
    # These are AD Sites and Services changes: subnet objects.
    # Description is changed and verified before any explicit deletion.
    # 111.111.5.0/24 is deleted; 111.111.4.0/24 is retained.
    @(
        @{
            Name = '111.111.5.0/24'
            Description = 'Changed the subnet description attribute again!!'
            DeleteAfterDescriptionChange = $true
        }
        @{
            Name = '111.111.4.0/24'
            Description = 'This description changed by script!!'
            DeleteAfterDescriptionChange = $false
        }
    )
}

function Get-LabSiteLinkADChangeDefinitions {
    [CmdletBinding()]
    param()

    # Synthetic only: baseline cost 7 / interval 15 remain unchanged.
    # Intervals must be multiples of 15 minutes (15 through 10080).
    # Only cost and replInterval are managed; no replication/delay here.
    @(
        @{
            Name                          = 'SemperisLabs-SemperisDevs'
            Cost                          = 444
            ReplicationFrequencyInMinutes = 105
        }
    )
}

function Get-LabFinalGroupADChangeDefinition {
    [CmdletBinding()]
    param()

    # Terminal stage: keep this AFTER every current/future synthetic category.
    # Stable key in Get-LabGroupDefinitions / LabGroupObjects, not a name lookup.
    # Remove every direct user link, including unlisted/disabled users.
    # Then add this verified demo user as the ONLY direct user and last write.
    # AddUserKey references Get-LabDemoUserDefinitions / LabDemoUserObjects.
    # Preserve nested groups/computers; do not recursively empty other groups.
    @{ GroupKey = 'HelpdeskOps'; AddUserKey = 'DemoUser10' }
}

# ======================================================================
# END OPERATOR-EDITABLE DATA DEFINITIONS
# ======================================================================

# Internal runtime state: populated from the definitions and AD results.
# Aggregates low-space results across local and DSP reports for one pause.
$script:LabDiskSpacePauseRequired = $false
# These are caches, not additional operator-editable data definitions.
$script:LabGroupDefinitions = $null
$script:LabGroupObjects = [ordered]@{}
$script:LabDemoUserDefinitions = $null
$script:LabDemoUserObjects = [ordered]@{}
$script:LabComputerDefinitions = $null
$script:LabComputerObjects = [ordered]@{}
$script:LabWmiFilterDefinitions = $null
$script:LabWmiFilterObjects = [ordered]@{}
$script:LabUnavailableOUPaths = @{}
# Verified baseline FGPP identities/values for the later synthetic phase.
$script:LabFgppChangePlans = @()
# Baseline results, including skips, used to pin synthetic GPO targets by GUID.
$script:LabGpoChangeTargets = @()
# This run's verified specific-ACL object/principal identities.
$script:LabSpecificAclTargets = [ordered]@{}

# ======================================================================
# SHARED HELPERS AND PROVISIONING FUNCTIONS
# ======================================================================
# Rebuilt per normal run from ALL configured managed targets, including existing ones.
# Keep the write handle open: another run cannot replace it during provisioning.
$script:LabGeneratedInventory = $null
$script:LabInventoryStream = $null
$script:LabInventoryFault = $null
$script:LabInventoryPath = $null
$script:LabInventoryDomain = $null
$script:LabInventoryBatchMode = $false
$script:LabInventoryIndex = @{}
$script:LabInventoryReadOnlyMode = $false
$script:LabInventoryCatalogTarget = $null
$script:LabInventoryCatalogMatches = @{}

function New-LabCleanupCatalogItem {
    [CmdletBinding()]
    param([string]$Id, [string]$Kind, [string]$Selector,
        [System.Collections.IDictionary]$Identity,
        [ValidateSet('Baseline','SyntheticBestEffort')][string]$Source = 'Baseline')
    # Metadata only. Never copy user passwords, credential-store values,
    # random password settings or complete provisioning hash tables to JSON.
    $item = [ordered]@{
        CatalogId=$Id; Source=$Source; Kind=$Kind; Selector=$Selector
        Status='NotResolved'; MatchCount=0; AbsentCount=0; Message=''; LastResolvedUtc=''
    }
    foreach ($key in $Identity.Keys) { $item[$key] = $Identity[$key] }
    return $item
}

function Get-LabBaselineCleanupCatalog {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Domain)
    # PURE definition projection: no AD/DNS discovery and no creation-count
    # prompt. Every baseline definition remains in JSON even when absent.
    $dn = [string]$Domain.DistinguishedName
    foreach ($definition in @(Get-LabOrganizationalUnitDefinitions)) {
        $parents = @($dn)
        if (-not [string]::IsNullOrWhiteSpace([string]$definition.ParentPath)) { $parents = @('{0},{1}' -f $definition.ParentPath,$dn) }
        if ($null -ne $definition.PSObject.Properties['PreviousParentPath']) {
            $previous = $dn
            if (-not [string]::IsNullOrWhiteSpace([string]$definition.PreviousParentPath)) { $previous = '{0},{1}' -f $definition.PreviousParentPath,$dn }
            $parents += $previous
        }
        New-LabCleanupCatalogItem -Id ('OU|' + $definition.Name + '|' + $definition.ParentPath) -Kind OU -Selector NamedAD -Identity @{
            Name=[string]$definition.Name; Attribute='name'; NamingContext='Domain'; ParentPaths=@($parents | Select-Object -Unique)
        }
    }
    $categories = @(
        @{ Kind='Group'; Definitions=(Get-LabGroupDefinitions -DomainDN $dn) }
        @{ Kind='Computer'; Definitions=(Get-LabComputerDefinitions -DomainDN $dn) }
        @{ Kind='User'; Definitions=(Get-LabDemoUserDefinitions -DomainDN $dn -DomainDNSRoot $Domain.DNSRoot) }
    )
    foreach ($category in $categories) {
        foreach ($key in $category.Definitions.Keys) {
            $definition = $category.Definitions[$key]
            $sam = [string]$definition.SamAccountName
            if ($category.Kind -eq 'Computer') { $sam = ConvertTo-LabComputerSamAccountName -SamAccountName $sam }
            New-LabCleanupCatalogItem -Id ($category.Kind + '|' + $key) -Kind $category.Kind -Selector Account -Identity @{
                Name=[string]$definition.Name; SamAccountName=$sam; Path=[string]$definition.Path; SamOnly=$false
            }
        }
    }
    foreach ($definition in @(Get-LabSpecialDomainAccountDefinitions)) {
        $suffix = [string]$definition.Suffix
        if ([string]::IsNullOrWhiteSpace($suffix) -or $suffix.Length -gt 20) { throw 'Invalid special-account suffix in baseline cleanup catalog.' }
        $prefix = [string]$Domain.NetBIOSName
        $sam = $prefix.Substring(0,[Math]::Min($prefix.Length,20 - $suffix.Length)) + $suffix
        New-LabCleanupCatalogItem -Id ('SpecialUser|' + $suffix) -Kind User -Selector Account -Identity @{
            Name=$sam; SamAccountName=$sam; Path=''; SamOnly=$true
        }
    }
    $settings = Get-LabGenericUserSettings
    if ([string]::IsNullOrWhiteSpace([string]$settings.SamAccountNamePrefix) -or
        $GenericUserMaximumCount -lt 1 -or $GenericUserMaximumCount -gt 999999) { throw 'Invalid generic-user baseline series.' }
    # One explicit range descriptor represents ALL possible instances. Do
    # not materialize up to 999999 missing JSON rows or issue per-missing-SAM
    # directory queries. Existing managed six-digit SAMs above today's cap
    # are included too, independent of the count entered on any prior run.
    New-LabCleanupCatalogItem -Id 'GenericUserSeries' -Kind User -Selector GenericSeries -Identity @{
        Name='All configured generic users'; SamAccountNamePrefix=[string]$settings.SamAccountNamePrefix
        NamePrefix=[string]$settings.NamePrefix; RelativePath=[string]$settings.RelativePath
        FirstIndex=1; MaximumConfiguredIndex=[int]$GenericUserMaximumCount; IndexWidth=6
        IncludeExistingAboveConfiguredMaximum=$true; ExistingInConfiguredRange=0
    }
    $sites = @(Get-LabSiteDefinitions)
    $named = @(
        @{ Kind='Site'; Attribute='name'; Context='Configuration'; Parent='CN=Sites,{ConfigurationNamingContext}'; Definitions=$sites }
        @{ Kind='SiteLink'; Attribute='name'; Context='Configuration'; Parent='CN=IP,CN=Inter-Site Transports,CN=Sites,{ConfigurationNamingContext}'; Definitions=@(Get-LabSiteLinkDefinitions) }
        @{ Kind='Subnet'; Attribute='name'; Context='Configuration'; Parent='CN=Subnets,CN=Sites,{ConfigurationNamingContext}'; Definitions=@(Get-LabSubnetDefinitions -SiteDefinitions $sites) }
        @{ Kind='WmiFilter'; Attribute='msWMI-Name'; Context='Domain'; Parent=('CN=SOM,CN=WMIPolicy,CN=System,' + $dn); Definitions=@((Get-LabWmiFilterDefinitions).Values) }
        @{ Kind='GPO'; Attribute='displayName'; Context='Domain'; Parent=('CN=Policies,CN=System,' + $dn); Definitions=@(Get-LabGpoDefinitions) }
        @{ Kind='FGPP'; Attribute='name'; Context='Domain'; Parent=('CN=Password Settings Container,CN=System,' + $dn); Definitions=@(Get-LabFineGrainedPasswordPolicyDefinitions -DomainDN $dn) }
    )
    foreach ($category in $named) {
        foreach ($definition in $category.Definitions) {
            $name = [string]$definition.Name
            if ($category.Kind -eq 'Subnet') { $name = ConvertTo-LabSubnetPrefix -Name $name }
            New-LabCleanupCatalogItem -Id ($category.Kind + '|' + $name) -Kind $category.Kind -Selector NamedAD -Identity @{
                Name=$name; Attribute=$category.Attribute; NamingContext=$category.Context; ParentPaths=@($category.Parent)
            }
        }
    }
    foreach ($definition in @(Get-LabDnsZoneDefinitions)) {
        New-LabCleanupCatalogItem -Id ('DnsZone|' + $definition.Name) -Kind DnsZone -Selector DnsZone -Identity @{ Name=[string]$definition.Name; ZoneName=[string]$definition.Name }
    }
    foreach ($definition in @(Get-LabDnsRecordDefinitions -DomainDNSRoot $Domain.DNSRoot)) {
        New-LabCleanupCatalogItem -Id ('A|' + $definition.ZoneName + '|' + $definition.Name) -Kind DnsRecord -Selector DnsExact -Identity @{
            Name=[string]$definition.Name; ZoneName=[string]$definition.ZoneName; RecordType='A'; Data=[string]$definition.IPv4Address
        }
        if ($definition.CreatePtr) {
            New-LabCleanupCatalogItem -Id ('AssociatedPTR|' + $definition.ZoneName + '|' + $definition.Name) -Kind DnsRecord -Selector AssociatedPTR -Identity @{
                Name=[string]$definition.Name; ForwardZoneName=[string]$definition.ZoneName
                IPv4Address=[string]$definition.IPv4Address; PtrDomainName=('{0}.{1}.' -f $definition.Name,$definition.ZoneName)
            }
        }
    }
    # Memberships/nesting, GPO settings and FGPP subjects are relationships or
    # child data of these targets, not extra objects to delete. Never follow
    # references into built-in groups, existing sites or the main DNS zone.
}

function Get-LabSyntheticCleanupCatalog {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Domain)
    $baseline = Get-LabWmiFilterDefinitions
    $changes = Get-LabWmiFilterADChangeDefinitions
    foreach ($key in $baseline.Keys) {
        if ($changes.Contains($key) -and $changes[$key].Contains('Name') -and
            -not [string]::IsNullOrWhiteSpace([string]$changes[$key].Name) -and $changes[$key].Name -ine $baseline[$key].Name) {
            New-LabCleanupCatalogItem -Id ('SyntheticWMI|' + $key) -Kind WmiFilter -Selector NamedAD -Source SyntheticBestEffort -Identity @{
                Name=[string]$changes[$key].Name; Attribute='msWMI-Name'; NamingContext='Domain'
                ParentPaths=@('CN=SOM,CN=WMIPolicy,CN=System,' + $Domain.DistinguishedName)
            }
        }
    }
    $index = 0
    foreach ($definition in @(Get-LabDnsADChangeDefinitions -DomainDNSRoot $Domain.DNSRoot)) {
        $index++
        if ($definition.Contains('PtrDomainName')) {
            New-LabCleanupCatalogItem -Id ('SyntheticPTR|' + $index) -Kind DnsRecord -Selector DnsExact -Source SyntheticBestEffort -Identity @{
                Name=[string]$definition.Name; ZoneName=[string]$definition.ZoneName; RecordType='PTR'; Data=[string]$definition.PtrDomainName
            }
            continue
        }
        if (-not $definition.Contains('IPv4Address')) { continue }
        $addresses = @([string]$definition.IPv4Address)
        if ($definition.Contains('OldIPv4Address')) { $addresses += [string]$definition.OldIPv4Address }
        foreach ($address in @($addresses | Select-Object -Unique)) {
            New-LabCleanupCatalogItem -Id ('SyntheticA|' + $index + '|' + $address) -Kind DnsRecord -Selector DnsExact -Source SyntheticBestEffort -Identity @{
                Name=[string]$definition.Name; ZoneName=[string]$definition.ZoneName; RecordType='A'; Data=$address
            }
            if ($definition.Action -eq 'SetAddress') {
                New-LabCleanupCatalogItem -Id ('SyntheticAssociatedPTR|' + $index + '|' + $address) -Kind DnsRecord -Selector AssociatedPTR -Source SyntheticBestEffort -Identity @{
                    Name=[string]$definition.Name; ForwardZoneName=[string]$definition.ZoneName; IPv4Address=$address
                    PtrDomainName=('{0}.{1}.' -f $definition.Name,$definition.ZoneName)
                }
            }
        }
    }
}

function New-LabGeneratedInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Domain)
    return [ordered]@{
        SchemaVersion=3; ScriptVersion='1.8.22'; ScriptFile=$script:LabExecutingScriptFile; ScriptPath=$script:LabExecutingScriptPath
        InventoryScope='CompleteBaselineCatalog'; InventoryStatus='NotScanned'; ScanStage=''; LastScanUtc=''
        ScanIssues=(New-Object System.Collections.ArrayList); RunId=[guid]::NewGuid().ToString()
        DomainSID=[string]$Domain.DomainSID.Value; DomainDN=[string]$Domain.DistinguishedName; DomainDNSRoot=[string]$Domain.DNSRoot
        CreatedUtc=[DateTime]::UtcNow.ToString('o'); UpdatedUtc=[DateTime]::UtcNow.ToString('o')
        CatalogSemantics='BaselineCatalog includes every baseline object definition plus an explicit full generic-user range, even when absent. Objects holds resolved GUID/exact-DNS targets; SyntheticCatalog is supplemental best effort.'
        BaselineCatalog=@(Get-LabBaselineCleanupCatalog -Domain $Domain)
        SyntheticCatalog=@(Get-LabSyntheticCleanupCatalog -Domain $Domain)
        Objects=(New-Object System.Collections.ArrayList)
    }
}

function Get-LabInventoryEntryKey {
    [CmdletBinding()]
    param($Entry)
    if ($Entry.Kind -eq 'GPO') { return ('GPO|' + ([guid]$Entry.GpoGuid).ToString()) }
    if ($Entry.Kind -in @('DnsZone','DnsRecord')) {
        return ('{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f $Entry.Kind,$Entry.ZoneGuid,$Entry.ObjectGuid,$Entry.ZoneName,$Entry.Name,$Entry.RecordType,([string]$Entry.Data).TrimEnd([char]46)).ToLowerInvariant()
    }
    return ('AD|' + ([guid]$Entry.ObjectGuid).ToString())
}

function Register-LabInventoryCatalogMatch {
    [CmdletBinding()]
    param([System.Collections.IDictionary]$Entry)
    if ($null -eq $script:LabInventoryCatalogTarget) { return }
    if (-not $Entry.Contains('CatalogIds')) { $Entry['CatalogIds'] = @() }
    $id = [string]$script:LabInventoryCatalogTarget.CatalogId
    if (@($Entry.CatalogIds) -cnotcontains $id) { $Entry.CatalogIds = @($Entry.CatalogIds) + @($id) }
    $key = Get-LabInventoryEntryKey -Entry $Entry
    $script:LabInventoryCatalogMatches[$key] = $true
    $script:LabInventoryCatalogTarget.MatchCount = $script:LabInventoryCatalogMatches.Count
}


function Get-LabGeneratedInventoryPath {
    [CmdletBinding()]
    param()
    if ((Get-Location).Provider.Name -ne 'FileSystem') {
        throw 'The current directory must use the FileSystem provider.'
    }
    if ([string]::IsNullOrWhiteSpace($script:LabExecutingInventoryFile) -or
        $script:LabExecutingInventoryFile -cne ([IO.Path]::GetFileNameWithoutExtension($script:LabExecutingScriptPath) + '.JSON')) {
        throw 'The executing script inventory filename is unavailable or inconsistent. Refusing to select another file.'
    }
    # Location selects the OUTPUT DIRECTORY only, never an input filename.
    return Join-Path (Get-Location).ProviderPath $script:LabExecutingInventoryFile
}

function Assert-LabInventoryHealthy {
    [CmdletBinding()]
    param()
    if ($null -ne $script:LabInventoryFault) {
        Stop-ScriptGracefully -Message ('Ownership inventory write failed; further provisioning is blocked: {0}. Review partial creations before rerunning.' -f $script:LabInventoryFault)
    }
}

function Save-LabGeneratedInventory {
    [CmdletBinding()]
    param()
    if ($script:LabInventoryReadOnlyMode -or $script:LabInventoryBatchMode) { return }
    try {
        $script:LabGeneratedInventory.UpdatedUtc = [DateTime]::UtcNow.ToString('o')
        $json = ConvertTo-Json -InputObject $script:LabGeneratedInventory -Depth 8
        $bytes = [Text.Encoding]::UTF8.GetBytes($json + [Environment]::NewLine)
        $script:LabInventoryStream.Position = 0
        $script:LabInventoryStream.Write($bytes, 0, $bytes.Length)
        $script:LabInventoryStream.SetLength($bytes.Length)
        $script:LabInventoryStream.Flush($true)
    }
    catch {
        $script:LabInventoryFault = $_.Exception.Message
        throw ('Could not save ownership inventory [{0}]: {1}' -f $script:LabInventoryPath, $script:LabInventoryFault)
    }
}

function Initialize-LabGeneratedInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Domain)
    try {
        $script:LabInventoryPath = Get-LabGeneratedInventoryPath
        $script:LabInventoryDomain = $Domain
        $script:LabInventoryIndex = @{}
        $script:LabGeneratedInventory = New-LabGeneratedInventory -Domain $Domain
        # OpenOrCreate avoids truncating a file before the exclusive writer
        # lock succeeds. Never delete a locked/read-only file as a workaround.
        $script:LabInventoryStream = [IO.File]::Open($script:LabInventoryPath,
            [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
        Save-LabGeneratedInventory
        Write-Status -Kind Info -Message ('Ownership inventory overwritten: [{0}]. EVERY baseline definition is cataloged, including absent targets; existing objects from older runs are cleanup targets. Built-in/reference-only objects are excluded.' -f $script:LabInventoryPath)
    }
    catch {
        if ($null -ne $script:LabInventoryStream) {
            $script:LabInventoryStream.Dispose()
            $script:LabInventoryStream = $null
        }
        Stop-ScriptGracefully -Message ('Cannot overwrite the current-directory JSON inventory. No provisioning was started. Close any file lock or correct permissions/free space, then retry. {0}' -f $_.Exception.Message)
    }
}

function Add-LabGeneratedADObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('User','Computer','Group','OU','Site','SiteLink','Subnet','WmiFilter','FGPP')][string]$Kind,
        [Parameter(Mandatory = $true)]$Object,
        [ValidateSet('CreatedThisRun','ConfiguredExisting')][string]$RecordOrigin = 'CreatedThisRun'
    )
    Assert-LabInventoryHealthy
    if ($null -eq $Object.ObjectGUID -or [guid]$Object.ObjectGUID -eq [guid]::Empty) { throw ('Cannot inventory {0}: no object GUID.' -f $Kind) }
    $guid = ([guid]$Object.ObjectGUID).ToString()
    $key = 'AD|' + $guid
    if ($RecordOrigin -eq 'CreatedThisRun' -and -not $script:LabInventoryIndex.ContainsKey($key)) {
        # Creation has already happened. Persist its returned GUID BEFORE
        # any follow-up directory read, password initialization or policy check.
        $partial = [ordered]@{
            Kind=$Kind; ObjectGuid=$guid; Name=[string]$Object.Name; SamAccountName=''
            DistinguishedName=[string]$Object.DistinguishedName
            RecordOrigin=$RecordOrigin; RecordedUtc=[DateTime]::UtcNow.ToString('o')
        }
        [void]$script:LabGeneratedInventory.Objects.Add($partial)
        $script:LabInventoryIndex[$key] = $partial
        Save-LabGeneratedInventory
    }
    # Read safety properties explicitly, not from an incomplete cached object.
    $current = Get-ADObject -Identity ([guid]$guid) -Properties objectSid,sAMAccountName,isCriticalSystemObject,userAccountControl `
        -Server $script:LabInventoryDomain.SelectedDomainController -ErrorAction Stop
    if (Test-LabInventoryProtectedObject -Object $current -Domain $script:LabInventoryDomain) {
        throw ('Built-in, critical, DC or existing-only reference object is excluded: {0}' -f $current.DistinguishedName)
    }
    if ($script:LabInventoryIndex.ContainsKey($key)) {
        $entry = $script:LabInventoryIndex[$key]
        if ($entry.Kind -cne $Kind) { throw 'One GUID was assigned conflicting inventory kinds.' }
        $entry.DistinguishedName = [string]$current.DistinguishedName
        $entry.Name = [string]$current.Name
        $entry.SamAccountName = [string]$current.sAMAccountName
    }
    else {
        $entry = [ordered]@{
            Kind=$Kind; ObjectGuid=$guid; Name=[string]$current.Name
            SamAccountName=[string]$current.sAMAccountName
            DistinguishedName=[string]$current.DistinguishedName
            RecordOrigin=$RecordOrigin; RecordedUtc=[DateTime]::UtcNow.ToString('o')
        }
        [void]$script:LabGeneratedInventory.Objects.Add($entry)
        $script:LabInventoryIndex[$key] = $entry
    }
    Register-LabInventoryCatalogMatch -Entry $entry
    Save-LabGeneratedInventory
}

function Add-LabGeneratedGpo {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Gpo,
        [ValidateSet('CreatedThisRun','ConfiguredExisting')][string]$RecordOrigin = 'CreatedThisRun')
    Assert-LabInventoryHealthy
    $guid = ([guid]$Gpo.Id).ToString()
    if ([guid]$Gpo.Id -eq [guid]::Empty) { throw 'GPO returned no GUID.' }
    if ($guid -in @('31b2f340-016d-11d2-945f-00c04fb984f9','6ac1786c-016f-11d2-945f-00c04fb984f9')) { throw 'Default domain/DC GPOs are excluded from inventory and cleanup.' }
    $key = 'GPO|' + $guid
    if ($script:LabInventoryIndex.ContainsKey($key)) { $script:LabInventoryIndex[$key].DisplayName = [string]$Gpo.DisplayName }
    else {
        $entry = [ordered]@{ Kind='GPO'; GpoGuid=$guid; DisplayName=[string]$Gpo.DisplayName; RecordOrigin=$RecordOrigin; RecordedUtc=[DateTime]::UtcNow.ToString('o') }
        [void]$script:LabGeneratedInventory.Objects.Add($entry)
        $script:LabInventoryIndex[$key] = $entry
    }
    Register-LabInventoryCatalogMatch -Entry $script:LabInventoryIndex[$key]
    Save-LabGeneratedInventory
}

function Add-LabGeneratedDnsObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('DnsZone','DnsRecord')][string]$Kind,
        [Parameter(Mandatory = $true)][string]$ZoneName,
        [string]$Name, [ValidateSet('A','PTR')][string]$RecordType, [string]$Data,
        [ValidateSet('CreatedThisRun','ConfiguredExisting')][string]$RecordOrigin = 'CreatedThisRun'
    )
    Assert-LabInventoryHealthy
    if ($Kind -eq 'DnsZone' -and ($ZoneName -ieq $script:LabInventoryDomain.DNSRoot -or $ZoneName -ilike '_msdcs.*')) { throw 'AD domain and forest-locator DNS zones are reference infrastructure, not cleanup targets.' }
    # Save the exact provider identity BEFORE extra directory reads can fail.
    # An unresolved entry is retained for review, never deleted by name alone.
    $entry = [ordered]@{
        Kind=$Kind; ZoneName=$ZoneName; Name=$Name; RecordType=$RecordType; Data=$Data
        ObjectGuid=''; DistinguishedName=''; ZoneGuid=''
        RecordOrigin=$RecordOrigin; RecordedUtc=[DateTime]::UtcNow.ToString('o')
    }
    [void]$script:LabGeneratedInventory.Objects.Add($entry)
    Save-LabGeneratedInventory
    $server = [string]$script:LabInventoryDomain.SelectedDomainController
    if ($Kind -eq 'DnsZone') {
        $object = Resolve-LabInventoryDnsZone -Domain $script:LabInventoryDomain -ZoneName $ZoneName
        $entry.ZoneGuid = ([guid]$object.ObjectGUID).ToString()
    }
    else {
        $object = Resolve-LabDnsDirectoryNode -Domain $script:LabInventoryDomain -ZoneName $ZoneName -Name $Name
        $zoneDN = Get-ParentDistinguishedName -DistinguishedName $object.DistinguishedName
        $zone = Get-ADObject -Identity $zoneDN -Server $server -ErrorAction Stop
        $entry.ZoneGuid = ([guid]$zone.ObjectGUID).ToString()
    }
    $entry.ObjectGuid = ([guid]$object.ObjectGUID).ToString()
    $entry.DistinguishedName = [string]$object.DistinguishedName
    # A DNS record has no independent GUID. Deduplicate only after resolving
    # zone/node GUID AND the exact owner/type/data; retain replaced-node IDs.
    $duplicates = @($script:LabGeneratedInventory.Objects | Where-Object {
        -not [object]::ReferenceEquals($_,$entry) -and $_.Kind -eq $Kind -and
        $_.ObjectGuid -eq $entry.ObjectGuid -and $_.ZoneGuid -eq $entry.ZoneGuid -and
        $_.ZoneName -ieq $ZoneName -and $_.Name -ieq $Name -and
        $_.RecordType -ieq $RecordType -and ([string]$_.Data).TrimEnd([char]46) -ieq ([string]$Data).TrimEnd([char]46)
    })
    if ($duplicates.Count -gt 0) {
        [void]$script:LabGeneratedInventory.Objects.Remove($entry)
        $entry = $duplicates[0]
    }
    Register-LabInventoryCatalogMatch -Entry $entry
    Save-LabGeneratedInventory
}

function Update-LabGeneratedDnsAddress {
    [CmdletBinding()]
    param([string]$ZoneName, [string]$Name, [string]$OldAddress, [string]$NewAddress)
    # Updating an inventory-owned A record keeps its current RDATA identity.
    # Configured existing records are captured by the inventory scan as well.
    $changed = $false
    foreach ($item in $script:LabGeneratedInventory.Objects) {
        if ($item.Kind -eq 'DnsRecord' -and $item.RecordType -eq 'A' -and
            $item.ZoneName -ieq $ZoneName -and $item.Name -ieq $Name -and $item.Data -eq $OldAddress) {
            $item.Data = $NewAddress
            $changed = $true
        }
    }
    if ($changed) { Save-LabGeneratedInventory }
}

function Test-LabInventoryProtectedObject {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Object, [Parameter(Mandatory = $true)]$Domain)
    # These properties MUST be explicitly requested by the caller. Refuse
    # built-ins and existing-only references even if definitions overlap.
    if (($Object.isCriticalSystemObject -eq $true -and $Object.ObjectClass -iin @('user','computer','group','organizationalUnit','site','siteLink','subnet','msWMI-Som','msDS-PasswordSettings')) -or
        ([int]$Object.userAccountControl -band 8192) -ne 0 -or
        $Object.ObjectClass -ieq 'nTDSDSA') { return $true }
    if (($Object.ObjectClass -ieq 'siteLink' -and $Object.Name -ieq 'DEFAULTIPSITELINK') -or
        ($Object.ObjectClass -ieq 'site' -and $Object.Name -ieq 'Default-First-Site-Name')) { return $true }
    $sid = [string]$Object.objectSid
    if ($null -ne $Object.objectSid -and $null -ne $Object.objectSid.PSObject.Properties['Value']) {
        $sid = [string]$Object.objectSid.Value
    }
    if ($sid -match '^S-1-5-32-' -or
        ($sid -match '^S-1-5-21-\d+-\d+-\d+-(\d+)$' -and [long]$Matches[1] -lt 1000)) { return $true }
    if ($Object.ObjectClass -ieq 'group') {
        $references = Get-LabExistingGroupDefinitions -DomainSID ([string]$Domain.DomainSID.Value) -DomainDN ([string]$Domain.DistinguishedName)
        $identities = @([string]$Object.DistinguishedName, [string]$Object.ObjectGUID, [string]$Object.sAMAccountName, $sid)
        foreach ($key in $references.Keys) {
            if ($identities -icontains [string]$references[$key].Identity) { return $true }
        }
    }
    return $false
}

function Add-LabInventoryScanIssue {
    [CmdletBinding()]
    param([string]$Target, [string]$Message)
    [void]$script:LabGeneratedInventory.ScanIssues.Add([ordered]@{ Target=$Target; Message=$Message })
    Write-Status -IndentLevel 2 -Kind Warning -Message ('Inventory could not verify [{0}]: {1} No ambiguous/name-only cleanup target was adopted.' -f $Target,$Message)
}

function Add-LabConfiguredInventoryMatch {
    [CmdletBinding()]
    param([string]$Kind, [AllowEmptyCollection()][object[]]$Objects = @())
    if ($Objects.Count -gt 1) { throw 'Multiple identities match one configured target; resolve the ambiguity.' }
    if ($Objects.Count -eq 0) { return }
    $classes = @{ User='user'; Computer='computer'; Group='group'; OU='organizationalUnit'; Site='site'; SiteLink='siteLink'; Subnet='subnet'; WmiFilter='msWMI-Som'; FGPP='msDS-PasswordSettings'; GPO='groupPolicyContainer' }
    if ($Objects[0].ObjectClass -ine $classes[$Kind]) { throw 'Configured identity conflicts with an unexpected object class.' }
    if ($Kind -eq 'GPO') {
        $gpo = [pscustomobject]@{ Id=[guid](([string]$Objects[0].Name).Trim('{}')); DisplayName=[string]$Objects[0].displayName }
        Add-LabGeneratedGpo -Gpo $gpo -RecordOrigin ConfiguredExisting
    }
    else { Add-LabGeneratedADObject -Kind $Kind -Object $Objects[0] -RecordOrigin ConfiguredExisting }
}

function Add-LabConfiguredAccountInventory {
    [CmdletBinding()]
    param($Domain, [string]$Kind, [string]$SamAccountName, [string]$Name, [string]$Path, [switch]$SamOnly)
    if ([string]::IsNullOrWhiteSpace($SamAccountName)) { throw 'Configured SAM must not be blank.' }
    $server = [string]$Domain.SelectedDomainController
    $samFilter = '(sAMAccountName={0})' -f (ConvertTo-LdapFilterValue -Value $SamAccountName)
    $sam = @(Get-ADObject -LDAPFilter $samFilter -SearchBase $Domain.DistinguishedName -Server $server -ErrorAction Stop)
    $named = @()
    if (-not $SamOnly) {
        # Search from an existing domain root so a not-yet-created parent OU
        # is a normal absence, not an inventory lookup failure.
        $nameFilter = '(name={0})' -f (ConvertTo-LdapFilterValue -Value $Name)
        $named = @(Get-ADObject -LDAPFilter $nameFilter -SearchBase $Domain.DistinguishedName -Server $server -ErrorAction Stop |
            Where-Object { (Get-ParentDistinguishedName -DistinguishedName $_.DistinguishedName) -ieq $Path })
    }
    if ($sam.Count -gt 1 -or $named.Count -gt 1 -or
        ($sam.Count -eq 1 -and $named.Count -eq 1 -and $sam[0].ObjectGUID -ne $named[0].ObjectGUID)) {
        throw 'SAM and configured CN/parent are ambiguous or identify different objects.'
    }
    $objects = $sam
    if ($objects.Count -eq 0) { $objects = $named }
    Add-LabConfiguredInventoryMatch -Kind $Kind -Objects $objects
}

function Add-LabConfiguredDnsRecordInventory {
    [CmdletBinding()]
    param($Domain, [string]$ZoneName, [string]$Name, [ValidateSet('A','PTR')][string]$RecordType, [string]$Data)
    $records = @(Get-LabDnsNodeRecords -ComputerName $Domain.SelectedDomainController -ZoneName $ZoneName -Name $Name | Where-Object {
        ([string]$_.RecordType -ieq 'A' -and $RecordType -eq 'A' -and [string]$_.RecordData.IPv4Address -eq $Data) -or
        ([string]$_.RecordType -ieq 'PTR' -and $RecordType -eq 'PTR' -and ([string]$_.RecordData.PtrDomainName).TrimEnd([char]46) -ieq $Data.TrimEnd([char]46))
    })
    if ($records.Count -gt 1) { throw 'Exact DNS owner/type/data is ambiguous.' }
    if ($records.Count -eq 1) {
        Add-LabGeneratedDnsObject -Kind DnsRecord -ZoneName $ZoneName -Name $Name -RecordType $RecordType -Data $Data -RecordOrigin ConfiguredExisting
    }
}

function Sync-LabConfiguredInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Domain,
        [ValidateSet('BeforeProvisioning','AfterProvisioning','BeforeRemoval','AfterRemoval')][string]$Stage)
    # Read-only discovery. Catalogs are projected from definitions BEFORE
    # discovery; absence never removes a definition from the JSON catalog.
    Assert-LabInventoryHealthy
    $server = [string]$Domain.SelectedDomainController
    $dn = [string]$Domain.DistinguishedName
    $script:LabGeneratedInventory.ScanStage = $Stage
    $script:LabGeneratedInventory.InventoryStatus = 'Scanning'
    $script:LabGeneratedInventory.ScanIssues.Clear()
    $script:LabInventoryBatchMode = $true
    $configurationDN = ''
    $configurationError = ''
    try { $configurationDN = [string](Get-ADRootDSE -Server $server -ErrorAction Stop).configurationNamingContext }
    catch { $configurationError = $_.Exception.Message }
    $zones = @(); $dnsError = ''
    try { $zones = @(Get-DnsServerZone -ComputerName $server -ErrorAction Stop) }
    catch { $dnsError = $_.Exception.Message }
    try {
        foreach ($target in @($script:LabGeneratedInventory.BaselineCatalog) + @($script:LabGeneratedInventory.SyntheticCatalog)) {
            $script:LabInventoryCatalogTarget = $target
            $script:LabInventoryCatalogMatches = @{}
            $target.MatchCount = 0; $target.AbsentCount = 0; $target.Status = 'Resolving'; $target.Message = ''
            try {
                switch ($target.Selector) {
                    'Account' {
                        Add-LabConfiguredAccountInventory -Domain $Domain -Kind $target.Kind -SamAccountName $target.SamAccountName -Name $target.Name -Path $target.Path -SamOnly:([bool]$target.SamOnly)
                    }
                    'GenericSeries' {
                        $target.ExistingInConfiguredRange = 0
                        $filter = '(sAMAccountName={0}*)' -f (ConvertTo-LdapFilterValue -Value $target.SamAccountNamePrefix)
                        $pattern = '^{0}([0-9]{{6}})$' -f [regex]::Escape([string]$target.SamAccountNamePrefix)
                        $users = @(Get-ADObject -LDAPFilter $filter -SearchBase $dn -Properties sAMAccountName -Server $server -ErrorAction Stop)
                        $indices = @{}
                        foreach ($user in $users) {
                            if ([string]$user.sAMAccountName -imatch $pattern -and [int]$Matches[1] -ge 1) {
                                $index = [int]$Matches[1]
                                try {
                                    Add-LabConfiguredInventoryMatch -Kind User -Objects @($user)
                                    if ($index -le $target.MaximumConfiguredIndex) { $indices[$index] = $true }
                                }
                                catch {
                                    $target.Status = 'Unresolved'
                                    Add-LabInventoryScanIssue -Target ([string]$user.sAMAccountName) -Message $_.Exception.Message
                                }
                            }
                        }
                        $target.ExistingInConfiguredRange = $indices.Count
                        $target.AbsentCount = [int]$target.MaximumConfiguredIndex - $indices.Count
                    }
                    'NamedAD' {
                        $base = $dn
                        if ($target.NamingContext -eq 'Configuration') {
                            if ([string]::IsNullOrWhiteSpace($configurationDN)) { throw ('Configuration discovery failed: ' + $configurationError) }
                            $base = $configurationDN
                        }
                        $parents = @($target.ParentPaths | ForEach-Object { ([string]$_).Replace('{ConfigurationNamingContext}',$configurationDN) })
                        $filter = '({0}={1})' -f $target.Attribute,(ConvertTo-LdapFilterValue -Value $target.Name)
                        $matches = @(Get-ADObject -LDAPFilter $filter -SearchBase $base -Properties displayName -Server $server -ErrorAction Stop |
                            Where-Object { $parents -icontains (Get-ParentDistinguishedName -DistinguishedName $_.DistinguishedName) })
                        # Multiple expressly configured OU locations may both
                        # contain old lab trees: remove both verified OU GUIDs.
                        # Duplicate exact WMI/GPO display names remain ambiguous.
                        if ($target.Kind -eq 'OU') {
                            foreach ($match in $matches) { Add-LabConfiguredInventoryMatch -Kind OU -Objects @($match) }
                        }
                        else { Add-LabConfiguredInventoryMatch -Kind $target.Kind -Objects $matches }
                    }
                    'DnsZone' {
                        if ($dnsError) { throw $dnsError }
                        if ($target.ZoneName -ieq $Domain.DNSRoot -or $target.ZoneName -ilike '_msdcs.*') {
                            $target.Status = 'Excluded'; $target.Message = 'Built-in AD DNS infrastructure is never a zone cleanup target.'; break
                        }
                        $matches = @($zones | Where-Object { $_.ZoneName -ieq $target.ZoneName })
                        if ($matches.Count -gt 1) { throw 'DNS zone identity is ambiguous.' }
                        if ($matches.Count -eq 1) {
                            if ([string]$matches[0].ZoneType -ine 'Primary' -or -not $matches[0].IsDsIntegrated) { throw 'Baseline zone is not a writable AD-integrated primary; manual review required.' }
                            Add-LabGeneratedDnsObject -Kind DnsZone -ZoneName $target.ZoneName -RecordOrigin ConfiguredExisting
                        }
                    }
                    'DnsExact' {
                        if ($dnsError) { throw $dnsError }
                        if (@($zones | Where-Object { $_.ZoneName -ieq $target.ZoneName }).Count -eq 1) {
                            Add-LabConfiguredDnsRecordInventory -Domain $Domain -ZoneName $target.ZoneName -Name $target.Name -RecordType $target.RecordType -Data $target.Data
                        }
                    }
                    'AssociatedPTR' {
                        if ($dnsError) { throw $dnsError }
                        $octets = ([string]$target.IPv4Address).Split('.'); [array]::Reverse($octets)
                        $reverse = ($octets -join '.') + '.in-addr.arpa'
                        foreach ($zone in @($zones | Where-Object { $_.IsReverseLookupZone -and $reverse.EndsWith(('.' + $_.ZoneName),[StringComparison]::OrdinalIgnoreCase) })) {
                            $owner = $reverse.Substring(0,$reverse.Length - $zone.ZoneName.Length - 1)
                            Add-LabConfiguredDnsRecordInventory -Domain $Domain -ZoneName $zone.ZoneName -Name $owner -RecordType PTR -Data $target.PtrDomainName
                        }
                    }
                    default { throw ('Unsupported baseline cleanup selector: ' + $target.Selector) }
                }
                if ($target.Status -eq 'Resolving') {
                    if ($target.MatchCount -gt 0) { $target.Status = 'Present' }
                    else { $target.Status = 'Absent' }
                }
                if ($target.Selector -ne 'GenericSeries' -and $target.Status -eq 'Absent') { $target.AbsentCount = 1 }
            }
            catch {
                $target.Status = 'Unresolved'; $target.Message = $_.Exception.Message
                Add-LabInventoryScanIssue -Target $target.CatalogId -Message $_.Exception.Message
            }
            finally { $target.LastResolvedUtc = [DateTime]::UtcNow.ToString('o') }
        }
    }
    finally {
        $script:LabInventoryCatalogTarget = $null
        $script:LabInventoryBatchMode = $false
        $script:LabGeneratedInventory.InventoryStatus = 'Complete'
        if ($script:LabGeneratedInventory.ScanIssues.Count -gt 0) { $script:LabGeneratedInventory.InventoryStatus = 'Incomplete' }
        $script:LabGeneratedInventory.LastScanUtc = [DateTime]::UtcNow.ToString('o')
        Save-LabGeneratedInventory
    }
    Write-Status -Kind Info -Message ('Baseline catalog [{0}]: {1} definitions/rules; {2} supplemental synthetic selectors; {3} recorded identities; status={4}. Absent baseline definitions remain in the JSON.' -f $Stage,$script:LabGeneratedInventory.BaselineCatalog.Count,$script:LabGeneratedInventory.SyntheticCatalog.Count,$script:LabGeneratedInventory.Objects.Count,$script:LabGeneratedInventory.InventoryStatus)
}

function Resolve-LabInventoryDnsZone {
    [CmdletBinding()]
    param($Domain, [string]$ZoneName)
    $server = [string]$Domain.SelectedDomainController
    $root = Get-ADRootDSE -Server $server -ErrorAction Stop
    $filter = '(&(objectClass=dnsZone)(name={0}))' -f (ConvertTo-LdapFilterValue -Value $ZoneName)
    $matches = @(
        foreach ($context in @($root.namingContexts | Sort-Object -Unique)) {
            if ($context -ine [string]$root.configurationNamingContext -and $context -ine [string]$root.schemaNamingContext) {
                Get-ADObject -LDAPFilter $filter -SearchBase $context -SearchScope Subtree -Server $server -ErrorAction Stop
            }
        }
    )
    if ($matches.Count -ne 1) { throw 'DNS zone directory identity is missing or ambiguous.' }
    return $matches[0]
}

function Test-LabRemovalRights {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Domain)
    Write-SectionHeader -Message 'Check all required removal rights...'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Administrator elevation is required.'
        }
        $sids = @($identity.Groups | ForEach-Object { $_.Value })
        if ($sids -notcontains ('{0}-512' -f $Domain.DomainSID.Value) -or
            -not $principal.IsInRole([Security.Principal.SecurityIdentifier]('{0}-512' -f $Domain.DomainSID.Value))) {
            throw 'Domain Admins for the current domain is missing from the logon token.'
        }
        $forest = Get-ADForest -Server $Domain.SelectedDomainController -ErrorAction Stop
        $rootDomain = Get-ADDomain -Identity $forest.RootDomain -Server $Domain.SelectedDomainController -ErrorAction Stop
        if ($sids -notcontains ('{0}-519' -f $rootDomain.DomainSID.Value) -or
            -not $principal.IsInRole([Security.Principal.SecurityIdentifier]('{0}-519' -f $rootDomain.DomainSID.Value))) {
            throw 'Enterprise Admins is missing from the logon token.'
        }
    }
    catch {
        Stop-ScriptGracefully -Message ('Removal denied: {0} No confirmation prompt or directory removal was started.' -f $_.Exception.Message)
    }
    finally { $identity.Dispose() }
    Write-Status -Kind Success -Message 'Administrator elevation, Domain Admins and Enterprise Admins confirmed in the current logon token.'
}

function Read-LabRemovalConfirmation {
    [CmdletBinding()]
    param([int]$ObjectCount, [string]$InventoryPath)
    # Fixed 15-second deadline: input does NOT disable or reset the timer.
    # Default focus, Enter, Escape, close, timeout and UI failure all cancel.
    $form = $null
    $timer = $null
    $deadline = New-Object System.Diagnostics.Stopwatch
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        $form = New-Object System.Windows.Forms.Form
        $form.Text = 'Remove ALL recorded generated content?'
        $form.ClientSize = New-Object System.Drawing.Size(700, 305)
        $form.StartPosition = 'CenterScreen'
        $form.FormBorderStyle = 'FixedDialog'
        $form.MaximizeBox = $false
        $form.MinimizeBox = $false
        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(18, 15)
        $label.Size = New-Object System.Drawing.Size(665, 220)
        $label.Text = ("DESTRUCTIVE REMOVAL: {0} configured-content inventory entries, INCLUDING objects from older runs.`r`n`r`n{1}`r`n`r`nRecorded OUs, AD sites and DNS zones will be removed WITH ALL DESCENDANTS, including unrecorded/pre-existing content. No rollback.`r`n`r`nChoose REMOVE ALL within 15 seconds; otherwise CANCEL." -f $ObjectCount,$InventoryPath)
        $remove = New-Object System.Windows.Forms.Button
        $remove.Text = 'REMOVE ALL'
        $remove.Location = New-Object System.Drawing.Point(450, 255)
        $remove.Size = New-Object System.Drawing.Size(105, 30)
        $remove.DialogResult = [Windows.Forms.DialogResult]::Yes
        $cancel = New-Object System.Windows.Forms.Button
        $cancel.Text = 'Cancel (default)'
        $cancel.Location = New-Object System.Drawing.Point(565, 255)
        $cancel.Size = New-Object System.Drawing.Size(120, 30)
        $cancel.DialogResult = [Windows.Forms.DialogResult]::Cancel
        $form.Controls.AddRange([Windows.Forms.Control[]]@($label,$remove,$cancel))
        $form.AcceptButton = $cancel
        $form.CancelButton = $cancel
        $form.ActiveControl = $cancel
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = 15000
        $timer.Add_Tick({ $form.DialogResult = [Windows.Forms.DialogResult]::Cancel; $form.Close() }.GetNewClosure())
        $form.Add_Shown({ $deadline.Start(); $timer.Start(); [void]$cancel.Focus() }.GetNewClosure())
        $answer = $form.ShowDialog()
        return ($answer -eq [Windows.Forms.DialogResult]::Yes -and $deadline.Elapsed.TotalSeconds -lt 15)
    }
    catch {
        Write-Status -Kind Warning -Message ('Removal confirmation unavailable; canceled safely: {0}' -f $_.Exception.Message)
        return $false
    }
    finally {
        $deadline.Stop()
        if ($null -ne $timer) { $timer.Stop(); $timer.Dispose() }
        if ($null -ne $form) { $form.Dispose() }
    }
}

function Get-LabInventoryADObject {
    [CmdletBinding()]
    param($Domain, [guid]$Identity)
    # Search by GUID in hosted naming contexts. Zero matches means absent;
    # any access/connection/search error propagates instead of meaning absent.
    $server = [string]$Domain.SelectedDomainController
    $root = Get-ADRootDSE -Server $server -ErrorAction Stop
    $escaped = ($Identity.ToByteArray() | ForEach-Object { '\{0:X2}' -f $_ }) -join ''
    $objects = @(
        foreach ($context in @($root.namingContexts | Sort-Object -Unique)) {
            if ($context -ine [string]$root.schemaNamingContext) {
                Get-ADObject -LDAPFilter ('(objectGUID={0})' -f $escaped) -SearchBase $context -SearchScope Subtree `
                    -Properties ProtectedFromAccidentalDeletion,userAccountControl -Server $server -ErrorAction Stop
            }
        }
    )
    if ($objects.Count -gt 1) { throw 'GUID lookup was ambiguous.' }
    if ($objects.Count -eq 1) { return $objects[0] }
    return $null
}

function Remove-LabInventoryADObject {
    [CmdletBinding()]
    param($Domain, $Entry)
    $server = [string]$Domain.SelectedDomainController
    $classes = @{ User='user'; Computer='computer'; Group='group'; OU='organizationalUnit'; Site='site'; SiteLink='siteLink'; Subnet='subnet'; WmiFilter='msWMI-Som'; FGPP='msDS-PasswordSettings' }
    $identity = [guid]$Entry.ObjectGuid
    $object = Get-LabInventoryADObject -Domain $Domain -Identity $identity
    if ($null -eq $object) { return 'Already absent' }
    if ($object.ObjectClass -ine $classes[$Entry.Kind]) { throw 'Recorded GUID has an unexpected object class.' }
    $object = Get-ADObject -Identity $identity -Properties ProtectedFromAccidentalDeletion,objectSid,sAMAccountName,isCriticalSystemObject,userAccountControl `
        -Server $server -ErrorAction Stop
    if (Test-LabInventoryProtectedObject -Object $object -Domain $Domain) { throw 'Built-in, critical, DC or existing-only reference cleanup target is excluded.' }
    $recursive = $Entry.Kind -in @('OU','Site')
    $subtree = @($object)
    if ($recursive) {
        $subtree = @(Get-ADObject -Filter * -SearchBase $object.DistinguishedName -SearchScope Subtree `
            -Properties ProtectedFromAccidentalDeletion,userAccountControl,objectSid,sAMAccountName,isCriticalSystemObject -Server $server -ErrorAction Stop)
        if (@($subtree | Where-Object { [guid]$_.ObjectGUID -eq $identity }).Count -ne 1) { throw 'Container subtree identity could not be verified.' }
    }
    foreach ($child in $subtree) {
        if (Test-LabInventoryProtectedObject -Object $child -Domain $Domain) { throw ('Protected built-in/reference object in target tree; entire container removal blocked: {0}' -f $child.DistinguishedName) }
        if (([int]$child.userAccountControl -band 8192) -ne 0 -or $child.ObjectClass -ieq 'nTDSDSA') {
            throw 'A domain controller account/NTDS Settings object is in the target tree. Demote or relocate the DC explicitly; automatic DC deletion is blocked.'
        }
    }
    # Protection is deliberately cleared ONLY inside the approved target.
    # No recursive ACL ownership takeover or parent-permission changes.
    foreach ($child in $subtree) {
        if ($child.ProtectedFromAccidentalDeletion -eq $true) {
            Set-ADObject -Identity $child.ObjectGUID -ProtectedFromAccidentalDeletion $false -Server $server -ErrorAction Stop
        }
    }
    $current = Get-ADObject -Identity $identity -Server $server -ErrorAction Stop
    if ($current.ObjectClass -ine $classes[$Entry.Kind] -or $current.DistinguishedName -ine $object.DistinguishedName) {
        throw 'Target moved or changed class during cleanup; deletion refused.'
    }
    if ($Entry.Kind -eq 'FGPP') {
        # Delete the PSO itself, regardless of current msDS-PSOAppliesTo links.
        Remove-ADFineGrainedPasswordPolicy -Identity $identity -Server $server -Confirm:$false -ErrorAction Stop
    }
    else {
        Remove-ADObject -Identity $identity -Recursive:$recursive -Server $server -Confirm:$false -ErrorAction Stop
    }
    if ($null -ne (Get-LabInventoryADObject -Domain $Domain -Identity $identity)) { throw 'GUID still exists after removal.' }
    return 'Removed'
}

function Remove-LabInventoryGpo {
    [CmdletBinding()]
    param($Domain, $Entry)
    $server = [string]$Domain.SelectedDomainController
    $guid = [guid]$Entry.GpoGuid
    if ($guid.ToString() -in @('31b2f340-016d-11d2-945f-00c04fb984f9','6ac1786c-016f-11d2-945f-00c04fb984f9')) { throw 'Default domain/DC policies cannot be removed.' }
    $policyDN = 'CN={{{0}}},CN=Policies,CN=System,{1}' -f $guid.ToString().ToUpperInvariant(),$Domain.DistinguishedName
    $escapedDN = ConvertTo-LdapFilterValue -Value $policyDN
    $gpos = @(Get-ADObject -LDAPFilter ('(&(objectClass=groupPolicyContainer)(distinguishedName={0}))' -f $escapedDN) `
        -SearchBase $Domain.DistinguishedName -Server $server -ErrorAction Stop)
    # Enumerate live gPLink attributes, NOT only the original inventory links.
    # This also removes orphan links when the GPO itself is already absent.
    $root = Get-ADRootDSE -Server $server -ErrorAction Stop
    $linkFilter = '(gPLink=*{0}*)' -f $escapedDN
    $targets = @(
        Get-ADObject -LDAPFilter $linkFilter -SearchBase $Domain.DistinguishedName -Properties gPLink -Server $server -ErrorAction Stop
        Get-ADObject -LDAPFilter $linkFilter -SearchBase ('CN=Sites,{0}' -f $root.configurationNamingContext) -Properties gPLink -Server $server -ErrorAction Stop
    )
    foreach ($target in $targets) {
        # Exact segment check prevents partial GUID/path matches.
        $segments = [regex]::Matches([string]$target.gPLink, '\[LDAP://(?<DN>[^;]+);[0-9]+\]')
        if (@($segments | Where-Object { $_.Groups['DN'].Value -ieq $policyDN }).Count -gt 0) {
            Remove-GPLink -Guid $guid -Target $target.DistinguishedName -Domain $Domain.DNSRoot -Server $server -Confirm:$false -ErrorAction Stop | Out-Null
        }
    }
    $remaining = @(
        Get-ADObject -LDAPFilter $linkFilter -SearchBase $Domain.DistinguishedName -Server $server -ErrorAction Stop
        Get-ADObject -LDAPFilter $linkFilter -SearchBase ('CN=Sites,{0}' -f $root.configurationNamingContext) -Server $server -ErrorAction Stop
    )
    if ($remaining.Count -gt 0) { throw 'GPO links remain; policy removal was not attempted.' }
    if ($gpos.Count -eq 0) { return 'Already absent (links checked)' }
    if ($gpos.Count -ne 1) { throw 'GPO directory identity is ambiguous.' }
    Remove-GPO -Guid $guid -Domain $Domain.DNSRoot -Server $server -Confirm:$false -ErrorAction Stop
    $remaining = @(Get-ADObject -LDAPFilter ('(distinguishedName={0})' -f $escapedDN) -SearchBase $Domain.DistinguishedName -Server $server -ErrorAction Stop)
    if ($remaining.Count -gt 0) { throw 'GPO directory object remains after removal.' }
    return 'Removed'
}

function Remove-LabInventoryDnsObject {
    [CmdletBinding()]
    param($Domain, $Entry)
    if ($Entry.Kind -eq 'DnsZone' -and ($Entry.ZoneName -ieq $Domain.DNSRoot -or $Entry.ZoneName -ilike '_msdcs.*')) { throw 'AD domain and forest-locator DNS zones cannot be removed.' }
    $server = [string]$Domain.SelectedDomainController
    if ([string]::IsNullOrWhiteSpace([string]$Entry.ObjectGuid) -or [string]::IsNullOrWhiteSpace([string]$Entry.ZoneGuid)) {
        throw 'Unresolved DNS directory identity; refusing name-only deletion. Review this partial creation manually.'
    }
    $zone = Get-LabInventoryADObject -Domain $Domain -Identity ([guid]$Entry.ZoneGuid)
    if ($null -eq $zone) { return 'Already absent' }
    if ($zone.ObjectClass -ine 'dnsZone' -or $zone.Name -ine $Entry.ZoneName) { throw 'DNS zone identity/name changed; no removal attempted.' }
    $providerZones = @(Get-DnsServerZone -ComputerName $server -ErrorAction Stop | Where-Object { $_.ZoneName -ieq $Entry.ZoneName })
    if ($providerZones.Count -eq 0) { throw 'Recorded zone exists in AD but is not hosted on the selected DNS server; no failover attempted.' }
    if ($providerZones.Count -ne 1 -or -not $providerZones[0].IsDsIntegrated) { throw 'DNS zone is not uniquely AD-integrated.' }
    $resolvedZone = Resolve-LabInventoryDnsZone -Domain $Domain -ZoneName $Entry.ZoneName
    if ([guid]$resolvedZone.ObjectGUID -ne [guid]$Entry.ZoneGuid) { throw 'A replacement DNS zone must not be removed.' }
    if ($Entry.Kind -eq 'DnsZone') {
        # Provider removal deletes every record/descendant in this owned zone.
        Remove-DnsServerZone -ComputerName $server -Name $Entry.ZoneName -Force -Confirm:$false -ErrorAction Stop
        if (@(Get-DnsServerZone -ComputerName $server -ErrorAction Stop | Where-Object { $_.ZoneName -ieq $Entry.ZoneName }).Count -ne 0) { throw 'DNS zone still exists after removal.' }
        return 'Removed with all descendants'
    }
    $node = Get-LabInventoryADObject -Domain $Domain -Identity ([guid]$Entry.ObjectGuid)
    if ($null -eq $node) { return 'Already absent' }
    if ($node.ObjectClass -ine 'dnsNode' -or $node.Name -ine $Entry.Name -or
        (Get-ParentDistinguishedName -DistinguishedName $node.DistinguishedName) -ine $zone.DistinguishedName) {
        throw 'DNS owner identity/location changed; no removal attempted.'
    }
    $records = @(Get-LabDnsNodeRecords -ComputerName $server -ZoneName $Entry.ZoneName -Name $Entry.Name | Where-Object {
        ([string]$_.RecordType -ieq $Entry.RecordType) -and (
            ($Entry.RecordType -eq 'A' -and [string]$_.RecordData.IPv4Address -eq $Entry.Data) -or
            ($Entry.RecordType -eq 'PTR' -and ([string]$_.RecordData.PtrDomainName).TrimEnd([char]46) -ieq ([string]$Entry.Data).TrimEnd([char]46)))
    })
    if ($records.Count -eq 0) { return 'Already absent (exact record)' }
    if ($records.Count -ne 1) { throw 'Exact DNS record identity is ambiguous.' }
    Remove-DnsServerResourceRecord -ComputerName $server -ZoneName $Entry.ZoneName -InputObject $records[0] -Force -Confirm:$false -ErrorAction Stop
    $remaining = @(Get-LabDnsNodeRecords -ComputerName $server -ZoneName $Entry.ZoneName -Name $Entry.Name | Where-Object {
        ([string]$_.RecordType -eq 'A' -and $Entry.RecordType -eq 'A' -and [string]$_.RecordData.IPv4Address -eq $Entry.Data) -or
        ([string]$_.RecordType -eq 'PTR' -and $Entry.RecordType -eq 'PTR' -and ([string]$_.RecordData.PtrDomainName).TrimEnd([char]46) -ieq ([string]$Entry.Data).TrimEnd([char]46))
    })
    if ($remaining.Count -ne 0) { throw 'Exact DNS record remains after removal.' }
    return 'Removed (unrelated records retained)'
}

function Test-LabRecordedInventoryEntryPresent {
    [CmdletBinding()]
    param($Domain, $Entry)
    if ($Entry.Kind -eq 'GPO') {
        $policyDN = 'CN={{{0}}},CN=Policies,CN=System,{1}' -f ([guid]$Entry.GpoGuid).ToString().ToUpperInvariant(),$Domain.DistinguishedName
        $filter = '(distinguishedName={0})' -f (ConvertTo-LdapFilterValue -Value $policyDN)
        return (@(Get-ADObject -LDAPFilter $filter -SearchBase $Domain.DistinguishedName -Server $Domain.SelectedDomainController -ErrorAction Stop).Count -gt 0)
    }
    if ([string]::IsNullOrWhiteSpace([string]$Entry.ObjectGuid)) { throw 'Recorded directory identity is unresolved.' }
    $object = Get-LabInventoryADObject -Domain $Domain -Identity ([guid]$Entry.ObjectGuid)
    if ($null -eq $object) { return $false }
    if ($Entry.Kind -ne 'DnsRecord') { return $true }
    $zones = @(Get-DnsServerZone -ComputerName $Domain.SelectedDomainController -ErrorAction Stop | Where-Object { $_.ZoneName -ieq $Entry.ZoneName })
    if ($zones.Count -eq 0) { throw 'DNS node still exists but its zone is not hosted; absence cannot be verified.' }
    return (@(Get-LabDnsNodeRecords -ComputerName $Domain.SelectedDomainController -ZoneName $Entry.ZoneName -Name $Entry.Name | Where-Object {
        ([string]$_.RecordType -ieq $Entry.RecordType) -and (
            ($Entry.RecordType -eq 'A' -and [string]$_.RecordData.IPv4Address -eq $Entry.Data) -or
            ($Entry.RecordType -eq 'PTR' -and ([string]$_.RecordData.PtrDomainName).TrimEnd([char]46) -ieq ([string]$Entry.Data).TrimEnd([char]46)))
    }).Count -gt 0)
}

function Invoke-LabGeneratedContentRemoval {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Domain)
    Test-LabRemovalRights -Domain $Domain
    $stream = $null; $reader = $null
    $script:LabInventoryReadOnlyMode = $true
    try {
        $path = Get-LabGeneratedInventoryPath
        # Lock and retain the trusted original. Read-only discovery refreshes
        # an IN-MEMORY union of recorded GUIDs and ALL baseline selectors.
        $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
        $reader = New-Object IO.StreamReader($stream)
        $inventory = ConvertFrom-Json -InputObject $reader.ReadToEnd() -ErrorAction Stop
        # Version labels are informational ONLY. Validate actual identities
        # and usable fields, not ScriptVersion, SchemaVersion or catalog age.
        if ($null -eq $inventory -or $inventory -isnot [System.Management.Automation.PSCustomObject]) {
            throw 'Inventory must contain one JSON object. Nothing was removed.'
        }
        $expectedIdentity = [ordered]@{
            DomainSID=[string]$Domain.DomainSID.Value
            DomainDN=[string]$Domain.DistinguishedName
            DomainDNSRoot=[string]$Domain.DNSRoot
        }
        foreach ($field in $expectedIdentity.Keys) {
            if ($null -eq $inventory.PSObject.Properties[$field] -or
                [string]::IsNullOrWhiteSpace([string]$inventory.$field)) {
                throw ('Inventory is missing required domain identity field [{0}]. Nothing was removed.' -f $field)
            }
            $identityMatches = ([string]$inventory.$field -ieq $expectedIdentity[$field])
            if ($field -eq 'DomainSID') { $identityMatches = ([string]$inventory.$field -ceq $expectedIdentity[$field]) }
            if (-not $identityMatches) {
                throw ('Inventory identity mismatch [{0}]: recorded=[{1}], current=[{2}]. Nothing was removed.' -f $field,$inventory.$field,$expectedIdentity[$field])
            }
        }
        if ($null -eq $inventory.PSObject.Properties['ScriptFile'] -or
            [string]::IsNullOrWhiteSpace([string]$inventory.ScriptFile)) {
            throw 'Inventory is missing required ScriptFile identity. Nothing was removed.'
        }
        $recordedBasename = [IO.Path]::GetFileNameWithoutExtension([string]$inventory.ScriptFile)
        $currentBasename = [IO.Path]::GetFileNameWithoutExtension($script:LabExecutingScriptFile)
        if ($recordedBasename -ine $currentBasename) {
            throw ('Inventory script basename mismatch: recorded=[{0}], current=[{1}]. Nothing was removed.' -f $recordedBasename,$currentBasename)
        }
        if ($null -eq $inventory.PSObject.Properties['Objects'] -or $inventory.Objects -isnot [array]) {
            throw 'Inventory must contain an Objects array (an empty array is allowed). Nothing was removed.'
        }
        # Saved catalogs are optional: current definitions are projected and
        # resolved below. The saved object identities remain cleanup targets.
        $inventoryRunId = [guid]::Empty
        if ($null -ne $inventory.PSObject.Properties['RunId']) {
            [void][guid]::TryParse([string]$inventory.RunId,[ref]$inventoryRunId)
        }
        if ($inventoryRunId -eq [guid]::Empty) {
            $inventoryRunId = [guid]::NewGuid()
            Write-Status -Kind Info -Message 'Inventory has no valid correlation RunId; using a new ID for this removal report only. Source JSON is unchanged.'
        }
        $inventoryIssues = New-Object System.Collections.ArrayList
        $recorded = New-Object System.Collections.ArrayList
        $kinds = @('User','Computer','Group','GPO','WmiFilter','FGPP','SiteLink','Subnet','Site','DnsRecord','DnsZone','OU')
        $entryIndex = -1
        foreach ($entry in @($inventory.Objects)) {
            $entryIndex++
            try {
                if ($null -eq $entry -or $entry -isnot [System.Management.Automation.PSCustomObject]) {
                    throw 'Saved entry is not a JSON object.'
                }
                if ($null -eq $entry.PSObject.Properties['Kind'] -or $entry.Kind -cnotin $kinds) {
                    throw 'Saved entry has an unknown or missing object kind.'
                }
                $copy = [ordered]@{}
                foreach ($property in $entry.PSObject.Properties) { $copy[$property.Name] = $property.Value }
                # Normalize absent optional fields for strict-mode safety.
                # An empty required identity is still rejected below.
                foreach ($field in @('ObjectGuid','ZoneGuid','ZoneName','Name','RecordType','Data','DistinguishedName')) {
                    if (-not $copy.Contains($field)) { $copy[$field] = '' }
                }
                if ($copy.Kind -eq 'GPO') {
                    if (-not $copy.Contains('GpoGuid') -or [guid]::Parse([string]$copy.GpoGuid) -eq [guid]::Empty) {
                        throw 'Saved entry has no nonempty GPO GUID.'
                    }
                }
                elseif ($copy.Kind -notin @('DnsZone','DnsRecord')) {
                    if ([guid]::Parse([string]$copy.ObjectGuid) -eq [guid]::Empty) { throw 'Saved entry has an empty object GUID.' }
                }
                else {
                    if ([string]::IsNullOrWhiteSpace([string]$copy.ZoneName)) { throw 'Saved DNS zone name is empty.' }
                    foreach ($field in @('ObjectGuid','ZoneGuid')) {
                        if ([guid]::Parse([string]$copy[$field]) -eq [guid]::Empty) { throw ('Saved DNS entry has an empty ' + $field + '.') }
                    }
                    if ($copy.Kind -eq 'DnsRecord' -and ($copy.RecordType -cnotin @('A','PTR') -or
                        [string]::IsNullOrWhiteSpace([string]$copy.Name) -or [string]::IsNullOrWhiteSpace([string]$copy.Data))) {
                        throw 'Saved DNS record identity is incomplete or its type is unsupported.'
                    }
                }
                # Prove the identity can be indexed before admitting this row.
                [void](Get-LabInventoryEntryKey -Entry $copy)
                [void]$recorded.Add($copy)
            }
            catch {
                $target = 'Inventory.Objects[{0}]' -f $entryIndex
                [void]$inventoryIssues.Add([ordered]@{ Target=$target; Message=$_.Exception.Message })
                Write-Status -Kind Warning -Message ('Skipping saved entry [{0}]: {1} Other usable entries will continue; independent current-baseline discovery still applies.' -f $entryIndex,$_.Exception.Message)
            }
        }
        # DNS discovery is needed even when the saved Objects list is empty.
        # Missing tools are discovery failures, not evidence of absence.
        $dnsModuleError = ''
        try { Import-Module DnsServer -Global -ErrorAction Stop }
        catch { $dnsModuleError = $_.Exception.Message }
        foreach ($command in @('Get-ADObject','Set-ADObject','Get-ADRootDSE','Remove-ADObject','Remove-ADFineGrainedPasswordPolicy')) { [void](Get-Command $command -Module ActiveDirectory -ErrorAction Stop) }
        $script:LabInventoryDomain = $Domain
        $script:LabInventoryIndex = @{}
        $script:LabGeneratedInventory = New-LabGeneratedInventory -Domain $Domain
        $script:LabGeneratedInventory.RunId = $inventoryRunId.ToString()
        foreach ($copy in $recorded) {
            $key = Get-LabInventoryEntryKey -Entry $copy
            if (-not $script:LabInventoryIndex.ContainsKey($key)) {
                [void]$script:LabGeneratedInventory.Objects.Add($copy)
                $script:LabInventoryIndex[$key] = $copy
            }
        }
        Sync-LabConfiguredInventory -Domain $Domain -Stage BeforeRemoval
        $preIssues = @($inventoryIssues) + @($script:LabGeneratedInventory.ScanIssues)
        # Freeze this identity list BEFORE confirmation. The post-removal scan
        # never starts another deletion pass or adopts replacement objects.
        $entries = @($script:LabGeneratedInventory.Objects)
        if ($dnsModuleError) { Write-Status -Kind Warning -Message ('DNS tools unavailable: {0}. DNS coverage is unresolved.' -f $dnsModuleError) }
        $gpoModuleError = ''
        if (@($entries | Where-Object { $_.Kind -eq 'GPO' }).Count -gt 0) {
            try {
                Import-Module GroupPolicy -Global -ErrorAction Stop
                foreach ($command in @('Remove-GPO','Remove-GPLink')) { [void](Get-Command $command -Module GroupPolicy -ErrorAction Stop) }
            }
            catch { $gpoModuleError = $_.Exception.Message }
        }
        if ($entries.Count -gt 0) {
            Write-SectionHeader -Message 'Removal is the ONLY selected operation'
            Write-Status -Kind Warning -BackgroundColor Red -Message ('Inventory: [{0}]. {1} recorded/resolved entries from EVERY baseline definition plus best-effort synthetic variants, including older runs. Approved OUs, sites and DNS zones include ALL descendants, even unrecorded/pre-existing content. No rollback.' -f $path,$entries.Count)
            if ($preIssues.Count -gt 0) { Write-Status -Kind Warning -Message 'Discovery is incomplete. Unresolved identities are not deleted by name; remaining targets and verification gaps will be reported.' }
            if (-not (Read-LabRemovalConfirmation -ObjectCount $entries.Count -InventoryPath $path)) {
                Write-Status -Kind Info -Message 'Removal canceled or timed out after 15 seconds. No directory objects were removed; original inventory unchanged.'
                return
            }
        }
        else { Write-Status -Kind Info -Message 'No existing identities resolved. Baseline catalog is still complete; verifying absence and any discovery gaps without a deletion prompt.' }
        $script:processingStopwatch = [Diagnostics.Stopwatch]::StartNew()
        $completed = 0; $failed = 0
        $results = New-Object System.Collections.ArrayList
        $order = @('User','Computer','Group','GPO','FGPP','WmiFilter','SiteLink','Subnet','Site','DnsRecord','DnsZone','OU')
        foreach ($kind in $order) {
            foreach ($entry in @($entries | Where-Object { $_.Kind -eq $kind } | Sort-Object -Property @{ Expression = { if ($_.Contains('DistinguishedName')) { ([string]$_.DistinguishedName).Length } else { 0 } }; Descending = $true })) {
                $key = Get-LabInventoryEntryKey -Entry $entry
                try {
                    if ($kind -eq 'GPO') {
                        if ($gpoModuleError) { throw ('GroupPolicy tools unavailable: ' + $gpoModuleError) }
                        $result = Remove-LabInventoryGpo -Domain $Domain -Entry $entry
                    }
                    elseif ($kind -in @('DnsRecord','DnsZone')) {
                        if ($dnsModuleError) { throw ('DNS tools unavailable: ' + $dnsModuleError) }
                        $result = Remove-LabInventoryDnsObject -Domain $Domain -Entry $entry
                    }
                    else { $result = Remove-LabInventoryADObject -Domain $Domain -Entry $entry }
                    $completed++
                    [void]$results.Add([ordered]@{ Key=$key; Kind=$kind; Status=$result; Message='' })
                    Write-Status -Kind Success -Message ('{0}: {1}. [{2}]' -f $kind,$result,$key)
                }
                catch {
                    $failed++
                    [void]$results.Add([ordered]@{ Key=$key; Kind=$kind; Status='Failed'; Message=$_.Exception.Message })
                    Write-Status -Kind Warning -Message ('{0} removal failed: {1}. [{2}]. Continuing; an approved container may still remove this entry.' -f $kind,$_.Exception.Message,$key)
                }
            }
        }
        # Verify both name/range selectors and every frozen recorded identity:
        # a renamed WMI filter may be found by its saved GUID, not its name.
        Sync-LabConfiguredInventory -Domain $Domain -Stage AfterRemoval
        $verificationIssues = New-Object System.Collections.ArrayList
        $remaining = New-Object System.Collections.ArrayList
        foreach ($entry in $entries) {
            $key = Get-LabInventoryEntryKey -Entry $entry
            try {
                if (Test-LabRecordedInventoryEntryPresent -Domain $Domain -Entry $entry) { [void]$remaining.Add($key) }
            }
            catch { [void]$verificationIssues.Add([ordered]@{ Key=$key; Message=$_.Exception.Message }) }
        }
        $baselineRemaining = 0; $syntheticRemaining = 0
        foreach ($target in $script:LabGeneratedInventory.BaselineCatalog) { $baselineRemaining += [int]$target.MatchCount }
        foreach ($target in $script:LabGeneratedInventory.SyntheticCatalog) { $syntheticRemaining += [int]$target.MatchCount }
        $postIssues = @($script:LabGeneratedInventory.ScanIssues)
        $status = 'NoTargetedContentFound'
        if ($failed -gt 0 -or $preIssues.Count -gt 0 -or $postIssues.Count -gt 0 -or $verificationIssues.Count -gt 0 -or $remaining.Count -gt 0 -or $baselineRemaining -gt 0 -or $syntheticRemaining -gt 0) { $status = 'ReviewRequired' }
        $report = [ordered]@{
            SchemaVersion=3; ScriptVersion='1.8.22'; InventoryPath=$path; RunId=$inventoryRunId.ToString()
            DomainSID=[string]$Domain.DomainSID.Value; SelectedDC=[string]$Domain.SelectedDomainController
            FinishedUtc=[DateTime]::UtcNow.ToString('o'); Status=$status
            RemovedOrAlreadyAbsent=$completed; EntryFailures=$failed
            SkippedInventoryEntries=$inventoryIssues.Count; InventoryIssues=@($inventoryIssues)
            RemainingBaselineMatches=$baselineRemaining; RemainingSyntheticMatches=$syntheticRemaining
            RemainingRecordedIdentities=@($remaining); VerificationIssues=@($verificationIssues)
            PreRemovalIssues=$preIssues; PostRemovalIssues=$postIssues; EntryResults=@($results)
            BaselineCatalog=$script:LabGeneratedInventory.BaselineCatalog
            SyntheticCatalog=$script:LabGeneratedInventory.SyntheticCatalog
            Limitations='Selected DC only; replication convergence not verified. Unknown historical WMI renames without preserved GUIDs/aliases can remain. Selector counts can overlap; they are not unique object totals.'
        }
        $suffix = '.RemovalResults.{0}.{1}.JSON' -f [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'),[guid]::NewGuid().ToString('N').Substring(0,8)
        $reportPath = Join-Path ([IO.Path]::GetDirectoryName($path)) ([IO.Path]::GetFileNameWithoutExtension($path) + $suffix)
        $reportStream = $null
        try {
            $reportStream = [IO.File]::Open($reportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
            $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $report -Depth 10) + [Environment]::NewLine)
            $reportStream.Write($bytes,0,$bytes.Length); $reportStream.Flush($true)
        }
        finally { if ($null -ne $reportStream) { $reportStream.Dispose() } }
        Write-Status -Kind Info -Message ('Removal finished [{0}]: {1} entries removed/already absent; {2} entry failures; remaining baseline/synthetic matches={3}/{4}; remaining recorded identities={5}; pre/post discovery issues={6}/{7}; verification gaps={8}. Original inventory unchanged; report [{9}]. No provisioning ran.' -f $status,$completed,$failed,$baselineRemaining,$syntheticRemaining,$remaining.Count,$preIssues.Count,$postIssues.Count,$verificationIssues.Count,$reportPath)
        Write-Status -Kind Info -Message 'Cleanup is best effort on the selected DC. Unknown historical WMI renames can remain; replication convergence is not verified. No blanket complete-removal claim is made.'
    }
    catch {
        Stop-ScriptGracefully -Message ('Removal stopped: {0}. No provisioning will run. Any earlier completed deletions remain committed; original inventory is retained. Review the transcript.' -f $_.Exception.Message)
    }
    finally {
        $script:LabInventoryReadOnlyMode = $false
        $script:LabInventoryCatalogTarget = $null
        if ($null -ne $reader) { $reader.Dispose() }
        elseif ($null -ne $stream) { $stream.Dispose() }
    }
}

function Format-OutputMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateRange(0, 10)]
        [int]$IndentLevel = $script:OutputIndentLevel
    )

    $prefix = ' ' * (2 * $IndentLevel)
    # Indent continuation lines as well as the first line of a message.
    return (($Message -split '\r?\n' | ForEach-Object { $prefix + $_ }) -join [Environment]::NewLine)
}

function Write-Status {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Kind,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateRange(0, 10)]
        [int]$IndentLevel = $script:OutputIndentLevel,

        [System.ConsoleColor]$BackgroundColor
    )

    $color = switch ($Kind) {
        'Info'    { 'Cyan' }
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
    }

    $outputMessage = '[{0}] {1}' -f $Kind.ToUpperInvariant(), $Message
    $hostParameters = @{ ForegroundColor = $color }
    # No implicit background: ordinary output and replication keep their styling.
    if ($PSBoundParameters.ContainsKey('BackgroundColor')) {
        $hostParameters.BackgroundColor = $BackgroundColor
    }
    Write-Host (Format-OutputMessage -Message $outputMessage -IndentLevel $IndentLevel) @hostParameters
}

function Write-SectionHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [System.ConsoleColor]$ForegroundColor = [System.ConsoleColor]::DarkGreen,

        [string]$Label = 'INFO'
    )

    # Headers never inherit the preceding section's/action's indentation.
    Write-Host ('[{0}] {1}' -f $Label, $Message.TrimStart()) -ForegroundColor $ForegroundColor -BackgroundColor Gray
    $script:OutputIndentLevel = 1
}

function Write-LabSectionCompleted {
    [CmdletBinding()]
    param()

    Assert-LabInventoryHealthy

    # Local wall-clock completion marker, not an elapsed-time/success claim.
    # Specify the culture and indentation; never inherit section/action state.
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
    Write-Host (Format-OutputMessage -Message ('[STATUS] section completed at: {0}' -f $timestamp) -IndentLevel 1) -ForegroundColor Magenta
}

function Write-LabDiskSpaceStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][double]$TotalBytes,
        [Parameter(Mandatory = $true)][double]$FreeBytes,
        [ValidateRange(0, 1048576)][double]$HighlightThresholdGB = 2,
        [ValidateRange(0, 10)][int]$IndentLevel = $script:OutputIndentLevel
    )

    $prefix = '[INFO] {0} | Total: {1:N2} GB | ' -f $Label, ($TotalBytes / 1GB)
    $available = 'Available: {0:N2} GB' -f ($FreeBytes / 1GB)
    Write-Host (Format-OutputMessage -Message $prefix -IndentLevel $IndentLevel) -ForegroundColor Cyan -NoNewline
    # Compare unrounded bytes; color only the Available field, not the prefix.
    if ($FreeBytes -lt ($HighlightThresholdGB * 1GB)) {
        Write-Host $available -ForegroundColor Yellow -BackgroundColor Red
    }
    else {
        Write-Host $available -ForegroundColor Cyan
    }

    # Mark only validated, successfully displayed disk values for the shared
    # post-inventory pause. Unknown/skipped disks cannot trigger it.
    if ($FreeBytes -lt ($DiskSpacePauseThresholdGB * 1GB)) {
        $script:LabDiskSpacePauseRequired = $true
    }
}

function Wait-LabDiskSpaceReview {
    [CmdletBinding()]
    param([ValidateRange(1, 300)][int]$Seconds = 10)

    if (-not $script:LabDiskSpacePauseRequired) { return }
    # Consume the shared flag so several low disks still cause only one wait.
    $script:LabDiskSpacePauseRequired = $false
    Write-Status -Kind Warning -BackgroundColor Red -Message ('At least one checked disk has less than {0:N2} GB free. Pausing {1} seconds for review, then continuing.' -f $DiskSpacePauseThresholdGB, $Seconds)
    Start-Sleep -Seconds $Seconds -ErrorAction Stop
}

function Show-LabLocalDiskSpace {
    [CmdletBinding()]
    param(
        [ValidateRange(0, 1048576)]
        [double]$WarningThresholdGB = 1
    )

    Write-SectionHeader -Message 'Check local fixed-disk space...'
    Write-Status -Kind Info -Message ('Computer: {0}. This section checks local fixed drives only; configured DSP servers are checked separately.' -f $env:COMPUTERNAME)
    $warningThresholdBytes = $WarningThresholdGB * 1GB
    try {
        # No ComputerName/CimSession: inventory is strictly local and read-only.
        $disks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType = 3' -ErrorAction Stop | Sort-Object -Property DeviceID)
    }
    catch {
        Write-Status -Kind Warning -BackgroundColor Red -Message ('Disk space could not be checked. Free space is UNKNOWN; continuing without a disk-space assessment. Details: {0}' -f $_.Exception.Message)
        return
    }

    if ($disks.Count -eq 0) {
        Write-Status -Kind Warning -BackgroundColor Red -Message 'No local fixed drives were returned. Free space is UNKNOWN; continuing without a disk-space assessment.'
        return
    }

    foreach ($disk in $disks) {
        try {
            if ($null -eq $disk.Size -or $null -eq $disk.FreeSpace) {
                throw 'Total or available disk space was not reported.'
            }
            $totalBytes = [double]$disk.Size
            $freeBytes = [double]$disk.FreeSpace
            if ($totalBytes -le 0 -or $freeBytes -lt 0 -or $freeBytes -gt $totalBytes) {
                throw 'Total or available disk space is invalid.'
            }
            Write-LabDiskSpaceStatus -Label ('Drive {0}' -f $disk.DeviceID) -TotalBytes $totalBytes -FreeBytes $freeBytes -HighlightThresholdGB $DiskSpaceHighlightThresholdGB
            # Compare raw bytes, not rounded display values; include exactly 1 GB.
            if ($freeBytes -le $warningThresholdBytes) {
                Write-Status -Kind Warning -BackgroundColor Red -Message ('*** LOW DISK SPACE *** Drive {0} is getting full: {1:N2} GB available (threshold: {2:N2} GB or less). Free space to avoid failed writes/backups. WARNING ONLY - the script will continue.' -f $disk.DeviceID, ($freeBytes / 1GB), $WarningThresholdGB)
            }
        }
        catch {
            Write-Status -Kind Warning -BackgroundColor Red -Message ('Disk space for drive {0} could not be assessed. Free space is UNKNOWN; continuing. Details: {1}' -f $disk.DeviceID, $_.Exception.Message)
        }
    }
}

function Get-LabDspScpRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$DirectoryServer,
        [Parameter(Mandatory = $true)][string]$DomainName,
        [Parameter(Mandatory = $true)][string]$ForestName,
        [ValidateRange(5, 300)][int]$TimeoutSeconds = 30
    )

    $job = $null
    try {
        # SCP serviceDNSName/keywords are read in each domain's full naming
        # context, not assumed to be present in a GC partial attribute set.
        $job = Start-Job -ArgumentList $DirectoryServer, $DomainName, $ForestName -ErrorAction Stop -ScriptBlock {
            param([string]$DirectoryServer, [string]$DomainName, [string]$ForestName)
            $ErrorActionPreference = 'Stop'
            Import-Module ActiveDirectory -ErrorAction Stop
            $forest = Get-ADForest -Identity $ForestName -Server $DirectoryServer -ErrorAction Stop
            $domains = @($forest.Domains | Sort-Object -Unique)
            if ($domains.Count -eq 0) { throw 'The forest returned no readable domain names.' }
            # Verified against DSP Consts.AdsnManagementSCP and ScpHelper:
            # management SCPs must advertise both collector/management roles.
            $filter = '(&(objectClass=serviceConnectionPoint)(name=Semperis.Adsn.Management)(keywords=Role=Management)(keywords=Role=Collector))'
            foreach ($name in $domains) {
                try {
                    $queryServer = [string]$name
                    if ($name -ieq $DomainName) { $queryServer = $DirectoryServer }
                    $rootDse = Get-ADRootDSE -Server $queryServer -ErrorAction Stop
                    if ([string]::IsNullOrWhiteSpace([string]$rootDse.defaultNamingContext)) {
                        throw 'No domain naming context was returned.'
                    }
                    $scps = @(Get-ADObject -LDAPFilter $filter -SearchBase ([string]$rootDse.defaultNamingContext) -SearchScope Subtree -Properties serviceDNSName -Server $queryServer -ErrorAction Stop)
                    foreach ($scp in $scps) {
                        [pscustomobject]@{
                            RecordType = 'Server'
                            ServerName = [string]$scp.serviceDNSName
                            SourceDN = [string]$scp.DistinguishedName
                        }
                    }
                }
                catch {
                    [pscustomobject]@{
                        RecordType = 'Warning'
                        Message = ('DSP SCP search in domain [{0}] could not be completed. Coverage is UNKNOWN. Details: {1}' -f $name, $_.Exception.Message)
                    }
                }
            }
        }
        $finished = Wait-Job -Job $job -Timeout $TimeoutSeconds -ErrorAction Stop
        if ($null -eq $finished) {
            throw ('DSP SCP discovery exceeded the {0}-second wait limit. Partial results were not used.' -f $TimeoutSeconds)
        }
        if ($job.State -ne 'Completed') {
            $reason = 'The DSP SCP discovery job did not complete successfully.'
            if ($job.ChildJobs.Count -gt 0 -and $null -ne $job.ChildJobs[0].JobStateInfo.Reason) {
                $reason = $job.ChildJobs[0].JobStateInfo.Reason.Message
            }
            throw $reason
        }
        Receive-Job -Job $job -ErrorAction Stop
    }
    finally {
        if ($null -ne $job) {
            try { Stop-Job -Job $job -ErrorAction SilentlyContinue | Out-Null } catch { }
            try { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue } catch { }
        }
    }
}

function Get-LabDspServerNames {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Domain,
        [ValidateRange(5, 300)][int]$TimeoutSeconds = 30
    )

    Write-SectionHeader -Message 'Discover DSP management servers from AD SCPs...'
    $names = @()
    try {
        $records = @(Get-LabDspScpRecords -DirectoryServer ([string]$Domain.SelectedDomainController) -DomainName ([string]$Domain.DNSRoot) -ForestName ([string]$Domain.Forest) -TimeoutSeconds $TimeoutSeconds)
        foreach ($record in $records) {
            if ($record.RecordType -eq 'Warning') {
                Write-Status -Kind Warning -BackgroundColor Red -Message ([string]$record.Message)
                continue
            }
            if ($record.RecordType -ne 'Server') { continue }
            $name = ([string]$record.ServerName).Trim().TrimEnd('.')
            if ([string]::IsNullOrWhiteSpace($name) -or [Uri]::CheckHostName($name) -eq [System.UriHostNameType]::Unknown -or $name -match '\s|[/\\]') {
                Write-Status -Kind Warning -BackgroundColor Red -Message ('DSP SCP [{0}] has no valid serviceDNSName. This registration was skipped; its disk space is UNKNOWN.' -f $record.SourceDN)
                continue
            }
            Write-Status -Kind Info -Message ('DSP management SCP discovered: [{0}] from [{1}].{2}       Registration does not prove current GPSM ownership or availability.' -f $name, $record.SourceDN, [Environment]::NewLine)
            $names += $name
        }
    }
    catch {
        Write-Status -Kind Warning -BackgroundColor Red -Message ('DSP SCP discovery could not be completed. DSP disk space is UNKNOWN; no additional credentials requested and AD activity will continue. Details: {0}' -f $_.Exception.Message)
        return
    }
    $names = @($names | Sort-Object -Unique)
    if ($names.Count -gt 1) {
        Write-Status -Kind Warning -Message 'Multiple DSP management-server hostnames were discovered. Each will be checked; stale or separate deployment registrations may be present.'
    }
    return $names
}

function Test-LabRemoteManagementPort {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][int]$Port,
        [ValidateRange(1, 700)][int]$TimeoutMilliseconds = 700
    )

    $client = New-Object System.Net.Sockets.TcpClient
    $waitHandle = $null
    try {
        $connection = $client.BeginConnect($ComputerName, $Port, $null, $null)
        $waitHandle = $connection.AsyncWaitHandle
        if (-not $waitHandle.WaitOne($TimeoutMilliseconds, $false)) { return $false }
        $client.EndConnect($connection)
        return $client.Connected
    }
    catch { return $false }
    finally {
        $client.Close()
        if ($null -ne $waitHandle) { $waitHandle.Close() }
    }
}

function Get-LabRemoteFixedDisks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [ValidateRange(5, 300)]
        [int]$TimeoutSeconds = 10
    )

    # The local job inherits the current user's identity. Its shared deadline
    # includes DNS, probes, authentication, query and fallback attempts.
    $job = $null
    try {
        $probeDefinition = ${function:Test-LabRemoteManagementPort}.ToString()
        $job = Start-Job -ArgumentList $ComputerName, $TimeoutSeconds, $probeDefinition -ErrorAction Stop -ScriptBlock {
            param([string]$RemoteComputerName, [int]$BudgetSeconds, [string]$PortProbeDefinition)
            $ErrorActionPreference = 'Stop'
            Set-Item -Path Function:Test-LabRemoteManagementPort -Value ([scriptblock]::Create($PortProbeDefinition))
            $clock = [System.Diagnostics.Stopwatch]::StartNew()
            # Standard endpoint choices only; do not discover/configure listeners.
            $endpoints = @(
                @{ Protocol = 'Wsman'; Port = 5985; UseSsl = $false }
                @{ Protocol = 'Wsman'; Port = 5986; UseSsl = $true }
                @{ Protocol = 'Dcom';  Port = 135;  UseSsl = $false }
            )
            $lastReason = 'No standard remote-management endpoint was reachable.'
            foreach ($endpoint in $endpoints) {
                $remainingMs = [int][Math]::Floor(($BudgetSeconds * 1000) - $clock.Elapsed.TotalMilliseconds)
                if ($remainingMs -le 0) { break }
                $probeWait = [Math]::Min(700, $remainingMs)
                if (-not (Test-LabRemoteManagementPort -ComputerName $RemoteComputerName -Port $endpoint.Port -TimeoutMilliseconds $probeWait)) { continue }
                $remainingSeconds = [int][Math]::Floor($BudgetSeconds - $clock.Elapsed.TotalSeconds)
                if ($remainingSeconds -lt 1) { break }
                $operationTimeoutSeconds = [Math]::Min(3, $remainingSeconds)
                $session = $null
                try {
                    $option = New-CimSessionOption -Protocol $endpoint.Protocol -ErrorAction Stop
                    $parameters = @{
                        ComputerName = $RemoteComputerName
                        SessionOption = $option
                        OperationTimeoutSec = $operationTimeoutSeconds
                        ErrorAction = 'Stop'
                    }
                    if ($endpoint.Protocol -eq 'Wsman') {
                        if ($endpoint.UseSsl) {
                            $parameters.SessionOption = New-CimSessionOption -UseSsl -ErrorAction Stop
                        }
                        $parameters.Port = $endpoint.Port
                        $parameters.Authentication = 'Kerberos'
                    }
                    $session = New-CimSession @parameters
                    $remainingSeconds = [int][Math]::Floor($BudgetSeconds - $clock.Elapsed.TotalSeconds)
                    if ($remainingSeconds -lt 1) { throw 'The shared remote-inventory deadline expired.' }
                    $operationTimeoutSeconds = [Math]::Min(3, $remainingSeconds)
                    $disks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType = 3' -CimSession $session -OperationTimeoutSec $operationTimeoutSeconds -ErrorAction Stop |
                        Select-Object -Property DeviceID, Size, FreeSpace)
                    if ($disks.Count -eq 0) { throw 'No fixed drives were returned.' }
                    return $disks
                }
                catch { $lastReason = $_.Exception.Message }
                finally {
                    if ($null -ne $session) {
                        try { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue } catch { }
                    }
                }
            }
            throw $lastReason
        }
        $finished = Wait-Job -Job $job -Timeout $TimeoutSeconds -ErrorAction Stop
        if ($null -eq $finished) {
            throw ('No usable disk inventory within the shared {0}-second wait budget.' -f $TimeoutSeconds)
        }
        if ($job.State -ne 'Completed') {
            $reason = 'No usable remote disk inventory was returned.'
            if ($job.ChildJobs.Count -gt 0 -and $null -ne $job.ChildJobs[0].JobStateInfo.Reason) {
                $reason = $job.ChildJobs[0].JobStateInfo.Reason.Message
            }
            throw $reason
        }
        # Only consume completed results; never publish partial timeout data.
        Receive-Job -Job $job -ErrorAction Stop
    }
    finally {
        if ($null -ne $job) {
            try { Stop-Job -Job $job -ErrorAction SilentlyContinue | Out-Null } catch { }
            try { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue } catch { }
        }
    }
}

function Show-LabDspDiskSpace {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$ComputerNames = @(),

        [ValidateRange(0, 1048576)]
        [double]$WarningThresholdGB = 1,

        [ValidateRange(5, 300)]
        [int]$TimeoutSeconds = 10
    )

    Write-SectionHeader -Message 'Check DSP server fixed-disk space...'
    $targets = @()
    foreach ($entry in @($ComputerNames)) {
        if ($null -eq $entry -or ($entry -is [string] -and [string]::IsNullOrWhiteSpace($entry))) { continue }
        if ($entry -isnot [string] -or $entry.Trim() -match '\s|[/\\]') {
            Write-Status -Kind Warning -BackgroundColor Red -Message 'Invalid DSP hostname returned by SCP discovery. Entry skipped; disk space is UNKNOWN.'
            continue
        }
        $targets += $entry.Trim()
    }
    $targets = @($targets | Sort-Object -Unique)
    if ($targets.Count -eq 0) {
        Write-Status -Kind Info -Message 'DSP disk-space check skipped: no valid DSP management-server hostnames were discovered. Free space is UNKNOWN.'
        return
    }

    $warningThresholdBytes = $WarningThresholdGB * 1GB
    foreach ($computerName in $targets) {
        Write-Status -Kind Info -Message ('DSP server [{0}]: best-effort CIM using logged-on Windows credentials{2}       shared wait budget {1} seconds plus job startup/cleanup. No additional credential prompts.' -f $computerName, $TimeoutSeconds, [Environment]::NewLine)
        try {
            $disks = @(Get-LabRemoteFixedDisks -ComputerName $computerName -TimeoutSeconds $TimeoutSeconds | Sort-Object -Property DeviceID)
            if ($disks.Count -eq 0) { throw 'No fixed drives were returned by the DSP server.' }
            foreach ($disk in $disks) {
                try {
                    if ($null -eq $disk.Size -or $null -eq $disk.FreeSpace) {
                        throw 'Total or available disk space was not reported.'
                    }
                    $totalBytes = [double]$disk.Size
                    $freeBytes = [double]$disk.FreeSpace
                    if ($totalBytes -le 0 -or $freeBytes -lt 0 -or $freeBytes -gt $totalBytes) {
                        throw 'Total or available disk space is invalid.'
                    }
                    Write-LabDiskSpaceStatus -Label ('DSP [{0}] Drive {1}' -f $computerName, $disk.DeviceID) -TotalBytes $totalBytes -FreeBytes $freeBytes -HighlightThresholdGB $DiskSpaceHighlightThresholdGB
                    if ($freeBytes -le $warningThresholdBytes) {
                        Write-Status -Kind Warning -BackgroundColor Red -Message ('*** LOW DISK SPACE ON DSP SERVER *** [{0}] Drive {1}: {2:N2} GB available (threshold: {3:N2} GB or less). DSP/GPSM backups may fail if this drive fills. WARNING ONLY - the script will continue.' -f $computerName, $disk.DeviceID, ($freeBytes / 1GB), $WarningThresholdGB)
                    }
                }
                catch {
                    Write-Status -Kind Warning -BackgroundColor Red -Message ('DSP [{0}] drive inventory could not be assessed. Free space is UNKNOWN; continuing with other drives. Details: {1}' -f $computerName, $_.Exception.Message)
                }
            }
        }
        catch {
            Write-Status -Kind Info -Message ('DSP disk-space check skipped for [{0}]. Free space is UNKNOWN; no usable remote inventory. Continuing without additional credentials or configuration changes. Details: {1}' -f $computerName, $_.Exception.Message)
        }
    }
}

function Write-CredentialStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Operational', 'Success', 'Warning', 'Error')]
        [string]$Kind,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [switch]$NoNewline,

        [ValidateRange(0, 10)]
        [int]$IndentLevel = $script:OutputIndentLevel
    )

    $foregroundColor = switch ($Kind) {
        'Operational' { 'Cyan' }
        'Success'     { 'Green' }
        'Warning'     { 'Yellow' }
        'Error'       { 'Red' }
    }

    $outputMessage = Format-OutputMessage -Message $Message -IndentLevel $IndentLevel
    if ($NoNewline) {
        Write-Host $outputMessage -ForegroundColor $foregroundColor -NoNewline
    }
    else {
        Write-Host $outputMessage -ForegroundColor $foregroundColor
    }
}

function Stop-ScriptGracefully {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateRange(0, 10)]
        [int]$IndentLevel = $script:OutputIndentLevel
    )

    Write-Status -Kind Error -Message $Message -IndentLevel $IndentLevel
    throw [System.OperationCanceledException]::new($Message)
}

function Initialize-CredentialNativeApi {
    [CmdletBinding()]
    param()

    $nativeTypeName = 'Semperis.Adfr.CredentialNativeV3'
    if ($null -eq ($nativeTypeName -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace Semperis.Adfr
{
    public static class CredentialNativeV3
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct FILETIME
        {
            public UInt32 LowDateTime;
            public UInt32 HighDateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CREDENTIAL
        {
            public UInt32 Flags;
            public UInt32 Type;
            public IntPtr TargetName;
            public IntPtr Comment;
            public FILETIME LastWritten;
            public UInt32 CredentialBlobSize;
            public IntPtr CredentialBlob;
            public UInt32 Persist;
            public UInt32 AttributeCount;
            public IntPtr Attributes;
            public IntPtr TargetAlias;
            public IntPtr UserName;
        }

        // Read directly into SecureString so PowerShell does not have to
        // marshal the nested native structure itself.
        public static System.Security.SecureString ReadPassword(IntPtr credentialPointer)
        {
            CREDENTIAL credential = Marshal.PtrToStructure<CREDENTIAL>(credentialPointer);
            int blobSize = checked((int)credential.CredentialBlobSize);
            if (blobSize < 2)
                return null;

            System.Security.SecureString password = new System.Security.SecureString();
            try
            {
                for (int offset = 0; offset + 1 < blobSize; offset += 2)
                {
                    short characterCode = Marshal.ReadInt16(credential.CredentialBlob, offset);
                    if (characterCode == 0)
                        break;
                    password.AppendChar((char)characterCode);
                }

                if (password.Length == 0)
                {
                    password.Dispose();
                    return null;
                }

                password.MakeReadOnly();
                return password;
            }
            catch
            {
                password.Dispose();
                throw;
            }
        }

        [DllImport("Advapi32.dll", EntryPoint = "CredReadW",
            CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CredReadNative(
            string target,
            UInt32 type,
            UInt32 flags,
            out IntPtr credential
        );

        // Capture the native error before returning through PowerShell.
        public static bool CredRead(string target, UInt32 type, UInt32 flags, out IntPtr credential, out int error)
        {
            bool succeeded = CredReadNative(target, type, flags, out credential);
            error = succeeded ? 0 : Marshal.GetLastWin32Error();
            return succeeded;
        }

        [DllImport("Advapi32.dll", EntryPoint = "CredWriteW",
            CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CredWriteNative(
            ref CREDENTIAL credential,
            UInt32 flags
        );

        // Capture the native error before returning through PowerShell.
        public static bool CredWrite(ref CREDENTIAL credential, UInt32 flags, out int error)
        {
            bool succeeded = CredWriteNative(ref credential, flags);
            error = succeeded ? 0 : Marshal.GetLastWin32Error();
            return succeeded;
        }

        [DllImport("Advapi32.dll", EntryPoint = "CredDeleteW",
            CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CredDeleteNative(
            string target,
            UInt32 type,
            UInt32 flags
        );

        // Capture the native error before returning through PowerShell.
        public static bool CredDelete(string target, UInt32 type, UInt32 flags, out int error)
        {
            bool succeeded = CredDeleteNative(target, type, flags);
            error = succeeded ? 0 : Marshal.GetLastWin32Error();
            return succeeded;
        }

        [DllImport("Advapi32.dll", EntryPoint = "CredFree",
            SetLastError = false)]
        public static extern void CredFree(IntPtr buffer);
    }
}
'@ -ErrorAction Stop
    }
}

function Test-AdwsConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [ValidateRange(100, 30000)]
        [int]$TimeoutMilliseconds = 2000
    )

    # Avoid an AD cmdlet's longer connection timeout for a powered-off DC.
    # This bounds the TCP connection wait, not DNS or a subsequent AD query.
    $client = New-Object System.Net.Sockets.TcpClient
    $waitHandle = $null
    try {
        $connection = $client.BeginConnect($Server, 9389, $null, $null)
        $waitHandle = $connection.AsyncWaitHandle
        if (-not $waitHandle.WaitOne($TimeoutMilliseconds, $false)) {
            return $false
        }
        $client.EndConnect($connection)
        return $client.Connected
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
        if ($null -ne $waitHandle) {
            $waitHandle.Close()
        }
    }
}

function Write-LabReplicationNotificationStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ConfigurationNamingContext
    )

    # This is a read-only configuration check, not a convergence test.
    # Intra-site notification is separate; there is no domain-wide Boolean.
    # Site-link options bit 0x1 is NTDSSITELINK_OPT_USE_NOTIFY. Test the bit,
    # not equality to 1, because other options can be enabled simultaneously.
    try {
        if ([string]::IsNullOrWhiteSpace($ConfigurationNamingContext)) {
            throw 'The configuration naming context was not returned.'
        }
        $transportDN = 'CN=IP,CN=Inter-Site Transports,CN=Sites,{0}' -f $ConfigurationNamingContext
        $links = @(Get-ADObject -LDAPFilter '(objectClass=siteLink)' -SearchBase $transportDN `
            -SearchScope OneLevel -Properties options -Server $Server -ErrorAction Stop)
        if ($links.Count -eq 0) {
            Write-Status -Kind Info -Message 'AD inter-site change notification: Not applicable (no readable IP site links found). Intra-site notification is separate.'
            return
        }
        $states = @()
        foreach ($link in ($links | Sort-Object Name)) {
            $enabled = (([int]$link.options -band 1) -ne 0)
            $states += ('{0}={1}' -f $link.Name, $enabled)
        }
        $continuation = [Environment]::NewLine + '       '
        Write-Status -Kind Info -Message ('AD inter-site change notification enabled (IP site links):{0}{1}{0}Configured flags only; intra-site notification is separate.' -f $continuation, ($states -join $continuation))
    }
    catch {
        # Diagnostic failures must not reject a validated writable DC or turn
        # an unreadable setting into False. Keep INFO directly before SUCCESS.
        Write-Status -IndentLevel 2 -Kind Warning -Message ('Could not read IP site-link change notification settings on [{0}]: {1}' -f $Server, $_.Exception.Message)
        Write-Status -Kind Info -Message ('AD inter-site change notification enabled (IP site links):{0}       Unknown (configuration could not be read)' -f [Environment]::NewLine)
    }
}

function Get-ValidatedDomainContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedDomainName
    )

    Write-Status -Kind Info -Message ("Checking domain controller '{0}'." -f $Server)
    if (-not (Test-AdwsConnection -Server $Server)) {
        Write-Status -Kind Warning -Message ("Skipping '{0}': AD Web Services TCP 9389 is not reachable (2-second connection wait)." -f $Server)
        return $null
    }

    try {
        # An open port alone is not enough: verify actual ADWS queries and
        # reject read-only DCs before choosing a server for OU provisioning.
        $rootDse = Get-ADRootDSE -Server $Server -ErrorAction Stop
        $controller = Get-ADDomainController -Identity $Server -Server $Server -ErrorAction Stop
        if ($controller.IsReadOnly) {
            throw 'This is a read-only domain controller; a writable DC is required.'
        }

        $domain = Get-ADDomain -Identity $rootDse.DefaultNamingContext -Server $Server -ErrorAction Stop
        if ($domain.DNSRoot -ine $ExpectedDomainName) {
            throw ("The DC belongs to '{0}', not the computer's domain '{1}'." -f $domain.DNSRoot, $ExpectedDomainName)
        }

        # Keep the real PDCEmulator property intact. All later AD commands use
        # this separate, validated server instead of requiring the FSMO holder.
        Add-Member -InputObject $domain -MemberType NoteProperty `
            -Name SelectedDomainController -Value $Server -Force
        Write-LabReplicationNotificationStatus -Server $Server -ConfigurationNamingContext ([string]$rootDse.configurationNamingContext)
        Write-Status -Kind Success -Message ("AD connectivity confirmed for {0}. Selected writable DC: {1}." -f $domain.DNSRoot, $Server)
        return $domain
    }
    catch {
        Write-Status -Kind Warning -Message ("Skipping domain controller '{0}': {1}" -f $Server, $_.Exception.Message)
        return $null
    }
}

# Windows management modules are OS components, not PowerShell Gallery packages.
function Get-LabManagementToolDefinition {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)

    switch ($Name) {
        'ActiveDirectory' {
            return [pscustomobject]@{
                Feature = 'RSAT-AD-PowerShell'
                Capability = 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
            }
        }
        'GroupPolicy' {
            return [pscustomobject]@{
                Feature = 'GPMC'
                Capability = 'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0'
            }
        }
        'DnsServer' {
            return [pscustomobject]@{
                Feature = 'RSAT-DNS-Server'
                Capability = 'Rsat.Dns.Tools~~~~0.0.1.0'
            }
        }
        'repadmin.exe' {
            return [pscustomobject]@{
                Feature = 'RSAT-ADDS-Tools'
                Capability = 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
            }
        }
        default { throw ('No standalone Windows management-tools installer is defined for [{0}]. Repair the inbox Windows/PowerShell component; no Gallery package will be substituted.' -f $Name) }
    }
}

function Install-LabWindowsManagementTools {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)

    $definition = Get-LabManagementToolDefinition -Name $Name
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Windows RSAT installation requires Windows.'
    }
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        throw 'Run the script in 64-bit Windows PowerShell to install and load Windows management tools.'
    }
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Installing Windows management tools requires elevation. Reopen Windows PowerShell as Administrator and rerun.'
        }
    }
    finally { $identity.Dispose() }

    # Read local OS type without depending on the AD or CIM modules being ready.
    $product = Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ProductOptions' -Name ProductType -ErrorAction Stop
    $productType = [string]$product.ProductType
    if ($productType -in @('ServerNT', 'LanmanNT')) {
        Import-Module ServerManager -Global -ErrorAction Stop | Out-Null
        Get-Command Install-WindowsFeature -Module ServerManager -ErrorAction Stop | Out-Null
        $featureName = [string]$definition.Feature
        Write-Status -IndentLevel 2 -Kind Info -Message ('Installing/repairing Windows Server feature [{0}] for [{1}] (no automatic reboot).' -f $featureName, $Name)
        # Use the fixed known name even if inventory is empty or inconclusive.
        # Do not specify -Restart and do not install/promote a server role.
        $result = Install-WindowsFeature -Name $featureName -ErrorAction Stop
        if ($null -eq $result) { throw ('Feature [{0}] installation returned no result.' -f $featureName) }
        if ([string]$result.RestartNeeded -in @('Yes', 'True')) {
            throw ('Feature [{0}] requires a restart. Restart manually and rerun; the script will not reboot or start provisioning.' -f $featureName)
        }
        if ($result.Success -ne $true) {
            throw ('Feature [{0}] installation failed. ExitCode: {1}. Check Windows servicing logs and the configured feature source.' -f $featureName, $result.ExitCode)
        }
        $confirmed = @(Get-WindowsFeature -Name $featureName -ErrorAction Stop | Where-Object {
            $_.Name -ieq $featureName -and $_.Installed -eq $true
        })
        if ($confirmed.Count -ne 1) { throw ('Feature [{0}] was not confirmed installed after the installation attempt.' -f $featureName) }
    }
    elseif ($productType -ieq 'WinNT') {
        Import-Module Dism -Global -ErrorAction Stop | Out-Null
        Get-Command Add-WindowsCapability -Module Dism -ErrorAction Stop | Out-Null
        $capabilityName = [string]$definition.Capability
        Write-Status -IndentLevel 2 -Kind Info -Message ('Installing/repairing Windows capability [{0}] for [{1}] (no automatic reboot).' -f $capabilityName, $Name)
        # Inventory can contain a blank Name on some hosts. Never feed its
        # returned Name into servicing: always use the complete fixed name.
        $result = Add-WindowsCapability -Online -Name $capabilityName -NoRestart -ErrorAction Stop
        if ($null -eq $result) { throw ('Capability [{0}] installation returned no result.' -f $capabilityName) }
        if ([string]$result.RestartNeeded -in @('Yes', 'True')) {
            throw ('Capability [{0}] requires a restart. Restart manually and rerun; the script will not reboot or start provisioning.' -f $capabilityName)
        }
        $confirmed = @(Get-WindowsCapability -Online -Name $capabilityName -ErrorAction Stop | Where-Object {
            $_.Name -ieq $capabilityName -and [string]$_.State -ieq 'Installed'
        })
        if ($confirmed.Count -ne 1) {
            throw ('Capability [{0}] was not confirmed installed after the installation attempt. Check supported Windows edition, servicing logs, Features on Demand/Windows Update access and WSUS policy.' -f $capabilityName)
        }
    }
    else { throw ('Unrecognized Windows ProductType [{0}]; automatic feature/capability installation was not attempted.' -f $productType) }

    Write-Status -IndentLevel 2 -Kind Success -Message ('Windows management tools for [{0}] are installed; verifying actual module/command availability next.' -f $Name)
}

function Import-LabPrerequisiteModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Purpose,
        [switch]$SkipInstallation
    )

    Write-Status -Kind Info -Message ('Checking PowerShell module [{0}].' -f $Name)
    # One initial import and at most one OS installation/import retry.
    for ($attempt = 0; $attempt -lt 2; $attempt++) {
        try {
            if ($attempt -eq 1) { Install-LabWindowsManagementTools -Name $Name }
            Write-Status -IndentLevel 3 -Kind Info -Message ('Import-Module {0}' -f $Name)
            # Force refresh only after servicing, not on a healthy loaded module.
            Import-Module -Name $Name -Global -Force:($attempt -eq 1) -ErrorAction Stop | Out-Null
            if (@(Get-Module -Name $Name -ErrorAction Stop).Count -eq 0) {
                throw ('Module [{0}] did not appear in the loaded-module list after import.' -f $Name)
            }
            # Verify cmdlets as well as module presence, including partial installs.
            $commands = @()
            switch ($Name) {
                'ActiveDirectory' { $commands = @('Add-ADFineGrainedPasswordPolicySubject', 'Add-ADGroupMember', 'Get-ADComputer', 'Get-ADDefaultDomainPasswordPolicy', 'Get-ADDomain', 'Get-ADDomainController', 'Get-ADFineGrainedPasswordPolicy', 'Get-ADForest', 'Get-ADGroup', 'Get-ADObject', 'Get-ADOrganizationalUnit', 'Get-ADReplicationSite', 'Get-ADRootDSE', 'Get-ADUser', 'Get-ADUserResultantPasswordPolicy', 'Move-ADObject', 'New-ADComputer', 'New-ADFineGrainedPasswordPolicy', 'New-ADGroup', 'New-ADObject', 'New-ADOrganizationalUnit', 'New-ADReplicationSite', 'New-ADReplicationSubnet', 'New-ADUser', 'Remove-ADComputer', 'Remove-ADFineGrainedPasswordPolicySubject', 'Remove-ADGroupMember', 'Remove-ADObject', 'Remove-ADOrganizationalUnit', 'Remove-ADReplicationSubnet', 'Rename-ADObject', 'Set-ADAccountPassword', 'Set-ADComputer', 'Set-ADFineGrainedPasswordPolicy', 'Set-ADGroup', 'Set-ADObject', 'Set-ADOrganizationalUnit', 'Set-ADReplicationSite', 'Set-ADReplicationSubnet', 'Set-ADUser') }
                'GroupPolicy' { $commands = @('Backup-GPO', 'Get-GPO', 'Get-GPOReport', 'Get-GPRegistryValue', 'New-GPO', 'Remove-GPRegistryValue', 'Set-GPRegistryValue') }
                'DnsServer' { $commands = @('Add-DnsServerPrimaryZone', 'Add-DnsServerResourceRecordA', 'Add-DnsServerResourceRecordPtr', 'Get-DnsServerResourceRecord', 'Get-DnsServerZone', 'Remove-DnsServerResourceRecord', 'Set-DnsServerPrimaryZone', 'Set-DnsServerResourceRecord') }
                'CimCmdlets' { $commands = @('Get-CimInstance', 'New-CimSession', 'New-CimSessionOption', 'Remove-CimSession') }
                'DnsClient' { $commands = @('Resolve-DnsName') }
            }
            foreach ($command in $commands) {
                Get-Command -Name $command -Module $Name -ErrorAction Stop | Out-Null
            }
            Write-Status -IndentLevel 2 -Kind Success -Message ('Module [{0}] is available and loaded; required commands verified.' -f $Name)
            return $true
        }
        catch {
            $detail = $_.Exception.Message
            if ($attempt -eq 0 -and -not $SkipInstallation) {
                Write-Status -IndentLevel 2 -Kind Warning -BackgroundColor Red -Message ('Module [{0}] is missing, incomplete or could not be loaded: {1} Attempting Windows management-tools installation/repair for: {2}.' -f $Name, $detail, $Purpose)
            }
            else {
                $action = 'Automatic installation/repair or verification failed.'
                if ($SkipInstallation) { $action = 'Installation is disabled for this credential-clear operation.' }
                Write-Status -IndentLevel 2 -Kind Warning -BackgroundColor Red -Message ('Module [{0}] is unavailable. {1} Details: {2} Required for: {3}. Check elevation, supported OS, Windows servicing/feature sources and restart requirements, then rerun.' -f $Name, $action, $detail, $Purpose)
                return $false
            }
        }
    }
    return $false
}

function Test-LabDnsRsatTools {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][bool]$DnsModuleLoaded)

    # Actual imported module/cmdlets are the final usability gate. Inventory
    # alone must not override an otherwise working DNS module on older hosts.
    if (-not $DnsModuleLoaded) { return $false }
    $details = @()
    try {
        if ($null -ne (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)) {
            $installed = @(Get-WindowsFeature -Name 'RSAT-DNS-Server' -ErrorAction Stop | Where-Object {
                $_.Name -ieq 'RSAT-DNS-Server' -and $_.Installed -eq $true
            })
            if ($installed.Count -eq 1) {
                Write-Status -IndentLevel 2 -Kind Success -Message 'DNS RSAT tools: server feature [RSAT-DNS-Server] is installed.'
                return $true
            }
        }
        if ($null -ne (Get-Command Get-WindowsCapability -ErrorAction SilentlyContinue)) {
            $installed = @(Get-WindowsCapability -Online -Name 'Rsat.Dns.Tools~~~~0.0.1.0' -ErrorAction Stop | Where-Object {
                $_.Name -ieq 'Rsat.Dns.Tools~~~~0.0.1.0' -and [string]$_.State -ieq 'Installed'
            })
            if ($installed.Count -eq 1) {
                Write-Status -IndentLevel 2 -Kind Success -Message 'DNS RSAT tools: capability [Rsat.Dns.Tools~~~~0.0.1.0] is installed.'
                return $true
            }
        }
    }
    catch { $details += $_.Exception.Message }
    Write-Status -IndentLevel 2 -Kind Warning -Message ('DNS package inventory is unconfirmed, but DnsServer is loaded and its required commands passed verification. No installation is needed solely to repair inventory. {0}' -f ($details -join ' '))
    return $true
}

function Resolve-LabRepadminCommand {
    [CmdletBinding()]
    param()

    $command = Get-Command -Name 'repadmin.exe' -CommandType Application -ErrorAction SilentlyContinue
    if ($null -ne $command) { return $command }
    # Servicing may install the binary without updating this process's PATH.
    $directories = @([Environment]::SystemDirectory,
        (Join-Path $env:SystemRoot 'System32'), (Join-Path $env:SystemRoot 'Sysnative')) | Select-Object -Unique
    foreach ($directory in $directories) {
        $path = Join-Path $directory 'repadmin.exe'
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            if (($env:Path -split ';') -notcontains $directory) {
                $env:Path = $env:Path + [IO.Path]::PathSeparator + $directory
            }
            # Verify name lookup too: existing checkpoints resolve by name.
            return (Get-Command -Name 'repadmin.exe' -CommandType Application -ErrorAction Stop)
        }
    }
    return $null
}

function Initialize-LabReplicationTools {
    [CmdletBinding()]
    param()

    Write-Status -Kind Info -Message 'Checking replication tool [repadmin.exe].'
    try {
        $command = Resolve-LabRepadminCommand
        if ($null -eq $command) {
            Write-Status -IndentLevel 2 -Kind Warning -BackgroundColor Red -Message 'repadmin.exe is missing. Attempting installation of the AD DS management tools.'
            Install-LabWindowsManagementTools -Name 'repadmin.exe'
            $command = Resolve-LabRepadminCommand
        }
        if ($null -eq $command) { throw 'repadmin.exe remains unavailable after installing AD DS management tools. Repair RSAT-ADDS-Tools/AD DS RSAT and rerun.' }
        Write-Status -IndentLevel 2 -Kind Success -Message ('Replication tool available: {0}' -f $command.Path)
    }
    catch {
        Stop-ScriptGracefully -IndentLevel 2 -Message ('Replication-tool prerequisite failed: {0} No password prompts or provisioning were started. No automatic reboot was attempted.' -f $_.Exception.Message)
    }
}

function Initialize-LabModulePrerequisites {
    [CmdletBinding()]
    param()

    Write-SectionHeader -Message 'Check/install required PowerShell modules and RSAT tools...'
    $failed = @()
    foreach ($requirement in @(
        @{ Name = 'ActiveDirectory'; Purpose = 'domain discovery, AD reads/writes and group membership changes' },
        @{ Name = 'GroupPolicy'; Purpose = 'GPO baseline and synthetic GPO changes' },
        @{ Name = 'DnsServer'; Purpose = 'baseline DNS zones, static A records and associated PTR management' },
        @{ Name = 'CimCmdlets'; Purpose = 'local domain discovery and local/remote disk inventory' },
        @{ Name = 'DnsClient'; Purpose = 'DNS SRV lookup during domain-controller discovery' }
    )) {
        if (-not (Import-LabPrerequisiteModule -Name $requirement.Name -Purpose $requirement.Purpose)) {
            $failed += $requirement.Name
        }
    }
    if ($failed.Count -gt 0) {
        Stop-ScriptGracefully -IndentLevel 2 -Message ('Required module prerequisites failed after load/installation attempts: {0}. No password prompts or provisioning were started. Repair the reported Windows components or restart if requested, then rerun.' -f ($failed -join ', '))
    }
    [void](Test-LabDnsRsatTools -DnsModuleLoaded $true)
}

function Get-DomainContext {
    [CmdletBinding()]
    param([switch]$SkipPrerequisiteInstallation)

    Write-SectionHeader -Message 'Discover Active Directory domain...'

    # Bootstrap is unavoidable here: discovery and rights checks need AD.
    # Full module/RSAT preflight follows rights validation in Invoke-Main.
    if (-not (Import-LabPrerequisiteModule -Name ActiveDirectory -Purpose 'domain discovery, rights checks and all AD provisioning' -SkipInstallation:$SkipPrerequisiteInstallation)) {
        Stop-ScriptGracefully -Message 'ActiveDirectory bootstrap failed after the permitted load/installation attempts. Review the prerequisite warning. No prompts or provisioning were started.'
    }

    if (-not (Import-LabPrerequisiteModule -Name CimCmdlets -Purpose 'local computer domain discovery' -SkipInstallation:$SkipPrerequisiteInstallation)) {
        Stop-ScriptGracefully -Message 'CIM bootstrap failed. Repair the inbox Windows PowerShell/CimCmdlets component and rerun. No prompts or provisioning were started.'
    }

    # Read the computer's domain locally, without first asking an arbitrary
    # DC (or the unavailable PDC) through Get-ADDomain.
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if (-not $computerSystem.PartOfDomain) {
            throw 'This computer is not joined to an Active Directory domain.'
        }
        $domainName = [string]$computerSystem.Domain
        if ([string]::IsNullOrWhiteSpace($domainName)) {
            throw 'The local computer did not report its domain name.'
        }
    }
    catch {
        Stop-ScriptGracefully -Message ("Could not identify the local computer's domain: {0}" -f $_.Exception.Message)
    }

    Write-Status -Kind Info -Message ("Finding a responsive writable DC for {0}." -f $domainName)
    $seenCandidates = @{}

    # Try progressively broader sources. A working local DC can be selected
    # immediately, without waiting for DC Locator or DNS fallback discovery.
    foreach ($discoveryStage in 0, 1, 2) {
        $candidates = @()
        switch ($discoveryStage) {
            0 {
                if ([int]$computerSystem.DomainRole -ge 4) {
                    $localName = [string]$computerSystem.DNSHostName
                    if ([string]::IsNullOrWhiteSpace($localName)) {
                        $localName = [string]$computerSystem.Name
                    }
                    if ($localName -notmatch '\.') {
                        $localName = '{0}.{1}' -f $localName, $domainName
                    }
                    $candidates += $localName
                }

                # This is only a candidate: the logon server can be offline
                # after sign-in and must pass the same validation as any DC.
                if (-not [string]::IsNullOrWhiteSpace($env:LOGONSERVER)) {
                    $logonServer = $env:LOGONSERVER.TrimStart([char]92)
                    if ($logonServer -notmatch '\.') {
                        $logonServer = '{0}.{1}' -f $logonServer, $domainName
                    }
                    $candidates += $logonServer
                }
            }
            1 {
                try {
                    $locatedDC = Get-ADDomainController -Discover -DomainName $domainName `
                        -Service ADWS -Writable -ForceDiscover -ErrorAction Stop
                    $candidates += [string]$locatedDC.HostName
                }
                catch {
                    Write-Status -Kind Warning -Message ("DC Locator did not return a writable ADWS DC: {0}" -f $_.Exception.Message)
                }
            }
            2 {
                # Enumerate alternatives even when Locator returns a stale,
                # unreachable DC. This lookup does not require a live ADWS DC.
                try {
                    $srvRecords = @(Resolve-DnsName -Name ("_ldap._tcp.dc._msdcs.{0}" -f $domainName) `
                        -Type SRV -DnsOnly -ErrorAction Stop)
                    foreach ($record in ($srvRecords | Where-Object { $_.Type -eq 'SRV' } | Sort-Object Priority, NameTarget)) {
                        $candidates += [string]$record.NameTarget
                    }
                }
                catch {
                    Write-Status -Kind Warning -Message ("DNS DC discovery failed: {0}" -f $_.Exception.Message)
                }
            }
        }

        foreach ($candidate in $candidates) {
            if ([string]::IsNullOrWhiteSpace($candidate)) {
                continue
            }
            $server = $candidate.Trim().TrimEnd([char]46)
            if ($seenCandidates.ContainsKey($server)) {
                continue
            }
            $seenCandidates[$server] = $true

            $domain = Get-ValidatedDomainContext -Server $server -ExpectedDomainName $domainName
            if ($null -ne $domain) {
                return $domain
            }
        }
    }

    Stop-ScriptGracefully -Message ("No responsive writable domain controller with working AD Web Services was found for '{0}'. Check DC availability, DNS, TCP 9389, and ADWS. No provisioning was started." -f $domainName)
}

function Test-OperatorRights {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Domain
    )

    Write-SectionHeader -Message 'Check operator rights...'

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    # Elevation is the first rights test, before either AD group token check.
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Stop-ScriptGracefully -Message 'Run this script from an elevated PowerShell session.'
    }
    Write-Status -Kind Success -Message 'Administrator elevation confirmed.'

    $tokenSids = @($identity.Groups | ForEach-Object { $_.Value })
    $domainAdminsSid = '{0}-512' -f $Domain.DomainSID.Value
    if ($tokenSids -notcontains $domainAdminsSid) {
        Stop-ScriptGracefully -Message 'The current logon token does not include the required Domain Admins group for this domain. Cannot continue; no provisioning was started. Sign in with the required account and reopen PowerShell.'
    }
    Write-Status -Kind Success -Message 'Domain Admins membership confirmed in the current logon token.'

    try {
        $forest = Get-ADForest -Server $Domain.SelectedDomainController -ErrorAction Stop
        $rootDomain = Get-ADDomain -Identity $forest.RootDomain -Server $Domain.SelectedDomainController -ErrorAction Stop
        $enterpriseAdminsSid = '{0}-519' -f $rootDomain.DomainSID.Value

        if ($tokenSids -contains $enterpriseAdminsSid) {
            Write-Status -Kind Success -Message 'The current logon token includes Enterprise Admins.'
        }
        else {
            Write-Status -Kind Warning -BackgroundColor Red -Message 'Without Enterprise Admins membership, some functions of this script will not work. Continuing...'
            Start-Sleep -Seconds 5
        }
    }
    catch {
        Write-Status -Kind Warning -Message ("Could not check Enterprise Admins membership: {0}" -f $_.Exception.Message)
    }

    # The continuation aligns with W in Without, after the nine-character prefix.
    $noticeMessage = '[NOTICE] Without Enterprise Admins rights, some changes cannot be made.'
    $noticeMessage += [Environment]::NewLine + (' ' * 9) + 'Use the least-privileged account appropriate for this lab.'
    Write-Host (Format-OutputMessage -Message $noticeMessage) -ForegroundColor White
}

function Read-SecurePasswordWithTimeout {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 60)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PromptMessage,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CredentialStatusMessage,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TimeoutNote,

        [ValidateNotNullOrEmpty()]
        [string]$WindowTitle = 'DEMO-account password'
    )

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $WindowTitle
    $form.ClientSize = New-Object System.Drawing.Size(460, 190)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true
    $form.ShowInTaskbar = $false
    $form.Tag = 'Pending'

    $label = New-Object System.Windows.Forms.Label
    # Separate status, instructions and cancel/timeout guidance with blank lines.
    $label.Text = "$CredentialStatusMessage`r`n`r`n$PromptMessage`r`n`r`n$TimeoutNote`r`nNo-input timeout: $TimeoutSeconds seconds; typing/pasting disables it."
    $label.Location = New-Object System.Drawing.Point(12, 10)
    $label.Font = $form.Font
    $label.Size = $label.GetPreferredSize([System.Drawing.Size]::new(436, 0))

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = [System.Drawing.Point]::new(12, ($label.Bottom + 12))
    $textBox.Size = New-Object System.Drawing.Size(436, 23)
    $textBox.UseSystemPasswordChar = $true

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = 'OK'
    $okButton.Location = [System.Drawing.Point]::new(292, ($textBox.Bottom + 17))
    $okButton.Size = New-Object System.Drawing.Size(75, 27)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = 'Cancel'
    $cancelButton.Location = [System.Drawing.Point]::new(373, $okButton.Top)
    $cancelButton.Size = New-Object System.Drawing.Size(75, 27)

    # Fit the actual text instead of reserving unused space above the prompt.
    $form.ClientSize = [System.Drawing.Size]::new(460, ($okButton.Bottom + 16))

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = $TimeoutSeconds * 1000
    # Mutable state is shared by GetNewClosure delegates. Never reset it
    # when text is cleared; queued timer ticks must also respect the latch.
    $inputState = [pscustomobject]@{ Started = $false }

    $form.Controls.AddRange(@($label, $textBox, $okButton, $cancelButton))
    $form.AcceptButton = $okButton
    $form.CancelButton = $cancelButton

    # Keep explicit delegate references so each event can be detached in
    # finally. This avoids leaving PowerShell closures attached across ISE runs.
    $textChangedHandler = [System.EventHandler]({
        if ($textBox.TextLength -gt 0) {
            $inputState.Started = $true
            $timer.Stop()
        }
    }.GetNewClosure())

    $timerTickHandler = [System.EventHandler]({
        if ($inputState.Started) { return }
        $timer.Stop()
        $form.Tag = 'TimedOut'
        $form.Close()
    }.GetNewClosure())

    $okClickHandler = [System.EventHandler]({
        if ($textBox.Text.Length -gt 0) {
            $form.Tag = 'Accepted'
            $timer.Stop()
            $form.Close()
        }
    }.GetNewClosure())

    $cancelClickHandler = [System.EventHandler]({
        $form.Tag = 'Cancelled'
        $timer.Stop()
        $form.Close()
    }.GetNewClosure())

    $formShownHandler = [System.EventHandler]({
        [void]$textBox.Focus()
        if (-not $inputState.Started) { $timer.Start() }
    }.GetNewClosure())

    $textBox.add_TextChanged($textChangedHandler)
    $timer.add_Tick($timerTickHandler)
    $okButton.add_Click($okClickHandler)
    $cancelButton.add_Click($cancelClickHandler)
    $form.add_Shown($formShownHandler)

    try {
        [void]$form.ShowDialog()

        if ($form.Tag -ne 'Accepted') {
            return $null
        }

        $securePassword = New-Object System.Security.SecureString
        foreach ($character in $textBox.Text.ToCharArray()) {
            $securePassword.AppendChar($character)
        }

        $securePassword.MakeReadOnly()
        return $securePassword
    }
    finally {
        $timer.Stop()

        if ($null -ne $textChangedHandler) {
            $textBox.remove_TextChanged($textChangedHandler)
        }
        if ($null -ne $timerTickHandler) {
            $timer.remove_Tick($timerTickHandler)
        }
        if ($null -ne $okClickHandler) {
            $okButton.remove_Click($okClickHandler)
        }
        if ($null -ne $cancelClickHandler) {
            $cancelButton.remove_Click($cancelClickHandler)
        }
        if ($null -ne $formShownHandler) {
            $form.remove_Shown($formShownHandler)
        }

        $textBox.Clear()
        $form.Dispose()
        $timer.Dispose()
    }
}

function Get-DemoPasswordFromCredentialStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Target,

        [ValidateNotNullOrEmpty()]
        [string]$CredentialLabel = 'DEMO',

        [ValidateRange(1, 60)]
        [int]$TimeoutSeconds = 7,

        [ValidateNotNullOrEmpty()]
        [string]$WindowTitle = 'DEMO-account password'
    )

    Write-SectionHeader -Message ('Retrieve/Update stored {0} password...' -f $CredentialLabel)

    try {
        Initialize-CredentialNativeApi
    }
    catch {
        $message = "Could not initialize Windows Credential Store access: $($_.Exception.Message)"
        Write-CredentialStatus -Kind Error -Message $message
        Stop-ScriptGracefully -Message $message
    }

    $credentialPointer = [IntPtr]::Zero
    [int]$readError = 0
    $credentialFound = [Semperis.Adfr.CredentialNativeV3]::CredRead(
        $Target,
        1,
        0,
        [ref]$credentialPointer,
        [ref]$readError
    )
    $storedPassword = $null

    if ($credentialFound) {
        try {
            $storedPassword = [Semperis.Adfr.CredentialNativeV3]::ReadPassword($credentialPointer)
        }
        catch {
            $message = "Could not read the stored $CredentialLabel password: $($_.Exception.Message)"
            Write-CredentialStatus -Kind Error -Message $message
            Stop-ScriptGracefully -Message $message
        }
        finally {
            [Semperis.Adfr.CredentialNativeV3]::CredFree($credentialPointer)
        }
    }
    elseif ($readError -ne 1168) {
        $message = "Windows Credential Store lookup failed with error $readError."
        Write-CredentialStatus -Kind Error -Message $message
        Stop-ScriptGracefully -Message $message
    }

    if ($null -ne $storedPassword) {
        $credentialStatusMessage = '{0} password found in the Windows Credential Store.' -f $CredentialLabel
        Write-CredentialStatus -Kind Success -Message $credentialStatusMessage
        $promptMessage = 'Password found. Enter a new password if you want it changed.'
        $timeoutNote = 'Cancel or timeout keeps the stored password.'
    }
    else {
        $credentialStatusMessage = 'No stored {0} password was found for this script and domain.' -f $CredentialLabel
        Write-CredentialStatus -Kind Warning -Message $credentialStatusMessage
        $promptMessage = 'No password was found. Enter a password to store it.'
        $timeoutNote = 'Cancel or timeout stops the run.'
    }

    try {
        $newPassword = Read-SecurePasswordWithTimeout `
            -TimeoutSeconds $TimeoutSeconds `
            -PromptMessage $promptMessage `
            -CredentialStatusMessage $credentialStatusMessage `
            -TimeoutNote $timeoutNote `
            -WindowTitle $WindowTitle

        if ($null -eq $newPassword) {
            if ($null -ne $storedPassword) {
                Write-CredentialStatus -Kind Operational -Message ('No new password entered; continuing with the stored {0} password.' -f $CredentialLabel)
                $passwordToUse = $storedPassword
                $storedPassword = $null
                return $passwordToUse
            }

            $message = '{0} password entry was cancelled or timed out and no stored password is available. Stopping without provisioning.' -f $CredentialLabel
            Write-CredentialStatus -Kind Warning -Message $message
            Stop-ScriptGracefully -Message $message
        }

        # A newly entered password replaces the prior stored value.
        if ($null -ne $storedPassword) {
            $storedPassword.Dispose()
            $storedPassword = $null
        }

        $securePassword = $newPassword
        $secretPointer = [IntPtr]::Zero
        $targetPointer = [IntPtr]::Zero
        $blobPointer = [IntPtr]::Zero
        $passwordBytes = $null

        try {
            $secretPointer = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode(
                $securePassword
            )
            $passwordBytes = New-Object byte[] ($securePassword.Length * 2)

            [Runtime.InteropServices.Marshal]::Copy(
                $secretPointer,
                $passwordBytes,
                0,
                $passwordBytes.Length
            )

            $targetPointer = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($Target)
            $blobPointer = [Runtime.InteropServices.Marshal]::AllocHGlobal($passwordBytes.Length)

            [Runtime.InteropServices.Marshal]::Copy(
                $passwordBytes,
                0,
                $blobPointer,
                $passwordBytes.Length
            )

            $credentialType = 'Semperis.Adfr.CredentialNativeV3+CREDENTIAL' -as [type]
            $credentialToStore = New-Object -TypeName $credentialType
            $credentialToStore.Type = 1
            $credentialToStore.TargetName = $targetPointer
            $credentialToStore.CredentialBlobSize = [uint32]$passwordBytes.Length
            $credentialToStore.CredentialBlob = $blobPointer
            $credentialToStore.Persist = 2 # CRED_PERSIST_LOCAL_MACHINE

            [int]$writeError = 0
            $writeSucceeded = [Semperis.Adfr.CredentialNativeV3]::CredWrite(
                [ref]$credentialToStore,
                0,
                [ref]$writeError
            )

            if (-not $writeSucceeded) {
                throw "Windows Credential Store write failed with error $writeError."
            }

            Write-CredentialStatus -IndentLevel 2 -Kind Success -Message ('{0} password saved in the Windows Credential Store.' -f $CredentialLabel)
            return $securePassword
        }
        catch {
            $securePassword.Dispose()
            $message = "Could not save the $CredentialLabel password in the Windows Credential Store: $($_.Exception.Message)"
            Write-CredentialStatus -IndentLevel 2 -Kind Error -Message $message
            Stop-ScriptGracefully -IndentLevel 2 -Message $message
        }
        finally {
            if ($null -ne $passwordBytes) {
                [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
            }

            if ($secretPointer -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($secretPointer)
            }

            if ($blobPointer -ne [IntPtr]::Zero) {
                for ($i = 0; $i -lt $passwordBytes.Length; $i++) {
                    [Runtime.InteropServices.Marshal]::WriteByte($blobPointer, $i, [byte]0)
                }
                [Runtime.InteropServices.Marshal]::FreeHGlobal($blobPointer)
            }

            if ($targetPointer -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::FreeHGlobal($targetPointer)
            }
        }
    }
    finally {
        if ($null -ne $storedPassword) {
            $storedPassword.Dispose()
        }
    }
}

function Clear-DemoPasswordFromCredentialStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Target,

        [ValidateNotNullOrEmpty()]
        [string]$CredentialLabel = 'demo'
    )

    Write-SectionHeader -Message ('Clear stored {0} password...' -f $CredentialLabel)

    Initialize-CredentialNativeApi

    [int]$deleteError = 0
    $deleted = [Semperis.Adfr.CredentialNativeV3]::CredDelete($Target, 1, 0, [ref]$deleteError)
    if ($deleted) {
        Write-CredentialStatus -IndentLevel 2 -Kind Success -Message ('Stored {0} password cleared from the Windows Credential Store.' -f $CredentialLabel)
        return $true
    }

    if ($deleteError -eq 1168) {
        Write-CredentialStatus -Kind Warning -Message ('No stored {0} password was found for this script and domain.' -f $CredentialLabel)
        return $false
    }

    $message = "Windows Credential Store deletion failed with error $deleteError."
    Write-CredentialStatus -IndentLevel 2 -Kind Error -Message $message
    Stop-ScriptGracefully -IndentLevel 2 -Message $message
}

# ======================================================================
# PROCESSING SUMMARY - IN-MEMORY COUNTERS; OPTIONAL READ-ONLY GROUP TREES
# ======================================================================
function Initialize-LabProcessingSummary {
    [CmdletBinding()]
    param([bool]$SyntheticEnabled)

    $categories = @('OUs','groups','computers','demo users','generic users',
        'special accounts','WMI filters','GPOs','FGPPs','AD sites','AD subnets','AD site links',
        'DNS zones','DNS records','DNS node ACLs','specific object ACLs','group nesting','group memberships',
        'other users','other AD objects')
    $rows = [ordered]@{}
    foreach ($phase in @('Baseline','Synthetic')) {
        $rows[$phase] = [ordered]@{}
        foreach ($category in $categories) {
            $rows[$phase][$category] = @{ Created=0L; Updated=0L; Deleted=0L; Added=0L; Removed=0L }
        }
    }
    # Reset on each processing run, including repeated execution in ISE.
    $script:LabProcessingSummary = @{
        Phase='Baseline'; SyntheticEnabled=$SyntheticEnabled
        Rows=$rows; Seen=@{}; UserCategories=@{}
    }
}

function Add-LabProcessingCount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [ValidateRange(0,2147483647)][long]$Created=0,
        [ValidateRange(0,2147483647)][long]$Updated=0,
        [ValidateRange(0,2147483647)][long]$Deleted=0,
        [ValidateRange(0,2147483647)][long]$Added=0,
        [ValidateRange(0,2147483647)][long]$Removed=0,
        [string]$Identity=''
    )
    # Keep existing isolated function tests/callers usable without a collector.
    $variable = Get-Variable -Name LabProcessingSummary -Scope Script -ErrorAction SilentlyContinue
    if ($null -eq $variable -or $null -eq $variable.Value) { return }
    $state = $variable.Value
    $row = $state.Rows[$state.Phase][$Category]
    if ($null -eq $row) { throw ('Unknown processing-summary category: {0}.' -f $Category) }
    $counts = @{ Created=$Created; Updated=$Updated; Deleted=$Deleted; Added=$Added; Removed=$Removed }
    foreach ($action in @('Created','Updated','Deleted','Added','Removed')) {
        $count = $counts[$action]
        if ($count -eq 0) { continue }
        if (-not [string]::IsNullOrEmpty($Identity)) {
            # Identified calls represent one object/link, never an aggregate.
            if ($count -ne 1) { throw 'Identified summary actions must have count 1.' }
            $key = '{0}|{1}|{2}|{3}' -f $state.Phase,$Category,$action,$Identity
            if ($state.Seen.ContainsKey($key)) { continue }
            $state.Seen[$key] = $true
        }
        $row[$action] += $count
    }
}

function Register-LabProcessingUser {
    [CmdletBinding()]
    param([guid]$Identity,[string]$Category)

    $variable = Get-Variable -Name LabProcessingSummary -Scope Script -ErrorAction SilentlyContinue
    if ($null -eq $variable -or $null -eq $variable.Value -or $Identity -eq [guid]::Empty) { return }
    $variable.Value.UserCategories[$Identity.ToString('D')] = $Category
}

function Get-LabProcessingDeletionCategory {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Object)

    switch ([string]$Object.ObjectClass) {
        'organizationalUnit' { return 'OUs' }
        'group' { return 'groups' }
        'computer' { return 'computers' }
        'user' {
            $variable = Get-Variable -Name LabProcessingSummary -Scope Script -ErrorAction SilentlyContinue
            if ($null -ne $variable -and $null -ne $variable.Value) {
                $key = ([guid]$Object.ObjectGUID).ToString('D')
                if ($variable.Value.UserCategories.ContainsKey($key)) { return $variable.Value.UserCategories[$key] }
            }
            return 'other users'
        }
        default { return 'other AD objects' }
    }
}

function Write-LabGroupNestingTreeNode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Group,
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.IDictionary]$Ancestors,
        [Parameter(Mandatory = $true)][hashtable]$State,
        [string]$Prefix = '',
        [string]$Connector = '',
        [bool]$LastChild = $true,
        [int]$Depth = 0,
        [ValidateSet('Members','MemberOf')][string]$Direction = 'Members',
        [guid]$HighlightGuid = [guid]::Empty,
        [switch]$SkipNode
    )

    # Read-only, path-local traversal: show shared groups on every path,
    # but stop self/circular membership on the path where it occurs.
    if ($State.Remaining -le 0) { return }
    $State.Remaining--
    $identity = ([guid]$Group.ObjectGUID).ToString('D')
    $label = ([string]$Group.Name).Replace("`r",' ').Replace("`n",' ')
    $line = $Prefix + $Connector + $label
    $nodeColor = 'White'
    if ([guid]$Group.ObjectGUID -eq $HighlightGuid) { $nodeColor = 'Cyan' }
    if ($Ancestors.Contains($identity)) {
        Write-Host ($line + ' [CIRCULAR REFERENCE - branch stopped]') -ForegroundColor $nodeColor
        return
    }
    if (-not $SkipNode) { Write-Host $line -ForegroundColor $nodeColor }
    $childPrefix = $Prefix
    if ($Connector.Length -gt 0) {
        if ($LastChild) { $childPrefix += '    ' }
        else { $childPrefix += '|   ' }
    }
    if ($Depth -ge 64) {
        Write-Host ($childPrefix + '`-- [WARNING] Depth limit reached; branch not fully displayed.') -ForegroundColor Yellow
        return
    }
    $nextAncestors = @{}
    foreach ($key in $Ancestors.Keys) { $nextAncestors[$key] = $true }
    $nextAncestors[$identity] = $true
    try {
        $current = Get-ADGroup -Identity ([guid]$Group.ObjectGUID) -Properties member,memberOf -Server $Server -ErrorAction Stop
        if ($null -eq $current) { throw 'The group was not returned; it may be hidden, deleted or inaccessible.' }
        $relationshipDNs = @($current.member)
        $relationshipLabel = 'member'
        if ($Direction -eq 'MemberOf') {
            $relationshipDNs = @($current.memberOf)
            $relationshipLabel = 'parent group'
        }
        $children = @(
            foreach ($memberDN in $relationshipDNs) {
                if ([string]::IsNullOrWhiteSpace([string]$memberDN)) { continue }
                try {
                    # Resolve direct members individually so an unreadable
                    # member cannot hide other branches. Users are not shown.
                    $member = Get-ADObject -Identity $memberDN -Server $Server -ErrorAction Stop
                    if ($null -eq $member) { throw 'Object not returned; visibility is unknown.' }
                    if ($member.ObjectClass -ieq 'group') {
                        [pscustomobject]@{ Name=[string]$member.Name; Group=$member; Warning=$null }
                    }
                }
                catch {
                    [pscustomobject]@{
                        Name=[string]$memberDN; Group=$null
                        Warning=('Unable to read {0} [{1}]: {2}' -f $relationshipLabel,$memberDN,$_.Exception.Message)
                    }
                }
            }
        )
        $children = @($children | Sort-Object -Property Name)
        if ($children.Count -eq 0 -and $SkipNode) {
            Write-Host ($childPrefix + '`-- [no visible group links]') -ForegroundColor White
        }
    }
    catch {
        Write-Host ($childPrefix + '`-- [WARNING] Unable to read ' + $Direction + ' relationships: ' + $_.Exception.Message) -ForegroundColor Yellow
        return
    }
    for ($i = 0; $i -lt $children.Count; $i++) {
        if ($State.Remaining -le 0) {
            Write-Host ($childPrefix + '`-- [WARNING] Display limit reached; remaining branches omitted.') -ForegroundColor Yellow
            break
        }
        $isLast = $i -eq ($children.Count - 1)
        $branch = '|-- '
        if ($isLast) { $branch = '`-- ' }
        $child = $children[$i]
        if ($null -ne $child.Warning) {
            $State.Remaining--
            Write-Host ($childPrefix + $branch + '[WARNING] ' + $child.Warning) -ForegroundColor Yellow
        }
        else {
            Write-LabGroupNestingTreeNode -Group $child.Group -Server $Server `
                -Ancestors $nextAncestors -State $State -Prefix $childPrefix `
                -Connector $branch -LastChild $isLast -Depth ($Depth + 1) `
                -Direction $Direction -HighlightGuid $HighlightGuid
        }
    }
}

function Write-LabFgppApplicationSummary {
    [CmdletBinding()]
    param([AllowNull()]$Domain = $null)

    # Read-only, final-state view. Never infer assignments from baseline
    # definitions: synthetic changes may already have removed those links.
    Write-Host '' -ForegroundColor White
    Write-Host '[FGPP APPLICATIONS] Current direct policy assignments' -ForegroundColor White
    try {
        if ($null -eq $Domain -or
            [string]::IsNullOrWhiteSpace([string]$Domain.SelectedDomainController) -or
            [string]::IsNullOrWhiteSpace([string]$Domain.DistinguishedName)) {
            throw 'Selected DC/domain context is unavailable; no alternate DC was queried.'
        }
        $server = [string]$Domain.SelectedDomainController
        $container = 'CN=Password Settings Container,CN=System,{0}' -f $Domain.DistinguishedName
        $policies = @(Get-ADFineGrainedPasswordPolicy -Filter * -Properties AppliesTo `
            -SearchBase $container -SearchScope OneLevel -Server $server -ErrorAction Stop |
            Sort-Object -Property Name)
        Write-Host ('  Current assignments on [{0}] (direct users/groups, not resultant per-user policy).' -f $server) -ForegroundColor White
        if ($policies.Count -eq 0) {
            Write-Host '  No FGPPs were returned; visibility depends on the current account.' -ForegroundColor White
        }
        foreach ($policy in $policies) {
            $name = ([string]$policy.Name).Replace("`r",' ').Replace("`n",' ')
            Write-Host ('  [{0}]' -f $name) -ForegroundColor White
            $subjects = @($policy.AppliesTo |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                ForEach-Object { [string]$_ } | Sort-Object -Unique)
            if ($subjects.Count -eq 0) {
                Write-Host '    (no direct assignments)' -ForegroundColor White
            }
            else {
                foreach ($subject in $subjects) {
                    # Full subject DNs show where the policy is assigned
                    # without guessing object type or expanding group members.
                    $subjectDN = $subject.Replace("`r",' ').Replace("`n",' ')
                    Write-Host ('    Applies to: {0}' -f $subjectDN) -ForegroundColor White
                }
            }
        }
        Write-Host '  Assigned subjects only; effective policy and replication convergence are not verified.' -ForegroundColor White
    }
    catch {
        Write-Host ('  [WARNING] FGPP application display unavailable: {0}' -f $_.Exception.Message) -ForegroundColor Yellow
    }
    finally {
        Write-Host '' -ForegroundColor White
    }
}

function Write-LabSelectedGroupNestingSummary {
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$GroupNames = @(),
        [AllowNull()]$Domain = $null,
        [switch]$NoLeadingBlankLine
    )

    $names = @(
        $seen = @{}
        foreach ($item in @($GroupNames)) {
            if ($item -isnot [string] -or [string]::IsNullOrWhiteSpace($item)) { continue }
            $name = $item.Trim()
            if (-not $seen.ContainsKey($name)) { $seen[$name] = $true; $name }
        }
    )
    # No header, added spacing or directory queries when disabled.
    if ($names.Count -eq 0) { return }
    if (-not $NoLeadingBlankLine) { Write-Host '' -ForegroundColor White }
    Write-Host '[GROUP NESTINGS] Optional display of selected group nesting structure' -ForegroundColor White
    foreach ($name in $names) {
        Write-Host '' -ForegroundColor White
        try {
            if ($null -eq $Domain -or
                [string]::IsNullOrWhiteSpace([string]$Domain.SelectedDomainController) -or
                [string]::IsNullOrWhiteSpace([string]$Domain.DistinguishedName)) {
                throw 'Selected DC/domain context is unavailable; no alternate DC was queried.'
            }
            $server = [string]$Domain.SelectedDomainController
            if (@('Administrators', 'BUILTIN\Administrators', 'BuiltinAdministrators') -icontains $name) {
                # Explicit DN avoids same-named groups elsewhere in the domain.
                # Resolve at display time; do not retain a prior object's SID.
                $builtinDN = 'CN=Administrators,CN=Builtin,{0}' -f $Domain.DistinguishedName
                $matches = @(Get-ADGroup -Identity $builtinDN -Server $server -ErrorAction Stop)
            }
            else {
                $escaped = ConvertTo-LdapFilterValue -Value $name
                $filter = '(|(name={0})(sAMAccountName={0}))' -f $escaped
                $matches = @(Get-ADGroup -LDAPFilter $filter -SearchBase $Domain.DistinguishedName `
                    -SearchScope Subtree -Server $server -ErrorAction Stop)
            }
            if ($matches.Count -eq 0) { throw 'Group not found or not visible to the current account; existence cannot be determined.' }
            if ($matches.Count -ne 1) { throw 'Multiple groups match this name/SAM; no arbitrary group was selected.' }
            $selectedGroup = $matches[0]
            $selectedGuid = [guid]$selectedGroup.ObjectGUID
            $selectedLabel = ([string]$selectedGroup.Name).Replace("`r",' ').Replace("`n",' ')
            Write-Host $selectedLabel -ForegroundColor Cyan
            # Branch headings make the opposite traversal directions explicit.
            # Each direction has an independent path-local guard and budget.
            Write-Host '|-- Member Of (parent groups)' -ForegroundColor White
            Write-LabGroupNestingTreeNode -Group $selectedGroup -Server $server `
                -Ancestors @{} -State @{ Remaining=2000 } -SkipNode `
                -Prefix '|   ' -Direction MemberOf -HighlightGuid $selectedGuid
            Write-Host '`-- Members (child groups)' -ForegroundColor White
            Write-LabGroupNestingTreeNode -Group $selectedGroup -Server $server `
                -Ancestors @{} -State @{ Remaining=2000 } -SkipNode `
                -Prefix '    ' -Direction Members -HighlightGuid $selectedGuid
        }
        catch {
            Write-Host ('{0} [WARNING] Group nesting display unavailable: {1}' -f $name,$_.Exception.Message) -ForegroundColor Yellow
        }
    }
    Write-Host '' -ForegroundColor White
}

function Write-LabProcessingSummary {
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$GroupNames = @(),
        [AllowNull()]$Domain = $null
    )

    $variable = Get-Variable -Name LabProcessingSummary -Scope Script -ErrorAction SilentlyContinue
    if ($null -eq $variable -or $null -eq $variable.Value) { return }
    $state = $variable.Value
    # Use one label width for both phases, including the square brackets.
    # Keep five spaces after the longest label before created/added.
    $summaryLabelWidth = 0
    foreach ($summaryPhase in @('Baseline','Synthetic')) {
        foreach ($summaryCategory in $state.Rows[$summaryPhase].Keys) {
            $labelLength = ('[{0}]' -f $summaryCategory).Length
            if ($labelLength -gt $summaryLabelWidth) { $summaryLabelWidth = $labelLength }
        }
    }
    Write-Host '' -ForegroundColor White
    Write-Host '[SUMMARY] Processing summary' -ForegroundColor White
    Write-LabFgppApplicationSummary -Domain $Domain
    Write-LabSelectedGroupNestingSummary -GroupNames $GroupNames -Domain $Domain -NoLeadingBlankLine
    foreach ($phase in @('Baseline','Synthetic')) {
        if ($phase -eq 'Baseline') { $heading = '[SECTION] Baseline processing phase' }
        else {
            Write-Host '' -ForegroundColor White
            $heading = '[SECTION] Synthetic AD Changes phase'
            if (-not $state.SyntheticEnabled) { $heading += ' (disabled)' }
        }
        Write-Host $heading -ForegroundColor White
        foreach ($category in $state.Rows[$phase].Keys) {
            $row = $state.Rows[$phase][$category]
            # Only show fallback categories when the deleted tree contained them.
            if ($category -in @('other users','other AD objects') -and
                ($row.Created + $row.Updated + $row.Deleted) -eq 0) { continue }
            $label = '[{0}]' -f $category
            if ($category -in @('group nesting','group memberships')) {
                $line = '  {0}     added {1}, removed {2}' -f $label.PadRight($summaryLabelWidth),$row.Added,$row.Removed
            }
            else {
                $line = '  {0}     created {1}, updated {2}, deleted {3}' -f $label.PadRight($summaryLabelWidth),$row.Created,$row.Updated,$row.Deleted
            }
            Write-Host $line -ForegroundColor White
        }
    }
    Write-Host '  Verified changes only; review earlier warnings/errors for skipped or partial work.' -ForegroundColor White
    Write-Host '' -ForegroundColor White
}

# ======================================================================
# SPECIFIC AD OBJECT ACLs - nTSecurityDescriptor DACL ONLY
# ======================================================================
function ConvertTo-LabDirectoryMappedRights {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int]$Rights)

    # Map raw GENERIC_* bits before subtracting read from a full-control ACE.
    # ActiveDirectoryRights.Generic* values themselves are already mapped.
    $unsigned = ([long]$Rights) -band 4294967295L
    $mapped = $unsigned -band 268435455L
    if (($unsigned -band 2147483648L) -ne 0) { $mapped = $mapped -bor 131220L }
    if (($unsigned -band 1073741824L) -ne 0) { $mapped = $mapped -bor 131112L }
    if (($unsigned -band 536870912L) -ne 0) { $mapped = $mapped -bor 131076L }
    if (($unsigned -band 268435456L) -ne 0) { $mapped = $mapped -bor 983551L }
    return [int]$mapped
}

function Get-LabDirectoryDaclFingerprint {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Security.AccessControl.RawSecurityDescriptor]$Descriptor)

    if ($null -eq $Descriptor.DiscretionaryAcl) { throw 'A null DACL is not eligible for targeted ACL edits.' }
    # Compare complete ACE bytes, ignoring order only. Keep duplicate ACEs.
    # No identity translation: preserve orphaned SIDs and object-specific ACEs.
    $parts = @(foreach ($ace in $Descriptor.DiscretionaryAcl) {
        $bytes = New-Object byte[] $ace.BinaryLength
        $ace.GetBinaryForm($bytes, 0)
        [Convert]::ToBase64String($bytes)
    })
    $protected = [int]$Descriptor.ControlFlags -band [int][System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
    return ('{0}|{1}' -f $protected, (($parts | Sort-Object) -join ';'))
}

function Set-LabDirectoryObjectAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $true)][guid]$ObjectGuid,
        [Parameter(Mandatory = $true)][string]$ExpectedDN,
        [Parameter(Mandatory = $true)][ValidateSet('user','group','organizationalUnit','groupPolicyContainer')][string]$ExpectedClass,
        [Parameter(Mandatory = $true)][System.Security.Principal.SecurityIdentifier]$TrusteeSid,
        [Parameter(Mandatory = $true)][ValidateSet('GrantReadWrite','RemoveExplicitTrustee','RemoveExplicitRead')][string]$Action,
        [ValidateSet('None','All')][string]$Scope = 'None'
    )

    # Generic helper: exact GUID + DN + class, any security principal SID.
    # For a GPO this changes ONLY its AD groupPolicyContainer, not SYSVOL,
    # GptTmpl.inf, delegation consistency or effective policy application.
    if ([string]::IsNullOrWhiteSpace($Server) -or $ObjectGuid -eq [guid]::Empty -or
        [string]::IsNullOrWhiteSpace($ExpectedDN)) { throw 'ACL edits require an explicit DC, nonempty GUID and exact DN.' }
    $target = Get-ADObject -Identity $ObjectGuid -Server $Server -ErrorAction Stop
    if ($target.DistinguishedName -ine $ExpectedDN -or $target.ObjectClass -ine $ExpectedClass) {
        throw 'ACL target moved or changed type; no name fallback or DC failover attempted.'
    }
    $entry = $null
    try {
        # GUID binding prevents committing to a replacement at the same DN.
        # Use psbase.Guid for every identity comparison: ADSI-adapted Guid
        # exposes a differently ordered hex string, not the .NET GUID.
        $entry = [System.DirectoryServices.DirectoryEntry]::new(('LDAP://{0}/<GUID={1}>' -f $Server,$ObjectGuid.ToString('D')))
        $entry.AuthenticationType = [System.DirectoryServices.AuthenticationTypes]::Secure
        $entry.psbase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        $attributes = @('objectGUID','distinguishedName','nTSecurityDescriptor')
        $entry.RefreshCache($attributes)
        if ([guid]$entry.psbase.Guid -ne $ObjectGuid -or [string]$entry.psbase.Properties['distinguishedName'].Value -ine $ExpectedDN) {
            throw 'ACL target identity changed before its security descriptor was read.'
        }
        $security = $entry.ObjectSecurity
        if (-not $security.AreAccessRulesCanonical) { throw 'Noncanonical DACL detected; refusing to reorder or replace unrelated ACEs.' }
        $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($security.GetSecurityDescriptorBinaryForm(), 0)
        $before = Get-LabDirectoryDaclFingerprint -Descriptor $raw
        $dacl = $raw.DiscretionaryAcl
        $readMask = [int][System.DirectoryServices.ActiveDirectoryRights]::GenericRead
        $writeMask = [int][System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
        $flags = [System.Security.AccessControl.AceFlags]::None
        if ($Scope -eq 'All') { $flags = [System.Security.AccessControl.AceFlags]::ContainerInherit }
        if ($Action -eq 'GrantReadWrite') {
            $granted = 0
            foreach ($ace in $dacl) {
                # Only an unrestricted allow with exactly the requested scope
                # satisfies this grant; inherited/property-specific ACEs do not.
                if ($ace -is [System.Security.AccessControl.CommonAce] -and -not $ace.IsCallback -and
                    $ace.AceType -eq [System.Security.AccessControl.AceType]::AccessAllowed -and
                    $ace.AceFlags -eq $flags -and $ace.SecurityIdentifier.Value -eq $TrusteeSid.Value) {
                    $granted = $granted -bor (ConvertTo-LabDirectoryMappedRights -Rights $ace.AccessMask)
                }
            }
            $missing = ($readMask -bor $writeMask) -band (-bnot $granted)
            if ($missing -ne 0) {
                $grant = [System.Security.AccessControl.CommonAce]::new($flags,
                    [System.Security.AccessControl.AceQualifier]::AccessAllowed, $missing, $TrusteeSid, $false, $null)
                # Preserve existing ACE bytes; insert after explicit ACEs and
                # before inherited ACEs, keeping an existing canonical DACL.
                $index = 0
                while ($index -lt $dacl.Count -and -not $dacl[$index].IsInherited) { $index++ }
                $dacl.InsertAce($index, $grant)
            }
        }
        else {
            for ($i = $dacl.Count - 1; $i -ge 0; $i--) {
                $ace = $dacl[$i]
                if ($ace.IsInherited -or $ace -isnot [System.Security.AccessControl.KnownAce] -or
                    $ace.SecurityIdentifier.Value -ne $TrusteeSid.Value) { continue }
                if ($Action -eq 'RemoveExplicitTrustee') {
                    # Remove this SID's explicit allow AND deny ACEs only.
                    $dacl.RemoveAce($i)
                    continue
                }
                # Remove explicit allow-read rights across every scope and
                # property on this object. Preserve denies, flags and GUIDs.
                if ($ace -isnot [System.Security.AccessControl.QualifiedAce] -or
                    $ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessAllowed) { continue }
                if ($ace.IsCallback -or ($ace -isnot [System.Security.AccessControl.CommonAce] -and
                    $ace -isnot [System.Security.AccessControl.ObjectAce])) {
                    throw 'Unsupported allow ACE for the read-removal SID; refusing a partial/ambiguous edit.'
                }
                $rights = ConvertTo-LabDirectoryMappedRights -Rights $ace.AccessMask
                $removeMask = $readMask
                $writeOnly = $writeMask -band (-bnot $readMask)
                if (($rights -band $writeOnly) -ne 0) {
                    # GenericRead and GenericWrite share ReadControl. Retain
                    # that shared bit when needed for the remaining write ACE.
                    $removeMask = $readMask -band (-bnot $writeMask)
                }
                $remaining = $rights -band (-bnot $removeMask)
                if ($remaining -eq 0) { $dacl.RemoveAce($i) }
                elseif ($remaining -ne $rights) { $ace.AccessMask = $remaining }
            }
        }
        # Work on a detached descriptor, not DirectoryEntry's cached copy.
        # .NET may merge equivalent adjacent ACEs when loading a DACL; use
        # that exact serialized result as the complete read-back expectation.
        $bytes = New-Object byte[] $raw.BinaryLength
        $raw.GetBinaryForm($bytes, 0)
        $writeSecurity = [System.DirectoryServices.ActiveDirectorySecurity]::new()
        $writeSecurity.SetSecurityDescriptorBinaryForm($bytes, [System.Security.AccessControl.AccessControlSections]::Access)
        if (-not $writeSecurity.AreAccessRulesCanonical) { throw 'Requested DACL would be noncanonical; refusing the write.' }
        $normalized = [System.Security.AccessControl.RawSecurityDescriptor]::new($writeSecurity.GetSecurityDescriptorBinaryForm(), 0)
        $expected = Get-LabDirectoryDaclFingerprint -Descriptor $normalized
        $changed = $before -cne $expected
        if ($changed) {
            # Refresh before commit to detect intervening DACL/identity edits.
            # This is not an atomic LDAP compare-and-swap; do not edit the same
            # lab DACL concurrently while this script is running.
            $entry.RefreshCache($attributes)
            $current = [System.Security.AccessControl.RawSecurityDescriptor]::new($entry.ObjectSecurity.GetSecurityDescriptorBinaryForm(), 0)
            if ([guid]$entry.psbase.Guid -ne $ObjectGuid -or [string]$entry.psbase.Properties['distinguishedName'].Value -ine $ExpectedDN -or
                (Get-LabDirectoryDaclFingerprint -Descriptor $current) -cne $before) {
                throw 'ACL target identity or DACL changed before commit; refusing to overwrite concurrent changes.'
            }
            $entry.ObjectSecurity = $writeSecurity
            $entry.CommitChanges()
        }
        # Verify every resulting ACE, not just the requested user's rights.
        $entry.RefreshCache($attributes)
        $verified = [System.Security.AccessControl.RawSecurityDescriptor]::new($entry.ObjectSecurity.GetSecurityDescriptorBinaryForm(), 0)
        if ([guid]$entry.psbase.Guid -ne $ObjectGuid -or [string]$entry.psbase.Properties['distinguishedName'].Value -ine $ExpectedDN -or
            (Get-LabDirectoryDaclFingerprint -Descriptor $verified) -cne $expected) {
            throw 'DACL read-back differs from the complete expected ACL; an earlier write may have committed.'
        }
        if ($changed) { Add-LabProcessingCount -Category 'specific object ACLs' -Updated 1 -Identity $ObjectGuid.ToString('D') }
        return [pscustomobject]@{ Changed=$changed; ObjectGuid=$ObjectGuid; TrusteeSid=$TrusteeSid.Value; Action=$Action }
    }
    finally { if ($null -ne $entry) { $entry.Dispose() } }
}

function Get-LabSpecificAclTrustee {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$UserKey,
        [Parameter(Mandatory = $true)][string]$Server)

    if (-not $script:LabDemoUserDefinitions.Contains($UserKey) -or
        -not $script:LabDemoUserObjects.Contains($UserKey) -or $null -eq $script:LabDemoUserObjects[$UserKey]) {
        throw ('ACL trustee [{0}] has no verified baseline demo-user reference.' -f $UserKey)
    }
    $definition = $script:LabDemoUserDefinitions[$UserKey]
    $guid = [guid]$script:LabDemoUserObjects[$UserKey].ObjectGUID
    if ($guid -eq [guid]::Empty) { throw 'ACL trustee GUID is empty.' }
    $user = Get-ADUser -Identity $guid -Properties SID -Server $Server -ErrorAction Stop
    if ([guid]$user.ObjectGUID -ne $guid -or $user.ObjectClass -ine 'user' -or
        $user.Name -cne $definition.Name -or $user.SamAccountName -ine $definition.SamAccountName -or
        (Get-ParentDistinguishedName -DistinguishedName $user.DistinguishedName) -ine $definition.Path -or $null -eq $user.SID) {
        throw 'ACL trustee does not match its baseline GUID/name/SAM/path/SID; no name fallback attempted.'
    }
    return $user
}

function Invoke-LabSpecificObjectAcls {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][ValidateSet('Baseline','Synthetic')][string]$Phase)

    try {
        $server = [string]$Domain.SelectedDomainController
        $domainDN = [string]$Domain.DistinguishedName
        if ([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($domainDN)) {
            throw 'Specific ACL changes require the selected DC and domain DN.'
        }
        $plans = @()
        $seen = @{}
        # Preflight every definition/identity before the first ACL mutation.
        if ($Phase -eq 'Baseline') {
            $script:LabSpecificAclTargets = [ordered]@{}
            foreach ($definition in @(Get-LabSpecificObjectAclDefinitions)) {
                $key = [string]$definition.Key
                if ([string]::IsNullOrWhiteSpace($key) -or $seen.ContainsKey($key) -or
                    [string]::IsNullOrWhiteSpace([string]$definition.RelativeDN) -or
                    $definition.ObjectClass -notin @('user','group','organizationalUnit','groupPolicyContainer') -or
                    $definition.Scope -notin @('None','All')) { throw 'Invalid/duplicate specific ACL baseline definition.' }
                $seen[$key] = $true
                $dn = '{0},{1}' -f $definition.RelativeDN,$domainDN
                if ($script:LabUnavailableOUPaths.ContainsKey($dn)) { throw 'ACL target OU was not successfully verified during baseline provisioning.' }
                $target = Get-ADObject -Identity $dn -Server $server -ErrorAction Stop
                if ($target.ObjectClass -ine $definition.ObjectClass -or $target.DistinguishedName -ine $dn -or
                    [guid]$target.ObjectGUID -eq [guid]::Empty) { throw 'Specific ACL target does not match its exact baseline DN/class.' }
                $user = Get-LabSpecificAclTrustee -UserKey $definition.TrusteeUserKey -Server $server
                $plans += [pscustomobject]@{
                    Key=$key; ObjectGuid=[guid]$target.ObjectGUID; ExpectedDN=$dn; ExpectedClass=[string]$definition.ObjectClass
                    UserKey=[string]$definition.TrusteeUserKey; UserGuid=[guid]$user.ObjectGUID; Sid=[string]$user.SID.Value
                    Scope=[string]$definition.Scope; Action='GrantReadWrite'
                }
            }
        }
        else {
            foreach ($definition in @(Get-LabSpecificObjectAclADChangeDefinitions)) {
                $key = [string]$definition.BaselineKey
                if ([string]::IsNullOrWhiteSpace($key) -or $seen.ContainsKey($key) -or
                    -not $script:LabSpecificAclTargets.Contains($key) -or
                    $definition.Action -notin @('RemoveExplicitTrustee','RemoveExplicitRead')) {
                    throw 'Synthetic ACL action requires a unique verified baseline key and supported action.'
                }
                $seen[$key] = $true
                $baseline = $script:LabSpecificAclTargets[$key]
                # Copy instead of modifying this run's verified baseline cache.
                $plan = $baseline.PSObject.Copy()
                $plan.Action = [string]$definition.Action
                $plans += $plan
            }
        }
        foreach ($plan in $plans) {
            $target = Get-ADObject -Identity $plan.ObjectGuid -Server $server -ErrorAction Stop
            $user = Get-LabSpecificAclTrustee -UserKey $plan.UserKey -Server $server
            if ($target.DistinguishedName -ine $plan.ExpectedDN -or $target.ObjectClass -ine $plan.ExpectedClass -or
                [guid]$user.ObjectGUID -ne $plan.UserGuid -or $user.SID.Value -ne $plan.Sid) {
                throw 'Specific ACL preflight no longer matches its pinned baseline object/principal.'
            }
        }
        $changed = 0
        foreach ($plan in $plans) {
            $user = Get-LabSpecificAclTrustee -UserKey $plan.UserKey -Server $server
            if ([guid]$user.ObjectGUID -ne $plan.UserGuid -or $user.SID.Value -ne $plan.Sid) { throw 'ACL trustee identity changed before update.' }
            $parameters = @{
                Server=$server; ObjectGuid=$plan.ObjectGuid; ExpectedDN=$plan.ExpectedDN; ExpectedClass=$plan.ExpectedClass
                TrusteeSid=[System.Security.Principal.SecurityIdentifier]::new($plan.Sid); Action=$plan.Action; Scope=$plan.Scope
            }
            $result = Set-LabDirectoryObjectAcl @parameters
            if ($result.Changed) { $changed++ }
            if ($Phase -eq 'Baseline') { $script:LabSpecificAclTargets[$plan.Key] = $plan }
            Write-Status -IndentLevel 2 -Kind Success -Message ('Verified specific ACL [{0}]: {1} for [{2}] ({3}); changed={4}.' -f $plan.ExpectedDN,$plan.Action,$plan.UserKey,$plan.Sid,$result.Changed)
        }
        Write-Status -IndentLevel 1 -Kind Info -Message 'Only explicit DACL entries are edited; inherited/group access and existing denies can affect effective access. GenericWrite retains shared ReadControl. No deny ACEs are added.'
        return [pscustomobject]@{ ChangedCount=$changed; UnchangedCount=($plans.Count - $changed) }
    }
    catch {
        Stop-ScriptGracefully -IndentLevel 2 -Message ('{0} specific ACL changes failed: {1} Earlier writes may remain committed; no rollback, name fallback or DC failover attempted.' -f $Phase,$_.Exception.Message)
    }
}

function Ensure-RequiredOrganizationalUnits {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Domain
    )

    Write-SectionHeader -Message 'Create/Update OUs...'
    # Per-run dependency failures; never modify ACLs to make a hidden OU visible.
    $script:LabUnavailableOUPaths = @{}

    $domainDN = [string]$Domain.DistinguishedName
    if ([string]::IsNullOrWhiteSpace($domainDN)) {
        Stop-ScriptGracefully -Message 'The discovered domain did not provide a distinguished name for OU provisioning.'
    }

    $requiredOUs = @(Get-LabOrganizationalUnitDefinitions)

    foreach ($ouDefinition in $requiredOUs) {
        # Omitted protection remains unmanaged for older OU definitions.
        $manageDeletionProtection = $null -ne $ouDefinition.PSObject.Properties['ProtectedFromAccidentalDeletion']
        if ($manageDeletionProtection -and $ouDefinition.ProtectedFromAccidentalDeletion -isnot [bool]) {
            Stop-ScriptGracefully -Message ("OU '{0}' ProtectedFromAccidentalDeletion must be a Boolean, not a string or number." -f $ouDefinition.Name)
        }
        $ouProperties = @('Description','DisplayName')
        if ($manageDeletionProtection) {
            $ouProperties += 'ProtectedFromAccidentalDeletion'
        }

        if ([string]::IsNullOrWhiteSpace($ouDefinition.ParentPath)) {
            $parentDN = $domainDN
        }
        else {
            $parentDN = '{0},{1}' -f $ouDefinition.ParentPath, $domainDN
        }

        Write-Status -Kind Info -Message ("Checking OU '{0}' under '{1}'." -f $ouDefinition.Name, $parentDN)

        $searchFilter = "Name -eq '$($ouDefinition.Name)'"
        try {
            $existingOUs = @(
                Get-ADOrganizationalUnit `
                    -Filter $searchFilter `
                    -SearchBase $parentDN `
                    -SearchScope OneLevel `
                    -Server $Domain.SelectedDomainController `
                    -Properties $ouProperties `
                    -ErrorAction Stop
            )
        }
        catch {
            $ouPath = 'OU={0},{1}' -f $ouDefinition.Name,$parentDN
            $script:LabUnavailableOUPaths[$ouPath] = $_.Exception.Message
            Write-Status -IndentLevel 2 -Kind Error -Message ("Could not check OU '{0}' under '{1}': {2}. Skipping this OU and continuing; its existence/state could not be verified. No ACL changes attempted." -f $ouDefinition.Name,$parentDN,$_.Exception.Message)
            continue
        }

        if ($existingOUs.Count -gt 1) {
            Stop-ScriptGracefully -Message ("More than one OU named '{0}' was found directly under '{1}'." -f $ouDefinition.Name, $parentDN)
        }

        # Only definitions with an explicit previous parent opt into migration.
        # Move the original OU by GUID so all descendants and memberships stay
        # attached to their existing objects; never merge two existing trees.
        $relocationUpdated = $false
        if ($null -ne $ouDefinition.PSObject.Properties['PreviousParentPath']) {
            if ($ouDefinition.PreviousParentPath -isnot [string]) {
                Stop-ScriptGracefully -Message ("OU '{0}' PreviousParentPath must be a relative string; use an empty string for the domain root." -f $ouDefinition.Name)
            }
            $previousParentDN = $domainDN
            if (-not [string]::IsNullOrWhiteSpace($ouDefinition.PreviousParentPath)) {
                $previousParentDN = '{0},{1}' -f $ouDefinition.PreviousParentPath,$domainDN
            }
            if ($previousParentDN -ieq $parentDN) {
                Stop-ScriptGracefully -Message ("OU '{0}' previous and desired parents are identical; correct the migration definition." -f $ouDefinition.Name)
            }
            try {
                $previousOUs = @(Get-ADOrganizationalUnit -Filter $searchFilter `
                    -SearchBase $previousParentDN -SearchScope OneLevel `
                    -Server $Domain.SelectedDomainController -Properties $ouProperties -ErrorAction Stop)
                if ($previousOUs.Count -gt 1) {
                    throw 'More than one matching OU was returned from the previous parent; no move or merge attempted.'
                }
                if ($previousOUs.Count -eq 1 -and $existingOUs.Count -eq 1) {
                    throw 'Both the previous and desired OU locations exist. Resolve the duplicate trees manually; no move, merge or deletion attempted.'
                }
                if ($previousOUs.Count -eq 1) {
                    $previousOU = $previousOUs[0]
                    $ouId = [guid]$previousOU.ObjectGUID
                    if ($ouId -eq [guid]::Empty) { throw 'The source OU did not provide a valid object GUID.' }
                    # Follow only the explicitly configured baseline protection
                    # setting. Do not bypass other ACLs or alter child objects.
                    if ($manageDeletionProtection -and
                        $ouDefinition.ProtectedFromAccidentalDeletion -eq $false -and
                        $previousOU.ProtectedFromAccidentalDeletion -eq $true) {
                        Set-ADOrganizationalUnit -Identity $ouId -ProtectedFromAccidentalDeletion $false `
                            -Server $Domain.SelectedDomainController -ErrorAction Stop
                    }
                    Write-Status -IndentLevel 3 -Kind Info -Message ("Moving existing OU tree '{0}' under '{1}'." -f $previousOU.DistinguishedName,$parentDN)
                    Move-ADObject -Identity $ouId -TargetPath $parentDN `
                        -Server $Domain.SelectedDomainController -ErrorAction Stop
                    $movedOU = Get-ADOrganizationalUnit -Identity $ouId -Properties $ouProperties `
                        -Server $Domain.SelectedDomainController -ErrorAction Stop
                    if ([guid]$movedOU.ObjectGUID -ne $ouId -or
                        (Get-ParentDistinguishedName -DistinguishedName $movedOU.DistinguishedName) -ine $parentDN -or
                        $movedOU.Name -ine $ouDefinition.Name) {
                        throw 'Moved OU read-back did not match the original GUID, configured name and desired parent.'
                    }
                    $existingOUs = @($movedOU)
                    $relocationUpdated = $true
                    Write-Status -IndentLevel 2 -Kind Success -Message ("Moved OU tree to '{0}'; existing child objects retain their identities." -f $movedOU.DistinguishedName)
                }
            }
            catch {
                Stop-ScriptGracefully -IndentLevel 2 -Message ("Could not reconcile the previous location of OU '{0}': {1} Earlier OU writes may have committed; inspect both locations before retrying. No merge, deletion, rollback or DC failover attempted." -f $ouDefinition.Name,$_.Exception.Message)
            }
        }

        if ($existingOUs.Count -eq 0) {
            Write-Status -IndentLevel 3 -Kind Info -Message ("Creating OU '{0}' under '{1}'." -f $ouDefinition.Name, $parentDN)
            $newOUParameters = @{
                Name        = $ouDefinition.Name
                Path        = $parentDN
                Server      = $Domain.SelectedDomainController
                PassThru    = $true
                ErrorAction = 'Stop'
            }

            if (-not [string]::IsNullOrWhiteSpace($ouDefinition.Description)) {
                $newOUParameters.Description = $ouDefinition.Description
            }

            # Optional managed display names leave older definitions unchanged.
            if ($null -ne $ouDefinition.PSObject.Properties['DisplayName']) {
                $newOUParameters.DisplayName = [string]$ouDefinition.DisplayName
            }

            if ($manageDeletionProtection) {
                $newOUParameters.ProtectedFromAccidentalDeletion = $ouDefinition.ProtectedFromAccidentalDeletion
            }

            try {
                Assert-LabInventoryHealthy
                $createdOU = New-ADOrganizationalUnit @newOUParameters
                Add-LabGeneratedADObject -Kind OU -Object $createdOU
            }
            catch {
                # An ACL-hidden existing OU can be absent from the search yet
                # reject creation with "name already in use". Do not retry,
                # change ACLs, or claim that the OU has been reconciled.
                $ouPath = 'OU={0},{1}' -f $ouDefinition.Name,$parentDN
                $script:LabUnavailableOUPaths[$ouPath] = $_.Exception.Message
                Write-Status -IndentLevel 4 -Kind Error -Message ("Could not create OU '{0}' under '{1}':`n        {2}.`n        It may already exist but be hidden by ACLs, or creation may be denied.`n        Skipping this OU and continuing script processing; no ACL changes attempted." -f $ouDefinition.Name,$parentDN,$_.Exception.Message)
                if ($ouDefinition.Name -ieq 'TEST' -and $parentDN -ieq $domainDN) {
                    Write-Status -IndentLevel 2 -Kind Warning -Message 'Generic-user provisioning will check OU TEST and skip if it is still unavailable.'
                }
                continue
            }

            Write-Status -IndentLevel 2 -Kind Success -Message ("Created OU '{0}'." -f $createdOU.DistinguishedName)
            Add-LabProcessingCount -Category 'OUs' -Created 1 -Identity ([string]$createdOU.ObjectGUID)
            continue
        }

        $existingOU = $existingOUs[0]
        $summaryUpdated = $relocationUpdated
        if ($manageDeletionProtection -and
            $existingOU.ProtectedFromAccidentalDeletion -ne $ouDefinition.ProtectedFromAccidentalDeletion) {
            Write-Status -IndentLevel 3 -Kind Info -Message ("Updating accidental-deletion protection on OU '{0}' to {1}." -f $existingOU.DistinguishedName, $ouDefinition.ProtectedFromAccidentalDeletion)
            try {
                Set-ADOrganizationalUnit `
                    -Identity $existingOU.DistinguishedName `
                    -ProtectedFromAccidentalDeletion $ouDefinition.ProtectedFromAccidentalDeletion `
                    -Server $Domain.SelectedDomainController `
                    -ErrorAction Stop
            }
            catch {
                Stop-ScriptGracefully -IndentLevel 2 -Message ("Could not update accidental-deletion protection on OU '{0}': {1}" -f $existingOU.DistinguishedName, $_.Exception.Message)
            }
            $summaryUpdated = $true
            Write-Status -IndentLevel 2 -Kind Success -Message ("OU '{0}' already exists; set accidental-deletion protection to {1}." -f $existingOU.DistinguishedName, $ouDefinition.ProtectedFromAccidentalDeletion)
        }

        # Manage DisplayName only when explicitly present in the definition.
        # SAM metadata and the future ACL comment never become AD writes.
        if ($null -ne $ouDefinition.PSObject.Properties['DisplayName'] -and
            [string]$existingOU.DisplayName -cne [string]$ouDefinition.DisplayName) {
            Write-Status -IndentLevel 3 -Kind Info -Message ("Updating display name on OU '{0}'." -f $existingOU.DistinguishedName)
            try {
                Set-ADOrganizationalUnit `
                    -Identity $existingOU.DistinguishedName `
                    -DisplayName $ouDefinition.DisplayName `
                    -Server $Domain.SelectedDomainController `
                    -ErrorAction Stop
            }
            catch {
                Stop-ScriptGracefully -IndentLevel 2 -Message ("Could not update the display name on OU '{0}': {1}" -f $existingOU.DistinguishedName, $_.Exception.Message)
            }
            $summaryUpdated = $true
            Write-Status -IndentLevel 2 -Kind Success -Message ("OU '{0}' already exists; updated its display name to the desired value." -f $existingOU.DistinguishedName)
        }

        $existingDescription = [string]$existingOU.Description

        if ([string]::IsNullOrWhiteSpace($ouDefinition.Description)) {
            if (-not [string]::IsNullOrEmpty($existingDescription)) {
                Write-Status -IndentLevel 3 -Kind Info -Message ("Updating OU '{0}': clearing its description to match the blank default." -f $existingOU.DistinguishedName)
                try {
                    Set-ADOrganizationalUnit `
                        -Identity $existingOU.DistinguishedName `
                        -Clear Description `
                        -Server $Domain.SelectedDomainController `
                        -ErrorAction Stop
                }
                catch {
                    Stop-ScriptGracefully -IndentLevel 2 -Message ("Could not clear the description on OU '{0}': {1}" -f $existingOU.DistinguishedName, $_.Exception.Message)
                }

                $summaryUpdated = $true
                Write-Status -IndentLevel 2 -Kind Success -Message ("OU '{0}' already exists; cleared its description to match the blank default." -f $existingOU.DistinguishedName)
            }
            else {
                Write-Status -Kind Info -Message ("OU '{0}' already exists with the desired blank description." -f $existingOU.DistinguishedName)
            }
        }
        elseif ($existingDescription -cne $ouDefinition.Description) {
            Write-Status -IndentLevel 3 -Kind Info -Message ("Updating description on OU '{0}'." -f $existingOU.DistinguishedName)
            try {
                Set-ADOrganizationalUnit `
                    -Identity $existingOU.DistinguishedName `
                    -Description $ouDefinition.Description `
                    -Server $Domain.SelectedDomainController `
                    -ErrorAction Stop
            }
            catch {
                Stop-ScriptGracefully -IndentLevel 2 -Message ("Could not update the description on OU '{0}': {1}" -f $existingOU.DistinguishedName, $_.Exception.Message)
            }

            $summaryUpdated = $true
            Write-Status -IndentLevel 2 -Kind Success -Message ("OU '{0}' already exists; updated its description to the desired value." -f $existingOU.DistinguishedName)
        }
        else {
            Write-Status -Kind Info -Message ("OU '{0}' already exists with the desired description." -f $existingOU.DistinguishedName)
        }
        if ($summaryUpdated) { Add-LabProcessingCount -Category 'OUs' -Updated 1 -Identity ([string]$existingOU.ObjectGUID) }
    }
}

function ConvertTo-LdapFilterValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    # RFC 4515 escaping; operators may put filter metacharacters in names.
    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
}

function Get-ParentDistinguishedName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName
    )

    # A comma escaped inside a CN is not the separator before the parent DN.
    $escaped = $false
    for ($index = 0; $index -lt $DistinguishedName.Length; $index++) {
        $character = $DistinguishedName[$index]
        if ($escaped) {
            $escaped = $false
        }
        elseif ($character -eq [char]92) {
            $escaped = $true
        }
        elseif ($character -eq ',') {
            return $DistinguishedName.Substring($index + 1)
        }
    }
    throw 'The distinguished name did not contain a parent separator.'
}

function Ensure-RequiredGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Domain,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$GroupDefinitions
    )

    Write-SectionHeader -Message 'Create/Update Groups...'
    $server = [string]$Domain.SelectedDomainController
    $domainDN = [string]$Domain.DistinguishedName
    $groupObjects = [ordered]@{}
    $plans = [ordered]@{}
    $samNames = @{}
    $targetNames = @{}
    $claimedObjects = @{}
    $checkedPaths = @{}
    $supportedProperties = @('Name', 'SamAccountName', 'DisplayName', 'Description', 'GroupCategory', 'GroupScope', 'Path')

    # Validate all definitions, target OUs, and existing identities before any
    # group writes. A non-group account or conflicting group is never adopted.
    Write-Status -Kind Info -Message 'Validating group definitions and existing-object identities.'
    try {
        if ([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($domainDN)) {
            throw 'Group provisioning requires the selected DC and domain DN.'
        }
        foreach ($key in $GroupDefinitions.Keys) {
            $definition = $GroupDefinitions[$key]
            if ($definition -isnot [System.Collections.IDictionary]) {
                throw ("Group definition '{0}' must be a hash table." -f $key)
            }
            foreach ($property in $supportedProperties) {
                if (-not $definition.Contains($property)) {
                    throw ("Group definition '{0}' is missing property '{1}'." -f $key, $property)
                }
                if ($null -ne $definition[$property] -and $definition[$property] -isnot [string]) {
                    throw ("Group definition '{0}' property '{1}' must be a string or null." -f $key, $property)
                }
            }
            foreach ($property in $definition.Keys) {
                if ($supportedProperties -notcontains $property) {
                    throw ("Group definition '{0}' has unsupported property '{1}'. Memberships must be managed separately." -f $key, $property)
                }
            }
            foreach ($property in @('Name', 'SamAccountName', 'GroupCategory', 'GroupScope', 'Path')) {
                if ([string]::IsNullOrWhiteSpace([string]$definition[$property])) {
                    throw ("Group definition '{0}' requires a nonblank '{1}'." -f $key, $property)
                }
            }
            if (@('Security', 'Distribution') -notcontains $definition.GroupCategory) {
                throw ("Group '{0}' has an invalid GroupCategory." -f $key)
            }
            if (@('Global', 'DomainLocal', 'Universal') -notcontains $definition.GroupScope) {
                throw ("Group '{0}' has an invalid GroupScope." -f $key)
            }
            if (-not $definition.Path.EndsWith(',' + $domainDN, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw ("Group '{0}' must target an OU in the discovered domain." -f $key)
            }
            $targetKey = '{0}|{1}' -f $definition.Path, $definition.Name
            if ($samNames.ContainsKey($definition.SamAccountName) -or $targetNames.ContainsKey($targetKey)) {
                throw ("Group '{0}' duplicates another definition's SAM name or target name/path." -f $key)
            }
            $samNames[$definition.SamAccountName] = $true
            $targetNames[$targetKey] = $true
            if (-not $checkedPaths.ContainsKey($definition.Path)) {
                Get-ADOrganizationalUnit -Identity $definition.Path -Server $server -ErrorAction Stop | Out-Null
                $checkedPaths[$definition.Path] = $true
            }

            $samFilter = '(sAMAccountName={0})' -f (ConvertTo-LdapFilterValue -Value $definition.SamAccountName)
            $nameFilter = '(name={0})' -f (ConvertTo-LdapFilterValue -Value $definition.Name)
            $samMatches = @(Get-ADObject -LDAPFilter $samFilter -SearchBase $domainDN -SearchScope Subtree -Server $server -ErrorAction Stop)
            $nameMatches = @(Get-ADObject -LDAPFilter $nameFilter -SearchBase $definition.Path -SearchScope OneLevel -Server $server -ErrorAction Stop)
            if ($samMatches.Count -gt 1 -or $nameMatches.Count -gt 1) {
                throw ("Group '{0}' matched multiple existing objects. Resolve the ambiguity before retrying." -f $key)
            }
            foreach ($matchedObject in (@($samMatches) + @($nameMatches))) {
                if ($matchedObject.ObjectClass -ine 'group') {
                    throw ("Group '{0}' conflicts with a non-group object: {1}." -f $key, $matchedObject.DistinguishedName)
                }
            }
            if ($samMatches.Count -eq 1 -and $nameMatches.Count -eq 1 -and $samMatches[0].ObjectGUID -ne $nameMatches[0].ObjectGUID) {
                throw ("Group '{0}' matches different objects by SAM name and target name/path. No merge or overwrite will be attempted." -f $key)
            }

            $existingGroup = $null
            if ($samMatches.Count -eq 1) {
                $existingGroup = Get-ADGroup -Identity $samMatches[0].ObjectGUID -Properties DisplayName, Description -Server $server -ErrorAction Stop
            }
            elseif ($nameMatches.Count -eq 1) {
                # Supports changing a SAM name when the name and target OU
                # still identify the existing group unambiguously.
                $existingGroup = Get-ADGroup -Identity $nameMatches[0].ObjectGUID -Properties DisplayName, Description -Server $server -ErrorAction Stop
            }
            if ($null -ne $existingGroup) {
                $guidKey = [string]$existingGroup.ObjectGUID
                if ($claimedObjects.ContainsKey($guidKey)) {
                    throw ("Group definitions '{0}' and '{1}' refer to the same existing group." -f $claimedObjects[$guidKey], $key)
                }
                $claimedObjects[$guidKey] = $key
            }
            $plans[$key] = $existingGroup
        }
    }
    catch {
        Stop-ScriptGracefully -Message ("Group preflight failed; no group changes were started: {0}" -f $_.Exception.Message)
    }

    foreach ($key in $GroupDefinitions.Keys) {
        $definition = $GroupDefinitions[$key]
        $existingGroup = $plans[$key]
        Write-Status -Kind Info -Message ("Checking group '{0}' (key: {1})." -f $definition.Name, $key)

        if ($null -eq $existingGroup) {
            Write-Status -IndentLevel 3 -Kind Info -Message ("Creating group '{0}' under '{1}'." -f $definition.Name, $definition.Path)
            try {
                $newParameters = @{
                    Name           = $definition.Name
                    SamAccountName = $definition.SamAccountName
                    GroupCategory  = $definition.GroupCategory
                    GroupScope     = $definition.GroupScope
                    Path           = $definition.Path
                    Server         = $server
                    PassThru       = $true
                    ErrorAction    = 'Stop'
                }
                foreach ($property in @('DisplayName', 'Description')) {
                    if (-not [string]::IsNullOrEmpty([string]$definition[$property])) {
                        $newParameters[$property] = $definition[$property]
                    }
                }
                Assert-LabInventoryHealthy
                $createdGroup = New-ADGroup @newParameters
                Add-LabGeneratedADObject -Kind Group -Object $createdGroup
                $groupObjects[$key] = Get-ADGroup -Identity $createdGroup.ObjectGUID -Properties DisplayName, Description -Server $server -ErrorAction Stop
            }
            catch {
                Stop-ScriptGracefully -IndentLevel 2 -Message ("Could not create or verify group '{0}': {1}" -f $definition.Name, $_.Exception.Message)
            }
            Write-Status -IndentLevel 2 -Kind Success -Message ("Created group '{0}'." -f $groupObjects[$key].DistinguishedName)
            Add-LabProcessingCount -Category 'groups' -Created 1 -Identity ([string]$createdGroup.ObjectGUID)
            continue
        }

        # GUID identity survives renames, SAM changes, and OU moves. Stable
        # definition keys are lookup handles, not persistent AD identities.
        $groupId = $existingGroup.ObjectGUID
        $changed = $false
        try {
            $currentParent = Get-ParentDistinguishedName -DistinguishedName $existingGroup.DistinguishedName
        }
        catch {
            Stop-ScriptGracefully -Message ("Could not determine the parent OU for group '{0}': {1}" -f $definition.Name, $_.Exception.Message)
        }
        if ($currentParent -ine $definition.Path) {
            Write-Status -IndentLevel 3 -Kind Info -Message ("Moving group '{0}' to '{1}'." -f $existingGroup.Name, $definition.Path)
            try {
                Move-ADObject -Identity $groupId -TargetPath $definition.Path -Server $server -ErrorAction Stop
            }
            catch {
                Stop-ScriptGracefully -IndentLevel 2 -Message ("Could not move group '{0}': {1}. Object protection was not disabled." -f $definition.Name, $_.Exception.Message)
            }
            Write-Status -IndentLevel 2 -Kind Success -Message ("Moved group '{0}' to the desired OU." -f $existingGroup.Name)
            $changed = $true
        }
        if ($existingGroup.Name -cne $definition.Name) {
            Write-Status -IndentLevel 3 -Kind Info -Message ("Renaming group '{0}' to '{1}'." -f $existingGroup.Name, $definition.Name)
            try {
                Rename-ADObject -Identity $groupId -NewName $definition.Name -Server $server -ErrorAction Stop
            }
            catch {
                Stop-ScriptGracefully -IndentLevel 2 -Message ("Could not rename group to '{0}': {1}" -f $definition.Name, $_.Exception.Message)
            }
            Write-Status -IndentLevel 2 -Kind Success -Message ("Renamed group to '{0}'." -f $definition.Name)
            $changed = $true
        }

        $setParameters = @{ Identity = $groupId; Server = $server; ErrorAction = 'Stop' }
        $clearAttributes = @()
        $changedProperties = @()
        foreach ($property in @('SamAccountName', 'DisplayName', 'Description', 'GroupCategory', 'GroupScope')) {
            $desiredValue = [string]$definition[$property]
            $currentValue = [string]$existingGroup.$property
            # Enum values are case-insensitive; text properties preserve the
            # operator's requested spelling/capitalization.
            $isDifferent = $currentValue -cne $desiredValue
            if ($property -eq 'GroupCategory' -or $property -eq 'GroupScope') {
                $isDifferent = $currentValue -ine $desiredValue
            }
            if (-not $isDifferent) {
                continue
            }
            $changedProperties += $property
            if (($property -eq 'DisplayName' -or $property -eq 'Description') -and [string]::IsNullOrEmpty($desiredValue)) {
                $clearAttributes += $property
            }
            else {
                $setParameters[$property] = $desiredValue
            }
        }
        if ($clearAttributes.Count -gt 0) {
            $setParameters['Clear'] = $clearAttributes
        }
        if ($changedProperties.Count -gt 0) {
            Write-Status -IndentLevel 3 -Kind Info -Message ("Updating group '{0}' properties: {1}." -f $definition.Name, ($changedProperties -join ', '))
            try {
                # Scope conversions remain subject to AD constraints. Never
                # alter memberships to make a conversion succeed.
                Set-ADGroup @setParameters
            }
            catch {
                Stop-ScriptGracefully -IndentLevel 2 -Message ("Could not update group '{0}': {1}. AD scope/category constraints may apply; no memberships were changed." -f $definition.Name, $_.Exception.Message)
            }
            Write-Status -IndentLevel 2 -Kind Success -Message ("Updated properties on group '{0}'." -f $definition.Name)
            $changed = $true
        }
        try {
            $groupObjects[$key] = Get-ADGroup -Identity $groupId -Properties DisplayName, Description -Server $server -ErrorAction Stop
        }
        catch {
            $errorIndentLevel = 1
            if ($changed) {
                $errorIndentLevel = 2
            }
            Stop-ScriptGracefully -IndentLevel $errorIndentLevel -Message ("Could not refresh group '{0}' after checking its properties: {1}" -f $definition.Name, $_.Exception.Message)
        }
        if ($changed) { Add-LabProcessingCount -Category 'groups' -Updated 1 -Identity ([string]$groupId) }
        if (-not $changed) {
            Write-Status -Kind Info -Message ("Group '{0}' already exists with the desired properties and OU. Memberships were not checked or changed." -f $definition.Name)
        }
    }

    # Later membership functions can consume these resolved groups by key.
    return ,$groupObjects
}

function ConvertTo-LabComputerSamAccountName {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$SamAccountName)

    # Keep friendly editable definitions; normalize exactly one terminal '$'.
    $baseName = $SamAccountName
    if ($baseName.EndsWith('$')) { $baseName = $baseName.Substring(0, $baseName.Length - 1) }
    if ($baseName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,18}$') {
        throw 'Computer SamAccountName must contain 1..19 letters/digits, dots, underscores or hyphens, optionally followed by one dollar sign.'
    }
    return ($baseName + '$')
}

function Ensure-LabComputers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.IDictionary]$ComputerDefinitions
    )

    Write-SectionHeader -Message 'Create/Update Computer Objects...'
    $server = [string]$Domain.SelectedDomainController
    $domainDN = [string]$Domain.DistinguishedName
    $computerObjects = [ordered]@{}
    $plans = [ordered]@{}
    $seenSam = @{}
    $seenTargets = @{}
    $claimedObjects = @{}
    $checkedPaths = @{}
    $skippedCount = 0
    # Support isolated function use as well as the normal OU-first main flow.
    $unavailableOUPaths = @{}
    $ouFailureState = Get-Variable -Name LabUnavailableOUPaths -Scope Script -ErrorAction SilentlyContinue
    if ($null -ne $ouFailureState) { $unavailableOUPaths = $ouFailureState.Value }
    $createdCount = 0
    $updatedCount = 0
    $unchangedCount = 0
    $fields = @('Name','SamAccountName','DisplayName','Description','Path')

    # Resolve every container and identity before starting any computer writes.
    # Exact SAM matches find moved/renamed objects. Target CN matches permit
    # correcting a changed SAM, but conflicting identities are never merged.
    try {
        if ([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($domainDN)) {
            throw 'Computer provisioning requires the selected DC and domain DN.'
        }
        foreach ($key in $ComputerDefinitions.Keys) {
            $definition = $ComputerDefinitions[$key]
            if ([string]::IsNullOrWhiteSpace([string]$key) -or $definition -isnot [System.Collections.IDictionary]) {
                throw 'Each computer definition needs a nonblank stable key and a hash table.'
            }
            foreach ($field in $fields) {
                if (-not $definition.Contains($field) -or ($null -ne $definition[$field] -and $definition[$field] -isnot [string])) {
                    throw ('Computer [{0}] requires string/null field [{1}].' -f $key,$field)
                }
            }
            foreach ($field in $definition.Keys) {
                if ($fields -notcontains $field) { throw ('Computer [{0}] has unsupported field [{1}].' -f $key,$field) }
            }
            foreach ($field in @('Name','SamAccountName','Path')) {
                if ([string]::IsNullOrWhiteSpace([string]$definition[$field])) { throw ('Computer [{0}] requires nonblank [{1}].' -f $key,$field) }
            }
            if ($definition.Name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$' -or $definition.Name -cne $definition.Name.Trim()) {
                throw ('Computer [{0}] needs a simple 1..64-character CN without DN delimiters or leading/trailing whitespace.' -f $key)
            }
            $samName = ConvertTo-LabComputerSamAccountName -SamAccountName $definition.SamAccountName
            if (-not $definition.Path.EndsWith(',' + $domainDN,[System.StringComparison]::OrdinalIgnoreCase)) {
                throw ('Computer [{0}] must target a container in the discovered domain.' -f $key)
            }
            $targetKey = '{0}|{1}' -f $definition.Path,$definition.Name
            if ($seenSam.ContainsKey($samName) -or $seenTargets.ContainsKey($targetKey)) { throw 'Duplicate computer SAM or target name/path definitions.' }
            $seenSam[$samName] = $true
            $seenTargets[$targetKey] = $true
            if (-not $checkedPaths.ContainsKey($definition.Path)) {
                $container = $null
                $containerUnavailable = $unavailableOUPaths.ContainsKey($definition.Path)
                if ($containerUnavailable) {
                    Write-Status -IndentLevel 2 -Kind Error -Message ('Computer target [{0}] was not verified during OU provisioning: {1}' -f $definition.Path,$unavailableOUPaths[$definition.Path])
                }
                else {
                    try {
                        $container = Get-ADObject -Identity $definition.Path -Server $server -ErrorAction Stop
                        if ($null -eq $container) { throw 'Container lookup returned no object.' }
                    }
                    catch {
                        $containerUnavailable = $true
                        Write-Status -IndentLevel 2 -Kind Error -Message ('Could not read computer target [{0}]: {1}. It may be missing, hidden or inaccessible; no ACL changes attempted.' -f $definition.Path,$_.Exception.Message)
                    }
                }
                if (-not $containerUnavailable -and (@('organizationalUnit','container') -notcontains $container.ObjectClass -or
                    $container.DistinguishedName -ine $definition.Path)) { throw 'Computer Path resolved to an unexpected object type or identity.' }
                $checkedPaths[$definition.Path] = -not $containerUnavailable
            }
            if (-not $checkedPaths[$definition.Path]) {
                $skippedCount++
                Write-Status -IndentLevel 2 -Kind Error -Message ('Skipping computer [{0}] (key: {1}): target [{2}] could not be verified. No computer read/write attempted for this definition; continuing with other definitions.' -f $definition.Name,$key,$definition.Path)
                continue
            }
            $samFilter = '(sAMAccountName={0})' -f (ConvertTo-LdapFilterValue -Value $samName)
            $nameFilter = '(name={0})' -f (ConvertTo-LdapFilterValue -Value $definition.Name)
            $samMatches = @(Get-ADObject -LDAPFilter $samFilter -SearchBase $domainDN -SearchScope Subtree -Server $server -ErrorAction Stop)
            $nameMatches = @(Get-ADObject -LDAPFilter $nameFilter -SearchBase $definition.Path -SearchScope OneLevel -Server $server -ErrorAction Stop)
            if ($samMatches.Count -gt 1 -or $nameMatches.Count -gt 1) { throw ('Computer [{0}] matched multiple objects.' -f $key) }
            foreach ($match in (@($samMatches) + @($nameMatches))) {
                if ($match.ObjectClass -ine 'computer' -or [guid]$match.ObjectGUID -eq [guid]::Empty) {
                    throw ('Computer [{0}] conflicts with a non-computer or invalid identity.' -f $key)
                }
            }
            if ($samMatches.Count -eq 1 -and $nameMatches.Count -eq 1 -and [guid]$samMatches[0].ObjectGUID -ne [guid]$nameMatches[0].ObjectGUID) {
                throw ('Computer [{0}] matches different objects by SAM and target CN; no merge will be attempted.' -f $key)
            }
            $existing = $null
            if ($samMatches.Count -eq 1) { $existing = $samMatches[0] }
            elseif ($nameMatches.Count -eq 1) { $existing = $nameMatches[0] }
            if ($null -ne $existing) {
                $guidKey = [string]$existing.ObjectGUID
                if ($claimedObjects.ContainsKey($guidKey)) { throw 'Two computer definitions claim the same existing object.' }
                $claimedObjects[$guidKey] = $key
            }
            $plans[$key] = [pscustomobject]@{ Definition=$definition; SamAccountName=$samName; Existing=$existing }
        }
    }
    catch {
        Stop-ScriptGracefully -IndentLevel 2 -Message ('Computer preflight failed; no computer writes started: {0}' -f $_.Exception.Message)
    }

    foreach ($key in $plans.Keys) {
        $plan = $plans[$key]
        $definition = $plan.Definition
        $created = $null -eq $plan.Existing
        $changed = $false
        Write-Status -Kind Info -Message ('Checking computer [{0}] (key: {1}).' -f $definition.Name,$key)
        try {
            if ($created) {
                Write-Status -IndentLevel 2 -Kind Info -Message ('Creating enabled computer [{0}] under [{1}].' -f $definition.Name,$definition.Path)
                $newParameters = @{
                    Name=$definition.Name; SamAccountName=$plan.SamAccountName
                    Path=$definition.Path; Enabled=$true; Server=$server
                    PassThru=$true; ErrorAction='Stop'
                }
                foreach ($field in @('DisplayName','Description')) {
                    if (-not [string]::IsNullOrEmpty([string]$definition[$field])) { $newParameters[$field] = $definition[$field] }
                }
                Assert-LabInventoryHealthy
                $computer = New-ADComputer @newParameters
                Add-LabGeneratedADObject -Kind Computer -Object $computer
                if ($null -eq $computer -or [guid]$computer.ObjectGUID -eq [guid]::Empty) { throw 'Computer creation returned no GUID.' }
                $identity = [guid]$computer.ObjectGUID
            }
            else {
                $identity = [guid]$plan.Existing.ObjectGUID
                $computer = Get-ADComputer -Identity $identity -Properties DisplayName,Description,Enabled -Server $server -ErrorAction Stop
                if ($null -eq $computer -or $computer.ObjectClass -ine 'computer' -or [guid]$computer.ObjectGUID -ne $identity) {
                    throw 'Existing computer identity could not be revalidated.'
                }
                $parent = Get-ParentDistinguishedName -DistinguishedName $computer.DistinguishedName
                if ($parent -ine $definition.Path) {
                    Write-Status -IndentLevel 2 -Kind Info -Message ('Moving computer [{0}] to [{1}].' -f $computer.Name,$definition.Path)
                    Move-ADObject -Identity $identity -TargetPath $definition.Path -Server $server -ErrorAction Stop
                    $changed = $true
                }
                if ($computer.Name -cne $definition.Name) {
                    Write-Status -IndentLevel 2 -Kind Info -Message ('Restoring computer CN [{0}].' -f $definition.Name)
                    Rename-ADObject -Identity $identity -NewName $definition.Name -Server $server -ErrorAction Stop
                    $changed = $true
                }
                $setParameters = @{ Identity=$identity; Server=$server; ErrorAction='Stop' }
                $clear = @()
                $changedFields = @()
                foreach ($field in @('SamAccountName','DisplayName','Description')) {
                    $desired = [string]$definition[$field]
                    if ($field -eq 'SamAccountName') { $desired = $plan.SamAccountName }
                    if ([string]$computer.$field -ceq $desired) { continue }
                    $changedFields += $field
                    if ($field -ne 'SamAccountName' -and $desired.Length -eq 0) { $clear += $field }
                    else { $setParameters[$field] = $desired }
                }
                # Enabled is a required baseline for every defined computer,
                # including an account disabled since the previous run.
                if ($computer.Enabled -ne $true) {
                    $setParameters['Enabled'] = $true
                    $changedFields += 'Enabled'
                }
                if ($clear.Count -gt 0) { $setParameters['Clear'] = $clear }
                if ($changedFields.Count -gt 0) {
                    Write-Status -IndentLevel 2 -Kind Info -Message ('Restoring computer [{0}] fields: {1}.' -f $definition.Name,($changedFields -join ', '))
                    Set-ADComputer @setParameters
                    $changed = $true
                }
            }
            # Publish only verified objects. GUID references survive later AD
            # changes, while cached DNs/properties must be refreshed after moves.
            $verified = Get-ADComputer -Identity $identity -Properties DisplayName,Description,Enabled -Server $server -ErrorAction Stop
            if ($null -eq $verified -or $verified.ObjectClass -ine 'computer' -or [guid]$verified.ObjectGUID -ne $identity -or
                $verified.Name -cne $definition.Name -or $verified.SamAccountName -cne $plan.SamAccountName -or
                (Get-ParentDistinguishedName -DistinguishedName $verified.DistinguishedName) -ine $definition.Path -or
                [string]$verified.DisplayName -cne [string]$definition.DisplayName -or [string]$verified.Description -cne [string]$definition.Description) {
                throw 'Computer read-back did not match the expected GUID, CN, SAM, path or managed properties.'
            }
            if ($verified.Enabled -ne $true) { throw 'Computer read-back did not confirm Enabled=True.' }
            $computerObjects[$key] = $verified
            if ($created) { $createdCount++ }
            elseif ($changed) { $updatedCount++ }
            else { $unchangedCount++ }
            Write-Status -IndentLevel 2 -Kind Success -Message ('Verified computer [{0}] as [{1}] (key: {2}).' -f $verified.DistinguishedName,$verified.SamAccountName,$key)
        }
        catch {
            Stop-ScriptGracefully -IndentLevel 2 -Message ('Could not reconcile computer [{0}]: {1} Earlier writes may have committed; no automatic rollback, protection bypass or DC failover was attempted.' -f $key,$_.Exception.Message)
        }
    }
    Add-LabProcessingCount -Category 'computers' -Created $createdCount -Updated $updatedCount
    $summaryKind = 'Success'
    if ($skippedCount -gt 0) { $summaryKind = 'Warning' }
    Write-Status -IndentLevel 0 -Kind $summaryKind -Message ('Computer objects: {0} verified ({1} created, {2} updated, {3} already matched), {4} skipped due to unavailable target containers. Verified computers are enabled; skipped computers were not reconciled and have no verified registry entry. Existing machine passwords, SPNs and DNS names were not managed.' -f $computerObjects.Count,$createdCount,$updatedCount,$unchangedCount,$skippedCount)
    return ,$computerObjects
}

function Get-LabGroupForNesting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Reference,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$GroupDefinitions,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$GroupObjects,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$ExistingGroupDefinitions,

        [Parameter(Mandatory = $true)]
        [string]$Server
    )

    # Accept a stable definition key, or an unambiguous configured Name/SAM
    # name. Existing-only groups must have an explicit registered identity;
    # do not guess at unrelated groups outside the configured registries.
    $matchingKeys = @()
    if ($GroupDefinitions.Contains($Reference)) {
        $matchingKeys = @($Reference)
    }
    else {
        foreach ($key in $GroupDefinitions.Keys) {
            $definition = $GroupDefinitions[$key]
            if ($definition.Name -ieq $Reference -or $definition.SamAccountName -ieq $Reference) {
                $matchingKeys += $key
            }
        }
    }
    if ($matchingKeys.Count -eq 0) {
        # Only explicitly registered existing-only groups are eligible for
        # this fallback. Never search/adopt an arbitrary group by name.
        $existingDefinitions = $ExistingGroupDefinitions
        $existingKeys = @()
        foreach ($existingKey in $existingDefinitions.Keys) {
            $existingDefinition = $existingDefinitions[$existingKey]
            if ($existingKey -ieq $Reference -or $existingDefinition.Name -ieq $Reference -or $existingDefinition.Identity -ieq $Reference) {
                $existingKeys += $existingKey
            }
        }
        if ($existingKeys.Count -gt 1) {
            throw ("Group reference '{0}' matched multiple existing-only definitions. Use a unique reference." -f $Reference)
        }
        if ($existingKeys.Count -eq 1) {
            $existingDefinition = $existingDefinitions[$existingKeys[0]]
            # Read by explicit SID/GUID/DN on the same DC as provisioning.
            # No New/Set/Move/Rename operation is performed for this group.
            return Get-ADGroup -Identity $existingDefinition.Identity -Properties member -Server $Server -ErrorAction Stop
        }
        throw (("Group '{0}' is not defined in Get-LabGroupDefinitions. " +
            'Add this group to Get-LabGroupDefinitions so Ensure-RequiredGroups can create/update it, ' +
            'then rerun the script. This membership was skipped.') -f $Reference)
    }
    if ($matchingKeys.Count -gt 1) {
        throw ("Group reference '{0}' matched {1} configured groups. Use a unique name or stable definition key." -f $Reference, $matchingKeys.Count)
    }
    $resolvedKey = $matchingKeys[0]
    if (-not $GroupObjects.Contains($resolvedKey) -or $null -eq $GroupObjects[$resolvedKey]) {
        throw ("Group '{0}' has no resolved group object. Create/reconcile groups before nesting." -f $Reference)
    }
    # Refresh from the same selected DC, using the identity established by
    # group provisioning. Read only direct links; never enumerate recursively.
    return Get-ADGroup -Identity $GroupObjects[$resolvedKey].ObjectGUID -Properties member -Server $Server -ErrorAction Stop
}

function Ensure-LabGroupNesting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Domain,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$GroupDefinitions,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$GroupObjects
    )

    Write-SectionHeader -Message 'Create/Update Group Nesting...'

    $groupNesting = Get-LabGroupNestingDefinitions

    $server = [string]$Domain.SelectedDomainController
    if ([string]::IsNullOrWhiteSpace($server)) {
        Stop-ScriptGracefully -Message 'Group nesting requires a selected writable DC.'
    }
    # Reuse the validated domain context; resolve RID-based parent identities
    # once, without another AD query and without provisioning those parents.
    $existingGroupDefinitions = Get-LabExistingGroupDefinitions -DomainSID ([string]$Domain.DomainSID.Value) -DomainDN ([string]$Domain.DistinguishedName)

    $addedCount = 0
    $existingCount = 0
    $skippedCount = 0

    foreach ($childReference in $groupNesting.Keys) {
        Write-Status -Kind Info -Message ("Checking nesting for child group '{0}'." -f $childReference)
        $parentReferences = @($groupNesting[$childReference])
        if ($parentReferences.Count -eq 0) {
            Write-Status -Kind Info -Message ("No parents configured for '{0}'; existing memberships were left unchanged." -f $childReference)
            continue
        }
        try {
            $childGroup = Get-LabGroupForNesting -Reference $childReference `
                -GroupDefinitions $GroupDefinitions -GroupObjects $GroupObjects `
                -ExistingGroupDefinitions $existingGroupDefinitions -Server $server
        }
        catch {
            Write-Status -Kind Warning -Message ("Skipping nesting for child group '{0}': {1}" -f $childReference, $_.Exception.Message)
            $skippedCount += $parentReferences.Count
            continue
        }

        $seenParents = @{}
        foreach ($parentReference in $parentReferences) {
            if ($parentReference -isnot [string] -or [string]::IsNullOrWhiteSpace($parentReference)) {
                Write-Status -Kind Warning -Message ("Skipping an invalid/blank parent reference for child '{0}'." -f $childGroup.Name)
                $skippedCount++
                continue
            }
            Write-Status -Kind Info -Message ("Checking direct membership of '{0}' in '{1}'." -f $childGroup.Name, $parentReference)
            try {
                $parentGroup = Get-LabGroupForNesting -Reference $parentReference `
                    -GroupDefinitions $GroupDefinitions -GroupObjects $GroupObjects `
                    -ExistingGroupDefinitions $existingGroupDefinitions -Server $server
            }
            catch {
                Write-Status -Kind Warning -Message ("Skipping parent '{0}' for child '{1}': {2}" -f $parentReference, $childGroup.Name, $_.Exception.Message)
                $skippedCount++
                continue
            }
            $parentGuid = [string]$parentGroup.ObjectGUID
            if ($seenParents.ContainsKey($parentGuid)) {
                Write-Status -Kind Info -Message ("Parent '{0}' was listed more than once for '{1}'; ignoring the duplicate." -f $parentGroup.Name, $childGroup.Name)
                continue
            }
            $seenParents[$parentGuid] = $true

            # Direct 'member' values keep this idempotent without traversing
            # intentionally cyclic nested groups (including self-membership).
            if (@($parentGroup.member) -icontains $childGroup.DistinguishedName) {
                Write-Status -Kind Info -Message ("Group '{0}' is already a direct member of '{1}'." -f $childGroup.Name, $parentGroup.Name)
                $existingCount++
                continue
            }
            if ($childGroup.ObjectGUID -eq $parentGroup.ObjectGUID) {
                Write-Status -IndentLevel 2 -Kind Warning -Message ("Creating intentional self-membership for '{0}'. Lab use only; this can cause unstable behavior." -f $childGroup.Name)
            }
            Write-Status -IndentLevel 3 -Kind Info -Message ("Adding group '{0}' as a member of '{1}'." -f $childGroup.Name, $parentGroup.Name)
            try {
                # Identity is the PARENT receiving the CHILD. Do not reverse.
                # Do not reject self-membership or circular nesting in this lab.
                Add-ADGroupMember -Identity $parentGroup.ObjectGUID `
                    -Members $childGroup.DistinguishedName -Server $server -ErrorAction Stop
                $verifiedParent = Get-ADGroup -Identity $parentGroup.ObjectGUID -Properties member -Server $server -ErrorAction Stop
                if (@($verifiedParent.member) -inotcontains $childGroup.DistinguishedName) {
                    throw 'The requested direct membership was not present on read-back.'
                }
            }
            catch {
                # An add may have committed even if verification fails. Stop;
                # do not silently retry a write against another DC.
                Stop-ScriptGracefully -IndentLevel 2 -Message ("Could not add or verify '{0}' in '{1}': {2}" -f $childGroup.Name, $parentGroup.Name, $_.Exception.Message)
            }
            Write-Status -IndentLevel 2 -Kind Success -Message ("Group '{0}' is now a direct member of '{1}'." -f $childGroup.Name, $parentGroup.Name)
            $addedCount++
        }
    }

    Add-LabProcessingCount -Category 'group nesting' -Added $addedCount
    $summary = 'Group nesting: {0} added, {1} already present, {2} skipped. No memberships were removed.' -f $addedCount, $existingCount, $skippedCount
    if ($skippedCount -gt 0) {
        Write-Status -IndentLevel 0 -Kind Warning -Message $summary
    }
    else {
        Write-Status -IndentLevel 0 -Kind Success -Message $summary
    }
    return [pscustomobject]@{
        AddedCount    = $addedCount
        ExistingCount = $existingCount
        SkippedCount  = $skippedCount
    }
}

function Assert-LabManagedUserPasswordSettings {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Settings)

    if ($Settings.PasswordLength -isnot [int] -or $Settings.PasswordLength -lt 30 -or $Settings.PasswordLength -gt 256 -or
        $Settings.SymbolCount -isnot [int] -or $Settings.SymbolCount -ne 2 -or
        $Settings.UppercaseCharacters -isnot [string] -or $Settings.UppercaseCharacters -cnotmatch '^[A-Z]+$' -or
        $Settings.LowercaseCharacters -isnot [string] -or $Settings.LowercaseCharacters -cnotmatch '^[a-z]+$' -or
        $Settings.DigitCharacters -isnot [string] -or $Settings.DigitCharacters -cnotmatch '^[0-9]+$' -or
        $Settings.SymbolCharacters -isnot [string] -or $Settings.SymbolCharacters -cnotmatch '^[!@#$%^&*()_+=?~-]{2}$' -or
        $Settings.SymbolCharacters[0] -ceq $Settings.SymbolCharacters[1]) {
        throw 'Managed user passwords require at least 30 characters (supported maximum 256), two distinct common symbols, and nonempty uppercase/lowercase/digit alphabets.'
    }
    if ($Settings.NonHumanMinimumLength -isnot [int] -or $Settings.NonHumanMinimumLength -lt 30 -or $Settings.NonHumanMinimumLength -gt 256 -or
        $Settings.AdminMinimumLength -isnot [int] -or $Settings.AdminMinimumLength -lt 20 -or $Settings.AdminMinimumLength -gt 256 -or
        @($Settings.AdminAccountPrefixes).Count -eq 0) {
        throw 'Non-human minimum must be at least 30 and admin minimum at least 20 (maximum 256); admin prefixes must be configured.'
    }
    foreach ($prefix in $Settings.AdminAccountPrefixes) {
        if ([string]::IsNullOrWhiteSpace([string]$prefix)) { throw 'Admin password-classification prefixes must not be blank.' }
    }
    if (@($Settings.ServiceAccountPrefixes).Count -eq 0 -or @($Settings.SharedPasswordAccountNames).Count -eq 0) {
        throw 'Service-account prefixes and the shared-password allowlist must not be empty.'
    }
    foreach ($name in @($Settings.ServiceAccountPrefixes) + @($Settings.SharedPasswordAccountNames)) {
        if ($name -isnot [string] -or [string]::IsNullOrWhiteSpace($name)) {
            throw 'Service prefixes and shared-password account names must be nonblank strings.'
        }
    }
    if (($Settings.UppercaseCharacters.Length + $Settings.LowercaseCharacters.Length + $Settings.DigitCharacters.Length) -gt 256) {
        throw 'Managed password alphanumeric alphabet must not exceed the random-index helper limit of 256 characters.'
    }
    if ($Settings.ServiceAccountPrefix -isnot [string] -or [string]::IsNullOrWhiteSpace($Settings.ServiceAccountPrefix)) {
        throw 'Managed password classification requires a nonblank service-account prefix.'
    }
}

function Test-LabUserRequiresManagedPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Definition,
        [Parameter(Mandatory = $true)][string]$DomainDN,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Settings
    )

    # Only explicit shared-password SAM names use Windows Credential Store.
    # No implicit shared-password fallback for new definitions or admin names.
    return (@($Settings.SharedPasswordAccountNames) -inotcontains [string]$Definition.SamAccountName)
}

function New-LabManagedUserPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Settings,
        [Parameter(Mandatory = $true)][string]$SamAccountName,
        [AllowEmptyCollection()][string[]]$AccountNames = @(),
        [ValidateRange(0,256)][int]$MinimumLength = 0
    )

    Assert-LabManagedUserPasswordSettings -Settings $Settings
    $upper = [string]$Settings.UppercaseCharacters
    $lower = [string]$Settings.LowercaseCharacters
    $digits = [string]$Settings.DigitCharacters
    $symbols = [string]$Settings.SymbolCharacters
    $alphanumeric = $upper + $lower + $digits
    $length = [Math]::Max([Math]::Max($Settings.PasswordLength,$Settings.NonHumanMinimumLength),$MinimumLength)
    $characters = New-Object char[] $length
    $random = $null
    $password = $null
    $candidate = $null
    # Avoid the SAM and three-character-or-longer name tokens. Custom password
    # filters can still reject a candidate; AD errors are never bypassed.
    $excludedTokens = @($SamAccountName)
    foreach ($name in $AccountNames) {
        foreach ($token in ($name -split '[,.\-_\s#]+')) {
            if ($token.Length -ge 3) { $excludedTokens += $token }
        }
    }
    try {
        $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        for ($attempt = 0; $attempt -lt 100; $attempt++) {
            # Fill the variable-length alphanumeric region with all three categories.
            $characters[0] = $upper[(Get-CryptographicRandomIndex -Random $random -UpperBound $upper.Length)]
            $characters[1] = $lower[(Get-CryptographicRandomIndex -Random $random -UpperBound $lower.Length)]
            $characters[2] = $digits[(Get-CryptographicRandomIndex -Random $random -UpperBound $digits.Length)]
            for ($i = 3; $i -lt ($characters.Length - $Settings.SymbolCount); $i++) {
                $characters[$i] = $alphanumeric[(Get-CryptographicRandomIndex -Random $random -UpperBound $alphanumeric.Length)]
            }
            # Include each of the two configured symbols exactly once.
            $characters[$characters.Length - 2] = $symbols[0]
            $characters[$characters.Length - 1] = $symbols[1]
            for ($i = $characters.Length - 1; $i -gt 0; $i--) {
                $j = Get-CryptographicRandomIndex -Random $random -UpperBound ($i + 1)
                $swap = $characters[$i]
                $characters[$i] = $characters[$j]
                $characters[$j] = $swap
            }
            $candidate = -join $characters
            $matchesIdentity = $false
            foreach ($token in $excludedTokens) {
                if (-not [string]::IsNullOrEmpty($token) -and $candidate.IndexOf($token,[System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $matchesIdentity = $true
                    break
                }
            }
            if ($matchesIdentity) { $candidate = $null; continue }
            $password = New-Object System.Security.SecureString
            foreach ($character in $characters) { $password.AppendChar($character) }
            $password.MakeReadOnly()
            return $password
        }
        throw 'Could not generate a managed password without identity tokens; no password value is logged.'
    }
    catch {
        if ($null -ne $password) { $password.Dispose() }
        throw
    }
    finally {
        $candidate = $null
        [Array]::Clear($characters, 0, $characters.Length)
        if ($null -ne $random) { $random.Dispose() }
    }
}

function Get-LabUserPasswordMinimum {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$SamAccountName,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Settings,
        [switch]$NonHuman
    )

    if ($NonHuman) { return [int]$Settings.NonHumanMinimumLength }
    foreach ($prefix in $Settings.ServiceAccountPrefixes) {
        if ($SamAccountName.StartsWith([string]$prefix,[StringComparison]::OrdinalIgnoreCase)) {
            return [int]$Settings.NonHumanMinimumLength
        }
    }
    # Explicit demo exceptions bypass only the script admin minimum;
    # the non-human rule above and effective AD policy still apply.
    if (@($Settings.OrdinaryDemoAccountNames) -icontains $SamAccountName) { return 0 }
    foreach ($prefix in $Settings.AdminAccountPrefixes) {
        if ($SamAccountName.StartsWith([string]$prefix,[StringComparison]::OrdinalIgnoreCase)) {
            return [int]$Settings.AdminMinimumLength
        }
    }
    if (@($Settings.AdminAccountNames) -icontains $SamAccountName) { return [int]$Settings.AdminMinimumLength }
    return 0 # Ordinary users follow the effective AD minimum.
}

function Get-LabUserPasswordRequirements {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [ValidateRange(0,256)][int]$LocalMinimumLength = 0,
        $ExistingUser
    )

    $server = [string]$Domain.SelectedDomainController
    if ([string]::IsNullOrWhiteSpace($server)) { throw 'Password-policy lookup requires the selected writable DC.' }
    $policy = $null
    if ($null -ne $ExistingUser) {
        # An empty result means no FGPP; a lookup error is NOT a fallback.
        $policy = Get-ADUserResultantPasswordPolicy -Identity $ExistingUser.ObjectGUID -Server $server -ErrorAction Stop
    }
    $fineGrained = ($null -ne $policy)
    if (-not $fineGrained) {
        $policy = Get-ADDefaultDomainPasswordPolicy -Identity $Domain.DistinguishedName -Server $server -ErrorAction Stop
    }
    if ($null -eq $policy -or $null -eq $policy.MinPasswordLength -or
        [int]$policy.MinPasswordLength -lt 0 -or [int]$policy.MinPasswordLength -gt 256 -or
        $null -eq $policy.ComplexityEnabled) {
        throw 'Password-policy lookup returned incomplete or unsupported requirements; no policy bypass attempted.'
    }
    $source = 'domain default'
    if ($fineGrained) { $source = 'FGPP [' + [string]$policy.Name + ']' }
    return [pscustomobject]@{
        MinimumLength = [Math]::Max($LocalMinimumLength,[int]$policy.MinPasswordLength)
        AdMinimumLength = [int]$policy.MinPasswordLength
        LocalMinimumLength = $LocalMinimumLength
        ComplexityEnabled = [bool]$policy.ComplexityEnabled
        PolicySource = $source
    }
}

function Assert-LabUserPasswordCandidate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Security.SecureString]$Password,
        [Parameter(Mandatory = $true)]$Requirements,
        [Parameter(Mandatory = $true)][string]$SamAccountName,
        [AllowEmptyCollection()][string[]]$AccountNames = @()
    )

    if ($Password.Length -lt $Requirements.MinimumLength) {
        throw ("Password for '{0}' is too short: requires at least {1} characters (script minimum {2}; {3} minimum {4}). Update the stored password with ClearStoredCreds and rerun if this is a shared-password account. Password value withheld." -f $SamAccountName,$Requirements.MinimumLength,$Requirements.LocalMinimumLength,$Requirements.PolicySource,$Requirements.AdMinimumLength)
    }
    if (-not $Requirements.ComplexityEnabled) { return }
    $pointer = [IntPtr]::Zero
    $plain = $null
    try {
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        $categories = 0
        foreach ($pattern in @('\p{Lu}','\p{Ll}','\p{Nd}','[^\p{L}\p{Nd}]','\p{Lo}')) {
            if ($plain -cmatch $pattern) { $categories++ }
        }
        if ($categories -lt 3) {
            throw ("Password for '{0}' does not meet standard AD complexity (at least three character categories); source: {1}. Password value withheld." -f $SamAccountName,$Requirements.PolicySource)
        }
        # Standard name checks only. DC-side filters and history remain authoritative.
        if ($SamAccountName.Length -ge 3 -and $plain.IndexOf($SamAccountName,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw ("Password for '{0}' contains its SAM name and fails standard AD complexity. Password value withheld." -f $SamAccountName)
        }
        foreach ($name in $AccountNames) {
            foreach ($part in @(([string]$name) -split '[,\.\-_ #\t]+')) {
                if ($part.Length -ge 3 -and $plain.IndexOf($part,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    throw ("Password for '{0}' contains an account-name token and fails standard AD complexity. Password value withheld." -f $SamAccountName)
                }
            }
        }
    }
    finally {
        $plain = $null
        if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    }
}

function Assert-LabPreservedAccountCanBeEnabled {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$User,
        [Parameter(Mandatory = $true)][bool]$DesiredEnabled,
        [Parameter(Mandatory = $true)][bool]$WillSetPassword
    )

    if ($DesiredEnabled -and -not $User.Enabled -and [long]$User.pwdLastSet -eq 0 -and -not $WillSetPassword) {
        throw ("Existing disabled account '{0}' has pwdLastSet=0. This may be incomplete creation OR a required password change; it does not prove that no password exists. This run preserves its password and will not enable it or repair it automatically. Review and repair this specific account explicitly, then rerun." -f $User.SamAccountName)
    }
}

function New-LabPasswordInitializedUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$NewUserParameters,
        [Parameter(Mandatory = $true)][ValidateSet('Shared','Managed','Generic')][string]$PasswordMode,
        [ValidateRange(0,256)][int]$LocalMinimumLength = 0,
        [System.Security.SecureString]$SharedPassword,
        [System.Collections.IDictionary]$PasswordSettings,
        [System.Security.Cryptography.RandomNumberGenerator]$Random
    )

    $server = [string]$Domain.SelectedDomainController
    $samName = [string]$NewUserParameters.SamAccountName
    $desiredEnabled = [bool]$NewUserParameters.Enabled
    $parameters = @{}
    foreach ($key in $NewUserParameters.Keys) { $parameters[$key] = $NewUserParameters[$key] }
    # Only this newly created GUID is initialized. Never adopt a partial object
    # from an earlier run or reset an existing svc- account as a recovery action.
    $parameters.Remove('AccountPassword')
    $parameters.Enabled = $false
    $parameters.Server = $server
    $parameters.PassThru = $true
    $parameters.ErrorAction = 'Stop'
    $generated = $null
    $created = $null
    $operation = 'create disabled user'
    try {
        Assert-LabInventoryHealthy
        $created = New-ADUser @parameters
        Add-LabGeneratedADObject -Kind User -Object $created
        if ($null -eq $created -or $null -eq $created.ObjectGUID -or [guid]$created.ObjectGUID -eq [guid]::Empty) {
            throw 'New-ADUser did not return the new object GUID; no password initialization attempted.'
        }
        $operation = 'read resultant policy for newly created user'
        $requirements = Get-LabUserPasswordRequirements -Domain $Domain -LocalMinimumLength $LocalMinimumLength -ExistingUser $created
        $password = $SharedPassword
        if ($PasswordMode -eq 'Managed') {
            $generated = New-LabManagedUserPassword -Settings $PasswordSettings -SamAccountName $samName `
                -AccountNames @([string]$parameters['Name'],[string]$parameters['DisplayName']) -MinimumLength $requirements.MinimumLength
            $password = $generated
        }
        elseif ($PasswordMode -eq 'Generic') {
            $generated = New-GenericUserPassword -Random $Random -Settings $PasswordSettings -MinimumLength $requirements.MinimumLength
            $password = $generated
        }
        $operation = 'validate candidate against script and effective AD minimum/standard complexity'
        Assert-LabUserPasswordCandidate -Password $password -Requirements $requirements -SamAccountName $samName `
            -AccountNames @([string]$parameters['Name'],[string]$parameters['DisplayName'])
        Write-Status -IndentLevel 3 -Kind Info -Message ("Initializing '{0}': password length {1}, required minimum {2}, source {3}; value not logged." -f $samName,$password.Length,$requirements.MinimumLength,$requirements.PolicySource)
        $operation = 'initialize password on newly created user'
        Set-ADAccountPassword -Identity $created.ObjectGUID -Reset -NewPassword $password -Server $server -ErrorAction Stop
        $operation = 'set new-user change-at-logon and enabled state'
        Set-ADUser -Identity $created.ObjectGUID -ChangePasswordAtLogon $false -Enabled $desiredEnabled -Server $server -ErrorAction Stop
        return $created
    }
    catch {
        throw ("New-user initialization failed for '{0}' during [{1}]: {2}. A partial account may remain; review it explicitly before retrying. Password filters and AD enforcement remain authoritative." -f $samName,$operation,$_.Exception.Message)
    }
    finally { if ($null -ne $generated) { $generated.Dispose() } }
}

function Ensure-LabDemoUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Domain,
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$UserDefinitions,
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$DemoPassword,
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$Tier0AdminPassword,
        [Parameter(Mandatory = $true)]
        [bool]$DoNotUpdateExistingPasswords,
        [switch]$RefreshAllPasswords
    )

    Write-SectionHeader -Message 'Create/Update Demo Users...'
    $server = [string]$Domain.SelectedDomainController
    $domainDN = [string]$Domain.DistinguishedName
    $userObjects = [ordered]@{}
    $plans = [ordered]@{}
    $passwordRequirements = @{}
    $localMinimums = @{}
    $samNames = @{}
    $upnNames = @{}
    $targetNames = @{}
    $claimedObjects = @{}
    $checkedPaths = @{}
    $managedPasswordUsers = @{}
    $managedPasswordSettings = Get-LabManagedUserPasswordSettings

    # Internal attribute translations, not a second desired-state data set.
    # Read/cmdlet property names differ from LDAP display names for some fields.
    $attributeMap = [ordered]@{
        SamAccountName    = @{ Read = 'SamAccountName';    Ldap = 'sAMAccountName' }
        GivenName         = @{ Read = 'GivenName';         Ldap = 'givenName' }
        Surname           = @{ Read = 'Surname';           Ldap = 'sn' }
        DisplayName       = @{ Read = 'DisplayName';       Ldap = 'displayName' }
        Initials          = @{ Read = 'Initials';          Ldap = 'initials' }
        Description       = @{ Read = 'Description';       Ldap = 'description' }
        Mail              = @{ Read = 'EmailAddress';      Ldap = 'mail' }
        Title             = @{ Read = 'Title';             Ldap = 'title' }
        Department        = @{ Read = 'Department';        Ldap = 'department' }
        Division          = @{ Read = 'Division';          Ldap = 'division' }
        Company           = @{ Read = 'Company';           Ldap = 'company' }
        TelephoneNumber   = @{ Read = 'OfficePhone';        Ldap = 'telephoneNumber' }
        FAX               = @{ Read = 'Fax';                Ldap = 'facsimileTelephoneNumber' }
        City              = @{ Read = 'City';               Ldap = 'l' }
        State             = @{ Read = 'State';              Ldap = 'st' }
        EmployeeID        = @{ Read = 'EmployeeID';         Ldap = 'employeeID' }
        UserPrincipalName = @{ Read = 'UserPrincipalName';  Ldap = 'userPrincipalName' }
    }
    $supportedProperties = @($attributeMap.Keys) + @('Name', 'Path', 'Enabled', 'PasswordNeverExpires', 'TelephoneNumberAlt', 'FAXalt')
    $readProperties = @($attributeMap.Values | ForEach-Object { $_.Read }) + @('Enabled', 'pwdLastSet', 'PasswordNeverExpires')

    # Check the whole demo-user plan before starting ANY demo-user writes.
    # Match by SAM or by CN in the target OU, never by duplicate mail/employeeID.
    # Reject ambiguous identities and non-user objects instead of overwriting.
    Write-Status -Kind Info -Message 'Validating demo-user definitions, target OUs and identities.'
    try {
        Assert-LabManagedUserPasswordSettings -Settings $managedPasswordSettings
        if ([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($domainDN) -or $DemoPassword.Length -eq 0) {
            throw 'Demo users require the selected DC, domain DN and a nonempty SecureString password.'
        }
        if ($Tier0AdminPassword.Length -eq 0) {
            throw 'Tier0Admin requires its own nonempty SecureString password; no DEMO fallback is permitted.'
        }
        foreach ($key in $UserDefinitions.Keys) {
            $definition = $UserDefinitions[$key]
            if ($definition -isnot [System.Collections.IDictionary]) {
                throw ("Demo user '{0}' must be a hash table." -f $key)
            }
            foreach ($property in @('Name', 'SamAccountName', 'Path', 'UserPrincipalName', 'Enabled')) {
                if (-not $definition.Contains($property)) {
                    throw ("Demo user '{0}' is missing '{1}'." -f $key, $property)
                }
            }
            foreach ($property in $definition.Keys) {
                if ($supportedProperties -notcontains $property) {
                    throw ("Demo user '{0}' has unsupported property '{1}'." -f $key, $property)
                }
                if ($property -in @('Enabled','PasswordNeverExpires')) {
                    if ($definition[$property] -isnot [bool]) {
                        throw ("Demo user '{0}' {1} must be a Boolean." -f $key, $property)
                    }
                }
                elseif ($null -ne $definition[$property] -and $definition[$property] -isnot [string]) {
                    throw ("Demo user '{0}' property '{1}' must be a string or null." -f $key, $property)
                }
            }
            foreach ($property in @('Name', 'SamAccountName', 'Path', 'UserPrincipalName')) {
                if ([string]::IsNullOrWhiteSpace([string]$definition[$property])) {
                    throw ("Demo user '{0}' requires a nonblank '{1}'." -f $key, $property)
                }
            }
            if ($definition.SamAccountName.Length -gt 20 -or $definition.SamAccountName -match '["/\\\[\]:;|=,+*?<>]') {
                throw ("Demo user '{0}' has an invalid SAM name (maximum 20 characters)." -f $key)
            }
            if (-not $definition.Path.EndsWith(',' + $domainDN, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw ("Demo user '{0}' must target an OU in the discovered domain." -f $key)
            }
            $targetKey = '{0}|{1}' -f $definition.Path, $definition.Name
            if ($samNames.ContainsKey($definition.SamAccountName) -or $upnNames.ContainsKey($definition.UserPrincipalName) -or $targetNames.ContainsKey($targetKey)) {
                throw ("Demo user '{0}' duplicates a configured SAM, UPN or CN/OU." -f $key)
            }
            $samNames[$definition.SamAccountName] = $true
            $upnNames[$definition.UserPrincipalName] = $true
            $targetNames[$targetKey] = $true
            if (-not $checkedPaths.ContainsKey($definition.Path)) {
                Get-ADOrganizationalUnit -Identity $definition.Path -Server $server -ErrorAction Stop | Out-Null
                $checkedPaths[$definition.Path] = $true
            }
            $samFilter = '(sAMAccountName={0})' -f (ConvertTo-LdapFilterValue -Value $definition.SamAccountName)
            $nameFilter = '(name={0})' -f (ConvertTo-LdapFilterValue -Value $definition.Name)
            $samMatches = @(Get-ADObject -LDAPFilter $samFilter -SearchBase $domainDN -SearchScope Subtree -Server $server -ErrorAction Stop)
            $nameMatches = @(Get-ADObject -LDAPFilter $nameFilter -SearchBase $definition.Path -SearchScope OneLevel -Server $server -ErrorAction Stop)
            if ($samMatches.Count -gt 1 -or $nameMatches.Count -gt 1) {
                throw ("Demo user '{0}' matched multiple objects; repair the ambiguity first." -f $key)
            }
            foreach ($match in (@($samMatches) + @($nameMatches))) {
                if ($match.ObjectClass -ine 'user') {
                    throw ("Demo user '{0}' conflicts with a non-user object: {1}." -f $key, $match.DistinguishedName)
                }
            }
            if ($samMatches.Count -eq 1 -and $nameMatches.Count -eq 1 -and $samMatches[0].ObjectGUID -ne $nameMatches[0].ObjectGUID) {
                throw ("Demo user '{0}' matches different users by SAM and CN/OU; no merge attempted." -f $key)
            }
            $existingUser = $null
            if ($samMatches.Count -eq 1) {
                $existingUser = Get-ADUser -Identity $samMatches[0].ObjectGUID -Properties $readProperties -Server $server -ErrorAction Stop
            }
            elseif ($nameMatches.Count -eq 1) {
                $existingUser = Get-ADUser -Identity $nameMatches[0].ObjectGUID -Properties $readProperties -Server $server -ErrorAction Stop
            }
            if ($null -ne $existingUser) {
                $guidKey = [string]$existingUser.ObjectGUID
                if ($claimedObjects.ContainsKey($guidKey)) {
                    throw ("Demo user '{0}' resolves to the same object as '{1}'." -f $key, $claimedObjects[$guidKey])
                }
                $claimedObjects[$guidKey] = $key
            }
            $upnFilter = '(userPrincipalName={0})' -f (ConvertTo-LdapFilterValue -Value $definition.UserPrincipalName)
            $upnMatches = @(Get-ADObject -LDAPFilter $upnFilter -SearchBase $domainDN -SearchScope Subtree -Server $server -ErrorAction Stop)
            foreach ($match in $upnMatches) {
                if ($null -eq $existingUser -or $match.ObjectGUID -ne $existingUser.ObjectGUID) {
                    throw ("Demo user '{0}' UPN belongs to another object: {1}." -f $key, $match.DistinguishedName)
                }
            }
            # Tier0Admin is selected by stable definition key, not OU/SID/name.
            $managedPasswordUsers[$key] = ($key -ine 'Tier0Admin' -and
                (Test-LabUserRequiresManagedPassword -Definition $definition -DomainDN $domainDN -Settings $managedPasswordSettings))
            $passwordForThisUser = $DemoPassword
            if ($key -ieq 'Tier0Admin') { $passwordForThisUser = $Tier0AdminPassword }
            $willSetPassword = ($null -eq $existingUser -or
                (-not $managedPasswordUsers[$key] -and ($RefreshAllPasswords -or -not $DoNotUpdateExistingPasswords)))
            $localMinimums[$key] = Get-LabUserPasswordMinimum -SamAccountName $definition.SamAccountName -Settings $managedPasswordSettings
            if ($null -ne $existingUser) {
                Assert-LabPreservedAccountCanBeEnabled -User $existingUser -DesiredEnabled $definition.Enabled -WillSetPassword $willSetPassword
                if ($definition.Contains('PasswordNeverExpires') -and $definition.PasswordNeverExpires -and
                    [long]$existingUser.pwdLastSet -eq 0 -and -not $willSetPassword) {
                    throw ("Demo user '{0}' requires a password change at logon (pwdLastSet=0), which conflicts with PasswordNeverExpires=True. This run preserves its password/change requirement; review this account explicitly before rerunning. No automatic reset or change-at-logon repair attempted." -f $key)
                }
            }
            if ($willSetPassword) {
                $passwordRequirements[$key] = Get-LabUserPasswordRequirements -Domain $Domain -LocalMinimumLength $localMinimums[$key] -ExistingUser $existingUser
                if (-not $managedPasswordUsers[$key]) {
                    Assert-LabUserPasswordCandidate -Password $passwordForThisUser -Requirements $passwordRequirements[$key] -SamAccountName $definition.SamAccountName `
                        -AccountNames @([string]$definition['Name'],[string]$definition['DisplayName'])
                }
            }
            $plans[$key] = $existingUser
        }
    }
    catch {
        Stop-ScriptGracefully -IndentLevel 2 -Message ("Demo-user preflight failed; no demo-user writes started: {0}" -f $_.Exception.Message)
    }

    foreach ($key in $UserDefinitions.Keys) {
        $definition = $UserDefinitions[$key]
        $existingUser = $plans[$key]
        $useManagedPassword = [bool]$managedPasswordUsers[$key]
        # All non-allowlisted users receive random passwords only at creation,
        # even with RefreshAllPasswords. Only
        # shared-password users are eligible for the explicit refresh override.
        $setPasswordThisRun = ($null -eq $existingUser -or
            (-not $useManagedPassword -and ($RefreshAllPasswords -or -not $DoNotUpdateExistingPasswords)))
        $summaryUpdated = $false
        $generatedPassword = $null
        $passwordForThisUser = $DemoPassword
        if ($key -ieq 'Tier0Admin') { $passwordForThisUser = $Tier0AdminPassword }
        Write-Status -Kind Info -Message ("Checking demo user '{0}' (key: {1})." -f $definition.Name, $key)
        try {
            if ($null -eq $existingUser) {
                Write-Status -IndentLevel 3 -Kind Info -Message ("Creating demo user '{0}' disabled in '{1}' before password initialization." -f $definition.Name, $definition.Path)
                $newParameters = @{
                    Name = $definition.Name
                    SamAccountName = $definition.SamAccountName
                    Path = $definition.Path
                    AccountPassword = $passwordForThisUser
                    Enabled = $definition.Enabled
                    ChangePasswordAtLogon = $false
                    Server = $server
                    PassThru = $true
                    ErrorAction = 'Stop'
                }
                if ($definition.Contains('PasswordNeverExpires')) {
                    $newParameters['PasswordNeverExpires'] = $definition.PasswordNeverExpires
                }
                foreach ($property in $attributeMap.Keys) {
                    if ($property -eq 'SamAccountName' -or -not $definition.Contains($property)) { continue }
                    if (-not [string]::IsNullOrEmpty([string]$definition[$property])) {
                        $newParameters[$attributeMap[$property].Read] = [string]$definition[$property]
                    }
                }
                $mode = 'Shared'
                if ($useManagedPassword) { $mode = 'Managed' }
                $createdUser = New-LabPasswordInitializedUser -Domain $Domain -NewUserParameters $newParameters -PasswordMode $mode `
                    -LocalMinimumLength $localMinimums[$key] -SharedPassword $passwordForThisUser -PasswordSettings $managedPasswordSettings
                $userId = $createdUser.ObjectGUID
                if ($useManagedPassword) {
                    Write-Status -IndentLevel 2 -Kind Success -Message ("Created demo user '{0}' with a fresh policy-aware random password (value not logged)." -f $definition.Name)
                }
                else {
                    $passwordSourceLabel = 'demo'
                    if ($key -ieq 'Tier0Admin') { $passwordSourceLabel = 'dedicated Tier0Admin' }
                    Write-Status -IndentLevel 2 -Kind Success -Message ("Created demo user '{0}' with the collected {1} password." -f $definition.Name, $passwordSourceLabel)
                }
            }
            else {
                $userId = $existingUser.ObjectGUID
                $currentParent = Get-ParentDistinguishedName -DistinguishedName $existingUser.DistinguishedName
                if ($currentParent -ine $definition.Path) {
                    Write-Status -IndentLevel 3 -Kind Info -Message ("Moving demo user '{0}' to '{1}'." -f $definition.Name, $definition.Path)
                    Move-ADObject -Identity $userId -TargetPath $definition.Path -Server $server -ErrorAction Stop
                    $summaryUpdated = $true
                    Write-Status -IndentLevel 2 -Kind Success -Message 'Demo-user OU restored.'
                }
                if ($existingUser.Name -cne $definition.Name) {
                    Write-Status -IndentLevel 3 -Kind Info -Message ("Restoring demo-user CN to '{0}'." -f $definition.Name)
                    Rename-ADObject -Identity $userId -NewName $definition.Name -Server $server -ErrorAction Stop
                    $summaryUpdated = $true
                    Write-Status -IndentLevel 2 -Kind Success -Message 'Demo-user CN restored.'
                }
                $replaceAttributes = @{}
                $clearAttributes = @()
                foreach ($property in $attributeMap.Keys) {
                    if (-not $definition.Contains($property)) { continue }
                    $readName = $attributeMap[$property].Read
                    $desiredValue = [string]$definition[$property]
                    if ([string]$existingUser.$readName -ceq $desiredValue) { continue }
                    if ([string]::IsNullOrEmpty($desiredValue)) {
                        $clearAttributes += $attributeMap[$property].Ldap
                    }
                    else {
                        $replaceAttributes[$attributeMap[$property].Ldap] = $desiredValue
                    }
                }
                if ($replaceAttributes.Count -gt 0 -or $clearAttributes.Count -gt 0) {
                    Write-Status -IndentLevel 3 -Kind Info -Message ("Restoring configured profile attributes for '{0}'." -f $definition.Name)
                    $setParameters = @{ Identity = $userId; Server = $server; ErrorAction = 'Stop' }
                    if ($replaceAttributes.Count -gt 0) { $setParameters['Replace'] = $replaceAttributes }
                    if ($clearAttributes.Count -gt 0) { $setParameters['Clear'] = $clearAttributes }
                    Set-ADUser @setParameters
                    $summaryUpdated = $true
                    Write-Status -IndentLevel 2 -Kind Success -Message 'Demo-user profile attributes restored.'
                }
                else {
                    Write-Status -Kind Info -Message 'Configured profile attributes already match the baseline.'
                }
                if ($setPasswordThisRun) {
                    # Existing managed-user passwords are never reset here.
                    $passwordSourceLabel = 'demo'
                    if ($key -ieq 'Tier0Admin') { $passwordSourceLabel = 'dedicated Tier0Admin' }
                    Write-Status -IndentLevel 3 -Kind Info -Message ("Resetting the {0} password for '{1}'." -f $passwordSourceLabel, $definition.Name)
                    # Re-read immediately before reset: never rely on a stale preflight policy.
                    $requirements = Get-LabUserPasswordRequirements -Domain $Domain -LocalMinimumLength $localMinimums[$key] -ExistingUser $existingUser
                    Assert-LabUserPasswordCandidate -Password $passwordForThisUser -Requirements $requirements -SamAccountName $definition.SamAccountName `
                        -AccountNames @([string]$definition['Name'],[string]$definition['DisplayName'])
                    Set-ADAccountPassword -Identity $userId -Reset -NewPassword $passwordForThisUser -Server $server -ErrorAction Stop
                    $summaryUpdated = $true
                    Set-ADUser -Identity $userId -ChangePasswordAtLogon $false -Server $server -ErrorAction Stop
                    Write-Status -IndentLevel 4 -Kind Success -Message 'Password reset; no password change required at logon.'
                }
                else {
                    if ($useManagedPassword) {
                        Write-Status -IndentLevel 2 -Kind Info -Message 'Existing managed-user password and password-change requirement preserved (passwords set only at creation).'
                    }
                    else {
                        Write-Status -IndentLevel 2 -Kind Info -Message 'Existing demo password and password-change requirement left unchanged.'
                    }
                }
                # Account-option reconciliation is independent of password
                # resets. Never set this flag on an unconfigured demo user.
                if ($definition.Contains('PasswordNeverExpires') -and
                    $existingUser.PasswordNeverExpires -ne $definition.PasswordNeverExpires) {
                    Write-Status -IndentLevel 3 -Kind Info -Message ("Restoring PasswordNeverExpires={0} for '{1}'." -f $definition.PasswordNeverExpires, $definition.Name)
                    Set-ADUser -Identity $userId -PasswordNeverExpires $definition.PasswordNeverExpires -Server $server -ErrorAction Stop
                    $summaryUpdated = $true
                    Write-Status -IndentLevel 2 -Kind Success -Message 'Demo-user password-expiration setting restored.'
                }
                if ($existingUser.Enabled -ne $definition.Enabled) {
                    Write-Status -IndentLevel 3 -Kind Info -Message ("Restoring Enabled={0} for '{1}'." -f $definition.Enabled, $definition.Name)
                    Set-ADUser -Identity $userId -Enabled $definition.Enabled -Server $server -ErrorAction Stop
                    $summaryUpdated = $true
                    Write-Status -IndentLevel 2 -Kind Success -Message 'Demo-user enabled state restored.'
                }
            }
            $verifiedUser = Get-ADUser -Identity $userId -Properties $readProperties -Server $server -ErrorAction Stop
            if ($verifiedUser.Name -cne $definition.Name -or (Get-ParentDistinguishedName -DistinguishedName $verifiedUser.DistinguishedName) -ine $definition.Path -or $verifiedUser.Enabled -ne $definition.Enabled) {
                throw 'Read-back did not match the configured CN, parent OU or enabled state.'
            }
            foreach ($property in $attributeMap.Keys) {
                if (-not $definition.Contains($property)) { continue }
                $readName = $attributeMap[$property].Read
                if ([string]$verifiedUser.$readName -cne [string]$definition[$property]) {
                    throw ("Read-back did not match baseline property '{0}'." -f $property)
                }
            }
            if ($definition.Contains('PasswordNeverExpires') -and
                $verifiedUser.PasswordNeverExpires -ne $definition.PasswordNeverExpires) {
                throw 'Read-back did not match baseline PasswordNeverExpires.'
            }
            # Enforce this password baseline only when this run set a password.
            # Existing users may deliberately require a password change at logon.
            if ($setPasswordThisRun -and [long]$verifiedUser.pwdLastSet -eq 0) {
                throw 'Read-back indicates a missing password or a required password change at logon.'
            }
            Register-LabProcessingUser -Identity $userId -Category 'demo users'
            if ($null -eq $existingUser) { Add-LabProcessingCount -Category 'demo users' -Created 1 -Identity ([string]$userId) }
            elseif ($summaryUpdated) { Add-LabProcessingCount -Category 'demo users' -Updated 1 -Identity ([string]$userId) }
            $userObjects[$key] = $verifiedUser
            Write-Status -IndentLevel 2 -Kind Success -Message ("Verified demo user '{0}' on the selected DC." -f $definition.Name)
        }
        catch {
            # Prior writes may have committed. Stop; never silently fail over
            # writes to another DC, roll back objects, or disable protection.
            Stop-ScriptGracefully -IndentLevel 2 -Message ("Could not reconcile demo user '{0}': {1}. Earlier writes may have committed; review the account before retrying. Domain/FGPP password policies still apply." -f $definition.Name, $_.Exception.Message)
        }
        finally {
            # Never dispose either collected password here; Invoke-Main owns
            # both. Only this user's random SecureString belongs to this loop.
            if ($null -ne $generatedPassword) { $generatedPassword.Dispose() }
            $passwordForThisUser = $null
        }
    }
    Write-Status -IndentLevel 0 -Kind Success -Message ("Demo-user baselines verified: {0}. Generic users and user memberships were not managed." -f $userObjects.Count)
    return ,$userObjects
}

function Ensure-SpecialDomainAccounts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Domain,
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$AccountPassword,
        [Parameter(Mandatory = $true)]
        [bool]$DoNotUpdateExistingPasswords,
        [switch]$RefreshAllPasswords
    )

    Write-SectionHeader -Message 'Create/Update Special Domain Accounts...'
    $server = [string]$Domain.SelectedDomainController
    $domainDN = [string]$Domain.DistinguishedName
    $domainPrefix = [string]$Domain.NetBIOSName
    if ([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($domainDN) -or
        [string]::IsNullOrWhiteSpace($domainPrefix) -or $AccountPassword.Length -eq 0) {
        Stop-ScriptGracefully -IndentLevel 2 -Message 'Special accounts require the selected DC, domain DN, NetBIOS name and a nonempty SecureString password.'
    }

    $passwordSettings = Get-LabManagedUserPasswordSettings
    Assert-LabManagedUserPasswordSettings -Settings $passwordSettings
    $definitions = @(Get-LabSpecialDomainAccountDefinitions)
    $plans = @()
    $nameCounts = @{}
    $skippedCount = 0
    $createdCount = 0
    $updatedCount = 0
    $readProperties = @('SamAccountName', 'GivenName', 'DisplayName', 'Description', 'Enabled', 'pwdLastSet')

    foreach ($definition in $definitions) {
        $suffix = [string]$definition.Suffix
        if ($suffix.Length -gt 20) {
            Write-Status -IndentLevel 2 -Kind Error -Message ("Special-account suffix [{0}] is too long ({1} characters; maximum 20). Creation and updating skipped." -f $suffix, $suffix.Length)
            $skippedCount++
            continue
        }
        if ([string]::IsNullOrWhiteSpace($suffix) -or $suffix -match '["/\\\[\]:;|=,+*?<>\x00-\x1f]' -or
            $suffix -ne $suffix.Trim() -or $suffix.EndsWith('.')) {
            Write-Status -IndentLevel 2 -Kind Error -Message ("Special-account suffix [{0}] is blank or invalid for a SAM name; skipped." -f $suffix)
            $skippedCount++
            continue
        }
        if ($null -eq $definition.PSObject.Properties['SpecialAcctPasswordReset'] -or
            $definition.SpecialAcctPasswordReset -isnot [bool]) {
            Write-Status -IndentLevel 2 -Kind Error -Message ("Special account [{0}] requires Boolean SpecialAcctPasswordReset = `$True or `$False in Get-LabSpecialDomainAccountDefinitions; skipped." -f $suffix)
            $skippedCount++
            continue
        }
        $relativePath = [string]$definition.RelativePath
        if ([string]::IsNullOrWhiteSpace($relativePath) -or $relativePath -notmatch '^OU=') {
            Write-Status -IndentLevel 2 -Kind Error -Message ("Special account [{0}] requires a relative OU path in Get-LabSpecialDomainAccountDefinitions; skipped." -f $suffix)
            $skippedCount++
            continue
        }
        $prefixLength = [Math]::Min($domainPrefix.Length, 20 - $suffix.Length)
        $samName = $domainPrefix.Substring(0, $prefixLength) + $suffix
        if ($prefixLength -lt $domainPrefix.Length) {
            Write-Status -Kind Warning -Message ("Shortened NetBIOS prefix [{0}] to [{1}] for account [{2}]; suffix retained." -f $domainPrefix, $domainPrefix.Substring(0, $prefixLength), $samName)
        }
        $manageDescription = $null -ne $definition.PSObject.Properties['Description']
        $description = ''
        if ($manageDescription) { $description = [string]$definition.Description }
        $plans += [pscustomobject]@{
            SamName = $samName
            Path = $relativePath.TrimEnd(',') + ',' + $domainDN
            ManageDescription = $manageDescription
            Description = $description
            ExistingUser = $null
            ResetExistingPassword = $false  # Random passwords are creation-only; legacy reset flags cannot rotate them.
        }
        if (-not $nameCounts.ContainsKey($samName)) { $nameCounts[$samName] = 0 }
        $nameCounts[$samName]++
    }

    # Check every usable identity and OU before ANY special-account writes.
    # Match by domain-wide SAM only; do not adopt unrelated target-OU CNs.
    # Reject duplicate generated names (case-insensitively), including those
    # produced by shortening the prefix. Skip all conflicting definitions.
    $readyPlans = @()
    foreach ($plan in $plans) {
        if ($nameCounts[$plan.SamName] -gt 1) {
            Write-Status -IndentLevel 2 -Kind Error -Message ("Generated special-account name [{0}] is duplicated in the definitions; skipped." -f $plan.SamName)
            $skippedCount++
            continue
        }
        try {
            Get-ADOrganizationalUnit -Identity $plan.Path -Server $server -ErrorAction Stop | Out-Null
            $escapedName = ConvertTo-LdapFilterValue -Value $plan.SamName
            $samMatches = @(Get-ADObject -LDAPFilter ('(sAMAccountName={0})' -f $escapedName) -SearchBase $domainDN -SearchScope Subtree -Server $server -ErrorAction Stop)
            $cnMatches = @(Get-ADObject -LDAPFilter ('(name={0})' -f $escapedName) -SearchBase $plan.Path -SearchScope OneLevel -Server $server -ErrorAction Stop)
            if ($samMatches.Count -gt 1 -or $cnMatches.Count -gt 1) {
                throw 'Multiple objects matched the SAM or target CN; repair the ambiguity first.'
            }
            if ($samMatches.Count -eq 1) {
                if ($samMatches[0].ObjectClass -ine 'user') {
                    throw 'The generated SAM belongs to a non-user object.'
                }
                $plan.ExistingUser = Get-ADUser -Identity $samMatches[0].ObjectGUID -Properties $readProperties -Server $server -ErrorAction Stop
            }
            if ($cnMatches.Count -eq 1 -and ($null -eq $plan.ExistingUser -or $cnMatches[0].ObjectGUID -ne $plan.ExistingUser.ObjectGUID)) {
                throw 'The target CN belongs to another object; no merge or overwrite attempted.'
            }
            $willSetPassword = ($null -eq $plan.ExistingUser -or $plan.ResetExistingPassword)
            if ($null -ne $plan.ExistingUser) {
                Assert-LabPreservedAccountCanBeEnabled -User $plan.ExistingUser -DesiredEnabled $true -WillSetPassword $willSetPassword
            }
            if ($willSetPassword) {
                $requirements = Get-LabUserPasswordRequirements -Domain $Domain -LocalMinimumLength $passwordSettings.NonHumanMinimumLength -ExistingUser $plan.ExistingUser
                # Candidate is generated after the new object exists and its actual PSO is read.
                # Never validate or reuse the shared demo credential for this account type.
            }
            $readyPlans += $plan
        }
        catch {
            Stop-ScriptGracefully -IndentLevel 2 -Message ("Special-account preflight failed for [{0}]; no special-account writes started: {1}" -f $plan.SamName, $_.Exception.Message)
        }
    }

    foreach ($plan in $readyPlans) {
        $samName = $plan.SamName
        $existingUser = $plan.ExistingUser
        Write-Status -Kind Info -Message ("Checking special account [{0}]." -f $samName)
        try {
            $summaryUpdated = $false
            if ($null -ne $existingUser) {
                $summaryUpdated = [bool]$plan.ResetExistingPassword -or -not $existingUser.Enabled -or
                    ((Get-ParentDistinguishedName -DistinguishedName $existingUser.DistinguishedName) -ine $plan.Path)
                foreach ($property in @('Name','SamAccountName','DisplayName','GivenName')) {
                    if ([string]$existingUser.$property -cne $samName) { $summaryUpdated = $true }
                }
                if ($plan.ManageDescription -and [string]$existingUser.Description -cne $plan.Description) {
                    $summaryUpdated = $true
                }
            }
            if ($null -eq $existingUser) {
                Write-Status -IndentLevel 3 -Kind Info -Message ("Creating account [{0}] disabled in '{1}' before password initialization." -f $samName, $plan.Path)
                $newParameters = @{
                    Name = $samName
                    SamAccountName = $samName
                    DisplayName = $samName
                    GivenName = $samName
                    Path = $plan.Path
                    Enabled = $true
                    AccountPassword = $AccountPassword
                    ChangePasswordAtLogon = $false
                    Server = $server
                    PassThru = $true
                    ErrorAction = 'Stop'
                }
                if ($plan.ManageDescription -and -not [string]::IsNullOrEmpty($plan.Description)) {
                    $newParameters['Description'] = $plan.Description
                }
                $newParameters.Remove('AccountPassword')
                $createdUser = New-LabPasswordInitializedUser -Domain $Domain -NewUserParameters $newParameters -PasswordMode Managed `
                    -LocalMinimumLength $passwordSettings.NonHumanMinimumLength -PasswordSettings $passwordSettings
                $userId = $createdUser.ObjectGUID
            }
            else {
                $userId = $existingUser.ObjectGUID
                if ((Get-ParentDistinguishedName -DistinguishedName $existingUser.DistinguishedName) -ine $plan.Path) {
                    Write-Status -IndentLevel 3 -Kind Info -Message ("Restoring the configured OU for [{0}]." -f $samName)
                    Move-ADObject -Identity $userId -TargetPath $plan.Path -Server $server -ErrorAction Stop
                }
                if ($existingUser.Name -cne $samName) {
                    Write-Status -IndentLevel 3 -Kind Info -Message ("Restoring Name to [{0}]." -f $samName)
                    Rename-ADObject -Identity $userId -NewName $samName -Server $server -ErrorAction Stop
                }
                $setParameters = @{
                    Identity = $userId
                    SamAccountName = $samName
                    DisplayName = $samName
                    GivenName = $samName
                    Server = $server
                    ErrorAction = 'Stop'
                }
                if ($plan.ManageDescription) {
                    if ([string]::IsNullOrEmpty($plan.Description)) { $setParameters['Clear'] = @('description') }
                    else { $setParameters['Description'] = $plan.Description }
                }
                Set-ADUser @setParameters
                # Preserve the existing random password and change-at-logon state.
                if (-not $existingUser.Enabled) {
                    Set-ADUser -Identity $userId -Enabled $true -Server $server -ErrorAction Stop
                }
                Write-Status -IndentLevel 2 -Kind Info -Message 'Existing random special-account password and password-change requirement left unchanged.'
            }
            $verifiedUser = Get-ADUser -Identity $userId -Properties $readProperties -Server $server -ErrorAction Stop
            foreach ($property in @('Name', 'SamAccountName', 'DisplayName', 'GivenName')) {
                if ([string]$verifiedUser.$property -cne $samName) {
                    throw ("Read-back did not match configured property '{0}'." -f $property)
                }
            }
            if ((Get-ParentDistinguishedName -DistinguishedName $verifiedUser.DistinguishedName) -ine $plan.Path -or
                -not $verifiedUser.Enabled) {
                throw 'Read-back did not match the configured OU or enabled state.'
            }
            # Only require a password without forced change when set this run.
            if (($null -eq $existingUser -or $plan.ResetExistingPassword) -and [long]$verifiedUser.pwdLastSet -eq 0) {
                throw 'Read-back did not match the configured password-at-logon state.'
            }
            if ($plan.ManageDescription -and [string]$verifiedUser.Description -cne $plan.Description) {
                throw 'Read-back did not match the configured description.'
            }
            Register-LabProcessingUser -Identity $userId -Category 'special accounts'
            if ($null -eq $existingUser) { Add-LabProcessingCount -Category 'special accounts' -Created 1 -Identity ([string]$userId) }
            elseif ($summaryUpdated) { Add-LabProcessingCount -Category 'special accounts' -Updated 1 -Identity ([string]$userId) }
            if ($null -eq $existingUser) { $createdCount++ }
            else { $updatedCount++ }
            Write-Status -IndentLevel 2 -Kind Success -Message ("Verified special account [{0}] on the selected DC." -f $samName)
        }
        catch {
            Stop-ScriptGracefully -IndentLevel 2 -Message ("Could not reconcile special account [{0}]: {1}. Earlier writes may have committed; review the account before retrying. Domain/FGPP password policies still apply." -f $samName, $_.Exception.Message)
        }
    }
    $summaryKind = 'Success'
    if ($skippedCount -gt 0) { $summaryKind = 'Warning' }
    Write-Status -IndentLevel 0 -Kind $summaryKind -Message ('Special domain accounts: {0} created, {1} updated, {2} skipped.' -f $createdCount, $updatedCount, $skippedCount)
    return [pscustomobject]@{
        VerifiedCount = $createdCount + $updatedCount
        CreatedCount = $createdCount
        UpdatedCount = $updatedCount
        SkippedCount = $skippedCount
    }
}

function ConvertTo-GenericUserCount {
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$Text,
        [ValidateRange(1, 999999)][int]$MaximumCount
    )

    # ASCII digits only: reject whitespace, signs, decimals, exponents,
    # Unicode digits, pasted line breaks and integer overflow.
    $value = 0
    if ($Text -cmatch '\A[0-9]+\z' -and [int]::TryParse($Text, [ref]$value) -and
        $value -ge 1 -and $value -le $MaximumCount) {
        return $value
    }
    return $null
}

function Read-GenericUserCountWithTimeout {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 999999)][int]$DefaultCount,
        [ValidateRange(1, 999999)][int]$MaximumCount,
        [ValidateRange(1, 60)][int]$TimeoutSeconds
    )

    if ($DefaultCount -gt $MaximumCount) {
        Stop-ScriptGracefully -Message 'GenericUserCount must be between 1 and GenericUserMaximumCount.'
    }
    Write-SectionHeader -Message 'Select generic-user count...'
    Write-Status -Kind Info -Message ('Enter 1-{0} generic users. After {1} seconds without input, the default of {2} is used. Typing/pasting disables the timeout.' -f $MaximumCount, $TimeoutSeconds, $DefaultCount)
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
    }
    catch {
        Write-Status -Kind Warning -Message ('Count dialog unavailable; using default {0}.' -f $DefaultCount)
        return $DefaultCount
    }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Generic-user count'
    $form.ClientSize = [System.Drawing.Size]::new(510, 205)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true
    $form.ShowInTaskbar = $false
    $form.Tag = [pscustomobject]@{ Count = $DefaultCount; Reason = 'Closed' }

    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Number of generic users (1-$MaximumCount), ASCII digits 0-9 only.`r`nCancel/no input uses $DefaultCount. Typing disables timeout."
    $label.Location = [System.Drawing.Point]::new(12, 12)
    $label.Size = [System.Drawing.Size]::new(486, 44)
    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = [System.Drawing.Point]::new(12, 62)
    $textBox.Size = [System.Drawing.Size]::new(486, 23)
    $textBox.MaxLength = 10
    $validationLabel = New-Object System.Windows.Forms.Label
    $validationLabel.Text = 'Enter a count, or wait for the default.'
    $validationLabel.Location = [System.Drawing.Point]::new(12, 94)
    $validationLabel.Size = [System.Drawing.Size]::new(486, 43)
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = 'OK'
    $okButton.Enabled = $false
    $okButton.Location = [System.Drawing.Point]::new(338, 158)
    $okButton.Size = [System.Drawing.Size]::new(75, 27)
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = 'Cancel'
    $cancelButton.Location = [System.Drawing.Point]::new(423, 158)
    $cancelButton.Size = [System.Drawing.Size]::new(75, 27)
    $form.Controls.AddRange(@($label, $textBox, $validationLabel, $okButton, $cancelButton))
    $form.AcceptButton = $okButton
    $form.CancelButton = $cancelButton
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 100
    $clock = New-Object System.Diagnostics.Stopwatch
    # Latch the first typed/pasted character before validation. Invalid or
    # cleared input must not restart the timer or the OK-button deadline.
    $inputState = [pscustomobject]@{ Started = $false }
    # Capture the pure validator so event closures do not depend on lookup
    # of script-local functions from their dynamic module scope.
    $countParser = ${function:ConvertTo-GenericUserCount}

    $textChangedHandler = [System.EventHandler]({
        if ($textBox.TextLength -gt 0) {
            $inputState.Started = $true
            $timer.Stop()
            $clock.Stop()
        }
        $value = & $countParser -Text $textBox.Text -MaximumCount $MaximumCount
        $okButton.Enabled = $null -ne $value
        if ($null -eq $value) { $validationLabel.Text = "Enter only digits 0-9, representing a number from 1 to $MaximumCount." }
        else { $validationLabel.Text = "Valid count: $value. Select OK when ready." }
    }.GetNewClosure())
    $timerTickHandler = [System.EventHandler]({
        if (-not $inputState.Started -and $clock.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
            $form.Tag.Reason = 'TimedOut'
            $timer.Stop()
            $form.Close()
        }
    }.GetNewClosure())
    $okClickHandler = [System.EventHandler]({
        # Enforce only the no-input deadline if a click races a timer tick.
        # Once editing begins, valid input remains acceptable at any time.
        if (-not $inputState.Started -and $clock.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
            $form.Tag.Reason = 'TimedOut'
            $timer.Stop()
            $form.Close()
            return
        }
        $value = & $countParser -Text $textBox.Text -MaximumCount $MaximumCount
        if ($null -ne $value) {
            $form.Tag.Count = $value
            $form.Tag.Reason = 'Accepted'
            $timer.Stop()
            $form.Close()
        }
    }.GetNewClosure())
    $cancelClickHandler = [System.EventHandler]({
        $form.Tag.Reason = 'Cancelled'
        $timer.Stop()
        $form.Close()
    }.GetNewClosure())
    $shownHandler = [System.EventHandler]({
        if (-not $inputState.Started) {
            $clock.Start()
            $timer.Start()
        }
        [void]$textBox.Focus()
    }.GetNewClosure())
    $textBox.add_TextChanged($textChangedHandler)
    $timer.add_Tick($timerTickHandler)
    $okButton.add_Click($okClickHandler)
    $cancelButton.add_Click($cancelClickHandler)
    $form.add_Shown($shownHandler)
    try {
        [void]$form.ShowDialog()
        if ($form.Tag.Reason -eq 'Accepted') {
            Write-Status -Kind Success -Message ('Using one-time generic-user count: {0}.' -f $form.Tag.Count)
        }
        else {
            Write-Status -Kind Info -Message ('Count prompt {0}; using default {1}.' -f $form.Tag.Reason, $DefaultCount)
        }
        return [int]$form.Tag.Count
    }
    finally {
        $timer.Stop()
        $clock.Stop()
        $textBox.remove_TextChanged($textChangedHandler)
        $timer.remove_Tick($timerTickHandler)
        $okButton.remove_Click($okClickHandler)
        $cancelButton.remove_Click($cancelClickHandler)
        $form.remove_Shown($shownHandler)
        $timer.Dispose()
        $form.Dispose()
    }
}

function Get-CryptographicRandomIndex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.RandomNumberGenerator]$Random,
        [ValidateRange(1, 256)][int]$UpperBound
    )

    # Rejection sampling avoids the modulo bias of byte % alphabet length.
    $buffer = New-Object byte[] 1
    $limit = 256 - (256 % $UpperBound)
    do { $Random.GetBytes($buffer) } while ([int]$buffer[0] -ge $limit)
    return ([int]$buffer[0] % $UpperBound)
}

function New-GenericUserPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.RandomNumberGenerator]$Random,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Settings,
        [ValidateRange(0,256)][int]$MinimumLength = 0
    )

    $upper = [string]$Settings.PasswordUppercaseCharacters
    $lower = [string]$Settings.PasswordLowercaseCharacters
    $digits = [string]$Settings.PasswordDigitCharacters
    $special = [string]$Settings.PasswordSpecialCharacters
    $alphanumeric = $upper + $lower + $digits
    $length = [Math]::Max(20,$MinimumLength)
    $characters = New-Object char[] $length
    $password = $null
    try {
        # Guarantee uppercase, lowercase and a digit in the variable-length alphanumeric region.
        $characters[0] = $upper[(Get-CryptographicRandomIndex -Random $Random -UpperBound $upper.Length)]
        $characters[1] = $lower[(Get-CryptographicRandomIndex -Random $Random -UpperBound $lower.Length)]
        $characters[2] = $digits[(Get-CryptographicRandomIndex -Random $Random -UpperBound $digits.Length)]
        for ($i = 3; $i -lt ($length - 2); $i++) {
            $characters[$i] = $alphanumeric[(Get-CryptographicRandomIndex -Random $Random -UpperBound $alphanumeric.Length)]
        }
        for ($i = ($length - 2); $i -lt $length; $i++) {
            $characters[$i] = $special[(Get-CryptographicRandomIndex -Random $Random -UpperBound $special.Length)]
        }
        # Fisher-Yates shuffle: the two special positions are not predictable.
        for ($i = $characters.Length - 1; $i -gt 0; $i--) {
            $j = Get-CryptographicRandomIndex -Random $Random -UpperBound ($i + 1)
            $swap = $characters[$i]
            $characters[$i] = $characters[$j]
            $characters[$j] = $swap
        }
        $password = New-Object System.Security.SecureString
        foreach ($character in $characters) { $password.AppendChar($character) }
        $password.MakeReadOnly()
        return $password
    }
    catch {
        if ($null -ne $password) { $password.Dispose() }
        throw
    }
    finally {
        [Array]::Clear($characters, 0, $characters.Length)
    }
}

function Ensure-GenericUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][ValidateRange(1, 999999)][int]$Count,
        [Parameter(Mandatory = $true)][ValidateRange(1, 999999)][int]$MaximumCount,
        [Parameter(Mandatory = $true)][bool]$DoNotUpdateExistingUsers
    )

    Write-SectionHeader -Message 'Create/Update Generic Users...'
    if ($Count -gt $MaximumCount) {
        Stop-ScriptGracefully -IndentLevel 2 -Message 'Generic-user count exceeds GenericUserMaximumCount; no generic accounts were processed.'
    }
    $settings = Get-LabGenericUserSettings
    $server = [string]$Domain.SelectedDomainController
    $domainDN = [string]$Domain.DistinguishedName
    $dnsRoot = [string]$Domain.DNSRoot
    if ([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($domainDN) -or [string]::IsNullOrWhiteSpace($dnsRoot)) {
        Stop-ScriptGracefully -IndentLevel 2 -Message 'Generic users require the selected DC, domain DN and DNS root.'
    }
    $targetPath = '{0},{1}' -f $settings.RelativePath, $domainDN
    Write-Status -IndentLevel 1 -Kind Info -Message ("Checking generic-user target OU '{0}' on [{1}]..." -f $targetPath, $server)
    try {
        # This function never creates the OU or falls back to another container.
        $targetOU = Get-ADOrganizationalUnit -Identity $targetPath -Server $server -ErrorAction Stop
        if ($null -eq $targetOU) { throw 'The OU lookup returned no object.' }
    }
    catch {
        Write-Status -IndentLevel 2 -Kind Error -Message ("OU '{0}' is missing or unavailable. No generic accounts can be created or updated; skipping this section: {1}" -f $targetPath, $_.Exception.Message)
        return [pscustomobject]@{ RequestedCount = $Count; VerifiedCount = 0; CreatedCount = 0; UpdatedCount = 0; UnchangedCount = 0; SkippedCount = $Count; OUUnavailable = $true }
    }

    $readProperties = @('sAMAccountName', 'givenName', 'sn', 'displayName', 'userPrincipalName', 'description', 'pwdLastSet', 'userAccountControl')
    $attributeMap = [ordered]@{
        SamAccountName = 'sAMAccountName'
        GivenName = 'givenName'
        Surname = 'sn'
        DisplayName = 'displayName'
        UserPrincipalName = 'userPrincipalName'
        Description = 'description'
    }

    $createdCount = 0
    $updatedCount = 0
    $unchangedCount = 0
    $skippedCount = 0
    $seenGuids = @{}
    if ($DoNotUpdateExistingUsers) {
        Write-Status -IndentLevel 1 -Kind Info -Message 'Create-only mode: existing generic users will be left untouched.'
    }
    else {
        Write-Status -IndentLevel 1 -Kind Info -Message 'Update mode: create missing generic users and reconcile changed attributes on existing users.'
    }
    Write-Status -IndentLevel 1 -Kind Info -Message ('Processing generic users 000001 through {0:D6} one at a time (maximum {1}); no batch lookups.' -f $Count, $MaximumCount)
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        for ($index = 1; $index -le $Count -and $index -le $MaximumCount; $index++) {
            # All constructions use the same six-digit, invariant index.
            $number = $index.ToString('D6', [System.Globalization.CultureInfo]::InvariantCulture)
            $definition = [ordered]@{
                SamAccountName = $settings.SamAccountNamePrefix + $number
                Name = $settings.NamePrefix + $number
                DisplayName = $settings.DisplayNamePrefix + $number
                GivenName = $settings.GivenName
                Surname = $settings.SurnamePrefix + $number
                UserPrincipalName = $settings.UserPrincipalNamePrefix + $number + '@' + $dnsRoot
                Description = $settings.DescriptionPrefix + $number
            }
            Write-Status -IndentLevel 1 -Kind Info -Message ("Checking generic user [{0}]." -f $definition.SamAccountName)
            $password = $null
            $changed = $false
            $existingUser = $null
            try {
                $samName = [string]$definition.SamAccountName
                if ($samName.Length -gt 20 -or $samName -match '["/\\\[\]:;|=,+*?<>\x00-\x1f]') {
                    throw ("Generic SAM [{0}] is invalid or exceeds 20 characters; check Get-LabGenericUserSettings." -f $samName)
                }
                # Exact lookups for this account only. Domain-wide SAM/UPN
                # equality checks preserve collision safety and OU restoration;
                # there is no prefix search or preloading of other accounts.
                $escapedSam = ConvertTo-LdapFilterValue -Value $samName
                $escapedUpn = ConvertTo-LdapFilterValue -Value $definition.UserPrincipalName
                $identityFilter = '(|(sAMAccountName={0})(userPrincipalName={1}))' -f $escapedSam, $escapedUpn
                $identityMatches = @(Get-ADObject -LDAPFilter $identityFilter -SearchBase $domainDN -SearchScope Subtree -Properties $readProperties -Server $server -ErrorAction Stop)
                $samMatches = @($identityMatches | Where-Object { $_.sAMAccountName -ieq $samName })
                if ($samMatches.Count -gt 1 -or ($samMatches.Count -eq 1 -and $samMatches[0].ObjectClass -ine 'user')) {
                    throw ("Generic SAM [{0}] is ambiguous or belongs to a non-user object." -f $samName)
                }
                if ($samMatches.Count -eq 1) { $existingUser = $samMatches[0] }
                if ($DoNotUpdateExistingUsers -and $null -ne $existingUser) {
                    # Existence is sufficient in create-only mode. Do not move,
                    # rename, modify or baseline-verify an existing account.
                    Register-LabProcessingUser -Identity $existingUser.ObjectGUID -Category 'generic users'
                    $skippedCount++
                    Write-Status -IndentLevel 2 -Kind Info -Message ("Existing generic user [{0}] left unchanged (DoNotUpdateGenericUsers = true)." -f $samName)
                    continue
                }
                foreach ($identityMatch in $identityMatches) {
                    if ($null -eq $existingUser -or $identityMatch.ObjectGUID -ne $existingUser.ObjectGUID) {
                        throw ("Generic account [{0}] conflicts with another object's UPN; no merge attempted." -f $samName)
                    }
                }
                # Check the target CN only when creating, moving or renaming.
                $needsCnCheck = ($null -eq $existingUser)
                if ($null -ne $existingUser) {
                    $needsCnCheck = ($existingUser.Name -cne $definition.Name -or
                        (Get-ParentDistinguishedName -DistinguishedName $existingUser.DistinguishedName) -ine $targetPath)
                }
                if ($needsCnCheck) {
                    $escapedName = ConvertTo-LdapFilterValue -Value $definition.Name
                    $cnFilter = '(name={0})' -f $escapedName
                    $cnMatches = @(Get-ADObject -LDAPFilter $cnFilter -SearchBase $targetPath -SearchScope OneLevel -Server $server -ErrorAction Stop)
                    foreach ($cnMatch in $cnMatches) {
                        if ($null -eq $existingUser -or $cnMatch.ObjectGUID -ne $existingUser.ObjectGUID) {
                            throw ("Generic account [{0}] conflicts with another object's CN; no merge attempted." -f $samName)
                        }
                    }
                }
                if ($null -eq $existingUser) {
                    Write-Status -IndentLevel 3 -Kind Info -Message ("Creating generic user [{0}] in '{1}'." -f $definition.SamAccountName, $targetPath)
                    $newParameters = @{
                        Name = $definition.Name
                        SamAccountName = $definition.SamAccountName
                        DisplayName = $definition.DisplayName
                        GivenName = $definition.GivenName
                        Surname = $definition.Surname
                        UserPrincipalName = $definition.UserPrincipalName
                        Description = $definition.Description
                        Path = $targetPath
                        Enabled = $true
                        AccountPassword = $password
                        ChangePasswordAtLogon = $false
                        Server = $server
                        PassThru = $true
                        ErrorAction = 'Stop'
                    }
                    $createdUser = New-LabPasswordInitializedUser -Domain $Domain -NewUserParameters $newParameters -PasswordMode Generic `
                        -PasswordSettings $settings -Random $random
                    $userId = $createdUser.ObjectGUID
                }
                else {
                    $userId = $existingUser.ObjectGUID
                    if ((Get-ParentDistinguishedName -DistinguishedName $existingUser.DistinguishedName) -ine $targetPath) {
                        Write-Status -IndentLevel 3 -Kind Info -Message ("Restoring generic-user OU for [{0}]." -f $definition.SamAccountName)
                        Move-ADObject -Identity $userId -TargetPath $targetPath -Server $server -ErrorAction Stop
                        $changed = $true
                    }
                    if ($existingUser.Name -cne $definition.Name) {
                        Write-Status -IndentLevel 3 -Kind Info -Message ("Restoring generic-user Name for [{0}]." -f $definition.SamAccountName)
                        Rename-ADObject -Identity $userId -NewName $definition.Name -Server $server -ErrorAction Stop
                        $changed = $true
                    }
                    $replace = @{}
                    foreach ($property in $attributeMap.Keys) {
                        $ldapName = $attributeMap[$property]
                        if ([string]$existingUser.$ldapName -cne [string]$definition[$property]) {
                            $replace[$ldapName] = [string]$definition[$property]
                        }
                    }
                    if ($replace.Count -gt 0) {
                        Set-ADUser -Identity $userId -Replace $replace -Server $server -ErrorAction Stop
                        $changed = $true
                    }
                    # Existing passwords and enabled states are deliberately
                    # preserved. Never delete accounts above the selected count.
                }
                $guidKey = ([guid]$userId).ToString('D')
                if ($guidKey -eq [guid]::Empty.ToString('D') -or $seenGuids.ContainsKey($guidKey)) {
                    throw 'Generic-user write returned a missing or duplicate object GUID.'
                }
                $seenGuids[$guidKey] = $true
                # Verify this account immediately, before advancing the loop.
                $verifiedUser = Get-ADObject -Identity $userId -Properties $readProperties -Server $server -ErrorAction Stop
                if ($null -eq $verifiedUser -or [guid]$verifiedUser.ObjectGUID -ne [guid]$userId) {
                    throw 'Read-back did not return the expected object GUID.'
                }
                if ($verifiedUser.ObjectClass -ine 'user') {
                    throw 'Read-back did not return a user object.'
                }
                if ($verifiedUser.Name -cne $definition.Name -or (Get-ParentDistinguishedName -DistinguishedName $verifiedUser.DistinguishedName) -ine $targetPath) {
                    throw 'Read-back did not match the configured Name or OU.'
                }
                foreach ($property in $attributeMap.Keys) {
                    $ldapName = $attributeMap[$property]
                    if ([string]$verifiedUser.$ldapName -cne [string]$definition[$property]) {
                        throw ("Read-back did not match property '{0}'." -f $property)
                    }
                }
                if (($null -eq $existingUser)) {
                    if (([int]$verifiedUser.userAccountControl -band 2) -ne 0 -or [long]$verifiedUser.pwdLastSet -eq 0) {
                        throw 'New-account read-back did not confirm enabled state and a password without required change at logon.'
                    }
                }
                Register-LabProcessingUser -Identity $userId -Category 'generic users'
                if (($null -eq $existingUser)) { $createdCount++ }
                elseif ($changed) { $updatedCount++ }
                else { $unchangedCount++ }
                Write-Status -IndentLevel 4 -Kind Success -Message ("Verified generic user [{0}]." -f $definition.SamAccountName)
            }
            catch {
                Stop-ScriptGracefully -IndentLevel 2 -Message ("Could not reconcile or verify generic user [{0}]: {1}. Earlier writes may have committed; review the account before retrying. Domain/FGPP password policies still apply." -f $definition.SamAccountName, $_.Exception.Message)
            }
            finally {
                if ($null -ne $password) { $password.Dispose() }
            }
        }
    }
    finally { $random.Dispose() }
    Add-LabProcessingCount -Category 'generic users' -Created $createdCount -Updated $updatedCount
    Write-Status -IndentLevel 0 -Kind Success -Message ('Generic users: {0} created, {1} updated, {2} already matched, {3} existing accounts left untouched. Accounts above {4} were not removed.' -f $createdCount, $updatedCount, $unchangedCount, $skippedCount, $Count)
    return [pscustomobject]@{
        RequestedCount = $Count
        VerifiedCount = $createdCount + $updatedCount + $unchangedCount
        CreatedCount = $createdCount
        UpdatedCount = $updatedCount
        UnchangedCount = $unchangedCount
        SkippedCount = $skippedCount
        OUUnavailable = $false
    }
}

function Resolve-LabMembershipObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Reference,
        [Parameter(Mandatory = $true)]
        [string]$DomainDN,
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$GroupDefinitions,
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$GroupObjects,
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$ExistingGroupDefinitions,
        [switch]$GroupOnly
    )

    # Stable definition keys and explicitly registered existing-only identities
    # are authoritative aliases. Otherwise search all three supported naming
    # attributes together; never pick an arbitrary first match.
    if ($GroupDefinitions.Contains($Reference)) {
        if (-not $GroupObjects.Contains($Reference) -or $null -eq $GroupObjects[$Reference]) {
            throw [System.Management.Automation.ItemNotFoundException]::new('Configured group has no provisioned group object.')
        }
        return Get-ADGroup -Identity $GroupObjects[$Reference].ObjectGUID -Properties DisplayName -Server $Server -ErrorAction Stop
    }
    $existingKeys = @()
    foreach ($key in $ExistingGroupDefinitions.Keys) {
        $definition = $ExistingGroupDefinitions[$key]
        if ($key -ieq $Reference -or $definition.Name -ieq $Reference -or $definition.Identity -ieq $Reference) {
            $existingKeys += $key
        }
    }
    if ($existingKeys.Count -gt 1) {
        throw 'Ambiguous existing-only group reference; use one unique definition key.'
    }
    if ($existingKeys.Count -eq 1) {
        return Get-ADGroup -Identity $ExistingGroupDefinitions[$existingKeys[0]].Identity -Properties DisplayName -Server $Server -ErrorAction Stop
    }

    # An explicit DN is scoped to this domain and resolved afresh every run.
    # Deleted/recreated accounts have new GUIDs/SIDs; no identity is persisted.
    # Do not fall back to a same-named object elsewhere when this DN is absent.
    if ($Reference -match '^(CN|OU)=') {
        if (-not $Reference.EndsWith((',' + $DomainDN), [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Explicit membership DN is outside the selected domain.'
        }
        $object = Get-ADObject -Identity $Reference -Properties displayName, sAMAccountName -Server $Server -ErrorAction Stop
        if ($GroupOnly -and $object.ObjectClass -ine 'group') {
            throw 'Explicit membership DN must identify a group for this reference.'
        }
        if (@('user', 'group', 'computer') -inotcontains [string]$object.ObjectClass) {
            throw 'Explicit membership DN must identify a user, group or computer.'
        }
        return $object
    }

    $escapedReference = ConvertTo-LdapFilterValue -Value $Reference
    $classFilter = '(|(objectClass=user)(objectClass=group)(objectClass=computer))'
    if ($GroupOnly) { $classFilter = '(objectClass=group)' }
    $filter = '(&{0}(|(displayName={1})(name={1})(sAMAccountName={1})))' -f $classFilter, $escapedReference
    $matches = @(Get-ADObject -LDAPFilter $filter -SearchBase $DomainDN -SearchScope Subtree -Properties displayName, sAMAccountName -Server $Server -ErrorAction Stop)
    if ($matches.Count -eq 0) {
        throw [System.Management.Automation.ItemNotFoundException]::new('No matching object exists in the selected domain.')
    }
    if ($matches.Count -ne 1) {
        throw ("Ambiguous reference: {0} objects matched DisplayName, Name or SamAccountName; use a unique value." -f $matches.Count)
    }
    return $matches[0]
}

function Write-LabMembershipLookupError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Reference,
        [Parameter(Mandatory = $true)]
        [string]$ObjectKind,
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$LookupError
    )

    $isMissing = $LookupError.Exception -is [System.Management.Automation.ItemNotFoundException] -or
        $LookupError.FullyQualifiedErrorId -match 'ADIdentityNotFoundException' -or
        $LookupError.Exception.GetType().Name -eq 'ADIdentityNotFoundException'
    # Shared Write-Status inserts one separator; the leading space below
    # supplies the requested second space: four spaces + '[ERROR]  [name]'.
    if ($isMissing) {
        Write-Status -IndentLevel 2 -Kind Error -Message (" [{0}] not found. The {1} does not exist in the selected domain. Add it to the script's appropriate object-creation definitions so it can be created, or create it separately, then rerun. Existing-only groups and computers must already exist. Generic users require OU=TEST and an index within the selected count." -f $Reference, $ObjectKind)
    }
    else {
        Write-Status -IndentLevel 2 -Kind Error -Message (" [{0}] could not be resolved as a {1}: {2}. Correct the reference or directory connectivity before rerunning; no arbitrary match was selected." -f $Reference, $ObjectKind, $LookupError.Exception.Message)
    }
}

function Ensure-LabGroupMemberships {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Domain,
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$GroupDefinitions,
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$GroupObjects,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.IDictionary]$MembershipDefinitions,
        [Parameter(Mandatory = $true)]
        [bool]$ExactMembership
    )

    Write-SectionHeader -Message 'Create/Update Group Memberships...'
    $server = [string]$Domain.SelectedDomainController
    $domainDN = [string]$Domain.DistinguishedName
    if ([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($domainDN)) {
        Stop-ScriptGracefully -IndentLevel 2 -Message 'Membership reconciliation requires the selected writable DC and domain DN.'
    }
    $mode = 'ADDITIVE (no removals)'
    if ($ExactMembership) { $mode = 'EXACT (required nesting protected)' }
    Write-Status -Kind Info -Message ('Group membership mode: {0}.' -f $mode)
    $existingDefinitions = Get-LabExistingGroupDefinitions -DomainSID ([string]$Domain.DomainSID.Value) -DomainDN ([string]$Domain.DistinguishedName)
    $resolverParameters = @{
        DomainDN = $domainDN
        Server = $server
        GroupDefinitions = $GroupDefinitions
        GroupObjects = $GroupObjects
        ExistingGroupDefinitions = $existingDefinitions
    }
    $addedCount = 0
    $removedCount = 0
    $existingCount = 0
    $errorCount = 0
    $skippedGroupCount = 0
    $removalSuppressedCount = 0
    $plans = [ordered]@{}
    $claimedGroups = @{}
    $protectedByParent = @{}
    $nestingProtectionComplete = $true

    # Validate every list and resolve every target/member before membership
    # writes. A missing object is logged and can never become an empty plan.
    foreach ($groupReference in $MembershipDefinitions.Keys) {
        if ($groupReference -isnot [string] -or [string]::IsNullOrWhiteSpace($groupReference)) {
            Stop-ScriptGracefully -IndentLevel 2 -Message 'Membership definitions require nonblank group-name keys; no membership writes started.'
        }
        $rawMembers = $MembershipDefinitions[$groupReference]
        if ($null -eq $rawMembers -or ($rawMembers -isnot [string] -and $rawMembers -isnot [array])) {
            Stop-ScriptGracefully -IndentLevel 2 -Message ("Membership [{0}] must contain a name or an array of names. Use @() for an explicitly empty list; no membership writes started." -f $groupReference)
        }
        foreach ($memberReference in @($rawMembers)) {
            if ($memberReference -isnot [string] -or [string]::IsNullOrWhiteSpace($memberReference)) {
                Stop-ScriptGracefully -IndentLevel 2 -Message ("Membership [{0}] contains a blank or invalid member reference; no membership writes started." -f $groupReference)
            }
        }
    }
    foreach ($groupReference in $MembershipDefinitions.Keys) {
        Write-Status -Kind Info -Message ("Resolving membership definition for group '{0}'." -f $groupReference)
        try {
            $groupObject = Resolve-LabMembershipObject -Reference $groupReference -GroupOnly @resolverParameters
        }
        catch {
            Write-LabMembershipLookupError -Reference $groupReference -ObjectKind 'group' -LookupError $_
            $errorCount++
            $skippedGroupCount++
            continue
        }
        $groupGuid = [string]$groupObject.ObjectGUID
        if ($claimedGroups.ContainsKey($groupGuid)) {
            Stop-ScriptGracefully -IndentLevel 2 -Message ("Membership definitions [{0}] and [{1}] target the same group. Use one authoritative list; no membership writes started." -f $claimedGroups[$groupGuid], $groupReference)
        }
        $claimedGroups[$groupGuid] = $groupReference
        $desiredMembers = [ordered]@{}
        $resolutionComplete = $true
        foreach ($memberReference in @($MembershipDefinitions[$groupReference])) {
            try {
                $memberObject = Resolve-LabMembershipObject -Reference $memberReference @resolverParameters
                $desiredMembers[[string]$memberObject.ObjectGUID] = $memberObject
            }
            catch {
                Write-LabMembershipLookupError -Reference $memberReference -ObjectKind 'user, group or computer' -LookupError $_
                $errorCount++
                $resolutionComplete = $false
            }
        }
        $plans[$groupReference] = [pscustomobject]@{
            Group = $groupObject
            DesiredMembers = $desiredMembers
            ResolutionComplete = $resolutionComplete
        }
    }

    # Invert child -> parents into parent -> protected children by GUID.
    # This also protects explicit self-membership. No recursive traversal.
    $nestingDefinitions = Get-LabGroupNestingDefinitions
    foreach ($childReference in $nestingDefinitions.Keys) {
        try {
            $childGroup = Resolve-LabMembershipObject -Reference $childReference -GroupOnly @resolverParameters
        }
        catch {
            Write-LabMembershipLookupError -Reference $childReference -ObjectKind 'required nesting child group' -LookupError $_
            $errorCount++
            $nestingProtectionComplete = $false
            continue
        }
        foreach ($parentReference in @($nestingDefinitions[$childReference])) {
            try {
                $parentGroup = Resolve-LabMembershipObject -Reference $parentReference -GroupOnly @resolverParameters
                $parentGuid = [string]$parentGroup.ObjectGUID
                if (-not $protectedByParent.ContainsKey($parentGuid)) {
                    $protectedByParent[$parentGuid] = [ordered]@{}
                }
                $protectedByParent[$parentGuid][[string]$childGroup.ObjectGUID] = $childGroup
            }
            catch {
                Write-LabMembershipLookupError -Reference $parentReference -ObjectKind 'required nesting parent group' -LookupError $_
                $errorCount++
                $nestingProtectionComplete = $false
            }
        }
    }

    foreach ($groupReference in $plans.Keys) {
        $plan = $plans[$groupReference]
        $groupGuid = [string]$plan.Group.ObjectGUID
        $desiredMembers = $plan.DesiredMembers
        if ($protectedByParent.ContainsKey($groupGuid)) {
            foreach ($childGuid in $protectedByParent[$groupGuid].Keys) {
                $desiredMembers[$childGuid] = $protectedByParent[$groupGuid][$childGuid]
            }
        }
        Write-Status -IndentLevel 1 -Kind Info -Message ("Checking direct members of group '{0}'." -f $groupReference)
        try {
            $currentGroup = Get-ADGroup -Identity $groupGuid -Properties member -Server $server -ErrorAction Stop
        }
        catch {
            Write-Status -IndentLevel 2 -Kind Error -Message (" [{0}] could not read direct membership: {1}. No changes attempted for this group." -f $groupReference, $_.Exception.Message)
            $errorCount++
            $skippedGroupCount++
            continue
        }
        $additionsSucceeded = $true
        foreach ($memberGuid in $desiredMembers.Keys) {
            $memberObject = $desiredMembers[$memberGuid]
            if (@($currentGroup.member) -icontains $memberObject.DistinguishedName) {
                Write-Status -IndentLevel 2 -Kind Info -Message ("'{0}' is already a direct member of '{1}'." -f $memberObject.Name, $groupReference)
                $existingCount++
                continue
            }
            Write-Status -IndentLevel 3 -Kind Info -Message ("Adding '{0}' to group '{1}'." -f $memberObject.Name, $groupReference)
            try {
                Add-ADGroupMember -Identity $groupGuid -Members $memberObject.DistinguishedName -Server $server -ErrorAction Stop
                $currentGroup = Get-ADGroup -Identity $groupGuid -Properties member -Server $server -ErrorAction Stop
                if (@($currentGroup.member) -inotcontains $memberObject.DistinguishedName) {
                    throw 'Requested direct membership was not present on read-back.'
                }
                $addedCount++
                Write-Status -IndentLevel 4 -Kind Success -Message ("Added '{0}' to '{1}' and verified direct membership." -f $memberObject.Name, $groupReference)
            }
            catch {
                Write-Status -IndentLevel 2 -Kind Error -Message (" [{0}] could not add/verify membership in [{1}]: {2}. Earlier writes may have committed; removals for this group are suppressed." -f $memberObject.Name, $groupReference, $_.Exception.Message)
                $errorCount++
                $additionsSucceeded = $false
            }
        }

        if (-not $ExactMembership) { continue }
        if (-not $plan.ResolutionComplete -or -not $nestingProtectionComplete -or -not $additionsSucceeded) {
            Write-Status -IndentLevel 2 -Kind Warning -Message ("Removals suppressed for [{0}]: member/nesting resolution or addition verification was incomplete." -f $groupReference)
            $removalSuppressedCount++
            continue
        }
        # Refresh before computing removals. All desired/protected members must
        # still be present; otherwise leave existing members alone this run.
        try {
            $currentGroup = Get-ADGroup -Identity $groupGuid -Properties member -Server $server -ErrorAction Stop
            $desiredDNs = @{}
            foreach ($memberObject in $desiredMembers.Values) {
                $desiredDNs[$memberObject.DistinguishedName] = $true
                if (@($currentGroup.member) -inotcontains $memberObject.DistinguishedName) {
                    throw ("Desired/protected member '{0}' was absent before removal planning." -f $memberObject.Name)
                }
            }
        }
        catch {
            Write-Status -IndentLevel 2 -Kind Error -Message (" [{0}] exact-membership pre-removal verification failed: {1}. No removals attempted." -f $groupReference, $_.Exception.Message)
            $errorCount++
            $removalSuppressedCount++
            continue
        }
        # Direct DN values only: avoids recursive cycle expansion, includes all
        # direct principal types, and does not require enumerating primary groups.
        foreach ($memberDN in @($currentGroup.member)) {
            if ($desiredDNs.ContainsKey($memberDN)) { continue }
            Write-Status -IndentLevel 3 -Kind Info -Message ("Removing unlisted direct member '{0}' from '{1}'." -f $memberDN, $groupReference)
            try {
                Remove-ADGroupMember -Identity $groupGuid -Members $memberDN -Server $server -Confirm:$false -ErrorAction Stop
                $verifiedGroup = Get-ADGroup -Identity $groupGuid -Properties member -Server $server -ErrorAction Stop
                if (@($verifiedGroup.member) -icontains $memberDN) {
                    throw 'Unlisted direct member was still present on read-back.'
                }
                $removedCount++
                Write-Status -IndentLevel 4 -Kind Success -Message ("Removed unlisted member '{0}' from '{1}' and verified." -f $memberDN, $groupReference)
            }
            catch {
                Write-Status -IndentLevel 2 -Kind Error -Message (" [{0}] could not remove/verify [{1}]: {2}. Stopping further removals for this group; earlier writes may have committed." -f $groupReference, $memberDN, $_.Exception.Message)
                $errorCount++
                $removalSuppressedCount++
                break
            }
        }
    }
    $summary = 'Group memberships: {0} added, {1} removed, {2} already present, {3} errors, {4} groups skipped, {5} exact-mode cleanups suppressed.' -f $addedCount, $removedCount, $existingCount, $errorCount, $skippedGroupCount, $removalSuppressedCount
    if ($errorCount -gt 0 -or $removalSuppressedCount -gt 0) {
        Write-Status -IndentLevel 0 -Kind Warning -Message $summary
    }
    else {
        Write-Status -IndentLevel 0 -Kind Success -Message $summary
    }
    Add-LabProcessingCount -Category 'group memberships' -Added $addedCount -Removed $removedCount
    return [pscustomobject]@{
        AddedCount = $addedCount
        RemovedCount = $removedCount
        ExistingCount = $existingCount
        ErrorCount = $errorCount
        SkippedGroupCount = $skippedGroupCount
        RemovalSuppressedCount = $removalSuppressedCount
    }
}

function ConvertTo-LabSubnetPrefix {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)

    if ($Name -cnotmatch '^([^/\s%]+)/([0-9]{1,3})$') {
        throw "Subnet Name must be an IPv4 or IPv6 network prefix, for example 10.0.0.0/8."
    }
    $addressText = $Matches[1]
    $prefixLength = [int]$Matches[2]
    $address = $null
    if (-not [System.Net.IPAddress]::TryParse($addressText, [ref]$address)) {
        throw ("Invalid IP address in subnet [{0}]." -f $Name)
    }
    $bytes = $address.GetAddressBytes()
    if ($bytes.Length -eq 4 -and $addressText -cnotmatch '^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$') {
        throw ("IPv4 subnet [{0}] requires four decimal octets without leading zeros." -f $Name)
    }
    if ($prefixLength -gt ($bytes.Length * 8)) {
        throw ("Invalid prefix length in subnet [{0}]." -f $Name)
    }
    $remaining = $prefixLength
    foreach ($value in $bytes) {
        $networkBits = [Math]::Min(8, $remaining)
        $hostMask = [int]([Math]::Pow(2, 8 - $networkBits) - 1)
        if (([int]$value -band $hostMask) -ne 0) {
            throw ("Subnet [{0}] has nonzero host bits; use the network address." -f $Name)
        }
        $remaining = [Math]::Max(0, $remaining - 8)
    }
    return ('{0}/{1}' -f $address.ToString(), $prefixLength)
}

function Test-LabDnsName {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)

    if ($Name.Length -gt 253 -or $Name.EndsWith('.')) { return $false }
    foreach ($label in ($Name -split '\.')) {
        if ($label -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$') { return $false }
    }
    return $true
}

function Test-LabDnsStaticRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Record)

    $property = $Record.PSObject.Properties['Timestamp']
    if ($null -eq $property) { throw 'DNS record timestamp was not returned; static state is unknown.' }
    $value = $property.Value
    # Providers render the unset timestamp as null, blank or zero.
    if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value) -or [string]$value -eq '0') { return $true }
    if ($value -is [datetime]) {
        return ($value -eq [datetime]::MinValue -or $value.ToUniversalTime() -eq [datetime]::FromFileTimeUtc(0))
    }
    return $false
}

function Get-LabDnsNodeRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][string]$ZoneName,
        [Parameter(Mandatory = $true)][string]$Name
    )

    # Full zone enumeration is intentional for these small labs: a nonexistent
    # node produces an empty result, but access/connection errors still throw.
    # Never suppress arbitrary DNS read failures and mistake them for absence.
    Get-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName -ErrorAction Stop |
        Where-Object { $_.HostName -ieq $Name }
}

function Test-LabDnsForestReplication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Zone,
        [Parameter(Mandatory = $true)][string]$ForestName
    )

    $partition = $Zone.PSObject.Properties['DirectoryPartitionName']
    if ($null -ne $partition -and -not [string]::IsNullOrWhiteSpace([string]$partition.Value)) {
        return ([string]$partition.Value -ieq ('ForestDnsZones.{0}' -f $ForestName))
    }
    $scope = $Zone.PSObject.Properties['ReplicationScope']
    if ($null -ne $scope) { return ([string]$scope.Value -ieq 'Forest') }
    throw 'DNS zone replication scope could not be read back.'
}

function Ensure-LabDnsZone {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][string]$ForestName,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Definition
    )

    $name = [string]$Definition.Name
    $reverse = -not [string]::IsNullOrWhiteSpace([string]$Definition.NetworkId)
    $existing = @(Get-DnsServerZone -ComputerName $ComputerName -ErrorAction Stop | Where-Object { $_.ZoneName -ieq $name })
    if ($existing.Count -gt 1) { throw ('Ambiguous DNS zone: {0}.' -f $name) }
    $action = 'Already matched'
    if ($existing.Count -eq 0) {
        Write-Status -IndentLevel 3 -Kind Info -Message ('Creating AD-integrated primary DNS zone [{0}] with forest-wide replication.' -f $name)
        $parameters = @{ ComputerName=$ComputerName; ReplicationScope=$Definition.ReplicationScope; DynamicUpdate=$Definition.DynamicUpdate; ErrorAction='Stop' }
        if ($reverse) { $parameters.NetworkId = [string]$Definition.NetworkId }
        else { $parameters.Name = $name }
        Assert-LabInventoryHealthy
        Add-DnsServerPrimaryZone @parameters | Out-Null
        Add-LabGeneratedDnsObject -Kind DnsZone -ZoneName $name
        $action = 'Created'
    }
    else {
        $zone = $existing[0]
        # Do not replace secondary/stub zones or delete/recreate any zone.
        if ([string]$zone.ZoneType -ine 'Primary') { throw 'Existing zone is not Primary; no destructive zone replacement was attempted.' }
        if ([bool]$zone.IsReverseLookupZone -ne $reverse) { throw 'Existing zone direction does not match its definition.' }
        if (-not $zone.IsDsIntegrated) {
            ConvertTo-DnsServerPrimaryZone -ComputerName $ComputerName -Name $name -ReplicationScope $Definition.ReplicationScope -Force -ErrorAction Stop | Out-Null
            $action = 'Updated'
        }
        $zone = Get-DnsServerZone -ComputerName $ComputerName -Name $name -ErrorAction Stop
        # ReplicationScope and DynamicUpdate belong to different parameter sets.
        if (-not (Test-LabDnsForestReplication -Zone $zone -ForestName $ForestName)) {
            Set-DnsServerPrimaryZone -ComputerName $ComputerName -Name $name -ReplicationScope $Definition.ReplicationScope -ErrorAction Stop | Out-Null
            $action = 'Updated'
        }
        if ([string]$zone.DynamicUpdate -ine [string]$Definition.DynamicUpdate) {
            Set-DnsServerPrimaryZone -ComputerName $ComputerName -Name $name -DynamicUpdate $Definition.DynamicUpdate -ErrorAction Stop | Out-Null
            $action = 'Updated'
        }
    }
    $zone = Get-DnsServerZone -ComputerName $ComputerName -Name $name -ErrorAction Stop
    if ($Definition.EnsureUnsigned -and $zone.IsSigned) {
        Write-Status -IndentLevel 2 -Kind Warning -BackgroundColor Red -Message ('Applying the requested unsigned baseline to DNSSEC-signed zone [{0}]. Parent DS records and trust anchors are not modified; review any existing DNSSEC delegation.' -f $name)
        Invoke-DnsServerZoneUnsign -ComputerName $ComputerName -ZoneName $name -Force -ErrorAction Stop | Out-Null
        if ($action -ne 'Created') { $action = 'Updated' }
    }
    $final = Get-DnsServerZone -ComputerName $ComputerName -Name $name -ErrorAction Stop
    if ([string]$final.ZoneName -ine $name -or [string]$final.ZoneType -ine 'Primary' -or -not $final.IsDsIntegrated -or
        [bool]$final.IsReverseLookupZone -ne $reverse -or [string]$final.DynamicUpdate -ine [string]$Definition.DynamicUpdate -or
        -not (Test-LabDnsForestReplication -Zone $final -ForestName $ForestName) -or ($Definition.EnsureUnsigned -and $final.IsSigned)) {
        throw 'DNS zone read-back did not match the requested baseline.'
    }
    Write-Status -IndentLevel 2 -Kind Success -Message ("{0} DNS zone [{1}]:`n          AD-integrated Primary, forest-wide replication, nonsecure and secure updates; DNSSEC signed={2}." -f $action, $name, $final.IsSigned)
    if ($action -eq 'Created') { Add-LabProcessingCount -Category 'DNS zones' -Created 1 -Identity $name }
    if ($action -eq 'Updated') { Add-LabProcessingCount -Category 'DNS zones' -Updated 1 -Identity $name }
    return $action
}

function Ensure-LabDnsARecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Definition
    )

    $zoneName = [string]$Definition.ZoneName
    $name = [string]$Definition.Name
    $address = [ipaddress]$Definition.IPv4Address
    $zones = @(Get-DnsServerZone -ComputerName $ComputerName -ErrorAction Stop | Where-Object { $_.ZoneName -ieq $zoneName })
    if ($zones.Count -ne 1 -or [string]$zones[0].ZoneType -ine 'Primary' -or $zones[0].IsReverseLookupZone) {
        throw ('Forward zone [{0}] must already exist as a writable primary on the selected DNS server; its settings were not changed.' -f $zoneName)
    }
    $nodeRecords = @(Get-LabDnsNodeRecords -ComputerName $ComputerName -ZoneName $zoneName -Name $name)
    if (@($nodeRecords | Where-Object { [string]$_.RecordType -ieq 'CNAME' }).Count -gt 0) { throw 'A CNAME already uses the requested name; it was not replaced.' }
    $records = @($nodeRecords | Where-Object { [string]$_.RecordType -ieq 'A' })
    $matches = @($records | Where-Object { [string]$_.RecordData.IPv4Address -eq [string]$address })
    $action = 'Already matched'
    $oldRecord = $null
    if ($matches.Count -gt 1) { throw 'Multiple matching A records were returned; no ambiguous update was attempted.' }
    if ($matches.Count -eq 1) { $oldRecord = $matches[0] }
    elseif ($records.Count -eq 1) { $oldRecord = $records[0] }
    elseif ($records.Count -gt 1) { throw 'Several different A records exist at this name, none matching the desired address; unrelated multivalue data was preserved.' }

    $desiredTtl = $null
    if ($Definition.Contains('TTLMinutes')) { $desiredTtl = [timespan]::FromMinutes([double]$Definition.TTLMinutes) }
    $addParameters = @{ ComputerName=$ComputerName; ZoneName=$zoneName; Name=$name; IPv4Address=$address; ErrorAction='Stop' }
    if ($null -ne $desiredTtl) { $addParameters.TimeToLive = $desiredTtl }
    # Omitting AgeRecord makes a new A record static. Do not grant AllowUpdateAny.
    # PTRs are reconciled independently so a reverse-zone error cannot block A.
    if ($null -eq $oldRecord) {
        Assert-LabInventoryHealthy
        Add-DnsServerResourceRecordA @addParameters | Out-Null
        Add-LabGeneratedDnsObject -Kind DnsRecord -ZoneName $zoneName -Name $name -RecordType A -Data ([string]$address)
        $action = 'Created'
    }
    elseif (-not (Test-LabDnsStaticRecord -Record $oldRecord)) {
        # The provider's Timestamp is read-only on some server versions. Replace
        # only this managed A record to make it static, retaining its TTL.
        if ($null -eq $desiredTtl) { $addParameters.TimeToLive = $oldRecord.TimeToLive }
        Write-Status -IndentLevel 3 -Kind Info -Message ('Replacing the managed aging A record [{0}.{1}] with a static record; unrelated records are retained.' -f $name, $zoneName)
        Remove-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $zoneName -InputObject $oldRecord -Force -ErrorAction Stop | Out-Null
        Add-DnsServerResourceRecordA @addParameters | Out-Null
        $action = 'Updated'
    }
    elseif ($matches.Count -eq 0 -or ($null -ne $desiredTtl -and [timespan]$oldRecord.TimeToLive -ne $desiredTtl)) {
        $newRecord = [Microsoft.Management.Infrastructure.CimInstance]::new($oldRecord)
        $newRecord.RecordData.IPv4Address = $address
        if ($null -ne $desiredTtl) { $newRecord.TimeToLive = $desiredTtl }
        Set-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $zoneName -OldInputObject $oldRecord -NewInputObject $newRecord -ErrorAction Stop | Out-Null
        Update-LabGeneratedDnsAddress -ZoneName $zoneName -Name $name -OldAddress ([string]$oldRecord.RecordData.IPv4Address) -NewAddress ([string]$address)
        $action = 'Updated'
    }
    $final = @(Get-LabDnsNodeRecords -ComputerName $ComputerName -ZoneName $zoneName -Name $name | Where-Object {
        [string]$_.RecordType -ieq 'A' -and [string]$_.RecordData.IPv4Address -eq [string]$address
    })
    if ($final.Count -ne 1 -or -not (Test-LabDnsStaticRecord -Record $final[0])) { throw 'Static A record read-back verification failed.' }
    if ($null -ne $desiredTtl -and [timespan]$final[0].TimeToLive -ne $desiredTtl) { throw 'Baseline A record TTL verification failed.' }
    Add-LabGeneratedDnsObject -Kind DnsRecord -ZoneName $zoneName -Name $name -RecordType A -Data ([string]$address) -RecordOrigin ConfiguredExisting
    Write-Status -IndentLevel 2 -Kind Success -Message ('{0} static A record [{1}.{2}] -> {3}.' -f $action, $name, $zoneName, $address)
    if ($null -ne $desiredTtl) { Write-Status -IndentLevel 3 -Kind Info -Message ('Verified TTL: {0} minute(s).' -f $Definition.TTLMinutes) }
    if ($action -eq 'Created') { Add-LabProcessingCount -Category 'DNS records' -Created 1 -Identity ('A|{0}|{1}' -f $zoneName,$name) }
    if ($action -eq 'Updated') { Add-LabProcessingCount -Category 'DNS records' -Updated 1 -Identity ('A|{0}|{1}' -f $zoneName,$name) }
    return $action
}

function Ensure-LabDnsPtrRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Definition
    )

    $octets = ([string]$Definition.IPv4Address) -split '\.'
    [array]::Reverse($octets)
    $reverseName = ($octets -join '.') + '.in-addr.arpa'
    $zones = @(Get-DnsServerZone -ComputerName $ComputerName -ErrorAction Stop | Where-Object {
        $_.IsReverseLookupZone -and $reverseName.EndsWith(('.' + $_.ZoneName), [System.StringComparison]::OrdinalIgnoreCase)
    } | Sort-Object -Property @{ Expression = { $_.ZoneName.Length }; Descending = $true })
    if ($zones.Count -eq 0) { throw ('No hosted reverse zone covers {0}; no extra reverse zone was created.' -f $Definition.IPv4Address) }
    # Use the longest matching suffix, including any pre-existing /24 zones.
    # Do not bypass a more-specific secondary to write into a broader primary.
    $zone = $zones[0]
    if ([string]$zone.ZoneType -ine 'Primary') { throw ('Most-specific reverse zone [{0}] is not a writable primary.' -f $zone.ZoneName) }
    $owner = $reverseName.Substring(0, $reverseName.Length - $zone.ZoneName.Length - 1)
    $fqdn = '{0}.{1}.' -f $Definition.Name, $Definition.ZoneName
    $nodeRecords = @(Get-LabDnsNodeRecords -ComputerName $ComputerName -ZoneName $zone.ZoneName -Name $owner)
    if (@($nodeRecords | Where-Object { [string]$_.RecordType -ieq 'CNAME' }).Count -gt 0) { throw 'Reverse owner is a CNAME/RFC2317 delegation; no alias or delegation was changed.' }
    $matches = @($nodeRecords | Where-Object { [string]$_.RecordType -ieq 'PTR' -and ([string]$_.RecordData.PtrDomainName).TrimEnd([char]46) -ieq $fqdn.TrimEnd([char]46) })
    if ($matches.Count -gt 1) { throw 'Associated PTR target is ambiguous; no update was attempted.' }
    $desiredTtl = $null
    if ($Definition.Contains('PtrTTLSeconds')) {
        $seconds = [double]$Definition.PtrTTLSeconds
        if (-not ($seconds -ge 1 -and $seconds -le 4294967295 -and $seconds -eq [math]::Floor($seconds))) { throw 'PtrTTLSeconds must be a whole number from 1 through 4294967295.' }
        $desiredTtl = [timespan]::FromSeconds($seconds)
    }
    $action = 'Already matched'
    if ($matches.Count -eq 0) {
        # Retain any unrelated PTR targets at this IP; ensure our target exists.
        $parameters = @{ ComputerName=$ComputerName; ZoneName=$zone.ZoneName; Name=$owner; PtrDomainName=$fqdn; ErrorAction='Stop' }
        if ($null -ne $desiredTtl) { $parameters.TimeToLive = $desiredTtl }
        Assert-LabInventoryHealthy
        Add-DnsServerResourceRecordPtr @parameters | Out-Null
        Add-LabGeneratedDnsObject -Kind DnsRecord -ZoneName $zone.ZoneName -Name $owner -RecordType PTR -Data $fqdn
        $action = 'Created'
    }
    elseif ($null -ne $desiredTtl -and [timespan]$matches[0].TimeToLive -ne $desiredTtl) {
        $copy = [Microsoft.Management.Infrastructure.CimInstance]::new($matches[0])
        $copy.TimeToLive = $desiredTtl
        Set-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $zone.ZoneName -OldInputObject $matches[0] -NewInputObject $copy -ErrorAction Stop | Out-Null
        $action = 'Updated'
    }
    $final = @(Get-LabDnsNodeRecords -ComputerName $ComputerName -ZoneName $zone.ZoneName -Name $owner | Where-Object {
        [string]$_.RecordType -ieq 'PTR' -and ([string]$_.RecordData.PtrDomainName).TrimEnd([char]46) -ieq $fqdn.TrimEnd([char]46)
    })
    if ($final.Count -ne 1) { throw 'Associated PTR read-back verification failed.' }
    Add-LabGeneratedDnsObject -Kind DnsRecord -ZoneName $zone.ZoneName -Name $owner -RecordType PTR -Data $fqdn -RecordOrigin ConfiguredExisting
    if ($null -ne $desiredTtl -and [timespan]$final[0].TimeToLive -ne $desiredTtl) { throw 'Baseline PTR TTL read-back verification failed.' }
    if ($action -eq 'Created') { Add-LabProcessingCount -Category 'DNS records' -Created 1 -Identity ('PTR|{0}|{1}|{2}' -f $zone.ZoneName,$owner,$fqdn) }
    if ($action -eq 'Updated') { Add-LabProcessingCount -Category 'DNS records' -Updated 1 -Identity ('PTR|{0}|{1}|{2}' -f $zone.ZoneName,$owner,$fqdn) }
    Write-Status -IndentLevel 2 -Kind Success -Message ('{0} associated PTR [{1}] -> {2}' -f $action, $Definition.IPv4Address, $fqdn)
}

# AD-integrated DNS ACLs belong to the dnsNode (shared by all records at a
# name), not an individual value in a multivalue A RRset. Never edit a zone
# ACL or parent ACL to manufacture record-level permissions.
function Resolve-LabDnsDirectoryNode {
    [CmdletBinding()]
    param($Domain, [string]$ZoneName, [string]$Name)

    $server = [string]$Domain.SelectedDomainController
    $zones = @(Get-DnsServerZone -ComputerName $server -ErrorAction Stop | Where-Object { $_.ZoneName -ieq $ZoneName })
    if ($zones.Count -ne 1 -or -not $zones[0].IsDsIntegrated -or [string]$zones[0].ZoneType -ine 'Primary') {
        throw 'ACL work requires one AD-integrated writable primary zone on the selected DC.'
    }
    $root = Get-ADRootDSE -Server $server -ErrorAction Stop
    $contexts = @($root.namingContexts | Where-Object {
        $_ -ine [string]$root.configurationNamingContext -and $_ -ine [string]$root.schemaNamingContext
    } | Sort-Object -Unique)
    $zoneFilter = '(&(objectClass=dnsZone)(name={0}))' -f (ConvertTo-LdapFilterValue -Value $ZoneName)
    $directoryZones = @(
        foreach ($context in $contexts) {
            # Search hosted data NCs, including legacy domain and custom DNS
            # application partitions. Do not assume ForestDnsZones storage.
            Get-ADObject -Server $server -SearchBase $context -SearchScope Subtree -LDAPFilter $zoneFilter -ErrorAction Stop
        }
    )
    if ($directoryZones.Count -ne 1) { throw 'DNS zone directory identity is missing or ambiguous; no ACL was changed.' }
    $nodeFilter = '(&(objectClass=dnsNode)(name={0}))' -f (ConvertTo-LdapFilterValue -Value $Name)
    $nodes = @(Get-ADObject -Server $server -SearchBase $directoryZones[0].DistinguishedName -SearchScope OneLevel -LDAPFilter $nodeFilter -Properties dNSTombstoned -ErrorAction Stop)
    if ($nodes.Count -ne 1 -or $nodes[0].dNSTombstoned -eq $true) { throw 'DNS node identity is missing, ambiguous or tombstoned; no ACL was changed.' }
    return $nodes[0]
}

function Set-LabDnsDemoUserAcl {
    [CmdletBinding()]
    param(
        $Domain, [string]$ZoneName, [string]$Name, [string]$SamAccountName,
        [ValidateSet('Remove','Grant')][string]$Mode
    )

    $server = [string]$Domain.SelectedDomainController
    $userFilter = '(sAMAccountName={0})' -f (ConvertTo-LdapFilterValue -Value $SamAccountName)
    $users = @(Get-ADUser -Server $server -SearchBase $Domain.DistinguishedName -LDAPFilter $userFilter -Properties SID -ErrorAction Stop)
    if ($users.Count -eq 0 -and $Mode -eq 'Remove') {
        Write-Status -IndentLevel 2 -Kind Info -Message ('DNS ACL baseline: user [{0}] does not exist yet; no current-user SID to remove from [{1}.{2}]. Orphaned SIDs are not guessed.' -f $SamAccountName, $Name, $ZoneName)
        return 'UserAbsent'
    }
    if ($users.Count -ne 1) { throw 'The configured demo user could not be resolved uniquely in the current domain.' }
    $sid = [System.Security.Principal.SecurityIdentifier]::new([string]$users[0].SID)
    $node = Resolve-LabDnsDirectoryNode -Domain $Domain -ZoneName $ZoneName -Name $Name
    $entry = $null
    try {
        $entry = [System.DirectoryServices.DirectoryEntry]::new(('LDAP://{0}/{1}' -f $server, $node.DistinguishedName))
        $entry.AuthenticationType = [System.DirectoryServices.AuthenticationTypes]::Secure
        # Bypass the ADSI adapter for .NET Options and GUID comparisons.
        # Adapted Guid can expose a differently ordered hex string; using
        # psbase.Guid preserves the real object-identity safeguard.
        $entry.psbase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        $entry.RefreshCache(@('objectGUID','nTSecurityDescriptor'))
        if ([guid]$entry.psbase.Guid -ne [guid]$node.ObjectGUID) { throw 'DNS node identity changed before ACL access.' }
        $security = $entry.ObjectSecurity
        $rules = @($security.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -eq $sid.Value })
        $action = 'Already matched'
        $rights = [System.DirectoryServices.ActiveDirectoryRights]::GenericRead -bor [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
        if ($Mode -eq 'Remove') {
            if ($rules.Count -gt 0) {
                # Remove only this SID's explicit allow/deny ACEs. Leave every
                # other trustee, inheritance, owner and audit rule unchanged.
                $security.PurgeAccessRules($sid)
                $action = 'Updated'
            }
        }
        else {
            $combined = 0
            foreach ($rule in $rules) {
                if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                    $rule.ObjectType -eq [guid]::Empty -and
                    $rule.InheritanceType -eq [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None) {
                    $combined = $combined -bor [int]$rule.ActiveDirectoryRights
                }
            }
            if (($combined -band [int]$rights) -ne [int]$rights) {
                $rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($sid, $rights,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
                [void]$security.AddAccessRule($rule)
                $action = 'Updated'
            }
        }
        if ($action -eq 'Updated') {
            $identity = Get-ADObject -Server $server -Identity $node.ObjectGUID -ErrorAction Stop
            if ($identity.DistinguishedName -ine $node.DistinguishedName) { throw 'DNS node moved before ACL commit.' }
            $entry.ObjectSecurity = $security
            $entry.CommitChanges()
        }
        $entry.RefreshCache(@('objectGUID','nTSecurityDescriptor'))
        if ([guid]$entry.psbase.Guid -ne [guid]$node.ObjectGUID) { throw 'DNS node identity changed during ACL verification.' }
        $verified = @($entry.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -eq $sid.Value })
        if ($Mode -eq 'Remove') {
            if ($verified.Count -gt 0) { throw 'Demo-user ACEs remain, possibly inherited. Parent ACLs were not modified.' }
            Write-Status -IndentLevel 2 -Kind Success -Message ('{0} DNS ACL baseline [{1}.{2}]: no ACE for [{3}] remains on the node.' -f $action, $Name, $ZoneName, $SamAccountName)
        }
        else {
            $combined = 0
            foreach ($rule in $verified) {
                if (-not $rule.IsInherited -and $rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                    $rule.ObjectType -eq [guid]::Empty -and
                    $rule.InheritanceType -eq [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None) {
                    $combined = $combined -bor [int]$rule.ActiveDirectoryRights
                }
            }
            if (($combined -band [int]$rights) -ne [int]$rights) { throw 'DNS node read/write ACE verification failed.' }
            Write-Status -IndentLevel 2 -Kind Success -Message ('{0} DNS node ACL [{1}.{2}]: explicit Read/Write allow for [{3}]. Existing deny ACEs and effective access are not evaluated.' -f $action, $Name, $ZoneName, $SamAccountName)
        }
        if ($action -eq 'Updated') { Add-LabProcessingCount -Category 'DNS node ACLs' -Updated 1 -Identity ('{0}|{1}' -f $ZoneName,$Name) }
        return $action
    }
    finally { if ($null -ne $entry) { $entry.Dispose() } }
}

function Set-LabDnsSyntheticTtl {
    [CmdletBinding()]
    param([string]$ComputerName, [System.Collections.IDictionary]$Definition)

    $records = @(Get-LabDnsNodeRecords -ComputerName $ComputerName -ZoneName $Definition.ZoneName -Name $Definition.Name | Where-Object { [string]$_.RecordType -ieq 'A' })
    if ($records.Count -ne 1 -or [string]$records[0].RecordData.IPv4Address -ne [string]$Definition.IPv4Address) { throw 'TTL target is missing or differs from its configured single-A identity.' }
    if (-not (Test-LabDnsStaticRecord -Record $records[0])) { throw 'TTL target is not a verified static baseline A record.' }
    $ttl = [timespan]::FromMinutes([double]$Definition.TTLMinutes)
    $action = 'Already matched'
    if ([timespan]$records[0].TimeToLive -ne $ttl) {
        $copy = [Microsoft.Management.Infrastructure.CimInstance]::new($records[0])
        $copy.TimeToLive = $ttl
        Set-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $Definition.ZoneName -OldInputObject $records[0] -NewInputObject $copy -ErrorAction Stop | Out-Null
        $action = 'Updated'
    }
    $final = @(Get-LabDnsNodeRecords -ComputerName $ComputerName -ZoneName $Definition.ZoneName -Name $Definition.Name | Where-Object { [string]$_.RecordType -ieq 'A' })
    if ($final.Count -ne 1 -or [string]$final[0].RecordData.IPv4Address -ne [string]$Definition.IPv4Address -or [timespan]$final[0].TimeToLive -ne $ttl -or -not (Test-LabDnsStaticRecord -Record $final[0])) { throw 'Synthetic A record TTL read-back failed.' }
    Write-Status -IndentLevel 2 -Kind Success -Message ('{0} A record [{1}.{2}] TTL: {3} minute(s).' -f $action, $Definition.Name, $Definition.ZoneName, $Definition.TTLMinutes)
    if ($action -eq 'Updated') { Add-LabProcessingCount -Category 'DNS records' -Updated 1 -Identity ('A|{0}|{1}' -f $Definition.ZoneName,$Definition.Name) }
    return $action
}

function Remove-LabDnsSyntheticA {
    [CmdletBinding()]
    param([string]$ComputerName, [System.Collections.IDictionary]$Definition)

    $records = @(Get-LabDnsNodeRecords -ComputerName $ComputerName -ZoneName $Definition.ZoneName -Name $Definition.Name | Where-Object { [string]$_.RecordType -ieq 'A' })
    $action = 'Already absent'
    if ($records.Count -gt 0) {
        if ($records.Count -ne 1 -or [string]$records[0].RecordData.IPv4Address -ne [string]$Definition.IPv4Address) { throw 'Delete target differs from its configured single-A identity; nothing was deleted.' }
        Remove-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $Definition.ZoneName -InputObject $records[0] -Force -ErrorAction Stop | Out-Null
        $action = 'Deleted'
    }
    $remaining = @(Get-LabDnsNodeRecords -ComputerName $ComputerName -ZoneName $Definition.ZoneName -Name $Definition.Name | Where-Object { [string]$_.RecordType -ieq 'A' })
    if ($remaining.Count -gt 0) { throw 'Synthetic A deletion read-back failed.' }
    Write-Status -IndentLevel 2 -Kind Success -Message ('{0} A record [{1}.{2}]. Associated PTR and other record types were not deleted.' -f $action, $Definition.Name, $Definition.ZoneName)
    if ($action -eq 'Deleted') { Add-LabProcessingCount -Category 'DNS records' -Deleted 1 -Identity ('A|{0}|{1}' -f $Definition.ZoneName,$Definition.Name) }
    return $action
}

function Remove-LabDnsOldPtr {
    [CmdletBinding()]
    param([string]$ComputerName, [System.Collections.IDictionary]$Definition, [string]$OldIPv4Address)

    $octets = $OldIPv4Address -split '\.'
    [array]::Reverse($octets)
    $reverseName = ($octets -join '.') + '.in-addr.arpa'
    $zones = @(Get-DnsServerZone -ComputerName $ComputerName -ErrorAction Stop | Where-Object {
        $_.IsReverseLookupZone -and $reverseName.EndsWith(('.' + $_.ZoneName), [System.StringComparison]::OrdinalIgnoreCase)
    } | Sort-Object -Property @{ Expression = { $_.ZoneName.Length }; Descending = $true })
    if ($zones.Count -eq 0) { throw ('No hosted reverse zone covers old address {0}; no extra reverse zone was created.' -f $OldIPv4Address) }
    if ([string]$zones[0].ZoneType -ine 'Primary') { throw 'Most-specific old-address reverse zone is not writable.' }
    $zoneName = [string]$zones[0].ZoneName
    $owner = $reverseName.Substring(0, $reverseName.Length - $zoneName.Length - 1)
    $target = '{0}.{1}' -f $Definition.Name, $Definition.ZoneName
    $records = @(Get-LabDnsNodeRecords -ComputerName $ComputerName -ZoneName $zoneName -Name $owner)
    if (@($records | Where-Object { [string]$_.RecordType -ieq 'CNAME' }).Count -gt 0) { throw 'Old PTR owner is a CNAME; no delegation was changed.' }
    $summaryRemoved = @()
    foreach ($record in @($records | Where-Object { [string]$_.RecordType -ieq 'PTR' -and ([string]$_.RecordData.PtrDomainName).TrimEnd([char]46) -ieq $target })) {
        Remove-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $zoneName -InputObject $record -Force -ErrorAction Stop | Out-Null
        $summaryRemoved += $record
    }
    $remaining = @(Get-LabDnsNodeRecords -ComputerName $ComputerName -ZoneName $zoneName -Name $owner | Where-Object { [string]$_.RecordType -ieq 'PTR' -and ([string]$_.RecordData.PtrDomainName).TrimEnd([char]46) -ieq $target })
    if ($remaining.Count -gt 0) { throw 'Old matching PTR remains after cleanup.' }
    foreach ($record in $summaryRemoved) {
        Add-LabProcessingCount -Category 'DNS records' -Deleted 1 -Identity ('PTR|{0}|{1}|{2}' -f $zoneName,$owner,$record.RecordData.PtrDomainName)
    }
    Write-Status -IndentLevel 2 -Kind Success -Message ('Old PTR target [{0}] for [{1}] is absent; unrelated PTR targets were retained.' -f $OldIPv4Address, $target)
}

function Invoke-LabDnsSyntheticPtr {
    [CmdletBinding()]
    param([string]$ComputerName, [System.Collections.IDictionary]$Definition)

    # Select an exact PTR target, not the entire owner/RRset or dnsNode.
    # Other targets at the same address and all forward A records survive.
    $target = ([string]$Definition.PtrDomainName).TrimEnd([char]46)
    if (-not (Test-LabDnsName -Name $target)) { throw 'Synthetic PTR target must be a valid DNS name.' }
    $delete = [string]$Definition.Action -eq 'DeletePtr'
    if (-not $delete -and [string]$Definition.Action -ne 'SetPtrTTL') { throw 'Unsupported synthetic PTR action.' }
    $ttl = $null
    if (-not $delete) {
        if (-not $Definition.Contains('TTLSeconds')) { throw 'Synthetic PTR TTL requires TTLSeconds.' }
        $seconds = [double]$Definition.TTLSeconds
        if (-not ($seconds -ge 1 -and $seconds -le 4294967295 -and $seconds -eq [math]::Floor($seconds))) {
            throw 'PTR TTLSeconds must be a whole number from 1 through 4294967295.'
        }
        $ttl = [timespan]::FromSeconds($seconds)
    }
    $nodeRecords = @(Get-LabDnsNodeRecords -ComputerName $ComputerName -ZoneName $Definition.ZoneName -Name $Definition.Name)
    if (@($nodeRecords | Where-Object { [string]$_.RecordType -ieq 'CNAME' }).Count -gt 0) { throw 'PTR owner is a CNAME; no alias or delegation was changed.' }
    $matches = @($nodeRecords | Where-Object {
        [string]$_.RecordType -ieq 'PTR' -and ([string]$_.RecordData.PtrDomainName).TrimEnd([char]46) -ieq $target
    })
    if ($matches.Count -gt 1) { throw 'Synthetic PTR target is ambiguous; no record was changed.' }
    $action = 'Already absent'
    if ($delete) {
        if ($matches.Count -eq 1) {
            Remove-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $Definition.ZoneName -InputObject $matches[0] -Force -ErrorAction Stop | Out-Null
            $action = 'Deleted'
        }
    }
    else {
        if ($matches.Count -ne 1) { throw 'Synthetic PTR TTL target is missing; no record was created.' }
        $action = 'Already matched'
        if ([timespan]$matches[0].TimeToLive -ne $ttl) {
            $copy = [Microsoft.Management.Infrastructure.CimInstance]::new($matches[0])
            $copy.TimeToLive = $ttl
            Set-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $Definition.ZoneName -OldInputObject $matches[0] -NewInputObject $copy -ErrorAction Stop | Out-Null
            $action = 'Updated'
        }
    }
    $final = @(Get-LabDnsNodeRecords -ComputerName $ComputerName -ZoneName $Definition.ZoneName -Name $Definition.Name | Where-Object {
        [string]$_.RecordType -ieq 'PTR' -and ([string]$_.RecordData.PtrDomainName).TrimEnd([char]46) -ieq $target
    })
    $identity = 'PTR|{0}|{1}|{2}' -f $Definition.ZoneName,$Definition.Name,($target + '.')
    if ($delete) {
        if ($final.Count -ne 0) { throw 'Synthetic PTR deletion read-back failed.' }
        if ($action -eq 'Deleted') { Add-LabProcessingCount -Category 'DNS records' -Deleted 1 -Identity $identity }
        Write-Status -IndentLevel 2 -Kind Success -Message ('{0} PTR [{1}.{2}] -> {3}. Forward records and unrelated PTR targets were retained.' -f $action, $Definition.Name, $Definition.ZoneName, $target)
    }
    else {
        if ($final.Count -ne 1 -or [timespan]$final[0].TimeToLive -ne $ttl) { throw 'Synthetic PTR TTL read-back failed.' }
        if ($action -eq 'Updated') { Add-LabProcessingCount -Category 'DNS records' -Updated 1 -Identity $identity }
        Write-Status -IndentLevel 2 -Kind Success -Message ('{0} PTR [{1}.{2}] -> {3}; TTL: {4} second(s).' -f $action, $Definition.Name, $Definition.ZoneName, $target, $Definition.TTLSeconds)
    }
    return $action
}

function Invoke-LabDnsADChanges {
    [CmdletBinding()]
    param($Domain, [AllowEmptyCollection()][object[]]$Definitions)

    $result = [pscustomobject]@{ ChangedCount=0; UnchangedCount=0; SkippedCount=0; PtrWarningCount=0 }
    $server = [string]$Domain.SelectedDomainController
    foreach ($definition in $Definitions) {
        try {
            if ($definition -isnot [System.Collections.IDictionary]) { throw 'DNS synthetic definitions must be hash tables.' }
            if (-not (Test-LabDnsName -Name $definition.ZoneName) -or -not (Test-LabDnsName -Name $definition.Name)) { throw 'Invalid DNS synthetic zone or owner.' }
            $zones = @(Get-DnsServerZone -ComputerName $server -ErrorAction Stop | Where-Object { $_.ZoneName -ieq $definition.ZoneName })
            $reverseAction = [string]$definition.Action -in @('DeletePtr','SetPtrTTL')
            if ($zones.Count -ne 1 -or [string]$zones[0].ZoneType -ine 'Primary' -or -not $zones[0].IsDsIntegrated -or
                [bool]$zones[0].IsReverseLookupZone -ne $reverseAction) { throw 'Synthetic DNS target must be an AD-integrated writable primary with the expected forward/reverse direction on the selected DC.' }
            $action = $null
            switch ([string]$definition.Action) {
                'DeleteA' { $action = Remove-LabDnsSyntheticA -ComputerName $server -Definition $definition }
                'DeletePtr' { $action = Invoke-LabDnsSyntheticPtr -ComputerName $server -Definition $definition }
                'SetPtrTTL' { $action = Invoke-LabDnsSyntheticPtr -ComputerName $server -Definition $definition }
                'SetTTL' {
                    if ([double]$definition.TTLMinutes -le 0 -or [double]$definition.TTLMinutes -gt 35791394) { throw 'TTL minutes are outside the DNS unsigned-32-bit seconds range.' }
                    $action = Set-LabDnsSyntheticTtl -ComputerName $server -Definition $definition
                }
                'SetAddress' {
                    foreach ($value in @($definition.IPv4Address, $definition.OldIPv4Address)) {
                        $ip = [ipaddress]$value
                        if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or [string]$ip -cne [string]$value) { throw 'Synthetic IP addresses must be canonical IPv4.' }
                    }
                    $current = @(Get-LabDnsNodeRecords -ComputerName $server -ZoneName $definition.ZoneName -Name $definition.Name | Where-Object { [string]$_.RecordType -ieq 'A' })
                    if ($current.Count -ne 1 -or @([string]$definition.OldIPv4Address, [string]$definition.IPv4Address) -notcontains [string]$current[0].RecordData.IPv4Address) { throw 'Address target differs from its configured old/new single-A identity.' }
                    $action = Ensure-LabDnsARecord -ComputerName $server -Definition $definition
                    # Forward success is independent. Establish the new PTR
                    # before removing only the old target; retry on reruns.
                    try {
                        Ensure-LabDnsPtrRecord -ComputerName $server -Definition $definition
                        if ([string]$definition.OldIPv4Address -ne [string]$definition.IPv4Address) {
                            Remove-LabDnsOldPtr -ComputerName $server -Definition $definition -OldIPv4Address $definition.OldIPv4Address
                        }
                    }
                    catch {
                        $result.PtrWarningCount++
                        Write-Status -IndentLevel 2 -Kind Warning -Message ('Associated PTR update for [{0}.{1}] ({2} -> {3}) was not verified: {4} The verified A record remains in place. Continuing...' -f $definition.Name, $definition.ZoneName, $definition.OldIPv4Address, $definition.IPv4Address, $_.Exception.Message)
                    }
                }
                'GrantAcl' {
                    # Refuse to grant write access to a missing/replaced owner.
                    $current = @(Get-LabDnsNodeRecords -ComputerName $server -ZoneName $definition.ZoneName -Name $definition.Name | Where-Object { [string]$_.RecordType -ieq 'A' })
                    if ($current.Count -ne 1 -or [string]$current[0].RecordData.IPv4Address -ne [string]$definition.IPv4Address) { throw 'DNS ACL target does not match the configured synthetic A address.' }
                    $action = Set-LabDnsDemoUserAcl -Domain $Domain -ZoneName $definition.ZoneName -Name $definition.Name -SamAccountName $definition.SamAccountName -Mode Grant
                }
                default { throw 'Unsupported synthetic DNS action.' }
            }
            if ($action -in @('Already matched','Already absent')) { $result.UnchangedCount++ }
            else { $result.ChangedCount++ }
        }
        catch {
            $result.SkippedCount++
            Write-Status -IndentLevel 2 -Kind Warning -Message ('Synthetic DNS action was not verified: {0} Earlier writes may remain; no rollback or DNS/DC failover attempted. Continuing with other DNS actions.' -f $_.Exception.Message)
        }
    }
    return $result
}

function Ensure-LabDnsBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$ZoneDefinitions,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$RecordDefinitions
    )

    Write-SectionHeader -Message 'Create/Update baseline DNS zones and records...'
    $result = [pscustomobject]@{
        Skipped=$false; ZoneVerifiedCount=0; ZoneFailedCount=0
        AVerifiedCount=0; AFailedCount=0; PtrVerifiedCount=0; PtrWarningCount=0
        AclResetCount=0; AclWarningCount=0
    }
    $server = [string]$Domain.SelectedDomainController
    $forestName = ([string]$Domain.Forest).TrimEnd([char]46)
    try {
        if ([string]::IsNullOrWhiteSpace($server) -or -not (Test-LabDnsName -Name $forestName)) { throw 'DNS baseline requires the selected writable DC and forest FQDN.' }
        $seenZones = @{}
        foreach ($definition in $ZoneDefinitions) {
            if ($definition -isnot [System.Collections.IDictionary]) { throw 'Each DNS zone definition must be a hash table.' }
            foreach ($key in @('Name','NetworkId','ReplicationScope','DynamicUpdate','EnsureUnsigned')) {
                if (-not $definition.Contains($key)) { throw ('Missing DNS zone field: {0}.' -f $key) }
            }
            if (-not (Test-LabDnsName -Name $definition.Name) -or $seenZones.ContainsKey($definition.Name)) { throw 'DNS zone names must be valid and unique.' }
            if ($definition.ReplicationScope -cne 'Forest' -or $definition.DynamicUpdate -cne 'NonsecureAndSecure' -or $definition.EnsureUnsigned -isnot [bool]) { throw 'Managed zones require Forest replication, NonsecureAndSecure updates and a Boolean EnsureUnsigned.' }
            if (-not [string]::IsNullOrWhiteSpace([string]$definition.NetworkId)) {
                $networkMatch = [regex]::Match([string]$definition.NetworkId, '^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/(8|16|24)$')
                if (-not $networkMatch.Success) { throw 'Reverse NetworkId must be a class-aligned IPv4 /8, /16 or /24.' }
                $networkIp = [ipaddress]$networkMatch.Groups[1].Value
                $prefix = [int]$networkMatch.Groups[2].Value
                $bytes = $networkIp.GetAddressBytes()
                if ($bytes.Count -ne 4) { throw 'Reverse NetworkId must be IPv4.' }
                for ($i = ($prefix / 8); $i -lt 4; $i++) { if ($bytes[$i] -ne 0) { throw 'Reverse NetworkId has nonzero host bits.' } }
                $parts = @($bytes[0..(($prefix / 8) - 1)] | ForEach-Object { [string]$_ })
                [array]::Reverse($parts)
                if ($definition.Name -ine (($parts -join '.') + '.in-addr.arpa')) { throw 'Reverse zone Name and NetworkId do not match.' }
            }
            elseif ([string]$definition.Name -match '\.in-addr\.arpa$') { throw 'An IPv4 reverse zone must include its NetworkId.' }
            $seenZones[$definition.Name] = $false
        }
        $seenRecords = @{}
        foreach ($definition in $RecordDefinitions) {
            if ($definition -isnot [System.Collections.IDictionary]) { throw 'Each DNS record definition must be a hash table.' }
            foreach ($key in @('ZoneName','Name','IPv4Address','Static','CreatePtr')) {
                if (-not $definition.Contains($key)) { throw ('Missing DNS A record field: {0}.' -f $key) }
            }
            if (-not (Test-LabDnsName -Name $definition.ZoneName) -or -not (Test-LabDnsName -Name $definition.Name) -or
                ('{0}.{1}' -f $definition.Name, $definition.ZoneName).Length -gt 253) { throw 'DNS A record owner/zone is invalid.' }
            if ([string]$definition.IPv4Address -notmatch '^([0-9]{1,3}\.){3}[0-9]{1,3}$') { throw 'A records require dotted-quad IPv4 addresses.' }
            $ip = [ipaddress]$definition.IPv4Address
            if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or [string]$ip -cne [string]$definition.IPv4Address) { throw 'A record IPv4 address is not canonical.' }
            if ($definition.Static -isnot [bool] -or -not $definition.Static -or $definition.CreatePtr -isnot [bool]) { throw 'DNS Static must be $true and CreatePtr must be Boolean.' }
            if ($definition.Contains('TTLMinutes') -and ([double]$definition.TTLMinutes -le 0 -or [double]$definition.TTLMinutes -gt 35791394)) { throw 'TTLMinutes must be positive and fit unsigned-32-bit DNS seconds.' }
            if ($definition.Contains('PtrTTLSeconds')) {
                $seconds = [double]$definition.PtrTTLSeconds
                if (-not $definition.CreatePtr -or -not ($seconds -ge 1 -and $seconds -le 4294967295 -and $seconds -eq [math]::Floor($seconds))) { throw 'PtrTTLSeconds requires CreatePtr and whole seconds from 1 through 4294967295.' }
            }
            if ($definition.Contains('AclResetSamAccountName') -and [string]::IsNullOrWhiteSpace([string]$definition.AclResetSamAccountName)) { throw 'ACL-reset demo-user name must not be blank.' }
            $key = '{0}|{1}' -f $definition.ZoneName, $definition.Name
            if ($seenRecords.ContainsKey($key)) { throw 'Only one desired A address per managed owner may be defined.' }
            $seenRecords[$key] = $true
        }
        foreach ($command in @('Get-DnsServerZone','Add-DnsServerPrimaryZone','ConvertTo-DnsServerPrimaryZone','Set-DnsServerPrimaryZone','Invoke-DnsServerZoneUnsign','Get-DnsServerResourceRecord','Add-DnsServerResourceRecordA','Set-DnsServerResourceRecord','Remove-DnsServerResourceRecord','Add-DnsServerResourceRecordPtr')) {
            Get-Command -Name $command -ErrorAction Stop | Out-Null
        }
        Get-DnsServerZone -ComputerName $server -ErrorAction Stop | Out-Null
    }
    catch {
        $result.Skipped = $true
        $result.ZoneFailedCount = $ZoneDefinitions.Count
        $result.AFailedCount = $RecordDefinitions.Count
        Write-Status -IndentLevel 2 -Kind Warning -BackgroundColor Red -Message ('DNS baseline skipped before DNS writes: {0} No tools were installed and no DNS/DC failover was attempted. Other baseline provisioning will continue.' -f $_.Exception.Message)
        return $result
    }
    Write-Status -Kind Info -Message ('DNS server: [{0}]. Main forward zone: [{1}] (current AD domain, not necessarily the forest root).' -f $server, $Domain.DNSRoot)
    foreach ($definition in $ZoneDefinitions) {
        try {
            [void](Ensure-LabDnsZone -ComputerName $server -ForestName $forestName -Definition $definition)
            $seenZones[$definition.Name] = $true
            $result.ZoneVerifiedCount++
        }
        catch {
            $result.ZoneFailedCount++
            Write-Status -IndentLevel 2 -Kind Warning -BackgroundColor Red -Message ('DNS zone [{0}] was not verified: {1} Earlier DNS writes may remain committed; no zone was deleted or rollback attempted. Continuing...' -f $definition.Name, $_.Exception.Message)
        }
    }
    foreach ($definition in $RecordDefinitions) {
        try {
            if ($seenZones.ContainsKey($definition.ZoneName) -and -not $seenZones[$definition.ZoneName]) { throw 'The managed forward zone did not pass baseline verification.' }
            [void](Ensure-LabDnsARecord -ComputerName $server -Definition $definition)
            $result.AVerifiedCount++
        }
        catch {
            $result.AFailedCount++
            Write-Status -IndentLevel 2 -Kind Warning -BackgroundColor Red -Message ('A record [{0}.{1}] was not verified: {2} PTR work for this record was skipped. Earlier writes may remain committed; no rollback attempted. Continuing...' -f $definition.Name, $definition.ZoneName, $_.Exception.Message)
            continue
        }
        if ($definition.Contains('AclResetSamAccountName')) {
            try {
                $aclAction = Set-LabDnsDemoUserAcl -Domain $Domain -ZoneName $definition.ZoneName -Name $definition.Name -SamAccountName $definition.AclResetSamAccountName -Mode Remove
                if ($aclAction -ne 'UserAbsent') { $result.AclResetCount++ }
            }
            catch {
                $result.AclWarningCount++
                Write-Status -IndentLevel 2 -Kind Warning -Message ('DNS baseline ACL cleanup for [{0}.{1}] was not verified: {2} The verified A record remains; continuing with PTR and other DNS work.' -f $definition.Name, $definition.ZoneName, $_.Exception.Message)
            }
        }
        if ($definition.CreatePtr) {
            try {
                Ensure-LabDnsPtrRecord -ComputerName $server -Definition $definition
                $result.PtrVerifiedCount++
            }
            catch {
                $result.PtrWarningCount++
                Write-Status -IndentLevel 2 -Kind Warning -Message ('Associated PTR for [{0}.{1}] ({2}) was not verified: {3} The verified A record remains in place. Continuing...' -f $definition.Name, $definition.ZoneName, $definition.IPv4Address, $_.Exception.Message)
            }
        }
    }
    $kind = 'Success'
    if (($result.ZoneFailedCount + $result.AFailedCount + $result.PtrWarningCount + $result.AclWarningCount) -gt 0) { $kind = 'Warning' }
    Write-Status -IndentLevel 1 -Kind $kind -Message ('DNS baseline: {0}/{1} zones, {2}/{3} static A records and {4} associated PTRs verified; {5} PTR warning(s). Verification is on [{6}], not forest-wide convergence.' -f $result.ZoneVerifiedCount, $ZoneDefinitions.Count, $result.AVerifiedCount, $RecordDefinitions.Count, $result.PtrVerifiedCount, $result.PtrWarningCount, $server)
    Write-Status -IndentLevel 1 -Kind $kind -Message ('DNS baseline ACLs: {0} node cleanup(s) verified; {1} warning(s).' -f $result.AclResetCount, $result.AclWarningCount)
    return $result
}

function Ensure-LabSites {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$SiteDefinitions
    )
    Write-SectionHeader -Message 'Create/Update AD Sites and Services Sites...'
    $createdCount = 0
    $updatedCount = 0
    $unchangedCount = 0
    try {
        $server = [string]$Domain.SelectedDomainController
        if ([string]::IsNullOrWhiteSpace($server)) { throw 'Site provisioning requires the selected writable DC.' }
        $plans = @()
        $seenNames = @{}
        $seenSubnets = @{}
        if ($SiteDefinitions.Count -gt 0) {
            $rootDse = Get-ADRootDSE -Server $server -ErrorAction Stop
            $configurationDN = [string]$rootDse.configurationNamingContext
            if ([string]::IsNullOrWhiteSpace($configurationDN)) { throw 'The configuration naming context was not returned.' }
            $siteContainer = 'CN=Sites,{0}' -f $configurationDN
            Get-ADObject -Identity $siteContainer -Server $server -ErrorAction Stop | Out-Null
            foreach ($definition in $SiteDefinitions) {
                if ($definition -isnot [System.Collections.IDictionary]) { throw 'Each site definition must be a hash table.' }
                $fields = @('Name','SamAccountName','DisplayName','Description','SubnetName','SubnetDescription')
                $optionalFields = @('Location','SubnetLocation')
                foreach ($field in $fields) {
                    if (-not $definition.Contains($field) -or $definition[$field] -isnot [string] -or
                        [string]::IsNullOrWhiteSpace($definition[$field])) { throw ('Site field [{0}] must be a nonblank string.' -f $field) }
                }
                foreach ($field in $definition.Keys) {
                    if ($fields -notcontains $field -and $optionalFields -notcontains $field) {
                        throw ('Unsupported site definition field [{0}].' -f $field)
                    }
                    if ($optionalFields -contains $field -and ($definition[$field] -isnot [string] -or
                        [string]::IsNullOrWhiteSpace($definition[$field]))) {
                        throw ('Optional site field [{0}] must be a nonblank string when supplied; omit it to leave it unmanaged.' -f $field)
                    }
                }
                # Use DNS-safe site labels, not the more permissive OU/link
                # naming rules. DisplayName may still contain spaces.
                if ($definition.Name -cnotmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$') {
                    throw ('Invalid AD site Name [{0}]. Use 1..63 ASCII letters/digits/hyphens, starting and ending with a letter or digit. Spaces, dots, underscores and DNs are not accepted; use DisplayName for a friendly label.' -f $definition.Name)
                }
                if ($seenNames.ContainsKey($definition.Name)) { throw 'Duplicate site names in Get-LabSiteDefinitions.' }
                $seenNames[$definition.Name] = $true
                $prefix = ConvertTo-LabSubnetPrefix -Name $definition.SubnetName
                if ($seenSubnets.ContainsKey($prefix)) { throw 'Multiple site definitions claim the same subnet prefix.' }
                $seenSubnets[$prefix] = $true
                $escaped = ConvertTo-LdapFilterValue -Value $definition.Name
                $matches = @(Get-ADObject -LDAPFilter ('(name={0})' -f $escaped) -SearchBase $siteContainer `
                    -SearchScope OneLevel -Properties description,displayName,location -Server $server -ErrorAction Stop)
                if ($matches.Count -gt 1) { throw ('Site [{0}] is ambiguous.' -f $definition.Name) }
                $existing = $null
                $expectedDN = 'CN={0},{1}' -f $definition.Name, $siteContainer
                if ($matches.Count -eq 1) {
                    $existing = $matches[0]
                    if ($existing.ObjectClass -ine 'site' -or $existing.Name -ine $definition.Name -or
                        $existing.DistinguishedName -ine $expectedDN -or [guid]$existing.ObjectGUID -eq [guid]::Empty) {
                        throw ('Site [{0}] conflicts with an unexpected object identity or type.' -f $definition.Name)
                    }
                }
                $expected = @{ description=$definition.Description; displayName=$definition.DisplayName }
                if ($definition.Contains('Location')) { $expected['location'] = $definition.Location }
                $plans += [pscustomobject]@{
                    Name=$definition.Name; ExpectedDN=$expectedDN; Existing=$existing
                    Expected=$expected
                    ReferenceSamAccountName=$definition.SamAccountName
                }
            }
        }
        # Every definition and existing identity has passed preflight.
        foreach ($plan in $plans) {
            Write-Status -Kind Info -Message ('Checking site [{0}] on [{1}].' -f $plan.Name, $server)
            Write-Status -Kind Info -Message ('SamAccountName [{0}] is definition reference metadata only; it is not written to the site.' -f $plan.ReferenceSamAccountName)
            $created = $null -eq $plan.Existing
            $changed = $false
            if ($created) {
                Write-Status -IndentLevel 3 -Kind Info -Message ('Creating AD site [{0}].' -f $plan.Name)
                Assert-LabInventoryHealthy
                $otherAttributes = @{ displayName=$plan.Expected.displayName }
                if ($plan.Expected.ContainsKey('location')) { $otherAttributes['location'] = $plan.Expected.location }
                $site = New-ADReplicationSite -Name $plan.Name -Description $plan.Expected.description `
                    -OtherAttributes $otherAttributes -Server $server -PassThru -ErrorAction Stop
                Add-LabGeneratedADObject -Kind Site -Object $site
                if ($null -eq $site -or [guid]$site.ObjectGUID -eq [guid]::Empty) { throw 'Site creation returned no object GUID.' }
                $identity = [guid]$site.ObjectGUID
            }
            else {
                $identity = [guid]$plan.Existing.ObjectGUID
                # Revalidate existence, GUID, type and exact DN immediately before
                # deciding whether an existing object needs an update.
                $current = Get-ADObject -Identity $identity -Properties description,displayName,location -Server $server -ErrorAction Stop
                if ($null -eq $current -or $current.ObjectClass -ine 'site' -or $current.Name -ine $plan.Name -or
                    $current.DistinguishedName -ine $plan.ExpectedDN -or [guid]$current.ObjectGUID -ne $identity) {
                    throw 'Site identity changed after preflight; no update will be attempted.'
                }
                $replace = @{}
                foreach ($attribute in $plan.Expected.Keys) {
                    if ([string]$current.$attribute -cne $plan.Expected[$attribute]) { $replace[$attribute] = $plan.Expected[$attribute] }
                }
                if ($replace.Count -gt 0) {
                    Write-Status -IndentLevel 3 -Kind Info -Message ('Restoring changed site fields for [{0}]: {1}.' -f $plan.Name, (($replace.Keys | Sort-Object) -join ', '))
                    Set-ADReplicationSite -Identity $identity -Replace $replace -Server $server -ErrorAction Stop
                    $changed = $true
                }
            }
            $verified = Get-ADObject -Identity $identity -Properties description,displayName,location -Server $server -ErrorAction Stop
            if ($null -eq $verified -or $verified.ObjectClass -ine 'site' -or $verified.Name -ine $plan.Name -or
                $verified.DistinguishedName -ine $plan.ExpectedDN -or [guid]$verified.ObjectGUID -ne $identity) { throw 'Site read-back did not match the expected identity.' }
            foreach ($attribute in $plan.Expected.Keys) {
                if ([string]$verified.$attribute -cne $plan.Expected[$attribute]) { throw ('Site [{0}] verification failed for [{1}].' -f $plan.Name, $attribute) }
            }
            if ($created) { $createdCount++ }
            elseif ($changed) { $updatedCount++ }
            else { $unchangedCount++ }
            Write-Status -IndentLevel 2 -Kind Success -Message ('Verified site [{0}]: DisplayName [{1}], Description [{2}], Location [{3}].' -f $plan.Name, $verified.displayName, $verified.description, $verified.location)
        }
        Write-Status -IndentLevel 0 -Kind Success -Message ('AD sites: {0} verified ({1} created, {2} updated, {3} already matched) on [{4}].' -f ($createdCount+$updatedCount+$unchangedCount), $createdCount, $updatedCount, $unchangedCount, $server)
        Add-LabProcessingCount -Category 'AD sites' -Created $createdCount -Updated $updatedCount
        return [pscustomobject]@{ CreatedCount=$createdCount; UpdatedCount=$updatedCount; UnchangedCount=$unchangedCount; VerifiedCount=($createdCount+$updatedCount+$unchangedCount) }
    }
    catch {
        Stop-ScriptGracefully -IndentLevel 2 -Message ('Site provisioning failed: {0} Earlier writes may have committed; no automatic rollback or DC failover was attempted.' -f $_.Exception.Message)
    }
}

function Ensure-LabSubnets {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$SubnetDefinitions
    )

    Write-SectionHeader -Message 'Create/Update AD Sites and Services Subnets...'
    $server = [string]$Domain.SelectedDomainController
    if ([string]::IsNullOrWhiteSpace($server)) {
        Stop-ScriptGracefully -IndentLevel 2 -Message 'Subnet provisioning requires the selected writable DC.'
    }
    $createdCount = 0
    $updatedCount = 0
    $unchangedCount = 0
    $skippedCount = 0
    $plans = New-Object 'System.Collections.Generic.List[object]'
    $seenNames = @{}
    $siteCache = @{}
    # Internal field-to-LDAP mapping, not operator-editable desired state.
    $attributeMap = [ordered]@{ Site = 'siteObject'; Location = 'location'; Description = 'description' }
    $readProperties = @('siteObject', 'location', 'description')

    if ($SubnetDefinitions.Count -gt 0) {
        Write-Status -IndentLevel 1 -Kind Info -Message 'Validating subnet prefixes, optional fields and named sites before subnet writes.'
        Write-Status -IndentLevel 1 -Kind Info -Message 'Explicit blank fields are cleared, including Site links; omitted fields are unmanaged.'
        try {
            $rootDse = Get-ADRootDSE -Server $server -ErrorAction Stop
            $configurationDN = [string]$rootDse.configurationNamingContext
            if ([string]::IsNullOrWhiteSpace($configurationDN)) { throw 'The configuration naming context was not returned.' }
            $subnetContainer = 'CN=Subnets,CN=Sites,{0}' -f $configurationDN
            # Confirm the container exists; an inaccessible container is not an empty list.
            Get-ADObject -Identity $subnetContainer -Server $server -ErrorAction Stop | Out-Null
            foreach ($definition in $SubnetDefinitions) {
                if ($definition -isnot [System.Collections.IDictionary] -or -not $definition.Contains('Name')) {
                    throw 'Each subnet definition must be a hash table containing Name.'
                }
                foreach ($field in $definition.Keys) {
                    if (@('Name', 'Site', 'Location', 'Description') -notcontains $field) {
                        throw ("Unsupported subnet field [{0}]; use Name, Site, Location or Description." -f $field)
                    }
                    if ($null -ne $definition[$field] -and $definition[$field] -isnot [string]) {
                        throw ("Subnet field [{0}] must be a string or null." -f $field)
                    }
                }
                if ([string]::IsNullOrWhiteSpace([string]$definition.Name)) { throw 'Subnet Name is mandatory and cannot be blank.' }
                $name = ConvertTo-LabSubnetPrefix -Name $definition.Name
                if ($seenNames.ContainsKey($name)) { throw ("Duplicate subnet prefix [{0}] in Get-LabSubnetDefinitions." -f $name) }
                $seenNames[$name] = $true
                $expected = [ordered]@{}
                $skipSubnet = $false
                foreach ($field in $attributeMap.Keys) {
                    if (-not $definition.Contains($field)) { continue }
                    $value = [string]$definition[$field]
                    if ([string]::IsNullOrWhiteSpace($value)) { $value = '' }
                    if ($field -eq 'Site' -and $value.Length -gt 0) {
                        if (-not $siteCache.ContainsKey($value)) {
                            try {
                                $site = Get-ADReplicationSite -Identity $value -Server $server -ErrorAction Stop
                                if ($null -eq $site) { throw 'The site lookup returned no object.' }
                                $siteCache[$value] = [string]$site.DistinguishedName
                            }
                            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                                $siteCache[$value] = $null
                            }
                        }
                        if ($null -eq $siteCache[$value]) {
                            Write-Status -IndentLevel 2 -Kind Warning -Message ("Subnet [{0}] specifies missing site [{1}]; skipping this subnet without creating or modifying it." -f $name, $value)
                            $skippedCount++
                            $skipSubnet = $true
                            break
                        }
                        $value = $siteCache[$value]
                    }
                    $expected[$attributeMap[$field]] = $value
                }
                if ($skipSubnet) { continue }
                $escapedName = ConvertTo-LdapFilterValue -Value $name
                $matches = @(Get-ADObject -LDAPFilter ('(name={0})' -f $escapedName) -SearchBase $subnetContainer `
                    -SearchScope OneLevel -Properties $readProperties -Server $server -ErrorAction Stop)
                if ($matches.Count -gt 1 -or ($matches.Count -eq 1 -and $matches[0].ObjectClass -ine 'subnet')) {
                    throw ("Subnet [{0}] is ambiguous or conflicts with a non-subnet object." -f $name)
                }
                $existingSubnet = $null
                if ($matches.Count -eq 1) { $existingSubnet = $matches[0] }
                $plans.Add([pscustomobject]@{ Name = $name; Expected = $expected; ExistingSubnet = $existingSubnet })
            }
        }
        catch {
            Stop-ScriptGracefully -IndentLevel 2 -Message ("Subnet preflight failed; no subnet writes started: {0}. Earlier provisioning sections may already have committed changes." -f $_.Exception.Message)
        }
    }

    foreach ($plan in $plans) {
        Write-Status -IndentLevel 1 -Kind Info -Message ("Checking subnet [{0}]." -f $plan.Name)
        try {
            $existingSubnet = $plan.ExistingSubnet
            $changed = $false
            if ($null -eq $existingSubnet) {
                Write-Status -IndentLevel 3 -Kind Info -Message ("Creating subnet [{0}]." -f $plan.Name)
                $newParameters = @{ Name = $plan.Name; Server = $server; PassThru = $true; ErrorAction = 'Stop' }
                # Omit blank Site so AD can create an unlinked subnet.
                foreach ($field in $attributeMap.Keys) {
                    $ldapName = $attributeMap[$field]
                    if ($plan.Expected.Contains($ldapName) -and $plan.Expected[$ldapName].Length -gt 0) {
                        $newParameters[$field] = $plan.Expected[$ldapName]
                    }
                }
                Assert-LabInventoryHealthy
                $createdSubnet = New-ADReplicationSubnet @newParameters
                Add-LabGeneratedADObject -Kind Subnet -Object $createdSubnet
                if ($null -eq $createdSubnet) { throw 'Subnet creation returned no object.' }
                $subnetDN = [string]$createdSubnet.DistinguishedName
                $subnetGuid = [guid]$createdSubnet.ObjectGUID
            }
            else {
                $subnetDN = [string]$existingSubnet.DistinguishedName
                $subnetGuid = [guid]$existingSubnet.ObjectGUID
                $replace = @{}
                $clear = @()
                foreach ($ldapName in $plan.Expected.Keys) {
                    $current = [string]$existingSubnet.$ldapName
                    $desired = [string]$plan.Expected[$ldapName]
                    if (($ldapName -eq 'siteObject' -and $current -ieq $desired) -or
                        ($ldapName -ne 'siteObject' -and $current -ceq $desired)) { continue }
                    if ($desired.Length -eq 0) { $clear += $ldapName }
                    else { $replace[$ldapName] = $desired }
                }
                if ($replace.Count -gt 0 -or $clear.Count -gt 0) {
                    Write-Status -IndentLevel 3 -Kind Info -Message ("Restoring changed subnet fields for [{0}]." -f $plan.Name)
                    $setParameters = @{ Identity = $subnetDN; Server = $server; ErrorAction = 'Stop' }
                    if ($replace.Count -gt 0) { $setParameters['Replace'] = $replace }
                    if ($clear.Count -gt 0) { $setParameters['Clear'] = $clear }
                    Set-ADReplicationSubnet @setParameters
                    $changed = $true
                }
            }
            if ([string]::IsNullOrWhiteSpace($subnetDN) -or $subnetGuid -eq [guid]::Empty) {
                throw 'Subnet provisioning returned no distinguished name or object GUID.'
            }
            $verified = Get-ADObject -Identity $subnetDN -Properties $readProperties -Server $server -ErrorAction Stop
            if ($null -eq $verified -or $verified.ObjectClass -ine 'subnet' -or
                [guid]$verified.ObjectGUID -ne $subnetGuid -or $verified.Name -ine $plan.Name) {
                throw 'Read-back did not return the expected subnet identity.'
            }
            foreach ($ldapName in $plan.Expected.Keys) {
                $actual = [string]$verified.$ldapName
                $desired = [string]$plan.Expected[$ldapName]
                if (($ldapName -eq 'siteObject' -and $actual -ine $desired) -or
                    ($ldapName -ne 'siteObject' -and $actual -cne $desired)) {
                    throw ("Read-back did not match subnet field [{0}]." -f $ldapName)
                }
            }
            if ($null -eq $existingSubnet) { $createdCount++ }
            elseif ($changed) { $updatedCount++ }
            else { $unchangedCount++ }
            Write-Status -IndentLevel 4 -Kind Success -Message ("Verified subnet [{0}]." -f $plan.Name)
        }
        catch {
            Stop-ScriptGracefully -IndentLevel 2 -Message ("Could not reconcile subnet [{0}]: {1}. Earlier writes may have committed. Check configuration-partition permissions and the object before retrying; no failover or rollback was attempted." -f $plan.Name, $_.Exception.Message)
        }
    }
    Add-LabProcessingCount -Category 'AD subnets' -Created $createdCount -Updated $updatedCount
    $summaryKind = 'Success'
    if ($skippedCount -gt 0) { $summaryKind = 'Warning' }
    Write-Status -IndentLevel 0 -Kind $summaryKind -Message ('AD subnets: {0} created, {1} updated, {2} already matched, {3} skipped. Unlisted subnets were not removed.' -f $createdCount, $updatedCount, $unchangedCount, $skippedCount)
    return [pscustomobject]@{
        VerifiedCount = $createdCount + $updatedCount + $unchangedCount
        CreatedCount = $createdCount
        UpdatedCount = $updatedCount
        UnchangedCount = $unchangedCount
        SkippedCount = $skippedCount
    }
}

# --- IP site-link baseline helpers (same Sites and Services section) -----
function Get-LabVerifiedSiteLinkObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Plan,
        [Parameter(Mandatory = $true)][guid]$Identity,
        [Parameter(Mandatory = $true)][string]$Server
    )
    if ($Identity -eq [guid]::Empty) { throw 'Site-link identity has an empty GUID.' }
    $object = Get-ADObject -Identity $Identity -Properties cost,replInterval,siteList -Server $Server -ErrorAction Stop
    if ($null -eq $object -or $object.ObjectClass -ine 'siteLink' -or
        [guid]$object.ObjectGUID -ne $Identity -or $object.Name -ine $Plan.Name -or
        $object.DistinguishedName -ine $Plan.ExpectedDN) {
        throw 'Site-link GUID, class, name or IP-transport parent changed; operation refused.'
    }
    return $object
}

function Test-LabSiteLinkManagedValues {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)]$Plan
    )
    $actualSites = @($Object.siteList | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    if ([int]$Object.cost -ne $Plan.Cost -or [int]$Object.replInterval -ne $Plan.Interval -or
        $actualSites.Count -ne $Plan.SiteDNs.Count) { return $false }
    foreach ($siteDN in $actualSites) {
        if ($Plan.SiteDNs -inotcontains $siteDN) { return $false }
    }
    return $true
}

function Ensure-LabSiteLinks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$SiteLinkDefinitions
    )
    Write-SectionHeader -Message 'Create/Update AD Sites and Services IP Site Links...'
    $createdCount = 0
    $updatedCount = 0
    $unchangedCount = 0
    try {
        $server = [string]$Domain.SelectedDomainController
        if ([string]::IsNullOrWhiteSpace($server)) { throw 'Site-link provisioning requires the selected writable DC.' }
        $plans = @()
        $seenNames = @{}
        if ($SiteLinkDefinitions.Count -gt 0) {
            $rootDse = Get-ADRootDSE -Server $server -ErrorAction Stop
            $configurationDN = [string]$rootDse.configurationNamingContext
            if ([string]::IsNullOrWhiteSpace($configurationDN)) { throw 'The configuration naming context was not returned.' }
            $siteContainer = 'CN=Sites,{0}' -f $configurationDN
            $transportDN = 'CN=IP,CN=Inter-Site Transports,{0}' -f $siteContainer
            $transport = Get-ADObject -Identity $transportDN -Server $server -ErrorAction Stop
            if ($transport.ObjectClass -ine 'interSiteTransport') { throw 'The IP transport container has an unexpected object class.' }
            foreach ($definition in $SiteLinkDefinitions) {
                if ($definition -isnot [System.Collections.IDictionary]) { throw 'Each site-link definition must be a hash table.' }
                $fields = @('Name','SitesIncluded','Cost','ReplicationFrequencyInMinutes')
                foreach ($field in $fields) {
                    if (-not $definition.Contains($field)) { throw ('Missing site-link field [{0}].' -f $field) }
                }
                foreach ($field in $definition.Keys) {
                    if ($fields -notcontains $field) { throw ('Unsupported site-link field [{0}].' -f $field) }
                }
                if ($definition.Name -isnot [string] -or $definition.Name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$' -or
                    $definition.Name -cne $definition.Name.Trim()) { throw 'Site-link Name must be a simple 1..63-character lab name.' }
                if ($definition.Name -ieq 'DEFAULTIPSITELINK') { throw 'DEFAULTIPSITELINK is excluded from managed site links.' }
                if ($seenNames.ContainsKey($definition.Name)) { throw 'Duplicate site-link names in Get-LabSiteLinkDefinitions.' }
                $seenNames[$definition.Name] = $true
                if ($definition.Cost -isnot [int] -or $definition.Cost -lt 1 -or $definition.Cost -gt 32767) {
                    throw 'Site-link Cost must be an integer from 1 through 32767.'
                }
                $interval = $definition.ReplicationFrequencyInMinutes
                if ($interval -isnot [int] -or $interval -lt 15 -or $interval -gt 10080 -or ($interval % 15) -ne 0) {
                    throw 'Site-link replication interval must be an integer multiple of 15 minutes from 15 through 10080.'
                }
                if ($definition.SitesIncluded -isnot [array] -or $definition.SitesIncluded.Count -lt 2) {
                    throw 'SitesIncluded must be an array naming at least two distinct existing sites.'
                }
                $siteDNs = @()
                $siteIdentities = @()
                $seenSites = @{}
                foreach ($siteName in $definition.SitesIncluded) {
                    if ($siteName -isnot [string] -or $siteName -cnotmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$') {
                        throw ('Invalid SitesIncluded site name [{0}]. Use the actual DNS-safe AD site Name (1..63 ASCII letters/digits/hyphens, starting and ending with a letter or digit), not its DisplayName or DN.' -f $siteName)
                    }
                    if ($seenSites.ContainsKey($siteName)) { throw 'A site-link definition contains duplicate sites.' }
                    $seenSites[$siteName] = $true
                    $siteDN = 'CN={0},{1}' -f $siteName,$siteContainer
                    $site = Get-ADObject -Identity $siteDN -Server $server -ErrorAction Stop
                    if ($null -eq $site -or $site.ObjectClass -ine 'site' -or $site.Name -ine $siteName -or
                        $site.DistinguishedName -ine $siteDN -or [guid]$site.ObjectGUID -eq [guid]::Empty) {
                        throw ('Site-link endpoint [{0}] has an unexpected identity or type.' -f $siteName)
                    }
                    $siteDNs += $siteDN
                    $siteIdentities += [pscustomobject]@{ Name=$siteName; DN=$siteDN; Guid=[guid]$site.ObjectGUID }
                }
                $escaped = ConvertTo-LdapFilterValue -Value $definition.Name
                $matches = @(Get-ADObject -LDAPFilter ('(name={0})' -f $escaped) -SearchBase $transportDN `
                    -SearchScope OneLevel -Properties cost,replInterval,siteList -Server $server -ErrorAction Stop)
                if ($matches.Count -gt 1) { throw ('Site link [{0}] is ambiguous.' -f $definition.Name) }
                $expectedDN = 'CN={0},{1}' -f $definition.Name,$transportDN
                $existing = $null
                if ($matches.Count -eq 1) {
                    $existing = $matches[0]
                    if ($existing.ObjectClass -ine 'siteLink' -or $existing.Name -ine $definition.Name -or
                        $existing.DistinguishedName -ine $expectedDN -or [guid]$existing.ObjectGUID -eq [guid]::Empty) {
                        throw 'Configured site-link name conflicts with an unexpected object identity or type.'
                    }
                }
                $plans += [pscustomobject]@{
                    Name=$definition.Name; ExpectedDN=$expectedDN; Existing=$existing
                    Cost=[int]$definition.Cost; Interval=[int]$interval
                    SiteDNs=[string[]]$siteDNs; SiteIdentities=$siteIdentities
                }
            }
        }
        # All definitions/endpoints pass preflight before any site-link write.
        foreach ($plan in $plans) {
            Write-Status -IndentLevel 1 -Kind Info -Message ('Checking IP site link [{0}] on [{1}].' -f $plan.Name,$server)
            foreach ($endpoint in $plan.SiteIdentities) {
                $site = Get-ADObject -Identity $endpoint.Guid -Server $server -ErrorAction Stop
                if ($null -eq $site -or $site.ObjectClass -ine 'site' -or [guid]$site.ObjectGUID -ne $endpoint.Guid -or
                    $site.Name -ine $endpoint.Name -or $site.DistinguishedName -ine $endpoint.DN) {
                    throw 'A site-link endpoint changed after preflight; no site-link write will be attempted.'
                }
            }
            $created = $null -eq $plan.Existing
            $changed = $false
            if ($created) {
                Write-Status -IndentLevel 3 -Kind Info -Message ('Creating IP site link [{0}].' -f $plan.Name)
                Assert-LabInventoryHealthy
                # Use explicit LDAP attributes; preserve AD defaults for all
                # unconfigured fields such as schedule/options/description.
                $link = New-ADObject -Name $plan.Name -Type siteLink -Path $transportDN `
                    -OtherAttributes @{ cost=$plan.Cost; replInterval=$plan.Interval; siteList=[string[]]$plan.SiteDNs } `
                    -Server $server -PassThru -ErrorAction Stop
                Add-LabGeneratedADObject -Kind SiteLink -Object $link
                if ($null -eq $link -or [guid]$link.ObjectGUID -eq [guid]::Empty) { throw 'Site-link creation returned no GUID.' }
                $identity = [guid]$link.ObjectGUID
            }
            else {
                $identity = [guid]$plan.Existing.ObjectGUID
                $current = Get-LabVerifiedSiteLinkObject -Plan $plan -Identity $identity -Server $server
                $replace = @{}
                if ([int]$current.cost -ne $plan.Cost) { $replace['cost'] = $plan.Cost }
                if ([int]$current.replInterval -ne $plan.Interval) { $replace['replInterval'] = $plan.Interval }
                $actualSites = @($current.siteList | ForEach-Object { [string]$_ } | Sort-Object -Unique)
                if ($actualSites.Count -ne $plan.SiteDNs.Count -or
                    @($actualSites | Where-Object { $plan.SiteDNs -inotcontains $_ }).Count -gt 0) {
                    $replace['siteList'] = [string[]]$plan.SiteDNs
                }
                if ($replace.Count -gt 0) {
                    Write-Status -IndentLevel 3 -Kind Info -Message ('Restoring changed site-link fields for [{0}]: {1}.' -f $plan.Name,(($replace.Keys | Sort-Object) -join ', '))
                    Assert-LabInventoryHealthy
                    Set-ADObject -Identity $identity -Replace $replace -Server $server -ErrorAction Stop
                    $changed = $true
                }
            }
            $verified = Get-LabVerifiedSiteLinkObject -Plan $plan -Identity $identity -Server $server
            if (-not (Test-LabSiteLinkManagedValues -Object $verified -Plan $plan)) {
                throw ('Site link [{0}] did not read back with its expected cost, replication interval and exact site membership.' -f $plan.Name)
            }
            if ($created) { $createdCount++ }
            elseif ($changed) { $updatedCount++ }
            else { $unchangedCount++ }
            Write-Status -IndentLevel 2 -Kind Success -Message ('Verified IP site link [{0}]: sites [{1}], cost {2}, replicate every {3} minutes.' -f $plan.Name,($plan.SiteIdentities.Name -join ', '),$plan.Cost,$plan.Interval)
        }
        Add-LabProcessingCount -Category 'AD site links' -Created $createdCount -Updated $updatedCount
        Write-Status -IndentLevel 0 -Kind Success -Message ('AD site links: {0} verified ({1} created, {2} updated, {3} already matched) on [{4}]. DEFAULTIPSITELINK and unlisted links were not modified.' -f ($createdCount+$updatedCount+$unchangedCount),$createdCount,$updatedCount,$unchangedCount,$server)
        return [pscustomobject]@{ CreatedCount=$createdCount; UpdatedCount=$updatedCount; UnchangedCount=$unchangedCount; VerifiedCount=($createdCount+$updatedCount+$unchangedCount) }
    }
    catch {
        Stop-ScriptGracefully -IndentLevel 2 -Message ('Site-link provisioning failed: {0} Earlier writes may have committed; no automatic rollback or DC failover was attempted.' -f $_.Exception.Message)
    }
}

# --- WMI filter baseline helpers (before GPO baseline helpers) -----------
function Get-LabWmiFilterAuthor {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$DomainDNSRoot)

    # Follow the requested current-domain expression, not the operator UPN.
    # Dispose the discovery object; every actual AD read/write uses our DC.
    $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    try {
        $domainName = [string]$currentDomain.Name
        if ([string]::IsNullOrWhiteSpace($domainName) -or $domainName -ine $DomainDNSRoot) {
            throw 'The current domain does not match the selected provisioning domain; no WMI filter writes will be attempted.'
        }
        return ('Administrator@' + $domainName)
    }
    finally {
        if ($null -ne $currentDomain) { $currentDomain.Dispose() }
    }
}

function ConvertTo-LabWmiFilterQueryData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Namespace,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Queries
    )

    if ($Namespace -cnotmatch '^root\\[A-Za-z0-9_]+(?:\\[A-Za-z0-9_]+)*$') {
        throw 'WMI namespace must be a local root\... namespace without delimiters.'
    }
    if ($Queries.Count -lt 1) { throw 'Each WMI filter must contain at least one WQL query.' }
    # GPMC msWMI-Parm2 encoding: count; then, for each query,
    # language-length;namespace-length;query-length;language;namespace;query;
    # Lengths are .NET UTF-16 character counts, not bytes or escaped strings.
    $parts = New-Object System.Text.StringBuilder
    [void]$parts.Append($Queries.Count.ToString([Globalization.CultureInfo]::InvariantCulture)).Append(';')
    foreach ($query in $Queries) {
        if ($query -isnot [string] -or [string]::IsNullOrWhiteSpace($query) -or
            $query.IndexOf([char]0) -ge 0 -or $query -notmatch '(?is)^\s*SELECT\s+.+\s+FROM\s+') {
            throw 'WMI queries must be nonblank SELECT ... FROM ... WQL strings without NUL characters.'
        }
        if ([regex]::Matches($query, '(?i)\bSELECT\b').Count -ne 1) {
            throw 'Put separate SELECT statements in separate Queries entries; they are ANDed by Group Policy.'
        }
        # A structural guard, NOT a complete WQL compiler or target evaluation.
        # Preserve WQL backslash escapes; mask quoted strings before counting.
        $unquoted = [regex]::Replace($query, '"(?:\\.|[^"\\])*"|''(?:\\.|[^''\\])*''', '')
        if ($unquoted.Contains('"') -or $unquoted.Contains("'")) { throw 'A WQL query contains an unmatched quote.' }
        [void]$parts.AppendFormat([Globalization.CultureInfo]::InvariantCulture,
            '3;{0};{1};WQL;{2};{3};', $Namespace.Length, $query.Length, $Namespace, $query)
    }
    return $parts.ToString()
}

function Assert-LabWmiFilterIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$ContainerDN,
        [Parameter(Mandatory = $true)][string]$FilterName,
        [guid]$ExpectedObjectGuid = [guid]::Empty,
        [string]$ExpectedFilterId = ''
    )

    if ($null -eq $Object -or $Object.ObjectClass -ine 'msWMI-Som' -or
        [guid]$Object.ObjectGUID -eq [guid]::Empty -or
        $Object.'msWMI-Name' -ine $FilterName) { throw 'WMI filter name, type or object GUID conflicts with the expected identity.' }
    $filterId = [string]$Object.'msWMI-ID'
    $id = [guid]::Empty
    if ($filterId -notmatch '^\{[0-9A-Fa-f-]{36}\}$' -or -not [guid]::TryParse($filterId, [ref]$id) -or
        $id -eq [guid]::Empty -or $Object.Name -ine $filterId -or
        $Object.DistinguishedName -ine ('CN={0},{1}' -f $Object.Name, $ContainerDN)) {
        throw 'WMI filter CN, msWMI-ID or parent container is inconsistent; refusing identity repair or adoption.'
    }
    if (($ExpectedObjectGuid -ne [guid]::Empty -and [guid]$Object.ObjectGUID -ne $ExpectedObjectGuid) -or
        (-not [string]::IsNullOrEmpty($ExpectedFilterId) -and $filterId -ine $ExpectedFilterId)) {
        throw 'WMI filter identity changed after preflight; no automatic retargeting is allowed.'
    }
}

function Ensure-LabWmiFilters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.IDictionary]$Definitions
    )

    Write-SectionHeader -Message 'Create/Update WMI filters...'
    # Never let a failed new batch leave stale references from an earlier run.
    $script:LabWmiFilterObjects = [ordered]@{}
    $objects = [ordered]@{}
    $createdCount = 0
    $updatedCount = 0
    $unchangedCount = 0
    try {
        $server = [string]$Domain.SelectedDomainController
        $domainDN = [string]$Domain.DistinguishedName
        if ([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($domainDN)) {
            throw 'WMI filter provisioning requires the selected writable DC and domain DN.'
        }
        $plans = @()
        $properties = @('msWMI-Name','msWMI-Author','msWMI-Parm1','msWMI-Parm2',
            'msWMI-ID','msWMI-CreationDate','msWMI-ChangeDate')
        if ($Definitions.Count -gt 0) {
            $author = Get-LabWmiFilterAuthor -DomainDNSRoot ([string]$Domain.DNSRoot)
            $containerDN = 'CN=SOM,CN=WMIPolicy,CN=System,{0}' -f $domainDN
            # A normal domain has this infrastructure. Missing/denied access
            # is fatal; do not create parent containers or bypass their ACLs.
            $container = Get-ADObject -Identity $containerDN -Server $server -ErrorAction Stop
            if ($null -eq $container -or $container.ObjectClass -ine 'container' -or
                $container.DistinguishedName -ine $containerDN -or [guid]$container.ObjectGUID -eq [guid]::Empty) {
                throw 'The WMI filter SOM container was not verified on the selected DC.'
            }
            $seenNames = @{}
            $seenGuids = @{}
            foreach ($key in $Definitions.Keys) {
                if ($key -isnot [string] -or $key -cnotmatch '^[A-Za-z][A-Za-z0-9_]*$') { throw 'WMI filter keys must be stable simple identifiers.' }
                $definition = $Definitions[$key]
                $fields = @('Name','Description','Namespace','Queries')
                if ($definition -isnot [System.Collections.IDictionary]) { throw 'Each WMI filter definition must be a hash table.' }
                foreach ($field in $fields) {
                    if (-not $definition.Contains($field)) { throw ('WMI filter [{0}] is missing field [{1}].' -f $key, $field) }
                }
                foreach ($field in $definition.Keys) {
                    if ($fields -notcontains $field) { throw ('Unsupported WMI filter field [{0}].' -f $field) }
                }
                $name = $definition.Name
                if ($name -isnot [string] -or [string]::IsNullOrWhiteSpace($name) -or $name -cne $name.Trim() -or $name.IndexOf([char]0) -ge 0) {
                    throw ('WMI filter [{0}] requires a nonblank, trimmed Name.' -f $key)
                }
                if ($definition.Description -isnot [string] -or $definition.Description.IndexOf([char]0) -ge 0 -or
                    $definition.Namespace -isnot [string] -or $definition.Queries -isnot [array]) {
                    throw ('WMI filter [{0}] needs string Description/Namespace and an explicit Queries array.' -f $key)
                }
                if ($seenNames.ContainsKey($name)) { throw ('Duplicate WMI filter Name [{0}].' -f $name) }
                $seenNames[$name] = $true
                $queryData = ConvertTo-LabWmiFilterQueryData -Namespace $definition.Namespace -Queries $definition.Queries
                # Resolve the visible baseline name first. A GUID-shaped CN
                # identifies the filter, but is not its human-readable name.
                $ldap = '(msWMI-Name={0})' -f (ConvertTo-LdapFilterValue -Value $name)
                $creationLdap = $ldap
                $alias = ''
                $aliasLdap = ''
                $syntheticDefinitions = Get-LabWmiFilterADChangeDefinitions
                if ($syntheticDefinitions.Contains($key) -and $syntheticDefinitions[$key].Contains('Name')) {
                    $alias = [string]$syntheticDefinitions[$key]['Name']
                    if (-not [string]::IsNullOrWhiteSpace($alias) -and $alias -ine $name) {
                        $aliasLdap = '(msWMI-Name={0})' -f (ConvertTo-LdapFilterValue -Value $alias)
                        $creationLdap = '(|{0}{1})' -f $ldap, $aliasLdap
                    }
                }
                # Do not combine baseline/alias results when resolving an
                # existing object. Distinct display names are not duplicates.
                # Do not hide wrong-type collisions with an objectClass filter.
                $matches = @(Get-ADObject -LDAPFilter $ldap -SearchBase $containerDN -SearchScope OneLevel `
                    -Properties $properties -Server $server -ErrorAction Stop)
                $resolvedName = $name
                if ($matches.Count -eq 0 -and -not [string]::IsNullOrEmpty($aliasLdap)) {
                    $matches = @(Get-ADObject -LDAPFilter $aliasLdap -SearchBase $containerDN -SearchScope OneLevel `
                        -Properties $properties -Server $server -ErrorAction Stop)
                    $resolvedName = $alias
                }
                if ($matches.Count -gt 1) {
                    $conflictingGuids = (@($matches | ForEach-Object { [string]$_.ObjectGUID }) -join ', ')
                    throw ('WMI filter display name [{0}] matches {1} objects. Resolve the exact-name duplicates before rerunning. Object GUIDs: {2}. No object was selected, merged or deleted.' -f $resolvedName, $matches.Count, $conflictingGuids)
                }
                $existing = $null
                $filterId = ''
                if ($matches.Count -eq 1) {
                    $existing = $matches[0]
                    Assert-LabWmiFilterIdentity -Object $existing -ContainerDN $containerDN -FilterName $resolvedName
                    $guidKey = ([guid]$existing.ObjectGUID).ToString()
                    if ($seenGuids.ContainsKey($guidKey)) { throw 'Multiple WMI definitions resolved to the same AD object GUID.' }
                    $seenGuids[$guidKey] = $true
                    $filterId = [string]$existing.'msWMI-ID'
                }
                else {
                    # Allocate a new ID only when neither visible name exists.
                    $filterId = [guid]::NewGuid().ToString('B').ToUpperInvariant()
                }
                $plans += [pscustomobject]@{
                    Key=$key; FilterName=$name; Existing=$existing; FilterId=$filterId; LdapFilter=$creationLdap
                    Expected=@{ 'msWMI-Name'=$name; 'msWMI-Author'=$author;
                        'msWMI-Parm1'=$definition.Description; 'msWMI-Parm2'=$queryData }
                }
            }
        }
        # All definitions, encoding and existing identities pass before writes.
        foreach ($plan in $plans) {
            Write-Status -Kind Info -Message ('Checking WMI filter [{0}] (key [{1}]) on [{2}].' -f $plan.FilterName, $plan.Key, $server)
            $created = $null -eq $plan.Existing
            $changed = $false
            $expectedChangeDate = ''
            $expectedCreationDate = ''
            if ($created) {
                $lateMatches = @(Get-ADObject -LDAPFilter $plan.LdapFilter -SearchBase $containerDN -SearchScope OneLevel `
                    -Properties $properties -Server $server -ErrorAction Stop)
                if ($lateMatches.Count -ne 0) { throw 'A same-name WMI filter appeared after preflight; refusing a duplicate creation.' }
                $stamp = [DateTime]::UtcNow.ToString('yyyyMMddHHmmss.ffffff', [Globalization.CultureInfo]::InvariantCulture) + '-000'
                $attributes = @{'msWMI-ID'=$plan.FilterId; 'msWMI-CreationDate'=$stamp; 'msWMI-ChangeDate'=$stamp}
                foreach ($attribute in $plan.Expected.Keys) {
                    # AD does not accept a zero-length attribute value; an
                    # absent Parm1 represents a deliberately blank description.
                    if ($plan.Expected[$attribute] -cne '') { $attributes[$attribute] = $plan.Expected[$attribute] }
                }
                Write-Status -IndentLevel 3 -Kind Info -Message ('Creating WMI filter [{0}].' -f $plan.FilterName)
                Assert-LabInventoryHealthy
                $newObject = New-ADObject -Name $plan.FilterId -Type 'msWMI-Som' -Path $containerDN `
                    -OtherAttributes $attributes -Server $server -PassThru -ErrorAction Stop
                Add-LabGeneratedADObject -Kind WmiFilter -Object $newObject
                if ($null -eq $newObject -or [guid]$newObject.ObjectGUID -eq [guid]::Empty) { throw 'WMI filter creation returned no object GUID.' }
                $identity = [guid]$newObject.ObjectGUID
                $expectedCreationDate = $stamp
                $expectedChangeDate = $stamp
            }
            else {
                $identity = [guid]$plan.Existing.ObjectGUID
                Write-Status -IndentLevel 3 -Kind Info -Message ('Using existing WMI filter [{0}]; object GUID [{1}]; filter ID [{2}].' -f $plan.Existing.'msWMI-Name', $identity, $plan.FilterId)
                if ([string]$plan.Existing.'msWMI-Name' -ine $plan.FilterName) {
                    # The baseline name was absent during preflight. Do not
                    # rename an alias over an independently created filter.
                    $baselineLdap = '(msWMI-Name={0})' -f (ConvertTo-LdapFilterValue -Value $plan.FilterName)
                    $lateBaseline = @(Get-ADObject -LDAPFilter $baselineLdap -SearchBase $containerDN -SearchScope OneLevel `
                        -Properties $properties -Server $server -ErrorAction Stop)
                    if ($lateBaseline.Count -ne 0) { throw 'The baseline WMI filter name appeared after alias preflight; rerun to resolve by baseline name without creating duplicates.' }
                }
                $current = Get-ADObject -Identity $identity -Properties $properties -Server $server -ErrorAction Stop
                Assert-LabWmiFilterIdentity -Object $current -ContainerDN $containerDN -FilterName ([string]$plan.Existing.'msWMI-Name') `
                    -ExpectedObjectGuid $identity -ExpectedFilterId $plan.FilterId
                $expectedCreationDate = [string]$current.'msWMI-CreationDate'
                $expectedChangeDate = [string]$current.'msWMI-ChangeDate'
                $replace = @{}
                $clear = @()
                foreach ($attribute in $plan.Expected.Keys) {
                    if ([string]$current.$attribute -cne $plan.Expected[$attribute]) {
                        if ($plan.Expected[$attribute] -ceq '') { $clear += $attribute }
                        else { $replace[$attribute] = $plan.Expected[$attribute] }
                    }
                }
                if ($replace.Count -gt 0 -or $clear.Count -gt 0) {
                    $expectedChangeDate = [DateTime]::UtcNow.ToString('yyyyMMddHHmmss.ffffff', [Globalization.CultureInfo]::InvariantCulture) + '-000'
                    $replace['msWMI-ChangeDate'] = $expectedChangeDate
                    $parameters = @{ Identity=$identity; Replace=$replace; Server=$server; ErrorAction='Stop' }
                    if ($clear.Count -gt 0) { $parameters.Clear = [string[]]$clear }
                    Write-Status -IndentLevel 3 -Kind Info -Message ('Restoring WMI filter baseline [{0}]: {1}.' -f $plan.FilterName, ((@($replace.Keys)+$clear | Sort-Object) -join ', '))
                    Set-ADObject @parameters
                    $changed = $true
                }
            }
            $verified = Get-ADObject -Identity $identity -Properties $properties -Server $server -ErrorAction Stop
            Assert-LabWmiFilterIdentity -Object $verified -ContainerDN $containerDN -FilterName $plan.FilterName `
                -ExpectedObjectGuid $identity -ExpectedFilterId $plan.FilterId
            foreach ($attribute in $plan.Expected.Keys) {
                if ([string]$verified.$attribute -cne $plan.Expected[$attribute]) { throw ('WMI filter [{0}] read-back failed for [{1}].' -f $plan.FilterName, $attribute) }
            }
            if ([string]$verified.'msWMI-CreationDate' -cne $expectedCreationDate -or
                [string]$verified.'msWMI-ChangeDate' -cne $expectedChangeDate) { throw 'WMI filter creation/change metadata did not verify.' }
            $objects[$plan.Key] = [pscustomobject]@{
                Key=$plan.Key; Name=$plan.FilterName; FilterId=$plan.FilterId
                ObjectGUID=$identity; DistinguishedName=[string]$verified.DistinguishedName
            }
            if ($created) { $createdCount++ }
            elseif ($changed) { $updatedCount++ }
            else { $unchangedCount++ }
            if ($created -or $changed) {
                Write-Status -IndentLevel 2 -Kind Success -Message ('Verified WMI filter [{0}]; ID [{1}].' -f $plan.FilterName, $plan.FilterId)
            }
            else {
                Write-Status -Kind Info -Message ('WMI filter [{0}] already matches its baseline; no values or timestamps changed.' -f $plan.FilterName)
            }
        }
        # Publish only after the complete batch verifies successfully.
        $script:LabWmiFilterObjects = $objects
        Write-Status -IndentLevel 0 -Kind Success -Message ('WMI filters: {0} verified ({1} created, {2} updated, {3} already matched) on [{4}].' -f $objects.Count, $createdCount, $updatedCount, $unchangedCount, $server)
        Add-LabProcessingCount -Category 'WMI filters' -Created $createdCount -Updated $updatedCount
        return [pscustomobject]@{ CreatedCount=$createdCount; UpdatedCount=$updatedCount;
            UnchangedCount=$unchangedCount; VerifiedCount=$objects.Count }
    }
    catch {
        Stop-ScriptGracefully -IndentLevel 2 -Message ('WMI filter provisioning failed: {0} Earlier writes may have committed; no rollback, ACL bypass or DC failover was attempted.' -f $_.Exception.Message)
    }
}

function Initialize-LabGroupPolicyTools {
    [CmdletBinding()]
    param()

    # Normally already imported by the post-rights module preflight.
    # Keep this helper usable independently without silently autoloading.
    if (-not (Get-Module -Name GroupPolicy -ErrorAction Stop)) {
        if (-not (Import-LabPrerequisiteModule -Name GroupPolicy -Purpose 'GPO baseline and synthetic GPO changes')) {
            Stop-ScriptGracefully -IndentLevel 2 -Message 'The GroupPolicy module is required for this script''s GPO workflow. Install/repair GPMC/RSAT, then retry. No prompts or provisioning were started.'
        }
    }
    try {
        foreach ($command in @('Get-GPO', 'New-GPO', 'Backup-GPO', 'Get-GPOReport', 'Get-GPRegistryValue', 'Set-GPRegistryValue', 'Remove-GPRegistryValue')) {
            Get-Command -Name $command -Module GroupPolicy -ErrorAction Stop | Out-Null
        }
    }
    catch {
        Write-Status -IndentLevel 2 -Kind Warning -BackgroundColor Red -Message ('Required GroupPolicy commands are missing/unavailable; GPO functions will not work: {0}' -f $_.Exception.Message)
        Stop-ScriptGracefully -IndentLevel 2 -Message 'Required GPO commands are unavailable. No prompts or provisioning were started.'
    }
    Write-Status -Kind Success -Message 'GroupPolicy module and required GPO commands are available.'
}

function Test-LabGpoMissingRegistrySettingError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord,
        [Parameter(Mandatory = $true)][string]$Key
    )

    if ($ErrorRecord.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::ObjectNotFound -or
        $ErrorRecord.FullyQualifiedErrorId -match '^(RegistryKeyNotFound|RegistryValueNotFound|KeyNotFound|ValueNotFound),') {
        return $true
    }
    # GroupPolicy also reports an absent Registry.pol KEY as ArgumentException
    # (keyPath), including after removal of its last value. Do not accept all
    # ArgumentExceptions: require this exact not-found message and query path.
    # Unknown/localized variants fail closed rather than hiding real failures.
    $expected = $Key -replace '^(?i:HKLM)(?=\\|$)', 'HKEY_LOCAL_MACHINE'
    $expected = $expected -replace '^(?i:HKCU)(?=\\|$)', 'HKEY_CURRENT_USER'
    $exception = $ErrorRecord.Exception
    while ($null -ne $exception) {
        if ($exception -is [System.ArgumentException] -and $exception.ParamName -ceq 'keyPath' -and
            $exception.Message -cmatch '^The following Group Policy registry setting was not found:\s*"([^"\r\n]+)"\.(?:\s|$)') {
            $reported = $Matches[1] -replace '^(?i:HKLM)(?=\\|$)', 'HKEY_LOCAL_MACHINE'
            $reported = $reported -replace '^(?i:HKCU)(?=\\|$)', 'HKEY_CURRENT_USER'
            if ($reported -ieq $expected) { return $true }
        }
        $exception = $exception.InnerException
    }
    return $false
}

function Get-LabGpoRegistrySetting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][guid]$Guid,
        [Parameter(Mandatory = $true)][string]$DomainName,
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][string]$ValueName
    )

    try {
        # Read the values directly under the KEY, then select the VALUE NAME.
        # Querying an absent -ValueName can throw ArgumentException (keyPath)
        # even though the registry key exists. An absent value is normal for
        # initialization and is not the same as a failed directory/GPO read.
        # Results can contain both value records and child-key navigation
        # records. Navigation records may omit HasValue and ValueName entirely.
        # Inspect property metadata before accessing optional properties so
        # Set-StrictMode remains enabled and malformed values are not hidden.
        $entries = @(Get-GPRegistryValue -Guid $Guid -Domain $DomainName -Server $Server `
            -Key $Key -ErrorAction Stop)
        $settings = @(
            foreach ($entry in $entries) {
                if ($null -eq $entry) { throw 'The GPO registry read returned a null entry.' }
                $properties = $entry.PSObject.Properties
                $hasValueProperty = $properties['HasValue']
                $nameProperty = $properties['ValueName']
                if ($null -eq $nameProperty) {
                    if ($null -ne $hasValueProperty -and [bool]$hasValueProperty.Value) {
                        throw 'The GPO registry value record is missing ValueName.'
                    }
                    if ($null -ne $properties['KeyPath'] -or $null -ne $properties['FullKeyPath']) {
                        continue
                    }
                    throw 'The GPO registry read returned an unrecognized object without value or key metadata.'
                }
                if ($null -ne $hasValueProperty -and -not [bool]$hasValueProperty.Value) {
                    continue
                }
                if ([string]$nameProperty.Value -ine $ValueName) { continue }
                # A real value can be identified by its name and payload even
                # if this module version does not expose the optional flag.
                foreach ($requiredProperty in @('PolicyState', 'Type', 'Value')) {
                    if ($null -eq $properties[$requiredProperty]) {
                        throw ('The GPO registry value [{0}] is missing [{1}] metadata.' -f $ValueName, $requiredProperty)
                    }
                }
                $entry
            }
        )
        if ($settings.Count -gt 1) { throw 'The GPO read returned multiple settings for one registry value.' }
        if ($settings.Count -eq 0) {
            return [pscustomobject]@{ Configured = $false; PolicyState = 'NotConfigured'; Type = $null; Value = $null }
        }
        $setting = $settings[0]
        if ($setting.ValueName -ine $ValueName) {
            throw 'The GPO read did not return the requested registry value.'
        }
        return [pscustomobject]@{
            Configured = $true
            PolicyState = [string]$setting.PolicyState
            Type = [string]$setting.Type
            Value = $setting.Value
        }
    }
    catch {
        # Do not treat permission, connectivity, parsing or arbitrary errors as
        # Not Configured. Accept only an explicit missing-key/value condition.
        $missingSetting = Test-LabGpoMissingRegistrySettingError -ErrorRecord $_ -Key $Key
        if (-not $missingSetting) { throw }
        # Reconfirm the GPO and its GPT on this SAME DC. A missing GPO, broken
        # SYSVOL share or access failure must not become a new-setting write.
        $confirmedGpo = Get-GPO -Guid $Guid -Domain $DomainName -Server $Server -ErrorAction Stop
        if ([guid]$confirmedGpo.Id -ne $Guid) { throw 'The GPO identity changed during the registry read.' }
        $gptIni = '\\{0}\SYSVOL\{1}\Policies\{{{2}}}\GPT.INI' -f $Server, $DomainName, $Guid
        Get-Content -LiteralPath $gptIni -ErrorAction Stop | Out-Null
        return [pscustomobject]@{ Configured = $false; PolicyState = 'NotConfigured'; Type = $null; Value = $null }
    }
}

function Assert-LabGpoSettingValue {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Setting)

    if ($Setting.Storage -ieq 'AdvancedAudit') {
        if ($Setting.Type -ine 'AuditFlags' -or $Setting.Value -isnot [int] -or $Setting.Value -lt 0 -or $Setting.Value -gt 3 -or
            $Setting.ValueName -notmatch '^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$') {
            throw 'AdvancedAudit requires a braced subcategory GUID, Type AuditFlags and integer Value 0..3.'
        }
        if (-not $Setting.Contains('GpoDisplayName') -or [string]::IsNullOrWhiteSpace([string]$Setting.GpoDisplayName) -or
            $Setting.GpoDisplayName -match '[,"\r\n]') { throw 'AdvancedAudit requires a CSV-safe GpoDisplayName.' }
        return
    }
    if ($Setting.Storage -ieq 'AccountPolicy') {
        if ($Setting.Type -ine 'Integer' -or
            ($Setting.Value -isnot [int] -and $Setting.Value -isnot [uint32] -and $Setting.Value -isnot [long])) {
            throw 'Native AccountPolicy values require Type Integer and an integer Value.'
        }
        if (-not $Setting.Contains('Section') -or $Setting.Section -isnot [string]) { throw 'Native AccountPolicy requires a Section.' }
        $minimum = 0
        $maximum = 99999
        switch ('{0}|{1}' -f $Setting.Section, $Setting.ValueName) {
            'Kerberos Policy|MaxTicketAge' { break }
            'Kerberos Policy|MaxServiceAge' { $minimum = 10; break }
            'System Access|ClearTextPassword' { $maximum = 1; break }
            'System Access|LockoutBadCount' { $maximum = 999; break }
            default { throw ('Unsupported native AccountPolicy [{0}] in [{1}].' -f $Setting.ValueName, $Setting.Section) }
        }
        if ($Setting.Value -lt $minimum -or $Setting.Value -gt $maximum) {
            throw ('AccountPolicy [{0}] requires a Value in {1}..{2} in its documented native units.' -f $Setting.ValueName, $minimum, $maximum)
        }
        return
    }
    if ($Setting.Contains('ReportValueType') -and ($Setting.ReportValueType -cne 'BooleanOrNumber' -or
        $Setting.Storage -ine 'SecurityOptions' -or $Setting.Type -ine 'DWord' -or $Setting.Value -notin @(0,1))) {
        throw 'BooleanOrNumber report verification requires a native Boolean-valued DWORD (0 or 1).'
    }
    if ($Setting.Type -ieq 'DWord') {
        if (($Setting.Value -isnot [int] -and $Setting.Value -isnot [uint32] -and $Setting.Value -isnot [long]) -or
            $Setting.Value -lt 0 -or $Setting.Value -gt [uint32]::MaxValue) {
            throw ('GPO setting [{0}] requires an unsigned 32-bit integer Value.' -f $Setting.ValueName)
        }
        return
    }
    if ($Setting.Type -ieq 'MultiString' -and $Setting.Storage -ieq 'RegistryPolicy') {
        if ($Setting.Value -isnot [System.Array] -or $Setting.Value.Count -eq 0) {
            throw ('Registry MultiString [{0}] requires a nonempty array of strings.' -f $Setting.ValueName)
        }
        foreach ($item in $Setting.Value) {
            if ($item -isnot [string] -or [string]::IsNullOrWhiteSpace($item) -or $item.IndexOf([char]0) -ge 0) {
                throw ('Registry MultiString [{0}] contains an invalid string element.' -f $Setting.ValueName)
            }
        }
        return
    }
    throw ('Unsupported type/storage for [{0}]: native SecurityOptions require DWord; AccountPolicy requires Integer; RegistryPolicy supports DWord or MultiString.' -f $Setting.ValueName)
}

function Test-LabGpoRegistrySettingMatches {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Current,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Desired
    )
    if (-not $Current.Configured -or $Current.PolicyState -ine 'Set' -or $Current.Type -ine $Desired.Type) { return $false }
    if ($Desired.Type -ieq 'DWord') { return ([long]$Current.Value -eq [long]$Desired.Value) }
    if ($Desired.Type -ieq 'MultiString') {
        if ($Current.Value -isnot [System.Array] -or $Current.Value.Count -ne $Desired.Value.Count) { return $false }
        for ($i = 0; $i -lt $Desired.Value.Count; $i++) {
            if ($Current.Value[$i] -isnot [string] -or $Current.Value[$i] -ine $Desired.Value[$i]) { return $false }
        }
        return $true
    }
    return $false
}

function Format-LabGpoRegistrySetting {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Setting)

    if (-not $Setting.Configured) { return '<Not Configured>' }
    if ($Setting.PolicyState -ine 'Set') {
        return ('<{0}; Type={1}; Value={2}>' -f $Setting.PolicyState, $Setting.Type, ($Setting.Value | ConvertTo-Json -Compress -Depth 4))
    }
    return ('{0} {1}' -f $Setting.Type, ($Setting.Value | ConvertTo-Json -Compress -Depth 4))
}

function Get-LabGpoIniEntry {
    # INI snapshots retain blank lines, including the empty element produced
    # by a trailing newline. Permit these elements as well as an empty array.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Lines,
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][string]$Key
    )
    $sectionIndex = -1
    $sectionEnd = $Lines.Count
    $entryIndex = -1
    $entryValue = $null
    $inSection = $false
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $line = $Lines[$i]
        if ($line -match '^\s*\[([^\]]+)\]\s*$') {
            if ($inSection) { $sectionEnd = $i; $inSection = $false }
            if ($Matches[1].Trim() -ieq $Section) {
                if ($sectionIndex -ge 0) { throw ('Duplicate INI section [{0}].' -f $Section) }
                $sectionIndex = $i
                $inSection = $true
            }
            continue
        }
        if (-not $inSection -or $line -match '^\s*(;|$)') { continue }
        if ($line -match '^\s*("[^"]+"|[^=]+?)\s*=\s*(.*?)\s*$') {
            $entryKey = $Matches[1].Trim().Trim('"')
            $value = $Matches[2]
            if ($entryKey -ieq $Key) {
                if ($entryIndex -ge 0) { throw ('Duplicate INI key [{0}] in [{1}].' -f $Key, $Section) }
                $entryIndex = $i
                $entryValue = $value
            }
        }
    }
    return [pscustomobject]@{ SectionIndex = $sectionIndex; SectionEnd = $sectionEnd; Index = $entryIndex; Value = $entryValue }
}

function Set-LabGpoIniEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Lines,
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value
    )
    $entry = Get-LabGpoIniEntry -Lines $Lines -Section $Section -Key $Key
    $result = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in $Lines) { [void]$result.Add($line) }
    if ($entry.Index -ge 0) { $result[$entry.Index] = '{0}={1}' -f $Key, $Value }
    elseif ($entry.SectionIndex -ge 0) { $result.Insert($entry.SectionEnd, ('{0}={1}' -f $Key, $Value)) }
    else {
        if ($result.Count -gt 0 -and $result[$result.Count - 1] -ne '') { [void]$result.Add('') }
        [void]$result.Add(('[' + $Section + ']'))
        [void]$result.Add(('{0}={1}' -f $Key, $Value))
    }
    return $result.ToArray()
}

function Get-LabGpoNativeEntry {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Setting)

    if ($Setting.Storage -ieq 'AccountPolicy') {
        Assert-LabGpoSettingValue -Setting $Setting
        return [pscustomobject]@{
            Section = [string]$Setting.Section
            Key = [string]$Setting.ValueName
            Value = ([uint32]$Setting.Value).ToString([Globalization.CultureInfo]::InvariantCulture)
        }
    }
    if ($Setting.Storage -ine 'SecurityOptions') { throw 'Only native security settings have a GptTmpl.inf entry.' }
    $key = ($Setting.Key -replace '^(HKLM|HKEY_LOCAL_MACHINE)\\', 'MACHINE\') + '\' + $Setting.ValueName
    return [pscustomobject]@{ Section = 'Registry Values'; Key = $key; Value = ('4,{0}' -f $Setting.Value) }
}

function Get-LabGpoSecurityValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Lines,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Setting
    )
    $mapping = Get-LabGpoNativeEntry -Setting $Setting
    $entry = Get-LabGpoIniEntry -Lines $Lines -Section $mapping.Section -Key $mapping.Key
    if ($entry.Index -lt 0) {
        return [pscustomobject]@{ Configured = $false; PolicyState = 'NotConfigured'; Type = $null; Value = $null }
    }
    if ($Setting.Storage -ieq 'AccountPolicy') {
        if ($entry.Value -notmatch '^[0-9]{1,5}$') { throw ('Malformed native AccountPolicy integer [{0}].' -f $Setting.ValueName) }
        $data = [uint32]::Parse($entry.Value, [Globalization.CultureInfo]::InvariantCulture)
        return [pscustomobject]@{ Configured = $true; PolicyState = 'Set'; Type = 'Integer'; Value = $data }
    }
    if ($entry.Value -notmatch '^4\s*,\s*(0[xX][0-9a-fA-F]+|[0-9]+)\s*$') {
        throw ('Native Security Option [{0}] is not a supported DWORD entry: [{1}].' -f $Setting.ValueName, $entry.Value)
    }
    $number = $Matches[1]
    $data = if ($number -match '^0[xX]') { [Convert]::ToUInt32($number.Substring(2), 16) } else { [uint32]::Parse($number, [Globalization.CultureInfo]::InvariantCulture) }
    return [pscustomobject]@{ Configured = $true; PolicyState = 'Set'; Type = 'DWord'; Value = $data }
}

function Merge-LabGpoSecurityExtension {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Extensions = '')

    # MS-GPSB 1.9; preserve existing CSE/tool groups and sort by CSE GUID.
    $securityCse = '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'
    $securityTool = '{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}'
    $guidPattern = '\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}'
    $groups = [regex]::Matches($Extensions, ('\[(?:' + $guidPattern + '){2,}\]'))
    if ((($groups | ForEach-Object { $_.Value }) -join '') -cne $Extensions) { throw 'Malformed GPO machine-extension list; refusing to replace it.' }
    $items = @{}
    foreach ($group in $groups) {
        $guids = @([regex]::Matches($group.Value, $guidPattern) | ForEach-Object { $_.Value })
        $cse = $guids[0]
        if ($items.ContainsKey($cse)) { throw 'Duplicate CSE groups in GPO machine-extension list.' }
        $items[$cse] = $group.Value
        if ($cse -ieq $securityCse -and $guids -inotcontains $securityTool) {
            $items[$cse] = $group.Value.Substring(0, $group.Value.Length - 1) + $securityTool + ']'
        }
    }
    if (-not $items.ContainsKey($securityCse)) { $items[$securityCse] = '[' + $securityCse + $securityTool + ']' }
    return (($items.Keys | Sort-Object | ForEach-Object { $items[$_] }) -join '')
}

function Get-LabGpoNextComputerVersion {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][uint32]$Version)
    # Do not allow a rollover to silently reset the machine version.
    if (($Version -band 65535) -eq 65535) { throw 'GPO computer-version rollover requires manual review; no native write was started.' }
    return [uint32]([long]$Version + 1)
}

function Get-LabGpoFileSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$Optional,
        [switch]$Unicode,
        [switch]$Utf8
    )
    if ($Unicode -and $Utf8) { throw 'Select only one snapshot encoding.' }
    try { $bytes = [IO.File]::ReadAllBytes($Path) }
    catch {
        $cause = $_.Exception.GetBaseException()
        if ($Optional -and ($cause -is [IO.FileNotFoundException] -or $cause -is [IO.DirectoryNotFoundException])) {
            return [pscustomobject]@{ Exists = $false; Text = ''; Hash = '<Absent>'; Lines = [string[]]@() }
        }
        throw
    }
    if ($Unicode) {
        if ($bytes.Length -lt 2 -or $bytes[0] -ne 255 -or $bytes[1] -ne 254 -or ($bytes.Length % 2) -ne 0) {
            throw ('Expected a UTF-16LE BOM in [{0}]; refusing a lossy security-template rewrite.' -f $Path)
        }
        $decoder = New-Object System.Text.UnicodeEncoding($false, $true, $true)
        $text = $decoder.GetString($bytes, 2, $bytes.Length - 2)
    }
    elseif ($Utf8) {
        $offset = 0
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) { $offset = 3 }
        $decoder = New-Object System.Text.UTF8Encoding($false, $true)
        $text = $decoder.GetString($bytes, $offset, $bytes.Length - $offset)
    }
    else {
        if ($bytes.Length -ge 2 -and ($bytes[0] -eq 255 -or $bytes[0] -eq 254)) { throw 'GPT.INI must use ANSI, not UTF-16.' }
        $text = [Text.Encoding]::Default.GetString($bytes)
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = [BitConverter]::ToString($sha.ComputeHash($bytes)) }
    finally { $sha.Dispose() }
    return [pscustomobject]@{ Exists = $true; Text = $text; Hash = $hash; Lines = [string[]]@($text -split '\r?\n') }
}

function Get-LabGpoSecurityState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Context)

    $ad = Get-ADObject -Identity $Context.Dn -Server $Context.Server -Properties `
        displayName, versionNumber, gPCMachineExtensionNames, gPCFileSysPath, gPCFunctionalityVersion, flags, uSNChanged -ErrorAction Stop
    if ($ad.ObjectClass -ine 'groupPolicyContainer' -or [guid]$ad.Name -ne $Context.Guid -or $ad.displayName -ine $Context.Name) {
        throw 'Native GPO identity check failed.'
    }
    foreach ($name in @('versionNumber', 'gPCFileSysPath', 'gPCFunctionalityVersion', 'flags', 'uSNChanged')) {
        $required = $ad.PSObject.Properties[$name]
        if ($null -eq $required -or $null -eq $required.Value) { throw ('Missing required GPO attribute [{0}].' -f $name) }
    }
    if ([int]$ad.gPCFunctionalityVersion -ne 2) { throw 'Unsupported GPO functionality version.' }
    # The domain-based GPC path is validated; file I/O stays pinned to Server.
    $expectedPath = '\\{0}\SYSVOL\{0}\Policies\{{{1}}}' -f $Context.DomainName, $Context.Guid
    if ([string]$ad.gPCFileSysPath -ine $expectedPath) { throw 'Unexpected GPO SYSVOL path; no native write was started.' }
    if (([int]$ad.flags -band 2) -ne 0) { throw 'Computer policy is disabled on this GPO; no native write was started.' }
    $rawVersion = [long]$ad.versionNumber
    if ($rawVersion -lt 0) { $rawVersion += 4294967296 }
    $version = [uint32]$rawVersion
    $extensions = ''
    $property = $ad.PSObject.Properties['gPCMachineExtensionNames']
    if ($null -ne $property) { $extensions = [string]$property.Value }
    $gpt = Get-LabGpoFileSnapshot -Path (Join-Path $Context.Root 'GPT.INI')
    $iniVersion = Get-LabGpoIniEntry -Lines $gpt.Lines -Section 'General' -Key 'Version'
    if ($iniVersion.Index -lt 0 -or $iniVersion.Value -notmatch '^[0-9]+$' -or [uint32]$iniVersion.Value -ne $version) {
        throw 'AD and GPT.INI versions are missing or inconsistent on the selected DC; repair before retrying.'
    }
    $inf = Get-LabGpoFileSnapshot -Path (Join-Path $Context.Root 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf') -Optional -Unicode
    if ($inf.Exists) {
        $unicode = Get-LabGpoIniEntry -Lines $inf.Lines -Section 'Unicode' -Key 'Unicode'
        $signature = Get-LabGpoIniEntry -Lines $inf.Lines -Section 'Version' -Key 'signature'
        $revision = Get-LabGpoIniEntry -Lines $inf.Lines -Section 'Version' -Key 'Revision'
        if ($unicode.Value -ine 'yes' -or $signature.Value -cne '"$CHICAGO$"' -or $revision.Value -ne '1') {
            throw 'Existing security-template header is invalid; refusing to replace it.'
        }
    }
    return [pscustomobject]@{ Version = $version; Extensions = $extensions; Gpt = $gpt; Inf = $inf; Usn = [string]$ad.uSNChanged }
}

function Assert-LabGpoSecurityReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][xml]$Report,
        [Parameter(Mandatory = $true)][object[]]$Settings
    )
    $nodes = @($Report.SelectNodes("//*[local-name()='Computer']/*[local-name()='ExtensionData']/*[local-name()='Extension']/*[local-name()='SecurityOptions' and namespace-uri()='http://www.microsoft.com/GroupPolicy/Settings/Security']"))
    $accountNodes = @($Report.SelectNodes("//*[local-name()='Computer']/*[local-name()='ExtensionData']/*[local-name()='Extension']/*[local-name()='Account' and namespace-uri()='http://www.microsoft.com/GroupPolicy/Settings/Security']"))
    foreach ($setting in $Settings) {
        if ($setting.Storage -ieq 'AccountPolicy') {
            $found = @($accountNodes | Where-Object {
                $nameNode = $_.SelectSingleNode("*[local-name()='Name']")
                $null -ne $nameNode -and $nameNode.InnerText -ieq $setting.ValueName
            })
            if ($found.Count -ne 1) { throw ('Native account report must contain exactly one [{0}] entry.' -f $setting.ValueName) }
            $category = if ($setting.Section -ieq 'Kerberos Policy') { 'Kerberos' }
                elseif ($setting.Section -ieq 'System Access' -and $setting.ValueName -ieq 'LockoutBadCount') { 'Account Lockout' }
                else { 'Password' }
            $typeNode = $found[0].SelectSingleNode("*[local-name()='Type']")
            if ($null -eq $typeNode -or $typeNode.InnerText -ine $category) { throw 'Native account report policy category did not match.' }
            if ($setting.ValueName -ieq 'ClearTextPassword') {
                $valueNode = $found[0].SelectSingleNode("*[local-name()='SettingBoolean']")
                if ($null -eq $valueNode -or $valueNode.InnerText -cnotmatch '^(true|false|0|1)$') { throw 'Native account report boolean is missing or malformed.' }
                $actual = if ($valueNode.InnerText -ceq 'true' -or $valueNode.InnerText -ceq '1') { 1 } else { 0 }
                if ($actual -ne $setting.Value) { throw 'Native reversible-encryption report value did not match.' }
            }
            else {
                $valueNode = $found[0].SelectSingleNode("*[local-name()='SettingNumber']")
                if ($null -eq $valueNode -or $valueNode.InnerText -notmatch '^[0-9]+$' -or [uint32]$valueNode.InnerText -ne [uint32]$setting.Value) {
                    throw ('Native account report value did not match [{0}]={1} in its native units.' -f $setting.ValueName, $setting.Value)
                }
            }
            continue
        }
        $key = ($setting.Key -replace '^(HKLM|HKEY_LOCAL_MACHINE)\\', 'MACHINE\') + '\' + $setting.ValueName
        $found = @($nodes | Where-Object {
            $keyNode = $_.SelectSingleNode("*[local-name()='KeyName']")
            $null -ne $keyNode -and $keyNode.InnerText -ieq $key
        })
        if ($found.Count -ne 1) { throw ('Native Security Options report must contain exactly one entry for [{0}].' -f $setting.ValueName) }
        $valueNode = $found[0].SelectSingleNode("*[local-name()='SettingNumber']")
        if ($null -eq $valueNode -and $setting.Contains('ReportValueType') -and $setting.ReportValueType -ceq 'BooleanOrNumber') {
            $booleanNode = $found[0].SelectSingleNode("*[local-name()='SettingBoolean']")
            if ($null -eq $booleanNode -or $booleanNode.InnerText -cnotmatch '^(true|false|0|1)$') {
                throw 'Native Security Options report Boolean is missing or malformed.'
            }
            $actual = if ($booleanNode.InnerText -ceq 'true' -or $booleanNode.InnerText -ceq '1') { 1 } else { 0 }
            if ($actual -ne $setting.Value) { throw 'Native Security Options report Boolean did not match the desired value.' }
        }
        elseif ($null -eq $valueNode -or $valueNode.InnerText -notmatch '^[0-9]+$' -or [uint32]$valueNode.InnerText -ne [uint32]$setting.Value) {
            throw ('Native Security Options report value did not match [{0}]={1}.' -f $setting.ValueName, $setting.Value)
        }
    }
}

function Write-LabGpoSettingCheck {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Setting)

    if ($Setting.Storage -ieq 'AdvancedAudit') {
        Write-Status -Kind Info -Message 'Checking native machine audit.csv subcategory (no individual registry entry).'
    }
    elseif ($Setting.Storage -ieq 'AccountPolicy') {
        Write-Status -Kind Info -Message ('Checking GPO native account-policy section [{0}]' -f $Setting.Section)
    }
    else { Write-Status -Kind Info -Message ('Checking GPO registry key [{0}]' -f $Setting.Key) }
    $path = '<Unknown>'
    if ($Setting.Contains('GpoSettingsPath') -and -not [string]::IsNullOrWhiteSpace([string]$Setting['GpoSettingsPath'])) { $path = [string]$Setting['GpoSettingsPath'] }
    $display = '<Unknown>'
    if ($Setting.Contains('GpoDisplayName') -and -not [string]::IsNullOrWhiteSpace([string]$Setting['GpoDisplayName'])) { $display = [string]$Setting['GpoDisplayName'] }
    $details = @(
        ('       GPO settings path: {0}' -f $path)
        ('       GPO display: {0}' -f $display)
        ('       policy storage: {0}' -f $Setting.Storage)
        ('       value name: [{0}]' -f $Setting.ValueName)
        ('       value type: [{0}]' -f $Setting.Type)
        ('       value data: [{0}]' -f ($Setting.Value | ConvertTo-Json -Compress -Depth 4))
    )
    foreach ($detail in $details) { Write-Host (Format-OutputMessage -Message $detail) -ForegroundColor Gray }
}

function Assert-LabGpoLinkUpdateAllowed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][xml]$Report,
        [Parameter(Mandatory = $true)][bool]$ApplyWhenLinked,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $linkCount = @($Report.SelectNodes("//*[local-name()='LinksTo']")).Count
    if ($linkCount -gt 0 -and -not $ApplyWhenLinked) {
        $message = 'GPO [{0}] has {1} reported link(s), but ApplyWhenLinked is False.' -f $Name, $linkCount
        # Tag only this expected policy refusal; other failures stay fatal.
        $denied = New-Object System.InvalidOperationException -ArgumentList $message
        $denied.Data['LabGpoLinkUpdateDenied'] = $true
        $denied.Data['GpoName'] = $Name
        $denied.Data['LinkCount'] = $linkCount
        throw $denied
    }
    return $linkCount
}

function Ensure-LabGpoNativeSecurityOptions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Context,
        [Parameter(Mandatory = $true)][object[]]$Settings,
        [Parameter(Mandatory = $true)]$InitialState
    )
    $plans = @(
        foreach ($setting in $Settings) {
            Write-LabGpoSettingCheck -Setting $setting
            $current = Get-LabGpoSecurityValue -Lines $InitialState.Inf.Lines -Setting $setting
            $legacy = [pscustomobject]@{ Configured = $false; PolicyState = 'NotConfigured'; Type = $null; Value = $null }
            if ($setting.Storage -ieq 'SecurityOptions') {
                $legacy = Get-LabGpoRegistrySetting -Guid $Context.Guid -DomainName $Context.DomainName -Server $Context.Server -Key $setting.Key -ValueName $setting.ValueName
            }
            [pscustomobject]@{ Setting = $setting; Current = $current; Legacy = $legacy; Matches = ($current.Configured -and [uint32]$current.Value -eq [uint32]$setting.Value) }
        }
    )
    $extensions = Merge-LabGpoSecurityExtension -Extensions $InitialState.Extensions
    $metadataChanged = $extensions -cne $InitialState.Extensions
    $needsWrite = @($plans | Where-Object { -not $_.Matches }).Count -gt 0 -or $metadataChanged
    if ($needsWrite) {
        $version = Get-LabGpoNextComputerVersion -Version $InitialState.Version
        $lines = $InitialState.Inf.Lines
        if (-not $InitialState.Inf.Exists) { $lines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[Registry Values]') }
        foreach ($plan in $plans) {
            if (-not $plan.Matches) {
                Write-Status -IndentLevel 3 -Kind Info -Message ('Updating native security policy [{0}]: old={1} -> new={2} {3}.' -f $plan.Setting.ValueName, (Format-LabGpoRegistrySetting -Setting $plan.Current), $plan.Setting.Type, $plan.Setting.Value)
                $mapping = Get-LabGpoNativeEntry -Setting $plan.Setting
                $lines = @(Set-LabGpoIniEntry -Lines $lines -Section $mapping.Section -Key $mapping.Key -Value $mapping.Value)
            }
        }
        # Preflight again after backup/planning. This is not an AD+SMB transaction;
        # linked updates require per-GPO opt-in; avoid concurrent settings edits.
        $fresh = Get-LabGpoSecurityState -Context $Context
        if ($fresh.Usn -ne $InitialState.Usn -or $fresh.Gpt.Hash -cne $InitialState.Gpt.Hash -or $fresh.Inf.Hash -cne $InitialState.Inf.Hash) {
            throw 'The GPO changed during native planning/backup; no native write was started.'
        }
        if (-not $Context.ApplyWhenLinked) {
            [xml]$preWriteReport = Get-GPOReport -Guid $Context.Guid -Domain $Context.DomainName -Server $Context.Server -ReportType Xml -ErrorAction Stop
            Assert-LabGpoLinkUpdateAllowed -Report $preWriteReport -ApplyWhenLinked $Context.ApplyWhenLinked -Name $Context.Name | Out-Null
        }
        $text = ($lines -join "`r`n").TrimEnd([char[]]"`r`n") + "`r`n"
        $infPath = Join-Path $Context.Root 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
        [void][IO.Directory]::CreateDirectory((Split-Path -Parent $infPath))
        [IO.File]::WriteAllText($infPath, $text, [Text.Encoding]::Unicode)
        $readInf = Get-LabGpoFileSnapshot -Path $infPath -Unicode
        if ($readInf.Text -cne $text) { throw 'Security-template content read-back failed before metadata update.' }
        $signedVersion = if ([long]$version -gt [int]::MaxValue) { [int]([long]$version - 4294967296) } else { [int]$version }
        Set-ADObject -Identity $Context.Dn -Server $Context.Server -Replace @{
            gPCMachineExtensionNames = $extensions
            versionNumber = $signedVersion
        } -ErrorAction Stop
        $iniLines = @(Set-LabGpoIniEntry -Lines $InitialState.Gpt.Lines -Section 'General' -Key 'Version' -Value ([string]$version))
        [IO.File]::WriteAllText((Join-Path $Context.Root 'GPT.INI'), ($iniLines -join "`r`n"), [Text.Encoding]::Default)
        $after = Get-LabGpoSecurityState -Context $Context
        if ($after.Version -ne $version -or $after.Extensions -cne $extensions -or $after.Inf.Hash -cne $readInf.Hash) {
            throw 'Native security-policy metadata/content verification failed.'
        }
    }
    # Report verification is separate from Registry.pol verification. Do not
    # remove old entries until native content AND editor/report state match.
    $nativeState = Get-LabGpoSecurityState -Context $Context
    if ((Merge-LabGpoSecurityExtension -Extensions $nativeState.Extensions) -cne $nativeState.Extensions) { throw 'Security CSE/tool registration verification failed.' }
    foreach ($plan in $plans) {
        $actual = Get-LabGpoSecurityValue -Lines $nativeState.Inf.Lines -Setting $plan.Setting
        if (-not $actual.Configured -or [uint32]$actual.Value -ne [uint32]$plan.Setting.Value) { throw 'Native security-template value read-back failed.' }
    }
    [xml]$nativeReport = Get-GPOReport -Guid $Context.Guid -Domain $Context.DomainName -Server $Context.Server -ReportType Xml -ErrorAction Stop
    Assert-LabGpoLinkUpdateAllowed -Report $nativeReport -ApplyWhenLinked $Context.ApplyWhenLinked -Name $Context.Name | Out-Null
    Assert-LabGpoSecurityReport -Report $nativeReport -Settings $Settings
    foreach ($plan in $plans) {
        $setting = $plan.Setting
        if ($setting.Storage -ine 'SecurityOptions') { continue } # Account policies have no registry duplicates.
        $legacyNow = Get-LabGpoRegistrySetting -Guid $Context.Guid -DomainName $Context.DomainName -Server $Context.Server -Key $setting.Key -ValueName $setting.ValueName
        if ($legacyNow.Configured -ne $plan.Legacy.Configured -or ($legacyNow.Configured -and
            ((Format-LabGpoRegistrySetting -Setting $legacyNow) -cne (Format-LabGpoRegistrySetting -Setting $plan.Legacy)))) {
            throw 'A legacy registry entry changed during native processing; stopping cleanup.'
        }
        if ($legacyNow.Configured) {
            Write-Status -IndentLevel 3 -Kind Info -Message ('Removing migrated Registry.pol entry [{0}]; native Security Options report is verified.' -f $setting.ValueName)
            if (-not $Context.ApplyWhenLinked) {
                [xml]$preCleanupReport = Get-GPOReport -Guid $Context.Guid -Domain $Context.DomainName -Server $Context.Server -ReportType Xml -ErrorAction Stop
                Assert-LabGpoLinkUpdateAllowed -Report $preCleanupReport -ApplyWhenLinked $Context.ApplyWhenLinked -Name $Context.Name | Out-Null
            }
            Remove-GPRegistryValue -Guid $Context.Guid -Domain $Context.DomainName -Server $Context.Server -Key $setting.Key -ValueName $setting.ValueName -ErrorAction Stop | Out-Null
        }
        $remaining = Get-LabGpoRegistrySetting -Guid $Context.Guid -DomainName $Context.DomainName -Server $Context.Server -Key $setting.Key -ValueName $setting.ValueName
        if ($remaining.Configured) { throw ('Legacy Registry.pol entry remains for [{0}].' -f $setting.ValueName) }
    }
    # Registry removal bumps versions too; re-read final native metadata/report.
    $final = Get-LabGpoSecurityState -Context $Context
    if ($final.Inf.Hash -cne $nativeState.Inf.Hash -or (Merge-LabGpoSecurityExtension -Extensions $final.Extensions) -cne $final.Extensions) {
        throw 'Native security content or registration changed during registry cleanup.'
    }
    [xml]$finalReport = Get-GPOReport -Guid $Context.Guid -Domain $Context.DomainName -Server $Context.Server -ReportType Xml -ErrorAction Stop
    Assert-LabGpoLinkUpdateAllowed -Report $finalReport -ApplyWhenLinked $Context.ApplyWhenLinked -Name $Context.Name | Out-Null
    Assert-LabGpoSecurityReport -Report $finalReport -Settings $Settings
    $changed = 0
    foreach ($plan in $plans) {
        $isChanged = -not $plan.Matches -or $metadataChanged -or $plan.Legacy.Configured
        if ($isChanged) { $changed++ }
        Write-Status -IndentLevel 4 -Kind Success -Message ("Verified native security policy [{0}]:`n            {1} {2};`n            security template,`n            extension registration,`n            AD/SYSVOL versions and native GPO report matched;`n            no managed registry-policy duplicate." -f $plan.Setting.ValueName, $plan.Setting.Type, $plan.Setting.Value)
    }
    return [pscustomobject]@{ ChangedCount = $changed; UnchangedCount = $plans.Count - $changed }
}

function Merge-LabGpoAuditExtension {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Extensions = '')
    # MS-GPAC 1.9; keep all existing CSE/tool groups, including Security.
    $cse = '{F3CCC681-B74C-4060-9F26-CD84525DCA2A}'
    $tool = '{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}'
    $pattern = '\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}'
    $groups = [regex]::Matches($Extensions, ('\[(?:' + $pattern + '){2,}\]'))
    if ((($groups | ForEach-Object { $_.Value }) -join '') -cne $Extensions) { throw 'Malformed GPO machine-extension list; no audit write attempted.' }
    $items = @{}
    foreach ($group in $groups) {
        $guids = @([regex]::Matches($group.Value, $pattern) | ForEach-Object { $_.Value })
        if ($items.ContainsKey($guids[0])) { throw 'Duplicate CSE groups; no audit write attempted.' }
        $items[$guids[0]] = $group.Value
        if ($guids[0] -ieq $cse -and $guids -inotcontains $tool) {
            $items[$guids[0]] = $group.Value.Substring(0, $group.Value.Length - 1) + $tool + ']'
        }
    }
    if (-not $items.ContainsKey($cse)) { $items[$cse] = '[' + $cse + $tool + ']' }
    return (($items.Keys | Sort-Object | ForEach-Object { $items[$_] }) -join '')
}

function Get-LabGpoAuditRows {
    [CmdletBinding()]
    param([AllowEmptyCollection()][string[]]$Lines = @())
    # MS-GPAC 2.2. Reject malformed input instead of silently dropping columns.
    $header = 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
    if ($Lines.Count -eq 0) { return }
    if ($Lines[0] -cne $header) { throw 'Unexpected audit.csv header; refusing a lossy rewrite.' }
    $seen = @{}
    foreach ($line in @($Lines | Select-Object -Skip 1)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -notmatch '^(?:"(?:[^"]|"")*"|[^",\r\n]*)(?:,(?:"(?:[^"]|"")*"|[^",\r\n]*)){6}$') {
            throw 'Malformed audit.csv row; expected exactly seven CSV fields.'
        }
        $fields = @($header, $line) | ConvertFrom-Csv -ErrorAction Stop
        $guid = [guid]::Empty
        $key = ''
        if ($fields.'Policy Target' -ieq 'System' -and [guid]::TryParse([string]$fields.'Subcategory GUID', [ref]$guid)) {
            $key = $guid.ToString('B')
            if ($seen.ContainsKey($key)) { throw 'Duplicate system audit subcategory GUID; no audit write attempted.' }
            $seen[$key] = $true
        }
        # Unmanaged subcategories, audit options and per-user rows are retained.
        [pscustomobject]@{ Fields = $fields; Line = $line; Guid = $key }
    }
}

function Get-LabGpoAuditPlan {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][string[]]$Lines = @(),
        [Parameter(Mandatory = $true)][object[]]$Settings
    )
    $rows = @(Get-LabGpoAuditRows -Lines $Lines)
    $header = 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
    $outputLines = @($header)
    $managed = @{}
    $changed = 0
    foreach ($setting in $Settings) {
        Assert-LabGpoSettingValue -Setting $setting
        $guid = ([guid]$setting.ValueName).ToString('B')
        if ($managed.ContainsKey($guid)) { throw 'Duplicate advanced audit desired-state GUID.' }
        $labels = @('No Auditing', 'Success', 'Failure', 'Success and Failure')
        $name = $setting.GpoDisplayName
        if ($name -match '[,"\r\n]' -or [string]::IsNullOrWhiteSpace([string]$name)) { throw 'Invalid audit display name.' }
        $desired = ',System,{0},{1},{2},,{3}' -f $name, $guid, $labels[[int]$setting.Value], $setting.Value
        $matches = @($rows | Where-Object { $_.Fields.'Policy Target' -ieq 'System' -and $_.Guid -ieq $guid })
        if ($matches.Count -ne 1 -or $matches[0].Line -cne $desired) { $changed++ }
        $managed[$guid] = $true
        $outputLines += $desired
    }
    foreach ($row in $rows) {
        if ($row.Fields.'Policy Target' -ieq 'System' -and $managed.ContainsKey($row.Guid)) { continue }
        $outputLines += $row.Line
    }
    return [pscustomobject]@{ Lines = [string[]]$outputLines; ChangedCount = $changed }
}

function Get-LabGpoAuditState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Context)
    $security = Get-LabGpoSecurityState -Context $Context
    $csv = Get-LabGpoFileSnapshot -Path (Join-Path $Context.Root 'Machine\Microsoft\Windows NT\Audit\audit.csv') -Optional -Utf8
    if ($csv.Exists) { Get-LabGpoAuditRows -Lines $csv.Lines | Out-Null }
    return [pscustomobject]@{ Security = $security; Csv = $csv }
}

function Ensure-LabGpoAdvancedAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Context,
        [Parameter(Mandatory = $true)][object[]]$Settings
    )
    $initial = Get-LabGpoAuditState -Context $Context
    foreach ($setting in $Settings) { Write-LabGpoSettingCheck -Setting $setting }
    $plan = Get-LabGpoAuditPlan -Lines $initial.Csv.Lines -Settings $Settings
    $extensions = Merge-LabGpoAuditExtension -Extensions $initial.Security.Extensions
    $metadataChanged = $extensions -cne $initial.Security.Extensions
    if ($plan.ChangedCount -gt 0 -or $metadataChanged) {
        $version = Get-LabGpoNextComputerVersion -Version $initial.Security.Version
        $fresh = Get-LabGpoAuditState -Context $Context
        if ($fresh.Security.Usn -cne $initial.Security.Usn -or
            $fresh.Security.Gpt.Hash -cne $initial.Security.Gpt.Hash -or
            $fresh.Security.Inf.Hash -cne $initial.Security.Inf.Hash -or
            $fresh.Csv.Hash -cne $initial.Csv.Hash) {
            throw 'GPO changed during advanced-audit planning; no audit write attempted.'
        }
        [xml]$report = Get-GPOReport -Guid $Context.Guid -Domain $Context.DomainName -Server $Context.Server -ReportType Xml -ErrorAction Stop
        Assert-LabGpoLinkUpdateAllowed -Report $report -ApplyWhenLinked $Context.ApplyWhenLinked -Name $Context.Name | Out-Null
        Write-Status -IndentLevel 3 -Kind Info -Message 'Updating native machine advanced-audit CSV and its CSE/version metadata; no local auditpol changes.'
        $path = Join-Path $Context.Root 'Machine\Microsoft\Windows NT\Audit\audit.csv'
        [void][IO.Directory]::CreateDirectory((Split-Path -Parent $path))
        $text = ($plan.Lines -join "`r`n") + "`r`n"
        [IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($true, $true)))
        $written = Get-LabGpoFileSnapshot -Path $path -Utf8
        if ($written.Text -cne $text) { throw 'Advanced-audit CSV read-back failed before metadata update.' }
        $signedVersion = if ([long]$version -gt [int]::MaxValue) { [int]([long]$version - 4294967296) } else { [int]$version }
        Set-ADObject -Identity $Context.Dn -Server $Context.Server -Replace @{
            gPCMachineExtensionNames = $extensions; versionNumber = $signedVersion
        } -ErrorAction Stop
        $ini = @(Set-LabGpoIniEntry -Lines $initial.Security.Gpt.Lines -Section 'General' -Key 'Version' -Value ([string]$version))
        [IO.File]::WriteAllText((Join-Path $Context.Root 'GPT.INI'), ($ini -join "`r`n"), [Text.Encoding]::Default)
    }
    $final = Get-LabGpoAuditState -Context $Context
    if ($metadataChanged -or $plan.ChangedCount -gt 0) {
        if ($final.Security.Version -ne $version -or $final.Csv.Hash -cne $written.Hash) { throw 'Advanced-audit version/content read-back failed.' }
    }
    if ($final.Security.Extensions -cne $extensions -or $final.Security.Inf.Hash -cne $initial.Security.Inf.Hash) { throw 'Advanced-audit extension registration or unrelated security-template verification failed.' }
    $verified = Get-LabGpoAuditPlan -Lines $final.Csv.Lines -Settings $Settings
    if ($verified.ChangedCount -ne 0) { throw 'Advanced-audit subcategory read-back failed.' }
    [xml]$finalReport = Get-GPOReport -Guid $Context.Guid -Domain $Context.DomainName -Server $Context.Server -ReportType Xml -ErrorAction Stop
    Assert-LabGpoLinkUpdateAllowed -Report $finalReport -ApplyWhenLinked $Context.ApplyWhenLinked -Name $Context.Name | Out-Null
    foreach ($setting in $Settings) {
        Write-Status -IndentLevel 2 -Kind Success -Message ("Verified [{0}]={1} in native machine audit.csv; CSE and AD/GPT versions matched.`n          Effective client policy is not tested." -f $setting.GpoDisplayName, $setting.Value)
    }
    $changed = $plan.ChangedCount
    if ($metadataChanged) { $changed = $Settings.Count }
    return [pscustomobject]@{ ChangedCount = $changed; UnchangedCount = $Settings.Count - $changed }
}

function Ensure-LabGpoDefinitionMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Context,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Definition,
        [switch]$VerifyOnly
    )
    if (-not $Definition.Contains('Comment') -and -not $Definition.Contains('GpoStatus')) { return }
    $read = Get-ADObject -Identity $Context.Dn -Server $Context.Server -Properties description, flags -ErrorAction Stop
    if ($read.ObjectClass -ine 'groupPolicyContainer' -or [guid]$read.Name -ne $Context.Guid) { throw 'GPO metadata identity mismatch.' }
    $comment = ''
    $property = $read.PSObject.Properties['description']
    if ($null -ne $property) { $comment = [string]$property.Value }
    $replace = @{}
    if ($Definition.Contains('Comment') -and $comment -cne $Definition.Comment) { $replace.description = $Definition.Comment }
    if ($Definition.Contains('GpoStatus') -and [int]$read.flags -ne 1) { $replace.flags = 1 }
    if ($replace.Count -eq 0) { return }
    if ($VerifyOnly) { throw 'GPO comment or Computer-only status did not verify.' }
    [xml]$report = Get-GPOReport -Guid $Context.Guid -Domain $Context.DomainName -Server $Context.Server -ReportType Xml -ErrorAction Stop
    Assert-LabGpoLinkUpdateAllowed -Report $report -ApplyWhenLinked $Context.ApplyWhenLinked -Name $Context.Name | Out-Null
    Write-Status -IndentLevel 3 -Kind Info -Message 'Updating GPO comment and Computer-only status (User Configuration disabled); links unchanged.'
    # GPC description is the GPMC Comment. GPC flags=1 disables only User.
    # Neither is a policy setting; no user SYSVOL file or local registry is edited.
    Set-ADObject -Identity $Context.Dn -Server $Context.Server -Replace $replace -ErrorAction Stop
    Ensure-LabGpoDefinitionMetadata -Context $Context -Definition $Definition -VerifyOnly
    $Context['SummaryMetadataChanged'] = $true
    Write-Status -IndentLevel 2 -Kind Success -Message 'Verified requested GPO comment and Computer-only status.'
}

function Test-LabGpoFileLockError {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Exception]$Exception)

    # .NET method calls may wrap IOException in MethodInvocationException.
    # Windows ERROR_SHARING_VIOLATION=32; ERROR_LOCK_VIOLATION=33.
    # Never infer recoverability from localized exception-message text.
    $current = $Exception
    while ($null -ne $current) {
        if ($current -is [System.IO.IOException]) {
            $win32Code = $current.HResult -band 65535
            if ($win32Code -in @(32,33)) { return $true }
        }
        $current = $current.InnerException
    }
    return $false
}

function Ensure-LabGpo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Definition,
        [switch]$ExistingOnly,
        [guid]$ExpectedGuid = [guid]::Empty
    )

    if ($ExistingOnly) { Write-SectionHeader -Message 'Apply synthetic GPO settings...' }
    else { Write-SectionHeader -Message 'Create/Update Lab Group Policy Object...' }
    $server = [string]$Domain.SelectedDomainController
    $domainName = [string]$Domain.DNSRoot
    $domainDN = [string]$Domain.DistinguishedName
    $changedCount = 0
    $unchangedCount = 0
    $wasCreated = $false
    $gpoGuid = $null
    $reconciliationStarted = $false
    $backupDirectory = $null
    try {
        if ($ExistingOnly -and $ExpectedGuid -eq [guid]::Empty) { throw 'Synthetic GPO changes require a verified nonempty baseline GUID.' }
        if ([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($domainName) -or
            [string]::IsNullOrWhiteSpace($domainDN)) { throw 'GPO provisioning requires the discovered domain and selected writable DC.' }
        if (-not $Definition.Contains('Name') -or $Definition.Name -isnot [string] -or
            [string]::IsNullOrWhiteSpace($Definition.Name)) { throw 'Get-LabGpoDefinition must contain a nonblank GPO Name.' }
        if (-not $Definition.Contains('BackupRoot') -or $Definition.BackupRoot -isnot [string] -or
            [string]::IsNullOrWhiteSpace($Definition.BackupRoot) -or -not [IO.Path]::IsPathRooted($Definition.BackupRoot)) {
            throw 'Get-LabGpoDefinition must contain an absolute BackupRoot for pre-write GPO backups.'
        }
        if (-not $Definition.Contains('ApplyWhenLinked') -or $Definition.ApplyWhenLinked -isnot [bool]) {
            throw 'Each GPO definition must specify ApplyWhenLinked as Boolean $True or $False, not a string.'
        }
        $ApplyWhenLinked = [bool]$Definition.ApplyWhenLinked
        if ($Definition.Contains('Comment') -and ($Definition.Comment -isnot [string] -or [string]::IsNullOrWhiteSpace($Definition.Comment))) {
            throw 'GPO Comment must be a nonblank string.'
        }
        if ($Definition.Contains('GpoStatus') -and $Definition.GpoStatus -cne 'UserSettingsDisabled') {
            throw 'The supported optional GpoStatus is UserSettingsDisabled (Computer enabled, User disabled).'
        }
        if (-not $Definition.Contains('Settings')) { throw 'Get-LabGpoDefinition must contain Settings.' }
        $desiredSettings = @($Definition.Settings)
        if ($desiredSettings.Count -eq 0) { throw 'No initial GPO settings were defined; no GPO was created or changed.' }
        $seen = @{}
        foreach ($setting in $desiredSettings) {
            if ($setting -isnot [System.Collections.IDictionary]) { throw 'Each GPO setting must be a hash table.' }
            foreach ($field in @('ValueName', 'Type', 'Value', 'Storage')) {
                if (-not $setting.Contains($field)) { throw ('GPO setting is missing [{0}].' -f $field) }
            }
            if ($setting.ValueName -isnot [string] -or [string]::IsNullOrWhiteSpace($setting.ValueName) -or
                $setting.ValueName -match '[\r\n="\[\]\\]' -or $setting.ValueName.StartsWith(';')) {
                throw 'Each GPO setting requires a nonblank, unambiguous ValueName.'
            }
            if ($setting.Storage -isnot [string] -or
                $setting.Storage -inotmatch '^(RegistryPolicy|SecurityOptions|AccountPolicy|AdvancedAudit)$') {
                throw ('Unsupported policy Storage for [{0}]; use RegistryPolicy, SecurityOptions, AccountPolicy or AdvancedAudit.' -f $setting.ValueName)
            }
            if ($setting.Storage -ieq 'AdvancedAudit') {
                Assert-LabGpoSettingValue -Setting $setting
                $identityKey = 'AdvancedAudit|{0}' -f ([guid]$setting.ValueName).ToString('B')
            }
            elseif ($setting.Storage -ieq 'AccountPolicy') {
                Assert-LabGpoSettingValue -Setting $setting
                $identityKey = 'AccountPolicy|{0}|{1}' -f $setting.Section, $setting.ValueName
            }
            else {
                if (-not $setting.Contains('Key') -or $setting.Key -isnot [string] -or
                    $setting.Key -notmatch '^(HKLM|HKEY_LOCAL_MACHINE)\\.+$' -or $setting.Key -match '[\r\n="\[\]]') {
                    throw 'Registry-backed settings require an HKLM Key without INI delimiters.'
                }
                Assert-LabGpoSettingValue -Setting $setting
                $identityKey = '{0}|{1}' -f ($setting.Key -replace '^HKEY_LOCAL_MACHINE\\', 'HKLM\'), $setting.ValueName
            }
            if ($seen.ContainsKey($identityKey)) { throw ('Duplicate GPO registry definition [{0}].' -f $identityKey) }
            $seen[$identityKey] = $true
        }

        $tickets = @($desiredSettings | Where-Object { $_.Storage -ieq 'AccountPolicy' -and $_.ValueName -ieq 'MaxTicketAge' })
        $services = @($desiredSettings | Where-Object { $_.Storage -ieq 'AccountPolicy' -and $_.ValueName -ieq 'MaxServiceAge' })
        if ($tickets.Count -eq 1 -and $services.Count -eq 1 -and $tickets[0].Value -ne 0 -and
            [long]$services[0].Value -gt ([long]$tickets[0].Value * 60)) {
            throw 'MaxServiceAge in minutes cannot exceed MaxTicketAge converted from hours to minutes.'
        }

        Write-Status -Kind Info -Message ('Checking GPO [{0}] on [{1}].' -f $Definition.Name, $server)
        if ($Definition.Contains('Warnings')) {
            foreach ($warning in @($Definition.Warnings)) { Write-Status -IndentLevel 2 -Kind Warning -Message $warning }
        }
        $auditSettings = @($desiredSettings | Where-Object { $_.Storage -ieq 'AdvancedAudit' })
        $registrySettings = @($desiredSettings | Where-Object { $_.Storage -ieq 'RegistryPolicy' })
        $securitySettings = @($desiredSettings | Where-Object { $_.Storage -ieq 'SecurityOptions' -or $_.Storage -ieq 'AccountPolicy' })
        Write-Status -Kind Info -Message ('Linked-update safeguard: ApplyWhenLinked = {0} for [{1}].' -f $ApplyWhenLinked, $Definition.Name)
        Write-Status -Kind Info -Message "RegistryPolicy, native security policies (SecurityOptions/AccountPolicy) and AdvancedAudit use separate writers and verification.`n       No GPO links or delayed changes will be created."
        Write-Status -Kind Warning -Message 'Avoid concurrent GPO settings edits. Existing links are preserved, and linked policy changes may affect lab targets. Native SYSVOL/AD writes are not transactional; file-lock failures skip this GPO and continue the script. Review any partial writes using the logged backup; other failures still stop.'
        # Use an exact LDAP query to distinguish absence from a failed Get-GPO.
        # A duplicate display name is ambiguous: never select an arbitrary GPO.
        $filter = '(&(objectClass=groupPolicyContainer)(displayName={0}))' -f (ConvertTo-LdapFilterValue -Value $Definition.Name)
        $existing = @(Get-ADObject -LDAPFilter $filter -SearchBase ('CN=Policies,CN=System,{0}' -f $domainDN) `
            -SearchScope OneLevel -Properties displayName -Server $server -ErrorAction Stop)
        if ($existing.Count -gt 1) { throw 'Multiple GPOs have the requested display name. Resolve the duplicate names before retrying.' }
        if ($existing.Count -eq 0) {
            if ($ExistingOnly) {
                $skipReason = 'The verified baseline GPO is no longer present; no replacement was created.'
                Write-Status -IndentLevel 2 -Kind Warning -Message ('Skipping synthetic GPO [{0}]: {1}' -f $Definition.Name, $skipReason)
                return [pscustomobject]@{
                    Id = $ExpectedGuid; Name = $Definition.Name; Created = $false
                    ChangedCount = 0; UnchangedCount = 0; VerifiedCount = 0
                    LinkCount = 0; Skipped = $true; SkipReason = $skipReason
                    PartialChangesPossible = $false
                }
            }
            Write-Status -IndentLevel 3 -Kind Info -Message ('Creating unlinked GPO [{0}].' -f $Definition.Name)
            Assert-LabInventoryHealthy
            $gpo = New-GPO -Name $Definition.Name -Domain $domainName -Server $server -ErrorAction Stop
            Add-LabGeneratedGpo -Gpo $gpo
            $wasCreated = $true
        }
        else {
            $existingGuid = [guid](([string]$existing[0].Name).Trim('{}'))
            if ($ExpectedGuid -ne [guid]::Empty -and $existingGuid -ne $ExpectedGuid) {
                throw 'GPO GUID differs from the verified baseline; refusing to change a replacement object.'
            }
            $gpo = Get-GPO -Guid $existingGuid -Domain $domainName -Server $server -ErrorAction Stop
        }
        if ($null -eq $gpo -or $gpo.DisplayName -ine $Definition.Name) { throw 'GPO identity read-back did not match the requested display name.' }
        $gpoGuid = [guid]$gpo.Id
        if ($ExpectedGuid -ne [guid]::Empty -and $gpoGuid -ne $ExpectedGuid) { throw 'GPO read-back GUID differs from the verified baseline.' }
        $gpo = Get-GPO -Guid $gpoGuid -Domain $domainName -Server $server -ErrorAction Stop
        if ($gpo.DisplayName -ine $Definition.Name -or [guid]$gpo.Id -ne $gpoGuid) { throw 'GPO name or GUID changed during initialization.' }
        [xml]$report = Get-GPOReport -Guid $gpoGuid -Domain $domainName -Server $server -ReportType Xml -ErrorAction Stop
        $initialLinkCount = Assert-LabGpoLinkUpdateAllowed -Report $report -ApplyWhenLinked $ApplyWhenLinked -Name $Definition.Name
        if ($initialLinkCount -gt 0) {
            Write-Status -IndentLevel 2 -Kind Warning -Message ('GPO [{0}] has {1} reported link(s). ApplyWhenLinked is True; continuing settings reconciliation without editing any links. Enabled links may deliver these changes to lab targets.' -f $Definition.Name, $initialLinkCount)
        }
        else {
            Write-Status -IndentLevel 2 -Kind Info -Message 'GPO has no reported links. Settings will be reconciled without creating links.'
        }
        $context = @{
            SummaryMetadataChanged = $false
            Guid = $gpoGuid; Name = $Definition.Name; Server = $server; DomainName = $domainName
            ApplyWhenLinked = $ApplyWhenLinked
            Dn = ('CN={{{0}}},CN=Policies,CN=System,{1}' -f $gpoGuid, $domainDN)
            Root = ('\\{0}\SYSVOL\{1}\Policies\{{{2}}}' -f $server, $domainName, $gpoGuid)
        }
        # Validate all native inputs before the backup and before any setting writes.
        $nativeState = $null
        if ($securitySettings.Count -gt 0) {
            $nativeState = Get-LabGpoSecurityState -Context $context
            Merge-LabGpoSecurityExtension -Extensions $nativeState.Extensions | Out-Null
            foreach ($setting in $securitySettings) { Get-LabGpoSecurityValue -Lines $nativeState.Inf.Lines -Setting $setting | Out-Null }
        }
        if ($auditSettings.Count -gt 0) {
            $auditPreflight = Get-LabGpoAuditState -Context $context
            Get-LabGpoAuditPlan -Lines $auditPreflight.Csv.Lines -Settings $auditSettings | Out-Null
            Merge-LabGpoAuditExtension -Extensions $auditPreflight.Security.Extensions | Out-Null
        }
        $backupDirectory = Join-Path $Definition.BackupRoot ('{0}_{1}_{2}' -f $gpoGuid, (Get-Date -Format 'yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N')))
        New-Item -Path $backupDirectory -ItemType Directory -ErrorAction Stop | Out-Null
        $backup = Backup-GPO -Guid $gpoGuid -Domain $domainName -Server $server -Path $backupDirectory -Comment 'Before lab registry/native security-policy reconciliation' -ErrorAction Stop
        if ($null -eq $backup -or [guid]$backup.Id -eq [guid]::Empty) { throw 'The pre-write GPO backup did not return a backup ID.' }
        Write-Status -Kind Info -Message ('Pre-write GPO backup [{0}] saved in [{1}].' -f $backup.Id, $backupDirectory)
        # From here onward, a later link-policy refusal may follow writes.
        $reconciliationStarted = $true
        Ensure-LabGpoDefinitionMetadata -Context $context -Definition $Definition
        if ($securitySettings.Count -gt 0 -and ($Definition.Contains('Comment') -or $Definition.Contains('GpoStatus'))) {
            $nativeState = Get-LabGpoSecurityState -Context $context
        }
        if ($securitySettings.Count -gt 0) {
            $nativeResult = Ensure-LabGpoNativeSecurityOptions -Context $context -Settings $securitySettings -InitialState $nativeState
            $changedCount += $nativeResult.ChangedCount
            $unchangedCount += $nativeResult.UnchangedCount
        }
        foreach ($setting in $registrySettings) {
            Write-LabGpoSettingCheck -Setting $setting
            # Always read from the GPO, NOT the operator machine's registry.
            $current = Get-LabGpoRegistrySetting -Guid $gpoGuid -DomainName $domainName -Server $server `
                -Key $setting.Key -ValueName $setting.ValueName
            $matchesDesired = Test-LabGpoRegistrySettingMatches -Current $current -Desired $setting
            $desiredText = Format-LabGpoRegistrySetting -Setting ([pscustomobject]@{
                Configured = $true; PolicyState = 'Set'; Type = $setting.Type; Value = $setting.Value
            })
            if (-not $matchesDesired) {
                $oldText = Format-LabGpoRegistrySetting -Setting $current
                Write-Status -IndentLevel 3 -Kind Info -Message ('Updating [{0}]: old={1} -> new={2}.' -f $setting.ValueName, $oldText, $desiredText)
                $policyValue = $null
                if ($setting.Type -ieq 'DWord') { $policyValue = [uint32]$setting.Value }
                else { $policyValue = [string[]]$setting.Value }
                if (-not $ApplyWhenLinked) {
                    [xml]$preRegistryReport = Get-GPOReport -Guid $gpoGuid -Domain $domainName -Server $server -ReportType Xml -ErrorAction Stop
                    Assert-LabGpoLinkUpdateAllowed -Report $preRegistryReport -ApplyWhenLinked $ApplyWhenLinked -Name $Definition.Name | Out-Null
                }
                Set-GPRegistryValue -Guid $gpoGuid -Domain $domainName -Server $server `
                    -Key $setting.Key -ValueName $setting.ValueName -Type $setting.Type -Value $policyValue -ErrorAction Stop | Out-Null
            }
            $verified = Get-LabGpoRegistrySetting -Guid $gpoGuid -DomainName $domainName -Server $server `
                -Key $setting.Key -ValueName $setting.ValueName
            if (-not (Test-LabGpoRegistrySettingMatches -Current $verified -Desired $setting)) {
                throw ('Read-back did not match {0} for [{1}].' -f $desiredText, $setting.ValueName)
            }
            if ($matchesDesired) {
                $unchangedCount++
                Write-Status -IndentLevel 4 -Kind Success -Message ('Verified [{0}]: {1} (already matched; no SET).' -f $setting.ValueName, $desiredText)
            }
            else {
                $changedCount++
                Write-Status -IndentLevel 4 -Kind Success -Message ('Verified [{0}]: old={1} -> new={2}.' -f $setting.ValueName, $oldText, $desiredText)
            }
        }
        if ($auditSettings.Count -gt 0) {
            $auditResult = Ensure-LabGpoAdvancedAudit -Context $context -Settings $auditSettings
            $changedCount += $auditResult.ChangedCount
            $unchangedCount += $auditResult.UnchangedCount
        }
        Ensure-LabGpoDefinitionMetadata -Context $context -Definition $Definition -VerifyOnly
        if ($securitySettings.Count -gt 0) {
            $finalNative = Get-LabGpoSecurityState -Context $context
            if ((Merge-LabGpoSecurityExtension -Extensions $finalNative.Extensions) -cne $finalNative.Extensions) { throw 'Final Security extension registration check failed.' }
            foreach ($setting in $securitySettings) {
                $actual = Get-LabGpoSecurityValue -Lines $finalNative.Inf.Lines -Setting $setting
                if (-not $actual.Configured -or [uint32]$actual.Value -ne [uint32]$setting.Value) { throw 'Final native security-template value check failed.' }
                if ($setting.Storage -ine 'SecurityOptions') { continue }
                $duplicate = Get-LabGpoRegistrySetting -Guid $gpoGuid -DomainName $domainName -Server $server -Key $setting.Key -ValueName $setting.ValueName
                if ($duplicate.Configured) { throw 'A managed native setting reappeared in Registry.pol.' }
            }
        }
        [xml]$finalReport = Get-GPOReport -Guid $gpoGuid -Domain $domainName -Server $server -ReportType Xml -ErrorAction Stop
        if ($securitySettings.Count -gt 0) { Assert-LabGpoSecurityReport -Report $finalReport -Settings $securitySettings }
        $finalLinkCount = Assert-LabGpoLinkUpdateAllowed -Report $finalReport -ApplyWhenLinked $ApplyWhenLinked -Name $Definition.Name
        if ($finalLinkCount -ne $initialLinkCount) {
            Write-Status -IndentLevel 2 -Kind Warning -Message ('Reported GPO link count changed during the run ({0} -> {1}); this script made no link changes. Review concurrent link administration and lab target scope.' -f $initialLinkCount, $finalLinkCount)
        }
        Write-Status -IndentLevel 0 -Kind Success -Message ("GPO [{0}]:`n            {1} settings changed, {2} already matched; verified on [{3}]; {4} reported link(s).`n            Link configuration was not changed by this script." -f $Definition.Name, $changedCount, $unchangedCount, $server, $finalLinkCount)
        if ($wasCreated) { Add-LabProcessingCount -Category 'GPOs' -Created 1 -Identity ([string]$gpoGuid) }
        elseif ($changedCount -gt 0 -or $context.SummaryMetadataChanged) { Add-LabProcessingCount -Category 'GPOs' -Updated 1 -Identity ([string]$gpoGuid) }
        return [pscustomobject]@{
            Id = $gpoGuid
            Name = $Definition.Name
            Created = $wasCreated
            ChangedCount = $changedCount
            UnchangedCount = $unchangedCount
            VerifiedCount = $changedCount + $unchangedCount
            LinkCount = $finalLinkCount
            Skipped = $false
            SkipReason = $null
            PartialChangesPossible = $false
        }
    }
    catch {
        # PowerShell may wrap a .NET exception; inspect its inner exceptions.
        # Do not classify failures by matching human-readable error text.
        $linkRefusal = $_.Exception
        while ($null -ne $linkRefusal -and
            -not ($linkRefusal -is [System.InvalidOperationException] -and
                $linkRefusal.Data.Contains('LabGpoLinkUpdateDenied') -and
                $linkRefusal.Data['LabGpoLinkUpdateDenied'] -eq $true)) {
            $linkRefusal = $linkRefusal.InnerException
        }
        if ($null -ne $linkRefusal -and $Definition.Contains('ApplyWhenLinked') -and
            $Definition.ApplyWhenLinked -is [bool] -and -not $Definition.ApplyWhenLinked -and
            [string]$linkRefusal.Data['GpoName'] -ceq [string]$Definition.Name) {
            $partialChangesPossible = $wasCreated -or $reconciliationStarted
            $skipReason = 'ApplyWhenLinked is False and {0} link(s) were reported (including any disabled links).' -f $linkRefusal.Data['LinkCount']
            if ($partialChangesPossible) {
                Write-Status -IndentLevel 2 -Kind Warning -BackgroundColor DarkRed -Message ('Skipping further updates to GPO [{0}]: {1} Earlier writes may have committed; this GPO was not fully verified. No rollback or link changes were attempted. Continuing with the remaining GPOs and script sections.' -f $Definition.Name, $skipReason)
            }
            else {
                Write-Status -IndentLevel 2 -Kind Warning -BackgroundColor DarkRed -Message ('Skipping GPO [{0}]: {1} No settings or metadata writes were made to this GPO. Continuing with the remaining GPOs and script sections.' -f $Definition.Name, $skipReason)
            }
            return [pscustomobject]@{
                Id = $gpoGuid
                Name = $Definition.Name
                Created = $wasCreated
                ChangedCount = $changedCount
                UnchangedCount = $unchangedCount
                VerifiedCount = 0
                LinkCount = [int]$linkRefusal.Data['LinkCount']
                Skipped = $true
                SkipReason = $skipReason
                PartialChangesPossible = $partialChangesPossible
            }
        }
        if (Test-LabGpoFileLockError -Exception $_.Exception) {
            $partialChangesPossible = $wasCreated -or $reconciliationStarted
            $skipReason = 'A file is in use by another process (Windows sharing/lock violation): {0}' -f $_.Exception.Message
            Write-Status -IndentLevel 2 -Kind Warning -Message ('Skipping further processing of GPO [{0}]: {1} This GPO was NOT fully verified and is excluded from successful GPO counts and later synthetic changes. Continuing with the remaining GPOs and script sections.' -f $Definition.Name, $skipReason)
            if ($partialChangesPossible) {
                Write-Status -IndentLevel 3 -Kind Warning -Message 'Earlier GPO writes may have committed; AD/SYSVOL versions or settings may be inconsistent. Review this GPO and its logged pre-write backup before rerunning. No rollback, link changes, automatic write retry or DC failover was attempted.'
            }
            else {
                Write-Status -IndentLevel 3 -Kind Warning -Message 'No GPO creation or settings reconciliation was started. No automatic write retry, rollback, link changes or DC failover was attempted.'
            }
            if (-not [string]::IsNullOrWhiteSpace($backupDirectory)) {
                Write-Status -IndentLevel 3 -Kind Warning -Message ('Pre-write backup location (if backup completed): [{0}].' -f $backupDirectory)
            }
            return [pscustomobject]@{
                Id = $gpoGuid
                Name = $Definition.Name
                Created = $wasCreated
                ChangedCount = 0
                UnchangedCount = 0
                VerifiedCount = 0
                LinkCount = $null
                Skipped = $true
                SkipReason = $skipReason
                PartialChangesPossible = $partialChangesPossible
            }
        }
        Stop-ScriptGracefully -IndentLevel 2 -Message ('Could not initialize lab GPO: {0} Earlier GPO writes may have committed. No link changes, replication wait, rollback or DC failover were attempted.' -f $_.Exception.Message)
    }
}

function Test-LabFgppValueMatches {
    [CmdletBinding()]
    param([AllowNull()]$Actual, [Parameter(Mandatory = $true)]$Expected)
    if ($null -eq $Actual) { return $false }
    if ($Expected -is [timespan]) {
        return ($Actual -is [timespan] -and $Actual.Ticks -eq $Expected.Ticks)
    }
    if ($Expected -is [bool]) { return ($Actual -is [bool] -and $Actual -eq $Expected) }
    if ($Expected -is [string]) { return ([string]$Actual -ceq $Expected) }
    return ($Actual -eq $Expected)
}

function Ensure-LabFineGrainedPasswordPolicies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Definitions
    )
    Write-SectionHeader -Message 'Create/Update Fine-Grained Password Policies...'
    $script:LabFgppChangePlans = @()
    $pendingChanges = @()
    $createdCount = 0
    $updatedCount = 0
    $unchangedCount = 0
    try {
        $server = [string]$Domain.SelectedDomainController
        $domainDN = [string]$Domain.DistinguishedName
        if ([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($domainDN)) {
            throw 'FGPP provisioning requires the selected writable DC and domain DN.'
        }
        if ($Definitions.Count -eq 0) { throw 'No FGPP definitions supplied; no policies were changed.' }
        $container = 'CN=Password Settings Container,CN=System,{0}' -f $domainDN
        Get-ADObject -Identity $container -Server $server -ErrorAction Stop | Out-Null
        # Domain defaults supply unspecified fields on creation only.
        $defaults = Get-ADDefaultDomainPasswordPolicy -Identity $domainDN -Server $server -ErrorAction Stop
        $seenNames = @{}
        $seenPrecedence = @{}
        $plans = @()
        foreach ($definition in $Definitions) {
            if ($definition -isnot [System.Collections.IDictionary]) { throw 'Each FGPP definition must be a hash table.' }
            foreach ($field in @('Name', 'Description', 'Precedence', 'MinPasswordLength', 'MinPasswordAgeDays',
                'MaxPasswordAgeDays', 'PasswordHistoryCount', 'ComplexityEnabled', 'ReversibleEncryptionEnabled',
                'LockoutThreshold', 'LockoutDurationMinutes', 'LockoutObservationWindowMinutes', 'SubjectGroupDNs',
                'RemoveSubjectsAfterReplication')) {
                if (-not $definition.Contains($field)) { throw ('FGPP definition is missing [{0}].' -f $field) }
            }
            if ($definition.Name -isnot [string] -or [string]::IsNullOrWhiteSpace($definition.Name) -or
                $definition.Name -match '[\\/\r\n]' -or $definition.Description -isnot [string] -or
                [string]::IsNullOrWhiteSpace($definition.Description)) { throw 'FGPP Name and Description must be nonblank strings without ambiguous name delimiters.' }
            if ($seenNames.ContainsKey($definition.Name)) { throw 'Duplicate FGPP names in the definitions.' }
            $seenNames[$definition.Name] = $true
            foreach ($field in @('Precedence', 'MinPasswordLength', 'MaxPasswordAgeDays', 'PasswordHistoryCount')) {
                if ($definition[$field] -isnot [int] -or $definition[$field] -lt 0) { throw ('FGPP [{0}] requires a nonnegative integer [{1}].' -f $definition.Name, $field) }
            }
            if ($definition.Precedence -lt 1 -or $definition.MinPasswordLength -gt 255 -or $definition.PasswordHistoryCount -gt 1024 -or
                $definition.MaxPasswordAgeDays -gt 99999) { throw 'FGPP precedence, password length, age or history is outside the supported definition range.' }
            if ($seenPrecedence.ContainsKey($definition.Precedence)) { throw 'Use different precedence values for the two lab FGPPs.' }
            $seenPrecedence[$definition.Precedence] = $true
            foreach ($field in @('MinPasswordAgeDays', 'LockoutThreshold', 'LockoutDurationMinutes', 'LockoutObservationWindowMinutes')) {
                if ($null -ne $definition[$field] -and ($definition[$field] -isnot [int] -or $definition[$field] -lt 0 -or $definition[$field] -gt 99999)) {
                    throw ('Optional FGPP [{0}] must be null or a nonnegative integer at most 99999.' -f $field)
                }
            }
            foreach ($field in @('ComplexityEnabled', 'ReversibleEncryptionEnabled')) {
                if ($null -ne $definition[$field] -and $definition[$field] -isnot [bool]) { throw ('FGPP [{0}] must be null or Boolean.' -f $field) }
            }
            if ($null -eq $definition.SubjectGroupDNs -or $definition.SubjectGroupDNs -isnot [array]) { throw 'SubjectGroupDNs must be an array, including explicit @() for an unassigned policy.' }
            if ($definition.RemoveSubjectsAfterReplication -isnot [bool]) { throw 'Temporary FGPP configuration requires a Boolean removal flag.' }
            if ($definition.RemoveSubjectsAfterReplication) {
                if ($definition.SubjectGroupDNs.Count -eq 0) {
                    throw 'Temporary FGPP assignment requires at least one subject.'
                }
            }
            $subjects = @()
            foreach ($subject in $definition.SubjectGroupDNs) {
                if ($subject -isnot [string] -or [string]::IsNullOrWhiteSpace($subject) -or
                    -not $subject.EndsWith((',' + $domainDN), [StringComparison]::OrdinalIgnoreCase)) { throw 'FGPP subjects must be explicit group DNs in the selected domain.' }
                $group = Get-ADGroup -Identity $subject -Properties GroupScope, GroupCategory -Server $server -ErrorAction Stop
                if ($group.GroupCategory -ine 'Security' -or $group.GroupScope -ine 'Global' -or $group.DistinguishedName -ine $subject) {
                    throw ('FGPP target [{0}] must resolve to that exact Global Security group.' -f $subject)
                }
                if ($subjects -inotcontains ([string]$group.DistinguishedName)) { $subjects += [string]$group.DistinguishedName }
            }
            $escaped = ConvertTo-LdapFilterValue -Value $definition.Name
            $matches = @(Get-ADObject -LDAPFilter ('(&(objectClass=msDS-PasswordSettings)(name={0}))' -f $escaped) `
                -SearchBase $container -SearchScope OneLevel -Server $server -ErrorAction Stop)
            if ($matches.Count -gt 1) { throw ('Multiple FGPP objects matched [{0}].' -f $definition.Name) }
            $current = $null
            if ($matches.Count -eq 1) {
                $current = Get-ADFineGrainedPasswordPolicy -Identity $matches[0].ObjectGUID -Properties * -Server $server -ErrorAction Stop
                if ($null -eq $current -or [guid]$current.ObjectGUID -eq [guid]::Empty -or
                    [guid]$current.ObjectGUID -ne [guid]$matches[0].ObjectGUID -or $current.Name -cne $definition.Name) {
                    throw 'FGPP identity read-back did not match the exact requested object.'
                }
            }
            $parameters = @{
                Description = $definition.Description
                Precedence = $definition.Precedence
                MinPasswordLength = $definition.MinPasswordLength
                MaxPasswordAge = (New-TimeSpan -Days $definition.MaxPasswordAgeDays)
                PasswordHistoryCount = $definition.PasswordHistoryCount
            }
            # This mapping is operational plumbing, not another desired-state list.
            $optional = @{
                MinPasswordAgeDays = 'MinPasswordAge'
                ComplexityEnabled = 'ComplexityEnabled'
                ReversibleEncryptionEnabled = 'ReversibleEncryptionEnabled'
                LockoutThreshold = 'LockoutThreshold'
                LockoutDurationMinutes = 'LockoutDuration'
                LockoutObservationWindowMinutes = 'LockoutObservationWindow'
            }
            foreach ($field in $optional.Keys) {
                $property = $optional[$field]
                if ($null -ne $definition[$field]) {
                    $value = $definition[$field]
                    if ($field -eq 'MinPasswordAgeDays') { $value = New-TimeSpan -Days $value }
                    elseif ($field.EndsWith('Minutes')) { $value = New-TimeSpan -Minutes $value }
                    $parameters[$property] = $value
                }
                elseif ($null -eq $current) { $parameters[$property] = $defaults.$property }
            }
            $minAge = if ($parameters.ContainsKey('MinPasswordAge')) { $parameters.MinPasswordAge } else { $current.MinPasswordAge }
            if ($parameters.MaxPasswordAge -ne [timespan]::Zero -and $minAge -ge $parameters.MaxPasswordAge) {
                throw ('FGPP [{0}] minimum password age must be less than its nonzero maximum age.' -f $definition.Name)
            }
            $duration = if ($parameters.ContainsKey('LockoutDuration')) { $parameters.LockoutDuration } else { $current.LockoutDuration }
            $window = if ($parameters.ContainsKey('LockoutObservationWindow')) { $parameters.LockoutObservationWindow } else { $current.LockoutObservationWindow }
            if ($duration -ne [timespan]::Zero -and $window -gt $duration) { throw 'FGPP lockout observation window cannot exceed nonzero lockout duration.' }
            $plans += [pscustomobject]@{
                Name=$definition.Name; Current=$current; Parameters=$parameters; Subjects=$subjects
                RemoveSubjectsAfterReplication=$definition.RemoveSubjectsAfterReplication
            }
        }

        # All identities, groups and desired values have passed preflight.
        foreach ($plan in $plans) {
            Write-Status -Kind Info -Message ('Checking FGPP [{0}] on [{1}].' -f $plan.Name, $server)
            $created = $null -eq $plan.Current
            $changed = $false
            if ($created) {
                Write-Status -IndentLevel 3 -Kind Info -Message ('Creating FGPP [{0}].' -f $plan.Name)
                $create = $plan.Parameters.Clone()
                Assert-LabInventoryHealthy
                $policy = New-ADFineGrainedPasswordPolicy -Name $plan.Name @create -Server $server -PassThru -ErrorAction Stop
                Add-LabGeneratedADObject -Kind FGPP -Object $policy
                if ($null -eq $policy -or [guid]$policy.ObjectGUID -eq [guid]::Empty) { throw 'New FGPP did not return an object GUID.' }
                $identity = $policy.ObjectGUID
            }
            else {
                $identity = $plan.Current.ObjectGUID
                $changes = @{}
                foreach ($property in $plan.Parameters.Keys) {
                    if (-not (Test-LabFgppValueMatches -Actual $plan.Current.$property -Expected $plan.Parameters[$property])) { $changes[$property] = $plan.Parameters[$property] }
                }
                if ($changes.Count -gt 0) {
                    Write-Status -IndentLevel 3 -Kind Info -Message ('Updating FGPP [{0}] fields: {1}.' -f $plan.Name, (($changes.Keys | Sort-Object) -join ', '))
                    Set-ADFineGrainedPasswordPolicy -Identity $identity @changes -Server $server -ErrorAction Stop
                    $changed = $true
                }
            }
            $verified = Get-ADFineGrainedPasswordPolicy -Identity $identity -Properties * -Server $server -ErrorAction Stop
            if ($null -eq $verified -or [guid]$verified.ObjectGUID -ne [guid]$identity -or $verified.Name -cne $plan.Name) { throw 'FGPP read-back returned an unexpected identity.' }
            foreach ($property in $plan.Parameters.Keys) {
                if (-not (Test-LabFgppValueMatches -Actual $verified.$property -Expected $plan.Parameters[$property])) { throw ('FGPP [{0}] read-back mismatch for [{1}].' -f $plan.Name, $property) }
            }
            $actualSubjects = @($verified.AppliesTo | ForEach-Object { [string]$_ })
            $missing = @($plan.Subjects | Where-Object { $actualSubjects -inotcontains $_ })
            if ($missing.Count -gt 0) {
                Write-Status -IndentLevel 3 -Kind Info -Message ('Assigning FGPP [{0}] to: {1}.' -f $plan.Name, ($missing -join '; '))
                Add-ADFineGrainedPasswordPolicySubject -Identity $identity -Subjects $missing -Server $server -ErrorAction Stop
                $changed = $true
            }
            # Verify intended subjects before removing extras; an empty list is
            # explicitly authoritative for the unassigned lab test policy.
            $assigned = Get-ADFineGrainedPasswordPolicy -Identity $identity -Properties * -Server $server -ErrorAction Stop
            if ($null -eq $assigned -or [guid]$assigned.ObjectGUID -ne [guid]$identity -or $assigned.Name -cne $plan.Name) { throw 'FGPP read-back returned an unexpected identity.' }
            $assignedSubjects = @($assigned.AppliesTo | ForEach-Object { [string]$_ })
            foreach ($subject in $plan.Subjects) { if ($assignedSubjects -inotcontains $subject) { throw 'FGPP desired subject assignment did not verify; extra subjects were not removed.' } }
            $extra = @($assignedSubjects | Where-Object { $plan.Subjects -inotcontains $_ })
            if ($extra.Count -gt 0) {
                Write-Status -IndentLevel 2 -Kind Warning -Message ('Removing extra subjects from managed FGPP [{0}]: {1}.' -f $plan.Name, ($extra -join '; '))
                Remove-ADFineGrainedPasswordPolicySubject -Identity $identity -Subjects $extra -Confirm:$false -Server $server -ErrorAction Stop
                $changed = $true
            }
            $final = Get-ADFineGrainedPasswordPolicy -Identity $identity -Properties * -Server $server -ErrorAction Stop
            if ($null -eq $final -or [guid]$final.ObjectGUID -ne [guid]$identity -or $final.Name -cne $plan.Name) { throw 'FGPP read-back returned an unexpected identity.' }
            foreach ($property in $plan.Parameters.Keys) {
                if (-not (Test-LabFgppValueMatches -Actual $final.$property -Expected $plan.Parameters[$property])) { throw 'FGPP final parameter verification failed.' }
            }
            $finalSubjects = @($final.AppliesTo | ForEach-Object { [string]$_ })
            if ($finalSubjects.Count -ne $plan.Subjects.Count -or @($finalSubjects | Where-Object { $plan.Subjects -inotcontains $_ }).Count -gt 0) { throw 'FGPP final exact subject verification failed.' }
            if ($plan.RemoveSubjectsAfterReplication) {
                # Cache only verified baseline state; do not mutate it here.
                $pendingChanges += [pscustomobject]@{
                    Name=$plan.Name; ObjectGUID=([guid]$identity)
                    Parameters=$plan.Parameters.Clone(); Subjects=@($plan.Subjects)
                }
            }
            if ($created) { $createdCount++ }
            elseif ($changed) { $updatedCount++ }
            else { $unchangedCount++ }
            Write-Status -IndentLevel 2 -Kind Success -Message ('Verified FGPP [{0}]: minimum length {1}, maximum age {2} days, history {3}; {4} assigned group(s).' -f $plan.Name, $final.MinPasswordLength, $final.MaxPasswordAge.TotalDays, $final.PasswordHistoryCount, $finalSubjects.Count)
        }
        $script:LabFgppChangePlans = @($pendingChanges)
        Write-Status -IndentLevel 2 -Kind Warning -Message 'FGPP baseline assignments are verified, not per-user resultant policy. Temporary assignment removal runs only in the later synthetic AD Changes phase. Competing policies, direct user assignments and PasswordNeverExpires may change effective behavior. No passwords or group memberships were changed by FGPP provisioning.'
        Write-Status -IndentLevel 0 -Kind Success -Message ('FGPPs: {0} created, {1} updated, {2} already matched; verified on [{3}].' -f $createdCount, $updatedCount, $unchangedCount, $server)
        Add-LabProcessingCount -Category 'FGPPs' -Created $createdCount -Updated $updatedCount
        return [pscustomobject]@{ CreatedCount=$createdCount; UpdatedCount=$updatedCount; UnchangedCount=$unchangedCount; VerifiedCount=($createdCount+$updatedCount+$unchangedCount) }
    }
    catch {
        Stop-ScriptGracefully -IndentLevel 2 -Message ('Could not reconcile lab FGPPs: {0} Earlier writes may have committed and temporary FGPP assignments may remain active; no rollback or DC failover was attempted.' -f $_.Exception.Message)
    }
}

function Invoke-LabReplicationCheckpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$SectionName,
        [ValidateSet('Domain', 'Configuration', 'Dns')][string]$Partition = 'Domain',
        [Parameter(Mandatory = $true)][ValidateSet('Baseline', 'Synthetic')][string]$Phase
    )

    try {
        $phaseLabel = $Phase.ToLowerInvariant()
        $server = [string]$Domain.SelectedDomainController
        $domainDN = [string]$Domain.DistinguishedName
        if ([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($domainDN) -or
            [string]::IsNullOrWhiteSpace($SectionName)) {
            throw ('{0} replication requires the selected writable DC, domain DN and section name.' -f $Phase)
        }
        $singleDnsSync = ($Partition -eq 'Dns' -and $Phase -eq 'Synthetic')
        $namingContext = $domainDN
        if ($Partition -eq 'Configuration') {
            $rootDse = Get-ADRootDSE -Server $server -ErrorAction Stop
            $namingContext = [string]$rootDse.configurationNamingContext
            if ([string]::IsNullOrWhiteSpace($namingContext)) {
                throw 'The selected DC did not return the Configuration naming context; no replication was attempted.'
            }
        }
        $namingContexts = @($namingContext)
        if ($singleDnsSync) {
            # One native invocation, not one invocation per naming context.
            # /A includes Schema/Configuration as well as DNS/domain data.
            $namingContexts = @('all hosted naming contexts (/A)')
        }
        elseif ($Partition -eq 'Dns') {
            $rootDse = Get-ADRootDSE -Server $server -ErrorAction Stop
            # Include custom hosted application NCs too, while excluding Schema
            # and Configuration. This covers an existing custom-scope AD zone.
            $namingContexts = @($rootDse.namingContexts | Where-Object {
                $_ -ine [string]$rootDse.configurationNamingContext -and
                $_ -ine [string]$rootDse.schemaNamingContext
            } | Sort-Object -Unique)
            if ($namingContexts.Count -eq 0) { throw 'The selected DC returned no hosted data naming contexts for DNS replication.' }
        }
        $repadmin = Get-Command -Name 'repadmin.exe' -CommandType Application -ErrorAction Stop
        Write-SectionHeader -Message ('Replicate {0} changes - {1}...' -f $phaseLabel, $SectionName)
        if ($singleDnsSync) {
            Write-Status -Kind Info -Message ('Forcing synthetic DNS checkpoint replication from [{0}] using one repadmin /syncall /A /d /e /P invocation across all hosted naming contexts, including Schema and Configuration. Native callbacks may list multiple partitions/partners. SYSVOL/DFSR convergence and DSP capture are not verified.' -f $server)
        }
        else {
            Write-Status -Kind Info -Message ('Forcing {0} {1}-partition replication from [{2}] for [{3}] using repadmin /syncall /d /e /P. SYSVOL/DFSR convergence and DSP capture are not verified.' -f $phaseLabel, $Partition, $server, ($namingContexts -join '; '))
        }
        # One checkpoint after the complete batch. /P pushes from the
        # selected DC; /e includes other sites. Only synthetic DNS uses /A.
        # All other checkpoints retain their explicit naming-context scope.
        foreach ($namingContext in $namingContexts) {
            if ($singleDnsSync) {
                $syncArguments = @('/syncall', $server, '/A', '/d', '/e', '/P')
            }
            else {
                $syncArguments = @('/syncall', $server, $namingContext, '/d', '/e', '/P')
            }
            & $repadmin.Path @syncArguments | ForEach-Object {
                $line = [string]$_
                if (-not [string]::IsNullOrWhiteSpace($line)) {
                    Write-Host (Format-OutputMessage -Message ('[INFO] {0}' -f $line) -IndentLevel 2) -ForegroundColor Gray
                }
            }
            $syncExitCode = $LASTEXITCODE
            if ($syncExitCode -ne 0) {
                throw ('{0} repadmin /syncall returned exit code {1} for [{2}]; the configured pause was not started.' -f $Phase, $syncExitCode, $namingContext)
            }
        }
        Write-Host (Format-OutputMessage -Message ('[INFO] pausing for {0} seconds for replication settling after {1} {2}...' -f $PauseTimeSeconds, $phaseLabel, $SectionName) -IndentLevel 1) -ForegroundColor Gray -BackgroundColor DarkGreen
        Start-Sleep -Seconds $PauseTimeSeconds -ErrorAction Stop
        Write-Status -IndentLevel 2 -Kind Success -Message ('{0} [{1}] replication command succeeded; {2}-second pause complete. AD/SYSVOL convergence and DSP capture have not been verified.' -f $Phase, $SectionName, $PauseTimeSeconds)
    }
    catch {
        if ($Partition -eq 'Dns') {
            Write-Status -IndentLevel 2 -Kind Warning -BackgroundColor Red -Message ('DNS replication checkpoint did not complete: {0} Earlier DNS writes remain committed; no rollback or DC failover was attempted. Continuing with other baseline sections.' -f $_.Exception.Message)
            return
        }
        Stop-ScriptGracefully -IndentLevel 2 -Message ('{0} replication checkpoint failed for [{1}]: {2} Earlier writes remain committed; no rollback or DC failover was attempted.' -f $Phase, $SectionName, $_.Exception.Message)
    }
}

function Invoke-LabBaselineReplicationSync {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$SectionName,
        [ValidateSet('Domain', 'Configuration', 'Dns')][string]$Partition = 'Domain'
    )

    Invoke-LabReplicationCheckpoint -Domain $Domain -SectionName $SectionName -Partition $Partition -Phase Baseline
}

function Invoke-LabSyntheticReplicationSync {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$SectionName,
        [ValidateSet('Domain', 'Configuration', 'Dns')][string]$Partition = 'Domain'
    )

    Invoke-LabReplicationCheckpoint -Domain $Domain -SectionName $SectionName -Partition $Partition -Phase Synthetic
}

function Invoke-LabGpoReplicationSync {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Domain)

    # Preserve the existing entry point; use the configurable baseline
    # standard as other object types. This does not force SYSVOL or DSP capture.
    Invoke-LabBaselineReplicationSync -Domain $Domain -SectionName 'GPOs' -Partition Domain
}

# ======================================================================
# SYNTHETIC AD CHANGES - POST-PROVISIONING
# ======================================================================
# A successful GUID LDAP read can return null for a missing target. Read
# failures propagate; permission/connection errors never mean "not found".
function Get-LabVerifiedComputerChangeTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][guid]$Identity,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Definition,
        [Parameter(Mandatory = $true)][string]$DomainDN,
        [Parameter(Mandatory = $true)][string]$Server
    )
    if ($Identity -eq [guid]::Empty) { throw 'Synthetic computer GUID is empty.' }
    $escapedGuid = ($Identity.ToByteArray() | ForEach-Object { '\{0:X2}' -f $_ }) -join ''
    $matches = @(Get-ADObject -LDAPFilter ('(objectGUID={0})' -f $escapedGuid) -SearchBase $DomainDN -SearchScope Subtree `
        -Properties SamAccountName,Description,userAccountControl -Server $Server -ErrorAction Stop)
    if ($matches.Count -eq 0) { return $null }
    if ($matches.Count -ne 1) { throw 'Synthetic computer GUID lookup is ambiguous.' }
    $computer = $matches[0]
    $expectedSam = ConvertTo-LabComputerSamAccountName -SamAccountName $Definition.SamAccountName
    if ($computer.ObjectClass -ine 'computer' -or [guid]$computer.ObjectGUID -ne $Identity -or
        $computer.Name -cne $Definition.Name -or $computer.SamAccountName -ine $expectedSam -or
        (Get-ParentDistinguishedName -DistinguishedName $computer.DistinguishedName) -ine $Definition.Path -or
        (([int]$computer.userAccountControl -band 8192) -ne 0)) {
        throw 'Synthetic computer no longer matches its verified baseline GUID/type/name/SAM/path, or is a domain controller.'
    }
    return $computer
}

function Invoke-LabComputerADChanges {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Definitions,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$ComputerDefinitions,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$ComputerObjects
    )
    try {
        $server = [string]$Domain.SelectedDomainController
        $domainDN = [string]$Domain.DistinguishedName
        if ([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($domainDN)) { throw 'Synthetic computer changes require the selected DC and domain DN.' }
        $plans = @()
        $seen = @{}
        $skipped = 0
        # Preflight all configured actions before the first computer mutation.
        foreach ($key in $Definitions.Keys) {
            $definition = $Definitions[$key]
            if ($definition -isnot [System.Collections.IDictionary] -or -not $definition.Contains('Action')) { throw 'Synthetic computer change requires an Action.' }
            $action = [string]$definition['Action']
            if ($action -notin @('Delete','SetDescription')) { throw 'Unsupported synthetic computer action.' }
            if (($action -eq 'Delete' -and $definition.Count -ne 1) -or
                ($action -eq 'SetDescription' -and ($definition.Count -ne 2 -or -not $definition.Contains('Description') -or
                    $definition['Description'] -isnot [string] -or [string]::IsNullOrWhiteSpace($definition['Description']) -or $definition['Description'].IndexOf([char]0) -ge 0))) {
                throw 'Synthetic computer actions must specify Delete only, or SetDescription with a nonblank Description.'
            }
            if (-not $ComputerDefinitions.Contains($key)) { throw 'Synthetic computer key lacks a baseline definition.' }
            if (-not $ComputerObjects.Contains($key) -or $null -eq $ComputerObjects[$key]) {
                Write-Status -IndentLevel 2 -Kind Error -Message ('Synthetic computer [{0}] has no verified baseline reference; it may be missing or baseline provisioning was skipped. Action [{1}] skipped; continuing.' -f $key,$action)
                $skipped++
                continue
            }
            $guid = [guid]$ComputerObjects[$key].ObjectGUID
            if ($guid -eq [guid]::Empty -or $seen.ContainsKey($guid.ToString())) { throw 'Invalid or duplicate synthetic computer GUID.' }
            $seen[$guid.ToString()] = $true
            $readParameters = @{ Identity=$guid; Definition=$ComputerDefinitions[$key]; DomainDN=$domainDN; Server=$server }
            $computer = Get-LabVerifiedComputerChangeTarget @readParameters
            if ($null -eq $computer) {
                Write-Status -IndentLevel 2 -Kind Error -Message ('Synthetic computer [{0}] does not exist on [{1}]. Action [{2}] skipped; continuing.' -f $key,$server,$action)
                $skipped++
                continue
            }
            $description = $null
            if ($action -eq 'SetDescription') { $description = [string]$definition['Description'] }
            $plans += [pscustomobject]@{ Key=$key; Action=$action; ReadParameters=$readParameters; Description=$description; InitialDescription=[string]$computer.Description }
        }
        $changed = 0
        $deleted = 0
        $unchanged = 0
        foreach ($plan in $plans) {
            $readParameters = $plan.ReadParameters
            $computer = Get-LabVerifiedComputerChangeTarget @readParameters
            if ($null -eq $computer) {
                Write-Status -IndentLevel 2 -Kind Error -Message ('Synthetic computer [{0}] no longer exists. Action [{1}] skipped; continuing.' -f $plan.Key,$plan.Action)
                $skipped++
                continue
            }
            if ($plan.Action -eq 'Delete') {
                Write-Status -IndentLevel 2 -Kind Info -Message ('Deleting verified computer [{0}]; GUID [{1}].' -f $computer.Name,$readParameters.Identity)
                try {
                    Remove-ADComputer -Identity $readParameters.Identity -Server $server -Confirm:$false -ErrorAction Stop
                }
                catch {
                    # Handle disappearance between the last read and delete.
                    # Only the AD not-found error is nonfatal; denied deletes
                    # and other failures still stop without protection bypass.
                    if ($_.CategoryInfo.Category -ne [System.Management.Automation.ErrorCategory]::ObjectNotFound) { throw }
                    $remaining = Get-LabVerifiedComputerChangeTarget @readParameters
                    if ($null -ne $remaining) { throw }
                    Write-Status -IndentLevel 2 -Kind Error -Message ('Synthetic computer [{0}] disappeared before deletion. Delete skipped; continuing.' -f $plan.Key)
                    $skipped++
                    continue
                }
                $remaining = Get-LabVerifiedComputerChangeTarget @readParameters
                if ($null -ne $remaining) { throw 'Synthetic computer deletion did not verify.' }
                Add-LabProcessingCount -Category 'computers' -Deleted 1 -Identity ([string]$readParameters.Identity)
                [void]$ComputerObjects.Remove($plan.Key)
                $deleted++
                Write-Status -IndentLevel 2 -Kind Success -Message ('Verified computer [{0}] deleted on [{1}].' -f $plan.Key,$server)
                continue
            }
            if ([string]$computer.Description -cne $plan.InitialDescription) { throw 'Synthetic computer description changed after preflight.' }
            if ([string]$computer.Description -ceq $plan.Description) { $unchanged++; continue }
            Write-Status -IndentLevel 2 -Kind Info -Message ('Changing computer [{0}] Description to [{1}].' -f $computer.Name,$plan.Description)
            Set-ADComputer -Identity $readParameters.Identity -Description $plan.Description -Server $server -ErrorAction Stop
            $verified = Get-LabVerifiedComputerChangeTarget @readParameters
            if ($null -eq $verified -or [string]$verified.Description -cne $plan.Description) { throw 'Synthetic computer Description read-back failed.' }
            Add-LabProcessingCount -Category 'computers' -Updated 1 -Identity ([string]$readParameters.Identity)
            $ComputerObjects[$plan.Key] = $verified
            $changed++
            Write-Status -IndentLevel 2 -Kind Success -Message ('Verified computer [{0}] Description: {1}.' -f $verified.Name,$plan.Description)
        }
        return [pscustomobject]@{ ChangedCount=$changed; DeletedCount=$deleted; UnchangedCount=$unchanged; SkippedCount=$skipped }
    }
    catch {
        Stop-ScriptGracefully -IndentLevel 2 -Message ('Synthetic computer changes failed: {0} Earlier writes may have committed. No creation, name fallback, protection bypass, rollback or DC failover attempted.' -f $_.Exception.Message)
    }
}

# Read only this run's verified user GUID; never adopt a same-name object.
function Get-LabVerifiedDemoUserChangeTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][guid]$Identity,
        [Parameter(Mandatory = $true)][string]$ExpectedName,
        [Parameter(Mandatory = $true)][string]$ExpectedSam,
        [Parameter(Mandatory = $true)][string]$Server
    )
    if ($Identity -eq [guid]::Empty) { throw 'Synthetic demo-user target GUID is empty.' }
    $user = Get-ADUser -Identity $Identity -Properties facsimileTelephoneNumber -Server $Server -ErrorAction Stop
    if ($null -eq $user -or [guid]$user.ObjectGUID -ne $Identity -or
        $user.ObjectClass -ine 'user' -or $user.Name -cne $ExpectedName -or
        $user.SamAccountName -ine $ExpectedSam) {
        throw 'Synthetic demo-user identity no longer matches the verified baseline GUID/name/SAM.'
    }
    return $user
}

function Invoke-LabDemoUserADChanges {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Definitions,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$UserDefinitions,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$UserObjects
    )
    try {
        $server = [string]$Domain.SelectedDomainController
        if ([string]::IsNullOrWhiteSpace($server)) { throw 'Synthetic demo-user changes require the selected DC.' }
        $plans = @()
        $seen = @{}
        # Preflight every target before any fax write.
        foreach ($key in $Definitions.Keys) {
            $definition = $Definitions[$key]
            if ($definition -isnot [System.Collections.IDictionary] -or $definition.Count -ne 1 -or
                -not $definition.Contains('FAX') -or $definition['FAX'] -isnot [string] -or
                [string]::IsNullOrWhiteSpace($definition['FAX']) -or $definition['FAX'].IndexOf([char]0) -ge 0) {
                throw 'Synthetic demo-user definitions require only one nonblank string FAX field.'
            }
            if (-not $UserDefinitions.Contains($key) -or -not $UserObjects.Contains($key) -or $null -eq $UserObjects[$key]) {
                throw ('Synthetic demo-user [{0}] lacks a verified baseline reference.' -f $key)
            }
            $baseline = $UserDefinitions[$key]
            $guid = [guid]$UserObjects[$key].ObjectGUID
            if ($guid -eq [guid]::Empty -or $seen.ContainsKey($guid.ToString())) { throw 'Invalid or duplicate synthetic demo-user GUID.' }
            $seen[$guid.ToString()] = $true
            $readParameters = @{ Identity=$guid; ExpectedName=[string]$baseline.Name; ExpectedSam=[string]$baseline.SamAccountName; Server=$server }
            $current = Get-LabVerifiedDemoUserChangeTarget @readParameters
            $plans += [pscustomobject]@{ Key=$key; ReadParameters=$readParameters; Fax=[string]$definition['FAX']; InitialFax=[string]$current.facsimileTelephoneNumber }
        }
        $changed = 0
        $unchanged = 0
        foreach ($plan in $plans) {
            $readParameters = $plan.ReadParameters
            $current = Get-LabVerifiedDemoUserChangeTarget @readParameters
            if ([string]$current.facsimileTelephoneNumber -cne $plan.InitialFax) { throw 'Synthetic demo-user fax changed after preflight.' }
            if ([string]$current.facsimileTelephoneNumber -ceq $plan.Fax) {
                $unchanged++
                Write-Status -IndentLevel 2 -Kind Info -Message ('Demo user [{0}] FAX already matches [{1}]; no write.' -f $current.Name, $plan.Fax)
                continue
            }
            Write-Status -IndentLevel 2 -Kind Info -Message ('Changing demo user [{0}] FAX to [{1}].' -f $current.Name, $plan.Fax)
            Set-ADUser -Identity $readParameters.Identity -Replace @{ facsimileTelephoneNumber=$plan.Fax } -Server $server -ErrorAction Stop
            $verified = Get-LabVerifiedDemoUserChangeTarget @readParameters
            if ([string]$verified.facsimileTelephoneNumber -cne $plan.Fax) { throw 'Synthetic demo-user fax read-back failed.' }
            Add-LabProcessingCount -Category 'demo users' -Updated 1 -Identity ([string]$readParameters.Identity)
            $changed++
            Write-Status -IndentLevel 2 -Kind Success -Message ('Verified demo user [{0}] FAX: {1}.' -f $verified.Name, $plan.Fax)
        }
        return [pscustomobject]@{ ChangedCount=$changed; UnchangedCount=$unchanged }
    }
    catch {
        Stop-ScriptGracefully -IndentLevel 2 -Message ('Synthetic demo-user changes failed: {0} Earlier writes may have committed. No password resets, account creation, name fallback, rollback or DC failover attempted.' -f $_.Exception.Message)
    }
}

# Target only verified baseline GUIDs. No creation, CN rename or link edits.
# Delete is an exclusive action; removal is nonrecursive and verified on DC.
function Invoke-LabWmiFilterADChanges {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Definitions,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Targets,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$BaselineDefinitions
    )
    try {
        $server = [string]$Domain.SelectedDomainController
        $domainDN = [string]$Domain.DistinguishedName
        if ([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($domainDN)) {
            throw 'Synthetic WMI changes require the selected DC and domain DN.'
        }
        $containerDN = 'CN=SOM,CN=WMIPolicy,CN=System,{0}' -f $domainDN
        $properties = @('msWMI-Name','msWMI-ID','msWMI-Parm1','msWMI-Parm2','msWMI-CreationDate','msWMI-ChangeDate')
        $plans = @()
        $seen = @{}
        # Preflight all change/delete targets before the first write.
        foreach ($key in $Definitions.Keys) {
            if (-not $Targets.Contains($key) -or -not $BaselineDefinitions.Contains($key)) {
                throw ('Synthetic WMI target [{0}] has no verified baseline reference.' -f $key)
            }
            $definition = $Definitions[$key]
            $baseline = $BaselineDefinitions[$key]
            if ($definition -isnot [System.Collections.IDictionary] -or $definition.Count -lt 1) {
                throw 'Synthetic WMI changes require a nonempty definition.'
            }
            foreach ($field in $definition.Keys) {
                if (@('Name','Description','Queries','Delete') -notcontains $field) { throw 'Unsupported synthetic WMI change field.' }
            }
            $delete = $false
            if ($definition.Contains('Delete')) {
                if ($definition['Delete'] -isnot [bool] -or -not $definition['Delete'] -or $definition.Count -ne 1) {
                    throw 'Synthetic WMI Delete must be Boolean true and cannot be combined with changes.'
                }
                $delete = $true
            }
            $target = $Targets[$key]
            $guid = [guid]$target.ObjectGUID
            if ($guid -eq [guid]::Empty -or $seen.ContainsKey($guid.ToString())) { throw 'Invalid or duplicate synthetic WMI target GUID.' }
            $seen[$guid.ToString()] = $true
            $name = [string]$baseline.Name
            if ($definition.Contains('Name')) {
                $name = [string]$definition['Name']
                if ([string]::IsNullOrWhiteSpace($name) -or $name -cne $name.Trim() -or $name.IndexOf([char]0) -ge 0) {
                    throw 'Synthetic WMI Name must be nonblank and trimmed.'
                }
            }
            $current = Get-ADObject -Identity $guid -Properties $properties -Server $server -ErrorAction Stop
            # Accept baseline or exact desired state for idempotent repeats.
            $currentName = [string]$current.'msWMI-Name'
            if ($currentName -ine [string]$baseline.Name -and $currentName -ine $name) { throw 'Synthetic WMI target name drifted unexpectedly.' }
            Assert-LabWmiFilterIdentity -Object $current -ContainerDN $containerDN -FilterName $currentName `
                -ExpectedObjectGuid $guid -ExpectedFilterId ([string]$target.FilterId)
            $expected = @{}
            if ($definition.Contains('Name')) {
                $expected['msWMI-Name'] = $name
                $ldap = '(msWMI-Name={0})' -f (ConvertTo-LdapFilterValue -Value $name)
                $collisions = @(Get-ADObject -LDAPFilter $ldap -SearchBase $containerDN -SearchScope OneLevel -Properties $properties -Server $server -ErrorAction Stop)
                if (@($collisions | Where-Object { [guid]$_.ObjectGUID -ne $guid }).Count -gt 0) { throw 'Synthetic WMI name collides with another object.' }
            }
            if ($definition.Contains('Description')) {
                if ($definition['Description'] -isnot [string] -or
                    [string]::IsNullOrEmpty($definition['Description']) -or $definition['Description'].IndexOf([char]0) -ge 0) {
                    throw 'Synthetic WMI Description must be a nonempty string without NUL characters.'
                }
                # Use the configured desired value, not current + suffix, so
                # repeats never append TEST more than once. Baseline Parm1
                # remains independently configured and is restored on rerun.
                $expected['msWMI-Parm1'] = $definition['Description']
            }
            if ($definition.Contains('Queries')) {
                if ($definition['Queries'] -isnot [array]) { throw 'Synthetic WMI Queries must be an explicit array.' }
                $expected['msWMI-Parm2'] = ConvertTo-LabWmiFilterQueryData -Namespace $baseline.Namespace -Queries $definition['Queries']
            }
            $plans += [pscustomobject]@{ Key=$key; Guid=$guid; FilterId=[string]$target.FilterId; Name=$name; Current=$current; Expected=$expected; Delete=$delete }
        }
        $changed = 0
        $unchanged = 0
        $deleted = 0
        foreach ($plan in $plans) {
            $current = Get-ADObject -Identity $plan.Guid -Properties $properties -Server $server -ErrorAction Stop
            Assert-LabWmiFilterIdentity -Object $current -ContainerDN $containerDN -FilterName ([string]$plan.Current.'msWMI-Name') `
                -ExpectedObjectGuid $plan.Guid -ExpectedFilterId $plan.FilterId
            foreach ($attribute in $properties) {
                if ([string]$current.$attribute -cne [string]$plan.Current.$attribute) { throw 'Synthetic WMI target changed after preflight.' }
            }
            if ($plan.Delete) {
                Write-Status -IndentLevel 2 -Kind Info -Message ('Deleting WMI filter [{0}]; GUID [{1}]; ID [{2}].' -f $plan.Name, $plan.Guid, $plan.FilterId)
                # No -Recursive: unexpected child objects must cause failure.
                Remove-ADObject -Identity $plan.Guid -Server $server -Confirm:$false -ErrorAction Stop
                # A successful, domain-wide GUID query must return no object.
                # Denied/failed reads are fatal, never interpreted as absence.
                $escapedGuid = (([guid]$plan.Guid).ToByteArray() | ForEach-Object { '\{0:X2}' -f $_ }) -join ''
                $remaining = @(Get-ADObject -LDAPFilter ('(objectGUID={0})' -f $escapedGuid) `
                    -SearchBase $domainDN -SearchScope Subtree -Server $server -ErrorAction Stop)
                if ($remaining.Count -ne 0) { throw 'Synthetic WMI deletion did not verify; target GUID is still present.' }
                Add-LabProcessingCount -Category 'WMI filters' -Deleted 1 -Identity ([string]$plan.Guid)
                [void]$Targets.Remove($plan.Key)
                $deleted++
                Write-Status -IndentLevel 2 -Kind Success -Message ('Verified WMI filter [{0}] deleted on [{1}]. GPO references were not edited.' -f $plan.Name, $server)
                continue
            }
            $replace = @{}
            foreach ($attribute in $plan.Expected.Keys) {
                if ([string]$current.$attribute -cne $plan.Expected[$attribute]) { $replace[$attribute] = $plan.Expected[$attribute] }
            }
            $stamp = [string]$current.'msWMI-ChangeDate'
            if ($replace.Count -gt 0) {
                if ($plan.Expected.ContainsKey('msWMI-Name')) {
                    $ldap = '(msWMI-Name={0})' -f (ConvertTo-LdapFilterValue -Value $plan.Name)
                    $collisions = @(Get-ADObject -LDAPFilter $ldap -SearchBase $containerDN -SearchScope OneLevel -Properties $properties -Server $server -ErrorAction Stop)
                    if (@($collisions | Where-Object { [guid]$_.ObjectGUID -ne $plan.Guid }).Count -gt 0) { throw 'Synthetic WMI name collision appeared after preflight.' }
                }
                $stamp = [DateTime]::UtcNow.ToString('yyyyMMddHHmmss.ffffff', [Globalization.CultureInfo]::InvariantCulture) + '-000'
                $replace['msWMI-ChangeDate'] = $stamp
                Write-Status -IndentLevel 2 -Kind Info -Message ('Changing WMI filter [{0}]: {1}.' -f $plan.Key, (($replace.Keys | Sort-Object) -join ', '))
                Set-ADObject -Identity $plan.Guid -Replace $replace -Server $server -ErrorAction Stop
                $changed++
            }
            else { $unchanged++ }
            $verified = Get-ADObject -Identity $plan.Guid -Properties $properties -Server $server -ErrorAction Stop
            Assert-LabWmiFilterIdentity -Object $verified -ContainerDN $containerDN -FilterName $plan.Name `
                -ExpectedObjectGuid $plan.Guid -ExpectedFilterId $plan.FilterId
            foreach ($attribute in $plan.Expected.Keys) {
                if ([string]$verified.$attribute -cne $plan.Expected[$attribute]) { throw ('Synthetic WMI read-back failed for [{0}].' -f $attribute) }
            }
            if ([string]$verified.'msWMI-CreationDate' -cne [string]$plan.Current.'msWMI-CreationDate' -or
                [string]$verified.'msWMI-ChangeDate' -cne $stamp) { throw 'Synthetic WMI metadata did not verify.' }
            if ($replace.Count -gt 0) {
                Add-LabProcessingCount -Category 'WMI filters' -Updated 1 -Identity ([string]$plan.Guid)
            }
            $Targets[$plan.Key].Name = $plan.Name
            Write-Status -IndentLevel 2 -Kind Success -Message ('Verified synthetic WMI filter [{0}]; ID [{1}].' -f $plan.Name, $plan.FilterId)
        }
        return [pscustomobject]@{ ChangedCount=$changed; UnchangedCount=$unchanged; DeletedCount=$deleted }
    }
    catch {
        Stop-ScriptGracefully -IndentLevel 2 -Message ('Synthetic WMI changes failed: {0} Earlier writes may have committed. No creation, recursive deletion, rollback, CN/ID changes, GPO link edits or DC failover attempted.' -f $_.Exception.Message)
    }
}

# These GPO changes reuse the baseline writer without creating new objects.
function Invoke-LabGpoADChanges {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Definitions,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Targets
    )
    $changedCount = 0
    $unchangedCount = 0
    $skippedCount = 0
    try {
        $seen = @{}
        foreach ($definition in $Definitions) {
            if ($definition -isnot [System.Collections.IDictionary] -or -not $definition.Contains('Name') -or
                [string]::IsNullOrWhiteSpace([string]$definition.Name)) { throw 'Synthetic GPO definitions require a nonblank Name.' }
            if ($seen.ContainsKey($definition.Name)) { throw 'Duplicate synthetic GPO target definition.' }
            $seen[$definition.Name] = $true
        }
        foreach ($definition in $Definitions) {
            $matches = @($Targets | Where-Object { $_.Name -ieq $definition.Name })
            if ($matches.Count -gt 1) { throw 'Ambiguous baseline GPO results; no arbitrary target was selected.' }
            if ($matches.Count -eq 0) {
                Write-Status -IndentLevel 2 -Kind Warning -Message ('Skipping synthetic GPO [{0}]: no verified baseline result is available for this run.' -f $definition.Name)
                $skippedCount++
                continue
            }
            $target = $matches[0]
            if ($target.Skipped) {
                Write-Status -IndentLevel 2 -Kind Warning -BackgroundColor DarkRed -Message ('Skipping synthetic GPO [{0}]: baseline processing was skipped. {1} No synthetic writes attempted; earlier partial baseline changes, if reported, are not rolled back.' -f $definition.Name, $target.SkipReason)
                $skippedCount++
                continue
            }
            if ([guid]$target.Id -eq [guid]::Empty -or $target.VerifiedCount -lt 1) { throw 'Synthetic GPO target lacks a verified baseline identity/settings result.' }
            # All reads/writes stay on the selected DC. ExistingOnly refuses
            # creation; ExpectedGuid rejects deleted/recreated same-name GPOs.
            $result = Ensure-LabGpo -Domain $Domain -Definition $definition -ExistingOnly -ExpectedGuid ([guid]$target.Id)
            Write-LabSectionCompleted
            if ($result.Skipped) {
                $skippedCount++
                continue
            }
            $changedCount += $result.ChangedCount
            $unchangedCount += $result.UnchangedCount
        }
        return [pscustomobject]@{ ChangedCount=$changedCount; UnchangedCount=$unchangedCount; SkippedCount=$skippedCount }
    }
    catch {
        Stop-ScriptGracefully -IndentLevel 2 -Message ('Synthetic GPO changes failed: {0} Earlier native writes may have committed; use the logged backup for manual recovery. No rollback, link edits or DC failover were attempted.' -f $_.Exception.Message)
    }
}

# These are FGPP changes: remove verified temporary group assignments.
# The policy objects are retained. Baseline provisioning never runs this step.
function Get-LabVerifiedFgppChangeTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Plan,
        [Parameter(Mandatory = $true)][string]$Server
    )
    $policy = Get-ADFineGrainedPasswordPolicy -Identity ([guid]$Plan.ObjectGUID) -Properties * -Server $Server -ErrorAction Stop
    if ($null -eq $policy -or [guid]$policy.ObjectGUID -eq [guid]::Empty -or
        [guid]$policy.ObjectGUID -ne [guid]$Plan.ObjectGUID -or $policy.Name -cne $Plan.Name) {
        throw 'Synthetic FGPP read-back did not match the verified baseline identity.'
    }
    foreach ($property in $Plan.Parameters.Keys) {
        if (-not (Test-LabFgppValueMatches -Actual $policy.$property -Expected $Plan.Parameters[$property])) {
            throw ('Synthetic FGPP [{0}] managed value [{1}] differs from baseline; no further changes attempted.' -f $Plan.Name, $property)
        }
    }
    return $policy
}

function Invoke-LabFgppADChanges {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Plans
    )
    $removedCount = 0
    $skippedCount = 0
    try {
        $server = [string]$Domain.SelectedDomainController
        if ([string]::IsNullOrWhiteSpace($server)) { throw 'Synthetic FGPP changes require the selected writable DC.' }
        foreach ($plan in $Plans) {
            if ([guid]$plan.ObjectGUID -eq [guid]::Empty -or [string]::IsNullOrWhiteSpace([string]$plan.Name) -or
                $plan.Subjects.Count -eq 0) {
                throw 'Invalid verified FGPP change plan; no assignment removal attempted.'
            }
            $policy = Get-LabVerifiedFgppChangeTarget -Plan $plan -Server $server
            $subjects = @($policy.AppliesTo | ForEach-Object { [string]$_ })
            if ($subjects.Count -eq 0) {
                Write-Status -IndentLevel 2 -Kind Warning -Message ('FGPP [{0}] is already unassigned; synthetic removal skipped.' -f $plan.Name)
                $skippedCount++
                continue
            }
            if ($subjects.Count -ne $plan.Subjects.Count -or @($subjects | Where-Object { $plan.Subjects -inotcontains $_ }).Count -gt 0) {
                throw ('FGPP [{0}] assignments differ from verified baseline; no removal attempted.' -f $plan.Name)
            }
            # The exact assignment and GUID above are validated before removal.
            # Verify removal on this DC without forced replication or a wait.
            Write-Status -IndentLevel 3 -Kind Info -Message ('Removing temporary FGPP [{0}] assignment from: {1}.' -f $plan.Name, ($plan.Subjects -join '; '))
            Remove-ADFineGrainedPasswordPolicySubject -Identity ([guid]$plan.ObjectGUID) -Subjects $plan.Subjects -Confirm:$false -Server $server -ErrorAction Stop
            $final = Get-LabVerifiedFgppChangeTarget -Plan $plan -Server $server
            if (@($final.AppliesTo).Count -ne 0) { throw 'Synthetic FGPP assignment removal did not verify; the policy still has assigned subjects.' }
            Write-Status -IndentLevel 2 -Kind Success -Message ('Temporary FGPP [{0}] assignment removed and verified on [{1}]; policy object retained.' -f $plan.Name, $server)
            # Retain the final identity, managed-value and subject recheck.
            # No dedicated forced replication or settling delay is performed.
            $final = Get-LabVerifiedFgppChangeTarget -Plan $plan -Server $server
            if (@($final.AppliesTo).Count -ne 0) { throw 'FGPP subjects changed after removal verification; no further removal attempted.' }
            Add-LabProcessingCount -Category 'FGPPs' -Updated 1 -Identity ([string]$plan.ObjectGUID)
            $removedCount++
        }
        return [pscustomobject]@{ RemovedCount=$removedCount; SkippedCount=$skippedCount }
    }
    catch {
        Stop-ScriptGracefully -IndentLevel 2 -Message ('Synthetic FGPP changes failed: {0} Earlier writes, including assignment removal, may have committed; other DCs may not yet reflect them. No rollback or DC failover was attempted.' -f $_.Exception.Message)
    }
}

# These are AD Sites and Services changes: subnet lookup and mutation helpers.
# Baseline provisioning is complete; only synthetic definitions are used here.
function Find-LabSubnetForADChange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ContainerDN,
        [Parameter(Mandatory = $true)][string]$Server,
        [guid]$ExpectedObjectGuid = [guid]::Empty
    )
    $escaped = ConvertTo-LdapFilterValue -Value $Name
    # A successful, exact, one-level lookup returning zero objects means
    # absent. Access/connectivity errors must propagate, not become absence.
    $matches = @(Get-ADObject -LDAPFilter ('(name={0})' -f $escaped) -SearchBase $ContainerDN `
        -SearchScope OneLevel -Properties description -Server $Server -ErrorAction Stop)
    if ($matches.Count -eq 0) { return $null }
    if ($matches.Count -ne 1) { throw ('Subnet change target [{0}] is ambiguous.' -f $Name) }
    $subnet = $matches[0]
    $expectedDN = 'CN={0},{1}' -f $Name, $ContainerDN
    if ($subnet.ObjectClass -ine 'subnet' -or $subnet.Name -ine $Name -or
        $subnet.DistinguishedName -ine $expectedDN -or [guid]$subnet.ObjectGUID -eq [guid]::Empty) {
        throw ('Subnet change target [{0}] did not resolve to the exact expected subnet object.' -f $Name)
    }
    if ($ExpectedObjectGuid -ne [guid]::Empty -and [guid]$subnet.ObjectGUID -ne $ExpectedObjectGuid) {
        throw ('Subnet [{0}] was replaced during the change sequence; no further changes will be attempted.' -f $Name)
    }
    return $subnet
}

function Invoke-LabSubnetADChanges {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Definitions
    )
    $changedCount = 0
    $deletedCount = 0
    $skippedCount = 0
    try {
        $server = [string]$Domain.SelectedDomainController
        if ([string]::IsNullOrWhiteSpace($server)) { throw 'Subnet AD changes require the selected writable DC.' }
        # Validate all editable definitions before the first mutation.
        $plans = @()
        $seen = @{}
        foreach ($definition in $Definitions) {
            if ($definition -isnot [System.Collections.IDictionary]) { throw 'Each subnet AD change definition must be a hash table.' }
            foreach ($field in @('Name','Description','DeleteAfterDescriptionChange')) {
                if (-not $definition.Contains($field)) { throw ('Subnet AD change definition is missing [{0}].' -f $field) }
            }
            foreach ($field in $definition.Keys) {
                if (@('Name','Description','DeleteAfterDescriptionChange') -notcontains $field) { throw ('Unsupported subnet AD change field [{0}].' -f $field) }
            }
            if ($definition.Name -isnot [string] -or $definition.Description -isnot [string] -or
                [string]::IsNullOrWhiteSpace($definition.Description) -or $definition.DeleteAfterDescriptionChange -isnot [bool]) {
                throw 'Subnet AD changes require a string Name, nonblank string Description and Boolean DeleteAfterDescriptionChange.'
            }
            $name = ConvertTo-LabSubnetPrefix -Name $definition.Name
            if ($seen.ContainsKey($name)) { throw ('Duplicate subnet AD change target [{0}].' -f $name) }
            $seen[$name] = $true
            $plans += [pscustomobject]@{ Name=$name; Description=$definition.Description; DeleteAfterDescriptionChange=$definition.DeleteAfterDescriptionChange }
        }
        if ($plans.Count -gt 0) {
            $rootDse = Get-ADRootDSE -Server $server -ErrorAction Stop
            $configurationDN = [string]$rootDse.configurationNamingContext
            if ([string]::IsNullOrWhiteSpace($configurationDN)) { throw 'The configuration naming context was not returned.' }
            $containerDN = 'CN=Subnets,CN=Sites,{0}' -f $configurationDN
            Get-ADObject -Identity $containerDN -Server $server -ErrorAction Stop | Out-Null
            foreach ($plan in $plans) {
                Write-Status -Kind Info -Message ('Validating AD change subnet [{0}] on [{1}].' -f $plan.Name, $server)
                $subnet = Find-LabSubnetForADChange -Name $plan.Name -ContainerDN $containerDN -Server $server
                if ($null -eq $subnet) {
                    Write-Status -IndentLevel 2 -Kind Warning -Message ('Subnet [{0}] does not exist; description change and deletion skipped.' -f $plan.Name)
                    $skippedCount++
                    continue
                }
                $identity = [guid]$subnet.ObjectGUID
                Write-Status -IndentLevel 3 -Kind Info -Message ('Changing subnet [{0}] Description to [{1}].' -f $plan.Name, $plan.Description)
                Set-ADReplicationSubnet -Identity $identity -Description $plan.Description -Server $server -ErrorAction Stop
                # Verify the SET against the same GUID/type/DN. Deletion targets
                # are checked again immediately before deletion on this DC.
                $verified = Find-LabSubnetForADChange -Name $plan.Name -ContainerDN $containerDN -Server $server -ExpectedObjectGuid $identity
                if ($null -eq $verified) {
                    Write-Status -IndentLevel 2 -Kind Warning -Message ('Subnet [{0}] disappeared after SET; description could not be verified and deletion skipped.' -f $plan.Name)
                    $skippedCount++
                    continue
                }
                if ([string]$verified.Description -cne $plan.Description) { throw ('Subnet [{0}] description read-back did not match; deletion will not be attempted.' -f $plan.Name) }
                Add-LabProcessingCount -Category 'AD subnets' -Updated 1 -Identity ([string]$identity)
                $changedCount++
                Write-Status -IndentLevel 2 -Kind Success -Message ('Verified subnet [{0}] Description: {1}' -f $plan.Name, $plan.Description)
                if ($plan.DeleteAfterDescriptionChange) {
                    # Revalidate identity and description immediately before
                    # deletion; no forced replication or settling delay.
                    $deleteTarget = Find-LabSubnetForADChange -Name $plan.Name -ContainerDN $containerDN -Server $server -ExpectedObjectGuid $identity
                    if ($null -eq $deleteTarget) {
                        Write-Status -IndentLevel 2 -Kind Warning -Message ('Subnet [{0}] disappeared before deletion; deletion skipped.' -f $plan.Name)
                        $skippedCount++
                        continue
                    }
                    if ([string]$deleteTarget.Description -cne $plan.Description) {
                        throw ('Subnet [{0}] description changed before deletion; deletion will not be attempted.' -f $plan.Name)
                    }
                    Write-Status -IndentLevel 3 -Kind Info -Message ('Deleting validated subnet [{0}] without confirmation.' -f $plan.Name)
                    Remove-ADReplicationSubnet -Identity $identity -Server $server -Confirm:$false -ErrorAction Stop
                    $remaining = Find-LabSubnetForADChange -Name $plan.Name -ContainerDN $containerDN -Server $server
                    if ($null -ne $remaining) { throw ('Subnet [{0}] still exists or was recreated after DELETE; deletion could not be verified.' -f $plan.Name) }
                    Add-LabProcessingCount -Category 'AD subnets' -Deleted 1 -Identity ([string]$identity)
                    $deletedCount++
                    Write-Status -IndentLevel 2 -Kind Success -Message ('Verified subnet [{0}] was deleted on [{1}].' -f $plan.Name, $server)
                }
            }
        }
        return [pscustomobject]@{ DescriptionChangedCount=$changedCount; DeletedCount=$deletedCount; SkippedCount=$skippedCount }
    }
    catch {
        Stop-ScriptGracefully -IndentLevel 2 -Message ('Subnet AD changes failed: {0} Earlier provisioning/changes may have committed; no automatic rollback or DC failover was attempted.' -f $_.Exception.Message)
    }
}

# Synthetic IP site-link changes: update only cost and replInterval.
# Keep all work before the terminal Helpdesk Ops membership batch.
function Invoke-LabSiteLinkADChanges {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Definitions
    )
    $changedCount = 0
    $unchangedCount = 0
    $skippedCount = 0
    try {
        $server = [string]$Domain.SelectedDomainController
        if ([string]::IsNullOrWhiteSpace($server)) { throw 'Site-link AD changes require the selected writable DC.' }
        $plans = @()
        $seen = @{}
        # Validate every definition before looking up targets or writing.
        foreach ($definition in $Definitions) {
            if ($definition -isnot [System.Collections.IDictionary]) { throw 'Each site-link AD change definition must be a hash table.' }
            $fields = @('Name','Cost','ReplicationFrequencyInMinutes')
            foreach ($field in $fields) {
                if (-not $definition.Contains($field)) { throw ('Missing site-link AD change field [{0}].' -f $field) }
            }
            foreach ($field in $definition.Keys) {
                if ($fields -notcontains $field) { throw ('Unsupported site-link AD change field [{0}].' -f $field) }
            }
            if ($definition.Name -isnot [string] -or $definition.Name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$' -or
                $definition.Name -cne $definition.Name.Trim()) { throw 'Site-link AD change Name must be a simple 1..63-character lab name.' }
            if ($definition.Name -ieq 'DEFAULTIPSITELINK') { throw 'DEFAULTIPSITELINK is excluded from synthetic site-link changes.' }
            if ($seen.ContainsKey($definition.Name)) { throw 'Duplicate site-link AD change target.' }
            $seen[$definition.Name] = $true
            if ($definition.Cost -isnot [int] -or $definition.Cost -lt 1 -or $definition.Cost -gt 32767) {
                throw 'Synthetic site-link Cost must be an integer from 1 through 32767.'
            }
            $interval = $definition.ReplicationFrequencyInMinutes
            if ($interval -isnot [int] -or $interval -lt 15 -or $interval -gt 10080 -or ($interval % 15) -ne 0) {
                throw 'Synthetic site-link replication interval must be an integer multiple of 15 minutes from 15 through 10080.'
            }
            $plans += [pscustomobject]@{
                Name=[string]$definition.Name; Cost=[int]$definition.Cost; Interval=[int]$interval
                ExpectedDN=$null; Identity=[guid]::Empty
            }
        }
        if ($plans.Count -gt 0) {
            $rootDse = Get-ADRootDSE -Server $server -ErrorAction Stop
            $configurationDN = [string]$rootDse.configurationNamingContext
            if ([string]::IsNullOrWhiteSpace($configurationDN)) { throw 'The configuration naming context was not returned.' }
            $transportDN = 'CN=IP,CN=Inter-Site Transports,CN=Sites,{0}' -f $configurationDN
            $transport = Get-ADObject -Identity $transportDN -Server $server -ErrorAction Stop
            if ($null -eq $transport -or $transport.ObjectClass -ine 'interSiteTransport' -or
                $transport.DistinguishedName -ine $transportDN) { throw 'The IP transport container has an unexpected identity or class.' }
            # Resolve all targets before the first mutation. Missing links
            # warn/skip; access and connection failures are fatal, not absence.
            foreach ($plan in $plans) {
                $plan.ExpectedDN = 'CN={0},{1}' -f $plan.Name,$transportDN
                $escaped = ConvertTo-LdapFilterValue -Value $plan.Name
                $matches = @(Get-ADObject -LDAPFilter ('(name={0})' -f $escaped) -SearchBase $transportDN `
                    -SearchScope OneLevel -Server $server -ErrorAction Stop)
                if ($matches.Count -eq 0) {
                    Write-Status -IndentLevel 2 -Kind Warning -Message ('Synthetic IP site link [{0}] is absent on [{1}]; skipped, not created.' -f $plan.Name,$server)
                    $skippedCount++
                    continue
                }
                if ($matches.Count -ne 1) { throw ('Synthetic site-link target [{0}] is ambiguous.' -f $plan.Name) }
                $object = $matches[0]
                if ($object.ObjectClass -ine 'siteLink' -or $object.Name -ine $plan.Name -or
                    $object.DistinguishedName -ine $plan.ExpectedDN -or [guid]$object.ObjectGUID -eq [guid]::Empty) {
                    throw ('Synthetic site-link target [{0}] has an unexpected identity or class.' -f $plan.Name)
                }
                $plan.Identity = [guid]$object.ObjectGUID
            }
            foreach ($plan in $plans) {
                if ($plan.Identity -eq [guid]::Empty) { continue }
                # Revalidate by GUID/class/name/DN immediately before SET.
                $current = Get-LabVerifiedSiteLinkObject -Plan $plan -Identity $plan.Identity -Server $server
                $originalSites = @($current.siteList | ForEach-Object { [string]$_ } | Sort-Object -Unique)
                $replace = @{}
                if ([int]$current.cost -ne $plan.Cost) { $replace['cost'] = $plan.Cost }
                if ([int]$current.replInterval -ne $plan.Interval) { $replace['replInterval'] = $plan.Interval }
                $changed = $replace.Count -gt 0
                if ($changed) {
                    Write-Status -IndentLevel 3 -Kind Info -Message ('Changing IP site link [{0}] to cost {1}, replication interval {2} minutes.' -f $plan.Name,$plan.Cost,$plan.Interval)
                    Assert-LabInventoryHealthy
                    # Never write siteList, schedule, options or description.
                    Set-ADObject -Identity $plan.Identity -Replace $replace -Server $server -ErrorAction Stop
                }
                $verified = Get-LabVerifiedSiteLinkObject -Plan $plan -Identity $plan.Identity -Server $server
                if ([int]$verified.cost -ne $plan.Cost -or [int]$verified.replInterval -ne $plan.Interval) {
                    throw ('Synthetic site link [{0}] cost/interval read-back did not match.' -f $plan.Name)
                }
                $verifiedSites = @($verified.siteList | ForEach-Object { [string]$_ } | Sort-Object -Unique)
                if ($originalSites.Count -ne $verifiedSites.Count -or
                    @($verifiedSites | Where-Object { $originalSites -inotcontains $_ }).Count -gt 0) {
                    throw ('Synthetic site link [{0}] membership changed during the operation; no repair attempted.' -f $plan.Name)
                }
                if ($changed) {
                    Add-LabProcessingCount -Category 'AD site links' -Updated 1 -Identity ([string]$plan.Identity)
                    $changedCount++
                }
                else { $unchangedCount++ }
                Write-Status -IndentLevel 2 -Kind Success -Message ('Verified synthetic IP site link [{0}]: cost {1}, replication interval {2} minutes on [{3}]; site membership retained.' -f $plan.Name,$plan.Cost,$plan.Interval,$server)
            }
        }
        return [pscustomobject]@{ ChangedCount=$changedCount; UnchangedCount=$unchangedCount; SkippedCount=$skippedCount }
    }
    catch {
        Stop-ScriptGracefully -IndentLevel 2 -Message ('Synthetic site-link changes failed: {0} Earlier writes may have committed; no automatic rollback or DC failover was attempted.' -f $_.Exception.Message)
    }
}

function Invoke-LabOuSyntheticDeletion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [AllowNull()]$RelativePath
    )

    # An empty setting is an explicit opt-out, before any directory access.
    if ($null -eq $RelativePath -or ($RelativePath -is [string] -and [string]::IsNullOrWhiteSpace($RelativePath))) {
        Write-Host (Format-OutputMessage -Message "[ADVISORY]  To generate activity to demo a deleted OU recovery, set the variable 'OUforSyntheticDeletion' in the DEFAULTS section." -IndentLevel 2) -ForegroundColor White
        return [pscustomobject]@{ Deleted=$false; Skipped=$true; DeletedObjectCount=0 }
    }

    try {
        $server = [string]$Domain.SelectedDomainController
        $domainDN = [string]$Domain.DistinguishedName
        if ([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($domainDN)) {
            throw 'OU deletion requires the selected writable DC and discovered domain DN.'
        }
        # Only a relative OU chain is accepted: no absolute domain DN, CN,
        # ADSI prefix, multivalued RDN or escaped DN syntax. Fail closed.
        if ($RelativePath -isnot [string] -or
            $RelativePath -notmatch '^OU=[^,=+\\<>;"\x00-\x1F]+(?:,OU=[^,=+\\<>;"\x00-\x1F]+)*$') {
            throw 'OUforSyntheticDeletion must be a relative OU-only DN (OU=name,OU=parent), without escaped or multivalued RDNs.'
        }
        $parts = @($RelativePath.Split(','))
        foreach ($part in $parts) {
            $value = $part.Substring(3)
            if ([string]::IsNullOrWhiteSpace($value) -or $value -cne $value.Trim()) {
                throw 'Deletion OU names cannot be blank or have leading/trailing spaces.'
            }
            if ($part -ieq 'OU=Domain Controllers') {
                throw 'Deletion of or beneath the Domain Controllers OU is refused.'
            }
        }
        $targetDN = '{0},{1}' -f $RelativePath,$domainDN
        $leafName = $parts[0].Substring(3)
        $parentDN = $domainDN
        if ($parts.Count -gt 1) { $parentDN = '{0},{1}' -f ($parts[1..($parts.Count - 1)] -join ','),$domainDN }
        $escapedName = ConvertTo-LdapFilterValue -Value $leafName
        $targetFilter = '(&(objectClass=organizationalUnit)(name={0}))' -f $escapedName
        $targets = @(Get-ADObject -LDAPFilter $targetFilter -SearchBase $parentDN -SearchScope OneLevel -Server $server -ErrorAction Stop)
        if ($targets.Count -eq 0) {
            Write-Status -IndentLevel 2 -Kind Warning -Message ('Synthetic OU deletion target [{0}] is absent or not visible on [{1}]; no deletion attempted.' -f $targetDN,$server)
            return [pscustomobject]@{ Deleted=$false; Skipped=$true; DeletedObjectCount=0 }
        }
        if ($targets.Count -ne 1 -or $targets[0].ObjectClass -ine 'organizationalUnit' -or
            $targets[0].DistinguishedName -ine $targetDN -or [guid]$targets[0].ObjectGUID -eq [guid]::Empty) {
            throw 'Deletion lookup did not resolve to exactly the configured OU and a nonempty GUID.'
        }
        $identity = [guid]$targets[0].ObjectGUID
        # Inspect protection and DC-account flags before any destructive write.
        # Read-only enumeration: never remove protection, change ACLs or
        # delete children individually. The sole delete targets the root OU.
        $subtree = @(Get-ADObject -LDAPFilter '(objectClass=*)' -SearchBase $targetDN -SearchScope Subtree `
            -Properties ProtectedFromAccidentalDeletion,userAccountControl -Server $server -ErrorAction Stop)
        $rootMatches = @($subtree | Where-Object { [guid]$_.ObjectGUID -eq $identity -and $_.DistinguishedName -ieq $targetDN })
        if ($rootMatches.Count -ne 1) { throw 'The deletion subtree did not contain the validated root OU exactly once.' }
        foreach ($item in $subtree) {
            if ($item.DistinguishedName -ine $targetDN -and
                -not ([string]$item.DistinguishedName).EndsWith(',' + $targetDN,[System.StringComparison]::OrdinalIgnoreCase)) {
                throw 'Subtree enumeration returned an object outside the configured OU.'
            }
            if ($item.ProtectedFromAccidentalDeletion -ne $false) {
                throw ('Object [{0}] is protected from accidental deletion or its protection state could not be read; no deletion attempted.' -f $item.DistinguishedName)
            }
            if (([int]$item.userAccountControl -band 8192) -ne 0) {
                throw ('Domain-controller account [{0}] was found; no deletion attempted.' -f $item.DistinguishedName)
            }
        }
        # Revalidate identity immediately before deleting the tree by GUID.
        $current = Get-ADObject -Identity $identity -Properties ProtectedFromAccidentalDeletion -Server $server -ErrorAction Stop
        if ($current.ObjectClass -ine 'organizationalUnit' -or $current.DistinguishedName -ine $targetDN -or
            [guid]$current.ObjectGUID -ne $identity -or $current.ProtectedFromAccidentalDeletion -ne $false) {
            throw 'Deletion target identity, location or protection changed; no deletion attempted.'
        }
        Write-Status -IndentLevel 3 -Kind Info -Message ('Deleting configured OU [{0}] using one Remove-ADOrganizationalUnit -Recursive call on [{1}]; {2} objects enumerated read-only before deletion. No per-child deletes or protection/ACL changes will be made.' -f $targetDN,$server,$subtree.Count)
        Remove-ADOrganizationalUnit -Identity $identity -Recursive -Confirm:$false -Server $server -ErrorAction Stop
        # Verify the original GUID is absent domain-wide and the target name
        # was not recreated at the same path. Errors never mean success.
        $escapedGuid = ($identity.ToByteArray() | ForEach-Object { '\{0:X2}' -f $_ }) -join ''
        $remaining = @(Get-ADObject -LDAPFilter ('(objectGUID={0})' -f $escapedGuid) -SearchBase $domainDN -SearchScope Subtree -Server $server -ErrorAction Stop)
        $replacement = @(Get-ADObject -LDAPFilter $targetFilter -SearchBase $parentDN -SearchScope OneLevel -Server $server -ErrorAction Stop)
        if ($remaining.Count -ne 0 -or $replacement.Count -ne 0) {
            throw 'Post-deletion verification found the original GUID or an OU at the configured path.'
        }
        Write-Status -IndentLevel 2 -Kind Success -Message ('Verified recursive deletion of OU [{0}] on [{1}]. Pre-deletion enumeration contained {2} objects; forest-wide convergence and DSP capture are not verified.' -f $targetDN,$server,$subtree.Count)
        foreach ($deletedObject in $subtree) {
            $category = Get-LabProcessingDeletionCategory -Object $deletedObject
            Add-LabProcessingCount -Category $category -Deleted 1 -Identity ([string]$deletedObject.ObjectGUID)
        }
        return [pscustomobject]@{ Deleted=$true; Skipped=$false; DeletedObjectCount=$subtree.Count }
    }
    catch {
        Stop-ScriptGracefully -IndentLevel 2 -Message ('Synthetic OU deletion failed: {0} Earlier writes may have committed; inspect the selected DC before retrying. No rollback, protection removal or DC failover was attempted.' -f $_.Exception.Message)
    }
}

function Invoke-LabADChangeCategories {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Domain)

    Write-SectionHeader -Message '****************************************'
    Write-SectionHeader -Message 'AD Changes - synthetic change activity...'
    Write-SectionHeader -Message '****************************************'
    Write-Status -Kind Info -Message 'MakeADChanges is True; running the configured synthetic AD changes.'
    # EXTENSION POINT: add all future synthetic changes inside this function.
    # Never put directory mutations after the terminal stage in the wrapper.
    # Category output convention: use Write-SectionHeader before each
    # implemented change category, matching the provisioning headings.
    # Example when implemented: Write-SectionHeader -Message 'AD Changes - demo users...'
    # Standard for implemented synthetic types with retained checkpoints:
    # heading -> all actions and verification -> summary -> one checkpoint.
    # FGPP and Sites and Services (sites/subnets/site links) are exempt:
    # no dedicated forced replication or settling delay in either phase.
    # Keep retained checkpoints outside object loops and skip/unchanged guards.
    # Use Domain for users, groups, computers, OUs and GPOs.
    # Example after future demo-user actions and their summary:
    # Invoke-LabSyntheticReplicationSync -Domain $Domain -SectionName 'demo users' -Partition Domain
    # A fatal action/checkpoint failure prevents subsequent categories.
    # Reserved categories stay silent until their change activity exists.
    # --- These are demo user changes ------------------------------------
    Write-SectionHeader -Message 'AD Changes - demo users...'
    $demoUserChanges = Get-LabDemoUserADChangeDefinitions
    $demoUserChangeResult = Invoke-LabDemoUserADChanges -Domain $Domain -Definitions $demoUserChanges `
        -UserDefinitions $script:LabDemoUserDefinitions -UserObjects $script:LabDemoUserObjects
    Write-Status -IndentLevel 0 -Kind Success -Message ('AD demo-user changes: {0} fax updates verified; {1} already matched.' -f $demoUserChangeResult.ChangedCount, $demoUserChangeResult.UnchangedCount)
    Invoke-LabSyntheticReplicationSync -Domain $Domain -SectionName 'demo users' -Partition Domain
    Write-LabSectionCompleted

    # --- These are group changes ----------------------------------------
    # Reserved: ordinary group mutations go here. Terminal Helpdesk Ops
    # removal is isolated in the fixed wrapper and MUST NOT move here.

    # --- These are computer changes -------------------------------------
    Write-SectionHeader -Message 'AD Changes - computers...'
    $computerChanges = Get-LabComputerADChangeDefinitions
    $computerChangeResult = Invoke-LabComputerADChanges -Domain $Domain -Definitions $computerChanges `
        -ComputerDefinitions $script:LabComputerDefinitions -ComputerObjects $script:LabComputerObjects
    $computerChangeKind = 'Success'
    if ($computerChangeResult.SkippedCount -gt 0) { $computerChangeKind = 'Warning' }
    Write-Status -IndentLevel 0 -Kind $computerChangeKind -Message ('AD computer changes: {0} Description updates verified; {1} deletions verified; {2} already matched; {3} actions skipped.' -f $computerChangeResult.ChangedCount,$computerChangeResult.DeletedCount,$computerChangeResult.UnchangedCount,$computerChangeResult.SkippedCount)
    Invoke-LabSyntheticReplicationSync -Domain $Domain -SectionName 'computers' -Partition Domain
    Write-LabSectionCompleted

    # --- These are organizational unit changes ---------------------------
    # EXTENSION POINT: future OU modifications go here; subtree deletion
    # runs later, immediately after synthetic FGPP processing.

    # --- These are specific AD object ACL changes ------------------------
    Write-SectionHeader -Message 'AD Changes - specific object ACLs...'
    $specificAclChangeResult = Invoke-LabSpecificObjectAcls -Domain $Domain -Phase Synthetic
    Write-Status -IndentLevel 0 -Kind Success -Message ('AD specific ACL changes: {0} changes verified; {1} already matched.' -f $specificAclChangeResult.ChangedCount,$specificAclChangeResult.UnchangedCount)
    Invoke-LabSyntheticReplicationSync -Domain $Domain -SectionName 'specific object ACLs' -Partition Domain
    Write-LabSectionCompleted

    # --- These are AD-integrated DNS changes -----------------------------
    Write-SectionHeader -Message 'AD Changes - DNS zones and records...'
    $dnsChanges = @(Get-LabDnsADChangeDefinitions -DomainDNSRoot $Domain.DNSRoot)
    $dnsChangeResult = Invoke-LabDnsADChanges -Domain $Domain -Definitions $dnsChanges
    $dnsSummaryKind = 'Success'
    if (($dnsChangeResult.SkippedCount + $dnsChangeResult.PtrWarningCount) -gt 0) { $dnsSummaryKind = 'Warning' }
    Write-Status -IndentLevel 1 -Kind $dnsSummaryKind -Message ('AD DNS changes: {0} changed and verified; {1} already matched/absent; {2} actions skipped; {3} PTR warning(s). Verification is on the selected DC, not forest-wide convergence.' -f $dnsChangeResult.ChangedCount, $dnsChangeResult.UnchangedCount, $dnsChangeResult.SkippedCount, $dnsChangeResult.PtrWarningCount)
    Invoke-LabSyntheticReplicationSync -Domain $Domain -SectionName 'DNS zones and records' -Partition Dns
    Write-LabSectionCompleted

    # --- These are WMI filter changes ------------------------------------
    Write-SectionHeader -Message 'AD Changes - WMI filters...'
    $wmiChanges = Get-LabWmiFilterADChangeDefinitions
    $wmiChangeResult = Invoke-LabWmiFilterADChanges -Domain $Domain -Definitions $wmiChanges `
        -Targets $script:LabWmiFilterObjects -BaselineDefinitions $script:LabWmiFilterDefinitions
    Write-Status -IndentLevel 0 -Kind Success -Message ('AD WMI changes: {0} filters changed and verified; {1} already matched; {2} deleted and verified. Retained filter IDs unchanged; GPO references not edited.' -f $wmiChangeResult.ChangedCount, $wmiChangeResult.UnchangedCount, $wmiChangeResult.DeletedCount)
    Invoke-LabSyntheticReplicationSync -Domain $Domain -SectionName 'WMI filters' -Partition Domain
    Write-LabSectionCompleted

    # --- These are GPO changes -------------------------------------------
    Write-SectionHeader -Message 'AD Changes - GPOs...'
    $gpoChanges = @(Get-LabGpoADChangeDefinitions)
    $gpoChangeResult = Invoke-LabGpoADChanges -Domain $Domain -Definitions $gpoChanges -Targets $script:LabGpoChangeTargets
    $gpoSummaryKind = 'Success'
    if ($gpoChangeResult.SkippedCount -gt 0) { $gpoSummaryKind = 'Warning' }
    Write-Status -IndentLevel 0 -Kind $gpoSummaryKind -Message ('AD GPO changes: {0} settings changed and verified; {1} already matched; {2} GPO targets skipped. Links unchanged.' -f $gpoChangeResult.ChangedCount, $gpoChangeResult.UnchangedCount, $gpoChangeResult.SkippedCount)
    Invoke-LabSyntheticReplicationSync -Domain $Domain -SectionName 'GPOs' -Partition Domain
    Write-LabSectionCompleted

    # --- These are FGPP changes ------------------------------------------
    # Remove temporary group assignments; retain the FGPP policy objects.
    Write-SectionHeader -Message 'AD Changes - FGPPs...'
    $fgppChangeResult = Invoke-LabFgppADChanges -Domain $Domain -Plans $script:LabFgppChangePlans
    $fgppSummaryKind = 'Success'
    if ($fgppChangeResult.SkippedCount -gt 0) { $fgppSummaryKind = 'Warning' }
    Write-Status -IndentLevel 0 -Kind $fgppSummaryKind -Message ('AD FGPP changes: {0} policy assignment removals verified; {1} targets skipped; policy objects retained.' -f $fgppChangeResult.RemovedCount, $fgppChangeResult.SkippedCount)
    Write-Status -IndentLevel 1 -Kind Info -Message 'FGPPs: dedicated forced replication and settling pause skipped.'
    Write-LabSectionCompleted

    # --- Delete the configured OU subtree after synthetic FGPPs -----------
    Write-SectionHeader -Message 'AD Changes - configured OU subtree deletion...'
    $ouDeletionResult = Invoke-LabOuSyntheticDeletion -Domain $Domain -RelativePath $OUforSyntheticDeletion
    if ($ouDeletionResult.Deleted) {
        Invoke-LabSyntheticReplicationSync -Domain $Domain -SectionName 'OU subtree deletion' -Partition Domain
    }
    Write-LabSectionCompleted

    # --- These are AD Sites and Services changes -------------------------
    # Change and delete 111.111.5.0/24; change only Description on 111.111.4.0/24.
    # Synthetic site-link changes follow subnets, before the terminal group batch.
    Write-SectionHeader -Message 'AD Changes - AD Sites and Services (subnets)...'
    $subnetChanges = @(Get-LabSubnetADChangeDefinitions)
    $subnetChangeResult = Invoke-LabSubnetADChanges -Domain $Domain -Definitions $subnetChanges
    $summaryKind = 'Success'
    if ($subnetChangeResult.SkippedCount -gt 0) { $summaryKind = 'Warning' }
    Write-Status -IndentLevel 0 -Kind $summaryKind -Message ('AD subnet changes: {0} descriptions changed and verified; {1} subnets deleted and verified; {2} targets skipped.' -f $subnetChangeResult.DescriptionChangedCount, $subnetChangeResult.DeletedCount, $subnetChangeResult.SkippedCount)
    Write-Status -IndentLevel 1 -Kind Info -Message 'AD subnets: dedicated forced replication and settling pause skipped.'
    Write-LabSectionCompleted

    Write-SectionHeader -Message 'AD Changes - AD Sites and Services IP Site Links...'
    $siteLinkChanges = @(Get-LabSiteLinkADChangeDefinitions)
    $siteLinkChangeResult = Invoke-LabSiteLinkADChanges -Domain $Domain -Definitions $siteLinkChanges
    $siteLinkSummaryKind = 'Success'
    if ($siteLinkChangeResult.SkippedCount -gt 0) { $siteLinkSummaryKind = 'Warning' }
    Write-Status -IndentLevel 0 -Kind $siteLinkSummaryKind -Message ('AD site-link changes: {0} updated and verified; {1} already matched; {2} targets skipped.' -f $siteLinkChangeResult.ChangedCount,$siteLinkChangeResult.UnchangedCount,$siteLinkChangeResult.SkippedCount)
    Write-Status -IndentLevel 1 -Kind Info -Message 'AD site links: dedicated forced replication and settling pause skipped.'
    Write-LabSectionCompleted
}

# Read the exact baseline group and classify ALL direct links before writes.
# No recursive enumeration: removing users from nested groups is not authorized.
function Get-LabFinalGroupUserState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][guid]$GroupGuid,
        [Parameter(Mandatory = $true)][string]$ExpectedName,
        [Parameter(Mandatory = $true)][string]$ExpectedSam,
        [Parameter(Mandatory = $true)][string]$Server
    )
    if ($GroupGuid -eq [guid]::Empty) { throw 'Final membership target has an empty GUID.' }
    $group = Get-ADGroup -Identity $GroupGuid -Properties member -Server $Server -ErrorAction Stop
    if ($null -eq $group -or [guid]$group.ObjectGUID -ne $GroupGuid -or
        $group.ObjectClass -ine 'group' -or $group.Name -cne $ExpectedName -or
        $group.SamAccountName -ine $ExpectedSam) {
        throw 'Final membership target no longer matches the verified baseline group; no name fallback attempted.'
    }
    $users = @()
    $nonUserCount = 0
    $seen = @{}
    $memberLinks = @()
    if ($null -ne $group.member) { $memberLinks = @($group.member) }
    foreach ($memberDN in $memberLinks) {
        if ([string]::IsNullOrWhiteSpace([string]$memberDN)) { throw 'Invalid blank direct membership link.' }
        $member = Get-ADObject -Identity ([string]$memberDN) -Server $Server -ErrorAction Stop
        if ($null -eq $member -or [guid]$member.ObjectGUID -eq [guid]::Empty -or
            $member.DistinguishedName -ine [string]$memberDN) { throw 'Direct member identity could not be verified.' }
        $memberKey = ([guid]$member.ObjectGUID).ToString()
        if ($seen.ContainsKey($memberKey)) { throw 'Duplicate direct member GUID; no arbitrary identity chosen.' }
        $seen[$memberKey] = $true
        if ($member.ObjectClass -ieq 'user' -or $member.ObjectClass -ieq 'inetOrgPerson') {
            $users += $member
        }
        elseif ($member.ObjectClass -ieq 'group' -or $member.ObjectClass -ieq 'computer') {
            $nonUserCount++
        }
        else {
            throw ('Cannot safely classify member [{0}] of class [{1}]. Resolve foreign/unknown principals before user cleanup.' -f $memberDN, $member.ObjectClass)
        }
    }
    return [pscustomobject]@{ Users=@($users); NonUserCount=$nonUserCount }
}

# Pin the final added user to this run's verified baseline identity.
function Get-LabFinalGroupAddedUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Definition,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$UserDefinitions,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$UserObjects,
        [Parameter(Mandatory = $true)][string]$Server
    )
    if (-not $Definition.Contains('AddUserKey') -or
        [string]::IsNullOrWhiteSpace([string]$Definition.AddUserKey)) { throw 'Final addition requires a configured demo-user key.' }
    $key = [string]$Definition.AddUserKey
    if (-not $UserDefinitions.Contains($key) -or -not $UserObjects.Contains($key) -or
        $null -eq $UserObjects[$key]) { throw 'Final addition requires a verified baseline demo-user reference.' }
    $expected = $UserDefinitions[$key]
    $guid = [guid]$UserObjects[$key].ObjectGUID
    if ($guid -eq [guid]::Empty -or [string]::IsNullOrWhiteSpace([string]$expected.Name) -or
        [string]::IsNullOrWhiteSpace([string]$expected.SamAccountName)) { throw 'Invalid final demo-user baseline identity.' }
    $user = Get-ADUser -Identity $guid -Server $Server -ErrorAction Stop
    if ($null -eq $user -or [guid]$user.ObjectGUID -ne $guid -or
        @('user','inetOrgPerson') -notcontains $user.ObjectClass -or
        $user.Name -cne $expected.Name -or $user.SamAccountName -ine $expected.SamAccountName) {
        throw 'Final added user does not match the verified baseline GUID/name/SAM; no replacement or name fallback attempted.'
    }
    return $user
}

function Invoke-LabFinalGroupMembershipChanges {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Domain,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Definition,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$GroupDefinitions,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$GroupObjects,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$UserDefinitions,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$UserObjects
    )
    try {
        $server = [string]$Domain.SelectedDomainController
        if ([string]::IsNullOrWhiteSpace($server)) { throw 'Final user removal requires the selected writable DC.' }
        if (-not $Definition.Contains('GroupKey') -or [string]::IsNullOrWhiteSpace([string]$Definition.GroupKey)) {
            throw 'Final user removal requires a configured stable group key.'
        }
        $key = [string]$Definition.GroupKey
        if (-not $GroupDefinitions.Contains($key) -or -not $GroupObjects.Contains($key) -or
            $null -eq $GroupObjects[$key]) { throw 'Final user removal requires a verified baseline group reference.' }
        $expected = $GroupDefinitions[$key]
        $groupGuid = [guid]$GroupObjects[$key].ObjectGUID
        if ([string]::IsNullOrWhiteSpace([string]$expected.Name) -or
            [string]::IsNullOrWhiteSpace([string]$expected.SamAccountName)) { throw 'Final group definition lacks its expected name/SAM.' }
        $readParameters = @{
            GroupGuid = $groupGuid
            ExpectedName = [string]$expected.Name
            ExpectedSam = [string]$expected.SamAccountName
            Server = $server
        }
        Write-Status -Kind Info -Message ('Checking all direct user members of [{0}] on [{1}]. Nested groups/computers will be retained.' -f $expected.Name, $server)
        # Complete classification before any removal. Unknown/inaccessible
        # members fail preflight rather than being silently ignored.
        $userParameters = @{
            Definition = $Definition
            UserDefinitions = $UserDefinitions
            UserObjects = $UserObjects
            Server = $server
        }
        # Validate the final user BEFORE destructive removals begin.
        $addedUser = Get-LabFinalGroupAddedUser @userParameters
        $addedUserGuid = [guid]$addedUser.ObjectGUID
        $state = Get-LabFinalGroupUserState @readParameters
        $removedCount = 0
        foreach ($user in @($state.Users)) {
            Write-Status -IndentLevel 3 -Kind Info -Message ('Removing direct user [{0}] from [{1}].' -f $user.DistinguishedName, $expected.Name)
            # One explicit link removal per user; never clear the whole member
            # attribute, delete accounts, or mutate another group's membership.
            Remove-ADGroupMember -Identity $groupGuid -Members ([guid]$user.ObjectGUID).ToString() -Server $server -Confirm:$false -ErrorAction Stop
            $removedCount++
            Write-Status -IndentLevel 4 -Kind Success -Message ('Removed direct user [{0}] from [{1}]; batch verification follows.' -f $user.Name, $expected.Name)
        }
        $final = Get-LabFinalGroupUserState @readParameters
        if (@($final.Users).Count -ne 0) { throw 'Direct users remain or were concurrently added; final removal did not verify.' }
        # The zero-user read verifies all removals even if a later add fails.
        foreach ($removedUser in @($state.Users)) {
            $linkIdentity = '{0}|{1}' -f $groupGuid, ([guid]$removedUser.ObjectGUID)
            Add-LabProcessingCount -Category 'group memberships' -Removed 1 -Identity $linkIdentity
        }
        # Keep the requested order even when Vladimir was already a member:
        # remove every direct user, verify zero, refresh him, THEN add him.
        $addedUser = Get-LabFinalGroupAddedUser @userParameters
        if ([guid]$addedUser.ObjectGUID -ne $addedUserGuid) { throw 'Final added-user identity changed during removals.' }
        Write-Status -IndentLevel 3 -Kind Info -Message ('Adding [{0}] as the only direct user of [{1}] and the last directory mutation.' -f $addedUser.Name, $expected.Name)
        Add-ADGroupMember -Identity $groupGuid -Members $addedUserGuid.ToString() -Server $server -Confirm:$false -ErrorAction Stop
        $verified = Get-LabFinalGroupUserState @readParameters
        if (@($verified.Users).Count -ne 1 -or [guid]$verified.Users[0].ObjectGUID -ne $addedUserGuid) {
            throw 'Final membership did not verify: the configured user must be the only direct user.'
        }
        # Count the verified addition before replication/settling can fail.
        $linkIdentity = '{0}|{1}' -f $groupGuid, $addedUserGuid
        Add-LabProcessingCount -Category 'group memberships' -Added 1 -Identity $linkIdentity
        Write-Status -IndentLevel 4 -Kind Success -Message ('Added and verified [{0}] as the only direct user of [{1}].' -f $addedUser.Name, $expected.Name)
        Write-Status -IndentLevel 0 -Kind Success -Message ('Final group changes [{0}]: {1} direct user links removed, then [{2}] added; {3} non-user members retained.' -f $expected.Name, $removedCount, $addedUser.Name, $verified.NonUserCount)
        # Terminal write boundary: only replication, logging and reads follow.
        Invoke-LabSyntheticReplicationSync -Domain $Domain -SectionName 'final Helpdesk Ops membership changes' -Partition Domain
        $settled = Get-LabFinalGroupUserState @readParameters
        if (@($settled.Users).Count -ne 1 -or [guid]$settled.Users[0].ObjectGUID -ne $addedUserGuid) {
            throw 'Final membership changed during replication/settling; no automatic retry or success claim.'
        }
        Write-Status -IndentLevel 2 -Kind Success -Message ("Final membership verified after replication on [{0}]: [{1}] is the only direct user.`n          No further script directory mutations will run. DSP display order is not guaranteed." -f $server, $addedUser.Name)
    }
    catch {
        Stop-ScriptGracefully -IndentLevel 2 -Message ('Terminal group membership changes failed: {0} Earlier removals/addition may have committed. No rollback, recursive cleanup, replacement target or DC failover was attempted.' -f $_.Exception.Message)
    }
}

# FIXED ORDERING WRAPPER. This is deliberately separate from the extensible
# category runner above. Add new synthetic work ONLY to that runner, never
# below the terminal call. No finally: preserve fatal-error stop semantics.
function Invoke-LabADChanges {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Domain)

    $summaryVariable = Get-Variable -Name LabProcessingSummary -Scope Script -ErrorAction SilentlyContinue
    if ($null -ne $summaryVariable -and $null -ne $summaryVariable.Value) { $summaryVariable.Value.Phase = 'Synthetic' }
    Invoke-LabADChangeCategories -Domain $Domain
    Write-SectionHeader -Message 'AD Changes - FINAL Helpdesk Ops membership changes...'
    $finalDefinition = Get-LabFinalGroupADChangeDefinition
    Invoke-LabFinalGroupMembershipChanges -Domain $Domain -Definition $finalDefinition `
        -GroupDefinitions $script:LabGroupDefinitions -GroupObjects $script:LabGroupObjects `
        -UserDefinitions $script:LabDemoUserDefinitions -UserObjects $script:LabDemoUserObjects
    Write-LabSectionCompleted
    # TERMINAL WRITE BOUNDARY: no further directory mutations permitted.
}

function Invoke-Main {
    [CmdletBinding()]
    param()

    $demoPassword = $null
    $tier0AdminPassword = $null
    try {
        # Literal here-string: preserve every banner space and backslash.
        # Do not route through status/indentation or formatting helpers.
        $startupBanner = @'
   ____              __           ___   ___  _____          __           __  _____                      __          
  /  _/__ _  _____  / /_____ ____/ _ | / _ \/ ___/__  ___  / /____ ___  / /_/ ___/__ ___  ___ _______ _/ /____  ____
 _/ // _ \ |/ / _ \/  '_/ -_)___/ __ |/ // / /__/ _ \/ _ \/ __/ -_) _ \/ __/ (_ / -_) _ \/ -_) __/ _ `/ __/ _ \/ __/
/___/_//_/___/\___/_/\_\\__/   /_/ |_/____/\___/\___/_//_/\__/\__/_//_/\__/\___/\__/_//_/\__/_/  \_,_/\__/\___/_/
'@
        Write-Host $startupBanner -ForegroundColor White
        Write-Host ''
        Write-SectionHeader -Message 'Starting Invoke-ADContentGenerator-v1_8_22' -ForegroundColor DarkBlue -Label 'STARTUP'
        Write-Host ''

        $startupInformation = @'
---------------------------------------------------------------
This script does the following:
- add/updates users
- add/updates generic users
- add/updates computers
- add/updates groups
- add/updates OUs
- add/updates GPOs
- add/updates FGPPs
- add/updates DNS zones and records
- add/updates AD Sites and Services objects (sites, subnets, site links)
- sets/resets some ACLs
- creates realistic OU structures
- creates complex nested group structures
- creates 'Admin-Tier0' to use as an unprivileged DSP logon.
- makes synthetic AD changes to simulate realistic activity
- This script is idempotent and can be re-run as needed.
- makes no system or configuration settings changes.
---------------------------------------------------------------
'@
        Write-Host $startupInformation -ForegroundColor Gray
        Write-Host ''

        # Clearing a current-user credential does not require elevation or AD
        # administrative membership. Domain discovery is needed to identify
        # the exact credential target used by this script.
        $domain = Get-DomainContext -SkipPrerequisiteInstallation:($ClearStoredCreds -or $RemoveAllGeneratedContent)
        if ($RemoveAllGeneratedContent) {
            Invoke-LabGeneratedContentRemoval -Domain $domain
            return
        }
        $script:LabGroupNestingSummaryDomain = $domain
        $script:LabGroupDefinitions = Get-LabGroupDefinitions -DomainDN $domain.DistinguishedName
        # Version-independent credential namespace; keep stable across future script revisions.
        $credentialTarget = 'Semperis.Invoke-ADContentGenerator.{0}' -f $domain.DNSRoot
        $tier0CredentialTarget = 'Semperis.Invoke-ADContentGenerator.Tier0Admin.{0}' -f $domain.DNSRoot

        if ($ClearStoredCreds) {
            [void](Clear-DemoPasswordFromCredentialStore -Target $credentialTarget)
            [void](Clear-DemoPasswordFromCredentialStore -Target $tier0CredentialTarget -CredentialLabel 'Tier0Admin')
            return
        }

        # Validate the toggle before provisioning writes. Do not treat the
        # nonempty string 'False' as Boolean True through implicit conversion.
        if ($MakeADChanges -isnot [bool]) {
            Stop-ScriptGracefully -Message 'DEFAULTS MakeADChanges must be the Boolean $True or $False, not a string or number.'
        }

        Test-OperatorRights -Domain $domain
        Initialize-LabModulePrerequisites
        Initialize-LabGroupPolicyTools
        # Install missing AD DS tools and verify executable lookup before writes.
        # Rights and native exit codes are still checked by each actual sync.
        Initialize-LabReplicationTools

        Initialize-LabGeneratedInventory -Domain $domain
        Sync-LabConfiguredInventory -Domain $domain -Stage BeforeProvisioning

        $demoPassword = Get-DemoPasswordFromCredentialStore -Target $credentialTarget -TimeoutSeconds $PasswordPromptTimeoutSeconds
        if ($null -eq $demoPassword) {
            Stop-ScriptGracefully -Message 'The credential helper returned no password. No provisioning was started.'
        }

        # Never use the shared DEMO entry as a fallback for Tier0Admin.
        $tier0AdminPassword = Get-DemoPasswordFromCredentialStore -Target $tier0CredentialTarget `
            -CredentialLabel 'Tier0Admin' -TimeoutSeconds $PasswordPromptTimeoutSeconds `
            -WindowTitle 'Tier0Admin account password'
        if ($null -eq $tier0AdminPassword -or $tier0AdminPassword.Length -eq 0) {
            Stop-ScriptGracefully -Message 'No Tier0Admin password is available. No provisioning was started.'
        }

        # Ask immediately after password retrieval/update, before AD writes.
        # Cancel/timeout uses the default; the saved default is not modified.
        $selectedGenericUserCount = Read-GenericUserCountWithTimeout `
            -DefaultCount $GenericUserCount -MaximumCount $GenericUserMaximumCount `
            -TimeoutSeconds $GenericUserPromptTimeoutSeconds

        Write-Status -Kind Success -Message 'Prerequisites passed; demo and dedicated Tier0Admin passwords are ready as SecureStrings.'
        if ($RefreshAllPasswords) {
            Write-Status -Kind Info -Message 'RefreshAllPasswords enabled: refresh allowlisted demo accounts and Tier0Admin using their respective Windows Credential Store entries. All random-password users, admins, service and special accounts are excluded.'
        }

        # Advisory disk inventory runs before baseline writes and outside the
        # AD-processing timer. Low space pauses for review; query failures
        # do not stop activity. Reset the aggregate flag for every run.
        $script:LabDiskSpacePauseRequired = $false
        Show-LabLocalDiskSpace -WarningThresholdGB $DiskSpaceWarningThresholdGB
        if ($CheckDspDiskSpace -isnot [bool]) {
            Write-Status -Kind Warning -Message 'DSP disk-space check skipped: DEFAULTS CheckDspDiskSpace must be Boolean $True or $False, not a string or number.'
        }
        elseif ($CheckDspDiskSpace) {
            $dspServerNames = @(Get-LabDspServerNames -Domain $domain -TimeoutSeconds $DspDiscoveryTimeoutSeconds)
            Show-LabDspDiskSpace -ComputerNames $dspServerNames `
                -WarningThresholdGB $DiskSpaceWarningThresholdGB -TimeoutSeconds $DspDiskCheckTimeoutSeconds
        }
        else {
            Write-Status -Kind Info -Message 'DSP disk-space check skipped (CheckDspDiskSpace = $False). No DSP SCP discovery or remote disk query performed.'
        }

        Wait-LabDiskSpaceReview -Seconds $DiskSpaceReviewPauseSeconds

        # Prompts and read-only discovery are complete. Start timing at the
        # AD-write boundary, before any object creation, update or reset.
        Initialize-LabProcessingSummary -SyntheticEnabled ([bool]$MakeADChanges)
        $script:processingStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $dnsZoneDefinitions = @(Get-LabDnsZoneDefinitions)
        $dnsRecordDefinitions = @(Get-LabDnsRecordDefinitions -DomainDNSRoot $domain.DNSRoot)
        $dnsResult = Ensure-LabDnsBaseline -Domain $domain -ZoneDefinitions $dnsZoneDefinitions -RecordDefinitions $dnsRecordDefinitions
        if (-not $dnsResult.Skipped) {
            Invoke-LabBaselineReplicationSync -Domain $domain -SectionName 'DNS zones and records' -Partition Dns
        }
        Write-LabSectionCompleted

        Ensure-RequiredOrganizationalUnits -Domain $domain
        Invoke-LabBaselineReplicationSync -Domain $domain -SectionName 'OUs' -Partition Domain
        Write-LabSectionCompleted

        # WMI filter baselines precede GPO settings; later synthetic changes
        # can use the verified stable-key registry without a name-only lookup.
        $script:LabWmiFilterDefinitions = Get-LabWmiFilterDefinitions
        $wmiFilterResult = Ensure-LabWmiFilters -Domain $domain -Definitions $script:LabWmiFilterDefinitions
        Write-Status -IndentLevel 1 -Kind Info -Message 'WMI filters: dedicated forced replication and settling pause skipped.'
        Write-LabSectionCompleted

        # Process all baseline GPOs immediately after WMI verification.
        # Remaining provisioning provides additional time before synthetic
        # GPO changes; the checkpoint does not guarantee convergence.
        $script:LabGpoChangeTargets = @()
        $gpoDefinitions = @(Get-LabGpoDefinitions)
        $gpoResults = @(
            foreach ($gpoDefinition in $gpoDefinitions) {
                Ensure-LabGpo -Domain $domain -Definition $gpoDefinition
                Write-LabSectionCompleted
            }
        )

        $script:LabGpoChangeTargets = $gpoResults

        # One standard configurable checkpoint after all GPOs, including
        # intentional policy skips and recoverable file-lock skips. This AD
        # checkpoint does not repair or verify any skipped GPO/SYSVOL state.
        # Other errors still stop before this step.
        Invoke-LabGpoReplicationSync -Domain $domain
        Write-LabSectionCompleted

        $script:LabComputerDefinitions = Get-LabComputerDefinitions -DomainDN $domain.DistinguishedName
        $script:LabComputerObjects = Ensure-LabComputers -Domain $domain -ComputerDefinitions $script:LabComputerDefinitions
        Invoke-LabBaselineReplicationSync -Domain $domain -SectionName 'computers' -Partition Domain
        Write-LabSectionCompleted

        $script:LabGroupObjects = Ensure-RequiredGroups -Domain $domain -GroupDefinitions $script:LabGroupDefinitions
        Write-LabSectionCompleted
        $groupNestingResult = Ensure-LabGroupNesting -Domain $domain `
            -GroupDefinitions $script:LabGroupDefinitions -GroupObjects $script:LabGroupObjects
        Invoke-LabBaselineReplicationSync -Domain $domain -SectionName 'groups and nesting' -Partition Domain
        Write-LabSectionCompleted

        $script:LabDemoUserDefinitions = Get-LabDemoUserDefinitions -DomainDN $domain.DistinguishedName -DomainDNSRoot $domain.DNSRoot
        $script:LabDemoUserObjects = Ensure-LabDemoUsers -Domain $domain `
            -UserDefinitions $script:LabDemoUserDefinitions -DemoPassword $demoPassword -Tier0AdminPassword $tier0AdminPassword `
            -DoNotUpdateExistingPasswords $DoNotUpdateDemoUsersPasswords -RefreshAllPasswords:$RefreshAllPasswords
        Invoke-LabBaselineReplicationSync -Domain $domain -SectionName 'demo users' -Partition Domain
        Write-LabSectionCompleted

        Write-SectionHeader -Message 'Create/Update specific object ACLs...'
        $specificAclResult = Invoke-LabSpecificObjectAcls -Domain $domain -Phase Baseline
        Write-Status -IndentLevel 0 -Kind Success -Message ('Baseline specific ACLs: {0} changes verified; {1} already matched.' -f $specificAclResult.ChangedCount,$specificAclResult.UnchangedCount)
        Invoke-LabBaselineReplicationSync -Domain $domain -SectionName 'specific object ACLs' -Partition Domain
        Write-LabSectionCompleted

        $specialAccountResult = Ensure-SpecialDomainAccounts -Domain $domain -AccountPassword $demoPassword `
            -DoNotUpdateExistingPasswords $DoNotUpdateSpecialDomainAcctPasswords -RefreshAllPasswords:$RefreshAllPasswords
        Invoke-LabBaselineReplicationSync -Domain $domain -SectionName 'special domain accounts' -Partition Domain
        Write-LabSectionCompleted

        $genericUserResult = Ensure-GenericUsers -Domain $domain -Count $selectedGenericUserCount -MaximumCount $GenericUserMaximumCount -DoNotUpdateExistingUsers $DoNotUpdateGenericUsers
        Invoke-LabBaselineReplicationSync -Domain $domain -SectionName 'generic users' -Partition Domain
        Write-LabSectionCompleted

        # --- Baseline AD Sites and Services: sites, subnets, IP links -----
        # Operator's AD site means the site of the computer running this script.
        # Do not use the selected DC's site as a substitute.
        $MyADSite = $null
        try {
            $operatorSite = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()
            try {
                $MyADSite = [string]$operatorSite.Name
            }
            finally {
                if ($null -ne $operatorSite) { $operatorSite.Dispose() }
            }
            if ([string]::IsNullOrWhiteSpace($MyADSite)) {
                throw 'The local computer site lookup returned an empty site name.'
            }
            Write-Status -Kind Info -Message ('Operator computer AD site ($MyADSite): [{0}].' -f $MyADSite)
        }
        catch {
            $MyADSite = ''
            Write-Status -IndentLevel 2 -Kind Warning -Message ('The current user''s AD site could not be determined. Continuing with subnet create/update for 111.111.4.0/24 and 111.111.5.0/24 as unlinked subnets. Existing site links on these subnets will be cleared. Details: {0}' -f $_.Exception.Message)
        }

        $siteDefinitions = @(Get-LabSiteDefinitions)
        $siteResult = Ensure-LabSites -Domain $domain -SiteDefinitions $siteDefinitions
        Write-Status -IndentLevel 1 -Kind Info -Message 'AD sites: dedicated forced replication and settling pause skipped.'
        Write-LabSectionCompleted

        $subnetDefinitions = @(Get-LabSubnetDefinitions -MyADSite $MyADSite -SiteDefinitions $siteDefinitions)
        $subnetResult = Ensure-LabSubnets -Domain $domain -SubnetDefinitions $subnetDefinitions
        Write-Status -IndentLevel 1 -Kind Info -Message 'AD subnets: dedicated forced replication and settling pause skipped.'
        Write-LabSectionCompleted

        $siteLinkDefinitions = @(Get-LabSiteLinkDefinitions)
        $siteLinkResult = Ensure-LabSiteLinks -Domain $domain -SiteLinkDefinitions $siteLinkDefinitions
        Write-Status -IndentLevel 1 -Kind Info -Message 'AD site links: dedicated forced replication and settling pause skipped.'
        Write-LabSectionCompleted

        $fgppDefinitions = @(Get-LabFineGrainedPasswordPolicyDefinitions -DomainDN $domain.DistinguishedName)
        $fgppResult = Ensure-LabFineGrainedPasswordPolicies -Domain $domain -Definitions $fgppDefinitions
        Write-Status -IndentLevel 1 -Kind Info -Message 'FGPPs: dedicated forced replication and settling pause skipped.'
        Write-LabSectionCompleted

        $membershipSettings = Get-LabGroupUserMembershipSettings
        if (-not $membershipSettings.Contains('ExactMembership') -or $membershipSettings.ExactMembership -isnot [bool]) {
            Stop-ScriptGracefully -IndentLevel 2 -Message 'Get-LabGroupUserMembershipSettings must define ExactMembership as $true or $false.'
        }
        $membershipDefinitions = Get-LabGroupUserMembershipDefinitions -DomainDN $domain.DistinguishedName
        $membershipResult = Ensure-LabGroupMemberships -Domain $domain `
            -GroupDefinitions $script:LabGroupDefinitions -GroupObjects $script:LabGroupObjects `
            -MembershipDefinitions $membershipDefinitions -ExactMembership $membershipSettings.ExactMembership
        Invoke-LabBaselineReplicationSync -Domain $domain -SectionName 'direct group memberships' -Partition Domain
        Write-LabSectionCompleted

        Write-SectionHeader -Message 'Provisioning summary...' -ForegroundColor White
        $dnsSummaryKind = 'Success'
        if ($dnsResult.Skipped -or ($dnsResult.ZoneFailedCount + $dnsResult.AFailedCount + $dnsResult.PtrWarningCount + $dnsResult.AclWarningCount) -gt 0) { $dnsSummaryKind = 'Warning' }
        Write-Status -Kind $dnsSummaryKind -Message ('DNS: {0}/{1} zones, {2}/{3} static A records and {4} PTRs verified; {5} zone failure(s), {6} A failure(s), {7} PTR warning(s); skipped={8}. DNS replication/convergence is not verified by these counts.' -f $dnsResult.ZoneVerifiedCount, $dnsZoneDefinitions.Count, $dnsResult.AVerifiedCount, $dnsRecordDefinitions.Count, $dnsResult.PtrVerifiedCount, $dnsResult.ZoneFailedCount, $dnsResult.AFailedCount, $dnsResult.PtrWarningCount, $dnsResult.Skipped)
        Write-Status -Kind $dnsSummaryKind -Message ('DNS ACL baseline: {0} cleanup(s) verified; {1} warning(s).' -f $dnsResult.AclResetCount, $dnsResult.AclWarningCount)
        Write-Status -Kind Success -Message ('WMI filters: {0} verified ({1} created, {2} updated, {3} already matched); stable-key references available in LabWmiFilterObjects. GPO associations were not changed.' -f $wmiFilterResult.VerifiedCount, $wmiFilterResult.CreatedCount, $wmiFilterResult.UpdatedCount, $wmiFilterResult.UnchangedCount)
        $computerSummaryKind = 'Success'
        if ($script:LabComputerObjects.Count -lt $script:LabComputerDefinitions.Count) { $computerSummaryKind = 'Warning' }
        Write-Status -Kind $computerSummaryKind -Message ('Computer objects: {0} of {1} definitions verified and available by stable key in LabComputerObjects. Review the computer section for skipped definitions.' -f $script:LabComputerObjects.Count,$script:LabComputerDefinitions.Count)
        if ($groupNestingResult.SkippedCount -gt 0) {
            Write-Status -Kind Warning -Message 'Some configured nesting links were skipped; review the nesting warnings.'
        }
        else {
            Write-Status -Kind Success -Message 'Configured group nesting links were confirmed on the selected DC.'
        }
        Write-Status -Kind Success -Message ('Group properties and {0} demo users were ensured; see the OU section for individual OU results.' -f $script:LabDemoUserObjects.Count)
        $specialSummaryKind = 'Success'
        if ($specialAccountResult.SkippedCount -gt 0) { $specialSummaryKind = 'Warning' }
        Write-Status -Kind $specialSummaryKind -Message ('Special domain accounts: {0} verified, {1} skipped.' -f $specialAccountResult.VerifiedCount, $specialAccountResult.SkippedCount)
        Write-Status -Kind Success -Message ('AD sites: {0} verified ({1} created, {2} updated, {3} already matched).' -f $siteResult.VerifiedCount, $siteResult.CreatedCount, $siteResult.UpdatedCount, $siteResult.UnchangedCount)
        $subnetSummaryKind = 'Success'
        if ($subnetResult.SkippedCount -gt 0) { $subnetSummaryKind = 'Warning' }
        Write-Status -Kind $subnetSummaryKind -Message ('AD subnets: {0} verified ({1} created, {2} updated, {3} already matched), {4} skipped.' -f $subnetResult.VerifiedCount, $subnetResult.CreatedCount, $subnetResult.UpdatedCount, $subnetResult.UnchangedCount, $subnetResult.SkippedCount)
        Write-Status -Kind Success -Message ('AD site links: {0} verified ({1} created, {2} updated, {3} already matched).' -f $siteLinkResult.VerifiedCount, $siteLinkResult.CreatedCount, $siteLinkResult.UpdatedCount, $siteLinkResult.UnchangedCount)
        Write-Status -Kind Success -Message ('FGPPs: {0} verified ({1} created, {2} updated, {3} already matched); baseline subjects verified on the selected DC; temporary assignments are not removed in baseline. Removal runs only in the later synthetic AD Changes phase when MakeADChanges=True.' -f $fgppResult.VerifiedCount, $fgppResult.CreatedCount, $fgppResult.UpdatedCount, $fgppResult.UnchangedCount)
        foreach ($gpoResult in $gpoResults) {
            if ($gpoResult.Skipped) {
                $skipDetail = 'No settings or metadata writes were made to this GPO.'
                if ($gpoResult.PartialChangesPossible) {
                    $skipDetail = 'Earlier writes may have committed; this GPO was not fully verified.'
                }
                Write-Status -Kind Warning -BackgroundColor DarkRed -Message ("GPO [{0}]: skipped. {1} {2}`n          Link configuration not changed by this script." -f $gpoResult.Name, $gpoResult.SkipReason, $skipDetail)
            }
            else {
                Write-Status -Kind Success -Message ("GPO [{0}]:`n            {1} policy settings verified ({2} changed, {3} already matched); {4} reported link(s);`n            link configuration not changed by this script." -f $gpoResult.Name, $gpoResult.VerifiedCount, $gpoResult.ChangedCount, $gpoResult.UnchangedCount, $gpoResult.LinkCount)
            }
        }
        if ($membershipResult.ErrorCount -gt 0 -or $membershipResult.RemovalSuppressedCount -gt 0) {
            Write-Status -IndentLevel 2 -Kind Warning -Message 'Group membership reconciliation was incomplete; review the named-object errors and suppressed-cleanup warnings.'
        }
        else {
            Write-Status -Kind Success -Message 'Configured direct group memberships were reconciled; required nesting was preserved.'
        }
        if ($genericUserResult.OUUnavailable) {
            Write-Status -Kind Warning -Message ('Generic-user section skipped: target OU unavailable; {0} accounts not processed.' -f $genericUserResult.SkippedCount)
        }
        else {
            Write-Status -Kind Success -Message ('Generic users: {0} verified ({1} created, {2} updated, {3} already matched); {4} existing accounts left untouched.' -f $genericUserResult.VerifiedCount, $genericUserResult.CreatedCount, $genericUserResult.UpdatedCount, $genericUserResult.UnchangedCount, $genericUserResult.SkippedCount)
        }
        Write-LabSectionCompleted
        # The baseline content and its summary are complete before this phase.
        if ($MakeADChanges) {
            # Snapshot baseline elapsed time without stopping or resetting the
            # cumulative timer. Match the final flush-left text and colors.
            if ($null -ne $script:processingStopwatch) {
                $baselineElapsed = $script:processingStopwatch.Elapsed
                # TotalHours avoids wrapping after 24 hours; preserve milliseconds.
                $baselineElapsedText = '{0:00}:{1:00}:{2:00}.{3:000}' -f ([long][Math]::Floor($baselineElapsed.TotalHours)), $baselineElapsed.Minutes, $baselineElapsed.Seconds, $baselineElapsed.Milliseconds
                Write-Host ('[INFO] Total elapsed processing time: {0} (HH:MM:SS.mmm).' -f $baselineElapsedText) -ForegroundColor White -BackgroundColor DarkMagenta
            }
            Invoke-LabADChanges -Domain $domain
        }
        else {
            Write-Status -Kind Info -Message 'AD Changes skipped: MakeADChanges is False. Content provisioning is complete.'
        }
    }
    finally {
        if ($null -ne $script:LabInventoryStream) {
            try {
                if ($null -eq $script:LabInventoryFault) {
                    Sync-LabConfiguredInventory -Domain $domain -Stage AfterProvisioning
                }
            }
            finally {
                $script:LabInventoryStream.Dispose()
                $script:LabInventoryStream = $null
            }
        }
        if ($null -ne $tier0AdminPassword) {
            $tier0AdminPassword.Dispose()
        }
        if ($null -ne $demoPassword) {
            $demoPassword.Dispose()
        }
    }
}

$transcriptStarted = $false
$script:LabProcessingSummary = $null
$script:LabGroupNestingSummaryDomain = $null
$script:processingStopwatch = $null
$transcriptPath = Join-Path $PSScriptRoot (
    'Invoke-ADContentGenerator-v1_8_22_{0}.txt' -f (Get-Date -Format 'yyyyMMdd_HHmmss')
)

try {
    try {
        Start-Transcript -Path $transcriptPath -ErrorAction Stop | Out-Null
        $transcriptStarted = $true
        Write-Status -Kind Info -Message ("Transcript: {0}" -f $transcriptPath)
    }
    catch {
        Write-Status -Kind Warning -Message ("Could not start a transcript: {0}" -f $_.Exception.Message)
    }

    # Invoke-Main starts timing only after prompts and read-only discovery,
    # immediately before provisioning. Early exits may never start a timer.
    try {
        Invoke-Main
    }
    finally {
        # Freeze elapsed time before final success/error status output.
        if ($null -ne $script:processingStopwatch) {
            $script:processingStopwatch.Stop()
        }
    }
    if ($RemoveAllGeneratedContent) {
        Write-Status -IndentLevel 0 -Kind Info -Message 'Removal mode exited; no provisioning ran. Review removal results above.'
    }
    else {
        Write-Status -IndentLevel 0 -Kind Success -Message 'Script completed.'
    }
    if (-not $RemoveAllGeneratedContent) {
        Write-LabProcessingSummary -GroupNames $DisplayGroupNestingSummary -Domain $script:LabGroupNestingSummaryDomain
    }
}
catch [System.OperationCanceledException] {
    # Stop-ScriptGracefully already printed the reason. Return from the script
    # rather than using exit, which can terminate or destabilize an ISE session.
    return
}
catch {
    Write-Status -Kind Error -Message ("Unexpected failure: {0}" -f $_.Exception.Message)
    return
}
finally {
    try {
        if ($null -ne $script:processingStopwatch) {
            $elapsed = $script:processingStopwatch.Elapsed
            # TotalHours avoids wrapping after 24 hours; preserve milliseconds.
            $elapsedText = '{0:00}:{1:00}:{2:00}.{3:000}' -f ([long][Math]::Floor($elapsed.TotalHours)), $elapsed.Minutes, $elapsed.Seconds, $elapsed.Milliseconds
            Write-Host ('[INFO] Total elapsed processing time: {0} (HH:MM:SS.mmm).' -f $elapsedText) -ForegroundColor White -BackgroundColor DarkMagenta
        }
    }
    finally {
        # Even a failed elapsed-time output must not bypass transcript cleanup.
        if ($transcriptStarted) {
            Stop-Transcript | Out-Null
        }
    }
}
