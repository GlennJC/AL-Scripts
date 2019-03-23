# Main

This script is designed to deploy Microsoft System Centre Configuration Manager (Current Branch) using Automated-Lab as the base deployment toolkit

This is a highly enhanced version of the CustomRoles toolkit in Automated Lab, and is designed to produce a fully-configured SCCM platform for build and deployment testing

Prerequisites:

- Installed version of Automated-Lab
- Download of the Microsoft Assessment and Deployment Kit - available here:
    https://developer.microsoft.com/en-us/windows/hardware/windows-assessment-deployment-kit
    - Tested with 1809 Version
- A Server operating system image for a three machine AL machine deployment (Domain Controller, SCCM Server, SQL Server):
    - Tested with Windows Server 2016 for all roles
- SCCM Requires SQL Server installed, assumed that existing AL SQL Role deployment method is used.
    - Tested with SQL Server 2017
- SCCM Prerequisites downloaded using SETUPDL.EXE, available in SCCM package in .\SMSSETUP\BIN\X64.
    - Tested with SCCM 1802

Known Restrictions/Limitations:

- Currently tested with a single AD Domain, Dedicated SCCM, and dedicated SQL Server
- Lab is using the new VLAN configuration component of AL
- SCCM Server has 3 additional drives attached for SCCM DP content, Sources, and WSUS Content, currently configured as 200gb each. Sizes can be changed based on requirements, but SCCM is a disk hog
- A minimum of 12gb of memory + multiple vCPU's is recommended due to number of running processes across the three servers. DC can safely drop to 2gb if there are memory constraints
- SCCM Requires a specific SQL collation setting, which needs to be specific during the Virtual Machine definition phase:

    ```ps
    $roles = (Get-LabMachineRoleDefinition -Role SQLServer2014 -Properties @{ Collation = 'SQL_Latin1_General_CP1_CI_AS' })
    Add-LabDiskDefinition -Name SCCMData -DiskSizeInGb 100
    Add-LabMachineDefinition -Name $SCCMServerName -DiskName SCCMData -Memory 4GB -Processors 4 -Roles $roles -IpAddress '192.168.40.20'
    ```

- All SCCM Generated certificates are self-signed, solution does not currently integrate with Certificate Services
- Note that the Breakdown of activities for SCCM configuration may not be ideal and does result in additional execution time to reload powershell modules / reconnect to SCCM site servers, however this is deliberate to allow specific functions to be disabled so manual configuration can be done as part of training / documentation development activities.

This script is a work in progress, there are some assumptions made resulting in some lack of error checking. Additional enhancements are in the pipeline, and are managed as enhancement requests within GitHub

Projected Functionality and Current Status
- AD Domain Build - Complete
    - DHCP Server and Scopes - Complete
    - OU Structure - Complete (23/03)
    - DNS Forwarder Fix (AL currently configures an Azure Forwarder which must be replaced)
- SQL Server Build - Complete (currently restricted to a single drive for all content)
- SCCM Server build - Base Install Complete
    - Windows Deployment Server - Base Install Complete
        - DHCP / PXE listen configuration - Complete
        - Boot Image Generation - Missing
    - Domain Join account created in AD and SCCM with premission restrictions on OU's - Complete
    - WSUS Install - Base Install Complete
        - Update of base products and components - Complete
        - Customisation of content types to download - Complete (23/03)
    - SCCM SUP Role - Complete (23/03)
    - Network Access Account in AD and SCCM + CM Config for Software Distribution Component - Complete
    - Client Push Account in AD and SCCM + CM Config for Client Push Installation - Complete
    - Default SCCM Boundary + Boundary Group creation - Complete
    - AD System Discovery - Complete
    - AD User Discovery - Complete
    - AD Group Discovery - Complete
    - Distribution Point Role - Missing
    - SCCM MDT Integration - Missing
    - Device Collections - Complete (23/03)

Update 11/03/19:
Major changes to the build process, the majority (soon all) settings are gathered from a JSON file stored in the same directory as the script. This file has settings subheading for all components.

This has resulted in a few changes:

1. All settings will be migrated to the config file. Currently there is some overlap for the main AL install process, however local variables have been created from settings in the config file. Eventually all settings will be pulled directly from the config file
2. The config file is based on my requirements for testing, so there are some configuration settings that may be less than ideal for a different setup (eg VLAN's). This mainly applies to the AL-Lab itself
3. Where possible, a non-specific approach for settings is being taken to aid in flexibility without requiring modifications to the main script. For example, AD OU Structure is completely arbitrary, and additional OU's can be added / removed. Current settings that are known to work:
    1. OU's (Note: OU's currently need to be created in a sequential order due to parent OU's needing to exist before the child is created)
    2. SCCM Service Accounts
    3. SCCM Domain Join Account OU's
    4. SCCM Boundary Groups
    5. SCCM Site Boundaries
4. Splatting is now used for most functions directly from the config file content (for some fields in functions, ie passwords that need ConvertTo-SecureString, some surrounding code is still used)
5. A MAJOR advantage of this new approach is that additional parameter settings for most cmdlets (for example New-ADUser for SCCM service accounts) can be added directly to the config file without requiring code changes. For example, add an office, phone number, ManagedBy field to an object. **NOTE:** The splatting processes makes no assumptions regarding parameter sets / invalid parameter types and the like pulled in from the Config File, all provided values will be passed to the function regardless.
6. Due to the behaviour of ConvertFrom-JSON when reading in the config file resulting in a complex PSCustomObject variable (and not the expected array / hashtable), additional conversions are required to convert these structures to HashTables to be used for splatting. For functions using the Invoke-LabCommand, the ConvertTo-PSObjectToHash function needs to be placed inside the ScriptBlock to allow these conversions to occur.

# Configuration File

The config file is stored and created using the Props.ps1 file.  Due to the way the object is constructed, comments are difficult to include, so are documented here

## LabProps

```powershell
LabProps = @{
        LabName = 'SCCMLAB1'
        VMPath = 'D:\AutomatedLab-VMs'
        ServerOS = 'Windows Server 2016 SERVERDATACENTER'
        ReferenceDiskSize = 80   
    }
```

LabProps is a hashtable of the settings for the automatedLab itself

## SwitchProps

```powershell
    SwitchProps = @{
        SwitchType = 'External'
        AdapterName = 'EXT-04'
        ManagementAdapter = $true
        vSwitchName = 'SCCMLab'
        vLANid = '50'
    }
```

SwitchProps is a hashtable for the main script, and defines the configuration of the switch that is created for the lab to connect to. Note that the current main script code is expecting some of these values (such as vLanID)

## NetworkProps

```powershell
NetworkProps = @{
        AddressSpace = '192.168.50.0'
        DefaultGW = '192.168.50.252'
        Netmask = '24'
        DNSServers = '192.168.50.10'
        DNSServerFowarder = '192.168.10.254'
        DHCPScope = @{
           Name          = 'Default Scope'
           StartRange    = '192.168.50.100'
           EndRange      = '192.168.50.150'
           SubnetMask    = '255.255.255.0'
           Description   = 'Default Scope for Clients'
           LeaseDuration = '0.08:00:00'
        }
        DHCPScopeOptions = @{
            DnsServer = '192.168.50.10'
            Router    = '192.168.50.252'
            ScopeId   = '192.168.50.100'
            DNSDomain = 'labtest.local'
            }
    }
```

NetworkProps defines the overall networking configuration for the lab (AddressSpace, DefaultGW, NetMask, DNSServers). The remaining configuration items are used to configure the DHCP scope inside the lab on the Domain controller. DHCPScope and DHCPScopeOptions can have additional parameters includes where the called functions support it:

* Add-DHCPServerv4Scope for DHCPScope
* Set-DhcpServerV4OptionValue for DHCPScopeOptions

## ADProps

```powershell
    ADProps = @{
        DomainName = 'labtest.local'
        DomainFunctionalLevel = 'Win2012R2'
        ForestFunctionalLevel = 'Win2012R2'
        OUStructure = @(
            @{Name="_Admin";ProtectedFromAccidentalDeletion=$false}
            @{Parent="OU=_Admin";Name="Service Accounts";Description="Service Accounts";ProtectedFromAccidentalDeletion=$false}
            @{Parent="OU=_Admin";Name="Privileged Users";Description="Admin User Accounts";ProtectedFromAccidentalDeletion=$false}
            @{Parent="OU=_Admin";Name="Privileged Groups";Description="Admin User Accounts";ProtectedFromAccidentalDeletion=$false}
            @{Name="_Workstations";ProtectedFromAccidentalDeletion=$false}
            @{Parent="OU=_Workstations";Name="Desktops";Description="Default Desktops";ProtectedFromAccidentalDeletion=$false}
            @{Parent="OU=_Workstations";Name="Staging";Description="Staging Desktop OU Used During Builds";ProtectedFromAccidentalDeletion=$false}
            @{Name="_Standard";ProtectedFromAccidentalDeletion=$false}
            @{Parent="OU=_Standard";Name="User Accounts";Description="Standard Users";ProtectedFromAccidentalDeletion=$false}
            @{Parent="OU=_Standard";Name="Groups";Description="Standard Groups";ProtectedFromAccidentalDeletion=$false}
            @{Parent="OU=_Standard";Name="Distribution Lists";Description="Exchange Distribution Lists";ProtectedFromAccidentalDeletion=$false}
        )
    }
```

ADProps defines the Active Directory settings. DomainName, DomainFunctionalLevel, and ForestFunctionalLevel are used as part of the AutomatedLab process, with OUStructure being used to create OU's on the Domain Controller. OUStructure is defined as an array of hashtables, and additional parameters can be included provided the **New-ADOrganizationalUnit** cmdlet supports them and the key name must match the parameter name for the cmdlet. The minimum key/value that needs to be provided is "Name" as this will be the name of the new OU. Currently, the OU structure needs to be entered into the configuration file in a specific order, noting that parent OU's need to exist before the child OU is created. Note: by default in recent windows versions, OU's are automatically created with the protection flag enabled, so **ProtectedFromAccidentalDeletion=$false** will need to be included for each OU that you dont want this flag set for.  The list of OU's is completely arbitrary, and can be as long as required.

## SCCMInstallProps

```powershell
    SCCMInstallProps = @{
        SccmSiteCode          = "S01"
        SccmSiteName          = "Primary Site"
        SccmBinariesDirectory = "$labSources\SoftwarePackages\SCCM1802"
        SccmPreReqsDirectory  = "$labSources\SoftwarePackages\SCCMPreReqs1802"
        SccmInstallDirectory  = "D:\Program Files\Microsoft Configuration Manager"
        AdkDownloadPath       = "$labSources\SoftwarePackages\ADK1809"
        AdkWinPEDownloadPath  = "$labSources\SoftwarePackages\ADK1809WinPEAddons"
        SqlServerName         = "$($LabName)-DB1"
    }
```

SCCMInstallProps defines the parameters required for the SCCM Custom role.  Currently, this is not used, rather the parameters should be modified in the main script

## SCCMConfigProps

The SCCMConfigProps section contains all SCCM configuration items, and due to its complexity, each sub-section is discussed individually

### ServiceAccounts

```powershell
ServiceAccounts = @(
            @{Role="DJ";Name="svcDJ";SamAccountName="svcDJ";UserPrincipalName="svcDJ";Password="Password123";Description="SCCM Domain Join Account";Enabled=$true;Path="OU=Service Accounts, OU=_Admin";ChangePasswordAtLogon=$False;PasswordNeverExpires=$True}
            @{Role="CP";Name="svcPush";SamAccountName="svcPush";UserPrincipalName="svcPush";Password="Password123";Description="SCCM Client Push Account";Enabled=$true;Path="OU=Service Accounts, OU=_Admin";ChangePasswordAtLogon=$False;PasswordNeverExpires=$True}
            @{Role="NA";Name="svcNAA";SamAccountName="svcNAA";UserPrincipalName="svcNAA";Password="Password123";Description="SCCM Network Access Account";Enabled=$true;Path="OU=Service Accounts, OU=_Admin";ChangePasswordAtLogon=$False;PasswordNeverExpires=$True}
        )
```

ServiceAccounts defines the service accounts that should be created specifically for SCCM. Additional parameters can be supplied, provided they are supported by the **New-ADUser** cmdlet. There are however a couple of parameters that need special consideration

* Role - defines what SCCM role this account will be used for, as additional configuration is performed based on this role.  Valid roles are: DJ = Domain Join Account, CP = Client Push Account, NA = Network Access Account. If an account role is not supplied, no additional configuration will be done, and the account will simply be a standard AD account
* UserPrincipalName - This will automatically be post-pended with the domain name where the account is being created
* Password - This should be supplied in plain text, and will automatically be converted using **ConvertTo-SecureString**
* Path - this should be the OU relative to the domain root where the account should be created. The domain portion will automatically be added based on the **Get-ADRootDSE** return value

### DomainJoinAccountOUs

```powershell
DomainJoinAccountOUs = @(
    @{OUName="OU=Desktops,OU=_Workstations"}
    @{OUName="OU=Staging,OU=_Workstations"}
    @{OUName="CN=Computers"}
)
```

DomainJoinAccountOUs defines those OUs that the Domain Join Account created in the ServiceAccounts section listed above should be granted rights to manage computer objects (add to domain etc).

### BoundaryGroups

```powershell
BoundaryGroups = @(
    @{Name="Default Boundary Group";SiteCode="S01"}
)
```

BoundaryGroups defines the boundary groups that should be created. The number of boundary groups is arbitrary and can be as few or as many required.

### SiteBoundaries

```powershell
SiteBoundaries = @(
    @{Name="192.168.50.0 Boundary";IPRange="192.168.50.1-192.168.50.254";MemberOfBoundaryGroupName="Default Boundary Group"}
    @{Name="192.168.51.0 Boundary";IPRange="192.168.51.1-192.168.51.254";MemberOfBoundaryGroupName="Default Boundary Group"}
    @{Name="192.168.52.0 Boundary";IPRange="192.168.52.1-192.168.52.254";MemberOfBoundaryGroupName="Default Boundary Group"}
)
```

SiteBoundries defines those site boundaries that should be created. Note that currently the only supported boundary type is **IPRange**

### DiscoveryMethods

```powershell
DiscoveryMethods = @{
    ActiveDirectorySystemDiscovery = @{
        Settings = @{SiteCode = "S01";Enabled=$true;EnableDeltaDiscovery=$true;DeltaDiscoveryMins=30;ActiveDirectoryContainer="LDAP://DC=LABTEST,DC=LOCAL";Recursive=$true}
        Schedule = @{RecurInterval="Days";RecurCount=1;Start="01/01/2001"}
    }
    ActiveDirectoryUserDiscovery = @{
        Settings = @{SiteCode = "S01";Enabled=$true;EnableDeltaDiscovery=$true;DeltaDiscoveryMins=30;ActiveDirectoryContainer="LDAP://DC=LABTEST,DC=LOCAL";Recursive=$true}
        Schedule = @{RecurInterval="Days";RecurCount=1;Start="01/01/2001"}
    }
    ActiveDirectoryGroupDiscovery = @{
        Settings = @{SiteCode = "S01";Enabled=$true;EnableDeltaDiscovery=$true;DeltaDiscoveryMins=30;DiscoverDistributionGroupMembership = $true}
        Scope = @{ Name = 'AD Group Discovery';SiteCode = "S01";RecursiveSearch = $true;LdapLocation="LDAP://DC=LABTEST,DC=LOCAL"}
        Schedule = @{RecurInterval="Days";RecurCount=1;Start="01/01/2001"}
    }
    HeartbeatDiscovery = @{
        Settings = @{SiteCode = "S01";Enabled=$true}
        Schedule = @{RecurInterval="Days";RecurCount=7}
    }
}
```

DiscoveryMethods defines the settings for the various Discovery Methods in SCCM. Each of the **Settings** can have additional parameters based on the various allowed parameters for the **Set-CMDiscoveryMethod** cmdlet, and **Schedule** can be any valid settings supported by the **New-CMSchedule** cmdlet. for the ActiveDirectoryGroupDiscovery method, an additional **Scope** option is available, and any valid settings used by **New-CMADGroupDiscoveryScope** can be included. Currently, only a single Scope option is supported for the Group Discovery item.

### Collections

```powershell
Collections = @{
    DeviceCollections = @(
        @{
            BasicSettings = @{Name = "All Servers";Comment = "All Servers";LimitingCollectionName="All Systems";RefreshType=2}
            Location = "Master Collections"
            Schedule = @{RecurInterval="Days";RecurCount=7}
            Variables = @(...)
            QueryMembershipRules = @(...)
            IncludeMembershipRules = @(...)
            ExcludeMembershipRules = @(...)
            DirectMembershipRules = @(...)
        }
    )
}
```

Collections defines those Device and User (Note User currently not implemented) collection to be created within SCCM. These are quite complex structure, so will be discussed in more detail. Note the collections within the Props.ps1 script have been taken from the excellent script at https://gallery.technet.microsoft.com/Set-of-Operational-SCCM-19fa8178#content and converted to be compatible with the format I required.

**Basic Settings**
Defines the overall basic settings of the collection.  Additional parameters can be provided, as long as they are supported by the **New-CMDeviceCollection** cmdlet

**Location**
Defines the location within the Hierarchy under "Device Collections" in SCCM. The folder provided should be separated by \ characters to designate sub-folders.  The folder hierarchy will be created if it does not exist

**Schedule**
Defines the refresh schedule for the collection, and can include any valid settings supported by the **New-CMSchedule** cmdlet (note that the refresh schedule may have limits on what type of schedule can be created). Currently if no schedule is supplied an error will be thrown

**Variables**
Defines any variables that should be assigned to collections. There can be zero or more variables defined.

```powershell
@{VariableName="MyVariable";Value="123"}
```

**Membership Rules**
There are 4 supported types of membership rules supported for each collection, noting that there can be multiple entries of each membership rule type, and collections can support zero or more membership rule types. Note that the script does not perform validation on the rule itself.

*Query Membership Rule*

Supports any parameters allowed by the **Add-CMDeviceCollectionQueryMembershipRule** cmdlet. Advice for properly formatted QueryExpression strings is to create the entry within SCCM, and then copy the query string out for use in the config file

```powershell
@{RuleName="All Servers";QueryExpression = "select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where OperatingSystemNameandVersion like '%Server%'"}
```

*Include Membership Rule*

Supports any parameters allowed by the **Add-CMDeviceCollectionIncludeMembershipRule** cmdlet. 

```powershell
@{IncludeCollectionName="All Workstations"}
```

*Exclude Membership Rule*

Supports any parameters allowed by the **Add-CMDeviceCollectionExcludeMembershipRule** cmdlet. 

```powershell
@{ExcludeCollectionName="WKS - SU - Exclusion"}
```

*Direct Membership Rule*

Supports any parameters allowed by the **Add-CMDeviceCollectionDirectMembershipRule** cmdlet. Each item listed must be an existing device within SCCM otherwise an error will be thrown.

```powershell
@('DeviceName'
'AnotherDevice'
)
```

### WSUSProps

Defines the properties for the WSUS/Software Update Point in SCCM

```powershell
WSUSProps = @{
            ContentDirectory='F:\WSUS'
            UpdateLanguages= @(
                'English'
            )
            
            EnabledProducts = @(
                'Windows Server 2016'
                'Windows Server 2012 R2'
                'Windows 10'
                'Office 2010'
                'Office 2016'
            )
            EnabledProductFamilies = @(
            )
            DisabledProducts = @(
            )
            DisabledClassifications = @(
                'Tools'
            )
            EnabledClassifications = @(
                'Critical Updates'    
                'Definition Updates'
                'Feature Packs'
                'Security Updates'
                'Service Packs'
                'Update Rollups'
                'Updates'
                'Upgrades'
            )
            Schedule = @{RecurInterval="Days";RecurCount=3}
        }
```

*ContentDirectory* defines the location on the SCCM server where WSUS content should be stored

*UpdateLanguages* defines a list of those languages that should be enabled for content download. Note that the language names must be the same as they appear in the SCCM console

*EnabledProducts* defines the list of product names that should be enabled for content download. Note the names must be the same as they appear in the SCCM console

*EnabledProductFamilies* defines the list of product families that should be enabled for content download (eg 'Windows', 'Office'). Note the names must be the same as they appear in the SCCM console

*Disabled Products* is a list of products that should be disabled. Note that by default, ALL products are disabled during initial configuration, and only those defined in the **EnabledProductFamilies** and **EnabledProducts** will then be re-enabled.  This setting therefore is designed to disable specific product(s) within a Product Family without requiring every individual product to be listed in the **EnabledProducts** list. For example, if you wanted all Office and Windows versions, except Office 2007, Office 2003 and Windows Vista, the configuration would be the following:

```powershell
EnabledProductFamilies = @(
    'Office'
    'Windows'
    ) 
DisabledProducts = @(
    'Office 2003'
    'Office 2007'
    'Windows Vista'
    )
```

*EnabledClassifications* defines those product classifications that should be enabled for content download. Note the names must be the same as they appear in the SCCM console

