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
    - OU Structure - Complete
    - DNS Forwarder Fix (AL currently configures an Azure Forwarder which must be replaced)
- SQL Server Build - Complete (currently restricted to a single drive for all content)
- SCCM Server build - Base Install Complete
    - Windows Deployment Server - Base Install Complete
        - DHCP / PXE listen configuration - Complete
        - Boot Image Generation - Missing
    - Domain Join account created in AD and SCCM with premission restrictions on OU's - Complete
    - WSUS Install - Base Install Complete
        - Update of base products and components - Complete
        - Customisation of content types to download - Missing
    - SCCM SUP Role - Missing
    - Network Access Account in AD and SCCM + CM Config for Software Distribution Component - Complete
    - Client Push Account in AD and SCCM + CM Config for Client Push Installation - Complete
    - Default SCCM Boundary + Boundary Group creation - Complete
    - AD System Discovery - Complete
    - AD USer Discovery - Complete
    - AD Group Discovery - Complete
    - Distribution Point Role - Missing
    - SCCM MDT Integration - Missing

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
5. A MAJOR advantage of this new approach is that additional parameter settings for most cmdlets (for example New-ADUser for SCCM service accounts) can be added directly to the config file without requiring code changes. For example, add an office, phone number, ManagedBy field to an object
6. Due to the behaviour of ConvertFrom-JSON when reading in the config file resulting in a complex PSCustomObject variable (and not the expected array / hashtable), additional conversions are required to convert these structures to HashTables to be used for splatting. For functions using the Invoke-LabCommand, the ConvertTo-PSObjectToHash function needs to be placed inside the ScriptBlock to allow these conversions to occur.