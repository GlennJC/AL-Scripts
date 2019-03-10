This script is designed to deploy Microsoft System Centre Configuration Manager (Current Branch) using Automated-Lab as the base deployment toolkit

This is a highly enhanced version of the CustomRoles toolkit in Automated Lab, and is designed to produce a fully-configured SCCM platform for build and deployment testing

Prerequisites:

- Installed version of Automated-Lab 
- Download of the Microsoft Assessment and Deployment Kit - available here:
    https://developer.microsoft.com/en-us/windows/hardware/windows-assessment-deployment-kit
    Tested with 1809 Version
- A Server operating system image for an two machine AL machine deployment (Domain Controller and SCCM Server:
    Tested with Windows Server 2016 for both roles
- SCCM Requires SQL Server installed, assumed that existing AL SQL Role deployment method is used.
    Tested with SQL Server 2017
- SCCM Prerequisites downloaded using SETUPDL.EXE, available in SCCM package in .\SMSSETUP\BIN\X64. It is assumed that the guest machine does not have internet access, so this set of packages (approx 600mb) must be downloaded and placed into the $LabSources\SoftwarePackages\SCCMPreReqs folder

Known Restrictions/Limitations:

- Currently tested with a single AD Domain, Dedicated SCCM, and dedicated SQL Server
- Lab is using the new VLAN configuration component of AL
- SCCM Server has 3 additional drivbes attached for SCCM DP content, Sources, and WSUS Content
- A minimum of 12gb of memory + multiple vCPU's is recommended due to number of running processes across the three servers
- SCCM Requires a specific SQL collation setting, which needs to be specific during the Virtual Machine definition phase:

    ```ps
    $roles = (Get-LabMachineRoleDefinition -Role SQLServer2014 -Properties @{ Collation = 'SQL_Latin1_General_CP1_CI_AS' })
    Add-LabDiskDefinition -Name SCCMData -DiskSizeInGb 100
    Add-LabMachineDefinition -Name $SCCMServerName -DiskName SCCMData -Memory 4GB -Processors 4 -Roles $roles -IpAddress '192.168.40.20'
    ```
 
- All SCCM Generated certificates are self-signed, solution does not currently integrate with Certificate Services


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

