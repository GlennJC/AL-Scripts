This script is designed to deploy Microsoft System Centre Configuration Manager (Current Branch) using Automated-Lab as the base deployment toolkit

Prerequisites:

- Installed version of Automated-Lab (Tested on v4.5.0)
- Download of the Microsoft Assessment and Deployment Kit - available here:
    https://developer.microsoft.com/en-us/windows/hardware/windows-assessment-deployment-kit
    Tested with 1709 Version
- A Server operating system image for an two machine AL machine deployment (Domain Controller and SCCM Server:
    Tested with Windows Server 2016 for both roles
- SCCM Requires SQL Server installed, assumed that existing AL SQL Role deployment method is used.
    Tested with SQL Server 2014
- SCCM Prerequisites downloaded using SETUPDL.EXE, available in SCCM package in .\SMSSETUP\BIN\X64. It is assumed that the guest machine does not have internet access, so this set of packages (approx 600mb) must be downloaded and placed into the $LabSources\SoftwarePackages\SCCMPreReqs folder

Known Restrictions/Limitations:

- Currently tested with a single AD Domain and Dedicated SCCM+SQL Server
- SCCM Server must have a second disk attached to hold the SCCM Binaries, SQL Databases, and SCCM Content Shares (assumed to be D:) - A default install of SQL + SCCM + ADK uses approx 20GB of disk space, 60GB or more is recommended if Operating Systems, Applications, and Drivers will be installed
- A minimum of 4gb of memory + multiple vCPU's is recommended due to number of running processes + SQL Server
- SCCM Requires a specific SQL collation setting, which needs to be specific during the Virtual Machine definition phase:

    ```ps
    $roles = (Get-LabMachineRoleDefinition -Role SQLServer2014 -Properties @{ Collation = 'SQL_Latin1_General_CP1_CI_AS' })
    Add-LabDiskDefinition -Name SCCMData -DiskSizeInGb 100
    Add-LabMachineDefinition -Name $SCCMServerName -DiskName SCCMData -Memory 4GB -Processors 4 -Roles $roles -IpAddress '192.168.40.20'
    ```
 
- All SCCM Generated certificates are self-signed, solution does not currently integrate with Certificate Services
- Currently SCCM binaries are assumed to be in the $LabSources\SoftwarePackages folder.  Evaluation version of SCCM available from Microsoft Evaluation Center is a self-extracting EXE, rather than an ISO, so an ISO image deployment has not been tested.

This script is a work in progress, there are some assumptions made resulting in some lack of error checking. Additional enhancements are in the pipeline, and are managed as enhancement requests within GitHub

Update 31/03/18

A version of this script is being developed to support the AutomatedLab 'CustomRoles' feature that will released as part of Version 5.0

Scripts are located in the 'AL Custom Role' folder, and all items should be copied to the 'LabSources\CustomRoles' folder with the 'SCCM' folder name, eg:

```yaml
C:\LabSources\CustomRoles
                        \SCCM
                            \DownloadADK.ps1
                            \HostInit.ps1
                            \InstallSCCM.ps1
```

To use from AL:

```ps
$SCCMRole = Get-LabPostInstallationActivity -CustomRole SCCM -Properties @{
    SCCMSiteCode = "CM1"
    SCCMBinariesDirectory = "$labSources\SoftwarePackages\SCCM1702"
    SCCMPreReqsDirectory = "$labSources\SoftwarePackages\SCCMPreReqs"
    AdkDownloadPath = "$labSources\SoftwarePackages\ADK"
}

$roles = (Get-LabMachineRoleDefinition -Role SQLServer2014 -Properties @{ Collation = 'SQL_Latin1_General_CP1_CI_AS' })
Add-LabDiskDefinition -Name SCCMData -DiskSizeInGb 100
Add-LabMachineDefinition -Name SCCMDC -Roles RootDC -DomainName contoso.com
Add-LabMachineDefinition -Name SCCMServer -DiskName SCCMData -Memory 4GB -Processors 4 -Roles $roles -PostInstallationActivity $SCCMRole -DomainName contoso.com

```
