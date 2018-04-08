This script is designed to deploy Microsoft Deployment Toolkit (MDT) to an Automated-Lab provisioned server and result in a fully functional MDT+WDS server to deploy images

Prerequisites:

- Installed version of Automated-Lab (Tested on v4.5.0)
- Download of the Microsoft Assessment and Deployment Kit - available here:
    https://developer.microsoft.com/en-us/windows/hardware/windows-assessment-deployment-kit
    (Tested with 1709 Version)
- A Server operating system image for an AL machine deployment:
    Tested on Windows Server 2012 R2, and Windows Server 2016

All other necessary files such as MDT are downloaded through the script.

Note: Script assumes internet access is avaiable to download binary files.  If no Internet access is available, at a minimum download the MDT installation files and place in the LabSources\SoftwarePackages folder, available at: https://download.microsoft.com/download/3/3/9/339BE62D-B4B8-4956-B58D-73C4685FC492/MicrosoftDeploymentToolkit_x64.msi

Known Limitations:
- Deployed Server can either be a member of a domain or standalone. Has not been tested where MDT is a DC.
- Script assumes that MDT+ADK, WDS and DHCP all reside on the same server. 

This script is a work in progress, there are some assumptions made resulting in some lack of error checking. Additional enhancements are in the pipeline, and are managed as enhancement requests within GitHub

Update 8/4:

A version of this script is has been developed to support the AutomatedLab 'CustomRoles' feature that will released as part of Version 5.0.

Scripts are located in the 'AL Custom Role' folder, and all items should be copied to the 'LabSources\CustomRoles' folder with the 'MDT' folder name, eg:

```yaml
C:\LabSources\CustomRoles
                        \MDT
                            \DownloadADK.ps1
                            \HostInit.ps1
                            \InstallMDT.ps1
                            \MDTApplications.XML
```

To use from AL:

```ps
$mdtRole = Get-LabPostInstallationActivity -CustomRole MDT -Properties @{
    DeploymentFolderLocation = 'D:\DeploymentShare'
    InstallUserID = 'MdtService'
    InstallPassword = 'Somepass1'
    OperatingSystems = 'Windows Server 2016 Datacenter (Desktop Experience)', 'Windows 10 Enterprise|10.0.10586.0|Windows 10 Enterprise 1511','Windows 10 Enterprise|10.0.15063.296|Windows 10 Enterprise 1703'
    AdkDownloadPath = "$labSources\SoftwarePackages\ADK"
    CreateTaskSequences = 'True'
}

Add-LabDiskDefinition -Name MDTData -DiskSizeInGb 100
Add-LabMachineDefinition -Name MDT1Server -Memory 4GB -Processors 2 -DiskName MDTData -OperatingSystem 'Windows Server 2016 Datacenter (Desktop Experience)' -IpAddress 192.168.81.10 -PostInstallationActivity $mdtRole

```

A feature has been added to support direct targeting of Operating Systems using a combination of the OS name and OS version. Within the 'OperatingSystems' parameter, multiple Operating Systems can be provided, with additional supported options being:

'OS Name' - System will search for an AutomatedLab Operating System name and pick the newest one of there are multiples
'OS Name|OS Version' - System will search for an AutomatedLab Operating System name, with the specific version
'OS Name|OS Version|Friendly Name' - System will search for an AutomatedLab Operating System name, with the specific version, and use the Friendly Name when registering the OS to MDT.

Any combination of these options can be used for each item in the OperatingSystems List.

Use the Get-LabAvailableOperatingSystems command provides Details on the available Operating Systems
